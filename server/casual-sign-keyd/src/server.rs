//! The daemon: an mTLS server (rustls, TLS 1.3 only, a client certificate required and
//! chained to the configured client CA) that serves get-certificate-chain and
//! sign-digest to callers on an allow-list of certificate fingerprints, rate-limits
//! signatures per caller, and records every request in its [`OpLog`] before answering.
//!
//! A caller whose certificate does not chain to the client CA never completes the
//! handshake; one that chains but is not on the allow-list is answered `CS-KEY-0001`
//! and recorded. Blocking I/O, one thread per connection, at most
//! [`KeydLimits::max_connections`] at once, with read and write timeouts.

use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use aws_lc_rs::digest::{SHA256, digest};
use der::Encode;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::pem::PemObject;

use crate::error::KeydError;
use crate::oplog::{OpLog, OpRecord, hex};
use crate::pem::tls_certificates;
use crate::signer::{DigestSigner, wire_id};
use crate::wire::{Request, Response, read_frame, valid_id, write_frame};

/// The hex SHA-256 of a DER certificate: how the allow-list and the log name a caller.
#[must_use]
pub fn fingerprint(cert_der: &[u8]) -> String {
    hex(digest(&SHA256, cert_der).as_ref())
}

/// The callers keyd answers, by client-certificate fingerprint.
#[derive(Debug, Clone, Default)]
pub struct AllowList {
    names: HashMap<String, String>,
}

impl AllowList {
    /// An empty list: nobody is answered.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow the certificate with this hex SHA-256 fingerprint, under `name` (for
    /// operators; the log records the fingerprint).
    pub fn allow(&mut self, fingerprint: &str, name: &str) {
        self.names
            .insert(fingerprint.to_ascii_lowercase(), name.to_owned());
    }

    /// Parse a list file: one `fingerprint [name]` per line, `#` comments.
    ///
    /// # Errors
    /// `CS-KEY-0010` for a line whose first word is not 64 hex digits.
    pub fn parse(text: &str) -> Result<Self, KeydError> {
        let mut out = Self::new();
        for (i, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            let mut words = line.split_whitespace();
            let fp = words.next().unwrap_or_default();
            if fp.len() != 64 || !fp.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(KeydError::TlsConfig(format!(
                    "allow-list line {} is not a SHA-256 fingerprint",
                    i.saturating_add(1)
                )));
            }
            out.allow(fp, words.next().unwrap_or("-"));
        }
        Ok(out)
    }

    /// Whether `fingerprint` is allowed.
    #[must_use]
    pub fn contains(&self, fingerprint: &str) -> bool {
        self.names.contains_key(fingerprint)
    }

    /// How many callers are allowed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Whether nobody is allowed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

/// Bounds on what one keyd serves.
#[derive(Debug, Clone, Copy)]
pub struct KeydLimits {
    /// Signatures per caller per minute.
    pub signatures_per_minute: u32,
    /// Connections at once; more are closed on accept.
    pub max_connections: usize,
    /// Read and write timeout per connection.
    pub io_timeout: Duration,
}

impl Default for KeydLimits {
    fn default() -> Self {
        Self {
            signatures_per_minute: 600,
            max_connections: 64,
            io_timeout: Duration::from_secs(30),
        }
    }
}

/// The keys, the allow-list, the rate limiter and the log: everything that decides an
/// answer, apart from TLS.
pub struct KeyService {
    keys: HashMap<String, Arc<dyn DigestSigner>>,
    allow: AllowList,
    log: Mutex<OpLog>,
    windows: Mutex<HashMap<String, (Instant, u32)>>,
    limits: KeydLimits,
}

impl core::fmt::Debug for KeyService {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyService")
            .field("keys", &self.keys.keys().collect::<Vec<_>>())
            .field("allowed", &self.allow.len())
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl KeyService {
    /// A service answering `allow`, recording to `log`.
    #[must_use]
    pub fn new(allow: AllowList, log: OpLog, limits: KeydLimits) -> Self {
        Self {
            keys: HashMap::new(),
            allow,
            log: Mutex::new(log),
            windows: Mutex::new(HashMap::new()),
            limits,
        }
    }

    /// Serve `key` under `alias`.
    ///
    /// # Errors
    /// `CS-KEY-0007` for an alias outside `[A-Za-z0-9._-]{1,64}`; `CS-KEY-0006` for a key
    /// whose algorithm keyd cannot name on the wire.
    pub fn add_key(&mut self, alias: &str, key: Arc<dyn DigestSigner>) -> Result<(), KeydError> {
        if !valid_id(alias, false) {
            return Err(KeydError::Malformed("alias outside [A-Za-z0-9._-]{1,64}"));
        }
        if wire_id(key.algorithm()).is_none() {
            return Err(KeydError::KeyConfig(
                crate::error::KeyConfigProblem::UnsupportedAlgorithm,
            ));
        }
        self.keys.insert(alias.to_owned(), key);
        Ok(())
    }

    fn record(&self, r: &OpRecord) -> Result<(), KeydError> {
        self.log
            .lock()
            .map_err(|_| KeydError::OperationLog("lock poisoned".into()))?
            .append(r)
    }

    fn within_rate(&self, caller: &str) -> bool {
        let Ok(mut w) = self.windows.lock() else {
            return false;
        };
        let now = Instant::now();
        let entry = w.entry(caller.to_owned()).or_insert((now, 0));
        if now.duration_since(entry.0) >= Duration::from_secs(60) {
            *entry = (now, 0);
        }
        if entry.1 >= self.limits.signatures_per_minute {
            return false;
        }
        entry.1 = entry.1.saturating_add(1);
        true
    }

    /// Refuse a caller that is not on the allow-list, recording it.
    fn admit(&self, caller: &str) -> Result<(), KeydError> {
        if self.allow.contains(caller) {
            return Ok(());
        }
        let err = KeydError::NotAuthorized;
        self.record(&OpRecord {
            time: now(),
            caller: caller.to_owned(),
            op: "connect",
            alias: String::new(),
            alg: String::new(),
            digest: String::new(),
            envelope: String::new(),
            outcome: err.code(),
        })?;
        Err(err)
    }

    /// Answer one request from `caller` (already admitted), recording it first.
    fn answer(&self, caller: &str, req: &Request) -> Response {
        match self.try_answer(caller, req) {
            Ok(r) => r,
            Err(e) => Response::Error(e.number()),
        }
    }

    fn try_answer(&self, caller: &str, req: &Request) -> Result<Response, KeydError> {
        match req {
            Request::Chain { alias } => {
                let found = self.keys.get(alias);
                let mut rec = OpRecord {
                    time: now(),
                    caller: caller.to_owned(),
                    op: "chain",
                    alias: alias.clone(),
                    alg: String::new(),
                    digest: String::new(),
                    envelope: String::new(),
                    outcome: "ok",
                };
                let Some(key) = found else {
                    rec.outcome = KeydError::UnknownAlias.code();
                    self.record(&rec)?;
                    return Err(KeydError::UnknownAlias);
                };
                let alg = wire_id(key.algorithm()).ok_or(KeydError::KeyConfig(
                    crate::error::KeyConfigProblem::UnsupportedAlgorithm,
                ))?;
                rec.alg = alg.to_string();
                let certs = key
                    .certificate_chain()
                    .iter()
                    .map(|c| {
                        c.to_der()
                            .map_err(|_| KeydError::Malformed("certificate does not encode"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                self.record(&rec)?;
                Ok(Response::Chain {
                    alg,
                    development: key.is_development(),
                    certs,
                })
            }
            Request::Sign {
                alias,
                alg,
                digest,
                envelope,
            } => {
                let mut rec = OpRecord {
                    time: now(),
                    caller: caller.to_owned(),
                    op: "sign",
                    alias: alias.clone(),
                    alg: alg.to_string(),
                    digest: hex(digest),
                    envelope: envelope.clone(),
                    outcome: "ok",
                };
                let result = self.sign(caller, alias, *alg, digest);
                if let Err(e) = &result {
                    rec.outcome = e.code();
                }
                // No signature leaves without its record (fail closed).
                self.record(&rec)?;
                result.map(Response::Signature)
            }
        }
    }

    fn sign(
        &self,
        caller: &str,
        alias: &str,
        alg: u8,
        digest: &[u8],
    ) -> Result<Vec<u8>, KeydError> {
        if !self.within_rate(caller) {
            return Err(KeydError::RateLimited);
        }
        let key = self.keys.get(alias).ok_or(KeydError::UnknownAlias)?;
        if wire_id(key.algorithm()) != Some(alg) {
            return Err(KeydError::Malformed("algorithm is not the key's"));
        }
        key.sign_digest(digest)
    }
}

/// The server's TLS configuration: its certificate chain and key (PEM), and the CA
/// (PEM) a client certificate must chain to. TLS 1.3 only; a client certificate is
/// mandatory.
///
/// # Errors
/// `CS-KEY-0010` when any of them does not load.
pub fn server_tls(
    chain_pem: &[u8],
    key_pem: &[u8],
    client_ca_pem: &[u8],
) -> Result<Arc<ServerConfig>, KeydError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let tls = |e: rustls::Error| KeydError::TlsConfig(e.to_string());
    let mut roots = RootCertStore::empty();
    for ca in tls_certificates(client_ca_pem)? {
        roots.add(ca).map_err(tls)?;
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|e| KeydError::TlsConfig(e.to_string()))?;
    let key = PrivateKeyDer::from_pem_slice(key_pem)
        .map_err(|_| KeydError::TlsConfig("the server key does not load".into()))?;
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(tls_certificates(chain_pem)?, key)
        .map_err(tls)?;
    Ok(Arc::new(config))
}

/// A bound keyd, ready to serve.
#[derive(Debug)]
pub struct Keyd {
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    service: Arc<KeyService>,
    open: Arc<AtomicUsize>,
}

impl Keyd {
    /// Bind `addr` (`127.0.0.1:0` picks a port).
    ///
    /// # Errors
    /// `CS-KEY-0011` when the address cannot be bound.
    pub fn bind(
        addr: &str,
        tls: Arc<ServerConfig>,
        service: KeyService,
    ) -> Result<Self, KeydError> {
        let listener = TcpListener::bind(addr)
            .map_err(|e| KeydError::Transport(format!("bind: {}", e.kind())))?;
        Ok(Self {
            listener,
            tls,
            service: Arc::new(service),
            open: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// The bound address.
    ///
    /// # Errors
    /// `CS-KEY-0011` if the socket cannot say.
    pub fn local_addr(&self) -> Result<SocketAddr, KeydError> {
        self.listener
            .local_addr()
            .map_err(|e| KeydError::Transport(e.kind().to_string()))
    }

    /// Serve until the process ends. Each connection runs on its own thread.
    pub fn serve(self) {
        let limits = self.service.limits;
        for stream in self.listener.incoming() {
            let Ok(stream) = stream else { continue };
            if self.open.fetch_add(1, Ordering::SeqCst) >= limits.max_connections {
                self.open.fetch_sub(1, Ordering::SeqCst);
                drop(stream);
                continue;
            }
            let tls = self.tls.clone();
            let service = self.service.clone();
            let open = self.open.clone();
            std::thread::spawn(move || {
                if let Err(e) = connection(stream, tls, &service, limits.io_timeout) {
                    // Codes and kinds only: no request content.
                    eprintln!("keyd: connection ended: {e}");
                }
                open.fetch_sub(1, Ordering::SeqCst);
            });
        }
    }
}

fn connection(
    stream: TcpStream,
    tls: Arc<ServerConfig>,
    service: &KeyService,
    timeout: Duration,
) -> Result<(), KeydError> {
    let io = |e: std::io::Error| KeydError::Transport(e.to_string());
    stream.set_read_timeout(Some(timeout)).map_err(io)?;
    stream.set_write_timeout(Some(timeout)).map_err(io)?;
    let conn = ServerConnection::new(tls).map_err(|e| KeydError::TlsConfig(e.to_string()))?;
    let mut s = StreamOwned::new(conn, stream);
    while s.conn.is_handshaking() {
        s.conn.complete_io(&mut s.sock).map_err(io)?;
    }
    // The verifier required a certificate chaining to the client CA; the allow-list
    // decides whether this one is answered.
    let caller = s
        .conn
        .peer_certificates()
        .and_then(|c| c.first())
        .map(|c| fingerprint(c.as_ref()))
        .ok_or(KeydError::NotAuthorized)?;
    if let Err(e) = service.admit(&caller) {
        let _ = write_frame(&mut s, &Response::Error(e.number()).encode()?);
        s.conn.send_close_notify();
        let _ = s.conn.complete_io(&mut s.sock);
        return Err(e);
    }
    while let Some(body) = read_frame(&mut s)? {
        let response = match Request::decode(&body) {
            Ok(req) => service.answer(&caller, &req),
            Err(e) => Response::Error(e.number()),
        };
        write_frame(&mut s, &response.encode()?)?;
    }
    s.conn.send_close_notify();
    let _ = s.conn.complete_io(&mut s.sock);
    Ok(())
}
