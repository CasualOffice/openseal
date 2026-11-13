//! The daemon: an mTLS server (rustls, TLS 1.3 only, a client certificate required and
//! chained to the configured client CA) that serves get-certificate-chain and
//! sign-digest to callers on an allow-list of certificate fingerprints, rate-limits
//! signatures per caller, and records every request in its [`OpLog`] before answering.
//!
//! A caller whose certificate does not chain to the client CA never completes the
//! handshake; one that chains but is not on the allow-list is answered `CS-KEY-0001`
//! and recorded.
//!
//! A second allow-list, the admin list (`OPENSEAL_KEYD_ADMIN_ALLOW_LIST`, docs/23 §5.4,
//! `CON-06`), names the console's admin identity. Its callers are answered `list-keys`,
//! `oplog-head`, `oplog-range` and `health`, which are read-only and carry certificates,
//! hashes, ids and codes, never a key; they cannot get a chain or a signature, and a
//! signing caller cannot call an admin operation (`CS-CON-0008`, recorded either way).
//! No fingerprint may be on both lists. Blocking I/O, one thread per connection, at most
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
use crate::wire::{
    Health, KeyHealth, KeyInfo, Request, Response, read_frame, valid_id, write_frame,
};

use casual_sign_seclog::{
    Kind, Label, Level, Outcome, Principal, SecurityEvent, SecurityLog, Service, Uuid, Value,
};

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

    /// The allowed fingerprints.
    pub fn fingerprints(&self) -> impl Iterator<Item = &str> {
        self.names.keys().map(String::as_str)
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
    admin: AllowList,
    started: Instant,
    log: Mutex<OpLog>,
    windows: Mutex<HashMap<String, (Instant, u32)>>,
    limits: KeydLimits,
    security: SecurityLog,
}

impl core::fmt::Debug for KeyService {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyService")
            .field("keys", &self.keys.keys().collect::<Vec<_>>())
            .field("allowed", &self.allow.len())
            .field("admins", &self.admin.len())
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
            admin: AllowList::new(),
            started: Instant::now(),
            log: Mutex::new(log),
            windows: Mutex::new(HashMap::new()),
            limits,
            security: SecurityLog::from_env(Service::Keyd),
        }
    }

    /// Write security events (`ASVS-08`: key use, refused callers, rate limits) to
    /// `log` rather than standard error.
    #[must_use]
    pub fn with_security_log(mut self, log: SecurityLog) -> Self {
        self.security = log;
        self
    }

    /// One security event about `caller` (by certificate fingerprint).
    fn event(
        &self,
        kind: Kind,
        outcome: Outcome,
        caller: &str,
        code: Option<&'static str>,
        extra: Vec<(&'static str, Value)>,
    ) {
        let mut ev = SecurityEvent::new(kind, outcome);
        if let Some(l) = Label::new(caller) {
            ev = ev.principal(Principal::Caller(l));
        }
        if let Some(c) = code {
            ev = ev.code(c);
        }
        for (k, v) in extra {
            ev = ev.with(k, v);
        }
        self.security.emit(&ev);
    }

    /// Answer the read-only admin operations to the callers on `admin` (the console's
    /// admin identity, docs/23 §5.4). They are answered nothing else.
    ///
    /// # Errors
    /// `CS-KEY-0010` when a fingerprint is on both the signing and the admin list.
    pub fn with_admin(mut self, admin: AllowList) -> Result<Self, KeydError> {
        if admin.fingerprints().any(|f| self.allow.contains(f)) {
            return Err(KeydError::TlsConfig(
                "a fingerprint is on both the signing and the admin allow-list".into(),
            ));
        }
        self.admin = admin;
        Ok(self)
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

    /// Refuse a caller that is on neither allow-list, recording it; otherwise say which.
    fn admit(&self, caller: &str) -> Result<Role, KeydError> {
        if self.allow.contains(caller) {
            return Ok(Role::Signer);
        }
        if self.admin.contains(caller) {
            return Ok(Role::Admin);
        }
        let err = KeydError::NotAuthorized;
        self.event(
            Kind::CallerRefused,
            Outcome::Failure,
            caller,
            Some(err.code()),
            vec![("reason", Value::Word("not_allowed"))],
        );
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

    /// Answer one request from `caller` (already admitted as `role`), recording it first.
    fn answer(&self, caller: &str, role: Role, req: &Request) -> Response {
        match self.try_answer(caller, role, req) {
            Ok(r) => r,
            Err(e) => Response::Error(e.number()),
        }
    }

    fn admin_record(&self, caller: &str, req: &Request, outcome: &'static str) -> OpRecord {
        OpRecord {
            time: now(),
            caller: caller.to_owned(),
            op: req.op_name(),
            alias: String::new(),
            alg: String::new(),
            digest: String::new(),
            envelope: String::new(),
            outcome,
        }
    }

    fn try_answer(&self, caller: &str, role: Role, req: &Request) -> Result<Response, KeydError> {
        // The two lists answer disjoint operations (docs/23 §5.4).
        if req.is_admin() != (role == Role::Admin) {
            let err = KeydError::AdminRefused;
            self.event(
                Kind::Denied,
                Outcome::Failure,
                caller,
                Some(err.code()),
                vec![("op", Value::Word(req.op_name()))],
            );
            self.record(&self.admin_record(caller, req, err.code()))?;
            return Err(err);
        }
        match req {
            Request::ListKeys
            | Request::OplogHead
            | Request::OplogRange { .. }
            | Request::Health => {
                self.record(&self.admin_record(caller, req, "ok"))?;
                self.admin_answer(req)
            }
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
                    self.key_event(caller, "chain", alias, None, Some(rec.outcome));
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
                self.key_event(caller, "chain", alias, None, None);
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
                match &result {
                    Err(KeydError::RateLimited) => self.event(
                        Kind::RateLimited,
                        Outcome::Failure,
                        caller,
                        Some(KeydError::RateLimited.code()),
                        vec![("op", Value::Word("sign"))],
                    ),
                    Err(e) => self.key_event(caller, "sign", alias, Some(envelope), Some(e.code())),
                    Ok(_) => self.key_event(caller, "sign", alias, Some(envelope), None),
                }
                result.map(Response::Signature)
            }
        }
    }

    /// `key.use`: `op` on `alias` for `envelope`, refused with `code` when given. The
    /// digest is not logged (the op log has it).
    fn key_event(
        &self,
        caller: &str,
        op: &'static str,
        alias: &str,
        envelope: Option<&str>,
        code: Option<&'static str>,
    ) {
        let mut extra = vec![("op", Value::Word(op))];
        if let Some(a) = Label::new(alias) {
            extra.push(("alias", Value::Label(a)));
        }
        if let Some(e) = envelope.and_then(|e| Uuid::parse_str(e).ok()) {
            extra.push(("envelope_id", Value::Id(e)));
        }
        let outcome = if code.is_some() {
            Outcome::Failure
        } else {
            Outcome::Success
        };
        self.event(Kind::KeyUse, outcome, caller, code, extra);
    }

    /// The read-only answers, after the call is recorded.
    fn admin_answer(&self, req: &Request) -> Result<Response, KeydError> {
        let log = || {
            self.log
                .lock()
                .map_err(|_| KeydError::OperationLog("lock poisoned".into()))
        };
        match req {
            Request::ListKeys => {
                let mut aliases: Vec<&String> = self.keys.keys().collect();
                aliases.sort();
                let mut out = Vec::with_capacity(aliases.len());
                for alias in aliases {
                    let Some(key) = self.keys.get(alias) else {
                        continue;
                    };
                    out.push(key_info(alias, key.as_ref())?);
                }
                Ok(Response::Keys(out))
            }
            Request::OplogHead => {
                let log = log()?;
                let (seq, head) = log.head();
                Ok(Response::Head {
                    seq,
                    hash: unhex(head).ok_or(KeydError::OperationLog("head".into()))?,
                })
            }
            Request::OplogRange { from, n } => {
                // The head under the lock; the file is read after it is released.
                let (path, upto) = {
                    let log = log()?;
                    (log.path().to_path_buf(), log.head().0)
                };
                Ok(Response::Range(crate::oplog::read_range(
                    &path,
                    *from,
                    usize::from(*n),
                    upto,
                )?))
            }
            Request::Health => {
                let log_seq = log()?.head().0;
                let mut aliases: Vec<&String> = self.keys.keys().collect();
                aliases.sort();
                let keys = aliases
                    .into_iter()
                    .filter_map(|a| {
                        self.keys.get(a).map(|k| KeyHealth {
                            alias: a.clone(),
                            backend: k.backend().to_owned(),
                            ok: k.healthy(),
                        })
                    })
                    .collect();
                Ok(Response::Health(Health {
                    log_seq,
                    uptime_s: self.started.elapsed().as_secs(),
                    keys,
                }))
            }
            Request::Chain { .. } | Request::Sign { .. } => {
                Err(KeydError::Malformed("not an admin operation"))
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

/// Which list admitted a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// The signing allow-list: get-certificate-chain and sign-digest.
    Signer,
    /// The admin allow-list: the read-only admin operations.
    Admin,
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    (0..s.len())
        .step_by(2)
        .map(|i| {
            s.get(i..i.saturating_add(2))
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        })
        .collect()
}

/// A name as the admin interface carries it: control characters replaced, at most
/// [`casual_sign_keyd_client::wire::MAX_NAME`] bytes.
fn name_text(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        let c = if c.is_control() { '?' } else { c };
        if out.len().saturating_add(c.len_utf8()) > casual_sign_keyd_client::wire::MAX_NAME {
            break;
        }
        out.push(c);
    }
    out
}

fn unix(t: &x509_cert::time::Time) -> i64 {
    i64::try_from(t.to_unix_duration().as_secs()).unwrap_or(i64::MAX)
}

/// What `list-keys` reports of one key: the chain, the signer certificate's validity and
/// names. Never the key.
fn key_info(alias: &str, key: &dyn DigestSigner) -> Result<KeyInfo, KeydError> {
    let alg = wire_id(key.algorithm()).ok_or(KeydError::KeyConfig(
        crate::error::KeyConfigProblem::UnsupportedAlgorithm,
    ))?;
    let chain = key.certificate_chain();
    let leaf = chain.first().ok_or(KeydError::KeyConfig(
        crate::error::KeyConfigProblem::NoCertificate,
    ))?;
    let tbs = leaf.tbs_certificate();
    let certs = chain
        .iter()
        .map(|c| {
            c.to_der()
                .map_err(|_| KeydError::Malformed("certificate does not encode"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(KeyInfo {
        alias: alias.to_owned(),
        backend: key.backend().to_owned(),
        alg,
        development: key.is_development(),
        not_before: unix(&tbs.validity().not_before),
        not_after: unix(&tbs.validity().not_after),
        subject: name_text(&tbs.subject().to_string()),
        issuer: name_text(&tbs.issuer().to_string()),
        certs,
    })
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
                    // Codes only: no request content.
                    let mut m = serde_json::Map::new();
                    m.insert("code".into(), e.code().into());
                    casual_sign_seclog::write(Service::Keyd, Level::Info, "connection_ended", m);
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
        if let Err(e) = s.conn.complete_io(&mut s.sock) {
            // A caller without a certificate chaining to the client CA, or speaking no
            // TLS 1.3 (ASVS-08, 9.2.5): who it was is unknown, so no principal.
            service.event(
                Kind::CallerRefused,
                Outcome::Failure,
                "",
                Some("CS-KEY-0011"),
                vec![("reason", Value::Word("handshake"))],
            );
            return Err(io(e));
        }
    }
    // The verifier required a certificate chaining to the client CA; the allow-list
    // decides whether this one is answered.
    let caller = s
        .conn
        .peer_certificates()
        .and_then(|c| c.first())
        .map(|c| fingerprint(c.as_ref()))
        .ok_or(KeydError::NotAuthorized)?;
    let admitted = service.admit(&caller);
    while let Some(body) = read_frame(&mut s)? {
        // A caller off the allow-list gets its refusal as the answer to its first
        // request (read first, so the refusal is not lost to a reset), and nothing else.
        if let Err(e) = &admitted {
            write_frame(&mut s, &Response::Error(e.number()).encode()?)?;
            break;
        }
        let response = match (&admitted, Request::decode(&body)) {
            (Ok(role), Ok(req)) => service.answer(&caller, *role, &req),
            (_, Err(e)) => Response::Error(e.number()),
            (Err(e), _) => Response::Error(e.number()),
        };
        write_frame(&mut s, &response.encode()?)?;
    }
    s.conn.send_close_notify();
    let _ = s.conn.complete_io(&mut s.sock);
    admitted.map(|_| ())
}
