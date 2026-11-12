//! The daemon: an mTLS server (rustls, TLS 1.3 only, a client certificate required and
//! chained to the configured client CA) that answers modeld's operations to callers on an
//! allow list of certificate fingerprints, bounds concurrent work with slots, and records
//! every request in its [`OpLog`] (counts and ids only). Copied from keyd's `server.rs`
//! (`server/casual-sign-keyd/src/server.rs`, stage 2E): the allow list, the TLS
//! configuration and the connection loop are keyd's; the service is modeld's.
//!
//! A caller whose certificate does not chain to the client CA never completes the
//! handshake; one that chains but is not on the allow list is answered `CS-ML-0015` and
//! recorded. Blocking I/O, one thread per connection, at most
//! [`ModeldLimits::max_connections`] at once, with read and write timeouts. modeld holds
//! no database, SMTP, webhook or keyd credential (ADR-029).

use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use aws_lc_rs::digest::{SHA256, digest};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::pem::PemObject;

use crate::client::tls_certificates;
use crate::error::ModeldError;
use crate::manifest::Bundle;
use crate::oplog::{OpLog, OpRecord, hex};
use crate::wire::{Info, Op, Request, Response, read_frame, write_frame};

/// The runtime version INFO reports until an inference runtime is linked.
pub const NO_RUNTIME: &str = "none";

/// The hex SHA-256 of a DER certificate: how the allow list and the log name a caller.
#[must_use]
pub fn fingerprint(cert_der: &[u8]) -> String {
    hex(digest(&SHA256, cert_der).as_ref())
}

/// The callers modeld answers, by client-certificate fingerprint (keyd's `AllowList`).
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

    /// Allow the certificate with this hex SHA-256 fingerprint, under `name`.
    pub fn allow(&mut self, fingerprint: &str, name: &str) {
        self.names
            .insert(fingerprint.to_ascii_lowercase(), name.to_owned());
    }

    /// Parse a list file: one `fingerprint [name]` per line, `#` comments.
    ///
    /// # Errors
    /// `CS-ML-0001` for a line whose first word is not 64 hex digits.
    pub fn parse(text: &str) -> Result<Self, ModeldError> {
        let mut out = Self::new();
        for (i, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            let mut words = line.split_whitespace();
            let fp = words.next().unwrap_or_default();
            if fp.len() != 64 || !fp.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(ModeldError::TlsConfig(format!(
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

/// Bounds on what one modeld serves.
#[derive(Debug, Clone, Copy)]
pub struct ModeldLimits {
    /// Operations running at once; more are answered busy (`CS-ML-0009`). INFO takes no
    /// slot.
    pub slots: usize,
    /// Connections at once; more are closed on accept.
    pub max_connections: usize,
    /// Read and write timeout per connection.
    pub io_timeout: Duration,
}

impl Default for ModeldLimits {
    fn default() -> Self {
        Self {
            slots: 1,
            max_connections: 64,
            io_timeout: Duration::from_secs(30),
        }
    }
}

/// How many slots fit (ADR-029 review defect 11): half the cores, but never more than the
/// memory left after the models, divided by one slot's peak. At least one.
#[must_use]
pub fn default_slots(cores: usize, memory_limit: u64, model_rss: u64, per_slot_peak: u64) -> usize {
    let by_cpu = cores / 2;
    let by_memory = memory_limit
        .saturating_sub(model_rss)
        .checked_div(per_slot_peak)
        .map_or(0, |n| usize::try_from(n).unwrap_or(usize::MAX));
    by_cpu.min(by_memory).max(1)
}

/// A slot held while an operation runs; released on drop.
struct Slot<'a>(&'a AtomicUsize);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The bundle, the allow list, the slots and the log: everything that decides an answer,
/// apart from TLS.
pub struct ModelService {
    bundle: Bundle,
    runtime: String,
    allow: AllowList,
    log: Mutex<OpLog>,
    busy: AtomicUsize,
    limits: ModeldLimits,
}

impl core::fmt::Debug for ModelService {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ModelService")
            .field("bundle", &self.bundle.id)
            .field("models", &self.bundle.installed.len())
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

/// Saturating `usize` to `u32`, for log counts.
fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

impl ModelService {
    /// A service over a verified `bundle`, answering `allow`, recording to `log`.
    #[must_use]
    pub fn new(bundle: Bundle, allow: AllowList, log: OpLog, limits: ModeldLimits) -> Self {
        Self {
            bundle,
            runtime: NO_RUNTIME.to_owned(),
            allow,
            log: Mutex::new(log),
            busy: AtomicUsize::new(0),
            limits,
        }
    }

    /// The verified bundle.
    #[must_use]
    pub fn bundle(&self) -> &Bundle {
        &self.bundle
    }

    fn record(&self, r: &OpRecord) -> Result<(), ModeldError> {
        self.log
            .lock()
            .map_err(|_| ModeldError::OperationLog("lock poisoned".into()))?
            .append(r)
    }

    fn take_slot(&self) -> Option<Slot<'_>> {
        let max = self.limits.slots;
        self.busy
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < max).then(|| n.saturating_add(1))
            })
            .ok()
            .map(|_| Slot(&self.busy))
    }

    /// Refuse a caller that is not on the allow list, recording it.
    fn admit(&self, caller: &str) -> Result<(), ModeldError> {
        if self.allow.contains(caller) {
            return Ok(());
        }
        let err = ModeldError::NotAuthorized;
        self.record(&OpRecord {
            time: now(),
            caller: caller.to_owned(),
            op: "connect",
            account: String::new(),
            job: String::new(),
            pages: 0,
            items: 0,
            millis: 0,
            outcome: err.code(),
            bundle: self.bundle.id.clone(),
        })?;
        Err(err)
    }

    /// Answer one request from an admitted `caller`, recording it. A request whose record
    /// cannot be written is answered with the log's error.
    pub fn answer(&self, caller: &str, req: &Request) -> Response {
        let started = Instant::now();
        let result = self.handle(req, started);
        let (outcome, items) = match &result {
            Ok(r) => ("ok", items(r)),
            Err(e) => (e.code(), 0),
        };
        let pages = match &req.op {
            Op::Ocr { pages, .. } | Op::Hash { pages, .. } => count(pages.len()),
            _ => 0,
        };
        let rec = OpRecord {
            time: now(),
            caller: caller.to_owned(),
            op: req.op.name(),
            account: req.account.clone(),
            job: req.job.clone(),
            pages,
            items,
            millis: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            outcome,
            bundle: self.bundle.id.clone(),
        };
        if let Err(e) = self.record(&rec) {
            return Response::Error(e.number());
        }
        result.unwrap_or_else(|e| Response::Error(e.number()))
    }

    fn handle(&self, req: &Request, started: Instant) -> Result<Response, ModeldError> {
        if let Op::Info = req.op {
            return Ok(Response::Info(Info {
                bundle_id: self.bundle.id.clone(),
                runtime: self.runtime.clone(),
                models: self
                    .bundle
                    .installed
                    .iter()
                    .map(|e| (e.id.clone(), e.sha256))
                    .collect(),
            }));
        }
        let _slot = self.take_slot().ok_or(ModeldError::Busy)?;
        let b = &self.bundle;
        let resp = match &req.op {
            Op::Info => return Err(ModeldError::Malformed("unreachable")),
            Op::Ocr { .. } => Response::Ocr(crate::ocr::run(b, req)?),
            Op::Hash { .. } => Response::Hash(crate::hash::run(b, req)?),
            Op::Embed { .. } => Response::Embed(crate::embed::run(b, req)?),
            Op::Entities(r) => Response::Spans(crate::entities::run(b, r)?),
            Op::Personal(r) => Response::Spans(crate::personal::run(b, r)?),
        };
        if started.elapsed() > Duration::from_millis(u64::from(req.deadline_ms)) {
            return Err(ModeldError::Deadline);
        }
        Ok(resp)
    }
}

/// How many items an answer carries, for the log.
fn items(r: &Response) -> u32 {
    match r {
        Response::Info(i) => count(i.models.len()),
        Response::Ocr(pages) => count(pages.iter().map(|p| p.words.len()).sum()),
        Response::Hash(h) => count(h.len()),
        Response::Embed(v) => count(v.len()),
        Response::Spans(s) => count(s.len()),
        Response::Error(_) => 0,
    }
}

/// The server's TLS configuration: its certificate chain and key (PEM), and the CA (PEM)
/// a client certificate must chain to. TLS 1.3 only; a client certificate is mandatory.
///
/// # Errors
/// `CS-ML-0001` when any of them does not load.
pub fn server_tls(
    chain_pem: &[u8],
    key_pem: &[u8],
    client_ca_pem: &[u8],
) -> Result<Arc<ServerConfig>, ModeldError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let tls = |e: rustls::Error| ModeldError::TlsConfig(e.to_string());
    let mut roots = RootCertStore::empty();
    for ca in tls_certificates(client_ca_pem)? {
        roots.add(ca).map_err(tls)?;
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|e| ModeldError::TlsConfig(e.to_string()))?;
    let key = PrivateKeyDer::from_pem_slice(key_pem)
        .map_err(|_| ModeldError::TlsConfig("the server key does not load".into()))?;
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(tls_certificates(chain_pem)?, key)
        .map_err(tls)?;
    Ok(Arc::new(config))
}

/// A bound modeld, ready to serve.
#[derive(Debug)]
pub struct Modeld {
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    service: Arc<ModelService>,
    open: Arc<AtomicUsize>,
}

impl Modeld {
    /// Bind `addr` (`127.0.0.1:0` picks a port).
    ///
    /// # Errors
    /// `CS-ML-0008` when the address cannot be bound.
    pub fn bind(
        addr: &str,
        tls: Arc<ServerConfig>,
        service: ModelService,
    ) -> Result<Self, ModeldError> {
        let listener = TcpListener::bind(addr)
            .map_err(|e| ModeldError::Transport(format!("bind: {}", e.kind())))?;
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
    /// `CS-ML-0008` if the socket cannot say.
    pub fn local_addr(&self) -> Result<SocketAddr, ModeldError> {
        self.listener
            .local_addr()
            .map_err(|e| ModeldError::Transport(e.kind().to_string()))
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
                    eprintln!("modeld: connection ended: {}", e.code());
                }
                open.fetch_sub(1, Ordering::SeqCst);
            });
        }
    }
}

fn connection(
    stream: TcpStream,
    tls: Arc<ServerConfig>,
    service: &ModelService,
    timeout: Duration,
) -> Result<(), ModeldError> {
    let io = |e: std::io::Error| ModeldError::Transport(e.kind().to_string());
    stream.set_read_timeout(Some(timeout)).map_err(io)?;
    stream.set_write_timeout(Some(timeout)).map_err(io)?;
    let conn = ServerConnection::new(tls).map_err(|e| ModeldError::TlsConfig(e.to_string()))?;
    let mut s = StreamOwned::new(conn, stream);
    while s.conn.is_handshaking() {
        s.conn.complete_io(&mut s.sock).map_err(io)?;
    }
    // The verifier required a certificate chaining to the client CA; the allow list
    // decides whether this one is answered.
    let caller = s
        .conn
        .peer_certificates()
        .and_then(|c| c.first())
        .map(|c| fingerprint(c.as_ref()))
        .ok_or(ModeldError::NotAuthorized)?;
    let admitted = service.admit(&caller);
    while let Some(body) = read_frame(&mut s)? {
        // A caller off the allow list gets its refusal as the answer to its first
        // request (read first, so the refusal is not lost to a reset), and nothing else.
        if let Err(e) = &admitted {
            write_frame(&mut s, &Response::Error(e.number()).encode()?)?;
            break;
        }
        let response = match Request::decode(&body) {
            Ok(req) => service.answer(&caller, &req),
            Err(e) => Response::Error(e.number()),
        };
        write_frame(&mut s, &response.encode()?)?;
    }
    s.conn.send_close_notify();
    let _ = s.conn.complete_io(&mut s.sock);
    admitted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_are_bounded_by_memory_as_well_as_cores() {
        const GIB: u64 = 1 << 30;
        // 32 cores, 4 GiB, 1.5 GiB of models, 0.5 GiB a slot: memory allows 5, not 16.
        assert_eq!(default_slots(32, 4 * GIB, 3 * GIB / 2, GIB / 2), 5);
        // Few cores: the CPU bound wins.
        assert_eq!(default_slots(4, 64 * GIB, GIB, GIB / 2), 2);
        // Never zero, even when the models alone fill the limit or the peak is unknown.
        assert_eq!(default_slots(32, GIB, 2 * GIB, GIB / 2), 1);
        assert_eq!(default_slots(1, 4 * GIB, GIB, 0), 1);
    }
}
