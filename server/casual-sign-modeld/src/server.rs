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
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
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
use crate::gliner::SpanModels;
use crate::manifest::Bundle;
use crate::ocr::OcrEngine;
use crate::oplog::{OpLog, OpRecord, hex};
use crate::raster::{Document, RasterLimits};
use crate::wire::{
    Info, OcrPage, Op, Request, Response, read_frame, read_frame_length, write_frame,
};

/// The largest read made for a caller not yet admitted: its frame is discarded through a
/// buffer this size, never held (review D2).
const PRE_ADMISSION_BUFFER: usize = 1024;

/// How much of a refused caller's first frame is read and discarded, so its refusal is not
/// lost to a reset from unread data. More is left unread.
const PRE_ADMISSION_DRAIN: usize = 64 << 10;

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

/// The container memory limit assumed when neither `OPENSEAL_MODELD_MEMORY_LIMIT` nor the
/// cgroup gives one (docs/33 §4, provisional).
pub const DEFAULT_MEMORY_LIMIT: u64 = 4 << 30;

/// One slot's peak memory: a raster child's cap plus ONNX Runtime's working memory
/// (docs/33 §3.3, provisional 512 MiB until measured in `ML-09`).
pub const PER_SLOT_PEAK: u64 = 512 << 20;

/// How many slots fit (ADR-029 review defect 11, docs/33 §3.3):
/// `min(max(1, cores / 2), (memory_limit - model_rss) / per_slot_peak)`. Zero means the
/// models leave no room for one slot, and modeld must not start. A `per_slot_peak` of
/// zero puts no memory bound on the count.
#[must_use]
pub fn default_slots(cores: usize, memory_limit: u64, model_rss: u64, per_slot_peak: u64) -> usize {
    let by_cpu = (cores / 2).max(1);
    let by_memory = memory_limit
        .saturating_sub(model_rss)
        .checked_div(per_slot_peak)
        .map_or(usize::MAX, |n| usize::try_from(n).unwrap_or(usize::MAX));
    by_cpu.min(by_memory)
}

/// Parse a memory size: bytes, or a whole number followed by `KiB`, `MiB` or `GiB`.
fn parse_bytes(text: &str) -> Option<u64> {
    let t = text.trim();
    let (digits, shift) = [("GiB", 30u32), ("MiB", 20), ("KiB", 10)]
        .iter()
        .find_map(|(unit, shift)| t.strip_suffix(unit).map(|d| (d.trim(), *shift)))
        .unwrap_or((t, 0));
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits
        .parse::<u64>()
        .ok()?
        .checked_mul(1u64.checked_shl(shift)?)
}

/// The settings that decide the slot count, as the daemon reads them.
#[derive(Debug, Clone, Copy, Default)]
pub struct SlotSettings<'a> {
    /// Cores available to the process.
    pub cores: usize,
    /// `OPENSEAL_MODELD_SLOTS`, if set.
    pub slots: Option<&'a str>,
    /// `OPENSEAL_MODELD_MEMORY_LIMIT`, if set: bytes, or a number with `KiB`, `MiB`, `GiB`.
    pub memory_limit: Option<&'a str>,
    /// The cgroup v2 `memory.max` of the container, if readable (`max` means none).
    pub cgroup_memory_max: Option<&'a str>,
    /// modeld's resident memory once the models are loaded, in bytes.
    pub model_rss: u64,
}

/// The slot count the daemon runs with (docs/33 §3.3): [`default_slots`] over the memory
/// limit (the operator's setting, else the cgroup's, else [`DEFAULT_MEMORY_LIMIT`]) and
/// [`PER_SLOT_PEAK`]; an operator's `OPENSEAL_MODELD_SLOTS` may lower it, never raise it.
///
/// # Errors
/// `CS-ML-0001` naming `OPENSEAL_MODELD_MEMORY_LIMIT` when the limit is invalid or leaves
/// no slot, or `OPENSEAL_MODELD_SLOTS` when that is invalid, zero or above the bound.
pub fn configured_slots(s: &SlotSettings<'_>) -> Result<usize, ModeldError> {
    const MEMORY: &str = "OPENSEAL_MODELD_MEMORY_LIMIT";
    let limit = match s.memory_limit {
        Some(text) => parse_bytes(text).ok_or(ModeldError::Setting(MEMORY))?,
        // An unreadable or unlimited cgroup falls back to the provisional default.
        None => s
            .cgroup_memory_max
            .and_then(parse_bytes)
            .unwrap_or(DEFAULT_MEMORY_LIMIT),
    };
    let bound = default_slots(s.cores, limit, s.model_rss, PER_SLOT_PEAK);
    if bound == 0 {
        return Err(ModeldError::Setting(MEMORY));
    }
    match s.slots {
        Some(n) => n
            .trim()
            .parse::<usize>()
            .ok()
            .filter(|n| (1..=bound).contains(n))
            .ok_or(ModeldError::Setting("OPENSEAL_MODELD_SLOTS")),
        None => Ok(bound),
    }
}

/// The resident memory a Linux `/proc/self/status` reports (`VmRSS:  1234 kB`), in bytes.
#[must_use]
pub fn resident_bytes(status: &str) -> Option<u64> {
    let line = status.lines().find_map(|l| l.strip_prefix("VmRSS:"))?;
    let kib = line.trim().strip_suffix("kB")?.trim();
    kib.parse::<u64>().ok()?.checked_mul(1024)
}

/// A slot held while an operation runs; released on drop.
struct Slot<'a>(&'a AtomicUsize);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// What one connection holds: at most one open document (docs/33 §3.1, §4). Dropping it
/// ends the document's raster child; nothing outlives the connection.
#[derive(Debug, Default)]
pub struct ConnectionState {
    open: Option<(u32, Document)>,
    next: u32,
}

/// The bundle, the allow list, the slots and the log: everything that decides an answer,
/// apart from TLS.
pub struct ModelService {
    bundle: Bundle,
    runtime: String,
    spans: SpanModels,
    allow: AllowList,
    log: Mutex<OpLog>,
    busy: AtomicUsize,
    limits: ModeldLimits,
    raster: Option<(PathBuf, RasterLimits)>,
    ocr: Option<OcrEngine>,
    security: casual_sign_seclog::SecurityLog,
}

impl core::fmt::Debug for ModelService {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ModelService")
            .field("bundle", &self.bundle.id)
            .field("models", &self.bundle.installed.len())
            .field("allowed", &self.allow.len())
            .field("limits", &self.limits)
            .field("raster", &self.raster.is_some())
            .field("ocr", &self.ocr)
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
            spans: SpanModels::default(),
            allow,
            log: Mutex::new(log),
            busy: AtomicUsize::new(0),
            limits,
            raster: None,
            ocr: None,
            security: casual_sign_seclog::SecurityLog::from_env(
                casual_sign_seclog::Service::Modeld,
            ),
        }
    }

    /// Write security events (`ASVS-08`: refused callers) to `log` rather than standard
    /// error.
    #[must_use]
    pub fn with_security_log(mut self, log: casual_sign_seclog::SecurityLog) -> Self {
        self.security = log;
        self
    }

    /// `transport.caller_refused` for `caller` (a certificate fingerprint, or empty when
    /// the handshake failed before one was known).
    fn caller_refused(&self, caller: &str, code: &'static str, reason: &'static str) {
        use casual_sign_seclog::{Kind, Label, Outcome, Principal, SecurityEvent, Value};
        let mut ev = SecurityEvent::new(Kind::CallerRefused, Outcome::Failure)
            .code(code)
            .with("reason", Value::Word(reason));
        if let Some(l) = Label::new(caller) {
            ev = ev.principal(Principal::Caller(l));
        }
        self.security.emit(&ev);
    }

    /// Replace the limits (the slot count is set once the models are loaded).
    #[must_use]
    pub fn with_limits(mut self, limits: ModeldLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Rasterise in child processes started from `exe` (the modeld binary, which runs as
    /// a raster child given [`crate::raster::CHILD_ARG`]) under `limits`. Without this,
    /// DOC_OPEN answers `CS-ML-0010`.
    #[must_use]
    pub fn with_raster(mut self, exe: &Path, limits: RasterLimits) -> Self {
        self.raster = Some((exe.to_owned(), limits));
        self
    }

    /// Load the OCR models the bundle holds (none: OCR answers `CS-ML-0010`). INFO then
    /// reports the ONNX Runtime version.
    ///
    /// # Errors
    /// `CS-ML-0002` or `CS-ML-0013` when the installed models do not load.
    pub fn with_ocr(mut self) -> Result<Self, ModeldError> {
        self.ocr = OcrEngine::load(&self.bundle)?;
        if let Some(engine) = &self.ocr {
            engine.runtime().clone_into(&mut self.runtime);
        }
        Ok(self)
    }

    /// The service answering ENTITIES and PERSONAL with `models` (loaded from this
    /// bundle by [`SpanModels::load`] before modeld measures its resident memory). INFO
    /// then reports the ONNX Runtime version.
    #[must_use]
    pub fn with_span_models(mut self, models: SpanModels) -> Self {
        if models.has_entities() || models.has_personal() {
            self.runtime = crate::gliner::runtime_version();
        }
        self.spans = models;
        self
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
        self.caller_refused(caller, err.code(), "not_allowed");
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

    /// Answer one request from an admitted `caller` on a connection holding `conn`,
    /// recording it. A request whose record cannot be written is answered with the log's
    /// error. An OCR page that failed is recorded with its page's code.
    pub fn answer(&self, caller: &str, req: &Request, conn: &mut ConnectionState) -> Response {
        let started = Instant::now();
        let result = self.handle(req, started, conn);
        let (outcome, items) = match &result {
            Ok(Response::Ocr(p)) if p.status != 0 => (ModeldError::from_number(p.status).code(), 0),
            Ok(r) => ("ok", items(r)),
            Err(e) => (e.code(), 0),
        };
        let pages = match &req.op {
            Op::Hash { pages, .. } => count(pages.len()),
            Op::Ocr { .. } => 1,
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

    fn handle(
        &self,
        req: &Request,
        started: Instant,
        conn: &mut ConnectionState,
    ) -> Result<Response, ModeldError> {
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
        if let Op::DocClose { doc } = req.op {
            return match conn.open.take() {
                Some((handle, d)) if handle == doc => {
                    drop(d);
                    Ok(Response::Closed)
                }
                other => {
                    conn.open = other;
                    Err(ModeldError::Malformed("unknown document handle"))
                }
            };
        }
        let _slot = self.take_slot().ok_or(ModeldError::Busy)?;
        let b = &self.bundle;
        let deadline = started
            .checked_add(Duration::from_millis(u64::from(req.deadline_ms)))
            .unwrap_or(started);
        let resp = match &req.op {
            Op::Info | Op::DocClose { .. } => return Err(ModeldError::Malformed("unreachable")),
            Op::DocOpen { pdf } => {
                let (exe, limits) = self.raster.as_ref().ok_or(ModeldError::NotInstalled)?;
                if conn.open.is_some() {
                    return Err(ModeldError::Malformed(
                        "a document is already open on this connection",
                    ));
                }
                let doc = Document::open(exe, pdf.clone(), *limits)?;
                conn.next = conn.next.wrapping_add(1).max(1);
                let pages = doc.pages();
                conn.open = Some((conn.next, doc));
                Response::Opened {
                    doc: conn.next,
                    pages,
                }
            }
            Op::Ocr {
                doc,
                page,
                dpi,
                scripts,
            } => {
                let open = match conn.open.as_mut() {
                    Some((handle, d)) if handle == doc => d,
                    _ => return Err(ModeldError::Malformed("unknown document handle")),
                };
                let engine = self.ocr.as_ref().ok_or(ModeldError::NotInstalled)?;
                Response::Ocr(read_page(engine, open, *page, *dpi, scripts)?)
            }
            Op::Hash { .. } => Response::Hash(crate::hash::run(b, req)?),
            Op::Embed { .. } => Response::Embed(crate::embed::run(b, req)?),
            Op::Entities(r) => Response::Spans(crate::entities::run(&self.spans, r, deadline)?),
            Op::Personal(r) => Response::Spans(crate::personal::run(&self.spans, r, deadline)?),
        };
        if started.elapsed() > Duration::from_millis(u64::from(req.deadline_ms)) {
            return Err(ModeldError::Deadline);
        }
        Ok(resp)
    }
}

/// Rasterise and read one page. A page that cannot be rasterised (over a cap, damaged,
/// over its time, or its child died) is answered with that page's code, not as an error:
/// the document stays open for its other pages.
fn read_page(
    engine: &OcrEngine,
    doc: &mut Document,
    page: u16,
    dpi: u16,
    scripts: &[String],
) -> Result<OcrPage, ModeldError> {
    let failed = |e: &ModeldError| OcrPage {
        page,
        status: e.number(),
        width: 0,
        height: 0,
        dpi: 0,
        rotate: 0,
        crop: [0.0; 4],
        words: Vec::new(),
        lines: Vec::new(),
        rules: Vec::new(),
        boxes: Vec::new(),
    };
    let raster = match doc.render(page, dpi) {
        Ok(r) => r,
        Err(
            e @ (ModeldError::OverBound(_) | ModeldError::Raster(_) | ModeldError::RasterChild),
        ) => {
            return Ok(failed(&e));
        }
        Err(e) => return Err(e),
    };
    let reading = engine.read(&raster, scripts)?;
    let found = crate::rules::find(&raster);
    Ok(OcrPage {
        page,
        status: 0,
        width: raster.width,
        height: raster.height,
        dpi: raster.dpi,
        rotate: raster.rotate,
        crop: raster.crop,
        words: reading.words,
        lines: reading.lines,
        rules: found.rules,
        boxes: found.boxes,
    })
}

/// How many items an answer carries, for the log.
fn items(r: &Response) -> u32 {
    match r {
        Response::Info(i) => count(i.models.len()),
        Response::Opened { pages, .. } => *pages,
        Response::Closed => 0,
        Response::Ocr(p) => count(p.words.len()),
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
                    // Codes only: no request content.
                    let mut m = serde_json::Map::new();
                    m.insert("code".into(), e.code().into());
                    casual_sign_seclog::write(
                        casual_sign_seclog::Service::Modeld,
                        casual_sign_seclog::Level::Info,
                        "connection_ended",
                        m,
                    );
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
        if let Err(e) = s.conn.complete_io(&mut s.sock) {
            // No certificate chaining to the client CA, or no TLS 1.3 (ASVS-08).
            let code = ModeldError::Transport(String::new()).code();
            service.caller_refused("", code, "handshake");
            return Err(io(e));
        }
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
    if let Err(e) = &admitted {
        refuse(&mut s, e)?;
        s.conn.send_close_notify();
        let _ = s.conn.complete_io(&mut s.sock);
        return admitted;
    }
    let mut state = ConnectionState::default();
    while let Some(body) = read_frame(&mut s)? {
        let response = match Request::decode(&body) {
            Ok(req) => service.answer(&caller, &req, &mut state),
            Err(e) => Response::Error(e.number()),
        };
        write_frame(&mut s, &response.encode()?)?;
    }
    s.conn.send_close_notify();
    let _ = s.conn.complete_io(&mut s.sock);
    admitted
}

/// Answer a caller off the allow list with its refusal, as the answer to its first
/// request, and nothing else. Its frame is never held: the length prefix is read, then at
/// most [`PRE_ADMISSION_DRAIN`] bytes of the body are discarded through a fixed buffer
/// (so the refusal is not lost to a reset from unread data), and the rest is left unread.
fn refuse(s: &mut (impl Read + Write), err: &ModeldError) -> Result<(), ModeldError> {
    let Some(n) = read_frame_length(s)? else {
        return Ok(());
    };
    let mut left = n.min(PRE_ADMISSION_DRAIN);
    let mut sink = [0u8; PRE_ADMISSION_BUFFER];
    while left > 0 {
        let buf = sink
            .get_mut(..left.min(PRE_ADMISSION_BUFFER))
            .unwrap_or_default();
        match s.read(buf) {
            Ok(0) => break,
            Ok(got) => left = left.saturating_sub(got),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(ModeldError::Transport(e.kind().to_string())),
        }
    }
    write_frame(s, &Response::Error(err.number()).encode()?)
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report.
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    /// A stream that announces a frame of `MAX_FRAME` bytes and then supplies zeros,
    /// remembering the largest read it was asked to fill and what was written to it.
    struct Hostile {
        header: [u8; 4],
        sent: usize,
        largest_read: usize,
        written: Vec<u8>,
    }

    impl Read for Hostile {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.largest_read = self.largest_read.max(buf.len());
            let n = if self.sent < 4 {
                let rest = &self.header[self.sent..];
                let n = rest.len().min(buf.len());
                buf[..n].copy_from_slice(&rest[..n]);
                n
            } else {
                buf.fill(0);
                buf.len()
            };
            self.sent += n;
            Ok(n)
        }
    }

    impl Write for Hostile {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Review D2: a caller that chains to the client CA but is not on the allow list
    /// must not make modeld allocate a frame-sized buffer before it is refused. With 64
    /// connections at 64 MiB each that was the container's whole memory limit.
    #[test]
    fn a_refused_caller_cannot_make_modeld_allocate_a_large_buffer() {
        let mut s = Hostile {
            header: u32::try_from(crate::wire::MAX_FRAME).unwrap().to_be_bytes(),
            sent: 0,
            largest_read: 0,
            written: Vec::new(),
        };
        refuse(&mut s, &ModeldError::NotAuthorized).unwrap();
        assert!(
            s.largest_read <= PRE_ADMISSION_BUFFER,
            "asked to fill {} bytes before admission",
            s.largest_read
        );
        assert!(s.sent <= 4 + PRE_ADMISSION_DRAIN, "read {} bytes", s.sent);
        let body = read_frame(&mut s.written.as_slice()).unwrap().unwrap();
        assert_eq!(
            body,
            Response::Error(ModeldError::NotAuthorized.number())
                .encode()
                .unwrap()
        );
    }

    /// Review D1: the daemon's slot count is bounded by its memory limit, not only by
    /// cores; an operator value above the memory bound, or a bound below one slot, stops
    /// modeld from starting (docs/33 §3.3).
    #[test]
    fn the_daemon_slot_count_is_bounded_by_its_memory_limit() {
        const GIB: u64 = 1 << 30;
        let base = SlotSettings {
            cores: 32,
            model_rss: GIB / 2,
            ..SlotSettings::default()
        };
        // No setting and no cgroup: the 4 GiB default limit, (4 - 0.5) GiB / 512 MiB = 7.
        assert_eq!(configured_slots(&base).unwrap(), 7);
        // The operator's limit wins over the cgroup's.
        let set = SlotSettings {
            memory_limit: Some("2GiB"),
            cgroup_memory_max: Some("68719476736\n"),
            ..base
        };
        assert_eq!(configured_slots(&set).unwrap(), 3);
        // The cgroup's limit is used when the operator sets none; `max` means none.
        let cgroup = SlotSettings {
            cgroup_memory_max: Some("1610612736\n"),
            ..base
        };
        assert_eq!(configured_slots(&cgroup).unwrap(), 2);
        let unlimited = SlotSettings {
            cgroup_memory_max: Some("max\n"),
            ..base
        };
        assert_eq!(configured_slots(&unlimited).unwrap(), 7);
        // An operator value at or below the bound is kept; above it is refused.
        let low = SlotSettings {
            slots: Some("3"),
            memory_limit: Some("2GiB"),
            ..base
        };
        assert_eq!(configured_slots(&low).unwrap(), 3);
        let high = SlotSettings {
            slots: Some("4"),
            ..low
        };
        assert_eq!(
            configured_slots(&high),
            Err(ModeldError::Setting("OPENSEAL_MODELD_SLOTS"))
        );
        // Models filling the limit leave no slot: modeld does not start.
        let full = SlotSettings {
            memory_limit: Some("512MiB"),
            ..base
        };
        assert_eq!(
            configured_slots(&full),
            Err(ModeldError::Setting("OPENSEAL_MODELD_MEMORY_LIMIT"))
        );
        // Garbage is refused, named, never echoed.
        for bad in ["", "lots", "-1", "4TB", "99999999999999999999"] {
            let s = SlotSettings {
                memory_limit: Some(bad),
                ..base
            };
            assert_eq!(
                configured_slots(&s),
                Err(ModeldError::Setting("OPENSEAL_MODELD_MEMORY_LIMIT")),
                "{bad}"
            );
        }
        for bad in ["0", "x", ""] {
            let s = SlotSettings {
                slots: Some(bad),
                ..base
            };
            assert_eq!(
                configured_slots(&s),
                Err(ModeldError::Setting("OPENSEAL_MODELD_SLOTS")),
                "{bad}"
            );
        }
    }

    #[test]
    fn resident_memory_is_read_from_proc_status() {
        let status = "Name:\tmodeld\nVmPeak:\t  9000 kB\nVmRSS:\t   2048 kB\nThreads:\t4\n";
        assert_eq!(resident_bytes(status), Some(2048 * 1024));
        assert_eq!(resident_bytes("Name:\tmodeld\n"), None);
        assert_eq!(resident_bytes("VmRSS:\tlots kB\n"), None);
    }

    #[test]
    fn slots_are_bounded_by_memory_as_well_as_cores() {
        const GIB: u64 = 1 << 30;
        // 32 cores, 4 GiB, 1.5 GiB of models, 0.5 GiB a slot: memory allows 5, not 16.
        assert_eq!(default_slots(32, 4 * GIB, 3 * GIB / 2, GIB / 2), 5);
        // Few cores: the CPU bound wins.
        assert_eq!(default_slots(4, 64 * GIB, GIB, GIB / 2), 2);
        // Zero when the models alone fill the limit: modeld refuses to start on that.
        assert_eq!(default_slots(32, GIB, 2 * GIB, GIB / 2), 0);
        // One core still gets one slot; an unknown peak puts no memory bound.
        assert_eq!(default_slots(1, 4 * GIB, GIB, GIB / 2), 1);
        assert_eq!(default_slots(8, 4 * GIB, GIB, 0), 4);
    }
}
