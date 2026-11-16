//! OpenSeal's worker (stage 2D, docs/24 §1, ADR-011, ADR-012): runs the workflow
//! engine's effects as idempotent jobs from the PostgreSQL queue and feeds their
//! results back through the engine.
//!
//! - [`apply()`]: decide a command and record the decision (state, chained audit events,
//!   relational rows, jobs) in one transaction.
//! - [`Worker`]: claim due jobs with `SKIP LOCKED`, keep leases alive with heartbeats,
//!   retry with exponential back-off and jitter, dead-letter with an operator alert.
//! - Effects: email over SMTP ([`email`]), reminders and expiry timers (`TimerDue` back
//!   through the engine), the seal job ([`seal`]: fill, flatten, certificate with the
//!   audit trail, seal at the envelope's profile through keyd's `RemoteKey`, verify the
//!   stored bytes independently, then `SealSucceeded` or `SealFailed`), webhooks
//!   ([`webhook`]: Standard Webhooks signatures, SSRF-safe delivery, delivery log),
//!   token revocation, operator alerts, purge, and payments behind [`PaymentGateway`]
//!   (a stub until slice 13).
//! - Document analysis ([`ml`], docs/33): the advisory `analyze_document` and
//!   `fingerprint_template` jobs against the model service, through the client only.
//!
//! **Idempotency.** Each effect is one job, keyed by `(envelope, effect id)`. A job's
//! external act is recorded as a job step when it happens; its result command (with an
//! id derived from the job) and its completion commit together. See [`worker`] for
//! what a crash at each point leaves.
//!
//! **Privacy.** Logs carry ids, kinds and codes only: never an address, a name, a
//! subject, a URL, a token or document content (`SEC-D01`).

pub mod apply;
pub use casual_sign_host::capture;
pub mod email;
mod error;
pub mod health;
pub mod jobs;
pub mod messenger;
pub mod ml;
pub mod seal;
pub mod tsa;
pub mod webhook;
pub mod worker;

pub use apply::{Applied, apply, apply_in, system_context};
pub use error::{Result, WorkerError};
pub use worker::{
    AlertSink, Boundary, Charge, Clock, EnvSecrets, FaultHook, JobOutcome, LogAlerts, NoPayments,
    OperatorAlert, PaymentGateway, SecretSource, SystemClock, Worker, WorkerConfig,
};

static SECURITY: std::sync::OnceLock<casual_sign_seclog::SecurityLog> = std::sync::OnceLock::new();

/// Write the worker's log lines and security events to `log` (`ASVS-08`). Unset, they go
/// to standard error. Set once, before the worker runs; a second call is ignored.
pub fn set_security_log(log: casual_sign_seclog::SecurityLog) {
    let _ = SECURITY.set(log);
}

/// The worker's security log.
pub(crate) fn security() -> &'static casual_sign_seclog::SecurityLog {
    SECURITY.get_or_init(|| {
        casual_sign_seclog::SecurityLog::from_env(casual_sign_seclog::Service::Worker)
    })
}

/// One log line, OpenSeal's JSON line (`casual-sign-seclog`, `"service":"worker"`), on
/// standard error. `level` is `DEBUG`, `INFO`, `WARN` or `ERROR`. Callers pass ids,
/// kinds, counts and codes only.
pub fn log(level: &str, event: &str, fields: &[(&str, String)]) {
    use casual_sign_seclog::Level;
    let level = match level {
        "ERROR" => Level::Error,
        "WARN" => Level::Warn,
        "DEBUG" => Level::Debug,
        _ => Level::Info,
    };
    let mut m = serde_json::Map::new();
    for (k, v) in fields {
        m.insert((*k).to_owned(), serde_json::Value::String(v.clone()));
    }
    security().info(level, event, m);
}

/// A back end (`keyd`, `tsa`) not reached or refusing: the `transport.backend_failed`
/// security event, with its code (ASVS 9.2.5).
pub(crate) fn backend_failed(
    backend: &'static str,
    code: &'static str,
    extra: &[(&'static str, casual_sign_seclog::Value)],
) {
    let mut ev = casual_sign_seclog::SecurityEvent::new(
        casual_sign_seclog::Kind::BackendFailed,
        casual_sign_seclog::Outcome::Failure,
    )
    .code(code)
    .with("backend", casual_sign_seclog::Value::Word(backend));
    for (k, v) in extra {
        ev = ev.with(k, v.clone());
    }
    security().emit(&ev);
}
