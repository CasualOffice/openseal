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
pub mod jobs;
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

/// One log line on standard error: `openseal-worker LEVEL event key=value ...`. Callers
/// pass ids, kinds, counts and codes only.
pub fn log(level: &str, event: &str, fields: &[(&str, String)]) {
    let mut line = format!("openseal-worker {level} {event}");
    for (k, v) in fields {
        line.push(' ');
        line.push_str(k);
        line.push('=');
        line.push_str(v);
    }
    eprintln!("{line}");
}
