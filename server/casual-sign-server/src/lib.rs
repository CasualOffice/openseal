//! OpenSeal's API server (stage 2C, docs/40): the envelope-centric `/api/v1` REST
//! surface, staff and API authentication, and the recipient ceremony, over the workflow
//! engine (`casual-sign-workflow`) and the store (`casual-sign-store`).
//!
//! - **Commands, one transaction.** Every change is a workflow command; the new state,
//!   its audit events (hash-chained) and its effects (as jobs) are written in one
//!   transaction before the answer.
//! - **Deny by default, per object.** Every route but login, the token endpoint, JWKS
//!   and the ceremony needs a principal and a scope; every object is reached through
//!   the principal's account only, and another account's object answers exactly as a
//!   missing one (`404 CS-API-0002`).
//! - **Errors** are RFC 9457 problem details with stable `CS-*` codes (docs/20).
//! - **Logs** are one JSON line each (`casual-sign-seclog`). The access log carries the
//!   request id, method, route template, status and duration only: never a path
//!   (ceremony paths hold tokens), query, address, user agent, name or document
//!   content (SEC-D01). Security events (sign-in, second factor, refusals, rate limits,
//!   administrative changes, document reads: `security`) name principals by id or by a
//!   keyed pseudonym (ASVS-08).
//!
//! The OpenAPI 3.1 document is `api/openapi.yaml`; the contract tests keep it and
//! [`routes::table`] equal.

mod anomaly;
mod apply;
mod auth;
mod call;
mod ceremony;
mod crypto;
mod dto;
mod error;
pub mod geo;
mod http;
pub mod idp;
mod mfa;
pub mod net;
mod passwords;
mod preview;
pub mod routes;
pub mod scan;
mod security;
mod state;
pub mod totp;
pub mod web;

pub mod api;

pub use anomaly::{AbnormalActivity, AlertSink, AnomalyConfig, LogAlerts};
pub use api::admin::{Bootstrapped, bootstrap, bootstrap_workspace};
pub use api::envelopes::issue_invitation_token;
pub use auth::{Credential, Principal, SCOPES, SecondFactor};
pub use crypto::JwtKeys;
pub use error::{ApiError, FieldProblem};
pub use mfa::MfaKey;
pub use routes::{Access, Route, app, table};
pub use scan::{Scanner, ScannerConfig};
pub use state::{AppState, Blobs, Clock, Config, ManualClock, RateLimits, SystemClock};

/// Replaces the default panic hook, which prints the panic's message (it may carry a
/// value from a request) to standard error, with one that logs where the panic happened
/// and the request id only (ASVS-26). The binary installs it at start-up; the answer to
/// the request is `routes`' last-resort `500` problem.
pub fn quiet_panics() {
    std::panic::set_hook(Box::new(|info| {
        let at = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_default();
        tracing::error!(
            at = %at,
            request_id = %error::request_id().unwrap_or_default(),
            "panicked"
        );
    }));
}
