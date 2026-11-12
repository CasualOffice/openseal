//! The OpenSeal platform console's server (CON-02, CON-03, CON-04 first part, CON-05
//! first part; ADR-028, docs/23 §5).
//!
//! A separate binary on a private listener with its own operator identity: operators are
//! not tenant users; they sign in with a password (Argon2id) and a mandatory TOTP second
//! factor, enrol themselves through a one-time link, and hold sessions of at most eight
//! hours (30 minutes idle) in a `__Host-` cookie with a CSRF token. Every operator action
//! is appended to the hash-chained operator log in the action's own transaction.
//!
//! The console reads tenant metadata only (ids, names, statuses, labels, counts) through
//! the `platform` schema's definer functions, as the `openseal_console` database role,
//! which has no grant on any `public` table. It has no blob store, no keyd signing
//! identity and no tenant repository: it depends on `casual-sign-platform-store`, never
//! on `casual-sign-store`, `-host` or `-server` (docs/23 §5.1, §5.2).

pub mod api;
pub mod auth;
pub mod crypto;
pub mod error;
pub mod health;
pub mod net;
pub mod state;
pub mod totp;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, patch, post};

pub use error::ConsoleError;
pub use state::{AppState, Clock, Config, RateLimits, SystemClock, check_listener};

/// The console API's prefix.
pub const PREFIX: &str = "/console/v1";

/// Every route, as `(method, path, roles)` with the path as the OpenAPI document writes it
/// and `roles` its `x-roles`: `public`, `pending`, `any`, `operators` or `owners` (the
/// [`auth::Need`] its handler takes). The contract tests check this list against
/// `api/console-openapi.yaml` and against the router.
pub const ROUTES: &[(&str, &str, &str)] = &[
    ("GET", "/livez", "public"),
    ("GET", "/readyz", "public"),
    ("POST", "/console/v1/auth/login", "public"),
    ("POST", "/console/v1/auth/totp", "pending"),
    ("POST", "/console/v1/auth/logout", "pending"),
    ("POST", "/console/v1/auth/enrolment/begin", "public"),
    ("POST", "/console/v1/auth/enrolment/finish", "public"),
    ("GET", "/console/v1/me", "any"),
    ("GET", "/console/v1/operators", "owners"),
    ("POST", "/console/v1/operators", "owners"),
    ("POST", "/console/v1/operators/{id}/disable", "owners"),
    ("GET", "/console/v1/operator-log", "operators"),
    ("GET", "/console/v1/operator-log/verify", "operators"),
    ("GET", "/console/v1/organizations", "any"),
    ("GET", "/console/v1/organizations/{id}", "any"),
    ("PATCH", "/console/v1/organizations/{id}", "operators"),
    ("PATCH", "/console/v1/workspaces/{id}", "operators"),
    ("GET", "/console/v1/approvals", "operators"),
    ("POST", "/console/v1/approvals", "operators"),
    ("POST", "/console/v1/approvals/{id}/grant", "operators"),
    (
        "POST",
        "/console/v1/organizations/{id}/suspend",
        "operators",
    ),
    ("POST", "/console/v1/organizations/{id}/resume", "operators"),
    ("GET", "/console/v1/health", "any"),
    ("GET", "/console/v1/dead-letters", "any"),
    ("GET", "/console/v1/alerts", "any"),
];

/// The console's router.
pub fn app(state: AppState) -> Router {
    let max_body = state.config().max_body_bytes;
    Router::new()
        .route("/livez", get(api::livez))
        .route("/readyz", get(api::readyz))
        .route("/console/v1/auth/login", post(api::login))
        .route("/console/v1/auth/totp", post(api::totp_step))
        .route("/console/v1/auth/logout", post(api::logout))
        .route("/console/v1/auth/enrolment/begin", post(api::enrol_begin))
        .route("/console/v1/auth/enrolment/finish", post(api::enrol_finish))
        .route("/console/v1/me", get(api::me))
        .route(
            "/console/v1/operators",
            get(api::operators).post(api::create_operator),
        )
        .route(
            "/console/v1/operators/{id}/disable",
            post(api::disable_operator),
        )
        .route("/console/v1/operator-log", get(api::operator_log))
        .route("/console/v1/operator-log/verify", get(api::verify_log))
        .route("/console/v1/organizations", get(api::organizations))
        .route(
            "/console/v1/organizations/{id}",
            get(api::organization).patch(api::patch_organization),
        )
        .route("/console/v1/workspaces/{id}", patch(api::patch_workspace))
        .route(
            "/console/v1/approvals",
            get(api::approvals).post(api::request_approval),
        )
        .route(
            "/console/v1/approvals/{id}/grant",
            post(api::grant_approval),
        )
        .route(
            "/console/v1/organizations/{id}/suspend",
            post(api::suspend_organization),
        )
        .route(
            "/console/v1/organizations/{id}/resume",
            post(api::resume_organization),
        )
        .route("/console/v1/health", get(api::health))
        .route("/console/v1/dead-letters", get(api::dead_letters))
        .route("/console/v1/alerts", get(api::alerts))
        .fallback(api::fallback)
        .layer(DefaultBodyLimit::max(max_body))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::context,
        ))
        .with_state(state)
}
