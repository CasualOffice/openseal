//! The OpenSeal platform console's server (CON-02, CON-03, CON-04 first part, CON-05
//! first part, PLAN-02 plans; ADR-028, docs/23 §5, §7).
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
//! identity (only keyd's admin identity) and no tenant repository: it depends on `casual-sign-platform-store`, never
//! on `casual-sign-store`, `-host` or `-server` (docs/23 §5.1, §5.2).
//!
//! keyd is read through its admin interface ([`keys`], `CON-06`): keys, certificates,
//! the operation log and health, with an identity keyd will not let sign.
//!
//! It also serves its own web UI (`console-ui/`, embedded at compile time; [`ui`]) at `/`
//! on the same private listener (CON-17).

pub mod api;
pub mod auth;
pub mod crypto;
pub mod error;
pub mod health;
pub mod keys;
pub mod net;
pub mod plans;
pub mod state;
pub mod totp;
pub mod tsa;
pub mod ui;
pub mod url_policy;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, patch, post};
use tower_http::catch_panic::CatchPanicLayer;

pub use error::ConsoleError;
pub use state::{AppState, Clock, Config, RateLimits, SystemClock, check_listener};

/// The console API's prefix.
pub const PREFIX: &str = "/console/v1";

/// Every route, as `(method, path, roles)` with the path as the OpenAPI document writes it
/// and `roles` its `x-roles`: `public`, `pending`, `any`, `operators`, `custodians` or `owners` (the
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
    ("GET", "/console/v1/plans", "any"),
    ("POST", "/console/v1/plans", "operators"),
    ("POST", "/console/v1/plans/{id}/archive", "operators"),
    ("GET", "/console/v1/organizations/{id}/plan", "any"),
    ("POST", "/console/v1/organizations/{id}/plan", "operators"),
    (
        "POST",
        "/console/v1/organizations/{id}/plan-overrides",
        "operators",
    ),
    (
        "POST",
        "/console/v1/plan-overrides/{id}/expire",
        "operators",
    ),
    ("GET", "/console/v1/keys", "any"),
    ("GET", "/console/v1/keys/log", "operators"),
    ("GET", "/console/v1/tsa", "any"),
    ("POST", "/console/v1/tsa/changes", "custodians"),
    ("POST", "/console/v1/tsa/changes/{id}/grant", "custodians"),
    ("POST", "/console/v1/tsa/changes/{id}/apply", "custodians"),
    ("GET", "/console/v1/health", "any"),
    ("GET", "/console/v1/dead-letters", "any"),
    ("GET", "/console/v1/alerts", "any"),
];

/// The console's router.
pub fn app(state: AppState) -> Router {
    let router = Router::new()
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
        .route(
            "/console/v1/plans",
            get(plans::plans).post(plans::create_plan),
        )
        .route("/console/v1/plans/{id}/archive", post(plans::archive_plan))
        .route(
            "/console/v1/organizations/{id}/plan",
            get(plans::organization_plan).post(plans::assign_plan),
        )
        .route(
            "/console/v1/organizations/{id}/plan-overrides",
            post(plans::set_override),
        )
        .route(
            "/console/v1/plan-overrides/{id}/expire",
            post(plans::expire_override),
        )
        .route("/console/v1/keys", get(keys::keys))
        .route("/console/v1/keys/log", get(keys::keys_log))
        .route("/console/v1/tsa", get(tsa::tsa))
        .route("/console/v1/tsa/changes", post(tsa::propose))
        .route("/console/v1/tsa/changes/{id}/grant", post(tsa::grant))
        .route("/console/v1/tsa/changes/{id}/apply", post(tsa::apply))
        .route("/console/v1/health", get(api::health))
        .route("/console/v1/dead-letters", get(api::dead_letters))
        .route("/console/v1/alerts", get(api::alerts));
    finish(router, state)
}

/// Around the routes: the UI for anything unmatched, the body limit, the last-resort
/// panic answer and the request middleware.
fn finish(router: Router<AppState>, state: AppState) -> Router {
    let max_body = state.config().max_body_bytes;
    router
        .fallback(ui::fallback)
        .layer(DefaultBodyLimit::max(max_body))
        // ASVS-26: inside the request middleware, so the answer carries `x-request-id`.
        .layer(CatchPanicLayer::custom(panicked))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::context,
        ))
        .with_state(state)
}

/// The last-resort answer to a handler that panicked (ASVS-26): `500 CS-CON-0014`
/// problem details naming the step `panic`, and nothing of the panic's message.
fn panicked(_payload: Box<dyn std::any::Any + Send + 'static>) -> axum::response::Response {
    axum::response::IntoResponse::into_response(ConsoleError::Internal("panic"))
}

/// Replaces the default panic hook, which prints the panic's message (it may carry a
/// value from a request) to standard error, with one that logs where the panic happened
/// only (ASVS-26). The binary installs it at start-up; the answer to the request is the
/// router's last-resort `500 CS-CON-0014` problem.
pub fn quiet_panics() {
    std::panic::set_hook(Box::new(|info| {
        let at = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_default();
        tracing::error!(at = %at, "panicked");
    }));
}

#[cfg(test)]
// Test code: a panic is the failure report (CLAUDE.md).
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use casual_sign_platform_store::PlatformStore;
    use casual_sign_platform_store::sqlx::postgres::PgPoolOptions;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;

    async fn boom() -> &'static str {
        panic!("secret-in-panic")
    }

    /// ASVS-26: a handler that panics answers `500 CS-CON-0014` problem details with the
    /// request id in `x-request-id`, and nothing of the panic.
    #[tokio::test]
    async fn a_handler_that_panics_answers_a_problem_with_the_request_id_only() {
        // A pool that never connects: no route here reaches the database.
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://nobody:none@127.0.0.1:9/none")
            .unwrap();
        let state = AppState::new(
            PlatformStore::new(pool),
            crypto::MfaKey::new(&[1u8; 32]).unwrap(),
            Arc::new(SystemClock),
            Config::default(),
        )
        .unwrap();
        let app = finish(Router::new().route("/boom", get(boom)), state);
        let r = app
            .oneshot(Request::get("/boom").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(r.headers().contains_key("x-request-id"));
        let body = r.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("CS-CON-0014"), "{body}");
        assert!(!body.contains("secret-in-panic"), "{body}");
    }
}
