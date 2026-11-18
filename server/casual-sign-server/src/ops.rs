//! The server's ops listener (`CON-05`, docs/23 §5.5): `GET /livez` and `GET /readyz` on
//! `OPENSEAL_OPS_LISTEN`, a port of its own that is never the public one, so a proxy or
//! an orchestrator asks without going through the API's middleware, limits or logs.
//! Bodies are empty; the console's ops routes answer the same way.
//!
//! Readiness is what a proxy in front of several replicas needs (`HRD-11`): a replica told
//! to stop answers `503` here for its drain period while it still serves every request
//! that reaches it, so the proxy takes it out of rotation before it stops taking
//! connections. A replica whose database does not answer is not ready either. The object
//! store is not asked: it is shared by every replica, so its outage would take all of them
//! out of the proxy and refuse even the requests that do not need it.

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::state::AppState;

/// The ops listener's routes over `state`.
pub fn ops_app(state: AppState) -> Router {
    Router::new()
        .route("/livez", get(livez))
        .route("/readyz", get(readyz))
        .with_state(state)
}

fn uncached(status: StatusCode) -> Response {
    let mut r = status.into_response();
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

/// `GET /livez`: the process answers.
async fn livez() -> Response {
    uncached(StatusCode::NO_CONTENT)
}

/// `GET /readyz`: `204` while this replica takes new requests; `503` while it drains
/// before a stop, or while its database does not answer.
async fn readyz(State(st): State<AppState>) -> Response {
    if st.draining() {
        return uncached(StatusCode::SERVICE_UNAVAILABLE);
    }
    match st.store().ping().await {
        Ok(()) => uncached(StatusCode::NO_CONTENT),
        Err(_) => uncached(StatusCode::SERVICE_UNAVAILABLE),
    }
}
