//! `/api/v1` handlers (docs/40 §3). Every handler runs behind the route guard (`http::guard`),
//! so a [`Principal`] is in its extensions; every object is reached through the
//! principal's account only (ADR-013), and an object the principal may not see answers
//! exactly as a missing one: `404 CS-API-0002` (SEC-A04).
//!
//! Order inside a handler: find the object (404), then check preconditions (412/428),
//! then read the body (400/422). So a call naming another account's object is refused
//! before anything it sent is looked at.

pub mod admin;
pub(crate) mod bulk;
pub mod envelopes;
pub(crate) mod folders;
pub(crate) mod mfa;
pub(crate) mod ml;
pub(crate) mod org;
pub(crate) mod switch;
pub(crate) mod templates;
pub(crate) mod webhooks;

use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use casual_sign_audit::{Context as RequestContext, Personal};
use casual_sign_workflow::{EnvelopeState, Principal as WfPrincipal};
use uuid::Uuid;

use crate::apply::{Loaded, load, uid};
use crate::auth::Principal;
use crate::error::ApiError;
use crate::net::ClientIp;
use casual_sign_store::{EnvelopeId, TenantTx};

/// A path id: a UUID, or no such object.
pub(crate) fn path_id(s: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(s).map_err(|_| ApiError::not_found())
}

/// A JSON response.
pub(crate) fn json(status: StatusCode, v: &serde_json::Value) -> Response {
    let mut r = (status, serde_json::to_vec(v).unwrap_or_default()).into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    r
}

/// A JSON response with an `ETag`.
pub(crate) fn json_tagged(status: StatusCode, v: &serde_json::Value, etag: &str) -> Response {
    let mut r = json(status, v);
    if let Ok(t) = HeaderValue::from_str(etag) {
        r.headers_mut().insert(header::ETAG, t);
    }
    r
}

/// The request's context as events record it (docs/32 §1.5): the client address
/// (see [`crate::net`]), the bounded user agent, the authentication methods of the
/// credential, and a hash naming its session. Personal data: kept in the chain only.
pub(crate) fn request_context(
    headers: &HeaderMap,
    ip: ClientIp,
    auth: Vec<casual_sign_audit::AuthMethod>,
    session: Option<casual_sign_audit::Hash256>,
) -> RequestContext {
    RequestContext {
        ip: ip.0.map(|i| Personal(i.to_string())),
        user_agent: crate::net::user_agent(headers).map(Personal),
        auth,
        session,
        // Set per ceremony request when the envelope captures location (GEO-01).
        location: None,
    }
}

/// The context of a staff request.
pub(crate) fn staff_context(headers: &HeaderMap, ip: ClientIp, p: &Principal) -> RequestContext {
    let (auth, session) = p.evidence();
    request_context(headers, ip, auth, Some(session))
}

/// Whether the principal may see the envelope: its sender, an administrator, or a
/// member allowed to see every envelope.
pub(crate) fn visible(p: &Principal, s: &EnvelopeState) -> bool {
    p.admin || p.view_all || s.sender_user_id.as_str() == p.user.to_string()
}

/// The engine principal for a staff command on `s`: its sender, else an
/// administrator; anyone else is the sender they are not, which the engine refuses.
pub(crate) fn staff(p: &Principal, s: &EnvelopeState) -> Result<WfPrincipal, ApiError> {
    let me = crate::apply::eid(p.user.0)?;
    Ok(if s.sender_user_id == me || !p.admin {
        WfPrincipal::Sender { user_id: me }
    } else {
        WfPrincipal::Admin { user_id: me }
    })
}

/// The envelope at `id`, if the principal may see it; otherwise `404`.
pub(crate) async fn envelope(
    tx: &mut TenantTx,
    p: &Principal,
    id: &str,
) -> Result<Loaded, ApiError> {
    let id = EnvelopeId(path_id(id)?);
    let l = load(tx, id).await?.ok_or_else(ApiError::not_found)?;
    if !visible(p, &l.state) {
        return Err(ApiError::not_found());
    }
    Ok(l)
}

/// The UUID of an engine id, for checks against path ids.
pub(crate) fn same_id(id: &casual_sign_model::Id, path: &str) -> bool {
    uid(id)
        .ok()
        .zip(Uuid::parse_str(path).ok())
        .is_some_and(|(a, b)| a == b)
}
