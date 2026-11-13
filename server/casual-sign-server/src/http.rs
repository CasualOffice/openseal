//! Middleware: request ids, security headers, redacted access logs, problem details for
//! the router's own refusals, and the per-route guard (authentication, scope, rate
//! limit, idempotency) every `/api/v1` route runs behind.

use std::time::Instant;

use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use casual_sign_store::repo::idempotency::Record;
use time::Duration as TimeDuration;

use crate::auth::{Principal, authenticate};
use crate::crypto::{same, sha256};
use crate::error::{ApiError, REQUEST_ID};
use crate::state::{AppState, RateDecision};

/// The strict policy every response carries: the API serves no active content, and no
/// page may frame it (SEC-A06).
const CSP: &str = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

/// Marks a response whose body reveals a secret shown once (a new API key, a client
/// secret, a session, a signing link): its idempotency record keeps no body.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SecretBearing;

/// The command id an idempotent request's engine commands derive from.
#[derive(Debug, Clone)]
pub(crate) struct CommandSeed(pub String);

/// Outermost: a request id for the request (in the `X-Request-Id` header and every
/// problem), security headers on every response, problem details for refusals the
/// router makes itself, and one access log line naming the route template, never the
/// path (ceremony paths carry tokens) or the query.
pub(crate) async fn request_context(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let id = uuid::Uuid::now_v7().to_string();
    let ip = crate::net::client_ip(
        crate::net::peer(&req),
        req.headers(),
        &state.config().trusted_proxies,
    );
    req.extensions_mut().insert(crate::net::ClientIp(ip));
    let method = req.method().clone();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unmatched".to_owned(), |m| m.as_str().to_owned());
    let started = Instant::now();
    let crash_subject = route_of_crash(&method, &route);
    let mut resp = REQUEST_ID
        .scope(id.clone(), async move {
            let resp = next.run(req).await;
            // P2-CRASH: the handler committed and answered; nothing is sent yet.
            casual_sign_host::crash::point("after_commit", &crash_subject);
            normalize(resp)
        })
        .await;
    let h = resp.headers_mut();
    // A web app page sets its own policy and permissions (row WEB-04, `web.rs`).
    for (name, value) in [
        ("content-security-policy", CSP),
        (
            "permissions-policy",
            "camera=(), microphone=(), geolocation=()",
        ),
    ] {
        if !h.contains_key(name) {
            h.insert(
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
        }
    }
    for (name, value) in [
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("x-frame-options", "DENY"),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
        (
            "strict-transport-security",
            "max-age=63072000; includeSubDomains",
        ),
    ] {
        h.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    if !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    if let Ok(v) = HeaderValue::from_str(&id) {
        h.insert(HeaderName::from_static("x-request-id"), v);
    }
    tracing::info!(
        request_id = %id,
        method = %method,
        route = %route,
        status = resp.status().as_u16(),
        ms = started.elapsed().as_millis() as u64,
        "request"
    );
    resp
}

/// The router's own refusals (no route, wrong method, body over the limit, wrong
/// media type) as problem details.
fn normalize(resp: Response) -> Response {
    // Handlers answer JSON (problems, or RFC 6749 errors from the token endpoint); the
    // router's own refusals are plain text or empty.
    let ours = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|v| v.as_bytes().starts_with(b"application/"));
    if ours || resp.status().is_success() {
        return resp;
    }
    match resp.status() {
        StatusCode::NOT_FOUND => ApiError::not_found().into_response(),
        StatusCode::METHOD_NOT_ALLOWED => ApiError::method_not_allowed().into_response(),
        StatusCode::PAYLOAD_TOO_LARGE => ApiError::too_large().into_response(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE => ApiError::unsupported_media().into_response(),
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => {
            ApiError::malformed("request").into_response()
        }
        _ => resp,
    }
}

fn rate_headers(resp: &mut Response, policy: &str, d: RateDecision) {
    let h = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&format!("\"{policy}\";q={};w=60", d.limit)) {
        h.insert(HeaderName::from_static("ratelimit-policy"), v);
    }
    if let Ok(v) = HeaderValue::from_str(&format!(
        "\"{policy}\";r={};t={}",
        d.remaining, d.reset_secs
    )) {
        h.insert(HeaderName::from_static("ratelimit"), v);
    }
}

/// Count a hit against `key`; a refusal carries `Retry-After`.
#[allow(clippy::result_large_err)] // The refusal is the response to send.
pub(crate) fn limit(
    state: &AppState,
    policy: &str,
    key: &str,
    per_minute: u32,
) -> Result<RateDecision, Response> {
    let d = state.0.limiter.hit(key, per_minute, state.now());
    if d.allowed {
        Ok(d)
    } else {
        let mut r = ApiError::rate_limited(d.reset_secs).into_response();
        rate_headers(&mut r, policy, d);
        Err(r)
    }
}

/// What the guard of one route checks.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Guard {
    /// The scope the route needs (`""`: any authenticated caller).
    pub scope: &'static str,
    /// The largest request body the route reads.
    pub max_body: usize,
    /// A session that still owes its second factor may call it (ASVS-01).
    pub signing_in: bool,
}

/// The guard of every `/api/v1` route: authenticate (401), refuse a session that owes
/// its second factor anywhere but signing in (403, ASVS-01), check the scope (403), count
/// the principal's rate (429), then, for a `POST` with `Idempotency-Key`, answer a
/// replay with the first response (docs/40 §1).
pub(crate) async fn guard(
    State((state, g)): State<(AppState, Guard)>,
    mut req: Request,
    next: Next,
) -> Response {
    let p = match authenticate(&state, req.method(), req.headers()).await {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    if let Some(owed) = p.second_factor.owed()
        && !g.signing_in
    {
        return ApiError::second_factor_required(owed).into_response();
    }
    if let Err(e) = p.require(g.scope) {
        return e.into_response();
    }
    let d = match limit(
        &state,
        "api",
        &format!("api:{}", p.key()),
        state.config().rate.api_per_minute,
    ) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let key = req
        .headers()
        .get("idempotency-key")
        .map(|v| v.to_str().map(str::to_owned));
    let mut resp = match (req.method() == Method::POST, key) {
        (true, Some(Ok(key))) => {
            if key.is_empty() || key.len() > 255 || !key.bytes().all(|b| b.is_ascii_graphic()) {
                return ApiError::invalid("/headers/Idempotency-Key").into_response();
            }
            req.extensions_mut().insert(p.clone());
            idempotent(&state, &p, &key, g, req, next).await
        }
        (true, Some(Err(_))) => {
            return ApiError::invalid("/headers/Idempotency-Key").into_response();
        }
        _ => {
            req.extensions_mut().insert(p);
            next.run(req).await
        }
    };
    rate_headers(&mut resp, "api", d);
    resp
}

async fn idempotent(
    state: &AppState,
    p: &Principal,
    key: &str,
    g: Guard,
    req: Request,
    next: Next,
) -> Response {
    match idempotent_inner(state, p, key, g, req, next).await {
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}

async fn idempotent_inner(
    state: &AppState,
    p: &Principal,
    key: &str,
    g: Guard,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let (mut parts, body) = req.into_parts();
    let bytes: Bytes = to_bytes(body, g.max_body)
        .await
        .map_err(|_| ApiError::too_large())?;
    let mut h = Vec::with_capacity(bytes.len().saturating_add(256));
    h.extend_from_slice(parts.method.as_str().as_bytes());
    h.push(0);
    h.extend_from_slice(parts.uri.path().as_bytes());
    h.push(0);
    h.extend_from_slice(&bytes);
    let request_sha256 = sha256(&h);
    let now = state.now();
    let principal = p.key();
    let mut tx = state.store().for_account(p.account).begin().await?;
    let since = now
        .checked_sub(TimeDuration::hours(24))
        .ok_or_else(|| ApiError::internal("time"))?;
    // A placeholder older than this was left by a server that died mid-request (P2-CRASH):
    // the retry takes it over and runs the request again. Its commands' ids derive from
    // the key, so whatever the dead request committed is `replayed`, not repeated.
    let abandoned = now
        .checked_sub(IN_PROGRESS_ABANDONED)
        .ok_or_else(|| ApiError::internal("time"))?;
    let mut expired_before = since;
    let first = tx.idempotency().get(&principal, key, since).await?;
    if let Some(rec) = first {
        if !same(&rec.request_sha256, &request_sha256) {
            return Err(ApiError::idempotency_mismatch());
        }
        if rec.status == 102 && rec.created_at >= abandoned {
            return Err(ApiError::idempotency_in_progress());
        }
        if rec.status == 102 {
            expired_before = abandoned;
        } else {
            return replay(rec);
        }
    }
    let placeholder = Record {
        principal: principal.clone(),
        key: key.to_owned(),
        request_sha256,
        status: 102,
        body: None,
        created_at: now,
    };
    if !tx.idempotency().put(&placeholder, expired_before).await? {
        return Err(ApiError::idempotency_in_progress());
    }
    tx.commit().await?;
    let digest = casual_sign_audit::Hash256(sha256(format!("{principal}\u{0}{key}").as_bytes()));
    let seed: String = digest.hex().chars().take(40).collect();
    let seed = format!("idem-{seed}");
    parts.extensions.insert(CommandSeed(seed));
    let route = parts
        .extensions
        .get::<MatchedPath>()
        .map_or_else(String::new, |m| m.as_str().to_owned());
    let method = parts.method.clone();
    let resp = next
        .run(Request::from_parts(parts, Body::from(bytes)))
        .await;
    // P2-CRASH: the handler committed; its answer is not yet kept for the key.
    casual_sign_host::crash::point("after_commit", &route_of_crash(&method, &route));
    let secret = resp.extensions().get::<SecretBearing>().is_some();
    let (rparts, rbody) = resp.into_parts();
    let rbytes = to_bytes(rbody, 64 * 1024 * 1024)
        .await
        .map_err(|_| ApiError::internal("response"))?;
    let status = i32::from(rparts.status.as_u16());
    let mut tx = state.store().for_account(p.account).begin().await?;
    let stored = (!secret && rparts.status.as_u16() < 500).then_some(&rbytes[..]);
    if rparts.status.is_server_error() {
        // A server error is not an answer to keep: let the client retry with the key.
        tx.idempotency()
            .put(
                &Record {
                    created_at: since
                        .checked_sub(TimeDuration::hours(1))
                        .ok_or_else(|| ApiError::internal("time"))?,
                    ..placeholder
                },
                crate::state::plus(now, TimeDuration::days(1))?,
            )
            .await?;
    } else {
        tx.idempotency()
            .finish(&principal, key, status, stored)
            .await?;
    }
    tx.commit().await?;
    Ok(Response::from_parts(rparts, Body::from(rbytes)))
}

/// How long a request may hold its key "in progress" before a retry counts it as
/// abandoned by a server that died (P2-CRASH). Far longer than any request runs.
const IN_PROGRESS_ABANDONED: TimeDuration = TimeDuration::minutes(5);

/// The first answer to a key, again.
fn replay(rec: Record) -> Result<Response, ApiError> {
    let Some(body) = rec.body else {
        return Err(ApiError::not_available(
            "the first response held a secret, shown once",
        ));
    };
    let status = u16::try_from(rec.status)
        .ok()
        .and_then(|s| StatusCode::from_u16(s).ok())
        .unwrap_or(StatusCode::OK);
    let mut r = (status, body).into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    r.headers_mut().insert(
        HeaderName::from_static("idempotency-replayed"),
        HeaderValue::from_static("true"),
    );
    Ok(r)
}

/// A route's crash-point subject, `<METHOD> <pattern>` (no token, no id).
#[cfg(feature = "crash-points")]
fn route_of_crash(method: &Method, route: &str) -> String {
    format!("{method} {route}")
}

/// Without the crash points: never read.
#[cfg(not(feature = "crash-points"))]
fn route_of_crash(_method: &Method, _route: &str) -> String {
    String::new()
}
