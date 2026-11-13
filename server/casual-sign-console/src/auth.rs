//! Who is calling: an operator session cookie with its CSRF token, a second factor, and
//! a role the route names (docs/23 §5.1). Deny by default: a handler gets an operator
//! only through [`Authed`], whose type parameter names the roles that may call it, so a
//! route cannot be written without choosing them.

use std::marker::PhantomData;
use std::net::IpAddr;

use axum::extract::{FromRequestParts, Request};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, header};
use axum::middleware::Next;
use axum::response::Response;
use casual_sign_platform_store::Role;
use uuid::Uuid;

use crate::crypto::{same, sha256};
use crate::error::ConsoleError;
use crate::state::AppState;

/// The session cookie: `__Host-` so it is Secure, host-only and path `/` (docs/23 §5.1).
pub const SESSION_COOKIE: &str = "__Host-os_op";
/// The header carrying the session's CSRF token on every state-changing request.
pub const CSRF_HEADER: &str = "x-csrf-token";

/// The request's id and the operator's address, set by the request middleware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ctx {
    /// A fresh id per request, echoed in `x-request-id` and the operator log.
    pub request: Uuid,
    /// The client address (through trusted proxies only).
    pub ip: Option<IpAddr>,
}

impl Ctx {
    /// The address as the operator log writes it.
    #[must_use]
    pub fn ip_text(&self) -> Option<String> {
        self.ip.map(|i| i.to_string())
    }
}

/// Request middleware: the request id and client address, and the console's response
/// headers: no caching, no framing, no sniffing, no referrer, a CSP that loads nothing
/// (unless the response set its own cache and page policy: the UI's files, crate::ui).
pub(crate) async fn context(
    axum::extract::State(state): axum::extract::State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let ip = crate::net::client_ip(
        crate::net::peer(&req),
        req.headers(),
        &state.config().trusted_proxies,
    );
    let ctx = Ctx {
        request: Uuid::now_v7(),
        ip,
    };
    req.extensions_mut().insert(ctx);
    let slot = crate::security::SecSlot::default();
    req.extensions_mut().insert(slot.clone());
    let method = req.method().clone();
    let route = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|m| m.as_str().to_owned());
    // Kept only to take the UUIDs a security event names.
    let path = req.uri().path().to_owned();
    let mut resp = next.run(req).await;
    crate::security::after(&state, ctx, &method, route.as_deref(), &path, &slot, &resp);
    let h = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&ctx.request.to_string()) {
        h.insert("x-request-id", v);
    }
    for (k, v) in [
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        ("cross-origin-resource-policy", "same-origin"),
    ] {
        h.insert(k, HeaderValue::from_static(v));
    }
    // The UI's files set their own cache policy and page policy (crate::ui); everything
    // else, the API above all, is never cached and may load nothing.
    for (k, v) in [
        ("cache-control", "no-store"),
        (
            "content-security-policy",
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        ),
    ] {
        h.entry(k).or_insert(HeaderValue::from_static(v));
    }
    resp
}

/// The value of cookie `name`, if sent once.
pub(crate) fn cookie<'h>(headers: &'h HeaderMap, name: &str) -> Option<&'h str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

/// The `Set-Cookie` value for a session token (or for clearing it, with `max_age` 0).
pub(crate) fn session_cookie(token: &str, max_age: u64) -> String {
    format!(
        "{SESSION_COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={max_age}"
    )
}

/// Which roles may call a route.
pub trait Need: Send + Sync + 'static {
    /// The roles, any one of which suffices.
    const ROLES: &'static [Role];
}

/// Any signed-in operator.
#[derive(Debug)]
pub struct AnyOperator;
impl Need for AnyOperator {
    const ROLES: &'static [Role] = &Role::ALL;
}

/// Operators who manage organizations and workspaces (and platform owners).
#[derive(Debug)]
pub struct Operators;
impl Need for Operators {
    const ROLES: &'static [Role] = &[Role::PlatformOwner, Role::Operator];
}

/// Key custodians: TSA, trust and seal-key changes (docs/23 §5.4, `CON-07`).
#[derive(Debug)]
pub struct KeyCustodians;
impl Need for KeyCustodians {
    const ROLES: &'static [Role] = &[Role::KeyCustodian];
}

/// Platform owners only (operators and roles).
#[derive(Debug)]
pub struct Owners;
impl Need for Owners {
    const ROLES: &'static [Role] = &[Role::PlatformOwner];
}

/// A signed-in operator with a second factor and a role in `N::ROLES`.
#[derive(Debug)]
pub struct Authed<N> {
    /// The operator.
    pub id: Uuid,
    /// Their roles.
    pub roles: Vec<Role>,
    /// SHA-256 of the session token: what the definer functions check.
    pub token_sha256: [u8; 32],
    /// The request.
    pub ctx: Ctx,
    _need: PhantomData<N>,
}

/// A session that has passed the password and may be waiting for its second factor.
#[derive(Debug)]
pub struct Pending {
    /// The operator.
    pub id: Uuid,
    /// SHA-256 of the session token.
    pub token_sha256: [u8; 32],
    /// The request.
    pub ctx: Ctx,
}

pub(crate) fn ctx_of(parts: &Parts) -> Ctx {
    parts.extensions.get::<Ctx>().copied().unwrap_or(Ctx {
        request: Uuid::nil(),
        ip: None,
    })
}

fn changes_state(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// The session behind the cookie, with the CSRF check on a state-changing request.
async fn session(
    parts: &Parts,
    state: &AppState,
) -> Result<(casual_sign_platform_store::Session, [u8; 32]), ConsoleError> {
    let token = cookie(&parts.headers, SESSION_COOKIE).ok_or(ConsoleError::NotAuthenticated)?;
    if token.is_empty() || token.len() > 64 {
        return Err(ConsoleError::NotAuthenticated);
    }
    let token_sha256 = sha256(token.as_bytes());
    let s = state
        .store()
        .resolve_session(&token_sha256, state.now())
        .await?
        .ok_or(ConsoleError::NotAuthenticated)?;
    // Refusals from here on name the session's operator (ASVS-08).
    if let Some(slot) = parts.extensions.get::<crate::security::SecSlot>() {
        slot.identify(casual_sign_seclog::Principal::Operator(s.operator));
    }
    if changes_state(&parts.method) {
        let sent = parts
            .headers
            .get(CSRF_HEADER)
            .and_then(|v| v.to_str().ok())
            .ok_or(ConsoleError::Csrf)?;
        if !same(&sha256(sent.as_bytes()), &s.csrf_sha256) {
            return Err(ConsoleError::Csrf);
        }
    }
    state.0.limiter.hit(
        &format!("session:{}", hex(&token_sha256)),
        state.config().rate.api_per_session,
        state.now(),
    )?;
    Ok((s, token_sha256))
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl<N: Need> FromRequestParts<AppState> for Authed<N> {
    type Rejection = ConsoleError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ConsoleError> {
        let (s, token_sha256) = session(parts, state).await?;
        if s.mfa_at.is_none() {
            return Err(ConsoleError::SecondFactor);
        }
        if !s.roles.iter().any(|r| N::ROLES.contains(r)) {
            return Err(ConsoleError::Forbidden);
        }
        Ok(Self {
            id: s.operator,
            roles: s.roles,
            token_sha256,
            ctx: ctx_of(parts),
            _need: PhantomData,
        })
    }
}

impl FromRequestParts<AppState> for Pending {
    type Rejection = ConsoleError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ConsoleError> {
        let (s, token_sha256) = session(parts, state).await?;
        Ok(Self {
            id: s.operator,
            token_sha256,
            ctx: ctx_of(parts),
        })
    }
}
