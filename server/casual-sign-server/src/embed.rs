//! Embedding (slice 9 `VS-09`, docs/40 §5; threats SEC-A06, SEC-A08).
//!
//! - **Who may frame us.** A workspace lists the origins of the pages allowed to frame
//!   its embedded views (`settings.embedding_origins`, an administrator's security
//!   setting). A view page's `frame-ancestors` is the one origin its view was created
//!   for, while that origin is still on the list, or else the list; with no list, and
//!   on every other page, `'none'`, with `X-Frame-Options: DENY` (http.rs drops that
//!   header only where the policy names an origin).
//! - **The view link.** `POST /envelopes/{id}/views/{signing|prepare|correct}` answers a
//!   link that lives five minutes and is spent once: the signing view binds to the first
//!   page that opens it (ceremony.rs; inside another site's frame the binding travels in
//!   the `X-OpenSeal-Binding` header, since that browser sends the frame no first-party
//!   cookie), and a prepare or correct link's first `POST /e/{token}/session` makes a
//!   view session that acts on that one envelope only, with the narrow set of
//!   operations its editor needs ([`reaches`]).
//! - **Where events go.** The frame origin and the return URL must be on the list when
//!   the view is created; the page posts its events to that origin only, never `*`, and
//!   the return URL gets `event` and the host's `state`.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use casual_sign_store::repo::embed_views::{EmbedTarget, NewView, ViewKind};
use casual_sign_store::{AccountId, EnvelopeId};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::api::envelopes::rfc3339;
use crate::api::{envelope as find, json as json_resp};
use crate::call::Call;
use crate::crypto::{random_secret, sha256};
use crate::dto::parse;
use crate::error::ApiError;
use crate::http::{SecretBearing, limit};
use crate::net::ClientIp;
use crate::state::AppState;

/// The workspace setting listing the origins that may frame its embedded views.
pub const SETTING: &str = "embedding_origins";
/// At most this many origins on the list.
pub const MAX_ORIGINS: usize = 20;
/// The longest origin, return URL and state (migration 0050).
const MAX_ORIGIN: usize = 255;
const MAX_URL: usize = 2048;
const MAX_STATE: usize = 1024;
/// A prepare or correct view session's bearer token starts with this.
pub(crate) const SESSION_PREFIX: &str = "osv_";
/// How long a view session lasts once its link is spent: one sitting in the editor.
const SESSION_TTL: std::time::Duration = std::time::Duration::from_secs(3600);
/// The header that carries an embedded signing view's binding in a cross-site frame.
pub(crate) const BINDING_HEADER: &str = "x-openseal-binding";

/// Whether `host` (lower case, no port, IPv6 in brackets) is a private-network host,
/// for which plain `http` is taken (owner instruction 81): a loopback, RFC 1918,
/// link-local or IPv6 unique-local address; `localhost`; a single-label name; or a
/// name under `.local`, `.internal`, `.lan`, `.localhost` or `.test`. A public host
/// needs `https`.
fn private_host(host: &str) -> bool {
    if let Some(v6) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return v6.parse::<std::net::Ipv6Addr>().is_ok_and(|a| {
            let first = a.segments()[0];
            a.is_loopback() || (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
        });
    }
    if let Ok(a) = host.parse::<std::net::Ipv4Addr>() {
        return a.is_loopback() || a.is_private() || a.is_link_local();
    }
    if host.chars().all(|c| c.is_ascii_digit() || c == '.') {
        // Digits and dots that are not an address are no host name either.
        return false;
    }
    !host.contains('.')
        || [".local", ".internal", ".lan", ".localhost", ".test"]
            .iter()
            .any(|t| host.ends_with(t))
}

/// The origin `s` names, as a browser compares it (`scheme://host[:port]`, lower case,
/// no default port), or `None` when it is not one: a path, query, fragment, user
/// name or wildcard; a scheme other than `https`, or `http` but to a public host (plain
/// `http` is for private-network and intranet hosts only); a host with characters a host
/// name has not.
#[must_use]
pub fn origin(s: &str) -> Option<String> {
    if s.is_empty() || s.len() > MAX_ORIGIN {
        return None;
    }
    let lower = s.to_ascii_lowercase();
    let (scheme, rest) = lower.split_once("://")?;
    if !matches!(scheme, "https" | "http") || rest.is_empty() {
        return None;
    }
    let (host, port) = if let Some(v6) = rest.strip_prefix('[') {
        let (inner, after) = v6.split_once(']')?;
        if inner.is_empty() || !inner.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
            return None;
        }
        let port = match after.strip_prefix(':') {
            Some(p) => p.to_owned(),
            None if after.is_empty() => String::new(),
            None => return None,
        };
        (format!("[{inner}]"), port)
    } else {
        match rest.split_once(':') {
            Some((h, p)) => (h.to_owned(), p.to_owned()),
            None => (rest.to_owned(), String::new()),
        }
    };
    let host_ok = host.starts_with('[')
        || (!host.is_empty()
            && host.len() <= 253
            && !host.starts_with('.')
            && !host.ends_with('.')
            && host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.'));
    if !host_ok {
        return None;
    }
    if !port.is_empty() {
        let n: u16 = port.parse().ok()?;
        if n == 0 || !port.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
    }
    if scheme == "http" && !private_host(&host) {
        return None;
    }
    let default = matches!((scheme, port.as_str()), ("https", "443") | ("http", "80"));
    Some(if port.is_empty() || default {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}:{port}")
    })
}

/// The origin of an absolute `http(s)` URL with no fragment, user name, whitespace or
/// control character (a return URL), as [`origin`] gives it.
#[must_use]
pub fn url_origin(url: &str) -> Option<String> {
    if url.is_empty()
        || url.len() > MAX_URL
        || url.contains('#')
        || url.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return None;
    }
    let (scheme, rest) = url.split_once("://")?;
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = rest.get(..end)?;
    if authority.contains('@') {
        return None;
    }
    origin(&format!("{scheme}://{authority}"))
}

/// The origins a workspace's settings allow to frame its views (unreadable entries are
/// skipped; the setting is checked when written).
#[must_use]
pub fn allowed(settings: &Value) -> Vec<String> {
    settings
        .get(SETTING)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .filter_map(origin)
                .collect()
        })
        .unwrap_or_default()
}

/// Check a new value of the setting: a list of at most [`MAX_ORIGINS`] distinct
/// origins, each written as [`origin`] writes it.
///
/// # Errors
///
/// `CS-API-0001` at `/settings/embedding_origins`.
pub(crate) fn check_setting(v: &Value) -> Result<(), ApiError> {
    let bad = || ApiError::invalid(&format!("/settings/{SETTING}"));
    let list = v.as_array().ok_or_else(bad)?;
    if list.len() > MAX_ORIGINS {
        return Err(bad());
    }
    let mut seen = std::collections::BTreeSet::new();
    for o in list {
        let s = o.as_str().ok_or_else(bad)?;
        if origin(s).as_deref() != Some(s) || !seen.insert(s) {
            return Err(bad());
        }
    }
    Ok(())
}

/// The `frame-ancestors` sources for a view created for `frame_origin` in a workspace
/// allowing `allowed`: that origin while it is still allowed, the list when the view
/// named none, else `'none'`.
#[must_use]
pub fn ancestors(frame_origin: Option<&str>, allowed: &[String]) -> String {
    let list = frame_origins(frame_origin, allowed);
    if list.is_empty() {
        "'none'".to_owned()
    } else {
        list.join(" ")
    }
}

/// The web app's page policy with `frame-ancestors` set to `sources`.
#[must_use]
pub fn page_csp(sources: &str) -> String {
    crate::web::PAGE_CSP.replace(
        "frame-ancestors 'none'",
        &format!("frame-ancestors {sources}"),
    )
}

/// What a view request may carry besides the recipient.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetIn {
    #[serde(default)]
    pub frame_origin: Option<String>,
    #[serde(default)]
    pub return_url: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
}

/// Check a view request's host page, return URL and state against the workspace's list.
///
/// # Errors
///
/// `CS-EMB-0001` (422) at `/frame_origin` or `/return_url` when not on the list or not
/// an origin or URL; `CS-API-0001` at `/state` when too long or holding a control
/// character.
pub(crate) fn target(t: TargetIn, allowed: &[String]) -> Result<EmbedTarget, ApiError> {
    let frame_origin = match t.frame_origin {
        Some(o) => {
            let norm = origin(&o).ok_or_else(|| ApiError::origin_not_allowed("/frame_origin"))?;
            if !allowed.contains(&norm) {
                return Err(ApiError::origin_not_allowed("/frame_origin"));
            }
            Some(norm)
        }
        None => None,
    };
    let return_url = match t.return_url {
        Some(u) => {
            let o = url_origin(&u).ok_or_else(|| ApiError::origin_not_allowed("/return_url"))?;
            if !allowed.contains(&o) {
                return Err(ApiError::origin_not_allowed("/return_url"));
            }
            Some(u)
        }
        None => None,
    };
    if let Some(s) = &t.state
        && (s.chars().count() > MAX_STATE || s.chars().any(char::is_control))
    {
        return Err(ApiError::invalid("/state"));
    }
    Ok(EmbedTarget {
        frame_origin,
        return_url,
        return_state: t.state,
    })
}

/// The origins a view's page posts its events to: the ones [`ancestors`] lets frame it.
#[must_use]
pub fn frame_origins(frame_origin: Option<&str>, allowed: &[String]) -> Vec<String> {
    match frame_origin {
        Some(o) => allowed
            .iter()
            .filter(|a| a.as_str() == o)
            .cloned()
            .collect(),
        None => allowed.to_vec(),
    }
}

/// The `embed` member a view answers its page: where its events go (`frame_origins`,
/// the only targets it posts to), where it returns, and the host's state.
#[must_use]
pub fn target_json(t: &EmbedTarget, allowed: &[String]) -> Value {
    json!({
        "frame_origin": t.frame_origin,
        "frame_origins": frame_origins(t.frame_origin.as_deref(), allowed),
        "return_url": t.return_url,
        "state": t.return_state,
    })
}

/// Whether a view session of `kind` bound to `envelope` may make this request: the
/// route template `route` (as the table names it) under that envelope's own path, and
/// only the operations its editor needs. Nothing else of the workspace is reachable.
#[must_use]
pub fn reaches(
    kind: ViewKind,
    envelope: EnvelopeId,
    method: &Method,
    route: &str,
    path: &str,
) -> bool {
    let Some(sub) = route.strip_prefix("/api/v1/envelopes/{id}") else {
        return false;
    };
    let mine = path
        .strip_prefix("/api/v1/envelopes/")
        .and_then(|r| r.split('/').next())
        .and_then(|id| Uuid::parse_str(id).ok())
        .is_some_and(|id| id == envelope.0);
    if !mine {
        return false;
    }
    let get = *method == Method::GET;
    let reading = matches!(
        sub,
        "" | "/status" | "/documents" | "/documents/{doc}" | "/documents/{doc}/content"
    );
    match kind {
        ViewKind::Prepare => {
            (reading && get)
                || (sub.is_empty() && *method == Method::PATCH)
                || matches!(
                    sub,
                    "/documents"
                        | "/documents/{doc}"
                        | "/documents/{doc}/detect-fields"
                        | "/documents/{doc}/analysis"
                        | "/recipients"
                        | "/recipients/{r}"
                        | "/fields"
                        | "/fields/{f}"
                        | "/send"
                        | "/schedule"
                        | "/suggestions"
                        | "/suggestions/{s}/accept"
                        | "/suggestions/{s}/dismiss"
                )
        }
        ViewKind::Correct => {
            (reading && get)
                || matches!(
                    sub,
                    "/recipients" | "/recipients/{r}" | "/correct" | "/resend"
                )
        }
        _ => false,
    }
}

// Views ------------------------------------------------------------------------------

/// `POST /envelopes/{id}/views/prepare` (docs/40 §5): an embedded editor for a draft.
pub(crate) async fn view_prepare(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    view_editor(c, &id, &body, ViewKind::Prepare).await
}

/// `POST /envelopes/{id}/views/correct` (docs/40 §5): an embedded correction of a sent
/// envelope.
pub(crate) async fn view_correct(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    view_editor(c, &id, &body, ViewKind::Correct).await
}

/// A prepare or correct view link: only an API client acting as itself may ask (a staff
/// session, or a view session, is `403 CS-AUTH-0010`); the envelope must be one it may
/// see, a draft for prepare, in flight for correct (`409 CS-WF-0001`).
async fn view_editor(
    c: Call,
    id: &str,
    body: &Bytes,
    kind: ViewKind,
) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let l = find(&mut tx, &c.p, id).await?;
    let client = match c.p.credential {
        crate::auth::Credential::ApiKey(k) | crate::auth::Credential::AccessToken(k) => k,
        _ => return Err(ApiError::not_embedding_owner()),
    };
    use casual_sign_model::EnvelopeStatus as S;
    let ok = match kind {
        ViewKind::Prepare => l.state.status == S::Draft,
        _ => matches!(l.state.status, S::Sent | S::Delivered),
    };
    if !ok {
        return Err(ApiError::wrong_state(kind.as_str()));
    }
    let req: TargetIn = if body.iter().all(u8::is_ascii_whitespace) {
        TargetIn::default()
    } else {
        parse(body)?
    };
    let acct = tx.account().get().await?;
    let t = target(req, &allowed(&acct.settings))?;
    let token = random_secret()?;
    let now = c.st.now();
    let expires = crate::state::plus_std(now, c.st.config().view_ttl)?;
    tx.embed_views()
        .create(&NewView {
            id: Uuid::now_v7(),
            envelope_id: l.id,
            kind,
            client_id: client,
            user_id: c.p.user,
            token_sha256: sha256(token.as_bytes()),
            expires_at: expires,
            target: t,
            created_at: now,
        })
        .await?;
    tx.commit().await?;
    let url = format!("{}/e/{token}", c.st.config().public_url);
    let mut r = json_resp(
        StatusCode::CREATED,
        &json!({ "url": url, "expires_at": rfc3339(expires) }),
    );
    r.extensions_mut().insert(SecretBearing);
    Ok(r)
}

// The view page and its session ---------------------------------------------------------

/// The page answer for a view whose workspace is `account` and frame origin
/// `frame_origin` (`None` for a link that opens nothing: `'none'`).
async fn page(st: &AppState, name: &str, account: Option<(AccountId, Option<String>)>) -> Response {
    let Some(app) = st.webapp() else {
        return ApiError::not_found().into_response();
    };
    let Some(mut r) = app.file(name) else {
        return ApiError::not_found().into_response();
    };
    let sources = match account {
        Some((acct, frame)) => match st.store().for_account(acct).begin().await {
            Ok(mut tx) => match tx.account().get().await {
                Ok(a) => ancestors(frame.as_deref(), &allowed(&a.settings)),
                Err(_) => "'none'".to_owned(),
            },
            Err(_) => "'none'".to_owned(),
        },
        None => "'none'".to_owned(),
    };
    if let Ok(v) = HeaderValue::from_str(&page_csp(&sources)) {
        r.headers_mut().insert(header::CONTENT_SECURITY_POLICY, v);
    }
    // The link is in the address: never cached anywhere.
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

/// `GET /s/{token}` for a browser: the signing page, whose `frame-ancestors` an
/// embedded view's token sets ([`ancestors`]); any other link's page is never framed.
pub(crate) async fn signing_page(st: &AppState, token: &str) -> Response {
    let hash = sha256(token.as_bytes());
    let mut found = None;
    if token.len() <= 128
        && let Ok(Some(target)) = st
            .store()
            .entry_points()
            .resolve_recipient_token(&hash, st.now())
            .await
        && let Ok(mut tx) = st.store().for_account(target.account_id).begin().await
        && let Ok(Some(rec)) = tx.recipients().token(&hash).await
        && rec.purpose == casual_sign_store::repo::recipients::TokenPurpose::Embedded
    {
        found = Some((target.account_id, rec.embed.frame_origin));
    }
    page(st, "sign.html", found).await
}

/// `GET /e/{token}`: the embedded prepare or correct page (`embed.html`), framed only by
/// the view's origin. Serving it spends nothing and records nothing.
pub(crate) async fn view_page(State(st): State<AppState>, Path(token): Path<String>) -> Response {
    let hash = sha256(token.as_bytes());
    let mut found = None;
    if token.len() <= 128
        && let Ok(Some(acct)) = st
            .store()
            .entry_points()
            .resolve_embed_view(&hash, st.now())
            .await
        && let Ok(mut tx) = st.store().for_account(acct).begin().await
        && let Ok(Some(v)) = tx.embed_views().unspent(&hash, st.now()).await
    {
        found = Some((acct, v.target.frame_origin));
    }
    page(&st, "embed.html", found).await
}

/// `POST /e/{token}/session`: spend the link once and answer the view session that
/// authenticates the embedded editor (`Authorization: Bearer osv_…`) on its envelope
/// until it ends; with the envelope, the kind and where events go. An unknown, expired
/// or spent link, a revoked client or a removed member is `401 CS-AUTH-0002`.
pub(crate) async fn view_session(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    let ok_media = method == Method::GET
        || headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|t| t.starts_with("application/json"));
    if !ok_media {
        return ApiError::unsupported_media().into_response();
    }
    let hash = sha256(token.as_bytes());
    let hex = casual_sign_audit::Hash256(hash).hex();
    let per = st.config().rate.ceremony_per_minute;
    if let Err(r) = limit(&st, "ceremony", &format!("view:{hex}"), per) {
        return r;
    }
    let ipkey = ip.0.map_or_else(
        || "none".to_owned(),
        |i| casual_sign_audit::Hash256(sha256(i.to_string().as_bytes())).hex(),
    );
    if let Err(r) = limit(
        &st,
        "ceremony",
        &format!("view-ip:{ipkey}"),
        per.saturating_mul(4),
    ) {
        return r;
    }
    match session_inner(&st, &hash, &token).await {
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}

async fn session_inner(st: &AppState, hash: &[u8; 32], token: &str) -> Result<Response, ApiError> {
    if token.len() > 128 {
        return Err(ApiError::expired());
    }
    let now = st.now();
    let acct = st
        .store()
        .entry_points()
        .resolve_embed_view(hash, now)
        .await?
        .ok_or_else(ApiError::expired)?;
    let mut tx = st.store().for_account(acct).begin().await?;
    let secret = format!("{SESSION_PREFIX}{}", random_secret()?);
    let ends = crate::state::plus_std(now, SESSION_TTL)?;
    let v = tx
        .embed_views()
        .spend(hash, &sha256(secret.as_bytes()), now, ends)
        .await?
        .ok_or_else(ApiError::expired)?;
    // The client and the member must still be live: a revoked client's links open
    // nothing.
    let client = tx
        .api_clients()
        .get(v.client_id)
        .await?
        .ok_or_else(ApiError::expired)?;
    if client.revoked_at.is_some() || client.expires_at.is_some_and(|e| e <= now) {
        return Err(ApiError::expired());
    }
    let member = tx
        .users()
        .get(v.user_id)
        .await?
        .ok_or_else(ApiError::expired)?;
    if member.disabled_at.is_some() {
        return Err(ApiError::expired());
    }
    let allowed = allowed(&tx.account().get().await?.settings);
    tx.commit().await?;
    let mut r = json_resp(
        StatusCode::OK,
        &json!({
            "session": secret,
            "envelope_id": v.envelope_id.0,
            "kind": v.kind.as_str(),
            "expires_at": rfc3339(ends),
            "embed": target_json(&v.target, &allowed),
        }),
    );
    r.extensions_mut().insert(SecretBearing);
    Ok(r)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn plain_http_is_taken_for_intranet_hosts_only() {
        // Owner instruction 81: private-network addresses and intranet names.
        for ok in [
            "http://10.1.2.3",
            "http://172.16.0.9:8080",
            "http://172.31.255.1",
            "http://192.168.1.20",
            "http://127.0.0.2",
            "http://169.254.10.10",
            "http://[fd12:3456::1]",
            "http://[fe80::1]",
            "http://[::1]",
            "http://intranet",
            "http://portal.corp.internal",
            "http://wiki.local",
            "http://sign.lan:8443",
            "http://localhost:3000",
            "http://embed-host.test",
        ] {
            assert_eq!(origin(ok).as_deref(), Some(ok), "{ok}");
        }
        for public in [
            "http://8.8.8.8",
            "http://172.32.0.1",
            "http://192.169.0.1",
            "http://11.0.0.1",
            "http://[2001:db8::1]",
            "http://example.com",
            "http://intranet.example.com",
            "http://local.example",
        ] {
            assert_eq!(origin(public), None, "{public}");
        }
        // Every host, public or not, may use https.
        assert_eq!(
            origin("https://8.8.8.8").as_deref(),
            Some("https://8.8.8.8")
        );
    }

    #[test]
    fn origins_are_written_as_a_browser_compares_them() {
        assert_eq!(
            origin("https://App.Example.com").as_deref(),
            Some("https://app.example.com")
        );
        assert_eq!(
            origin("https://app.example.com:443").as_deref(),
            Some("https://app.example.com")
        );
        assert_eq!(
            origin("https://app.example.com:8443").as_deref(),
            Some("https://app.example.com:8443")
        );
        assert_eq!(
            origin("http://localhost:3000").as_deref(),
            Some("http://localhost:3000")
        );
        assert_eq!(
            origin("http://embed-host.test").as_deref(),
            Some("http://embed-host.test")
        );
        assert_eq!(
            origin("http://[::1]:8080").as_deref(),
            Some("http://[::1]:8080")
        );
        for bad in [
            "",
            "app.example.com",
            "http://app.example.com",
            "https://app.example.com/",
            "https://app.example.com/path",
            "https://app.example.com?x",
            "https://*.example.com",
            "https://user@app.example.com",
            "https://app.example.com:0",
            "https://app.example.com:99999",
            "https://app example.com",
            "ftp://app.example.com",
            "javascript://x",
            "https://",
            "'none'",
            "https://a.example; script-src *",
        ] {
            assert_eq!(origin(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_return_url_has_an_allowed_origin_and_no_fragment() {
        assert_eq!(
            url_origin("https://app.example.com/done?x=1").as_deref(),
            Some("https://app.example.com")
        );
        assert_eq!(
            url_origin("https://app.example.com").as_deref(),
            Some("https://app.example.com")
        );
        assert_eq!(url_origin("https://app.example.com/done#x"), None);
        assert_eq!(url_origin("https://evil@app.example.com/"), None);
        assert_eq!(url_origin("javascript:alert(1)"), None);
        assert_eq!(url_origin("https://app.example.com/a b"), None);
    }

    #[test]
    fn frame_ancestors_are_the_views_origin_while_allowed_else_none() {
        let list = vec![
            "https://a.example".to_owned(),
            "https://b.example".to_owned(),
        ];
        assert_eq!(
            ancestors(Some("https://b.example"), &list),
            "https://b.example"
        );
        assert_eq!(
            ancestors(None, &list),
            "https://a.example https://b.example"
        );
        assert_eq!(ancestors(Some("https://c.example"), &list), "'none'");
        assert_eq!(ancestors(None, &[]), "'none'");
        assert!(page_csp("https://a.example").ends_with("frame-ancestors https://a.example"));
        assert!(!page_csp("https://a.example").contains("'none'\""));
    }

    #[test]
    fn the_setting_is_a_short_list_of_distinct_origins() {
        assert!(check_setting(&json!([])).is_ok());
        assert!(check_setting(&json!(["https://a.example", "http://localhost:3000"])).is_ok());
        assert!(check_setting(&json!(["https://A.example"])).is_err());
        assert!(check_setting(&json!(["https://a.example", "https://a.example"])).is_err());
        assert!(check_setting(&json!("https://a.example")).is_err());
        assert!(check_setting(&json!([1])).is_err());
        let many: Vec<String> = (0..=MAX_ORIGINS)
            .map(|i| format!("https://h{i}.example"))
            .collect();
        assert!(check_setting(&json!(many)).is_err());
    }

    #[test]
    fn a_view_session_reaches_its_own_envelope_and_editor_only() {
        let e = EnvelopeId(Uuid::now_v7());
        let other = Uuid::now_v7();
        let p = |s: &str| format!("/api/v1/envelopes/{}{s}", e.0);
        let prep = ViewKind::Prepare;
        assert!(reaches(
            prep,
            e,
            &Method::GET,
            "/api/v1/envelopes/{id}",
            &p("")
        ));
        assert!(reaches(
            prep,
            e,
            &Method::PATCH,
            "/api/v1/envelopes/{id}",
            &p("")
        ));
        assert!(!reaches(
            prep,
            e,
            &Method::DELETE,
            "/api/v1/envelopes/{id}",
            &p("")
        ));
        assert!(reaches(
            prep,
            e,
            &Method::POST,
            "/api/v1/envelopes/{id}/send",
            &p("/send")
        ));
        assert!(reaches(
            prep,
            e,
            &Method::POST,
            "/api/v1/envelopes/{id}/fields",
            &p("/fields")
        ));
        assert!(!reaches(
            prep,
            e,
            &Method::POST,
            "/api/v1/envelopes/{id}/void",
            &p("/void")
        ));
        assert!(!reaches(
            prep,
            e,
            &Method::POST,
            "/api/v1/envelopes/{id}/views/prepare",
            &p("/views/prepare")
        ));
        assert!(!reaches(
            prep,
            e,
            &Method::POST,
            "/api/v1/envelopes/{id}/correct",
            &p("/correct")
        ));
        assert!(!reaches(
            prep,
            e,
            &Method::GET,
            "/api/v1/envelopes/{id}",
            &format!("/api/v1/envelopes/{other}")
        ));
        assert!(!reaches(
            prep,
            e,
            &Method::GET,
            "/api/v1/envelopes",
            "/api/v1/envelopes"
        ));
        assert!(!reaches(
            prep,
            e,
            &Method::GET,
            "/api/v1/accounts/me",
            "/api/v1/accounts/me"
        ));
        let cor = ViewKind::Correct;
        assert!(reaches(
            cor,
            e,
            &Method::POST,
            "/api/v1/envelopes/{id}/correct",
            &p("/correct")
        ));
        assert!(reaches(
            cor,
            e,
            &Method::PATCH,
            "/api/v1/envelopes/{id}/recipients/{r}",
            &p("/recipients/x")
        ));
        assert!(!reaches(
            cor,
            e,
            &Method::POST,
            "/api/v1/envelopes/{id}/send",
            &p("/send")
        ));
        assert!(!reaches(
            cor,
            e,
            &Method::PATCH,
            "/api/v1/envelopes/{id}",
            &p("")
        ));
    }
}
