//! OAuth 2.1 acting for a member (slice 8, docs/40 §2; `VS-08A`, `VS-08B`).
//!
//! - **Authorization code with PKCE** (OAuth 2.1 §4.1): an OAuth app of the workspace
//!   sends a member's browser to `GET /oauth/authorize`, which hands the request to the
//!   web app's consent screen; the screen reads the checked request
//!   (`GET /oauth/authorize/request`) and answers it (`POST /oauth/authorize`), which
//!   records the member's consent and issues a code bound to the redirect URI and the
//!   S256 challenge. The app's token request (`grant_type=authorization_code`, client
//!   secret, verifier) spends the code once and gets an access token acting as the
//!   member and a refresh token. Refresh tokens rotate on every use; one spent twice
//!   revokes its whole family (§4.3.1).
//! - **JWT bearer grant** (RFC 7523, DocuSign's JWT grant): a JWT integration holds a
//!   public key; a member consents once through the same screen; afterwards the
//!   integration signs an assertion (`iss` its id, `sub` the member, `aud` this server)
//!   and gets an access token acting as that member, with no refresh token.
//!
//! A token acting for a member names the consent (`grt`); revoking it
//! (`DELETE /oauth/consents/{id}`) ends the token on its next request. A token never
//! holds more than the client's scopes, the consent's, and the member's own profile.
//! Codes and refresh tokens are stored as SHA-256 only.

use axum::body::Bytes;
use axum::extract::{Path, Query, RawQuery, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use casual_sign_seclog::Principal as Who;
use casual_sign_store::repo::api_clients::{ApiClient, ApiClientKind};
use casual_sign_store::repo::oauth::{NewCode, NewRefresh, Refresh};
use casual_sign_store::{AccountId, ApiClientId, OAuthConsentId, TenantTx, UserId};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::admin::{Identified, TokenIn, login_limit, oauth_error};
use super::envelopes::rfc3339;
use super::{json, path_id};
use crate::auth::Credential;
use crate::call::Call;
use crate::crypto::{AUDIENCE, Claims, random_secret, same, sha256};
use crate::dto::parse;
use crate::error::ApiError;
use crate::http::SecretBearing;
use crate::net::ClientIp;
use crate::state::AppState;

/// The JWT bearer grant's `grant_type` (RFC 7523 §2.1).
pub(crate) const JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/// How long an authorization code lives (OAuth 2.1 §4.1.2 recommends at most 10 minutes).
const CODE_SECS: i64 = 600;
/// How long a refresh token lives unused.
const REFRESH_DAYS: i64 = 30;
/// Refresh tokens start with this, for secret scanning (SEC-A10).
const REFRESH_PREFIX: &str = "osr_";
/// The longest an assertion may live (RFC 7523 §3: the issuer limits it; DocuSign's 1 h).
const ASSERTION_SECS: i64 = 3600;
/// Clock skew allowed on an assertion's `iat`.
const SKEW_SECS: i64 = 60;
/// The longest `state` carried back to the client.
const MAX_STATE: usize = 512;
/// The longest redirect URI.
const MAX_REDIRECT: usize = 2048;
/// At most this many redirect URIs per client.
pub(crate) const MAX_REDIRECTS: usize = 10;
/// The longest public key PEM.
const MAX_PEM: usize = 8192;

/// Whether `uri` may be registered as a redirect URI: `https://` with a host and no
/// fragment, or `http://` to the loopback address for a native app (RFC 8252 §7.3).
/// Matched exactly at authorization, never by prefix.
#[must_use]
pub(crate) fn redirect_uri_ok(uri: &str) -> bool {
    if uri.is_empty()
        || uri.len() > MAX_REDIRECT
        || uri.contains('#')
        || uri.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return false;
    }
    let host_of = |rest: &str| -> String {
        let authority = rest.split(['/', '?']).next().unwrap_or("");
        if authority.contains('@') {
            return String::new();
        }
        authority.to_owned()
    };
    if let Some(rest) = uri.strip_prefix("https://") {
        let host = host_of(rest);
        return !host.is_empty() && !host.starts_with(':');
    }
    if let Some(rest) = uri.strip_prefix("http://") {
        let host = host_of(rest);
        let name = if host.starts_with('[') {
            host.split(']')
                .next()
                .map(|h| format!("{h}]"))
                .unwrap_or_default()
        } else {
            host.split(':').next().unwrap_or("").to_owned()
        };
        return matches!(name.as_str(), "localhost" | "127.0.0.1" | "[::1]");
    }
    false
}

/// One DER element at the start of `der`: its tag, its contents and what follows.
/// Bounded: definite lengths of at most two bytes (a key PEM is at most 8 KiB).
fn der(der: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = der.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = match first {
        0..=0x7f => (usize::from(first), rest),
        0x81 => {
            let (&b, rest) = rest.split_first()?;
            (usize::from(b), rest)
        }
        0x82 => {
            let (hi, rest) = rest.split_first()?;
            let (lo, rest) = rest.split_first()?;
            (usize::from(*hi) << 8 | usize::from(*lo), rest)
        }
        _ => return None,
    };
    if rest.len() < len {
        return None;
    }
    let (body, after) = rest.split_at(len);
    Some((tag, body, after))
}

/// `id-ecPublicKey` with `prime256v1`, and `rsaEncryption`, as DER contents of the
/// SubjectPublicKeyInfo's algorithm identifier.
const EC_P256_ALG: &[u8] = &[
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07,
];
const RSA_OID: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
];

/// The verifying key a `PUBLIC KEY` PEM (SubjectPublicKeyInfo) names for `alg`: an EC
/// P-256 key for ES256 (its uncompressed point), an RSA key for RS256 (its PKCS#1
/// body). The structure is read here; the signature is checked by `jsonwebtoken` on
/// aws-lc-rs (ADR-006).
fn decoding_key(pem: &str, alg: Algorithm) -> Option<DecodingKey> {
    let body: String = pem
        .lines()
        .map(str::trim)
        .skip_while(|l| *l != "-----BEGIN PUBLIC KEY-----")
        .skip(1)
        .take_while(|l| *l != "-----END PUBLIC KEY-----")
        .collect();
    let spki = base64::engine::general_purpose::STANDARD
        .decode(body)
        .ok()?;
    let (0x30, seq, []) = der(&spki)? else {
        return None;
    };
    let (0x30, algorithm, rest) = der(seq)? else {
        return None;
    };
    let (0x03, bits, []) = der(rest)? else {
        return None;
    };
    let (&0, key) = bits.split_first()? else {
        return None;
    };
    match alg {
        Algorithm::ES256
            if algorithm == EC_P256_ALG && key.len() == 65 && key.first() == Some(&4) =>
        {
            Some(DecodingKey::from_ec_der(key))
        }
        Algorithm::RS256 if algorithm.starts_with(RSA_OID) => {
            // The PKCS#1 RSAPublicKey: a sequence of the modulus and the exponent.
            let (0x30, _, []) = der(key)? else {
                return None;
            };
            Some(DecodingKey::from_rsa_der(key))
        }
        _ => None,
    }
}

/// Whether `pem` is a public key a JWT integration may register (EC P-256 or RSA,
/// `-----BEGIN PUBLIC KEY-----`, at most 8 KiB), and never a private key.
#[must_use]
pub(crate) fn public_key_ok(pem: &str) -> bool {
    pem.len() <= MAX_PEM
        && pem.trim_start().starts_with("-----BEGIN PUBLIC KEY-----")
        && !pem.contains("PRIVATE")
        && (decoding_key(pem, Algorithm::ES256).is_some()
            || decoding_key(pem, Algorithm::RS256).is_some())
}

/// Percent-encode every byte but RFC 3986's unreserved ones.
fn enc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `uri` with `params` added to its query.
fn with_query(uri: &str, params: &[(&str, &str)]) -> String {
    let mut out = uri.to_owned();
    let mut sep = if uri.contains('?') { '&' } else { '?' };
    for (k, v) in params {
        out.push(sep);
        out.push_str(k);
        out.push('=');
        out.push_str(&enc(v));
        sep = '&';
    }
    out
}

/// An authorization request (OAuth 2.1 §4.1.1), from the query or the consent screen.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthorizeIn {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    #[serde(default)]
    state: Option<String>,
    code_challenge: String,
    code_challenge_method: String,
    /// The member's answer, on `POST` only: `allow` or `deny`.
    #[serde(default)]
    decision: Option<String>,
}

/// An authorization request checked against its client and the member.
struct Checked {
    client: ApiClient,
    scopes: Vec<String>,
}

fn is_b64url(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Check an authorization request. Every refusal is a problem shown on the consent
/// screen, never a redirect: a redirect URI is followed only once it is the client's.
async fn check(c: &Call, tx: &mut TenantTx, q: &AuthorizeIn) -> Result<Checked, ApiError> {
    // Only a member signed in to the web app consents; a key or a token cannot.
    if !matches!(c.p.credential, Credential::Session(_)) {
        return Err(ApiError::invalid("/credential"));
    }
    let id = Uuid::parse_str(&q.client_id).map_err(|_| ApiError::invalid("/client_id"))?;
    let client = tx
        .api_clients()
        .get(ApiClientId(id))
        .await?
        .ok_or_else(|| ApiError::invalid("/client_id"))?;
    let now = c.st.now();
    if client.revoked_at.is_some()
        || client.expires_at.is_some_and(|e| e <= now)
        || !matches!(
            client.kind,
            ApiClientKind::OauthApp | ApiClientKind::JwtIntegration
        )
    {
        return Err(ApiError::invalid("/client_id"));
    }
    if !client.redirect_uris.contains(&q.redirect_uri) {
        return Err(ApiError::invalid("/redirect_uri"));
    }
    if q.response_type != "code" {
        return Err(ApiError::invalid("/response_type"));
    }
    if q.code_challenge_method != "S256"
        || !(43..=128).contains(&q.code_challenge.len())
        || !is_b64url(&q.code_challenge)
    {
        return Err(ApiError::invalid("/code_challenge"));
    }
    if q.state
        .as_deref()
        .is_some_and(|s| s.len() > MAX_STATE || s.bytes().any(|b| !(0x20..0x7f).contains(&b)))
    {
        return Err(ApiError::invalid("/state"));
    }
    let mut scopes: Vec<String> = Vec::new();
    for s in q.scope.split(' ').filter(|s| !s.is_empty()) {
        // Within the client's scopes and the member's own: a consent never widens.
        if !client.scopes.iter().any(|g| g == s) || !c.p.scopes.contains(s) {
            return Err(ApiError::invalid("/scope"));
        }
        if !scopes.iter().any(|x| x == s) {
            scopes.push(s.to_owned());
        }
    }
    if scopes.is_empty() || scopes.len() > 32 {
        return Err(ApiError::invalid("/scope"));
    }
    Ok(Checked { client, scopes })
}

/// `GET /oauth/authorize`: the authorization endpoint (OAuth 2.1 §4.1.1). Hands the
/// request, unchanged, to the web app's consent screen, which signs the member in if
/// needed; nothing is checked or recorded here.
pub(crate) async fn authorize_redirect(RawQuery(q): RawQuery) -> Response {
    let target = format!("/app.html#/authorize?{}", q.unwrap_or_default());
    match HeaderValue::from_str(&target) {
        Ok(v) => {
            let mut r = StatusCode::SEE_OTHER.into_response();
            r.headers_mut().insert(header::LOCATION, v);
            r
        }
        Err(_) => ApiError::invalid("/").into_response(),
    }
}

/// `GET /oauth/authorize/request`: the checked request, for the consent screen to show:
/// the client's name and the scopes asked.
pub(crate) async fn authorize_request(
    c: Call,
    Query(q): Query<AuthorizeIn>,
) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let k = check(&c, &mut tx, &q).await?;
    Ok(json(
        StatusCode::OK,
        &json!({
            "client": { "id": k.client.id.to_string(), "name": k.client.name, "kind": k.client.kind.as_str() },
            "scopes": k.scopes,
            "redirect_uri": q.redirect_uri,
        }),
    ))
}

/// `POST /oauth/authorize`: the member's answer. `allow` records their consent and
/// answers the redirect carrying a one-time code; `deny` answers the redirect carrying
/// `access_denied`. Both carry `state` and `iss` (RFC 9207).
pub(crate) async fn authorize(c: Call, body: Bytes) -> Result<Response, ApiError> {
    let q: AuthorizeIn = parse(&body)?;
    let mut tx = c.tx().await?;
    let k = check(&c, &mut tx, &q).await?;
    let iss = c.st.config().public_url.clone();
    let state = q.state.clone().unwrap_or_default();
    let mut params: Vec<(&str, &str)> = Vec::new();
    let redirect = match q.decision.as_deref() {
        Some("deny") => {
            params.push(("error", "access_denied"));
            if q.state.is_some() {
                params.push(("state", &state));
            }
            params.push(("iss", &iss));
            with_query(&q.redirect_uri, &params)
        }
        Some("allow") => {
            let now = c.st.now();
            let consent = tx
                .oauth()
                .consent_to(
                    OAuthConsentId(Uuid::now_v7()),
                    k.client.id,
                    c.p.user,
                    &k.scopes,
                    now,
                )
                .await?;
            let code = random_secret()?;
            tx.oauth()
                .create_code(&NewCode {
                    id: Uuid::now_v7(),
                    consent_id: consent.id,
                    code_sha256: sha256(code.as_bytes()),
                    redirect_uri: q.redirect_uri.clone(),
                    code_challenge: q.code_challenge.clone(),
                    scopes: k.scopes.clone(),
                    expires_at: crate::state::plus(now, time::Duration::seconds(CODE_SECS))?,
                })
                .await?;
            tx.commit().await?;
            params.push(("code", &code));
            if q.state.is_some() {
                params.push(("state", &state));
            }
            params.push(("iss", &iss));
            let to = with_query(&q.redirect_uri, &params);
            let mut r = json(StatusCode::OK, &json!({ "redirect_to": to }));
            r.extensions_mut().insert(SecretBearing);
            return Ok(r);
        }
        _ => return Err(ApiError::invalid("/decision")),
    };
    Ok(json(StatusCode::OK, &json!({ "redirect_to": redirect })))
}

/// `GET /.well-known/oauth-authorization-server`: RFC 8414 metadata, so a standard
/// OAuth library configures itself.
pub(crate) async fn metadata(State(st): State<AppState>) -> Response {
    let base = st.config().public_url.trim_end_matches('/').to_owned();
    let mut r = json(
        StatusCode::OK,
        &json!({
            "issuer": st.config().public_url,
            "authorization_endpoint": format!("{base}/api/v1/oauth/authorize"),
            "token_endpoint": format!("{base}/api/v1/oauth/token"),
            "jwks_uri": format!("{base}/.well-known/jwks.json"),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials", JWT_BEARER],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
            "scopes_supported": crate::auth::SCOPES,
            "authorization_response_iss_parameter_supported": true,
        }),
    );
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    r
}

/// `GET /oauth/consents`: the apps the caller let act as them, live ones only.
pub(crate) async fn consents(c: Call) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let list = tx.oauth().consents_of(c.p.user).await?;
    let mut items = Vec::with_capacity(list.len());
    for k in list {
        let name = tx
            .api_clients()
            .get(k.client_id)
            .await?
            .map(|x| x.name)
            .unwrap_or_default();
        items.push(json!({
            "id": k.id.to_string(),
            "client": { "id": k.client_id.to_string(), "name": name },
            "scopes": k.scopes,
            "granted_at": rfc3339(k.granted_at),
        }));
    }
    Ok(json(StatusCode::OK, &json!({ "items": items })))
}

/// `DELETE /oauth/consents/{id}`: the caller withdraws a consent; its refresh tokens
/// stop at once and its access tokens on their next request. Another member's is `404`.
pub(crate) async fn revoke_consent(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let id = OAuthConsentId(path_id(&id)?);
    let mut tx = c.tx().await?;
    tx.oauth().revoke_consent(id, c.p.user, c.st.now()).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// Token grants ------------------------------------------------------------------------

fn refused(code: &'static str) -> Response {
    oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", code)
}

fn unavailable() -> Response {
    oauth_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        "CS-DB-0001",
    )
}

/// The token response: an access token acting for `user` under `consent`, and a
/// refresh token when one was minted.
fn issue(
    st: &AppState,
    client: ApiClientId,
    account: AccountId,
    user: UserId,
    consent: OAuthConsentId,
    scopes: &[String],
    refresh: Option<&str>,
) -> Response {
    let now = st.now();
    let ttl = st.config().access_token_ttl.as_secs();
    let claims = Claims {
        iss: st.config().public_url.clone(),
        sub: client.to_string(),
        acct: account.to_string(),
        aud: AUDIENCE.to_owned(),
        scope: scopes.join(" "),
        iat: now.unix_timestamp(),
        exp: now
            .unix_timestamp()
            .saturating_add(i64::try_from(ttl).unwrap_or(3600)),
        jti: Uuid::now_v7().to_string(),
        usr: Some(user.to_string()),
        grt: Some(consent.to_string()),
    };
    let Ok(t) = st.0.jwt.sign(&claims) else {
        return oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "CS-API-0010",
        );
    };
    let mut body = json!({ "access_token": t, "token_type": "Bearer", "expires_in": ttl, "scope": claims.scope });
    if let (Some(r), Value::Object(m)) = (refresh, &mut body) {
        m.insert("refresh_token".into(), Value::String(r.to_owned()));
    }
    let mut r = json(StatusCode::OK, &body);
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r.extensions_mut().insert(SecretBearing);
    r
}

/// Mint and store a refresh token of `family`.
async fn mint_refresh(
    st: &AppState,
    tx: &mut TenantTx,
    consent: OAuthConsentId,
    family: Uuid,
    scopes: &[String],
) -> Result<String, ApiError> {
    let now = st.now();
    let token = format!("{REFRESH_PREFIX}{}", random_secret()?);
    tx.oauth()
        .create_refresh(&NewRefresh {
            id: Uuid::now_v7(),
            consent_id: consent,
            family_id: family,
            token_sha256: sha256(token.as_bytes()),
            scopes: scopes.to_vec(),
            created_at: now,
            expires_at: crate::state::plus(now, time::Duration::days(REFRESH_DAYS))?,
        })
        .await?;
    Ok(token)
}

/// The scopes three lists all hold, in the first's order.
fn within(asked: &[String], consent: &[String], client: &[String]) -> Vec<String> {
    asked
        .iter()
        .filter(|s| consent.contains(s) && client.contains(s))
        .cloned()
        .collect()
}

/// `grant_type=authorization_code` for the authenticated OAuth app `c`: the code is
/// spent first, so a wrong verifier or redirect URI still burns it (OAuth 2.1 §4.1.3).
pub(super) async fn code_grant(
    st: &AppState,
    mut tx: TenantTx,
    c: &ApiClient,
    account: AccountId,
    req: &TokenIn,
) -> Response {
    let (Some(code), Some(redirect), Some(verifier)) =
        (&req.code, &req.redirect_uri, &req.code_verifier)
    else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "CS-API-0001");
    };
    let now = st.now();
    let Ok(spent) = tx.oauth().spend_code(&sha256(code.as_bytes()), now).await else {
        return unavailable();
    };
    let Some(spent) = spent else {
        return refused("CS-AUTH-0014");
    };
    if tx.commit().await.is_err() {
        return unavailable();
    }
    let Ok(mut tx) = st.store().for_account(account).begin().await else {
        return unavailable();
    };
    let Ok(Some(consent)) = tx.oauth().consent(spent.consent_id).await else {
        return refused("CS-AUTH-0014");
    };
    let challenge = URL_SAFE_NO_PAD.encode(sha256(verifier.as_bytes()));
    let verifier_ok = (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
        && same(
            &sha256(challenge.as_bytes()),
            &sha256(spent.code_challenge.as_bytes()),
        );
    if consent.client_id != c.id
        || consent.revoked_at.is_some()
        || spent.expires_at <= now
        || spent.redirect_uri != *redirect
        || !verifier_ok
    {
        return refused("CS-AUTH-0014");
    }
    let scopes = within(&spent.scopes, &consent.scopes, &c.scopes);
    if scopes.is_empty() {
        return refused("CS-AUTH-0014");
    }
    let Ok(refresh) = mint_refresh(st, &mut tx, consent.id, Uuid::now_v7(), &scopes).await else {
        return unavailable();
    };
    if tx.commit().await.is_err() {
        return unavailable();
    }
    issue(
        st,
        c.id,
        account,
        consent.user_id,
        consent.id,
        &scopes,
        Some(&refresh),
    )
}

/// `grant_type=refresh_token` for the authenticated OAuth app `c`: the token is
/// rotated; one spent before revokes its family, which is committed before refusing.
pub(super) async fn refresh_grant(
    st: &AppState,
    mut tx: TenantTx,
    c: &ApiClient,
    account: AccountId,
    req: &TokenIn,
) -> Response {
    let Some(token) = &req.refresh_token else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "CS-API-0001");
    };
    let Ok(found) = tx
        .oauth()
        .spend_refresh(&sha256(token.as_bytes()), st.now())
        .await
    else {
        return unavailable();
    };
    let Refresh::Live {
        consent_id,
        family_id,
        scopes,
    } = found
    else {
        if tx.commit().await.is_err() {
            return unavailable();
        }
        return refused("CS-AUTH-0014");
    };
    let Ok(Some(consent)) = tx.oauth().consent(consent_id).await else {
        return refused("CS-AUTH-0014");
    };
    if consent.client_id != c.id || consent.revoked_at.is_some() {
        // Not this client's token: spent nothing (the transaction is dropped).
        return refused("CS-AUTH-0014");
    }
    let mut scopes = within(&scopes, &consent.scopes, &c.scopes);
    if let Some(asked) = &req.scope {
        let asked: Vec<String> = asked
            .split(' ')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        if asked.iter().any(|a| !scopes.contains(a)) {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_scope", "CS-AUTH-0006");
        }
        scopes = asked;
    }
    if scopes.is_empty() {
        return refused("CS-AUTH-0014");
    }
    let Ok(next) = mint_refresh(st, &mut tx, consent.id, family_id, &scopes).await else {
        return unavailable();
    };
    if tx.commit().await.is_err() {
        return unavailable();
    }
    issue(
        st,
        c.id,
        account,
        consent.user_id,
        consent.id,
        &scopes,
        Some(&next),
    )
}

/// An assertion's claims (RFC 7523 §3).
#[derive(Debug, Deserialize)]
struct Assertion {
    sub: String,
    iat: i64,
    exp: i64,
    #[serde(default)]
    scope: Option<String>,
}

/// The `iss` of an assertion, read before its signature is checked only to find the
/// key that must then verify it.
fn issuer_of(jwt: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct Iss {
        iss: String,
    }
    let payload = jwt.split('.').nth(1)?;
    let raw = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice::<Iss>(&raw).ok().map(|i| i.iss)
}

/// `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`: the integration named by
/// the assertion's `iss` must have signed it with its registered key (ES256 or RS256),
/// for this server (`aud`), unexpired and at most an hour long, acting for a member
/// (`sub`) who consented to the scopes asked.
pub(super) async fn jwt_grant(
    st: &AppState,
    ip: ClientIp,
    req: &TokenIn,
    who: &mut Identified,
) -> Response {
    let Some(assertion) = &req.assertion else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "CS-API-0001");
    };
    let bad_client = || oauth_error(StatusCode::UNAUTHORIZED, "invalid_client", "CS-AUTH-0007");
    let Some(iss) = issuer_of(assertion) else {
        return refused("CS-AUTH-0014");
    };
    let Ok(id) = Uuid::parse_str(&iss) else {
        return bad_client();
    };
    *who = Some((Who::Client(id), None));
    if let Err(r) = login_limit(st, ip, &format!("client:{id}")) {
        return r;
    }
    let now = st.now();
    let Ok(found) = st
        .store()
        .entry_points()
        .resolve_jwt_client(ApiClientId(id), now)
        .await
    else {
        return unavailable();
    };
    let Some(account) = found else {
        return bad_client();
    };
    *who = Some((Who::Client(id), Some(account.0)));
    let Ok(mut tx) = st.store().for_account(account).begin().await else {
        return unavailable();
    };
    let Ok(Some(c)) = tx.api_clients().get(ApiClientId(id)).await else {
        return bad_client();
    };
    let Some(pem) = c.public_key_pem.as_deref() else {
        return bad_client();
    };
    let Some(alg) = jsonwebtoken::decode_header(assertion)
        .ok()
        .map(|h| h.alg)
        .filter(|a| matches!(a, Algorithm::ES256 | Algorithm::RS256))
    else {
        return refused("CS-AUTH-0014");
    };
    let Some(key) = decoding_key(pem, alg) else {
        return refused("CS-AUTH-0014");
    };
    let base = st.config().public_url.trim_end_matches('/').to_owned();
    let mut v = Validation::new(alg);
    // Expiry is checked against the server's clock below, not the system's.
    v.validate_exp = false;
    v.required_spec_claims.clear();
    v.set_issuer(&[iss.as_str()]);
    v.set_audience(&[
        st.config().public_url.clone(),
        base.clone(),
        format!("{base}/api/v1/oauth/token"),
    ]);
    let Ok(data) = jsonwebtoken::decode::<Assertion>(assertion, &key, &v) else {
        return refused("CS-AUTH-0014");
    };
    let a = data.claims;
    let t = now.unix_timestamp();
    if a.exp <= t
        || a.iat > t.saturating_add(SKEW_SECS)
        || a.exp.saturating_sub(a.iat) > ASSERTION_SECS
    {
        return refused("CS-AUTH-0014");
    }
    let Ok(user) = Uuid::parse_str(&a.sub).map(UserId) else {
        return refused("CS-AUTH-0014");
    };
    let Ok(consent) = tx.oauth().live_consent(c.id, user).await else {
        return unavailable();
    };
    let Some(consent) = consent else {
        // DocuSign's `consent_required`: the member has not let this integration act.
        return refused("CS-AUTH-0005");
    };
    let asked: Vec<String> = a
        .scope
        .or_else(|| req.scope.clone())
        .map(|s| {
            s.split(' ')
                .filter(|x| !x.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_else(|| consent.scopes.clone());
    let scopes = within(&asked, &consent.scopes, &c.scopes);
    if scopes.is_empty() || scopes.len() != asked.len() {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_scope", "CS-AUTH-0006");
    }
    issue(st, c.id, account, user, consent.id, &scopes, None)
}

#[cfg(test)]
// Tests may unwrap, index and panic (CLAUDE.md).
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn redirect_uris_are_https_or_loopback_http_without_fragments_or_credentials() {
        for ok in [
            "https://app.example.com/callback",
            "https://app.example.com:8443/cb?x=1",
            "http://localhost:8080/cb",
            "http://127.0.0.1/cb",
            "http://[::1]:9000/cb",
        ] {
            assert!(redirect_uri_ok(ok), "{ok}");
        }
        for bad in [
            "",
            "http://app.example.com/cb",
            "https://app.example.com/cb#frag",
            "https://user@app.example.com/cb",
            "https:///cb",
            "javascript:alert(1)",
            "https://app.example.com/c b",
            "http://localhost.evil.example/cb",
        ] {
            assert!(!redirect_uri_ok(bad), "{bad}");
        }
    }

    #[test]
    fn a_redirect_keeps_its_query_and_encodes_what_it_adds() {
        assert_eq!(
            with_query(
                "https://a.example/cb?x=1",
                &[("code", "a b"), ("state", "s&t")]
            ),
            "https://a.example/cb?x=1&code=a%20b&state=s%26t"
        );
        assert_eq!(
            with_query("https://a.example/cb", &[("error", "access_denied")]),
            "https://a.example/cb?error=access_denied"
        );
    }

    #[test]
    fn an_assertion_issuer_is_read_from_its_payload_only() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"iss":"abc","sub":"x"}"#);
        assert_eq!(issuer_of(&format!("h.{payload}.s")).as_deref(), Some("abc"));
        assert_eq!(issuer_of("nonsense"), None);
    }

    #[test]
    fn only_a_public_key_is_accepted() {
        assert!(!public_key_ok(
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"
        ));
        assert!(!public_key_ok("not a key"));
    }
}
