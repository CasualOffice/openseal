//! The account, its members, API clients, and the authentication endpoints: local
//! login and logout (session cookie and CSRF token), the OAuth 2.1 client-credentials
//! token endpoint, and the JWKS that verifies its tokens (docs/40 §2).

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use casual_sign_audit::Personal;
use casual_sign_store::repo::accounts::{LoginKind, NewUser, PermissionProfile, ProfileKind};
use casual_sign_store::repo::api_clients::{ApiClientKind, NewApiClient};
use casual_sign_store::repo::sessions::{LoginMethod, NewSession};
use casual_sign_store::{
    AccountId, ApiClientId, PermissionProfileId, StaffSessionId, Store, UserId,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::envelopes::rfc3339;
use super::{json, path_id};
use crate::auth::{API_KEY_PREFIX, CSRF_HEADER, Credential, SCOPES, SESSION_COOKIE};
use crate::call::Call;
use crate::crypto::{
    AUDIENCE, Claims, hash_password, random_secret, same, sha256, verify_password,
};
use crate::dto::parse;
use crate::error::ApiError;
use crate::http::{SecretBearing, limit};
use crate::net::ClientIp;
use crate::state::AppState;

// Account -------------------------------------------------------------------------------

/// `GET /accounts/me`.
pub(crate) async fn account(c: Call) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let a = tx.account().get().await?;
    Ok(json(
        StatusCode::OK,
        &json!({
            "id": a.id.to_string(), "name": a.name, "settings": a.settings,
            "data_region": a.data_region, "created_at": rfc3339(a.created_at),
        }),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountPatch {
    settings: serde_json::Map<String, Value>,
}

/// `PATCH /accounts/me {settings}`: a JSON merge into the account's settings. The
/// server's own keys (`builtin_profiles`) cannot be changed.
pub(crate) async fn patch_account(c: Call, body: Bytes) -> Result<Response, ApiError> {
    let req: AccountPatch = parse(&body)?;
    let mut tx = c.tx().await?;
    let a = tx.account().get().await?;
    let mut settings = match a.settings {
        Value::Object(m) => m,
        _ => serde_json::Map::new(),
    };
    for (k, v) in req.settings {
        if k == "builtin_profiles" {
            return Err(ApiError::invalid("/settings/builtin_profiles"));
        }
        if k == "workflow_policy"
            && serde_json::from_value::<casual_sign_workflow::Policy>(v.clone()).is_err()
        {
            return Err(ApiError::invalid("/settings/workflow_policy"));
        }
        if v.is_null() {
            settings.remove(&k);
        } else {
            settings.insert(k, v);
        }
    }
    let settings = Value::Object(settings);
    tx.account().set_settings(&settings).await?;
    tx.commit().await?;
    Ok(json(StatusCode::OK, &json!({ "settings": settings })))
}

// Users ---------------------------------------------------------------------------------

fn member_json(m: &casual_sign_store::repo::accounts::Member) -> Value {
    json!({
        "id": m.user_id.to_string(),
        "email": m.email.get(),
        "name": m.name.get(),
        "login_kind": m.login_kind.as_str(),
        "permission_profile_id": m.permission_profile_id.to_string(),
        "disabled": m.disabled_at.is_some(),
    })
}

/// `GET /users`.
pub(crate) async fn users(c: Call) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let items: Vec<Value> = tx.users().list().await?.iter().map(member_json).collect();
    Ok(json(StatusCode::OK, &json!({ "items": items })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserIn {
    email: String,
    name: String,
    /// `admin`, `sender` or `viewer` (the account's built-in profiles), or a profile id.
    profile: String,
    #[serde(default)]
    password: Option<String>,
}

/// The profile a name or id means in this account.
async fn profile_id(
    tx: &mut casual_sign_store::TenantTx,
    name: &str,
) -> Result<PermissionProfileId, ApiError> {
    if let Ok(u) = Uuid::parse_str(name) {
        let id = PermissionProfileId(u);
        return match tx.users().profile(id).await? {
            Some(_) => Ok(id),
            None => Err(ApiError::invalid("/profile")),
        };
    }
    let a = tx.account().get().await?;
    a.settings
        .get("builtin_profiles")
        .and_then(|p| p.get(name))
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .map(PermissionProfileId)
        .ok_or_else(|| ApiError::invalid("/profile"))
}

fn normalize_email(e: &str) -> Result<String, ApiError> {
    let e = e.trim();
    if e.len() < 3 || e.len() > 320 || !e.contains('@') {
        return Err(ApiError::invalid("/email"));
    }
    Ok(e.to_lowercase())
}

fn check_password(p: &str) -> Result<(), ApiError> {
    // NIST SP 800-63B: at least 12 characters here, at most 256; no composition rules.
    let n = p.chars().count();
    if !(12..=256).contains(&n) {
        return Err(ApiError::invalid("/password"));
    }
    Ok(())
}

/// `POST /users`: a new local member.
pub(crate) async fn create_user(c: Call, body: Bytes) -> Result<Response, ApiError> {
    let req: UserIn = parse(&body)?;
    let email = normalize_email(&req.email)?;
    let name = req.name.trim().to_owned();
    if name.is_empty() || name.chars().count() > 255 {
        return Err(ApiError::invalid("/name"));
    }
    let phc = match &req.password {
        Some(p) => {
            check_password(p)?;
            let p = p.clone();
            Some(
                tokio::task::spawn_blocking(move || hash_password(&p))
                    .await
                    .map_err(|_| ApiError::internal("argon2"))??,
            )
        }
        None => None,
    };
    let mut tx = c.tx().await?;
    let profile = profile_id(&mut tx, &req.profile).await?;
    let id = UserId(Uuid::now_v7());
    tx.users()
        .create_member(
            &NewUser {
                id,
                email: Personal(req.email.trim().to_owned()),
                email_normalized: Personal(email),
                name: Personal(name),
                login_kind: LoginKind::Local,
                idp: None,
            },
            profile,
        )
        .await?;
    if let Some(phc) = phc {
        tx.users().set_password_hash(id, &Personal(phc)).await?;
    }
    let m = tx
        .users()
        .get(id)
        .await?
        .ok_or_else(|| ApiError::internal("user"))?;
    tx.commit().await?;
    Ok(json(StatusCode::CREATED, &member_json(&m)))
}

/// `GET /users/{id}`.
pub(crate) async fn user(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let id = UserId(path_id(&id)?);
    let mut tx = c.tx().await?;
    let m = tx.users().get(id).await?.ok_or_else(ApiError::not_found)?;
    Ok(json(StatusCode::OK, &member_json(&m)))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserPatch {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

/// `PATCH /users/{id} {name?, password?}`. A new password ends the member's sessions.
pub(crate) async fn patch_user(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let id = UserId(path_id(&id)?);
    let mut tx = c.tx().await?;
    tx.users().get(id).await?.ok_or_else(ApiError::not_found)?;
    let req: UserPatch = parse(&body)?;
    if let Some(n) = &req.name {
        let n = n.trim();
        if n.is_empty() || n.chars().count() > 255 {
            return Err(ApiError::invalid("/name"));
        }
        tx.users().rename(id, &Personal(n.to_owned())).await?;
    }
    if let Some(p) = req.password {
        check_password(&p)?;
        let phc = tokio::task::spawn_blocking(move || hash_password(&p))
            .await
            .map_err(|_| ApiError::internal("argon2"))??;
        tx.users().set_password_hash(id, &Personal(phc)).await?;
        tx.sessions().revoke_all(id, c.st.now()).await?;
    }
    let m = tx.users().get(id).await?.ok_or_else(ApiError::not_found)?;
    tx.commit().await?;
    Ok(json(StatusCode::OK, &member_json(&m)))
}

/// `DELETE /users/{id}`: remove the member from this account (their sessions end).
pub(crate) async fn delete_user(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let id = UserId(path_id(&id)?);
    if id == c.p.user {
        return Err(ApiError::invalid("/id"));
    }
    let mut tx = c.tx().await?;
    tx.users().get(id).await?.ok_or_else(ApiError::not_found)?;
    tx.users().remove_member(id).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// API clients ---------------------------------------------------------------------------

fn client_json(c: &casual_sign_store::repo::api_clients::ApiClient) -> Value {
    json!({
        "id": c.id.to_string(),
        "kind": c.kind.as_str(),
        "name": c.name,
        "owner_user_id": c.owner_user_id.map(|u| u.to_string()),
        "key_prefix": c.key_prefix,
        "scopes": c.scopes,
        "expires_at": c.expires_at.map(rfc3339),
        "revoked": c.revoked_at.is_some(),
    })
}

/// `GET /api-clients`.
pub(crate) async fn clients(c: Call) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let items: Vec<Value> = tx
        .api_clients()
        .list()
        .await?
        .iter()
        .map(client_json)
        .collect();
    Ok(json(StatusCode::OK, &json!({ "items": items })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientIn {
    name: String,
    /// `api_key` or `oauth_app`.
    kind: String,
    scopes: Vec<String>,
    /// The member it acts as; the caller when absent.
    #[serde(default)]
    owner_user_id: Option<String>,
    #[serde(default)]
    expires_in_days: Option<u32>,
}

/// `POST /api-clients`: a personal API key (`osk_…`) or an OAuth client
/// (`client_id` + `client_secret`). The secret is in this response only (SEC-A10).
pub(crate) async fn create_client(c: Call, body: Bytes) -> Result<Response, ApiError> {
    let req: ClientIn = parse(&body)?;
    let kind = match req.kind.as_str() {
        "api_key" => ApiClientKind::ApiKey,
        "oauth_app" => ApiClientKind::OauthApp,
        _ => return Err(ApiError::invalid("/kind")),
    };
    let name = req.name.trim();
    if name.is_empty() || name.chars().count() > 255 {
        return Err(ApiError::invalid("/name"));
    }
    if req.scopes.is_empty() || req.scopes.iter().any(|s| !SCOPES.contains(&s.as_str())) {
        return Err(ApiError::invalid("/scopes"));
    }
    // A client never holds more than the caller does.
    if req.scopes.iter().any(|s| !c.p.scopes.contains(s.as_str())) {
        return Err(ApiError::forbidden("the scopes it grants"));
    }
    if req.expires_in_days.is_some_and(|d| d == 0 || d > 3650) {
        return Err(ApiError::invalid("/expires_in_days"));
    }
    let mut tx = c.tx().await?;
    let owner = match &req.owner_user_id {
        Some(o) => {
            let o = UserId(Uuid::parse_str(o).map_err(|_| ApiError::invalid("/owner_user_id"))?);
            tx.users()
                .get(o)
                .await?
                .ok_or_else(|| ApiError::invalid("/owner_user_id"))?;
            o
        }
        None => c.p.user,
    };
    let id = ApiClientId(Uuid::now_v7());
    let secret = random_secret()?;
    let (shown, prefix) = match kind {
        ApiClientKind::ApiKey => {
            let prefix = format!(
                "{API_KEY_PREFIX}{}",
                secret.chars().take(8).collect::<String>()
            );
            (format!("{API_KEY_PREFIX}{secret}"), prefix)
        }
        _ => (
            format!("oss_{secret}"),
            "oss_".to_owned() + &secret.chars().take(4).collect::<String>(),
        ),
    };
    tx.api_clients()
        .create(&NewApiClient {
            id,
            kind,
            name: name.to_owned(),
            owner_user_id: Some(owner),
            key_prefix: Some(prefix),
            secret_sha256: Some(sha256(shown.as_bytes())),
            scopes: req.scopes.clone(),
            expires_at: req
                .expires_in_days
                .map(|d| crate::state::plus(c.st.now(), time::Duration::days(i64::from(d))))
                .transpose()?,
        })
        .await?;
    let stored = tx
        .api_clients()
        .get(id)
        .await?
        .ok_or_else(|| ApiError::internal("client"))?;
    tx.commit().await?;
    let mut out = client_json(&stored);
    if let Value::Object(m) = &mut out {
        match kind {
            ApiClientKind::ApiKey => m.insert("key".into(), Value::String(shown)),
            _ => {
                m.insert("client_id".into(), Value::String(id.to_string()));
                m.insert("client_secret".into(), Value::String(shown))
            }
        };
    }
    let mut r = json(StatusCode::CREATED, &out);
    r.extensions_mut().insert(SecretBearing);
    Ok(r)
}

/// `GET /api-clients/{id}`.
pub(crate) async fn client(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let id = ApiClientId(path_id(&id)?);
    let mut tx = c.tx().await?;
    let x = tx
        .api_clients()
        .get(id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    Ok(json(StatusCode::OK, &client_json(&x)))
}

/// `DELETE /api-clients/{id}`: revoke. Its key and every token it holds stop working
/// on their next request.
pub(crate) async fn revoke_client(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let id = ApiClientId(path_id(&id)?);
    let mut tx = c.tx().await?;
    tx.api_clients().revoke(id, c.st.now()).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// Login, sessions, tokens ---------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginIn {
    email: String,
    password: String,
    #[serde(default)]
    account_id: Option<String>,
}

#[allow(clippy::result_large_err)] // The refusal is the response to send.
fn login_limit(st: &AppState, ip: ClientIp, name: &str) -> Result<(), Response> {
    let per = st.config().rate.login_per_minute;
    let ipkey = ip.0.map_or_else(|| "none".to_owned(), |i| i.to_string());
    let ipdigest = casual_sign_audit::Hash256(sha256(ipkey.as_bytes())).hex();
    limit(
        st,
        "login",
        &format!("login-ip:{ipdigest}"),
        per.saturating_mul(10),
    )?;
    let digest = casual_sign_audit::Hash256(sha256(name.as_bytes())).hex();
    limit(st, "login", &format!("login-name:{digest}"), per)?;
    Ok(())
}

fn cookie(name: &str, value: &str, max_age: u64, secure: bool) -> Option<HeaderValue> {
    let secure = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}"
    ))
    .ok()
}

/// `POST /auth/login {email, password, account_id?}`: a local password login
/// (Argon2id). Answers the session cookie and a CSRF token every changing request must
/// echo in `X-CSRF-Token`. Unknown emails take as long as wrong passwords (SEC-A09).
pub(crate) async fn login(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    body: Bytes,
) -> Response {
    match login_inner(&st, ip, &body).await {
        Ok(r) | Err(r) => r,
    }
}

async fn login_inner(st: &AppState, ip: ClientIp, body: &[u8]) -> Result<Response, Response> {
    let req: LoginIn = parse(body).map_err(IntoResponse::into_response)?;
    let email = req.email.trim().to_lowercase();
    login_limit(st, ip, &email)?;
    let found = st
        .store()
        .entry_points()
        .resolve_user_login(Some(&email), None)
        .await
        .map_err(|e| ApiError::from(e).into_response())?;
    let wanted = req
        .account_id
        .as_deref()
        .and_then(|a| Uuid::parse_str(a).ok());
    let target = found
        .iter()
        .find(|(_, a)| wanted.is_none_or(|w| a.0 == w))
        .copied();
    let phc = match target {
        Some((u, a)) => {
            let mut tx = st
                .store()
                .for_account(a)
                .begin()
                .await
                .map_err(|e| ApiError::from(e).into_response())?;
            tx.users()
                .password_hash(u)
                .await
                .map_err(|e| ApiError::from(e).into_response())?
                .map(|p| p.0)
        }
        None => None,
    };
    let dummy = st.0.dummy_phc.clone();
    let password = req.password.clone();
    let ok = tokio::task::spawn_blocking(move || {
        let ok = verify_password(&password, phc.as_deref().unwrap_or(&dummy));
        ok && phc.is_some()
    })
    .await
    .unwrap_or(false);
    let (Some((user, account)), true) = (target, ok) else {
        return Err(ApiError::bad_credentials().into_response());
    };
    let now = st.now();
    let secret = random_secret().map_err(IntoResponse::into_response)?;
    let csrf = random_secret().map_err(IntoResponse::into_response)?;
    let expires = crate::state::plus_std(now, st.config().session_ttl)
        .map_err(IntoResponse::into_response)?;
    let mut tx = st
        .store()
        .for_account(account)
        .begin()
        .await
        .map_err(|e| ApiError::from(e).into_response())?;
    tx.sessions()
        .create(&NewSession {
            id: StaffSessionId(Uuid::now_v7()),
            user_id: user,
            token_sha256: sha256(secret.as_bytes()),
            csrf_sha256: sha256(csrf.as_bytes()),
            method: LoginMethod::Password,
            created_at: now,
            expires_at: expires,
        })
        .await
        .map_err(|e| ApiError::from(e).into_response())?;
    tx.commit()
        .await
        .map_err(|e| ApiError::from(e).into_response())?;
    let mut r = json(
        StatusCode::OK,
        &json!({
            "account_id": account.to_string(), "user_id": user.to_string(),
            "csrf_token": csrf, "expires_at": rfc3339(expires),
        }),
    );
    if let Some(v) = cookie(
        SESSION_COOKIE,
        &secret,
        st.config().session_ttl.as_secs(),
        st.config().secure_cookies,
    ) {
        r.headers_mut().insert(header::SET_COOKIE, v);
    }
    r.extensions_mut().insert(SecretBearing);
    Ok(r)
}

/// `POST /auth/logout`: end the current session.
pub(crate) async fn logout(c: Call) -> Result<Response, ApiError> {
    let Credential::Session(s) = c.p.credential else {
        return Err(ApiError::invalid("/credential"));
    };
    let mut tx = c.tx().await?;
    tx.sessions().revoke(s, c.st.now()).await?;
    tx.commit().await?;
    let mut r = StatusCode::NO_CONTENT.into_response();
    if let Some(v) = cookie(SESSION_COOKIE, "", 0, c.st.config().secure_cookies) {
        r.headers_mut().insert(header::SET_COOKIE, v);
    }
    Ok(r)
}

/// `GET /auth/session`: who the credential is.
pub(crate) async fn session(c: Call) -> Result<Response, ApiError> {
    let kind = match c.p.credential {
        Credential::Session(_) => "session",
        Credential::ApiKey(_) => "api_key",
        Credential::AccessToken(_) => "access_token",
    };
    Ok(json(
        StatusCode::OK,
        &json!({
            "account_id": c.p.account.to_string(), "user_id": c.p.user.to_string(),
            "credential": kind, "client_id": c.p.client().map(|x| x.to_string()),
            "scopes": c.p.scopes, "admin": c.p.admin,
        }),
    ))
}

#[derive(Debug, Deserialize)]
struct TokenIn {
    grant_type: String,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

fn oauth_error(status: StatusCode, error: &str, code: &str) -> Response {
    let mut r = json(
        status,
        &json!({ "error": error, "error_description": code }),
    );
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

fn basic(headers: &HeaderMap) -> Option<(String, String)> {
    use base64::Engine as _;
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, b) = v.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b.trim())
        .ok()?;
    let raw = String::from_utf8(raw).ok()?;
    let (i, s) = raw.split_once(':')?;
    Some((i.to_owned(), s.to_owned()))
}

/// `POST /oauth/token`: the client-credentials grant (OAuth 2.1 §4.2). Client
/// authentication by HTTP Basic or by `client_id` and `client_secret` in the
/// `application/x-www-form-urlencoded` (or JSON) body. Errors are RFC 6749 §5.2
/// shaped, with the `CS-*` code as `error_description`.
pub(crate) async fn token(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let form = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|t| t.starts_with("application/x-www-form-urlencoded"));
    let req: Option<TokenIn> = if form {
        serde_urlencoded_parse(&body)
    } else {
        serde_json::from_slice(&body).ok()
    };
    let Some(req) = req else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "CS-API-0001");
    };
    if req.grant_type != "client_credentials" {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "CS-API-0001",
        );
    }
    let Some((id, secret)) =
        basic(&headers).or(req.client_id.clone().zip(req.client_secret.clone()))
    else {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client", "CS-AUTH-0007");
    };
    if let Err(r) = login_limit(&st, ip, &format!("client:{id}")) {
        return r;
    }
    let now = st.now();
    let Ok(Some((account, client))) = st
        .store()
        .entry_points()
        .resolve_api_key(&sha256(secret.as_bytes()), now)
        .await
    else {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client", "CS-AUTH-0007");
    };
    if Uuid::parse_str(&id).ok() != Some(client.0) {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client", "CS-AUTH-0007");
    }
    let Ok(mut tx) = st.store().for_account(account).begin().await else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "CS-DB-0001",
        );
    };
    let Ok(Some(c)) = tx.api_clients().get(client).await else {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client", "CS-AUTH-0007");
    };
    if c.kind != ApiClientKind::OauthApp {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client", "CS-AUTH-0007");
    }
    let granted: Vec<String> = match &req.scope {
        Some(s) => {
            let asked: Vec<&str> = s.split(' ').filter(|x| !x.is_empty()).collect();
            if asked.iter().any(|a| !c.scopes.iter().any(|g| g == a)) {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_scope", "CS-AUTH-0006");
            }
            asked.into_iter().map(str::to_owned).collect()
        }
        None => c.scopes.clone(),
    };
    let ttl = st.config().access_token_ttl.as_secs();
    let claims = Claims {
        iss: st.config().public_url.clone(),
        sub: client.to_string(),
        acct: account.to_string(),
        aud: AUDIENCE.to_owned(),
        scope: granted.join(" "),
        iat: now.unix_timestamp(),
        exp: now
            .unix_timestamp()
            .saturating_add(i64::try_from(ttl).unwrap_or(3600)),
        jti: Uuid::now_v7().to_string(),
    };
    let Ok(t) = st.0.jwt.sign(&claims) else {
        return oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "CS-API-0010",
        );
    };
    let mut r = json(
        StatusCode::OK,
        &json!({ "access_token": t, "token_type": "Bearer", "expires_in": ttl, "scope": claims.scope }),
    );
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r.extensions_mut().insert(SecretBearing);
    r
}

/// `application/x-www-form-urlencoded`, for the four token parameters.
fn serde_urlencoded_parse(body: &[u8]) -> Option<TokenIn> {
    let text = std::str::from_utf8(body).ok()?;
    let mut m = serde_json::Map::new();
    for pair in text.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        m.insert(decode(k)?, Value::String(decode(v)?));
    }
    serde_json::from_value(Value::Object(m)).ok()
}

fn decode(s: &str) -> Option<String> {
    let mut out = Vec::with_capacity(s.len());
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        match b {
            b'+' => out.push(b' '),
            b'%' => {
                let h = [bytes.next()?, bytes.next()?];
                out.push(u8::from_str_radix(std::str::from_utf8(&h).ok()?, 16).ok()?);
            }
            b => out.push(b),
        }
    }
    String::from_utf8(out).ok()
}

/// `GET /.well-known/jwks.json`.
pub(crate) async fn jwks(State(st): State<AppState>) -> Response {
    let mut r = json(StatusCode::OK, &st.0.jwt.jwks());
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    r
}

// Bootstrap -----------------------------------------------------------------------------

/// What [`bootstrap`] made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bootstrapped {
    /// The account.
    pub account: AccountId,
    /// Its first administrator.
    pub admin: UserId,
    /// The built-in profiles: admin, sender, viewer.
    pub profiles: [PermissionProfileId; 3],
}

/// Create an account with its built-in permission profiles and a first administrator
/// who logs in with `password` (the `bootstrap` command of the binary, and tests).
///
/// # Errors
///
/// Store errors; `CS-API-0001` for a password outside 12 to 256 characters.
pub async fn bootstrap(
    store: &Store,
    name: &str,
    admin_email: &str,
    admin_name: &str,
    password: &str,
) -> Result<Bootstrapped, ApiError> {
    check_password(password)?;
    let email = normalize_email(admin_email)?;
    let account = AccountId(Uuid::now_v7());
    store.create_account(account, name).await?;
    let profiles = [
        PermissionProfileId(Uuid::now_v7()),
        PermissionProfileId(Uuid::now_v7()),
        PermissionProfileId(Uuid::now_v7()),
    ];
    let admin = UserId(Uuid::now_v7());
    let pw = password.to_owned();
    let phc = tokio::task::spawn_blocking(move || hash_password(&pw))
        .await
        .map_err(|_| ApiError::internal("argon2"))??;
    let mut tx = store.for_account(account).begin().await?;
    for (id, (n, kind)) in profiles.iter().zip([
        ("Administrator", ProfileKind::Admin),
        ("Sender", ProfileKind::Sender),
        ("Viewer", ProfileKind::Viewer),
    ]) {
        tx.users()
            .create_profile(&PermissionProfile {
                id: *id,
                name: n.to_owned(),
                kind,
                permissions: Vec::new(),
            })
            .await?;
    }
    tx.account()
        .set_settings(&json!({ "builtin_profiles": {
            "admin": profiles[0].to_string(), "sender": profiles[1].to_string(), "viewer": profiles[2].to_string(),
        }}))
        .await?;
    tx.users()
        .create_member(
            &NewUser {
                id: admin,
                email: Personal(admin_email.trim().to_owned()),
                email_normalized: Personal(email),
                name: Personal(admin_name.to_owned()),
                login_kind: LoginKind::Local,
                idp: None,
            },
            profiles[0],
        )
        .await?;
    tx.users().set_password_hash(admin, &Personal(phc)).await?;
    tx.commit().await?;
    Ok(Bootstrapped {
        account,
        admin,
        profiles,
    })
}

#[allow(dead_code)]
fn _csrf_header_is_documented() -> &'static str {
    let _ = same;
    CSRF_HEADER
}
