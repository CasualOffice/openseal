//! The account, its members, API clients, and the authentication endpoints: local
//! login and logout (session cookie and CSRF token), the OAuth 2.1 client-credentials
//! token endpoint, and the JWKS that verifies its tokens (docs/40 §2).

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use casual_sign_audit::Personal;
use casual_sign_host::jobs::SecurityNotice;
use casual_sign_store::repo::accounts::{LoginKind, NewUser};
use casual_sign_store::repo::api_clients::{ApiClientKind, NewApiClient};
use casual_sign_store::repo::sessions::{LoginMethod, NewSession};
use casual_sign_store::{
    AccountId, ApiClientId, BuiltinProfiles, Meter, OrganizationId, PermissionProfileId,
    StaffSessionId, Store, TenantTx, UserId,
};
use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use super::envelopes::rfc3339;
use super::{json, path_id};
use crate::auth::{API_KEY_PREFIX, CSRF_HEADER, Credential, SCOPES, session_cookie};
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
        // Who must sign in with a second factor (ASVS-01). Requiring one needs the
        // server's sealing key, or nobody could enrol.
        if k == "mfa_policy" && !v.is_null() {
            match v.as_str() {
                Some("optional") => {}
                Some("administrators" | "everyone") => {
                    if c.st.mfa_key().is_none() {
                        return Err(ApiError::not_available("second factor not configured"));
                    }
                }
                _ => return Err(ApiError::invalid("/settings/mfa_policy")),
            }
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

// Electronic disclosure (ERSD) -----------------------------------------------------------

/// The longest disclosure text taken, in bytes of UTF-8 (docs/21).
pub(crate) const ERSD_MAX_BYTES: usize = 100_000;
/// The most published versions `GET /ersd-versions` lists.
const ERSD_LIST_MAX: i64 = 100;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ErsdPublish {
    /// The text recipients read and consent to.
    text: String,
    /// Its language tag; `en` when absent.
    #[serde(default)]
    language: Option<String>,
}

/// A hash as the API writes it everywhere: `sha256:<hex>`.
fn hex32(b: &[u8; 32]) -> String {
    casual_sign_audit::Hash256(*b).to_string()
}

fn ersd_json(d: &casual_sign_store::repo::accounts::PublishedDisclosure) -> Value {
    json!({
        "id": d.id.to_string(), "version": d.version, "label": d.version.to_string(),
        "language": d.language, "sha256": hex32(&d.sha256),
        "published_at": rfc3339(d.published_at),
    })
}

/// A language tag as `ersd_versions` takes it: 2 to 35 ASCII letters, digits and `-`,
/// starting with a letter.
fn language_tag(s: &str) -> bool {
    (2..=35).contains(&s.len())
        && s.starts_with(|c: char| c.is_ascii_alphabetic())
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// `POST /ersd-versions {text, language?}` (ERSD-01): publish `text` as the account's
/// next disclosure version and make it the one recipients must accept, in one step:
/// the new `ersd_versions` row (version one more than the language's highest), its
/// `ersd.published` admin event, and `settings.workflow_policy.ersd = {version: "<n>",
/// hash}` with its `workspace.settings_changed` event commit together. Envelopes
/// already sent then ask for consent to the new version (the engine's rule: consent
/// binds the version and the hash). The text is never logged.
///
/// `422 CS-API-0001` for an empty or blank text, one with a NUL, or a bad language tag;
/// `413 CS-API-0006` beyond [`ERSD_MAX_BYTES`].
pub(crate) async fn publish_ersd(c: Call, body: Bytes) -> Result<Response, ApiError> {
    let req: ErsdPublish = parse(&body)?;
    if req.text.len() > ERSD_MAX_BYTES {
        return Err(ApiError::too_large());
    }
    if req.text.trim().is_empty() || req.text.contains('\0') {
        return Err(ApiError::invalid("/text"));
    }
    let language = req.language.unwrap_or_else(|| "en".to_owned());
    if !language_tag(&language) {
        return Err(ApiError::invalid("/language"));
    }
    let hash = sha256(req.text.as_bytes());
    let now = c.st.now();
    let mut tx = c.tx().await?;
    let d = tx
        .account()
        .publish_disclosure(Uuid::now_v7(), &language, &req.text, &hash, now)
        .await?;
    let a = tx.account().get().await?;
    let mut settings = match a.settings {
        Value::Object(m) => m,
        _ => serde_json::Map::new(),
    };
    let mut policy = settings
        .get("workflow_policy")
        .cloned()
        .filter(|p| serde_json::from_value::<casual_sign_workflow::Policy>(p.clone()).is_ok())
        .unwrap_or_else(|| {
            serde_json::to_value(casual_sign_workflow::Policy::default()).unwrap_or(Value::Null)
        });
    let Some(p) = policy.as_object_mut() else {
        return Err(ApiError::internal("workflow policy"));
    };
    p.insert(
        "ersd".into(),
        json!({"version": d.version.to_string(), "hash": hex32(&hash)}),
    );
    if serde_json::from_value::<casual_sign_workflow::Policy>(policy.clone()).is_err() {
        return Err(ApiError::internal("workflow policy"));
    }
    settings.insert("workflow_policy".into(), policy);
    tx.account().set_settings(&Value::Object(settings)).await?;
    tx.commit().await?;
    Ok(json(StatusCode::CREATED, &ersd_json(&d)))
}

/// `GET /ersd-versions` (ERSD-01): `{current, items}`. `current` is the disclosure the
/// workflow policy names, with its published text (`{label, sha256, version, language,
/// published_at, text}`; `text` null when no intact published row has that hash), or
/// null when the account requires none; `items` the published versions, newest first,
/// at most 100, without their text.
pub(crate) async fn ersd_versions(c: Call) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let a = tx.account().get().await?;
    let policy = crate::apply::policy_of(&a.settings);
    let items = tx.account().disclosures(ERSD_LIST_MAX).await?;
    let current = match &policy.ersd {
        None => Value::Null,
        Some(e) => {
            let text = tx.account().disclosure(&e.hash.0).await?;
            let row = items.iter().find(|d| d.sha256 == e.hash.0);
            let intact = text
                .as_ref()
                .is_some_and(|d| sha256(d.body.as_bytes()) == e.hash.0);
            json!({
                "label": e.version, "sha256": hex32(&e.hash.0),
                "version": row.map(|d| d.version), "language": row.map(|d| d.language.clone()),
                "published_at": row.map(|d| rfc3339(d.published_at)),
                "text": if intact { text.map(|d| d.body) } else { None },
            })
        }
    };
    let items: Vec<Value> = items.iter().map(ersd_json).collect();
    Ok(json(
        StatusCode::OK,
        &json!({ "current": current, "items": items }),
    ))
}

// Admin log -----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdminEventsQuery {
    /// The `seq` after which to start (exclusive).
    #[serde(default)]
    cursor: Option<u64>,
    #[serde(default)]
    limit: Option<i64>,
    /// `json` (default) or `csv`.
    #[serde(default)]
    format: Option<String>,
    /// `page` (the default) verifies the page read; `full` re-verifies the whole log first.
    #[serde(default)]
    verify: Option<String>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A CSV field, quoted (RFC 4180) when it holds a comma, quote or line break.
fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_owned()
    }
}

/// `GET /admin-events?cursor&limit&format=json|csv&verify=page|full` (ORG-05, docs/23 §2.5):
/// a page of this workspace's admin log, oldest first, each event with its hash, `prev`
/// and its canonical bytes as the JSON they are. Each page is verified as it is read
/// (each event against the one before it, the event at the cursor included; the last
/// page against the stored head), so an export walked by cursor checks every link once
/// and a broken link is `500 CS-DB-0014`, never a quiet partial log. `verify=full`
/// re-verifies the whole log first.
pub(crate) async fn admin_events(
    c: Call,
    axum::extract::Query(q): axum::extract::Query<AdminEventsQuery>,
) -> Result<Response, ApiError> {
    let (limit, csv, full) = q.read()?;
    let mut tx = c.tx().await?;
    if full {
        tx.verified_admin_log().await?;
    }
    let page = tx.verified_admin_events(q.cursor, limit).await?;
    tx.commit().await?;
    Ok(admin_log_response(&page, limit, csv))
}

impl AdminEventsQuery {
    /// The page size, whether CSV was asked for, and whether the whole chain is to be
    /// verified (`verify=full`) rather than the page read (`verify=page`, the default).
    pub(crate) fn read(&self) -> Result<(i64, bool, bool), ApiError> {
        let limit = self.limit.unwrap_or(100);
        if !(1..=casual_sign_store::ADMIN_EVENTS_MAX_PAGE).contains(&limit) {
            return Err(ApiError::invalid("/query/limit"));
        }
        let csv = match self.format.as_deref() {
            None | Some("json") => false,
            Some("csv") => true,
            Some(_) => return Err(ApiError::invalid("/query/format")),
        };
        let full = match self.verify.as_deref() {
            None | Some("page") => false,
            Some("full") => true,
            Some(_) => return Err(ApiError::invalid("/query/verify")),
        };
        Ok((limit, csv, full))
    }

    /// The `seq` after which to start.
    pub(crate) fn cursor(&self) -> Option<u64> {
        self.cursor
    }
}

/// A page of an admin log (a workspace's or an organization's) as JSON, or as CSV with
/// the next cursor in `X-Next-Cursor`.
pub(crate) fn admin_log_response(
    page: &[casual_sign_store::StoredAdminEvent],
    limit: i64,
    csv: bool,
) -> Response {
    let next = (i64::try_from(page.len()).ok() == Some(limit))
        .then(|| page.last().map(|e| e.seq))
        .flatten();
    if csv {
        let mut out = String::from("seq,at,action,hash,prev,event\r\n");
        for e in page {
            let event = String::from_utf8_lossy(&e.canonical);
            out.push_str(&format!(
                "{},{},{},{},{},{}\r\n",
                e.seq,
                rfc3339(e.at),
                csv_field(&e.action),
                hex(&e.hash),
                e.prev.map(|p| hex(&p)).unwrap_or_default(),
                csv_field(&event)
            ));
        }
        let mut r = (StatusCode::OK, out).into_response();
        r.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/csv; charset=utf-8"),
        );
        if let Some(v) = next.and_then(|n| HeaderValue::from_str(&n.to_string()).ok()) {
            r.headers_mut().insert("x-next-cursor", v);
        }
        return r;
    }
    let items: Vec<Value> = page
        .iter()
        .map(|e| {
            json!({
                "seq": e.seq,
                "at": rfc3339(e.at),
                "action": e.action,
                "hash": hex(&e.hash),
                "prev": e.prev.map(|p| hex(&p)),
                "event": serde_json::from_slice::<Value>(&e.canonical).unwrap_or(Value::Null),
            })
        })
        .collect();
    json(
        StatusCode::OK,
        &json!({ "items": items, "next_cursor": next }),
    )
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
    /// Email the member a one-time link to set their password (WEB-06); not with
    /// `password`.
    #[serde(default)]
    invite: bool,
}

/// Record an invitation for `user` and queue the job that emails its link, revoking
/// any earlier open one (WEB-06).
async fn invite_member(
    c: &Call,
    tx: &mut casual_sign_store::TenantTx,
    user: UserId,
) -> Result<(), ApiError> {
    let now = c.st.now();
    tx.users().revoke_invitations(user, now).await?;
    let id = casual_sign_store::UserInvitationId(Uuid::now_v7());
    tx.users()
        .create_invitation(id, user, c.p.user, now)
        .await?;
    let job = casual_sign_host::jobs::user_invitation_job(
        casual_sign_store::JobId(Uuid::now_v7()),
        id.0,
        now,
    );
    tx.jobs().enqueue(&job).await?;
    Ok(())
}

/// Queue the email that tells `user` their password or second factor changed (ASVS-04),
/// in the transaction that makes the change, so a change that commits always tells them
/// and one that rolls back never does. The job carries ids only; the mail holds no secret.
pub(crate) async fn security_notice(
    tx: &mut TenantTx,
    user: UserId,
    notice: casual_sign_host::jobs::SecurityNotice,
    now: OffsetDateTime,
) -> Result<(), casual_sign_store::StoreError> {
    let job = casual_sign_host::jobs::security_notice_job(
        casual_sign_store::JobId(Uuid::now_v7()),
        user.0,
        notice,
        now,
    );
    tx.jobs().enqueue(&job).await?;
    Ok(())
}

/// The member as the API shows them, with their latest invitation's state.
async fn member_with_invitation(
    tx: &mut casual_sign_store::TenantTx,
    m: &casual_sign_store::repo::accounts::Member,
    now: time::OffsetDateTime,
) -> Result<Value, ApiError> {
    let mut v = member_json(m);
    let latest = tx.users().invitations(m.user_id).await?.into_iter().next();
    let state = latest.map(|i| {
        if i.accepted_at.is_some() {
            "accepted"
        } else if i.revoked_at.is_some() {
            "revoked"
        } else if i.expires_at.is_some_and(|e| e <= now) {
            "expired"
        } else if i.sent_at.is_some() {
            "sent"
        } else {
            "pending"
        }
    });
    if let Some(o) = v.as_object_mut() {
        o.insert("invitation".into(), json!(state));
    }
    Ok(v)
}

/// The profile a name or id means in this account.
pub(crate) async fn profile_id(
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

/// The profile a name or id means, refused (`CS-AUTH-0006`) when it gives more than
/// the caller holds (UXW-07, `Principal::may_grant`).
pub(crate) async fn granted_profile(
    c: &Call,
    tx: &mut casual_sign_store::TenantTx,
    name: &str,
) -> Result<PermissionProfileId, ApiError> {
    let id = profile_id(tx, name).await?;
    let p = tx
        .users()
        .profile(id)
        .await?
        .ok_or_else(|| ApiError::invalid("/profile"))?;
    c.p.may_grant(p.kind, &p.permissions)?;
    Ok(id)
}

/// Refuse (`CS-AUTH-0006`) a change to another member whose profile gives more than
/// the caller holds (UXW-07): someone who manages users with a custom profile cannot
/// re-profile, disable, rename, reset, re-invite (PRF-01) or remove a member above
/// them. The caller's own record is theirs to change as the route allows.
async fn outranks(
    c: &Call,
    tx: &mut casual_sign_store::TenantTx,
    target: &casual_sign_store::repo::accounts::Member,
) -> Result<(), ApiError> {
    if target.user_id == c.p.user {
        return Ok(());
    }
    let p = tx
        .users()
        .profile(target.permission_profile_id)
        .await?
        .ok_or_else(|| ApiError::internal("profile"))?;
    c.p.may_grant(p.kind, &p.permissions)
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
    // ASVS-02: nor one seen in breaches, from the bundled list, offline.
    if crate::passwords::is_common(p) {
        return Err(ApiError::common_password("/password"));
    }
    Ok(())
}

/// `POST /users`: a new local member.
pub(crate) async fn create_user(c: Call, body: Bytes) -> Result<Response, ApiError> {
    let req: UserIn = parse(&body)?;
    if req.invite && req.password.is_some() {
        return Err(ApiError::invalid("/invite"));
    }
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
    let profile = granted_profile(&c, &mut tx, &req.profile).await?;
    let id = UserId(Uuid::now_v7());
    // Seats are checked against the plan under the seat counters' lock, so two parallel
    // invites cannot both take the last seat (PLAN-04, `CS-PLAN-0003`).
    let seats = tx.gauge_lock(Meter::Seats).await?;
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
    tx.gauge_check(seats, c.st.now(), "member.add", id.0)
        .await?;
    if let Some(phc) = phc {
        tx.users().set_password_hash(id, &Personal(phc)).await?;
    }
    if req.invite {
        invite_member(&c, &mut tx, id).await?;
    }
    let m = tx
        .users()
        .get(id)
        .await?
        .ok_or_else(|| ApiError::internal("user"))?;
    let v = member_with_invitation(&mut tx, &m, c.st.now()).await?;
    tx.commit().await?;
    Ok(json(StatusCode::CREATED, &v))
}

/// `GET /users/{id}`.
pub(crate) async fn user(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let id = UserId(path_id(&id)?);
    let mut tx = c.tx().await?;
    let m = tx.users().get(id).await?.ok_or_else(ApiError::not_found)?;
    let v = member_with_invitation(&mut tx, &m, c.st.now()).await?;
    Ok(json(StatusCode::OK, &v))
}

/// `POST /users/{id}/invite`: email the member a new one-time set-password link; any
/// earlier open link stops working (WEB-06).
pub(crate) async fn reinvite_user(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let id = UserId(path_id(&id)?);
    let mut tx = c.tx().await?;
    let m = tx.users().get(id).await?.ok_or_else(ApiError::not_found)?;
    // A member above the caller is not theirs to re-invite either (PRF-01).
    outranks(&c, &mut tx, &m).await?;
    if m.disabled_at.is_some() || m.login_kind != LoginKind::Local {
        return Err(ApiError::invalid("/id"));
    }
    invite_member(&c, &mut tx, id).await?;
    let v = member_with_invitation(&mut tx, &m, c.st.now()).await?;
    tx.commit().await?;
    Ok(json(StatusCode::ACCEPTED, &v))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptIn {
    token: String,
    password: String,
}

/// `POST /auth/accept-invite {token, password}` (WEB-06): spend an invitation's
/// one-time link and set the member's password; they then log in. An unknown, expired,
/// spent or revoked link is `401 CS-AUTH-0002`, all alike. Rate-limited as login.
pub(crate) async fn accept_invite(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    body: Bytes,
) -> Response {
    match accept_inner(&st, ip, &body).await {
        Ok(r) | Err(r) => r,
    }
}

async fn accept_inner(st: &AppState, ip: ClientIp, body: &[u8]) -> Result<Response, Response> {
    let req: AcceptIn = parse(body).map_err(IntoResponse::into_response)?;
    login_limit(st, ip, "accept-invite")?;
    let refuse = || ApiError::expired().into_response();
    if req.token.is_empty() || req.token.len() > 128 {
        return Err(refuse());
    }
    check_password(&req.password).map_err(IntoResponse::into_response)?;
    let now = st.now();
    let found = st
        .store()
        .entry_points()
        .resolve_user_invitation(&sha256(req.token.as_bytes()), now)
        .await
        .map_err(|e| ApiError::from(e).into_response())?;
    let Some((account, invitation, user)) = found else {
        return Err(refuse());
    };
    let password = req.password.clone();
    let phc = tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(|_| ApiError::internal("argon2").into_response())?
        .map_err(IntoResponse::into_response)?;
    let inner = async {
        // The link reached the member's own address: they set their own password, even
        // when they belong to other accounts too, and their sessions end in every one
        // (SEC-ID-01).
        let mut tx = st.store().for_account(account).begin().await?;
        let who = tx
            .users()
            .accept_invitation_with_password(invitation, &Personal(phc), now)
            .await?;
        if who != Some(user) {
            return Ok(None);
        }
        security_notice(&mut tx, user, SecurityNotice::PasswordSet, now).await?;
        tx.commit().await?;
        Ok::<_, casual_sign_store::StoreError>(Some(()))
    };
    match inner.await {
        Ok(Some(())) => Ok(json(
            StatusCode::OK,
            &json!({"account_id": account.to_string(), "user_id": user.to_string()}),
        )),
        Ok(None) => Err(refuse()),
        Err(e) => Err(ApiError::from(e).into_response()),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserPatch {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    password: Option<String>,
    /// `admin`, `sender`, `viewer` or a profile id (WEB-06).
    #[serde(default)]
    profile: Option<String>,
    /// Disable or enable the member in this account (WEB-06).
    #[serde(default)]
    disabled: Option<bool>,
}

/// `PATCH /users/{id} {name?, password?, profile?, disabled?}`. A new password ends the
/// member's sessions; so does disabling them, which also revokes their open
/// invitations. An administrator cannot change their own profile or disable themselves.
///
/// The name and password are the user's in every account (SEC-ID-01): an administrator
/// changes them only for a user who belongs to this account alone, and a user of other
/// accounts too is `403 CS-API-0015`. The user changes their own through their session,
/// and a new password then ends their sessions in every account. Profile and disabling
/// are this account's membership only.
pub(crate) async fn patch_user(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let id = UserId(path_id(&id)?);
    let mut tx = c.tx().await?;
    let target = tx.users().get(id).await?.ok_or_else(ApiError::not_found)?;
    outranks(&c, &mut tx, &target).await?;
    let req: UserPatch = parse(&body)?;
    if id == c.p.user && (req.profile.is_some() || req.disabled.is_some()) {
        return Err(ApiError::invalid(if req.profile.is_some() {
            "/profile"
        } else {
            "/disabled"
        }));
    }
    // Re-profiling or enabling may take a seat: checked under the seat counters' lock
    // (PLAN-04, `CS-PLAN-0003`); a change that frees or keeps seats is never refused.
    let seats = if req.profile.is_some() || req.disabled == Some(false) {
        Some(tx.gauge_lock(Meter::Seats).await?)
    } else {
        None
    };
    if let Some(p) = &req.profile {
        let profile = granted_profile(&c, &mut tx, p).await?;
        tx.users().set_profile(id, profile).await?;
    }
    if let Some(off) = req.disabled {
        let now = c.st.now();
        tx.users().set_disabled(id, off.then_some(now)).await?;
        if off {
            tx.sessions().revoke_all(id, now).await?;
            tx.users().revoke_invitations(id, now).await?;
        }
    }
    if let Some(seats) = seats {
        tx.gauge_check(seats, c.st.now(), "member.change", Uuid::now_v7())
            .await?;
    }
    let name = match &req.name {
        Some(n) => {
            let n = n.trim();
            if n.is_empty() || n.chars().count() > 255 {
                return Err(ApiError::invalid("/name"));
            }
            Some(Personal(n.to_owned()))
        }
        None => None,
    };
    let phc = match req.password {
        Some(p) => {
            check_password(&p)?;
            let phc = tokio::task::spawn_blocking(move || hash_password(&p))
                .await
                .map_err(|_| ApiError::internal("argon2"))??;
            Some(Personal(phc))
        }
        None => None,
    };
    let now = c.st.now();
    match c.p.credential {
        // The user, through their own session: the store derives the user from it.
        Credential::Session(session) if id == c.p.user && (name.is_some() || phc.is_some()) => {
            let who = tx
                .users()
                .update_own(session, name.as_ref(), phc.as_ref(), now)
                .await?;
            if who != Some(id) {
                return Err(ApiError::expired());
            }
        }
        // An administrator (or an API key, even the user's own): this account's sole
        // members only; the store refuses a user of another account too.
        _ => {
            if let Some(n) = &name {
                tx.users().rename(id, n).await?;
            }
            if let Some(phc) = &phc {
                tx.users().set_password_hash(id, phc).await?;
                tx.sessions().revoke_all(id, now).await?;
            }
        }
    }
    if phc.is_some() {
        security_notice(&mut tx, id, SecurityNotice::PasswordChanged, now).await?;
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
    let target = tx.users().get(id).await?.ok_or_else(ApiError::not_found)?;
    outranks(&c, &mut tx, &target).await?;
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

pub(crate) fn cookie(name: &str, value: &str, max_age: u64, secure: bool) -> Option<HeaderValue> {
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
        session_cookie(st.config().secure_cookies),
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
    let secure = c.st.config().secure_cookies;
    if let Some(v) = cookie(session_cookie(secure), "", 0, secure) {
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
            "second_factor": c.p.second_factor.as_str(),
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

/// What [`bootstrap`] or [`bootstrap_workspace`] made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bootstrapped {
    /// The organization the account is a workspace of.
    pub organization: OrganizationId,
    /// The account (workspace).
    pub account: AccountId,
    /// Its first administrator.
    pub admin: UserId,
    /// The built-in profiles: admin, sender, viewer.
    pub profiles: [PermissionProfileId; 3],
}

pub(crate) fn new_profiles() -> BuiltinProfiles {
    BuiltinProfiles {
        admin: PermissionProfileId(Uuid::now_v7()),
        sender: PermissionProfileId(Uuid::now_v7()),
        viewer: PermissionProfileId(Uuid::now_v7()),
    }
}

/// The first organization of an install, its first workspace with the built-in
/// permission profiles, and a first administrator who logs in with `password` and owns
/// the organization (the `bootstrap` command of the binary). Refused once any
/// organization exists (docs/23 §2.1): later ones come from the platform console.
///
/// # Errors
///
/// Store errors (`CS-DB-0006` when an organization exists); `CS-API-0001` for a password
/// outside 12 to 256 characters, or `common_password` for one on the breached list.
pub async fn bootstrap(
    store: &Store,
    name: &str,
    admin_email: &str,
    admin_name: &str,
    password: &str,
) -> Result<Bootstrapped, ApiError> {
    check_password(password)?;
    let email = normalize_email(admin_email)?;
    let phc = phc_of(password).await?;
    let organization = OrganizationId(Uuid::now_v7());
    let account = AccountId(Uuid::now_v7());
    let profiles = new_profiles();
    let tx = store
        .bootstrap_organization(organization, account, name, &profiles)
        .await?;
    let b = first_admin(
        tx,
        organization,
        account,
        profiles,
        admin_email,
        email,
        admin_name,
        phc,
        true,
    )
    .await?;
    Ok(b)
}

/// A new workspace of an existing organization, with its built-in profiles and a first
/// administrator of the workspace (who gets no organization role), in one transaction. The caller must have
/// established its right to create workspaces in `organization`; until ORG-03's routes,
/// tests and the console's organization creation are the callers.
///
/// # Errors
///
/// Store errors (`CS-DB-0003` when the organization is not active); `CS-API-0001` for a
/// password outside 12 to 256 characters, or `common_password` for one on the breached
/// list.
pub async fn bootstrap_workspace(
    store: &Store,
    organization: OrganizationId,
    name: &str,
    admin_email: &str,
    admin_name: &str,
    password: &str,
) -> Result<Bootstrapped, ApiError> {
    check_password(password)?;
    let email = normalize_email(admin_email)?;
    let phc = phc_of(password).await?;
    let account = AccountId(Uuid::now_v7());
    let profiles = new_profiles();
    // One transaction: a failing first administrator (a duplicate email, say) leaves no
    // workspace behind (ORG-02 review).
    let mut org = store.for_organization(organization).begin().await?;
    let proof = org.create_workspace(account, name, &profiles).await?;
    let tx = org.into_workspace(&proof).await?;
    first_admin(
        tx,
        organization,
        account,
        profiles,
        admin_email,
        email,
        admin_name,
        phc,
        false,
    )
    .await
}

async fn phc_of(password: &str) -> Result<String, ApiError> {
    let pw = password.to_owned();
    tokio::task::spawn_blocking(move || hash_password(&pw))
        .await
        .map_err(|_| ApiError::internal("argon2"))?
}

#[allow(clippy::too_many_arguments)] // One private helper of the two bootstrap paths.
async fn first_admin(
    mut tx: TenantTx,
    organization: OrganizationId,
    account: AccountId,
    profiles: BuiltinProfiles,
    admin_email: &str,
    email: String,
    admin_name: &str,
    phc: String,
    owner: bool,
) -> Result<Bootstrapped, ApiError> {
    let admin = UserId(Uuid::now_v7());
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
            profiles.admin,
        )
        .await?;
    tx.users().set_password_hash(admin, &Personal(phc)).await?;
    if owner {
        tx.account()
            .make_first_owner(admin, OffsetDateTime::now_utc())
            .await?;
    }
    tx.commit().await?;
    Ok(Bootstrapped {
        organization,
        account,
        admin,
        profiles: [profiles.admin, profiles.sender, profiles.viewer],
    })
}

#[allow(dead_code)]
fn _csrf_header_is_documented() -> &'static str {
    let _ = same;
    CSRF_HEADER
}

// One's own profile (UXW-37) ----------------------------------------------------------

/// Every notice a member can turn on or off, with its default.
const NOTICES: &[(&str, bool)] = &[("completed", true), ("declined", true), ("viewed", false)];

/// At most this many bytes of a saved signature or initials image (the table's limit).
const MARK_MAX: usize = 5 * 1024 * 1024;

/// The longest base64 text of a [`MARK_MAX`] image.
const MARK_B64_MAX: usize = MARK_MAX.div_ceil(3) * 4;

fn notices_json(saved: Option<&Value>) -> Value {
    let mut out = serde_json::Map::new();
    for (k, default) in NOTICES {
        let v = saved
            .and_then(|s| s.get(*k))
            .and_then(Value::as_bool)
            .unwrap_or(*default);
        out.insert((*k).to_owned(), Value::Bool(v));
    }
    Value::Object(out)
}

fn mark_json(m: Option<&Personal<Vec<u8>>>) -> Value {
    use base64::Engine as _;
    m.map_or(
        Value::Null,
        |m| json!({ "image_base64": base64::engine::general_purpose::STANDARD.encode(m.get()) }),
    )
}

/// A saved mark from a request: `null` removes it; `{image_base64}` is a PNG or JPEG.
fn mark_in(v: &Value, pointer: &str) -> Result<Option<Personal<Vec<u8>>>, ApiError> {
    use base64::Engine as _;
    if v.is_null() {
        return Ok(None);
    }
    let bad = || ApiError::invalid(pointer);
    let obj = v.as_object().filter(|o| o.len() == 1).ok_or_else(bad)?;
    let s = obj
        .get("image_base64")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= MARK_B64_MAX)
        .ok_or_else(bad)?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| bad())?;
    if raw.is_empty() || raw.len() > MARK_MAX {
        return Err(bad());
    }
    Ok(Some(Personal(raw)))
}

/// A saved mark is a PNG or a JPEG by its signature: checked after the malware scan,
/// which comes before anything else reads an upload (ASVS-11).
fn mark_type(raw: &[u8], pointer: &str) -> Result<(), ApiError> {
    let png = raw.starts_with(b"\x89PNG\r\n\x1a\n");
    let jpeg = raw.starts_with(b"\xff\xd8\xff");
    if png || jpeg {
        Ok(())
    } else {
        Err(ApiError::invalid(pointer))
    }
}

async fn me_json(c: &Call, tx: &mut TenantTx) -> Result<Value, ApiError> {
    let m = tx
        .users()
        .get(c.p.user)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let p = tx.users().member_profile(c.p.user).await?;
    Ok(json!({
        "id": m.user_id.to_string(), "name": m.name.get(), "email": m.email.get(),
        "notifications": notices_json(p.as_ref().map(|p| &p.notifications)),
        "signature": mark_json(p.as_ref().and_then(|p| p.signature.as_ref())),
        "initials": mark_json(p.as_ref().and_then(|p| p.initials.as_ref())),
    }))
}

/// `GET /users/me` (UXW-37): the signed-in user's own profile `{id, name, email,
/// notifications {completed, declined, viewed}, signature, initials}`, each mark
/// `{image_base64}` or null. Personal data, to its own user only.
pub(crate) async fn me(c: Call) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let v = me_json(&c, &mut tx).await?;
    tx.commit().await?;
    Ok(json(StatusCode::OK, &v))
}

/// `{"a": null}` is `Some(Null)`, an absent member `None`.
fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(d).map(Some)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MePatch {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    notifications: Option<serde_json::Map<String, Value>>,
    #[serde(default, deserialize_with = "present")]
    signature: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    initials: Option<Value>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    current_password: Option<String>,
}

/// `PATCH /users/me {name?, notifications?, signature?, initials?, password?,
/// current_password?}` (UXW-37). Notices and marks are this account's; the name and the
/// password are the user's in every account, so they change only through the user's own
/// session (SEC-ID-01). A new password needs the current one (`401 CS-AUTH-0007` when
/// wrong) and ends every other session of the user, in every account; this one stays.
pub(crate) async fn patch_me(c: Call, body: Bytes) -> Result<Response, ApiError> {
    let req: MePatch = parse(&body)?;
    let session = match c.p.credential {
        Credential::Session(s) => Some(s),
        _ => None,
    };
    if req.current_password.is_some() && req.password.is_none() {
        return Err(ApiError::invalid("/current_password"));
    }
    let name = match &req.name {
        Some(n) => {
            let n = n.trim();
            if n.is_empty() || n.chars().count() > 255 {
                return Err(ApiError::invalid("/name"));
            }
            Some(Personal(n.to_owned()))
        }
        None => None,
    };
    if let Some(n) = &req.notifications
        && n.iter()
            .any(|(k, v)| !NOTICES.iter().any(|(x, _)| x == k) || !v.is_boolean())
    {
        return Err(ApiError::invalid("/notifications"));
    }
    let signature = req
        .signature
        .as_ref()
        .map(|v| mark_in(v, "/signature"))
        .transpose()?;
    let initials = req
        .initials
        .as_ref()
        .map(|v| mark_in(v, "/initials"))
        .transpose()?;
    // Each saved mark is scanned before anything else reads it, its type included, and
    // before any transaction opens (ASVS-11).
    for (m, at) in [(&signature, "/signature"), (&initials, "/initials")] {
        if let Some(Some(m)) = m {
            crate::scan::screen(
                &c.st,
                c.uploader(),
                casual_sign_store::UploadKind::ProfileMark,
                vec![("user", c.p.user.to_string())],
                m.get(),
            )
            .await?;
            mark_type(m.get(), at)?;
        }
    }
    if session.is_none() && (name.is_some() || req.password.is_some()) {
        return Err(ApiError::invalid("/credential"));
    }
    let now = c.st.now();
    let mut tx = c.tx().await?;
    if let (Some(s), Some(new)) = (session, req.password.clone()) {
        let per = c.st.config().rate.login_per_minute;
        let key = casual_sign_audit::Hash256(sha256(c.p.user.to_string().as_bytes())).hex();
        if let Err(r) = limit(&c.st, "login", &format!("password-change:{key}"), per) {
            return Ok(r);
        }
        check_password(&new)?;
        let current = req.current_password.clone().unwrap_or_default();
        let stored = tx.users().own_password_hash(s, now).await?;
        let dummy = c.st.0.dummy_phc.clone();
        let phc = stored.as_ref().map(|p| p.get().clone());
        let verified = tokio::task::spawn_blocking(move || {
            let ok = verify_password(&current, phc.as_deref().unwrap_or(&dummy));
            ok.then(|| hash_password(&new))
        })
        .await
        .map_err(|_| ApiError::internal("argon2"))?;
        let (Some(stored), Some(new_phc)) = (stored, verified) else {
            return Err(ApiError::bad_credentials());
        };
        let who = tx
            .users()
            .change_own_password(s, &stored, &Personal(new_phc?), now)
            .await?;
        if who != Some(c.p.user) {
            return Err(ApiError::expired());
        }
        security_notice(&mut tx, c.p.user, SecurityNotice::PasswordChanged, now).await?;
    }
    if let (Some(s), Some(n)) = (session, &name) {
        let who = tx.users().update_own(s, Some(n), None, now).await?;
        if who != Some(c.p.user) {
            return Err(ApiError::expired());
        }
    }
    if req.notifications.is_some() || signature.is_some() || initials.is_some() {
        let old = tx.users().member_profile(c.p.user).await?;
        let mut notices = notices_json(old.as_ref().map(|p| &p.notifications));
        if let (Some(n), Some(o)) = (&req.notifications, notices.as_object_mut()) {
            for (k, v) in n {
                o.insert(k.clone(), v.clone());
            }
        }
        let p = casual_sign_store::repo::accounts::MemberProfile {
            notifications: notices,
            signature: signature.unwrap_or_else(|| old.as_ref().and_then(|p| p.signature.clone())),
            initials: initials.unwrap_or_else(|| old.as_ref().and_then(|p| p.initials.clone())),
        };
        tx.users().set_member_profile(c.p.user, &p, now).await?;
    }
    let v = me_json(&c, &mut tx).await?;
    tx.commit().await?;
    Ok(json(StatusCode::OK, &v))
}

// Password reset (UXW-38) ---------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResetIn {
    email: String,
}

/// `POST /auth/password-reset {email}` (UXW-38), no session: `202 {}` for any
/// well-formed address, so the answer never tells whether it has an account. For a
/// local, enabled user it records a reset and queues the job that emails the one-time
/// link (the worker draws the token and stores only its SHA-256, for an hour). Rate
/// limited as login, per address and per client; at most one email a minute per user.
pub(crate) async fn password_reset(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    body: Bytes,
) -> Response {
    match reset_inner(&st, ip, &body).await {
        Ok(r) | Err(r) => r,
    }
}

async fn reset_inner(st: &AppState, ip: ClientIp, body: &[u8]) -> Result<Response, Response> {
    let req: ResetIn = parse(body).map_err(IntoResponse::into_response)?;
    let email = normalize_email(&req.email).map_err(IntoResponse::into_response)?;
    login_limit(st, ip, &format!("password-reset:{email}"))?;
    let now = st.now();
    let reset = casual_sign_store::PasswordResetId(Uuid::now_v7());
    // The reset and its job are one statement whether or not the address has an
    // account, so the answer takes as long either way (SEC-A13, UXW-38C).
    let job = casual_sign_host::jobs::password_reset_job(
        casual_sign_store::JobId(Uuid::now_v7()),
        reset.0,
        now,
    );
    st.store()
        .entry_points()
        .request_password_reset(&email, reset, &job, now)
        .await
        .map_err(|e| ApiError::from(e).into_response())?;
    Ok(json(StatusCode::ACCEPTED, &json!({})))
}

/// `POST /auth/password-reset/confirm {token, password}` (UXW-38): spend the emailed
/// link once and set the user's password; their sessions end in every account. An
/// unknown, expired, spent or revoked link is `401 CS-AUTH-0002`, all alike.
pub(crate) async fn password_reset_confirm(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    body: Bytes,
) -> Response {
    match confirm_inner(&st, ip, &body).await {
        Ok(r) | Err(r) => r,
    }
}

async fn confirm_inner(st: &AppState, ip: ClientIp, body: &[u8]) -> Result<Response, Response> {
    let req: AcceptIn = parse(body).map_err(IntoResponse::into_response)?;
    login_limit(st, ip, "password-reset-confirm")?;
    let refuse = || ApiError::expired().into_response();
    if req.token.is_empty() || req.token.len() > 128 {
        return Err(refuse());
    }
    check_password(&req.password).map_err(IntoResponse::into_response)?;
    let now = st.now();
    let found = st
        .store()
        .entry_points()
        .resolve_password_reset(&sha256(req.token.as_bytes()), now)
        .await
        .map_err(|e| ApiError::from(e).into_response())?;
    let Some((account, reset, user)) = found else {
        return Err(refuse());
    };
    let password = req.password.clone();
    let phc = tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(|_| ApiError::internal("argon2").into_response())?
        .map_err(IntoResponse::into_response)?;
    let inner = async {
        let mut tx = st.store().for_account(account).begin().await?;
        let who = tx
            .users()
            .use_password_reset(reset, &Personal(phc), now)
            .await?;
        if who != Some(user) {
            return Ok(false);
        }
        security_notice(&mut tx, user, SecurityNotice::PasswordReset, now).await?;
        tx.commit().await?;
        Ok::<_, casual_sign_store::StoreError>(true)
    };
    match inner.await {
        Ok(true) => Ok(json(
            StatusCode::OK,
            &json!({"account_id": account.to_string(), "user_id": user.to_string()}),
        )),
        Ok(false) => Err(refuse()),
        Err(e) => Err(ApiError::from(e).into_response()),
    }
}

/// `GET /auth/providers` (UXW-39), no session: the SSO identity providers sign-in
/// offers, `{items: [{id, name, url}]}`. Empty until SSO is built (FG-173).
pub(crate) async fn providers() -> Response {
    json(StatusCode::OK, &json!({ "items": [] }))
}
