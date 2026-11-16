//! The console API's handlers (`/console/v1`, `api/console-openapi.yaml`).
//!
//! Every handler that reads or writes anything takes an [`Authed`] whose type names the
//! roles allowed; every write runs a definer function that re-checks the session, and
//! appends its operator event in the same transaction. Responses carry ids, names of
//! organizations and workspaces (tenant metadata), statuses, labels and counts: never a
//! tenant user's e-mail or name, a document, a field value or a job payload.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Path, Query, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use casual_sign_platform_store::{
    Detail, EventDraft, NewOperator, OrgAction, OrgScope, Role, StoredEvent,
};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::auth::{AnyOperator, Authed, Ctx, Operators, Owners, Pending, hex, session_cookie};
use crate::crypto::{
    MAX_PASSWORD_BYTES, hash_password, password_acceptable, random_bytes, random_secret, sha256,
    verify_password,
};
use crate::error::ConsoleError;
use crate::security::SecSlot;
use crate::state::AppState;
use crate::totp;

/// How long an enrolment link lasts.
pub const ENROLMENT_TTL: time::Duration = time::Duration::hours(24);

/// A JSON body; anything else, or malformed JSON, is `CS-CON-0010` (and a non-JSON
/// content type cannot be sent cross-site without a preflight, so the sign-in routes need
/// no CSRF token).
pub struct Body<T>(pub T);

impl<T> core::fmt::Debug for Body<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Body(..)")
    }
}

/// A request body holding a secret: its `Debug` names the type only.
macro_rules! redacted_debug {
    ($($t:ident),*) => {$(
        impl core::fmt::Debug for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($t), "(..)"))
            }
        }
    )*};
}
redacted_debug!(Login, Code, EnrolBegin, EnrolFinish);

impl<T: DeserializeOwned, S: Send + Sync> FromRequest<S> for Body<T> {
    type Rejection = ConsoleError;

    async fn from_request(req: Request, state: &S) -> Result<Self, ConsoleError> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(v)) => Ok(Self(v)),
            Err(JsonRejection::MissingJsonContentType(_)) => Err(ConsoleError::Csrf),
            Err(_) => Err(ConsoleError::Invalid("body")),
        }
    }
}

pub(crate) fn rfc3339(t: OffsetDateTime) -> Value {
    t.format(&Rfc3339).map_or(Value::Null, Value::String)
}

pub(crate) fn opt_time(t: Option<OffsetDateTime>) -> Value {
    t.map_or(Value::Null, rfc3339)
}

/// Normalize and check an operator e-mail.
fn email(raw: &str) -> Result<String, ConsoleError> {
    let e = raw.trim().to_lowercase();
    let ok = (3..=254).contains(&e.len())
        && e.find('@')
            .is_some_and(|i| i > 0 && i < e.len().saturating_sub(1))
        && !e.chars().any(|c| c.is_whitespace() || c.is_control());
    if ok {
        Ok(e)
    } else {
        Err(ConsoleError::Invalid("email"))
    }
}

async fn spawn<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, ConsoleError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| ConsoleError::Internal("blocking task"))
}

/// Append one event in its own transaction (sign-in records, refusals).
async fn record(state: &AppState, draft: EventDraft) -> Result<(), ConsoleError> {
    let mut tx = state.store().begin().await?;
    tx.append(&draft).await?;
    tx.commit().await?;
    Ok(())
}

/// The outcome of [`casual_sign_platform_store::PlatformTx::append_on`] after a write
/// that found its target: no organization at that point means it vanished between the
/// write and its copy, and the transaction must not commit.
fn copied(copy: Option<(Uuid, u64)>) -> Result<(), ConsoleError> {
    copy.map(|_| ()).ok_or(ConsoleError::NotFound)
}

pub(crate) fn event(
    action: &str,
    operator: Option<Uuid>,
    ctx: &Ctx,
    now: OffsetDateTime,
) -> EventDraft {
    EventDraft::new(action, operator, now).from_request(ctx.request, ctx.ip_text())
}

// Ops ---------------------------------------------------------------------------------

/// `GET /livez`: the process is up.
pub async fn livez() -> StatusCode {
    StatusCode::NO_CONTENT
}

/// `GET /readyz`: the database answers.
pub async fn readyz(State(state): State<AppState>) -> StatusCode {
    match state.store().ping().await {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

// Sign-in ------------------------------------------------------------------------------

/// Sign-in body.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Login {
    email: String,
    password: String,
}

/// `POST /console/v1/auth/login`: check the password; a session that reaches nothing
/// until `POST /auth/totp`.
pub async fn login(State(state): State<AppState>, req: Request) -> Result<Response, ConsoleError> {
    let ctx = req.extensions().get::<Ctx>().copied().unwrap_or(Ctx {
        request: Uuid::nil(),
        ip: None,
    });
    let slot = req
        .extensions()
        .get::<SecSlot>()
        .cloned()
        .unwrap_or_default();
    let Body(body) = Body::<Login>::from_request(req, &state).await?;
    slot.identify(crate::security::subject_email(&state, &body.email));
    let now = state.now();
    let rate = state.config().rate;
    let ip_key = ctx.ip.map_or_else(|| "none".to_owned(), |i| i.to_string());
    state
        .0
        .limiter
        .hit(&format!("login-ip:{ip_key}"), rate.login_per_ip, now)?;
    let email = email(&body.email).unwrap_or_default();
    state.0.limiter.hit(
        &format!("login-email:{}", hex(&sha256(email.as_bytes()))),
        rate.login_per_email,
        now,
    )?;
    if body.password.len() > MAX_PASSWORD_BYTES {
        return Err(ConsoleError::Invalid("password"));
    }
    let found = if email.is_empty() {
        None
    } else {
        state.store().operator_login(&email).await?
    };
    let phc = found
        .as_ref()
        .and_then(|o| o.password_hash.clone())
        .unwrap_or_else(|| state.0.dummy_phc.clone());
    let password = body.password;
    let matches = spawn(move || verify_password(&password, &phc)).await?;
    let operator = match found {
        Some(o) if matches && !o.disabled && o.password_hash.is_some() => o.id,
        other => {
            let who = other.map(|o| o.id);
            record(
                &state,
                event("operator.sign_in_refused", who, &ctx, now)
                    .with("step", Detail::Code("password".into())),
            )
            .await?;
            return Err(ConsoleError::NotAuthenticated);
        }
    };
    slot.identify(casual_sign_seclog::Principal::Operator(operator));
    let token = random_secret()?;
    let csrf = random_secret()?;
    let ttl = time::Duration::try_from(state.config().session_ttl)
        .map_err(|_| ConsoleError::Internal("ttl"))?;
    let expires = now.checked_add(ttl).ok_or(ConsoleError::Internal("time"))?;
    let mut tx = state.store().begin().await?;
    let opened = tx
        .open_session(
            operator,
            &sha256(token.as_bytes()),
            &sha256(csrf.as_bytes()),
            ctx.ip_text().as_deref(),
            now,
            expires,
        )
        .await?;
    if !opened {
        drop(tx);
        record(
            &state,
            event("operator.sign_in_refused", Some(operator), &ctx, now)
                .with("step", Detail::Code("session".into())),
        )
        .await?;
        return Err(ConsoleError::NotAuthenticated);
    }
    tx.append(&event("operator.session_opened", Some(operator), &ctx, now))
        .await?;
    tx.commit().await?;
    let mut resp = Json(json!({ "csrf_token": csrf, "second_factor": "totp" })).into_response();
    let max_age = state.config().session_ttl.as_secs();
    if let Ok(v) = HeaderValue::from_str(&session_cookie(&token, max_age)) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    Ok(resp)
}

/// TOTP body.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Code {
    code: String,
}

/// `POST /console/v1/auth/totp`: the second factor, at sign-in and as the re-entry
/// sensitive actions need. Each code is single-use.
pub async fn totp_step(
    State(state): State<AppState>,
    slot: SecSlot,
    pending: Pending,
    Body(body): Body<Code>,
) -> Result<Json<Value>, ConsoleError> {
    let now = state.now();
    state.0.limiter.hit(
        &format!("totp:{}", pending.id),
        state.config().rate.totp_per_operator,
        now,
    )?;
    let sealed = state
        .store()
        .operator_seed(pending.id)
        .await?
        .ok_or(ConsoleError::SecondFactor)?;
    let seed = state.0.mfa.open(pending.id, &sealed)?;
    let step = totp::matching_step(&seed, body.code.trim(), totp::step_at(now.unix_timestamp()));
    let mut tx = state.store().begin().await?;
    let accepted = match step {
        Some(step) => tx.confirm_mfa(&pending.token_sha256, step, now).await?,
        None => false,
    };
    if !accepted {
        drop(tx);
        // ASVS 2.8.5: the code matched a step already used.
        slot.reason(if step.is_some() { "reused" } else { "wrong" });
        record(
            &state,
            event(
                "operator.sign_in_refused",
                Some(pending.id),
                &pending.ctx,
                now,
            )
            .with("step", Detail::Code("totp".into())),
        )
        .await?;
        return Err(ConsoleError::SecondFactor);
    }
    tx.append(&event(
        "operator.signed_in",
        Some(pending.id),
        &pending.ctx,
        now,
    ))
    .await?;
    tx.commit().await?;
    let session = state
        .store()
        .resolve_session(&pending.token_sha256, now)
        .await?
        .ok_or(ConsoleError::NotAuthenticated)?;
    Ok(Json(json!({
        "operator": pending.id,
        "roles": session.roles.iter().map(|r| r.as_str()).collect::<Vec<_>>(),
        "expires_at": rfc3339(session.expires_at),
    })))
}

/// `POST /console/v1/auth/logout`.
pub async fn logout(
    State(state): State<AppState>,
    pending: Pending,
) -> Result<Response, ConsoleError> {
    let now = state.now();
    let mut tx = state.store().begin().await?;
    tx.revoke_session(&pending.token_sha256, now).await?;
    tx.append(&event(
        "operator.signed_out",
        Some(pending.id),
        &pending.ctx,
        now,
    ))
    .await?;
    tx.commit().await?;
    let mut resp = StatusCode::NO_CONTENT.into_response();
    if let Ok(v) = HeaderValue::from_str(&session_cookie("", 0)) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    Ok(resp)
}

/// Enrolment step 1 body.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolBegin {
    token: String,
}

fn enrol_token(raw: &str) -> Result<[u8; 32], ConsoleError> {
    if raw.is_empty() || raw.len() > 64 {
        return Err(ConsoleError::NotAuthenticated);
    }
    Ok(sha256(raw.as_bytes()))
}

/// `POST /console/v1/auth/enrolment/begin`: a fresh TOTP seed for the operator the link
/// names, shown once as an `otpauth://` URI.
pub async fn enrol_begin(
    State(state): State<AppState>,
    req: Request,
) -> Result<Json<Value>, ConsoleError> {
    let ctx = req.extensions().get::<Ctx>().copied().unwrap_or(Ctx {
        request: Uuid::nil(),
        ip: None,
    });
    let Body(body) = Body::<EnrolBegin>::from_request(req, &state).await?;
    let now = state.now();
    let ip_key = ctx.ip.map_or_else(|| "none".to_owned(), |i| i.to_string());
    state.0.limiter.hit(
        &format!("login-ip:{ip_key}"),
        state.config().rate.login_per_ip,
        now,
    )?;
    let token = enrol_token(&body.token)?;
    let (operator, _) = state
        .store()
        .pending_enrolment(&token, now)
        .await?
        .ok_or(ConsoleError::NotAuthenticated)?;
    let seed = random_bytes::<{ totp::SEED_BYTES }>()?;
    let sealed = state.0.mfa.seal(operator, &seed)?;
    let mut tx = state.store().begin().await?;
    let id = tx
        .begin_enrolment(&token, &sealed, now)
        .await?
        .ok_or(ConsoleError::NotAuthenticated)?;
    tx.commit().await?;
    Ok(Json(
        json!({ "operator": id, "otpauth_uri": totp::otpauth_uri(&seed, id) }),
    ))
}

/// Enrolment step 2 body.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolFinish {
    token: String,
    password: String,
    code: String,
}

/// `POST /console/v1/auth/enrolment/finish`: the operator sets their password and proves
/// the seed with a code; the link is spent.
pub async fn enrol_finish(
    State(state): State<AppState>,
    req: Request,
) -> Result<StatusCode, ConsoleError> {
    let ctx = req.extensions().get::<Ctx>().copied().unwrap_or(Ctx {
        request: Uuid::nil(),
        ip: None,
    });
    let slot = req
        .extensions()
        .get::<SecSlot>()
        .cloned()
        .unwrap_or_default();
    let Body(body) = Body::<EnrolFinish>::from_request(req, &state).await?;
    let now = state.now();
    let ip_key = ctx.ip.map_or_else(|| "none".to_owned(), |i| i.to_string());
    state.0.limiter.hit(
        &format!("login-ip:{ip_key}"),
        state.config().rate.login_per_ip,
        now,
    )?;
    if !password_acceptable(&body.password) {
        return Err(ConsoleError::Invalid("password"));
    }
    let token = enrol_token(&body.token)?;
    let (operator, sealed) = state
        .store()
        .pending_enrolment(&token, now)
        .await?
        .ok_or(ConsoleError::NotAuthenticated)?;
    let sealed = sealed.ok_or(ConsoleError::SecondFactor)?;
    let seed = state.0.mfa.open(operator, &sealed)?;
    let step = totp::matching_step(&seed, body.code.trim(), totp::step_at(now.unix_timestamp()))
        .ok_or(ConsoleError::SecondFactor)?;
    let password = body.password;
    let phc = spawn(move || hash_password(&password)).await??;
    let mut tx = state.store().begin().await?;
    let id = tx
        .finish_enrolment(&token, &phc, step, now)
        .await?
        .ok_or(ConsoleError::NotAuthenticated)?;
    slot.identify(casual_sign_seclog::Principal::Operator(id));
    tx.append(&event("operator.enrolled", Some(id), &ctx, now))
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /console/v1/me`.
pub async fn me(op: Authed<AnyOperator>) -> Json<Value> {
    Json(json!({
        "operator": op.id,
        "roles": op.roles.iter().map(|r| r.as_str()).collect::<Vec<_>>(),
    }))
}

// Operators ----------------------------------------------------------------------------

/// `GET /console/v1/operators` (platform owners).
pub async fn operators(
    State(state): State<AppState>,
    _op: Authed<Owners>,
) -> Result<Json<Value>, ConsoleError> {
    let list = state.store().operators().await?;
    Ok(Json(json!({
        "operators": list.iter().map(|o| json!({
            "id": o.id,
            "email": o.email,
            "roles": o.roles.iter().map(|r| r.as_str()).collect::<Vec<_>>(),
            "created_at": rfc3339(o.created_at),
            "disabled_at": opt_time(o.disabled_at),
        })).collect::<Vec<_>>(),
    })))
}

/// New operator body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewOperatorBody {
    email: String,
    roles: Vec<String>,
}

/// `POST /console/v1/operators` (platform owners): a new operator and their one-time
/// enrolment token, which the owner passes on; the owner never knows the operator's
/// password or second factor.
pub async fn create_operator(
    State(state): State<AppState>,
    op: Authed<Owners>,
    Body(body): Body<NewOperatorBody>,
) -> Result<Response, ConsoleError> {
    let email = email(&body.email)?;
    let mut roles = Vec::new();
    for r in &body.roles {
        let role = Role::parse(r).ok_or(ConsoleError::Invalid("roles"))?;
        if !roles.contains(&role) {
            roles.push(role);
        }
    }
    if roles.is_empty() {
        return Err(ConsoleError::Invalid("roles"));
    }
    let now = state.now();
    let token = random_secret()?;
    let id = Uuid::now_v7();
    let expires = now
        .checked_add(ENROLMENT_TTL)
        .ok_or(ConsoleError::Internal("time"))?;
    let new = NewOperator {
        id,
        email: &email,
        enrolment_sha256: sha256(token.as_bytes()),
        enrolment_expires: expires,
    };
    let mut tx = state.store().begin().await?;
    if !tx
        .create_operator(&op.token_sha256, &new, &roles, now)
        .await?
    {
        return Err(ConsoleError::Conflict);
    }
    tx.append(
        &event("operator.operator_created", Some(op.id), &op.ctx, now)
            .with("operator_id", Detail::Id(id))
            .with(
                "roles",
                Detail::Codes(roles.iter().map(|r| r.as_str().to_owned()).collect()),
            ),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(
            json!({ "id": id, "enrolment_token": token, "enrolment_expires_at": rfc3339(expires) }),
        ),
    )
        .into_response())
}

/// `POST /console/v1/operators/{id}/disable` (platform owners).
pub async fn disable_operator(
    State(state): State<AppState>,
    op: Authed<Owners>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ConsoleError> {
    let now = state.now();
    let mut tx = state.store().begin().await?;
    if !tx.disable_operator(&op.token_sha256, id, now).await? {
        return Err(ConsoleError::NotFound);
    }
    tx.append(
        &event("operator.operator_disabled", Some(op.id), &op.ctx, now)
            .with("operator_id", Detail::Id(id)),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// The operator log ----------------------------------------------------------------------

/// Paging.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogPage {
    after: Option<u64>,
    limit: Option<u32>,
}

fn event_json(e: &StoredEvent) -> Value {
    let body = String::from_utf8(e.canonical.clone())
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .unwrap_or(Value::Null);
    json!({
        "seq": e.seq,
        "hash": e.hash.hex(),
        "prev": e.prev.map(|h| h.hex()),
        "action": e.action,
        "operator": e.operator,
        "at": rfc3339(e.at),
        "event": body,
    })
}

/// `GET /console/v1/operator-log`.
pub async fn operator_log(
    State(state): State<AppState>,
    _op: Authed<Operators>,
    Query(q): Query<LogPage>,
) -> Result<Json<Value>, ConsoleError> {
    let events = state
        .store()
        .events(q.after, q.limit.unwrap_or(100))
        .await?;
    Ok(Json(json!({
        "events": events.iter().map(event_json).collect::<Vec<_>>(),
        "next_after": events.last().map(|e| e.seq),
    })))
}

/// `GET /console/v1/operator-log/verify`.
pub async fn verify_log(
    State(state): State<AppState>,
    _op: Authed<Operators>,
) -> Result<Json<Value>, ConsoleError> {
    let r = state.store().verify_log().await?;
    Ok(Json(
        json!({ "verified": true, "events": r.events, "head": r.head.map(|h| h.hex()) }),
    ))
}

// Organizations and workspaces ----------------------------------------------------------

/// Paging by id.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrgPage {
    after: Option<Uuid>,
    limit: Option<u32>,
}

fn org_json(o: &casual_sign_platform_store::OrganizationRow) -> Value {
    let mut v = json!({
        "id": o.id,
        "name": o.name,
        "status": o.status,
        "data_regions": o.data_regions,
        "created_at": rfc3339(o.created_at),
        "counts": { "workspaces": o.workspaces, "members": o.members, "envelopes": o.envelopes },
    });
    if let (Some(owners), Some(counts)) =
        (o.owners, v.get_mut("counts").and_then(Value::as_object_mut))
    {
        counts.insert("owners".into(), json!(owners));
    }
    v
}

/// `GET /console/v1/organizations`.
pub async fn organizations(
    State(state): State<AppState>,
    _op: Authed<AnyOperator>,
    Query(q): Query<OrgPage>,
) -> Result<Json<Value>, ConsoleError> {
    let list = state
        .store()
        .organizations(q.after, q.limit.unwrap_or(50))
        .await?;
    Ok(Json(json!({
        "organizations": list.iter().map(org_json).collect::<Vec<_>>(),
        "next_after": list.last().map(|o| o.id),
    })))
}

/// `GET /console/v1/organizations/{id}`: properties, counts and workspaces.
pub async fn organization(
    State(state): State<AppState>,
    _op: Authed<AnyOperator>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ConsoleError> {
    let o = state
        .store()
        .organization(id)
        .await?
        .ok_or(ConsoleError::NotFound)?;
    let ws = state.store().workspaces(id).await?;
    let mut v = org_json(&o);
    let workspaces = Value::Array(
        ws.iter()
            .map(|w| {
                json!({
                    "id": w.id,
                    "name": w.name,
                    "status": w.status,
                    "data_region": w.data_region,
                    "created_at": rfc3339(w.created_at),
                    "counts": {
                        "members": w.members,
                        "templates": w.templates,
                        "envelopes": w.envelopes,
                        "envelopes_draft": w.envelopes_draft,
                        "envelopes_in_progress": w.envelopes_in_progress,
                        "envelopes_completed": w.envelopes_completed,
                    },
                })
            })
            .collect(),
    );
    if let Some(obj) = v.as_object_mut() {
        obj.insert("workspaces".into(), workspaces);
    }
    Ok(Json(v))
}

fn only_keys(body: &Map<String, Value>, allowed: &[&'static str]) -> Result<(), ConsoleError> {
    if body.is_empty() {
        return Err(ConsoleError::Invalid("body"));
    }
    match body.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(_) => Err(ConsoleError::Invalid("body")),
        None => Ok(()),
    }
}

/// `PATCH /console/v1/organizations/{id}` (operators): `name`, `data_regions`.
pub async fn patch_organization(
    State(state): State<AppState>,
    op: Authed<Operators>,
    Path(id): Path<Uuid>,
    Body(body): Body<Map<String, Value>>,
) -> Result<StatusCode, ConsoleError> {
    only_keys(&body, &["name", "data_regions"])?;
    let name = match body.get("name") {
        None => None,
        Some(Value::String(n)) if (1..=255).contains(&n.trim().chars().count()) => {
            Some(n.trim().to_owned())
        }
        Some(_) => return Err(ConsoleError::Invalid("name")),
    };
    let regions = match body.get("data_regions") {
        None => None,
        Some(Value::Array(a)) => Some(
            a.iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .ok_or(ConsoleError::Invalid("data_regions"))
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Some(_) => return Err(ConsoleError::Invalid("data_regions")),
    };
    let now = state.now();
    let mut tx = state.store().begin().await?;
    if let Some(n) = &name {
        if !tx.rename_organization(&op.token_sha256, id, n, now).await? {
            return Err(ConsoleError::NotFound);
        }
        copied(
            tx.append_on(
                &op.token_sha256,
                OrgScope::Organization(id),
                &event("operator.organization.renamed", Some(op.id), &op.ctx, now)
                    .with("organization", Detail::Id(id)),
            )
            .await?,
        )?;
    }
    if let Some(r) = &regions {
        let found = tx
            .set_organization_regions(&op.token_sha256, id, r, now)
            .await
            .map_err(|e| match ConsoleError::from(e) {
                ConsoleError::Invalid(_) => ConsoleError::Invalid("data_regions"),
                other => other,
            })?;
        if !found {
            return Err(ConsoleError::NotFound);
        }
        copied(
            tx.append_on(
                &op.token_sha256,
                OrgScope::Organization(id),
                &event(
                    "operator.organization.regions_set",
                    Some(op.id),
                    &op.ctx,
                    now,
                )
                .with("organization", Detail::Id(id))
                .with("data_regions", Detail::Codes(r.clone())),
            )
            .await?,
        )?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `PATCH /console/v1/workspaces/{id}` (operators): `data_region` (a label of the
/// organization's, or null), `status` (`active` or `archived`).
pub async fn patch_workspace(
    State(state): State<AppState>,
    op: Authed<Operators>,
    Path(id): Path<Uuid>,
    Body(body): Body<Map<String, Value>>,
) -> Result<StatusCode, ConsoleError> {
    only_keys(&body, &["data_region", "status"])?;
    let region = match body.get("data_region") {
        None => None,
        Some(Value::Null) => Some(None),
        Some(Value::String(s)) => Some(Some(s.clone())),
        Some(_) => return Err(ConsoleError::Invalid("data_region")),
    };
    let status = match body.get("status") {
        None => None,
        Some(Value::String(s)) if s == "active" || s == "archived" => Some(s.clone()),
        Some(_) => return Err(ConsoleError::Invalid("status")),
    };
    let now = state.now();
    let mut tx = state.store().begin().await?;
    if let Some(r) = &region {
        let found = tx
            .set_workspace_region(&op.token_sha256, id, r.as_deref(), now)
            .await
            .map_err(|e| match ConsoleError::from(e) {
                ConsoleError::Invalid(_) => ConsoleError::Invalid("data_region"),
                other => other,
            })?;
        if !found {
            return Err(ConsoleError::NotFound);
        }
        let mut ev = event("operator.workspace.region_set", Some(op.id), &op.ctx, now)
            .with("workspace", Detail::Id(id));
        if let Some(label) = r {
            ev = ev.with("data_region", Detail::Code(label.clone()));
        }
        copied(
            tx.append_on(&op.token_sha256, OrgScope::Workspace(id), &ev)
                .await?,
        )?;
    }
    if let Some(s) = &status {
        if !tx
            .set_workspace_status(&op.token_sha256, id, s, now)
            .await?
        {
            return Err(ConsoleError::NotFound);
        }
        let action = if s == "archived" {
            "operator.workspace.archived"
        } else {
            "operator.workspace.restored"
        };
        copied(
            tx.append_on(
                &op.token_sha256,
                OrgScope::Workspace(id),
                &event(action, Some(op.id), &op.ctx, now).with("workspace", Detail::Id(id)),
            )
            .await?,
        )?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// Health ---------------------------------------------------------------------------------

/// `GET /console/v1/health`: database, job queue, dead letters, connections, configured
/// services, and whether the operator log verifies.
pub async fn health(
    State(state): State<AppState>,
    _op: Authed<AnyOperator>,
) -> Result<Json<Value>, ConsoleError> {
    let now = state.now();
    let store = state.store();
    let database = store.ping().await.is_ok();
    let jobs = store.job_stats(now).await?;
    let dead: i64 = jobs
        .iter()
        .filter(|j| j.status == "dead")
        .map(|j| j.jobs)
        .sum();
    let pool = store.pool_stats().await?;
    let targets = store.service_targets().await?;
    let services = crate::health::probe_all(targets, state.config().probe_timeout).await;
    let keyd = crate::keys::health(&state).await;
    let log = match store.verify_log().await {
        Ok(r) => json!({ "verified": true, "events": r.events }),
        Err(e) => json!({ "verified": false, "code": ConsoleError::from(e).code() }),
    };
    Ok(Json(json!({
        "at": rfc3339(now),
        "database": { "status": if database { "up" } else { "down" } },
        "jobs": jobs.iter().map(|j| json!({
            "kind": j.kind, "status": j.status, "jobs": j.jobs, "oldest_seconds": j.oldest_seconds,
        })).collect::<Vec<_>>(),
        "dead_letters": dead,
        "connections": pool.iter().map(|(s, n)| json!({ "state": s, "connections": n })).collect::<Vec<_>>(),
        "services": services,
        "keyd": keyd,
        "operator_log": log,
    })))
}

/// Limit.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limit {
    limit: Option<u32>,
}

/// `GET /console/v1/dead-letters`: ids, kind, workspace, envelope, error code, attempts
/// and time; never the payload.
pub async fn dead_letters(
    State(state): State<AppState>,
    _op: Authed<AnyOperator>,
    Query(q): Query<Limit>,
) -> Result<Json<Value>, ConsoleError> {
    let list = state.store().dead_jobs(q.limit.unwrap_or(50)).await?;
    Ok(Json(json!({
        "dead_letters": list.iter().map(|d| json!({
            "id": d.id, "kind": d.kind, "workspace_id": d.workspace_id, "envelope_id": d.envelope_id,
            "error_code": d.error_code, "attempts": d.attempts, "finished_at": opt_time(d.finished_at),
        })).collect::<Vec<_>>(),
    })))
}

/// `GET /console/v1/alerts`.
pub async fn alerts(
    State(state): State<AppState>,
    _op: Authed<AnyOperator>,
    Query(q): Query<Limit>,
) -> Result<Json<Value>, ConsoleError> {
    let list = state.store().alerts(q.limit.unwrap_or(50)).await?;
    Ok(Json(json!({
        "alerts": list.iter().map(|a| json!({
            "id": a.id, "at": rfc3339(a.at), "source": a.source, "code": a.code, "resolves": a.resolves,
        })).collect::<Vec<_>>(),
    })))
}

// Two-person actions -------------------------------------------------------------------

/// `GET /console/v1/approvals`: requests of the last day, newest first.
pub async fn approvals(
    State(state): State<AppState>,
    _op: Authed<Operators>,
) -> Result<Json<Value>, ConsoleError> {
    let now = state.now();
    // Organization actions only; key changes are the key custodians' (`GET /tsa`).
    let list: Vec<_> = state
        .store()
        .approvals(now)
        .await?
        .into_iter()
        .filter(|a| a.action.starts_with("organization."))
        .collect();
    Ok(Json(json!({
        "approvals": list.iter().map(|a| json!({
            "id": a.id,
            "requester": a.requester,
            "action": a.action,
            "organization": a.target,
            "created_at": rfc3339(a.created_at),
            "expires_at": rfc3339(a.expires_at),
            "approvers": a.approvers,
            "used": a.used,
            "live": !a.used && now < a.expires_at,
        })).collect::<Vec<_>>(),
    })))
}

/// New approval request body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalBody {
    action: String,
    organization: uuid::Uuid,
}

/// `POST /console/v1/approvals`: ask a second operator to approve a sensitive action
/// (step 1 of 3). Needs a second factor entered within 5 minutes.
pub async fn request_approval(
    State(state): State<AppState>,
    op: Authed<Operators>,
    Body(body): Body<ApprovalBody>,
) -> Result<Response, ConsoleError> {
    let action = OrgAction::parse(&body.action).ok_or(ConsoleError::Invalid("action"))?;
    let now = state.now();
    if state
        .store()
        .organization(body.organization)
        .await?
        .is_none()
    {
        return Err(ConsoleError::NotFound);
    }
    let id = Uuid::now_v7();
    let mut tx = state.store().begin().await?;
    tx.request_approval(&op.token_sha256, id, action, body.organization, now)
        .await?;
    tx.append(
        &event("operator.approval.requested", Some(op.id), &op.ctx, now)
            .with("approval", Detail::Id(id))
            .with("action", Detail::Code(action.as_str().to_owned()))
            .with("organization", Detail::Id(body.organization)),
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(json!({ "id": id }))).into_response())
}

/// `POST /console/v1/approvals/{id}/grant`: approve another operator's request (step 2).
pub async fn grant_approval(
    State(state): State<AppState>,
    op: Authed<Operators>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ConsoleError> {
    let now = state.now();
    let mut tx = state.store().begin().await?;
    if !tx.grant_approval(&op.token_sha256, id, now).await? {
        return Err(ConsoleError::NotFound);
    }
    tx.append(
        &event("operator.approval.granted", Some(op.id), &op.ctx, now)
            .with("approval", Detail::Id(id)),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Apply body: the approval to spend.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyBody {
    approval: uuid::Uuid,
}

async fn apply_org(
    state: &AppState,
    op: &Authed<Operators>,
    org: Uuid,
    approval: Uuid,
    action: OrgAction,
) -> Result<StatusCode, ConsoleError> {
    let now = state.now();
    let mut tx = state.store().begin().await?;
    if !tx
        .apply_org_action(&op.token_sha256, approval, action, org, now)
        .await?
    {
        return Err(ConsoleError::NotFound);
    }
    let name = match action {
        OrgAction::Suspend => "operator.organization.suspended",
        OrgAction::Resume => "operator.organization.resumed",
    };
    copied(
        tx.append_on(
            &op.token_sha256,
            OrgScope::Organization(org),
            &event(name, Some(op.id), &op.ctx, now)
                .with("organization", Detail::Id(org))
                .with("approval", Detail::Id(approval)),
        )
        .await?,
    )?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /console/v1/organizations/{id}/suspend` (step 3): with an approval granted by
/// another operator. New work in the organization is refused; envelopes already sent
/// continue (docs/23 §5.3).
pub async fn suspend_organization(
    State(state): State<AppState>,
    op: Authed<Operators>,
    Path(id): Path<Uuid>,
    Body(body): Body<ApplyBody>,
) -> Result<StatusCode, ConsoleError> {
    apply_org(&state, &op, id, body.approval, OrgAction::Suspend).await
}

/// `POST /console/v1/organizations/{id}/resume` (step 3).
pub async fn resume_organization(
    State(state): State<AppState>,
    op: Authed<Operators>,
    Path(id): Path<Uuid>,
    Body(body): Body<ApplyBody>,
) -> Result<StatusCode, ConsoleError> {
    apply_org(&state, &op, id, body.approval, OrgAction::Resume).await
}
