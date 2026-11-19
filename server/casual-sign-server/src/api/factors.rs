//! Staff passkeys (WebAuthn) as a second factor, a person's management of their own
//! factors, and an administrator's reset of a member's lost factors (CON-13, ASVS-32;
//! ASVS 2.3.2, 2.5.7; docs/40 §2, ADR-039).
//!
//! - `POST /auth/mfa/passkeys/options {purpose}`: a challenge for one ceremony
//!   (`register`, `verify` at sign-in, `reauthenticate` for step-up), kept on the session
//!   for five minutes and spent by the call that answers it, with the options the
//!   browser's `navigator.credentials.create` or `.get` takes.
//! - `POST /auth/mfa/passkeys {name, credential}`: register a passkey. As the first
//!   factor it is the enrolment a workspace's policy asks for, and shows ten recovery
//!   codes once; as a further one, the session must have passed its factor and
//!   re-authenticated within five minutes (a stolen session cannot add its own key).
//! - `GET /auth/mfa/passkeys`; `PATCH` and `DELETE /auth/mfa/passkeys/{id}`: list,
//!   rename and remove, the last two after a re-authentication (`403 CS-AUTH-0013`).
//! - `DELETE /auth/mfa/totp` and `POST /auth/mfa/recovery-codes`: remove the TOTP
//!   authenticator (to replace it), and replace the recovery codes, each after a
//!   re-authentication, which proves the current factor (ASVS-32).
//! - `POST /users/{id}/second-factor/reset {identity_verified_by}`: an administrator,
//!   from a session that re-authenticated within five minutes, resets a member who lost
//!   every factor (ASVS 2.5.7). The member must belong to this workspace alone
//!   (SEC-ID-01); their factors and recovery codes go, their sessions end, they enrol a
//!   new factor at their next sign-in whatever the policy, and they are told by email.
//!   The administrative log records how their identity was proved. There is no
//!   self-service path around a lost factor: a recovery code, or an administrator.
//!
//! Assertions are checked by [`crate::webauthn`]; a passkey's signature counter that
//! does not move is refused as a possible clone (`reason: counter`). Credentials, codes
//! and challenges are never logged.

use axum::body::Bytes;
use axum::extract::Path;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use casual_sign_host::jobs::SecurityNotice;
use casual_sign_seclog::{Kind, Value};
use casual_sign_store::repo::sessions::{NewPasskey, OwnFactors, Passkey};
use casual_sign_store::{StaffSessionId, TenantTx, UserId};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use super::admin::{member_in_scope, outranks, security_notice};
use super::envelopes::rfc3339;
use super::mfa::session;
use super::{json, path_id};
use crate::auth::{Credential, SecondFactor};
use crate::call::Call;
use crate::crypto::random_bytes;
use crate::dto::parse;
use crate::error::ApiError;
use crate::http::SecretBearing;
use crate::mfa::{RECOVERY_CODES, recovery_code, recovery_hash};
use crate::webauthn::{
    self, ALGORITHMS, Assertion, MAX_AUTHENTICATOR_DATA, MAX_CLIENT_DATA, MAX_CREDENTIAL_ID,
    MAX_PUBLIC_KEY, MAX_SIGNATURE, MAX_USER_HANDLE, Registration, RelyingParty, b64, unb64,
};

/// How long a ceremony's challenge holds (docs/21).
pub(crate) const CHALLENGE_SECS: i64 = 300;
/// Passkeys a person may hold (docs/21).
pub(crate) const MAX_PASSKEYS: usize = 10;

/// This server as a relying party; `409 CS-API-0014` when passkeys are unavailable (a
/// public URL whose host is an IP address).
pub(crate) fn rp(c: &Call) -> Result<RelyingParty, ApiError> {
    RelyingParty::from_public_url(
        &c.st.config().public_url,
        c.st.config().webauthn_rp_id.as_deref(),
    )
    .ok_or_else(ApiError::method_unavailable)
}

/// The user handle of a staff user's passkeys: their id's 16 bytes (no personal data).
fn user_handle(user: UserId) -> [u8; 16] {
    *user.0.as_bytes()
}

/// Attempts per user per minute: the login limit (docs/21). `what` keeps challenges
/// apart from answers, so asking for options does not spend the answers' allowance.
fn limit_as(c: &Call, what: &str) -> Result<(), ApiError> {
    let d = c.st.0.limiter.hit(
        &format!("{what}:{}", c.p.user),
        c.st.config().rate.login_per_minute,
        c.st.now(),
    );
    if d.allowed {
        Ok(())
    } else {
        Err(ApiError::rate_limited(d.reset_secs))
    }
}

/// Second-factor answers per user per minute, shared with the TOTP step.
fn limit(c: &Call) -> Result<(), ApiError> {
    limit_as(c, "mfa")
}

/// A response that shows a secret once, or a challenge: never cached, never kept by
/// idempotency.
fn secret_json(status: StatusCode, v: &serde_json::Value) -> Response {
    let mut r = json(status, v);
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r.extensions_mut().insert(SecretBearing);
    r
}

async fn own_factors(
    tx: &mut TenantTx,
    s: StaffSessionId,
    c: &Call,
) -> Result<OwnFactors, ApiError> {
    tx.sessions()
        .own_factors(s, c.st.now())
        .await?
        .ok_or_else(ApiError::expired)
}

/// Adding to factors the user already has: only from a session that passed one, and
/// re-authenticated within five minutes.
fn may_add_to(c: &Call, f: &OwnFactors) -> Result<(), ApiError> {
    if f.any() {
        if c.p.second_factor != SecondFactor::Passed {
            return Err(ApiError::second_factor_required("verify"));
        }
        c.p.require_recent_auth(c.st.now())?;
    }
    Ok(())
}

fn passkey_json(k: &Passkey) -> serde_json::Value {
    json!({
        "id": k.id.to_string(),
        "name": k.name,
        "created_at": rfc3339(k.created_at),
        "last_used_at": k.last_used_at.map(rfc3339),
        "backup_eligible": k.backup_eligible,
    })
}

fn descriptor(k: &Passkey) -> serde_json::Value {
    json!({ "type": "public-key", "id": b64(&k.credential_id), "transports": k.transports })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OptionsIn {
    purpose: String,
}

/// `POST /auth/mfa/passkeys/options {purpose}`: the options for one WebAuthn ceremony,
/// its challenge kept on the session. `409 CS-API-0009` for `verify` or `reauthenticate`
/// without a passkey; `409 CS-API-0014` when passkeys are unavailable.
pub(crate) async fn options(c: Call, body: Bytes) -> Result<Response, ApiError> {
    let s = session(&c)?;
    limit_as(&c, "webauthn-options")?;
    let req: OptionsIn = parse(&body)?;
    let purpose: &'static str = match req.purpose.as_str() {
        "register" => "register",
        "verify" => "verify",
        "reauthenticate" => "reauthenticate",
        _ => return Err(ApiError::invalid("/purpose")),
    };
    let rp = rp(&c)?;
    let now = c.st.now();
    let mut tx = c.tx().await?;
    let f = own_factors(&mut tx, s, &c).await?;
    let keys = tx.sessions().own_passkeys(s, now).await?;
    let challenge = random_bytes::<32>()?;
    let options = if purpose == "register" {
        may_add_to(&c, &f)?;
        if keys.len() >= MAX_PASSKEYS {
            return Err(ApiError::not_available("too many passkeys"));
        }
        let me = tx
            .users()
            .get(f.user_id)
            .await?
            .ok_or_else(ApiError::expired)?;
        json!({
            "rp": { "id": rp.id(), "name": "OpenSeal" },
            "user": {
                "id": b64(&user_handle(f.user_id)),
                "name": me.email.get(),
                "displayName": me.name.get(),
            },
            "challenge": b64(&challenge),
            "pubKeyCredParams": ALGORITHMS
                .iter()
                .map(|a| json!({ "type": "public-key", "alg": a }))
                .collect::<Vec<_>>(),
            "timeout": CHALLENGE_SECS * 1000,
            "excludeCredentials": keys.iter().map(descriptor).collect::<Vec<_>>(),
            "authenticatorSelection": {
                "residentKey": "discouraged",
                "requireResidentKey": false,
                "userVerification": "preferred",
            },
            "attestation": "none",
        })
    } else {
        if keys.is_empty() {
            return Err(ApiError::not_available("no passkey"));
        }
        json!({
            "challenge": b64(&challenge),
            "rpId": rp.id(),
            "allowCredentials": keys.iter().map(descriptor).collect::<Vec<_>>(),
            "userVerification": "preferred",
            "timeout": CHALLENGE_SECS * 1000,
        })
    };
    let until = now
        .checked_add(time::Duration::seconds(CHALLENGE_SECS))
        .ok_or_else(|| ApiError::internal("time"))?;
    tx.sessions()
        .set_webauthn_challenge(s, &challenge, purpose, until)
        .await?;
    tx.commit().await?;
    Ok(secret_json(
        StatusCode::OK,
        &json!({ "purpose": purpose, "public_key": options }),
    ))
}

/// Spend the session's challenge for `purpose` in a transaction of its own, so a refused
/// answer spends it too: each challenge is answered once.
async fn take_challenge(c: &Call, s: StaffSessionId, purpose: &str) -> Result<Vec<u8>, ApiError> {
    let mut tx = c.tx().await?;
    let ch = tx
        .sessions()
        .take_webauthn_challenge(s, purpose, c.st.now())
        .await?;
    tx.commit().await?;
    ch.ok_or_else(ApiError::second_factor_refused)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialIn {
    id: String,
    client_data_json: String,
    authenticator_data: String,
    public_key: String,
    public_key_algorithm: i32,
    #[serde(default)]
    transports: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterIn {
    #[serde(default)]
    name: Option<String>,
    credential: CredentialIn,
}

/// A passkey's name: trimmed, 1 to 64 characters, no control characters. Absent or
/// empty: "Passkey".
fn passkey_name(n: Option<&str>) -> Result<String, ApiError> {
    let n = n.map(str::trim).unwrap_or_default();
    if n.is_empty() {
        return Ok("Passkey".into());
    }
    if n.chars().count() > 64 || n.chars().any(char::is_control) {
        return Err(ApiError::invalid("/name"));
    }
    Ok(n.to_owned())
}

/// The transports a browser may report (WebAuthn Level 2 §5.8.4), as hints only.
fn transports(t: &[String]) -> Vec<String> {
    t.iter()
        .filter(|x| {
            matches!(
                x.as_str(),
                "usb" | "nfc" | "ble" | "internal" | "hybrid" | "smart-card"
            )
        })
        .take(8)
        .cloned()
        .collect()
}

/// `POST /auth/mfa/passkeys {name?, credential}`: register a passkey (see the module).
pub(crate) async fn register(c: Call, body: Bytes) -> Response {
    let mut reason: Option<&'static str> = None;
    let r = register_inner(&c, &body, &mut reason)
        .await
        .unwrap_or_else(IntoResponse::into_response);
    crate::security::answered(&c.st, Kind::MfaEnrol, &r, |ev| {
        let ev = ev.with("factor", Value::Word("passkey"));
        match reason {
            Some(w) => ev.with("reason", Value::Word(w)),
            None => ev,
        }
    });
    r
}

async fn register_inner(
    c: &Call,
    body: &[u8],
    reason: &mut Option<&'static str>,
) -> Result<Response, ApiError> {
    let s = session(c)?;
    limit(c)?;
    let req: RegisterIn = parse(body)?;
    let name = passkey_name(req.name.as_deref())?;
    let rp = rp(c)?;
    {
        let mut tx = c.tx().await?;
        let f = own_factors(&mut tx, s, c).await?;
        may_add_to(c, &f)?;
    }
    let challenge = take_challenge(c, s, "register").await.inspect_err(|_| {
        *reason = Some("challenge");
    })?;
    let cr = &req.credential;
    let id = unb64(&cr.id, MAX_CREDENTIAL_ID).ok_or_else(|| ApiError::invalid("/credential/id"))?;
    let cd = unb64(&cr.client_data_json, MAX_CLIENT_DATA)
        .ok_or_else(|| ApiError::invalid("/credential/client_data_json"))?;
    let ad = unb64(&cr.authenticator_data, MAX_AUTHENTICATOR_DATA)
        .ok_or_else(|| ApiError::invalid("/credential/authenticator_data"))?;
    let pk = unb64(&cr.public_key, MAX_PUBLIC_KEY)
        .ok_or_else(|| ApiError::invalid("/credential/public_key"))?;
    let reg = webauthn::verify_registration(
        &rp,
        &challenge,
        &Registration {
            credential_id: &id,
            client_data_json: &cd,
            authenticator_data: &ad,
            public_key: &pk,
            algorithm: cr.public_key_algorithm,
        },
    )
    .map_err(|e| {
        *reason = Some(e.as_str());
        ApiError::second_factor_refused()
    })?;
    let mut codes = Vec::with_capacity(RECOVERY_CODES);
    let mut hashes = Vec::with_capacity(RECOVERY_CODES);
    for _ in 0..RECOVERY_CODES {
        let code = recovery_code()?;
        hashes.push(recovery_hash(&code).ok_or_else(|| ApiError::internal("recovery"))?);
        codes.push(code);
    }
    let now = c.st.now();
    let key = NewPasskey {
        id: Uuid::now_v7(),
        credential_id: reg.credential_id,
        public_key: reg.public_key,
        algorithm: reg.algorithm,
        sign_count: reg.sign_count,
        name,
        transports: transports(&cr.transports),
        backup_eligible: reg.backup_eligible,
    };
    let mut tx = c.tx().await?;
    let codes_set = tx
        .sessions()
        .add_own_passkey(s, &key, &hashes, now)
        .await?
        .ok_or_else(|| ApiError::not_available("passkey not added"))?;
    let user = own_factors(&mut tx, s, c).await?.user_id;
    // ASVS-04: the user is told by email that a passkey was added.
    security_notice(&mut tx, user, SecurityNotice::PasskeyAdded, now).await?;
    let saved = tx
        .sessions()
        .own_passkeys(s, now)
        .await?
        .into_iter()
        .find(|k| k.id == key.id)
        .ok_or_else(|| ApiError::internal("passkey"))?;
    tx.commit().await?;
    let mut out = json!({ "passkey": passkey_json(&saved), "second_factor": "passed" });
    if codes_set && let Some(o) = out.as_object_mut() {
        o.insert("recovery_codes".into(), json!(codes));
    }
    Ok(secret_json(StatusCode::CREATED, &out))
}

/// An assertion as the API takes it (each part base64url).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AssertionIn {
    credential_id: String,
    client_data_json: String,
    authenticator_data: String,
    signature: String,
    #[serde(default)]
    user_handle: Option<String>,
}

/// Pass the session's factor with a passkey assertion answering its challenge for
/// `purpose` (`verify` or `reauthenticate`), in `tx`. On a refusal, `reason` names the
/// check that failed (`counter` for a counter that did not move).
///
/// # Errors
///
/// `401 CS-AUTH-0012` for any refusal; `409 CS-API-0014` when passkeys are unavailable.
pub(crate) async fn pass_with_passkey(
    c: &Call,
    tx: &mut TenantTx,
    s: StaffSessionId,
    purpose: &str,
    a: &AssertionIn,
    reason: &mut Option<&'static str>,
) -> Result<(), ApiError> {
    let rp = rp(c)?;
    let refuse = |reason: &mut Option<&'static str>, why: &'static str| {
        *reason = Some(why);
        ApiError::second_factor_refused()
    };
    let challenge = match take_challenge(c, s, purpose).await {
        Ok(ch) => ch,
        Err(_) => return Err(refuse(reason, "challenge")),
    };
    let malformed = |reason: &mut Option<&'static str>| refuse(reason, "malformed");
    let id = unb64(&a.credential_id, MAX_CREDENTIAL_ID).ok_or_else(|| malformed(reason))?;
    let cd = unb64(&a.client_data_json, MAX_CLIENT_DATA).ok_or_else(|| malformed(reason))?;
    let ad =
        unb64(&a.authenticator_data, MAX_AUTHENTICATOR_DATA).ok_or_else(|| malformed(reason))?;
    let sig = unb64(&a.signature, MAX_SIGNATURE).ok_or_else(|| malformed(reason))?;
    let handle = match &a.user_handle {
        Some(h) => Some(unb64(h, MAX_USER_HANDLE).ok_or_else(|| malformed(reason))?),
        None => None,
    };
    let now = c.st.now();
    let keys = tx.sessions().own_passkeys(s, now).await?;
    let key = keys
        .iter()
        .find(|k| k.credential_id == id)
        .ok_or_else(|| refuse(reason, "credential"))?;
    let user = own_factors(tx, s, c).await?.user_id;
    let got = webauthn::verify_assertion(
        &rp,
        &challenge,
        &key.public_key,
        key.algorithm,
        &user_handle(user),
        &Assertion {
            client_data_json: &cd,
            authenticator_data: &ad,
            signature: &sig,
            user_handle: handle.as_deref(),
        },
    )
    .map_err(|e| refuse(reason, e.as_str()))?;
    tx.sessions()
        .use_own_passkey(s, key.id, got.sign_count, now)
        .await?
        .ok_or_else(|| refuse(reason, "counter"))?;
    Ok(())
}

/// `GET /auth/mfa/passkeys`: the caller's passkeys, in every workspace of theirs.
pub(crate) async fn list(c: Call) -> Result<Response, ApiError> {
    let s = session(&c)?;
    let mut tx = c.tx().await?;
    let keys = tx.sessions().own_passkeys(s, c.st.now()).await?;
    tx.commit().await?;
    Ok(json(
        StatusCode::OK,
        &json!({ "items": keys.iter().map(passkey_json).collect::<Vec<_>>() }),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RenameIn {
    name: String,
}

/// `PATCH /auth/mfa/passkeys/{id} {name}`: rename one, after a re-authentication.
pub(crate) async fn rename(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let s = session(&c)?;
    let id = path_id(&id)?;
    let req: RenameIn = parse(&body)?;
    if req.name.trim().is_empty() {
        return Err(ApiError::invalid("/name"));
    }
    let name = passkey_name(Some(&req.name))?;
    let now = c.st.now();
    c.p.require_recent_auth(now)?;
    let mut tx = c.tx().await?;
    if !tx.sessions().rename_own_passkey(s, id, &name, now).await? {
        return Err(ApiError::not_found());
    }
    let k = tx
        .sessions()
        .own_passkeys(s, now)
        .await?
        .into_iter()
        .find(|k| k.id == id)
        .ok_or_else(ApiError::not_found)?;
    tx.commit().await?;
    Ok(json(StatusCode::OK, &passkey_json(&k)))
}

/// `DELETE /auth/mfa/passkeys/{id}`: remove one, after a re-authentication. With it the
/// last factor, the recovery codes go too, and the workspace's policy may ask for a new
/// one at once.
pub(crate) async fn remove(c: Call, Path(id): Path<String>) -> Response {
    let r = remove_inner(&c, &id)
        .await
        .unwrap_or_else(IntoResponse::into_response);
    crate::security::answered(&c.st, Kind::MfaRemove, &r, |ev| {
        ev.with("factor", Value::Word("passkey"))
            .with("by", Value::Word("self"))
    });
    r
}

async fn remove_inner(c: &Call, id: &str) -> Result<Response, ApiError> {
    let s = session(c)?;
    let id = path_id(id)?;
    let now = c.st.now();
    let mut tx = c.tx().await?;
    // Not theirs answers as missing, before the re-authentication is asked for.
    if !tx
        .sessions()
        .own_passkeys(s, now)
        .await?
        .iter()
        .any(|k| k.id == id)
    {
        return Err(ApiError::not_found());
    }
    c.p.require_recent_auth(now)?;
    if !tx.sessions().remove_own_passkey(s, id, now).await? {
        return Err(ApiError::not_found());
    }
    security_notice(&mut tx, c.p.user, SecurityNotice::PasskeyRemoved, now).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `DELETE /auth/mfa/totp`: remove the TOTP authenticator, to replace it (ASVS-32),
/// after a re-authentication, which proved it. `409 CS-API-0009` when there is none.
pub(crate) async fn remove_totp(c: Call) -> Response {
    let r = async {
        let s = session(&c)?;
        let now = c.st.now();
        c.p.require_recent_auth(now)?;
        let mut tx = c.tx().await?;
        if !tx.sessions().remove_own_totp(s, now).await? {
            return Err(ApiError::not_available("no authenticator app"));
        }
        security_notice(&mut tx, c.p.user, SecurityNotice::FactorRemoved, now).await?;
        tx.commit().await?;
        Ok(StatusCode::NO_CONTENT.into_response())
    }
    .await
    .unwrap_or_else(IntoResponse::into_response);
    crate::security::answered(&c.st, Kind::MfaRemove, &r, |ev| {
        ev.with("factor", Value::Word("totp"))
            .with("by", Value::Word("self"))
    });
    r
}

/// `POST /auth/mfa/recovery-codes`: ten new recovery codes, shown once, replacing the
/// earlier ones, after a re-authentication. `409 CS-API-0009` without a factor.
pub(crate) async fn replace_recovery_codes(c: Call) -> Response {
    let r = async {
        let s = session(&c)?;
        let now = c.st.now();
        c.p.require_recent_auth(now)?;
        let mut codes = Vec::with_capacity(RECOVERY_CODES);
        let mut hashes = Vec::with_capacity(RECOVERY_CODES);
        for _ in 0..RECOVERY_CODES {
            let code = recovery_code()?;
            hashes.push(recovery_hash(&code).ok_or_else(|| ApiError::internal("recovery"))?);
            codes.push(code);
        }
        let mut tx = c.tx().await?;
        if !tx
            .sessions()
            .replace_own_recovery_codes(s, &hashes, now)
            .await?
        {
            return Err(ApiError::not_available("no second factor"));
        }
        security_notice(
            &mut tx,
            c.p.user,
            SecurityNotice::RecoveryCodesReplaced,
            now,
        )
        .await?;
        tx.commit().await?;
        Ok(secret_json(
            StatusCode::OK,
            &json!({ "recovery_codes": codes }),
        ))
    }
    .await
    .unwrap_or_else(IntoResponse::into_response);
    crate::security::answered(&c.st, Kind::MfaEnrol, &r, |ev| {
        ev.with("factor", Value::Word("recovery_code"))
    });
    r
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResetIn {
    identity_verified_by: String,
}

/// How an administrator proved the identity of a member who lost their factors
/// (ASVS 2.5.7): a closed list, recorded in the administrative log.
fn verified_by(s: &str) -> Option<&'static str> {
    match s {
        "in_person" => Some("in_person"),
        "video_call" => Some("video_call"),
        "phone_callback" => Some("phone_callback"),
        "manager_confirmation" => Some("manager_confirmation"),
        "identity_document" => Some("identity_document"),
        _ => None,
    }
}

/// `POST /users/{id}/second-factor/reset {identity_verified_by}`: see the module.
/// `403 CS-AUTH-0006` for a caller that is not an administrator or not a staff session;
/// `403 CS-AUTH-0013` without a recent re-authentication; `403 CS-API-0015` for a member
/// of another workspace too; `422` for oneself.
pub(crate) async fn reset_member(c: Call, Path(id): Path<String>, body: Bytes) -> Response {
    let mut target: Option<Uuid> = None;
    let r = reset_inner(&c, &id, &body, &mut target)
        .await
        .unwrap_or_else(IntoResponse::into_response);
    crate::security::answered(&c.st, Kind::MfaRemove, &r, |ev| {
        let ev = ev
            .with("factor", Value::Word("all"))
            .with("by", Value::Word("admin"));
        match target {
            Some(u) => ev.with("member", Value::Id(u)),
            None => ev,
        }
    });
    r
}

async fn reset_inner(
    c: &Call,
    id: &str,
    body: &[u8],
    target: &mut Option<Uuid>,
) -> Result<Response, ApiError> {
    let id = UserId(path_id(id)?);
    let mut tx = c.tx().await?;
    // The member first: another workspace's answers as missing (SEC-A04).
    let member = member_in_scope(c, &mut tx, id).await?;
    *target = Some(id.0);
    // A person, signed in and re-authenticated: never an API key or token.
    if !matches!(c.p.credential, Credential::Session(_)) {
        return Err(ApiError::forbidden("admin"));
    }
    let org = super::org::admin_of(&c.st, &c.p).await?;
    if !c.p.admin && org.is_none() {
        return Err(ApiError::forbidden("admin"));
    }
    outranks(c, &mut tx, &member).await?;
    if id == c.p.user {
        return Err(ApiError::invalid("/id"));
    }
    let req: ResetIn = parse(body)?;
    let how = verified_by(&req.identity_verified_by)
        .ok_or_else(|| ApiError::invalid("/identity_verified_by"))?;
    let now = c.st.now();
    c.p.require_recent_auth(now)?;
    let done = tx
        .sessions()
        .reset_member_factors(id, how, now)
        .await?
        .ok_or_else(ApiError::shared_user)?;
    tx.sessions().revoke_all(id, now).await?;
    security_notice(&mut tx, id, SecurityNotice::FactorsReset, now).await?;
    tx.commit().await?;
    Ok(json(
        StatusCode::OK,
        &json!({
            "user_id": id.to_string(),
            "removed": { "totp": done.had_totp, "passkeys": done.passkeys },
            "identity_verified_by": how,
            "enrol_at_next_sign_in": true,
        }),
    ))
}

/// The caller's factors for `GET /auth/session`: what they have, so the web app offers
/// the right step and step-up. `null` for keys and tokens, and for users who do not
/// sign in with a password.
pub(crate) async fn session_factors(c: &Call) -> Result<serde_json::Value, ApiError> {
    let Credential::Session(s) = c.p.credential else {
        return Ok(serde_json::Value::Null);
    };
    let mut tx = c.tx().await?;
    let f = tx.sessions().own_factors(s, c.st.now()).await?;
    tx.commit().await?;
    Ok(match f {
        Some(f) => json!({
            "totp": f.totp,
            "passkeys": f.passkeys,
            "recovery_codes_left": f.recovery_codes_left,
            "reset_by_admin": f.factor_reset,
            "passkeys_available": rp(c).is_ok(),
        }),
        None => serde_json::Value::Null,
    })
}
