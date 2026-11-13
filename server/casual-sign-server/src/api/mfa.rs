//! The staff second factor (ASVS-01, docs/40 §2): TOTP enrolment, the
//! sign-in step, and one-time recovery codes.
//!
//! A session that owes a factor reaches only these routes, `GET /auth/session` and
//! `POST /auth/logout` (`Access::SigningIn`); everything else answers `403 CS-AUTH-0011`
//! until it passes. Each code is accepted once: the database takes a TOTP code only for
//! a time step later than any accepted before for the user, and spends a recovery code
//! as it is used (migration 0032). Attempts are rate-limited per user as logins are.
//! Codes, seeds and recovery codes are never logged.

use axum::body::Bytes;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use axum::response::Response;
use casual_sign_seclog::{Kind, Value};
use casual_sign_store::StaffSessionId;
use serde::Deserialize;
use serde_json::json;

use super::json;
use crate::auth::Credential;
use crate::call::Call;
use crate::crypto::random_bytes;
use crate::dto::parse;
use crate::error::ApiError;
use crate::http::SecretBearing;
use crate::mfa::{RECOVERY_CODES, recovery_code, recovery_hash};
use crate::totp;

/// The session making the call: these routes are for staff sessions only.
fn session(c: &Call) -> Result<StaffSessionId, ApiError> {
    match c.p.credential {
        Credential::Session(s) => Ok(s),
        Credential::ApiKey(_) | Credential::AccessToken(_) => Err(ApiError::invalid("/credential")),
    }
}

/// Second-factor attempts per user per minute: the login limit (docs/21).
fn limit(c: &Call) -> Result<(), ApiError> {
    let d = c.st.0.limiter.hit(
        &format!("mfa:{}", c.p.user),
        c.st.config().rate.login_per_minute,
        c.st.now(),
    );
    if d.allowed {
        Ok(())
    } else {
        Err(ApiError::rate_limited(d.reset_secs))
    }
}

/// A response that shows a secret once: never cached, never kept by idempotency.
fn secret_json(v: &serde_json::Value) -> Response {
    let mut r = json(StatusCode::OK, v);
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r.extensions_mut().insert(SecretBearing);
    r
}

fn now_step(c: &Call) -> u64 {
    totp::step_at(c.st.now().unix_timestamp())
}

fn key(c: &Call) -> Result<std::sync::Arc<crate::mfa::MfaKey>, ApiError> {
    c.st.mfa_key()
        .cloned()
        .ok_or_else(|| ApiError::not_available("second factor not configured"))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyIn {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    recovery_code: Option<String>,
}

/// `POST /auth/mfa/verify {code} | {recovery_code}`: pass the session's second factor
/// with a code from the user's authenticator, or by spending a recovery code. `401
/// CS-AUTH-0012` for a wrong code, a code already used, or a spent recovery code.
pub(crate) async fn verify(c: Call, body: Bytes) -> Response {
    let mut factor = "totp";
    let mut reused = false;
    let r = verify_inner(&c, &body, &mut factor, &mut reused)
        .await
        .unwrap_or_else(IntoResponse::into_response);
    crate::security::answered(&c.st, Kind::Mfa, &r, |ev| {
        let ev = ev.with("factor", Value::Word(factor));
        // ASVS 2.8.5: a code for a time step already used is logged as such.
        if reused {
            ev.with("reason", Value::Word("reused"))
        } else {
            ev
        }
    });
    r
}

async fn verify_inner(
    c: &Call,
    body: &[u8],
    factor: &mut &'static str,
    reused: &mut bool,
) -> Result<Response, ApiError> {
    let s = session(c)?;
    limit(c)?;
    let req: VerifyIn = parse(body)?;
    if req.recovery_code.is_some() {
        *factor = "recovery_code";
    }
    let now = c.st.now();
    let mut tx = c.tx().await?;
    match (req.code, req.recovery_code) {
        (Some(code), None) => {
            let own = tx
                .sessions()
                .own_totp(s, now)
                .await?
                .ok_or_else(ApiError::expired)?;
            let sealed = match (own.confirmed, own.seed_sealed) {
                (true, Some(sealed)) => sealed,
                _ => return Err(ApiError::second_factor_refused()),
            };
            let seed = key(c)?.open(own.user_id.0, &sealed)?;
            let step = totp::matching_step(&seed, code.trim(), now_step(c))
                .ok_or_else(ApiError::second_factor_refused)?;
            let step = i64::try_from(step).map_err(|_| ApiError::internal("step"))?;
            // The code matched; refused now only for a step already used.
            *reused = true;
            tx.sessions()
                .verify_own_totp(s, step, now)
                .await?
                .ok_or_else(ApiError::second_factor_refused)?;
            *reused = false;
            tx.commit().await?;
            Ok(json(StatusCode::OK, &json!({ "second_factor": "passed" })))
        }
        (None, Some(code)) => {
            let hash = recovery_hash(&code).ok_or_else(ApiError::second_factor_refused)?;
            let left = tx
                .sessions()
                .use_own_recovery_code(s, &hash, now)
                .await?
                .ok_or_else(ApiError::second_factor_refused)?;
            tx.commit().await?;
            Ok(json(
                StatusCode::OK,
                &json!({ "second_factor": "passed", "recovery_codes_left": left }),
            ))
        }
        _ => Err(ApiError::invalid("/code")),
    }
}

/// `POST /auth/mfa/totp/enrol`: a new TOTP seed for the session's own user, shown once
/// as an `otpauth://` URI and as base32 text; enrolment holds only once confirmed. `409
/// CS-API-0009` when the user already has a confirmed factor, or none can be configured.
pub(crate) async fn enrol(c: Call) -> Result<Response, ApiError> {
    let s = session(&c)?;
    limit(&c)?;
    let key = key(&c)?;
    let now = c.st.now();
    let mut tx = c.tx().await?;
    let own = tx
        .sessions()
        .own_totp(s, now)
        .await?
        .ok_or_else(ApiError::expired)?;
    if own.confirmed {
        return Err(ApiError::not_available("already enrolled"));
    }
    let seed = random_bytes::<{ totp::SEED_BYTES }>()?;
    let sealed = key.seal(own.user_id.0, &seed)?;
    tx.sessions()
        .begin_own_totp(s, &sealed, now)
        .await?
        .ok_or_else(|| ApiError::not_available("already enrolled"))?;
    tx.commit().await?;
    Ok(secret_json(&json!({
        "otpauth_uri": totp::otpauth_uri(&seed, own.user_id.0),
        "secret": totp::base32(&seed),
    })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmIn {
    code: String,
}

/// `POST /auth/mfa/totp/confirm {code}`: a code from the new authenticator confirms the
/// enrolment; the answer shows the ten recovery codes once, and the session has passed
/// its second factor. `401 CS-AUTH-0012` for a wrong code; `409 CS-API-0009` before
/// `enrol` or after a confirmation.
pub(crate) async fn confirm(c: Call, body: Bytes) -> Response {
    let r = confirm_inner(&c, &body)
        .await
        .unwrap_or_else(IntoResponse::into_response);
    crate::security::answered(&c.st, Kind::MfaEnrol, &r, |ev| {
        ev.with("factor", Value::Word("totp"))
    });
    r
}

async fn confirm_inner(c: &Call, body: &[u8]) -> Result<Response, ApiError> {
    let s = session(c)?;
    limit(c)?;
    let req: ConfirmIn = parse(body)?;
    let key = key(c)?;
    let now = c.st.now();
    let mut tx = c.tx().await?;
    let own = tx
        .sessions()
        .own_totp(s, now)
        .await?
        .ok_or_else(ApiError::expired)?;
    let sealed = match (own.confirmed, own.seed_sealed) {
        (false, Some(sealed)) => sealed,
        (true, _) => return Err(ApiError::not_available("already enrolled")),
        (false, None) => return Err(ApiError::not_available("enrol first")),
    };
    let seed = key.open(own.user_id.0, &sealed)?;
    let step = totp::matching_step(&seed, req.code.trim(), now_step(c))
        .ok_or_else(ApiError::second_factor_refused)?;
    let step = i64::try_from(step).map_err(|_| ApiError::internal("step"))?;
    let mut codes = Vec::with_capacity(RECOVERY_CODES);
    let mut hashes = Vec::with_capacity(RECOVERY_CODES);
    for _ in 0..RECOVERY_CODES {
        let code = recovery_code()?;
        hashes.push(recovery_hash(&code).ok_or_else(|| ApiError::internal("recovery"))?);
        codes.push(code);
    }
    tx.sessions()
        .confirm_own_totp(s, &sealed, step, &hashes, now)
        .await?
        .ok_or_else(ApiError::second_factor_refused)?;
    // ASVS-04: the user is told by email that a factor was added.
    super::admin::security_notice(
        &mut tx,
        own.user_id,
        casual_sign_host::jobs::SecurityNotice::FactorAdded,
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(secret_json(&json!({
        "second_factor": "passed",
        "recovery_codes": codes,
    })))
}
