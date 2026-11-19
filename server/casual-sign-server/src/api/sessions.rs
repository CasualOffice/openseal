//! A staff user's own sessions and re-authentication (ASVS-06, ASVS-07, docs/40 §2).
//!
//! - `GET /auth/sessions`: the person's live sessions in every workspace they belong to,
//!   the calling one marked `current`; each workspace's idle and absolute limits applied.
//! - `DELETE /auth/sessions/{id}` and `POST /auth/sessions/end-others`: end one of
//!   them, or every other one. Both are sensitive: they need a re-authentication within
//!   the last five minutes (`403 CS-AUTH-0013`), so a stolen session cannot sign its
//!   owner out everywhere.
//! - `POST /auth/reauthenticate {password, code? | recovery_code?}`: prove the password
//!   again, and the second factor when the user has one, opening the five-minute window
//!   in which sensitive actions are served (`Principal::require_recent_auth`).
//!
//! Only staff sessions reach these: an API key or token is `422 CS-API-0001`
//! (`/credential`). Passwords and codes are never logged.

use axum::body::Bytes;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use casual_sign_seclog::{Kind, Value as SecValue};
use casual_sign_store::StaffSessionId;
use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;

use super::envelopes::rfc3339;
use super::mfa::{key, now_step, session};
use super::{json, path_id};
use crate::auth::{STEP_UP_WINDOW_SECS, ran_out};
use crate::call::Call;
use crate::crypto::{StaffPassword, verify_staff_password};
use crate::dto::parse;
use crate::error::ApiError;
use crate::mfa::recovery_hash;
use crate::totp;

/// `start` plus `secs`, or `None` beyond the calendar.
fn after(start: OffsetDateTime, secs: u64) -> Option<OffsetDateTime> {
    start.checked_add(time::Duration::seconds(i64::try_from(secs).ok()?))
}

/// `GET /auth/sessions`: the caller's own live sessions, in every workspace of theirs.
pub(crate) async fn list(c: Call) -> Result<Response, ApiError> {
    let me = session(&c)?;
    let now = c.st.now();
    let mut tx = c.tx().await?;
    let rows = tx.sessions().own_sessions(me, now).await?;
    let items: Vec<Value> = rows
        .iter()
        .filter_map(|s| {
            let l = casual_sign_policy::org::effective_session(&s.organization_policy, &s.settings);
            if ran_out(s.last_seen_at, l.idle, now) || ran_out(s.created_at, l.max_age, now) {
                return None;
            }
            let ends = after(s.created_at, l.max_age).map_or(s.expires_at, |e| e.min(s.expires_at));
            Some(json!({
                "id": s.id.to_string(),
                "workspace": { "id": s.account_id.to_string(), "name": s.account_name },
                "method": s.method.as_str(),
                "client": s.client_label,
                "created_at": rfc3339(s.created_at),
                "last_seen_at": rfc3339(s.last_seen_at),
                "idle_expires_at": after(s.last_seen_at, l.idle).map(rfc3339),
                "expires_at": rfc3339(ends),
                "current": s.id == me,
            }))
        })
        .collect();
    Ok(json(StatusCode::OK, &json!({ "items": items })))
}

/// End `target` (or every other session with `None`), after the step-up check.
async fn end(c: &Call, target: Option<StaffSessionId>) -> Result<u64, ApiError> {
    let me = session(c)?;
    if target == Some(me) {
        // The calling session ends by `POST /auth/logout`, which also clears its cookie.
        return Err(ApiError::invalid("/id"));
    }
    let now = c.st.now();
    c.p.require_recent_auth(now)?;
    let mut tx = c.tx().await?;
    let n = tx.sessions().end_own(me, target, now).await?;
    tx.commit().await?;
    Ok(n)
}

/// `DELETE /auth/sessions/{id}`: end one of the caller's other sessions. `404` for a
/// session that is not theirs, already ended, or unknown alike.
pub(crate) async fn end_one(c: Call, Path(id): Path<String>) -> Response {
    let r = async {
        let id = StaffSessionId(path_id(&id)?);
        match end(&c, Some(id)).await? {
            0 => Err(ApiError::not_found()),
            _ => Ok(StatusCode::NO_CONTENT.into_response()),
        }
    }
    .await
    .unwrap_or_else(IntoResponse::into_response);
    crate::security::answered(&c.st, Kind::SessionEnd, &r, |ev| {
        ev.with("scope", SecValue::Word("one"))
    });
    r
}

/// `POST /auth/sessions/end-others`: end every other session of the caller, in every
/// workspace. Answers `{ended}`.
pub(crate) async fn end_others(c: Call) -> Response {
    let mut count = 0;
    let r = match end(&c, None).await {
        Ok(n) => {
            count = n;
            json(StatusCode::OK, &json!({ "ended": n }))
        }
        Err(e) => e.into_response(),
    };
    crate::security::answered(&c.st, Kind::SessionEnd, &r, |ev| {
        ev.with("scope", SecValue::Word("others"))
            .with("count", SecValue::Count(count))
    });
    r
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReauthIn {
    password: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    recovery_code: Option<String>,
    /// A passkey's assertion answering the session's `reauthenticate` challenge (CON-13).
    #[serde(default)]
    passkey: Option<super::factors::AssertionIn>,
}

/// Re-authentication attempts per user per minute: the login limit (docs/21).
fn limit(c: &Call) -> Result<(), ApiError> {
    let d = c.st.0.limiter.hit(
        &format!("reauth:{}", c.p.user),
        c.st.config().rate.login_per_minute,
        c.st.now(),
    );
    if d.allowed {
        Ok(())
    } else {
        Err(ApiError::rate_limited(d.reset_secs))
    }
}

/// `POST /auth/reauthenticate {password, code? | recovery_code? | passkey?}`: prove the
/// password again, and the second factor when the user has one (a TOTP code, single use,
/// a recovery code, spent, or a passkey's assertion, CON-13). Answers `{reauthenticated_until}`. `401 CS-AUTH-0007` for a
/// wrong password, `401 CS-AUTH-0012` for a wrong or reused code, `422 CS-API-0001`
/// (`/code`) when the user has a factor and none was sent.
pub(crate) async fn reauthenticate(c: Call, body: Bytes) -> Response {
    let mut factor = "password";
    let mut reason: Option<&'static str> = None;
    let r = reauth_inner(&c, &body, &mut factor, &mut reason)
        .await
        .unwrap_or_else(IntoResponse::into_response);
    crate::security::answered(&c.st, Kind::Reauth, &r, |ev| {
        let ev = ev.with("factor", SecValue::Word(factor));
        match reason {
            Some(w) => ev.with("reason", SecValue::Word(w)),
            None => ev,
        }
    });
    r
}

async fn reauth_inner(
    c: &Call,
    body: &[u8],
    factor: &mut &'static str,
    reason: &mut Option<&'static str>,
) -> Result<Response, ApiError> {
    let s = session(c)?;
    limit(c)?;
    let req: ReauthIn = parse(body)?;
    let now = c.st.now();
    let mut tx = c.tx().await?;
    let phc = tx.users().own_password_hash(s, now).await?.map(|p| p.0);
    let dummy = c.st.0.dummy_phc.clone();
    let password = req.password;
    // Under the pepper, as at sign-in (ASVS-29); the sign-in re-makes an old hash.
    let pepper = c.st.pepper();
    let ok = tokio::task::spawn_blocking(move || {
        let ok = verify_staff_password(
            pepper.as_deref(),
            &password,
            phc.as_deref().unwrap_or(&dummy),
        );
        ok != StaffPassword::Wrong && phc.is_some()
    })
    .await
    .unwrap_or(false);
    if !ok {
        return Err(ApiError::bad_credentials());
    }
    let own = tx.sessions().own_totp(s, now).await?;
    let has_passkey = tx
        .sessions()
        .own_factors(s, now)
        .await?
        .is_some_and(|f| f.passkeys > 0);
    if own.as_ref().is_some_and(|o| o.confirmed) || has_passkey {
        match (req.code, req.recovery_code, req.passkey) {
            (None, None, Some(a)) => {
                *factor = "passkey";
                super::factors::pass_with_passkey(c, &mut tx, s, "reauthenticate", &a, reason)
                    .await?;
            }
            (Some(code), None, None) => {
                *factor = "totp";
                let sealed = own
                    .and_then(|o| o.seed_sealed.map(|x| (o.user_id, x)))
                    .ok_or_else(ApiError::second_factor_refused)?;
                let opened = key(c)?.open(sealed.0.0, &sealed.1)?;
                let step = totp::matching_step(&opened.seed, code.trim(), now_step(c))
                    .ok_or_else(ApiError::second_factor_refused)?;
                let step = i64::try_from(step).map_err(|_| ApiError::internal("step"))?;
                // Single use, as at sign-in: a code for a step already used is refused.
                tx.sessions()
                    .verify_own_totp(s, step, now)
                    .await?
                    .ok_or_else(ApiError::second_factor_refused)?;
                // HRD-12: as at sign-in, a seed still under the previous key moves under
                // the current one once its code has passed.
                if let Some(new) = opened.resealed {
                    tx.sessions()
                        .reseal_own_totp(s, &sealed.1, &new, now)
                        .await?;
                }
            }
            (None, Some(code), None) => {
                *factor = "recovery_code";
                let hash = recovery_hash(&code).ok_or_else(ApiError::second_factor_refused)?;
                tx.sessions()
                    .use_own_recovery_code(s, &hash, now)
                    .await?
                    .ok_or_else(ApiError::second_factor_refused)?;
            }
            _ => return Err(ApiError::invalid("/code")),
        }
    }
    tx.sessions().set_reauth_at(s, now).await?;
    tx.commit().await?;
    let until = now
        .checked_add(time::Duration::seconds(STEP_UP_WINDOW_SECS))
        .ok_or_else(|| ApiError::internal("time"))?;
    Ok(json(
        StatusCode::OK,
        &json!({ "reauthenticated_until": rfc3339(until) }),
    ))
}
