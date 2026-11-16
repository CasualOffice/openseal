//! The seal key alias (docs/23 §5.4, `CON-10`, `HRD-06`; `SEC-X05`): which key keyd seals
//! with, from when. A key custodian proposes `{alias, active_from}`, another grants it, and
//! the proposer applies it, each with a second factor from the last 5 minutes; the
//! database re-checks every step and refuses an `active_from` before the change is applied
//! (migration 0035). The console proposes only an alias keyd serves now with a certificate
//! valid at `active_from`; the worker reads the alias per seal job and refuses one keyd
//! does not serve or whose change is not fully approved (`CS-CON-0006`). Grant and apply
//! are the key-change steps shared with the TSAs ([`crate::tsa`]), each route taking only
//! changes of its own kind. Without `active_from` the change starts when it is applied.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use casual_sign_platform_store::{Detail, KeyAction, SealProfile};
use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::api::{Body, event, rfc3339};
use crate::auth::{AnyOperator, Authed, KeyCustodians};
use crate::error::ConsoleError;
use crate::state::AppState;

fn profile_json(p: &SealProfile) -> Value {
    json!({
        "id": p.id,
        "alias": p.active_alias,
        "active_from": rfc3339(p.active_from),
        "changed_at": rfc3339(p.changed_at),
        "approval": p.approval,
    })
}

/// `GET /console/v1/seal`: the alias in force now, every version (newest start first)
/// and the alias changes of the last day with the payload each proposes.
pub async fn seal(
    State(state): State<AppState>,
    _op: Authed<AnyOperator>,
) -> Result<Json<Value>, ConsoleError> {
    let now = state.now();
    let store = state.store();
    let profiles = store.seal_profiles().await?;
    let current = profiles.iter().find(|p| p.active_from <= now);
    let mut changes = Vec::new();
    for a in store
        .approvals(now)
        .await?
        .into_iter()
        .filter(|a| a.action == KeyAction::SealActivate.as_str())
    {
        let payload = store.approval_payload(a.id).await?;
        changes.push(json!({
            "id": a.id,
            "requester": a.requester,
            "payload": payload,
            "created_at": rfc3339(a.created_at),
            "expires_at": rfc3339(a.expires_at),
            "approvers": a.approvers,
            "used": a.used,
            "live": !a.used && now < a.expires_at,
        }));
    }
    Ok(Json(json!({
        "current": current.map(profile_json),
        "profiles": profiles.iter().map(profile_json).collect::<Vec<_>>(),
        "changes": changes,
    })))
}

/// A proposed alias change.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeBody {
    /// keyd's alias for the key to seal with.
    alias: String,
    /// From when (RFC 3339), not before now; omitted, from when the change is applied.
    active_from: Option<String>,
}

/// keyd's alias rule: 1 to 64 of `[A-Za-z0-9._-]`.
fn alias_ok(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// `POST /console/v1/seal/changes`: propose sealing with another alias from
/// `active_from` (step 1 of 3). Key custodians, with a second factor entered within 5
/// minutes. Refused (`CS-CON-0006`, `alias`) unless keyd serves the alias now with a
/// certificate valid at `active_from` (now, when it is omitted); refused when the console
/// has no keyd to ask.
pub async fn propose(
    State(state): State<AppState>,
    op: Authed<KeyCustodians>,
    Body(body): Body<ChangeBody>,
) -> Result<Response, ConsoleError> {
    let now = state.now();
    if !alias_ok(&body.alias) {
        return Err(ConsoleError::KeyRefused("alias"));
    }
    // Whole seconds in UTC: the database's pattern, and the instant the payload hashes.
    // Omitted, the database starts the version when the change is applied.
    let stated = match &body.active_from {
        Some(t) => Some(
            OffsetDateTime::parse(t, &Rfc3339)
                .map_err(|_| ConsoleError::Invalid("active_from"))?
                .to_offset(time::UtcOffset::UTC)
                .replace_nanosecond(0)
                .map_err(|_| ConsoleError::Invalid("active_from"))?,
        ),
        None => None,
    };
    if stated.is_some_and(|from| from < now.replace_nanosecond(0).unwrap_or(now)) {
        return Err(ConsoleError::KeyRefused("active_from"));
    }
    let from = stated.unwrap_or(now);
    let Some(client) = state.config().keyd.clone() else {
        return Err(ConsoleError::KeyRefused("alias"));
    };
    let keys = tokio::task::spawn_blocking(move || client.list_keys())
        .await
        .map_err(|_| ConsoleError::Internal("keyd call"))?
        .map_err(|e| ConsoleError::Keyd(e.code()))?;
    let at = from.unix_timestamp();
    if !keys
        .iter()
        .any(|k| k.alias == body.alias && k.not_before <= at && at <= k.not_after)
    {
        return Err(ConsoleError::KeyRefused("alias"));
    }
    let from_text = match stated {
        Some(t) => Value::String(
            t.format(&Rfc3339)
                .map_err(|_| ConsoleError::Invalid("active_from"))?,
        ),
        None => Value::Null,
    };
    let profile = Uuid::now_v7();
    let payload = json!({ "id": profile, "alias": body.alias, "active_from": from_text });
    let id = Uuid::now_v7();
    let mut tx = state.store().begin().await?;
    tx.request_key_change(
        &op.token_sha256,
        id,
        KeyAction::SealActivate,
        profile,
        &payload,
        now,
    )
    .await?;
    tx.append(
        &event("operator.key_change.requested", Some(op.id), &op.ctx, now)
            .with("approval", Detail::Id(id))
            .with(
                "action",
                Detail::Code(KeyAction::SealActivate.as_str().to_owned()),
            )
            .with("profile", Detail::Id(profile)),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "id": id, "profile": profile, "active_from": from_text })),
    )
        .into_response())
}

/// `POST /console/v1/seal/changes/{id}/grant`: approve another key custodian's alias
/// change (step 2). Not found for a change of another kind.
pub async fn grant(
    State(state): State<AppState>,
    op: Authed<KeyCustodians>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ConsoleError> {
    crate::tsa::grant_key_change(&state, &op, id, &[KeyAction::SealActivate]).await
}

/// `POST /console/v1/seal/changes/{id}/apply`: apply one's own approved alias change
/// (step 3). Not found for a change of another kind; refused (`CS-CON-0006`,
/// `active_from`) when its stated start has passed.
pub async fn apply(
    State(state): State<AppState>,
    op: Authed<KeyCustodians>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ConsoleError> {
    // The payload was checked when proposed and is hash-bound, so the database's only
    // `OS012` at this step is a start already past.
    match crate::tsa::apply_key_change(&state, &op, id, &[KeyAction::SealActivate]).await {
        Err(ConsoleError::KeyRefused(_)) => Err(ConsoleError::KeyRefused("active_from")),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_follow_keyds_rule() {
        assert!(alias_ok("platform-2027"));
        assert!(alias_ok("a.b_c"));
        assert!(!alias_ok(""));
        assert!(!alias_ok("has space"));
        assert!(!alias_ok(&"x".repeat(65)));
    }
}
