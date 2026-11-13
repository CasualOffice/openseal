//! Time-stamping authorities (docs/23 §5.4, `CON-07`; `SEC-X05`, `SEC-X06`): the TSAs the
//! worker uses, in the database, changed only by two key custodians. A custodian proposes
//! a change (the whole payload is stored for the approver), another grants it, and the
//! proposer applies it; each step needs a second factor from the last 5 minutes, and the
//! database re-checks every step (migration 0034). A proposed URL must pass the `SEC-W01`
//! address policy now ([`crate::url_policy`]); the worker checks it again when it
//! connects. `OPENSEAL_TSA_URLS` stays the worker's fallback while the table has no
//! enabled row.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use casual_sign_platform_store::{Detail, KeyAction, TsaEndpoint};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::api::{Body, event, rfc3339};
use crate::auth::{AnyOperator, Authed, KeyCustodians, hex};
use crate::error::ConsoleError;
use crate::state::AppState;

/// The default priority of a new endpoint.
pub const DEFAULT_PRIORITY: i32 = 100;

fn endpoint_json(t: &TsaEndpoint) -> Value {
    json!({
        "id": t.id,
        "url": t.url,
        "policy_oid": t.policy_oid,
        "priority": t.priority,
        "enabled": t.enabled,
        "cert_sha256": t.cert_sha256.as_deref().map(hex),
        "changed_at": rfc3339(t.changed_at),
        "approval": t.approval,
    })
}

/// `GET /console/v1/tsa`: the configured TSAs and the key changes of the last day with
/// the payload each proposes.
pub async fn tsa(
    State(state): State<AppState>,
    _op: Authed<AnyOperator>,
) -> Result<Json<Value>, ConsoleError> {
    let now = state.now();
    let store = state.store();
    let endpoints = store.tsa_endpoints().await?;
    let mut changes = Vec::new();
    for a in store
        .approvals(now)
        .await?
        .into_iter()
        .filter(|a| a.action.starts_with("tsa."))
    {
        let payload = store.approval_payload(a.id).await?;
        changes.push(json!({
            "id": a.id,
            "requester": a.requester,
            "action": a.action,
            "endpoint": a.target,
            "payload": payload,
            "created_at": rfc3339(a.created_at),
            "expires_at": rfc3339(a.expires_at),
            "approvers": a.approvers,
            "used": a.used,
            "live": !a.used && now < a.expires_at,
        }));
    }
    Ok(Json(json!({
        "endpoints": endpoints.iter().map(endpoint_json).collect::<Vec<_>>(),
        "changes": changes,
    })))
}

/// A proposed TSA change.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeBody {
    /// `set` or `remove`.
    action: String,
    /// The endpoint; a new one when omitted for `set`.
    id: Option<Uuid>,
    url: Option<String>,
    policy_oid: Option<String>,
    priority: Option<i32>,
    enabled: Option<bool>,
    cert_sha256: Option<String>,
}

fn oid_ok(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    (2..=32).contains(&parts.len())
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 10 && p.bytes().all(|b| b.is_ascii_digit()))
        && parts.first().is_some_and(|f| matches!(*f, "0" | "1" | "2"))
        && parts.iter().all(|p| *p == "0" || !p.starts_with('0'))
}

/// Check a proposed change and build its payload: `(action, endpoint, payload)`.
async fn payload(
    state: &AppState,
    body: ChangeBody,
) -> Result<(KeyAction, Uuid, Value), ConsoleError> {
    match body.action.as_str() {
        "set" => {
            let url = body.url.ok_or(ConsoleError::Invalid("url"))?;
            let allow = state.config().tsa_allow.clone();
            let checked = url.clone();
            let ok =
                tokio::task::spawn_blocking(move || crate::url_policy::permits(&checked, &allow))
                    .await
                    .map_err(|_| ConsoleError::Internal("url check"))?;
            if !ok {
                return Err(ConsoleError::KeyRefused("url"));
            }
            if let Some(o) = &body.policy_oid
                && !oid_ok(o)
            {
                return Err(ConsoleError::KeyRefused("policy_oid"));
            }
            let cert = match body.cert_sha256 {
                Some(c) => {
                    let c = c.to_ascii_lowercase();
                    if c.len() != 64 || !c.bytes().all(|b| b.is_ascii_hexdigit()) {
                        return Err(ConsoleError::KeyRefused("cert_sha256"));
                    }
                    Some(c)
                }
                None => None,
            };
            let priority = body.priority.unwrap_or(DEFAULT_PRIORITY);
            if !(0..=1000).contains(&priority) {
                return Err(ConsoleError::KeyRefused("priority"));
            }
            let id = body.id.unwrap_or_else(Uuid::now_v7);
            Ok((
                KeyAction::TsaSet,
                id,
                json!({
                    "id": id,
                    "url": url,
                    "policy_oid": body.policy_oid,
                    "priority": priority,
                    "enabled": body.enabled.unwrap_or(true),
                    "cert_sha256": cert,
                }),
            ))
        }
        "remove" => {
            let id = body.id.ok_or(ConsoleError::Invalid("id"))?;
            if body.url.is_some()
                || body.policy_oid.is_some()
                || body.priority.is_some()
                || body.enabled.is_some()
                || body.cert_sha256.is_some()
            {
                return Err(ConsoleError::Invalid("action"));
            }
            if !state
                .store()
                .tsa_endpoints()
                .await?
                .iter()
                .any(|t| t.id == id)
            {
                return Err(ConsoleError::NotFound);
            }
            Ok((KeyAction::TsaRemove, id, json!({ "id": id })))
        }
        _ => Err(ConsoleError::Invalid("action")),
    }
}

/// `POST /console/v1/tsa/changes`: propose a TSA change (step 1 of 3). Key custodians,
/// with a second factor entered within 5 minutes.
pub async fn propose(
    State(state): State<AppState>,
    op: Authed<KeyCustodians>,
    Body(body): Body<ChangeBody>,
) -> Result<Response, ConsoleError> {
    let (action, endpoint, payload) = payload(&state, body).await?;
    let now = state.now();
    let id = Uuid::now_v7();
    let mut tx = state.store().begin().await?;
    tx.request_key_change(&op.token_sha256, id, action, endpoint, &payload, now)
        .await?;
    tx.append(
        &event("operator.key_change.requested", Some(op.id), &op.ctx, now)
            .with("approval", Detail::Id(id))
            .with("action", Detail::Code(action.as_str().to_owned()))
            .with("endpoint", Detail::Id(endpoint)),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "id": id, "endpoint": endpoint })),
    )
        .into_response())
}

/// `POST /console/v1/tsa/changes/{id}/grant`: approve another key custodian's change
/// (step 2).
pub async fn grant(
    State(state): State<AppState>,
    op: Authed<KeyCustodians>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ConsoleError> {
    let now = state.now();
    let mut tx = state.store().begin().await?;
    if !tx.grant_key_change(&op.token_sha256, id, now).await? {
        return Err(ConsoleError::NotFound);
    }
    tx.append(
        &event("operator.key_change.granted", Some(op.id), &op.ctx, now)
            .with("approval", Detail::Id(id)),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /console/v1/tsa/changes/{id}/apply`: apply one's own approved change (step 3).
pub async fn apply(
    State(state): State<AppState>,
    op: Authed<KeyCustodians>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ConsoleError> {
    let now = state.now();
    let mut tx = state.store().begin().await?;
    let action = tx.apply_key_change(&op.token_sha256, id, now).await?;
    let name = if action == KeyAction::TsaRemove.as_str() {
        "operator.tsa.removed"
    } else {
        "operator.tsa.set"
    };
    tx.append(&event(name, Some(op.id), &op.ctx, now).with("approval", Detail::Id(id)))
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_oids_are_dotted_decimal_from_an_arc_of_zero_one_or_two() {
        assert!(oid_ok("1.2.3.4"));
        assert!(oid_ok("2.16.840.1.114412.7.1"));
        for bad in ["", "1", "3.1", "1..2", "1.02", "1.a", "1.12345678901"] {
            assert!(!oid_ok(bad), "{bad}");
        }
    }
}
