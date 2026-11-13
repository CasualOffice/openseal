//! Keys and certificates (docs/23 §5.4, `CON-06`): what keyd's admin interface reports,
//! read with the console's admin identity, which keyd answers only `list-keys`,
//! `oplog-head`, `oplog-range` and `health` (it cannot sign, `CS-CON-0008`). Certificates,
//! their validity and fingerprints, keyd's operation-log records (hashes, ids and codes)
//! and backend state: never a key, and nothing the console could sign with.
//!
//! keyd is reached only when `OPENSEAL_CONSOLE_KEYD_ADDR` is set; until then these
//! routes answer `configured: false`.

use axum::Json;
use axum::extract::{Query, State};
use casual_sign_keyd_client::wire::{MAX_RANGE, algorithm_name};
use casual_sign_keyd_client::{AdminClient, KeyInfo, KeydError, hex};
use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::auth::{AnyOperator, Authed, Operators};
use crate::crypto::sha256;
use crate::error::ConsoleError;
use crate::state::AppState;

/// Days before `notAfter` from which a certificate is `expiring` (the first of the 90,
/// 30 and 7-day alerts, docs/23 §5.4).
pub const EXPIRING_DAYS: i64 = 90;

const DAY: i64 = 86_400;

fn keyd_error(e: &KeydError) -> ConsoleError {
    ConsoleError::Keyd(e.code())
}

/// Run a blocking keyd call off the async runtime.
async fn ask<T: Send + 'static>(
    client: AdminClient,
    f: impl FnOnce(&AdminClient) -> Result<T, KeydError> + Send + 'static,
) -> Result<T, ConsoleError> {
    tokio::task::spawn_blocking(move || f(&client))
        .await
        .map_err(|_| ConsoleError::Internal("keyd call"))?
        .map_err(|e| keyd_error(&e))
}

fn time_text(unix: i64) -> Value {
    OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|t| t.format(&Rfc3339).ok())
        .map_or(Value::Null, Value::String)
}

/// A certificate's state at `now`: `not_yet_valid`, `expired`, `expiring` (within
/// [`EXPIRING_DAYS`]) or `valid`.
#[must_use]
pub fn status(not_before: i64, not_after: i64, now: i64) -> &'static str {
    if now < not_before {
        "not_yet_valid"
    } else if now > not_after {
        "expired"
    } else if not_after.saturating_sub(now) <= EXPIRING_DAYS.saturating_mul(DAY) {
        "expiring"
    } else {
        "valid"
    }
}

fn key_json(k: &KeyInfo, now: i64) -> Value {
    let chain: Vec<Value> = k
        .certs
        .iter()
        .map(|c| json!({ "sha256": hex(&sha256(c)), "bytes": c.len() }))
        .collect();
    json!({
        "alias": k.alias,
        "backend": k.backend,
        "algorithm": algorithm_name(k.alg),
        "development": k.development,
        "subject": k.subject,
        "issuer": k.issuer,
        "not_before": time_text(k.not_before),
        "not_after": time_text(k.not_after),
        "days_left": k.not_after.saturating_sub(now).div_euclid(DAY),
        "status": status(k.not_before, k.not_after, now),
        "sha256": k.certs.first().map(|c| hex(&sha256(c))),
        "chain": chain,
    })
}

/// `GET /console/v1/keys`: each key keyd serves, its certificate chain (SHA-256
/// fingerprints), validity and status, and keyd's operation-log head.
pub async fn keys(
    State(state): State<AppState>,
    _op: Authed<AnyOperator>,
) -> Result<Json<Value>, ConsoleError> {
    let Some(client) = state.config().keyd.clone() else {
        return Ok(Json(json!({ "configured": false, "keys": [] })));
    };
    let now = state.now().unix_timestamp();
    let (keys, head) = ask(client, |c| Ok((c.list_keys()?, c.oplog_head()?))).await?;
    Ok(Json(json!({
        "configured": true,
        "keys": keys.iter().map(|k| key_json(k, now)).collect::<Vec<_>>(),
        "log": { "seq": head.0, "sha256": head.1 },
    })))
}

/// The page of keyd's log to read.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogPage {
    from: Option<u64>,
    limit: Option<u16>,
}

/// `GET /console/v1/keys/log`: keyd's operation-log records from `from` (default 1),
/// at most `limit` (default 100, at most 256): sequence, time, caller fingerprint,
/// operation, alias, algorithm, digest, envelope id and outcome.
pub async fn keys_log(
    State(state): State<AppState>,
    _op: Authed<Operators>,
    Query(q): Query<LogPage>,
) -> Result<Json<Value>, ConsoleError> {
    let from = q.from.unwrap_or(1).max(1);
    let limit = q.limit.unwrap_or(100);
    if limit == 0 || limit > MAX_RANGE {
        return Err(ConsoleError::Invalid("limit"));
    }
    let Some(client) = state.config().keyd.clone() else {
        return Ok(Json(json!({ "configured": false, "records": [] })));
    };
    let records = ask(client, move |c| c.oplog_range(from, limit)).await?;
    Ok(Json(json!({
        "configured": true,
        "records": records.iter().map(|r| json!({
            "seq": r.seq,
            "at": time_text(i64::try_from(r.time).unwrap_or(i64::MAX)),
            "caller": r.caller,
            "op": r.op,
            "alias": r.alias,
            "algorithm": r.alg,
            "digest": r.digest,
            "envelope_id": r.envelope,
            "outcome": r.outcome,
        })).collect::<Vec<_>>(),
    })))
}

/// keyd's part of the health page: `not_configured`, `up` with each key's backend state,
/// or `down` with keyd's code.
pub async fn health(state: &AppState) -> Value {
    let Some(client) = state.config().keyd.clone() else {
        return json!({ "status": "not_configured" });
    };
    match ask(client, |c| c.health()).await {
        Ok(h) => json!({
            "status": if h.keys.iter().all(|k| k.ok) { "up" } else { "degraded" },
            "log_seq": h.log_seq,
            "uptime_seconds": h.uptime_s,
            "keys": h.keys.iter().map(|k| json!({
                "alias": k.alias, "backend": k.backend, "ok": k.ok,
            })).collect::<Vec<_>>(),
        }),
        Err(e) => json!({ "status": "down", "code": e.code() }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_certificate_is_expiring_from_ninety_days_and_expired_after_not_after() {
        let nb = 1_000;
        let na = nb + 400 * DAY;
        assert_eq!(status(nb, na, nb - 1), "not_yet_valid");
        assert_eq!(status(nb, na, nb), "valid");
        assert_eq!(status(nb, na, na - 91 * DAY), "valid");
        assert_eq!(status(nb, na, na - 90 * DAY), "expiring");
        assert_eq!(status(nb, na, na), "expiring");
        assert_eq!(status(nb, na, na + 1), "expired");
    }
}
