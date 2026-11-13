//! Key monitoring (docs/23 §5.4): the certificate expiry scan (`CON-08`) and the
//! reconciliation of keyd's signatures against the seals the worker recorded (`CON-09`).
//! Both run daily (hourly for reconciliation) inside `casual-sign-console serve`, and on
//! demand through `POST /console/v1/keys/expiry-scan` and `POST /console/v1/reconciliation`.
//! Both read keyd with the console's admin identity, which cannot sign, and write only
//! append-only rows: `platform.alerts`, `platform.reconciliation_runs` and, for a
//! mismatch, an operator-log event.

use std::collections::{BTreeMap, BTreeSet};

use axum::Json;
use axum::extract::{Query, State};
use casual_sign_keyd_client::wire::{LogEntry, MAX_RANGE};
use casual_sign_keyd_client::{AdminClient, KeyInfo, KeydError, hex};
use casual_sign_platform_store::{Detail, EventDraft, ReconciliationRun};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::api::{Limit, rfc3339};
use crate::auth::{AnyOperator, Authed, Ctx, Operators};
use crate::crypto::sha256;
use crate::error::ConsoleError;
use crate::state::AppState;

const DAY: i64 = 86_400;

/// The alert thresholds before a signer certificate's `notAfter`, in days (docs/23 §5.4).
pub const EXPIRY_THRESHOLDS: [i64; 3] = [90, 30, 7];

/// The code of a certificate expiry alert.
pub const EXPIRY_CODE: &str = "CS-CON-0018";

/// The code of a reconciliation mismatch alert.
pub const MISMATCH_CODE: &str = "CS-CON-0009";

/// Signatures newer than this are not judged yet: their seal job may still be storing
/// the seal or retrying (an hour, longer than a seal job's lease).
pub const GRACE: Duration = Duration::hours(1);

/// keyd's and the worker's clocks may differ by this much; seal records are judged up to
/// this long before the cut-off, against keyd's records of this run and the previous one.
pub const SKEW: Duration = Duration::minutes(5);

/// Most keyd records one run reads; the next run carries on.
pub const MAX_RECORDS_PER_RUN: u64 = 100_000;

/// The alert level of a certificate valid until `not_after` at `now` (Unix seconds):
/// `Some(0)` when it has expired, `Some(t)` for the smallest threshold `t` it is within,
/// `None` when it is further than the largest.
#[must_use]
pub fn expiry_level(not_after: i64, now: i64) -> Option<i64> {
    if now > not_after {
        return Some(0);
    }
    let left = not_after.saturating_sub(now);
    EXPIRY_THRESHOLDS
        .iter()
        .rev()
        .copied()
        .find(|t| left <= t.saturating_mul(DAY))
}

/// Run a blocking keyd call off the async runtime.
async fn ask<T: Send + 'static>(
    client: AdminClient,
    f: impl FnOnce(&AdminClient) -> Result<T, KeydError> + Send + 'static,
) -> Result<T, ConsoleError> {
    tokio::task::spawn_blocking(move || f(&client))
        .await
        .map_err(|_| ConsoleError::Internal("keyd call"))?
        .map_err(|e| ConsoleError::Keyd(e.code()))
}

fn draft(
    action: &str,
    operator: Option<Uuid>,
    ctx: Option<&Ctx>,
    at: OffsetDateTime,
) -> EventDraft {
    let d = EventDraft::new(action, operator, at);
    match ctx {
        Some(c) => d.from_request(c.request, c.ip_text()),
        None => d,
    }
}

/// What one expiry scan found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiryReport {
    /// Keys scanned.
    pub keys: usize,
    /// Alerts raised now: (alias, level in days, 0 for expired).
    pub raised: Vec<(String, i64)>,
}

fn key_subject(k: &KeyInfo, level: i64) -> Value {
    json!({
        "alias": k.alias,
        "sha256": k.certs.first().map(|c| hex(&sha256(c))),
        "days": level,
    })
}

/// `certificate_expiry_scan`: an alert (`CS-CON-0018`, source `certificate_expiry_scan`)
/// for each keyd signer certificate the first time it comes within 90, 30 and 7 days of
/// its `notAfter`, and once it has expired. keyd itself refuses to sign under an expired
/// alias (`CS-CON-0006`). `None` when keyd is not configured.
///
/// # Errors
/// keyd's code (`CS-KEY-*`, `CS-CON-0008`); a database error.
pub async fn expiry_scan(state: &AppState) -> Result<Option<ExpiryReport>, ConsoleError> {
    let Some(client) = state.config().keyd.clone() else {
        return Ok(None);
    };
    let keys = ask(client, AdminClient::list_keys).await?;
    let now = state.now();
    let mut raised = Vec::new();
    let mut tx = None;
    for k in &keys {
        let Some(level) = expiry_level(k.not_after, now.unix_timestamp()) else {
            continue;
        };
        let subject = key_subject(k, level);
        if state
            .store()
            .alert_raised("certificate_expiry_scan", EXPIRY_CODE, &subject)
            .await?
        {
            continue;
        }
        if tx.is_none() {
            tx = Some(state.store().begin().await?);
        }
        if let Some(t) = tx.as_mut() {
            t.raise_alert(
                Uuid::now_v7(),
                now,
                "certificate_expiry_scan",
                EXPIRY_CODE,
                &subject,
            )
            .await?;
        }
        raised.push((k.alias.clone(), level));
    }
    if let Some(t) = tx {
        t.commit().await?;
    }
    Ok(Some(ExpiryReport {
        keys: keys.len(),
        raised,
    }))
}

/// `POST /console/v1/keys/expiry-scan`: run the expiry scan now.
pub async fn expiry_scan_now(
    State(state): State<AppState>,
    _op: Authed<Operators>,
) -> Result<Json<Value>, ConsoleError> {
    let Some(r) = expiry_scan(&state).await? else {
        return Ok(Json(json!({ "configured": false })));
    };
    Ok(Json(json!({
        "configured": true,
        "keys": r.keys,
        "raised": r.raised.iter().map(|(alias, days)| json!({ "alias": alias, "days": days }))
            .collect::<Vec<_>>(),
    })))
}

/// A keyd signature, as reconciliation judges it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Signature {
    seq: u64,
    envelope: Option<Uuid>,
    digest: Option<Vec<u8>>,
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || s.is_empty() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            s.get(i..i.saturating_add(2))
                .and_then(|b| u8::from_str_radix(b, 16).ok())
        })
        .collect()
}

fn signature_of(r: &LogEntry) -> Option<Signature> {
    (r.op == "sign" && r.outcome == "ok").then(|| Signature {
        seq: r.seq,
        envelope: Uuid::parse_str(&r.envelope).ok(),
        digest: unhex(&r.digest),
    })
}

/// keyd's records from `from`, oldest first, stopping before the first at or after
/// `cutoff` (Unix seconds) or after `budget` records. Returns them and whether the
/// budget stopped the read.
async fn read_log(
    client: &AdminClient,
    from: u64,
    cutoff: i64,
    budget: u64,
) -> Result<(Vec<LogEntry>, bool), ConsoleError> {
    let mut out = Vec::new();
    let mut next = from;
    loop {
        let left = budget.saturating_sub(u64::try_from(out.len()).unwrap_or(u64::MAX));
        if left == 0 {
            return Ok((out, true));
        }
        let n = u16::try_from(left.min(u64::from(MAX_RANGE))).unwrap_or(MAX_RANGE);
        let page = ask(client.clone(), move |c| c.oplog_range(next, n)).await?;
        let full = page.len() == usize::from(n);
        for r in page {
            if i64::try_from(r.time).unwrap_or(i64::MAX) >= cutoff {
                return Ok((out, false));
            }
            next = r.seq.saturating_add(1);
            out.push(r);
        }
        if !full {
            return Ok((out, false));
        }
    }
}

/// What a reconciliation run judged.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Judged {
    signatures: u32,
    matched: u32,
    /// (keyd seq, envelope) of orphaned retries.
    orphaned: Vec<(u64, Uuid)>,
    /// Alert subjects.
    mismatches: Vec<Value>,
}

/// Match keyd's signatures against the seal records of their envelopes (`of_envelopes`),
/// and the seal records stored in the window (`in_window`) against keyd's signatures of
/// this run and the previous one (`known`).
fn judge(
    signatures: &[Signature],
    of_envelopes: &[(Uuid, Vec<u8>)],
    in_window: &[(Uuid, Vec<u8>)],
    known: &BTreeSet<Vec<u8>>,
) -> Judged {
    let mut by_env: BTreeMap<Uuid, BTreeSet<&[u8]>> = BTreeMap::new();
    for (e, d) in of_envelopes {
        by_env.entry(*e).or_default().insert(d.as_slice());
    }
    let mut j = Judged::default();
    for s in signatures {
        j.signatures = j.signatures.saturating_add(1);
        let rows = s.envelope.and_then(|e| by_env.get(&e));
        match (s.envelope, &s.digest, rows) {
            (Some(_), Some(d), Some(rows)) if rows.contains(d.as_slice()) => {
                j.matched = j.matched.saturating_add(1);
            }
            // The envelope sealed with another signature: a seal job that signed, then
            // lost its lease or failed a check, and sealed again.
            (Some(e), Some(_), Some(_)) => j.orphaned.push((s.seq, e)),
            (e, _, _) => j.mismatches.push(json!({
                "direction": "signature_without_seal",
                "keyd_seq": s.seq,
                "envelope_id": e,
            })),
        }
    }
    for (e, d) in in_window {
        if !known.contains(d) {
            j.mismatches.push(json!({
                "direction": "seal_without_signature",
                "envelope_id": e,
                "digest": hex(d),
            }));
        }
    }
    j
}

/// One reconciliation run: read keyd's log from where the last run stopped up to an hour
/// ago ([`GRACE`]), match each signature with the seal records of its envelope, and each
/// seal record stored since the last run's cut-off with keyd's signatures; record the run
/// with its orphaned retries, and raise an alert (`CS-CON-0009`) and an operator event
/// for every other mismatch. `None` when keyd is not configured.
///
/// # Errors
/// keyd's code (`CS-KEY-*`, `CS-CON-0008`); a database error.
pub async fn reconcile(
    state: &AppState,
    operator: Option<Uuid>,
    ctx: Option<&Ctx>,
) -> Result<Option<ReconciliationRun>, ConsoleError> {
    let Some(client) = state.config().keyd.clone() else {
        return Ok(None);
    };
    let now = state.now();
    let last = state
        .store()
        .reconciliation_runs(1)
        .await?
        .into_iter()
        .next();
    let from_seq = last.as_ref().map_or(1, |r| r.next_seq);
    let mut cutoff = now.checked_sub(GRACE).unwrap_or(now);
    let (records, capped) = read_log(
        &client,
        from_seq,
        cutoff.unix_timestamp(),
        MAX_RECORDS_PER_RUN,
    )
    .await?;
    if capped && let Some(r) = records.last() {
        // Judge seal records only up to the last signature read.
        let t = i64::try_from(r.time).unwrap_or(i64::MAX).saturating_add(1);
        cutoff = cutoff.min(OffsetDateTime::from_unix_timestamp(t).unwrap_or(cutoff));
    }
    let next_seq = records.last().map_or(from_seq, |r| r.seq.saturating_add(1));
    let signatures: Vec<Signature> = records.iter().filter_map(signature_of).collect();

    // keyd's digests of this run and the previous one, for the seal records' side.
    let mut known: BTreeSet<Vec<u8>> = signatures.iter().filter_map(|s| s.digest.clone()).collect();
    if let Some(prev) = &last
        && prev.from_seq < prev.next_seq
    {
        let n = prev.next_seq.saturating_sub(prev.from_seq);
        let (before, _) = read_log(&client, prev.from_seq, i64::MAX, n).await?;
        known.extend(
            before
                .iter()
                .filter_map(signature_of)
                .filter_map(|s| s.digest),
        );
    }

    let envelopes: Vec<Uuid> = signatures
        .iter()
        .filter_map(|s| s.envelope)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let of_envelopes: Vec<(Uuid, Vec<u8>)> = state
        .store()
        .seal_digests_of(&envelopes)
        .await?
        .into_iter()
        .map(|d| (d.envelope, d.digest))
        .collect();
    let window_from = last.as_ref().map_or(OffsetDateTime::UNIX_EPOCH, |r| {
        r.cutoff.checked_sub(SKEW).unwrap_or(r.cutoff)
    });
    let window_to = cutoff.checked_sub(SKEW).unwrap_or(cutoff);
    let in_window: Vec<(Uuid, Vec<u8>)> = if window_from < window_to {
        state
            .store()
            .seal_digests(window_from, window_to)
            .await?
            .into_iter()
            .map(|d| (d.envelope, d.digest))
            .collect()
    } else {
        Vec::new()
    };
    let j = judge(&signatures, &of_envelopes, &in_window, &known);

    let run = ReconciliationRun {
        id: Uuid::now_v7(),
        at: now,
        from_seq,
        upto_seq: next_seq.saturating_sub(1),
        next_seq,
        cutoff,
        signatures: j.signatures,
        matched: j.matched,
        unmatched: u32::try_from(j.mismatches.len()).unwrap_or(u32::MAX),
        orphaned: Value::Array(
            j.orphaned
                .iter()
                .take(1000)
                .map(|(seq, e)| json!({ "seq": seq, "envelope_id": e }))
                .collect(),
        ),
    };
    let mut tx = state.store().begin().await?;
    tx.record_reconciliation(&run).await?;
    for subject in &j.mismatches {
        let mut s = subject.clone();
        if let Value::Object(m) = &mut s {
            m.insert("run".into(), json!(run.id));
        }
        tx.raise_alert(Uuid::now_v7(), now, "reconciliation", MISMATCH_CODE, &s)
            .await?;
    }
    if !j.mismatches.is_empty() {
        tx.append(
            &draft("operator.reconciliation.mismatch", operator, ctx, now)
                .with("run", Detail::Id(run.id))
                .with("code", Detail::Code(MISMATCH_CODE.to_owned()))
                .with("unmatched", Detail::Count(run.unmatched)),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(Some(run))
}

fn run_json(r: &ReconciliationRun) -> Value {
    json!({
        "id": r.id,
        "at": rfc3339(r.at),
        "from_seq": r.from_seq,
        "upto_seq": r.upto_seq,
        "next_seq": r.next_seq,
        "cutoff": rfc3339(r.cutoff),
        "signatures": r.signatures,
        "matched": r.matched,
        "unmatched": r.unmatched,
        "orphaned": r.orphaned,
    })
}

/// `POST /console/v1/reconciliation`: run reconciliation now.
pub async fn reconcile_now(
    State(state): State<AppState>,
    op: Authed<Operators>,
) -> Result<Json<Value>, ConsoleError> {
    let Some(run) = reconcile(&state, Some(op.id), Some(&op.ctx)).await? else {
        return Ok(Json(json!({ "configured": false })));
    };
    Ok(Json(json!({ "configured": true, "run": run_json(&run) })))
}

/// `GET /console/v1/reconciliation`: the newest runs.
pub async fn runs(
    State(state): State<AppState>,
    _op: Authed<AnyOperator>,
    Query(q): Query<Limit>,
) -> Result<Json<Value>, ConsoleError> {
    let list = state
        .store()
        .reconciliation_runs(q.limit.unwrap_or(50))
        .await?;
    Ok(Json(json!({
        "runs": list.iter().map(run_json).collect::<Vec<_>>(),
    })))
}

/// The background schedule inside `serve`: the expiry scan daily, reconciliation hourly,
/// both first a minute after start. Failures are logged by code and retried at the next
/// tick; nothing here stops the console.
pub async fn schedule(state: AppState) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    let mut hours: u32 = 0;
    loop {
        tick.tick().await;
        if hours.is_multiple_of(24)
            && let Err(e) = expiry_scan(&state).await
        {
            tracing::warn!(code = e.code(), "certificate_expiry_scan failed");
        }
        if let Err(e) = reconcile(&state, None, None).await {
            tracing::warn!(code = e.code(), "reconciliation failed");
        }
        hours = hours.wrapping_add(1);
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)] // Tests: a missing element fails the test.
mod tests {
    use super::*;

    #[test]
    fn a_certificate_alerts_at_ninety_thirty_and_seven_days_and_once_expired() {
        let na = 1_000 * DAY;
        assert_eq!(expiry_level(na, na - 91 * DAY), None);
        assert_eq!(expiry_level(na, na - 90 * DAY), Some(90));
        assert_eq!(expiry_level(na, na - 31 * DAY), Some(90));
        assert_eq!(expiry_level(na, na - 30 * DAY), Some(30));
        assert_eq!(expiry_level(na, na - 7 * DAY), Some(7));
        assert_eq!(expiry_level(na, na), Some(7));
        assert_eq!(expiry_level(na, na + 1), Some(0));
    }

    #[test]
    fn hex_digests_parse_and_bad_ones_do_not() {
        assert_eq!(unhex("00ff10"), Some(vec![0, 255, 16]));
        assert_eq!(unhex("-"), None);
        assert_eq!(unhex("abc"), None);
        assert_eq!(unhex("zz"), None);
    }

    #[test]
    fn signatures_match_orphan_or_alert_and_records_without_a_signature_alert() {
        let (a, b, c) = (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3));
        let sig = |seq, e: Uuid, d: u8| Signature {
            seq,
            envelope: Some(e),
            digest: Some(vec![d; 32]),
        };
        let signatures = [sig(1, a, 1), sig(2, b, 2), sig(3, b, 3), sig(4, c, 4)];
        let rows = [(a, vec![1; 32]), (b, vec![3; 32])];
        let window = [(a, vec![1; 32]), (b, vec![3; 32]), (c, vec![9; 32])];
        let known: BTreeSet<Vec<u8>> = signatures.iter().filter_map(|s| s.digest.clone()).collect();
        let j = judge(&signatures, &rows, &window, &known);
        assert_eq!(j.signatures, 4);
        assert_eq!(j.matched, 2);
        assert_eq!(
            j.orphaned,
            vec![(2, b)],
            "b sealed with its later signature"
        );
        assert_eq!(j.mismatches.len(), 2, "{:?}", j.mismatches);
        assert_eq!(j.mismatches[0]["keyd_seq"], 4);
        assert_eq!(j.mismatches[1]["direction"], "seal_without_signature");
    }
}
