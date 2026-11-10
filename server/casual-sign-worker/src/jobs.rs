//! Effects as jobs (ADR-011, ADR-012): kinds, idempotency keys, due times, attempt
//! budgets, and the retry back-off with jitter.

use std::time::Duration;

use casual_sign_audit::Timestamp;
use casual_sign_store::repo::jobs::NewJob;
use casual_sign_store::{EnvelopeId, JobId};
use casual_sign_workflow::{Effect, EffectKind, EnvelopeState};
use uuid::Uuid;

use crate::apply::{EffectJob, odt};
use crate::error::{Result, WorkerError};

/// Every job kind the worker runs, one per effect kind (`Cancel` enqueues nothing).
pub const KINDS: &[&str] = &[
    SEND_INVITATION,
    SEND_REMINDER,
    SEND_EXPIRY_WARNING,
    NOTIFY_SENDER,
    NOTIFY_RECIPIENTS,
    SEND_COMPLETION_COPIES,
    TIMER,
    SEAL_ENVELOPE,
    REVOKE_TOKENS,
    DELIVER_WEBHOOK,
    CHARGE_PAYMENT,
    ALERT_OPERATOR,
    PURGE_DATA,
    DELETE_DRAFT,
];

/// `SendInvitation`.
pub const SEND_INVITATION: &str = "send_invitation";
/// `SendReminder`.
pub const SEND_REMINDER: &str = "send_reminder";
/// `SendExpiryWarning`.
pub const SEND_EXPIRY_WARNING: &str = "send_expiry_warning";
/// `NotifySender`.
pub const NOTIFY_SENDER: &str = "notify_sender";
/// `NotifyRecipients`.
pub const NOTIFY_RECIPIENTS: &str = "notify_recipients";
/// `SendCompletionCopies`.
pub const SEND_COMPLETION_COPIES: &str = "send_completion_copies";
/// `Schedule`: fires `TimerDue` when due.
pub const TIMER: &str = "timer";
/// `SealEnvelope`.
pub const SEAL_ENVELOPE: &str = "seal_envelope";
/// `RevokeTokens`.
pub const REVOKE_TOKENS: &str = "revoke_tokens";
/// `DeliverWebhook`.
pub const DELIVER_WEBHOOK: &str = "deliver_webhook";
/// `ChargePayment`.
pub const CHARGE_PAYMENT: &str = "charge_payment";
/// `AlertOperator`.
pub const ALERT_OPERATOR: &str = "alert_operator";
/// `PurgeData`.
pub const PURGE_DATA: &str = "purge_data";
/// `DeleteDraft`.
pub const DELETE_DRAFT: &str = "delete_draft";

/// The job kind of an effect, or `None` for `Cancel`.
#[must_use]
pub fn kind_of(effect: &EffectKind) -> Option<&'static str> {
    Some(match effect {
        EffectKind::SendInvitation { .. } => SEND_INVITATION,
        EffectKind::SendReminder { .. } => SEND_REMINDER,
        EffectKind::SendExpiryWarning { .. } => SEND_EXPIRY_WARNING,
        EffectKind::NotifySender { .. } => NOTIFY_SENDER,
        EffectKind::NotifyRecipients { .. } => NOTIFY_RECIPIENTS,
        EffectKind::SendCompletionCopies { .. } => SEND_COMPLETION_COPIES,
        EffectKind::Schedule { .. } => TIMER,
        EffectKind::SealEnvelope { .. } => SEAL_ENVELOPE,
        EffectKind::RevokeTokens { .. } => REVOKE_TOKENS,
        EffectKind::DeliverWebhook { .. } => DELIVER_WEBHOOK,
        EffectKind::ChargePayment { .. } => CHARGE_PAYMENT,
        EffectKind::AlertOperator { .. } => ALERT_OPERATOR,
        EffectKind::PurgeData { .. } => PURGE_DATA,
        EffectKind::DeleteDraft => DELETE_DRAFT,
        // `Cancel`, and any effect a newer engine adds: nothing to enqueue until the
        // worker learns it (the engine guards cancelled timers and seal jobs itself).
        _ => return None,
    })
}

/// Attempts before a job of `kind` is dead. Webhooks get about three days of
/// back-off (docs/40 §4: ≈ 15 attempts); the rest as many, so a transient outage of a
/// day is ridden out.
#[must_use]
pub fn max_attempts(kind: &str) -> i32 {
    match kind {
        ALERT_OPERATOR | REVOKE_TOKENS | TIMER => 20,
        _ => 15,
    }
}

/// The idempotency key of an effect: `effect:<envelope>:<command>:<index>`, unique per
/// account (docs/24 §1).
#[must_use]
pub fn idempotency_key(envelope: EnvelopeId, effect: &Effect) -> String {
    format!(
        "effect:{}:{}:{}",
        envelope.0.hyphenated(),
        effect.id.command.as_str(),
        effect.id.index
    )
}

/// The job that performs `effect`, or `None` for `Cancel`. Due now, at a timer's time,
/// or at a seal retry's `not_before`.
///
/// # Errors
///
/// `CS-WRK-0001` for a time outside the database's range.
pub fn job_for(
    envelope: EnvelopeId,
    effect: &Effect,
    state: &EnvelopeState,
    now: Timestamp,
) -> Result<Option<NewJob>> {
    let Some(kind) = kind_of(&effect.kind) else {
        return Ok(None);
    };
    let run_at = match &effect.kind {
        EffectKind::Schedule { at, .. } => *at,
        EffectKind::SealEnvelope {
            not_before: Some(t),
        } => *t,
        _ => now,
    };
    let payload = EffectJob {
        envelope_id: envelope.0,
        effect: effect.clone(),
        decided_at: now.unix_millis(),
        version: state.version,
        status: state.status,
    };
    let payload = serde_json::to_value(&payload).map_err(|_| WorkerError::BadJob {
        kind: kind.to_owned(),
    })?;
    Ok(Some(NewJob {
        id: JobId(Uuid::new_v4()),
        envelope_id: Some(envelope),
        kind: kind.to_owned(),
        idempotency_key: idempotency_key(envelope, effect),
        payload,
        run_at: odt(run_at)?,
        max_attempts: max_attempts(kind),
    }))
}

/// A claimed job's payload.
///
/// # Errors
///
/// `CS-WRK-0004` when it does not read back, or its effect is not of its kind.
pub fn parse(kind: &str, payload: &serde_json::Value) -> Result<EffectJob> {
    let bad = || WorkerError::BadJob {
        kind: kind.chars().take(64).collect(),
    };
    let job: EffectJob = serde_json::from_value(payload.clone()).map_err(|_| bad())?;
    if kind_of(&job.effect.kind) != Some(kind) {
        return Err(bad());
    }
    Ok(job)
}

/// The delay before attempt `attempt + 1` after `attempt` failed: exponential from 30
/// seconds, doubling, capped at 12 hours, with "equal jitter" (half fixed, half drawn
/// from `random`, a value in `[0, 1)`), so workers that failed together do not retry in
/// step. Fifteen attempts span about three days.
#[must_use]
pub fn backoff(attempt: i32, random: f64) -> Duration {
    const BASE: u64 = 30;
    const CAP: u64 = 12 * 3600;
    let exp = u32::try_from(attempt.saturating_sub(1).clamp(0, 20)).unwrap_or(20);
    let full = BASE.saturating_mul(1u64 << exp).min(CAP);
    let half = full / 2;
    let r = if random.is_finite() {
        random.clamp(0.0, 1.0)
    } else {
        0.0
    };
    // `half` is at most 6 hours in seconds: exact in an f64.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    // Bounded above: `r` in [0, 1] and `half` ≤ 21,600.
    let extra = (half as f64 * r) as u64;
    Duration::from_secs(half.saturating_add(extra))
}

/// A random value in `[0, 1)` from the platform's generator (the worker is a host: it
/// may sample randomness; the engine never does).
#[must_use]
pub fn random_unit() -> f64 {
    let mut b = [0u8; 8];
    if aws_lc_rs::rand::fill(&mut b).is_err() {
        return 0.5;
    }
    // 53 random bits as a fraction.
    let v = u64::from_le_bytes(b) >> 11;
    #[allow(clippy::cast_precision_loss)]
    // A 53-bit integer is exact in an f64.
    let f = v as f64 / (1u64 << 53) as f64;
    f
}

/// `t` plus `d`, saturating at the end of the representable range.
#[must_use]
pub fn after(t: time::OffsetDateTime, d: Duration) -> time::OffsetDateTime {
    let d = time::Duration::try_from(d).unwrap_or(time::Duration::MAX);
    t.saturating_add(d)
}

/// A fresh random UUID (lease tokens, ids).
#[must_use]
pub fn random_uuid() -> Uuid {
    Uuid::new_v4()
}

/// A UUID derived from `parts`: the same parts give the same id (webhook delivery ids,
/// so a re-run records the same delivery). SHA-256, then the version 8 and variant bits.
#[must_use]
pub fn derived_uuid(parts: &[&[u8]]) -> Uuid {
    let mut ctx = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    for p in parts {
        ctx.update(&u64::try_from(p.len()).unwrap_or(u64::MAX).to_be_bytes());
        ctx.update(p);
    }
    let d = ctx.finish();
    let mut b = [0u8; 16];
    for (slot, v) in b.iter_mut().zip(d.as_ref()) {
        *slot = *v;
    }
    uuid::Builder::from_custom_bytes(b).into_uuid()
}

#[cfg(test)]
// Tests may unwrap and index (CLAUDE.md).
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_with_jitter_and_is_capped() {
        assert_eq!(backoff(1, 0.0), Duration::from_secs(15));
        assert_eq!(backoff(1, 1.0), Duration::from_secs(30));
        assert_eq!(backoff(2, 0.0), Duration::from_secs(30));
        assert_eq!(backoff(3, 0.0), Duration::from_secs(60));
        assert_eq!(backoff(40, 1.0), Duration::from_secs(12 * 3600));
        assert_eq!(backoff(-5, f64::NAN), Duration::from_secs(15));
        let total: u64 = (1..=15).map(|a| backoff(a, 1.0).as_secs()).sum();
        // About three days in the worst case, at least a day and a half in the best.
        assert!(total > 2 * 86_400 && total < 4 * 86_400, "{total}");
        let r = random_unit();
        assert!((0.0..1.0).contains(&r));
    }

    #[test]
    fn derived_ids_are_stable_and_distinct() {
        let a = derived_uuid(&[b"job", b"sub"]);
        assert_eq!(a, derived_uuid(&[b"job", b"sub"]));
        assert_ne!(a, derived_uuid(&[b"jo", b"bsub"]));
        assert_eq!(a.get_version_num(), 8);
    }
}
