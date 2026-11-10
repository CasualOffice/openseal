//! Effects as jobs (ADR-011, ADR-012). The contract (kinds, idempotency keys, payload,
//! due times, attempt budgets) is [`casual_sign_host::jobs`], shared with the API
//! server; this adds what only the runner needs: the retry back-off with jitter, lease
//! and delivery ids.

use std::time::Duration;

use uuid::Uuid;

pub use casual_sign_host::jobs::{
    ALERT_OPERATOR, CHARGE_PAYMENT, DELETE_DRAFT, DELIVER_WEBHOOK, EffectJob, KINDS,
    NOTIFY_RECIPIENTS, NOTIFY_SENDER, PURGE_DATA, SEAL_ENVELOPE, SEND_COMPLETION_COPIES,
    SEND_EXPIRY_WARNING, SEND_INVITATION, SEND_REMINDER, TIMER, idempotency_key, job_for, kind_of,
    max_attempts,
};

use crate::error::Result;

/// A claimed job's payload ([`casual_sign_host::jobs::parse`]).
///
/// # Errors
///
/// `CS-WRK-0004` when it does not read back, or its effect is not of its kind.
pub fn parse(kind: &str, payload: &serde_json::Value) -> Result<EffectJob> {
    Ok(casual_sign_host::jobs::parse(kind, payload)?)
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
