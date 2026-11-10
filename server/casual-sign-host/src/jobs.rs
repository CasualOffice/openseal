//! The job contract (docs/24 §1, ADR-011, ADR-012): one job per effect, written by
//! [`crate::apply`] and run by the worker.
//!
//! - **kind**: the effect's kind in snake case ([`KINDS`]; `Schedule` is `timer`).
//! - **idempotency key**: `effect:<envelope>:<command id>:<index>`, the effect's id, so
//!   a decision recorded again names the same job and the queue keeps one.
//! - **payload**: [`EffectJob`]: the envelope id, the effect as the engine serialized
//!   it, the decision's time, and the envelope's version and status after it. Ids and
//!   parameters only, never personal data.
//! - **run at**: a `Schedule`'s time, a `SealEnvelope`'s `not_before`, else the
//!   decision's time.
//!
//! `Cancel` and `RevokeTokens` enqueue nothing: the engine guards cancelled timers and
//! seal jobs itself, and tokens are revoked inside the deciding transaction, so a
//! revoked link stops working when the answer is given.

use casual_sign_audit::Timestamp;
use casual_sign_model::EnvelopeStatus;
use casual_sign_store::repo::jobs::NewJob;
use casual_sign_store::{EnvelopeId, JobId};
use casual_sign_workflow::{Effect, EffectKind, EnvelopeState};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{HostError, Result};
use crate::ids::odt;

/// Every job kind, one per effect kind that enqueues one.
pub const KINDS: &[&str] = &[
    SEND_INVITATION,
    SEND_REMINDER,
    SEND_EXPIRY_WARNING,
    NOTIFY_SENDER,
    NOTIFY_RECIPIENTS,
    SEND_COMPLETION_COPIES,
    TIMER,
    SEAL_ENVELOPE,
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

/// The payload of a job made from an effect: everything a job needs to find its work,
/// ids only (the effect itself carries ids and parameters, never personal data).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectJob {
    /// The envelope.
    pub envelope_id: Uuid,
    /// The effect.
    pub effect: Effect,
    /// When the decision that produced it was taken (milliseconds since the epoch): the
    /// event time webhooks report.
    pub decided_at: i64,
    /// The envelope's version after that decision (webhooks carry it so receivers can
    /// drop stale events, docs/40 §4).
    pub version: u64,
    /// The envelope's status after that decision.
    pub status: EnvelopeStatus,
}

/// The job kind of an effect, or `None` for one that enqueues nothing (`Cancel`,
/// `RevokeTokens`, and any effect a newer engine adds until the worker learns it).
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
        EffectKind::DeliverWebhook { .. } => DELIVER_WEBHOOK,
        EffectKind::ChargePayment { .. } => CHARGE_PAYMENT,
        EffectKind::AlertOperator { .. } => ALERT_OPERATOR,
        EffectKind::PurgeData { .. } => PURGE_DATA,
        EffectKind::DeleteDraft => DELETE_DRAFT,
        _ => return None,
    })
}

/// Attempts before a job of `kind` is dead. Webhooks get about three days of
/// back-off (docs/40 §4: ≈ 15 attempts); the rest as many, so a transient outage of a
/// day is ridden out.
#[must_use]
pub fn max_attempts(kind: &str) -> i32 {
    match kind {
        ALERT_OPERATOR | TIMER => 20,
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

/// The job that performs `effect`, or `None` when it enqueues nothing. Due now, at a
/// timer's time, or at a seal retry's `not_before`.
///
/// # Errors
///
/// `CS-WRK-0001` for a time outside the database's range; `CS-WRK-0004` (never) for an
/// effect that does not serialize.
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
    let payload = serde_json::to_value(&payload).map_err(|_| HostError::BadJob {
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
    let bad = || HostError::BadJob {
        kind: kind.chars().take(64).collect(),
    };
    let job: EffectJob = serde_json::from_value(payload.clone()).map_err(|_| bad())?;
    if kind_of(&job.effect.kind) != Some(kind) {
        return Err(bad());
    }
    Ok(job)
}
