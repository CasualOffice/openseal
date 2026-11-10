//! Effects: what the worker must do after the transaction commits (docs/24 §1, ADR-011).
//!
//! An effect is data. Jobs perform it idempotently, keyed by `(envelope_id, effect id)`;
//! the id is derived from the command id and the effect's position, so re-running a
//! decision names the same jobs.

use casual_sign_audit::{Channel, Timestamp};
use casual_sign_model::{Id, Text};
use serde::{Deserialize, Serialize};

/// An effect's id: the command that produced it and its position among that command's
/// effects.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EffectId {
    /// The command.
    pub command: Id,
    /// Position, from 0.
    pub index: u32,
}

/// What a scheduled timer is for (docs/24 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Timer {
    /// Send reminders to recipients who have not acted.
    Reminder,
    /// Expire the envelope if required actions are still open.
    Expiry,
    /// Warn recipients who have not acted that the envelope expires soon.
    ExpiryWarning,
}

/// What an invitation is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvitationKind {
    /// Act: sign, approve, view, specify recipients.
    Act,
    /// A carbon copy.
    Copy,
}

/// What a notification tells its readers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Notice {
    /// The envelope was voided.
    Voided,
    /// A recipient declined.
    Declined,
    /// The envelope expired.
    Expired,
    /// The envelope completed.
    Completed,
    /// A recipient is locked after failed authentication.
    AuthLocked,
    /// An invitation bounced.
    Bounced,
    /// A correction changed what this recipient must do.
    Corrected,
}

/// What an operator alert is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Alert {
    /// Sealing failed; it is retried and the envelope stays `completing`.
    SealFailed,
}

/// What a webhook delivery reports (docs/40 §4). Webhook deliveries are not audit
/// events (docs/32 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum WebhookTopic {
    /// `envelope.sent`.
    EnvelopeSent,
    /// `envelope.delivered`.
    EnvelopeDelivered,
    /// `envelope.corrected`.
    EnvelopeCorrected,
    /// `envelope.completing`.
    EnvelopeCompleting,
    /// `envelope.completed`.
    EnvelopeCompleted,
    /// `envelope.declined`.
    EnvelopeDeclined,
    /// `envelope.voided`.
    EnvelopeVoided,
    /// `envelope.expired`.
    EnvelopeExpired,
    /// `envelope.purged`.
    EnvelopePurged,
    /// `recipient.sent`.
    RecipientSent,
    /// `recipient.delivered`.
    RecipientDelivered,
    /// `recipient.completed`.
    RecipientCompleted,
    /// `recipient.declined`.
    RecipientDeclined,
    /// `recipient.reassigned`.
    RecipientReassigned,
    /// `recipient.auth_failed` (locked).
    RecipientAuthLocked,
    /// `recipient.auto_responded`.
    RecipientAutoResponded,
}

/// One thing for the worker to do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum EffectKind {
    /// Send the recipient their invitation (or, for `none` delivery, tell the host the
    /// link is live). The worker answers with `InvitationDispatched` or
    /// `InvitationBounced`.
    SendInvitation {
        /// The recipient.
        recipient: Id,
        /// How.
        channel: Channel,
        /// Act or copy.
        invitation: InvitationKind,
    },
    /// Send a reminder. The worker answers with `ReminderDispatched`.
    SendReminder {
        /// The recipient.
        recipient: Id,
        /// How.
        channel: Channel,
    },
    /// Warn that the envelope expires soon.
    SendExpiryWarning {
        /// The recipient.
        recipient: Id,
        /// How.
        channel: Channel,
    },
    /// Tell the sender.
    NotifySender {
        /// What.
        notice: Notice,
        /// The recipient concerned, when one is.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recipient: Option<Id>,
    },
    /// Tell recipients.
    NotifyRecipients {
        /// Who.
        recipients: Vec<Id>,
        /// What.
        notice: Notice,
    },
    /// Send the completed documents (and certificate) to these recipients.
    SendCompletionCopies {
        /// Who.
        recipients: Vec<Id>,
    },
    /// Fire a timer command (`TimerDue`) at `at`.
    Schedule {
        /// What for.
        timer: Timer,
        /// When.
        at: Timestamp,
    },
    /// Drop these pending jobs and timers: the envelope stopped, or they were replaced.
    Cancel {
        /// The effects to drop.
        effects: Vec<EffectId>,
    },
    /// Flatten, build the certificate, embed the trail, seal at the envelope's profile,
    /// verify with an independent validator, then answer `SealSucceeded` or `SealFailed`.
    SealEnvelope {
        /// Not before this time (a retry's back-off).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        not_before: Option<Timestamp>,
    },
    /// Revoke the recipient's signing tokens.
    RevokeTokens {
        /// The recipient.
        recipient: Id,
    },
    /// Deliver a webhook to subscribers.
    DeliverWebhook {
        /// What happened.
        topic: WebhookTopic,
        /// The recipient concerned, when one is.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recipient: Option<Id>,
    },
    /// Charge a payment field through the `PaymentGateway` (slice 13).
    ChargePayment {
        /// The payer.
        recipient: Id,
        /// The payment field.
        field: Id,
    },
    /// Alert the operator.
    AlertOperator {
        /// What.
        alert: Alert,
        /// The failing job's error code.
        code: Text,
    },
    /// Delete the documents and personal data, keeping a tombstone (docs/32 §7).
    PurgeData {
        /// The policy or request.
        policy: Text,
    },
    /// Delete a draft's stored blobs and rows.
    DeleteDraft,
}

/// An effect and its id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Effect {
    /// The job key, with the envelope id.
    pub id: EffectId,
    /// What to do.
    pub kind: EffectKind,
}
