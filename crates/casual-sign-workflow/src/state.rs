//! The envelope aggregate the engine reads and returns (docs/22 §3–6).
//!
//! The server maps its rows to an [`EnvelopeState`], calls [`crate::decide`], and writes
//! back the state it gets. Personal data (names, addresses, reasons, subject, document
//! names) is wrapped in [`Personal`] and field values sit behind [`Fields`], so `Debug`
//! of a state prints ids, statuses and counts only (`SEC-D01`).

use std::collections::{BTreeMap, BTreeSet};

use casual_sign_audit::{AuthMethod, DocumentHash, Hash256, MarkKind, Personal, Timestamp};
use casual_sign_model::{
    DateFormat, Delivery, EnvelopeStatus, Field, Id, RecipientStatus, RecipientType,
    ReminderPolicy, RoutingOrder, SealProfile, SignatureType, SigningOptions, Text,
};
use serde::{Deserialize, Serialize};

use crate::effect::{EffectId, Timer};

/// A recipient as the sender configures them: everything a correction may change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientSpec {
    /// The recipient's id, minted by the host.
    pub id: Id,
    /// What they do.
    #[serde(rename = "type")]
    pub rtype: RecipientType,
    /// Their routing order.
    pub routing_order: RoutingOrder,
    /// Their name.
    pub name: Personal<Text>,
    /// Their email address; may be empty when an earlier agent, intermediary or editor
    /// will supply it, or when delivery is `none` or `sms`.
    pub email: Personal<Text>,
    /// Their phone number, for SMS delivery and SMS or voice authentication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone: Option<Personal<Text>>,
    /// How their invitation travels.
    #[serde(default)]
    pub delivery: Delivery,
    /// Authentication requirements, every one of which must pass.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auth: Vec<AuthMethod>,
    /// When set, they sign only through the integrator's embedded session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedded_client_user_id: Option<Id>,
    /// Their time zone as minutes east of UTC, for `date_signed` (the host resolves the
    /// zone; the engine holds no time-zone database). -1440 to 1440.
    #[serde(default)]
    pub time_zone_offset_minutes: i16,
    /// Their date format for `date_signed`, when the field names none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_format: Option<DateFormat>,
    /// For a witness: the recipient they witness.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_for: Option<Id>,
    /// Documents this recipient may not see (document visibility, `WF-02`, docs/24 §4).
    /// They are never served to them, never count toward what they view, and their act
    /// records only the documents they saw. A recipient sees at least one document and
    /// is never hidden a document that carries one of their fields.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded_documents: Vec<Id>,
    /// Delayed routing (`WF-02`, docs/24 §4): hours to wait, once routing reaches this
    /// recipient, before they are invited and may act. 0 (the default) invites at once;
    /// at most [`crate::limits::MAX_ROUTE_DELAY_HOURS`] (`CS-WF-0023`); not for a
    /// carbon copy (`CS-WF-0004`).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub route_delay_hours: u16,
    /// How a signer signs (ADR-046 §3.1): simple (absent) or remote with a provider.
    /// Only a `signer` may be remote; two remote signers never share a routing order
    /// (`CS-RSP-0007`).
    #[serde(default, skip_serializing_if = "SignatureType::is_simple")]
    pub signature: SignatureType,
}

// serde's skip_serializing_if passes a reference.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(n: &u16) -> bool {
    *n == 0
}

// serde's skip_serializing_if passes a reference.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_u32(n: &u32) -> bool {
    *n == 0
}

impl RecipientSpec {
    /// Whether the recipient may see document `id` (`WF-02`).
    #[must_use]
    pub fn sees(&self, id: &Id) -> bool {
        !self.excluded_documents.contains(id)
    }
}

/// Consent to electronic records as recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentRecord {
    /// The disclosure's version label.
    pub ersd_version: Text,
    /// SHA-256 of the disclosure text shown.
    pub ersd_hash: Hash256,
}

/// A remote signing session open for a recipient (ADR-046 §3.4): the recipient's
/// `signing_remotely` sub-state. Their values are frozen while it is open; it closes when
/// the provider's signature is embedded, or fails and reopens their fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteSession {
    /// The session id, minted by the host.
    pub session: Id,
    /// The provider, as the recipient's signature type names it.
    pub provider_id: Id,
    /// When it opened.
    pub started_at: Timestamp,
    /// The documents were prepared (their hashes recorded in
    /// `recipient.remote_signing_prepared`).
    #[serde(default)]
    pub prepared: bool,
}

/// A recipient and how far they have come (docs/22 §5, docs/24 §3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientState {
    /// What the sender configured.
    pub spec: RecipientSpec,
    /// Where they are.
    pub status: RecipientStatus,
    /// Requirements passed in this round.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auth_passed: Vec<AuthMethod>,
    /// Failed attempts since the last reset.
    #[serde(default)]
    pub auth_failures: u32,
    /// Locked after too many failures; the sender's resend unlocks.
    #[serde(default)]
    pub auth_locked: bool,
    /// The disclosure they accepted, while it stands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent: Option<ConsentRecord>,
    /// Marks adopted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub adopted: Vec<MarkKind>,
    /// Documents viewed to their last page.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub viewed_to_end: BTreeSet<Id>,
    /// The staff user hosting an in-person signing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_person_host: Option<Id>,
    /// The documents, with the hashes they saw, they signed, approved or viewed when
    /// they completed. A correction that replaces one sends them back to act again.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub acted_documents: Vec<DocumentHash>,
    /// They chose to finish later and have not finished since.
    #[serde(default)]
    pub finish_later: bool,
    /// When they completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<Timestamp>,
    /// The reason they declined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declined_reason: Option<Personal<Text>>,
    /// Who they reassigned to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reassigned_to: Option<Id>,
    /// Who reassigned to them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reassigned_from: Option<Id>,
    /// Delayed routing (`WF-02`): routing reached them and they wait until this time to
    /// be invited and act. Set when their turn comes with a `route_delay_hours`; cleared
    /// when they go out of turn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held_until: Option<Timestamp>,
    /// Their open remote signing session (ADR-046 §3.4), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<RemoteSession>,
    /// Remote signing sessions that failed for them, for the sender's notice after the
    /// third (ADR-046 §3.12).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub remote_failures: u32,
}

impl RecipientState {
    /// A recipient routing has not reached.
    #[must_use]
    pub fn new(spec: RecipientSpec) -> Self {
        Self {
            spec,
            status: RecipientStatus::Created,
            auth_passed: Vec::new(),
            auth_failures: 0,
            auth_locked: false,
            consent: None,
            adopted: Vec::new(),
            viewed_to_end: BTreeSet::new(),
            in_person_host: None,
            acted_documents: Vec::new(),
            finish_later: false,
            completed_at: None,
            declined_reason: None,
            reassigned_to: None,
            reassigned_from: None,
            held_until: None,
            remote: None,
            remote_failures: 0,
        }
    }

    /// Whether delayed routing still holds them at `now` (`WF-02`): not invited, and
    /// refused every act as not yet their turn.
    #[must_use]
    pub fn held(&self, now: Timestamp) -> bool {
        self.held_until.is_some_and(|t| t > now)
    }

    /// The recipient's id.
    #[must_use]
    pub fn id(&self) -> &Id {
        &self.spec.id
    }

    /// Whether the envelope waits for them: a required action, and not handed over.
    #[must_use]
    pub fn is_required(&self) -> bool {
        self.spec.rtype.has_required_action() && self.status != RecipientStatus::Reassigned
    }

    /// Whether every authentication requirement has passed.
    #[must_use]
    pub fn auth_satisfied(&self) -> bool {
        self.spec.auth.iter().all(|m| self.auth_passed.contains(m))
    }
}

/// A document of the envelope (docs/22 §4). The engine sees hashes, never bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentSpec {
    /// The document's id.
    pub id: Id,
    /// Its display name (never a path).
    pub name: Personal<Text>,
    /// SHA-256 of the uploaded bytes.
    pub upload_hash: Hash256,
    /// Size of the upload in bytes, at most 2^53 - 1.
    pub bytes: u64,
    /// SHA-256 of the normalized bytes delivered to signers (docs/30 §1).
    pub delivered_hash: Hash256,
    /// Pages of the delivered document, 1 to 5,000.
    pub pages: u32,
    /// SHA-256 of the admission report, and its finding count (docs/30 §2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission: Option<(Hash256, u32)>,
}

/// A document and whether its delivered bytes are fixed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentState {
    /// What was uploaded and admitted.
    pub spec: DocumentSpec,
    /// Fixed at send (or at the correction that added it): `document.fixed` recorded.
    #[serde(default)]
    pub fixed: bool,
}

impl DocumentState {
    /// The document's id.
    #[must_use]
    pub fn id(&self) -> &Id {
        &self.spec.id
    }

    /// The document and its delivered hash, as events record it.
    #[must_use]
    pub fn hash(&self) -> DocumentHash {
        DocumentHash {
            document_id: self.spec.id.clone(),
            hash: self.spec.delivered_hash,
        }
    }
}

/// The envelope's fields, with values. `Debug` prints the count only: values are what
/// signers typed (docs/32 §1.5).
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Fields(pub Vec<Field>);

impl core::fmt::Debug for Fields {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Fields({})", self.0.len())
    }
}

/// A scheduled timer the engine is waiting for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledTimer {
    /// The effect that scheduled it, which its `TimerDue` names.
    pub id: EffectId,
    /// What it is for.
    pub timer: Timer,
    /// When it is due.
    pub at: Timestamp,
}

/// What the engine keeps for itself: applied commands, pending timers and the pending
/// seal job. Changing only these is not a state change that needs an audit event.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Bookkeeping {
    /// Every applied command id and the SHA-256 of its canonical form, for idempotent
    /// re-application.
    #[serde(default)]
    pub applied: BTreeMap<Id, Hash256>,
    /// Timers scheduled and not yet fired or cancelled.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scheduled: Vec<ScheduledTimer>,
    /// The seal job pending while `completing`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_job: Option<EffectId>,
    /// Recipients delayed routing holds whose invitation has not gone out (`WF-02`).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub held: BTreeSet<Id>,
}

/// An envelope (docs/22 §3) as the engine sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeState {
    /// The envelope's id.
    pub id: Id,
    /// The tenant.
    pub account_id: Id,
    /// The sender (owner).
    pub sender_user_id: Id,
    /// Where it is.
    pub status: EnvelopeStatus,
    /// Optimistic concurrency: raised by every accepted state change (docs/24 §1).
    pub version: u64,
    /// Email subject.
    pub subject: Personal<Text>,
    /// Email message.
    pub message: Personal<Text>,
    /// Documents, in order.
    pub documents: Vec<DocumentState>,
    /// Recipients, in the order added (routing order is their own member).
    pub recipients: Vec<RecipientState>,
    /// Fields, with values.
    pub fields: Fields,
    /// When it expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
    /// Reminders.
    #[serde(default)]
    pub reminders: ReminderPolicy,
    /// What recipients may do.
    #[serde(default)]
    pub options: SigningOptions,
    /// The PAdES level.
    #[serde(default)]
    pub seal_profile: SealProfile,
    /// When it was created.
    pub created_at: Timestamp,
    /// When it was sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent_at: Option<Timestamp>,
    /// A draft scheduled to send itself at this time (`WF-02`, docs/24 §2); cleared when
    /// it is sent or the schedule is cancelled. A scheduled draft cannot be edited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_at: Option<Timestamp>,
    /// When it reached a terminal status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<Timestamp>,
    /// The void reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub void_reason: Option<Personal<Text>>,
    /// The sealed documents' hashes, once completed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sealed: Vec<DocumentHash>,
    /// Documents and personal data purged (or a draft deleted); nothing more happens.
    #[serde(default)]
    pub purged: bool,
    /// When an envelope that ended without completing was removed from the sender's
    /// lists (`Command::DeleteEnded`, WEB-08); its evidence stays.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<Timestamp>,
    /// Documents past their lock point (ADR-046 §3.2): a remote signature was prepared
    /// over them, so their layout is frozen (`CS-RSP-0007`).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub locked_documents: BTreeSet<Id>,
    /// The engine's own records.
    #[serde(default)]
    pub book: Bookkeeping,
}

impl EnvelopeState {
    /// The recipient's position.
    #[must_use]
    pub fn recipient_index(&self, id: &Id) -> Option<usize> {
        self.recipients.iter().position(|r| r.id() == id)
    }

    /// The recipient.
    #[must_use]
    pub fn recipient(&self, id: &Id) -> Option<&RecipientState> {
        self.recipients.iter().find(|r| r.id() == id)
    }

    /// The document.
    #[must_use]
    pub fn document(&self, id: &Id) -> Option<&DocumentState> {
        self.documents.iter().find(|d| d.id() == id)
    }

    /// Whether it is terminal or purged: nothing but recording access may follow.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.purged || self.status.is_terminal()
    }

    /// Whether routing lets recipient `index` act: every required recipient with a lower
    /// routing order has completed (docs/24 §4).
    #[must_use]
    pub fn turn_reached(&self, index: usize) -> bool {
        let Some(me) = self.recipients.get(index) else {
            return false;
        };
        self.recipients.iter().all(|q| {
            !q.is_required()
                || q.spec.routing_order >= me.spec.routing_order
                || q.status == RecipientStatus::Completed
        })
    }

    /// The documents recipient `index` may see, as events record them (`WF-02`).
    #[must_use]
    pub fn visible_documents(&self, index: usize) -> Vec<DocumentHash> {
        let Some(r) = self.recipients.get(index) else {
            return Vec::new();
        };
        self.documents
            .iter()
            .filter(|d| r.spec.sees(d.id()))
            .map(DocumentState::hash)
            .collect()
    }

    /// Everything but the engine's bookkeeping and the version: what an audit event must
    /// account for when it changes.
    #[must_use]
    pub fn observable(&self) -> Self {
        let mut s = self.clone();
        s.book = Bookkeeping::default();
        s.version = 0;
        s
    }

    /// Every pending timer and seal job, as effect ids.
    #[must_use]
    pub fn pending_effects(&self) -> Vec<EffectId> {
        let mut ids: Vec<EffectId> = self.book.scheduled.iter().map(|t| t.id.clone()).collect();
        ids.extend(self.book.seal_job.iter().cloned());
        ids
    }
}
