//! Envelope and recipient vocabulary (docs/22 §3, §5; docs/24 §2–4): statuses, recipient
//! types, routing order and the envelope's settings.
//!
//! These are the plain values the workflow engine (`casual-sign-workflow`) moves through
//! its state machines. The aggregate that holds them together with hashes and times lives
//! in the engine, because it carries audit types (`Hash256`, `Timestamp`) this crate does
//! not depend on (stage 2A decision, docs/24 §As built).

use serde::{Deserialize, Serialize};

use crate::ModelError;

/// An envelope's status (docs/22 §3, docs/24 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeStatus {
    /// Being prepared; documents, recipients and fields may change freely.
    Draft,
    /// Sent; routing has reached at least one recipient.
    Sent,
    /// Every recipient routing has reached has opened it (DocuSign's meaning, docs/48 §6).
    /// A reporting state with the same permissions as [`Self::Sent`].
    Delivered,
    /// Every required action is done; flattening, the certificate and sealing run.
    Completing,
    /// Sealed and verified. Terminal.
    Completed,
    /// A recipient declined. Terminal.
    Declined,
    /// The sender or an administrator voided it. Terminal.
    Voided,
    /// Its expiry passed with required actions open. Terminal.
    Expired,
}

impl EnvelopeStatus {
    /// Whether no further status change is possible (purge only marks, docs/32 §7).
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Declined | Self::Voided | Self::Expired
        )
    }

    /// Whether recipients may act: [`Self::Sent`] or [`Self::Delivered`].
    #[must_use]
    pub fn is_in_flight(self) -> bool {
        matches!(self, Self::Sent | Self::Delivered)
    }
}

/// A recipient's status (docs/22 §5, docs/24 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipientStatus {
    /// Routing has not reached them.
    Created,
    /// Routing reached them; their invitation is out.
    Sent,
    /// They opened their link.
    Delivered,
    /// They passed every authentication requirement.
    Authenticated,
    /// They finished their part.
    Completed,
    /// They declined.
    Declined,
    /// Their invitation bounced; the sender is alerted and may correct the address.
    AutoResponded,
    /// They handed their part to a new recipient at the same routing order.
    Reassigned,
}

impl RecipientStatus {
    /// Whether routing has reached them and they have not finished, declined or handed
    /// over: their invitation and tokens are live.
    #[must_use]
    pub fn is_active(self) -> bool {
        matches!(
            self,
            Self::Sent | Self::Delivered | Self::Authenticated | Self::AutoResponded
        )
    }

    /// Whether they have opened their link (and not finished).
    #[must_use]
    pub fn has_opened(self) -> bool {
        matches!(self, Self::Delivered | Self::Authenticated)
    }
}

/// What a recipient does (docs/22 §5, docs/24 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipientType {
    /// Signs.
    Signer,
    /// Signs in person, hosted by a staff user who authenticates first.
    InPersonSigner,
    /// Approves or declines; never signs.
    Approver,
    /// Needs to view: completes by viewing every document to the end.
    Viewer,
    /// Receives a copy; no action.
    Cc,
    /// Allowed to edit later recipients and fields before signing; then signs.
    Editor,
    /// Updates later recipients (name, email, authentication), then completes.
    Intermediary,
    /// Specifies later recipients' names and emails, then completes.
    Agent,
    /// Witnesses a signer and signs (slice 16).
    Witness,
    /// A legal-entity seal applied through `RemoteSigner` (slice 18).
    Seal,
    /// A notary (slice 31).
    Notary,
}

impl RecipientType {
    /// Whether the envelope waits for this recipient: everyone but a carbon copy.
    #[must_use]
    pub fn has_required_action(self) -> bool {
        !matches!(self, Self::Cc)
    }

    /// Whether this recipient signs (and so may hold signature and input fields).
    #[must_use]
    pub fn signs(self) -> bool {
        matches!(
            self,
            Self::Signer
                | Self::InPersonSigner
                | Self::Editor
                | Self::Witness
                | Self::Seal
                | Self::Notary
        )
    }

    /// Whether this recipient may name or edit later recipients (docs/24 §3).
    #[must_use]
    pub fn edits_recipients(self) -> bool {
        matches!(self, Self::Editor | Self::Intermediary | Self::Agent)
    }
}

/// A routing order: recipients with equal numbers act in parallel, distinct numbers in
/// sequence (docs/24 §4). 1 to 999, as DocuSign's `routingOrder`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct RoutingOrder(u32);

impl RoutingOrder {
    /// The highest routing order.
    pub const MAX: u32 = 999;

    /// Builds a routing order, refusing 0 and anything over 999 (`CS-WF-0004`).
    pub fn new(order: u32) -> Result<Self, ModelError> {
        if (1..=Self::MAX).contains(&order) {
            Ok(Self(order))
        } else {
            Err(ModelError::RoutingOrderOutOfRange { order })
        }
    }

    /// The number.
    #[must_use]
    pub fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for RoutingOrder {
    type Error = ModelError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<RoutingOrder> for u32 {
    fn from(value: RoutingOrder) -> Self {
        value.0
    }
}

/// How a recipient's invitation travels (docs/22 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Delivery {
    /// By email.
    #[default]
    Email,
    /// By SMS.
    Sms,
    /// Embedded: the host delivers the link.
    None,
}

/// The PAdES level the envelope is sealed at (docs/22 §3, docs/31).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum SealProfile {
    /// PAdES B-T (the default).
    #[default]
    #[serde(rename = "pades-b-t")]
    PadesBT,
    /// PAdES B-LT.
    #[serde(rename = "pades-b-lt")]
    PadesBLt,
    /// PAdES B-LTA.
    #[serde(rename = "pades-b-lta")]
    PadesBLta,
}

impl SealProfile {
    /// The profile's name as `document.sealed` records it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PadesBT => "pades-b-t",
            Self::PadesBLt => "pades-b-lt",
            Self::PadesBLta => "pades-b-lta",
        }
    }
}

/// What recipients may do besides finishing (docs/22 §3 `signing_options`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningOptions {
    /// A recipient may hand their part to someone else.
    #[serde(default = "yes")]
    pub allow_reassign: bool,
    /// A recipient may decline.
    #[serde(default = "yes")]
    pub allow_decline: bool,
    /// A recipient may stop and finish later.
    #[serde(default = "yes")]
    pub allow_finish_later: bool,
}

fn yes() -> bool {
    true
}

impl Default for SigningOptions {
    fn default() -> Self {
        Self {
            allow_reassign: true,
            allow_decline: true,
            allow_finish_later: true,
        }
    }
}

/// When reminders go out (docs/22 §3 `reminder_policy`): first after `first_after_days`
/// days, then every `then_every_days` days. Zero turns the step off. At most 999 days
/// each (DocuSign's bound).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(try_from = "ReminderPolicyWire", into = "ReminderPolicyWire")]
pub struct ReminderPolicy {
    first_after_days: u16,
    then_every_days: u16,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReminderPolicyWire {
    #[serde(default)]
    first_after_days: u16,
    #[serde(default)]
    then_every_days: u16,
}

impl ReminderPolicy {
    /// The most days either step may be.
    pub const MAX_DAYS: u16 = 999;

    /// Builds a policy, refusing a step over 999 days (`CS-WF-0004`).
    pub fn new(first_after_days: u16, then_every_days: u16) -> Result<Self, ModelError> {
        if first_after_days > Self::MAX_DAYS || then_every_days > Self::MAX_DAYS {
            return Err(ModelError::ReminderOutOfRange);
        }
        Ok(Self {
            first_after_days,
            then_every_days,
        })
    }

    /// No reminders.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Days after sending before the first reminder; 0 for none.
    #[must_use]
    pub fn first_after_days(self) -> u16 {
        self.first_after_days
    }

    /// Days between later reminders; 0 for none.
    #[must_use]
    pub fn then_every_days(self) -> u16 {
        self.then_every_days
    }
}

impl TryFrom<ReminderPolicyWire> for ReminderPolicy {
    type Error = ModelError;
    fn try_from(w: ReminderPolicyWire) -> Result<Self, Self::Error> {
        Self::new(w.first_after_days, w.then_every_days)
    }
}

impl From<ReminderPolicy> for ReminderPolicyWire {
    fn from(p: ReminderPolicy) -> Self {
        Self {
            first_after_days: p.first_after_days,
            then_every_days: p.then_every_days,
        }
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (CLAUDE.md): a failure here is the test failing.
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn routing_order_is_bounded() {
        assert!(RoutingOrder::new(0).is_err());
        assert_eq!(RoutingOrder::new(1).unwrap().get(), 1);
        assert_eq!(RoutingOrder::new(999).unwrap().get(), 999);
        let e = RoutingOrder::new(1000).unwrap_err();
        assert_eq!(e.code(), "CS-WF-0004");
        assert!(serde_json::from_str::<RoutingOrder>("0").is_err());
        assert_eq!(serde_json::from_str::<RoutingOrder>("7").unwrap().get(), 7);
    }

    #[test]
    fn terminal_statuses() {
        use EnvelopeStatus::*;
        for s in [Completed, Declined, Voided, Expired] {
            assert!(s.is_terminal());
        }
        for s in [Draft, Sent, Delivered, Completing] {
            assert!(!s.is_terminal());
        }
    }

    #[test]
    fn reminder_policy_is_bounded_and_round_trips() {
        assert!(ReminderPolicy::new(1000, 0).is_err());
        let p = ReminderPolicy::new(2, 3).unwrap();
        let s = serde_json::to_string(&p).unwrap();
        assert_eq!(s, r#"{"first_after_days":2,"then_every_days":3}"#);
        assert_eq!(serde_json::from_str::<ReminderPolicy>(&s).unwrap(), p);
        assert!(serde_json::from_str::<ReminderPolicy>(r#"{"first_after_days":1000}"#).is_err());
    }

    #[test]
    fn seal_profile_wire_names() {
        assert_eq!(
            serde_json::to_string(&SealProfile::PadesBLta).unwrap(),
            "\"pades-b-lta\""
        );
        assert_eq!(SealProfile::default().as_str(), "pades-b-t");
    }

    #[test]
    fn signing_options_default_to_allowed() {
        let o: SigningOptions = serde_json::from_str("{}").unwrap();
        assert_eq!(o, SigningOptions::default());
        assert!(o.allow_decline && o.allow_reassign && o.allow_finish_later);
    }
}
