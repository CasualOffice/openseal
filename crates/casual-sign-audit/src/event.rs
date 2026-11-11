//! The audit event (docs/32 §2) and its types (docs/32 §3).
//!
//! An event is `{ v, envelope_id, seq, prev, at, type, actor, context, data }`. Its hash
//! is SHA-256 over the RFC 8785 canonical JSON of the event without a `hash` member;
//! `prev` is the previous event's hash, `null` on the first (`seq` 0).
//!
//! **Personal data** is wrapped in [`Personal`], whose `Debug` never prints the value, so
//! an event can be logged by id and type without leaking a name or address (SEC-D01).
//! [`PERSONAL_MEMBERS`] lists where it sits on the wire, for purge and export (docs/32 §7,
//! docs/07 data classification). Values a signer typed are never in an event: only their
//! hashes are (docs/32 §1.5).

use std::collections::BTreeMap;

use casual_sign_model::Id;
use serde::{Deserialize, Serialize};

use crate::error::{AuditError, ShapeFault};
use crate::hash::Hash256;
use crate::jcs;
use crate::json::{MAX_SAFE_INTEGER, Value};
use crate::location::{Location, location_from_serde};
use crate::time::Timestamp;

/// The event schema version this build writes and reads.
pub const EVENT_VERSION: u64 = 1;

/// Where personal data sits in an event on the wire, as JSON member paths. Purge removes
/// these with the documents; export of a data subject's records reads them.
pub const PERSONAL_MEMBERS: &[&str] = &[
    "actor.name",
    "actor.email",
    "context.ip",
    "context.user_agent",
    "context.location",
    "data.reason",
    "data.host_claim",
];

/// A personal value (a name, an address, free text a person wrote). Serialized as the
/// value itself; `Debug` prints `<personal>` so it never reaches a log in clear.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Personal<T>(pub T);

impl<T> core::fmt::Debug for Personal<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("<personal>")
    }
}

impl<T> Personal<T> {
    /// The value.
    pub fn get(&self) -> &T {
        &self.0
    }
}

/// Who acted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ActorKind {
    /// The platform itself: a job, a timer, the sealing service.
    System,
    /// The envelope's sender.
    Sender,
    /// A recipient.
    Recipient,
    /// Another user of the account (an administrator, an in-person host).
    User,
    /// An embedding host application, through the API.
    Host,
}

/// The actor of an event. Name and email are personal data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    /// What kind of actor.
    pub kind: ActorKind,
    /// The actor's id (user, recipient or API client), when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Id>,
    /// The name shown, as it was at the time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<Personal<String>>,
    /// The email address, as it was at the time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<Personal<String>>,
}

impl Actor {
    /// The platform itself.
    #[must_use]
    pub fn system() -> Self {
        Self {
            kind: ActorKind::System,
            id: None,
            name: None,
            email: None,
        }
    }
}

/// How a recipient was authenticated (docs/48 §7, docs/09 UETA §9 attribution).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuthMethod {
    /// Possession of the emailed link.
    EmailLink,
    /// An access code the sender shared out of band.
    AccessCode,
    /// A one-time code by SMS.
    SmsOtp,
    /// A one-time code by voice call.
    VoiceOtp,
    /// Knowledge-based authentication.
    Kba,
    /// Identity document verification.
    IdVerification,
    /// Single sign-on through the account's identity provider.
    Sso,
    /// A signed-in account user.
    AccountLogin,
    /// The embedding host asserts it authenticated the signer.
    HostAsserted,
    /// A one-time code by email (SEC-A02). Added after the others, so every chain
    /// written before it hashes exactly as it did (`tests/compat.rs`).
    EmailOtp,
}

/// Request context. IP, user agent and location are personal data.
///
/// Every member is absent from the wire when unset, so an event without a location
/// hashes exactly as it did before `location` existed (GEO-01; `tests/compat.rs`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Context {
    /// The client's IP address as the server saw it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<Personal<String>>,
    /// The client's user agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<Personal<String>>,
    /// Authentication methods satisfied in this session.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auth: Vec<AuthMethod>,
    /// A hash naming the session (never the session secret).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<Hash256>,
    /// Where the signer was: from their device, or approximated from the IP address with
    /// the reason the device was not used (GEO-01). Recorded on recipient actions when
    /// the envelope captures location (docs/24 §3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<Personal<Location>>,
}

/// How a message reached a recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Channel {
    /// Email.
    Email,
    /// SMS.
    Sms,
    /// WhatsApp.
    Whatsapp,
    /// A link the sender or host delivered.
    Link,
}

/// How a signature image was made (ESIGN §7006(5) adoption, docs/09).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AdoptionMethod {
    /// Drawn on a pad.
    Draw,
    /// Typed and set in a script face.
    Type,
    /// An uploaded image.
    Upload,
}

/// Which mark was adopted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum MarkKind {
    /// A full signature.
    Signature,
    /// Initials.
    Initials,
}

/// One document's hash in an event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentHash {
    /// The document.
    pub document_id: Id,
    /// SHA-256 of its bytes.
    pub hash: Hash256,
}

/// The events of docs/32 §3, each with its data. Wire form: `"type"` is the dotted name,
/// `"data"` the object of the variant's members (always an object, `{}` when empty).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
#[non_exhaustive]
pub enum EventData {
    // Envelope ------------------------------------------------------------------------
    /// The envelope was created.
    #[serde(rename = "envelope.created")]
    EnvelopeCreated {
        /// SHA-256 of the subject as entered (the subject itself is on the certificate).
        subject_hash: Hash256,
    },
    /// The envelope was sent.
    #[serde(rename = "envelope.sent")]
    EnvelopeSent {
        /// Recipients at send.
        recipients: u32,
        /// Documents at send.
        documents: u32,
    },
    /// The sender corrected the envelope after sending.
    #[serde(rename = "envelope.corrected")]
    EnvelopeCorrected {
        /// The members changed, by path (`recipient.email`, `expires_at`, …).
        changed: Vec<String>,
    },
    /// The sender voided the envelope.
    #[serde(rename = "envelope.voided")]
    EnvelopeVoided {
        /// The sender's reason.
        reason: Personal<String>,
    },
    /// A recipient's decline ended the envelope.
    #[serde(rename = "envelope.declined")]
    EnvelopeDeclined {
        /// The recipient who declined.
        recipient_id: Id,
    },
    /// The envelope expired.
    #[serde(rename = "envelope.expired")]
    EnvelopeExpired {},
    /// Every recipient finished; flattening, the certificate and sealing begin. The
    /// certificate prints the head of the chain ending here.
    #[serde(rename = "envelope.completing")]
    EnvelopeCompleting {},
    /// The sealed documents are ready.
    #[serde(rename = "envelope.completed")]
    EnvelopeCompleted {
        /// SHA-256 of each sealed document.
        sealed: Vec<DocumentHash>,
    },
    /// Documents and personal data were purged (docs/32 §7); a tombstone remains.
    #[serde(rename = "envelope.purged")]
    EnvelopePurged {
        /// The retention policy or request that purged it.
        policy: String,
    },
    /// An envelope that ended without completing was removed from the sender's lists
    /// (WEB-08); nothing was purged: its documents, state and this chain stay.
    #[serde(rename = "envelope.deleted")]
    EnvelopeDeleted {},

    // Document ------------------------------------------------------------------------
    /// A document was uploaded.
    #[serde(rename = "document.added")]
    DocumentAdded {
        /// The document.
        document_id: Id,
        /// SHA-256 of the uploaded bytes.
        upload_hash: Hash256,
        /// Size in bytes.
        bytes: u64,
    },
    /// The document was admitted (docs/30 §2).
    #[serde(rename = "document.admitted")]
    DocumentAdmitted {
        /// The document.
        document_id: Id,
        /// SHA-256 of the admission report.
        report_hash: Hash256,
        /// Findings in the report.
        findings: u32,
    },
    /// The bytes delivered to signers were fixed at send (docs/30 §1).
    #[serde(rename = "document.fixed")]
    DocumentFixed {
        /// The document.
        document_id: Id,
        /// SHA-256 of the delivered bytes.
        delivered_hash: Hash256,
        /// Pages.
        pages: u32,
    },
    /// A document was replaced by a correction.
    #[serde(rename = "document.replaced")]
    DocumentReplaced {
        /// The document.
        document_id: Id,
        /// The hash it had.
        previous_hash: Hash256,
        /// The hash it has now.
        delivered_hash: Hash256,
    },
    /// Field values were drawn into the document (docs/30 §7).
    #[serde(rename = "document.flattened")]
    DocumentFlattened {
        /// The document.
        document_id: Id,
        /// SHA-256 of the flattened bytes.
        flattened_hash: Hash256,
    },
    /// The document was sealed (docs/31).
    #[serde(rename = "document.sealed")]
    DocumentSealed {
        /// The document.
        document_id: Id,
        /// SHA-256 of the sealed bytes.
        sealed_hash: Hash256,
        /// The seal profile (`pades-b-lta`, …).
        profile: String,
        /// SHA-256 of the sealing certificate (DER).
        certificate_fingerprint: Hash256,
        /// The timestamp authority's time, when one was applied.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tsa_time: Option<Timestamp>,
    },

    // Recipient -----------------------------------------------------------------------
    /// An invitation was sent.
    #[serde(rename = "invitation.sent")]
    InvitationSent {
        /// The recipient.
        recipient_id: Id,
        /// How.
        channel: Channel,
    },
    /// An invitation bounced.
    #[serde(rename = "invitation.bounced")]
    InvitationBounced {
        /// The recipient.
        recipient_id: Id,
        /// How it was sent.
        channel: Channel,
    },
    /// A reminder was sent.
    #[serde(rename = "reminder.sent")]
    ReminderSent {
        /// The recipient.
        recipient_id: Id,
        /// How.
        channel: Channel,
    },
    /// The recipient opened the link.
    #[serde(rename = "recipient.delivered")]
    RecipientDelivered {
        /// The recipient.
        recipient_id: Id,
    },
    /// The recipient was asked to authenticate.
    #[serde(rename = "recipient.auth_challenged")]
    RecipientAuthChallenged {
        /// The recipient.
        recipient_id: Id,
        /// The method.
        method: AuthMethod,
    },
    /// The recipient authenticated.
    #[serde(rename = "recipient.auth_passed")]
    RecipientAuthPassed {
        /// The recipient.
        recipient_id: Id,
        /// The method.
        method: AuthMethod,
    },
    /// An authentication attempt failed.
    #[serde(rename = "recipient.auth_failed")]
    RecipientAuthFailed {
        /// The recipient.
        recipient_id: Id,
        /// The method.
        method: AuthMethod,
        /// The attempt number, from 1.
        attempt: u32,
    },
    /// The recipient consented to electronic records (ESIGN §7001(c), docs/09).
    #[serde(rename = "recipient.consented")]
    RecipientConsented {
        /// The recipient.
        recipient_id: Id,
        /// The disclosure's version label.
        ersd_version: String,
        /// SHA-256 of the disclosure text shown.
        ersd_hash: Hash256,
    },
    /// The recipient withdrew consent.
    #[serde(rename = "recipient.consent_withdrawn")]
    RecipientConsentWithdrawn {
        /// The recipient.
        recipient_id: Id,
        /// The disclosure version withdrawn from.
        ersd_version: String,
    },
    /// The recipient viewed a document.
    #[serde(rename = "recipient.viewed_document")]
    RecipientViewedDocument {
        /// The recipient.
        recipient_id: Id,
        /// The document and the hash of the bytes shown.
        document: DocumentHash,
        /// Pages seen, 1-based.
        pages_seen: Vec<u32>,
    },
    /// The recipient adopted a signature or initials (intent, ESIGN §7006(5)).
    #[serde(rename = "recipient.signature_adopted")]
    RecipientSignatureAdopted {
        /// The recipient.
        recipient_id: Id,
        /// Signature or initials.
        mark: MarkKind,
        /// How it was made.
        method: AdoptionMethod,
        /// SHA-256 of the image or strokes as stored.
        image_hash: Hash256,
    },
    /// The recipient completed a field.
    #[serde(rename = "recipient.field_completed")]
    RecipientFieldCompleted {
        /// The recipient.
        recipient_id: Id,
        /// The field.
        field_id: Id,
        /// SHA-256 of the value (the value is in the sealed document).
        value_hash: Hash256,
    },
    /// The recipient signed.
    #[serde(rename = "recipient.signed")]
    RecipientSigned {
        /// The recipient.
        recipient_id: Id,
        /// The documents signed, with the hashes of the bytes they saw.
        documents: Vec<DocumentHash>,
        /// SHA-256 of each field value, by field id.
        field_value_hashes: BTreeMap<Id, Hash256>,
    },
    /// The recipient approved.
    #[serde(rename = "recipient.approved")]
    RecipientApproved {
        /// The recipient.
        recipient_id: Id,
        /// The documents approved.
        documents: Vec<DocumentHash>,
    },
    /// The recipient finished their part (any role).
    #[serde(rename = "recipient.completed")]
    RecipientCompleted {
        /// The recipient.
        recipient_id: Id,
    },
    /// The recipient declined.
    #[serde(rename = "recipient.declined")]
    RecipientDeclined {
        /// The recipient.
        recipient_id: Id,
        /// The reason they gave.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<Personal<String>>,
    },
    /// The recipient handed their part to someone else.
    #[serde(rename = "recipient.reassigned")]
    RecipientReassigned {
        /// The recipient.
        recipient_id: Id,
        /// The new recipient.
        to_recipient_id: Id,
        /// The reason they gave.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<Personal<String>>,
    },
    /// The recipient chose to finish later.
    #[serde(rename = "recipient.finish_later")]
    RecipientFinishLater {
        /// The recipient.
        recipient_id: Id,
    },
    /// A user hosted the recipient's signing in person.
    #[serde(rename = "recipient.in_person_hosted")]
    RecipientInPersonHosted {
        /// The recipient.
        recipient_id: Id,
        /// The host user.
        host_user_id: Id,
    },

    // Access --------------------------------------------------------------------------
    /// The sender viewed the envelope.
    #[serde(rename = "envelope.viewed_by_sender")]
    EnvelopeViewedBySender {},
    /// A document was downloaded (the actor says by whom).
    #[serde(rename = "document.downloaded")]
    DocumentDownloaded {
        /// The document and the hash of the bytes served.
        document: DocumentHash,
    },
    /// The certificate of completion was downloaded.
    #[serde(rename = "certificate.downloaded")]
    CertificateDownloaded {
        /// SHA-256 of the bytes served.
        hash: Hash256,
    },
    /// A signer's attachment was downloaded (WEB-08; the actor says by whom).
    #[serde(rename = "attachment.downloaded")]
    AttachmentDownloaded {
        /// The attachment field whose value names the file.
        field_id: Id,
        /// SHA-256 of the bytes served.
        hash: Hash256,
    },

    // Integration ---------------------------------------------------------------------
    /// An embedding host asserted that it authenticated the signer.
    #[serde(rename = "auth.asserted_by_host")]
    AuthAssertedByHost {
        /// The recipient.
        recipient_id: Id,
        /// The host's statement of how (free text it supplied).
        host_claim: Personal<String>,
    },
}

impl EventData {
    /// Every wire type name of docs/32 §3, in the order of the table.
    pub const TYPES: &'static [&'static str] = &[
        "envelope.created",
        "envelope.sent",
        "envelope.corrected",
        "envelope.voided",
        "envelope.declined",
        "envelope.expired",
        "envelope.completing",
        "envelope.completed",
        "envelope.purged",
        "envelope.deleted",
        "document.added",
        "document.admitted",
        "document.fixed",
        "document.replaced",
        "document.flattened",
        "document.sealed",
        "invitation.sent",
        "invitation.bounced",
        "reminder.sent",
        "recipient.delivered",
        "recipient.auth_challenged",
        "recipient.auth_passed",
        "recipient.auth_failed",
        "recipient.consented",
        "recipient.consent_withdrawn",
        "recipient.viewed_document",
        "recipient.signature_adopted",
        "recipient.field_completed",
        "recipient.signed",
        "recipient.approved",
        "recipient.completed",
        "recipient.declined",
        "recipient.reassigned",
        "recipient.finish_later",
        "recipient.in_person_hosted",
        "envelope.viewed_by_sender",
        "document.downloaded",
        "certificate.downloaded",
        "attachment.downloaded",
        "auth.asserted_by_host",
    ];
}

/// One audit event (docs/32 §2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// Schema version ([`EVENT_VERSION`]).
    pub v: u64,
    /// The envelope whose chain this is.
    pub envelope_id: Id,
    /// Position in the chain, dense from 0.
    pub seq: u64,
    /// The previous event's hash; `None` on the first.
    pub prev: Option<Hash256>,
    /// The server's time.
    pub at: Timestamp,
    /// Who acted.
    pub actor: Actor,
    /// Request context.
    pub context: Context,
    /// The type and its data.
    pub data: EventData,
}

/// A serde value to this crate's JSON tree.
pub(crate) fn from_serde(v: serde_json::Value) -> Result<Value, AuditError> {
    Ok(match v {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(b),
        serde_json::Value::Number(n) => {
            // Integers must be exact in a double (I-JSON).
            if let Some(u) = n.as_u64()
                && u > MAX_SAFE_INTEGER
            {
                return Err(AuditError::shape(ShapeFault::Seq));
            }
            Value::Number(n.as_f64().ok_or(AuditError::shape(ShapeFault::Seq))?)
        }
        serde_json::Value::String(s) => Value::String(s),
        serde_json::Value::Array(a) => Value::Array(
            a.into_iter()
                .map(from_serde)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        serde_json::Value::Object(o) => Value::Object(
            o.into_iter()
                .map(|(k, v)| Ok((k, from_serde(v)?)))
                .collect::<Result<Vec<_>, AuditError>>()?,
        ),
    })
}

/// This crate's JSON tree to a serde value (for typed decoding).
pub(crate) fn to_serde(v: &Value) -> serde_json::Value {
    match v {
        Value::Null => serde_json::Value::Null,
        Value::Bool(b) => serde_json::Value::Bool(*b),
        Value::Number(n) => match Value::Number(*n).as_safe_u64() {
            Some(u) => serde_json::Value::from(u),
            None => serde_json::Number::from_f64(*n).map_or(serde_json::Value::Null, Into::into),
        },
        Value::String(s) => serde_json::Value::String(s.clone()),
        Value::Array(a) => serde_json::Value::Array(a.iter().map(to_serde).collect()),
        Value::Object(o) => {
            serde_json::Value::Object(o.iter().map(|(k, v)| (k.clone(), to_serde(v))).collect())
        }
    }
}

fn member<T: Serialize>(v: &T, what: &'static str) -> Result<Value, AuditError> {
    from_serde(serde_json::to_value(v).map_err(|_| AuditError::shape(ShapeFault::Member(what)))?)
}

impl AuditEvent {
    /// The event as a JSON tree, without `hash`.
    ///
    /// # Errors
    ///
    /// `CS-AUD-0003` when `seq` or `v` is beyond 2^53 − 1, or `prev` is set on the
    /// first event or missing on a later one.
    pub fn to_value(&self) -> Result<Value, AuditError> {
        if self.seq > MAX_SAFE_INTEGER {
            return Err(AuditError::shape(ShapeFault::Seq));
        }
        if (self.seq == 0) != self.prev.is_none() {
            return Err(AuditError::shape(ShapeFault::Prev));
        }
        if self.v != EVENT_VERSION {
            return Err(AuditError::shape(ShapeFault::Version));
        }
        let typed = member(&self.data, "data")?;
        let ty = typed
            .get("type")
            .cloned()
            .ok_or(AuditError::shape(ShapeFault::Data))?;
        let data = typed
            .get("data")
            .cloned()
            .unwrap_or(Value::Object(Vec::new()));
        // Both are at most 2^53 − 1 (checked above), exact in a double.
        let (v, seq) = (self.v as f64, self.seq as f64);
        Ok(Value::Object(vec![
            ("v".into(), Value::Number(v)),
            (
                "envelope_id".into(),
                Value::String(self.envelope_id.as_str().into()),
            ),
            ("seq".into(), Value::Number(seq)),
            (
                "prev".into(),
                self.prev
                    .map_or(Value::Null, |h| Value::String(h.to_string())),
            ),
            ("at".into(), Value::String(self.at.to_string())),
            ("type".into(), ty),
            ("actor".into(), member(&self.actor, "actor")?),
            ("context".into(), member(&self.context, "context")?),
            ("data".into(), data),
        ]))
    }

    /// The canonical JSON (RFC 8785) of the event without `hash`: the bytes hashed.
    ///
    /// # Errors
    ///
    /// As [`AuditEvent::to_value`].
    pub fn canonical(&self) -> Result<Vec<u8>, AuditError> {
        jcs::to_vec(&self.to_value()?)
    }

    /// `SHA-256(JCS(event without hash))` (docs/32 §2, ADR-010).
    ///
    /// # Errors
    ///
    /// As [`AuditEvent::to_value`].
    pub fn hash(&self) -> Result<Hash256, AuditError> {
        Ok(Hash256::digest(&self.canonical()?))
    }

    /// Decode an event from its JSON tree. A `hash` member, and members a later version
    /// added, are ignored here; verification hashes the tree as received.
    ///
    /// # Errors
    ///
    /// `CS-AUD-0003` naming what was wrong.
    pub fn from_value(v: &Value) -> Result<Self, AuditError> {
        let get = |name: &'static str| {
            v.get(name)
                .ok_or(AuditError::shape(ShapeFault::Member(name)))
        };
        let version = get("v")?
            .as_safe_u64()
            .ok_or(AuditError::shape(ShapeFault::Version))?;
        if version != EVENT_VERSION {
            return Err(AuditError::shape(ShapeFault::Version));
        }
        let envelope_id = get("envelope_id")?
            .as_str()
            .and_then(|s| Id::new(s).ok())
            .ok_or(AuditError::shape(ShapeFault::Id))?;
        let seq = get("seq")?
            .as_safe_u64()
            .ok_or(AuditError::shape(ShapeFault::Seq))?;
        let prev = match get("prev")? {
            Value::Null => None,
            Value::String(s) => Some(Hash256::parse(s)?),
            _ => return Err(AuditError::shape(ShapeFault::Prev)),
        };
        if (seq == 0) != prev.is_none() {
            return Err(AuditError::shape(ShapeFault::Prev));
        }
        let at = Timestamp::parse(
            get("at")?
                .as_str()
                .ok_or(AuditError::shape(ShapeFault::Timestamp))?,
        )?;
        let typed = Value::Object(vec![
            ("type".into(), get("type")?.clone()),
            ("data".into(), get("data")?.clone()),
        ]);
        let data: EventData = serde_json::from_value(to_serde(&typed))
            .map_err(|_| AuditError::shape(ShapeFault::Data))?;
        let actor: Actor = serde_json::from_value(to_serde(get("actor")?))
            .map_err(|_| AuditError::shape(ShapeFault::Member("actor")))?;
        let context_value = get("context")?;
        // A location's own fault is named (`CS-AUD-0011`) when it is the location that
        // is wrong.
        if let Some(l) = context_value.get("location") {
            location_from_serde(to_serde(l))?;
        }
        let context: Context = serde_json::from_value(to_serde(context_value))
            .map_err(|_| AuditError::shape(ShapeFault::Member("context")))?;
        Ok(Self {
            v: version,
            envelope_id,
            seq,
            prev,
            at,
            actor,
            context,
            data,
        })
    }
}

// Tests may unwrap, index and panic (CLAUDE.md).
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::location::FallbackReason;

    fn id(s: &str) -> Id {
        Id::new(s).unwrap()
    }

    #[test]
    fn personal_values_never_print_in_debug() {
        let a = Actor {
            kind: ActorKind::Recipient,
            id: Some(id("r1")),
            name: Some(Personal("Ada Lovelace".into())),
            email: Some(Personal("ada@example.com".into())),
        };
        let d = format!("{a:?}");
        assert!(!d.contains("Ada") && !d.contains("example"), "{d}");
        assert_eq!(
            serde_json::to_value(&a).unwrap()["email"],
            serde_json::json!("ada@example.com")
        );
    }

    #[test]
    fn spec_example_shape_round_trips() {
        let e = AuditEvent {
            v: 1,
            envelope_id: id("0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"),
            seq: 17,
            prev: Some(Hash256::digest(b"16")),
            at: Timestamp::parse("2026-11-10T09:14:03.512Z").unwrap(),
            actor: Actor {
                kind: ActorKind::Recipient,
                id: Some(id("r1")),
                name: Some(Personal("Ada".into())),
                email: Some(Personal("ada@example.com".into())),
            },
            context: Context {
                ip: Some(Personal("203.0.113.7".into())),
                user_agent: Some(Personal("UA/1.0".into())),
                auth: vec![AuthMethod::EmailLink, AuthMethod::SmsOtp],
                session: Some(Hash256::digest(b"s")),
                location: None,
            },
            data: EventData::RecipientSigned {
                recipient_id: id("r1"),
                documents: vec![DocumentHash {
                    document_id: id("d1"),
                    hash: Hash256::digest(b"doc"),
                }],
                field_value_hashes: [(id("f1"), Hash256::digest(b"v"))].into(),
            },
        };
        let v = e.to_value().unwrap();
        let text = String::from_utf8(jcs::to_vec(&v).unwrap()).unwrap();
        assert!(text.starts_with(r#"{"actor":{"email":"ada@example.com","id":"r1","kind":"recipient","name":"Ada"},"at":"2026-11-10T09:14:03.512Z","context":{"auth":["email_link","sms_otp"],"#), "{text}");
        assert!(
            text.contains(r#""seq":17,"type":"recipient.signed","v":1}"#),
            "{text}"
        );
        assert_eq!(AuditEvent::from_value(&v).unwrap(), e);
    }

    #[test]
    fn every_type_name_is_a_variant_and_has_object_data() {
        for name in EventData::TYPES {
            // Each name decodes with some data, or at least is recognised as a variant.
            let v = serde_json::json!({ "type": name, "data": {} });
            let r: Result<EventData, _> = serde_json::from_value(v);
            match r {
                Ok(_) => {}
                Err(e) => assert!(
                    e.to_string().contains("missing field"),
                    "{name} is not a variant: {e}"
                ),
            }
        }
        let empty = EventData::EnvelopeExpired {};
        assert_eq!(
            serde_json::to_value(&empty).unwrap(),
            serde_json::json!({"type": "envelope.expired", "data": {}})
        );
        assert_eq!(EventData::TYPES.len(), 40);
    }

    #[test]
    fn prev_is_null_exactly_on_the_first_event() {
        let mut e = AuditEvent {
            v: 1,
            envelope_id: id("e"),
            seq: 0,
            prev: Some(Hash256::default()),
            at: Timestamp::from_unix_millis(0).unwrap(),
            actor: Actor::system(),
            context: Context::default(),
            data: EventData::EnvelopeExpired {},
        };
        assert_eq!(e.to_value().unwrap_err().code(), "CS-AUD-0003");
        e.prev = None;
        assert!(e.to_value().is_ok());
        e.seq = 1;
        assert_eq!(e.to_value().unwrap_err().code(), "CS-AUD-0003");
    }

    fn located(location: Location) -> AuditEvent {
        AuditEvent {
            v: 1,
            envelope_id: id("e"),
            seq: 0,
            prev: None,
            at: Timestamp::from_unix_millis(0).unwrap(),
            actor: Actor::system(),
            context: Context {
                ip: Some(Personal("203.0.113.7".into())),
                location: Some(Personal(location)),
                ..Context::default()
            },
            data: EventData::RecipientDelivered {
                recipient_id: id("r1"),
            },
        }
    }

    #[test]
    fn a_location_is_in_the_canonical_form_and_round_trips() {
        let e = located(
            Location::device(51.507_412, -0.127_758, 9.5)
                .unwrap()
                .with_place(Some("GB"), Some("England"), Some("London"))
                .unwrap(),
        );
        let v = e.to_value().unwrap();
        let text = String::from_utf8(jcs::to_vec(&v).unwrap()).unwrap();
        assert!(
            text.contains(r#""context":{"ip":"203.0.113.7","location":{"accuracy_m":10,"city":"London","country":"GB","latitude":51.5074,"longitude":-0.1278,"region":"England","source":"device"}}"#),
            "{text}"
        );
        assert_eq!(AuditEvent::from_value(&v).unwrap(), e);
        // Every coordinate the device rounding can give survives JCS and back.
        for (lat, lon) in [
            (-89.99995, 179.99995),
            (0.00005, -0.00005),
            (-33.8688, 151.2093),
        ] {
            let e = located(Location::device(lat, lon, 1.0).unwrap());
            let v = jcs::to_vec(&e.to_value().unwrap()).unwrap();
            let back = AuditEvent::from_value(&crate::json::parse(&v, 32).unwrap()).unwrap();
            assert_eq!(back, e);
            assert_eq!(back.hash().unwrap(), e.hash().unwrap());
        }
        // An IP approximation that states a refusal.
        let e = located(Location::ip_unresolved(FallbackReason::Declined, None).unwrap());
        let text = String::from_utf8(e.canonical().unwrap()).unwrap();
        assert!(
            text.contains(r#""location":{"reason":"declined","source":"ip"}"#),
            "{text}"
        );
    }

    #[test]
    fn a_bad_location_in_a_stored_event_is_named() {
        let e = located(Location::device(1.0, 2.0, 3.0).unwrap());
        let mut v = e.to_value().unwrap();
        let Value::Object(members) = &mut v else {
            panic!()
        };
        let ctx = &mut members.iter_mut().find(|(k, _)| k == "context").unwrap().1;
        let Value::Object(cm) = ctx else { panic!() };
        let loc = &mut cm.iter_mut().find(|(k, _)| k == "location").unwrap().1;
        let Value::Object(lm) = loc else { panic!() };
        lm.iter_mut().find(|(k, _)| k == "latitude").unwrap().1 = Value::Number(1.000_01);
        let err = AuditEvent::from_value(&v).unwrap_err();
        assert_eq!(
            err,
            AuditError::Location {
                fault: crate::error::LocationFault::Precision
            }
        );
        assert_eq!(err.code(), "CS-AUD-0011");
    }

    #[test]
    fn a_location_never_prints_in_debug() {
        let e = located(
            Location::device(51.5074, -0.1278, 9.0)
                .unwrap()
                .with_place(Some("GB"), None, Some("London"))
                .unwrap(),
        );
        let d = format!("{e:?}");
        assert!(!d.contains("51.5") && !d.contains("London"), "{d}");
        assert!(PERSONAL_MEMBERS.contains(&"context.location"));
    }
}
