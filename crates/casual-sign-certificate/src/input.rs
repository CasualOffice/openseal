//! What a certificate shows (docs/32 §6), supplied by the host from its envelope record,
//! and the choices that shape it.
//!
//! Every value here is printed as given; the host builds it from the same records the
//! audit chain was written from. The chain itself is passed alongside: the certificate
//! prints its head and embeds it whole.

use casual_sign_audit::{AdoptionMethod, AuthMethod, Chain, Hash256, Location, Timestamp};
use casual_sign_flatten::Art;
use casual_sign_model::DateFormat;

/// A person named on the certificate: personal data.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Party {
    /// Full name.
    pub name: String,
    /// Email address (masked per [`CertificateOptions::email_mask`]).
    pub email: String,
}

/// Section 1: the envelope summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeSummary {
    /// The envelope id; must be the chain's.
    pub id: String,
    /// The subject.
    pub subject: String,
    /// Its status as shown (`Completed`, `Declined`, `Voided`).
    pub status: String,
    /// The sender.
    pub sender: Party,
    /// The account's name.
    pub account: String,
    /// When it was created.
    pub created: Timestamp,
    /// When it was sent.
    pub sent: Option<Timestamp>,
    /// When it completed.
    pub completed: Option<Timestamp>,
    /// The seal profile that will be or was applied (`pades-b-lta`).
    pub seal_profile: String,
}

/// Section 2: one document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentRow {
    /// Its name.
    pub name: String,
    /// Pages.
    pub pages: u32,
    /// SHA-256 of the bytes delivered to signers (`document.fixed`).
    pub delivered: Hash256,
    /// SHA-256 of the sealed file, when the certificate is made after sealing (a
    /// separate certificate). `None` for a certificate inside the document it seals:
    /// that hash covers the certificate, so it cannot be printed in it.
    pub sealed: Option<Hash256>,
}

/// What a recipient does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Role {
    /// Signs.
    Signer,
    /// Approves.
    Approver,
    /// Signs in person, hosted by a user.
    InPersonSigner,
    /// Witnesses another signature.
    Witness,
}

/// One authentication step and its result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthStep {
    /// The method.
    pub method: AuthMethod,
    /// Whether it passed.
    pub passed: bool,
    /// When.
    pub at: Option<Timestamp>,
}

/// A signature or initials as adopted.
#[derive(Debug, Clone, PartialEq)]
pub struct Mark {
    /// The marks, drawn exactly as on the document.
    pub art: Art,
    /// How it was made.
    pub method: AdoptionMethod,
}

/// How a recipient's part ended.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    /// Not finished.
    Pending,
    /// Signed at.
    Signed(Timestamp),
    /// Approved at.
    Approved(Timestamp),
    /// Declined at, with the reason given.
    Declined {
        /// When.
        at: Timestamp,
        /// The reason, as typed.
        reason: Option<String>,
    },
}

/// A recipient's consent to electronic records (ESIGN §7001(c), docs/09).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consent {
    /// The disclosure's version label.
    pub version: String,
    /// SHA-256 of the disclosure text shown.
    pub hash: Hash256,
    /// When it was accepted.
    pub accepted: Timestamp,
}

/// Section 3: one recipient's events, in routing order.
#[derive(Debug, Clone, PartialEq)]
pub struct RecipientRow {
    /// Routing order, from 1.
    pub routing_order: u32,
    /// Name and email.
    pub party: Party,
    /// Role.
    pub role: Role,
    /// Authentication steps and results.
    pub auth: Vec<AuthStep>,
    /// The IP address the recipient acted from.
    pub ip: Option<String>,
    /// The user agent.
    pub user_agent: Option<String>,
    /// Where the recipient was when they signed, approved or declined: the location
    /// recorded in that event's context (GEO-01). Bounded by construction (docs/21).
    pub location: Option<Location>,
    /// The adopted signature.
    pub signature: Option<Mark>,
    /// The adopted initials.
    pub initials: Option<Mark>,
    /// When the invitation was sent.
    pub sent: Option<Timestamp>,
    /// When the recipient first viewed.
    pub viewed: Option<Timestamp>,
    /// How it ended.
    pub outcome: Outcome,
    /// Consent to electronic records.
    pub consent: Option<Consent>,
}

/// Whether a copy went to a carbon-copy recipient or a viewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CopyKind {
    /// Receives a copy when complete.
    CarbonCopy,
    /// May view while in progress.
    Viewer,
}

/// Section 5: a carbon-copy recipient or viewer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyRow {
    /// Name and email.
    pub party: Party,
    /// Which.
    pub kind: CopyKind,
    /// When the copy was delivered.
    pub delivered: Option<Timestamp>,
}

/// Section 5a: a file a signer attached to an attachment field (WEB-06).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentRow {
    /// Who attached it (personal data).
    pub recipient: String,
    /// The field: its data label, else its id.
    pub field: String,
    /// The file's media type (`application/pdf`, `image/png`, `image/jpeg`).
    pub media_type: String,
    /// Its size in bytes.
    pub bytes: u64,
    /// SHA-256 of the file as stored.
    pub sha256: Hash256,
}

/// Section 4: the electronic record and signature disclosure as shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disclosure {
    /// Version label.
    pub version: String,
    /// The text, as shown to recipients.
    pub text: String,
}

/// Section 6: the seal.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SealInfo {
    /// The certificate is inside the document the seal will cover: the seal's details
    /// are in the document's signature, applied after this page was made.
    Pending,
    /// A separate certificate made after sealing: what the seal used.
    Applied {
        /// The sealing certificate's subject.
        subject: String,
        /// Its issuer.
        issuer: String,
        /// SHA-256 of the certificate (DER).
        fingerprint: Hash256,
        /// The timestamp authority.
        tsa: Option<String>,
        /// The time it gave.
        time: Option<Timestamp>,
    },
}

/// Everything a certificate shows.
#[derive(Debug, Clone)]
pub struct CertificateInput<'a> {
    /// Section 1.
    pub envelope: EnvelopeSummary,
    /// Section 2, in envelope order.
    pub documents: Vec<DocumentRow>,
    /// Section 3, in routing order.
    pub recipients: Vec<RecipientRow>,
    /// Section 5.
    pub copies: Vec<CopyRow>,
    /// Section 5a (WEB-06): files signers attached, by hash; the files themselves are
    /// kept by the host, and each one's hash is bound into the chain by its
    /// `recipient.field_completed` event.
    pub attachments: Vec<AttachmentRow>,
    /// Section 4's disclosure, when the account uses one.
    pub disclosure: Option<Disclosure>,
    /// Section 6.
    pub seal: SealInfo,
    /// Section 7: where to verify online, when the operator publishes a page.
    pub verify_url: Option<String>,
    /// The chain up to now: its head is printed, the whole of it embedded.
    pub chain: &'a Chain,
    /// When the certificate is made (supplied: the engine reads no clock).
    pub generated: Timestamp,
    /// `Some` for an envelope that ended without completing (UXW-30): the certificate
    /// says how it ended and never claims completion. `None`: a certificate of
    /// completion, byte for byte as before.
    pub ending: Option<Ending>,
}

/// How an envelope that did not complete ended (UXW-30).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EndKind {
    /// A recipient declined.
    Declined,
    /// The sender (or an administrator) voided it.
    Voided,
    /// It expired before every recipient finished.
    Expired,
}

impl EndKind {
    /// The word printed: `declined`, `voided`, `expired`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Declined => "declined",
            Self::Voided => "voided",
            Self::Expired => "expired",
        }
    }
}

/// The end of an envelope that did not complete (UXW-30). A certificate with an ending
/// is an envelope certificate, never a certificate of completion: its title, summary
/// and seal section say how the envelope ended and that no document was sealed as a
/// completed agreement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ending {
    /// How it ended.
    pub kind: EndKind,
    /// When: the time of the chain's `envelope.declined`, `envelope.voided` or
    /// `envelope.expired`.
    pub at: Timestamp,
    /// Who ended it, as shown (the declining recipient, the voiding sender); `None` for
    /// an expiry.
    pub by: Option<String>,
    /// The reason given, as typed.
    pub reason: Option<String>,
}

/// Page size.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum PageSize {
    /// ISO A4, 595.28 × 841.89 points.
    A4,
    /// US Letter, 612 × 792 points.
    Letter,
}

impl PageSize {
    /// Width and height in points.
    #[must_use]
    pub fn points(self) -> (f64, f64) {
        match self {
            Self::A4 => (595.28, 841.89),
            Self::Letter => (612.0, 792.0),
        }
    }
}

/// How email addresses appear (an account setting, docs/32 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum EmailMask {
    /// In full.
    #[default]
    Show,
    /// The first character of the local part, then `***`, then the domain:
    /// `a***@example.com`.
    Partial,
    /// Not shown.
    Hidden,
}

/// Where the disclosure text goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum DisclosurePlacement {
    /// In section 4.
    Inline,
    /// Its hash in section 4, the text in an appendix after section 7.
    #[default]
    Appendix,
}

/// Choices that shape a certificate.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct CertificateOptions {
    /// Page size.
    pub page: PageSize,
    /// The account's date format.
    pub date_format: DateFormat,
    /// The account's offset from UTC, in minutes east (supplied: no time-zone
    /// database in the engine).
    pub utc_offset_minutes: i32,
    /// The zone's name as printed after times (`Europe/Paris`); `UTC±hh:mm` when absent.
    pub zone_label: Option<String>,
    /// How emails appear.
    pub email_mask: EmailMask,
    /// Where the disclosure text goes.
    pub disclosure: DisclosurePlacement,
}

impl Default for CertificateOptions {
    fn default() -> Self {
        Self {
            page: PageSize::A4,
            date_format: DateFormat::YyyyMmDd,
            utc_offset_minutes: 0,
            zone_label: None,
            email_mask: EmailMask::Show,
            disclosure: DisclosurePlacement::Appendix,
        }
    }
}
