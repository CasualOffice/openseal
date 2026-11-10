//! The verification report: per signature an ETSI EN 319 102-1 indication with its
//! sub-indication and the docs/20 code, the result of each check, and the classified
//! revisions after it (docs/31 §7).

use core::fmt;
use core::time::Duration;

/// The main status indication of ETSI EN 319 102-1 §5.1.3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Indication {
    /// Every check passed.
    TotalPassed,
    /// A check failed in a way more data cannot repair: the signature is invalid.
    TotalFailed(Reason),
    /// A check could not conclude: more data (a trust anchor, revocation data, a proof of
    /// existence) could change the answer.
    Indeterminate(Reason),
}

impl Indication {
    /// The reason, unless passed.
    #[must_use]
    pub const fn reason(&self) -> Option<Reason> {
        match self {
            Self::TotalPassed => None,
            Self::TotalFailed(r) | Self::Indeterminate(r) => Some(*r),
        }
    }

    /// The ETSI name: `TOTAL_PASSED`, `TOTAL_FAILED` or `INDETERMINATE`.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::TotalPassed => "TOTAL_PASSED",
            Self::TotalFailed(_) => "TOTAL_FAILED",
            Self::Indeterminate(_) => "INDETERMINATE",
        }
    }
}

impl fmt::Display for Indication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.reason() {
            None => f.write_str(self.name()),
            Some(r) => write!(f, "{} {} ({})", self.name(), r.sub.name(), r.code),
        }
    }
}

/// Why a signature did not pass: the sub-indication and the docs/20 code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reason {
    /// The sub-indication.
    pub sub: SubIndication,
    /// The stable `CS-VER-*` (or crypto `CS-SEAL-*`) code from docs/20.
    pub code: &'static str,
}

/// Sub-indications. All but [`SubIndication::DisallowedModification`] are ETSI EN 319
/// 102-1 §5.1.3 names; that one is OpenSeal's, because the standard has no sub-indication
/// for a PDF changed after signing in a way its permissions forbid (ISO 32000-2 §12.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SubIndication {
    /// The signature or its container is not well formed (ByteRange, CMS, SubFilter).
    FormatFailure,
    /// The digest of the signed bytes differs from the signed `message-digest`.
    HashFailure,
    /// The signature value does not verify with the signer's key.
    SigCryptoFailure,
    /// ETSI vocabulary, not produced: a revocation before the best signature time is
    /// [`SubIndication::RevokedNoPoe`] (EN 319 102-1 §5.5.4, as EU DSS reports it).
    Revoked,
    /// The proven signing time is before the signer certificate's validity.
    NotYetValid,
    /// The signer certificate is revoked and no proof of existence predates it.
    RevokedNoPoe,
    /// A certificate was outside its validity at the time it had to be valid, and no
    /// proof of existence predates its expiry.
    OutOfBoundsNoPoe,
    /// The signer certificate is not in the signature.
    NoSigningCertificateFound,
    /// No path from the signer certificate to a supplied trust anchor.
    NoCertificateChainFound,
    /// A path exists but a certificate breaks a constraint (basic constraints, key usage,
    /// extended key usage, an unprocessed critical extension).
    ChainConstraintsFailure,
    /// An algorithm, key size or identifier the verifier does not accept (docs/31 §8).
    CryptoConstraintsFailure,
    /// A signature attribute fails its checks (here: an invalid signature timestamp).
    SigConstraintsFailure,
    /// No usable revocation data for a certificate that needs it.
    TryLater,
    /// A later revision changes the document in a way its permissions do not allow
    /// (OpenSeal; `CS-VER-0007`).
    DisallowedModification,
}

impl SubIndication {
    /// The ETSI name (or `DISALLOWED_MODIFICATION`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::FormatFailure => "FORMAT_FAILURE",
            Self::HashFailure => "HASH_FAILURE",
            Self::SigCryptoFailure => "SIG_CRYPTO_FAILURE",
            Self::Revoked => "REVOKED",
            Self::NotYetValid => "NOT_YET_VALID",
            Self::RevokedNoPoe => "REVOKED_NO_POE",
            Self::OutOfBoundsNoPoe => "OUT_OF_BOUNDS_NO_POE",
            Self::NoSigningCertificateFound => "NO_SIGNING_CERTIFICATE_FOUND",
            Self::NoCertificateChainFound => "NO_CERTIFICATE_CHAIN_FOUND",
            Self::ChainConstraintsFailure => "CHAIN_CONSTRAINTS_FAILURE",
            Self::CryptoConstraintsFailure => "CRYPTO_CONSTRAINTS_FAILURE",
            Self::SigConstraintsFailure => "SIG_CONSTRAINTS_FAILURE",
            Self::TryLater => "TRY_LATER",
            Self::DisallowedModification => "DISALLOWED_MODIFICATION",
        }
    }
}

/// The outcome of one check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    /// Not run, because an earlier check decided the verdict or it does not apply.
    NotRun,
    /// Passed.
    Passed,
    /// Failed, with the reason.
    Failed(Reason),
}

impl Check {
    /// True when passed.
    #[must_use]
    pub const fn passed(&self) -> bool {
        matches!(self, Self::Passed)
    }
}

/// Every check made on one signature, in the order they run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checks {
    /// `/ByteRange` shape and coverage of its revision (`CS-VER-0001`).
    pub byte_range: Check,
    /// The digest of the signed bytes (`CS-VER-0002`).
    pub digest: Check,
    /// The CMS signature and its signed attributes (`CS-VER-0003`).
    pub signature: Check,
    /// The signature timestamp, or for a document timestamp its token (`CS-VER-0006`).
    pub timestamp: Check,
    /// The certificate chains of the signer and of every TSA (`CS-VER-0004`, `-0005`).
    pub chain: Check,
    /// Revocation of every certificate in those chains (`CS-VER-0005`, `CS-SEAL-0004`).
    pub revocation: Check,
    /// The revisions after the signed one (`CS-VER-0007`).
    pub modifications: Check,
}

impl Default for Checks {
    fn default() -> Self {
        Self {
            byte_range: Check::NotRun,
            digest: Check::NotRun,
            signature: Check::NotRun,
            timestamp: Check::NotRun,
            chain: Check::NotRun,
            revocation: Check::NotRun,
            modifications: Check::NotRun,
        }
    }
}

/// What kind of signature this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureKind {
    /// An approval signature (`/Type /Sig`, no DocMDP reference).
    Approval,
    /// A certification signature with its DocMDP permission level (1, 2 or 3).
    Certification {
        /// `/P`: 1 no changes, 2 form filling and signing, 3 also annotations.
        permissions: u8,
    },
    /// A document timestamp (`/Type /DocTimeStamp`, `ETSI.RFC3161`).
    DocumentTimestamp,
}

/// Where the time a signature was validated at came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeSource {
    /// The signature's own verified timestamp token.
    SignatureTimestamp,
    /// A verified document timestamp over a later revision (proof of existence).
    DocumentTimestamp,
    /// The supplied validation time: nothing proves an earlier existence.
    ValidationTime,
}

/// A verified timestamp token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimestampInfo {
    /// `genTime`, since the Unix epoch.
    pub gen_time: Duration,
}

/// A class of change found in a revision after a signature (docs/31 §7). Anything not in
/// the whitelist is [`ModificationClass::Disallowed`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ModificationClass {
    /// `/DSS` and `/VRI` additions (PAdES B-LT).
    DssUpdate,
    /// A document timestamp and its field (PAdES B-LTA).
    DocumentTimestamp,
    /// `/Info` or XMP metadata: not rendered.
    Metadata,
    /// A new signature, its field and widget (DocMDP P=2 or 3, or no DocMDP).
    Signature,
    /// A form field's value or appearance (DocMDP P=2 or 3, or no DocMDP; not a field a
    /// FieldMDP lock covers).
    FormFill,
    /// An annotation added or changed (DocMDP P=3, or no DocMDP).
    Annotation,
    /// Anything else: page content, resources, the page tree, catalog entries outside the
    /// list, object overrides, removed or dangling objects.
    Disallowed(Disallowed),
}

/// Why a change is disallowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Disallowed {
    /// An object outside every permitted class was changed or added where it is
    /// referenced from the signed revision (the object number).
    ObjectChanged(u32),
    /// An object of the signed revision was removed (freed).
    ObjectRemoved(u32),
    /// A page dictionary changed outside `/Annots` (the page object number).
    PageChanged(u32),
    /// An annotation was removed from a page.
    AnnotationRemoved(u32),
    /// A catalog entry outside `/DSS`, `/AcroForm`, `/Extensions`, `/Metadata` changed.
    CatalogChanged,
    /// The trailer's `/Root` points at a different catalog, or `/Encrypt` appeared.
    TrailerChanged,
    /// A form field changed outside its value and appearance, or fields were removed.
    FieldChanged(u32),
    /// A field locked by a FieldMDP transform was changed (the field object number).
    LockedField(u32),
    /// A permitted class the DocMDP level forbids (the level).
    NotPermitted(u8),
    /// A signature dictionary of an earlier signature was changed.
    SignatureChanged(u32),
    /// The revision could not be read for comparison.
    Unreadable,
}

/// The changes one revision made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevisionChanges {
    /// Zero-based revision index (oldest first).
    pub revision: usize,
    /// The classes found, sorted, de-duplicated.
    pub classes: Vec<ModificationClass>,
}

impl RevisionChanges {
    /// True when no class is [`ModificationClass::Disallowed`].
    #[must_use]
    pub fn allowed(&self) -> bool {
        !self
            .classes
            .iter()
            .any(|c| matches!(c, ModificationClass::Disallowed(_)))
    }
}

/// The verification of one signature or document timestamp.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureReport {
    /// The signature field's object number, when indirect.
    pub field: Option<u32>,
    /// The signature dictionary's object number, when indirect.
    pub value: Option<u32>,
    /// `/SubFilter`.
    pub sub_filter: Option<String>,
    /// Approval, certification or document timestamp.
    pub kind: SignatureKind,
    /// `/ByteRange` as read, when well formed enough to read.
    pub byte_range: Option<[u64; 4]>,
    /// The revision the ByteRange covers, when it ends on one.
    pub signed_revision: Option<usize>,
    /// True when the ByteRange reaches the end of the file.
    pub covers_whole_document: bool,
    /// The verdict.
    pub indication: Indication,
    /// Each check.
    pub checks: Checks,
    /// The time the signer's chain and revocation were checked at.
    pub validation_time: Duration,
    /// Where that time came from.
    pub time_source: TimeSource,
    /// The signature timestamp (for a document timestamp, its own token), if verified.
    pub timestamp: Option<TimestampInfo>,
    /// Every revision after the signed one, classified.
    pub modifications_after: Vec<RevisionChanges>,
}

/// A failure to read the document at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DocumentError {
    /// The docs/20 code from the reader (`CS-PDF-*`).
    pub code: &'static str,
}

/// The verification of a whole document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationReport {
    /// Set when the PDF could not be read; then there are no signatures.
    pub error: Option<DocumentError>,
    /// Number of revisions.
    pub revisions: usize,
    /// Each signature and document timestamp, in ByteRange order (earliest first).
    pub signatures: Vec<SignatureReport>,
    /// Every revision after the first, classified against the one before it.
    pub revision_changes: Vec<RevisionChanges>,
    /// True when the last signature or document timestamp covers the whole file, so no
    /// unsigned bytes follow it.
    pub covered_by_last_signature: bool,
}

impl VerificationReport {
    /// True when there is at least one signature, every one is `TOTAL_PASSED`, and the
    /// last covers the whole document.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.error.is_none()
            && !self.signatures.is_empty()
            && self.covered_by_last_signature
            && self
                .signatures
                .iter()
                .all(|s| s.indication == Indication::TotalPassed)
    }
}
