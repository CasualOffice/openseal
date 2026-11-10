//! Why a seal was not made. [`SealError::code`] gives the stable docs/20 code; messages
//! carry object numbers, counts and indexes, never document content or names.

use core::fmt;

use casual_sign_crypto::CryptoError;
use casual_sign_pdf::{PdfError, WriteError};
use casual_sign_verify::Reason;

use crate::source::SourceError;

/// Why a seal, an augmentation or a renewal failed.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum SealError {
    /// The input could not be admitted (its `CS-PDF-*` code).
    Read(PdfError),
    /// The incremental update could not be written (its `CS-WRT-*` code): an unsound
    /// file, a DocMDP level that forbids signing, object numbers exhausted.
    Write(WriteError),
    /// A cryptographic step failed (its code: `CS-SEAL-0001` key provider,
    /// `CS-SEAL-0002` TSA answer refused, `CS-SEAL-0005` algorithm, ...).
    Crypto(CryptoError),
    /// The host's timestamp source failed (`CS-SEAL-0002`).
    Timestamp(SourceError),
    /// The CMS or timestamp token is larger than its placeholder (`CS-SEAL-0003`),
    /// after the one retry with the measured size (docs/31 §9). Never truncated.
    Overflow {
        /// Bytes reserved in `/Contents`.
        reserved: usize,
        /// Bytes the DER needed.
        needed: usize,
    },
    /// Revocation data for the requested level could not be collected (`CS-SEAL-0004`).
    Revocation(RevocationProblem),
    /// The request does not fit this document (`CS-SEAL-0006`, proposed).
    Request(RequestProblem),
    /// Our own output failed verification (`CS-SEAL-0010`, P0).
    SelfCheck(SelfCheckFailure),
    /// Our own output could not be laid out: the placeholder was not found once in the
    /// update, or a ByteRange value did not fit its fixed width (`CS-SEAL-0010`).
    Layout(LayoutProblem),
}

impl SealError {
    /// The stable docs/20 code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Read(e) => e.code(),
            Self::Write(e) => e.code(),
            Self::Crypto(e) => e.code(),
            Self::Timestamp(_) => "CS-SEAL-0002",
            Self::Overflow { .. } => "CS-SEAL-0003",
            Self::Revocation(_) => "CS-SEAL-0004",
            Self::Request(_) => "CS-SEAL-0006",
            Self::SelfCheck(_) | Self::Layout(_) => "CS-SEAL-0010",
        }
    }
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ", self.code())?;
        match self {
            Self::Read(e) => write!(f, "input not admitted: {e}"),
            Self::Write(e) => write!(f, "update not written: {e}"),
            Self::Crypto(e) => write!(f, "{e}"),
            Self::Timestamp(e) => write!(f, "timestamp source: {e}"),
            Self::Overflow { reserved, needed } => {
                write!(
                    f,
                    "signature of {needed} bytes exceeds its {reserved}-byte placeholder"
                )
            }
            Self::Revocation(p) => write!(f, "revocation data: {p}"),
            Self::Request(p) => write!(f, "request: {p}"),
            Self::SelfCheck(c) => write!(f, "our own output failed verification: {c}"),
            Self::Layout(p) => write!(f, "layout: {p}"),
        }
    }
}

impl core::error::Error for SealError {}

impl From<PdfError> for SealError {
    fn from(e: PdfError) -> Self {
        Self::Read(e)
    }
}

impl From<WriteError> for SealError {
    fn from(e: WriteError) -> Self {
        Self::Write(e)
    }
}

impl From<CryptoError> for SealError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

/// What in a request does not fit the document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequestProblem {
    /// A certification signature must be the document's first signature (ISO 32000-2
    /// §12.8.2.2).
    CertificationNotFirst,
    /// The named field exists and is not a signature field.
    FieldNotSignature,
    /// The named signature field already holds a signature.
    FieldAlreadySigned,
    /// The field name is empty, too long, or contains a period (ISO 32000-2 §12.7.4.2).
    FieldName,
    /// The named field cannot be signed in place (no indirect field object).
    FieldUnsupported,
    /// The page index is not a page of the document.
    PageOutOfRange,
    /// The document has no page to hold the widget.
    NoPages,
    /// The rectangle is not finite, or has a negative extent.
    Rect,
    /// A text entry (name, reason, location, contact) is longer than 4,000 bytes.
    TextTooLong,
    /// The signing time cannot be written as a PDF date (after 9999-12-31).
    Time,
    /// The catalog, AcroForm, field array, page or annotation array is not the kind of
    /// object ISO 32000-2 requires (the object number; 0 when direct).
    Structure(u32),
    /// A renewal was asked of a document with no document timestamp.
    NoDocumentTimestamp,
    /// An augmentation was asked of a document with no signature.
    NoSignature,
    /// The profile asked for cannot be reached by this operation.
    Profile,
}

impl fmt::Display for RequestProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CertificationNotFirst => {
                f.write_str("a certification signature must be the first")
            }
            Self::FieldNotSignature => f.write_str("the named field is not a signature field"),
            Self::FieldAlreadySigned => f.write_str("the named field is already signed"),
            Self::FieldName => f.write_str("field name empty, too long or containing a period"),
            Self::FieldUnsupported => f.write_str("the named field cannot be signed in place"),
            Self::PageOutOfRange => f.write_str("page index out of range"),
            Self::NoPages => f.write_str("the document has no page"),
            Self::Rect => f.write_str("rectangle not finite or inverted"),
            Self::TextTooLong => f.write_str("text entry longer than 4000 bytes"),
            Self::Time => f.write_str("signing time not representable"),
            Self::Structure(n) => write!(f, "object {n} is not of the required kind"),
            Self::NoDocumentTimestamp => f.write_str("no document timestamp to renew"),
            Self::NoSignature => f.write_str("no signature to augment"),
            Self::Profile => f.write_str("profile not reachable by this operation"),
        }
    }
}

/// Why revocation data could not be collected. `index` numbers certificates in the
/// order the engine visited them (signer chain first, then TSA chains).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RevocationProblem {
    /// The issuer of a certificate is in neither the signature nor the source's
    /// certificates.
    IssuerNotFound {
        /// The certificate's index.
        index: usize,
    },
    /// Neither an OCSP response nor a CRL showing the certificate not revoked at the
    /// time asked (docs/31 §9: the host seals at B-T and schedules the augmentation).
    NoAnswer {
        /// The certificate's index.
        index: usize,
    },
    /// The data shows the certificate revoked at the time asked.
    Revoked {
        /// The certificate's index.
        index: usize,
    },
    /// The host's revocation source failed.
    Source(SourceError),
    /// More certificates than the DSS bound (4,096) would hold.
    TooMany,
}

impl fmt::Display for RevocationProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IssuerNotFound { index } => write!(f, "issuer of certificate {index} not found"),
            Self::NoAnswer { index } => write!(f, "no usable OCSP or CRL for certificate {index}"),
            Self::Revoked { index } => write!(f, "certificate {index} is revoked"),
            Self::Source(e) => write!(f, "source: {e}"),
            Self::TooMany => f.write_str("too many certificates"),
        }
    }
}

/// Which part of our own output failed verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CheckName {
    /// The output could not be read at all.
    Document,
    /// Our signature or document timestamp is not in the report.
    Missing,
    /// ByteRange shape or coverage.
    ByteRange,
    /// Digest of the signed bytes.
    Digest,
    /// CMS signature value and signed attributes.
    Signature,
    /// The signature or document timestamp token.
    Timestamp,
    /// Certificate chain to a supplied anchor.
    Chain,
    /// Revocation of the chains (B-LT and B-LTA).
    Revocation,
    /// A revision this operation added is not an allowed change for some signature.
    Modifications,
    /// The signature kind (approval, certification level) is not the one requested.
    Kind,
    /// The last signature does not cover the whole file.
    Coverage,
}

/// Our own output failed verification (`CS-SEAL-0010`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfCheckFailure {
    /// Index of the signature in the verifier's report (ByteRange order).
    pub signature: usize,
    /// The check that failed.
    pub check: CheckName,
    /// The verifier's reason, when it gave one.
    pub reason: Option<Reason>,
}

impl fmt::Display for SelfCheckFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "signature {} check {:?}", self.signature, self.check)?;
        if let Some(r) = self.reason {
            write!(f, " ({} {})", r.sub.name(), r.code)?;
        }
        Ok(())
    }
}

/// Our own output could not be laid out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LayoutProblem {
    /// The `/ByteRange` and `/Contents` placeholder was found this many times in the
    /// update (it must be exactly once).
    Placeholder(usize),
    /// A ByteRange value does not fit the placeholder's fixed width.
    ByteRangeWidth,
    /// A DER structure of ours could not be encoded.
    Encoding,
}

impl fmt::Display for LayoutProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Placeholder(n) => write!(f, "placeholder found {n} times"),
            Self::ByteRangeWidth => f.write_str("ByteRange does not fit its width"),
            Self::Encoding => f.write_str("DER encoding failed"),
        }
    }
}
