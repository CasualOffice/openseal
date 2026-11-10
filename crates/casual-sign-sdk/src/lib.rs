//! OpenSeal SDK: one facade over admit, normalize, fill, flatten, certificate, seal and
//! verify (docs/19, stage 1J `T-1J`).
//!
//! The engine crates each do one stage of the pipeline of docs/30 §1:
//!
//! ```text
//! bytes ─▶ admit ─▶ prepare (normalize) ─▶ [deliver: hash fixed] ─▶ fill_and_flatten
//!       ─▶ complete (certificate + audit-trail.json) ─▶ seal ─▶ verify
//! ```
//!
//! [`Engine`] runs them in that order with one set of [`Limits`] and one [`FontSet`], so
//! a host (the `openseal` CLI, the server, the desktop app) calls six methods instead of
//! wiring nine crates. Each step that writes appends one incremental update, and the
//! facade checks the invariant of docs/30 §1 at every step: the bytes it was given are a
//! prefix of the bytes it returns (`CS-WRT-0001` otherwise, [`SdkError::Prefix`]).
//!
//! Like every engine crate it is pure: no I/O, no clock, no randomness, no key. Times
//! are supplied ([`SealRequest::signing_time`], [`VerifyOptions::validation_time`],
//! [`CertificateInput::generated`]); the key, the time-stamping authority and the
//! revocation responders come through [`KeyProvider`], [`TimestampSource`] and
//! [`RevocationSource`], which the host implements. It builds for
//! `wasm32-unknown-unknown`.
//!
//! **Signed input** (docs/30 §2) cannot be normalized without breaking its signatures:
//! [`Engine::prepare`] refuses it with `CS-PDF-0014`. [`Engine::keep_signed`] accepts it
//! as delivered, unchanged, when it is structurally sound, unencrypted and its DocMDP
//! permits another signature; [`Engine::seal`] then appends a second signature.
//!
//! Every error is an [`SdkError`] whose [`SdkError::code`] is the docs/20 code of the
//! stage that failed.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use casual_sign_fields::{evaluate_envelope, validate};
use casual_sign_pdf::{Admitted, NormalizeOptions, OutputXref, WriteError, admit_with, normalize};

pub use casual_sign_audit::{ChainReport, Hash256, VerifyOptions as TrailOptions};
pub use casual_sign_certificate::{CertificateInput, CertificateOptions};
pub use casual_sign_crypto::{Certificate, KeyError, KeyProvider, Signature, SignatureAlgorithm};
pub use casual_sign_fields::{Conversion, Converted, Issue, Outcome, Skipped, Unmapped};
pub use casual_sign_flatten::{
    Art, Capture, FlattenOptions, FlattenReport, FontSet, FormMode, Ink, InkPoint, NotDrawn,
};
pub use casual_sign_pdf::{
    AdmissionReport, Credentials, FieldType as PdfFieldType, FormField, Limits,
    NormalizationReport, PdfError,
};
pub use casual_sign_seal::{
    ArchiveOptions, CrlQuery, DocMdp, NoRevocation, NoTimestamps, OcspQuery, Profile,
    RevocationSource, SealError, SealKind, SealReport, SealRequest, Sealed, SourceError,
    TimestampSource, TrustStore,
};
pub use casual_sign_verify::{
    Indication, SignatureReport, VerificationReport, VerifyOptions, verify as verify_bytes,
};

/// The field model the facade takes: fields, values and identifiers (docs/22 §6).
pub mod model {
    pub use casual_sign_fields::{DisplayRect, PageGeometry};
    pub use casual_sign_model::{
        Align, DateFormat, Field, FieldOptions, FieldType, FieldValue, FontFamily, Format, Id,
        LengthRule, Placement, Points, Rgb, Text, Validation, ValidationRule,
    };
}

/// What [`CertificateInput`] is built from: the audit chain and the certificate's rows
/// (docs/32).
pub mod evidence {
    pub use casual_sign_audit::{
        Actor, ActorKind, AdoptionMethod, AuditEvent, AuthMethod, Chain, Channel, Context,
        DocumentHash, EventData, MarkKind, Personal, TRAIL_FILE_NAME, Timestamp,
    };
    pub use casual_sign_certificate::{
        AuthStep, Consent, CopyKind, CopyRow, Disclosure, DisclosurePlacement, DocumentRow,
        EmailMask, EnvelopeSummary, Mark, Outcome, PageSize, Party, RecipientRow, Role, SealInfo,
    };
}

/// The parts of a [`VerificationReport`] a host reads or prints (docs/31 §7).
pub mod verify {
    pub use casual_sign_verify::{
        Check, Checks, Disallowed, DocumentError, Indication, ModificationClass, Reason,
        RevisionChanges, SignatureKind, SignatureReport, SubIndication, TimePolicy, TimeSource,
        TimestampInfo, VerificationReport,
    };
}

use model::{Field, FieldValue, Id};

/// A host's cancellation check: true stops the current step with the reader's
/// cancellation code (`CS-PDF-0013`). Called from every loop a file can lengthen.
pub type CancelFn = Arc<dyn Fn() -> bool + Send + Sync>;

/// The pipeline step whose output did not start with its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Step {
    /// [`Engine::fill_and_flatten`].
    Flatten,
    /// [`Engine::complete`].
    Certificate,
    /// [`Engine::seal`] or [`Engine::augment`].
    Seal,
}

impl Step {
    /// The step's name, as the CLI prints it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Flatten => "flatten",
            Self::Certificate => "certificate",
            Self::Seal => "seal",
        }
    }
}

/// Why a step failed. Each variant carries the failing crate's error, whose code is in
/// docs/20; messages carry codes, object numbers and counts, never document content.
#[derive(Debug)]
#[non_exhaustive]
pub enum SdkError {
    /// Reading the PDF failed or was refused (`CS-PDF-*`).
    Pdf(PdfError),
    /// Writing failed or was refused (`CS-WRT-*`, or `CS-PDF-0014` for signed input).
    Write(WriteError),
    /// Field values do not complete the fields (`CS-FLD-*`): every problem, sorted by
    /// field id. The first one's code is [`SdkError::code`].
    Fields(Vec<Issue>),
    /// Flattening failed (`CS-FLT-*`).
    Flatten(casual_sign_flatten::FlattenError),
    /// The certificate of completion could not be made (`CS-CRT-*`, `CS-AUD-*`).
    Certificate(casual_sign_certificate::CertificateError),
    /// Sealing failed (`CS-SEAL-*`, or the read and write codes it met).
    Seal(SealError),
    /// A step's output did not start with its input (`CS-WRT-0001`): the invariant of
    /// docs/30 §1. Never expected; a P0 if seen.
    Prefix(Step),
}

impl SdkError {
    /// The stable docs/20 code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Pdf(e) => e.code(),
            Self::Write(e) => e.code(),
            Self::Fields(issues) => issues.first().map_or("CS-FLD-0002", Issue::code),
            Self::Flatten(e) => e.code(),
            Self::Certificate(e) => e.code(),
            Self::Seal(e) => e.code(),
            Self::Prefix(_) => "CS-WRT-0001",
        }
    }
}

impl fmt::Display for SdkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pdf(e) => write!(f, "admission: {e}"),
            Self::Write(e) => write!(f, "write: {e}"),
            Self::Fields(issues) => write!(
                f,
                "{}: {} field problem(s), the first on field {}",
                self.code(),
                issues.len(),
                issues.first().map_or("-", |i| i.field_id.as_str())
            ),
            Self::Flatten(e) => write!(f, "flatten: {e}"),
            Self::Certificate(e) => write!(f, "certificate: {e}"),
            Self::Seal(e) => write!(f, "seal: {e}"),
            Self::Prefix(step) => write!(
                f,
                "CS-WRT-0001: the {} output does not start with its input",
                step.name()
            ),
        }
    }
}

impl std::error::Error for SdkError {}

impl From<PdfError> for SdkError {
    fn from(e: PdfError) -> Self {
        Self::Pdf(e)
    }
}

impl From<WriteError> for SdkError {
    fn from(e: WriteError) -> Self {
        Self::Write(e)
    }
}

/// The document as delivered to signers (docs/30 §1): its bytes, their SHA-256 (the
/// hash the audit chain records in `document.fixed`), and what admission and
/// normalization found and did.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Delivered {
    /// The delivered bytes. Every later revision starts with them.
    pub bytes: Vec<u8>,
    /// SHA-256 of [`Delivered::bytes`].
    pub hash: Hash256,
    /// What admission of the uploaded bytes found.
    pub admission: AdmissionReport,
    /// What normalization removed and renumbered; `None` for signed input kept as it is
    /// ([`Engine::keep_signed`]).
    pub normalization: Option<NormalizationReport>,
}

/// What [`Engine::fill_and_flatten`] draws: the document's fields (placed by geometry,
/// anchors or tags, or converted from its AcroForm) and the signers' values.
#[derive(Debug, Clone, Copy)]
pub struct Fill<'a> {
    /// Every field of the document.
    pub fields: &'a [Field],
    /// The signers' values by field id. Fields that hold their own `value` or `default`
    /// need no entry; formula fields are computed (docs/30 §6).
    pub values: &'a BTreeMap<Id, FieldValue>,
    /// Signature, initials and stamp art by the id a [`FieldValue::Signature`] names.
    pub captures: &'a BTreeMap<Id, Capture>,
    /// Printed in a signature's "Signed by" caption.
    pub envelope_id: Option<&'a str>,
    /// The AcroForm conversion the fields came from ([`Engine::convert_form`]), so the
    /// form's own widgets are removed (or filled in place) with the right fields.
    pub acroform: Option<&'a Conversion>,
    /// Refuse when a required field is empty or a group rule is unmet (`CS-FLD-0001`,
    /// `CS-FLD-0003`), as completion does. When false only those two are tolerated: a
    /// value that fails validation is always refused.
    pub require_complete: bool,
}

/// The flattened document and what was drawn.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Filled {
    /// The delivered bytes followed by one update.
    pub bytes: Vec<u8>,
    /// The values evaluated (linked, computed, hidden ones dropped) and every tolerated
    /// issue.
    pub outcome: Outcome,
    /// What flattening drew, filled, kept and embedded.
    pub report: FlattenReport,
}

/// The completed document: certificate of completion appended and `audit-trail.json`
/// embedded, ready to seal.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Completed {
    /// The flattened bytes followed by one update.
    pub bytes: Vec<u8>,
    /// `audit-trail.json` as embedded: RFC 8785 canonical JSON of the chain.
    pub trail: Vec<u8>,
    /// SHA-256 of [`Completed::trail`], printed on the certificate.
    pub trail_sha256: Hash256,
    /// The certificate's first page, from 0.
    pub first_page: usize,
    /// Pages the certificate added.
    pub pages_added: usize,
}

/// The facade. Cheap to clone (the faces are shared).
#[derive(Clone)]
pub struct Engine {
    limits: Limits,
    fonts: Arc<FontSet>,
    cancel: Option<CancelFn>,
}

impl fmt::Debug for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Engine")
            .field("limits", &self.limits)
            .field("fonts", &self.fonts.len())
            .field("cancel", &self.cancel.is_some())
            .finish()
    }
}

/// Codes [`Fill::require_complete`] `false` tolerates: a required field left empty and
/// a group rule unmet.
const TOLERATED_WHEN_PARTIAL: [&str; 2] = ["CS-FLD-0001", "CS-FLD-0003"];

impl Engine {
    /// An engine reading within `limits` (docs/21) and drawing with `fonts` (pass
    /// [`FontSet::bundled`] for the Liberation faces and two script faces).
    #[must_use]
    pub fn new(limits: Limits, fonts: FontSet) -> Self {
        Self {
            limits,
            fonts: Arc::new(fonts),
            cancel: None,
        }
    }

    /// The same engine, stopping a step when `cancel` returns true (`CS-PDF-0013`).
    #[must_use]
    pub fn with_cancel(mut self, cancel: CancelFn) -> Self {
        self.cancel = Some(cancel);
        self
    }

    /// The limits every step reads within.
    #[must_use]
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    fn cancelled(&self) -> bool {
        self.cancel.as_ref().is_some_and(|c| c())
    }

    fn open<'a>(
        &self,
        bytes: &'a [u8],
        credentials: &Credentials,
    ) -> Result<Admitted<'a>, SdkError> {
        let cancel = || self.cancelled();
        Ok(admit_with(bytes, &self.limits, credentials, &cancel)?)
    }

    /// Admit `bytes` (docs/30 §2): parse within the limits, recover what readers
    /// recover, and classify. `credentials` holds passwords for an encrypted file.
    ///
    /// # Errors
    /// [`SdkError::Pdf`] with the refusal's `CS-PDF-*` code.
    pub fn admit(
        &self,
        bytes: &[u8],
        credentials: &Credentials,
    ) -> Result<AdmissionReport, SdkError> {
        Ok(self.open(bytes, credentials)?.report)
    }

    /// Admit and normalize `bytes` into the document delivered to signers (docs/30 §3):
    /// a fresh, unencrypted file with active content, embedded files and external
    /// references removed, each listed in the report. Its hash is fixed here.
    ///
    /// # Errors
    /// [`SdkError::Pdf`] when admission refuses; [`SdkError::Write`] with `CS-PDF-0014`
    /// for signed input (use [`Engine::keep_signed`]) or the writer's code.
    pub fn prepare(&self, bytes: &[u8], credentials: &Credentials) -> Result<Delivered, SdkError> {
        let mut admitted = self.open(bytes, credentials)?;
        let admission = admitted.report.clone();
        let cancel = || self.cancelled();
        let normalized = normalize(
            &mut admitted,
            &NormalizeOptions::with_xref(OutputXref::Stream),
            &cancel,
        )?;
        let hash = Hash256::digest(&normalized.bytes);
        Ok(Delivered {
            bytes: normalized.bytes,
            hash,
            admission,
            normalization: Some(normalized.report),
        })
    }

    /// Accept signed input as delivered, unchanged, so a seal can be appended after its
    /// signatures (docs/30 §2, "keep the existing signatures and append").
    ///
    /// The file must count as signed, have been read without xref repair, be
    /// unencrypted (an update to an encrypted file would have to be encrypted), and
    /// carry no DocMDP P1 certification (which forbids any later signature). Fields
    /// cannot be flattened into such a file, and no certificate pages can be appended
    /// to it, without invalidating its signatures: seal it directly.
    ///
    /// # Errors
    /// [`SdkError::Pdf`] when admission refuses; [`SdkError::Write`] with `CS-WRT-0003`
    /// (repaired), `CS-WRT-0006` (encrypted), `CS-WRT-0004` (DocMDP P1), or `CS-PDF-0014`
    /// reversed: an unsigned file, which [`Engine::prepare`] takes.
    pub fn keep_signed(&self, bytes: &[u8]) -> Result<Delivered, SdkError> {
        let admitted = self.open(bytes, &Credentials::default())?;
        let report = admitted.report;
        if !report.is_signed() {
            return Err(SdkError::Write(WriteError::Signed));
        }
        if report.repaired {
            return Err(SdkError::Write(WriteError::NotSound));
        }
        if report.encryption.is_some() {
            return Err(SdkError::Write(WriteError::Encrypted));
        }
        if report.docmdp == Some(1) {
            return Err(SdkError::Write(WriteError::ChangeForbidden { docmdp: 1 }));
        }
        Ok(Delivered {
            bytes: bytes.to_vec(),
            hash: Hash256::digest(bytes),
            admission: report,
            normalization: None,
        })
    }

    /// Convert the delivered document's AcroForm fields into OpenSeal fields on
    /// `document_id`, minting each id with `next_id` (the engine makes no ids).
    ///
    /// # Errors
    /// [`SdkError::Pdf`] when reading crosses a limit or is cancelled.
    pub fn convert_form(
        &self,
        delivered: &[u8],
        document_id: &Id,
        next_id: &mut dyn FnMut() -> Id,
    ) -> Result<Conversion, SdkError> {
        let mut admitted = self.open(delivered, &Credentials::default())?;
        let report = admitted.report.clone();
        let cancel = || self.cancelled();
        Ok(casual_sign_fields::convert_acroform(
            &mut admitted.document,
            &report,
            document_id,
            next_id,
            &cancel,
        )?)
    }

    /// Evaluate the fields' values as completion does (linking, locking, formulas,
    /// visibility, validation; docs/30 §6) and flatten the result into the delivered
    /// document as one incremental update (docs/30 §7).
    ///
    /// # Errors
    /// [`SdkError::Fields`] with every issue when the values are invalid (or incomplete
    /// under [`Fill::require_complete`]); [`SdkError::Pdf`] or [`SdkError::Flatten`]
    /// when the document cannot take the update; [`SdkError::Prefix`] if the invariant
    /// broke.
    pub fn fill_and_flatten(
        &self,
        delivered: &[u8],
        fill: &Fill<'_>,
        options: &FlattenOptions,
    ) -> Result<Filled, SdkError> {
        let outcome = evaluate_envelope(fill.fields, fill.values);
        let refused: Vec<Issue> = outcome
            .issues
            .iter()
            .filter(|i| fill.require_complete || !TOLERATED_WHEN_PARTIAL.contains(&i.code()))
            .cloned()
            .collect();
        if !refused.is_empty() {
            return Err(SdkError::Fields(refused));
        }
        // Values evaluation computed or carried are checked once more, field by field,
        // so nothing invalid is drawn even if a rule changed between the two.
        let mut bad = Vec::new();
        for f in fill.fields {
            if let Some(v) = outcome.values.get(&f.id)
                && let Err(error) = validate(f, v)
            {
                bad.push(Issue {
                    field_id: f.id.clone(),
                    error,
                });
            }
        }
        if !bad.is_empty() {
            return Err(SdkError::Fields(bad));
        }
        let mut admitted = self.open(delivered, &Credentials::default())?;
        let input = casual_sign_flatten::FlattenInput {
            fields: fill.fields,
            values: &outcome.values,
            captures: fill.captures,
            envelope_id: fill.envelope_id,
            acroform: fill.acroform,
        };
        let cancel = || self.cancelled();
        let flat =
            casual_sign_flatten::flatten(&mut admitted, &input, &self.fonts, options, &cancel)
                .map_err(SdkError::Flatten)?;
        if !flat.bytes.starts_with(delivered) {
            return Err(SdkError::Prefix(Step::Flatten));
        }
        Ok(Filled {
            bytes: flat.bytes,
            outcome,
            report: flat.report,
        })
    }

    /// Append the certificate of completion to the flattened document and embed the
    /// chain's `audit-trail.json` as its associated file (docs/30 §8, docs/32 §6). The
    /// chain in `input` must verify and should end at `envelope.completing`: the seal
    /// that follows covers the certificate and the trail.
    ///
    /// # Errors
    /// [`SdkError::Certificate`] when the input is over its limits, the chain does not
    /// verify, or the document cannot take the pages; [`SdkError::Prefix`] if the
    /// invariant broke.
    pub fn complete(
        &self,
        flattened: &[u8],
        input: &CertificateInput<'_>,
        options: &CertificateOptions,
    ) -> Result<Completed, SdkError> {
        let mut admitted = self.open(flattened, &Credentials::default())?;
        let appended =
            casual_sign_certificate::append_certificate(&mut admitted, input, &self.fonts, options)
                .map_err(SdkError::Certificate)?;
        if !appended.bytes.starts_with(flattened) {
            return Err(SdkError::Prefix(Step::Certificate));
        }
        let trail = input
            .chain
            .to_trail_json()
            .map_err(|e| SdkError::Certificate(e.into()))?;
        Ok(Completed {
            bytes: appended.bytes,
            trail,
            trail_sha256: appended.trail_sha256,
            first_page: appended.first_page,
            pages_added: appended.pages_added,
        })
    }

    /// `base` when no field of `bytes` has that name, else `base` followed by the
    /// lowest number that is free: a name for a new signature field that cannot collide
    /// with the document's own fields (a signed document's earlier seal among them).
    ///
    /// # Errors
    /// [`SdkError::Pdf`] when admission refuses.
    pub fn free_field_name(&self, bytes: &[u8], base: &str) -> Result<String, SdkError> {
        let report = self.admit(bytes, &Credentials::default())?;
        let taken = |n: &str| report.fields.iter().any(|f| f.name == n);
        if !taken(base) {
            return Ok(base.to_owned());
        }
        let mut i: u32 = 1;
        loop {
            let candidate = format!("{base}{i}");
            if !taken(&candidate) || i == u32::MAX {
                return Ok(candidate);
            }
            i = i.saturating_add(1);
        }
    }

    /// A seal request at `profile` reading within this engine's limits, signed at
    /// `signing_time` (supplied: the engine reads no clock). Fill in the trust store,
    /// reason and kind before sealing.
    #[must_use]
    pub fn seal_request(
        &self,
        profile: Profile,
        field_name: &str,
        signing_time: core::time::Duration,
    ) -> SealRequest {
        let mut r = SealRequest::new(profile, field_name, signing_time);
        r.limits = self.limits;
        r
    }

    /// Seal `bytes` at the request's PAdES profile (docs/31 §4): append the signature,
    /// timestamp it for B-T and above, add the DSS for B-LT and a document timestamp for
    /// B-LTA. The output was verified by `casual-sign-verify` before it is returned.
    ///
    /// # Errors
    /// [`SdkError::Seal`] with the seal's code; [`SdkError::Prefix`] if the invariant
    /// broke.
    pub fn seal(
        &self,
        bytes: &[u8],
        request: &SealRequest,
        key: &dyn KeyProvider,
        timestamps: &dyn TimestampSource,
        revocation: &dyn RevocationSource,
    ) -> Result<Sealed, SdkError> {
        let sealed = casual_sign_seal::seal(bytes, request, key, timestamps, revocation)
            .map_err(SdkError::Seal)?;
        if !sealed.bytes.starts_with(bytes) {
            return Err(SdkError::Prefix(Step::Seal));
        }
        Ok(sealed)
    }

    /// Bring a sealed file to B-LT or B-LTA later (docs/31 §9), when revocation data
    /// was unavailable at completion.
    ///
    /// # Errors
    /// [`SdkError::Seal`] with the seal's code; [`SdkError::Prefix`] if the invariant
    /// broke.
    pub fn augment(
        &self,
        bytes: &[u8],
        profile: Profile,
        options: &ArchiveOptions,
        timestamps: &dyn TimestampSource,
        revocation: &dyn RevocationSource,
    ) -> Result<Sealed, SdkError> {
        let sealed = casual_sign_seal::augment(bytes, profile, options, timestamps, revocation)
            .map_err(SdkError::Seal)?;
        if !sealed.bytes.starts_with(bytes) {
            return Err(SdkError::Prefix(Step::Seal));
        }
        Ok(sealed)
    }

    /// Verification options at `validation_time` reading within this engine's limits.
    #[must_use]
    pub fn verify_options(&self, validation_time: core::time::Duration) -> VerifyOptions {
        let mut o = VerifyOptions::at(validation_time);
        o.limits = self.limits;
        o
    }

    /// Verify every signature and document timestamp of `bytes`, ours or not (docs/31
    /// §7): rung 1 of the verification ladder. Never fails: problems are in the report.
    #[must_use]
    pub fn verify(
        &self,
        bytes: &[u8],
        trust: &TrustStore,
        options: &VerifyOptions,
    ) -> VerificationReport {
        casual_sign_verify::verify(bytes, trust, options)
    }

    /// Verify an `audit-trail.json` (docs/32 §4): every hash, link, sequence number
    /// and time. Never fails: problems are in the report.
    #[must_use]
    pub fn verify_trail(&self, trail: &[u8], options: &TrailOptions) -> ChainReport {
        casual_sign_audit::verify_trail(trail, options)
    }
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report.
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn codes_are_the_stages() {
        assert_eq!(SdkError::Prefix(Step::Seal).code(), "CS-WRT-0001");
        assert_eq!(SdkError::Write(WriteError::Signed).code(), "CS-PDF-0014");
        assert_eq!(SdkError::Fields(Vec::new()).code(), "CS-FLD-0002");
    }

    #[test]
    fn keep_signed_refuses_unsigned() {
        let e = Engine::new(Limits::default(), FontSet::new());
        let pdf = b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 10 10]>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n";
        let err = e.keep_signed(pdf).unwrap_err();
        assert_eq!(err.code(), "CS-PDF-0014");
    }
}
