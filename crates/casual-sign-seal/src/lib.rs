//! OpenSeal sealing: PAdES B-B, B-T, B-LT and B-LTA as incremental updates (docs/31).
//!
//! [`seal`] appends a signature revision to a PDF (docs/31 §4): a `/Sig` field with an
//! invisible or visible widget, a signature dictionary with `/Filter /Adobe.PPKLite`,
//! `/SubFilter /ETSI.CAdES.detached`, `/M` from the supplied time (no CMS
//! `signingTime`), and for a certification signature a DocMDP `/Reference` and the
//! catalog's `/Perms`. The `/Contents` placeholder is sized by computation
//! ([`casual_sign_crypto::cms::max_der_len`] with the chain and the TSA's token bound,
//! plus a margin); the `/ByteRange` is a fixed-width placeholder filled in place, so no
//! offset moves. The covered bytes are digested, the DER signed attributes go to the
//! [`KeyProvider`], the signature value is timestamped for B-T (RFC 3161, unsigned
//! attribute), and the CMS is written into `/Contents`. A CMS larger than its
//! placeholder is `CS-SEAL-0003`, retried once with the measured size, never
//! truncated.
//!
//! For B-LT a second revision adds the `/DSS` with `/Certs`, `/OCSPs`, `/CRLs` and a
//! `/VRI` entry for the signature; for B-LTA a third adds a document timestamp
//! (`/Type /DocTimeStamp`, `/SubFilter /ETSI.RFC3161`) over the whole file.
//! [`augment`] brings an already sealed file to B-LT or B-LTA later (docs/31 §9: when
//! OCSP was unavailable at completion), and [`renew_lta`] adds validation data for the
//! last document timestamp and a new one over it (the renewal job, slice 17).
//!
//! **Every output is verified with `casual-sign-verify` before it is returned**
//! (docs/31 §4 step 8); a failure is `CS-SEAL-0010`. The input is always a prefix of
//! the output (docs/30 §1).
//!
//! The crate performs no I/O, reads no clock and samples no randomness: the time, the
//! key ([`KeyProvider`]), the TSA ([`TimestampSource`], nonce included) and revocation
//! answers ([`RevocationSource`]) are supplied. Output is deterministic apart from the
//! CMS signature value and the TSA's token: ECDSA is randomized unless the provider uses
//! RFC 6979 (the test provider, aws-lc-rs, does not); RSA PKCS#1 v1.5 is deterministic.

mod check;
mod dss;
mod error;
mod form;
mod revision;
mod source;
mod text;

use core::time::Duration;

use casual_sign_crypto::cms::{max_der_len, sign_detached};
use casual_sign_crypto::tsp::{TimestampRequest, TimestampToken, verify_timestamp_response};
use casual_sign_crypto::{DigestAlgorithm, DigestValue, KeyProvider};
use casual_sign_pdf::{Admitted, Object, admit};
use casual_sign_verify::SignatureKind;

pub use casual_sign_pdf::{Dictionary, Limits, Rect};
pub use casual_sign_verify::{TrustStore, VerificationReport};
pub use dss::{DssReport, vri_key};
pub use error::{
    CheckName, LayoutProblem, RequestProblem, RevocationProblem, SealError, SelfCheckFailure,
};
pub use source::{
    CrlQuery, NoRevocation, NoTimestamps, OcspQuery, RevocationSource, SourceError, TimestampSource,
};

use crate::check::Expect;
use crate::form::{FieldSpec, never};
use crate::revision::{MARGIN, RevisionSpec, ToSign, Written, write_with_retry};
use crate::text::{pdf_date, text_string};

/// A PAdES baseline level (ETSI EN 319 142-1; docs/31 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Profile {
    /// B-B: the CMS signature only. Tests; never alone in production.
    BaselineB,
    /// B-T: and a signature timestamp. The default.
    BaselineT,
    /// B-LT: and a DSS with the validation data.
    BaselineLt,
    /// B-LTA: and a document timestamp over the whole.
    BaselineLta,
}

impl Profile {
    /// The ETSI name, as EU DSS reports it: `PAdES-BASELINE-B` and so on.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::BaselineB => "PAdES-BASELINE-B",
            Self::BaselineT => "PAdES-BASELINE-T",
            Self::BaselineLt => "PAdES-BASELINE-LT",
            Self::BaselineLta => "PAdES-BASELINE-LTA",
        }
    }
}

/// A certification signature's DocMDP permission level (ISO 32000-2 §12.8.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocMdp {
    /// No changes.
    P1,
    /// Form filling and signing.
    P2,
    /// Form filling, signing and annotations.
    P3,
}

impl DocMdp {
    /// `/P`.
    #[must_use]
    pub const fn level(self) -> u8 {
        match self {
            Self::P1 => 1,
            Self::P2 => 2,
            Self::P3 => 3,
        }
    }
}

/// Approval or certification (docs/31 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealKind {
    /// An approval signature.
    Approval,
    /// A certification signature: the document's first, with DocMDP.
    Certification {
        /// What later revisions may do.
        docmdp: DocMdp,
    },
}

/// The widget's normal appearance.
#[derive(Debug, Clone, PartialEq)]
pub enum Appearance {
    /// A thin black border.
    Border,
    /// A content stream drawn in the widget's box (`/BBox [0 0 width height]`), with its
    /// resources. Fonts in the resources must be embedded (docs/30 §7).
    Content {
        /// The content stream.
        content: Vec<u8>,
        /// Its `/Resources`.
        resources: Option<Dictionary>,
    },
}

/// A visible signature widget.
#[derive(Debug, Clone, PartialEq)]
pub struct Visible {
    /// Zero-based page index (a new field only).
    pub page: u32,
    /// The widget rectangle in the page's default user space (a new field only; an
    /// existing field keeps its widget's rectangle).
    pub rect: Rect,
    /// What it shows.
    pub appearance: Appearance,
}

/// What to seal and how (docs/31 §4).
#[derive(Debug, Clone)]
pub struct SealRequest {
    /// The baseline level to reach.
    pub profile: Profile,
    /// Approval or certification.
    pub kind: SealKind,
    /// The signature field: an existing unsigned `/Sig` field by its full name, or the
    /// partial name of a new one (no period).
    pub field_name: String,
    /// `/Name`.
    pub name: Option<String>,
    /// `/Reason`.
    pub reason: Option<String>,
    /// `/Location`.
    pub location: Option<String>,
    /// `/ContactInfo`.
    pub contact_info: Option<String>,
    /// A visible widget; `None` for an invisible one on the first page.
    pub visible: Option<Visible>,
    /// The signing time for `/M` and for revocation checks, since the Unix epoch.
    pub signing_time: Duration,
    /// Trust anchors for the self-check: with anchors, the chain (and for B-LT and
    /// B-LTA revocation) must pass; without, only integrity is required.
    pub trust: TrustStore,
    /// Reader limits (docs/21).
    pub limits: Limits,
}

impl SealRequest {
    /// An invisible approval signature at `profile` in a new field `field_name`.
    #[must_use]
    pub fn new(profile: Profile, field_name: &str, signing_time: Duration) -> Self {
        Self {
            profile,
            kind: SealKind::Approval,
            field_name: field_name.to_string(),
            name: None,
            reason: None,
            location: None,
            contact_info: None,
            visible: None,
            signing_time,
            trust: TrustStore::new(),
            limits: Limits::default(),
        }
    }
}

/// For [`augment`] and [`renew_lta`]: the time revocation is checked at, and the
/// self-check's anchors and limits.
#[derive(Debug, Clone)]
pub struct ArchiveOptions {
    /// Now, since the Unix epoch (supplied).
    pub time: Duration,
    /// Trust anchors for the self-check.
    pub trust: TrustStore,
    /// Reader limits.
    pub limits: Limits,
}

/// Where a signature or document timestamp was laid out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    /// `/ByteRange`.
    pub byte_range: [u64; 4],
    /// Bytes reserved in `/Contents`.
    pub placeholder_len: usize,
    /// Bytes of DER written.
    pub der_len: usize,
    /// 1, or 2 when the first placeholder overflowed (docs/31 §9).
    pub attempts: u8,
}

impl From<&Written> for Layout {
    fn from(w: &Written) -> Self {
        Self {
            byte_range: w.byte_range,
            placeholder_len: w.placeholder,
            der_len: w.der_len,
            attempts: w.attempts,
        }
    }
}

/// What an operation did.
#[derive(Debug, Clone)]
pub struct SealReport {
    /// The signature written by [`seal`].
    pub signature: Option<Layout>,
    /// The signature timestamp's `genTime` (B-T and above).
    pub signature_timestamp: Option<Duration>,
    /// The `/VRI` key of the signature (B-LT and above).
    pub vri_key: Option<String>,
    /// The DSS revision.
    pub dss: Option<DssReport>,
    /// The document timestamp written.
    pub document_timestamp: Option<Layout>,
    /// Its `genTime`.
    pub document_timestamp_time: Option<Duration>,
    /// Revisions appended.
    pub revisions_added: usize,
    /// Our verifier's report on the output (docs/31 §4 step 8).
    pub verification: VerificationReport,
}

/// A sealed file and its report.
#[derive(Clone)]
pub struct Sealed {
    /// The output: the input followed by the new revisions.
    pub bytes: Vec<u8>,
    /// What was done.
    pub report: SealReport,
}

impl core::fmt::Debug for Sealed {
    /// The report and the output's length: never the document's bytes (CLAUDE.md).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sealed")
            .field("bytes", &self.bytes.len())
            .field("report", &self.report)
            .finish()
    }
}

/// Ask `source` for a timestamp over `imprint` and check the answer (docs/31 §6).
fn take_timestamp(
    source: &dyn TimestampSource,
    imprint: &DigestValue,
) -> Result<TimestampToken, SealError> {
    let nonce = source.nonce();
    if nonce.is_empty() {
        // A source with no nonce is no TSA at all (`NoTimestamps`).
        return Err(SealError::Timestamp(SourceError::NotConfigured));
    }
    let request = TimestampRequest::new(imprint, &nonce)?;
    let response = source
        .timestamp(request.as_der())
        .map_err(SealError::Timestamp)?;
    Ok(verify_timestamp_response(&response, &request)?)
}

fn name(n: &[u8]) -> Object {
    Object::Name(n.to_vec())
}

/// The signature dictionary's entries before `/ByteRange` and `/Contents`.
fn signature_head(request: &SealRequest) -> Result<Dictionary, SealError> {
    let mut d = Dictionary::new();
    d.insert(b"Type", name(b"Sig"));
    d.insert(b"Filter", name(b"Adobe.PPKLite"));
    d.insert(b"SubFilter", name(b"ETSI.CAdES.detached"));
    if let SealKind::Certification { docmdp } = request.kind {
        let mut params = Dictionary::new();
        params.insert(b"Type", name(b"TransformParams"));
        params.insert(b"P", Object::Integer(i64::from(docmdp.level())));
        params.insert(b"V", name(b"1.2"));
        let mut r = Dictionary::new();
        r.insert(b"Type", name(b"SigRef"));
        r.insert(b"TransformMethod", name(b"DocMDP"));
        r.insert(b"TransformParams", Object::Dictionary(params));
        d.insert(b"Reference", Object::Array(vec![Object::Dictionary(r)]));
    }
    d.insert(
        b"M",
        Object::String(pdf_date(request.signing_time).map_err(SealError::Request)?),
    );
    for (key, value) in [
        (&b"Name"[..], &request.name),
        (b"Reason", &request.reason),
        (b"Location", &request.location),
        (b"ContactInfo", &request.contact_info),
    ] {
        if let Some(v) = value {
            d.insert(
                key,
                Object::String(text_string(v).map_err(SealError::Request)?),
            );
        }
    }
    Ok(d)
}

/// Append a document timestamp over the whole of `input` (B-LTA).
fn document_timestamp(
    input: &[u8],
    source: &dyn TimestampSource,
    limits: &Limits,
) -> Result<(Written, Duration), SealError> {
    let field = {
        let admitted = admit(input, limits, &never)?;
        form::free_name(&admitted, "DocTimeStamp")
    };
    let mut head = Dictionary::new();
    head.insert(b"Type", name(b"DocTimeStamp"));
    head.insert(b"Filter", name(b"Adobe.PPKLite"));
    head.insert(b"SubFilter", name(b"ETSI.RFC3161"));
    let spec = RevisionSpec {
        limits,
        field: FieldSpec {
            name: &field,
            visible: None,
        },
        head,
        certification: false,
        archival: true,
    };
    let mut gen_time = Duration::ZERO;
    let mut content = |t: ToSign<'_>| -> Result<Vec<u8>, SealError> {
        let digest = DigestAlgorithm::Sha256.digest_ranges(t.bytes, &t.ranges)?;
        let token = take_timestamp(source, &digest)?;
        gen_time = token.gen_time();
        Ok(token.as_der().to_vec())
    };
    let placeholder = source.token_len_bound().saturating_add(MARGIN);
    let w = write_with_retry(input, &spec, placeholder, &mut content)?;
    Ok((w, gen_time))
}

fn revision_count<'a>(input: &'a [u8], limits: &Limits) -> Result<Admitted<'a>, SealError> {
    Ok(admit(input, limits, &never)?)
}

/// Seal `input` (an admitted-clean PDF: the bytes delivered to signers, flattened)
/// as `request` asks, signing through `key`, timestamping through `timestamps` (B-T and
/// above) and collecting revocation data through `revocation` (B-LT and above).
///
/// # Errors
/// [`SealError`] with its docs/20 code: the input's `CS-PDF-*` or the writer's
/// `CS-WRT-*` code; `CS-SEAL-0001` key provider; `CS-SEAL-0002` TSA; `CS-SEAL-0003`
/// placeholder overflow after one retry; `CS-SEAL-0004` revocation data;
/// `CS-SEAL-0005` algorithm; `CS-SEAL-0006` a request that does not fit the document;
/// `CS-SEAL-0010` our own output failed verification.
pub fn seal(
    input: &[u8],
    request: &SealRequest,
    key: &dyn KeyProvider,
    timestamps: &dyn TimestampSource,
    revocation: &dyn RevocationSource,
) -> Result<Sealed, SealError> {
    let limits = &request.limits;
    let head = signature_head(request)?;
    let first_new = {
        let admitted = revision_count(input, limits)?;
        if matches!(request.kind, SealKind::Certification { .. })
            && !admitted.report.signatures.is_empty()
        {
            return Err(SealError::Request(RequestProblem::CertificationNotFirst));
        }
        admitted.document.revisions().len()
    };
    let timestamped = request.profile >= Profile::BaselineT;
    let bound = if timestamped {
        timestamps.token_len_bound()
    } else {
        0
    };
    let placeholder = max_der_len(key, bound)?.saturating_add(MARGIN);
    let alg = key.algorithm().digest_algorithm();
    let mut ts_time = None;
    let mut content = |t: ToSign<'_>| -> Result<Vec<u8>, SealError> {
        let digest = alg.digest_ranges(t.bytes, &t.ranges)?;
        let signed = sign_detached(key, &digest)?;
        let token = if timestamped {
            let tok = take_timestamp(timestamps, &alg.digest(signed.signature_value()))?;
            ts_time = Some(tok.gen_time());
            Some(tok.as_der().to_vec())
        } else {
            None
        };
        Ok(signed.to_der(token.as_deref())?)
    };
    let spec = RevisionSpec {
        limits,
        field: FieldSpec {
            name: &request.field_name,
            visible: request.visible.as_ref(),
        },
        head,
        certification: matches!(request.kind, SealKind::Certification { .. }),
        archival: false,
    };
    let written = write_with_retry(input, &spec, placeholder, &mut content)?;
    let kind = match request.kind {
        SealKind::Approval => SignatureKind::Approval,
        SealKind::Certification { docmdp } => SignatureKind::Certification {
            permissions: docmdp.level(),
        },
    };
    let mut expects = vec![Expect {
        byte_range: written.byte_range,
        kind,
        timestamped,
        revocation: request.profile >= Profile::BaselineLt,
    }];
    let mut report = SealReport {
        signature: Some(Layout::from(&written)),
        signature_timestamp: ts_time,
        vri_key: None,
        dss: None,
        document_timestamp: None,
        document_timestamp_time: None,
        revisions_added: 1,
        verification: VerificationReport {
            error: None,
            revisions: 0,
            signatures: Vec::new(),
            revision_changes: Vec::new(),
            covered_by_last_signature: false,
        },
    };
    let mut bytes = written.bytes;
    if request.profile >= Profile::BaselineLt {
        let (b, d) = dss::add_dss(
            &bytes,
            core::slice::from_ref(&written.contents),
            request.signing_time,
            revocation,
            limits,
        )?;
        bytes = b;
        report.vri_key = Some(vri_key(&written.contents));
        report.dss = Some(d);
        report.revisions_added = report.revisions_added.saturating_add(1);
    }
    if request.profile >= Profile::BaselineLta {
        let (w, t) = document_timestamp(&bytes, timestamps, limits)?;
        expects.push(Expect {
            byte_range: w.byte_range,
            kind: SignatureKind::DocumentTimestamp,
            timestamped: true,
            revocation: false,
        });
        report.document_timestamp = Some(Layout::from(&w));
        report.document_timestamp_time = Some(t);
        report.revisions_added = report.revisions_added.saturating_add(1);
        bytes = w.bytes;
    }
    let validation_time = [
        Some(request.signing_time),
        report.signature_timestamp,
        report.document_timestamp_time,
    ]
    .into_iter()
    .flatten()
    .max()
    .unwrap_or(request.signing_time);
    report.verification = check::self_check(
        &bytes,
        &request.trust,
        validation_time,
        limits,
        &expects,
        first_new,
        request.profile != Profile::BaselineLt,
    )?;
    Ok(Sealed { bytes, report })
}

/// The decoded `/Contents` of each signature and document timestamp in `admitted`, with
/// whether it is a document timestamp and where its ByteRange ends.
fn signature_contents(admitted: &mut Admitted<'_>) -> Vec<(Vec<u8>, bool, u64)> {
    let infos = admitted.report.signatures.clone();
    let doc = &mut admitted.document;
    let mut out = Vec::new();
    for info in infos {
        let dict = match (info.value, info.field) {
            (Some(v), _) => doc.object(v, &never).ok(),
            (None, Some(f)) => doc
                .object(f, &never)
                .ok()
                .and_then(|fo| fo.get(b"V").cloned())
                .and_then(|v| doc.resolve(&v, &never).ok()),
            (None, None) => None,
        };
        let Some(Object::Dictionary(d)) = dict else {
            continue;
        };
        let Some(Object::String(contents)) = d.get(b"Contents") else {
            continue;
        };
        let doc_ts = d.name(b"Type") == Some(b"DocTimeStamp")
            || d.name(b"SubFilter") == Some(b"ETSI.RFC3161");
        let end = match d.get(b"ByteRange") {
            Some(Object::Array(a)) => {
                let v = |i: usize| a.get(i).and_then(Object::as_i64).unwrap_or(0);
                u64::try_from(v(2).saturating_add(v(3))).unwrap_or(0)
            }
            _ => 0,
        };
        out.push((contents.clone(), doc_ts, end));
    }
    out
}

fn archive(
    input: &[u8],
    targets: &[Vec<u8>],
    lta: bool,
    first_new: usize,
    options: &ArchiveOptions,
    timestamps: &dyn TimestampSource,
    revocation: &dyn RevocationSource,
) -> Result<Sealed, SealError> {
    let limits = &options.limits;
    let (mut bytes, d) = dss::add_dss(input, targets, options.time, revocation, limits)?;
    let mut report = SealReport {
        signature: None,
        signature_timestamp: None,
        vri_key: None,
        dss: Some(d),
        document_timestamp: None,
        document_timestamp_time: None,
        revisions_added: 1,
        verification: VerificationReport {
            error: None,
            revisions: 0,
            signatures: Vec::new(),
            revision_changes: Vec::new(),
            covered_by_last_signature: false,
        },
    };
    let mut expects = Vec::new();
    if lta {
        let (w, t) = document_timestamp(&bytes, timestamps, limits)?;
        expects.push(Expect {
            byte_range: w.byte_range,
            kind: SignatureKind::DocumentTimestamp,
            timestamped: true,
            revocation: false,
        });
        report.document_timestamp = Some(Layout::from(&w));
        report.document_timestamp_time = Some(t);
        report.revisions_added = 2;
        bytes = w.bytes;
    }
    let at = report
        .document_timestamp_time
        .map_or(options.time, |t| t.max(options.time));
    report.verification =
        check::self_check(&bytes, &options.trust, at, limits, &expects, first_new, lta)?;
    Ok(Sealed { bytes, report })
}

/// Bring a sealed file to B-LT (or B-LTA) later: a DSS revision with validation data
/// for every signature and document timestamp whose CMS can be read, then, for B-LTA,
/// a document timestamp (docs/31 §9: the augmentation scheduled when OCSP and CRLs were
/// unavailable at completion). Revocation is checked at `options.time`.
///
/// # Errors
/// As [`seal`]; `CS-SEAL-0006` when the file has no readable signature or `profile` is
/// below B-LT.
pub fn augment(
    input: &[u8],
    profile: Profile,
    options: &ArchiveOptions,
    timestamps: &dyn TimestampSource,
    revocation: &dyn RevocationSource,
) -> Result<Sealed, SealError> {
    if profile < Profile::BaselineLt {
        return Err(SealError::Request(RequestProblem::Profile));
    }
    let mut admitted = revision_count(input, &options.limits)?;
    let first_new = admitted.document.revisions().len();
    let targets: Vec<Vec<u8>> = signature_contents(&mut admitted)
        .into_iter()
        .filter(|(c, _, _)| dss::certificates_of(c).is_ok())
        .map(|(c, _, _)| c)
        .collect();
    if targets.is_empty() {
        return Err(SealError::Request(RequestProblem::NoSignature));
    }
    archive(
        input,
        &targets,
        profile == Profile::BaselineLta,
        first_new,
        options,
        timestamps,
        revocation,
    )
}

/// Renew a B-LTA file (ETSI EN 319 142-1 §5.5): add validation data for its last
/// document timestamp's TSA chain, then a new document timestamp over everything, before
/// the last one's TSA certificate or algorithm weakens (docs/31 §2; slice 17).
///
/// # Errors
/// As [`seal`]; `CS-SEAL-0006` when the file has no document timestamp.
pub fn renew_lta(
    input: &[u8],
    options: &ArchiveOptions,
    timestamps: &dyn TimestampSource,
    revocation: &dyn RevocationSource,
) -> Result<Sealed, SealError> {
    let mut admitted = revision_count(input, &options.limits)?;
    let first_new = admitted.document.revisions().len();
    let last = signature_contents(&mut admitted)
        .into_iter()
        .filter(|(_, doc_ts, _)| *doc_ts)
        .max_by_key(|(_, _, end)| *end)
        .map(|(c, _, _)| c)
        .ok_or(SealError::Request(RequestProblem::NoDocumentTimestamp))?;
    archive(
        input,
        &[last],
        true,
        first_new,
        options,
        timestamps,
        revocation,
    )
}
