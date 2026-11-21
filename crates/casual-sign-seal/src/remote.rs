//! Signing in two phases, for a key the platform does not hold (ADR-046 §3.3): a remote
//! provider (a CSC service) signs over a hash the signer authorizes at the provider,
//! minutes after we compute it, possibly in another process.
//!
//! [`prepare`] appends the signature revision with a fixed-width `/ByteRange` and a zero
//! `/Contents` placeholder sized for the signer's chain, fills the ByteRange, digests the
//! covered bytes and builds the DER signed attributes (`content-type`, `message-digest`,
//! ESS `signing-certificate-v2`; no `signingTime`). [`Prepared`] is plain data a host
//! stores. [`complete`] checks the provider's value over those attributes under the
//! certificate's key, adds our RFC 3161 signature timestamp (B-T), writes the CMS into
//! the placeholder, adds the DSS for that signature at B-LT, and verifies the result with
//! `casual-sign-verify`. It never re-lays out: a CMS larger than the placeholder is
//! `CS-RSP-0005`, because a new layout is a new hash the signer did not authorize.
//!
//! The crate stays pure: the time, the signature value, the TSA and the revocation
//! answers are supplied.

use core::time::Duration;

use casual_sign_crypto::cms::{external_signature, max_der_len_for, signed_attributes_der};
use casual_sign_crypto::{Certificate, DigestAlgorithm, SignatureAlgorithm};
use casual_sign_pdf::Limits;
use casual_sign_verify::{SignatureKind, TrustStore};

use crate::check::{self, Expect};
use crate::error::{RemoteProblem, RequestProblem, SealError};
use crate::form::FieldSpec;
use crate::revision::{Laid, MARGIN, MAX_PLACEHOLDER, RevisionSpec, embed, lay_out};
use crate::{
    Layout, Profile, RevocationSource, SealKind, SealReport, SealRequest, Sealed, TimestampSource,
    VerificationReport, dss, revision_count, signature_head, take_timestamp, vri_key,
};

/// The remote signer, as the provider describes its credential before signing
/// (`credentials/info`: the chain and the key's algorithm).
#[derive(Debug, Clone)]
pub struct ExternalSigner {
    /// The signer certificate first, then intermediates (and optionally the root).
    pub chain: Vec<Certificate>,
    /// The algorithm the provider will sign with.
    pub algorithm: SignatureAlgorithm,
}

/// A signature revision laid out and waiting for the provider's value: everything
/// [`complete`] needs, as plain data a host stores (the bytes content-addressed, the
/// rest in its session row).
#[derive(Clone)]
pub struct Prepared {
    /// The input followed by the new revision, its `/Contents` placeholder zero.
    pub bytes: Vec<u8>,
    /// `[0, a, b, c]`: every byte but the `/Contents` hex string.
    pub byte_range: [u64; 4],
    /// Bytes reserved in `/Contents`.
    pub placeholder_len: usize,
    /// The digest of the ByteRange, the `message-digest` signed attribute.
    pub byte_range_digest: Vec<u8>,
    /// The DER `SET OF` signed attributes the provider's value is over.
    pub signed_attributes: Vec<u8>,
    /// The digest of [`Prepared::signed_attributes`]: the hash sent to the provider
    /// (ADR-046 §3.5).
    pub to_be_signed: Vec<u8>,
    /// The signer.
    pub signer: ExternalSigner,
    /// The level [`complete`] reaches: B-B, B-T or B-LT.
    pub profile: Profile,
    /// Approval or certification, as requested.
    pub kind: SealKind,
    /// The signing time written as `/M`, since the Unix epoch.
    pub signing_time: Duration,
    /// The input's revision count: the first revision this signature adds.
    pub first_new_revision: usize,
}

impl core::fmt::Debug for Prepared {
    /// Lengths and the layout: never the document's bytes (CLAUDE.md).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Prepared")
            .field("bytes", &self.bytes.len())
            .field("byte_range", &self.byte_range)
            .field("placeholder_len", &self.placeholder_len)
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

impl Prepared {
    /// The digest algorithm of the ByteRange and of the signed attributes.
    #[must_use]
    pub const fn digest_algorithm(&self) -> DigestAlgorithm {
        self.signer.algorithm.digest_algorithm()
    }

    /// The laid-out revision, checked against the recorded ByteRange: the second range
    /// reaches the end and the gap is exactly a zero hex placeholder.
    fn laid(&self) -> Result<Laid, SealError> {
        checked_laid(&self.bytes, self.byte_range, self.placeholder_len)
    }
}

/// A stored revision as [`Laid`], checked against its recorded ByteRange: the second
/// range reaches the end and the gap is exactly a zero hex placeholder.
pub(crate) fn checked_laid(
    bytes: &[u8],
    byte_range: [u64; 4],
    placeholder_len: usize,
) -> Result<Laid, SealError> {
    let altered = SealError::Remote(RemoteProblem::PreparedAltered);
    let [zero, a, b, c] = byte_range;
    let a = usize::try_from(a).map_err(|_| altered.clone())?;
    let b = usize::try_from(b).map_err(|_| altered.clone())?;
    let c = usize::try_from(c).map_err(|_| altered.clone())?;
    let hex_len = placeholder_len.saturating_mul(2);
    let consistent = zero == 0
        && b.checked_add(c) == Some(bytes.len())
        && a.checked_add(hex_len).and_then(|v| v.checked_add(2)) == Some(b);
    if !consistent {
        return Err(altered);
    }
    let slot = bytes.get(a..b).ok_or(altered.clone())?;
    let (Some(b'<'), Some(b'>')) = (slot.first(), slot.last()) else {
        return Err(altered);
    };
    if !slot
        .get(1..slot.len().saturating_sub(1))
        .is_some_and(|h| h.iter().all(|&x| x == b'0'))
    {
        return Err(altered);
    }
    Ok(Laid {
        bytes: bytes.to_vec(),
        a,
        b,
        placeholder: placeholder_len,
    })
}

/// Lay out a signature revision of `input` as `request` asks, for `signer`, with room for
/// a signature timestamp of at most `timestamp_token_bound` bytes (B-T and B-LT), and
/// compute what the provider must sign.
///
/// # Errors
/// As [`crate::seal`]: the input's `CS-PDF-*` or the writer's `CS-WRT-*` code;
/// `CS-SEAL-0005` when the chain is empty or its key does not fit the algorithm;
/// `CS-SEAL-0006` for a request that does not fit (B-LTA, which a remote signature never
/// takes: the account's B-LTA is applied once at completion, ADR-046 §3.6).
pub fn prepare(
    input: &[u8],
    request: &SealRequest,
    signer: &ExternalSigner,
    timestamp_token_bound: usize,
) -> Result<Prepared, SealError> {
    if request.profile > Profile::BaselineLt {
        return Err(SealError::Request(RequestProblem::Profile));
    }
    let limits = &request.limits;
    let head = signature_head(request)?;
    let first_new_revision = {
        let admitted = revision_count(input, limits)?;
        if matches!(request.kind, SealKind::Certification { .. })
            && !admitted.report.signatures.is_empty()
        {
            return Err(SealError::Request(RequestProblem::CertificationNotFirst));
        }
        admitted.document.revisions().len()
    };
    let bound = if request.profile >= Profile::BaselineT {
        timestamp_token_bound
    } else {
        0
    };
    let placeholder = max_der_len_for(&signer.chain, signer.algorithm, bound)?
        .saturating_add(MARGIN)
        .min(MAX_PLACEHOLDER);
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
    let laid = lay_out(input, &spec, placeholder)?;
    let alg = signer.algorithm.digest_algorithm();
    let t = laid.to_sign();
    let digest = alg.digest_ranges(t.bytes, &t.ranges)?;
    let leaf = signer.chain.first().ok_or(SealError::Crypto(
        casual_sign_crypto::CryptoError::UnsupportedAlgorithm,
    ))?;
    let signed_attributes = signed_attributes_der(leaf, &digest)?;
    let to_be_signed = alg.digest(&signed_attributes).as_bytes().to_vec();
    Ok(Prepared {
        byte_range: laid.byte_range(),
        placeholder_len: laid.placeholder,
        bytes: laid.bytes,
        byte_range_digest: digest.as_bytes().to_vec(),
        signed_attributes,
        to_be_signed,
        signer: signer.clone(),
        profile: request.profile,
        kind: request.kind,
        signing_time: request.signing_time,
        first_new_revision,
    })
}

/// For [`complete`]: the self-check's anchors (the provider's configured roots and
/// ours) and the reader limits.
#[derive(Debug, Clone)]
pub struct CompleteOptions {
    /// Trust anchors for the self-check and the DSS.
    pub trust: TrustStore,
    /// Reader limits (docs/21).
    pub limits: Limits,
}

/// Embed the provider's signature `value` (over [`Prepared::to_be_signed`]) into the
/// prepared revision: check it, timestamp it (B-T and above), write the CMS, add the DSS
/// for it at B-LT, and verify the result.
///
/// # Errors
/// `CS-RSP-0004` ([`SealError::Remote`]) when the value does not verify over the
/// prepared attributes under the signer certificate, or the prepared data was altered;
/// `CS-RSP-0005` ([`SealError::RemoteOverflow`]) when the CMS is larger than the
/// placeholder; `CS-SEAL-0002` TSA; `CS-SEAL-0004` revocation data; `CS-SEAL-0010` our
/// own output failed verification.
pub fn complete(
    prepared: &Prepared,
    value: &[u8],
    timestamps: &dyn TimestampSource,
    revocation: &dyn RevocationSource,
    options: &CompleteOptions,
) -> Result<Sealed, SealError> {
    let laid = prepared.laid()?;
    let alg = prepared.digest_algorithm();
    let digest = {
        let t = laid.to_sign();
        alg.digest_ranges(t.bytes, &t.ranges)?
    };
    let leaf = prepared
        .signer
        .chain
        .first()
        .ok_or(SealError::Remote(RemoteProblem::PreparedAltered))?;
    if digest.as_bytes() != prepared.byte_range_digest.as_slice()
        || signed_attributes_der(leaf, &digest)? != prepared.signed_attributes
    {
        return Err(SealError::Remote(RemoteProblem::PreparedAltered));
    }
    let signed = external_signature(
        &prepared.signer.chain,
        prepared.signer.algorithm,
        &prepared.signed_attributes,
        value,
    )
    .map_err(|_| SealError::Remote(RemoteProblem::SignatureValue))?;
    let timestamped = prepared.profile >= Profile::BaselineT;
    let mut ts_time = None;
    let token = if timestamped {
        let tok = take_timestamp(timestamps, &alg.digest(signed.signature_value()))?;
        ts_time = Some(tok.gen_time());
        Some(tok.as_der().to_vec())
    } else {
        None
    };
    let der = signed.to_der(token.as_deref())?;
    let written = embed(laid, &der).map_err(|e| match e {
        SealError::Overflow { reserved, needed } => SealError::RemoteOverflow { reserved, needed },
        other => other,
    })?;
    let kind = match prepared.kind {
        SealKind::Approval => SignatureKind::Approval,
        SealKind::Certification { docmdp } => SignatureKind::Certification {
            permissions: docmdp.level(),
        },
    };
    let lt = prepared.profile >= Profile::BaselineLt;
    let expects = [Expect {
        byte_range: written.byte_range,
        kind,
        timestamped,
        revocation: lt,
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
    let at = ts_time.map_or(prepared.signing_time, |t| t.max(prepared.signing_time));
    if lt {
        let (b, d) = dss::add_dss(
            &bytes,
            core::slice::from_ref(&written.contents),
            prepared.signing_time,
            revocation,
            &options.trust,
            &options.limits,
        )?;
        bytes = b;
        report.vri_key = Some(vri_key(&written.contents));
        report.dss = Some(d);
        report.revisions_added = 2;
    }
    report.verification = check::self_check(
        &bytes,
        &options.trust,
        at,
        &options.limits,
        &expects,
        prepared.first_new_revision,
        !lt,
    )?;
    Ok(Sealed { bytes, report })
}
