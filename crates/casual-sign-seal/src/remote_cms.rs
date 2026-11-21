//! Signing with a provider's own CMS (ADR-047 §3.2 to §3.4): an India eSign Service
//! Provider creates the signer's key and certificate only when it signs, and answers
//! with a whole CMS (`PKCS7pdf`) over the hash we sent, so nothing about the signer is
//! known when the revision is laid out.
//!
//! [`prepare_for_cms`] lays out the signature revision as [`crate::prepare`] does, with
//! a `/Contents` placeholder of the planned size and the `/SubFilter` the provider's CMS
//! will be carried under, and returns the SHA-256 ByteRange digest: the `InputHash`.
//! [`complete_cms`] checks the provider's CMS before anything is written (DER, one
//! SignerInfo, `message-digest` equal to that digest, a signature that verifies over the
//! signed attributes as received under the certificate the provider named, a strong
//! algorithm, CAdES-conformant if prepared as `ETSI.CAdES.detached`), keeps a signature
//! time-stamp it carries or adds ours (B-T) without touching a signed byte, embeds it
//! without ever re-laying out (`CS-RSP-0005`), adds the DSS at B-LT, and verifies the
//! result with `casual-sign-verify`, which also checks the chain to the anchors.

use core::time::Duration;

use casual_sign_crypto::foreign::{append_unsigned_attribute, check_foreign, is_ber};
use casual_sign_crypto::{CryptoError, DigestAlgorithm, oid};
use casual_sign_verify::SignatureKind;

use crate::check::{self, Expect};
use crate::error::{RemoteProblem, RequestProblem, SealError};
use crate::form::FieldSpec;
use crate::remote::{CompleteOptions, checked_laid};
use crate::revision::{MAX_PLACEHOLDER, RevisionSpec, embed, lay_out};
use crate::{
    Layout, Profile, RevocationSource, SealKind, SealReport, SealRequest, Sealed, TimestampSource,
    VerificationReport, dss, revision_count, signature_head_with, take_timestamp, vri_key,
};

/// Which `/SubFilter` a provider's CMS is carried under, fixed when the revision is laid
/// out (it is inside the signed bytes), from what the operator's catalogue says the
/// provider's CMS is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmsFormat {
    /// `ETSI.CAdES.detached`: the provider's signed attributes are CAdES-conformant; a
    /// CMS that is not is refused.
    Cades,
    /// `adbe.pkcs7.detached`: the one case we write it (ADR-047 §3.3, docs/31 §2).
    Pkcs7,
}

impl CmsFormat {
    /// The `/SubFilter` name.
    #[must_use]
    pub const fn sub_filter(self) -> &'static str {
        match self {
            Self::Cades => "ETSI.CAdES.detached",
            Self::Pkcs7 => "adbe.pkcs7.detached",
        }
    }
}

/// A revision laid out for a provider's CMS: plain data a host stores.
#[derive(Clone)]
pub struct PreparedForCms {
    /// The input followed by the new revision, its `/Contents` placeholder zero.
    pub bytes: Vec<u8>,
    /// `[0, a, b, c]`.
    pub byte_range: [u64; 4],
    /// Bytes reserved in `/Contents`.
    pub placeholder_len: usize,
    /// The SHA-256 digest of the ByteRange: the hash the provider signs.
    pub byte_range_digest: Vec<u8>,
    /// The `/SubFilter` written.
    pub format: CmsFormat,
    /// B-B, B-T or B-LT.
    pub profile: Profile,
    /// The signing time written as `/M`, since the Unix epoch.
    pub signing_time: Duration,
    /// The input's revision count.
    pub first_new_revision: usize,
}

impl core::fmt::Debug for PreparedForCms {
    /// Lengths and the layout: never the document's bytes.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PreparedForCms")
            .field("bytes", &self.bytes.len())
            .field("byte_range", &self.byte_range)
            .field("placeholder_len", &self.placeholder_len)
            .field("format", &self.format)
            .finish_non_exhaustive()
    }
}

/// What [`complete_cms`] found and did, for the audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderCms {
    /// The provider's signed attributes are CAdES-conformant.
    pub cades: bool,
    /// The CMS came with its own signature time-stamp, kept.
    pub provider_timestamp: bool,
}

/// Lay out a signature revision of `input` for a provider's CMS of at most
/// `placeholder_len` bytes (our time-stamp included), under `format`.
///
/// # Errors
/// As [`crate::prepare`]: the input's `CS-PDF-*` or the writer's `CS-WRT-*` code;
/// `CS-SEAL-0006` for B-LTA, a certification signature, or a placeholder of 0 or over
/// the largest CMS read.
pub fn prepare_for_cms(
    input: &[u8],
    request: &SealRequest,
    format: CmsFormat,
    placeholder_len: usize,
) -> Result<PreparedForCms, SealError> {
    if request.profile > Profile::BaselineLt {
        return Err(SealError::Request(RequestProblem::Profile));
    }
    if !matches!(request.kind, SealKind::Approval)
        || placeholder_len == 0
        || placeholder_len > MAX_PLACEHOLDER
    {
        return Err(SealError::Request(RequestProblem::Profile));
    }
    let limits = &request.limits;
    let head = signature_head_with(request, format.sub_filter().as_bytes())?;
    let first_new_revision = revision_count(input, limits)?.document.revisions().len();
    let spec = RevisionSpec {
        limits,
        field: FieldSpec {
            name: &request.field_name,
            visible: request.visible.as_ref(),
        },
        head,
        certification: false,
        archival: false,
    };
    let laid = lay_out(input, &spec, placeholder_len)?;
    let t = laid.to_sign();
    let digest = DigestAlgorithm::Sha256.digest_ranges(t.bytes, &t.ranges)?;
    Ok(PreparedForCms {
        byte_range: laid.byte_range(),
        placeholder_len: laid.placeholder,
        bytes: laid.bytes,
        byte_range_digest: digest.as_bytes().to_vec(),
        format,
        profile: request.profile,
        signing_time: request.signing_time,
        first_new_revision,
    })
}

fn problem(e: &CryptoError) -> SealError {
    SealError::Remote(match e {
        CryptoError::DigestMismatch => RemoteProblem::MessageDigest,
        CryptoError::SigningCertificateMismatch | CryptoError::SignerCertificateNotFound => {
            RemoteProblem::Certificate
        }
        _ => RemoteProblem::Cms,
    })
}

/// Embed the provider's `cms` (signed by `signer_certificate`, DER) into the prepared
/// revision: check it, time-stamp it if it has no time-stamp (B-T and above), write it,
/// add the DSS at B-LT, and verify the result.
///
/// # Errors
/// `CS-RSP-0004` ([`SealError::Remote`]): the prepared data was altered, the CMS is BER,
/// malformed, over other bytes, by another certificate, does not verify, is weak, or is
/// not CAdES-conformant for a CAdES revision; `CS-RSP-0005` when it does not fit the
/// placeholder; `CS-SEAL-0002` TSA; `CS-SEAL-0004` revocation data; `CS-SEAL-0010` the
/// result does not verify (a chain that does not reach the anchors, a revoked or
/// expired certificate, a provider time-stamp that does not verify).
pub fn complete_cms(
    prepared: &PreparedForCms,
    cms: &[u8],
    signer_certificate: &[u8],
    timestamps: &dyn TimestampSource,
    revocation: &dyn RevocationSource,
    options: &CompleteOptions,
) -> Result<(Sealed, ProviderCms), SealError> {
    let laid = checked_laid(
        &prepared.bytes,
        prepared.byte_range,
        prepared.placeholder_len,
    )?;
    let digest = {
        let t = laid.to_sign();
        DigestAlgorithm::Sha256.digest_ranges(t.bytes, &t.ranges)?
    };
    if digest.as_bytes() != prepared.byte_range_digest.as_slice() {
        return Err(SealError::Remote(RemoteProblem::PreparedAltered));
    }
    if is_ber(cms) {
        return Err(SealError::Remote(RemoteProblem::Ber));
    }
    let found = check_foreign(cms, &digest, signer_certificate).map_err(|e| problem(&e))?;
    if prepared.format == CmsFormat::Cades && !found.cades {
        return Err(SealError::Remote(RemoteProblem::Format));
    }
    let timestamped = prepared.profile >= Profile::BaselineT;
    let mut ts_time = None;
    let der = if timestamped && !found.timestamped {
        let token = take_timestamp(
            timestamps,
            &DigestAlgorithm::Sha256.digest(&found.signature_value),
        )?;
        ts_time = Some(token.gen_time());
        append_unsigned_attribute(cms, oid::ID_SIGNATURE_TIME_STAMP_TOKEN, token.as_der())
            .map_err(|e| problem(&e))?
    } else {
        casual_sign_crypto::foreign::trimmed(cms).map_err(|e| problem(&e))?
    };
    let written = embed(laid, &der).map_err(|e| match e {
        SealError::Overflow { reserved, needed } => SealError::RemoteOverflow { reserved, needed },
        other => other,
    })?;
    let lt = prepared.profile >= Profile::BaselineLt;
    let expects = [Expect {
        byte_range: written.byte_range,
        kind: SignatureKind::Approval,
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
    if let Some(s) = report.verification.signatures.last()
        && report.signature_timestamp.is_none()
    {
        report.signature_timestamp = s.timestamp.as_ref().map(|t| t.gen_time);
    }
    Ok((
        Sealed { bytes, report },
        ProviderCms {
            cades: found.cades,
            provider_timestamp: found.timestamped,
        },
    ))
}
