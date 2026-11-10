//! docs/31 §4 step 8: verify our own output with `casual-sign-verify` before returning
//! it. A seal that does not verify is `CS-SEAL-0010`.
//!
//! What must hold, for each signature or document timestamp this operation wrote: the
//! ByteRange, digest, CMS signature and (when one was taken) timestamp checks pass; the
//! kind is the one requested; with trust anchors supplied, the chain passes, and for
//! B-LT and B-LTA signatures revocation passes too. For every signature in the file,
//! each revision this operation added is an allowed change; and the last signature
//! covers the whole file unless a DSS follows it. Without trust anchors a chain cannot be judged, so it is not
//! required (integrity still is).

use core::time::Duration;

use casual_sign_pdf::Limits;
use casual_sign_verify::{
    Check, SignatureKind, TrustStore, VerificationReport, VerifyOptions, verify,
};

use crate::error::{CheckName, SealError, SelfCheckFailure};

/// One signature or document timestamp this operation wrote.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Expect {
    pub(crate) byte_range: [u64; 4],
    pub(crate) kind: SignatureKind,
    /// A signature timestamp was embedded (or this is a document timestamp).
    pub(crate) timestamped: bool,
    /// Revocation must pass when anchors are supplied.
    pub(crate) revocation: bool,
}

fn fail(signature: usize, check: CheckName, c: Option<&Check>) -> SealError {
    let reason = match c {
        Some(Check::Failed(r)) => Some(*r),
        _ => None,
    };
    SealError::SelfCheck(SelfCheckFailure {
        signature,
        check,
        reason,
    })
}

/// Verify `bytes` and hold our signatures to `expects`. `first_new_revision` is the
/// index of the first revision this operation added; `ends_signed` is false when the
/// last revision is a DSS (B-LT), which no signature covers by design.
pub(crate) fn self_check(
    bytes: &[u8],
    trust: &TrustStore,
    validation_time: Duration,
    limits: &Limits,
    expects: &[Expect],
    first_new_revision: usize,
    ends_signed: bool,
) -> Result<VerificationReport, SealError> {
    let mut options = VerifyOptions::at(validation_time);
    options.limits = *limits;
    let report = verify(bytes, trust, &options);
    if report.error.is_some() {
        return Err(fail(0, CheckName::Document, None));
    }
    let anchors = trust.anchor_count() > 0;
    for e in expects {
        let Some((i, s)) = report
            .signatures
            .iter()
            .enumerate()
            .find(|(_, s)| s.byte_range == Some(e.byte_range))
        else {
            return Err(fail(0, CheckName::Missing, None));
        };
        let c = &s.checks;
        let mut required = vec![
            (CheckName::ByteRange, &c.byte_range),
            (CheckName::Digest, &c.digest),
            (CheckName::Signature, &c.signature),
        ];
        if e.timestamped {
            required.push((CheckName::Timestamp, &c.timestamp));
        }
        if anchors {
            required.push((CheckName::Chain, &c.chain));
            if e.revocation {
                required.push((CheckName::Revocation, &c.revocation));
            }
        }
        for (name, check) in required {
            if !check.passed() {
                return Err(fail(i, name, Some(check)));
            }
        }
        if !matches!(c.modifications, Check::Passed | Check::NotRun) {
            return Err(fail(i, CheckName::Modifications, Some(&c.modifications)));
        }
        if s.kind != e.kind {
            return Err(fail(i, CheckName::Kind, None));
        }
    }
    for (i, s) in report.signatures.iter().enumerate() {
        if s.modifications_after
            .iter()
            .any(|m| m.revision >= first_new_revision && !m.allowed())
        {
            return Err(fail(
                i,
                CheckName::Modifications,
                Some(&s.checks.modifications),
            ));
        }
    }
    if ends_signed && !report.covered_by_last_signature {
        return Err(fail(
            report.signatures.len().saturating_sub(1),
            CheckName::Coverage,
            None,
        ));
    }
    Ok(report)
}
