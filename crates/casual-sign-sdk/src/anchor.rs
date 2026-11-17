//! Public anchoring of audit chain heads (docs/32 §5, `FG-158`): the host's two halves.
//!
//! - [`timestamp_statement`]: ask a time-stamping authority (through the host's
//!   [`TimestampSource`], nonce included) for a token over an anchor's statement, and
//!   check the answer before it is stored.
//! - [`verify_anchor_proof`]: what a verifier runs on an envelope's proof file, offline:
//!   the head is a leaf of the anchored tree, the token is the TSA's over the tree's
//!   statement, the TSA chains to the verifier's anchors, and (given the trail) the head
//!   is the trail's event at the proof's sequence number.

use core::time::Duration;

pub use casual_sign_audit::AuditError;
pub use casual_sign_audit::anchor::{
    ANCHOR_FORMAT, ANCHOR_PROOF_FORMAT, Anchor, AnchorProof, MAX_ANCHOR_LEAVES, anchor_statement,
};
pub use casual_sign_audit::merkle::{InclusionProof, MerkleTree};
use casual_sign_audit::{Hash256, VerifyOptions as TrailOptions};
use casual_sign_crypto::DigestValue;
use casual_sign_crypto::tsp::{TimestampRequest, verify_timestamp_response};
use casual_sign_seal::{SealError, SourceError, TimestampSource, TrustStore};
pub use casual_sign_verify::TimestampVerdict;
use casual_sign_verify::verify_timestamp;

/// A checked token over a statement.
#[derive(Clone, Debug)]
pub struct StatementToken {
    /// The DER `TimeStampToken`, as stored and published.
    pub der: Vec<u8>,
    /// Its `genTime` since the Unix epoch.
    pub gen_time: Duration,
}

/// Ask `source` for a timestamp over `statement` and check the answer: status, nonce,
/// imprint, signature and the TSA's key purpose (docs/31 §6), as a seal's.
///
/// # Errors
///
/// `CS-SEAL-0002` when the source has no TSA, none answers, or the answer fails a check.
pub fn timestamp_statement(
    source: &dyn TimestampSource,
    statement: &Hash256,
) -> Result<StatementToken, SealError> {
    let nonce = source.nonce();
    if nonce.is_empty() {
        return Err(SealError::Timestamp(SourceError::NotConfigured));
    }
    let imprint = DigestValue::from_bytes(
        casual_sign_crypto::DigestAlgorithm::Sha256,
        statement.as_bytes(),
    )?;
    let request = TimestampRequest::new(&imprint, &nonce)?;
    let answer = source
        .timestamp(request.as_der())
        .map_err(SealError::Timestamp)?;
    let token = verify_timestamp_response(&answer, &request)?;
    Ok(StatementToken {
        der: token.as_der().to_vec(),
        gen_time: token.gen_time(),
    })
}

/// The verdict on a proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorOutcome {
    /// Every check passed.
    Passed,
    /// Inclusion, the token or the trail failed: the proof does not show what it claims.
    Failed,
    /// Nothing failed, but the TSA does not chain to a trusted anchor at its time.
    Indeterminate,
}

/// What [`verify_anchor_proof`] found.
#[derive(Clone, Debug)]
pub struct AnchorVerification {
    /// The proof as read.
    pub proof: AnchorProof,
    /// The head is the leaf at its index of the tree of the anchor's size and root
    /// (`CS-AUD-0009` otherwise).
    pub inclusion: Result<(), AuditError>,
    /// The token over the anchor's statement and its TSA's chain.
    pub timestamp: TimestampVerdict,
    /// With a trail: it verifies and its event at the proof's sequence number is the
    /// head (`CS-AUD-0008`, `CS-AUD-0012` otherwise).
    pub trail: Option<Result<(), AuditError>>,
}

impl AnchorVerification {
    /// The overall verdict.
    #[must_use]
    pub fn outcome(&self) -> AnchorOutcome {
        let trail_ok = self.trail.as_ref().is_none_or(Result::is_ok);
        if self.inclusion.is_err() || !self.timestamp.token.passed() || !trail_ok {
            AnchorOutcome::Failed
        } else if self.timestamp.chain.passed() {
            AnchorOutcome::Passed
        } else {
            AnchorOutcome::Indeterminate
        }
    }
}

/// Verify the anchor proof file `proof`, and with `trail` (an `audit-trail.json`, for
/// example the one embedded in the sealed PDF) that the anchored head is one of its
/// events. No I/O, no clock: the token's own time is the time proved.
///
/// # Errors
///
/// The `CS-AUD-*` code when the file cannot be read as a proof (`CS-AUD-0001` to
/// `0003`, `0009` for a statement that does not match its root and size).
pub fn verify_anchor_proof(
    proof: &[u8],
    trail: Option<&[u8]>,
    trust: &TrustStore,
) -> Result<AnchorVerification, AuditError> {
    let proof = AnchorProof::from_json(proof)?;
    let inclusion = proof.check_inclusion();
    let timestamp = verify_timestamp(
        &proof.anchor.timestamp_token,
        proof.anchor.statement().as_bytes(),
        trust,
    );
    let trail = trail.map(|t| proof.check_trail(t, &TrailOptions::default()));
    Ok(AnchorVerification {
        proof,
        inclusion,
        timestamp,
        trail,
    })
}
