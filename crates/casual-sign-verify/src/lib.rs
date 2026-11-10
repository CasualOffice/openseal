//! Verifies any signed PDF, OpenSeal's or not (docs/31 §7): ByteRange coverage, digests,
//! CMS signatures, certificate chains to a supplied trust store at the signing time,
//! revocation, timestamps, and a classification of every revision after each signature.
//! The same code runs in the server, the browser (WASM) and the CLI.
//!
//! [`verify`] takes the file's bytes, a [`TrustStore`] and [`VerifyOptions`], and returns
//! a [`VerificationReport`]. It performs no I/O, reads no clock and fetches nothing: the
//! validation time and any revocation answers are supplied (ADR-004). The verdict for each
//! signature uses the vocabulary of ETSI EN 319 102-1 ([`Indication`], [`SubIndication`]);
//! each [`Reason`] carries a docs/20 code.
//!
//! What is checked, per signature (a `/Sig` value or a `/DocTimeStamp`):
//!
//! - `/ByteRange` is `[0 b c d]`, its single gap is exactly this dictionary's `/Contents`
//!   hex string, nothing lies outside the file, and `c + d` ends a revision (SEC-S02);
//! - the digest of those bytes, then the CMS (via `casual-sign-crypto`, signed attributes
//!   hashed as received) for `ETSI.CAdES.detached` and `adbe.pkcs7.detached`, or the RFC
//!   3161 token for `ETSI.RFC3161`;
//! - the signature timestamp (unsigned attribute), whose `genTime` becomes the signing
//!   time; a later verified document timestamp is also a proof of existence;
//! - the signer's and every TSA's chain to a supplied anchor, valid at the time each must
//!   be valid, with basic constraints, key usage and the TSA key purpose;
//! - revocation of every certificate in those chains from the document's `/DSS` or the
//!   supplied answers, the OCSP responder included;
//! - every revision after the signed one, classified by a whitelist (DSS, document
//!   timestamp, metadata, new signatures and form filling where DocMDP and FieldMDP allow,
//!   annotations where DocMDP allows) so that shadow and incremental-saving attacks show as
//!   a disallowed modification (SEC-S01).

mod byterange;
mod certsig;
mod chain;
mod diff;
mod report;
mod revocation;
mod verify;

use core::time::Duration;

pub use casual_sign_crypto::CryptoError;
pub use casual_sign_pdf::Limits;
pub use report::{
    Check, Checks, Disallowed, DocumentError, Indication, ModificationClass, Reason,
    RevisionChanges, SignatureKind, SignatureReport, SubIndication, TimeSource, TimestampInfo,
    VerificationReport,
};

/// The certificates the caller trusts, and intermediates it supplies for path building.
/// No root is built in: an empty store makes every signature at best
/// [`SubIndication::NoCertificateChainFound`], while integrity is still checked.
#[derive(Clone, Debug, Default)]
pub struct TrustStore {
    anchors: Vec<chain::Cert>,
    intermediates: Vec<chain::Cert>,
}

impl TrustStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Trust the DER certificate `der` as an anchor.
    ///
    /// # Errors
    /// [`CryptoError::Malformed`] (`CS-VER-0003`) when it is not a DER certificate.
    pub fn add_anchor(&mut self, der: &[u8]) -> Result<(), CryptoError> {
        self.anchors.push(chain::parse(der)?);
        Ok(())
    }

    /// Offer the DER certificate `der` for path building (not trusted by itself).
    ///
    /// # Errors
    /// [`CryptoError::Malformed`] (`CS-VER-0003`) when it is not a DER certificate.
    pub fn add_intermediate(&mut self, der: &[u8]) -> Result<(), CryptoError> {
        self.intermediates.push(chain::parse(der)?);
        Ok(())
    }

    /// Number of anchors.
    #[must_use]
    pub fn anchor_count(&self) -> usize {
        self.anchors.len()
    }
}

/// Which time certificates are checked at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TimePolicy {
    /// ETSI EN 319 102-1 with proofs of existence (the default): a signature is checked at
    /// the earliest time a verified timestamp proves it existed (its own signature
    /// timestamp, or a later document timestamp), else at the validation time.
    #[default]
    ProofOfExistence,
    /// Everything at the validation time; timestamps are verified but prove nothing.
    ValidationTime,
}

/// What the caller supplies besides the document: the time, and revocation answers it has
/// fetched or stored.
#[derive(Clone, Debug)]
pub struct VerifyOptions {
    /// The validation time, since the Unix epoch. Supplied, never read from a clock.
    pub validation_time: Duration,
    /// How signing time is decided.
    pub time_policy: TimePolicy,
    /// DER OCSP responses (RFC 6960) to use besides the document's DSS.
    pub ocsp_responses: Vec<Vec<u8>>,
    /// DER CRLs (RFC 5280) to use besides the document's DSS.
    pub crls: Vec<Vec<u8>>,
    /// Reader limits (docs/21).
    pub limits: Limits,
}

impl VerifyOptions {
    /// Defaults at `validation_time`: proof-of-existence policy, no supplied revocation
    /// data, docs/21 limits.
    #[must_use]
    pub fn at(validation_time: Duration) -> Self {
        Self {
            validation_time,
            time_policy: TimePolicy::default(),
            ocsp_responses: Vec::new(),
            crls: Vec::new(),
            limits: Limits::default(),
        }
    }
}

/// Verify every signature and document timestamp in the PDF `bytes`.
///
/// Never panics on any input; a file that cannot be read gives a report with
/// [`VerificationReport::error`] set and no signatures.
#[must_use]
pub fn verify(bytes: &[u8], trust: &TrustStore, options: &VerifyOptions) -> VerificationReport {
    verify::run(bytes, trust, options)
}
