//! A detached RFC 3161 token over a digest the caller computed: what public anchoring of
//! audit chain heads needs (docs/32 §5, `FG-158`). The token's signature, imprint and
//! TSA key purpose are checked by `casual-sign-crypto`; this builds the TSA's chain to the
//! caller's anchors and checks it at the token's `genTime`. Revocation of the TSA's chain
//! is not checked here (no revocation data travels with an anchor).

use core::time::Duration;

use casual_sign_crypto::cms::ParsedCms;
use casual_sign_crypto::tsp::verify_timestamp_token;
use casual_sign_crypto::{CryptoError, DigestAlgorithm, DigestValue};

use crate::TrustStore;
use crate::chain::{self, Cert, ChainFailure, Purpose};
use crate::report::{Check, Reason, SubIndication};

const CHAIN: &str = "CS-VER-0004";
const REVOKED_OR_EXPIRED: &str = "CS-VER-0005";
const TIMESTAMP: &str = "CS-VER-0006";
const ALGORITHM: &str = "CS-SEAL-0005";

/// What a token over a digest proves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimestampVerdict {
    /// The token: well formed, signed by its TSA certificate, with the `timeStamping`
    /// purpose, over exactly the digest given.
    pub token: Check,
    /// The TSA certificate's chain to an anchor of the trust store, valid at `genTime`.
    /// [`Check::NotRun`] when the token failed.
    pub chain: Check,
    /// `genTime` since the Unix epoch, when the token passed.
    pub gen_time: Option<Duration>,
    /// SHA-256 of the TSA certificate's DER, when the token passed.
    pub tsa_certificate_sha256: Option<[u8; 32]>,
}

impl TimestampVerdict {
    /// True when the token and its chain both passed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.token.passed() && self.chain.passed()
    }
}

const fn reason(sub: SubIndication, code: &'static str) -> Reason {
    Reason { sub, code }
}

/// Verify `token` (a DER `TimeStampToken`) as a timestamp over the SHA-256 digest
/// `sha256`, its TSA chained to `trust`'s anchors (with its intermediates and the
/// certificates in the token).
///
/// Never panics on any input.
#[must_use]
pub fn verify_timestamp(token: &[u8], sha256: &[u8; 32], trust: &TrustStore) -> TimestampVerdict {
    let failed = |r: Reason| TimestampVerdict {
        token: Check::Failed(r),
        chain: Check::NotRun,
        gen_time: None,
        tsa_certificate_sha256: None,
    };
    let Ok(imprint) = DigestValue::from_bytes(DigestAlgorithm::Sha256, sha256) else {
        return failed(reason(SubIndication::FormatFailure, TIMESTAMP));
    };
    let tst = match verify_timestamp_token(token, &imprint) {
        Ok(t) => t,
        Err(CryptoError::UnsupportedAlgorithm) => {
            return failed(reason(SubIndication::CryptoConstraintsFailure, ALGORITHM));
        }
        Err(_) => return failed(reason(SubIndication::SigConstraintsFailure, TIMESTAMP)),
    };
    let mut pool = trust.intermediates.clone();
    if let Ok(p) = ParsedCms::parse(tst.as_der()) {
        pool.extend(p.certificates().filter_map(Cert::from_parsed));
    }
    let tsa = Cert::from_parsed(tst.tsa_certificate());
    let fingerprint = tsa
        .as_ref()
        .and_then(|c| <[u8; 32]>::try_from(DigestAlgorithm::Sha256.digest(&c.der).as_bytes()).ok());
    let chain = match tsa
        .as_ref()
        .and_then(|c| chain::build(c, &pool, &trust.anchors))
    {
        None => Check::Failed(reason(SubIndication::NoCertificateChainFound, CHAIN)),
        Some(path) => match chain::validate(&path, tst.gen_time(), Purpose::Tsa) {
            Ok(()) => Check::Passed,
            Err(ChainFailure::NoChain) => {
                Check::Failed(reason(SubIndication::NoCertificateChainFound, CHAIN))
            }
            Err(ChainFailure::Constraints) => {
                Check::Failed(reason(SubIndication::ChainConstraintsFailure, CHAIN))
            }
            Err(ChainFailure::OutOfValidity { .. }) => {
                Check::Failed(reason(SubIndication::OutOfBoundsNoPoe, REVOKED_OR_EXPIRED))
            }
        },
    };
    TimestampVerdict {
        token: Check::Passed,
        chain,
        gen_time: Some(tst.gen_time()),
        tsa_certificate_sha256: fingerprint,
    }
}
