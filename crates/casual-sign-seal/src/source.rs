//! The seams through which the host supplies network answers: a TSA and revocation
//! responders. The engine performs no I/O (ADR-004): it builds each request as DER, the
//! host sends it and hands back the DER answer, and the engine checks the answer before
//! embedding it (docs/31 §6, §9).

use core::fmt;

use casual_sign_crypto::Certificate;

/// Why a host source gave no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SourceError {
    /// The service could not be reached or failed (after the host's own failover).
    Unavailable,
    /// The service refused the request.
    Refused,
    /// No such service is configured (for example a B-B seal's [`NoTimestamps`]).
    NotConfigured,
}

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "unavailable",
            Self::Refused => "refused",
            Self::NotConfigured => "not configured",
        })
    }
}

/// An RFC 3161 time-stamping authority, or a list of them with failover (docs/31 §6).
///
/// The engine builds a `TimeStampReq` (with `certReq` true and the nonce from
/// [`TimestampSource::nonce`]) and checks the answer's status, nonce, imprint, CMS
/// signature, ESSCertIDv2 and the TSA key purpose before embedding the token.
pub trait TimestampSource {
    /// An upper bound on the DER length of one `TimeStampToken` from this source (from a
    /// probe of the TSA, cached by the host), used to size placeholders by computation
    /// (docs/31 §4 step 2). An underestimate costs one retry, never a truncation.
    fn token_len_bound(&self) -> usize;

    /// A fresh nonce for the next request: 8 to 32 bytes, not all zero. The engine
    /// samples no randomness (CLAUDE.md), so the host supplies it.
    fn nonce(&self) -> Vec<u8>;

    /// Send the DER `TimeStampReq` and return the DER `TimeStampResp`.
    ///
    /// # Errors
    /// [`SourceError`] when no TSA answered; sealing fails with `CS-SEAL-0002`.
    fn timestamp(&self, request_der: &[u8]) -> Result<Vec<u8>, SourceError>;
}

/// A [`TimestampSource`] for PAdES B-B, which takes no timestamp: every call fails with
/// [`SourceError::NotConfigured`].
#[derive(Debug, Clone, Copy, Default)]
pub struct NoTimestamps;

impl TimestampSource for NoTimestamps {
    fn token_len_bound(&self) -> usize {
        0
    }

    fn nonce(&self) -> Vec<u8> {
        Vec::new()
    }

    fn timestamp(&self, _request_der: &[u8]) -> Result<Vec<u8>, SourceError> {
        Err(SourceError::NotConfigured)
    }
}

/// A question for an OCSP responder about one certificate.
#[derive(Debug, Clone, Copy)]
pub struct OcspQuery<'a> {
    /// The DER `OCSPRequest` (RFC 6960) with a SHA-256 `CertID`, unsigned, no nonce.
    pub request_der: &'a [u8],
    /// The certificate asked about (its AIA names the responder).
    pub certificate: &'a Certificate,
    /// Its issuer.
    pub issuer: &'a Certificate,
}

/// A question for a CRL covering one certificate.
#[derive(Debug, Clone, Copy)]
pub struct CrlQuery<'a> {
    /// The certificate asked about (its CRL distribution points name the CRL).
    pub certificate: &'a Certificate,
    /// Its issuer, which must have signed the CRL (indirect CRLs are refused).
    pub issuer: &'a Certificate,
}

/// OCSP responders and CRL distribution points, reached by the host (docs/31 §4 step 9).
///
/// For each certificate in the signer's and the TSAs' chains (trust anchors excepted) the
/// engine asks [`RevocationSource::ocsp`] first and falls back to
/// [`RevocationSource::crl`] (docs/31 §9). Each answer must show the certificate not
/// revoked at the time asked, or it is not embedded.
pub trait RevocationSource {
    /// The DER `OCSPResponse` to `query`, or `None` when the certificate names no
    /// responder or the responder had no answer.
    ///
    /// # Errors
    /// [`SourceError`] when the host's fetching failed.
    fn ocsp(&self, query: &OcspQuery<'_>) -> Result<Option<Vec<u8>>, SourceError>;

    /// The DER CRL covering `query.certificate`, or `None`.
    ///
    /// # Errors
    /// [`SourceError`] when the host's fetching failed.
    fn crl(&self, query: &CrlQuery<'_>) -> Result<Option<Vec<u8>>, SourceError>;

    /// Issuer certificates the signature does not carry (fetched by the host through
    /// AIA, or configured), for completing chains. Empty by default.
    fn certificates(&self) -> &[Certificate] {
        &[]
    }
}

/// A [`RevocationSource`] with no answers, for B-B and B-T seals.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoRevocation;

impl RevocationSource for NoRevocation {
    fn ocsp(&self, _query: &OcspQuery<'_>) -> Result<Option<Vec<u8>>, SourceError> {
        Ok(None)
    }

    fn crl(&self, _query: &CrlQuery<'_>) -> Result<Option<Vec<u8>>, SourceError> {
        Ok(None)
    }
}
