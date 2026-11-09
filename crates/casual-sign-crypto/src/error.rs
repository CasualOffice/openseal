//! Typed errors with stable docs/20 codes. Messages name the check that failed and never
//! carry document bytes, key material, names or serial numbers.

use core::fmt;

/// The structure an error is about, so a caller can tell a bad CMS from a bad CRL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Structure {
    /// CMS `ContentInfo` / `SignedData` (RFC 5652).
    Cms,
    /// An X.509 certificate supplied by the caller or embedded in a structure.
    Certificate,
    /// An RFC 3161 `TimeStampResp`.
    TimestampResponse,
    /// An RFC 3161 `TimeStampToken` (CMS `SignedData` over `TSTInfo`).
    TimestampToken,
    /// An RFC 6960 `OCSPResponse`.
    OcspResponse,
    /// An RFC 5280 `CertificateList`.
    Crl,
}

impl Structure {
    const fn name(self) -> &'static str {
        match self {
            Self::Cms => "CMS SignedData",
            Self::Certificate => "certificate",
            Self::TimestampResponse => "timestamp response",
            Self::TimestampToken => "timestamp token",
            Self::OcspResponse => "OCSP response",
            Self::Crl => "CRL",
        }
    }
}

/// A required signed attribute (RFC 5652 §11, RFC 5035).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignedAttribute {
    /// `content-type`.
    ContentType,
    /// `message-digest`.
    MessageDigest,
    /// ESS `signing-certificate-v2`.
    SigningCertificateV2,
}

/// Why an RFC 3161 response or token was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimestampFailure {
    /// `PKIStatus` was neither `granted` nor `grantedWithMods`.
    NotGranted,
    /// The response carried no token.
    NoToken,
    /// The token's content is not `id-ct-TSTInfo`.
    NotTstInfo,
    /// The nonce differs from the request's, or is missing.
    NonceMismatch,
    /// The message imprint (algorithm or hash) differs from what was asked.
    ImprintMismatch,
    /// The TSA certificate lacks a critical `id-kp-timeStamping` extended key usage.
    NotTimestampingCertificate,
    /// The token's `message-digest` does not match its `TSTInfo`.
    TokenDigest,
    /// The token's ESS `signing-certificate-v2` does not name the TSA certificate.
    SigningCertificate,
    /// The token's CMS signature does not verify, or its signer or attributes are wrong.
    Signature,
}

/// Why OCSP or CRL data cannot answer the question asked of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RevocationFailure {
    /// OCSP `responseStatus` was not `successful`.
    NotSuccessful,
    /// Not an `id-pkix-ocsp-basic` response.
    NotBasic,
    /// The response or CRL is not signed by the issuer or by a responder it authorized.
    UnauthorizedSigner,
    /// The response or CRL does not cover the certificate asked about.
    NotCovered,
    /// The asked time is outside what the response or CRL speaks for.
    OutOfPeriod,
    /// A critical CRL extension this crate does not process (indirect or delta CRLs).
    UnsupportedCriticalExtension,
}

/// Every failure of this crate. [`CryptoError::code`] gives the stable docs/20 code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    /// The DER did not decode as the structure, or had trailing bytes other than zero padding.
    Malformed(Structure),
    /// The input is larger than this crate's bound for the structure.
    TooLarge(Structure),
    /// An algorithm, curve, key size or parameter set this crate does not accept.
    UnsupportedAlgorithm,
    /// A byte range lies outside the data it is said to cover.
    RangeOutOfBounds,
    /// The `message-digest` attribute differs from the digest of the content.
    DigestMismatch,
    /// The signature does not verify with the signer's public key.
    SignatureInvalid,
    /// A required signed attribute is absent or appears more than once.
    MissingSignedAttribute(SignedAttribute),
    /// The `content-type` attribute differs from the encapsulated content type.
    ContentTypeMismatch,
    /// The SignedData does not have exactly one SignerInfo.
    SignerCount,
    /// No certificate in the structure matches the signer identifier.
    SignerCertificateNotFound,
    /// ESS `signing-certificate-v2` does not identify the signer certificate.
    SigningCertificateMismatch,
    /// The key provider failed or refused.
    KeyProvider(KeyError),
    /// Our own output could not be encoded as DER.
    Encoding,
    /// A TSA response checked at sealing time was refused.
    TimestampResponse(TimestampFailure),
    /// An embedded timestamp token was refused at verification time.
    TimestampToken(TimestampFailure),
    /// OCSP or CRL data is unusable for the question asked.
    Revocation(RevocationFailure),
    /// The certificate was revoked at the time asked about.
    Revoked,
}

impl CryptoError {
    /// The stable docs/20 code.
    ///
    /// Mapping notes: a malformed or unverifiable CMS is `CS-VER-0003`; an unsupported
    /// algorithm is `CS-SEAL-0005`; unusable revocation data is `CS-SEAL-0004`; a TSA
    /// response refused while sealing is `CS-SEAL-0002`, an embedded token refused while
    /// verifying `CS-VER-0006`.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Malformed(s) | Self::TooLarge(s) => match s {
                Structure::Cms | Structure::Certificate => "CS-VER-0003",
                Structure::TimestampResponse => "CS-SEAL-0002",
                Structure::TimestampToken => "CS-VER-0006",
                Structure::OcspResponse | Structure::Crl => "CS-SEAL-0004",
            },
            Self::UnsupportedAlgorithm => "CS-SEAL-0005",
            Self::RangeOutOfBounds => "CS-VER-0001",
            Self::DigestMismatch => "CS-VER-0002",
            Self::SignatureInvalid
            | Self::MissingSignedAttribute(_)
            | Self::ContentTypeMismatch
            | Self::SignerCount
            | Self::SignerCertificateNotFound
            | Self::SigningCertificateMismatch => "CS-VER-0003",
            Self::KeyProvider(_) => "CS-SEAL-0001",
            Self::Encoding => "CS-SEAL-0010",
            Self::TimestampResponse(_) => "CS-SEAL-0002",
            Self::TimestampToken(_) => "CS-VER-0006",
            Self::Revocation(_) => "CS-SEAL-0004",
            Self::Revoked => "CS-VER-0005",
        }
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            Self::Malformed(s) => write!(f, "{code}: malformed {}", s.name()),
            Self::TooLarge(s) => write!(f, "{code}: {} over its size bound", s.name()),
            Self::UnsupportedAlgorithm => write!(f, "{code}: unsupported algorithm or key"),
            Self::RangeOutOfBounds => write!(f, "{code}: byte range outside the data"),
            Self::DigestMismatch => write!(f, "{code}: message digest mismatch"),
            Self::SignatureInvalid => write!(f, "{code}: signature does not verify"),
            Self::MissingSignedAttribute(a) => {
                write!(f, "{code}: signed attribute missing or repeated: {a:?}")
            }
            Self::ContentTypeMismatch => write!(f, "{code}: content-type attribute mismatch"),
            Self::SignerCount => write!(f, "{code}: not exactly one SignerInfo"),
            Self::SignerCertificateNotFound => write!(f, "{code}: signer certificate not found"),
            Self::SigningCertificateMismatch => {
                write!(
                    f,
                    "{code}: signing-certificate-v2 does not match the signer"
                )
            }
            Self::KeyProvider(e) => write!(f, "{code}: key provider: {e}"),
            Self::Encoding => write!(f, "{code}: could not encode our own DER"),
            Self::TimestampResponse(r) => write!(f, "{code}: timestamp response refused: {r:?}"),
            Self::TimestampToken(r) => write!(f, "{code}: timestamp token refused: {r:?}"),
            Self::Revocation(r) => write!(f, "{code}: revocation data unusable: {r:?}"),
            Self::Revoked => write!(f, "{code}: certificate revoked at the time asked"),
        }
    }
}

impl core::error::Error for CryptoError {}

/// What a [`crate::KeyProvider`] reports when it cannot sign. Carries no key material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyError {
    /// The backend (HSM, KMS, `keyd`) is unreachable or failed.
    Unavailable,
    /// The backend refused this request (policy, rate limit, authorization).
    Refused,
    /// The backend returned something that is not a signature of the declared algorithm.
    BadSignature,
}

impl KeyError {
    /// The stable docs/20 code: always `CS-SEAL-0001`.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        "CS-SEAL-0001"
    }
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("unavailable"),
            Self::Refused => f.write_str("refused"),
            Self::BadSignature => f.write_str("returned a malformed signature"),
        }
    }
}

impl core::error::Error for KeyError {}

impl From<KeyError> for CryptoError {
    fn from(e: KeyError) -> Self {
        Self::KeyProvider(e)
    }
}
