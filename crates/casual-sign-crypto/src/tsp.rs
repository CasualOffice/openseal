//! RFC 3161 timestamps (docs/31 §6): build a `TimeStampReq`, check a `TimeStampResp`
//! (status, nonce, message imprint, the TSA's CMS signature, ESSCertIDv2 per RFC 5816,
//! the TSA certificate's `timeStamping` key purpose). No network: the host sends the
//! request and hands back the answer. Building the TSA chain to a trust anchor is the
//! verifier's job (docs/31 §7), not this module's.

use core::time::Duration;

use der::Decode;
use der::asn1::{Int, OctetString};
use x509_cert::Certificate;
use x509_cert::ext::pkix::ExtendedKeyUsage;
use x509_tsp::cmpv2::status::PkiStatus;
use x509_tsp::{MessageImprint, TimeStampReq, TimeStampResp, TspVersion, TstInfo};

use crate::cms::ParsedCms;
use crate::der_walk;
use crate::digest::{DigestAlgorithm, DigestValue};
use crate::error::{CryptoError, Structure, TimestampFailure};
use crate::oid;
use crate::signature::to_der;

/// Largest `TimeStampResp` parsed (the token is a CMS, bounded the same way).
pub const MAX_TSP_RESPONSE_LEN: usize = crate::cms::MAX_CMS_LEN;
/// Longest nonce accepted, in bytes (RFC 3161 suggests 64 bits; 32 bytes is ample).
pub const MAX_NONCE_LEN: usize = 32;

/// A `TimeStampReq` with `certReq` true and a caller-supplied nonce (the engine samples
/// no randomness, ADR-004).
#[derive(Clone, Debug)]
pub struct TimestampRequest {
    imprint: DigestValue,
    nonce: Int,
    der: Vec<u8>,
}

impl TimestampRequest {
    /// A request for `imprint` (for PAdES B-T, the digest of the signature value) with
    /// `nonce` read as an unsigned big-endian integer.
    ///
    /// # Errors
    /// [`CryptoError::UnsupportedAlgorithm`] for an empty, all-zero or over-long nonce;
    /// [`CryptoError::Encoding`] if DER cannot be produced.
    pub fn new(imprint: &DigestValue, nonce: &[u8]) -> Result<Self, CryptoError> {
        let trimmed = match nonce.iter().position(|&b| b != 0) {
            Some(i) => nonce.get(i..).unwrap_or_default(),
            None => return Err(CryptoError::UnsupportedAlgorithm),
        };
        if trimmed.len() > MAX_NONCE_LEN {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        let mut bytes = Vec::with_capacity(trimmed.len().saturating_add(1));
        if trimmed.first().is_some_and(|&b| b & 0x80 != 0) {
            bytes.push(0);
        }
        bytes.extend_from_slice(trimmed);
        let nonce = Int::new(&bytes).map_err(|_| CryptoError::Encoding)?;
        let req = TimeStampReq {
            version: TspVersion::V1,
            message_imprint: message_imprint(imprint)?,
            req_policy: None,
            nonce: Some(nonce.clone()),
            cert_req: true,
            extensions: None,
        };
        Ok(Self {
            imprint: imprint.clone(),
            nonce,
            der: to_der(&req)?,
        })
    }

    /// The DER request to send to the TSA.
    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }
}

fn message_imprint(d: &DigestValue) -> Result<MessageImprint, CryptoError> {
    let id = d.algorithm().algorithm_identifier();
    Ok(MessageImprint {
        hash_algorithm: x509_cert::spki::AlgorithmIdentifier {
            oid: id.oid,
            parameters: None,
        },
        hashed_message: OctetString::new(d.as_bytes()).map_err(|_| CryptoError::Encoding)?,
    })
}

/// A verified timestamp token.
#[derive(Clone, Debug)]
pub struct TimestampToken {
    der: Vec<u8>,
    gen_time: Duration,
    tsa_certificate: Certificate,
}

impl TimestampToken {
    /// The whole `TimeStampToken` (a CMS `ContentInfo`), to embed as the
    /// `signature-time-stamp` unsigned attribute.
    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }

    /// `genTime` as time since the Unix epoch.
    #[must_use]
    pub const fn gen_time(&self) -> Duration {
        self.gen_time
    }

    /// The TSA certificate that signed the token; the caller builds its chain.
    #[must_use]
    pub const fn tsa_certificate(&self) -> &Certificate {
        &self.tsa_certificate
    }
}

/// Check a TSA's answer to `request` at sealing time (docs/31 §6).
///
/// # Errors
/// [`CryptoError::TimestampResponse`] (`CS-SEAL-0002`) naming the failed check, or
/// [`CryptoError::UnsupportedAlgorithm`] for an algorithm outside docs/31 §8.
pub fn verify_timestamp_response(
    response: &[u8],
    request: &TimestampRequest,
) -> Result<TimestampToken, CryptoError> {
    if response.len() > MAX_TSP_RESPONSE_LEN {
        return Err(CryptoError::TooLarge(Structure::TimestampResponse));
    }
    let tlv = der_walk::single_tlv(response)
        .ok_or(CryptoError::Malformed(Structure::TimestampResponse))?;
    let resp = TimeStampResp::from_der(tlv)
        .map_err(|_| CryptoError::Malformed(Structure::TimestampResponse))?;
    if !matches!(
        resp.status.status,
        PkiStatus::Accepted | PkiStatus::GrantedWithMods
    ) {
        return Err(CryptoError::TimestampResponse(TimestampFailure::NotGranted));
    }
    // The token's raw bytes: the second element of the response SEQUENCE.
    let token_der = der_walk::children(tlv)
        .and_then(|c| c.get(1).copied())
        .ok_or(CryptoError::TimestampResponse(TimestampFailure::NoToken))?;
    check_token(token_der, &request.imprint, Some(&request.nonce)).map_err(|e| match e {
        CryptoError::TimestampToken(f) => CryptoError::TimestampResponse(f),
        CryptoError::Malformed(Structure::TimestampToken | Structure::Cms) => {
            CryptoError::Malformed(Structure::TimestampResponse)
        }
        CryptoError::TooLarge(_) => CryptoError::TooLarge(Structure::TimestampResponse),
        CryptoError::UnsupportedAlgorithm => e,
        other => CryptoError::TimestampResponse(cms_failure(other)),
    })
}

/// Check a token embedded in a signature (docs/31 §7) against the imprint the verifier
/// computed (for PAdES B-T, the digest of the signature value). No nonce: it is not kept.
///
/// # Errors
/// [`CryptoError::TimestampToken`] (`CS-VER-0006`) naming the failed check, or
/// [`CryptoError::UnsupportedAlgorithm`].
pub fn verify_timestamp_token(
    token: &[u8],
    imprint: &DigestValue,
) -> Result<TimestampToken, CryptoError> {
    let tlv =
        der_walk::single_tlv(token).ok_or(CryptoError::Malformed(Structure::TimestampToken))?;
    check_token(tlv, imprint, None)
}

/// How a CMS-level failure inside a token is reported.
fn cms_failure(e: CryptoError) -> TimestampFailure {
    match e {
        CryptoError::DigestMismatch => TimestampFailure::TokenDigest,
        CryptoError::SigningCertificateMismatch => TimestampFailure::SigningCertificate,
        _ => TimestampFailure::Signature,
    }
}

fn check_token(
    token_der: &[u8],
    imprint: &DigestValue,
    nonce: Option<&Int>,
) -> Result<TimestampToken, CryptoError> {
    let fail = CryptoError::TimestampToken;
    let cms = ParsedCms::parse_as(token_der, Structure::TimestampToken)?;
    let (ty, content) = cms.encapsulated();
    if ty != oid::ID_CT_TST_INFO {
        return Err(fail(TimestampFailure::NotTstInfo));
    }
    let econtent = content.ok_or(fail(TimestampFailure::NotTstInfo))?;
    let tst_bytes: OctetString = econtent
        .decode_as()
        .map_err(|_| CryptoError::Malformed(Structure::TimestampToken))?;
    let tst = TstInfo::from_der(tst_bytes.as_bytes())
        .map_err(|_| CryptoError::Malformed(Structure::TimestampToken))?;

    let alg = DigestAlgorithm::from_oid(&tst.message_imprint.hash_algorithm.oid)
        .ok_or(fail(TimestampFailure::ImprintMismatch))?;
    if alg != imprint.algorithm()
        || tst.message_imprint.hashed_message.as_bytes() != imprint.as_bytes()
    {
        return Err(fail(TimestampFailure::ImprintMismatch));
    }
    if let Some(expected) = nonce
        && tst.nonce.as_ref() != Some(expected)
    {
        return Err(fail(TimestampFailure::NonceMismatch));
    }

    let content_digest = cms.digest_algorithm().digest(tst_bytes.as_bytes());
    let signer = cms
        .verify_signer(oid::ID_CT_TST_INFO, &content_digest)
        .map_err(|e| match e {
            CryptoError::UnsupportedAlgorithm => e,
            CryptoError::Malformed(_) => CryptoError::Malformed(Structure::TimestampToken),
            other => fail(cms_failure(other)),
        })?;

    let eku_ok = matches!(
        signer.certificate.tbs_certificate().get_extension::<ExtendedKeyUsage>(),
        Ok(Some((true, eku))) if eku.0.contains(&oid::KP_TIME_STAMPING)
    );
    if !eku_ok {
        return Err(fail(TimestampFailure::NotTimestampingCertificate));
    }
    Ok(TimestampToken {
        der: token_der.to_vec(),
        gen_time: tst.gen_time.to_unix_duration(),
        tsa_certificate: signer.certificate,
    })
}
