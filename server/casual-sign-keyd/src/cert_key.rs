//! What the signer certificate says about its key, and the probe that proves a backend's
//! key is that certificate's: sign a fixed message's digest through the backend and
//! verify it against the certificate's public key with aws-lc-rs. A key that is not the
//! certificate's would otherwise be found only by the seal's self-check, per seal.

use aws_lc_rs::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use casual_sign_crypto::{Certificate, SignatureAlgorithm};
use der::Decode;
use der::asn1::{ObjectIdentifier, UintRef};

use crate::error::{KeyConfigProblem, KeydError};
use crate::signer::{DigestSigner, digest_for};

const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// Smallest RSA modulus keyd signs with (docs/31 §4: RSA 3072 or more for our seals).
pub const MIN_RSA_SIGN_BITS: usize = 3072;

/// The key family of a signer certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CertKey {
    /// ECDSA P-256.
    P256,
    /// ECDSA P-384.
    P384,
    /// RSA with a modulus of this many bits.
    Rsa(usize),
}

#[derive(der::Sequence)]
struct RsaPublicKey<'a> {
    modulus: UintRef<'a>,
    exponent: UintRef<'a>,
}

fn unsupported() -> KeydError {
    KeydError::KeyConfig(KeyConfigProblem::UnsupportedAlgorithm)
}

/// The key family `cert` certifies.
pub(crate) fn cert_key(cert: &Certificate) -> Result<CertKey, KeydError> {
    let spki = cert.tbs_certificate().subject_public_key_info();
    if spki.algorithm.oid == EC_PUBLIC_KEY {
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
        match curve {
            Some(c) if c == P256 => Ok(CertKey::P256),
            Some(c) if c == P384 => Ok(CertKey::P384),
            _ => Err(unsupported()),
        }
    } else if spki.algorithm.oid == RSA {
        let key = RsaPublicKey::from_der(spki.subject_public_key.raw_bytes())
            .map_err(|_| KeydError::KeyConfig(KeyConfigProblem::BadCertificate))?;
        let bytes = key.modulus.as_bytes();
        let top = bytes.first().copied().unwrap_or(0);
        let bits = bytes
            .len()
            .saturating_mul(8)
            .saturating_sub(top.leading_zeros() as usize);
        Ok(CertKey::Rsa(bits))
    } else {
        Err(unsupported())
    }
}

/// The algorithm a key of `cert` signs with: fixed by the curve for ECDSA; for RSA,
/// `rsa_algorithm` (PKCS#1 v1.5 SHA-256 when `None`) with a modulus of 3072 to 8192 bits.
///
/// # Errors
/// `CS-KEY-0006` for any other key, size or scheme.
pub fn algorithm_for(
    cert: &Certificate,
    rsa_algorithm: Option<SignatureAlgorithm>,
) -> Result<SignatureAlgorithm, KeydError> {
    match cert_key(cert)? {
        CertKey::P256 => Ok(SignatureAlgorithm::EcdsaP256Sha256),
        CertKey::P384 => Ok(SignatureAlgorithm::EcdsaP384Sha384),
        CertKey::Rsa(bits) => {
            if !(MIN_RSA_SIGN_BITS..=casual_sign_crypto::MAX_RSA_BITS).contains(&bits) {
                return Err(unsupported());
            }
            let alg = rsa_algorithm.unwrap_or(SignatureAlgorithm::RsaPkcs1Sha256);
            if crate::signer::is_ecdsa(alg) || crate::signer::wire_id(alg).is_none() {
                return Err(unsupported());
            }
            Ok(alg)
        }
    }
}

fn verification(alg: SignatureAlgorithm) -> Option<&'static dyn VerificationAlgorithm> {
    Some(match alg {
        SignatureAlgorithm::EcdsaP256Sha256 => &signature::ECDSA_P256_SHA256_ASN1,
        SignatureAlgorithm::EcdsaP384Sha384 => &signature::ECDSA_P384_SHA384_ASN1,
        SignatureAlgorithm::RsaPkcs1Sha256 => &signature::RSA_PKCS1_2048_8192_SHA256,
        SignatureAlgorithm::RsaPkcs1Sha384 => &signature::RSA_PKCS1_2048_8192_SHA384,
        SignatureAlgorithm::RsaPkcs1Sha512 => &signature::RSA_PKCS1_2048_8192_SHA512,
        SignatureAlgorithm::RsaPssSha256 => &signature::RSA_PSS_2048_8192_SHA256,
        SignatureAlgorithm::RsaPssSha384 => &signature::RSA_PSS_2048_8192_SHA384,
        SignatureAlgorithm::RsaPssSha512 => &signature::RSA_PSS_2048_8192_SHA512,
        _ => return None,
    })
}

/// The fixed message the probe signs; it is not a CMS structure, so a probe signature
/// can never be mistaken for a seal.
const PROBE: &[u8] = b"OpenSeal keyd key-certificate probe";

/// Sign the probe's digest through `signer` and verify it against the signer
/// certificate's public key.
///
/// # Errors
/// `CS-KEY-0006` (`KeyCertificateMismatch`) when it does not verify; the backend's own
/// error when it cannot sign.
pub fn probe(signer: &dyn DigestSigner) -> Result<(), KeydError> {
    let cert = signer
        .certificate_chain()
        .first()
        .ok_or(KeydError::KeyConfig(KeyConfigProblem::NoCertificate))?;
    let alg = signer.algorithm();
    let verify = verification(alg).ok_or_else(unsupported)?;
    let sig = signer.sign_digest(&digest_for(alg, PROBE))?;
    let public = cert
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes();
    UnparsedPublicKey::new(verify, public)
        .verify(PROBE, &sig)
        .map_err(|_| KeydError::KeyConfig(KeyConfigProblem::KeyCertificateMismatch))
}
