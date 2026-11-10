//! Checking a signature made over DER bytes (a certificate's `tbsCertificate`) with a
//! public key and an `AlgorithmIdentifier`.
//!
//! Provenance: adapted from `casual-sign-crypto/src/signature.rs` (this repository,
//! Apache-2.0, stage 1F), whose equivalent is `pub(crate)`. Chain building needs it and
//! the crypto crate is not ours to change in stage 1H; the accessor it should export is
//! listed in the T-1H report, after which this module is deleted. Primitives come from the
//! RustCrypto crates ADR-006 names; nothing is implemented here.

use casual_sign_crypto::{CryptoError, DigestAlgorithm, MAX_RSA_BITS, MIN_RSA_VERIFY_BITS, oid};
use der::Sequence;
use der::asn1::ObjectIdentifier;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

/// `RSASSA-PSS-params` (RFC 4055 §3.1).
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
struct PssParams {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    hash: Option<AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    mask_gen: Option<AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    salt_len: Option<u32>,
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    trailer: Option<u32>,
}

/// How to check one signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Scheme {
    Ecdsa(DigestAlgorithm),
    RsaPkcs1(DigestAlgorithm),
    RsaPss {
        hash: DigestAlgorithm,
        salt_len: usize,
    },
}

impl Scheme {
    const fn digest_algorithm(self) -> DigestAlgorithm {
        match self {
            Self::Ecdsa(d) | Self::RsaPkcs1(d) | Self::RsaPss { hash: d, .. } => d,
        }
    }

    /// From a signature `AlgorithmIdentifier`. SHA-1 schemes are unsupported (docs/31 §8).
    pub(crate) fn from_algorithm_identifier(
        alg: &AlgorithmIdentifierOwned,
        digest_hint: Option<DigestAlgorithm>,
    ) -> Result<Self, CryptoError> {
        let params_absent_or_null = alg.parameters.as_ref().is_none_or(|p| p.is_null());
        let id = alg.oid;
        let ecdsa = [
            (oid::ECDSA_WITH_SHA256, DigestAlgorithm::Sha256),
            (oid::ECDSA_WITH_SHA384, DigestAlgorithm::Sha384),
            (oid::ECDSA_WITH_SHA512, DigestAlgorithm::Sha512),
        ];
        if let Some((_, d)) = ecdsa.iter().find(|(o, _)| *o == id) {
            return if alg.parameters.is_none() {
                Ok(Self::Ecdsa(*d))
            } else {
                Err(CryptoError::UnsupportedAlgorithm)
            };
        }
        let pkcs1 = [
            (oid::SHA256_WITH_RSA, DigestAlgorithm::Sha256),
            (oid::SHA384_WITH_RSA, DigestAlgorithm::Sha384),
            (oid::SHA512_WITH_RSA, DigestAlgorithm::Sha512),
        ];
        if let Some((_, d)) = pkcs1.iter().find(|(o, _)| *o == id) {
            return if params_absent_or_null {
                Ok(Self::RsaPkcs1(*d))
            } else {
                Err(CryptoError::UnsupportedAlgorithm)
            };
        }
        if id == oid::RSA_ENCRYPTION && params_absent_or_null {
            return digest_hint
                .map(Self::RsaPkcs1)
                .ok_or(CryptoError::UnsupportedAlgorithm);
        }
        if id == oid::RSASSA_PSS {
            let params: PssParams = alg
                .parameters
                .as_ref()
                .ok_or(CryptoError::UnsupportedAlgorithm)?
                .decode_as()
                .map_err(|_| CryptoError::UnsupportedAlgorithm)?;
            let hash_id = params
                .hash
                .as_ref()
                .ok_or(CryptoError::UnsupportedAlgorithm)?;
            let hash =
                DigestAlgorithm::from_oid(&hash_id.oid).ok_or(CryptoError::UnsupportedAlgorithm)?;
            let mgf = params.mask_gen.ok_or(CryptoError::UnsupportedAlgorithm)?;
            let mgf_hash: AlgorithmIdentifierOwned = mgf
                .parameters
                .as_ref()
                .ok_or(CryptoError::UnsupportedAlgorithm)?
                .decode_as()
                .map_err(|_| CryptoError::UnsupportedAlgorithm)?;
            if mgf.oid != oid::MGF1
                || DigestAlgorithm::from_oid(&mgf_hash.oid) != Some(hash)
                || params.trailer.is_some_and(|t| t != 1)
            {
                return Err(CryptoError::UnsupportedAlgorithm);
            }
            let salt_len = usize::try_from(params.salt_len.unwrap_or(20))
                .map_err(|_| CryptoError::UnsupportedAlgorithm)?;
            return Ok(Self::RsaPss { hash, salt_len });
        }
        Err(CryptoError::UnsupportedAlgorithm)
    }
}

enum PublicKey<'a> {
    P256(&'a [u8]),
    P384(&'a [u8]),
    Rsa(&'a [u8]),
}

fn classify(spki: &SubjectPublicKeyInfoOwned) -> Result<PublicKey<'_>, CryptoError> {
    let key = spki
        .subject_public_key
        .as_bytes()
        .ok_or(CryptoError::UnsupportedAlgorithm)?;
    if spki.algorithm.oid == oid::ID_EC_PUBLIC_KEY {
        let curve: ObjectIdentifier = spki
            .algorithm
            .parameters
            .as_ref()
            .ok_or(CryptoError::UnsupportedAlgorithm)?
            .decode_as()
            .map_err(|_| CryptoError::UnsupportedAlgorithm)?;
        return if curve == oid::SECP256R1 {
            Ok(PublicKey::P256(key))
        } else if curve == oid::SECP384R1 {
            Ok(PublicKey::P384(key))
        } else {
            Err(CryptoError::UnsupportedAlgorithm)
        };
    }
    if spki.algorithm.oid == oid::RSA_ENCRYPTION {
        return Ok(PublicKey::Rsa(key));
    }
    Err(CryptoError::UnsupportedAlgorithm)
}

/// Verify `signature` over `message` with the key in `spki` under `alg`.
///
/// # Errors
/// [`CryptoError::SignatureInvalid`] when it does not verify;
/// [`CryptoError::UnsupportedAlgorithm`] for a key or scheme outside docs/31 §8.
pub(crate) fn verify(
    spki: &SubjectPublicKeyInfoOwned,
    alg: &AlgorithmIdentifierOwned,
    digest_hint: Option<DigestAlgorithm>,
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;

    let scheme = Scheme::from_algorithm_identifier(alg, digest_hint)?;
    let prehash = scheme.digest_algorithm().digest(message);
    match (classify(spki)?, scheme) {
        (PublicKey::P256(k), Scheme::Ecdsa(_)) => {
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(k)
                .map_err(|_| CryptoError::SignatureInvalid)?;
            let sig = p256::ecdsa::Signature::from_der(signature)
                .map_err(|_| CryptoError::SignatureInvalid)?;
            key.verify_prehash(prehash.as_bytes(), &sig)
                .map_err(|_| CryptoError::SignatureInvalid)
        }
        (PublicKey::P384(k), Scheme::Ecdsa(_)) => {
            let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(k)
                .map_err(|_| CryptoError::SignatureInvalid)?;
            let sig = p384::ecdsa::Signature::from_der(signature)
                .map_err(|_| CryptoError::SignatureInvalid)?;
            key.verify_prehash(prehash.as_bytes(), &sig)
                .map_err(|_| CryptoError::SignatureInvalid)
        }
        (PublicKey::Rsa(k), Scheme::RsaPkcs1(_) | Scheme::RsaPss { .. }) => {
            rsa_verify(k, scheme, prehash.as_bytes(), signature)
        }
        _ => Err(CryptoError::UnsupportedAlgorithm),
    }
}

#[cfg(feature = "rsa")]
fn rsa_verify(
    pkcs1_key: &[u8],
    scheme: Scheme,
    prehash: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::signature::hazmat::PrehashVerifier;
    use rsa::traits::PublicKeyParts;
    use sha2::{Sha256, Sha384, Sha512};

    let key =
        rsa::PublicKey::from_pkcs1_der(pkcs1_key).map_err(|_| CryptoError::UnsupportedAlgorithm)?;
    let bits = key.size().saturating_mul(8);
    if !(MIN_RSA_VERIFY_BITS..=MAX_RSA_BITS).contains(&bits) {
        return Err(CryptoError::UnsupportedAlgorithm);
    }
    let bad = |_| CryptoError::SignatureInvalid;
    match scheme {
        Scheme::RsaPkcs1(d) => {
            let sig = rsa::pkcs1v15::Signature::try_from(signature).map_err(bad)?;
            match d {
                DigestAlgorithm::Sha256 => {
                    rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key).verify_prehash(prehash, &sig)
                }
                DigestAlgorithm::Sha384 => {
                    rsa::pkcs1v15::VerifyingKey::<Sha384>::new(key).verify_prehash(prehash, &sig)
                }
                DigestAlgorithm::Sha512 => {
                    rsa::pkcs1v15::VerifyingKey::<Sha512>::new(key).verify_prehash(prehash, &sig)
                }
            }
            .map_err(bad)
        }
        Scheme::RsaPss { hash, salt_len } => {
            let sig = rsa::pss::Signature::try_from(signature).map_err(bad)?;
            match hash {
                DigestAlgorithm::Sha256 => {
                    rsa::pss::VerifyingKey::<Sha256>::new_with_salt_len(key, salt_len)
                        .verify_prehash(prehash, &sig)
                }
                DigestAlgorithm::Sha384 => {
                    rsa::pss::VerifyingKey::<Sha384>::new_with_salt_len(key, salt_len)
                        .verify_prehash(prehash, &sig)
                }
                DigestAlgorithm::Sha512 => {
                    rsa::pss::VerifyingKey::<Sha512>::new_with_salt_len(key, salt_len)
                        .verify_prehash(prehash, &sig)
                }
            }
            .map_err(bad)
        }
        Scheme::Ecdsa(_) => Err(CryptoError::UnsupportedAlgorithm),
    }
}

#[cfg(not(feature = "rsa"))]
fn rsa_verify(_: &[u8], _: Scheme, _: &[u8], _: &[u8]) -> Result<(), CryptoError> {
    Err(CryptoError::UnsupportedAlgorithm)
}
