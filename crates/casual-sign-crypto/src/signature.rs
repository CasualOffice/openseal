//! Signature algorithms (docs/31 §4: RSA 3072+ PKCS#1 v1.5 and PSS, ECDSA P-256 and
//! P-384) and public-key verification with RustCrypto, which builds for `wasm32`.

use der::asn1::{Any, ObjectIdentifier};
use der::{Decode, Encode, Sequence};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

use crate::digest::DigestAlgorithm;
use crate::error::CryptoError;
use crate::oid;

/// Smallest RSA modulus accepted when **verifying** others' signatures. Our own seals use
/// 3072 bits or more (docs/31 §4); 2048 is still common among TSAs and CAs.
pub const MIN_RSA_VERIFY_BITS: usize = 2048;
/// Largest RSA modulus accepted, bounding the cost of one verification.
pub const MAX_RSA_BITS: usize = 8192;

/// A signature algorithm a [`crate::KeyProvider`] signs with, and the verifier accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// ECDSA over P-256 with SHA-256; signature is a DER `Ecdsa-Sig-Value`.
    EcdsaP256Sha256,
    /// ECDSA over P-384 with SHA-384; signature is a DER `Ecdsa-Sig-Value`.
    EcdsaP384Sha384,
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    RsaPkcs1Sha256,
    /// RSASSA-PKCS1-v1_5 with SHA-384.
    RsaPkcs1Sha384,
    /// RSASSA-PKCS1-v1_5 with SHA-512.
    RsaPkcs1Sha512,
    /// RSASSA-PSS with SHA-256, MGF1-SHA-256, salt 32.
    RsaPssSha256,
    /// RSASSA-PSS with SHA-384, MGF1-SHA-384, salt 48.
    RsaPssSha384,
    /// RSASSA-PSS with SHA-512, MGF1-SHA-512, salt 64.
    RsaPssSha512,
}

impl SignatureAlgorithm {
    /// The digest the signature is computed over; the CMS builder digests the content with
    /// it too, so `digestAlgorithm` and the signature agree (RFC 5652 §5.4).
    #[must_use]
    pub const fn digest_algorithm(self) -> DigestAlgorithm {
        match self {
            Self::EcdsaP256Sha256 | Self::RsaPkcs1Sha256 | Self::RsaPssSha256 => {
                DigestAlgorithm::Sha256
            }
            Self::EcdsaP384Sha384 | Self::RsaPkcs1Sha384 | Self::RsaPssSha384 => {
                DigestAlgorithm::Sha384
            }
            Self::RsaPkcs1Sha512 | Self::RsaPssSha512 => DigestAlgorithm::Sha512,
        }
    }

    /// The `signatureAlgorithm` written into a SignerInfo.
    ///
    /// # Errors
    /// [`CryptoError::Encoding`] if the PSS parameters cannot be encoded (never expected).
    pub fn algorithm_identifier(self) -> Result<AlgorithmIdentifierOwned, CryptoError> {
        let plain = |oid| AlgorithmIdentifierOwned {
            oid,
            parameters: None,
        };
        let rsa = |oid| AlgorithmIdentifierOwned {
            oid,
            parameters: Some(Any::null()),
        };
        Ok(match self {
            Self::EcdsaP256Sha256 => plain(oid::ECDSA_WITH_SHA256),
            Self::EcdsaP384Sha384 => plain(oid::ECDSA_WITH_SHA384),
            Self::RsaPkcs1Sha256 => rsa(oid::SHA256_WITH_RSA),
            Self::RsaPkcs1Sha384 => rsa(oid::SHA384_WITH_RSA),
            Self::RsaPkcs1Sha512 => rsa(oid::SHA512_WITH_RSA),
            Self::RsaPssSha256 | Self::RsaPssSha384 | Self::RsaPssSha512 => {
                let d = self.digest_algorithm();
                let params = PssParams {
                    hash: Some(d.algorithm_identifier()),
                    mask_gen: Some(AlgorithmIdentifierOwned {
                        oid: oid::MGF1,
                        parameters: Some(
                            Any::encode_from(&d.algorithm_identifier())
                                .map_err(|_| CryptoError::Encoding)?,
                        ),
                    }),
                    salt_len: Some(
                        u32::try_from(d.output_len()).map_err(|_| CryptoError::Encoding)?,
                    ),
                    trailer: None,
                };
                AlgorithmIdentifierOwned {
                    oid: oid::RSASSA_PSS,
                    parameters: Some(Any::encode_from(&params).map_err(|_| CryptoError::Encoding)?),
                }
            }
        })
    }

    /// Whether the key is RSA.
    #[must_use]
    pub const fn is_rsa(self) -> bool {
        !matches!(self, Self::EcdsaP256Sha256 | Self::EcdsaP384Sha384)
    }
}

/// `RSASSA-PSS-params` (RFC 4055 §3.1). Absent fields take the SHA-1 defaults, which this
/// crate refuses.
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

/// How to check one signature, decided from an `AlgorithmIdentifier`.
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
    pub(crate) const fn digest_algorithm(self) -> DigestAlgorithm {
        match self {
            Self::Ecdsa(d) | Self::RsaPkcs1(d) | Self::RsaPss { hash: d, .. } => d,
        }
    }

    /// From a signature `AlgorithmIdentifier`. `digest_hint` is the CMS `digestAlgorithm`,
    /// used when a signer wrote plain `rsaEncryption` (RFC 3370 §3.2).
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
            let hash = DigestAlgorithm::from_algorithm_identifier(
                params
                    .hash
                    .as_ref()
                    .ok_or(CryptoError::UnsupportedAlgorithm)?,
            )?;
            let mgf = params.mask_gen.ok_or(CryptoError::UnsupportedAlgorithm)?;
            let mgf_hash: AlgorithmIdentifierOwned = mgf
                .parameters
                .as_ref()
                .ok_or(CryptoError::UnsupportedAlgorithm)?
                .decode_as()
                .map_err(|_| CryptoError::UnsupportedAlgorithm)?;
            if mgf.oid != oid::MGF1
                || DigestAlgorithm::from_algorithm_identifier(&mgf_hash)? != hash
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

/// The public key, classified.
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

/// `RSAPublicKey` (RFC 8017 A.1.1), read only for its modulus length.
#[derive(Sequence)]
struct RsaPublicKeyRef<'a> {
    modulus: der::asn1::UintRef<'a>,
    public_exponent: der::asn1::UintRef<'a>,
}

/// RSA modulus length in bytes for an RSA SPKI; `None` for other keys.
pub(crate) fn rsa_modulus_len(spki: &SubjectPublicKeyInfoOwned) -> Option<usize> {
    match classify(spki).ok()? {
        PublicKey::Rsa(k) => {
            let key = RsaPublicKeyRef::from_der(k).ok()?;
            let _ = key.public_exponent;
            Some(key.modulus.as_bytes().len())
        }
        _ => None,
    }
}

/// Check that a public key can be used with a signature algorithm.
pub(crate) fn key_matches(
    spki: &SubjectPublicKeyInfoOwned,
    alg: SignatureAlgorithm,
) -> Result<(), CryptoError> {
    let ok = matches!(
        (classify(spki)?, alg),
        (PublicKey::P256(_), SignatureAlgorithm::EcdsaP256Sha256)
            | (PublicKey::P384(_), SignatureAlgorithm::EcdsaP384Sha384)
    ) || (alg.is_rsa() && rsa_modulus_len(spki).is_some());
    if ok {
        Ok(())
    } else {
        Err(CryptoError::UnsupportedAlgorithm)
    }
}

/// Verify `signature` over `message` with the key in `spki` under `scheme`.
///
/// # Errors
/// [`CryptoError::SignatureInvalid`] when it does not verify;
/// [`CryptoError::UnsupportedAlgorithm`] for a key or scheme outside docs/31 §4, or RSA
/// without the `rsa` feature.
pub(crate) fn verify(
    spki: &SubjectPublicKeyInfoOwned,
    scheme: Scheme,
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;

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

/// Without the `rsa` feature RSA is unsupported here; hosts verify RSA with aws-lc-rs
/// (ADR-006).
#[cfg(not(feature = "rsa"))]
fn rsa_verify(_: &[u8], _: Scheme, _: &[u8], _: &[u8]) -> Result<(), CryptoError> {
    Err(CryptoError::UnsupportedAlgorithm)
}

/// Encode helper used by the builders.
pub(crate) fn to_der<T: Encode>(value: &T) -> Result<Vec<u8>, CryptoError> {
    value.to_der().map_err(|_| CryptoError::Encoding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pss_parameters_round_trip() {
        for alg in [
            SignatureAlgorithm::RsaPssSha256,
            SignatureAlgorithm::RsaPssSha384,
            SignatureAlgorithm::RsaPssSha512,
        ] {
            let id = alg.algorithm_identifier().unwrap();
            let scheme = Scheme::from_algorithm_identifier(&id, None).unwrap();
            let d = alg.digest_algorithm();
            assert_eq!(
                scheme,
                Scheme::RsaPss {
                    hash: d,
                    salt_len: d.output_len()
                }
            );
        }
    }

    #[test]
    fn sha1_defaults_and_unknown_algorithms_are_refused() {
        let pss_default = AlgorithmIdentifierOwned {
            oid: oid::RSASSA_PSS,
            parameters: Some(
                Any::encode_from(&PssParams {
                    hash: None,
                    mask_gen: None,
                    salt_len: None,
                    trailer: None,
                })
                .unwrap(),
            ),
        };
        assert_eq!(
            Scheme::from_algorithm_identifier(&pss_default, None),
            Err(CryptoError::UnsupportedAlgorithm)
        );
        let sha1_rsa = AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5"),
            parameters: Some(Any::null()),
        };
        assert_eq!(
            Scheme::from_algorithm_identifier(&sha1_rsa, Some(DigestAlgorithm::Sha256)),
            Err(CryptoError::UnsupportedAlgorithm)
        );
    }
}
