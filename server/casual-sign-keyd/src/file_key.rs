//! The development file key (docs/31 §5): a PEM private key and its certificate chain,
//! signing through aws-lc-rs (ADR-006). **Refused unless `OPENSEAL_DEV_INSECURE_KEY=1`**
//! ([`DevKeyConsent`]), and every seal made with one must carry
//! [`DEV_REASON`] ([`DigestSigner::is_development`]).
//!
//! The loading logic follows `casual-sign-cli`'s `key.rs` (this repository), with the
//! RSA scheme configurable and a digest-signing path for keyd.

use aws_lc_rs::digest::Digest;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    self, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair, KeyPair,
    RsaEncoding, RsaKeyPair,
};
use casual_sign_crypto::{Certificate, KeyError, KeyProvider, Signature, SignatureAlgorithm};
use der::asn1::ObjectIdentifier;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::pem::PemObject;

use crate::error::{KeyConfigProblem, KeydError};
use crate::signer::{DigestSigner, aws_digest, check_digest};

/// `/Reason` of every seal made with a file key (docs/31 §5).
pub const DEV_REASON: &str = "Development key \u{2014} not for production";

/// The environment variable that permits a file key.
pub const DEV_KEY_VARIABLE: &str = "OPENSEAL_DEV_INSECURE_KEY";

const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// Proof that the operator permitted a development file key. Only
/// [`DevKeyConsent::from_env_value`] makes one, and only for exactly `"1"`.
#[derive(Debug, Clone, Copy)]
pub struct DevKeyConsent(());

impl DevKeyConsent {
    /// Consent from the value of `OPENSEAL_DEV_INSECURE_KEY`.
    ///
    /// # Errors
    /// `CS-KEY-0004` unless the value is exactly `"1"`.
    pub fn from_env_value(value: Option<&str>) -> Result<Self, KeydError> {
        match value {
            Some("1") => Ok(Self(())),
            _ => Err(KeydError::InsecureKeyRefused),
        }
    }

    /// Consent read from the process environment.
    ///
    /// # Errors
    /// `CS-KEY-0004` unless `OPENSEAL_DEV_INSECURE_KEY=1`.
    pub fn from_env() -> Result<Self, KeydError> {
        Self::from_env_value(std::env::var(DEV_KEY_VARIABLE).ok().as_deref())
    }
}

enum Pair {
    Ec(EcdsaKeyPair),
    Rsa(RsaKeyPair),
}

/// A private key held in this process, with its chain. Development only.
pub struct FileKey {
    pair: Pair,
    algorithm: SignatureAlgorithm,
    chain: Vec<Certificate>,
}

impl core::fmt::Debug for FileKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FileKey")
            .field("algorithm", &self.algorithm)
            .field("chain", &self.chain.len())
            .finish_non_exhaustive()
    }
}

fn rsa_encoding(alg: SignatureAlgorithm) -> Option<&'static dyn RsaEncoding> {
    Some(match alg {
        SignatureAlgorithm::RsaPkcs1Sha256 => &signature::RSA_PKCS1_SHA256,
        SignatureAlgorithm::RsaPkcs1Sha384 => &signature::RSA_PKCS1_SHA384,
        SignatureAlgorithm::RsaPkcs1Sha512 => &signature::RSA_PKCS1_SHA512,
        SignatureAlgorithm::RsaPssSha256 => &signature::RSA_PSS_SHA256,
        SignatureAlgorithm::RsaPssSha384 => &signature::RSA_PSS_SHA384,
        SignatureAlgorithm::RsaPssSha512 => &signature::RSA_PSS_SHA512,
        _ => return None,
    })
}

impl FileKey {
    /// Load the key in `key_pem` for the first certificate of `chain`. The key must be
    /// that certificate's: ECDSA P-256 or P-384, or RSA signing with `rsa_algorithm`
    /// (PKCS#1 v1.5 SHA-256 when `None`).
    ///
    /// # Errors
    /// `CS-KEY-0006` when the key or the chain is unusable. Consent is checked first:
    /// without it there is nothing to load.
    pub fn load(
        _consent: DevKeyConsent,
        key_pem: &[u8],
        chain: Vec<Certificate>,
        rsa_algorithm: Option<SignatureAlgorithm>,
    ) -> Result<Self, KeydError> {
        let cfg = |p| KeydError::KeyConfig(p);
        let signer = chain.first().ok_or(cfg(KeyConfigProblem::NoCertificate))?;
        let spki = signer.tbs_certificate().subject_public_key_info();
        let cert_key = spki.subject_public_key.raw_bytes();
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
        let key = PrivateKeyDer::from_pem_slice(key_pem)
            .map_err(|_| cfg(KeyConfigProblem::BadKeyFile))?;
        let (pair, algorithm) = if spki.algorithm.oid == EC_PUBLIC_KEY {
            let (alg, sa) = match curve {
                Some(c) if c == P256 => (
                    &ECDSA_P256_SHA256_ASN1_SIGNING,
                    SignatureAlgorithm::EcdsaP256Sha256,
                ),
                Some(c) if c == P384 => (
                    &ECDSA_P384_SHA384_ASN1_SIGNING,
                    SignatureAlgorithm::EcdsaP384Sha384,
                ),
                _ => return Err(cfg(KeyConfigProblem::UnsupportedAlgorithm)),
            };
            let kp = EcdsaKeyPair::from_private_key_der(alg, key.secret_der())
                .map_err(|_| cfg(KeyConfigProblem::BadKeyFile))?;
            if kp.public_key().as_ref() != cert_key {
                return Err(cfg(KeyConfigProblem::KeyCertificateMismatch));
            }
            (Pair::Ec(kp), sa)
        } else if spki.algorithm.oid == RSA {
            // 3072 to 8192 bits and a supported scheme (docs/31 §4).
            let sa = crate::cert_key::algorithm_for(signer, rsa_algorithm)?;
            if rsa_encoding(sa).is_none() {
                return Err(cfg(KeyConfigProblem::UnsupportedAlgorithm));
            }
            let kp = match &key {
                PrivateKeyDer::Pkcs1(k) => RsaKeyPair::from_der(k.secret_pkcs1_der()),
                PrivateKeyDer::Pkcs8(k) => RsaKeyPair::from_pkcs8(k.secret_pkcs8_der()),
                _ => return Err(cfg(KeyConfigProblem::BadKeyFile)),
            }
            .map_err(|_| cfg(KeyConfigProblem::BadKeyFile))?;
            if kp.public_key().as_ref() != cert_key {
                return Err(cfg(KeyConfigProblem::KeyCertificateMismatch));
            }
            (Pair::Rsa(kp), sa)
        } else {
            return Err(cfg(KeyConfigProblem::UnsupportedAlgorithm));
        };
        Ok(Self {
            pair,
            algorithm,
            chain,
        })
    }
}

impl DigestSigner for FileKey {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn certificate_chain(&self) -> &[Certificate] {
        &self.chain
    }

    fn is_development(&self) -> bool {
        true
    }

    fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, KeydError> {
        check_digest(self.algorithm, digest)?;
        let d = Digest::import_less_safe(digest, aws_digest(self.algorithm.digest_algorithm()))
            .map_err(|_| KeydError::Malformed("digest length does not match the algorithm"))?;
        match &self.pair {
            Pair::Ec(kp) => kp
                .sign_digest(&d)
                .map(|s| s.as_ref().to_vec())
                .map_err(|e| KeydError::backend("file key ECDSA", e)),
            Pair::Rsa(kp) => {
                let enc = rsa_encoding(self.algorithm)
                    .ok_or(KeydError::KeyConfig(KeyConfigProblem::UnsupportedAlgorithm))?;
                let mut out = vec![0u8; kp.public_modulus_len()];
                kp.sign_digest(enc, &d, &mut out)
                    .map_err(|e| KeydError::backend("file key RSA", e))?;
                Ok(out)
            }
        }
    }
}

impl KeyProvider for FileKey {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn certificate_chain(&self) -> &[Certificate] {
        &self.chain
    }

    /// Signs the attributes whole (not their digest), so the FIPS-approved aws-lc-rs
    /// `sign` is used in process (`SPK-02`).
    fn sign(&self, signed_attrs_der: &[u8]) -> Result<Signature, KeyError> {
        let rng = SystemRandom::new();
        match &self.pair {
            Pair::Ec(kp) => kp
                .sign(&rng, signed_attrs_der)
                .map(|s| Signature::new(s.as_ref().to_vec()))
                .map_err(|_| KeyError::Unavailable),
            Pair::Rsa(kp) => {
                let enc = rsa_encoding(self.algorithm).ok_or(KeyError::Unavailable)?;
                let mut out = vec![0u8; kp.public_modulus_len()];
                kp.sign(enc, &rng, signed_attrs_der, &mut out)
                    .map_err(|_| KeyError::Unavailable)?;
                Ok(Signature::new(out))
            }
        }
    }
}
