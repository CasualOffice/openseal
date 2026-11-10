//! A development file key (docs/31 §5): a PEM private key and its certificate chain,
//! signing through `aws-lc-rs` (ADR-006). Production keys live in `keyd` behind an HSM
//! or KMS; the CLI refuses a key file unless `--insecure-file-key` is given, and every
//! seal made with one carries the development reason.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair, KeyPair,
    RSA_PKCS1_SHA256, RsaKeyPair,
};
use casual_sign_sdk::{Certificate, KeyError, KeyProvider, Signature, SignatureAlgorithm};
use der::Decode;
use der::asn1::ObjectIdentifier;

/// `/Reason` of every seal made with a file key (docs/31 §5).
pub(crate) const DEV_REASON: &str = "Development key \u{2014} not for production";

const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// The PEM blocks of `text`: (label, DER). A block that does not decode is an error.
pub(crate) fn pem_blocks(text: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let s = std::str::from_utf8(text).map_err(|_| "not a PEM file (not UTF-8)".to_owned())?;
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(begin) = rest.find("-----BEGIN ") {
        let tail = rest.get(begin..).unwrap_or_default();
        let Some(end_at) = tail.find("-----END ") else {
            return Err("a PEM block has no END line".into());
        };
        let after_end = tail.get(end_at..).unwrap_or_default();
        let close = after_end
            .get(9..)
            .and_then(|t| t.find("-----"))
            .map(|i| end_at.saturating_add(9).saturating_add(i).saturating_add(5))
            .ok_or_else(|| "a PEM END line is not closed".to_owned())?;
        let block = tail.get(..close).unwrap_or_default();
        let (label, der) = pem_rfc7468::decode_vec(block.as_bytes())
            .map_err(|e| format!("a PEM block does not decode: {e}"))?;
        out.push((label.to_owned(), der));
        rest = tail.get(close..).unwrap_or_default();
    }
    Ok(out)
}

/// The certificates of a PEM file (or one DER certificate), in order.
pub(crate) fn certificates(bytes: &[u8]) -> Result<Vec<Certificate>, String> {
    if bytes.first() == Some(&0x30) {
        return Certificate::from_der(bytes)
            .map(|c| vec![c])
            .map_err(|e| format!("not a DER certificate: {e}"));
    }
    let mut out = Vec::new();
    for (label, der) in pem_blocks(bytes)? {
        if label == "CERTIFICATE" {
            out.push(
                Certificate::from_der(&der)
                    .map_err(|e| format!("a certificate does not parse: {e}"))?,
            );
        }
    }
    if out.is_empty() {
        return Err("no CERTIFICATE block".into());
    }
    Ok(out)
}

enum Pair {
    Ec(EcdsaKeyPair),
    Rsa(RsaKeyPair),
}

/// A private key held in this process, with its chain.
pub(crate) struct FileKey {
    pair: Pair,
    algorithm: SignatureAlgorithm,
    chain: Vec<Certificate>,
}

impl std::fmt::Debug for FileKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileKey")
            .field("algorithm", &self.algorithm)
            .field("chain", &self.chain.len())
            .finish_non_exhaustive()
    }
}

impl FileKey {
    /// Load the key in `key_pem` for the first certificate of `chain`. The key must be
    /// that certificate's: ECDSA P-256 or P-384, or RSA (PKCS#1 v1.5 with SHA-256).
    pub(crate) fn load(key_pem: &[u8], chain: Vec<Certificate>) -> Result<Self, String> {
        let signer = chain.first().ok_or("the chain has no certificate")?;
        let spki = signer.tbs_certificate().subject_public_key_info();
        let cert_key = spki.subject_public_key.raw_bytes();
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
        let blocks = pem_blocks(key_pem)?;
        let (label, der) = blocks
            .into_iter()
            .find(|(l, _)| l.ends_with("PRIVATE KEY"))
            .ok_or("no PRIVATE KEY block in the key file")?;
        if label == "ENCRYPTED PRIVATE KEY" {
            return Err(
                "an encrypted key file is not supported; decrypt it to PKCS#8 first".into(),
            );
        }
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
                _ => return Err("the certificate's curve is not P-256 or P-384".into()),
            };
            let kp = EcdsaKeyPair::from_private_key_der(alg, &der)
                .map_err(|e| format!("the key does not load: {e}"))?;
            if kp.public_key().as_ref() != cert_key {
                return Err("the key is not the certificate's".into());
            }
            (Pair::Ec(kp), sa)
        } else if spki.algorithm.oid == RSA {
            let kp = match label.as_str() {
                "RSA PRIVATE KEY" => RsaKeyPair::from_der(&der),
                _ => RsaKeyPair::from_pkcs8(&der),
            }
            .map_err(|e| format!("the key does not load: {e}"))?;
            if kp.public_key().as_ref() != cert_key {
                return Err("the key is not the certificate's".into());
            }
            (Pair::Rsa(kp), SignatureAlgorithm::RsaPkcs1Sha256)
        } else {
            return Err("the certificate's key is neither ECDSA nor RSA".into());
        };
        Ok(Self {
            pair,
            algorithm,
            chain,
        })
    }
}

impl KeyProvider for FileKey {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn certificate_chain(&self) -> &[Certificate] {
        &self.chain
    }

    fn sign(&self, signed_attrs_der: &[u8]) -> Result<Signature, KeyError> {
        let rng = SystemRandom::new();
        match &self.pair {
            Pair::Ec(kp) => kp
                .sign(&rng, signed_attrs_der)
                .map(|s| Signature::new(s.as_ref().to_vec()))
                .map_err(|_| KeyError::Unavailable),
            Pair::Rsa(kp) => {
                let mut out = vec![0u8; kp.public_modulus_len()];
                kp.sign(&RSA_PKCS1_SHA256, &rng, signed_attrs_der, &mut out)
                    .map_err(|_| KeyError::Unavailable)?;
                Ok(Signature::new(out))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report.
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn pem_blocks_split_and_decode() {
        let text = b"junk\n-----BEGIN A-----\nAQID\n-----END A-----\n-----BEGIN B-----\nBAU=\n-----END B-----\n";
        let blocks = pem_blocks(text).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0], ("A".to_owned(), vec![1, 2, 3]));
        assert_eq!(blocks[1], ("B".to_owned(), vec![4, 5]));
        assert!(pem_blocks(b"-----BEGIN A-----\nAQID\n").is_err());
    }
}
