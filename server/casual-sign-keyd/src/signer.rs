//! The digest-signing seam every keyd backend implements, and the encodings around it:
//! the wire id of each algorithm, the DER `Ecdsa-Sig-Value` a PKCS#11 module's raw
//! `r || s` becomes, and the `DigestInfo` an RSA PKCS#1 v1.5 signature wraps.
//!
//! keyd signs **digests** (docs/31 §5): the caller hashes the CMS signed attributes, so
//! no document byte and no signed attribute crosses to keyd.

use aws_lc_rs::digest;
use casual_sign_crypto::{Certificate, DigestAlgorithm, KeyError, Signature, SignatureAlgorithm};
use der::asn1::{AnyRef, ObjectIdentifier, OctetStringRef, UintRef};
use der::{Encode, Sequence};
use spki::AlgorithmIdentifier;

use crate::error::KeydError;

/// A key that signs a digest it is handed. Implemented by the PKCS#11 key, the
/// development file key and keyd's remote client.
pub trait DigestSigner: Send + Sync {
    /// The algorithm the key signs with.
    fn algorithm(&self) -> SignatureAlgorithm;

    /// The signer certificate first, then intermediates.
    fn certificate_chain(&self) -> &[Certificate];

    /// Whether this is a development file key, whose seals must carry
    /// `/Reason (Development key — not for production)` (docs/31 §5).
    fn is_development(&self) -> bool;

    /// Sign `digest`, already computed with the algorithm's hash. The output is a DER
    /// `Ecdsa-Sig-Value` for ECDSA and the modulus-length value for RSA.
    ///
    /// # Errors
    /// [`KeydError`]: `CS-KEY-0007` for a digest of the wrong length, `CS-KEY-0003` when
    /// the backend fails.
    fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, KeydError>;

    /// The backend kind keyd's admin interface reports: `pkcs11`, `kms:<provider>`,
    /// `file-dev` or `remote` (docs/23 §5.4).
    fn backend(&self) -> &'static str;

    /// Whether the backend answers now (an open HSM session), for keyd's `health`.
    /// Never signs.
    fn healthy(&self) -> bool {
        true
    }
}

/// The hash of `data` with `alg`'s digest (aws-lc-rs, ADR-006).
#[must_use]
pub fn digest_for(alg: SignatureAlgorithm, data: &[u8]) -> Vec<u8> {
    digest::digest(aws_digest(alg.digest_algorithm()), data)
        .as_ref()
        .to_vec()
}

pub(crate) fn aws_digest(alg: DigestAlgorithm) -> &'static digest::Algorithm {
    match alg {
        DigestAlgorithm::Sha384 => &digest::SHA384,
        DigestAlgorithm::Sha512 => &digest::SHA512,
        _ => &digest::SHA256,
    }
}

/// The digest length `alg` signs over; a request with another length is refused.
#[must_use]
pub fn digest_len(alg: SignatureAlgorithm) -> usize {
    aws_digest(alg.digest_algorithm()).output_len
}

/// Refuse a digest whose length is not `alg`'s (docs/31 §5).
pub(crate) fn check_digest(alg: SignatureAlgorithm, digest: &[u8]) -> Result<(), KeydError> {
    if digest.len() == digest_len(alg) {
        Ok(())
    } else {
        Err(KeydError::Malformed(
            "digest length does not match the algorithm",
        ))
    }
}

/// Sign the DER signed attributes through a digest signer: hash, then sign the hash.
/// The `KeyProvider` implementations of this crate's keys are this function.
pub(crate) fn sign_attributes(
    signer: &dyn DigestSigner,
    signed_attrs_der: &[u8],
) -> Result<Signature, KeyError> {
    let digest = digest_for(signer.algorithm(), signed_attrs_der);
    signer
        .sign_digest(&digest)
        .map(Signature::new)
        .map_err(|e| match e {
            KeydError::NotAuthorized
            | KeydError::UnknownAlias
            | KeydError::RateLimited
            | KeydError::InsecureKeyRefused => KeyError::Refused,
            _ => KeyError::Unavailable,
        })
}

/// The protocol's id for `alg`; `None` for one keyd does not serve.
#[must_use]
pub(crate) fn wire_id(alg: SignatureAlgorithm) -> Option<u8> {
    Some(match alg {
        SignatureAlgorithm::EcdsaP256Sha256 => 1,
        SignatureAlgorithm::EcdsaP384Sha384 => 2,
        SignatureAlgorithm::RsaPkcs1Sha256 => 3,
        SignatureAlgorithm::RsaPkcs1Sha384 => 4,
        SignatureAlgorithm::RsaPkcs1Sha512 => 5,
        SignatureAlgorithm::RsaPssSha256 => 6,
        SignatureAlgorithm::RsaPssSha384 => 7,
        SignatureAlgorithm::RsaPssSha512 => 8,
        _ => return None,
    })
}

/// The algorithm with protocol id `id`.
#[must_use]
pub(crate) fn from_wire_id(id: u8) -> Option<SignatureAlgorithm> {
    Some(match id {
        1 => SignatureAlgorithm::EcdsaP256Sha256,
        2 => SignatureAlgorithm::EcdsaP384Sha384,
        3 => SignatureAlgorithm::RsaPkcs1Sha256,
        4 => SignatureAlgorithm::RsaPkcs1Sha384,
        5 => SignatureAlgorithm::RsaPkcs1Sha512,
        6 => SignatureAlgorithm::RsaPssSha256,
        7 => SignatureAlgorithm::RsaPssSha384,
        8 => SignatureAlgorithm::RsaPssSha512,
        _ => return None,
    })
}

/// Whether `alg` is an ECDSA algorithm.
#[must_use]
pub(crate) fn is_ecdsa(alg: SignatureAlgorithm) -> bool {
    matches!(
        alg,
        SignatureAlgorithm::EcdsaP256Sha256 | SignatureAlgorithm::EcdsaP384Sha384
    )
}

#[derive(Sequence)]
struct EcdsaSigValue<'a> {
    r: UintRef<'a>,
    s: UintRef<'a>,
}

/// A PKCS#11 `CKM_ECDSA` signature (`r || s`, each the field size) as the DER
/// `Ecdsa-Sig-Value` CMS carries (RFC 3279 §2.2.3).
pub(crate) fn ecdsa_raw_to_der(raw: &[u8]) -> Result<Vec<u8>, KeydError> {
    let half = raw.len() / 2;
    if raw.is_empty() || !raw.len().is_multiple_of(2) {
        return Err(KeydError::backend(
            "C_Sign",
            "ECDSA signature of odd or zero length",
        ));
    }
    let (r, s) = raw.split_at(half);
    let bad = |e: der::Error| KeydError::backend("ECDSA signature encoding", e);
    EcdsaSigValue {
        r: UintRef::new(r).map_err(bad)?,
        s: UintRef::new(s).map_err(bad)?,
    }
    .to_der()
    .map_err(bad)
}

/// SHA-256, SHA-384, SHA-512 (NIST CSOR, RFC 5754).
const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

#[derive(Sequence)]
struct DigestInfo<'a> {
    algorithm: AlgorithmIdentifier<AnyRef<'a>>,
    digest: &'a OctetStringRef,
}

/// The DER `DigestInfo` (RFC 8017 §9.2) that `CKM_RSA_PKCS` signs for PKCS#1 v1.5.
pub(crate) fn digest_info(alg: DigestAlgorithm, digest: &[u8]) -> Result<Vec<u8>, KeydError> {
    let oid = match alg {
        DigestAlgorithm::Sha384 => SHA384,
        DigestAlgorithm::Sha512 => SHA512,
        _ => SHA256,
    };
    let bad = |e: der::Error| KeydError::backend("DigestInfo encoding", e);
    DigestInfo {
        algorithm: AlgorithmIdentifier {
            oid,
            parameters: Some(AnyRef::NULL),
        },
        digest: OctetStringRef::new(digest).map_err(bad)?,
    }
    .to_der()
    .map_err(bad)
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report.
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn wire_ids_round_trip() {
        for id in 1..=8 {
            let alg = from_wire_id(id).unwrap();
            assert_eq!(wire_id(alg), Some(id));
        }
        assert_eq!(from_wire_id(0), None);
        assert_eq!(from_wire_id(9), None);
    }

    #[test]
    fn sha256_digest_info_has_the_rfc_8017_prefix() {
        let di = digest_info(DigestAlgorithm::Sha256, &[0u8; 32]).unwrap();
        // RFC 8017 §9.2 note 1: the 19-byte SHA-256 prefix.
        let prefix = [
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ];
        assert_eq!(&di[..19], &prefix);
        assert_eq!(di.len(), 19 + 32);
    }

    #[test]
    fn raw_ecdsa_becomes_der_with_minimal_integers() {
        let mut raw = vec![0u8; 64];
        raw[31] = 1; // r = 1
        raw[32] = 0x80; // s has its top bit set: needs a leading zero
        let der = ecdsa_raw_to_der(&raw).unwrap();
        assert_eq!(&der[..5], &[0x30, 0x26, 0x02, 0x01, 0x01]);
        assert_eq!(&der[5..8], &[0x02, 0x21, 0x00]);
        assert!(ecdsa_raw_to_der(&[1, 2, 3]).is_err());
        assert!(ecdsa_raw_to_der(&[]).is_err());
    }

    #[test]
    fn a_digest_of_the_wrong_length_is_refused() {
        let alg = SignatureAlgorithm::EcdsaP384Sha384;
        assert!(check_digest(alg, &[0; 48]).is_ok());
        let err = check_digest(alg, &[0; 32]).unwrap_err();
        assert_eq!(err.code(), "CS-KEY-0007");
    }
}
