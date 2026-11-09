//! SHA-2 digests over byte ranges, without copying (docs/31 §4 step 4).

use core::ops::Range;

use der::asn1::ObjectIdentifier;
use sha2::Digest as _;
use spki::AlgorithmIdentifierOwned;

use crate::error::CryptoError;
use crate::oid;

/// The digest algorithms this crate supports. SHA-1 and MD5 are never accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DigestAlgorithm {
    /// SHA-256, the default.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl DigestAlgorithm {
    /// Output length in bytes.
    #[must_use]
    pub const fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// The algorithm's object identifier.
    #[must_use]
    pub const fn oid(self) -> ObjectIdentifier {
        match self {
            Self::Sha256 => oid::ID_SHA256,
            Self::Sha384 => oid::ID_SHA384,
            Self::Sha512 => oid::ID_SHA512,
        }
    }

    /// The algorithm from its object identifier, if supported.
    #[must_use]
    pub fn from_oid(id: &ObjectIdentifier) -> Option<Self> {
        [Self::Sha256, Self::Sha384, Self::Sha512]
            .into_iter()
            .find(|a| a.oid() == *id)
    }

    /// From an `AlgorithmIdentifier`, accepting absent or NULL parameters (RFC 5754 §2).
    pub(crate) fn from_algorithm_identifier(
        id: &AlgorithmIdentifierOwned,
    ) -> Result<Self, CryptoError> {
        let alg = Self::from_oid(&id.oid).ok_or(CryptoError::UnsupportedAlgorithm)?;
        match &id.parameters {
            None => Ok(alg),
            Some(p) if p.is_null() => Ok(alg),
            Some(_) => Err(CryptoError::UnsupportedAlgorithm),
        }
    }

    /// The `AlgorithmIdentifier` we write: parameters absent, as RFC 5754 §2 prefers.
    #[must_use]
    pub fn algorithm_identifier(self) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: self.oid(),
            parameters: None,
        }
    }

    /// Digest of one slice.
    #[must_use]
    pub fn digest(self, data: &[u8]) -> DigestValue {
        let mut h = Hasher::new(self);
        h.update(data);
        h.finish()
    }

    /// Digest of `ranges` of `data`, in order, without copying them. Every range must lie
    /// inside `data` and have `start <= end`; overlap and coverage are the caller's checks
    /// (docs/31 §7 ByteRange rules live in the verifier).
    ///
    /// # Errors
    /// [`CryptoError::RangeOutOfBounds`] (`CS-VER-0001`) for a range outside `data`.
    pub fn digest_ranges(
        self,
        data: &[u8],
        ranges: &[Range<usize>],
    ) -> Result<DigestValue, CryptoError> {
        let mut h = Hasher::new(self);
        for r in ranges {
            h.update(data.get(r.clone()).ok_or(CryptoError::RangeOutOfBounds)?);
        }
        Ok(h.finish())
    }
}

/// An incremental hasher for callers that stream.
#[derive(Clone, Debug)]
pub struct Hasher(Inner);

#[derive(Clone, Debug)]
enum Inner {
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
}

impl Hasher {
    /// A new hasher for `alg`.
    #[must_use]
    pub fn new(alg: DigestAlgorithm) -> Self {
        Self(match alg {
            DigestAlgorithm::Sha256 => Inner::Sha256(sha2::Sha256::new()),
            DigestAlgorithm::Sha384 => Inner::Sha384(sha2::Sha384::new()),
            DigestAlgorithm::Sha512 => Inner::Sha512(sha2::Sha512::new()),
        })
    }

    /// Feed bytes.
    pub fn update(&mut self, data: &[u8]) {
        match &mut self.0 {
            Inner::Sha256(h) => h.update(data),
            Inner::Sha384(h) => h.update(data),
            Inner::Sha512(h) => h.update(data),
        }
    }

    /// The digest.
    #[must_use]
    pub fn finish(self) -> DigestValue {
        match self.0 {
            Inner::Sha256(h) => DigestValue::new(DigestAlgorithm::Sha256, h.finalize().to_vec()),
            Inner::Sha384(h) => DigestValue::new(DigestAlgorithm::Sha384, h.finalize().to_vec()),
            Inner::Sha512(h) => DigestValue::new(DigestAlgorithm::Sha512, h.finalize().to_vec()),
        }
    }
}

/// A digest and the algorithm that made it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DigestValue {
    algorithm: DigestAlgorithm,
    bytes: Vec<u8>,
}

impl DigestValue {
    fn new(algorithm: DigestAlgorithm, bytes: Vec<u8>) -> Self {
        Self { algorithm, bytes }
    }

    /// A digest computed elsewhere (for example by a host with aws-lc-rs).
    ///
    /// # Errors
    /// [`CryptoError::UnsupportedAlgorithm`] if the length does not fit the algorithm.
    pub fn from_bytes(algorithm: DigestAlgorithm, bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != algorithm.output_len() {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        Ok(Self::new(algorithm, bytes.to_vec()))
    }

    /// The algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> DigestAlgorithm {
        self.algorithm
    }

    /// The digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_hash_like_the_concatenation() {
        let data = b"0123456789";
        let got = DigestAlgorithm::Sha256
            .digest_ranges(data, &[0..3, 7..10])
            .unwrap();
        assert_eq!(got, DigestAlgorithm::Sha256.digest(b"012789"));
    }

    #[test]
    fn range_outside_data_is_refused() {
        let err = DigestAlgorithm::Sha384
            .digest_ranges(b"abc", &[0..4])
            .unwrap_err();
        assert_eq!(err.code(), "CS-VER-0001");
        // A reversed range must be refused, not panic; clippy flags the literal on purpose.
        #[allow(clippy::reversed_empty_ranges)]
        let err = DigestAlgorithm::Sha512
            .digest_ranges(b"abc", &[2..1])
            .unwrap_err();
        assert_eq!(err, CryptoError::RangeOutOfBounds);
    }

    #[test]
    fn known_answers() {
        // FIPS 180-2 "abc" vectors (first bytes).
        assert_eq!(
            DigestAlgorithm::Sha256.digest(b"abc").as_bytes()[..4],
            [0xba, 0x78, 0x16, 0xbf]
        );
        assert_eq!(
            DigestAlgorithm::Sha384.digest(b"abc").as_bytes()[..4],
            [0xcb, 0x00, 0x75, 0x3f]
        );
        assert_eq!(
            DigestAlgorithm::Sha512.digest(b"abc").as_bytes()[..4],
            [0xdd, 0xaf, 0x35, 0xa1]
        );
    }
}
