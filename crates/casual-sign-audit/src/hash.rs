//! SHA-256 values as the audit trail writes them: `sha256:` and 64 lower-case hex digits.

use core::fmt;

use casual_sign_crypto::DigestAlgorithm;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{AuditError, ShapeFault};

/// A SHA-256 digest: an event hash, a document hash, a field value hash.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hash256(pub [u8; 32]);

const PREFIX: &str = "sha256:";

impl Hash256 {
    /// SHA-256 of `data` (through `casual-sign-crypto`, ADR-006).
    #[must_use]
    pub fn digest(data: &[u8]) -> Self {
        Self::from_digest(&DigestAlgorithm::Sha256.digest(data))
    }

    /// SHA-256 of the concatenation of `parts`, without copying them.
    #[must_use]
    pub fn digest_parts(parts: &[&[u8]]) -> Self {
        let mut h = casual_sign_crypto::Hasher::new(DigestAlgorithm::Sha256);
        for p in parts {
            h.update(p);
        }
        Self::from_digest(&h.finish())
    }

    fn from_digest(d: &casual_sign_crypto::DigestValue) -> Self {
        let mut out = [0u8; 32];
        for (o, b) in out.iter_mut().zip(d.as_bytes()) {
            *o = *b;
        }
        Self(out)
    }

    /// The 32 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The 64 lower-case hex digits, without the prefix.
    #[must_use]
    pub fn hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// Parse `sha256:` and 64 lower-case hex digits; nothing else is accepted, so a
    /// hash has exactly one written form.
    ///
    /// # Errors
    ///
    /// `CS-AUD-0003` ([`ShapeFault::Hash`]).
    pub fn parse(text: &str) -> Result<Self, AuditError> {
        let bad = || AuditError::shape(ShapeFault::Hash);
        let hex = text.strip_prefix(PREFIX).ok_or_else(bad)?;
        if hex.len() != 64 {
            return Err(bad());
        }
        let mut out = [0u8; 32];
        for (i, o) in out.iter_mut().enumerate() {
            let at = i.saturating_mul(2);
            let pair = hex.get(at..at.saturating_add(2)).ok_or_else(bad)?;
            if !pair.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
                return Err(bad());
            }
            *o = u8::from_str_radix(pair, 16).map_err(|_| bad())?;
        }
        Ok(Self(out))
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{PREFIX}{}", self.hex())
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl Serialize for Hash256 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Hash256 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

// Tests may unwrap, index and panic (CLAUDE.md).
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_digest_and_round_trip() {
        let h = Hash256::digest(b"abc");
        assert_eq!(
            h.to_string(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(Hash256::parse(&h.to_string()).unwrap(), h);
        assert_eq!(Hash256::digest_parts(&[b"a", b"bc"]), h);
    }

    #[test]
    fn only_one_written_form() {
        let h = Hash256::digest(b"abc").to_string();
        for bad in [
            h.to_uppercase(),
            h.replace("sha256:", "SHA256:"),
            h.replace("sha256:", ""),
            format!("{h}0"),
            h[..h.len() - 1].to_owned(),
            h.replace('a', "g"),
        ] {
            assert!(Hash256::parse(&bad).is_err(), "{bad}");
        }
    }
}
