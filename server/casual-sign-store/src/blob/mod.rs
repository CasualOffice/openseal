//! Content-addressed, write-once blob storage (docs/22 §2, §4, §9).
//!
//! A blob's key is the SHA-256 of its bytes, computed here, never supplied. `put` of bytes
//! already stored is a no-op that returns the same key; nothing ever replaces a stored
//! blob, and there is no delete (purge belongs to the retention job, slice 15, which
//! records `envelope.purged` first). `get` re-hashes what it read and refuses bytes that do
//! not match their key (`CS-BLOB-0003`), so corruption or tampering in the store is
//! caught at the point of use.

use core::fmt;
use core::future::Future;

use casual_sign_audit::Hash256;

use crate::error::{Result, StoreError};

mod fs;
mod s3;

pub use fs::FsBlobStore;
pub use s3::{S3BlobStore, S3Config};

/// The default cap on one blob: 256 MiB (an envelope's total is 200 MiB, docs/21).
pub const DEFAULT_MAX_BLOB_BYTES: u64 = 256 * 1024 * 1024;

/// A blob's key: the SHA-256 of its bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlobKey(pub [u8; 32]);

impl BlobKey {
    /// The key of `bytes`.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(*Hash256::digest(bytes).as_bytes())
    }

    /// 64 lower-case hexadecimal digits.
    #[must_use]
    pub fn hex(&self) -> String {
        Hash256(self.0).hex()
    }

    /// Parse 64 lower-case hexadecimal digits.
    ///
    /// # Errors
    ///
    /// `CS-BLOB-0005` for anything else.
    pub fn parse(text: &str) -> Result<Self> {
        if text.len() != 64 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(StoreError::BlobKey);
        }
        let mut out = [0u8; 32];
        for (slot, pair) in out.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
            let pair = core::str::from_utf8(pair).map_err(|_| StoreError::BlobKey)?;
            *slot = u8::from_str_radix(pair, 16).map_err(|_| StoreError::BlobKey)?;
        }
        Ok(Self(out))
    }
}

impl fmt::Debug for BlobKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlobKey({})", self.hex())
    }
}

impl fmt::Display for BlobKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex())
    }
}

/// A content-addressed, write-once blob store.
pub trait BlobStore: Send + Sync {
    /// Store `bytes` under their SHA-256 and return it. Storing bytes already present is
    /// a no-op; a stored blob is never replaced.
    ///
    /// # Errors
    ///
    /// `CS-BLOB-0004` over the size cap; `CS-BLOB-0001` the store failed.
    fn put(&self, bytes: &[u8]) -> impl Future<Output = Result<BlobKey>> + Send;

    /// The bytes stored under `key`, verified against it.
    ///
    /// # Errors
    ///
    /// `CS-BLOB-0002` no such blob; `CS-BLOB-0003` the bytes do not match the key;
    /// `CS-BLOB-0004` over the size cap; `CS-BLOB-0001` the store failed.
    fn get(&self, key: &BlobKey) -> impl Future<Output = Result<Vec<u8>>> + Send;

    /// Whether a blob is stored under `key`.
    ///
    /// # Errors
    ///
    /// `CS-BLOB-0001` the store failed.
    fn exists(&self, key: &BlobKey) -> impl Future<Output = Result<bool>> + Send;
}

/// Check bytes read back against their key.
pub(crate) fn verified(key: &BlobKey, bytes: Vec<u8>) -> Result<Vec<u8>> {
    if BlobKey::of(&bytes) == *key {
        Ok(bytes)
    } else {
        Err(StoreError::BlobCorrupt)
    }
}

/// Refuse a blob over `max` bytes.
pub(crate) fn within(len: u64, max: u64) -> Result<()> {
    if len > max {
        Err(StoreError::BlobTooLarge { max })
    } else {
        Ok(())
    }
}

#[cfg(test)]
// Tests may unwrap, index and panic (CLAUDE.md).
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn key_round_trips_through_hex_and_refuses_anything_else() {
        let k = BlobKey::of(b"hello");
        assert_eq!(
            k.hex(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert_eq!(BlobKey::parse(&k.hex()).unwrap(), k);
        for bad in [
            "",
            "2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824",
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b982",
            "../../etc/passwd",
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b982g",
        ] {
            assert_eq!(
                BlobKey::parse(bad).unwrap_err().code(),
                "CS-BLOB-0005",
                "{bad}"
            );
        }
    }

    #[test]
    fn verified_refuses_bytes_that_do_not_match_their_key() {
        let k = BlobKey::of(b"hello");
        assert!(verified(&k, b"hello".to_vec()).is_ok());
        assert_eq!(
            verified(&k, b"hellO".to_vec()).unwrap_err().code(),
            "CS-BLOB-0003"
        );
    }
}
