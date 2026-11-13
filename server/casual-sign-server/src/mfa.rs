//! The sealing of staff TOTP seeds and the recovery codes (ASVS-01, docs/40 §2).
//!
//! [`MfaKey`] is copied from `casual-sign-console/src/crypto.rs` at `a9dd15b` (CON-02),
//! the operators' seed sealing, with the account-independent user id as the associated
//! data. Primitives are `aws-lc-rs`'s (ADR-006).

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use uuid::Uuid;

use crate::crypto::{random_bytes, sha256};
use crate::error::ApiError;

/// Recovery codes issued at enrolment.
pub(crate) const RECOVERY_CODES: usize = 10;
/// Random bytes in a recovery code: 112 bits (ASVS 2.6.2).
const RECOVERY_BYTES: usize = 14;

/// The key that seals staff users' TOTP seeds at rest (AES-256-GCM), from
/// `OPENSEAL_MFA_KEY` through `casual-sign-secrets`. The database holds only the sealed
/// seed; the key never reaches it.
pub struct MfaKey(LessSafeKey);

impl core::fmt::Debug for MfaKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MfaKey(..)")
    }
}

impl MfaKey {
    /// From 32 key bytes.
    ///
    /// # Errors
    ///
    /// `CS-API-0010` when the bytes are not an AES-256 key.
    pub fn new(bytes: &[u8]) -> Result<Self, ApiError> {
        if bytes.len() != 32 {
            return Err(ApiError::internal("mfa key length"));
        }
        let key =
            UnboundKey::new(&AES_256_GCM, bytes).map_err(|_| ApiError::internal("mfa key"))?;
        Ok(Self(LessSafeKey::new(key)))
    }

    /// A random key, for development only (`OPENSEAL_DEV_INSECURE_KEY=1`): seeds sealed
    /// under it do not open after a restart.
    ///
    /// # Errors
    ///
    /// `CS-API-0010` when the system's generator fails.
    pub fn generate() -> Result<Self, ApiError> {
        Self::new(&random_bytes::<32>()?)
    }

    /// Seal `seed` for `user`: nonce, ciphertext, tag. The user id is the associated
    /// data, so a sealed seed copied to another user's row does not open.
    pub(crate) fn seal(&self, user: Uuid, seed: &[u8]) -> Result<Vec<u8>, ApiError> {
        let nonce_bytes = random_bytes::<NONCE_LEN>()?;
        let mut buf = seed.to_vec();
        self.0
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(user.as_bytes()),
                &mut buf,
            )
            .map_err(|_| ApiError::internal("seal"))?;
        let mut out = nonce_bytes.to_vec();
        out.extend_from_slice(&buf);
        Ok(out)
    }

    /// Open a sealed seed of `user`.
    pub(crate) fn open(&self, user: Uuid, sealed: &[u8]) -> Result<Vec<u8>, ApiError> {
        let bad = || ApiError::internal("mfa seed does not open");
        let (nonce, body) = sealed.split_at_checked(NONCE_LEN).ok_or_else(bad)?;
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| bad())?;
        let mut buf = body.to_vec();
        let plain = self
            .0
            .open_in_place(nonce, Aad::from(user.as_bytes()), &mut buf)
            .map_err(|_| bad())?;
        Ok(plain.to_vec())
    }
}

/// A recovery code as the user is shown it: 112 random bits in base32, grouped by
/// fives with `-` (`XXXXX-XXXXX-XXXXX-XXXXX-XXX`).
pub(crate) fn recovery_code() -> Result<String, ApiError> {
    let raw = crate::totp::base32(&random_bytes::<RECOVERY_BYTES>()?);
    let groups: Vec<String> = raw
        .as_bytes()
        .chunks(5)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    Ok(groups.join("-"))
}

/// The SHA-256 a recovery code is stored and looked up by: of its letters and digits
/// only, upper-cased, so spacing, dashes and case do not matter when it is typed.
/// `None` when it cannot be a code (wrong length or alphabet).
pub(crate) fn recovery_hash(entered: &str) -> Option<[u8; 32]> {
    if entered.len() > 64 {
        return None;
    }
    let canon: String = entered
        .chars()
        .filter(|c| !matches!(c, '-' | ' '))
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let ok = canon.len() == 23
        && canon
            .bytes()
            .all(|b| matches!(b, b'A'..=b'Z' | b'2'..=b'7'));
    ok.then(|| sha256(canon.as_bytes()))
}

#[cfg(test)]
// Tests may unwrap (CLAUDE.md).
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_seed_opens_only_for_its_user_and_key() {
        let key = MfaKey::new(&[7u8; 32]).unwrap();
        let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let sealed = key.seal(a, b"12345678901234567890").unwrap();
        assert_eq!(key.open(a, &sealed).unwrap(), b"12345678901234567890");
        assert!(key.open(b, &sealed).is_err());
        assert!(MfaKey::new(&[8u8; 32]).unwrap().open(a, &sealed).is_err());
        assert!(key.open(a, &sealed[..10]).is_err());
    }

    #[test]
    fn a_recovery_code_hashes_alike_however_it_is_typed() {
        let code = recovery_code().unwrap();
        assert_eq!(code.len(), 27, "{code}");
        let h = recovery_hash(&code).unwrap();
        assert_eq!(
            recovery_hash(&code.to_lowercase().replace('-', " ")),
            Some(h)
        );
        assert_eq!(recovery_hash("not a code"), None);
        assert_ne!(recovery_hash(&recovery_code().unwrap()), Some(h));
    }
}
