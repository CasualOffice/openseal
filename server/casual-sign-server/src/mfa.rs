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
///
/// During a rotation (`HRD-12`, docs/65 §Rotation) it also holds the key it replaced,
/// `OPENSEAL_MFA_PREVIOUS_KEY`: a seed opens under either, and one opened under the
/// previous key is re-sealed under the current one ([`MfaKey::reseal`]), so every seed
/// ends under the new key and the old one can be retired.
pub struct MfaKey {
    current: LessSafeKey,
    previous: Option<LessSafeKey>,
}

impl core::fmt::Debug for MfaKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MfaKey(..)")
    }
}

/// A sealed seed, opened by [`MfaKey::open`].
pub(crate) struct Opened {
    /// The seed.
    pub(crate) seed: Vec<u8>,
    /// The seed sealed again under the current key, when it opened only under the
    /// previous one: what the caller stores in its place.
    pub(crate) resealed: Option<Vec<u8>>,
}

/// What [`MfaKey::reseal`] made of one sealed seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reseal {
    /// Already under the current key: nothing to do.
    Current,
    /// It opened under the previous key; this is the same seed sealed under the current
    /// one, to replace it.
    Resealed(Vec<u8>),
    /// It opens under neither key (sealed under a lost key, or not this user's): only a
    /// recovery code or a new enrolment helps that user.
    Unopened,
}

/// What `casual-sign-server mfa-reseal` did ([`reseal_all`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResealReport {
    /// Seeds moved from the previous key to the current one.
    pub resealed: usize,
    /// Seeds already under the current key.
    pub current: usize,
    /// Seeds that open under neither key.
    pub unopened: usize,
    /// Seeds changed by their user between the read and the re-seal (re-enrolled, or
    /// re-sealed on use meanwhile): left as they are.
    pub changed: usize,
}

fn aes_key(bytes: &[u8]) -> Result<LessSafeKey, ApiError> {
    if bytes.len() != 32 {
        return Err(ApiError::internal("mfa key length"));
    }
    let key = UnboundKey::new(&AES_256_GCM, bytes).map_err(|_| ApiError::internal("mfa key"))?;
    Ok(LessSafeKey::new(key))
}

fn open_with(key: &LessSafeKey, user: Uuid, sealed: &[u8]) -> Option<Vec<u8>> {
    let (nonce, body) = sealed.split_at_checked(NONCE_LEN)?;
    let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
    let mut buf = body.to_vec();
    let plain = key
        .open_in_place(nonce, Aad::from(user.as_bytes()), &mut buf)
        .ok()?;
    Some(plain.to_vec())
}

impl MfaKey {
    /// From 32 key bytes.
    ///
    /// # Errors
    ///
    /// `CS-API-0010` when the bytes are not an AES-256 key.
    pub fn new(bytes: &[u8]) -> Result<Self, ApiError> {
        Ok(Self {
            current: aes_key(bytes)?,
            previous: None,
        })
    }

    /// This key, also opening seeds sealed under `previous` (32 bytes), the key it
    /// replaces in a rotation (`OPENSEAL_MFA_PREVIOUS_KEY`).
    ///
    /// # Errors
    ///
    /// `CS-API-0010` when the bytes are not an AES-256 key.
    pub fn with_previous(self, previous: &[u8]) -> Result<Self, ApiError> {
        Ok(Self {
            current: self.current,
            previous: Some(aes_key(previous)?),
        })
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
        self.current
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

    /// Open a sealed seed of `user`: under the current key, else under the previous one,
    /// in which case [`Opened::resealed`] is the seed sealed under the current key.
    pub(crate) fn open(&self, user: Uuid, sealed: &[u8]) -> Result<Opened, ApiError> {
        if let Some(seed) = open_with(&self.current, user, sealed) {
            return Ok(Opened {
                seed,
                resealed: None,
            });
        }
        let seed = self
            .previous
            .as_ref()
            .and_then(|p| open_with(p, user, sealed))
            .ok_or_else(|| ApiError::internal("mfa seed does not open"))?;
        let resealed = Some(self.seal(user, &seed)?);
        Ok(Opened { seed, resealed })
    }

    /// What a sealed seed of `user` needs to end under the current key (`HRD-12`).
    ///
    /// # Errors
    ///
    /// `CS-API-0010` when the system's generator fails.
    pub fn reseal(&self, user: Uuid, sealed: &[u8]) -> Result<Reseal, ApiError> {
        if open_with(&self.current, user, sealed).is_some() {
            return Ok(Reseal::Current);
        }
        match self
            .previous
            .as_ref()
            .and_then(|p| open_with(p, user, sealed))
        {
            Some(seed) => Ok(Reseal::Resealed(self.seal(user, &seed)?)),
            None => Ok(Reseal::Unopened),
        }
    }
}

/// `casual-sign-server mfa-reseal` (`HRD-12`): every staff seed still under the previous
/// key re-sealed under the current one, through `store` as the schema owner. Each is
/// replaced only if it is still the value read, so a user re-enrolling or signing in
/// meanwhile wins.
///
/// # Errors
///
/// The store's, or `CS-API-0010` when the system's generator fails.
pub async fn reseal_all(
    store: &casual_sign_store::Store,
    key: &MfaKey,
) -> Result<ResealReport, ApiError> {
    let mut report = ResealReport::default();
    for (user, sealed) in store.totp_seeds().await? {
        match key.reseal(user.0, &sealed)? {
            Reseal::Current => report.current = report.current.saturating_add(1),
            Reseal::Unopened => report.unopened = report.unopened.saturating_add(1),
            Reseal::Resealed(new) => {
                if store.reseal_totp_seed(user, &sealed, &new).await? {
                    report.resealed = report.resealed.saturating_add(1);
                } else {
                    report.changed = report.changed.saturating_add(1);
                }
            }
        }
    }
    Ok(report)
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
        assert_eq!(key.open(a, &sealed).unwrap().seed, b"12345678901234567890");
        assert!(key.open(a, &sealed).unwrap().resealed.is_none());
        assert!(key.open(b, &sealed).is_err());
        assert!(MfaKey::new(&[8u8; 32]).unwrap().open(a, &sealed).is_err());
        assert!(key.open(a, &sealed[..10]).is_err());
    }

    #[test]
    fn a_seed_under_the_previous_key_opens_and_is_resealed_under_the_new_one() {
        let (old, new) = ([7u8; 32], [9u8; 32]);
        let a = Uuid::from_u128(1);
        let sealed = MfaKey::new(&old)
            .unwrap()
            .seal(a, b"seed-seed-seed")
            .unwrap();
        let rotated = MfaKey::new(&new).unwrap().with_previous(&old).unwrap();
        let opened = rotated.open(a, &sealed).unwrap();
        assert_eq!(opened.seed, b"seed-seed-seed");
        let resealed = opened.resealed.unwrap();
        // The new value opens under the new key alone, and is the same seed.
        let only_new = MfaKey::new(&new).unwrap();
        assert_eq!(only_new.open(a, &resealed).unwrap().seed, b"seed-seed-seed");
        assert!(only_new.open(a, &sealed).is_err());
        assert_eq!(rotated.reseal(a, &resealed).unwrap(), Reseal::Current);
        assert!(matches!(
            rotated.reseal(a, &sealed).unwrap(),
            Reseal::Resealed(_)
        ));
        // Another user's seed, or a third key's, opens under neither.
        assert_eq!(
            rotated.reseal(Uuid::from_u128(2), &sealed).unwrap(),
            Reseal::Unopened
        );
        let third = MfaKey::new(&[3u8; 32]).unwrap().seal(a, b"x").unwrap();
        assert_eq!(rotated.reseal(a, &third).unwrap(), Reseal::Unopened);
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
