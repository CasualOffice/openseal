//! Secrets the console mints and checks: random tokens and their SHA-256, Argon2id
//! password hashes, and the sealing of TOTP seeds. Primitives come from `aws-lc-rs` and
//! RustCrypto's `argon2` (ADR-006; CLAUDE.md: cryptography is never hand-rolled). The
//! token and Argon2id helpers follow `casual-sign-server`'s `crypto.rs` at `80e293b`.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::digest;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use uuid::Uuid;

use crate::error::ConsoleError;

/// `N` random bytes from the operating system.
///
/// # Errors
/// `CS-CON-0014` when the system's generator fails.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], ConsoleError> {
    let mut out = [0u8; N];
    SystemRandom::new()
        .fill(&mut out)
        .map_err(|_| ConsoleError::Internal("random"))?;
    Ok(out)
}

/// A 256-bit random secret as base64url text (43 characters).
///
/// # Errors
/// As [`random_bytes`].
pub fn random_secret() -> Result<String, ConsoleError> {
    Ok(URL_SAFE_NO_PAD.encode(random_bytes::<32>()?))
}

/// SHA-256 of a secret's text, the only form in which secrets are stored.
#[must_use]
pub fn sha256(text: &[u8]) -> [u8; 32] {
    let d = digest::digest(&digest::SHA256, text);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// Constant-time equality of two hashes.
#[must_use]
pub fn same(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Argon2id with OWASP's second recommended configuration (19 MiB, 2 passes, 1 lane), as
/// the server's staff passwords.
fn argon() -> Result<Argon2<'static>, ConsoleError> {
    let params =
        Params::new(19 * 1024, 2, 1, None).map_err(|_| ConsoleError::Internal("argon2"))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// The Argon2id PHC string of a password, with a fresh random salt.
///
/// # Errors
/// `CS-CON-0014` when hashing fails.
pub fn hash_password(secret: &str) -> Result<String, ConsoleError> {
    let salt_bytes = random_bytes::<16>()?;
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|_| ConsoleError::Internal("salt"))?;
    argon()?
        .hash_password(secret.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| ConsoleError::Internal("argon2"))
}

/// Whether `secret` matches the PHC string. A malformed stored string never matches.
#[must_use]
pub fn verify_password(secret: &str, phc: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    argon().is_ok_and(|a| a.verify_password(secret.as_bytes(), &parsed).is_ok())
}

/// Shortest operator password accepted (characters).
pub const MIN_PASSWORD_CHARS: usize = 12;
/// Longest operator password accepted (bytes): bounds Argon2's input.
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// Whether `p` is an acceptable new operator password: 12 characters to 1 KiB.
#[must_use]
pub fn password_acceptable(p: &str) -> bool {
    p.chars().count() >= MIN_PASSWORD_CHARS && p.len() <= MAX_PASSWORD_BYTES
}

/// The key that seals operators' TOTP seeds at rest (AES-256-GCM), from
/// `OPENSEAL_CONSOLE_MFA_KEY` through `casual-sign-secrets`. The database holds only the
/// sealed seed; the key never reaches it.
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
    /// `CS-CON-0014` when the bytes are not an AES-256 key.
    pub fn new(bytes: &[u8]) -> Result<Self, ConsoleError> {
        if bytes.len() != 32 {
            return Err(ConsoleError::Internal("mfa key length"));
        }
        let key =
            UnboundKey::new(&AES_256_GCM, bytes).map_err(|_| ConsoleError::Internal("mfa key"))?;
        Ok(Self(LessSafeKey::new(key)))
    }

    /// Seal `seed` for `operator`: nonce, ciphertext, tag. The operator id is the
    /// associated data, so a sealed seed copied to another operator's row does not open.
    ///
    /// # Errors
    /// `CS-CON-0014` when sealing fails.
    pub fn seal(&self, operator: Uuid, seed: &[u8]) -> Result<Vec<u8>, ConsoleError> {
        let nonce_bytes = random_bytes::<NONCE_LEN>()?;
        let mut buf = seed.to_vec();
        self.0
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(operator.as_bytes()),
                &mut buf,
            )
            .map_err(|_| ConsoleError::Internal("seal"))?;
        let mut out = nonce_bytes.to_vec();
        out.extend_from_slice(&buf);
        Ok(out)
    }

    /// Open a sealed seed of `operator`.
    ///
    /// # Errors
    /// `CS-CON-0014` when it does not open (wrong key, wrong operator, altered bytes).
    pub fn open(&self, operator: Uuid, sealed: &[u8]) -> Result<Vec<u8>, ConsoleError> {
        let bad = || ConsoleError::Internal("mfa seed does not open");
        let (nonce, body) = sealed.split_at_checked(NONCE_LEN).ok_or_else(bad)?;
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| bad())?;
        let mut buf = body.to_vec();
        let plain = self
            .0
            .open_in_place(nonce, Aad::from(operator.as_bytes()), &mut buf)
            .map_err(|_| bad())?;
        Ok(plain.to_vec())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // tests may unwrap (CLAUDE.md)
mod tests {
    use super::*;

    #[test]
    fn a_sealed_seed_opens_only_for_its_operator_and_key() {
        let key = MfaKey::new(&[7u8; 32]).unwrap();
        let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let sealed = key.seal(a, b"12345678901234567890").unwrap();
        assert_eq!(key.open(a, &sealed).unwrap(), b"12345678901234567890");
        assert!(key.open(b, &sealed).is_err());
        assert!(MfaKey::new(&[8u8; 32]).unwrap().open(a, &sealed).is_err());
        let mut altered = sealed.clone();
        *altered.last_mut().unwrap() ^= 1;
        assert!(key.open(a, &altered).is_err());
        assert!(MfaKey::new(&[1u8; 16]).is_err());
    }

    #[test]
    fn passwords_hash_and_verify() {
        let phc = hash_password("correct horse battery").unwrap();
        assert!(phc.starts_with("$argon2id$"));
        assert!(verify_password("correct horse battery", &phc));
        assert!(!verify_password("wrong", &phc));
        assert!(!verify_password("x", "not a phc"));
        assert!(!password_acceptable("short"));
        assert!(password_acceptable("twelve chars"));
    }
}
