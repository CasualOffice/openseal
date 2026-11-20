//! Provider secrets at rest (ADR-046 §3.11): an account's own OAuth client secret, and a
//! session's PKCE verifier and authorization code, sealed with AES-256-GCM under
//! `OPENSEAL_PROVIDER_SECRETS_KEY` (32 bytes, base64), with the key it replaced in a
//! rotation (`OPENSEAL_PROVIDER_SECRETS_PREVIOUS_KEY`) still opening what it sealed, as
//! `OPENSEAL_MFA_KEY` rotates (docs/65).
//!
//! A sealed value is `nonce (12) ‖ ciphertext ‖ tag (16)`. The associated data is
//! `openseal-provider-secret-v1` followed by each binding part, length-prefixed, so a
//! value sealed for one account, provider or session and name does not open for another
//! (moved to another row, it fails).

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::error::CscError;

/// The associated data's fixed prefix.
const CONTEXT: &[u8] = b"openseal-provider-secret-v1";

/// Largest value sealed: a client secret or an authorization code.
pub const MAX_PLAINTEXT: usize = 2048;

/// The key that seals provider secrets. Its `Debug` names nothing.
pub struct ProviderSecretsKey {
    current: LessSafeKey,
    previous: Option<LessSafeKey>,
}

impl core::fmt::Debug for ProviderSecretsKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ProviderSecretsKey(..)")
    }
}

fn aes(bytes: &[u8]) -> Result<LessSafeKey, CscError> {
    if bytes.len() != 32 {
        return Err(CscError::SecretsKey);
    }
    let key = UnboundKey::new(&AES_256_GCM, bytes).map_err(|_| CscError::SecretsKey)?;
    Ok(LessSafeKey::new(key))
}

fn aad(binding: &[&[u8]]) -> Vec<u8> {
    let mut out = CONTEXT.to_vec();
    for part in binding {
        out.extend_from_slice(&u32::try_from(part.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

fn open_with(key: &LessSafeKey, sealed: &[u8], binding: &[&[u8]]) -> Option<Vec<u8>> {
    let (nonce, body) = sealed.split_at_checked(NONCE_LEN)?;
    let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
    let mut buf = body.to_vec();
    let plain = key
        .open_in_place(nonce, Aad::from(aad(binding).as_slice()), &mut buf)
        .ok()?;
    Some(plain.to_vec())
}

impl ProviderSecretsKey {
    /// From 32 key bytes.
    ///
    /// # Errors
    /// `CS-RSP-0009` when the bytes are not an AES-256 key.
    pub fn new(bytes: &[u8]) -> Result<Self, CscError> {
        Ok(Self {
            current: aes(bytes)?,
            previous: None,
        })
    }

    /// This key, also opening values sealed under `previous` (a rotation).
    ///
    /// # Errors
    /// `CS-RSP-0009` when the bytes are not an AES-256 key.
    pub fn with_previous(self, previous: &[u8]) -> Result<Self, CscError> {
        Ok(Self {
            current: self.current,
            previous: Some(aes(previous)?),
        })
    }

    /// From `OPENSEAL_PROVIDER_SECRETS_KEY` (and `…_PREVIOUS_KEY`), each 32 bytes as
    /// base64, read through `casual-sign-secrets` (`NAME` or `NAME_FILE`). `None` when
    /// the key is not set: remote signing then stays off.
    ///
    /// # Errors
    /// `CS-KEY-0005` an unreadable secret; `CS-RSP-0009` a value that is not a key.
    pub fn from_env() -> Result<Option<Self>, CscError> {
        let read = |name: &str| -> Result<Option<Vec<u8>>, CscError> {
            let Some(s) = casual_sign_secrets::env_secret(name).map_err(CscError::Secret)? else {
                return Ok(None);
            };
            STANDARD
                .decode(s.expose().trim())
                .map(Some)
                .map_err(|_| CscError::SecretsKey)
        };
        let Some(current) = read("OPENSEAL_PROVIDER_SECRETS_KEY")? else {
            return Ok(None);
        };
        let key = Self::new(&current)?;
        Ok(Some(
            match read("OPENSEAL_PROVIDER_SECRETS_PREVIOUS_KEY")? {
                Some(p) => key.with_previous(&p)?,
                None => key,
            },
        ))
    }

    /// Seal `plain`, bound to `binding` (account, provider or session, name).
    ///
    /// # Errors
    /// `CS-RSP-0009` when `plain` is empty or longer than [`MAX_PLAINTEXT`], or no
    /// nonce could be drawn.
    pub fn seal(&self, plain: &[u8], binding: &[&[u8]]) -> Result<Vec<u8>, CscError> {
        if plain.is_empty() || plain.len() > MAX_PLAINTEXT {
            return Err(CscError::SecretsKey);
        }
        let mut nonce = [0u8; NONCE_LEN];
        aws_lc_rs::rand::fill(&mut nonce).map_err(|_| CscError::SecretsKey)?;
        let mut buf = plain.to_vec();
        self.current
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad(binding).as_slice()),
                &mut buf,
            )
            .map_err(|_| CscError::SecretsKey)?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&buf);
        Ok(out)
    }

    /// Open a value sealed for `binding`, under the current key or the previous one.
    ///
    /// # Errors
    /// `CS-RSP-0009` when it opens under neither (another row's value, a lost key,
    /// tampering).
    pub fn open(&self, sealed: &[u8], binding: &[&[u8]]) -> Result<Vec<u8>, CscError> {
        open_with(&self.current, sealed, binding)
            .or_else(|| {
                self.previous
                    .as_ref()
                    .and_then(|p| open_with(p, sealed, binding))
            })
            .ok_or(CscError::SecretsKey)
    }
}

/// The binding of an account's own client secret for `provider`.
#[must_use]
pub fn client_secret_binding<'a>(account: &'a [u8], provider: &'a str) -> [&'a [u8]; 3] {
    [account, provider.as_bytes(), b"client_secret"]
}

/// The binding of a session's PKCE verifier or authorization code (`what`).
#[must_use]
pub fn session_binding<'a>(account: &'a [u8], session: &'a [u8], what: &'a str) -> [&'a [u8]; 3] {
    [account, session, what.as_bytes()]
}

#[cfg(test)]
// Tests may unwrap (CLAUDE.md).
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn key(b: u8) -> ProviderSecretsKey {
        ProviderSecretsKey::new(&[b; 32]).unwrap()
    }

    #[test]
    fn a_sealed_secret_opens_only_for_its_own_row() {
        let k = key(7);
        let sealed = k
            .seal(
                b"client-secret",
                &client_secret_binding(b"acct-a", "csc-ci"),
            )
            .unwrap();
        assert!(
            !sealed.windows(13).any(|w| w == b"client-secret"),
            "not in clear"
        );
        assert_eq!(
            k.open(&sealed, &client_secret_binding(b"acct-a", "csc-ci"))
                .unwrap(),
            b"client-secret"
        );
        // Moved to another account's row, or another provider's: it does not open.
        assert!(
            k.open(&sealed, &client_secret_binding(b"acct-b", "csc-ci"))
                .is_err()
        );
        assert!(
            k.open(&sealed, &client_secret_binding(b"acct-a", "csc-other"))
                .is_err()
        );
        // A flipped bit anywhere fails.
        let mut bad = sealed.clone();
        if let Some(last) = bad.last_mut() {
            *last ^= 1;
        }
        assert!(
            k.open(&bad, &client_secret_binding(b"acct-a", "csc-ci"))
                .is_err()
        );
        // Under another key, nothing opens.
        assert!(
            key(8)
                .open(&sealed, &client_secret_binding(b"acct-a", "csc-ci"))
                .is_err()
        );
    }

    #[test]
    fn a_value_sealed_under_the_previous_key_opens_during_a_rotation() {
        let old = key(1);
        let sealed = old.seal(b"v", &[b"x"]).unwrap();
        let rotated = ProviderSecretsKey::new(&[2; 32])
            .unwrap()
            .with_previous(&[1; 32])
            .unwrap();
        assert_eq!(rotated.open(&sealed, &[b"x"]).unwrap(), b"v");
        assert!(
            ProviderSecretsKey::new(&[2; 32])
                .unwrap()
                .open(&sealed, &[b"x"])
                .is_err()
        );
    }

    #[test]
    fn parts_cannot_be_shifted_between_binding_members() {
        let k = key(3);
        let sealed = k.seal(b"v", &[b"ab", b"c"]).unwrap();
        assert!(k.open(&sealed, &[b"a", b"bc"]).is_err());
    }

    #[test]
    fn empty_and_oversized_values_and_short_keys_are_refused() {
        assert!(key(1).seal(b"", &[]).is_err());
        assert!(key(1).seal(&[0u8; MAX_PLAINTEXT + 1], &[]).is_err());
        assert!(ProviderSecretsKey::new(&[0u8; 16]).is_err());
    }
}
