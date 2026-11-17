//! Seal tokens (`KEYD-02`, ADR-036, `SEC-S05`): keyd signs for an envelope only when the
//! request carries the database's word that the envelope owes a seal.
//!
//! The database mints a token in `openseal_keyd_seal_token` (migration 0040): an
//! HMAC-SHA-256 over [`seal_token_message`] for the envelope and an expiry ten minutes
//! ahead, under a key the application role cannot read, and only while the envelope is
//! `completing` or has ended (declined, voided, expired) without its envelope
//! certificate. The worker carries it; keyd holds the same key and verifies it here. A
//! compromised worker or server can therefore get signatures only for an envelope the
//! database says owes one, never for a digest under an envelope id of its choosing;
//! putting an envelope into that state leaves its trace in the database, and every
//! signature is still matched against the seals recorded (`KEYD-03`).
//!
//! The MAC is computed and compared by aws-lc-rs (ADR-006), in constant time.

use aws_lc_rs::hmac;
use casual_sign_keyd_client::wire::{SEAL_TOKEN_MAC, SealToken, seal_token_message};

use crate::error::KeydError;

/// Longest a token may still have to live when keyd sees it: the database mints ten
/// minutes; five more allow for clock skew between the database and keyd.
pub const MAX_TOKEN_LIFETIME_S: u64 = 15 * 60;

/// Length of the token key.
pub const SEAL_TOKEN_KEY_LEN: usize = 32;

/// The key keyd and the database share to mint and verify seal tokens. Never logged:
/// `Debug` prints nothing of it.
pub struct SealTokenKey(hmac::Key);

impl core::fmt::Debug for SealTokenKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SealTokenKey(..)")
    }
}

impl SealTokenKey {
    /// The key from its 32 bytes.
    ///
    /// # Errors
    /// `CS-KEY-0012` (`OPENSEAL_KEYD_SEAL_TOKEN_KEY`) for any other length.
    pub fn new(bytes: &[u8]) -> Result<Self, KeydError> {
        if bytes.len() != SEAL_TOKEN_KEY_LEN {
            return Err(KeydError::Setting("OPENSEAL_KEYD_SEAL_TOKEN_KEY"));
        }
        Ok(Self(hmac::Key::new(hmac::HMAC_SHA256, bytes)))
    }

    /// The key from 64 hex digits (surrounding white space ignored), as the operator's
    /// secret file holds it.
    ///
    /// # Errors
    /// `CS-KEY-0012` (`OPENSEAL_KEYD_SEAL_TOKEN_KEY`) for anything else.
    pub fn from_hex(text: &str) -> Result<Self, KeydError> {
        let t = text.trim();
        let bad = || KeydError::Setting("OPENSEAL_KEYD_SEAL_TOKEN_KEY");
        if t.len() != SEAL_TOKEN_KEY_LEN.saturating_mul(2) {
            return Err(bad());
        }
        let bytes = (0..t.len())
            .step_by(2)
            .map(|i| {
                t.get(i..i.saturating_add(2))
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
            })
            .collect::<Option<Vec<u8>>>()
            .ok_or_else(bad)?;
        Self::new(&bytes)
    }

    /// The token for `envelope` expiring at `expires` (Unix seconds), as the database
    /// mints it: for tests and tooling; keyd itself only verifies.
    #[must_use]
    pub fn mint(&self, envelope: &str, expires: u64) -> SealToken {
        SealToken {
            expires,
            mac: hmac::sign(&self.0, &seal_token_message(envelope, expires))
                .as_ref()
                .to_vec(),
        }
    }

    /// Whether `token` lets keyd sign for `envelope` at `now` (Unix seconds): present,
    /// for a named envelope, not expired, not living longer than
    /// [`MAX_TOKEN_LIFETIME_S`], and its MAC this key's over that envelope and expiry.
    ///
    /// # Errors
    /// `CS-KEY-0015` otherwise.
    pub fn check(
        &self,
        envelope: &str,
        token: Option<&SealToken>,
        now: u64,
    ) -> Result<(), KeydError> {
        let t = token.ok_or(KeydError::SealRefused)?;
        if envelope.is_empty()
            || t.mac.len() != SEAL_TOKEN_MAC
            || now > t.expires
            || t.expires.saturating_sub(now) > MAX_TOKEN_LIFETIME_S
        {
            return Err(KeydError::SealRefused);
        }
        hmac::verify(&self.0, &seal_token_message(envelope, t.expires), &t.mac)
            .map_err(|_| KeydError::SealRefused)
    }
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report.
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
    use super::*;

    const ENV: &str = "0192f3a4-0000-7000-8000-000000000001";

    #[test]
    fn a_token_for_the_envelope_within_its_life_is_accepted_and_nothing_else_is() {
        let key = SealTokenKey::new(&[7; 32]).unwrap();
        let now = 1_800_000_000;
        let good = key.mint(ENV, now + 600);
        key.check(ENV, Some(&good), now).unwrap();
        key.check(ENV, Some(&good), now + 600).unwrap();
        let refused = |t: Option<&SealToken>, env: &str, at: u64| {
            assert_eq!(key.check(env, t, at).unwrap_err().code(), "CS-KEY-0015");
        };
        refused(None, ENV, now);
        refused(Some(&good), ENV, now + 601);
        refused(Some(&good), "0192f3a4-0000-7000-8000-000000000002", now);
        refused(Some(&good), "", now);
        let long = key.mint(ENV, now + MAX_TOKEN_LIFETIME_S + 1);
        refused(Some(&long), ENV, now);
        let other = SealTokenKey::new(&[8; 32]).unwrap().mint(ENV, now + 600);
        refused(Some(&other), ENV, now);
        let mut later = good.clone();
        later.expires += 1;
        refused(Some(&later), ENV, now);
        let mut short = good;
        short.mac.pop();
        refused(Some(&short), ENV, now);
    }

    #[test]
    fn the_key_loads_from_64_hex_digits_only() {
        assert!(SealTokenKey::from_hex(&format!("{}\n", "ab".repeat(32))).is_ok());
        for bad in ["", "ab", &"zz".repeat(32), &"ab".repeat(33)] {
            assert_eq!(
                SealTokenKey::from_hex(bad).unwrap_err().code(),
                "CS-KEY-0012"
            );
        }
        assert_eq!(
            format!("{:?}", SealTokenKey::new(&[1; 32]).unwrap()),
            "SealTokenKey(..)"
        );
    }
}
