//! Time-based one-time passwords, RFC 6238 over RFC 4226 (docs/23 §5.1).
//!
//! The HMAC is `aws-lc-rs`'s (ADR-006); this module only does what the RFCs define on
//! top of it: the time step, the dynamic truncation and the decimal code. Operators use
//! SHA-1, 6 digits and 30-second steps, which every authenticator app supports; the
//! other algorithms and lengths exist for the RFC's test vectors. A code is checked
//! against the steps one before and one after now (clock drift); the database makes each
//! step single-use per operator.

use aws_lc_rs::hmac;

/// Seconds per step (RFC 6238 §4.1, the default `X`).
pub const STEP_SECONDS: u64 = 30;
/// Digits in an operator's code.
pub const DIGITS: u32 = 6;
/// Bytes in an operator's seed (160 bits, RFC 4226 §4 R6).
pub const SEED_BYTES: usize = 20;

/// The HMAC behind a code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// HMAC-SHA-1, what authenticator apps use.
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

impl Algorithm {
    fn hmac(self) -> hmac::Algorithm {
        match self {
            Self::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            Self::Sha256 => hmac::HMAC_SHA256,
            Self::Sha512 => hmac::HMAC_SHA512,
        }
    }
}

/// The time step containing Unix time `unix` (seconds; before 1970 counts as step 0).
#[must_use]
pub fn step_at(unix: i64) -> u64 {
    u64::try_from(unix).unwrap_or(0) / STEP_SECONDS
}

/// The HOTP value (RFC 4226 §5.3) for `counter`, as a number below `10^digits`.
/// `digits` is clamped to 6..=9.
#[must_use]
pub fn hotp(alg: Algorithm, key: &[u8], counter: u64, digits: u32) -> u32 {
    let tag = hmac::sign(&hmac::Key::new(alg.hmac(), key), &counter.to_be_bytes());
    let mac = tag.as_ref();
    // Dynamic truncation: the low four bits of the last byte give the offset of four
    // bytes, read big-endian with the top bit cleared. Every HMAC here is at least 20
    // bytes, so offset + 4 <= 19 is in range; `get` keeps it panic-free regardless.
    let offset = mac.last().map_or(0, |b| usize::from(b & 0x0f));
    let word = mac
        .get(offset..offset.saturating_add(4))
        .and_then(|w| <[u8; 4]>::try_from(w).ok())
        .map_or(0, |w| u32::from_be_bytes(w) & 0x7fff_ffff);
    let modulus = 10u32.checked_pow(digits.clamp(6, 9)).unwrap_or(1_000_000);
    word.checked_rem(modulus).unwrap_or(0)
}

/// An operator's code for `step`, as six digits.
#[must_use]
pub fn code(key: &[u8], step: u64) -> String {
    format!("{:06}", hotp(Algorithm::Sha1, key, step, DIGITS))
}

/// The step in `now_step - 1 ..= now_step + 1` whose code is `entered`, if any. The
/// comparison does not stop at the first differing digit.
#[must_use]
pub fn matching_step(key: &[u8], entered: &str, now_step: u64) -> Option<u64> {
    if entered.len() != 6 || !entered.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut found = None;
    for step in [
        now_step.checked_sub(1),
        Some(now_step),
        now_step.checked_add(1),
    ]
    .into_iter()
    .flatten()
    {
        let expected = code(key, step);
        let diff = expected
            .bytes()
            .zip(entered.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        if diff == 0 && found.is_none() {
            found = Some(step);
        }
    }
    found
}

/// RFC 4648 base32 without padding, for the `otpauth://` URI an authenticator scans.
#[must_use]
pub fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &b in bytes {
        buffer = (buffer << 8) | u32::from(b);
        bits = bits.saturating_add(8);
        while bits >= 5 {
            bits = bits.saturating_sub(5);
            let index = usize::try_from((buffer >> bits) & 31).unwrap_or(0);
            out.push(char::from(ALPHABET.get(index).copied().unwrap_or(b'A')));
        }
        buffer &= (1u32 << bits).wrapping_sub(1);
    }
    if bits > 0 {
        let index = usize::try_from((buffer << (5u32.saturating_sub(bits))) & 31).unwrap_or(0);
        out.push(char::from(ALPHABET.get(index).copied().unwrap_or(b'A')));
    }
    out
}

/// The enrolment URI for an operator's authenticator. The label is "OpenSeal console"
/// and the operator id, never the e-mail.
#[must_use]
pub fn otpauth_uri(seed: &[u8], operator: uuid::Uuid) -> String {
    format!(
        "otpauth://totp/OpenSeal%20console:{operator}?secret={}&issuer=OpenSeal%20console&algorithm=SHA1&digits=6&period=30",
        base32(seed)
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // tests may unwrap (CLAUDE.md)
mod tests {
    use super::*;

    // RFC 6238 Appendix B: the seeds are the ASCII digits "1234567890" repeated to the
    // HMAC's key length.
    const SEED20: &[u8] = b"12345678901234567890";
    const SEED32: &[u8] = b"12345678901234567890123456789012";
    const SEED64: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    #[test]
    fn rfc6238_appendix_b_vectors() {
        let table: [(i64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];
        for (t, sha1, sha256, sha512) in table {
            let step = step_at(t);
            let got = |alg, key| format!("{:08}", hotp(alg, key, step, 8));
            assert_eq!(got(Algorithm::Sha1, SEED20), sha1, "SHA-1 at {t}");
            assert_eq!(got(Algorithm::Sha256, SEED32), sha256, "SHA-256 at {t}");
            assert_eq!(got(Algorithm::Sha512, SEED64), sha512, "SHA-512 at {t}");
        }
    }

    #[test]
    fn rfc4226_appendix_d_six_digit_codes() {
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, want) in (0u64..).zip(expected) {
            assert_eq!(code(SEED20, counter), want);
        }
    }

    #[test]
    fn a_code_matches_only_its_own_step_and_the_neighbours() {
        let now = step_at(1_234_567_890);
        for (delta, ok) in [(-2i64, false), (-1, true), (0, true), (1, true), (2, false)] {
            let s = now.checked_add_signed(delta).unwrap();
            let entered = code(SEED20, s);
            assert_eq!(
                matching_step(SEED20, &entered, now) == Some(s),
                ok,
                "delta {delta}"
            );
        }
        assert_eq!(matching_step(SEED20, "12345", now), None);
        assert_eq!(matching_step(SEED20, "12345a", now), None);
    }

    #[test]
    fn base32_matches_rfc4648_vectors() {
        for (input, want) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(base32(input.as_bytes()), want);
        }
    }
}
