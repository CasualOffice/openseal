//! Breached and common passwords (ASVS-02, ASVS 2.1.7, NIST SP 800-63B §5.1.1.2): a
//! password a staff user sets, changes or resets is refused when it is on a list of
//! passwords seen in breaches, checked offline against a list bundled in the binary.
//!
//! The list is `data/common-passwords.txt`: the 1,000,000 most common passwords of the
//! Xato corpus as SecLists publishes them (MIT, `data/LICENSE-SECLISTS`), lower-cased,
//! and only those of 12 to 256 characters kept, since shorter ones are refused anyway;
//! `data/PROVENANCE.md` records the source and how the file was made. The comparison
//! ignores case, so `Password1234` is refused as `password1234` is.

use std::collections::HashSet;
use std::sync::LazyLock;

/// The bundled list, one lower-case password per line.
const LIST: &str = include_str!("../data/common-passwords.txt");

static COMMON: LazyLock<HashSet<&'static str>> = LazyLock::new(|| LIST.lines().collect());

/// Whether `password`, ignoring case, is on the bundled list of breached passwords.
pub(crate) fn is_common(password: &str) -> bool {
    COMMON.contains(password.to_lowercase().as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listed_passwords_are_common_whatever_their_case() {
        assert!(is_common("password1234"));
        assert!(is_common("PassWord1234"));
        assert!(is_common("123456789012"));
    }

    #[test]
    fn an_unlisted_passphrase_is_not_common() {
        assert!(!is_common("reset test password 2026"));
        assert!(!is_common(""));
    }

    #[test]
    fn the_list_is_lower_case_and_within_the_length_limits() {
        assert!(COMMON.len() > 40_000);
        for p in LIST.lines() {
            assert_eq!(p, p.to_lowercase());
            assert!((12..=256).contains(&p.chars().count()), "{} chars", p.len());
        }
    }
}
