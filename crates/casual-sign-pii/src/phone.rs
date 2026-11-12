//! Phone numbers, validated with libphonenumber's metadata through the `phonenumber`
//! crate, as Presidio's `PhoneRecognizer` does through Python `phonenumbers`.
//!
//! Presidio runs libphonenumber's `PhoneNumberMatcher` (leniency 1, "valid") for each of
//! its default regions. The Rust port has no matcher, so candidates come from a pattern
//! of digits and separators; each must hold 7 to 15 digits (E.164's maximum), must not
//! be shaped like a date or an IPv4 address (the matcher's own date exclusion), and
//! must parse as a valid number: with a leading `+` under its own country code,
//! otherwise under the first of Presidio's regions for which it is valid.
//!
//! The crate is handed only these short ASCII candidates, never the document text.

use std::sync::LazyLock;

use phonenumber::country::Id;
use regex::Regex;

/// Presidio's `PhoneRecognizer.SCORE`, in thousandths.
pub(crate) const SCORE: u16 = 400;

/// Presidio's `DEFAULT_SUPPORTED_REGIONS`, in its order.
const REGIONS: [Id; 8] = [
    Id::US,
    Id::GB,
    Id::DE,
    Id::FR,
    Id::IL,
    Id::IN,
    Id::CA,
    Id::BR,
];

static NOT_A_PHONE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r"(?-u)^(?:[0-9]{1,4}[/.\-][0-9]{1,2}[/.\-][0-9]{2,4}|[0-9]{1,3}(?:\.[0-9]{1,3}){3})$",
    )
    .ok()
});

/// Whether a candidate (ASCII digits, spaces, `+().-`) is a valid phone number.
pub(crate) fn valid(candidate: &str) -> bool {
    let digits = candidate.bytes().filter(u8::is_ascii_digit).count();
    if !(7..=15).contains(&digits) || !candidate.is_ascii() {
        return false;
    }
    if NOT_A_PHONE.as_ref().is_none_or(|re| re.is_match(candidate)) {
        return false;
    }
    if candidate.starts_with('+') {
        return phonenumber::parse(None, candidate).is_ok_and(|n| phonenumber::is_valid(&n));
    }
    let trunk = candidate.trim_start_matches('(').starts_with('0');
    REGIONS.iter().any(|&region| {
        (trunk || !TRUNK_REQUIRED.contains(&region))
            && phonenumber::parse(Some(region), candidate).is_ok_and(|n| phonenumber::is_valid(&n))
    })
}

/// Regions whose national numbers are written with the trunk prefix 0, so a number
/// without it is not one of theirs. Stands in for the matcher's
/// `isNationalPrefixPresentIfRequired` check (leniency "valid"), which the Rust port
/// lacks: their formats' national-prefix rules are "0$1" and not optional. US and CA
/// (prefix 1, optional), IN and BR (optional for mobiles) are not listed. Without it,
/// order and invoice numbers read as German or French numbers.
const TRUNK_REQUIRED: [Id; 4] = [Id::GB, Id::DE, Id::FR, Id::IL];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fictional_numbers_are_valid() {
        assert!(valid("(202) 555-0123"));
        assert!(valid("+44 20 7946 0958"));
        assert!(valid("020 7946 0958"));
        assert!(valid("+61 491 570 156"));
    }

    #[test]
    fn dates_addresses_and_short_runs_are_not() {
        assert!(!valid("12-05-2024"));
        assert!(!valid("2024.05.12"));
        assert!(!valid("192.168.100.200"));
        assert!(!valid("12 34"));
        assert!(!valid("+0 000 000 000"));
        assert!(!valid("1234567890123456"));
    }
}
