//! IBAN formats per country, from Presidio's `iban_patterns.py` (MIT), written as runs
//! of a character class: `n` digit, `a` upper-case letter, `c` letter or digit, `z` the
//! digit 0. Each spec covers the BBAN, after the country code and check digits.
//!
//! Departure: Presidio 2.2.364 gives Portugal 17 digits; the IBAN registry gives 21
//! (`PT50 0002 0123 1234 5678 9015 4`), so PT is corrected here. Every other length was
//! checked against the registry's IBAN lengths.

const FORMATS: &[(&[u8; 2], &str)] = &[
    (b"AL", "8n16c"),
    (b"AD", "8n12c"),
    (b"AT", "16n"),
    (b"AZ", "4c20n"),
    (b"BH", "4a14c"),
    (b"BY", "4c4n16c"),
    (b"BE", "12n"),
    (b"BA", "16n"),
    (b"BR", "23n1a1c"),
    (b"BG", "4a6n8c"),
    (b"CR", "1z17n"),
    (b"HR", "17n"),
    (b"CY", "8n16c"),
    (b"CZ", "20n"),
    (b"DK", "14n"),
    (b"DO", "4a20n"),
    (b"TL", "19n"),
    (b"EE", "16n"),
    (b"FO", "14n"),
    (b"FI", "14n"),
    (b"FR", "10n11c2n"),
    (b"GE", "2c16n"),
    (b"DE", "18n"),
    (b"GI", "4a15c"),
    (b"GR", "7n16c"),
    (b"GL", "14n"),
    (b"GT", "24c"),
    (b"HU", "24n"),
    (b"IS", "22n"),
    (b"IE", "4c14n"),
    (b"IL", "19n"),
    (b"IT", "1a10n12c"),
    (b"JO", "4a22n"),
    (b"KZ", "3n13c"),
    (b"XK", "16n"),
    (b"KW", "4a22c"),
    (b"LV", "4a13c"),
    (b"LB", "4n20c"),
    (b"LI", "5n12c"),
    (b"LT", "16n"),
    (b"LU", "3n13c"),
    (b"MT", "4a5n18c"),
    (b"MR", "23n"),
    (b"MU", "4a19n1a"),
    (b"MD", "20c"),
    (b"MC", "10n11c2n"),
    (b"ME", "18n"),
    (b"NL", "4a10n"),
    (b"MK", "3n10c2n"),
    (b"NO", "11n"),
    (b"PK", "4c16n"),
    (b"PS", "4c17n"),
    (b"PL", "24n"),
    (b"PT", "21n"),
    (b"QA", "4a17c"),
    (b"RO", "4a16c"),
    (b"SM", "1a10n12c"),
    (b"SA", "2n18c"),
    (b"RS", "18n"),
    (b"SK", "20n"),
    (b"SI", "15n"),
    (b"ES", "20n"),
    (b"SE", "20n"),
    (b"CH", "5n12c"),
    (b"TN", "20n"),
    (b"TR", "5n17c"),
    (b"AE", "19n"),
    (b"GB", "4a14n"),
    (b"VA", "18n"),
    (b"VG", "4c16n"),
    (b"EG", "25n"),
    (b"IQ", "4a15n"),
    (b"LY", "21n"),
    (b"LC", "4a24c"),
    (b"SC", "4a20n3a"),
    (b"UA", "6n19c"),
];

fn spec(country: &[u8]) -> Option<&'static str> {
    FORMATS
        .iter()
        .find(|(cc, _)| cc.as_slice() == country)
        .map(|(_, s)| *s)
}

/// Runs of (count, class) from a spec such as `"4a14n"`.
fn runs(spec: &str) -> impl Iterator<Item = (usize, u8)> + '_ {
    let mut n: usize = 0;
    spec.bytes().filter_map(move |b| {
        if b.is_ascii_digit() {
            n = n
                .saturating_mul(10)
                .saturating_add(usize::from(b.wrapping_sub(b'0')));
            None
        } else {
            let run = (n, b);
            n = 0;
            Some(run)
        }
    })
}

/// The full IBAN length for a country code, if the country uses IBANs.
pub(crate) fn length(country: &[u8]) -> Option<usize> {
    spec(country).map(|s| runs(s).map(|(n, _)| n).sum::<usize>().saturating_add(4))
}

/// Whether a compact IBAN's BBAN fits its country's format (length included).
pub(crate) fn format_ok(iban: &[u8]) -> bool {
    let (Some(country), Some(bban)) = (iban.get(..2), iban.get(4..)) else {
        return false;
    };
    let Some(spec) = spec(country) else {
        return false;
    };
    let mut chars = bban.iter();
    for (n, class) in runs(spec) {
        for _ in 0..n {
            let Some(&b) = chars.next() else { return false };
            let ok = match class {
                b'n' => b.is_ascii_digit(),
                b'a' => b.is_ascii_uppercase(),
                b'z' => b == b'0',
                _ => b.is_ascii_digit() || b.is_ascii_uppercase(),
            };
            if !ok {
                return false;
            }
        }
    }
    chars.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_match_the_iban_registry() {
        let registry: &[(&[u8], usize)] = &[
            (b"AL", 28),
            (b"AD", 24),
            (b"AT", 20),
            (b"BE", 16),
            (b"BR", 29),
            (b"CH", 21),
            (b"CR", 22),
            (b"DE", 22),
            (b"ES", 24),
            (b"FR", 27),
            (b"GB", 22),
            (b"IE", 22),
            (b"IT", 27),
            (b"LC", 32),
            (b"MT", 31),
            (b"NL", 18),
            (b"NO", 15),
            (b"PL", 28),
            (b"PT", 25),
            (b"SC", 31),
            (b"SE", 24),
            (b"UA", 29),
        ];
        for (cc, len) in registry {
            assert_eq!(length(cc), Some(*len), "{}", String::from_utf8_lossy(cc));
        }
        assert_eq!(length(b"US"), None);
    }

    #[test]
    fn format_checks_classes_and_length() {
        assert!(format_ok(b"GB82WEST12345698765432"));
        assert!(!format_ok(b"GB82WES712345698765432"));
        assert!(!format_ok(b"GB82WEST1234569876543"));
        assert!(!format_ok(b"GB82WEST123456987654321"));
        assert!(format_ok(b"CR05015202001026284066"));
        assert!(!format_ok(b"CR05115202001026284066"));
        assert!(!format_ok(b"XX"));
    }
}
