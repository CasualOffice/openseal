//! Check-digit algorithms. Each takes ASCII digits (or, for IBAN, ASCII alphanumerics)
//! and returns `false`, never panics, on anything else.
//!
//! Luhn and Verhoeff follow Presidio's `CreditCardRecognizer` and
//! `InAadhaarRecognizer`; mod-97 follows ISO 13616 as Presidio's `IbanRecognizer` does,
//! computed piecewise so no big integer is needed.

/// Luhn (ISO/IEC 7812-1) over ASCII digits, check digit last.
pub(crate) fn luhn(digits: &[u8]) -> bool {
    if digits.is_empty() {
        return false;
    }
    // A doubled digit's digit sum, by digit.
    const DOUBLED: [u32; 10] = [0, 2, 4, 6, 8, 1, 3, 5, 7, 9];
    let mut sum: u32 = 0;
    for (i, &b) in digits.iter().rev().enumerate() {
        let Some(d) = digit(b) else { return false };
        let v = if i.is_multiple_of(2) {
            d
        } else {
            DOUBLED.get(d as usize).copied().unwrap_or(0)
        };
        // At most 9 per digit: no overflow below 477 million digits.
        sum = sum.wrapping_add(v);
    }
    sum.is_multiple_of(10)
}

/// ISO 13616 mod-97 over a compact IBAN (country, check digits, BBAN), ASCII upper-case
/// letters and digits only: true when the remainder is 1.
pub(crate) fn iban_mod97(iban: &[u8]) -> bool {
    if iban.len() < 5 {
        return false;
    }
    let (head, bban) = iban.split_at(4);
    // `rem` stays below 97, so `rem * 100 + 35` fits easily: wrapping never happens.
    let mut rem: u32 = 0;
    for &b in bban.iter().chain(head) {
        if let Some(d) = digit(b) {
            rem = rem.wrapping_mul(10).wrapping_add(d) % 97;
        } else if b.is_ascii_uppercase() {
            let v = u32::from(b.wrapping_sub(b'A')).wrapping_add(10);
            rem = rem.wrapping_mul(100).wrapping_add(v) % 97;
        } else {
            return false;
        }
    }
    rem == 1
}

const VERHOEFF_D: [[u8; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const VERHOEFF_P: [[u8; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/// Verhoeff over ASCII digits, check digit last: true when the final state is 0 (the
/// inverse table's 0 maps to 0, so Presidio's `inv[c] == 0` is `c == 0`).
pub(crate) fn verhoeff(digits: &[u8]) -> bool {
    if digits.is_empty() {
        return false;
    }
    let mut c: u8 = 0;
    for (i, &b) in digits.iter().rev().enumerate() {
        let Some(d) = digit(b) else { return false };
        let p = VERHOEFF_P.get(i % 8).and_then(|row| row.get(d as usize));
        let next = p.and_then(|&p| {
            VERHOEFF_D
                .get(c as usize)
                .and_then(|row| row.get(p as usize))
        });
        match next {
            Some(&n) => c = n,
            None => return false,
        }
    }
    c == 0
}

fn digit(b: u8) -> Option<u32> {
    b.is_ascii_digit().then(|| u32::from(b.wrapping_sub(b'0')))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_known_values() {
        assert!(luhn(b"4111111111111111"));
        assert!(luhn(b"378282246310005"));
        assert!(luhn(b"79927398713"));
        assert!(!luhn(b"4111111111111112"));
        assert!(!luhn(b""));
        assert!(!luhn(b"41x1"));
    }

    #[test]
    fn mod97_known_values() {
        assert!(iban_mod97(b"DE89370400440532013000"));
        assert!(iban_mod97(b"GB82WEST12345698765432"));
        assert!(!iban_mod97(b"DE88370400440532013000"));
        assert!(!iban_mod97(b"de89370400440532013000"));
        assert!(!iban_mod97(b"DE8"));
    }

    #[test]
    fn verhoeff_known_values() {
        // The algorithm's textbook example: 236 has check digit 3.
        assert!(verhoeff(b"2363"));
        assert!(!verhoeff(b"2364"));
        assert!(!verhoeff(b""));
        assert!(!verhoeff(b"23a3"));
    }
}
