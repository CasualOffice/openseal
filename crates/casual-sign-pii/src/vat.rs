//! EU VAT identification numbers for the main member states: the country prefix, the
//! national format and its check digits. Written from each tax administration's
//! published algorithm, as the European Commission's VIES documentation lists them.
//! Countries covered: AT, BE, DE, DK, ES, FI, FR, IT, NL, PL, PT, SE. Not covered
//! (no check, or not yet): the other fifteen member states and XI (docs/33 §5.4).

use crate::checksum::{self, digit, value};

/// Whether `vat` (upper-case ASCII, country prefix first, no spaces) is a valid VAT
/// number of a covered country.
pub(crate) fn valid(vat: &[u8]) -> bool {
    let Some((cc, n)) = vat.split_first_chunk::<2>() else {
        return false;
    };
    match cc {
        b"AT" => at(n),
        b"BE" => be(n),
        b"DE" => de(n),
        b"DK" => dk(n),
        b"ES" => es(n),
        b"FI" => fi(n),
        b"FR" => fr(n),
        b"IT" => it(n),
        b"NL" => nl(n),
        b"PL" => pl(n),
        b"PT" => pt(n),
        b"SE" => se(n),
        _ => false,
    }
}

fn all_digits(n: &[u8], len: usize) -> bool {
    n.len() == len && n.iter().all(u8::is_ascii_digit)
}

/// Austria: `U` and eight digits; the eighth checks the first seven, alternate
/// digits doubled with their digit sums taken.
fn at(n: &[u8]) -> bool {
    let Some((b'U', d)) = n.split_first() else {
        return false;
    };
    if !all_digits(d, 8) {
        return false;
    }
    let mut sum: u32 = 0;
    for (i, &b) in d.iter().take(7).enumerate() {
        let v = digit(b).unwrap_or(0);
        let v = if i % 2 == 1 {
            let w = v.wrapping_mul(2);
            (w / 10).wrapping_add(w % 10)
        } else {
            v
        };
        sum = sum.wrapping_add(v);
    }
    let check = (10u32.wrapping_sub(sum.wrapping_add(4) % 10)) % 10;
    d.get(7).copied().and_then(digit) == Some(check)
}

/// Belgium: ten digits starting 0 or 1; the last two are 97 minus the first eight
/// mod 97.
fn be(n: &[u8]) -> bool {
    if !all_digits(n, 10) || !matches!(n.first(), Some(b'0' | b'1')) {
        return false;
    }
    let (Some(body), Some(check)) = (n.get(..8).and_then(value), n.get(8..).and_then(value)) else {
        return false;
    };
    97u64.wrapping_sub(body % 97) == check
}

/// Germany: nine digits, the first not 0, ISO 7064 MOD 11,10.
fn de(n: &[u8]) -> bool {
    all_digits(n, 9) && n.first() != Some(&b'0') && checksum::iso7064_mod11_10(n)
}

/// Denmark: eight digits, the first not 0, weights 2, 7, 6, 5, 4, 3, 2, 1 summing to a
/// multiple of 11.
fn dk(n: &[u8]) -> bool {
    all_digits(n, 8)
        && n.first() != Some(&b'0')
        && checksum::weighted_zero(n, &[2, 7, 6, 5, 4, 3, 2, 1], 11)
}

/// Spain: a NIF (eight digits and a check letter), an NIE (X, Y or Z, seven digits and
/// a check letter) or a CIF (an entity letter, seven digits and a check digit or
/// letter).
fn es(n: &[u8]) -> bool {
    if n.len() != 9 {
        return false;
    }
    if es_nif(n) || es_nie(n) {
        return true;
    }
    let Some((&first, rest)) = n.split_first() else {
        return false;
    };
    if !b"ABCDEFGHJNPQRSUVW".contains(&first) {
        return false;
    }
    let (Some(body), Some(&control)) = (rest.get(..7), rest.get(7)) else {
        return false;
    };
    if !body.iter().all(u8::is_ascii_digit) {
        return false;
    }
    let mut sum: u32 = 0;
    for (i, &b) in body.iter().enumerate() {
        let v = digit(b).unwrap_or(0);
        sum = sum.wrapping_add(if i % 2 == 0 {
            let w = v.wrapping_mul(2);
            (w / 10).wrapping_add(w % 10)
        } else {
            v
        });
    }
    let c = (10u32.wrapping_sub(sum % 10)) % 10;
    digit(control) == Some(c) || b"JABCDEFGHI".get(c as usize) == Some(&control)
}

const NIF_LETTERS: &[u8; 23] = b"TRWAGMYFPDXBNJZSQVHLCKE";

/// Spanish DNI/NIF: eight digits and the letter at their value mod 23.
pub(crate) fn es_nif(n: &[u8]) -> bool {
    let (Some(d), Some(&letter)) = (n.get(..8), n.get(8)) else {
        return false;
    };
    n.len() == 9 && value(d).is_some_and(|v| NIF_LETTERS.get((v % 23) as usize) == Some(&letter))
}

/// Spanish NIE: X, Y or Z (read as 0, 1, 2), seven digits and the NIF letter.
pub(crate) fn es_nie(n: &[u8]) -> bool {
    let Some((&first, rest)) = n.split_first() else {
        return false;
    };
    let lead = match first {
        b'X' => b'0',
        b'Y' => b'1',
        b'Z' => b'2',
        _ => return false,
    };
    let mut as_nif = Vec::with_capacity(9);
    as_nif.push(lead);
    as_nif.extend_from_slice(rest);
    es_nif(&as_nif)
}

/// Finland: eight digits; weights 7, 9, 10, 5, 8, 4, 2 give a remainder mod 11 whose
/// complement is the eighth digit (remainder 1 is never issued).
fn fi(n: &[u8]) -> bool {
    if !all_digits(n, 8) {
        return false;
    }
    let Some(r) = n
        .get(..7)
        .and_then(|b| checksum::weighted_rem(b, &[7, 9, 10, 5, 8, 4, 2], 11))
    else {
        return false;
    };
    let check = match r {
        0 => 0,
        1 => return false,
        r => 11u32.wrapping_sub(r),
    };
    n.get(7).copied().and_then(digit) == Some(check)
}

/// France: a two-digit key and the nine-digit SIREN; the key is (12 + 3 × (SIREN
/// mod 97)) mod 97. The newer alphanumeric keys are not checked and not recognised.
fn fr(n: &[u8]) -> bool {
    if !all_digits(n, 11) {
        return false;
    }
    let (Some(key), Some(siren)) = (n.get(..2).and_then(value), n.get(2..).and_then(value)) else {
        return false;
    };
    (12u64.wrapping_add((siren % 97).wrapping_mul(3))) % 97 == key
}

/// Italy: eleven digits, Luhn over all of them, and an office code (digits 8 to 10)
/// of 001 to 100, 120, 121, 888 or 999.
fn it(n: &[u8]) -> bool {
    if !all_digits(n, 11) {
        return false;
    }
    let office = n.get(7..10).and_then(value).unwrap_or(0);
    matches!(office, 1..=100 | 120 | 121 | 888 | 999) && checksum::luhn(n)
}

/// The Netherlands: nine digits, `B` and two digits. The nine pass the 11-test with
/// weights 9 to 2 and the check digit, or, for numbers issued from 2020, the whole
/// "NL…" string passes ISO 7064 mod 97.
fn nl(n: &[u8]) -> bool {
    let (Some(d), Some(b'B'), Some(tail)) = (n.get(..9), n.get(9), n.get(10..)) else {
        return false;
    };
    if n.len() != 12 || !d.iter().all(u8::is_ascii_digit) || !all_digits(tail, 2) {
        return false;
    }
    let eleven = d
        .get(..8)
        .and_then(|b| checksum::weighted_rem(b, &[9, 8, 7, 6, 5, 4, 3, 2], 11))
        .is_some_and(|r| r != 10 && d.get(8).copied().and_then(digit) == Some(r));
    eleven || nl_mod97(n)
}

/// ISO 7064 mod 97 over "NL" and the number, letters as 10 to 35: remainder 1.
fn nl_mod97(n: &[u8]) -> bool {
    let mut rem: u32 = 0;
    for &b in b"NL".iter().chain(n) {
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

/// Poland (NIP): ten digits; weights 6, 5, 7, 2, 3, 4, 5, 6, 7 mod 11 give the tenth
/// (10 is never issued).
fn pl(n: &[u8]) -> bool {
    if !all_digits(n, 10) {
        return false;
    }
    let r = n
        .get(..9)
        .and_then(|b| checksum::weighted_rem(b, &[6, 5, 7, 2, 3, 4, 5, 6, 7], 11));
    r.is_some_and(|r| r != 10 && n.get(9).copied().and_then(digit) == Some(r))
}

/// Portugal (NIF): nine digits, the first not 0; weights 9 to 2, check 11 minus the
/// remainder mod 11, where 10 and 11 mean 0.
fn pt(n: &[u8]) -> bool {
    if !all_digits(n, 9) || n.first() == Some(&b'0') {
        return false;
    }
    let Some(r) = n
        .get(..8)
        .and_then(|b| checksum::weighted_rem(b, &[9, 8, 7, 6, 5, 4, 3, 2], 11))
    else {
        return false;
    };
    let check = match 11u32.wrapping_sub(r) {
        10 | 11 => 0,
        c => c,
    };
    n.get(8).copied().and_then(digit) == Some(check)
}

/// Sweden: twelve digits ending `01`; the first ten pass Luhn (the organisation
/// number).
fn se(n: &[u8]) -> bool {
    all_digits(n, 12)
        && n.get(10..) == Some(b"01".as_slice())
        && n.get(..10).is_some_and(checksum::luhn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spanish_letters() {
        assert!(es_nif(b"12345678Z"));
        assert!(!es_nif(b"12345678A"));
        assert!(es_nie(b"X1234567L"));
        assert!(!es_nie(b"X1234567M"));
        assert!(!es_nie(b""));
    }

    #[test]
    fn unknown_country_or_short_input_is_not_valid() {
        assert!(!valid(b"XX123456789"));
        assert!(!valid(b"D"));
        assert!(!valid(b""));
    }
}
