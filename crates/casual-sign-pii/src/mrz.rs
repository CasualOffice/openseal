//! The second line of a passport's machine-readable zone (ICAO Doc 9303 Part 4, TD3):
//! 44 characters holding the document number, nationality, date of birth, sex, expiry
//! date and an optional personal number, each numeric field followed by a 7-3-1 check
//! digit, and a composite check digit over all of them at the end. Written from Doc
//! 9303 Part 3 §4.9. TD1 and TD2 (identity cards, visas) are not recognised yet.

/// The line's length.
pub(crate) const LEN: usize = 44;

/// A character's value: digits as themselves, letters A to Z as 10 to 35, the filler
/// `<` as 0.
fn val(c: u8) -> Option<u32> {
    match c {
        b'0'..=b'9' => Some(u32::from(c.wrapping_sub(b'0'))),
        b'A'..=b'Z' => Some(u32::from(c.wrapping_sub(b'A')).wrapping_add(10)),
        b'<' => Some(0),
        _ => None,
    }
}

/// The 7-3-1 check digit of `field`.
fn check<'a>(field: impl Iterator<Item = &'a u8>) -> Option<u32> {
    const W: [u32; 3] = [7, 3, 1];
    let mut sum: u32 = 0;
    for (i, &c) in field.enumerate() {
        let w = W.get(i % 3).copied().unwrap_or(1);
        // At most 39 characters of value 35 or less, times 7: no overflow.
        sum = sum.wrapping_add(val(c)?.wrapping_mul(w));
    }
    Some(sum % 10)
}

/// Whether a field's check digit holds; `<` as a check digit means 0 only where Doc
/// 9303 allows it (the optional personal number left empty).
fn field_ok(line: &[u8], from: usize, to: usize, filler_allowed: bool) -> bool {
    let (Some(field), Some(&c)) = (line.get(from..to), line.get(to)) else {
        return false;
    };
    let want = if c == b'<' && filler_allowed && field.iter().all(|&b| b == b'<') {
        Some(0)
    } else {
        c.is_ascii_digit().then(|| u32::from(c.wrapping_sub(b'0')))
    };
    want.is_some() && check(field.iter()) == want
}

/// Whether `line` (44 ASCII bytes) is a TD3 second line whose five check digits hold.
pub(crate) fn td3_line2(line: &[u8]) -> bool {
    if line.len() != LEN {
        return false;
    }
    let composite = line
        .get(0..10)
        .into_iter()
        .chain(line.get(13..20))
        .chain(line.get(21..43))
        .flatten();
    let last = line
        .get(43)
        .copied()
        .and_then(|c| c.is_ascii_digit().then(|| u32::from(c.wrapping_sub(b'0'))));
    field_ok(line, 0, 9, false)
        && field_ok(line, 13, 19, false)
        && field_ok(line, 21, 27, false)
        && field_ok(line, 28, 42, true)
        && last.is_some()
        && check(composite) == last
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icao_specimen() {
        // ICAO Doc 9303 Part 4's specimen passport (Anna Maria Eriksson, Utopia).
        assert!(td3_line2(b"L898902C36UTO7408122F1204159ZE184226B<<<<<10"));
        assert!(!td3_line2(b"L898902C36UTO7408122F1204159ZE184226B<<<<<11"));
        assert!(!td3_line2(b"L898902C37UTO7408122F1204159ZE184226B<<<<<10"));
        assert!(!td3_line2(b"L898902C36UTO7408122F1204159ZE184226B<<<<<1"));
    }
}
