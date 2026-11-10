//! PDF values written from request data: dates (ISO 32000-2 §7.9.4), text strings
//! (§7.9.2.2), numbers for content streams, upper-case hex.

use core::time::Duration;

use crate::error::RequestProblem;

/// Longest text entry accepted (docs/21 "Text field value", the same bound flattening
/// uses for names and reasons).
pub(crate) const MAX_TEXT_BYTES: usize = 4_000;

/// 9999-12-31T23:59:59Z, the last instant a PDF date can name.
const MAX_SECS: u64 = 253_402_300_799;

/// Year, month, day from days since 1970-01-01 (H. Hinnant's `civil_from_days`).
fn civil(days: u64) -> (u64, u64, u64) {
    let z = days.saturating_add(719_468);
    let era = z / 146_097;
    let doe = z.saturating_sub(era.saturating_mul(146_097));
    let yoe = doe
        .saturating_sub(doe / 1_460)
        .saturating_add(doe / 36_524)
        .saturating_sub(doe / 146_096)
        / 365;
    let doy = doe.saturating_sub(
        yoe.saturating_mul(365)
            .saturating_add(yoe / 4)
            .saturating_sub(yoe / 100),
    );
    let mp = doy.saturating_mul(5).saturating_add(2) / 153;
    let d = doy
        .saturating_sub(mp.saturating_mul(153).saturating_add(2) / 5)
        .saturating_add(1);
    let m = if mp < 10 {
        mp.saturating_add(3)
    } else {
        mp.saturating_sub(9)
    };
    let y = yoe
        .saturating_add(era.saturating_mul(400))
        .saturating_add(u64::from(m <= 2));
    (y, m, d)
}

/// `D:YYYYMMDDHHmmSS+00'00'` for `t` since the Unix epoch, in UTC.
pub(crate) fn pdf_date(t: Duration) -> Result<Vec<u8>, RequestProblem> {
    let secs = t.as_secs();
    if secs > MAX_SECS {
        return Err(RequestProblem::Time);
    }
    let (y, mo, d) = civil(secs / 86_400);
    let rem = secs % 86_400;
    let (h, mi, s) = (rem / 3_600, (rem % 3_600) / 60, rem % 60);
    Ok(format!("D:{y:04}{mo:02}{d:02}{h:02}{mi:02}{s:02}+00'00'").into_bytes())
}

/// A PDF text string: the bytes themselves when printable ASCII, else UTF-16BE with a
/// byte-order mark.
pub(crate) fn text_string(s: &str) -> Result<Vec<u8>, RequestProblem> {
    if s.len() > MAX_TEXT_BYTES {
        return Err(RequestProblem::TextTooLong);
    }
    if s.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return Ok(s.as_bytes().to_vec());
    }
    let mut out = vec![0xFE, 0xFF];
    for unit in s.encode_utf16() {
        out.extend_from_slice(&unit.to_be_bytes());
    }
    Ok(out)
}

/// Upper-case hexadecimal.
pub(crate) fn hex_upper(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for &b in bytes {
        for nibble in [b >> 4, b & 0x0f] {
            s.push(char::from(
                HEX.get(usize::from(nibble)).copied().unwrap_or(b'0'),
            ));
        }
    }
    s
}

/// A number for a content stream: at most three decimals, no exponent, no trailing
/// zeros. Non-finite values, which a validated request never holds, are written as 0.
pub(crate) fn num(v: f64) -> String {
    if !v.is_finite() {
        return "0".to_string();
    }
    let s = format!("{v:.3}");
    let s = s.trim_end_matches('0').trim_end_matches('.');
    if s.is_empty() || s == "-0" {
        "0".to_string()
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_are_utc_pdf_dates() {
        assert_eq!(
            pdf_date(Duration::ZERO).ok(),
            Some(b"D:19700101000000+00'00'".to_vec())
        );
        // 2026-11-01T12:00:00Z
        assert_eq!(
            pdf_date(Duration::from_secs(1_793_534_400)).ok(),
            Some(b"D:20261101120000+00'00'".to_vec())
        );
        // A leap day.
        assert_eq!(
            pdf_date(Duration::from_secs(951_782_400)).ok(),
            Some(b"D:20000229000000+00'00'".to_vec())
        );
        assert_eq!(
            pdf_date(Duration::from_secs(MAX_SECS)).ok(),
            Some(b"D:99991231235959+00'00'".to_vec())
        );
        assert_eq!(
            pdf_date(Duration::from_secs(MAX_SECS + 1)),
            Err(RequestProblem::Time)
        );
    }

    #[test]
    fn text_is_ascii_or_utf16() {
        assert_eq!(text_string("Seal").ok(), Some(b"Seal".to_vec()));
        assert_eq!(text_string("é").ok(), Some(vec![0xFE, 0xFF, 0x00, 0xE9]));
        assert_eq!(
            text_string(&"x".repeat(MAX_TEXT_BYTES + 1)),
            Err(RequestProblem::TextTooLong)
        );
    }

    #[test]
    fn numbers_and_hex() {
        assert_eq!(num(1.0), "1");
        assert_eq!(num(0.5), "0.5");
        assert_eq!(num(-0.0001), "0");
        assert_eq!(num(f64::NAN), "0");
        assert_eq!(hex_upper(&[0x0a, 0xff]), "0AFF");
    }
}
