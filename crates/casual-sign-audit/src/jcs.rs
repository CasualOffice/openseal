//! The JSON Canonicalization Scheme, RFC 8785 (ADR-010).
//!
//! - Members are sorted by their names as arrays of UTF-16 code units (§3.2.3).
//! - Strings are written as ECMAScript's `JSON.stringify` writes them (§3.2.2.2): `"` and
//!   `\` escaped, the five short escapes for their control characters, other control
//!   characters as `\u00xx` in lower-case hex, everything else as UTF-8.
//! - Numbers are written as ECMAScript's `Number.prototype.toString` writes them
//!   (§3.2.2.3): the shortest digits that round-trip, from Rust's own shortest
//!   formatting, laid out by ECMA-262's `Number::toString` rules. `-0` is `0`;
//!   non-finite numbers cannot be written.
//! - No whitespace.

use core::cmp::Ordering;

use crate::error::{AuditError, JsonFault};
use crate::json::Value;

/// The canonical form of `value`.
///
/// # Errors
///
/// `CS-AUD-0001` ([`JsonFault::NonFinite`]) for a NaN or infinite number, which only a
/// tree built in code can hold: the parser refuses them.
pub fn to_vec(value: &Value) -> Result<Vec<u8>, AuditError> {
    let mut out = Vec::new();
    write(&mut out, value)?;
    Ok(out)
}

/// Order two member names by their UTF-16 code units (RFC 8785 §3.2.3).
#[must_use]
pub fn utf16_order(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

fn write(out: &mut Vec<u8>, value: &Value) -> Result<(), AuditError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => out.extend_from_slice(number(*n)?.as_bytes()),
        Value::String(s) => string(out, s),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write(out, item)?;
            }
            out.push(b']');
        }
        Value::Object(members) => {
            let mut sorted: Vec<&(String, Value)> = members.iter().collect();
            sorted.sort_by(|a, b| utf16_order(&a.0, &b.0));
            out.push(b'{');
            for (i, (k, v)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                string(out, k);
                out.push(b':');
                write(out, v)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn string(out: &mut Vec<u8>, s: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\r' => out.extend_from_slice(b"\\r"),
            c if u32::from(c) < 0x20 => {
                let b = u8::try_from(u32::from(c)).unwrap_or(0);
                out.extend_from_slice(b"\\u00");
                out.push(HEX.get(usize::from(b >> 4)).copied().unwrap_or(b'0'));
                out.push(HEX.get(usize::from(b & 0xf)).copied().unwrap_or(b'0'));
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// `d[.ddd]e[-]x` split into its digits and exponent.
fn split_sci(sci: &str) -> (String, i32) {
    let (mantissa, exp) = sci.split_once('e').unwrap_or((sci, "0"));
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    (digits, exp.parse().unwrap_or(0))
}

/// The digits `d1…dk` and exponent `e` of `x` = d1.d2…dk × 10^e (x > 0, finite) that
/// ECMA-262 asks for: k as small as possible; among those, the closest to `x`; of two
/// equally close, the even one.
///
/// Rust's `{:e}` gives the shortest digits that round-trip and the closest of them,
/// but breaks an exact tie upwards (`1424953923781206.25` → `…206.3`, where
/// ECMAScript writes `…206.2`). A tie is recognised from the exact expansion (Rust
/// prints a double's exact digits when given a precision; 800 covers the 767 a double
/// can have), and settled towards the even candidate when both round-trip.
fn shortest(x: f64) -> (String, i32) {
    let (digits, exp) = split_sci(&format!("{x:e}"));
    let (exact, exact_exp) = split_sci(&format!("{x:.800e}"));
    let exact = exact.trim_end_matches('0');
    let k = digits.len();
    if exact.len() != k.saturating_add(1) || !exact.ends_with('5') {
        return (digits, exp);
    }
    let lower = exact.get(..k).unwrap_or_default().to_owned();
    let Some(upper) = increment(&lower) else {
        return (digits, exp);
    };
    let round_trips = |d: &str| {
        let (first, rest) = d.split_at(1.min(d.len()));
        format!("{first}.{rest}e{exact_exp}").parse::<f64>().ok() == Some(x)
    };
    if !(round_trips(&lower) && round_trips(&upper)) {
        return (digits, exp);
    }
    let even = |d: &str| d.bytes().last().is_some_and(|b| b % 2 == 0);
    let chosen = if even(&lower) { lower } else { upper };
    (chosen, exact_exp)
}

/// The decimal digit string plus one in its last place, if it keeps its length.
fn increment(d: &str) -> Option<String> {
    let mut b = d.as_bytes().to_vec();
    for slot in b.iter_mut().rev() {
        if *slot == b'9' {
            *slot = b'0';
        } else {
            *slot = slot.saturating_add(1);
            return String::from_utf8(b).ok();
        }
    }
    None
}

/// `n` as ECMAScript's `Number.prototype.toString` writes it (ECMA-262 §6.1.6.1.20).
///
/// # Errors
///
/// `CS-AUD-0001` for NaN and the infinities.
pub fn number(n: f64) -> Result<String, AuditError> {
    if !n.is_finite() {
        return Err(AuditError::Json {
            fault: JsonFault::NonFinite,
            offset: 0,
        });
    }
    if n == 0.0 {
        return Ok("0".to_owned());
    }
    let (digits, exp) = shortest(n.abs());
    // ECMA-262: the value is 0.d1…dk × 10^n, so n is one more than the exponent of
    // d1.d2…dk.
    let k = i32::try_from(digits.len()).unwrap_or(i32::MAX);
    let n_exp = exp.saturating_add(1);
    let mut out = String::new();
    if n < 0.0 {
        out.push('-');
    }
    if k <= n_exp && n_exp <= 21 {
        // Digits then n − k zeros.
        out.push_str(&digits);
        for _ in 0..n_exp.saturating_sub(k) {
            out.push('0');
        }
    } else if 0 < n_exp && n_exp <= 21 {
        // The point inside the digits.
        let split = usize::try_from(n_exp).unwrap_or(0);
        let (int, frac) = digits.split_at(split.min(digits.len()));
        out.push_str(int);
        out.push('.');
        out.push_str(frac);
    } else if -6 < n_exp && n_exp <= 0 {
        // 0.000ddd
        out.push_str("0.");
        for _ in 0..n_exp.saturating_neg() {
            out.push('0');
        }
        out.push_str(&digits);
    } else {
        // Exponential: d[.ddd]e±(n − 1).
        let (first, rest) = digits.split_at(1.min(digits.len()));
        out.push_str(first);
        if !rest.is_empty() {
            out.push('.');
            out.push_str(rest);
        }
        out.push('e');
        let e = n_exp.saturating_sub(1);
        out.push(if e < 0 { '-' } else { '+' });
        out.push_str(&e.unsigned_abs().to_string());
    }
    Ok(out)
}

// Tests may unwrap, index and panic (CLAUDE.md).
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;

    /// RFC 8785 Appendix B: IEEE 754 bit patterns and their canonical text.
    const APPENDIX_B: &[(u64, &str)] = &[
        (0x0000_0000_0000_0000, "0"),
        (0x8000_0000_0000_0000, "0"),
        (0x0000_0000_0000_0001, "5e-324"),
        (0x8000_0000_0000_0001, "-5e-324"),
        (0x7fef_ffff_ffff_ffff, "1.7976931348623157e+308"),
        (0xffef_ffff_ffff_ffff, "-1.7976931348623157e+308"),
        (0x4340_0000_0000_0000, "9007199254740992"),
        (0xc340_0000_0000_0000, "-9007199254740992"),
        (0x4430_0000_0000_0000, "295147905179352830000"),
        (0x44b5_2d02_c7e1_4af5, "9.999999999999997e+22"),
        (0x44b5_2d02_c7e1_4af6, "1e+23"),
        (0x44b5_2d02_c7e1_4af7, "1.0000000000000001e+23"),
        (0x444b_1ae4_d6e2_ef4e, "999999999999999700000"),
        (0x444b_1ae4_d6e2_ef4f, "999999999999999900000"),
        (0x444b_1ae4_d6e2_ef50, "1e+21"),
        (0x3eb0_c6f7_a0b5_ed8c, "9.999999999999997e-7"),
        (0x3eb0_c6f7_a0b5_ed8d, "0.000001"),
        (0x41b3_de43_5555_5553, "333333333.3333332"),
        (0x41b3_de43_5555_5554, "333333333.33333325"),
        (0x41b3_de43_5555_5555, "333333333.3333333"),
        (0x41b3_de43_5555_5556, "333333333.3333334"),
        (0x41b3_de43_5555_5557, "333333333.33333343"),
        (0xbecb_f647_612f_3696, "-0.0000033333333333333333"),
        (0x4314_3ff3_c1cb_0959, "1424953923781206.2"),
    ];

    #[test]
    fn rfc8785_appendix_b_numbers() {
        for (bits, want) in APPENDIX_B {
            let got = number(f64::from_bits(*bits)).unwrap();
            assert_eq!(&got, want, "{bits:#018x}");
        }
        // NaN and Infinity cannot be written.
        for bits in [0x7fff_ffff_ffff_ffff_u64, 0x7ff0_0000_0000_0000] {
            assert_eq!(
                number(f64::from_bits(bits)).unwrap_err().code(),
                "CS-AUD-0001"
            );
        }
    }

    #[test]
    fn rfc8785_section_3_2_2_example() {
        let input = br#"{
  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
  "literals": [null, true, false]
}"#;
        let want = "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"string\":\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}";
        let got = to_vec(&parse(input, 8).unwrap()).unwrap();
        assert_eq!(String::from_utf8(got).unwrap(), want);
    }

    #[test]
    fn rfc8785_section_3_2_3_sorting() {
        let input = br#"{
  "\u20ac": "Euro Sign",
  "\r": "Carriage Return",
  "\ufb33": "Hebrew Letter Dalet With Dagesh",
  "1": "One",
  "\ud83d\ude00": "Emoji: Grinning Face",
  "\u0080": "Control",
  "\u00f6": "Latin Small Letter O With Diaeresis"
}"#;
        let got = String::from_utf8(to_vec(&parse(input, 8).unwrap()).unwrap()).unwrap();
        let want = "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",\"\u{f6}\":\"Latin Small Letter O With Diaeresis\",\"\u{20ac}\":\"Euro Sign\",\"\u{1f600}\":\"Emoji: Grinning Face\",\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}";
        assert_eq!(got, want);
    }

    #[test]
    fn rfc8785_appendix_e_like_nesting() {
        // Nested objects sort at every level; arrays keep their order.
        let input = br#"{"b":[{"z":1,"a":2},3],"a":{"y":null,"x":true}}"#;
        let got = to_vec(&parse(input, 8).unwrap()).unwrap();
        assert_eq!(got, br#"{"a":{"x":true,"y":null},"b":[{"a":2,"z":1},3]}"#);
    }

    #[test]
    fn integers_and_small_values() {
        for (n, want) in [
            (1.0, "1"),
            (-1.0, "-1"),
            (10.0, "10"),
            (1e21, "1e+21"),
            (1e20, "100000000000000000000"),
            (0.1, "0.1"),
            (1e-7, "1e-7"),
            (123.456, "123.456"),
            (1.5e300, "1.5e+300"),
        ] {
            assert_eq!(number(n).unwrap(), want);
        }
    }

    #[test]
    fn control_characters_escape_in_lower_case_hex() {
        let v = Value::String("\u{1}\u{1f}\u{7f}\u{2028}".into());
        assert_eq!(
            to_vec(&v).unwrap(),
            "\"\\u0001\\u001f\u{7f}\u{2028}\"".as_bytes()
        );
    }
}
