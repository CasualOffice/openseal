//! A JSON tree and a strict, bounded parser for it (RFC 8259 with the I-JSON
//! restrictions of RFC 7493 that RFC 8785 requires).
//!
//! The parser is what verification reads untrusted audit JSON with, so it refuses rather
//! than guesses: a duplicate member name, a lone surrogate, a number beyond a double, a
//! byte-order mark, a control character in a string, or anything after the value. Nesting
//! depth and input size are bounded before work ([`crate::AuditLimits`]). Objects keep
//! their members in the order received; [`crate::jcs`] sorts them when writing.

use std::collections::BTreeSet;

use crate::error::{AuditError, JsonFault};

/// A JSON value. Numbers are IEEE 754 doubles, as RFC 8785 §3.2.2.3 requires.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A finite number.
    Number(f64),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Value>),
    /// An object: members in the order received, names unique.
    Object(Vec<(String, Value)>),
}

impl Value {
    /// The member `name` of an object.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Value> {
        match self {
            Self::Object(members) => members.iter().find(|(k, _)| k == name).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The string, if this is one.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    /// The number as an integer from 0 to 2^53 − 1, if it is one.
    #[must_use]
    pub fn as_safe_u64(&self) -> Option<u64> {
        match self {
            Self::Number(n) if n.fract() == 0.0 && *n >= 0.0 && *n <= MAX_SAFE_INTEGER_F64 => {
                // Exact: an integral double in range converts without rounding.
                // Checked above: integral, non-negative, at most 2^53 − 1.
                Some(*n as u64)
            }
            _ => None,
        }
    }

    /// The array's items, if this is an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// This object without the member `name` (other values unchanged).
    #[must_use]
    pub fn without(&self, name: &str) -> Self {
        match self {
            Self::Object(members) => {
                Self::Object(members.iter().filter(|(k, _)| k != name).cloned().collect())
            }
            other => other.clone(),
        }
    }
}

/// 2^53 − 1, the largest integer every JSON reader holds exactly (RFC 7493 §2.2).
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
// 2^53 − 1 is exactly representable as a double.
const MAX_SAFE_INTEGER_F64: f64 = MAX_SAFE_INTEGER as f64;

/// Parse `input` as one JSON value, nesting at most `max_depth` arrays and objects.
///
/// # Errors
///
/// `CS-AUD-0001` for malformed text, `CS-AUD-0002` when nesting passes `max_depth`.
pub fn parse(input: &[u8], max_depth: usize) -> Result<Value, AuditError> {
    let mut p = Parser {
        s: input,
        pos: 0,
        max_depth,
    };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.pos != input.len() {
        return Err(p.err(JsonFault::TrailingData));
    }
    Ok(v)
}

struct Parser<'a> {
    s: &'a [u8],
    pos: usize,
    max_depth: usize,
}

impl Parser<'_> {
    fn err(&self, fault: JsonFault) -> AuditError {
        AuditError::Json {
            fault,
            offset: self.pos,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.pos).copied()
    }

    fn bump(&mut self) {
        self.pos = self.pos.saturating_add(1);
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.bump();
        }
    }

    fn expect(&mut self, b: u8) -> Result<(), AuditError> {
        if self.peek() == Some(b) {
            self.bump();
            Ok(())
        } else {
            Err(self.err(JsonFault::Syntax))
        }
    }

    fn literal(&mut self, word: &[u8], v: Value) -> Result<Value, AuditError> {
        let end = self.pos.saturating_add(word.len());
        if self.s.get(self.pos..end) == Some(word) {
            self.pos = end;
            Ok(v)
        } else {
            Err(self.err(JsonFault::Syntax))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, AuditError> {
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(Value::String),
            Some(b't') => self.literal(b"true", Value::Bool(true)),
            Some(b'f') => self.literal(b"false", Value::Bool(false)),
            Some(b'n') => self.literal(b"null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(self.err(JsonFault::Syntax)),
        }
    }

    fn deeper(&self, depth: usize) -> Result<usize, AuditError> {
        let d = depth.saturating_add(1);
        if d > self.max_depth {
            return Err(AuditError::Limit {
                limit: "JSON nesting depth",
                max: u64::try_from(self.max_depth).unwrap_or(u64::MAX),
            });
        }
        Ok(d)
    }

    fn object(&mut self, depth: usize) -> Result<Value, AuditError> {
        let depth = self.deeper(depth)?;
        self.expect(b'{')?;
        let mut members: Vec<(String, Value)> = Vec::new();
        let mut names: BTreeSet<String> = BTreeSet::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.bump();
            return Ok(Value::Object(members));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(self.err(JsonFault::Syntax));
            }
            let at = self.pos;
            let name = self.string()?;
            if !names.insert(name.clone()) {
                return Err(AuditError::Json {
                    fault: JsonFault::DuplicateKey,
                    offset: at,
                });
            }
            self.ws();
            self.expect(b':')?;
            self.ws();
            let v = self.value(depth)?;
            members.push((name, v));
            self.ws();
            match self.peek() {
                Some(b',') => self.bump(),
                Some(b'}') => {
                    self.bump();
                    return Ok(Value::Object(members));
                }
                _ => return Err(self.err(JsonFault::Syntax)),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, AuditError> {
        let depth = self.deeper(depth)?;
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.bump();
            return Ok(Value::Array(items));
        }
        loop {
            self.ws();
            items.push(self.value(depth)?);
            self.ws();
            match self.peek() {
                Some(b',') => self.bump(),
                Some(b']') => {
                    self.bump();
                    return Ok(Value::Array(items));
                }
                _ => return Err(self.err(JsonFault::Syntax)),
            }
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.bump();
        }
        self.pos.saturating_sub(start)
    }

    fn number(&mut self) -> Result<Value, AuditError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.bump();
        }
        match self.peek() {
            Some(b'0') => self.bump(),
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(self.err(JsonFault::Syntax)),
        }
        if self.peek() == Some(b'.') {
            self.bump();
            if self.digits() == 0 {
                return Err(self.err(JsonFault::Syntax));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.bump();
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.bump();
            }
            if self.digits() == 0 {
                return Err(self.err(JsonFault::Syntax));
            }
        }
        let text = self
            .s
            .get(start..self.pos)
            .and_then(|b| core::str::from_utf8(b).ok())
            .ok_or_else(|| self.err(JsonFault::Syntax))?;
        // Rust's parser rounds correctly to the nearest double (as ECMAScript does).
        let n: f64 = text.parse().map_err(|_| AuditError::Json {
            fault: JsonFault::Syntax,
            offset: start,
        })?;
        if !n.is_finite() {
            return Err(AuditError::Json {
                fault: JsonFault::NumberOutOfRange,
                offset: start,
            });
        }
        Ok(Value::Number(n))
    }

    fn hex4(&mut self) -> Result<u32, AuditError> {
        let mut v: u32 = 0;
        for _ in 0..4 {
            let d = match self.peek() {
                Some(c @ b'0'..=b'9') => c.wrapping_sub(b'0'),
                Some(c @ b'a'..=b'f') => c.wrapping_sub(b'a').wrapping_add(10),
                Some(c @ b'A'..=b'F') => c.wrapping_sub(b'A').wrapping_add(10),
                _ => return Err(self.err(JsonFault::Syntax)),
            };
            v = (v << 4) | u32::from(d);
            self.bump();
        }
        Ok(v)
    }

    fn string(&mut self) -> Result<String, AuditError> {
        self.expect(b'"')?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let Some(b) = self.peek() else {
                return Err(self.err(JsonFault::Syntax));
            };
            match b {
                b'"' => {
                    self.bump();
                    break;
                }
                b'\\' => {
                    self.bump();
                    let Some(e) = self.peek() else {
                        return Err(self.err(JsonFault::Syntax));
                    };
                    let at = self.pos;
                    self.bump();
                    let c = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            let lone = AuditError::Json {
                                fault: JsonFault::LoneSurrogate,
                                offset: at,
                            };
                            let code = if (0xD800..0xDC00).contains(&hi) {
                                if self.peek() != Some(b'\\') {
                                    return Err(lone);
                                }
                                self.bump();
                                if self.peek() != Some(b'u') {
                                    return Err(lone);
                                }
                                self.bump();
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(lone);
                                }
                                0x10000_u32
                                    .saturating_add((hi.saturating_sub(0xD800)) << 10)
                                    .saturating_add(lo.saturating_sub(0xDC00))
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err(lone);
                            } else {
                                hi
                            };
                            char::from_u32(code).ok_or(lone)?
                        }
                        _ => {
                            return Err(AuditError::Json {
                                fault: JsonFault::Syntax,
                                offset: at,
                            });
                        }
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                }
                0x00..=0x1F => return Err(self.err(JsonFault::Syntax)),
                _ => {
                    out.push(b);
                    self.bump();
                }
            }
        }
        String::from_utf8(out).map_err(|_| self.err(JsonFault::Syntax))
    }
}

// Tests may unwrap, index and panic (CLAUDE.md).
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    fn fault(s: &str) -> JsonFault {
        match parse(s.as_bytes(), 32) {
            Err(AuditError::Json { fault, .. }) => fault,
            other => panic!("{s}: {other:?}"),
        }
    }

    #[test]
    fn refuses_what_i_json_forbids() {
        assert_eq!(fault(r#"{"a":1,"a":2}"#), JsonFault::DuplicateKey);
        assert_eq!(fault(r#""\ud800""#), JsonFault::LoneSurrogate);
        assert_eq!(fault(r#""\udc00x""#), JsonFault::LoneSurrogate);
        assert_eq!(fault(r#""\ud800\u0041""#), JsonFault::LoneSurrogate);
        assert_eq!(fault("1e400"), JsonFault::NumberOutOfRange);
        assert_eq!(fault("-1e400"), JsonFault::NumberOutOfRange);
        assert_eq!(fault("1 2"), JsonFault::TrailingData);
        // A leading zero is read as `0` followed by more.
        assert_eq!(fault("01"), JsonFault::TrailingData);
        for bad in [
            "",
            "1.",
            ".5",
            "+1",
            "1e",
            "[1,]",
            "{\"a\"}",
            "\"\u{1}\"",
            "\u{feff}1",
            "NaN",
            "tru",
            "\"\\x\"",
            "{,}",
            "[",
        ] {
            assert_eq!(fault(bad), JsonFault::Syntax, "{bad:?}");
        }
    }

    #[test]
    fn invalid_utf8_is_refused() {
        assert!(matches!(
            parse(b"\"\xff\"", 4),
            Err(AuditError::Json {
                fault: JsonFault::Syntax,
                ..
            })
        ));
    }

    #[test]
    fn depth_is_bounded() {
        let deep = "[".repeat(33) + &"]".repeat(33);
        assert_eq!(
            parse(deep.as_bytes(), 32).unwrap_err().code(),
            "CS-AUD-0002"
        );
        let ok = "[".repeat(32) + &"]".repeat(32);
        assert!(parse(ok.as_bytes(), 32).is_ok());
    }

    #[test]
    fn surrogate_pairs_and_escapes_decode() {
        let v = parse(br#""\ud83d\ude00\n\/""#, 4).unwrap();
        assert_eq!(v, Value::String("\u{1F600}\n/".into()));
    }

    #[test]
    fn safe_integers() {
        assert_eq!(
            Value::Number(9_007_199_254_740_991.0).as_safe_u64(),
            Some(MAX_SAFE_INTEGER)
        );
        assert_eq!(Value::Number(9_007_199_254_740_992.0).as_safe_u64(), None);
        assert_eq!(Value::Number(-1.0).as_safe_u64(), None);
        assert_eq!(Value::Number(1.5).as_safe_u64(), None);
    }
}
