//! Tokens of the PDF object syntax (ISO 32000-2 §7.2, §7.3).
//!
//! The lexer never recurses and never allocates more than the string and name caps.
//! Over-long strings and names are scanned to their end without being stored, so that
//! a lenient read can drop the one value and carry on.

use crate::error::{PdfError, Result, off};

/// PDF white-space characters (§7.2.3).
pub(crate) fn is_ws(c: u8) -> bool {
    matches!(c, 0 | 9 | 10 | 12 | 13 | 32)
}

/// PDF delimiters (§7.2.3).
pub(crate) fn is_delim(c: u8) -> bool {
    matches!(
        c,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

/// A regular character: neither white space nor a delimiter.
pub(crate) fn is_regular(c: u8) -> bool {
    !is_ws(c) && !is_delim(c)
}

pub(crate) fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => c.checked_sub(b'0'),
        b'a'..=b'f' => c.checked_sub(b'a' - 10),
        b'A'..=b'F' => c.checked_sub(b'A' - 10),
        _ => None,
    }
}

/// One token.
#[derive(Debug, PartialEq)]
pub(crate) enum Tok<'a> {
    Int(i64),
    Real(f64),
    Str(Vec<u8>),
    Name(Vec<u8>),
    /// A string over the cap, in lenient mode; its bytes were skipped.
    LongStr,
    /// A name over the cap, in lenient mode.
    LongName,
    AOpen,
    AClose,
    DOpen,
    DClose,
    Kw(&'a [u8]),
    /// A stray delimiter (`)`, `>`, `{`, `}`), consumed.
    Stray(u8),
}

/// A lexer over the whole input, positioned anywhere in it.
#[derive(Debug, Clone)]
pub(crate) struct Lexer<'a> {
    pub(crate) b: &'a [u8],
    pub(crate) pos: usize,
    pub(crate) max_string: usize,
    pub(crate) max_name: usize,
    /// Over-long strings and names become [`Tok::LongStr`] / [`Tok::LongName`]
    /// instead of an error.
    pub(crate) lenient: bool,
    /// Most values one parsed object may hold (read by the parser).
    pub(crate) max_values: usize,
}

impl<'a> Lexer<'a> {
    pub(crate) fn new(
        b: &'a [u8],
        pos: usize,
        max_string: usize,
        max_name: usize,
        lenient: bool,
    ) -> Self {
        Self {
            b,
            pos,
            max_string,
            max_name,
            lenient,
            max_values: usize::MAX,
        }
    }

    /// Cap the values one parsed object may hold.
    pub(crate) fn with_max_values(mut self, n: usize) -> Self {
        self.max_values = n;
        self
    }

    pub(crate) fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }

    fn bump(&mut self) {
        self.pos = self.pos.saturating_add(1);
    }

    /// Skip white space and comments.
    pub(crate) fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if is_ws(c) {
                self.bump();
            } else if c == b'%' {
                while let Some(c) = self.peek() {
                    if c == b'\n' || c == b'\r' {
                        break;
                    }
                    self.bump();
                }
            } else {
                break;
            }
        }
    }

    fn take_regular(&mut self) -> &'a [u8] {
        let start = self.pos;
        while self.peek().is_some_and(is_regular) {
            self.bump();
        }
        self.b.get(start..self.pos).unwrap_or_default()
    }

    fn malformed(&self, at: usize) -> PdfError {
        PdfError::Malformed {
            object: None,
            offset: off(at),
        }
    }

    /// The next token, or `None` at the end of input.
    pub(crate) fn next_tok(&mut self) -> Result<Option<Tok<'a>>> {
        self.skip_ws();
        let at = self.pos;
        let Some(c) = self.peek() else {
            return Ok(None);
        };
        let tok = match c {
            b'[' => {
                self.bump();
                Tok::AOpen
            }
            b']' => {
                self.bump();
                Tok::AClose
            }
            b'<' => {
                self.bump();
                if self.peek() == Some(b'<') {
                    self.bump();
                    Tok::DOpen
                } else {
                    self.hex_string(at)?
                }
            }
            b'>' => {
                self.bump();
                if self.peek() == Some(b'>') {
                    self.bump();
                    Tok::DClose
                } else {
                    Tok::Stray(b'>')
                }
            }
            b'(' => {
                self.bump();
                self.literal_string(at)?
            }
            b'/' => {
                self.bump();
                self.name(at)?
            }
            b')' | b'{' | b'}' => {
                self.bump();
                Tok::Stray(c)
            }
            b'0'..=b'9' | b'+' | b'-' | b'.' => number(self.take_regular()),
            _ => {
                let k = self.take_regular();
                if k.is_empty() {
                    // Unreachable for a regular char; consume one byte to make progress.
                    self.bump();
                    Tok::Stray(c)
                } else {
                    Tok::Kw(k)
                }
            }
        };
        Ok(Some(tok))
    }

    fn too_long_string(&self, at: usize) -> Result<Tok<'a>> {
        if self.lenient {
            Ok(Tok::LongStr)
        } else {
            Err(PdfError::StringTooLong { offset: off(at) })
        }
    }

    fn hex_string(&mut self, at: usize) -> Result<Tok<'a>> {
        let mut out = Vec::new();
        let mut high: Option<u8> = None;
        let mut digits: usize = 0;
        let cap_digits = self.max_string.saturating_mul(2);
        loop {
            let Some(c) = self.peek() else {
                return Err(self.malformed(at));
            };
            self.bump();
            if c == b'>' {
                break;
            }
            if is_ws(c) {
                continue;
            }
            let v = hexval(c).ok_or_else(|| self.malformed(at))?;
            digits = digits.saturating_add(1);
            if digits > cap_digits {
                continue;
            }
            match high.take() {
                None => high = Some(v),
                Some(h) => out.push(h << 4 | v),
            }
        }
        if let Some(h) = high {
            out.push(h << 4);
        }
        if digits > cap_digits {
            return self.too_long_string(at);
        }
        Ok(Tok::Str(out))
    }

    fn literal_string(&mut self, at: usize) -> Result<Tok<'a>> {
        let mut out = Vec::new();
        let mut depth: usize = 1;
        let mut long = false;
        loop {
            let Some(c) = self.peek() else {
                return Err(self.malformed(at));
            };
            self.bump();
            let byte = match c {
                b'(' => {
                    depth = depth.saturating_add(1);
                    Some(c)
                }
                b')' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        break;
                    }
                    Some(c)
                }
                b'\r' => {
                    // An unescaped end-of-line is read as a single LF (§7.3.4.2).
                    if self.peek() == Some(b'\n') {
                        self.bump();
                    }
                    Some(b'\n')
                }
                b'\\' => self.escape(),
                _ => Some(c),
            };
            if let Some(byte) = byte {
                if out.len() >= self.max_string {
                    long = true;
                } else {
                    out.push(byte);
                }
            }
        }
        if long {
            return self.too_long_string(at);
        }
        Ok(Tok::Str(out))
    }

    /// The byte an escape stands for, after the backslash; `None` for a line
    /// continuation.
    fn escape(&mut self) -> Option<u8> {
        let e = self.peek()?;
        self.bump();
        match e {
            b'n' => Some(b'\n'),
            b'r' => Some(b'\r'),
            b't' => Some(b'\t'),
            b'b' => Some(8),
            b'f' => Some(12),
            b'\n' => None,
            b'\r' => {
                if self.peek() == Some(b'\n') {
                    self.bump();
                }
                None
            }
            b'0'..=b'7' => {
                let mut v = u32::from(e & 7);
                for _ in 0..2 {
                    match self.peek() {
                        Some(d @ b'0'..=b'7') => {
                            v = (v << 3) | u32::from(d & 7);
                            self.bump();
                        }
                        _ => break,
                    }
                }
                Some(v.to_le_bytes().first().copied().unwrap_or(0))
            }
            other => Some(other),
        }
    }

    fn name(&mut self, at: usize) -> Result<Tok<'a>> {
        let raw = self.take_regular();
        let mut out = Vec::with_capacity(raw.len().min(self.max_name));
        let mut i = 0usize;
        let mut long = false;
        while let Some(&c) = raw.get(i) {
            let decoded = if c == b'#' {
                let h = raw.get(i.saturating_add(1)).copied().and_then(hexval);
                let l = raw.get(i.saturating_add(2)).copied().and_then(hexval);
                match (h, l) {
                    (Some(h), Some(l)) => {
                        i = i.saturating_add(3);
                        h << 4 | l
                    }
                    _ => {
                        i = i.saturating_add(1);
                        c
                    }
                }
            } else {
                i = i.saturating_add(1);
                c
            };
            if out.len() >= self.max_name {
                long = true;
                break;
            }
            out.push(decoded);
        }
        if long {
            return if self.lenient {
                Ok(Tok::LongName)
            } else {
                Err(PdfError::NameTooLong { offset: off(at) })
            };
        }
        Ok(Tok::Name(out))
    }

    /// Read an unsigned integer token without building other tokens; used for
    /// look-ahead (`n g R`, `n g obj`, xref entries). Leaves `pos` after it.
    pub(crate) fn uint(&mut self) -> Option<u64> {
        self.skip_ws();
        let start = self.pos;
        let mut v: u64 = 0;
        while let Some(c @ b'0'..=b'9') = self.peek() {
            v = v.checked_mul(10)?.checked_add(u64::from(c & 0x0f))?;
            self.bump();
        }
        if self.pos == start || self.peek().is_some_and(is_regular) {
            return None;
        }
        Some(v)
    }

    /// True if the next token is exactly the keyword `k`; consumes it if so.
    pub(crate) fn keyword(&mut self, k: &[u8]) -> bool {
        self.skip_ws();
        let save = self.pos;
        let got = self.take_regular();
        if got == k {
            true
        } else {
            self.pos = save;
            false
        }
    }
}

/// A number token, leniently: malformed numbers read as 0, as common readers do.
fn number(s: &[u8]) -> Tok<'static> {
    let Ok(text) = core::str::from_utf8(s) else {
        return Tok::Int(0);
    };
    if !text.contains('.')
        && let Ok(i) = text.parse::<i64>()
    {
        return Tok::Int(i);
    }
    match text.parse::<f64>() {
        Ok(r) if r.is_finite() => Tok::Real(r),
        // "-.", "--5", "1.2.3": read as zero.
        _ => Tok::Int(0),
    }
}

#[cfg(test)]
mod tests {
    // Tests index and unwrap freely: a panic is the failure report.
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
    use super::*;

    fn toks(s: &[u8]) -> Vec<Tok<'_>> {
        let mut lx = Lexer::new(s, 0, 64, 16, false);
        let mut v = Vec::new();
        while let Some(t) = lx.next_tok().unwrap() {
            v.push(t);
        }
        v
    }

    #[test]
    fn reads_every_token_kind() {
        let t = toks(b"<< /A#20b 12 -3.5 (a\\(b\\)\\101\r\nc) <41 4> [true] >> % c\nobj");
        assert_eq!(t[0], Tok::DOpen);
        assert_eq!(t[1], Tok::Name(b"A b".to_vec()));
        assert_eq!(t[2], Tok::Int(12));
        assert_eq!(t[3], Tok::Real(-3.5));
        assert_eq!(t[4], Tok::Str(b"a(b)A\nc".to_vec()));
        assert_eq!(t[5], Tok::Str(vec![0x41, 0x40]));
        assert_eq!(t[6], Tok::AOpen);
        assert_eq!(t[7], Tok::Kw(b"true"));
        assert_eq!(t[8], Tok::AClose);
        assert_eq!(t[9], Tok::DClose);
        assert_eq!(t[10], Tok::Kw(b"obj"));
    }

    #[test]
    fn over_long_string_is_an_error_when_strict_and_skipped_when_lenient() {
        let long = [b"(".as_slice(), &[b'a'; 65], b") 7"].concat();
        let mut strict = Lexer::new(&long, 0, 64, 16, false);
        assert_eq!(strict.next_tok().unwrap_err().code(), "CS-PDF-0008");
        let mut lenient = Lexer::new(&long, 0, 64, 16, true);
        assert_eq!(lenient.next_tok().unwrap(), Some(Tok::LongStr));
        assert_eq!(lenient.next_tok().unwrap(), Some(Tok::Int(7)));
    }

    #[test]
    fn over_long_name_is_capped() {
        let long = [b"/".as_slice(), &[b'N'; 17]].concat();
        let mut strict = Lexer::new(&long, 0, 64, 16, false);
        assert_eq!(strict.next_tok().unwrap_err().code(), "CS-PDF-0008");
        let ok = [b"/".as_slice(), &[b'N'; 16]].concat();
        assert!(matches!(
            Lexer::new(&ok, 0, 64, 16, false).next_tok().unwrap(),
            Some(Tok::Name(_))
        ));
    }

    #[test]
    fn unterminated_string_is_malformed() {
        let mut lx = Lexer::new(b"(abc", 0, 64, 16, false);
        assert_eq!(lx.next_tok().unwrap_err().code(), "CS-PDF-0005");
    }

    #[test]
    fn malformed_numbers_read_as_zero() {
        assert_eq!(toks(b"--5 1.2.3"), vec![Tok::Int(0), Tok::Int(0)]);
    }
}
