//! A bounded tokenizer for content streams and CMaps (ISO 32000-2 §7.8.2, §9.10.3).
//!
//! The reader in `casual-sign-pdf` parses objects; content streams are a different
//! grammar (operands followed by an operator, inline images), so they are tokenized
//! here. Every value is bounded: nesting, elements per array, token length. Nothing
//! read from the stream sizes an allocation.

/// Deepest nesting of arrays and dictionaries inside a content stream.
pub(crate) const MAX_NESTING: usize = 32;
/// Most elements in one array operand (a `TJ` array is the only large one in practice).
pub(crate) const MAX_ARRAY_ELEMENTS: usize = 65_536;
/// Longest number or keyword token, in bytes.
const MAX_TOKEN: usize = 64;

/// An operand.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Operand {
    /// A number.
    Num(f64),
    /// A string, decoded to bytes.
    Str(Vec<u8>),
    /// A name, without `/`.
    Name(Vec<u8>),
    /// An array.
    Array(Vec<Operand>),
    /// A dictionary (contents dropped: no text operator needs one), `true`, `false`,
    /// `null` or anything else that carries no value we use.
    Other,
}

impl Operand {
    pub(crate) fn num(&self) -> Option<f64> {
        match self {
            Self::Num(n) => Some(*n),
            _ => None,
        }
    }
}

/// A token.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Token<'a> {
    /// An operand.
    Operand(Operand),
    /// An operator keyword. An inline image (`BI … ID … EI`) is one `BI` token.
    Op(&'a [u8]),
}

/// Why tokenizing stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LexError {
    /// Nested deeper than [`MAX_NESTING`] (`CS-PDF-0004`).
    TooDeep,
    /// An array over [`MAX_ARRAY_ELEMENTS`] elements (`CS-PDF-0002`).
    TooManyValues,
}

impl LexError {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::TooDeep => "CS-PDF-0004",
            Self::TooManyValues => "CS-PDF-0002",
        }
    }
}

fn is_ws(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n' | b'\x0c' | b'\0')
}

fn is_delim(c: u8) -> bool {
    matches!(
        c,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(c.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

/// A tokenizer over one buffer.
#[derive(Debug)]
pub(crate) struct Lexer<'a> {
    b: &'a [u8],
    pos: usize,
    /// Inside an inline image's dictionary, where a `BI` must not start another.
    in_image: bool,
}

enum Item<'a> {
    Tok(Token<'a>),
    ArrayEnd,
    DictEnd,
}

impl<'a> Lexer<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
        Self {
            b,
            pos: 0,
            in_image: false,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }

    fn bump(&mut self) {
        self.pos = self.pos.saturating_add(1);
    }

    fn skip_ws(&mut self) {
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

    /// The next token; `None` at the end of the buffer.
    pub(crate) fn next_token(&mut self) -> Option<Result<Token<'a>, LexError>> {
        loop {
            match self.item(0)? {
                Ok(Item::Tok(t)) => return Some(Ok(t)),
                // A stray `]` or `>>` outside any array or dictionary: skip it.
                Ok(Item::ArrayEnd | Item::DictEnd) => {}
                Err(e) => return Some(Err(e)),
            }
        }
    }

    fn item(&mut self, depth: usize) -> Option<Result<Item<'a>, LexError>> {
        self.skip_ws();
        let c = self.peek()?;
        let r = match c {
            b'(' => {
                self.bump();
                Ok(Item::Tok(Token::Operand(Operand::Str(self.literal()))))
            }
            b'<' => {
                if self.b.get(self.pos.saturating_add(1)) == Some(&b'<') {
                    self.pos = self.pos.saturating_add(2);
                    self.dict(depth)
                        .map(|()| Item::Tok(Token::Operand(Operand::Other)))
                } else {
                    self.bump();
                    Ok(Item::Tok(Token::Operand(Operand::Str(self.hex()))))
                }
            }
            b'>' => {
                self.bump();
                if self.peek() == Some(b'>') {
                    self.bump();
                }
                Ok(Item::DictEnd)
            }
            b'[' => {
                self.bump();
                self.array(depth)
                    .map(|a| Item::Tok(Token::Operand(Operand::Array(a))))
            }
            b']' => {
                self.bump();
                Ok(Item::ArrayEnd)
            }
            b'{' | b'}' | b')' => {
                self.bump();
                Ok(Item::Tok(Token::Operand(Operand::Other)))
            }
            b'/' => {
                self.bump();
                Ok(Item::Tok(Token::Operand(Operand::Name(self.name()))))
            }
            _ => {
                let start = self.pos;
                while let Some(c) = self.peek() {
                    if is_ws(c) || is_delim(c) {
                        break;
                    }
                    self.bump();
                }
                let word = self.b.get(start..self.pos).unwrap_or_default();
                Ok(Item::Tok(self.word(word)))
            }
        };
        Some(r)
    }

    fn word(&mut self, word: &'a [u8]) -> Token<'a> {
        if let Some(n) = number(word) {
            return Token::Operand(Operand::Num(n));
        }
        match word {
            b"true" | b"false" | b"null" => Token::Operand(Operand::Other),
            b"BI" if !self.in_image => {
                self.in_image = true;
                self.skip_inline_image();
                self.in_image = false;
                Token::Op(b"BI")
            }
            _ => Token::Op(word),
        }
    }

    fn array(&mut self, depth: usize) -> Result<Vec<Operand>, LexError> {
        let depth = depth.saturating_add(1);
        if depth > MAX_NESTING {
            return Err(LexError::TooDeep);
        }
        let mut out = Vec::new();
        loop {
            match self.item(depth) {
                None | Some(Ok(Item::ArrayEnd)) => return Ok(out),
                Some(Ok(Item::DictEnd)) => {}
                Some(Ok(Item::Tok(Token::Operand(o)))) => {
                    if out.len() >= MAX_ARRAY_ELEMENTS {
                        return Err(LexError::TooManyValues);
                    }
                    out.push(o);
                }
                // An operator inside an array is damage; keep reading the array.
                Some(Ok(Item::Tok(Token::Op(_)))) => {}
                Some(Err(e)) => return Err(e),
            }
        }
    }

    fn dict(&mut self, depth: usize) -> Result<(), LexError> {
        let depth = depth.saturating_add(1);
        if depth > MAX_NESTING {
            return Err(LexError::TooDeep);
        }
        loop {
            match self.item(depth) {
                None | Some(Ok(Item::DictEnd)) => return Ok(()),
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(e),
            }
        }
    }

    fn literal(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut level: u32 = 0;
        while let Some(c) = self.peek() {
            self.bump();
            match c {
                b'(' => {
                    level = level.saturating_add(1);
                    out.push(c);
                }
                b')' => {
                    if level == 0 {
                        return out;
                    }
                    level = level.saturating_sub(1);
                    out.push(c);
                }
                b'\\' => {
                    let Some(e) = self.peek() else { break };
                    self.bump();
                    match e {
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'\r' => {
                            if self.peek() == Some(b'\n') {
                                self.bump();
                            }
                        }
                        b'\n' => {}
                        b'0'..=b'7' => {
                            let mut v: u32 = u32::from(e.wrapping_sub(b'0'));
                            for _ in 0..2 {
                                match self.peek() {
                                    Some(d @ b'0'..=b'7') => {
                                        self.bump();
                                        v = v
                                            .wrapping_mul(8)
                                            .wrapping_add(u32::from(d.wrapping_sub(b'0')));
                                    }
                                    _ => break,
                                }
                            }
                            out.push((v & 0xff) as u8);
                        }
                        other => out.push(other),
                    }
                }
                _ => out.push(c),
            }
        }
        out
    }

    fn hex(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut hi: Option<u8> = None;
        while let Some(c) = self.peek() {
            self.bump();
            if c == b'>' {
                break;
            }
            let Some(v) = hexval(c) else { continue };
            match hi.take() {
                Some(h) => out.push(h.wrapping_shl(4) | v),
                None => hi = Some(v),
            }
        }
        if let Some(h) = hi {
            out.push(h.wrapping_shl(4));
        }
        out
    }

    fn name(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(c) = self.peek() {
            if is_ws(c) || is_delim(c) {
                break;
            }
            self.bump();
            if c == b'#' {
                let h = self.peek().and_then(hexval);
                let l = self
                    .b
                    .get(self.pos.saturating_add(1))
                    .copied()
                    .and_then(hexval);
                if let (Some(h), Some(l)) = (h, l) {
                    self.pos = self.pos.saturating_add(2);
                    out.push(h.wrapping_shl(4) | l);
                    continue;
                }
            }
            if out.len() < 256 {
                out.push(c);
            }
        }
        out
    }

    /// Skip an inline image: its dictionary up to `ID`, then the data up to an `EI`
    /// that stands alone between whitespace (§8.9.7).
    fn skip_inline_image(&mut self) {
        // The dictionary: tokens up to the `ID` keyword.
        loop {
            self.skip_ws();
            let Some(c) = self.peek() else { return };
            if c == b'I' && self.b.get(self.pos.saturating_add(1)) == Some(&b'D') {
                let after = self.b.get(self.pos.saturating_add(2)).copied();
                if after.is_none_or(|a| is_ws(a) || is_delim(a)) {
                    self.pos = self.pos.saturating_add(3);
                    break;
                }
            }
            if self.item(MAX_NESTING).is_none() {
                return;
            }
        }
        // The data: find whitespace, `EI`, then whitespace or the end.
        let rest = self.b.get(self.pos..).unwrap_or_default();
        let mut i: usize = 0;
        while let Some(w) = rest.get(i..i.saturating_add(3)) {
            if is_ws(w.first().copied().unwrap_or(0))
                && w.get(1..3) == Some(b"EI".as_slice())
                && rest.get(i.saturating_add(3)).copied().is_none_or(is_ws)
            {
                self.pos = self.pos.saturating_add(i).saturating_add(3);
                return;
            }
            i = i.saturating_add(1);
        }
        // No `EI`: the image runs to the end of the buffer.
        self.pos = self.b.len();
    }
}

/// A PDF number: `[+-]?\d*\.?\d*` with at least one digit.
pub(crate) fn number(w: &[u8]) -> Option<f64> {
    if w.is_empty() || w.len() > MAX_TOKEN {
        return None;
    }
    let mut digits = false;
    let mut dot = false;
    for (i, &c) in w.iter().enumerate() {
        match c {
            b'0'..=b'9' => digits = true,
            b'.' if !dot => dot = true,
            b'+' | b'-' if i == 0 => {}
            _ => return None,
        }
    }
    if !digits {
        return None;
    }
    let s = core::str::from_utf8(w).ok()?;
    // `1.` and `.5` parse; a leading `+` too.
    let v: f64 = s.parse().ok()?;
    v.is_finite().then_some(v)
}

#[cfg(test)]
mod tests {
    // Tests may unwrap and index (CLAUDE.md): a failure here is the test failing.
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    fn toks(b: &[u8]) -> Vec<Token<'_>> {
        let mut l = Lexer::new(b);
        let mut out = Vec::new();
        while let Some(t) = l.next_token() {
            out.push(t.unwrap());
        }
        out
    }

    #[test]
    fn reads_operands_and_operators() {
        let t = toks(b"BT /F1 12 Tf (a\\(b\\)\\101) Tj <4142 4> Tj [(x) -250 (y)] TJ ET");
        assert_eq!(t[0], Token::Op(b"BT"));
        assert_eq!(t[1], Token::Operand(Operand::Name(b"F1".to_vec())));
        assert_eq!(t[2], Token::Operand(Operand::Num(12.0)));
        assert_eq!(t[4], Token::Operand(Operand::Str(b"a(b)A".to_vec())));
        assert_eq!(t[6], Token::Operand(Operand::Str(vec![0x41, 0x42, 0x40])));
        assert_eq!(
            t[8],
            Token::Operand(Operand::Array(vec![
                Operand::Str(b"x".to_vec()),
                Operand::Num(-250.0),
                Operand::Str(b"y".to_vec())
            ]))
        );
        assert_eq!(t.last(), Some(&Token::Op(b"ET")));
    }

    #[test]
    fn skips_inline_images_and_dictionaries() {
        let t = toks(b"q BI /W 2 /H 2 /BPC 8 ID \x00EI\x01\xff EI Q /P <</MCID 0>> BDC");
        assert_eq!(
            t,
            vec![
                Token::Op(b"q"),
                Token::Op(b"BI"),
                Token::Op(b"Q"),
                Token::Operand(Operand::Name(b"P".to_vec())),
                Token::Operand(Operand::Other),
                Token::Op(b"BDC"),
            ]
        );
    }

    #[test]
    fn deep_nesting_stops_with_a_code() {
        let mut deep = vec![b'['; MAX_NESTING + 1];
        deep.extend_from_slice(b"] TJ");
        let mut l = Lexer::new(&deep);
        assert_eq!(l.next_token(), Some(Err(LexError::TooDeep)));
    }

    #[test]
    fn numbers_follow_the_pdf_grammar() {
        assert_eq!(number(b"-.5"), Some(-0.5));
        assert_eq!(number(b"3."), Some(3.0));
        assert_eq!(number(b"1e5"), None);
        assert_eq!(number(b"--1"), None);
        assert_eq!(number(b"."), None);
    }
}
