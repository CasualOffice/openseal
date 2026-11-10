//! A bounded tokenizer for content streams (ISO 32000-2 §7.8.2, §8.9.7), on the
//! reader's own lexer, so text extraction and admission read content the same way
//! (`PDF-API-01`).
//!
//! Content is a different grammar from the object syntax: operands followed by an
//! operator, and inline images whose data is raw bytes. Every value is bounded:
//! nesting ([`MAX_CONTENT_NESTING`]), values per operand ([`MAX_OPERAND_VALUES`]),
//! string and name length (the document's [`Limits`]). Nothing read from the stream
//! sizes an allocation.

use core::fmt;

use crate::Limits;
use crate::lexer::{Lexer, Tok, is_regular, is_ws};
use crate::xref::find;

/// Deepest nesting of arrays and dictionaries inside one content-stream operand.
pub const MAX_CONTENT_NESTING: usize = 32;

/// Most values (array elements, dictionary keys and values) in one operand. A `TJ`
/// array is the only large one in practice.
pub const MAX_OPERAND_VALUES: usize = 65_536;

/// An operand in a content stream.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Operand {
    /// An integer.
    Integer(i64),
    /// A real number.
    Real(f64),
    /// A literal or hexadecimal string, decoded to bytes.
    String(Vec<u8>),
    /// A name, without `/`, `#xx` escapes applied.
    Name(Vec<u8>),
    /// An array.
    Array(Vec<Operand>),
    /// A dictionary, entries in stream order (marked-content properties, inline image
    /// parameters).
    Dictionary(Vec<(Vec<u8>, Operand)>),
    /// `true` or `false`.
    Bool(bool),
    /// `null`.
    Null,
}

impl Operand {
    /// The numeric value of an integer or real.
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            // Rounds above 2^53, which no meaningful content number reaches.
            Self::Integer(i) => Some(*i as f64),
            Self::Real(r) => Some(*r),
            _ => None,
        }
    }

    /// The name, if this is a name.
    #[must_use]
    pub fn as_name(&self) -> Option<&[u8]> {
        match self {
            Self::Name(n) => Some(n),
            _ => None,
        }
    }

    /// The bytes, if this is a string.
    #[must_use]
    pub fn as_string(&self) -> Option<&[u8]> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }
}

/// A content-stream token.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum ContentToken<'a> {
    /// An operand.
    Operand(Operand),
    /// An operator (any keyword other than `true`, `false` and `null`).
    Operator(&'a [u8]),
    /// An inline image, `BI` … `ID` … `EI`, as one token: its parameters and its data.
    InlineImage {
        /// The parameters between `BI` and `ID`, in order (abbreviated keys as written).
        parameters: Vec<(Vec<u8>, Operand)>,
        /// The data between `ID` and `EI` (the white space before `EI` excluded).
        data: &'a [u8],
    },
}

/// Why tokenizing stopped. The token stream ends after an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContentError {
    /// An operand nested deeper than [`MAX_CONTENT_NESTING`] (`CS-PDF-0004`).
    TooDeep {
        /// Byte offset in the stream.
        offset: usize,
    },
    /// An operand with more than [`MAX_OPERAND_VALUES`] values (`CS-PDF-0002`).
    TooManyValues {
        /// Byte offset in the stream.
        offset: usize,
    },
    /// A string or name over the document's limits (`CS-PDF-0008`).
    TooLong {
        /// Byte offset in the stream.
        offset: usize,
    },
}

impl ContentError {
    /// The stable code from docs/20.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::TooDeep { .. } => "CS-PDF-0004",
            Self::TooManyValues { .. } => "CS-PDF-0002",
            Self::TooLong { .. } => "CS-PDF-0008",
        }
    }
}

impl fmt::Display for ContentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            Self::TooDeep { offset } => write!(f, "{code}: content operand too deep at {offset}"),
            Self::TooManyValues { offset } => {
                write!(f, "{code}: content operand too large at {offset}")
            }
            Self::TooLong { offset } => {
                write!(f, "{code}: content string or name too long at {offset}")
            }
        }
    }
}

impl std::error::Error for ContentError {}

/// Tokens of a decoded content stream (or a CMap or Type 3 glyph procedure, which use
/// the same grammar). Stray delimiters and unknown bytes are skipped, as viewers do.
///
/// ```
/// use casual_sign_pdf::{ContentLexer, ContentToken, Limits, Operand};
/// let tokens: Vec<_> = ContentLexer::new(b"BT /F1 12 Tf (Hi) Tj ET", &Limits::default())
///     .collect::<Result<_, _>>()
///     .unwrap();
/// assert_eq!(tokens[1], ContentToken::Operand(Operand::Name(b"F1".to_vec())));
/// assert_eq!(tokens[3], ContentToken::Operator(b"Tf"));
/// ```
#[derive(Debug, Clone)]
pub struct ContentLexer<'a> {
    lx: Lexer<'a>,
    done: bool,
}

/// An array or dictionary being built.
enum Frame {
    Array(Vec<Operand>),
    Dict(Vec<(Vec<u8>, Operand)>, Option<Vec<u8>>),
}

impl<'a> ContentLexer<'a> {
    /// Tokenize `data` with the string and name caps of `limits`.
    #[must_use]
    pub fn new(data: &'a [u8], limits: &Limits) -> Self {
        Self {
            lx: Lexer::new(
                data,
                0,
                usize::try_from(limits.max_string_bytes).unwrap_or(usize::MAX),
                usize::from(limits.max_name_bytes),
                true,
            ),
            done: false,
        }
    }

    /// Byte offset of the next token.
    #[must_use]
    pub fn position(&self) -> usize {
        self.lx.pos
    }

    /// One operand, or `None` when the tokens do not make one (`Err` on a limit).
    /// `first` is a token already read. An operator met inside an unfinished operand
    /// is left to be read next.
    fn operand(&mut self, first: Tok<'a>) -> Result<Option<Operand>, ContentError> {
        let mut stack: Vec<Frame> = Vec::new();
        let mut values: usize = 0;
        let mut tok = first;
        loop {
            let at = self.lx.pos;
            let value = match tok {
                Tok::AOpen | Tok::DOpen if stack.len() >= MAX_CONTENT_NESTING => {
                    return Err(ContentError::TooDeep { offset: at });
                }
                Tok::AOpen => {
                    stack.push(Frame::Array(Vec::new()));
                    None
                }
                Tok::DOpen => {
                    stack.push(Frame::Dict(Vec::new(), None));
                    None
                }
                Tok::AClose => match stack.pop() {
                    Some(Frame::Array(a)) => Some(Operand::Array(a)),
                    // An unbalanced `]`: what was open is dropped.
                    Some(Frame::Dict(..)) | None => None,
                },
                Tok::DClose => match stack.pop() {
                    Some(Frame::Dict(d, _)) => Some(Operand::Dictionary(d)),
                    Some(Frame::Array(..)) | None => None,
                },
                Tok::Int(i) => Some(Operand::Integer(i)),
                Tok::Real(r) => Some(Operand::Real(r)),
                Tok::Str(s) => Some(Operand::String(s)),
                Tok::Name(n) => Some(Operand::Name(n)),
                Tok::LongStr | Tok::LongName => return Err(ContentError::TooLong { offset: at }),
                Tok::Kw(b"true") => Some(Operand::Bool(true)),
                Tok::Kw(b"false") => Some(Operand::Bool(false)),
                Tok::Kw(b"null") => Some(Operand::Null),
                // An operator inside an operand: the operand ends unfinished, and
                // the operator is read next.
                Tok::Kw(k) => {
                    self.lx.pos = at.saturating_sub(k.len());
                    return Ok(None);
                }
                Tok::Stray(_) => None,
            };
            if let Some(v) = value {
                values = values.saturating_add(1);
                if values > MAX_OPERAND_VALUES {
                    return Err(ContentError::TooManyValues { offset: at });
                }
                match stack.last_mut() {
                    None => return Ok(Some(v)),
                    Some(Frame::Array(a)) => a.push(v),
                    Some(Frame::Dict(d, key)) => match key.take() {
                        Some(k) => d.push((k, v)),
                        // A non-name where a key belongs is dropped.
                        None => {
                            if let Operand::Name(n) = v {
                                *key = Some(n);
                            }
                        }
                    },
                }
            } else if stack.is_empty() {
                // A stray delimiter or an unbalanced close with nothing open.
                return Ok(None);
            }
            tok = match self.next_raw() {
                Some(t) => t,
                // The stream ended inside an operand.
                None => return Ok(None),
            };
        }
    }

    /// The next lexer token, skipping bytes the lexer cannot read.
    fn next_raw(&mut self) -> Option<Tok<'a>> {
        loop {
            let at = self.lx.pos;
            match self.lx.next_tok() {
                Ok(t) => return t,
                // An unterminated string or bad hex: skip a byte, as viewers do.
                Err(_) => self.lx.pos = self.lx.pos.max(at.saturating_add(1)),
            }
        }
    }

    /// After `BI`: the parameters up to `ID`, then the data up to `EI`.
    fn inline_image(&mut self) -> Result<ContentToken<'a>, ContentError> {
        let mut parameters = Vec::new();
        let mut key: Option<Vec<u8>> = None;
        loop {
            let Some(tok) = self.next_raw() else {
                return Ok(ContentToken::InlineImage {
                    parameters,
                    data: &[],
                });
            };
            match tok {
                Tok::Kw(b"ID") => break,
                // Another keyword among the parameters (`true`, `false` and `null` are
                // values): skipped, so an operand never hands it back here.
                Tok::Kw(k) if !matches!(k, b"true" | b"false" | b"null") => continue,
                _ => {}
            }
            let Some(v) = self.operand(tok)? else {
                continue;
            };
            if parameters.len() >= MAX_OPERAND_VALUES {
                return Err(ContentError::TooManyValues {
                    offset: self.lx.pos,
                });
            }
            match key.take() {
                Some(k) => parameters.push((k, v)),
                None => {
                    if let Operand::Name(n) = v {
                        key = Some(n);
                    }
                }
            }
        }
        // One white-space byte follows `ID`; the data runs to an `EI` that stands
        // alone between white space (or the end).
        let b = self.lx.b;
        let start = self.lx.pos.saturating_add(1).min(b.len());
        let (data_end, next) = inline_image_end(b, start);
        self.lx.pos = next;
        Ok(ContentToken::InlineImage {
            parameters,
            data: b.get(start..data_end).unwrap_or_default(),
        })
    }
}

/// Where inline image data starting at `start` ends: (end of the data, position after
/// `EI`). `EI` counts when white space precedes it and a delimiter, white space or the
/// end follows; with no such `EI` the data runs to the end.
pub(crate) fn inline_image_end(b: &[u8], start: usize) -> (usize, usize) {
    let mut from = start;
    while let Some(p) = find(b, b"EI", from) {
        let before = p
            .checked_sub(1)
            .and_then(|i| b.get(i))
            .is_some_and(|&c| is_ws(c));
        let after = b.get(p.saturating_add(2)).is_none_or(|&c| !is_regular(c));
        if before && after {
            return (p.saturating_sub(1).max(start), p.saturating_add(2));
        }
        from = p.saturating_add(2);
    }
    (b.len(), b.len())
}

impl<'a> Iterator for ContentLexer<'a> {
    type Item = Result<ContentToken<'a>, ContentError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        loop {
            let tok = self.next_raw()?;
            let r = match tok {
                Tok::Kw(b"BI") => self.inline_image(),
                Tok::Kw(k) if !matches!(k, b"true" | b"false" | b"null") => {
                    Ok(ContentToken::Operator(k))
                }
                other => match self.operand(other) {
                    Ok(Some(v)) => Ok(ContentToken::Operand(v)),
                    Ok(None) => continue,
                    Err(e) => Err(e),
                },
            };
            if r.is_err() {
                self.done = true;
            }
            return Some(r);
        }
    }
}

#[cfg(test)]
mod tests {
    // Tests index and unwrap freely: a panic is the failure report.
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
    use super::*;

    fn toks(b: &[u8]) -> Vec<ContentToken<'_>> {
        ContentLexer::new(b, &Limits::default())
            .collect::<Result<_, _>>()
            .unwrap()
    }

    #[test]
    fn reads_operands_and_operators() {
        let t = toks(b"q 1 0 0 1 72.5 -3 cm [(a) -120 (b)] TJ /P <</MCID 3>> BDC");
        assert_eq!(t[0], ContentToken::Operator(b"q"));
        assert_eq!(t[5], ContentToken::Operand(Operand::Real(72.5)));
        assert_eq!(t[6], ContentToken::Operand(Operand::Integer(-3)));
        assert_eq!(t[7], ContentToken::Operator(b"cm"));
        assert_eq!(
            t[8],
            ContentToken::Operand(Operand::Array(vec![
                Operand::String(b"a".to_vec()),
                Operand::Integer(-120),
                Operand::String(b"b".to_vec()),
            ]))
        );
        assert_eq!(
            t[11],
            ContentToken::Operand(Operand::Dictionary(vec![(
                b"MCID".to_vec(),
                Operand::Integer(3)
            )]))
        );
        assert_eq!(t[12], ContentToken::Operator(b"BDC"));
    }

    #[test]
    fn inline_images_are_one_token_with_their_data() {
        let t = toks(b"BI /W 2 /H 1 /CS /G /BPC 8 ID \x00EI\xff EI Q");
        match &t[0] {
            ContentToken::InlineImage { parameters, data } => {
                assert_eq!(parameters.len(), 4);
                assert_eq!(parameters[0], (b"W".to_vec(), Operand::Integer(2)));
                assert_eq!(*data, b"\x00EI\xff");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(t[1], ContentToken::Operator(b"Q"));
    }

    #[test]
    fn nesting_and_size_are_bounded() {
        let deep = [vec![b'['; 40], vec![b']'; 40]].concat();
        let e = ContentLexer::new(&deep, &Limits::default())
            .find_map(Result::err)
            .unwrap();
        assert_eq!(e.code(), "CS-PDF-0004");
        let mut big = b"[".to_vec();
        for _ in 0..70_000 {
            big.extend_from_slice(b"1 ");
        }
        big.push(b']');
        let e = ContentLexer::new(&big, &Limits::default())
            .find_map(Result::err)
            .unwrap();
        assert_eq!(e.code(), "CS-PDF-0002");
    }

    #[test]
    fn stray_bytes_are_skipped() {
        let t = toks(b") } ] 5 Tw (unterminated");
        assert_eq!(t[0], ContentToken::Operand(Operand::Integer(5)));
        assert_eq!(t[1], ContentToken::Operator(b"Tw"));
    }
}
