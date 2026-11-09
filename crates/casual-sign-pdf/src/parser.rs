//! Iterative object parser: an explicit stack, so nesting is a counted limit and never
//! a stack overflow (`CS-PDF-0004`).

use crate::error::{PdfError, Result, off};
use crate::lexer::{Lexer, Tok};
use crate::object::{Dictionary, ObjRef, Object};

/// Most value-level warnings kept from one parse; the rest are counted only.
const MAX_WARNINGS: usize = 64;

/// Problems a lenient parse stepped over: the value was dropped and parsing went on.
#[derive(Debug, Default)]
pub(crate) struct Warnings {
    pub(crate) list: Vec<PdfError>,
}

impl Warnings {
    fn push(&mut self, e: PdfError) {
        if self.list.len() < MAX_WARNINGS {
            self.list.push(e);
        }
    }
}

enum Key {
    Need,
    Have(Vec<u8>),
    /// The key was an over-long name: drop its value.
    Skip,
}

enum Frame {
    Array(Vec<Object>),
    Dict(Dictionary, Key),
}

/// Parse one direct object at the lexer's position.
pub(crate) fn parse_object(
    lx: &mut Lexer<'_>,
    max_depth: usize,
    warns: &mut Warnings,
) -> Result<Object> {
    let mut stack: Vec<Frame> = Vec::new();
    loop {
        lx.skip_ws();
        let at = lx.pos;
        let malformed = PdfError::Malformed {
            object: None,
            offset: off(at),
        };
        let Some(tok) = lx.next_tok()? else {
            return Err(malformed);
        };
        // `None` means the token was a key-to-skip marker already handled.
        let value: Option<Object> = match tok {
            Tok::AOpen | Tok::DOpen if stack.len() >= max_depth => {
                return Err(PdfError::TooDeep { offset: off(at) });
            }
            Tok::AOpen => {
                stack.push(Frame::Array(Vec::new()));
                continue;
            }
            Tok::DOpen => {
                stack.push(Frame::Dict(Dictionary::new(), Key::Need));
                continue;
            }
            Tok::AClose => match stack.pop() {
                Some(Frame::Array(a)) => Some(Object::Array(a)),
                _ => return Err(malformed),
            },
            Tok::DClose => match stack.pop() {
                // A key with no value is dropped.
                Some(Frame::Dict(d, _)) => Some(Object::Dictionary(d)),
                _ => return Err(malformed),
            },
            Tok::Int(i) => Some(int_or_ref(lx, i)),
            Tok::Real(r) => Some(Object::Real(r)),
            Tok::Str(s) => Some(Object::String(s)),
            Tok::Name(n) => Some(Object::Name(n)),
            Tok::LongStr => {
                warns.push(PdfError::StringTooLong { offset: off(at) });
                Some(Object::Null)
            }
            Tok::LongName => {
                warns.push(PdfError::NameTooLong { offset: off(at) });
                if let Some(Frame::Dict(_, key @ Key::Need)) = stack.last_mut() {
                    *key = Key::Skip;
                    None
                } else {
                    Some(Object::Null)
                }
            }
            Tok::Kw(b"true") => Some(Object::Bool(true)),
            Tok::Kw(b"false") => Some(Object::Bool(false)),
            Tok::Kw(b"null") => Some(Object::Null),
            Tok::Kw(_) | Tok::Stray(_) => return Err(malformed),
        };
        let Some(value) = value else { continue };
        match stack.last_mut() {
            None => return Ok(value),
            Some(Frame::Array(a)) => a.push(value),
            Some(Frame::Dict(d, key)) => match core::mem::replace(key, Key::Need) {
                Key::Need => match value {
                    Object::Name(n) => *key = Key::Have(n),
                    _ => return Err(malformed),
                },
                Key::Have(k) => d.push(k, value),
                Key::Skip => {}
            },
        }
    }
}

/// After an integer: `g R` makes it a reference; otherwise the lexer is put back.
fn int_or_ref(lx: &mut Lexer<'_>, i: i64) -> Object {
    let save = lx.pos;
    if let Ok(num) = u32::try_from(i)
        && let Some(generation) = lx.uint().and_then(|g| u16::try_from(g).ok())
        && lx.keyword(b"R")
    {
        return Object::Reference(ObjRef { num, generation });
    }
    lx.pos = save;
    Object::Integer(i)
}

#[cfg(test)]
mod tests {
    // Tests index and unwrap freely: a panic is the failure report.
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
    use super::*;

    fn parse(s: &[u8], depth: usize, lenient: bool) -> (Result<Object>, Warnings) {
        let mut lx = Lexer::new(s, 0, 32, 8, lenient);
        let mut w = Warnings::default();
        (parse_object(&mut lx, depth, &mut w), w)
    }

    #[test]
    fn parses_nested_values_and_references() {
        let (o, _) = parse(
            b"<< /K [1 2 0 R 3.5 (s)] /D << /N /x >> /R 12 0 R >>",
            8,
            false,
        );
        let o = o.unwrap();
        let k = o.get(b"K").unwrap();
        let Object::Array(a) = k else { panic!("array") };
        assert_eq!(a[0], Object::Integer(1));
        assert_eq!(
            a[1],
            Object::Reference(ObjRef {
                num: 2,
                generation: 0
            })
        );
        assert_eq!(o.get(b"R").unwrap().as_ref().unwrap().num, 12);
        assert_eq!(
            o.get(b"D").unwrap().get(b"N").unwrap().as_name(),
            Some(b"x".as_slice())
        );
    }

    #[test]
    fn depth_cap_is_exact() {
        let ok = [vec![b'['; 8], vec![b']'; 8]].concat();
        assert!(parse(&ok, 8, false).0.is_ok());
        let deep = [vec![b'['; 9], vec![b']'; 9]].concat();
        assert_eq!(parse(&deep, 8, false).0.unwrap_err().code(), "CS-PDF-0004");
    }

    #[test]
    fn hundred_thousand_levels_is_an_error_not_a_stack_overflow() {
        let deep = [vec![b'['; 100_000], vec![b']'; 100_000]].concat();
        assert_eq!(
            parse(&deep, 256, false).0.unwrap_err().code(),
            "CS-PDF-0004"
        );
    }

    #[test]
    fn lenient_parse_drops_over_long_values_and_keys() {
        let s = b"<< /A (0123456789012345678901234567890123456789) /NNNNNNNNNNNN 1 /B 2 >>";
        let (o, w) = parse(s, 8, true);
        let o = o.unwrap();
        assert_eq!(o.get(b"A"), Some(&Object::Null));
        assert_eq!(o.get(b"B"), Some(&Object::Integer(2)));
        assert_eq!(o.dict().unwrap().len(), 2);
        assert_eq!(w.list.len(), 2);
        assert_eq!(parse(s, 8, false).0.unwrap_err().code(), "CS-PDF-0008");
    }

    #[test]
    fn unbalanced_input_is_malformed() {
        assert_eq!(
            parse(b"<< /A ]", 8, false).0.unwrap_err().code(),
            "CS-PDF-0005"
        );
        assert_eq!(
            parse(b"[1 2", 8, false).0.unwrap_err().code(),
            "CS-PDF-0005"
        );
        assert_eq!(
            parse(b"<< 1 2 >>", 8, false).0.unwrap_err().code(),
            "CS-PDF-0005"
        );
    }
}
