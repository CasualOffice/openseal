//! Serializing the object model (ISO 32000-2 §7.3), deterministically.
//!
//! The same object always gives the same bytes: dictionary entries keep the order
//! given, one entry per key (the last, which is the one every reader uses, at its own
//! position), names are `#`-escaped, strings are literal when printable and
//! hexadecimal otherwise, and reals never use an exponent. Writing is iterative, so
//! a deeply nested value built by a caller cannot exhaust the stack.

use std::borrow::Cow;
use std::collections::BTreeSet;

use crate::object::{Dictionary, ObjRef, Object};

/// The body of an indirect object to write.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Body<'a> {
    /// A value that is not a stream.
    Value(Object),
    /// A stream: its dictionary (`/Length` is written from the data) and its encoded
    /// bytes, as stored.
    Stream {
        /// The stream dictionary.
        dict: Dictionary,
        /// The encoded data.
        data: Cow<'a, [u8]>,
    },
}

/// One step of the iterative writer.
enum Item<'o> {
    Value(&'o Object),
    Raw(&'static [u8]),
    Key(&'o [u8]),
}

fn is_delimiter(c: u8) -> bool {
    matches!(
        c,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

const HEX: &[u8; 16] = b"0123456789ABCDEF";

fn hex_digit(n: u8) -> u8 {
    HEX.get(usize::from(n & 0x0f)).copied().unwrap_or(b'0')
}

/// `/name`, with `#xx` for every byte outside `!`..`~`, delimiters and `#`.
pub(crate) fn write_name(out: &mut Vec<u8>, name: &[u8]) {
    out.push(b'/');
    for &c in name {
        if (0x21..=0x7e).contains(&c) && !is_delimiter(c) && c != b'#' {
            out.push(c);
        } else {
            out.extend_from_slice(&[b'#', hex_digit(c >> 4), hex_digit(c)]);
        }
    }
}

/// A literal string when every byte is printable ASCII or common white space,
/// otherwise a hexadecimal string.
pub(crate) fn write_string(out: &mut Vec<u8>, s: &[u8]) {
    let printable = s
        .iter()
        .all(|&c| (0x20..=0x7e).contains(&c) || matches!(c, b'\n' | b'\r' | b'\t'));
    if printable {
        out.push(b'(');
        for &c in s {
            match c {
                b'(' | b')' | b'\\' => out.extend_from_slice(&[b'\\', c]),
                b'\n' => out.extend_from_slice(b"\\n"),
                b'\r' => out.extend_from_slice(b"\\r"),
                b'\t' => out.extend_from_slice(b"\\t"),
                _ => out.push(c),
            }
        }
        out.push(b')');
    } else {
        out.push(b'<');
        for &c in s {
            out.extend_from_slice(&[hex_digit(c >> 4), hex_digit(c)]);
        }
        out.push(b'>');
    }
}

/// A real in plain decimal (Rust's shortest round-trip form never uses an exponent).
/// A value that is not finite, which the reader never produces, is written as 0.
pub(crate) fn write_real(out: &mut Vec<u8>, r: f64) {
    if !r.is_finite() || r == 0.0 {
        out.push(b'0');
        return;
    }
    out.extend_from_slice(format!("{r}").as_bytes());
}

fn write_ref(out: &mut Vec<u8>, r: ObjRef) {
    out.extend_from_slice(format!("{} {} R", r.num, r.generation).as_bytes());
}

/// Push a dictionary's entries (last entry per key) for the iterative writer.
fn push_dict<'o>(out: &mut Vec<u8>, stack: &mut Vec<Item<'o>>, d: &'o Dictionary) {
    out.extend_from_slice(b"<<");
    stack.push(Item::Raw(b">>"));
    let mut seen: BTreeSet<&[u8]> = BTreeSet::new();
    let entries: Vec<(&[u8], &Object)> = d.iter().collect();
    for (k, v) in entries.into_iter().rev() {
        if seen.insert(k) {
            stack.push(Item::Value(v));
            stack.push(Item::Key(k));
        }
    }
}

/// Write one direct value. A stream writes only its dictionary.
pub(crate) fn write_value(out: &mut Vec<u8>, root: &Object) {
    let mut stack: Vec<Item<'_>> = vec![Item::Value(root)];
    while let Some(item) = stack.pop() {
        match item {
            Item::Raw(b) => out.extend_from_slice(b),
            Item::Key(k) => {
                write_name(out, k);
                out.push(b' ');
            }
            Item::Value(v) => match v {
                Object::Null => out.extend_from_slice(b"null"),
                Object::Bool(true) => out.extend_from_slice(b"true"),
                Object::Bool(false) => out.extend_from_slice(b"false"),
                Object::Integer(i) => out.extend_from_slice(i.to_string().as_bytes()),
                Object::Real(r) => write_real(out, *r),
                Object::String(s) => write_string(out, s),
                Object::Name(n) => write_name(out, n),
                Object::Reference(r) => write_ref(out, *r),
                Object::Array(a) => {
                    out.push(b'[');
                    stack.push(Item::Raw(b"]"));
                    for (i, e) in a.iter().enumerate().rev() {
                        stack.push(Item::Value(e));
                        if i > 0 {
                            stack.push(Item::Raw(b" "));
                        }
                    }
                }
                Object::Dictionary(d) => push_dict(out, &mut stack, d),
                Object::Stream(s) => push_dict(out, &mut stack, &s.dict),
            },
        }
    }
}

/// Write a stream's dictionary with `/Length` set to the data's length, then the data.
fn write_stream_body(out: &mut Vec<u8>, dict: &Dictionary, data: &[u8]) {
    let mut d = dict.clone();
    let len = i64::try_from(data.len()).unwrap_or(i64::MAX);
    d.insert(b"Length", Object::Integer(len));
    write_value(out, &Object::Dictionary(d));
    out.extend_from_slice(b"\nstream\n");
    out.extend_from_slice(data);
    out.extend_from_slice(b"\nendstream");
}

/// `num gen obj … endobj` followed by a newline.
pub(crate) fn write_indirect(out: &mut Vec<u8>, r: ObjRef, body: &Body<'_>) {
    out.extend_from_slice(format!("{} {} obj\n", r.num, r.generation).as_bytes());
    match body {
        Body::Value(v) => write_value(out, v),
        Body::Stream { dict, data } => write_stream_body(out, dict, data),
    }
    out.extend_from_slice(b"\nendobj\n");
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report.
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn ser(o: &Object) -> String {
        let mut out = Vec::new();
        write_value(&mut out, o);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn names_are_escaped() {
        let mut out = Vec::new();
        write_name(&mut out, b"A B#(x)/\x00\xff");
        assert_eq!(out, b"/A#20B#23#28x#29#2F#00#FF");
    }

    #[test]
    fn strings_are_literal_or_hex() {
        assert_eq!(
            ser(&Object::String(b"a(b)\\c\n".to_vec())),
            "(a\\(b\\)\\\\c\\n)"
        );
        assert_eq!(ser(&Object::String(vec![0xfe, 0xff, 0, 65])), "<FEFF0041>");
        assert_eq!(ser(&Object::String(Vec::new())), "()");
    }

    #[test]
    fn numbers_never_use_exponents() {
        assert_eq!(ser(&Object::Real(1e20)), "100000000000000000000");
        assert_eq!(ser(&Object::Real(0.000_001)), "0.000001");
        assert_eq!(ser(&Object::Real(-0.0)), "0");
        assert_eq!(ser(&Object::Real(f64::NAN)), "0");
        assert_eq!(ser(&Object::Integer(-42)), "-42");
    }

    #[test]
    fn dictionaries_keep_order_and_the_last_duplicate() {
        let d: Dictionary = [
            (b"B".to_vec(), Object::Integer(1)),
            (
                b"A".to_vec(),
                Object::Array(vec![Object::Null, Object::Bool(true)]),
            ),
            (b"B".to_vec(), Object::Integer(2)),
        ]
        .into_iter()
        .collect();
        assert_eq!(ser(&Object::Dictionary(d)), "<</A [null true]/B 2>>");
    }

    #[test]
    fn deep_nesting_does_not_recurse() {
        let mut o = Object::Null;
        for _ in 0..200_000 {
            o = Object::Array(vec![o]);
        }
        let s = ser(&o);
        assert_eq!(s.len(), 200_000 * 2 + 4);
        // Drop iteratively: the derived drop would recurse.
        let mut cur = o;
        while let Object::Array(mut a) = cur {
            cur = a.pop().unwrap_or(Object::Null);
        }
    }

    #[test]
    fn stream_length_is_the_data_length() {
        let mut d = Dictionary::new();
        d.insert(
            b"Length",
            Object::Reference(ObjRef {
                num: 9,
                generation: 0,
            }),
        );
        d.insert(b"Filter", Object::Name(b"FlateDecode".to_vec()));
        let mut out = Vec::new();
        let body = Body::Stream {
            dict: d,
            data: Cow::Borrowed(b"abc"),
        };
        write_indirect(
            &mut out,
            ObjRef {
                num: 3,
                generation: 1,
            },
            &body,
        );
        assert_eq!(
            out,
            b"3 1 obj\n<</Length 3/Filter /FlateDecode>>\nstream\nabc\nendstream\nendobj\n"
        );
    }
}
