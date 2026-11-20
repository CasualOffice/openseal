//! The conversion protocol: one request and one answer per connection, over the daemon's
//! Unix socket and, with the same frames, between the daemon and its per-job child
//! (stdin and stdout).
//!
//! ```text
//! request  = "OSCV" version:u8 op:u8 len:u32be body[len]        op 0 ping (len 0), 1 convert
//! answer   = "OSCV" version:u8 status:u8 rest
//!   status 0 converted: external:u32be len:u32be pdf[len]
//!   status 1 refused:   code:u8 reason:u8                         (ConvertError::from_wire)
//!   status 2 pong
//! ```
//!
//! Every length is checked against [`MAX_INPUT`] or [`MAX_OUTPUT`] before a buffer is
//! allocated; either side reads the other's frames as hostile input.

use std::io::{Read, Write};

use crate::error::{ConvertError, Reason};

/// The frame's first bytes.
pub const MAGIC: [u8; 4] = *b"OSCV";
/// The protocol version.
pub const VERSION: u8 = 1;
/// A ping: is the daemon there.
pub const OP_PING: u8 = 0;
/// Convert the body, a `.docx`.
pub const OP_CONVERT: u8 = 1;
/// The largest `.docx` taken, bytes (64 MiB: above the server's 50 MiB upload cap).
pub const MAX_INPUT: usize = 64 << 20;
/// The largest PDF answered, bytes.
pub const MAX_OUTPUT: usize = 128 << 20;

const STATUS_OK: u8 = 0;
const STATUS_REFUSED: u8 = 1;
const STATUS_PONG: u8 = 2;

/// A converted document.
#[derive(Clone, PartialEq, Eq)]
pub struct Converted {
    /// The PDF.
    pub pdf: Vec<u8>,
    /// Relationships the document points outside itself with (`TargetMode="External"`:
    /// linked pictures, hyperlinks, attached templates). None is fetched; the count is
    /// reported so the evidence says the document referred outside itself.
    pub external_refs: u32,
}

impl core::fmt::Debug for Converted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never the bytes: they are document content.
        f.debug_struct("Converted")
            .field("pdf_len", &self.pdf.len())
            .field("external_refs", &self.external_refs)
            .finish()
    }
}

/// A request read by the daemon or the child.
#[derive(PartialEq, Eq)]
pub enum Request {
    /// Is the daemon there.
    Ping,
    /// Convert these bytes.
    Convert(Vec<u8>),
}

impl core::fmt::Debug for Request {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Ping => f.write_str("Ping"),
            Self::Convert(b) => write!(f, "Convert({} bytes)", b.len()),
        }
    }
}

/// An answer's head: what follows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Head {
    /// A PDF of `len` bytes follows, with this many external references.
    Converted { external: u32, len: usize },
    /// Refused.
    Refused(ConvertError),
    /// A ping's answer.
    Pong,
}

const PROTOCOL: ConvertError = ConvertError::Unavailable(Reason::Protocol);

/// The request header for `op` with a body of `len` bytes.
#[must_use]
pub fn request_header(op: u8, len: u32) -> [u8; 10] {
    let [a, b, c, d] = MAGIC;
    let [l0, l1, l2, l3] = len.to_be_bytes();
    [a, b, c, d, VERSION, op, l0, l1, l2, l3]
}

/// Parse a request header: the op and the body length, checked against [`MAX_INPUT`].
///
/// # Errors
/// `CS-CNV-0005 protocol` for a header that is not this protocol's; `CS-CNV-0003 input`
/// for a body over [`MAX_INPUT`].
pub fn parse_request_header(h: [u8; 10]) -> Result<(u8, usize), ConvertError> {
    let [a, b, c, d, v, op, l0, l1, l2, l3] = h;
    if [a, b, c, d] != MAGIC || v != VERSION || op > OP_CONVERT {
        return Err(PROTOCOL);
    }
    let len = usize::try_from(u32::from_be_bytes([l0, l1, l2, l3])).map_err(|_| PROTOCOL)?;
    if op == OP_PING && len != 0 {
        return Err(PROTOCOL);
    }
    if len > MAX_INPUT {
        return Err(ConvertError::OverLimit(Reason::Input));
    }
    Ok((op, len))
}

/// Read one request.
///
/// # Errors
/// As [`parse_request_header`]; `CS-CNV-0005 protocol` when the stream ends early.
pub fn read_request(r: &mut impl Read) -> Result<Request, ConvertError> {
    let mut h = [0u8; 10];
    r.read_exact(&mut h).map_err(|_| PROTOCOL)?;
    let (op, len) = parse_request_header(h)?;
    if op == OP_PING {
        return Ok(Request::Ping);
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).map_err(|_| PROTOCOL)?;
    Ok(Request::Convert(body))
}

/// Write a convert request for `docx`.
///
/// # Errors
/// The writer's error; `InvalidInput` for a body over [`MAX_INPUT`].
pub fn write_convert(w: &mut impl Write, docx: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(docx.len())
        .ok()
        .filter(|_| docx.len() <= MAX_INPUT)
        .ok_or(std::io::ErrorKind::InvalidInput)?;
    w.write_all(&request_header(OP_CONVERT, len))?;
    w.write_all(docx)?;
    w.flush()
}

fn answer_prefix(status: u8) -> [u8; 6] {
    let [a, b, c, d] = MAGIC;
    [a, b, c, d, VERSION, status]
}

/// Write an answer: the PDF, or the refusal.
///
/// # Errors
/// The writer's error; `InvalidInput` for a PDF over [`MAX_OUTPUT`] (the caller answers
/// `CS-CNV-0003 output` instead).
pub fn write_answer(
    w: &mut impl Write,
    answer: &Result<Converted, ConvertError>,
) -> std::io::Result<()> {
    match answer {
        Ok(c) => {
            let len = u32::try_from(c.pdf.len())
                .ok()
                .filter(|_| c.pdf.len() <= MAX_OUTPUT)
                .ok_or(std::io::ErrorKind::InvalidInput)?;
            w.write_all(&answer_prefix(STATUS_OK))?;
            w.write_all(&c.external_refs.to_be_bytes())?;
            w.write_all(&len.to_be_bytes())?;
            w.write_all(&c.pdf)?;
        }
        Err(e) => {
            w.write_all(&answer_prefix(STATUS_REFUSED))?;
            w.write_all(&[e.number(), e.reason().number()])?;
        }
    }
    w.flush()
}

/// Write a ping's answer.
///
/// # Errors
/// The writer's error.
pub fn write_pong(w: &mut impl Write) -> std::io::Result<()> {
    w.write_all(&answer_prefix(STATUS_PONG))?;
    w.flush()
}

/// Parse an answer's first six bytes and, for a status that carries more, the next
/// `rest` (8 bytes for status 0, 2 for status 1; see [`rest_len`]).
pub(crate) fn parse_head(prefix: [u8; 6], rest: &[u8]) -> Result<Head, ConvertError> {
    let [a, b, c, d, v, status] = prefix;
    if [a, b, c, d] != MAGIC || v != VERSION {
        return Err(PROTOCOL);
    }
    match (status, rest) {
        (STATUS_OK, [e0, e1, e2, e3, l0, l1, l2, l3]) => {
            let len =
                usize::try_from(u32::from_be_bytes([*l0, *l1, *l2, *l3])).map_err(|_| PROTOCOL)?;
            if len > MAX_OUTPUT {
                return Err(ConvertError::OverLimit(Reason::Output));
            }
            Ok(Head::Converted {
                external: u32::from_be_bytes([*e0, *e1, *e2, *e3]),
                len,
            })
        }
        (STATUS_REFUSED, [n, r]) => ConvertError::from_wire(*n, *r)
            .map(Head::Refused)
            .ok_or(PROTOCOL),
        (STATUS_PONG, []) => Ok(Head::Pong),
        _ => Err(PROTOCOL),
    }
}

/// How many bytes follow an answer prefix with this status before any PDF.
pub(crate) fn rest_len(prefix: [u8; 6]) -> usize {
    match prefix.get(5) {
        Some(&STATUS_OK) => 8,
        Some(&STATUS_REFUSED) => 2,
        _ => 0,
    }
}

/// A PDF answer's bytes must start as a PDF does; anything else is not trusted.
pub(crate) fn looks_like_pdf(pdf: &[u8]) -> bool {
    pdf.starts_with(b"%PDF-")
}

/// Read one answer (the daemon reading its child, or a blocking client).
///
/// # Errors
/// The refusal the answer carries; `CS-CNV-0005 protocol` for frames outside the
/// protocol or a PDF that does not start as one; `CS-CNV-0003 output` over
/// [`MAX_OUTPUT`].
pub fn read_answer(r: &mut impl Read) -> Result<Option<Converted>, ConvertError> {
    let mut prefix = [0u8; 6];
    r.read_exact(&mut prefix).map_err(|_| PROTOCOL)?;
    let mut rest = vec![0u8; rest_len(prefix)];
    r.read_exact(&mut rest).map_err(|_| PROTOCOL)?;
    match parse_head(prefix, &rest)? {
        Head::Pong => Ok(None),
        Head::Refused(e) => Err(e),
        Head::Converted { external, len } => {
            let mut pdf = vec![0u8; len];
            r.read_exact(&mut pdf).map_err(|_| PROTOCOL)?;
            if !looks_like_pdf(&pdf) {
                return Err(PROTOCOL);
            }
            Ok(Some(Converted {
                pdf,
                external_refs: external,
            }))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests may unwrap (CLAUDE.md).
mod tests {
    use super::*;

    #[test]
    fn a_converted_answer_round_trips() {
        let c = Converted {
            pdf: b"%PDF-1.7\n...".to_vec(),
            external_refs: 3,
        };
        let mut buf = Vec::new();
        write_answer(&mut buf, &Ok(c.clone())).unwrap();
        assert_eq!(read_answer(&mut buf.as_slice()), Ok(Some(c)));
    }

    #[test]
    fn a_refusal_round_trips() {
        let mut buf = Vec::new();
        write_answer(&mut buf, &Err(ConvertError::Macros)).unwrap();
        assert_eq!(read_answer(&mut buf.as_slice()), Err(ConvertError::Macros));
    }

    #[test]
    fn a_lying_length_is_refused_before_allocating() {
        let mut buf = answer_prefix(STATUS_OK).to_vec();
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            read_answer(&mut buf.as_slice()),
            Err(ConvertError::OverLimit(Reason::Output))
        );
        let mut h = request_header(OP_CONVERT, u32::MAX);
        assert_eq!(
            read_request(&mut h.as_slice()),
            Err(ConvertError::OverLimit(Reason::Input))
        );
        h[0] = b'X';
        assert_eq!(read_request(&mut h.as_slice()), Err(PROTOCOL));
    }

    #[test]
    fn an_answer_that_is_not_a_pdf_is_refused() {
        let mut buf = Vec::new();
        write_answer(
            &mut buf,
            &Ok(Converted {
                pdf: b"<html>".to_vec(),
                external_refs: 0,
            }),
        )
        .unwrap();
        assert_eq!(read_answer(&mut buf.as_slice()), Err(PROTOCOL));
    }

    #[test]
    fn a_truncated_or_unknown_frame_is_a_protocol_error() {
        let mut buf = Vec::new();
        write_answer(&mut buf, &Err(ConvertError::Macros)).unwrap();
        buf.pop();
        assert_eq!(read_answer(&mut buf.as_slice()), Err(PROTOCOL));
        let mut bad = answer_prefix(9).to_vec();
        bad.push(0);
        assert_eq!(read_answer(&mut bad.as_slice()), Err(PROTOCOL));
        let ping = request_header(OP_PING, 1);
        assert_eq!(read_request(&mut ping.as_slice()), Err(PROTOCOL));
    }
}
