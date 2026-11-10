//! keyd's protocol inside the mutually authenticated TLS stream: length-prefixed binary
//! frames, every field bounded, every read checked. A frame from the network is hostile
//! input: nothing here indexes, unwraps or does unchecked arithmetic on it.
//!
//! ```text
//! frame    = len:u32be body            (len <= MAX_FRAME)
//! request  = 0x01 op alias:str8 [sign]
//!   op     = 0x01 get-certificate-chain | 0x02 sign-digest
//!   sign   = alg:u8 digest:bytes8 envelope:str8
//! response = 0x01 0x00 ok-body | 0x01 0x01 code:u16be
//!   chain  = alg:u8 development:u8 count:u8 (der:bytes32){count}
//!   sig    = signature:bytes16
//! str8     = len:u8 [A-Za-z0-9._-]{len}
//! ```
//!
//! An alias and an envelope id are identifiers: their alphabet keeps the operation log
//! free of anything a caller could smuggle into it.

use std::io::{Read, Write};

use crate::error::KeydError;

/// Protocol version.
pub(crate) const VERSION: u8 = 1;
/// Largest frame either side reads: a chain of [`crate::pem::MAX_CHAIN`] certificates of
/// at most [`MAX_CERT`] bytes fits.
pub(crate) const MAX_FRAME: usize = 1 << 20;
/// Largest certificate in a chain.
pub(crate) const MAX_CERT: usize = 64 * 1024;
/// Longest alias or envelope id.
pub(crate) const MAX_ID: usize = 64;
/// Longest digest (SHA-512).
pub(crate) const MAX_DIGEST: usize = 64;

const OP_CHAIN: u8 = 1;
const OP_SIGN: u8 = 2;

/// A request to keyd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Request {
    /// The key's algorithm and certificate chain.
    Chain {
        /// Key alias.
        alias: String,
    },
    /// Sign a digest.
    Sign {
        /// Key alias.
        alias: String,
        /// Wire id of the algorithm the caller expects.
        alg: u8,
        /// The digest.
        digest: Vec<u8>,
        /// The envelope the seal is for, for the operation log.
        envelope: String,
    },
}

/// keyd's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Response {
    /// The chain.
    Chain {
        /// Wire id of the key's algorithm.
        alg: u8,
        /// A development file key.
        development: bool,
        /// DER certificates, signer first.
        certs: Vec<Vec<u8>>,
    },
    /// A signature value.
    Signature(Vec<u8>),
    /// Refused or failed, with the `CS-KEY-` number.
    Error(u16),
}

fn malformed(why: &'static str) -> KeydError {
    KeydError::Malformed(why)
}

/// Whether `s` is a valid identifier (alias or envelope id).
pub(crate) fn valid_id(s: &str, allow_empty: bool) -> bool {
    (allow_empty || !s.is_empty())
        && s.len() <= MAX_ID
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A cursor over a frame body.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], KeydError> {
        if n > self.0.len() {
            return Err(malformed("truncated"));
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, KeydError> {
        self.take(1)?.first().copied().ok_or(malformed("truncated"))
    }

    fn u16(&mut self) -> Result<u16, KeydError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes(
            b.try_into().map_err(|_| malformed("truncated"))?,
        ))
    }

    fn u32(&mut self) -> Result<u32, KeydError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes(
            b.try_into().map_err(|_| malformed("truncated"))?,
        ))
    }

    fn bytes8(&mut self) -> Result<&'a [u8], KeydError> {
        let n = self.u8()?;
        self.take(usize::from(n))
    }

    fn id(&mut self, allow_empty: bool) -> Result<String, KeydError> {
        let raw = self.bytes8()?;
        let s = core::str::from_utf8(raw).map_err(|_| malformed("identifier is not ASCII"))?;
        if !valid_id(s, allow_empty) {
            return Err(malformed(
                "identifier has a character outside [A-Za-z0-9._-]",
            ));
        }
        Ok(s.to_owned())
    }

    fn end(&self) -> Result<(), KeydError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(malformed("trailing bytes"))
        }
    }
}

fn put8(out: &mut Vec<u8>, b: &[u8]) -> Result<(), KeydError> {
    out.push(u8::try_from(b.len()).map_err(|_| malformed("field over 255 bytes"))?);
    out.extend_from_slice(b);
    Ok(())
}

impl Request {
    /// Encode.
    pub(crate) fn encode(&self) -> Result<Vec<u8>, KeydError> {
        let mut out = vec![VERSION];
        match self {
            Self::Chain { alias } => {
                out.push(OP_CHAIN);
                put8(&mut out, alias.as_bytes())?;
            }
            Self::Sign {
                alias,
                alg,
                digest,
                envelope,
            } => {
                out.push(OP_SIGN);
                put8(&mut out, alias.as_bytes())?;
                out.push(*alg);
                put8(&mut out, digest)?;
                put8(&mut out, envelope.as_bytes())?;
            }
        }
        Ok(out)
    }

    /// Decode a frame body.
    pub(crate) fn decode(body: &[u8]) -> Result<Self, KeydError> {
        let mut r = Reader(body);
        if r.u8()? != VERSION {
            return Err(malformed("unknown protocol version"));
        }
        let op = r.u8()?;
        let alias = r.id(false)?;
        let req = match op {
            OP_CHAIN => Self::Chain { alias },
            OP_SIGN => {
                let alg = r.u8()?;
                let digest = r.bytes8()?;
                if digest.len() > MAX_DIGEST {
                    return Err(malformed("digest too long"));
                }
                let digest = digest.to_vec();
                let envelope = r.id(true)?;
                Self::Sign {
                    alias,
                    alg,
                    digest,
                    envelope,
                }
            }
            _ => return Err(malformed("unknown operation")),
        };
        r.end()?;
        Ok(req)
    }
}

impl Response {
    /// Encode.
    pub(crate) fn encode(&self) -> Result<Vec<u8>, KeydError> {
        let mut out = vec![VERSION];
        match self {
            Self::Chain {
                alg,
                development,
                certs,
            } => {
                out.push(0);
                out.push(*alg);
                out.push(u8::from(*development));
                out.push(u8::try_from(certs.len()).map_err(|_| malformed("chain too long"))?);
                for c in certs {
                    if c.len() > MAX_CERT {
                        return Err(malformed("certificate too large"));
                    }
                    let n =
                        u32::try_from(c.len()).map_err(|_| malformed("certificate too large"))?;
                    out.extend_from_slice(&n.to_be_bytes());
                    out.extend_from_slice(c);
                }
            }
            Self::Signature(sig) => {
                out.push(0);
                let n = u16::try_from(sig.len()).map_err(|_| malformed("signature too large"))?;
                out.extend_from_slice(&n.to_be_bytes());
                out.extend_from_slice(sig);
            }
            Self::Error(code) => {
                out.push(1);
                out.extend_from_slice(&code.to_be_bytes());
            }
        }
        Ok(out)
    }

    /// Decode a frame body answering `request`.
    pub(crate) fn decode(body: &[u8], request: &Request) -> Result<Self, KeydError> {
        let mut r = Reader(body);
        if r.u8()? != VERSION {
            return Err(malformed("unknown protocol version"));
        }
        let resp = match r.u8()? {
            1 => Self::Error(r.u16()?),
            0 => match request {
                Request::Chain { .. } => {
                    let alg = r.u8()?;
                    let development = match r.u8()? {
                        0 => false,
                        1 => true,
                        _ => return Err(malformed("development flag")),
                    };
                    let count = r.u8()?;
                    if count == 0 || usize::from(count) > crate::pem::MAX_CHAIN {
                        return Err(malformed("chain length"));
                    }
                    let mut certs = Vec::with_capacity(usize::from(count));
                    for _ in 0..count {
                        let n = usize::try_from(r.u32()?).map_err(|_| malformed("length"))?;
                        if n > MAX_CERT {
                            return Err(malformed("certificate too large"));
                        }
                        certs.push(r.take(n)?.to_vec());
                    }
                    Self::Chain {
                        alg,
                        development,
                        certs,
                    }
                }
                Request::Sign { .. } => {
                    let n = r.u16()?;
                    Self::Signature(r.take(usize::from(n))?.to_vec())
                }
            },
            _ => return Err(malformed("unknown status")),
        };
        r.end()?;
        Ok(resp)
    }
}

/// Read one frame. `Ok(None)` at a clean end of stream before a frame starts.
pub(crate) fn read_frame(stream: &mut impl Read) -> Result<Option<Vec<u8>>, KeydError> {
    let mut len = [0u8; 4];
    let mut got = 0usize;
    while got < len.len() {
        let slot = len.get_mut(got..).ok_or(malformed("truncated"))?;
        match stream.read(slot) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(malformed("truncated frame length")),
            Ok(n) => got = got.saturating_add(n),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(KeydError::Transport(e.kind().to_string())),
        }
    }
    let n = usize::try_from(u32::from_be_bytes(len)).map_err(|_| malformed("frame length"))?;
    if n > MAX_FRAME {
        return Err(malformed("frame over the limit"));
    }
    let mut body = vec![0u8; n];
    stream
        .read_exact(&mut body)
        .map_err(|e| KeydError::Transport(e.kind().to_string()))?;
    Ok(Some(body))
}

/// Write one frame.
pub(crate) fn write_frame(stream: &mut impl Write, body: &[u8]) -> Result<(), KeydError> {
    if body.len() > MAX_FRAME {
        return Err(malformed("frame over the limit"));
    }
    let n = u32::try_from(body.len()).map_err(|_| malformed("frame length"))?;
    let io = |e: std::io::Error| KeydError::Transport(e.kind().to_string());
    stream.write_all(&n.to_be_bytes()).map_err(io)?;
    stream.write_all(body).map_err(io)?;
    stream.flush().map_err(io)
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report.
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    fn sign_request() -> Request {
        Request::Sign {
            alias: "platform".into(),
            alg: 1,
            digest: vec![7; 32],
            envelope: "env_01J9".into(),
        }
    }

    #[test]
    fn requests_and_responses_round_trip() {
        for req in [Request::Chain { alias: "a".into() }, sign_request()] {
            assert_eq!(Request::decode(&req.encode().unwrap()).unwrap(), req);
        }
        let chain = Response::Chain {
            alg: 2,
            development: true,
            certs: vec![vec![0x30, 0], vec![0x30, 1, 2]],
        };
        let req = Request::Chain { alias: "a".into() };
        assert_eq!(
            Response::decode(&chain.encode().unwrap(), &req).unwrap(),
            chain
        );
        let sig = Response::Signature(vec![9; 70]);
        assert_eq!(
            Response::decode(&sig.encode().unwrap(), &sign_request()).unwrap(),
            sig
        );
        let err = Response::Error(8);
        assert_eq!(Response::decode(&err.encode().unwrap(), &req).unwrap(), err);
    }

    /// Every truncation and every extension of a valid request is refused, not panicked on.
    #[test]
    fn truncated_or_extended_frames_are_refused() {
        let body = sign_request().encode().unwrap();
        for n in 0..body.len() {
            assert!(Request::decode(&body[..n]).is_err(), "prefix {n}");
        }
        let mut longer = body.clone();
        longer.push(0);
        assert!(Request::decode(&longer).is_err());
        let resp = Response::Chain {
            alg: 1,
            development: false,
            certs: vec![vec![1; 10]],
        }
        .encode()
        .unwrap();
        let req = Request::Chain { alias: "a".into() };
        for n in 0..resp.len() {
            assert!(Response::decode(&resp[..n], &req).is_err(), "prefix {n}");
        }
    }

    #[test]
    fn identifiers_outside_the_alphabet_are_refused() {
        for bad in ["", "a b", "a\nb", "ünï", "a/b"] {
            let body = Request::Chain { alias: bad.into() }.encode().unwrap();
            assert!(Request::decode(&body).is_err(), "{bad:?}");
        }
        let long = "a".repeat(MAX_ID + 1);
        let body = Request::Chain { alias: long }.encode().unwrap();
        assert!(Request::decode(&body).is_err());
    }

    #[test]
    fn an_oversized_frame_is_refused_before_it_is_read() {
        let mut stream: &[u8] = &[0xff, 0xff, 0xff, 0xff, 0, 0];
        assert_eq!(read_frame(&mut stream).unwrap_err().code(), "CS-KEY-0007");
        let mut empty: &[u8] = &[];
        assert_eq!(read_frame(&mut empty).unwrap(), None);
        let mut short: &[u8] = &[0, 0];
        assert!(read_frame(&mut short).is_err());
    }

    /// Bytes from a deterministic generator never panic the decoder.
    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut x: u32 = 0x1234_5678;
        let req = Request::Chain { alias: "a".into() };
        for len in 0..200usize {
            let body: Vec<u8> = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    x.to_le_bytes()[0]
                })
                .collect();
            let _ = Request::decode(&body);
            let _ = Response::decode(&body, &req);
            let _ = Response::decode(&body, &sign_request());
        }
    }
}
