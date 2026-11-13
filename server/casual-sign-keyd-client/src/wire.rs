//! keyd's protocol inside the mutually authenticated TLS stream: length-prefixed binary
//! frames, every field bounded, every read checked. A frame from the network is hostile
//! input: nothing here indexes, unwraps or does unchecked arithmetic on it.
//!
//! ```text
//! frame    = len:u32be body            (len <= MAX_FRAME)
//! request  = 0x01 op args
//!   op     = 0x01 get-certificate-chain alias:str8
//!          | 0x02 sign-digest alias:str8 alg:u8 digest:bytes8 envelope:str8
//!          | 0x03 list-keys | 0x04 oplog-head | 0x05 oplog-range from:u64be n:u16be
//!          | 0x06 health                               (admin operations, CON-06)
//! response = 0x01 0x00 ok-body | 0x01 0x01 code:u16be
//!   chain  = alg:u8 development:u8 count:u8 (der:bytes32){count}
//!   sig    = signature:bytes16
//!   keys   = count:u8 (alias:str8 backend:text8 alg:u8 development:u8
//!            not_before:i64be not_after:i64be subject:text16 issuer:text16
//!            n:u8 (der:bytes32){n}){count}
//!   head   = seq:u64be hash:32 bytes
//!   range  = count:u16be (seq:u64be time:u64be caller op alias alg digest envelope
//!            outcome, each text8){count}
//!   health = log_seq:u64be uptime:u64be count:u8 (alias:str8 backend:text8 ok:u8){count}
//! str8     = len:u8 [A-Za-z0-9._-]{len}
//! text8    = len:u8 printable ASCII;  text16 = len:u16be UTF-8 without control characters
//! ```
//!
//! An alias and an envelope id are identifiers: their alphabet keeps the operation log
//! free of anything a caller could smuggle into it. The admin operations are read-only:
//! they return certificates, validity and the operation log's records (hashes, ids and
//! codes), never a key or document byte (docs/23 §5.4).
//!
//! Moved from `casual-sign-keyd` (`CON-06`, `CON-15`) so that callers carry the wire
//! format without `cryptoki`.

use std::io::{Read, Write};

use crate::error::KeydError;

/// Protocol version.
pub const VERSION: u8 = 1;
/// Largest frame either side reads: a chain of [`MAX_CHAIN`] certificates of
/// at most [`MAX_CERT`] bytes fits.
pub const MAX_FRAME: usize = 1 << 20;
/// Largest certificate in a chain.
pub const MAX_CERT: usize = 64 * 1024;
/// Longest alias or envelope id.
pub const MAX_ID: usize = 64;
/// Longest digest (SHA-512).
pub const MAX_DIGEST: usize = 64;

/// Most certificates a chain may hold (as `casual-sign-keyd`'s `MAX_CHAIN`).
pub const MAX_CHAIN: usize = 8;
/// Most keys one `list-keys` answer carries.
pub const MAX_KEYS: usize = 64;
/// Most records one `oplog-range` answer carries.
pub const MAX_RANGE: u16 = 256;
/// Longest subject or issuer name.
pub const MAX_NAME: usize = 1024;

const OP_CHAIN: u8 = 1;
const OP_SIGN: u8 = 2;
const OP_LIST_KEYS: u8 = 3;
const OP_OPLOG_HEAD: u8 = 4;
const OP_OPLOG_RANGE: u8 = 5;
const OP_HEALTH: u8 = 6;

/// A request to keyd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
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
    /// Admin: every key's alias, backend, algorithm, chain and validity.
    ListKeys,
    /// Admin: the operation log's last sequence number and hash.
    OplogHead,
    /// Admin: up to `n` operation-log records from sequence `from`.
    OplogRange {
        /// First sequence number (1-based).
        from: u64,
        /// Most records, at most [`MAX_RANGE`].
        n: u16,
    },
    /// Admin: each key's backend state, the log's sequence and the uptime.
    Health,
}

impl Request {
    /// Whether this is an admin operation (answered only to the admin allow-list).
    #[must_use]
    pub const fn is_admin(&self) -> bool {
        matches!(
            self,
            Self::ListKeys | Self::OplogHead | Self::OplogRange { .. } | Self::Health
        )
    }

    /// The operation's name in keyd's operation log.
    #[must_use]
    pub const fn op_name(&self) -> &'static str {
        match self {
            Self::Chain { .. } => "chain",
            Self::Sign { .. } => "sign",
            Self::ListKeys => "list-keys",
            Self::OplogHead => "oplog-head",
            Self::OplogRange { .. } => "oplog-range",
            Self::Health => "health",
        }
    }
}

/// One key as `list-keys` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    /// The alias.
    pub alias: String,
    /// `pkcs11`, `kms:<provider>`, `file-dev` or `remote`.
    pub backend: String,
    /// Wire id of the key's algorithm.
    pub alg: u8,
    /// A development file key.
    pub development: bool,
    /// The signer certificate's `notBefore`, Unix seconds.
    pub not_before: i64,
    /// The signer certificate's `notAfter`, Unix seconds.
    pub not_after: i64,
    /// The signer certificate's subject (RFC 4514).
    pub subject: String,
    /// The signer certificate's issuer (RFC 4514).
    pub issuer: String,
    /// DER certificates, signer first.
    pub certs: Vec<Vec<u8>>,
}

/// One operation-log record as `oplog-range` reports it: hashes, ids and codes only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// Sequence number, from 1.
    pub seq: u64,
    /// Unix seconds.
    pub time: u64,
    /// The caller's certificate fingerprint (hex SHA-256), or `-`.
    pub caller: String,
    /// The operation.
    pub op: String,
    /// The key alias, or `-`.
    pub alias: String,
    /// The algorithm's wire id, or `-`.
    pub alg: String,
    /// The hex digest signed, or `-`.
    pub digest: String,
    /// The envelope id, or `-`.
    pub envelope: String,
    /// `ok` or the code.
    pub outcome: String,
}

/// One key's backend state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyHealth {
    /// The alias.
    pub alias: String,
    /// The backend kind.
    pub backend: String,
    /// Whether the backend answers (an open HSM session, say).
    pub ok: bool,
}

/// keyd's `health` answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Health {
    /// The operation log's last sequence number.
    pub log_seq: u64,
    /// Seconds since keyd started.
    pub uptime_s: u64,
    /// Each key.
    pub keys: Vec<KeyHealth>,
}

/// keyd's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
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
    /// Refused or failed, with the `CS-KEY-` number ([`crate::ADMIN_REFUSED`] for
    /// `CS-CON-0008`).
    Error(u16),
    /// The keys.
    Keys(Vec<KeyInfo>),
    /// The log's head.
    Head {
        /// Last sequence number (0 for an empty log).
        seq: u64,
        /// Its hash (32 zero bytes for an empty log).
        hash: Vec<u8>,
    },
    /// Log records.
    Range(Vec<LogEntry>),
    /// Health.
    Health(Health),
}

fn malformed(why: &'static str) -> KeydError {
    KeydError::Malformed(why)
}

/// The name of the algorithm with wire id `id` (as `casual-sign-keyd` assigns them), for
/// display; `unknown` for an id keyd does not use.
#[must_use]
pub const fn algorithm_name(id: u8) -> &'static str {
    match id {
        1 => "ecdsa-p256-sha256",
        2 => "ecdsa-p384-sha384",
        3 => "rsa-pkcs1-sha256",
        4 => "rsa-pkcs1-sha384",
        5 => "rsa-pkcs1-sha512",
        6 => "rsa-pss-sha256",
        7 => "rsa-pss-sha384",
        8 => "rsa-pss-sha512",
        _ => "unknown",
    }
}

/// Whether `s` is a valid identifier (alias or envelope id).
#[must_use]
pub fn valid_id(s: &str, allow_empty: bool) -> bool {
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

    fn u64(&mut self) -> Result<u64, KeydError> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes(
            b.try_into().map_err(|_| malformed("truncated"))?,
        ))
    }

    fn i64(&mut self) -> Result<i64, KeydError> {
        let b = self.take(8)?;
        Ok(i64::from_be_bytes(
            b.try_into().map_err(|_| malformed("truncated"))?,
        ))
    }

    fn text8(&mut self) -> Result<String, KeydError> {
        let raw = self.bytes8()?;
        if !raw.iter().all(|b| (0x20..0x7f).contains(b)) {
            return Err(malformed("text outside printable ASCII"));
        }
        core::str::from_utf8(raw)
            .map(str::to_owned)
            .map_err(|_| malformed("text outside printable ASCII"))
    }

    fn text16(&mut self) -> Result<String, KeydError> {
        let n = usize::from(self.u16()?);
        if n > MAX_NAME {
            return Err(malformed("name too long"));
        }
        let s = core::str::from_utf8(self.take(n)?).map_err(|_| malformed("name not UTF-8"))?;
        if s.chars().any(char::is_control) {
            return Err(malformed("name with a control character"));
        }
        Ok(s.to_owned())
    }

    fn chain(&mut self, count: u8) -> Result<Vec<Vec<u8>>, KeydError> {
        if count == 0 || usize::from(count) > MAX_CHAIN {
            return Err(malformed("chain length"));
        }
        let mut certs = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let n = usize::try_from(self.u32()?).map_err(|_| malformed("length"))?;
            if n > MAX_CERT {
                return Err(malformed("certificate too large"));
            }
            certs.push(self.take(n)?.to_vec());
        }
        Ok(certs)
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

fn put_text8(out: &mut Vec<u8>, s: &str) -> Result<(), KeydError> {
    if !s.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return Err(malformed("text outside printable ASCII"));
    }
    put8(out, s.as_bytes())
}

fn put_text16(out: &mut Vec<u8>, s: &str) -> Result<(), KeydError> {
    if s.len() > MAX_NAME || s.chars().any(char::is_control) {
        return Err(malformed("name too long or with a control character"));
    }
    let n = u16::try_from(s.len()).map_err(|_| malformed("name too long"))?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

fn put_chain(out: &mut Vec<u8>, certs: &[Vec<u8>]) -> Result<(), KeydError> {
    if certs.is_empty() || certs.len() > MAX_CHAIN {
        return Err(malformed("chain length"));
    }
    out.push(u8::try_from(certs.len()).map_err(|_| malformed("chain too long"))?);
    for c in certs {
        if c.len() > MAX_CERT {
            return Err(malformed("certificate too large"));
        }
        let n = u32::try_from(c.len()).map_err(|_| malformed("certificate too large"))?;
        out.extend_from_slice(&n.to_be_bytes());
        out.extend_from_slice(c);
    }
    Ok(())
}

impl Request {
    /// Encode.
    ///
    /// # Errors
    /// `CS-KEY-0007` for a field over its bound.
    pub fn encode(&self) -> Result<Vec<u8>, KeydError> {
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
            Self::ListKeys => out.push(OP_LIST_KEYS),
            Self::OplogHead => out.push(OP_OPLOG_HEAD),
            Self::OplogRange { from, n } => {
                out.push(OP_OPLOG_RANGE);
                out.extend_from_slice(&from.to_be_bytes());
                out.extend_from_slice(&n.to_be_bytes());
            }
            Self::Health => out.push(OP_HEALTH),
        }
        Ok(out)
    }

    /// Decode a frame body.
    ///
    /// # Errors
    /// `CS-KEY-0007` for anything that does not follow the protocol.
    pub fn decode(body: &[u8]) -> Result<Self, KeydError> {
        let mut r = Reader(body);
        if r.u8()? != VERSION {
            return Err(malformed("unknown protocol version"));
        }
        let op = r.u8()?;
        let req = match op {
            OP_CHAIN => Self::Chain {
                alias: r.id(false)?,
            },
            OP_LIST_KEYS => Self::ListKeys,
            OP_OPLOG_HEAD => Self::OplogHead,
            OP_OPLOG_RANGE => {
                let from = r.u64()?;
                let n = r.u16()?;
                if n == 0 || n > MAX_RANGE {
                    return Err(malformed("range length"));
                }
                Self::OplogRange { from, n }
            }
            OP_HEALTH => Self::Health,
            OP_SIGN => {
                let alias = r.id(false)?;
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
    ///
    /// # Errors
    /// `CS-KEY-0007` for a field or a list over its bound.
    pub fn encode(&self) -> Result<Vec<u8>, KeydError> {
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
                put_chain(&mut out, certs)?;
            }
            Self::Keys(keys) => {
                out.push(0);
                if keys.len() > MAX_KEYS {
                    return Err(malformed("too many keys"));
                }
                out.push(u8::try_from(keys.len()).map_err(|_| malformed("too many keys"))?);
                for k in keys {
                    if !valid_id(&k.alias, false) {
                        return Err(malformed("alias"));
                    }
                    put8(&mut out, k.alias.as_bytes())?;
                    put_text8(&mut out, &k.backend)?;
                    out.push(k.alg);
                    out.push(u8::from(k.development));
                    out.extend_from_slice(&k.not_before.to_be_bytes());
                    out.extend_from_slice(&k.not_after.to_be_bytes());
                    put_text16(&mut out, &k.subject)?;
                    put_text16(&mut out, &k.issuer)?;
                    put_chain(&mut out, &k.certs)?;
                }
            }
            Self::Head { seq, hash } => {
                out.push(0);
                out.extend_from_slice(&seq.to_be_bytes());
                if hash.len() != 32 {
                    return Err(malformed("head hash length"));
                }
                out.extend_from_slice(hash);
            }
            Self::Range(entries) => {
                out.push(0);
                let n = u16::try_from(entries.len()).map_err(|_| malformed("range length"))?;
                if n > MAX_RANGE {
                    return Err(malformed("range length"));
                }
                out.extend_from_slice(&n.to_be_bytes());
                for e in entries {
                    out.extend_from_slice(&e.seq.to_be_bytes());
                    out.extend_from_slice(&e.time.to_be_bytes());
                    for t in [
                        &e.caller,
                        &e.op,
                        &e.alias,
                        &e.alg,
                        &e.digest,
                        &e.envelope,
                        &e.outcome,
                    ] {
                        put_text8(&mut out, t)?;
                    }
                }
            }
            Self::Health(h) => {
                out.push(0);
                out.extend_from_slice(&h.log_seq.to_be_bytes());
                out.extend_from_slice(&h.uptime_s.to_be_bytes());
                if h.keys.len() > MAX_KEYS {
                    return Err(malformed("too many keys"));
                }
                out.push(u8::try_from(h.keys.len()).map_err(|_| malformed("too many keys"))?);
                for k in &h.keys {
                    if !valid_id(&k.alias, false) {
                        return Err(malformed("alias"));
                    }
                    put8(&mut out, k.alias.as_bytes())?;
                    put_text8(&mut out, &k.backend)?;
                    out.push(u8::from(k.ok));
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
    ///
    /// # Errors
    /// `CS-KEY-0007` for anything that does not follow the protocol.
    pub fn decode(body: &[u8], request: &Request) -> Result<Self, KeydError> {
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
                    let certs = r.chain(count)?;
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
                Request::ListKeys => {
                    let count = r.u8()?;
                    if usize::from(count) > MAX_KEYS {
                        return Err(malformed("too many keys"));
                    }
                    let mut keys = Vec::with_capacity(usize::from(count));
                    for _ in 0..count {
                        let alias = r.id(false)?;
                        let backend = r.text8()?;
                        let alg = r.u8()?;
                        let development = match r.u8()? {
                            0 => false,
                            1 => true,
                            _ => return Err(malformed("development flag")),
                        };
                        let not_before = r.i64()?;
                        let not_after = r.i64()?;
                        let subject = r.text16()?;
                        let issuer = r.text16()?;
                        let n = r.u8()?;
                        let certs = r.chain(n)?;
                        keys.push(KeyInfo {
                            alias,
                            backend,
                            alg,
                            development,
                            not_before,
                            not_after,
                            subject,
                            issuer,
                            certs,
                        });
                    }
                    Self::Keys(keys)
                }
                Request::OplogHead => {
                    let seq = r.u64()?;
                    let hash = r.take(32)?.to_vec();
                    Self::Head { seq, hash }
                }
                Request::OplogRange { n: asked, .. } => {
                    let n = r.u16()?;
                    if n > *asked {
                        return Err(malformed("more records than asked"));
                    }
                    let mut entries = Vec::with_capacity(usize::from(n));
                    for _ in 0..n {
                        let seq = r.u64()?;
                        let time = r.u64()?;
                        entries.push(LogEntry {
                            seq,
                            time,
                            caller: r.text8()?,
                            op: r.text8()?,
                            alias: r.text8()?,
                            alg: r.text8()?,
                            digest: r.text8()?,
                            envelope: r.text8()?,
                            outcome: r.text8()?,
                        });
                    }
                    Self::Range(entries)
                }
                Request::Health => {
                    let log_seq = r.u64()?;
                    let uptime_s = r.u64()?;
                    let count = r.u8()?;
                    if usize::from(count) > MAX_KEYS {
                        return Err(malformed("too many keys"));
                    }
                    let mut keys = Vec::with_capacity(usize::from(count));
                    for _ in 0..count {
                        let alias = r.id(false)?;
                        let backend = r.text8()?;
                        let ok = match r.u8()? {
                            0 => false,
                            1 => true,
                            _ => return Err(malformed("health flag")),
                        };
                        keys.push(KeyHealth { alias, backend, ok });
                    }
                    Self::Health(Health {
                        log_seq,
                        uptime_s,
                        keys,
                    })
                }
            },
            _ => return Err(malformed("unknown status")),
        };
        r.end()?;
        Ok(resp)
    }
}

/// Read one frame. `Ok(None)` at a clean end of stream before a frame starts.
///
/// # Errors
/// `CS-KEY-0007` for a frame over [`MAX_FRAME`] or truncated; `CS-KEY-0011` when the
/// stream fails.
pub fn read_frame(stream: &mut impl Read) -> Result<Option<Vec<u8>>, KeydError> {
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
///
/// # Errors
/// `CS-KEY-0007` for a body over [`MAX_FRAME`]; `CS-KEY-0011` when the stream fails.
pub fn write_frame(stream: &mut impl Write, body: &[u8]) -> Result<(), KeydError> {
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

    /// The admin operations and their answers round-trip, and a truncated answer is
    /// refused (CON-06).
    #[test]
    fn admin_requests_and_answers_round_trip() {
        let reqs = [
            Request::ListKeys,
            Request::OplogHead,
            Request::OplogRange { from: 7, n: 3 },
            Request::Health,
        ];
        for req in &reqs {
            assert!(req.is_admin());
            assert_eq!(&Request::decode(&req.encode().unwrap()).unwrap(), req);
        }
        assert!(!sign_request().is_admin());
        let keys = Response::Keys(vec![KeyInfo {
            alias: "platform".into(),
            backend: "pkcs11".into(),
            alg: 1,
            development: false,
            not_before: 1_767_225_600,
            not_after: -5,
            subject: "CN=Seal,O=Ex\u{e4}mple".into(),
            issuer: "CN=Root".into(),
            certs: vec![vec![0x30, 0], vec![0x30, 1]],
        }]);
        let head = Response::Head {
            seq: 9,
            hash: vec![3; 32],
        };
        let range = Response::Range(vec![LogEntry {
            seq: 7,
            time: 1_800_000_000,
            caller: "ab".repeat(32),
            op: "sign".into(),
            alias: "platform".into(),
            alg: "1".into(),
            digest: "cd".repeat(32),
            envelope: "env_1".into(),
            outcome: "ok".into(),
        }]);
        let health = Response::Health(Health {
            log_seq: 9,
            uptime_s: 60,
            keys: vec![KeyHealth {
                alias: "platform".into(),
                backend: "file-dev".into(),
                ok: true,
            }],
        });
        for (req, resp) in reqs.iter().zip([keys, head, range, health]) {
            let body = resp.encode().unwrap();
            assert_eq!(Response::decode(&body, req).unwrap(), resp);
            for n in 0..body.len() {
                assert!(Response::decode(&body[..n], req).is_err(), "prefix {n}");
            }
        }
        // A range answer longer than asked is refused.
        let two = Response::Range(vec![
            LogEntry {
                seq: 1,
                time: 0,
                caller: "-".into(),
                op: "chain".into(),
                alias: "a".into(),
                alg: "-".into(),
                digest: "-".into(),
                envelope: "-".into(),
                outcome: "ok".into(),
            };
            2
        ]);
        let asked_one = Request::OplogRange { from: 1, n: 1 };
        assert!(Response::decode(&two.encode().unwrap(), &asked_one).is_err());
        // A range of zero or over the bound is refused.
        for n in [0, MAX_RANGE + 1] {
            let body = Request::OplogRange { from: 1, n }.encode().unwrap();
            assert!(Request::decode(&body).is_err(), "{n}");
        }
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
            for admin in [
                Request::ListKeys,
                Request::OplogHead,
                Request::OplogRange { from: 1, n: 5 },
                Request::Health,
            ] {
                let _ = Response::decode(&body, &admin);
            }
        }
    }
}
