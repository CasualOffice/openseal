//! Decryption of password-protected input: the standard security handler (ISO 32000-2
//! §7.6.4), revisions 2 to 6, with crypt filters (§7.6.5).
//!
//! Primitives come from RustCrypto (`md-5`, `rc4`, `aes`, `cbc`, `sha2`), as ADR-006
//! names them for decrypting input only: nothing here protects anything OpenSeal
//! writes (normalization writes the document unencrypted, docs/30 §2). The one use of
//! an encryption direction, AES-128-CBC in Algorithm 2.B, is a step of the revision 6
//! password hash, not protection of data.
//!
//! The host supplies passwords in [`Credentials`]; the empty user password is always
//! tried first, and no other password is ever guessed (`SEC-P09`). Strings are
//! decrypted when their object is loaded and streams when they are decoded, each
//! charged to the document's decode budget like any filter output.

use core::fmt;

use aes::{Aes128, Aes256};
use cbc::cipher::{BlockCipherDecrypt, BlockModeDecrypt, BlockModeEncrypt, KeyInit, KeyIvInit};
use md5::{Digest, Md5};
use rc4::{Rc4, StreamCipher};
use sha2::{Sha256, Sha384, Sha512};
use zeroize::Zeroizing;

use crate::error::{PdfError, Result};
use crate::object::{Dictionary, Object};

/// Most passwords one [`Credentials`] holds; more are ignored. Each costs at most two
/// password checks (user and owner), a few hundred hashes at revision 6.
pub const MAX_PASSWORDS: usize = 16;

/// The padding string of Algorithm 2 (ISO 32000-2 §7.6.4.3.2, step a).
const PAD: [u8; 32] = [
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
];

/// Most rounds of Algorithm 2.B. The algorithm ends by round 288 (a last byte of at
/// most 255 is at most the round number less 32); this only states the bound.
const MAX_R6_ROUNDS: u32 = 320;

/// One password from the host.
#[derive(Clone)]
enum Password {
    /// Text: encoded for the revision (PDFDocEncoding up to revision 4, SASLprep and
    /// UTF-8 from revision 5).
    Text(Zeroizing<String>),
    /// Bytes, used as they are.
    Bytes(Zeroizing<Vec<u8>>),
}

/// Passwords the host supplies to open encrypted documents (`CS-PDF-0009` without the
/// right one).
///
/// The empty user password is always tried first, so a document that opens without a
/// password in a viewer opens here with `Credentials::default()`. Each password given
/// is tried as the user password, then as the owner password. Passwords are never
/// guessed, logged or kept in the report; they are wiped from memory when dropped.
#[derive(Clone, Default)]
pub struct Credentials {
    passwords: Vec<Password>,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("passwords", &self.passwords.len())
            .finish()
    }
}

impl Credentials {
    /// No password besides the empty user password.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a password typed by a person. Up to revision 4 it is encoded in
    /// PDFDocEncoding (characters it lacks make it unusable there); from revision 5 it
    /// is prepared with SASLprep and encoded in UTF-8, as ISO 32000-2 §7.6.4.3.3
    /// requires. At most [`MAX_PASSWORDS`] are kept.
    #[must_use]
    pub fn with_password(mut self, password: &str) -> Self {
        if self.passwords.len() < MAX_PASSWORDS {
            self.passwords
                .push(Password::Text(Zeroizing::new(password.to_owned())));
        }
        self
    }

    /// Add a password as raw bytes, used unchanged for every revision (for passwords
    /// produced by another system in a known encoding).
    #[must_use]
    pub fn with_password_bytes(mut self, password: &[u8]) -> Self {
        if self.passwords.len() < MAX_PASSWORDS {
            self.passwords
                .push(Password::Bytes(Zeroizing::new(password.to_vec())));
        }
        self
    }

    /// The candidates for one revision: the empty password, then each given one.
    fn candidates(&self, revision: u8) -> Vec<(Zeroizing<Vec<u8>>, bool)> {
        let mut out = vec![(Zeroizing::new(Vec::new()), true)];
        for p in &self.passwords {
            let bytes = match p {
                Password::Bytes(b) => Some(b.to_vec()),
                Password::Text(t) if revision <= 4 => pdfdoc_encode(t),
                Password::Text(t) => Some(match stringprep::saslprep(t) {
                    Ok(prepared) => prepared.as_bytes().to_vec(),
                    // Prohibited characters: the plain UTF-8, as other readers try.
                    Err(_) => t.as_bytes().to_vec(),
                }),
            };
            if let Some(mut b) = bytes {
                b.truncate(if revision <= 4 { 32 } else { 127 });
                out.push((Zeroizing::new(b), false));
            }
        }
        out
    }
}

/// Encode text in PDFDocEncoding (Annex D); `None` when a character has no code.
fn pdfdoc_encode(s: &str) -> Option<Vec<u8>> {
    s.chars()
        .map(|c| {
            let cp = u32::from(c);
            (0u8..=255)
                .find(|&b| crate::text::pdfdoc(b) == c && crate::text::pdfdoc(b) != '\u{FFFD}')
                .or_else(|| u8::try_from(cp).ok().filter(|_| cp < 0x18))
        })
        .collect()
}

/// A cipher, for the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Cipher {
    /// Not encrypted (`/Identity`, or `/None`).
    None,
    /// RC4 with the key length in [`EncryptionInfo::key_bits`].
    Rc4,
    /// AES-128 in CBC mode (`AESV2`).
    Aes128,
    /// AES-256 in CBC mode (`AESV3`).
    Aes256,
}

/// Which password opened the document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PasswordKind {
    /// The user password (possibly the empty one).
    User,
    /// The owner password.
    Owner,
}

/// How an encrypted document was protected and opened. It carries no password or key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct EncryptionInfo {
    /// `/V`, the algorithm version.
    pub version: u8,
    /// `/R`, the standard security handler's revision.
    pub revision: u8,
    /// Length of the file key in bits.
    pub key_bits: u16,
    /// Cipher for strings (`/StrF`).
    pub strings: Cipher,
    /// Cipher for streams (`/StmF`).
    pub streams: Cipher,
    /// Which password opened it.
    pub opened_with: PasswordKind,
    /// True when it opened with the empty user password: no password was needed.
    pub empty_password: bool,
    /// `/P`, the permission flags the author set (ISO 32000-2 Table 22). OpenSeal
    /// removes encryption on normalization, so they do not bind its output.
    pub permissions: u32,
    /// `/EncryptMetadata`: false when the XMP metadata is in clear.
    pub encrypt_metadata: bool,
}

/// How one crypt filter decrypts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Identity,
    Rc4,
    AesV2,
    AesV3,
}

impl Method {
    fn cipher(self) -> Cipher {
        match self {
            Self::Identity => Cipher::None,
            Self::Rc4 => Cipher::Rc4,
            Self::AesV2 => Cipher::Aes128,
            Self::AesV3 => Cipher::Aes256,
        }
    }
}

/// An authenticated standard security handler: the file key and the crypt filters.
pub(crate) struct Crypt {
    key: Zeroizing<Vec<u8>>,
    strings: Method,
    streams: Method,
    embedded: Method,
    /// Named crypt filters from `/CF`, for streams with their own `/Crypt` filter.
    named: Vec<(Vec<u8>, Method)>,
    /// The `/Encrypt` dictionary's object number: its strings are not encrypted.
    pub(crate) dict_object: Option<u32>,
    pub(crate) info: EncryptionInfo,
}

impl fmt::Debug for Crypt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Crypt").field("info", &self.info).finish()
    }
}

/// Decrypted bytes, and whether the ciphertext was damaged (an AES length that is not
/// a whole number of blocks, or bad padding): what could be decrypted is kept.
pub(crate) struct Plain {
    pub(crate) bytes: Vec<u8>,
    pub(crate) damaged: bool,
}

fn malformed(object: Option<u32>) -> PdfError {
    PdfError::Malformed { object, offset: 0 }
}

fn string<'d>(d: &'d Dictionary, key: &[u8]) -> Option<&'d [u8]> {
    match d.get(key) {
        Some(Object::String(s)) => Some(s),
        _ => None,
    }
}

fn md5(parts: &[&[u8]]) -> [u8; 16] {
    let mut h = Md5::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn rc4(key: &[u8], data: &mut [u8]) {
    // Keys here are 5 to 16 bytes, always within RC4's 1 to 256.
    if let Ok(mut c) = Rc4::new_from_slice(key) {
        c.apply_keystream(data);
    }
}

/// AES-CBC decryption of whole blocks in place, with the given key and IV.
fn aes_cbc_decrypt(key: &[u8], iv: &[u8], data: &mut [u8]) -> bool {
    let blocks = data.chunks_exact_mut(16);
    match key.len() {
        16 => match cbc::Decryptor::<Aes128>::new_from_slices(key, iv) {
            Ok(mut d) => {
                for chunk in blocks {
                    let mut b = aes::Block::default();
                    b.copy_from_slice(chunk);
                    d.decrypt_block(&mut b);
                    chunk.copy_from_slice(&b);
                }
                true
            }
            Err(_) => false,
        },
        32 => match cbc::Decryptor::<Aes256>::new_from_slices(key, iv) {
            Ok(mut d) => {
                for chunk in blocks {
                    let mut b = aes::Block::default();
                    b.copy_from_slice(chunk);
                    d.decrypt_block(&mut b);
                    chunk.copy_from_slice(&b);
                }
                true
            }
            Err(_) => false,
        },
        _ => false,
    }
}

/// AES-128-CBC encryption of whole blocks in place: a step of Algorithm 2.B only.
fn aes128_cbc_hash_step(key: &[u8], iv: &[u8], data: &mut [u8]) -> bool {
    match cbc::Encryptor::<Aes128>::new_from_slices(key, iv) {
        Ok(mut e) => {
            for chunk in data.chunks_exact_mut(16) {
                let mut b = aes::Block::default();
                b.copy_from_slice(chunk);
                e.encrypt_block(&mut b);
                chunk.copy_from_slice(&b);
            }
            true
        }
        Err(_) => false,
    }
}

/// Algorithm 2.B (ISO 32000-2 §7.6.4.3.4): the revision 6 password hash; revision 5
/// uses one SHA-256.
fn hash_v5(revision: u8, password: &[u8], salt: &[u8], udata: &[u8]) -> [u8; 32] {
    let mut k: Vec<u8> = {
        let mut h = Sha256::new();
        h.update(password);
        h.update(salt);
        h.update(udata);
        h.finalize().to_vec()
    };
    if revision >= 6 {
        let mut round: u32 = 0;
        while round < MAX_R6_ROUNDS {
            let unit_len = password
                .len()
                .saturating_add(k.len())
                .saturating_add(udata.len());
            let mut k1: Vec<u8> = Vec::with_capacity(unit_len.saturating_mul(64));
            for _ in 0..64 {
                k1.extend_from_slice(password);
                k1.extend_from_slice(&k);
                k1.extend_from_slice(udata);
            }
            let (Some(key), Some(iv)) = (k.get(..16), k.get(16..32)) else {
                break;
            };
            if !aes128_cbc_hash_step(key, iv, &mut k1) {
                break;
            }
            let e = k1;
            let sum: u32 = e.iter().take(16).map(|&b| u32::from(b)).sum();
            k = match sum % 3 {
                0 => Sha256::digest(&e).to_vec(),
                1 => Sha384::digest(&e).to_vec(),
                _ => Sha512::digest(&e).to_vec(),
            };
            round = round.saturating_add(1);
            let last = u32::from(e.last().copied().unwrap_or(0));
            if round >= 64 && last <= round.saturating_sub(32) {
                break;
            }
        }
    }
    let mut out = [0u8; 32];
    for (o, b) in out.iter_mut().zip(k.iter()) {
        *o = *b;
    }
    out
}

/// The parsed `/Encrypt` dictionary of the standard handler.
struct Params<'d> {
    v: u8,
    r: u8,
    /// File key length in bytes (5 to 16 up to revision 4; 32 after).
    n: usize,
    o: &'d [u8],
    u: &'d [u8],
    oe: &'d [u8],
    ue: &'d [u8],
    p: u32,
    encrypt_metadata: bool,
    strings: Method,
    streams: Method,
    embedded: Method,
    named: Vec<(Vec<u8>, Method)>,
}

fn crypt_filter_method(cf: &Dictionary) -> Option<Method> {
    Some(match cf.name(b"CFM") {
        None | Some(b"None") => Method::Identity,
        Some(b"V2") => Method::Rc4,
        Some(b"AESV2") => Method::AesV2,
        Some(b"AESV3") => Method::AesV3,
        Some(_) => return None,
    })
}

fn params<'d>(enc: &'d Dictionary, object: Option<u32>) -> Result<Params<'d>> {
    let int = |k: &[u8]| enc.get(k).and_then(Object::as_i64);
    let v = u8::try_from(int(b"V").unwrap_or(0)).map_err(|_| PdfError::UnsupportedSecurity)?;
    let r = u8::try_from(int(b"R").ok_or_else(|| malformed(object))?)
        .map_err(|_| PdfError::UnsupportedSecurity)?;
    if !matches!(v, 1 | 2 | 4 | 5) || !(2..=6).contains(&r) {
        return Err(PdfError::UnsupportedSecurity);
    }
    // /P is a 32-bit signed value; some writers store it unsigned.
    let p = int(b"P").ok_or_else(|| malformed(object))?;
    let p = u32::try_from(p & 0xFFFF_FFFF).unwrap_or(0);
    let encrypt_metadata = !matches!(enc.get(b"EncryptMetadata"), Some(Object::Bool(false)));
    let o = string(enc, b"O").ok_or_else(|| malformed(object))?;
    let u = string(enc, b"U").ok_or_else(|| malformed(object))?;
    let need = if r <= 4 { 32 } else { 48 };
    if o.len() < need || u.len() < need {
        return Err(malformed(object));
    }
    let (o, u) = (
        o.get(..need).unwrap_or_default(),
        u.get(..need).unwrap_or_default(),
    );
    let (oe, ue) = if r >= 5 {
        let oe = string(enc, b"OE").ok_or_else(|| malformed(object))?;
        let ue = string(enc, b"UE").ok_or_else(|| malformed(object))?;
        if oe.len() < 32 || ue.len() < 32 {
            return Err(malformed(object));
        }
        (
            oe.get(..32).unwrap_or_default(),
            ue.get(..32).unwrap_or_default(),
        )
    } else {
        (&[][..], &[][..])
    };
    let mut named: Vec<(Vec<u8>, Method)> = Vec::new();
    let mut cf_length: Option<i64> = None;
    let (strings, streams, embedded) = if v >= 4 {
        let cf = match enc.get(b"CF") {
            Some(Object::Dictionary(d)) => Some(d),
            _ => None,
        };
        for (name, value) in cf.into_iter().flat_map(Dictionary::iter) {
            if let Object::Dictionary(d) = value {
                let m = crypt_filter_method(d).ok_or(PdfError::UnsupportedSecurity)?;
                named.push((name.to_vec(), m));
            }
        }
        let pick = |key: &[u8], default: Method| -> Result<Method> {
            match enc.get(key) {
                None => Ok(default),
                Some(Object::Name(n)) if n == b"Identity" => Ok(Method::Identity),
                Some(Object::Name(n)) => named
                    .iter()
                    .find(|(k, _)| k == n)
                    .map(|(_, m)| *m)
                    .ok_or_else(|| malformed(object)),
                Some(_) => Err(malformed(object)),
            }
        };
        let streams = pick(b"StmF", Method::Identity)?;
        let strings = pick(b"StrF", Method::Identity)?;
        let embedded = pick(b"EFF", streams)?;
        if let Some(Object::Name(n)) = enc.get(b"StmF")
            && let Some(Object::Dictionary(d)) = cf.and_then(|c| c.get(n))
        {
            cf_length = d.get(b"Length").and_then(Object::as_i64);
        }
        (strings, streams, embedded)
    } else {
        (Method::Rc4, Method::Rc4, Method::Rc4)
    };
    let uses_aes256 = [strings, streams, embedded].contains(&Method::AesV3)
        || named.iter().any(|(_, m)| *m == Method::AesV3);
    let n = match (v, r) {
        (5, _) | (_, 5..) => 32,
        (1, _) => 5,
        _ if r == 2 => 5,
        (4, _) => {
            // A crypt filter's /Length is in bits, but some writers give bytes.
            let bits = cf_length.or_else(|| int(b"Length")).unwrap_or(128);
            let bits = if bits < 40 {
                bits.saturating_mul(8)
            } else {
                bits
            };
            usize::try_from(bits / 8).unwrap_or(0)
        }
        _ => usize::try_from(int(b"Length").unwrap_or(40) / 8).unwrap_or(0),
    };
    if !(5..=16).contains(&n) && n != 32 {
        return Err(malformed(object));
    }
    if uses_aes256 != (n == 32) {
        return Err(PdfError::UnsupportedSecurity);
    }
    Ok(Params {
        v,
        r,
        n,
        o,
        u,
        oe,
        ue,
        p,
        encrypt_metadata,
        strings,
        streams,
        embedded,
        named,
    })
}

/// Algorithm 2: the file key from a (padded) user password, revisions 2 to 4.
fn key_r4(p: &Params<'_>, password: &[u8], id0: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut padded = Zeroizing::new([0u8; 32]);
    for (i, slot) in padded.iter_mut().enumerate() {
        *slot = password
            .get(i)
            .copied()
            .or_else(|| PAD.get(i.saturating_sub(password.len())).copied())
            .unwrap_or(0);
    }
    let mut h = Md5::new();
    h.update(padded.as_slice());
    h.update(p.o);
    h.update(p.p.to_le_bytes());
    h.update(id0);
    if p.r >= 4 && !p.encrypt_metadata {
        h.update([0xFF, 0xFF, 0xFF, 0xFF]);
    }
    let mut digest: [u8; 16] = h.finalize().into();
    if p.r >= 3 {
        for _ in 0..50 {
            digest = md5(&[digest.get(..p.n).unwrap_or(&digest)]);
        }
    }
    Zeroizing::new(digest.get(..p.n).unwrap_or(&digest).to_vec())
}

/// Algorithms 4 and 5: does `key` open the user entry `/U`?
fn user_matches(p: &Params<'_>, key: &[u8], id0: &[u8]) -> bool {
    if p.r == 2 {
        let mut u = PAD;
        rc4(key, &mut u);
        return u.as_slice() == p.u;
    }
    let mut x = md5(&[&PAD, id0]);
    rc4(key, &mut x);
    for i in 1u8..=19 {
        let k: Vec<u8> = key.iter().map(|b| b ^ i).collect();
        rc4(&k, &mut x);
    }
    p.u.get(..16) == Some(x.as_slice())
}

/// Algorithm 7 (after Algorithm 3 steps a to d): the user password an owner password
/// unlocks, revisions 2 to 4.
fn owner_to_user(p: &Params<'_>, owner: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut padded = Zeroizing::new([0u8; 32]);
    for (i, slot) in padded.iter_mut().enumerate() {
        *slot = owner
            .get(i)
            .copied()
            .or_else(|| PAD.get(i.saturating_sub(owner.len())).copied())
            .unwrap_or(0);
    }
    let mut digest = md5(&[padded.as_slice()]);
    if p.r >= 3 {
        for _ in 0..50 {
            digest = md5(&[&digest]);
        }
    }
    let key = digest.get(..p.n).unwrap_or(&digest);
    let mut user = Zeroizing::new(p.o.to_vec());
    if p.r == 2 {
        rc4(key, &mut user);
    } else {
        for i in (0u8..=19).rev() {
            let k: Vec<u8> = key.iter().map(|b| b ^ i).collect();
            rc4(&k, &mut user);
        }
    }
    user
}

/// Algorithms 2.A, 11 and 12: the file key from a password, revisions 5 and 6.
fn key_r6(p: &Params<'_>, password: &[u8]) -> Option<(Zeroizing<Vec<u8>>, PasswordKind)> {
    let part = |s: &[u8], a: usize, b: usize| s.get(a..b).unwrap_or_default().to_vec();
    let (o_hash, o_vsalt, o_ksalt) = (part(p.o, 0, 32), part(p.o, 32, 40), part(p.o, 40, 48));
    let (u_hash, u_vsalt, u_ksalt) = (part(p.u, 0, 32), part(p.u, 32, 40), part(p.u, 40, 48));
    let (kind, salt, udata, wrapped) =
        if hash_v5(p.r, password, &o_vsalt, p.u).as_slice() == o_hash.as_slice() {
            (PasswordKind::Owner, o_ksalt, p.u, p.oe)
        } else if hash_v5(p.r, password, &u_vsalt, &[]).as_slice() == u_hash.as_slice() {
            (PasswordKind::User, u_ksalt, &[][..], p.ue)
        } else {
            return None;
        };
    let intermediate = Zeroizing::new(hash_v5(p.r, password, &salt, udata));
    let mut key = Zeroizing::new(wrapped.to_vec());
    aes_cbc_decrypt(intermediate.as_slice(), &[0u8; 16], &mut key).then_some((key, kind))
}

/// Check `/Perms` (Algorithm 13) where it can be decrypted: a mismatch means `/P` was
/// altered, which matters to nobody here (permissions do not bind OpenSeal's output),
/// so it is only used to reject a key that decrypts nothing sensible.
fn perms_ok(key: &[u8], enc: &Dictionary) -> bool {
    let Some(perms) = string(enc, b"Perms").and_then(|s| s.get(..16)) else {
        return true;
    };
    let Ok(cipher) = Aes256::new_from_slice(key) else {
        return false;
    };
    let mut b = aes::Block::default();
    b.copy_from_slice(perms);
    cipher.decrypt_block(&mut b);
    b.get(9..12) == Some(b"adb".as_slice())
}

impl Crypt {
    /// Authenticate with the empty user password, then each of `credentials`.
    ///
    /// # Errors
    ///
    /// `CS-PDF-0009` when no password opens it; `CS-PDF-0010` for a handler,
    /// revision or crypt filter method the standard handler does not define, or the
    /// public-key handler; `CS-PDF-0005` for an `/Encrypt` dictionary missing what the
    /// standard handler needs.
    pub(crate) fn open(
        enc: &Dictionary,
        dict_object: Option<u32>,
        id0: &[u8],
        credentials: &Credentials,
    ) -> Result<Self> {
        match enc.name(b"Filter") {
            Some(b"Standard") => {}
            Some(b"Adobe.PubSec") => return Err(PdfError::PublicKeySecurity),
            _ if enc
                .name(b"SubFilter")
                .is_some_and(|s| s.starts_with(b"adbe.pkcs7")) =>
            {
                return Err(PdfError::PublicKeySecurity);
            }
            Some(_) => return Err(PdfError::UnsupportedSecurity),
            None => return Err(malformed(dict_object)),
        }
        let p = params(enc, dict_object)?;
        for (password, empty) in credentials.candidates(p.r) {
            let opened = if p.r <= 4 {
                let key = key_r4(&p, &password, id0);
                if user_matches(&p, &key, id0) {
                    Some((key, PasswordKind::User))
                } else {
                    let user = owner_to_user(&p, &password);
                    let key = key_r4(&p, &user, id0);
                    user_matches(&p, &key, id0).then_some((key, PasswordKind::Owner))
                }
            } else {
                key_r6(&p, &password).filter(|(k, _)| p.r == 5 || perms_ok(k, enc))
            };
            if let Some((key, kind)) = opened {
                let key_bits = u16::try_from(key.len().saturating_mul(8)).unwrap_or(u16::MAX);
                return Ok(Self {
                    key,
                    strings: p.strings,
                    streams: p.streams,
                    embedded: p.embedded,
                    named: p.named,
                    dict_object,
                    info: EncryptionInfo {
                        version: p.v,
                        revision: p.r,
                        key_bits,
                        strings: p.strings.cipher(),
                        streams: p.streams.cipher(),
                        opened_with: kind,
                        empty_password: empty && kind == PasswordKind::User,
                        permissions: p.p,
                        encrypt_metadata: p.encrypt_metadata,
                    },
                });
            }
        }
        Err(PdfError::Encrypted)
    }

    /// Algorithm 1: the key for object `num`, generation `generation`.
    fn object_key(&self, method: Method, num: u32, generation: u16) -> Zeroizing<Vec<u8>> {
        if method == Method::AesV3 {
            return self.key.clone();
        }
        let n = num.to_le_bytes();
        let g = generation.to_le_bytes();
        let salt: &[u8] = if method == Method::AesV2 {
            b"sAlT"
        } else {
            b""
        };
        let digest = md5(&[
            self.key.as_slice(),
            n.get(..3).unwrap_or_default(),
            &g,
            salt,
        ]);
        let len = self.key.len().saturating_add(5).min(16);
        Zeroizing::new(digest.get(..len).unwrap_or(&digest).to_vec())
    }

    fn run(&self, method: Method, num: u32, generation: u16, data: &[u8]) -> Plain {
        match method {
            Method::Identity => Plain {
                bytes: data.to_vec(),
                damaged: false,
            },
            Method::Rc4 => {
                let mut out = data.to_vec();
                rc4(&self.object_key(method, num, generation), &mut out);
                Plain {
                    bytes: out,
                    damaged: false,
                }
            }
            Method::AesV2 | Method::AesV3 => {
                if data.is_empty() {
                    return Plain {
                        bytes: Vec::new(),
                        damaged: false,
                    };
                }
                let (Some(iv), Some(body)) = (data.get(..16), data.get(16..)) else {
                    return Plain {
                        bytes: Vec::new(),
                        damaged: true,
                    };
                };
                let whole = body.len().saturating_sub(body.len() % 16);
                let mut out = body.get(..whole).unwrap_or_default().to_vec();
                let mut damaged = whole != body.len();
                let key = self.object_key(method, num, generation);
                if !aes_cbc_decrypt(&key, iv, &mut out) {
                    return Plain {
                        bytes: Vec::new(),
                        damaged: true,
                    };
                }
                // PKCS #7 padding: 1 to 16 bytes, each holding the count.
                match out.last().copied() {
                    Some(pad @ 1..=16)
                        if out.len() >= usize::from(pad)
                            && out.iter().rev().take(usize::from(pad)).all(|&b| b == pad) =>
                    {
                        out.truncate(out.len().saturating_sub(usize::from(pad)));
                    }
                    _ => damaged = true,
                }
                Plain {
                    bytes: out,
                    damaged,
                }
            }
        }
    }

    /// True when strings are encrypted (`/StrF` is not `/Identity`).
    pub(crate) fn strings_encrypted(&self) -> bool {
        self.strings != Method::Identity
    }

    /// Decrypt a string of object `num`.
    pub(crate) fn string(&self, num: u32, generation: u16, data: &[u8]) -> Plain {
        self.run(self.strings, num, generation, data)
    }

    /// The method for a stream: none for xref streams (§7.5.8.1) and, when
    /// `/EncryptMetadata` is false, for metadata streams; a `/Crypt` filter's named
    /// filter when the stream has one (§7.4.10); else `/EFF` for embedded files and
    /// `/StmF` for the rest. `crypt_name` is the `/Crypt` filter's `/Name`.
    fn stream_method(&self, dict: &Dictionary, crypt_name: Option<&[u8]>) -> Result<Method> {
        let ty = dict.name(b"Type");
        if ty == Some(b"XRef") || (ty == Some(b"Metadata") && !self.info.encrypt_metadata) {
            return Ok(Method::Identity);
        }
        if let Some(name) = crypt_name {
            if name == b"Identity" {
                return Ok(Method::Identity);
            }
            return self
                .named
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, m)| *m)
                .ok_or(PdfError::UnsupportedSecurity);
        }
        Ok(if ty == Some(b"EmbeddedFile") {
            self.embedded
        } else {
            self.streams
        })
    }

    /// Decrypt the data of stream object `num`; `None` when it is not encrypted.
    pub(crate) fn stream(
        &self,
        num: u32,
        generation: u16,
        dict: &Dictionary,
        crypt_name: Option<&[u8]>,
        data: &[u8],
    ) -> Result<Option<Plain>> {
        let method = self.stream_method(dict, crypt_name)?;
        Ok((method != Method::Identity).then(|| self.run(method, num, generation, data)))
    }
}

#[cfg(test)]
mod tests {
    // Tests index and unwrap freely: a panic is the failure report.
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    #[test]
    fn passwords_are_never_printed() {
        let c = Credentials::new().with_password("secret");
        assert_eq!(format!("{c:?}"), "Credentials { passwords: 1 }");
    }

    #[test]
    fn credentials_hold_at_most_the_cap() {
        let mut c = Credentials::new();
        for i in 0..40 {
            c = c.with_password(&i.to_string());
        }
        // The empty password and MAX_PASSWORDS others.
        assert_eq!(c.candidates(4).len(), MAX_PASSWORDS + 1);
    }

    #[test]
    fn pdfdoc_encoding_of_passwords() {
        assert_eq!(pdfdoc_encode("ab\u{2022}").unwrap(), b"ab\x80");
        assert_eq!(pdfdoc_encode("\u{e9}").unwrap(), b"\xe9");
        assert!(pdfdoc_encode("\u{4e2d}").is_none());
    }

    #[test]
    fn r6_hash_ends_and_differs_from_r5() {
        let a = hash_v5(6, b"user", b"12345678", &[]);
        let b = hash_v5(5, b"user", b"12345678", &[]);
        assert_ne!(a, b);
        assert_eq!(a, hash_v5(6, b"user", b"12345678", &[]));
    }
}
