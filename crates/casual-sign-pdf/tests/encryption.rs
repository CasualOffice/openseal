//! Decryption of password-protected input (`PDF-ENC-01`, docs/30 §2).
//!
//! The fixtures are encrypted here, with the same RustCrypto primitives, from the
//! algorithms of ISO 32000-2 §7.6 written out again in the encrypting direction. That
//! direction exists only in this test; the product never encrypts. Real files from
//! other writers (qpdf, PDFBox, pyHanko, Adobe, LibreOffice) are checked over the
//! corpus, where pyHanko decrypts the same files independently.
// Test code: a panic is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::cast_possible_truncation
)]

mod common;

use aes::cipher::{BlockCipherEncrypt, BlockModeEncrypt, KeyInit, KeyIvInit};
use casual_sign_pdf::{
    Change, Cipher, Credentials, FindingKind, IncrementalUpdate, Limits, NormalizeOptions, Object,
    OutputXref, PasswordKind, admit, admit_strict, admit_strict_with, admit_with, normalize,
};
use common::{never, zlib};
use md5::{Digest, Md5};
use rc4::{Rc4, StreamCipher};
use sha2::{Sha256, Sha384, Sha512};

const PAD: [u8; 32] = [
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
];
const ID0: &[u8] = b"0123456789abcdef";
const P: i32 = -3904;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Scheme {
    /// V1 R2, RC4 40-bit.
    Rc4_40,
    /// V2 R3, RC4 128-bit.
    Rc4_128,
    /// V4 R4, AESV2 crypt filters.
    Aes128,
    /// V4 R4, RC4 (V2) crypt filter, metadata in clear.
    Rc4CfClearMetadata,
    /// V5 R6, AESV3.
    Aes256,
    /// V5 R5 (the deprecated Adobe extension level 3 hash), AESV3.
    Aes256R5,
}

impl Scheme {
    fn r(self) -> u8 {
        match self {
            Self::Rc4_40 => 2,
            Self::Rc4_128 => 3,
            Self::Aes128 | Self::Rc4CfClearMetadata => 4,
            Self::Aes256R5 => 5,
            Self::Aes256 => 6,
        }
    }
    fn n(self) -> usize {
        match self {
            Self::Rc4_40 => 5,
            Self::Aes256 | Self::Aes256R5 => 32,
            _ => 16,
        }
    }
    fn aes(self) -> bool {
        matches!(self, Self::Aes128 | Self::Aes256 | Self::Aes256R5)
    }
    fn encrypt_metadata(self) -> bool {
        self != Self::Rc4CfClearMetadata
    }
}

fn md5(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Md5::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().to_vec()
}

fn rc4(key: &[u8], data: &mut [u8]) {
    Rc4::new_from_slice(key).unwrap().apply_keystream(data);
}

fn padded(pw: &[u8]) -> Vec<u8> {
    let mut v = pw.iter().take(32).copied().collect::<Vec<_>>();
    v.extend_from_slice(&PAD[..32 - v.len()]);
    v
}

fn aes_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8], pad: bool) -> Vec<u8> {
    let mut buf = data.to_vec();
    if pad {
        let n = 16 - buf.len() % 16;
        buf.extend(std::iter::repeat_n(n as u8, n));
    }
    assert_eq!(buf.len() % 16, 0);
    macro_rules! run {
        ($c:ty) => {{
            let mut e = cbc::Encryptor::<$c>::new_from_slices(key, iv).unwrap();
            for chunk in buf.chunks_exact_mut(16) {
                let mut b = aes::Block::default();
                b.copy_from_slice(chunk);
                e.encrypt_block(&mut b);
                chunk.copy_from_slice(&b);
            }
        }};
    }
    match key.len() {
        16 => run!(aes::Aes128),
        32 => run!(aes::Aes256),
        _ => panic!("key length"),
    }
    buf
}

fn hash_v5(r: u8, pw: &[u8], salt: &[u8], udata: &[u8]) -> Vec<u8> {
    let mut k = Sha256::digest([pw, salt, udata].concat()).to_vec();
    if r == 5 {
        return k;
    }
    let mut round = 0u32;
    loop {
        let k1: Vec<u8> = [pw, &k[..], udata].concat().repeat(64);
        let e = aes_cbc_encrypt(&k[..16], &k[16..32], &k1, false);
        let sum: u32 = e[..16].iter().map(|&b| u32::from(b)).sum();
        k = match sum % 3 {
            0 => Sha256::digest(&e).to_vec(),
            1 => Sha384::digest(&e).to_vec(),
            _ => Sha512::digest(&e).to_vec(),
        };
        round += 1;
        if round >= 64 && u32::from(*e.last().unwrap()) <= round - 32 {
            break;
        }
    }
    k.truncate(32);
    k
}

/// An encryption: the `/Encrypt` dictionary's text and the file key.
struct Enc {
    scheme: Scheme,
    dict: String,
    key: Vec<u8>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|c| format!("{c:02X}")).collect()
}

fn setup(scheme: Scheme, user: &[u8], owner: &[u8]) -> Enc {
    let r = scheme.r();
    let n = scheme.n();
    if r >= 5 {
        let key: Vec<u8> = (0..32u8)
            .map(|i| i.wrapping_mul(7).wrapping_add(3))
            .collect();
        let (uvs, uks, ovs, oks) = (b"uvsalt01", b"ukslt002", b"ovsalt03", b"okslt004");
        let mut u = hash_v5(r, user, uvs, &[]);
        u.extend_from_slice(uvs);
        u.extend_from_slice(uks);
        let ue = aes_cbc_encrypt(&hash_v5(r, user, uks, &[]), &[0; 16], &key, false);
        let mut o = hash_v5(r, owner, ovs, &u);
        o.extend_from_slice(ovs);
        o.extend_from_slice(oks);
        let oe = aes_cbc_encrypt(&hash_v5(r, owner, oks, &u), &[0; 16], &key, false);
        let mut perms = [0u8; 16];
        perms[..4].copy_from_slice(&P.to_le_bytes());
        perms[4..8].copy_from_slice(&[0xFF; 4]);
        perms[8] = b'T';
        perms[9..12].copy_from_slice(b"adb");
        let cipher = aes::Aes256::new_from_slice(&key).unwrap();
        let mut b = aes::Block::default();
        b.copy_from_slice(&perms);
        cipher.encrypt_block(&mut b);
        let dict = format!(
            "<</Filter/Standard/V 5/R {r}/Length 256/P {P}/O<{}>/U<{}>/OE<{}>/UE<{}>/Perms<{}>/CF<</StdCF<</CFM/AESV3/AuthEvent/DocOpen/Length 32>>>>/StmF/StdCF/StrF/StdCF>>",
            hex(&o),
            hex(&u),
            hex(&oe),
            hex(&ue),
            hex(&b)
        );
        return Enc { scheme, dict, key };
    }
    // Algorithm 3: /O.
    let mut ok = md5(&[&padded(owner)]);
    if r >= 3 {
        for _ in 0..50 {
            ok = md5(&[&ok]);
        }
    }
    let ok = &ok[..n];
    let mut o = padded(user);
    rc4(ok, &mut o);
    if r >= 3 {
        for i in 1u8..=19 {
            let k: Vec<u8> = ok.iter().map(|b| b ^ i).collect();
            rc4(&k, &mut o);
        }
    }
    // Algorithm 2: the key.
    let meta: &[u8] = if r >= 4 && !scheme.encrypt_metadata() {
        &[0xFF; 4]
    } else {
        &[]
    };
    let mut key = md5(&[&padded(user), &o, &P.to_le_bytes(), ID0, meta]);
    if r >= 3 {
        for _ in 0..50 {
            key = md5(&[&key[..n]]);
        }
    }
    key.truncate(n);
    // Algorithms 4 and 5: /U.
    let u = if r == 2 {
        let mut u = PAD.to_vec();
        rc4(&key, &mut u);
        u
    } else {
        let mut x = md5(&[&PAD, ID0]);
        rc4(&key, &mut x);
        for i in 1u8..=19 {
            let k: Vec<u8> = key.iter().map(|b| b ^ i).collect();
            rc4(&k, &mut x);
        }
        x.extend_from_slice(&[0xAB; 16]);
        x
    };
    let (v, extra) = match scheme {
        Scheme::Rc4_40 => (1, String::new()),
        Scheme::Rc4_128 => (2, "/Length 128".to_string()),
        Scheme::Aes128 => (
            4,
            "/Length 128/CF<</StdCF<</CFM/AESV2/AuthEvent/DocOpen/Length 16>>>>/StmF/StdCF/StrF/StdCF"
                .to_string(),
        ),
        Scheme::Rc4CfClearMetadata => (
            4,
            "/Length 128/CF<</StdCF<</CFM/V2/Length 16>>>>/StmF/StdCF/StrF/StdCF/EncryptMetadata false"
                .to_string(),
        ),
        _ => unreachable!(),
    };
    let dict = format!(
        "<</Filter/Standard/V {v}/R {r}{extra}/P {P}/O<{}>/U<{}>>>",
        hex(&o),
        hex(&u)
    );
    Enc { scheme, dict, key }
}

impl Enc {
    fn object_key(&self, num: u32) -> Vec<u8> {
        if self.scheme.r() >= 5 {
            return self.key.clone();
        }
        let salt: &[u8] = if self.scheme.aes() { b"sAlT" } else { b"" };
        let mut k = md5(&[&self.key, &num.to_le_bytes()[..3], &[0, 0], salt]);
        k.truncate((self.key.len() + 5).min(16));
        k
    }

    fn encrypt(&self, num: u32, data: &[u8]) -> Vec<u8> {
        let key = self.object_key(num);
        if self.scheme.aes() {
            let iv: Vec<u8> = (0..16u8).map(|i| i ^ num as u8).collect();
            let mut out = iv.clone();
            out.extend(aes_cbc_encrypt(&key, &iv, data, true));
            out
        } else {
            let mut out = data.to_vec();
            rc4(&key, &mut out);
            out
        }
    }
}

/// An object to write: its body, with `{{text}}` marking a string to encrypt; and,
/// for a stream, its dictionary entries and data (`encrypt` false leaves it in clear,
/// as an xref, metadata or Identity stream is).
enum Obj {
    Value(String),
    Stream {
        dict: String,
        data: Vec<u8>,
        encrypt: bool,
    },
}

fn strings(enc: &Enc, num: u32, body: &str) -> String {
    let mut out = String::new();
    let mut rest = body;
    while let Some(at) = rest.find("{{") {
        out.push_str(&rest[..at]);
        let end = rest[at..].find("}}").unwrap() + at;
        let plain = &rest[at + 2..end];
        out.push_str(&format!("<{}>", hex(&enc.encrypt(num, plain.as_bytes()))));
        rest = &rest[end + 2..];
    }
    out.push_str(rest);
    out
}

/// A classic-xref file encrypted with `enc`; the `/Encrypt` dictionary is object 99.
fn file(enc: &Enc, objs: &[(u32, Obj)]) -> Vec<u8> {
    let mut out = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n".to_vec();
    let mut offs = std::collections::BTreeMap::new();
    for (n, o) in objs {
        offs.insert(*n, out.len());
        out.extend_from_slice(format!("{n} 0 obj\n").as_bytes());
        match o {
            Obj::Value(body) => out.extend_from_slice(strings(enc, *n, body).as_bytes()),
            Obj::Stream {
                dict,
                data,
                encrypt,
            } => {
                let data = if *encrypt {
                    enc.encrypt(*n, data)
                } else {
                    data.clone()
                };
                out.extend_from_slice(
                    format!(
                        "<<{}/Length {}>>\nstream\n",
                        strings(enc, *n, dict),
                        data.len()
                    )
                    .as_bytes(),
                );
                out.extend_from_slice(&data);
                out.extend_from_slice(b"\nendstream");
            }
        }
        out.extend_from_slice(b"\nendobj\n");
    }
    offs.insert(99, out.len());
    out.extend_from_slice(format!("99 0 obj\n{}\nendobj\n", enc.dict).as_bytes());
    let size = 100;
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {size}\n0000000000 65535 f \n").as_bytes());
    for n in 1..size {
        match offs.get(&n) {
            Some(o) => out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes()),
            None => out.extend_from_slice(b"0000000000 65535 f \n"),
        }
    }
    out.extend_from_slice(
        format!(
            "trailer\n<</Size {size}/Root 1 0 R/Info 3 0 R/Encrypt 99 0 R/ID[<{}><{}>]>>\nstartxref\n{xref}\n%%EOF\n",
            hex(ID0),
            hex(ID0)
        )
        .as_bytes(),
    );
    out
}

/// The refusal code, or `None` when the file opened (a short failure message).
fn code(r: Result<casual_sign_pdf::Admitted<'_>, casual_sign_pdf::PdfError>) -> &'static str {
    match r {
        Ok(_) => "opened",
        Err(e) => e.code(),
    }
}

const CONTENT: &[u8] = b"BT /F1 12 Tf 72 720 Td (Encrypted page) Tj ET";

/// One page with a Flate content stream, an /Info title, a text field with a value,
/// and a metadata stream.
fn sample(enc: &Enc) -> Vec<u8> {
    file(
        enc,
        &[
            (
                1,
                Obj::Value(
                    "<</Type/Catalog/Pages 2 0 R/Metadata 6 0 R/AcroForm<</Fields[7 0 R]>>>>"
                        .into(),
                ),
            ),
            (2, Obj::Value("<</Type/Pages/Kids[4 0 R]/Count 1>>".into())),
            (
                3,
                Obj::Value("<</Title{{Secret title}}/Producer{{test}}>>".into()),
            ),
            (
                4,
                Obj::Value(
                    "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 5 0 R>>".into(),
                ),
            ),
            (
                5,
                Obj::Stream {
                    dict: "/Filter/FlateDecode".into(),
                    data: zlib(CONTENT),
                    encrypt: true,
                },
            ),
            (
                6,
                Obj::Stream {
                    dict: "/Type/Metadata/Subtype/XML".into(),
                    data: b"<x:xmpmeta/>".to_vec(),
                    encrypt: enc.scheme.encrypt_metadata(),
                },
            ),
            (
                7,
                Obj::Value("<</FT/Tx/T{{Name field}}/V{{Ada}}/Rect[0 0 10 10]/P 4 0 R>>".into()),
            ),
        ],
    )
}

const ALL: [Scheme; 6] = [
    Scheme::Rc4_40,
    Scheme::Rc4_128,
    Scheme::Aes128,
    Scheme::Rc4CfClearMetadata,
    Scheme::Aes256,
    Scheme::Aes256R5,
];

fn title(a: &mut casual_sign_pdf::Admitted<'_>) -> Vec<u8> {
    let info = a.document.trailer().get(b"Info").cloned().unwrap();
    match a.document.resolve(&info, &never).unwrap() {
        Object::Dictionary(d) => match d.get(b"Title") {
            Some(Object::String(s)) => s.clone(),
            other => panic!("title {other:?}"),
        },
        other => panic!("info {other:?}"),
    }
}

#[test]
fn each_handler_opens_with_the_user_or_owner_password_and_refuses_without() {
    for scheme in ALL {
        let enc = setup(scheme, b"userpw", b"ownerpw");
        let bytes = sample(&enc);
        let limits = Limits::default();
        // No password, or a wrong one: refused in both modes.
        for creds in [
            Credentials::new(),
            Credentials::new().with_password("wrong"),
        ] {
            assert_eq!(
                code(admit_with(&bytes, &limits, &creds, &never)),
                "CS-PDF-0009",
                "{scheme:?}"
            );
            assert_eq!(
                code(admit_strict_with(&bytes, &limits, &creds, &never)),
                "CS-PDF-0009"
            );
        }
        for (pw, kind) in [
            ("userpw", PasswordKind::User),
            ("ownerpw", PasswordKind::Owner),
        ] {
            let creds = Credentials::new().with_password("wrong").with_password(pw);
            let mut a = admit_strict_with(&bytes, &limits, &creds, &never)
                .unwrap_or_else(|e| panic!("{scheme:?} {pw}: {e}"));
            let info = a.report.encryption.expect("encryption reported");
            assert_eq!(info.opened_with, kind, "{scheme:?}");
            assert!(!info.empty_password);
            assert_eq!(info.revision, scheme.r());
            assert_eq!(usize::from(info.key_bits), scheme.n() * 8);
            assert_eq!(info.permissions, P as u32);
            assert_eq!(info.encrypt_metadata, scheme.encrypt_metadata());
            let cipher = match scheme {
                Scheme::Aes128 => Cipher::Aes128,
                Scheme::Aes256 | Scheme::Aes256R5 => Cipher::Aes256,
                _ => Cipher::Rc4,
            };
            assert_eq!(info.streams, cipher);
            assert!(a.report.has_code("CS-PDF-0109"));
            assert_eq!(a.report.page_count, 1);
            assert_eq!(title(&mut a), b"Secret title", "{scheme:?}");
            assert_eq!(a.report.fields[0].name, "Name field");
            assert_eq!(a.document.decode_stream(5, &never).unwrap(), CONTENT);
            assert_eq!(
                a.document.decode_stream(6, &never).unwrap(),
                b"<x:xmpmeta/>",
                "{scheme:?} metadata"
            );
        }
    }
}

#[test]
fn an_empty_user_password_opens_without_credentials() {
    for scheme in ALL {
        let enc = setup(scheme, b"", b"ownerpw");
        let bytes = sample(&enc);
        let mut a =
            admit(&bytes, &Limits::default(), &never).unwrap_or_else(|e| panic!("{scheme:?}: {e}"));
        let info = a.report.encryption.unwrap();
        assert!(info.empty_password);
        assert_eq!(info.opened_with, PasswordKind::User);
        assert_eq!(title(&mut a), b"Secret title");
    }
}

#[test]
fn password_bytes_are_used_unchanged() {
    let enc = setup(Scheme::Rc4_128, b"caf\xe9", b"o");
    let bytes = sample(&enc);
    let limits = Limits::default();
    let by_bytes = Credentials::new().with_password_bytes(b"caf\xe9");
    assert!(admit_with(&bytes, &limits, &by_bytes, &never).is_ok());
    // The same text, encoded to PDFDocEncoding for revision 3.
    let by_text = Credentials::new().with_password("caf\u{e9}");
    assert!(admit_with(&bytes, &limits, &by_text, &never).is_ok());
    // From revision 5 text is UTF-8 after SASLprep.
    let enc = setup(Scheme::Aes256, "caf\u{e9}".as_bytes(), b"o");
    let bytes = sample(&enc);
    assert!(admit_with(&bytes, &limits, &by_text, &never).is_ok());
}

#[test]
fn normalization_writes_the_document_decrypted() {
    for scheme in ALL {
        for form in [OutputXref::Stream, OutputXref::Table] {
            let enc = setup(scheme, b"", b"ownerpw");
            let bytes = sample(&enc);
            let mut a = admit(&bytes, &Limits::default(), &never).unwrap();
            let n = normalize(&mut a, &NormalizeOptions::with_xref(form), &never).unwrap();
            assert!(
                n.report
                    .removed
                    .iter()
                    .any(|r| r.kind == FindingKind::Encrypted && r.code == "CS-PDF-0109")
            );
            let mut out = admit_strict(&n.bytes, &Limits::default(), &never)
                .unwrap_or_else(|e| panic!("{scheme:?} {form:?}: {e}"));
            assert!(out.report.encryption.is_none());
            assert!(!out.document.trailer().contains(b"Encrypt"));
            assert_eq!(title(&mut out), b"Secret title");
            assert_eq!(out.report.fields[0].name, "Name field");
            let content = out.report.pages[0].object;
            let Object::Dictionary(page) = out.document.object(content, &never).unwrap() else {
                panic!("page");
            };
            let c = page.get(b"Contents").unwrap().as_ref().unwrap().num;
            assert_eq!(out.document.decode_stream(c, &never).unwrap(), CONTENT);
            // Nothing of the cipher text is left.
            let secret = enc.encrypt(3, b"Secret title");
            assert!(
                !n.bytes
                    .windows(secret.len())
                    .any(|w| w == secret.as_slice())
            );
        }
    }
}

#[test]
fn crypt_filters_identity_and_per_stream() {
    let enc = setup(Scheme::Aes128, b"", b"o");
    let bytes = file(
        &enc,
        &[
            (1, Obj::Value("<</Type/Catalog/Pages 2 0 R>>".into())),
            (2, Obj::Value("<</Type/Pages/Kids[4 0 R]/Count 1>>".into())),
            (3, Obj::Value("<<>>".into())),
            (
                4,
                Obj::Value(
                    "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents[5 0 R 6 0 R]>>"
                        .into(),
                ),
            ),
            // A stream with its own /Crypt filter naming /Identity: stored in clear.
            (
                5,
                Obj::Stream {
                    dict: "/Filter[/Crypt/FlateDecode]/DecodeParms[<</Name/Identity>> null]".into(),
                    data: zlib(b"q Q"),
                    encrypt: false,
                },
            ),
            // One naming the document's crypt filter: encrypted.
            (
                6,
                Obj::Stream {
                    dict: "/Filter/Crypt/DecodeParms<</Type/CryptFilterDecodeParms/Name/StdCF>>"
                        .into(),
                    data: CONTENT.to_vec(),
                    encrypt: true,
                },
            ),
        ],
    );
    let mut a = admit_strict(&bytes, &Limits::default(), &never).unwrap();
    assert_eq!(a.document.decode_stream(5, &never).unwrap(), b"q Q");
    assert_eq!(a.document.decode_stream(6, &never).unwrap(), CONTENT);
    let n = normalize(&mut a, &NormalizeOptions::default(), &never).unwrap();
    let out = admit_strict(&n.bytes, &Limits::default(), &never).unwrap();
    assert!(out.report.encryption.is_none());
    assert!(!n.bytes.windows(6).any(|w| w == b"/Crypt"));

    // A document whose stream filter is /Identity: streams in clear, strings not.
    let mut enc = setup(Scheme::Aes128, b"", b"o");
    enc.dict = enc.dict.replace("/StmF/StdCF", "/StmF/Identity");
    let rebuilt = file(
        &enc,
        &[
            (1, Obj::Value("<</Type/Catalog/Pages 2 0 R>>".into())),
            (2, Obj::Value("<</Type/Pages/Kids[4 0 R]/Count 1>>".into())),
            (3, Obj::Value("<</Title{{Secret title}}>>".into())),
            (
                4,
                Obj::Value(
                    "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 5 0 R>>".into(),
                ),
            ),
            (
                5,
                Obj::Stream {
                    dict: String::new(),
                    data: CONTENT.to_vec(),
                    encrypt: false,
                },
            ),
        ],
    );
    let mut a = admit_strict(&rebuilt, &Limits::default(), &never).unwrap();
    assert_eq!(a.report.encryption.unwrap().streams, Cipher::None);
    assert_eq!(a.document.decode_stream(5, &never).unwrap(), CONTENT);
    assert_eq!(title(&mut a), b"Secret title");
}

#[test]
fn signature_contents_are_not_decrypted() {
    let enc = setup(Scheme::Rc4_128, b"", b"o");
    let bytes = file(
        &enc,
        &[
            (
                1,
                Obj::Value("<</Type/Catalog/Pages 2 0 R/AcroForm<</Fields[5 0 R]>>>>".into()),
            ),
            (2, Obj::Value("<</Type/Pages/Kids[4 0 R]/Count 1>>".into())),
            (3, Obj::Value("<<>>".into())),
            (
                4,
                Obj::Value("<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>".into()),
            ),
            (5, Obj::Value("<</FT/Sig/T{{sig}}/V 6 0 R>>".into())),
            (
                6,
                Obj::Value(
                    "<</Type/Sig/SubFilter/adbe.pkcs7.detached/ByteRange[0 1 2 3]/Contents<3082DEAD>/Name{{Signer}}>>"
                        .into(),
                ),
            ),
        ],
    );
    let mut a = admit_strict(&bytes, &Limits::default(), &never).unwrap();
    assert!(a.report.is_signed());
    let Object::Dictionary(sig) = a.document.object(6, &never).unwrap() else {
        panic!("sig");
    };
    assert_eq!(
        sig.get(b"Contents"),
        Some(&Object::String(vec![0x30, 0x82, 0xDE, 0xAD]))
    );
    assert_eq!(sig.get(b"Name"), Some(&Object::String(b"Signer".to_vec())));
}

#[test]
fn decryption_is_charged_to_the_document_budget() {
    // Strings: a 2 MiB encrypted string, with a 1 MiB budget, is refused when read;
    // the same file unencrypted reads (strings are not decoded, so not charged).
    let enc = setup(Scheme::Rc4_128, b"", b"o");
    let big = "x".repeat(2 << 20);
    let body = format!("<</Title{{{{{big}}}}}>>");
    let objs = |info: &str| {
        vec![
            (1, Obj::Value("<</Type/Catalog/Pages 2 0 R>>".into())),
            (2, Obj::Value("<</Type/Pages/Kids[4 0 R]/Count 1>>".into())),
            (3, Obj::Value(info.to_string())),
            (
                4,
                Obj::Value("<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>".into()),
            ),
        ]
    };
    let bytes = file(&enc, &objs(&body));
    let small = Limits {
        max_total_decoded_bytes: 1 << 20,
        ..Limits::default()
    };
    assert_eq!(code(admit(&bytes, &small, &never)), "CS-PDF-0003");
    assert!(admit(&bytes, &Limits::default(), &never).is_ok());

    // Streams: decrypting is charged as well as decoding. A 600 KiB unfiltered stream
    // costs 1.2 MiB to read encrypted, 600 KiB in clear.
    let data = vec![b' '; 600 << 10];
    let objs = |encrypt: bool| {
        vec![
            (1, Obj::Value("<</Type/Catalog/Pages 2 0 R>>".into())),
            (2, Obj::Value("<</Type/Pages/Kids[4 0 R]/Count 1>>".into())),
            (3, Obj::Value("<<>>".into())),
            (
                4,
                Obj::Value(
                    "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 5 0 R>>".into(),
                ),
            ),
            (
                5,
                Obj::Stream {
                    dict: String::new(),
                    data: data.clone(),
                    encrypt,
                },
            ),
        ]
    };
    let bytes = file(&enc, &objs(true));
    assert_eq!(code(admit_strict(&bytes, &small, &never)), "CS-PDF-0003");
    // The same stream under the /Identity stream filter is not decrypted.
    let mut clear = setup(Scheme::Aes128, b"", b"o");
    clear.dict = clear.dict.replace("/StmF/StdCF", "/StmF/Identity");
    let bytes = file(&clear, &objs(false));
    assert!(admit_strict(&bytes, &small, &never).is_ok());
}

#[test]
fn unsupported_and_malformed_encryption() {
    let enc = setup(Scheme::Rc4_128, b"", b"o");
    let bytes = sample(&enc);
    let swap = |from: &str, to: &str| {
        let s = bytes
            .windows(from.len())
            .position(|w| w == from.as_bytes())
            .unwrap();
        // The /Encrypt object is the last before the xref, so its length may change:
        // the xref offset shifts and the default reader corrects it; strict reading
        // corrects it within ±1 KiB too.
        let mut b = bytes.clone();
        b.splice(s..s + from.len(), to.bytes());
        b
    };
    for (from, to, want) in [
        ("/Filter/Standard", "/Filter/Adobe.PubSec", "CS-PDF-0010"),
        ("/Filter/Standard", "/Filter/FOPN_fowe", "CS-PDF-0010"),
        ("/R 3", "/R 9", "CS-PDF-0010"),
        ("/O<", "/X<", "CS-PDF-0005"),
    ] {
        let b = swap(from, to);
        for strict in [false, true] {
            let r = if strict {
                admit_strict(&b, &Limits::default(), &never)
            } else {
                admit(&b, &Limits::default(), &never)
            };
            assert_eq!(code(r), want, "{from} -> {to}");
        }
    }
}

#[test]
fn appending_to_an_encrypted_document_is_refused() {
    let enc = setup(Scheme::Aes128, b"", b"o");
    let bytes = sample(&enc);
    let a = admit(&bytes, &Limits::default(), &never).unwrap();
    let e = IncrementalUpdate::new(&a, Change::FillAndSign).unwrap_err();
    assert_eq!(e.code(), "CS-WRT-0006");
}
