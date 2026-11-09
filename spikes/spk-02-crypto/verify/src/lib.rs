//! SPK-02 verifier: checks the last PAdES signature in a PDF using RustCrypto only
//! (`der`, `x509-cert`, `cms`, `sha2`, `p256`, optional `rsa`), so it builds for
//! `wasm32-unknown-unknown` with no C code. Spike quality: it proves the stack, it is not
//! `casual-sign-verify` (no chain building, no revocation, no revision classification).
//!
//! It checks: ByteRange shape (starts at 0, the gap is exactly the `/Contents` hex string,
//! runs to end of file); the CMS parses; content-type is id-data; message-digest equals
//! SHA-256 over the ByteRange; signing-certificate-v2 hashes the signer certificate; and the
//! signature over the signed attributes verifies with the signer certificate's key.

#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::vec::Vec;

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier};
use der::asn1::{ObjectIdentifier, OctetString};
use der::{Decode, Encode, Header, Reader, SliceReader};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

/// id-signedData.
pub const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
/// id-data.
pub const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
/// id-contentType.
pub const ID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
/// id-messageDigest.
pub const ID_MESSAGE_DIGEST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
/// id-aa-signingCertificateV2 (RFC 5035).
pub const ID_SIGNING_CERT_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
/// id-sha256.
pub const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
/// ecdsa-with-SHA256.
pub const ID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
/// sha256WithRSAEncryption.
pub const ID_RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
/// rsaEncryption (some signers put this in SignerInfo.signatureAlgorithm).
pub const ID_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// Which bytes the signature over the signed attributes is checked against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttrBytes {
    /// The attributes exactly as they appear in the file, with the `[0]` tag replaced by
    /// the SET tag (what RFC 5652 §5.4 asks for, and what pyHanko does).
    AsReceived,
    /// Decode with `der` and re-encode. `der` 0.8 sorts SET OF on decode, so this differs
    /// from the file whenever a signer wrote the attributes out of DER order.
    Reencoded,
}

/// What failed. Spike error codes, not docs/20 codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// No `/ByteRange` or it is malformed.
    ByteRange = 1,
    /// The ByteRange does not cover the whole file except the `/Contents` string.
    Coverage = 2,
    /// `/Contents` is not hex or the CMS does not parse.
    Cms = 3,
    /// A required signed attribute is missing or malformed.
    Attributes = 4,
    /// message-digest does not equal the digest of the covered bytes.
    Digest = 5,
    /// The signer certificate is not in the CMS.
    SignerCert = 6,
    /// signing-certificate-v2 does not match the signer certificate.
    EssCertId = 7,
    /// The signature does not verify.
    Signature = 8,
    /// An algorithm this spike does not handle.
    Unsupported = 9,
}

/// A successful check.
#[derive(Debug, Clone)]
pub struct Verified {
    /// `[o1, l1, o2, l2]`.
    pub byte_range: [usize; 4],
    /// Signature algorithm OID as text.
    pub signature_algorithm: alloc::string::String,
    /// DER length of the CMS (without zero padding).
    pub cms_len: usize,
    /// Bytes reserved in `/Contents` (decoded).
    pub reserved_len: usize,
}

impl From<der::Error> for VerifyError {
    fn from(_: der::Error) -> Self {
        VerifyError::Cms
    }
}

fn parse_uint(s: &[u8]) -> Option<usize> {
    if s.is_empty() || s.len() > 12 {
        return None;
    }
    let mut v: usize = 0;
    for &c in s {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add(usize::from(c - b'0'))?;
    }
    Some(v)
}

fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).rposition(|w| w == needle)
}

/// Parse the last `/ByteRange [a b c d]` in the file.
pub fn byte_range(pdf: &[u8]) -> Result<[usize; 4], VerifyError> {
    let at = rfind(pdf, b"/ByteRange").ok_or(VerifyError::ByteRange)?;
    let rest = pdf.get(at + 10..).ok_or(VerifyError::ByteRange)?;
    let open = rest
        .iter()
        .position(|&c| c == b'[')
        .ok_or(VerifyError::ByteRange)?;
    let close = rest
        .iter()
        .position(|&c| c == b']')
        .ok_or(VerifyError::ByteRange)?;
    let inner = rest.get(open + 1..close).ok_or(VerifyError::ByteRange)?;
    let mut out = [0usize; 4];
    let mut n = 0;
    for tok in inner
        .split(|c| c.is_ascii_whitespace())
        .filter(|t| !t.is_empty())
    {
        let slot = out.get_mut(n).ok_or(VerifyError::ByteRange)?;
        *slot = parse_uint(tok).ok_or(VerifyError::ByteRange)?;
        n += 1;
    }
    if n != 4 {
        return Err(VerifyError::ByteRange);
    }
    Ok(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// The TLVs inside one constructed TLV.
fn children(tlv: &[u8]) -> Result<Vec<&[u8]>, VerifyError> {
    let mut r = SliceReader::new(tlv)?;
    let h = Header::decode(&mut r)?;
    let content = r.read_slice(h.length())?;
    let mut cr = SliceReader::new(content)?;
    let mut out = Vec::new();
    while !cr.is_finished() {
        out.push(cr.tlv_bytes()?);
    }
    Ok(out)
}

/// Raw bytes of the first SignerInfo's `[0] IMPLICIT SignedAttributes`, as in the file.
fn raw_signed_attrs(cms_der: &[u8]) -> Result<Vec<u8>, VerifyError> {
    let ci = children(cms_der)?;
    let explicit = ci.get(1).ok_or(VerifyError::Cms)?;
    let sd = *children(explicit)?.first().ok_or(VerifyError::Cms)?;
    let sd_items = children(sd)?;
    let signer_infos = *sd_items.last().ok_or(VerifyError::Cms)?;
    let si = *children(signer_infos)?.first().ok_or(VerifyError::Cms)?;
    let si_items = children(si)?;
    let attrs = *si_items.get(3).ok_or(VerifyError::Cms)?;
    if attrs.first() != Some(&0xA0) {
        return Err(VerifyError::Attributes);
    }
    let mut v = attrs.to_vec();
    if let Some(first) = v.first_mut() {
        *first = 0x31; // [0] IMPLICIT -> SET OF, per RFC 5652 §5.4
    }
    Ok(v)
}

/// signing-certificate-v2 value types (RFC 5035), which RustCrypto does not provide.
pub mod ess {
    use alloc::vec::Vec;
    use der::Sequence;
    use der::asn1::OctetString;
    use spki::AlgorithmIdentifierOwned;
    use x509_cert::ext::pkix::name::GeneralNames;
    use x509_cert::serial_number::SerialNumber;

    /// `IssuerSerial`.
    #[derive(Clone, Debug, PartialEq, Eq, Sequence)]
    pub struct IssuerSerial {
        /// Issuer as GeneralNames (a directoryName).
        pub issuer: GeneralNames,
        /// Serial number.
        pub serial_number: SerialNumber,
    }

    /// `ESSCertIDv2`. `hashAlgorithm` is `DEFAULT id-sha256`, so DER omits it for SHA-256.
    #[derive(Clone, Debug, PartialEq, Eq, Sequence)]
    pub struct EssCertIdV2 {
        /// Absent means SHA-256.
        #[asn1(optional = "true")]
        pub hash_algorithm: Option<AlgorithmIdentifierOwned>,
        /// Hash of the whole certificate DER.
        pub cert_hash: OctetString,
        /// Optional issuer and serial.
        #[asn1(optional = "true")]
        pub issuer_serial: Option<IssuerSerial>,
    }

    /// `SigningCertificateV2` (policies omitted).
    #[derive(Clone, Debug, PartialEq, Eq, Sequence)]
    pub struct SigningCertificateV2 {
        /// First entry identifies the signer certificate.
        pub certs: Vec<EssCertIdV2>,
    }
}

/// Verify the last signature in `pdf`.
pub fn verify_pdf(pdf: &[u8], mode: AttrBytes) -> Result<Verified, VerifyError> {
    let br = byte_range(pdf)?;
    let [o1, l1, o2, l2] = br;
    // Coverage: [0, l1) and [o2, o2+l2) with the gap exactly `<hex>` and the end at EOF.
    if o1 != 0 || o2 <= l1 || o2.checked_add(l2) != Some(pdf.len()) {
        return Err(VerifyError::Coverage);
    }
    let gap = pdf.get(l1..o2).ok_or(VerifyError::Coverage)?;
    let (Some(&b'<'), Some(&b'>')) = (gap.first(), gap.last()) else {
        return Err(VerifyError::Coverage);
    };
    let hex = gap.get(1..gap.len() - 1).ok_or(VerifyError::Coverage)?;
    if hex.len() % 2 != 0 {
        return Err(VerifyError::Cms);
    }
    let mut contents = Vec::with_capacity(hex.len() / 2);
    for pair in hex.chunks_exact(2) {
        let (Some(h), Some(l)) = (
            pair.first().and_then(|&c| hex_val(c)),
            pair.get(1).and_then(|&c| hex_val(c)),
        ) else {
            return Err(VerifyError::Cms);
        };
        contents.push(h << 4 | l);
    }
    let reserved_len = contents.len();
    // The CMS is followed by zero padding; take exactly one TLV.
    let cms_der = SliceReader::new(&contents)?.tlv_bytes()?;

    let ci = ContentInfo::from_der(cms_der)?;
    if ci.content_type != ID_SIGNED_DATA {
        return Err(VerifyError::Cms);
    }
    let sd: SignedData = ci.content.decode_as()?;
    let si = sd
        .signer_infos
        .0
        .as_slice()
        .first()
        .ok_or(VerifyError::Cms)?;
    if si.digest_alg.oid != ID_SHA256 {
        return Err(VerifyError::Unsupported);
    }
    let attrs = si.signed_attrs.as_ref().ok_or(VerifyError::Attributes)?;
    let mut message_digest: Option<OctetString> = None;
    let mut content_type_ok = false;
    let mut ess: Option<ess::SigningCertificateV2> = None;
    for a in attrs.iter() {
        let v = a.values.as_slice().first().ok_or(VerifyError::Attributes)?;
        if a.oid == ID_MESSAGE_DIGEST {
            message_digest = Some(v.decode_as()?);
        } else if a.oid == ID_CONTENT_TYPE {
            content_type_ok = v.decode_as::<ObjectIdentifier>()? == ID_DATA;
        } else if a.oid == ID_SIGNING_CERT_V2 {
            ess = Some(v.decode_as()?);
        }
    }
    if !content_type_ok {
        return Err(VerifyError::Attributes);
    }
    let message_digest = message_digest.ok_or(VerifyError::Attributes)?;

    // Digest of the covered bytes.
    let mut h = Sha256::new();
    h.update(pdf.get(..l1).ok_or(VerifyError::Coverage)?);
    h.update(pdf.get(o2..).ok_or(VerifyError::Coverage)?);
    if h.finalize().as_slice() != message_digest.as_bytes() {
        return Err(VerifyError::Digest);
    }

    // Signer certificate.
    let SignerIdentifier::IssuerAndSerialNumber(isn) = &si.sid else {
        return Err(VerifyError::Unsupported);
    };
    let cert: &Certificate = sd
        .certificates
        .as_ref()
        .ok_or(VerifyError::SignerCert)?
        .0
        .iter()
        .find_map(|c| match c {
            CertificateChoices::Certificate(c)
                if c.tbs_certificate().issuer() == &isn.issuer
                    && c.tbs_certificate().serial_number() == &isn.serial_number =>
            {
                Some(c)
            }
            _ => None,
        })
        .ok_or(VerifyError::SignerCert)?;
    let cert_der = cert.to_der()?;

    // ESS signing-certificate-v2 must name this certificate.
    let ess = ess.ok_or(VerifyError::Attributes)?;
    let first = ess.certs.first().ok_or(VerifyError::EssCertId)?;
    if first
        .hash_algorithm
        .as_ref()
        .is_some_and(|a| a.oid != ID_SHA256)
        || first.cert_hash.as_bytes() != Sha256::digest(&cert_der).as_slice()
    {
        return Err(VerifyError::EssCertId);
    }

    let signed_bytes = match mode {
        AttrBytes::AsReceived => raw_signed_attrs(cms_der)?,
        AttrBytes::Reencoded => attrs.to_der()?,
    };
    let spk = cert
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .as_bytes()
        .ok_or(VerifyError::SignerCert)?;
    let sig = si.signature.as_bytes();
    let alg = si.signature_algorithm.oid;
    if alg == ID_ECDSA_SHA256 {
        use p256::ecdsa::signature::Verifier;
        let key =
            p256::ecdsa::VerifyingKey::from_sec1_bytes(spk).map_err(|_| VerifyError::SignerCert)?;
        let sig = p256::ecdsa::Signature::from_der(sig).map_err(|_| VerifyError::Signature)?;
        key.verify(&signed_bytes, &sig)
            .map_err(|_| VerifyError::Signature)?;
    } else if alg == ID_RSA_SHA256 || alg == ID_RSA {
        verify_rsa(spk, &signed_bytes, sig)?;
    } else {
        return Err(VerifyError::Unsupported);
    }
    Ok(Verified {
        byte_range: br,
        signature_algorithm: alloc::format!("{alg}"),
        cms_len: cms_der.len(),
        reserved_len,
    })
}

#[cfg(feature = "rsa")]
fn verify_rsa(spk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), VerifyError> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::signature::Verifier;
    let key = rsa::PublicKey::from_pkcs1_der(spk).map_err(|_| VerifyError::SignerCert)?;
    let vk = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key);
    let sig = rsa::pkcs1v15::Signature::try_from(sig).map_err(|_| VerifyError::Signature)?;
    vk.verify(msg, &sig).map_err(|_| VerifyError::Signature)
}

#[cfg(not(feature = "rsa"))]
fn verify_rsa(_: &[u8], _: &[u8], _: &[u8]) -> Result<(), VerifyError> {
    Err(VerifyError::Unsupported)
}

/// WASM entry points: a raw `alloc` + `verify` pair, no wasm-bindgen, so the measured
/// size is the verifier itself. Returns 0 on success, else a [`VerifyError`] code.
pub mod wasm_abi {
    use super::{AttrBytes, verify_pdf};
    use alloc::vec::Vec;

    /// Allocate `len` bytes for the host to write the PDF into.
    #[unsafe(no_mangle)]
    pub extern "C" fn spk02_alloc(len: usize) -> *mut u8 {
        let mut v: Vec<u8> = Vec::with_capacity(len);
        let p = v.as_mut_ptr();
        core::mem::forget(v);
        p
    }

    /// Verify the PDF at `ptr..ptr+len` (written by the host after `spk02_alloc`).
    ///
    /// # Safety
    /// `ptr` must come from `spk02_alloc(len)` and hold `len` initialized bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn spk02_verify(ptr: *const u8, len: usize) -> i32 {
        // SAFETY: the caller contract above.
        let pdf = unsafe { core::slice::from_raw_parts(ptr, len) };
        match verify_pdf(pdf, AttrBytes::AsReceived) {
            Ok(_) => 0,
            Err(e) => e as i32,
        }
    }
}
