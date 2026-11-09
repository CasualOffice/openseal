//! SPK-02 native path: PAdES B-B with aws-lc-rs for keys, signing and hashing, and
//! RustCrypto (`der`, `x509-cert`, `cms`) for every structure.
//!
//! Throwaway PKI generated at run time (P-256 root; a P-256 leaf and an RSA-3072 leaf).
//! Private keys never leave memory. Writes to `out/` (git-ignored):
//!   ca.pem                    trust root for pyHanko
//!   p256.pdf, rsa3072.pdf     sealed one-page PDFs
//!   p256-unsorted-attrs.pdf   signed attributes deliberately written out of DER order
//!   *-tampered.pdf            one byte flipped inside the signed range
//! Then runs the RustCrypto verifier (`spk02-verify`) natively over every file.

use std::fs;
use std::path::Path;
use std::time::Instant;

use aws_lc_rs::digest::{self, SHA256};
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{self as awssig, EcdsaKeyPair, KeyPair as _, RsaKeyPair};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
};
use der::asn1::{Any, OctetString, SetOfVec};
use der::{Decode, Encode};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType, IsCa,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PKCS_RSA_SHA256, RsaKeySize, SerialNumber,
};
use spk02_verify::ess::{EssCertIdV2, IssuerSerial, SigningCertificateV2};
use spk02_verify::{
    AttrBytes, ID_CONTENT_TYPE, ID_DATA, ID_ECDSA_SHA256, ID_MESSAGE_DIGEST, ID_RSA_SHA256,
    ID_SHA256, ID_SIGNED_DATA, ID_SIGNING_CERT_V2,
};
use spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;
use x509_cert::attr::Attribute;
use x509_cert::ext::pkix::name::GeneralName;

type Res<T> = Result<T, Box<dyn std::error::Error>>;

/// A signing key as `keyd` would hold it: it signs a digest and returns DER.
enum Key {
    P256(EcdsaKeyPair),
    Rsa(RsaKeyPair),
}

impl Key {
    /// Signs a SHA-256 digest of the DER signed attributes (the `keyd` contract: it never
    /// sees the document). aws-lc-rs marks `sign_digest` "not FIPS-approved"; see report.
    fn sign_digest(&self, d: &digest::Digest) -> Res<Vec<u8>> {
        Ok(match self {
            Key::P256(k) => k
                .sign_digest(d)
                .map_err(|_| "ecdsa sign")?
                .as_ref()
                .to_vec(),
            Key::Rsa(k) => {
                let mut sig = vec![0u8; k.public_modulus_len()];
                k.sign_digest(&awssig::RSA_PKCS1_SHA256, d, &mut sig)
                    .map_err(|_| "rsa sign")?;
                sig
            }
        })
    }
    /// Largest possible signature, for placeholder sizing.
    fn max_sig_len(&self) -> usize {
        match self {
            // SEQUENCE{INTEGER r, INTEGER s}, each up to 33 bytes with a sign pad.
            Key::P256(_) => 72,
            Key::Rsa(k) => k.public_modulus_len(),
        }
    }
    fn sig_alg(&self) -> AlgorithmIdentifierOwned {
        match self {
            Key::P256(_) => AlgorithmIdentifierOwned {
                oid: ID_ECDSA_SHA256,
                parameters: None,
            },
            Key::Rsa(_) => AlgorithmIdentifierOwned {
                oid: ID_RSA_SHA256,
                parameters: Some(Any::null()),
            },
        }
    }
}

fn name(cn: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    dn.push(DnType::OrganizationName, "OpenSeal SPK-02 throwaway");
    dn
}

/// Port of tools/verify-sealed.py `one_page_pdf` (ours). Returns (pdf, xref offset).
fn one_page_pdf(text: &str) -> (Vec<u8>, usize) {
    let stream = format!("BT /F1 24 Tf 72 720 Td ({text}) Tj ET");
    let objects: Vec<Vec<u8>> = vec![
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>".to_vec(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec(),
        format!("<< /Length {} >>\nstream\n{stream}\nendstream", stream.len()).into_bytes(),
    ];
    let mut out = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n".to_vec();
    let mut offsets = vec![];
    for (i, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref = out.len();
    out.extend_from_slice(
        format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes(),
    );
    for off in offsets {
        out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    (out, xref)
}

const BR_PLACEHOLDER: &str = "[0 ********** ********** **********]";

/// Append an incremental update with a signature field and placeholders.
/// Returns (pdf, offset of '<' of /Contents, offset after '>').
fn add_sig_field(pdf: &[u8], prev_xref: usize, reserved: usize) -> (Vec<u8>, usize, usize) {
    let mut out = pdf.to_vec();
    let mut offs = std::collections::BTreeMap::new();
    let obj = |out: &mut Vec<u8>,
               offs: &mut std::collections::BTreeMap<u32, usize>,
               n: u32,
               body: &str| {
        offs.insert(n, out.len());
        out.extend_from_slice(format!("{n} 0 obj\n{body}\nendobj\n").as_bytes());
    };
    obj(
        &mut out,
        &mut offs,
        1,
        "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R] /SigFlags 3 >> >>",
    );
    obj(
        &mut out,
        &mut offs,
        3,
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R /Annots [7 0 R] >>",
    );
    // Signature dictionary: written by hand to find the /Contents offsets.
    offs.insert(6, out.len());
    out.extend_from_slice(
        format!(
            "6 0 obj\n<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /M (D:20260101000000Z) /Reason (SPK-02 throwaway test key) /ByteRange {BR_PLACEHOLDER} /Contents "
        )
        .as_bytes(),
    );
    let c_start = out.len();
    out.push(b'<');
    out.extend(std::iter::repeat_n(b'0', reserved * 2));
    out.push(b'>');
    let c_end = out.len();
    out.extend_from_slice(b" >>\nendobj\n");
    obj(
        &mut out,
        &mut offs,
        7,
        "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Seal1) /V 6 0 R /F 132 /Rect [0 0 0 0] /P 3 0 R >>",
    );
    let xref = out.len();
    let mut x = String::from("xref\n0 2\n0000000000 65535 f \n");
    x += &format!(
        "{:010} 00000 n \n3 1\n{:010} 00000 n \n6 2\n{:010} 00000 n \n{:010} 00000 n \n",
        offs[&1], offs[&3], offs[&6], offs[&7]
    );
    x += &format!(
        "trailer\n<< /Size 8 /Root 1 0 R /Prev {prev_xref} >>\nstartxref\n{xref}\n%%EOF\n"
    );
    out.extend_from_slice(x.as_bytes());
    (out, c_start, c_end)
}

fn attr(
    oid: der::asn1::ObjectIdentifier,
    value: &(impl der::Tagged + der::EncodeValue),
) -> Res<Attribute> {
    Ok(Attribute {
        oid,
        values: SetOfVec::try_from(vec![Any::encode_from(value)?])?,
    })
}

struct Signer<'a> {
    key: Key,
    cert: Certificate,
    chain: Vec<&'a Certificate>,
}

/// Build the signed attributes (DER-sorted by `SetOfVec`).
fn signed_attrs(s: &Signer, md: &[u8]) -> Res<SetOfVec<Attribute>> {
    let cert_hash = digest::digest(&SHA256, &s.cert.to_der()?);
    let ess = SigningCertificateV2 {
        certs: vec![EssCertIdV2 {
            hash_algorithm: None, // DEFAULT id-sha256: DER requires it absent
            cert_hash: OctetString::new(cert_hash.as_ref())?,
            issuer_serial: Some(IssuerSerial {
                issuer: vec![GeneralName::DirectoryName(
                    s.cert.tbs_certificate().issuer().clone(),
                )],
                serial_number: s.cert.tbs_certificate().serial_number().clone(),
            }),
        }],
    };
    Ok(SetOfVec::try_from(vec![
        attr(ID_CONTENT_TYPE, &ID_DATA)?,
        attr(ID_MESSAGE_DIGEST, &OctetString::new(md)?)?,
        attr(ID_SIGNING_CERT_V2, &ess)?,
    ])?)
}

fn cms_der(s: &Signer, attrs: SetOfVec<Attribute>, signature: Vec<u8>) -> Res<Vec<u8>> {
    let tbs = s.cert.tbs_certificate();
    let si = SignerInfo {
        version: CmsVersion::V1,
        sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: tbs.issuer().clone(),
            serial_number: tbs.serial_number().clone(),
        }),
        digest_alg: AlgorithmIdentifierOwned {
            oid: ID_SHA256,
            parameters: None,
        },
        signed_attrs: Some(attrs),
        signature_algorithm: s.key.sig_alg(),
        signature: OctetString::new(signature)?,
        unsigned_attrs: None, // B-T would put signature-time-stamp here
    };
    let mut certs = vec![CertificateChoices::Certificate(s.cert.clone())];
    certs.extend(
        s.chain
            .iter()
            .map(|c| CertificateChoices::Certificate((*c).clone())),
    );
    let sd = SignedData {
        version: CmsVersion::V1,
        digest_algorithms: SetOfVec::try_from(vec![AlgorithmIdentifierOwned {
            oid: ID_SHA256,
            parameters: None,
        }])?,
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: ID_DATA,
            econtent: None,
        },
        certificates: Some(CertificateSet(SetOfVec::try_from(certs)?)),
        crls: None,
        signer_infos: SignerInfos(SetOfVec::try_from(vec![si])?),
    };
    Ok(ContentInfo {
        content_type: ID_SIGNED_DATA,
        content: Any::encode_from(&sd)?,
    }
    .to_der()?)
}

/// Seal `pdf`. With `unsorted`, the signed attributes are rewritten in reverse (non-DER)
/// order before signing, as some third-party signers do.
fn seal(pdf: &[u8], prev_xref: usize, s: &Signer, unsorted: bool) -> Res<(Vec<u8>, usize, usize)> {
    // 1. Size the placeholder by a dry run with a zero digest and a maximal signature.
    let dry = cms_der(
        s,
        signed_attrs(s, &[0u8; 32])?,
        vec![0u8; s.key.max_sig_len()],
    )?;
    let reserved = dry.len();
    // 2. Placeholder, then ByteRange in place (fixed width).
    let (mut out, c_start, c_end) = add_sig_field(pdf, prev_xref, reserved);
    let br = format!(
        "[0 {:<10} {:<10} {:<10}]",
        c_start,
        c_end,
        out.len() - c_end
    );
    assert_eq!(br.len(), BR_PLACEHOLDER.len());
    let at = out
        .windows(BR_PLACEHOLDER.len())
        .position(|w| w == BR_PLACEHOLDER.as_bytes())
        .ok_or("br")?;
    out[at..at + br.len()].copy_from_slice(br.as_bytes());
    // 3. Hash the covered bytes with aws-lc-rs.
    let mut ctx = digest::Context::new(&SHA256);
    ctx.update(&out[..c_start]);
    ctx.update(&out[c_end..]);
    let md = ctx.finish();
    // 4. Signed attributes, DER; optionally reorder.
    let attrs = signed_attrs(s, md.as_ref())?;
    let sorted_set = attrs.to_der()?;
    let set_bytes = if unsorted {
        reverse_set(&sorted_set)?
    } else {
        sorted_set.clone()
    };
    // 5. Sign the digest of the SET encoding.
    let t = Instant::now();
    let sig = s.key.sign_digest(&digest::digest(&SHA256, &set_bytes))?;
    let sign_us = t.elapsed().as_micros();
    // 6. Assemble; for the unsorted case splice the reordered bytes in (same length).
    let mut der_cms = cms_der(s, attrs, sig)?;
    if unsorted {
        let mut implicit = sorted_set.clone();
        implicit[0] = 0xA0;
        let pos = der_cms
            .windows(implicit.len())
            .position(|w| w == implicit)
            .ok_or("attrs")?;
        der_cms[pos + 1..pos + implicit.len()].copy_from_slice(&set_bytes[1..]);
    }
    if der_cms.len() > reserved {
        return Err(format!("placeholder overflow: {} > {reserved}", der_cms.len()).into());
    }
    let hex: String = der_cms.iter().map(|b| format!("{b:02X}")).collect();
    out[c_start + 1..c_start + 1 + hex.len()].copy_from_slice(hex.as_bytes());
    eprintln!(
        "    sign_digest took {sign_us} us; CMS {} bytes, reserved {reserved}",
        der_cms.len()
    );
    Ok((out, der_cms.len(), reserved))
}

/// Reverse the elements of a DER SET (header unchanged, so the length is the same).
fn reverse_set(set: &[u8]) -> Res<Vec<u8>> {
    let mut r = der::SliceReader::new(set)?;
    let h = der::Header::decode(&mut r)?;
    let hdr_len = set.len() - usize::try_from(h.length())?;
    let mut items = vec![];
    use der::Reader;
    let body = r.read_slice(h.length())?;
    let mut br = der::SliceReader::new(body)?;
    while !br.is_finished() {
        items.push(br.tlv_bytes()?.to_vec());
    }
    items.reverse();
    let mut out = set[..hdr_len].to_vec();
    for i in items {
        out.extend(i);
    }
    Ok(out)
}

fn tamper(pdf: &[u8]) -> Vec<u8> {
    let mut v = pdf.to_vec();
    let at = v.windows(11).position(|w| w == b"(Agreement)").unwrap() + 1;
    v[at] ^= 0x20; // 'A' -> 'a', inside ByteRange part 1
    v
}

fn main() -> Res<()> {
    let out_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../out");
    fs::create_dir_all(&out_dir)?;

    // Throwaway PKI, fixed validity (time is supplied, never sampled).
    let ca_key = rcgen::KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut ca_p = CertificateParams::new(Vec::<String>::new())?;
    ca_p.distinguished_name = name("SPK-02 Throwaway Root");
    ca_p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_p.not_before = rcgen::date_time_ymd(2026, 1, 1);
    ca_p.not_after = rcgen::date_time_ymd(2036, 1, 1);
    ca_p.serial_number = Some(SerialNumber::from(1u64));
    let ca = CertifiedIssuer::self_signed(ca_p, ca_key)?;
    fs::write(out_dir.join("ca.pem"), ca.pem())?;
    let ca_cert = Certificate::from_der(ca.der())?;

    let leaf = |cn: &str, serial: u64, key: &rcgen::KeyPair| -> Res<Certificate> {
        let mut p = CertificateParams::new(Vec::<String>::new())?;
        p.distinguished_name = name(cn);
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::ContentCommitment,
        ];
        p.not_before = rcgen::date_time_ymd(2026, 1, 1);
        p.not_after = rcgen::date_time_ymd(2030, 1, 1);
        p.serial_number = Some(SerialNumber::from(serial));
        Ok(Certificate::from_der(p.signed_by(key, &ca)?.der())?)
    };

    // P-256 leaf: key generated by aws-lc-rs directly, PKCS#8 handed to rcgen for the cert.
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let p256_pkcs8 = EcdsaKeyPair::generate_pkcs8(&awssig::ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .map_err(|_| "gen")?;
    let p256 =
        EcdsaKeyPair::from_pkcs8(&awssig::ECDSA_P256_SHA256_ASN1_SIGNING, p256_pkcs8.as_ref())
            .map_err(|_| "load")?;
    let p256_rc = rcgen::KeyPair::try_from(p256_pkcs8.as_ref())?;
    let p256_cert = leaf("SPK-02 Throwaway Seal P-256", 2, &p256_rc)?;
    assert_eq!(
        p256.public_key().as_ref(),
        p256_cert
            .tbs_certificate()
            .subject_public_key_info()
            .subject_public_key
            .raw_bytes()
    );

    // RSA-3072 leaf.
    let t = Instant::now();
    let rsa = RsaKeyPair::generate(KeySize::Rsa3072).map_err(|_| "rsa gen")?;
    eprintln!("RSA-3072 keygen took {} ms", t.elapsed().as_millis());
    use aws_lc_rs::encoding::AsDer;
    let rsa_pkcs8 =
        AsDer::<aws_lc_rs::encoding::Pkcs8V1Der>::as_der(&rsa).map_err(|_| "rsa der")?;
    let rsa_rc =
        rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&rsa_pkcs8.as_ref().into(), &PKCS_RSA_SHA256)?;
    let rsa_cert = leaf("SPK-02 Throwaway Seal RSA-3072", 3, &rsa_rc)?;
    let _ = RsaKeySize::_3072; // rcgen can also generate RSA via aws-lc-rs; not needed here

    let (pdf, xref) = one_page_pdf("Agreement");
    let cases: Vec<(&str, Signer, bool)> = vec![
        (
            "p256",
            Signer {
                key: Key::P256(p256),
                cert: p256_cert.clone(),
                chain: vec![&ca_cert],
            },
            false,
        ),
        (
            "rsa3072",
            Signer {
                key: Key::Rsa(rsa),
                cert: rsa_cert,
                chain: vec![&ca_cert],
            },
            false,
        ),
    ];
    let p256_again =
        EcdsaKeyPair::from_pkcs8(&awssig::ECDSA_P256_SHA256_ASN1_SIGNING, p256_pkcs8.as_ref())
            .map_err(|_| "load")?;
    let unsorted = Signer {
        key: Key::P256(p256_again),
        cert: p256_cert,
        chain: vec![&ca_cert],
    };

    let mut written = vec![];
    for (label, s, uns) in
        cases
            .iter()
            .map(|(l, s, u)| (*l, s, *u))
            .chain([("p256-unsorted-attrs", &unsorted, true)])
    {
        eprintln!("{label}:");
        let (sealed, _cms_len, _reserved) = seal(&pdf, xref, s, uns)?;
        fs::write(out_dir.join(format!("{label}.pdf")), &sealed)?;
        written.push(format!("{label}.pdf"));
        if !uns {
            fs::write(
                out_dir.join(format!("{label}-tampered.pdf")),
                tamper(&sealed),
            )?;
            written.push(format!("{label}-tampered.pdf"));
        }
    }

    println!("RustCrypto verifier (native build of spk02-verify):");
    for f in &written {
        let bytes = fs::read(out_dir.join(f))?;
        let a = spk02_verify::verify_pdf(&bytes, AttrBytes::AsReceived);
        let b = spk02_verify::verify_pdf(&bytes, AttrBytes::Reencoded);
        let show = |r: &Result<spk02_verify::Verified, spk02_verify::VerifyError>| match r {
            Ok(v) => format!(
                "valid (alg {}, cms {} of {} reserved, ByteRange {:?})",
                v.signature_algorithm, v.cms_len, v.reserved_len, v.byte_range
            ),
            Err(e) => format!("INVALID {e:?}"),
        };
        println!("  {f:28} as-received: {}", show(&a));
        println!("  {:28} re-encoded:  {}", "", show(&b));
    }
    Ok(())
}
