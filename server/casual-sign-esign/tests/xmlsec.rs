//! Our XML Signature profile against xmlsec1, the independent implementation (ADR-047 §4,
//! `RSP-02` acceptance (2) and (3)):
//!
//! - answers xmlsec1 signed (`fixtures/make.sh`: Canonical XML 1.0 and Exclusive
//!   Canonicalization, RSA and P-256, over text, namespaces, escapes, CR and CDATA)
//!   verify under the configured certificate and read;
//! - every altered, unsigned, wrapped, re-ordered or hostile copy is refused;
//! - requests we sign verify under our verifier and, where xmlsec1 can be run, under
//!   xmlsec1 (`xmlsec1` on the path, or `OPENSEAL_XMLSEC1_IMAGE` naming a container
//!   image that has it; CI sets `OPENSEAL_REQUIRE_XMLSEC1=1`, so there a missing xmlsec1
//!   fails the test instead of skipping it).
// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use aws_lc_rs::digest::{Digest, SHA256};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, RsaKeyPair};
use casual_sign_esign::dsig::read_verified;
use casual_sign_esign::{Algorithm, AuthMode, EsignError, Request, Status, VerifyingKey, response};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(fixtures().join(name)).unwrap()
}

fn key(cert: &str) -> VerifyingKey {
    VerifyingKey::from_certificate(&fixture(cert)).unwrap()
}

const SIGNED: [(&str, &str); 3] = [
    ("response-rsa-c14n.xml", "esp-rsa.der"),
    ("response-rsa-exc.xml", "esp-rsa.der"),
    ("response-p256-c14n.xml", "esp-p256.der"),
];

#[test]
fn answers_xmlsec1_signed_verify_and_read() {
    for (file, cert) in SIGNED {
        let r =
            response::read(&fixture(file), &key(cert)).unwrap_or_else(|e| panic!("{file}: {e}"));
        assert_eq!(r.status, Status::Signed, "{file}");
        assert_eq!(r.txn, "0192f3a4-0000-7000-8000-000000000001");
        assert_eq!(r.res_code.as_deref(), Some("RC-2026-0001"));
        assert_eq!(r.err_code, None);
        assert_eq!(r.signatures.len(), 1);
        assert_eq!(r.signatures[0].id, "1");
        assert!(r.user_certificate.is_some());
    }
}

#[test]
fn another_key_refuses_every_answer() {
    for (file, _) in SIGNED {
        assert_eq!(
            response::read(&fixture(file), &key("other-rsa.der")).unwrap_err(),
            if file.contains("p256") {
                EsignError::Profile("signature method")
            } else {
                EsignError::SignatureInvalid
            },
            "{file}"
        );
    }
}

fn altered(file: &str, from: &str, to: &str) -> Vec<u8> {
    let text = String::from_utf8(fixture(file)).unwrap();
    assert!(text.contains(from), "{file} has no {from:?}");
    text.replacen(from, to, 1).into_bytes()
}

fn refused(bytes: &[u8], cert: &str) -> EsignError {
    response::read(bytes, &key(cert)).unwrap_err()
}

#[test]
fn any_change_to_the_signed_content_is_a_digest_mismatch() {
    for (file, cert) in SIGNED {
        for (from, to) in [
            ("RC-2026-0001", "RC-2026-0002"),
            ("status=\"1\"", "status=\"0\""),
            ("<inner c=", "<inner d="),
            ("with cr", "with  cr"),
            ("&lt;raw", "&lt;Raw"),
        ] {
            let bytes = if from == "&lt;raw" {
                altered(file, "<![CDATA[<raw", "<![CDATA[<Raw")
            } else {
                altered(file, from, to)
            };
            assert_eq!(
                refused(&bytes, cert),
                EsignError::DigestMismatch,
                "{file}: {from}"
            );
        }
    }
}

#[test]
fn a_changed_signed_info_or_value_does_not_verify() {
    let (file, cert) = SIGNED[0];
    let text = String::from_utf8(fixture(file)).unwrap();
    let at = text.find("<SignatureValue>").unwrap() + "<SignatureValue>".len();
    let mut b = text.into_bytes();
    b[at + 10] = if b[at + 10] == b'A' { b'B' } else { b'A' };
    assert_eq!(refused(&b, cert), EsignError::SignatureInvalid);
    let b = altered(file, "<DigestValue>", "<DigestValue>\n");
    assert_eq!(
        refused(&b, cert),
        EsignError::SignatureInvalid,
        "SignedInfo text"
    );
}

#[test]
fn unsigned_wrapped_reordered_and_out_of_profile_answers_are_refused() {
    let (file, cert) = SIGNED[0];
    let text = String::from_utf8(fixture(file)).unwrap();
    let start = text.find("<Signature xmlns").unwrap();
    let end = text.find("</Signature>").unwrap() + "</Signature>".len();
    let signature = &text[start..end];
    let unsigned = format!("{}{}", &text[..start], &text[end..]);
    let cases: Vec<(String, EsignError)> = vec![
        (unsigned.clone(), EsignError::Profile("no signature")),
        // The signature moved first: it no longer encloses... the last element is not it.
        (
            text.replacen(signature, "", 1)
                .replacen("<UserX509Certificate>", &format!("{signature}<UserX509Certificate>"), 1),
            EsignError::Profile("signature not last in the root"),
        ),
        // A forged answer wrapped inside the signature, the genuine one left to verify.
        (
            text.replacen(
                "<KeyInfo>",
                "<Object><EsignResp status=\"1\" txn=\"forged\"/></Object><KeyInfo>",
                1,
            ),
            EsignError::Profile("signature children"),
        ),
        // A second signature.
        (
            text.replacen("</Signatures>", &format!("</Signatures>{signature}"), 1),
            EsignError::Profile("more than one signature"),
        ),
        // The signature inside a child, a forged root around it.
        (
            text.replacen(signature, &format!("<Wrap>{signature}</Wrap>"), 1),
            EsignError::Profile("signature not last in the root"),
        ),
        (
            text.replacen("<Reference URI=\"\">", "<Reference URI=\"#x\">", 1),
            EsignError::Profile("reference URI"),
        ),
        (
            text.replacen(
                "#enveloped-signature\"/>",
                "#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/TR/1999/REC-xpath-19991116\"/>",
                1,
            ),
            EsignError::Profile("transforms"),
        ),
        (
            text.replacen(
                "REC-xml-c14n-20010315\"/>",
                "REC-xml-c14n-20010315#WithComments\"/>",
                1,
            ),
            EsignError::Profile("canonicalization method"),
        ),
        (
            text.replacen("xmldsig-more#rsa-sha256", "xmldsig#rsa-sha1", 1),
            EsignError::Profile("signature method"),
        ),
        (
            text.replacen("xmlenc#sha256", "xmldsig#sha1", 1),
            EsignError::Profile("reference children"),
        ),
        (
            text.replacen("<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">", "<Signature xmlns=\"urn:not-dsig\">", 1),
            EsignError::Profile("signature not last in the root"),
        ),
    ];
    for (i, (bytes, want)) in cases.into_iter().enumerate() {
        assert_eq!(refused(bytes.as_bytes(), cert), want, "case {i}");
    }
}

#[test]
fn dtd_entity_and_oversize_answers_are_refused_before_any_check() {
    let (file, cert) = SIGNED[0];
    let text = String::from_utf8(fixture(file)).unwrap();
    let dtd = text.replacen(
        "<EsignResp",
        "<!DOCTYPE EsignResp [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><EsignResp",
        1,
    );
    assert!(
        matches!(refused(dtd.as_bytes(), cert), EsignError::Xml(e) if e.code() == "CS-XML-0005")
    );
    let entity = text.replacen("RC-2026-0001", "&x;", 1);
    assert!(
        matches!(refused(entity.as_bytes(), cert), EsignError::Xml(e) if e.code() == "CS-XML-0004")
    );
    let big = text.replacen(
        "<Signatures>",
        &format!("<Pad>{}</Pad><Signatures>", "A".repeat(512 * 1024)),
        1,
    );
    assert!(
        matches!(refused(big.as_bytes(), cert), EsignError::Xml(e) if e.code() == "CS-XML-0001")
    );
    let latin = text.replacen("UTF-8", "ISO-8859-1", 1);
    assert!(
        matches!(refused(latin.as_bytes(), cert), EsignError::Xml(e) if e.code() == "CS-XML-0006")
    );
}

fn rsa_key() -> (RsaKeyPair, Vec<u8>) {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["asp.test".into()])
        .unwrap()
        .self_signed(&kp)
        .unwrap();
    (
        RsaKeyPair::from_pkcs8(&kp.serialize_der()).unwrap(),
        cert.der().to_vec(),
    )
}

fn p256_key() -> (EcdsaKeyPair, Vec<u8>) {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["asp.test".into()])
        .unwrap()
        .self_signed(&kp)
        .unwrap();
    (
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &kp.serialize_der()).unwrap(),
        cert.der().to_vec(),
    )
}

fn request(hash: &[u8; 32]) -> Request<'_> {
    Request {
        asp_id: "ASP-OPENSEAL-TEST",
        txn: "0192f3a4-0000-7000-8000-0000000000aa",
        unix_time: 1_795_286_707,
        auth_mode: AuthMode::Otp,
        response_url: "https://sign.example.test/rsp/esign/test-esp/response",
        sha256: hash,
        doc_info: "Lease <agreement> & schedule \"A\"",
    }
}

/// Our signed requests, RSA and P-256, as keyd would sign them (a digest in).
fn signed_requests() -> Vec<(&'static str, String, Vec<u8>)> {
    let hash = [0x5au8; 32];
    let (rsa, rsa_cert) = rsa_key();
    let rsa_signed = request(&hash)
        .signed(Algorithm::RsaSha256, Some(&rsa_cert), &mut |d| {
            let d = Digest::import_less_safe(d, &SHA256).unwrap();
            let mut out = vec![0; rsa.public_modulus_len()];
            rsa.sign_digest(&aws_lc_rs::signature::RSA_PKCS1_SHA256, &d, &mut out)
                .unwrap();
            Ok(out)
        })
        .unwrap();
    let (ec, ec_cert) = p256_key();
    let ec_signed = request(&hash)
        .signed(Algorithm::EcdsaP256Sha256, None, &mut |d| {
            let d = Digest::import_less_safe(d, &SHA256).unwrap();
            Ok(ec.sign_digest(&d).unwrap().as_ref().to_vec())
        })
        .unwrap();
    vec![("rsa", rsa_signed, rsa_cert), ("p256", ec_signed, ec_cert)]
}

#[test]
fn our_signed_requests_verify_under_our_profile() {
    for (name, xml, cert) in signed_requests() {
        let k = VerifyingKey::from_certificate(&cert).unwrap();
        read_verified(xml.as_bytes(), &k).unwrap_or_else(|e| panic!("{name}: {e}"));
        let tampered = xml.replacen("ASP-OPENSEAL-TEST", "ASP-OPENSEAL-TESU", 1);
        assert_eq!(
            read_verified(tampered.as_bytes(), &k).unwrap_err(),
            EsignError::DigestMismatch
        );
    }
}

/// xmlsec1 as a command: on the path, or in the container image named by
/// `OPENSEAL_XMLSEC1_IMAGE` with `dir` mounted at /w.
fn xmlsec1(dir: &Path, args: &[&str]) -> Option<std::process::Output> {
    if let Ok(image) = std::env::var("OPENSEAL_XMLSEC1_IMAGE") {
        let mount = format!("{}:/w", dir.display());
        let mut c = Command::new("docker");
        c.args(["run", "--rm", "-v", &mount, "-w", "/w", &image, "xmlsec1"]);
        c.args(args);
        return c.output().ok();
    }
    Command::new("xmlsec1")
        .current_dir(dir)
        .args(args)
        .output()
        .ok()
}

#[test]
fn our_signed_requests_verify_under_xmlsec1() {
    let dir = std::env::temp_dir().join(format!("openseal-xmlsec-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut ran = false;
    for (name, xml, cert) in signed_requests() {
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64_lines(&cert)
        );
        std::fs::write(dir.join(format!("{name}.xml")), &xml).unwrap();
        std::fs::write(dir.join(format!("{name}.pem")), pem).unwrap();
        let bad = xml.replacen("ASP-OPENSEAL-TEST", "ASP-OPENSEAL-TESU", 1);
        std::fs::write(dir.join(format!("{name}-bad.xml")), bad).unwrap();
        let cert_arg = format!("{name}.pem");
        let Some(ok) = xmlsec1(
            &dir,
            &[
                "--verify",
                "--pubkey-cert-pem",
                &cert_arg,
                &format!("{name}.xml"),
            ],
        ) else {
            continue;
        };
        ran = true;
        assert!(
            ok.status.success(),
            "{name}: xmlsec1 refused our request: {}",
            String::from_utf8_lossy(&ok.stderr)
        );
        let bad = xmlsec1(
            &dir,
            &[
                "--verify",
                "--pubkey-cert-pem",
                &cert_arg,
                &format!("{name}-bad.xml"),
            ],
        )
        .unwrap();
        assert!(
            !bad.status.success(),
            "{name}: xmlsec1 took a tampered request"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
    if !ran {
        assert!(
            std::env::var("OPENSEAL_REQUIRE_XMLSEC1").as_deref() != Ok("1"),
            "xmlsec1 is required here (OPENSEAL_REQUIRE_XMLSEC1) and could not be run"
        );
        eprintln!("xmlsec1 not available: the independent check runs on CI");
    }
}

fn base64_lines(der: &[u8]) -> String {
    use base64::Engine as _;
    let b = base64::engine::general_purpose::STANDARD.encode(der);
    b.as_bytes()
        .chunks(64)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("\n")
}
