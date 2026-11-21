//! The answer reader's own checks, on answers signed for the test (the signature itself
//! is xmlsec.rs's subject): what a signed answer must hold before any value is used.
// Test code: a panic is the failure report (CLAUDE.md).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use aws_lc_rs::digest::{Digest, SHA256};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
use casual_sign_esign::dsig::sign_enveloped;
use casual_sign_esign::{Algorithm, EsignError, Status, VerifyingKey, response};

struct Esp {
    key: EcdsaKeyPair,
    verifying: VerifyingKey,
}

fn esp() -> Esp {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["esp.test".into()])
        .unwrap()
        .self_signed(&kp)
        .unwrap();
    Esp {
        key: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &kp.serialize_der())
            .unwrap(),
        verifying: VerifyingKey::from_certificate(cert.der()).unwrap(),
    }
}

impl Esp {
    fn answer(&self, body: &str) -> Vec<u8> {
        sign_enveloped(body, Algorithm::EcdsaP256Sha256, None, &mut |d| {
            let d = Digest::import_less_safe(d, &SHA256).unwrap();
            Ok(self.key.sign_digest(&d).unwrap().as_ref().to_vec())
        })
        .unwrap()
        .into_bytes()
    }

    fn read(&self, body: &str) -> Result<response::Response, EsignError> {
        response::read(&self.answer(body), &self.verifying)
    }
}

const CERT: &str = "<UserX509Certificate>QUJD</UserX509Certificate>";

fn sigs(n: usize) -> String {
    (1..=n)
        .map(|i| format!("<DocSignature id=\"{i}\" sigHashAlgorithm=\"SHA256\" error=\"\">QUJD</DocSignature>"))
        .collect()
}

#[test]
fn a_failed_answer_carries_its_code_and_never_its_message() {
    let e = esp();
    let r = e
        .read("<EsignResp status=\"0\" txn=\"t1\" ts=\"x\" resCode=\"R1\" errCode=\"ESP-944\" errMsg=\"Ann &amp; her Aadhaar\"></EsignResp>")
        .unwrap();
    assert_eq!(r.status, Status::Failed);
    assert_eq!(r.err_code.as_deref(), Some("ESP-944"));
    assert!(!format!("{r:?}").contains("Aadhaar"));
    assert_eq!(
        e.read("<EsignResp status=\"0\" txn=\"t1\" errCode=\"NA\"></EsignResp>")
            .unwrap_err(),
        EsignError::Response("errCode")
    );
}

#[test]
fn a_signed_answer_needs_a_certificate_and_a_signature() {
    let e = esp();
    let ok = e
        .read(&format!(
            "<EsignResp status=\"1\" txn=\"t1\" resCode=\"R1\" errCode=\"NA\">{CERT}<Signatures>{}</Signatures></EsignResp>",
            sigs(1)
        ))
        .unwrap();
    assert_eq!(ok.signatures[0].value, b"ABC");
    assert_eq!(
        e.read(&format!(
            "<EsignResp status=\"1\" txn=\"t1\"><Signatures>{}</Signatures></EsignResp>",
            sigs(1)
        ))
        .unwrap_err(),
        EsignError::Response("signed without a signature")
    );
    assert_eq!(
        e.read(&format!(
            "<EsignResp status=\"1\" txn=\"t1\">{CERT}</EsignResp>"
        ))
        .unwrap_err(),
        EsignError::Response("signed without a signature")
    );
}

#[test]
fn out_of_bounds_or_malformed_members_are_refused() {
    let e = esp();
    let wrap = |inner: &str| format!("<EsignResp status=\"1\" txn=\"t1\">{inner}</EsignResp>");
    for (body, want) in [
        (
            wrap(&format!("{CERT}<Signatures>{}</Signatures>", sigs(6))),
            "too many signatures",
        ),
        (
            wrap(&format!(
                "{CERT}<Signatures>{}{}</Signatures>",
                sigs(1),
                sigs(1)
            )),
            "signature id",
        ),
        (
            wrap(&format!("{CERT}{CERT}<Signatures>{}</Signatures>", sigs(1))),
            "repeated element",
        ),
        (
            wrap(&format!(
                "<UserX509Certificate>{}</UserX509Certificate><Signatures>{}</Signatures>",
                "QUJD".repeat(4097),
                sigs(1)
            )),
            "certificate",
        ),
        (
            wrap(&format!(
                "<UserX509Certificate>not base64!</UserX509Certificate><Signatures>{}</Signatures>",
                sigs(1)
            )),
            "certificate",
        ),
        (
            "<EsignResp status=\"1\" txn=\"t1&quot;x\"></EsignResp>".to_owned(),
            "attribute form",
        ),
        (
            "<EsignResp status=\"3\" txn=\"t1\"></EsignResp>".to_owned(),
            "status",
        ),
        ("<EsignResp status=\"1\"></EsignResp>".to_owned(), "txn"),
        ("<Other status=\"1\" txn=\"t1\"></Other>".to_owned(), "root"),
        (
            "<EsignResp xmlns=\"urn:x\" status=\"1\" txn=\"t1\"></EsignResp>".to_owned(),
            "root namespace",
        ),
    ] {
        assert_eq!(
            e.read(&body).unwrap_err(),
            EsignError::Response(want),
            "{want}"
        );
    }
}

#[test]
fn a_document_the_signer_rejected_has_its_error_and_no_value() {
    let e = esp();
    let r = e
        .read(&format!(
            "<EsignResp status=\"1\" txn=\"t1\">{CERT}<Signatures>{}<DocSignature id=\"2\" error=\"User Rejected\"/></Signatures></EsignResp>",
            sigs(1)
        ))
        .unwrap();
    assert_eq!(r.signatures[1].error.as_deref(), Some("User Rejected"));
    assert!(r.signatures[1].value.is_empty());
}
