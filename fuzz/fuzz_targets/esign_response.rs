//! Bytes into the India eSign answer reader (`casual-sign-esign`, ADR-047 §3.4, §3.5):
//! the bounded reader, the XML Signature profile, canonicalization and the answer's
//! members. Any panic or hang is a finding. Seeds: the xmlsec1-signed answers in
//! `server/casual-sign-esign/tests/fixtures` (run with that directory as the corpus).
//! A read answer must keep the bounds docs/21 sets.
#![no_main]

use casual_sign_esign::response::{self, MAX_DOC_SIGNATURES};
use casual_sign_esign::VerifyingKey;
use libfuzzer_sys::fuzz_target;

static ESP: &[u8] = include_bytes!("../../server/casual-sign-esign/tests/fixtures/esp-rsa.der");

fuzz_target!(|data: &[u8]| {
    let key = VerifyingKey::from_certificate(ESP).expect("the fixture certificate");
    if let Ok(r) = response::read(data, &key) {
        assert!(r.signatures.len() <= MAX_DOC_SIGNATURES);
        assert!(r.txn.len() <= 64);
    }
    // The canonicalization alone, on whatever the reader takes.
    if let Ok(dom) = casual_sign_xml::parse(data, &casual_sign_xml::Limits::esign(), &|| false)
        && let Some(root) = dom.root()
    {
        for m in [
            casual_sign_esign::c14n::Method::Inclusive,
            casual_sign_esign::c14n::Method::Exclusive,
        ] {
            let _ = casual_sign_esign::c14n::canonicalize(&dom, root, m, None);
        }
    }
});
