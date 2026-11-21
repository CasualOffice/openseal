//! The CI stub ESP's own answer (`tools/e2e/auth_stubs.py esign`, `RSP-02`) through
//! `complete_cms`: the CMS the stub builds by hand with `openssl` must be one our engine
//! embeds, as the real stack's worker does. `fixtures/esign-stub/` holds an answer the
//! stub made for the digest of the revision this test prepares
//! (`tools/e2e/make_esign_fixture.py`), with the stub's root.
// Test code: a panic is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use core::time::Duration;
use std::path::PathBuf;

use casual_sign_seal::{
    CmsFormat, CompleteOptions, Limits, NoRevocation, Profile, SealRequest, complete_cms,
    prepare_for_cms,
};
use casual_sign_verify::{Indication, VerifyOptions, verify};
use common::*;

fn fixture(name: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/esign-stub")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn prepared(format: CmsFormat) -> casual_sign_seal::PreparedForCms {
    // B-T, as the worker prepares (B-LT adds only the DSS): the signing time is before the
    // ESP issues the one-time certificate, which exists only once the signer
    // authenticated at the ESP; the time-stamp comes after.
    let mut r = SealRequest::new(Profile::BaselineT, "Remote_esign", SIGNING_TIME);
    r.name = Some("eSign signer".into());
    prepare_for_cms(&one_page("Agreement"), &r, format, 24 * 1024).unwrap()
}

/// The certificate's `notBefore`, since the Unix epoch.
fn not_before(der: &[u8]) -> Duration {
    use cms::cert::x509::der::Decode as _;
    let c = cms::cert::x509::Certificate::from_der(der).unwrap();
    c.tbs_certificate().validity().not_before.to_unix_duration()
}

/// The digests the fixture's answers must be made for:
/// `OPENSEAL_PRINT_ESIGN_DIGESTS=1 cargo test -p casual-sign-seal --test remote_cms_stub`.
#[test]
fn print_the_digests_when_asked() {
    if std::env::var("OPENSEAL_PRINT_ESIGN_DIGESTS").is_ok() {
        for (v, f) in [("cades", CmsFormat::Cades), ("adobe", CmsFormat::Pkcs7)] {
            println!("{v} {}", hex(&prepared(f).byte_range_digest));
        }
    }
}

#[test]
fn the_stub_esps_cms_is_embedded_and_verifies() {
    let mut trust = common::trust();
    trust.add_anchor(&fixture("root.der")).unwrap();
    let options = CompleteOptions {
        trust: trust.clone(),
        limits: Limits::default(),
    };
    for (variant, format) in [("cades", CmsFormat::Cades), ("adobe", CmsFormat::Pkcs7)] {
        let p = prepared(format);
        let want = String::from_utf8(fixture(&format!("{variant}.digest.hex"))).unwrap();
        assert_eq!(
            hex(&p.byte_range_digest),
            want.trim(),
            "{variant}: the fixture was made for another revision: regenerate it"
        );
        let cms = fixture(&format!("{variant}.cms"));
        let user = fixture(&format!("{variant}.user.der"));
        // Our time-stamp a minute after the ESP issued the certificate.
        let issued = not_before(&user);
        assert!(
            issued > SIGNING_TIME,
            "the certificate is born after the preparation"
        );
        let tsa = TestTsa::new(issued + Duration::from_secs(60));
        let (s, found) = complete_cms(&p, &cms, &user, &tsa, &NoRevocation, &options)
            .unwrap_or_else(|e| panic!("{variant}: {e:?}"));
        assert_eq!(found.cades, variant == "cades");
        let report = verify(
            &s.bytes,
            &trust,
            &VerifyOptions::at(issued + Duration::from_secs(120)),
        );
        assert!(
            report
                .signatures
                .iter()
                .all(|x| !matches!(x.indication, Indication::TotalFailed(_))),
            "{variant}: {:?}",
            report.signatures
        );
    }
}
