//! A provider's own CMS (ADR-047 §3.2 to §3.4, `RSP-02` acceptance (2) and (3)):
//! `prepare_for_cms` lays out the revision and gives the SHA-256 ByteRange digest the
//! ESP signs; `complete_cms` embeds the ESP's `PKCS7pdf` answer, CAdES-like under
//! `ETSI.CAdES.detached` or Adobe-like (`signingTime`, no ESS) under
//! `adbe.pkcs7.detached`, keeps the ESP's time-stamp or adds ours, and refuses a BER
//! CMS, one over other bytes, by another certificate, a non-CAdES CMS for a CAdES
//! revision, and one too large for the placeholder. The "ESP" is the test key, its CMS
//! assembled around attributes written here.
// Test code: a panic is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use casual_sign_crypto::cms::{external_signature, signed_attributes_der};
use casual_sign_crypto::tsp::{TimestampRequest, verify_timestamp_response};
use casual_sign_crypto::{DigestAlgorithm, KeyProvider};
use casual_sign_seal::{
    CmsFormat, CompleteOptions, Limits, PreparedForCms, Profile, RemoteProblem, SealError,
    SealRequest, TimestampSource, complete_cms, prepare_for_cms,
};
use casual_sign_verify::{Indication, VerifyOptions, verify};
use common::*;

fn request(profile: Profile) -> SealRequest {
    let mut r = SealRequest::new(profile, "Remote_esign", SIGNING_TIME);
    r.name = Some("eSign signer".into());
    r.trust = trust();
    r
}

fn options() -> CompleteOptions {
    CompleteOptions {
        trust: trust(),
        limits: Limits::default(),
    }
}

/// Adobe-like signed attributes: content-type, signingTime, message-digest (no ESS), in
/// DER set order.
fn adobe_attributes(digest: &[u8]) -> Vec<u8> {
    let mut ct = hex("30180609 2a864886f70d010903 310b0609 2a864886f70d010701");
    let mut st = hex("301c0609 2a864886f70d010905 310f170d");
    st.extend_from_slice(b"261121000000Z");
    let mut md = hex("302f0609 2a864886f70d010904 31220420");
    md.extend_from_slice(digest);
    let mut body = Vec::new();
    body.append(&mut ct);
    body.append(&mut st);
    body.append(&mut md);
    let mut set = vec![0x31, body.len() as u8];
    set.extend(body);
    set
}

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// The ESP: sign `attrs` with `key` and assemble its CMS, with a time-stamp token if
/// given.
fn esp_cms(key: &TestProvider, attrs: &[u8], token: Option<&[u8]>) -> Vec<u8> {
    let value = key.sign(attrs).unwrap().as_bytes().to_vec();
    external_signature(key.certificate_chain(), key.algorithm(), attrs, &value)
        .unwrap()
        .to_der(token)
        .unwrap()
}

fn cades_cms(key: &TestProvider, p: &PreparedForCms) -> Vec<u8> {
    let d = DigestAlgorithm::Sha256.digest(&[]);
    let _ = d;
    let digest =
        casual_sign_crypto::DigestValue::from_bytes(DigestAlgorithm::Sha256, &p.byte_range_digest)
            .unwrap();
    let attrs = signed_attributes_der(&key.certificate_chain()[0], &digest).unwrap();
    esp_cms(key, &attrs, None)
}

fn leaf_der(key: &TestProvider) -> Vec<u8> {
    der_of(&key.certificate_chain()[0])
}

fn prepared(format: CmsFormat, placeholder: usize) -> PreparedForCms {
    prepare_for_cms(
        &one_page("Agreement"),
        &request(Profile::BaselineLt),
        format,
        placeholder,
    )
    .unwrap()
}

fn indications(bytes: &[u8]) -> Vec<Indication> {
    let report = verify(bytes, &trust(), &VerifyOptions::at(VALIDATION_TIME));
    assert!(report.error.is_none(), "{:?}", report.error);
    report.signatures.iter().map(|s| s.indication).collect()
}

#[test]
fn the_hash_sent_is_the_byte_range_digest_of_the_prepared_bytes() {
    let p = prepared(CmsFormat::Cades, 16 * 1024);
    let [_, a, b, c] = p.byte_range;
    let (a, b, c) = (a as usize, b as usize, c as usize);
    assert_eq!(b + c, p.bytes.len());
    let mut h = casual_sign_crypto::Hasher::new(DigestAlgorithm::Sha256);
    h.update(&p.bytes[..a]);
    h.update(&p.bytes[b..]);
    assert_eq!(h.finish().as_bytes(), p.byte_range_digest.as_slice());
    assert_eq!(count(&p.bytes, b"/ETSI.CAdES.detached"), 1);
    let q = prepared(CmsFormat::Pkcs7, 16 * 1024);
    assert_eq!(count(&q.bytes, b"/adbe.pkcs7.detached"), 1);
}

#[test]
fn a_cades_like_cms_completes_under_etsi_cades_with_our_time_stamp_and_the_dss() {
    for key in [p256(), rsa()] {
        let p = prepared(CmsFormat::Cades, 24 * 1024);
        let tsa = TestTsa::new(SIGNING_TIME);
        let rev = TestRevocation::default();
        let (s, found) = complete_cms(
            &p,
            &cades_cms(&key, &p),
            &leaf_der(&key),
            &tsa,
            &rev,
            &options(),
        )
        .unwrap();
        assert!(found.cades && !found.provider_timestamp);
        assert!(s.report.signature_timestamp.is_some(), "ours added");
        assert!(s.report.dss.is_some());
        let a = p.byte_range[1] as usize;
        assert_eq!(
            &s.bytes[..a],
            &p.bytes[..a],
            "embedded into the prepared bytes"
        );
        assert_eq!(indications(&s.bytes), vec![Indication::TotalPassed]);
    }
}

#[test]
fn an_adobe_like_cms_completes_under_adbe_pkcs7_detached_and_verifies() {
    let key = rsa();
    let p = prepared(CmsFormat::Pkcs7, 24 * 1024);
    let cms = esp_cms(&key, &adobe_attributes(&p.byte_range_digest), None);
    let tsa = TestTsa::new(SIGNING_TIME);
    let (s, found) = complete_cms(
        &p,
        &cms,
        &leaf_der(&key),
        &tsa,
        &TestRevocation::default(),
        &options(),
    )
    .unwrap();
    assert!(!found.cades);
    assert_eq!(count(&s.bytes, b"/adbe.pkcs7.detached"), 1);
    assert_eq!(indications(&s.bytes), vec![Indication::TotalPassed]);
}

#[test]
fn a_time_stamp_the_esp_carries_is_kept() {
    let key = p256();
    let p = prepared(CmsFormat::Cades, 24 * 1024);
    let tsa = TestTsa::new(SIGNING_TIME);
    let digest =
        casual_sign_crypto::DigestValue::from_bytes(DigestAlgorithm::Sha256, &p.byte_range_digest)
            .unwrap();
    let attrs = signed_attributes_der(&key.certificate_chain()[0], &digest).unwrap();
    let value = key.sign(&attrs).unwrap().as_bytes().to_vec();
    let signed =
        external_signature(key.certificate_chain(), key.algorithm(), &attrs, &value).unwrap();
    let imprint = DigestAlgorithm::Sha256.digest(signed.signature_value());
    let req = TimestampRequest::new(&imprint, &tsa.nonce()).unwrap();
    let resp = tsa.timestamp(req.as_der()).unwrap();
    let token = verify_timestamp_response(&resp, &req).unwrap();
    let cms = signed.to_der(Some(token.as_der())).unwrap();
    let calls_before = tsa.calls.get();
    let (s, found) = complete_cms(
        &p,
        &cms,
        &leaf_der(&key),
        &tsa,
        &TestRevocation::default(),
        &options(),
    )
    .unwrap();
    assert!(found.provider_timestamp);
    assert_eq!(tsa.calls.get(), calls_before, "no time-stamp of ours");
    assert_eq!(indications(&s.bytes), vec![Indication::TotalPassed]);
}

fn refused(p: &PreparedForCms, cms: &[u8], signer: &[u8]) -> SealError {
    complete_cms(
        p,
        cms,
        signer,
        &TestTsa::new(SIGNING_TIME),
        &TestRevocation::default(),
        &options(),
    )
    .unwrap_err()
}

#[test]
fn a_cms_over_other_bytes_by_another_signer_ber_or_not_cades_is_refused() {
    let key = rsa();
    let p = prepared(CmsFormat::Cades, 24 * 1024);
    let good = cades_cms(&key, &p);
    // Other bytes: the CMS of another preparation.
    let other = prepare_for_cms(
        &one_page("Another agreement"),
        &request(Profile::BaselineLt),
        CmsFormat::Cades,
        24 * 1024,
    )
    .unwrap();
    assert_eq!(
        refused(&p, &cades_cms(&key, &other), &leaf_der(&key)),
        SealError::Remote(RemoteProblem::MessageDigest)
    );
    // Another certificate than UserX509Certificate.
    assert_eq!(
        refused(&p, &good, &leaf_der(&p256())),
        SealError::Remote(RemoteProblem::Certificate)
    );
    // BER: the same CMS with an indefinite outer length.
    let mut ber = vec![0x30, 0x80];
    let header = if good[1] == 0x82 { 4 } else { 3 };
    ber.extend_from_slice(&good[header..]);
    ber.extend_from_slice(&[0, 0]);
    assert_eq!(
        refused(&p, &ber, &leaf_der(&key)),
        SealError::Remote(RemoteProblem::Ber)
    );
    // Adobe-like attributes for a revision prepared as CAdES.
    let adobe = esp_cms(&key, &adobe_attributes(&p.byte_range_digest), None);
    assert_eq!(
        refused(&p, &adobe, &leaf_der(&key)),
        SealError::Remote(RemoteProblem::Format)
    );
    // A signature value that does not verify.
    let mut broken = good.clone();
    let n = broken.len();
    broken[n - 5] ^= 0x01;
    assert_eq!(
        refused(&p, &broken, &leaf_der(&key)),
        SealError::Remote(RemoteProblem::Cms)
    );
    // The prepared bytes altered after the hash was sent.
    let mut altered = p.clone();
    altered.bytes[10] ^= 0x01;
    assert_eq!(
        refused(&altered, &good, &leaf_der(&key)),
        SealError::Remote(RemoteProblem::PreparedAltered)
    );
}

#[test]
fn a_cms_larger_than_the_placeholder_is_refused_never_re_laid_out() {
    let key = rsa();
    let p = prepared(CmsFormat::Cades, 2 * 1024);
    let e = refused(&p, &cades_cms(&key, &p), &leaf_der(&key));
    assert_eq!(e.code(), "CS-RSP-0005", "{e:?}");
}
