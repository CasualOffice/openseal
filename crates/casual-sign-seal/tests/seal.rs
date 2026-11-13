//! Sealing at every PAdES baseline level, checked by our verifier here and by pyHanko
//! and EU DSS over `fixtures/sealed` (rule 26; `tools/verify-sealed.py`).
// Test code: a panic is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use casual_sign_seal::{
    Appearance, ArchiveOptions, CheckName, DocMdp, Limits, NoRevocation, NoTimestamps, Profile,
    Rect, RequestProblem, RevocationProblem, SealError, SealKind, SealRequest, Visible, augment,
    renew_lta, seal, vri_key,
};
use casual_sign_verify::{Indication, SignatureKind, SubIndication, VerifyOptions, verify};
use common::*;

fn request(profile: Profile) -> SealRequest {
    let mut r = SealRequest::new(profile, "Seal1", SIGNING_TIME);
    r.name = Some("OpenSeal test platform".into());
    r.reason = Some("Agreement completed".into());
    r.trust = trust();
    r
}

fn ours(bytes: &[u8]) -> Vec<(SignatureKind, Indication)> {
    let report = verify(bytes, &trust(), &VerifyOptions::at(VALIDATION_TIME));
    assert!(report.error.is_none());
    report
        .signatures
        .iter()
        .map(|s| (s.kind, s.indication))
        .collect()
}

fn passed(bytes: &[u8]) -> bool {
    ours(bytes)
        .iter()
        .all(|(_, i)| *i == Indication::TotalPassed)
}

#[test]
fn b_b_is_intact_and_waits_for_revocation_data() {
    let input = one_page("Agreement");
    let s = seal(
        &input,
        &request(Profile::BaselineB),
        &p256(),
        &NoTimestamps,
        &NoRevocation,
    )
    .unwrap();
    assert!(s.bytes.starts_with(&input), "the input is a prefix");
    let v = ours(&s.bytes);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].0, SignatureKind::Approval);
    match v[0].1 {
        Indication::Indeterminate(r) => assert_eq!(r.sub, SubIndication::TryLater),
        other => panic!("{other:?}"),
    }
    let sig = s.report.signature.unwrap();
    assert_eq!(sig.attempts, 1);
    assert!(sig.der_len <= sig.placeholder_len);
    assert_eq!(sig.byte_range[0], 0);
    assert_eq!(
        sig.byte_range[2] + sig.byte_range[3],
        s.bytes.len() as u64,
        "the second range reaches the end"
    );
    // /M from the supplied time; no CMS signingTime (the crypto crate writes none).
    assert_eq!(count(&s.bytes, b"/M (D:20261101120000+00'00')"), 1);
    assert_eq!(count(&s.bytes, b"/SubFilter /ETSI.CAdES.detached"), 1);
    assert_eq!(count(&s.bytes, b"/Filter /Adobe.PPKLite"), 1);
    // An invisible widget has no appearance stream: a new one reads as form filling,
    // which DocMDP P=1 forbids (pyHanko).
    assert_eq!(count(&s.bytes, b"/AP "), 0);
    assert_eq!(count(&s.bytes, b"/Rect [0 0 0 0]"), 1);
}

#[test]
fn every_profile_and_key_verifies() {
    for (label, provider) in [("p256", p256()), ("rsa", rsa())] {
        for profile in [
            Profile::BaselineT,
            Profile::BaselineLt,
            Profile::BaselineLta,
        ] {
            let tsa = TestTsa::new(SIGNING_TIME);
            let input = one_page("Agreement");
            let s = seal(
                &input,
                &request(profile),
                &provider,
                &tsa,
                &TestRevocation::default(),
            )
            .unwrap_or_else(|e| panic!("{label} {profile:?}: {e}"));
            assert!(s.bytes.starts_with(&input));
            assert!(s.report.signature_timestamp.is_some());
            let v = ours(&s.bytes);
            if profile == Profile::BaselineT {
                assert!(matches!(
                    v[0].1,
                    Indication::Indeterminate(r) if r.sub == SubIndication::TryLater
                ));
            } else {
                assert!(passed(&s.bytes), "{label} {profile:?}: {v:?}");
                let dss = s.report.dss.as_ref().unwrap();
                assert_eq!(dss.vri_keys, vec![s.report.vri_key.clone().unwrap()]);
                assert!(dss.ocsp_responses >= 2, "signer and TSA by OCSP");
                assert!(dss.crls >= 1, "intermediate by CRL");
            }
            if profile == Profile::BaselineLta {
                assert_eq!(v.len(), 2);
                assert_eq!(v[1].0, SignatureKind::DocumentTimestamp);
                assert_eq!(s.report.revisions_added, 3);
            }
        }
    }
}

#[test]
fn rsa_seals_are_deterministic() {
    // RSA PKCS#1 v1.5 is deterministic, so the same request gives the same bytes.
    let input = one_page("Agreement");
    let a = seal(
        &input,
        &request(Profile::BaselineB),
        &rsa(),
        &NoTimestamps,
        &NoRevocation,
    )
    .unwrap();
    let b = seal(
        &input,
        &request(Profile::BaselineB),
        &rsa(),
        &NoTimestamps,
        &NoRevocation,
    )
    .unwrap();
    assert_eq!(a.bytes, b.bytes);
}

#[test]
fn certification_levels_carry_docmdp() {
    for (docmdp, p) in [(DocMdp::P1, 1u8), (DocMdp::P2, 2), (DocMdp::P3, 3)] {
        let mut r = request(Profile::BaselineLt);
        r.kind = SealKind::Certification { docmdp };
        let tsa = TestTsa::new(SIGNING_TIME);
        let s = seal(
            &one_page("Agreement"),
            &r,
            &p256(),
            &tsa,
            &TestRevocation::default(),
        )
        .unwrap();
        let v = ours(&s.bytes);
        assert_eq!(v[0].0, SignatureKind::Certification { permissions: p });
        assert!(passed(&s.bytes));
        assert_eq!(count(&s.bytes, b"/TransformMethod /DocMDP"), 1);
        // The catalog carries /Perms in the signature revision and keeps it in the DSS one.
        assert_eq!(count(&s.bytes, b"/Perms <</DocMDP "), 2);
        assert_eq!(
            count(&s.bytes, format!("/P {p}/V /1.2").as_bytes()),
            1,
            "TransformParams /P"
        );
    }
}

#[test]
fn certification_must_be_first() {
    let first = seal(
        &one_page("Agreement"),
        &request(Profile::BaselineB),
        &p256(),
        &NoTimestamps,
        &NoRevocation,
    )
    .unwrap();
    let mut r = request(Profile::BaselineB);
    r.field_name = "Seal2".into();
    r.kind = SealKind::Certification { docmdp: DocMdp::P2 };
    let e = seal(&first.bytes, &r, &p256(), &NoTimestamps, &NoRevocation).unwrap_err();
    assert_eq!(e, SealError::Request(RequestProblem::CertificationNotFirst));
    assert_eq!(e.code(), "CS-SEAL-0006");
}

#[test]
fn p1_forbids_a_second_signature_but_not_the_dss() {
    let mut r = request(Profile::BaselineLt);
    r.kind = SealKind::Certification { docmdp: DocMdp::P1 };
    let tsa = TestTsa::new(SIGNING_TIME);
    let s = seal(
        &one_page("Agreement"),
        &r,
        &p256(),
        &tsa,
        &TestRevocation::default(),
    )
    .unwrap();
    let mut r2 = request(Profile::BaselineB);
    r2.field_name = "Seal2".into();
    let e = seal(&s.bytes, &r2, &p256(), &NoTimestamps, &NoRevocation).unwrap_err();
    assert_eq!(e.code(), "CS-WRT-0004");
}

#[test]
fn two_sequential_signatures_both_pass() {
    let tsa = TestTsa::new(SIGNING_TIME);
    let rev = TestRevocation::default();
    let mut r = request(Profile::BaselineLt);
    r.kind = SealKind::Certification { docmdp: DocMdp::P2 };
    let first = seal(&one_page("Agreement"), &r, &p256(), &tsa, &rev).unwrap();
    let mut r2 = request(Profile::BaselineLt);
    r2.field_name = "Seal2".into();
    let second = seal(&first.bytes, &r2, &rsa(), &tsa, &rev).unwrap();
    assert!(second.bytes.starts_with(&first.bytes));
    let v = ours(&second.bytes);
    assert_eq!(v.len(), 2);
    assert!(passed(&second.bytes), "{v:?}");
    assert_eq!(v[0].0, SignatureKind::Certification { permissions: 2 });
    assert_eq!(v[1].0, SignatureKind::Approval);
    // The second DSS keeps the first's entries and adds a VRI key.
    assert_eq!(count(&second.bytes, b"/VRI <<"), 2);
}

#[test]
fn visible_and_existing_fields() {
    let tsa = TestTsa::new(SIGNING_TIME);
    let rev = TestRevocation::default();
    let mut r = request(Profile::BaselineLt);
    r.visible = Some(Visible {
        page: 0,
        rect: Rect {
            llx: 72.0,
            lly: 300.0,
            urx: 272.0,
            ury: 350.0,
        },
        appearance: Appearance::Border,
    });
    let s = seal(&one_page("Agreement"), &r, &p256(), &tsa, &rev).unwrap();
    assert!(passed(&s.bytes));
    assert_eq!(count(&s.bytes, b"/Rect [72 300 272 350]"), 1);
    assert_eq!(count(&s.bytes, b"re S Q"), 1);

    // Into the form's existing, empty signature field, with a custom appearance.
    let mut r = request(Profile::BaselineLt);
    r.field_name = "Signer1".into();
    r.visible = Some(Visible {
        page: 0,
        rect: Rect {
            llx: 0.0,
            lly: 0.0,
            urx: 0.0,
            ury: 0.0,
        },
        appearance: Appearance::Content {
            content: b"0 0 1 rg 0 0 200 50 re f".to_vec(),
            resources: None,
        },
    });
    let input = form_pdf();
    let s = seal(&input, &r, &p256(), &tsa, &rev).unwrap();
    assert!(s.bytes.starts_with(&input));
    assert!(passed(&s.bytes));
    assert_eq!(
        count(&s.bytes, b"/T (Signer1)"),
        2,
        "field replaced, not added"
    );

    // Not a signature field.
    r.field_name = "Name".into();
    assert_eq!(
        seal(&input, &r, &p256(), &tsa, &rev).unwrap_err(),
        SealError::Request(RequestProblem::FieldNotSignature)
    );
    // Already signed.
    r.field_name = "Signer1".into();
    assert_eq!(
        seal(&s.bytes, &r, &p256(), &tsa, &rev).unwrap_err(),
        SealError::Request(RequestProblem::FieldAlreadySigned)
    );
}

#[test]
fn request_problems_are_refused() {
    let input = one_page("Agreement");
    let mut r = request(Profile::BaselineB);
    r.field_name = "a.b".into();
    assert_eq!(
        seal(&input, &r, &p256(), &NoTimestamps, &NoRevocation).unwrap_err(),
        SealError::Request(RequestProblem::FieldName)
    );
    let mut r = request(Profile::BaselineB);
    r.visible = Some(Visible {
        page: 3,
        rect: Rect {
            llx: 0.0,
            lly: 0.0,
            urx: 10.0,
            ury: 10.0,
        },
        appearance: Appearance::Border,
    });
    assert_eq!(
        seal(&input, &r, &p256(), &NoTimestamps, &NoRevocation).unwrap_err(),
        SealError::Request(RequestProblem::PageOutOfRange)
    );
    // B-T with no timestamp source.
    let e = seal(
        &input,
        &request(Profile::BaselineT),
        &p256(),
        &NoTimestamps,
        &NoRevocation,
    )
    .unwrap_err();
    assert_eq!(e.code(), "CS-SEAL-0002");
}

#[test]
fn revocation_falls_back_to_crls_and_fails_without_any() {
    let tsa = TestTsa::new(SIGNING_TIME);
    let crl_only = TestRevocation {
        no_ocsp: true,
        ..Default::default()
    };
    let s = seal(
        &one_page("Agreement"),
        &request(Profile::BaselineLt),
        &p256(),
        &tsa,
        &crl_only,
    )
    .unwrap();
    assert!(passed(&s.bytes));
    assert_eq!(s.report.dss.as_ref().unwrap().ocsp_responses, 0);

    let none = TestRevocation {
        nothing: true,
        ..Default::default()
    };
    let e = seal(
        &one_page("Agreement"),
        &request(Profile::BaselineLt),
        &p256(),
        &tsa,
        &none,
    )
    .unwrap_err();
    assert!(matches!(
        e,
        SealError::Revocation(RevocationProblem::NoAnswer { .. })
    ));
    assert_eq!(e.code(), "CS-SEAL-0004");
}

/// HRD-02: a real CA hands out the seal certificate and its issuing CA, never the offline
/// root, and a TSA's token stops below its root too, while the host fetches no issuers.
/// B-LT and B-LTA, sealed or augmented later, must still walk each chain to its root,
/// finding it among the request's trust anchors (before: `CS-SEAL-0004`, issuer not found).
#[test]
fn validation_data_finds_the_root_among_the_trust_anchors() {
    let tsa = TestTsa::new(SIGNING_TIME);
    let rev = TestRevocation {
        no_issuers: true,
        ..Default::default()
    };
    let input = one_page("Agreement");
    for profile in [Profile::BaselineLt, Profile::BaselineLta] {
        let s = seal(&input, &request(profile), &p256_below_root(), &tsa, &rev)
            .unwrap_or_else(|e| panic!("{profile:?}: {e}"));
        assert!(passed(&s.bytes), "{profile:?}: {:?}", ours(&s.bytes));
        assert!(s.report.dss.as_ref().unwrap().ocsp_responses >= 2);
    }
    let bt = seal(
        &input,
        &request(Profile::BaselineT),
        &p256_below_root(),
        &tsa,
        &rev,
    )
    .unwrap();
    let options = ArchiveOptions {
        time: SIGNING_TIME,
        trust: trust(),
        limits: Limits::default(),
    };
    let lta = augment(&bt.bytes, Profile::BaselineLta, &options, &tsa, &rev).unwrap();
    assert!(passed(&lta.bytes), "{:?}", ours(&lta.bytes));

    // With the root nowhere at all, the walk still stops: issuer not found.
    let mut r = request(Profile::BaselineLt);
    r.trust = casual_sign_seal::TrustStore::new();
    let e = seal(&input, &r, &p256_below_root(), &tsa, &rev).unwrap_err();
    assert!(
        matches!(
            e,
            SealError::Revocation(RevocationProblem::IssuerNotFound { .. })
        ),
        "{e}"
    );
}

/// HRD-02: production CAs scope their CRLs with a critical Issuing Distribution Point
/// (DigiCert's timestamping CA does, and its OCSP answers no SHA-256 CertID, so the CRL is
/// all there is). Sealing must embed them and our verifier must accept them from the DSS
/// (before: `CS-SEAL-0004`, an unsupported critical CRL extension).
#[test]
fn crls_scoped_by_an_issuing_distribution_point_are_used() {
    let tsa = TestTsa::new(SIGNING_TIME);
    let scoped = TestRevocation {
        no_ocsp: true,
        scoped_crls: true,
        ..Default::default()
    };
    for (label, provider) in [("p256", p256()), ("rsa", rsa())] {
        let s = seal(
            &one_page("Agreement"),
            &request(Profile::BaselineLta),
            &provider,
            &tsa,
            &scoped,
        )
        .unwrap_or_else(|e| panic!("{label}: {e}"));
        let dss = s.report.dss.as_ref().unwrap();
        assert_eq!(dss.ocsp_responses, 0);
        assert_eq!(dss.crls, 2, "the intermediate's and the root's scoped CRLs");
        assert!(passed(&s.bytes), "{label}: {:?}", ours(&s.bytes));
    }
}

/// HRD-02: a TSA's token may carry a cross-certificate of a trusted root (DigiCert's
/// carries "Trusted Root G4" issued by "Assured ID Root CA"). A trust anchor ends a path
/// and needs no revocation data, so the walk stops at any certificate with an anchor's
/// subject and key instead of chasing an issuer no one holds (before: `CS-SEAL-0004`).
#[test]
fn a_cross_certificate_of_a_trust_anchor_ends_the_walk() {
    let mut tsa = TestTsa::new(SIGNING_TIME);
    tsa.cross_certificate = true;
    for profile in [Profile::BaselineLt, Profile::BaselineLta] {
        let s = seal(
            &one_page("Agreement"),
            &request(profile),
            &p256(),
            &tsa,
            &TestRevocation::default(),
        )
        .unwrap_or_else(|e| panic!("{profile:?}: {e}"));
        assert!(passed(&s.bytes), "{profile:?}: {:?}", ours(&s.bytes));
    }
}

#[test]
fn augment_and_renew() {
    let tsa = TestTsa::new(SIGNING_TIME);
    let rev = TestRevocation::default();
    let bt = seal(
        &one_page("Agreement"),
        &request(Profile::BaselineT),
        &p256(),
        &tsa,
        &rev,
    )
    .unwrap();
    let options = ArchiveOptions {
        time: SIGNING_TIME,
        trust: trust(),
        limits: Limits::default(),
    };
    let lta = augment(&bt.bytes, Profile::BaselineLta, &options, &tsa, &rev).unwrap();
    assert!(lta.bytes.starts_with(&bt.bytes));
    assert!(passed(&lta.bytes), "{:?}", ours(&lta.bytes));
    let renewed = renew_lta(&lta.bytes, &options, &tsa, &rev).unwrap();
    assert!(renewed.bytes.starts_with(&lta.bytes));
    let v = ours(&renewed.bytes);
    assert_eq!(v.len(), 3);
    assert!(passed(&renewed.bytes), "{v:?}");
    assert_eq!(
        v.iter()
            .filter(|(k, _)| *k == SignatureKind::DocumentTimestamp)
            .count(),
        2
    );
    // The renewal's DSS carries a VRI entry for the previous document timestamp.
    assert_eq!(renewed.report.dss.as_ref().unwrap().vri_keys.len(), 1);
    assert_eq!(
        renew_lta(&bt.bytes, &options, &tsa, &rev).unwrap_err(),
        SealError::Request(RequestProblem::NoDocumentTimestamp)
    );
}

// ---------------------------------------------------------------- guards

/// Guard: placeholder overflow is retried once with the measured size (docs/31 §9).
#[test]
fn an_underestimated_token_bound_costs_one_retry() {
    let mut tsa = TestTsa::new(SIGNING_TIME);
    tsa.bound = Some(10);
    let s = seal(
        &one_page("Agreement"),
        &request(Profile::BaselineT),
        &p256(),
        &tsa,
        &NoRevocation,
    )
    .unwrap();
    let sig = s.report.signature.unwrap();
    assert_eq!(sig.attempts, 2);
    assert!(sig.der_len <= sig.placeholder_len);
    assert_eq!(tsa.calls.get(), 2);
}

/// Guard: a CMS that outgrows its placeholder twice is `CS-SEAL-0003`, never truncated.
#[test]
fn an_overflow_after_the_retry_is_an_error() {
    let mut tsa = TestTsa::new(SIGNING_TIME);
    tsa.bound = Some(10);
    tsa.grow_step = 4096;
    let e = seal(
        &one_page("Agreement"),
        &request(Profile::BaselineT),
        &p256(),
        &tsa,
        &NoRevocation,
    )
    .unwrap_err();
    assert!(matches!(e, SealError::Overflow { .. }), "{e:?}");
    assert_eq!(e.code(), "CS-SEAL-0003");
}

/// Guard: our own output is verified before it is returned (docs/31 §4 step 8).
#[test]
fn a_seal_that_does_not_verify_is_refused() {
    let mut bad = p256();
    bad.corrupt = true;
    let e = seal(
        &one_page("Agreement"),
        &request(Profile::BaselineB),
        &bad,
        &NoTimestamps,
        &NoRevocation,
    )
    .unwrap_err();
    assert_eq!(e.code(), "CS-SEAL-0010");
    match e {
        SealError::SelfCheck(f) => assert_eq!(f.check, CheckName::Signature),
        other => panic!("{other:?}"),
    }
}

/// Guard: the ByteRange is filled in place at the placeholder's width.
#[test]
fn byte_range_keeps_the_placeholder_width() {
    let s = seal(
        &one_page("Agreement"),
        &request(Profile::BaselineB),
        &p256(),
        &NoTimestamps,
        &NoRevocation,
    )
    .unwrap();
    let at = s
        .bytes
        .windows(12)
        .position(|w| w == b"/ByteRange [")
        .unwrap()
        + 11;
    let end = at + s.bytes[at..].iter().position(|&b| b == b']').unwrap();
    assert_eq!(
        end + 1 - at,
        b"[0 9999999999 9999999999 9999999999]".len(),
        "width kept"
    );
    let br = s.report.signature.unwrap().byte_range;
    let text = String::from_utf8(s.bytes[at..=end].to_vec()).unwrap();
    assert!(
        text.starts_with(&format!("[0 {} {} {}", br[1], br[2], br[3])),
        "{text}"
    );
    assert_eq!(s.bytes[br[1] as usize], b'<');
    assert_eq!(s.bytes[br[2] as usize - 1], b'>');
}

/// Guard: the VRI key is the upper-case hex SHA-1 of the whole /Contents string.
#[test]
fn vri_key_names_the_signature_contents() {
    let tsa = TestTsa::new(SIGNING_TIME);
    let s = seal(
        &one_page("Agreement"),
        &request(Profile::BaselineLt),
        &p256(),
        &tsa,
        &TestRevocation::default(),
    )
    .unwrap();
    let br = s.report.signature.unwrap().byte_range;
    let hex = &s.bytes[br[1] as usize + 1..br[2] as usize - 1];
    let contents: Vec<u8> = hex
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect();
    let key = vri_key(&contents);
    assert_eq!(key.len(), 40);
    assert!(
        key.bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
    );
    assert_eq!(s.report.vri_key.as_deref(), Some(key.as_str()));
    assert_eq!(count(&s.bytes, format!("/{key} <<").as_bytes()), 1);
}

/// docs/30 §1 (`PDF-INV-01`): the delivered bytes are a prefix of every sealed output,
/// for both cross-reference forms, every profile, and a renewal.
#[test]
fn the_input_is_a_prefix_of_every_output() {
    use casual_sign_pdf::{NormalizeOptions, OutputXref, admit, normalize};
    let never = || false;
    let raw = one_page("Agreement");
    for xref in [OutputXref::Table, OutputXref::Stream] {
        let mut a = admit(&raw, &Limits::default(), &never).unwrap();
        let input = normalize(&mut a, &NormalizeOptions::with_xref(xref), &never)
            .unwrap()
            .bytes;
        let tsa = TestTsa::new(SIGNING_TIME);
        let rev = TestRevocation::default();
        let mut last = Vec::new();
        for profile in [
            Profile::BaselineB,
            Profile::BaselineT,
            Profile::BaselineLt,
            Profile::BaselineLta,
        ] {
            let s = seal(&input, &request(profile), &p256(), &tsa, &rev).unwrap();
            assert!(s.bytes.starts_with(&input), "{xref:?} {profile:?}");
            assert!(s.bytes.len() > input.len());
            last = s.bytes;
        }
        let options = ArchiveOptions {
            time: SIGNING_TIME,
            trust: trust(),
            limits: Limits::default(),
        };
        let renewed = renew_lta(&last, &options, &tsa, &rev).unwrap();
        assert!(renewed.bytes.starts_with(&last));
        assert!(renewed.bytes.starts_with(&input));
    }
}
