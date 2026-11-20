//! `RSP-01` gate 2 (ADR-046 §3.2), in our verifier: a document with remote signatures —
//! final values flattened and the rest materialized at the lock point (R0), each remote
//! signature its own revision after a fill in place, later fills, then the platform seal
//! last — has every signature intact and trusted, and every revision after each one
//! classifies as form filling, signing or DSS data. A page-content change after a remote
//! signature is disallowed. pyHanko and EU DSS judge the same documents in
//! `fixtures/sealed/remote-csc-*.pdf` (`tools/verify-sealed.py`).
// Test code: a panic is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;
#[path = "common/remote.rs"]
mod remote;

use casual_sign_seal::Profile;
use casual_sign_verify::{Indication, ModificationClass, SignatureKind, VerifyOptions, verify};
use common::*;
use remote::{Scenario, build, page_content_change};

fn check(bytes: &[u8], signatures: usize) {
    let report = verify(bytes, &trust(), &VerifyOptions::at(VALIDATION_TIME));
    assert!(report.error.is_none(), "{:?}", report.error);
    let sigs: Vec<_> = report
        .signatures
        .iter()
        .filter(|s| s.kind != SignatureKind::DocumentTimestamp)
        .collect();
    assert_eq!(sigs.len(), signatures, "{:?}", report.signatures);
    for s in &report.signatures {
        assert_eq!(s.indication, Indication::TotalPassed, "{s:?}");
        for m in &s.modifications_after {
            assert!(m.allowed(), "{m:?}");
            for c in &m.classes {
                assert!(
                    matches!(
                        c,
                        ModificationClass::FormFill
                            | ModificationClass::Signature
                            | ModificationClass::DssUpdate
                            | ModificationClass::DocumentTimestamp
                    ),
                    "{c:?}"
                );
            }
        }
    }
}

#[test]
fn simple_remote_simple_with_the_platform_seal_last_passes_and_classifies_as_filling() {
    let b = build(Scenario::SimpleRemoteSimple, Profile::BaselineLt);
    check(&b.bytes, 2);
    // The fill after the remote signature is form filling for it.
    let report = verify(&b.bytes, &trust(), &VerifyOptions::at(VALIDATION_TIME));
    let first = &report.signatures[0];
    assert!(
        first
            .modifications_after
            .iter()
            .any(|m| m.classes.contains(&ModificationClass::FormFill)),
        "{:?}",
        first.modifications_after
    );
}

#[test]
fn two_remote_signers_then_the_platform_seal_at_b_lta_all_pass() {
    let b = build(Scenario::TwoRemote, Profile::BaselineLta);
    check(&b.bytes, 3);
    assert!(b.bytes.starts_with(&b.after_first_remote));
}

/// Guard: drawing a later value into page content after a remote signature is a
/// disallowed change for that signature (the reason values are materialized).
#[test]
fn a_page_content_change_after_a_remote_signature_is_disallowed() {
    let b = build(Scenario::SimpleRemoteSimple, Profile::BaselineLt);
    let changed = page_content_change(&b.after_first_remote, &b.later_field);
    let report = verify(&changed, &trust(), &VerifyOptions::at(VALIDATION_TIME));
    let first = &report.signatures[0];
    assert!(
        first.modifications_after.iter().any(|m| !m.allowed()),
        "{:?}",
        first.modifications_after
    );
    assert_ne!(first.indication, Indication::TotalPassed);
}
