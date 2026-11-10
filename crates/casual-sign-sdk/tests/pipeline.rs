//! The facade end to end (`T-1J`): admit, prepare, fill and flatten, complete, seal at
//! B-T, verify, on `fixtures/hostile/valid.pdf`, a form and signed input, with the
//! prefix invariant at every step.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    missing_docs
)]

#[path = "../../casual-sign-seal/tests/common/mod.rs"]
mod common;
mod support;

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use casual_sign_sdk::model::{FieldType, FieldValue, Id, Text};
use casual_sign_sdk::{
    Credentials, Engine, Fill, FlattenOptions, FontSet, Indication, Limits, NoRevocation, Profile,
    SdkError, TrailOptions,
};
use support::{Class, run};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn engine() -> Engine {
    Engine::new(Limits::default(), FontSet::bundled())
}

/// `fixtures/hostile/valid.pdf`, generated when absent (it is not committed).
fn valid_pdf() -> Vec<u8> {
    let path = repo_root().join("fixtures/hostile/valid.pdf");
    if !path.exists() {
        let out = Command::new("python3")
            .args(["-I", "fixtures/tools/generate.py"])
            .current_dir(repo_root())
            .output()
            .expect("python3 generates fixtures/hostile");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    std::fs::read(path).unwrap()
}

#[test]
fn valid_pdf_through_every_step() {
    let e = engine();
    let bytes = valid_pdf();
    let r = run(&e, "valid.pdf", &bytes);
    assert_eq!(r.failure, None, "{:?}", r.steps);
    assert_eq!(r.class, Some(Class::Plain));
    assert_eq!(
        r.steps,
        [
            "admit",
            "normalize",
            "fill",
            "flatten",
            "certificate",
            "seal",
            "verify"
        ]
    );
    assert!(r.prefix);
    let sealed = r.sealed.unwrap();
    assert!(sealed.starts_with(&r.delivered));
    // Offline, a B-T seal has no revocation data: INDETERMINATE/TRY_LATER, as EU DSS
    // says offline; with the PKI's CRLs supplied it passes.
    let offline = r.offline.unwrap();
    let sig = offline.signatures.last().unwrap();
    assert_eq!(sig.indication.name(), "INDETERMINATE");
    assert_eq!(sig.indication.reason().unwrap().sub.name(), "TRY_LATER");
    assert!(sig.checks.digest.passed() && sig.checks.timestamp.passed());
    assert!(r.online.unwrap().all_passed());
}

#[test]
fn a_flipped_byte_after_sealing_fails() {
    let e = engine();
    let r = run(&e, "valid.pdf", &valid_pdf());
    let mut sealed = r.sealed.unwrap();
    // A byte of the delivered document, inside the signed range.
    let at = r.delivered.len() / 2;
    sealed[at] ^= 0x01;
    let report = e.verify(
        &sealed,
        &support::trust_store(),
        &e.verify_options(common::VALIDATION_TIME),
    );
    assert!(!report.all_passed());
    assert!(matches!(
        report.signatures.last().map(|s| s.indication),
        Some(Indication::TotalFailed(_)) | None
    ));
}

#[test]
fn synthetic_form_converted_filled_and_sealed() {
    let e = engine();
    let r = run(&e, "form.pdf", &common::form_pdf());
    assert_eq!(r.failure, None, "{:?}", r.steps);
    assert_eq!(r.class, Some(Class::Form));
    assert!(
        r.fields.0 >= 1 && r.fields.0 == r.fields.1,
        "{:?}",
        r.fields
    );
    assert!(r.prefix);
}

/// A real form from the corpus (`fixtures/corpus/files`, or `OPENSEAL_CORPUS_DIR`; not
/// committed): an IRS W-9 with text fields, checkboxes and `/MaxLen`.
#[test]
fn corpus_form_converted_filled_and_sealed() {
    let dir = std::env::var_os("OPENSEAL_CORPUS_DIR")
        .map_or_else(|| repo_root().join("fixtures/corpus/files"), PathBuf::from);
    let mut ran = 0;
    for name in [
        "irs-fw9-2000.pdf",
        "pysamples-libreoffice-form.pdf",
        "pdfbox-fillformfield.pdf",
    ] {
        let Ok(bytes) = std::fs::read(dir.join(name)) else {
            continue;
        };
        let e = engine();
        let r = run(&e, name, &bytes);
        assert_eq!(r.failure, None, "{name}: {:?}", r.steps);
        assert_eq!(r.class, Some(Class::Form), "{name}");
        assert!(r.fields.1 > 0, "{name}");
        assert!(r.prefix, "{name}");
        ran += 1;
    }
    if ran == 0 {
        eprintln!(
            "SKIPPED: corpus forms absent; fetch with python3 -I fixtures/corpus/fetch.py irs-fw9-2000.pdf"
        );
    }
}

#[test]
fn signed_input_kept_and_sealed_again() {
    // A B-T seal from the first run is signed input for the second.
    let e = engine();
    let first = run(&e, "valid.pdf", &valid_pdf()).sealed.unwrap();
    assert_eq!(
        e.prepare(&first, &Credentials::default())
            .unwrap_err()
            .code(),
        "CS-PDF-0014"
    );
    let r = run(&e, "sealed.pdf", &first);
    assert_eq!(r.failure, None, "{:?}", r.steps);
    assert_eq!(r.class, Some(Class::Signed));
    assert_eq!(r.steps, ["admit", "keep", "seal", "verify"]);
    let report = r.online.unwrap();
    assert_eq!(report.signatures.len(), 2);
    assert!(report.all_passed());
}

#[test]
fn invalid_value_is_refused_before_drawing() {
    let e = engine();
    let delivered = e.prepare(&valid_pdf(), &Credentials::default()).unwrap();
    let mut field = support::geometry_field(&delivered.admission);
    field.field_type = FieldType::Checkbox;
    let fields = vec![field];
    // A text value in a checkbox.
    let values = [(
        Id::new("note").unwrap(),
        FieldValue::Text(Text::new("yes").unwrap()),
    )]
    .into_iter()
    .collect();
    let caps = support::captures();
    let fill = Fill {
        fields: &fields,
        values: &values,
        captures: &caps,
        envelope_id: None,
        acroform: None,
        require_complete: false,
    };
    let err = e
        .fill_and_flatten(&delivered.bytes, &fill, &FlattenOptions::default())
        .unwrap_err();
    assert!(matches!(err, SdkError::Fields(_)), "{err}");
    assert_eq!(err.code(), "CS-FLD-0002");
}

#[test]
fn required_field_left_empty_refused_when_complete_is_required() {
    let e = engine();
    let delivered = e.prepare(&valid_pdf(), &Credentials::default()).unwrap();
    let mut field = support::geometry_field(&delivered.admission);
    field.required = true;
    let fields = vec![field];
    let values = std::collections::BTreeMap::new();
    let caps = support::captures();
    let mut fill = Fill {
        fields: &fields,
        values: &values,
        captures: &caps,
        envelope_id: None,
        acroform: None,
        require_complete: true,
    };
    let err = e
        .fill_and_flatten(&delivered.bytes, &fill, &FlattenOptions::default())
        .unwrap_err();
    assert_eq!(err.code(), "CS-FLD-0001");
    fill.require_complete = false;
    let ok = e
        .fill_and_flatten(&delivered.bytes, &fill, &FlattenOptions::default())
        .unwrap();
    assert!(ok.bytes.starts_with(&delivered.bytes));
    assert_eq!(ok.outcome.issues.len(), 1);
}

#[test]
fn cancellation_stops_admission() {
    let flag = Arc::new(AtomicBool::new(true));
    let f = Arc::clone(&flag);
    let e = engine().with_cancel(Arc::new(move || f.load(Ordering::Relaxed)));
    let err = e.admit(&valid_pdf(), &Credentials::default()).unwrap_err();
    assert_eq!(err.code(), "CS-PDF-0013");
    flag.store(false, Ordering::Relaxed);
    assert!(e.admit(&valid_pdf(), &Credentials::default()).is_ok());
}

#[test]
fn trail_tamper_is_detected() {
    let e = engine();
    let delivered = e.prepare(&valid_pdf(), &Credentials::default()).unwrap();
    let chain = support::chain(delivered.hash, 3);
    let trail = chain.to_trail_json().unwrap();
    assert!(e.verify_trail(&trail, &TrailOptions::default()).is_valid());
    let text = String::from_utf8(trail).unwrap();
    let tampered = text.replacen("rcp-1", "rcp-2", 1);
    assert!(
        !e.verify_trail(tampered.as_bytes(), &TrailOptions::default())
            .is_valid()
    );
}

#[test]
fn b_b_seal_without_timestamp_source() {
    let e = engine();
    let delivered = e.prepare(&valid_pdf(), &Credentials::default()).unwrap();
    let mut req = e.seal_request(Profile::BaselineB, "Seal", common::SIGNING_TIME);
    req.trust = support::trust_store();
    let sealed = e
        .seal(
            &delivered.bytes,
            &req,
            &common::p256(),
            &casual_sign_sdk::NoTimestamps,
            &NoRevocation,
        )
        .unwrap();
    assert!(sealed.bytes.starts_with(&delivered.bytes));
    // B-T with no timestamp source is refused, never downgraded.
    let req = e.seal_request(Profile::BaselineT, "Seal", common::SIGNING_TIME);
    let err = e
        .seal(
            &delivered.bytes,
            &req,
            &common::p256(),
            &casual_sign_sdk::NoTimestamps,
            &NoRevocation,
        )
        .unwrap_err();
    assert_eq!(err.code(), "CS-SEAL-0002");
}
