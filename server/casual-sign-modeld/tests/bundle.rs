//! The model bundle (ML-09; `SEC-I03`): modeld refuses to start on a one-byte weight
//! change, an unlisted or missing file, a symbolic link, or a profile it does not know.
//! The files are synthetic bytes, not weights.
#![cfg(feature = "server")]
// Test code: a panic is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use std::path::Path;
use std::process::Command;

use casual_sign_modeld::{Bundle, BundleProblem, Manifest, ModeldError};
use common::*;

const DET: &[u8] = b"synthetic detector bytes";
const REC: &[u8] = b"synthetic recogniser bytes";
const NER: &[u8] = b"synthetic entity model bytes";

fn two_profiles(dir: &Path) -> Manifest {
    let text = bundle(
        dir,
        &[
            ("det", "ocr", "ocr/det.onnx", DET),
            ("rec", "ocr", "ocr/rec.onnx", REC),
            ("ner", "extraction", "ner/model.onnx", NER),
        ],
    );
    Manifest::parse(&text).unwrap()
}

fn problem(e: ModeldError) -> BundleProblem {
    assert_eq!(e.code(), "CS-ML-0002", "{e}");
    match e {
        ModeldError::Bundle(p) => p,
        other => panic!("{other}"),
    }
}

#[test]
fn an_intact_bundle_verifies_with_a_stable_id() {
    let dir = scratch("bundle-intact");
    let m = two_profiles(&dir);
    let all = ["ocr".to_owned(), "extraction".to_owned()];
    let b = Bundle::verify(&dir, &m, &all).unwrap();
    assert_eq!(b.installed.len(), 3);
    assert_eq!(
        Bundle::verify(&dir, &m, &[]).unwrap().id,
        b.id,
        "same files, same id"
    );
    std::fs::remove_file(dir.join("ner/model.onnx")).unwrap();
    let ocr_only = Bundle::verify(&dir, &m, &["ocr".into()]).unwrap();
    assert_eq!(ocr_only.installed.len(), 2);
    assert_ne!(ocr_only.id, b.id, "the id names what is installed");
    assert!(ocr_only.model("ner").is_none());
}

/// **A one-byte change to a weight file stops modeld from starting** (`SEC-I03`).
#[test]
fn a_one_byte_change_is_refused() {
    let dir = scratch("bundle-one-byte");
    let m = two_profiles(&dir);
    let path = dir.join("ocr/rec.onnx");
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[7] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();
    let p = problem(Bundle::verify(&dir, &m, &["ocr".into()]).unwrap_err());
    assert_eq!(p, BundleProblem::Hash("ocr/rec.onnx".into()));
    // Not even an operator who does not enable the profile can serve the changed file.
    let p = problem(Bundle::verify(&dir, &m, &[]).unwrap_err());
    assert_eq!(p, BundleProblem::Hash("ocr/rec.onnx".into()));
}

#[test]
fn a_file_of_another_size_is_refused() {
    let dir = scratch("bundle-size");
    let m = two_profiles(&dir);
    let mut longer = DET.to_vec();
    longer.push(b'!');
    std::fs::write(dir.join("ocr/det.onnx"), longer).unwrap();
    let p = problem(Bundle::verify(&dir, &m, &[]).unwrap_err());
    assert_eq!(p, BundleProblem::Size("ocr/det.onnx".into()));
}

#[test]
fn an_unlisted_file_is_refused() {
    let dir = scratch("bundle-unlisted");
    let m = two_profiles(&dir);
    std::fs::write(dir.join("ocr/extra.onnx"), b"x").unwrap();
    let p = problem(Bundle::verify(&dir, &m, &[]).unwrap_err());
    assert_eq!(p, BundleProblem::Unlisted("ocr/extra.onnx".into()));
}

#[test]
fn a_missing_file_of_an_enabled_profile_is_refused() {
    let dir = scratch("bundle-missing");
    let m = two_profiles(&dir);
    std::fs::remove_file(dir.join("ocr/det.onnx")).unwrap();
    let p = problem(Bundle::verify(&dir, &m, &["ocr".into()]).unwrap_err());
    assert_eq!(p, BundleProblem::Missing("ocr/det.onnx".into()));
    let p = problem(Bundle::verify(&dir, &m, &["layout".into()]).unwrap_err());
    assert_eq!(p, BundleProblem::UnknownProfile("layout".into()));
}

/// A symbolic link could point outside the read-only mount, even to a listed name.
#[cfg(unix)]
#[test]
fn a_symbolic_link_is_refused() {
    let dir = scratch("bundle-symlink");
    let m = two_profiles(&dir);
    let elsewhere = scratch("bundle-symlink-target").join("rec.onnx");
    std::fs::write(&elsewhere, REC).unwrap();
    std::fs::remove_file(dir.join("ocr/rec.onnx")).unwrap();
    std::os::unix::fs::symlink(&elsewhere, dir.join("ocr/rec.onnx")).unwrap();
    let p = problem(Bundle::verify(&dir, &m, &[]).unwrap_err());
    assert_eq!(p, BundleProblem::Unlisted("ocr/rec.onnx".into()));
}

fn modeld(bundle_dir: &Path) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_casual-sign-modeld"))
        .env_clear()
        .env("OPENSEAL_MODELD_BUNDLE", bundle_dir)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The binary checks the bundle against its compiled-in manifest before anything else: a
/// file the manifest does not list stops it with `CS-ML-0002`, while a clean bundle gets
/// as far as the TLS settings.
#[test]
fn the_daemon_refuses_to_start_on_a_bundle_its_manifest_does_not_list() {
    let dir = scratch("bundle-daemon");
    std::fs::write(dir.join("planted.onnx"), b"not in the manifest").unwrap();
    let (ok, err) = modeld(&dir);
    assert!(!ok);
    assert!(
        err.contains("CS-ML-0002") && err.contains("planted.onnx"),
        "{err}"
    );

    let clean = scratch("bundle-daemon-clean");
    let (ok, err) = modeld(&clean);
    assert!(!ok);
    assert!(
        err.contains("CS-ML-0001") && err.contains("OPENSEAL_MODELD_TLS_CERT"),
        "{err}"
    );
}
