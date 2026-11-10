//! Every `xfa_*` row of `fixtures/hostile/manifest.tsv` (`XFA-01`, docs/21 §XFA): the
//! reader refuses the file as dynamic (`CS-PDF-0012`, checked by casual-sign-pdf's
//! manifest test); its packets, read with `xfa_packets`, are refused by the layout
//! with the code below, or laid out for the control.
// Test code: a panic is the failure report (CLAUDE.md).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::Command;

use casual_sign_pdf::{Credentials, Limits, xfa_packets};
use casual_sign_xfa::{Faces, XfaLimits, lay_out};

/// The code each fixture must be refused with; `None` for one that lays out. A manifest
/// row named `xfa_*` missing here fails the test.
const EXPECT: &[(&str, Option<&str>)] = &[
    ("xfa_valid.pdf", None),
    ("xfa_too_large.pdf", Some("CS-XFA-0001")),
    ("xfa_depth_257.pdf", Some("CS-XFA-0002")),
    ("xfa_nodes_4m.pdf", Some("CS-XFA-0003")),
    ("xfa_attributes_257.pdf", Some("CS-XFA-0003")),
    ("xfa_billion_laughs.pdf", Some("CS-XFA-0005")),
    ("xfa_external_entity.pdf", Some("CS-XFA-0005")),
    ("xfa_undefined_entity.pdf", Some("CS-XFA-0004")),
    ("xfa_unbalanced.pdf", Some("CS-XFA-0004")),
    ("xfa_no_template.pdf", Some("CS-XFA-0006")),
    ("xfa_instances_200k.pdf", Some("CS-XFA-0007")),
    ("xfa_pages_2001.pdf", Some("CS-XFA-0008")),
];

fn hostile_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/hostile")
}

fn rows() -> Vec<String> {
    let text = std::fs::read_to_string(hostile_dir().join("manifest.tsv")).unwrap();
    text.lines()
        .skip(1)
        .filter_map(|l| l.split('\t').next())
        .filter(|f| f.starts_with("xfa_"))
        .map(str::to_owned)
        .collect()
}

/// Generate the fixtures once if one is missing (they are not committed).
fn ensure() {
    if rows().iter().all(|f| hostile_dir().join(f).exists()) {
        return;
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let ok = Command::new("python3")
        .args(["-I", "fixtures/tools/generate.py"])
        .current_dir(root)
        .status()
        .is_ok_and(|s| s.success());
    assert!(ok, "fixtures/tools/generate.py failed");
}

#[test]
fn every_xfa_fixture_is_refused_with_its_code_or_laid_out() {
    ensure();
    let rows = rows();
    assert!(!rows.is_empty());
    let faces = Faces::bundled();
    let mut problems = Vec::new();
    for file in &rows {
        let Some((_, want)) = EXPECT.iter().find(|(f, _)| f == file) else {
            problems.push(format!("{file}: in the manifest, not in EXPECT"));
            continue;
        };
        let bytes = std::fs::read(hostile_dir().join(file)).unwrap();
        let packets = xfa_packets(&bytes, &Limits::default(), &Credentials::default(), &|| {
            false
        })
        .unwrap_or_else(|e| panic!("{file}: reading the packets: {e}"))
        .unwrap_or_else(|| panic!("{file}: no XFA"));
        match (
            lay_out(&packets, &faces, &XfaLimits::default(), &|| false),
            want,
        ) {
            (Ok(laid), None) => {
                assert_eq!(laid.report.pages, 1, "{file}");
                assert_eq!(laid.report.widgets, 1, "{file}");
            }
            (Err(e), Some(code)) if e.code() == *code => {}
            (Err(e), want) => problems.push(format!("{file}: expected {want:?}, got {e}")),
            (Ok(_), Some(code)) => problems.push(format!("{file}: expected {code}, laid out")),
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
}

#[test]
fn the_control_admits_after_layout() {
    ensure();
    let bytes = std::fs::read(hostile_dir().join("xfa_valid.pdf")).unwrap();
    let packets = xfa_packets(&bytes, &Limits::default(), &Credentials::default(), &|| {
        false
    })
    .unwrap()
    .unwrap();
    let laid = lay_out(&packets, &Faces::bundled(), &XfaLimits::default(), &|| {
        false
    })
    .unwrap();
    let admitted = casual_sign_pdf::admit_strict(&laid.pdf, &Limits::default(), &|| false).unwrap();
    assert_eq!(admitted.report.pages.len(), 1);
    assert_eq!(admitted.report.fields.len(), 1);
    assert!(!admitted.report.has_xfa);
}

#[test]
fn layout_is_deterministic() {
    ensure();
    let bytes = std::fs::read(hostile_dir().join("xfa_valid.pdf")).unwrap();
    let packets = xfa_packets(&bytes, &Limits::default(), &Credentials::default(), &|| {
        false
    })
    .unwrap()
    .unwrap();
    let a = lay_out(&packets, &Faces::bundled(), &XfaLimits::default(), &|| {
        false
    })
    .unwrap();
    let b = lay_out(&packets, &Faces::bundled(), &XfaLimits::default(), &|| {
        false
    })
    .unwrap();
    assert_eq!(a, b);
}

#[test]
fn cancellation_stops_the_layout() {
    ensure();
    let bytes = std::fs::read(hostile_dir().join("xfa_nodes_4m.pdf")).unwrap();
    let packets = xfa_packets(&bytes, &Limits::default(), &Credentials::default(), &|| {
        false
    })
    .unwrap()
    .unwrap();
    let e = lay_out(&packets, &Faces::bundled(), &XfaLimits::default(), &|| true).unwrap_err();
    assert_eq!(e.code(), "CS-XFA-0009");
}
