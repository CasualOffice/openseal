//! `PDF-INV-01` (docs/30 §1): for every admitted file, normalize, then append a
//! trivial incremental update, and check that
//!
//! - the update starts with the normalized bytes, byte for byte;
//! - both the normalized and the appended file are admitted again strictly;
//! - page count and every page's MediaBox equal the original's;
//! - lopdf (the oracle, ADR-005) reads the same page count from the appended file.
//!
//! Run over the hostile fixtures' `open*` rows and, when it has been fetched
//! (`python3 -I fixtures/corpus/fetch.py`), the real corpus in `fixtures/corpus/files`.
//! Set `OPENSEAL_INV_OUT` to a folder to keep the normalized and appended outputs (for
//! checking them with another validator), and `OPENSEAL_CORPUS_DIR` to read the
//! corpus from another folder.
// Test code: a panic is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::path::{Path, PathBuf};

use casual_sign_pdf::{
    AdmissionReport, Change, Dictionary, IncrementalUpdate, Limits, NormalizeOptions, Object,
    OutputXref, admit, admit_strict, normalize,
};
use common::never;

/// Strict refusals that concern one stream's data, which normalization copies as it
/// is (docs/30 §3): the output is refused strictly with the same code, and opens
/// under the default reader.
const CONTENT_CODES: &[&str] = &["CS-PDF-0003", "CS-PDF-0011", "CS-PDF-0013"];

#[derive(Debug, Default)]
struct Counts {
    files: u32,
    refused: u32,
    signed: u32,
    signed_appended: u32,
    /// Signed, and refused for appending: xref needed repair (`CS-WRT-0003`).
    signed_unsound: u32,
    /// Signed, and refused for appending: DocMDP level 1 (`CS-WRT-0004`).
    signed_docmdp: u32,
    checked: u32,
    strict_after: u32,
    content_kept: u32,
}

fn media_boxes(r: &AdmissionReport) -> Vec<[f64; 4]> {
    r.pages
        .iter()
        .map(|p| {
            [
                p.media_box.llx,
                p.media_box.lly,
                p.media_box.urx,
                p.media_box.ury,
            ]
        })
        .collect()
}

/// Admit strictly, or (for a content-code original) check the same strict code and
/// admit by default. Returns the report.
fn readmit(bytes: &[u8], original_strict: Option<&str>, what: &str) -> AdmissionReport {
    let strict = admit_strict(bytes, &Limits::default(), &never);
    match (original_strict, strict) {
        (Some(code), Err(e)) if CONTENT_CODES.contains(&code) => {
            assert_eq!(e.code(), code, "{what}: strict refused with another code");
            let a = admit(bytes, &Limits::default(), &never)
                .unwrap_or_else(|e| panic!("{what}: default refused: {e}"));
            assert!(!a.report.repaired, "{what}: needed repair");
            a.report
        }
        (_, Ok(a)) => a.report,
        (_, Err(e)) => panic!("{what}: strict refused: {e}"),
    }
}

/// A signed file is not normalized (`CS-PDF-0014`); the update goes on it directly
/// when it is sound and DocMDP allows filling and signing, and must keep every
/// signature and page.
fn check_signed_append(bytes: &[u8], report: &AdmissionReport, name: &str, counts: &mut Counts) {
    let a = admit(bytes, &Limits::default(), &never).unwrap();
    if let Err(e) = IncrementalUpdate::new(&a, Change::FillAndSign) {
        assert!(
            matches!(e.code(), "CS-WRT-0003" | "CS-WRT-0004"),
            "{name}: {e}"
        );
        if e.code() == "CS-WRT-0003" {
            counts.signed_unsound += 1;
        } else {
            counts.signed_docmdp += 1;
        }
        return;
    }
    let appended = append_info(bytes, name);
    assert!(appended.starts_with(bytes), "{name}: prefix");
    let after = match admit_strict(bytes, &Limits::default(), &never) {
        Ok(_) => admit_strict(&appended, &Limits::default(), &never),
        Err(_) => admit(&appended, &Limits::default(), &never),
    }
    .unwrap_or_else(|e| panic!("{name}: appended file refused: {e}"))
    .report;
    assert_eq!(after.page_count, report.page_count, "{name}: page count");
    assert_eq!(media_boxes(&after), media_boxes(report), "{name}: MediaBox");
    assert_eq!(
        after.signatures.len(),
        report.signatures.len(),
        "{name}: signatures"
    );
    assert_eq!(
        after.revisions.len(),
        report.revisions.len() + 1,
        "{name}: revisions"
    );
    counts.signed_appended += 1;
}

/// The trivial update: the old /Info entries and one new one.
fn append_info(normalized: &[u8], what: &str) -> Vec<u8> {
    let mut a = admit(normalized, &Limits::default(), &never).unwrap();
    let mut info = match a.document.trailer().get(b"Info").cloned() {
        Some(i) => match a.document.resolve(&i, &never).unwrap() {
            Object::Dictionary(d) => d,
            _ => Dictionary::new(),
        },
        None => Dictionary::new(),
    };
    info.insert(b"OpenSealTest", Object::String(b"PDF-INV-01".to_vec()));
    let mut u = IncrementalUpdate::new(&a, Change::FillAndSign)
        .unwrap_or_else(|e| panic!("{what}: cannot append: {e}"));
    let r = u.add(Object::Dictionary(info)).unwrap();
    u.set_info(r);
    u.finish()
        .unwrap_or_else(|e| panic!("{what}: append failed: {e}"))
}

fn check_file(path: &Path, out_dir: Option<&Path>, counts: &mut Counts) {
    let name = path.file_name().unwrap().to_string_lossy().into_owned();
    let bytes = std::fs::read(path).unwrap();
    counts.files += 1;
    let Ok(mut original) = admit(&bytes, &Limits::default(), &never) else {
        counts.refused += 1;
        return;
    };
    let original_strict = admit_strict(&bytes, &Limits::default(), &never)
        .err()
        .map(|e| e.code());
    let report = original.report.clone();
    for form in [OutputXref::Stream, OutputXref::Table] {
        let what = format!("{name} ({form:?})");
        let n = match normalize(&mut original, &NormalizeOptions::with_xref(form), &never) {
            Ok(n) => n,
            Err(e) if e.code() == "CS-PDF-0014" => {
                counts.signed += 1;
                check_signed_append(&bytes, &report, &name, counts);
                return;
            }
            Err(e) => panic!("{what}: normalize failed: {e}"),
        };
        let normalized = readmit(&n.bytes, original_strict, &format!("{what} normalized"));
        let appended = append_info(&n.bytes, &what);
        assert!(
            appended.starts_with(&n.bytes),
            "{what}: the update does not start with the normalized bytes"
        );
        let after = readmit(&appended, original_strict, &format!("{what} appended"));
        for r in [&normalized, &after] {
            assert_eq!(r.page_count, report.page_count, "{what}: page count");
            assert_eq!(media_boxes(r), media_boxes(&report), "{what}: MediaBox");
        }
        assert_eq!(after.revisions.len(), 2, "{what}: revisions");
        let lopdf = lopdf::Document::load_mem(&appended)
            .unwrap_or_else(|e| panic!("{what}: lopdf cannot read the output: {e}"));
        assert_eq!(
            lopdf.get_pages().len(),
            report.page_count as usize,
            "{what}: lopdf page count"
        );
        if let Some(dir) = out_dir {
            let stem = name.trim_end_matches(".pdf");
            let tag = format!("{form:?}").to_lowercase();
            std::fs::write(dir.join(format!("{stem}.{tag}.normalized.pdf")), &n.bytes).unwrap();
            std::fs::write(dir.join(format!("{stem}.{tag}.appended.pdf")), &appended).unwrap();
        }
        if original_strict.is_some_and(|c| CONTENT_CODES.contains(&c)) {
            counts.content_kept += 1;
        } else {
            counts.strict_after += 1;
        }
        // Each form is checked from the same admitted original.
        original = admit(&bytes, &Limits::default(), &never).unwrap();
    }
    counts.checked += 1;
}

fn out_dir(sub: &str) -> Option<PathBuf> {
    let dir = PathBuf::from(std::env::var_os("OPENSEAL_INV_OUT")?).join(sub);
    std::fs::create_dir_all(&dir).unwrap();
    Some(dir)
}

#[test]
fn pdf_inv_01_hostile_fixtures() {
    if !common::ensure_hostile() {
        return;
    }
    let out = out_dir("hostile");
    let mut counts = Counts::default();
    for row in common::manifest() {
        if !row[3].starts_with("open") {
            continue;
        }
        check_file(
            &common::hostile_dir().join(&row[0]),
            out.as_deref(),
            &mut counts,
        );
    }
    eprintln!("PDF-INV-01 fixtures/hostile: {counts:?}");
    assert_eq!(counts.refused, 0, "an open* row was refused");
    assert_eq!(counts.checked, counts.files);
    assert!(counts.checked >= 20, "{counts:?}");
}

#[test]
fn pdf_inv_01_corpus() {
    // A worktree can point at a corpus fetched in another checkout.
    let dir = std::env::var_os("OPENSEAL_CORPUS_DIR").map_or_else(
        || common::repo_root().join("fixtures/corpus/files"),
        PathBuf::from,
    );
    if !dir.is_dir() {
        eprintln!(
            "SKIPPED: fixtures/corpus/files absent; fetch it with python3 -I fixtures/corpus/fetch.py"
        );
        return;
    }
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("pdf")))
        .collect();
    files.sort();
    let out = out_dir("corpus");
    let mut counts = Counts::default();
    // Every file is checked and every failure listed, not just the first.
    let mut failures = Vec::new();
    for f in &files {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            check_file(f, out.as_deref(), &mut counts);
        }));
        if let Err(e) = r {
            let msg = e
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|s| (*s).to_string()))
                .unwrap_or_default();
            failures.push(msg);
        }
    }
    eprintln!("PDF-INV-01 corpus ({}): {counts:?}", dir.display());
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
