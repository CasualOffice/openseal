//! Every row of `fixtures/hostile/manifest.tsv` (`F-005`), under both modes (`T-1A`).
//!
//! Strict: the row's `strict_code`, or success for `-`. Default: `refuse` is an error
//! with that code; `open+report` and `open+remove` open with the finding named in
//! `DEFAULT_FINDING` (removal itself is stage 1B); `open` opens with no finding.
// Test code: a panic is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use casual_sign_pdf::{Credentials, Limits, admit, admit_strict, admit_strict_with, admit_with};

/// The finding the default reader must report for each `open+…` row. A manifest row
/// missing here fails the test, so the manifest cannot grow past the reader unseen.
const DEFAULT_FINDING: &[(&str, &str)] = &[
    ("xref_size_2g_table.pdf", "CS-PDF-0101"),
    ("xref_size_2g_stream.pdf", "CS-PDF-0101"),
    ("prev_loop.pdf", "CS-PDF-0101"),
    ("prev_self_loop.pdf", "CS-PDF-0101"),
    ("ref_chain_65.pdf", "CS-PDF-0004"),
    ("flate_bomb_content.pdf", "CS-PDF-0003"),
    ("flate_double.pdf", "CS-PDF-0003"),
    ("filter_chain_9.pdf", "CS-PDF-0011"),
    ("string_16mib_plus.pdf", "CS-PDF-0008"),
    ("name_128.pdf", "CS-PDF-0008"),
    ("content_ops_2m.pdf", "CS-PDF-0013"),
    ("truncated.pdf", "CS-PDF-0101"),
    ("broken_xref_offsets.pdf", "CS-PDF-0101"),
    ("broken_startxref.pdf", "CS-PDF-0101"),
    ("active_openaction_js.pdf", "CS-PDF-0103"),
    ("active_launch.pdf", "CS-PDF-0103"),
    ("active_uri_on_open.pdf", "CS-PDF-0105"),
    ("active_submitform.pdf", "CS-PDF-0103"),
    ("active_embedded_file.pdf", "CS-PDF-0104"),
    ("xref_w_huge.pdf", "CS-PDF-0101"),
    ("active_xfa.pdf", "CS-PDF-0103"),
    ("active_richmedia.pdf", "CS-PDF-0104"),
    ("active_3d.pdf", "CS-PDF-0104"),
    ("active_external_stream.pdf", "CS-PDF-0105"),
    ("active_gotor.pdf", "CS-PDF-0105"),
    ("active_gotoe.pdf", "CS-PDF-0105"),
    ("active_importdata.pdf", "CS-PDF-0103"),
    ("active_js_nametree.pdf", "CS-PDF-0103"),
    ("lzw_bomb.pdf", "CS-PDF-0003"),
    ("encrypted_empty_password.pdf", "CS-PDF-0109"),
    ("encrypted_flate_bomb.pdf", "CS-PDF-0003"),
];

fn input_for(file: &str) -> (Vec<u8>, Limits) {
    // Default limits for every row: the fixtures cross exactly the limit their row names
    // (fixtures/tools/generate.py; two defects there, found by T-1A, were fixed at source).
    let bytes = std::fs::read(common::hostile_dir().join(file)).unwrap();
    (bytes, Limits::default())
}

fn check_row(row: &[String; 5]) -> Result<(), String> {
    let [file, _, strict_code, default, _] = row;
    let (bytes, limits) = input_for(file);

    let strict = admit_strict(&bytes, &limits, &common::never);
    match (strict_code.as_str(), &strict) {
        ("-", Ok(_)) => {}
        ("-", Err(e)) => return Err(format!("{file}: strict expected success, got {e}")),
        (code, Err(e)) if e.code() == code => {}
        (code, Err(e)) => return Err(format!("{file}: strict expected {code}, got {e}")),
        (code, Ok(a)) => {
            return Err(format!(
                "{file}: strict expected {code}, got success {:?}",
                a.report.findings
            ));
        }
    }

    let lenient = admit(&bytes, &limits, &common::never);
    match default.as_str() {
        "refuse" => match &lenient {
            Err(e) if e.code() == strict_code => {}
            Err(e) => {
                return Err(format!(
                    "{file}: default expected refusal {strict_code}, got {e}"
                ));
            }
            Ok(a) => {
                return Err(format!(
                    "{file}: default expected refusal, opened with {:?}",
                    a.report.findings
                ));
            }
        },
        "open" => match &lenient {
            Ok(a) if a.report.findings.is_empty() && a.report.page_count > 0 => {}
            Ok(a) => {
                return Err(format!(
                    "{file}: expected a clean open, got {:?}",
                    a.report.findings
                ));
            }
            Err(e) => return Err(format!("{file}: expected open, got {e}")),
        },
        "open+report" | "open+remove" => {
            let want = DEFAULT_FINDING
                .iter()
                .find(|(f, _)| f == file)
                .map(|(_, c)| *c)
                .ok_or_else(|| format!("{file}: no expected finding in DEFAULT_FINDING"))?;
            match &lenient {
                Ok(a) if a.report.has_code(want) && a.report.page_count > 0 => {}
                Ok(a) => {
                    return Err(format!(
                        "{file}: expected finding {want}, got {:?}",
                        a.report.findings
                    ));
                }
                Err(e) => return Err(format!("{file}: expected open with {want}, got {e}")),
            }
        }
        other => return Err(format!("{file}: unknown default outcome {other}")),
    }
    Ok(())
}

#[test]
fn every_manifest_row_holds_in_both_modes() {
    if !common::ensure_hostile() {
        return;
    }
    let rows = common::manifest();
    assert!(rows.len() >= 32, "manifest has {} rows", rows.len());
    let failures: Vec<String> = rows.iter().filter_map(|r| check_row(r).err()).collect();
    assert!(
        failures.is_empty(),
        "{} of {} rows failed:\n{}",
        failures.len(),
        rows.len(),
        failures.join("\n")
    );
}

/// Encrypted rows give the same outcome with a wrong password as with none, and the
/// password-protected one opens with its password (`PDF-ENC-01`).
#[test]
fn encrypted_rows_with_passwords() {
    if !common::ensure_hostile() {
        return;
    }
    let wrong = Credentials::new().with_password("not-the-password");
    for row in common::manifest() {
        if !row[0].starts_with("encrypted_") {
            continue;
        }
        let bytes = std::fs::read(common::hostile_dir().join(&row[0])).unwrap();
        let l = Limits::default();
        let code = |r: Result<casual_sign_pdf::Admitted<'_>, casual_sign_pdf::PdfError>| {
            r.err().map(|e| e.code())
        };
        assert_eq!(
            code(admit_with(&bytes, &l, &wrong, &common::never)),
            code(admit(&bytes, &l, &common::never)),
            "{}",
            row[0]
        );
        assert_eq!(
            code(admit_strict_with(&bytes, &l, &wrong, &common::never)),
            code(admit_strict(&bytes, &l, &common::never)),
            "{}",
            row[0]
        );
    }
    let bytes = std::fs::read(common::hostile_dir().join("encrypted_wrong_password.pdf")).unwrap();
    let right = Credentials::new().with_password("openseal-user");
    let a = admit_strict_with(&bytes, &Limits::default(), &right, &common::never).unwrap();
    assert!(a.report.has_code("CS-PDF-0109"));
    assert_eq!(a.report.page_count, 1);
}

#[test]
fn input_of_exactly_the_size_cap_is_not_refused_for_size() {
    let mut bytes = common::classic(&common::pages(1), "");
    let limits = Limits {
        max_input_bytes: bytes.len() as u64,
        ..Limits::default()
    };
    assert!(admit_strict(&bytes, &limits, &common::never).is_ok());
    bytes.push(b'\n');
    assert_eq!(
        admit(&bytes, &limits, &common::never).unwrap_err().code(),
        "CS-PDF-0001"
    );
}

#[test]
fn every_open_row_has_an_expected_finding() {
    for row in common::manifest() {
        if row[3].starts_with("open+") {
            assert!(
                DEFAULT_FINDING.iter().any(|(f, _)| *f == row[0]),
                "{} missing from DEFAULT_FINDING",
                row[0]
            );
        }
    }
}

#[test]
fn report_details_on_the_controls() {
    if !common::ensure_hostile() {
        return;
    }
    for file in ["valid.pdf", "valid_xrefstream.pdf"] {
        let bytes = std::fs::read(common::hostile_dir().join(file)).unwrap();
        let a = admit_strict(&bytes, &Limits::default(), &common::never).unwrap();
        let r = &a.report;
        assert_eq!(r.page_count, 3, "{file}");
        assert!(!r.repaired, "{file}");
        assert_eq!(r.revisions.len(), 1, "{file}");
        assert_eq!(r.revisions[0].end_offset, bytes.len() as u64, "{file}");
        assert_eq!(r.version.map(|v| (v.major, v.minor)), Some((1, 7)));
        for p in &r.pages {
            assert_eq!((p.media_box.urx, p.media_box.ury), (612.0, 792.0));
            assert_eq!(p.rotate, 0);
        }
    }
    let bytes = std::fs::read(common::hostile_dir().join("revisions_1001.pdf")).unwrap();
    let limits = Limits {
        max_revisions: 2000,
        ..Limits::default()
    };
    let a = admit_strict(&bytes, &limits, &common::never).unwrap();
    assert_eq!(a.report.revisions.len(), 1002);
    assert!(
        a.report
            .revisions
            .windows(2)
            .all(|w| w[0].end_offset < w[1].end_offset)
    );
    assert_eq!(
        a.report.revisions.last().unwrap().end_offset,
        bytes.len() as u64
    );
}

#[test]
fn flate_bomb_many_is_stopped_by_the_document_budget_when_the_ratio_allows_it() {
    if !common::ensure_hostile() {
        return;
    }
    // Zeros deflate at about 1028:1, over docs/21's 1000:1, so with default limits the
    // ratio cap stops this file first. Lift the ratio to see the per-document budget.
    let bytes = std::fs::read(common::hostile_dir().join("flate_bomb_many.pdf")).unwrap();
    let limits = Limits {
        max_decode_ratio: u32::MAX,
        ..Limits::default()
    };
    for e in [
        admit(&bytes, &limits, &common::never).unwrap_err(),
        admit_strict(&bytes, &limits, &common::never).unwrap_err(),
    ] {
        assert!(
            matches!(e, casual_sign_pdf::PdfError::DecodeBudget { .. }),
            "{e}"
        );
    }
}
