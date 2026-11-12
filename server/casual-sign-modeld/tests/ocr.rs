//! OCR with the real PP-OCRv6 weights (piece D; `ML-02`). Needs a fetched bundle:
//!
//! ```sh
//! python3 -I tools/ml/fetch-models.py --profile ocr --profile runtime --dest "$DIR"
//! OPENSEAL_MODELD_TEST_BUNDLE="$DIR" cargo test -p casual-sign-modeld --test ocr -- --nocapture
//! ```
//!
//! Without `OPENSEAL_MODELD_TEST_BUNDLE` each test prints `SKIPPED` and returns.
//!
//! The measure (docs/33 §5.1, ML-02's exit): every synthetic scan of `fixtures/ml` is
//! rasterised at 200 DPI through the raster child and read through the service as the
//! worker would (DOC_OPEN, OCR, DOC_CLOSE). A truth word is recalled when an OCR word
//! with the same text (surrounding punctuation aside) lies on it. Recall is printed per
//! file; the Latin-script scans must reach 95% together.
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

use casual_sign_modeld::raster::RasterLimits;
use casual_sign_modeld::wire::{OcrPage, Op, Request, Response};
use casual_sign_modeld::{AllowList, ConnectionState, ModelService, ModeldLimits, OpLog};

const EXE: &str = env!("CARGO_BIN_EXE_casual-sign-modeld");

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn service(name: &str) -> Option<ModelService> {
    let bundle = common::real_bundle(&format!("{name}-bundle"), &["ocr", "runtime"])?;
    let dir = common::scratch(&format!("{name}-run"));
    let service = ModelService::new(
        bundle,
        AllowList::new(),
        OpLog::open(&dir.join("oplog.tsv")).unwrap(),
        ModeldLimits::default(),
    )
    .with_raster(Path::new(EXE), RasterLimits::default())
    .with_ocr()
    .unwrap();
    Some(service)
}

fn request(op: Op) -> Request {
    Request {
        deadline_ms: 120_000,
        account: "acc-ocr".into(),
        job: "job-ocr".into(),
        op,
    }
}

/// OCR every page of `pdf` through the service, as the worker would.
fn read_pdf(s: &ModelService, pdf: Vec<u8>, dpi: u16, scripts: &[&str]) -> Vec<OcrPage> {
    let mut conn = ConnectionState::default();
    let Response::Opened { doc, pages } = s.answer("t", &request(Op::DocOpen { pdf }), &mut conn)
    else {
        panic!("DOC_OPEN failed");
    };
    let mut out = Vec::new();
    for page in 0..u16::try_from(pages).unwrap() {
        let op = Op::Ocr {
            doc,
            page,
            dpi,
            scripts: scripts.iter().map(|s| (*s).to_owned()).collect(),
        };
        match s.answer("t", &request(op), &mut conn) {
            Response::Ocr(p) => out.push(p),
            other => panic!("OCR answered {other:?}"),
        }
    }
    assert_eq!(
        s.answer("t", &request(Op::DocClose { doc }), &mut conn),
        Response::Closed
    );
    out
}

/// Surrounding punctuation aside, the word's text.
fn core(t: &str) -> String {
    t.trim_matches(|c: char| c.is_ascii_punctuation() || c == '…')
        .to_owned()
}

/// The OCR words of a page in displayed space: `(text, x0, y0, x1, y1)`.
fn displayed_words(p: &OcrPage) -> Vec<(String, [f32; 4])> {
    p.words
        .iter()
        .map(|w| {
            let pts: Vec<(f32, f32)> = w.quad.iter().map(|q| p.to_displayed(*q)).collect();
            let xs = pts.iter().map(|q| q.0);
            let ys = pts.iter().map(|q| q.1);
            (
                w.text.clone(),
                [
                    xs.clone().fold(f32::MAX, f32::min),
                    ys.clone().fold(f32::MAX, f32::min),
                    xs.fold(f32::MIN, f32::max),
                    ys.fold(f32::MIN, f32::max),
                ],
            )
        })
        .collect()
}

/// `(script, recalled, total)` over the truth words of one scan.
fn recall(truth: &serde_json::Value, pages: &[OcrPage]) -> Vec<(String, usize, usize)> {
    let mut by_script: std::collections::BTreeMap<String, (usize, usize)> = Default::default();
    for p in truth["pages"].as_array().unwrap() {
        let index = usize::try_from(p["page"].as_u64().unwrap()).unwrap();
        let words = displayed_words(&pages[index]);
        for w in p["words"].as_array().unwrap() {
            if w["role"] == "signature_ink" {
                continue;
            }
            let text = w["text"].as_str().unwrap();
            let r: Vec<f32> = w["rect"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_f64().unwrap() as f32)
                .collect();
            let (cx, cy) = (r[0] + r[2] / 2.0, r[1] + r[3] / 2.0);
            let hit = words.iter().any(|(t, b)| {
                core(t) == core(text)
                    && cx >= b[0] - 4.0
                    && cx <= b[2] + 4.0
                    && cy >= b[1] - 4.0
                    && cy <= b[3] + 4.0
            });
            let e = by_script
                .entry(w["script"].as_str().unwrap().to_owned())
                .or_default();
            e.0 += usize::from(hit);
            e.1 += 1;
        }
    }
    by_script.into_iter().map(|(s, (h, t))| (s, h, t)).collect()
}

/// **ML-02's measure:** word recall on the synthetic scans at 200 DPI, per file; Latin
/// scans at least 95% together. Arabic and Devanagari are read with the packs the bundle
/// holds and reported, not bounded (PP-OCRv6 small has no Arabic or Devanagari
/// characters; the PP-OCRv5 packs come from piece X's export).
#[test]
fn scans_are_read_at_200_dpi_with_latin_word_recall_of_95_percent() {
    let Some(s) = service("ocr-recall") else {
        return;
    };
    let mut names: Vec<_> = std::fs::read_dir(repo().join("fixtures/ml/scans"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    names.sort();
    let (mut latin_hit, mut latin_total) = (0, 0);
    for scan in names {
        let stem = scan.file_stem().unwrap().to_str().unwrap().to_owned();
        let truth: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(repo().join(format!("fixtures/ml/truth/{stem}.json")))
                .unwrap(),
        )
        .unwrap();
        let started = std::time::Instant::now();
        let pages = read_pdf(&s, std::fs::read(&scan).unwrap(), 200, &[]);
        let ms = started.elapsed().as_millis() / pages.len() as u128;
        for p in &pages {
            assert_eq!(p.status, 0, "{stem} page {}", p.page);
            assert_eq!(p.dpi, 200);
        }
        for (script, hit, total) in recall(&truth, &pages) {
            eprintln!(
                "ML-02 OCR {stem} [{script}]: {hit}/{total} = {:.1}% ({ms} ms/page)",
                100.0 * hit as f64 / total as f64
            );
            if script == "Latn" {
                latin_hit += hit;
                latin_total += total;
            }
        }
    }
    let r = latin_hit as f64 / latin_total as f64;
    eprintln!(
        "ML-02 OCR Latin scans: {latin_hit}/{latin_total} = {:.2}%",
        r * 100.0
    );
    assert!(r >= 0.95, "Latin word recall {r:.4}");
}

/// A page rendered at 200 DPI comes back with every word in NFC and the geometry the
/// rasteriser used; words are not empty and carry confidences; a script pack the
/// bundle lacks is refused (`CS-ML-0010`) and the document stays open.
#[test]
fn ocr_answers_words_in_nfc_with_geometry_and_refuses_a_missing_pack() {
    let Some(s) = service("ocr-shape") else {
        return;
    };
    let scan = repo().join("fixtures/ml/scans/latin-services--200dpi-q75-rot90.pdf");
    let pages = read_pdf(&s, std::fs::read(&scan).unwrap(), 150, &[]);
    assert_eq!(pages.len(), 2);
    for p in &pages {
        assert_eq!((p.status, p.dpi, p.rotate), (0, 150, 90));
        assert!(!p.words.is_empty() && !p.lines.is_empty());
        for w in &p.words {
            assert!(!w.text.trim().is_empty());
            assert!(
                unicode_is_nfc(&w.text),
                "word not in NFC: {:?}",
                w.text.len()
            );
            assert!(w.conf > 0 && w.conf <= 10_000);
        }
    }
    assert!(
        pages.iter().any(|p| !p.rules.is_empty()),
        "the services form has signature rules"
    );
    let mut conn = ConnectionState::default();
    let Response::Opened { doc, .. } = s.answer(
        "t",
        &request(Op::DocOpen {
            pdf: std::fs::read(&scan).unwrap(),
        }),
        &mut conn,
    ) else {
        panic!("open");
    };
    let ocr = |scripts: Vec<String>| Op::Ocr {
        doc,
        page: 0,
        dpi: 100,
        scripts,
    };
    assert_eq!(
        s.answer("t", &request(ocr(vec!["arabic".into()])), &mut conn),
        Response::Error(10)
    );
    assert!(matches!(
        s.answer("t", &request(ocr(vec![])), &mut conn),
        Response::Ocr(OcrPage { status: 0, .. })
    ));
}

/// NFC check without a dependency: composing changes nothing. (Decomposed `e` + U+0301
/// is the case OCR output could produce.)
fn unicode_is_nfc(s: &str) -> bool {
    !s.chars().any(|c| ('\u{300}'..='\u{36f}').contains(&c))
}
