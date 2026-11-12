//! The rasteriser and the rule finder (piece C; `ML-02`, `ML-02B`, `PDF-REN-01`,
//! `SEC-I01`, `SEC-I02`): each `ml_*` hostile fixture refused with its code by the raster
//! child, the time cap killing the child alone, a child over its memory limit reported
//! and replaced, rules mapped back to PDF user space within 1 pt under every `/Rotate` and
//! a crop box, and rules and boxes found on the synthetic scans of `fixtures/ml`.
// Test code: a panic is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use casual_sign_modeld::ModeldError;
use casual_sign_modeld::raster::{Document, Raster, RasterLimits, render_bytes};
use casual_sign_modeld::rules::{Found, find};
use casual_sign_modeld::wire::OcrPage;

const EXE: &str = env!("CARGO_BIN_EXE_casual-sign-modeld");

/// A point in PDF user space.
type Point = (f32, f32);

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The ML hostile fixtures, generated once if missing (`generate.py --ml`, about 1 s).
fn ml_fixtures() -> PathBuf {
    let dir = repo().join("fixtures/hostile/ml");
    let missing = std::fs::read_to_string(dir.join("manifest.tsv"))
        .unwrap()
        .lines()
        .skip(1)
        .any(|l| !dir.join(l.split('\t').next().unwrap()).exists());
    if missing {
        let out = Command::new("python3")
            .args(["-I", "fixtures/tools/generate.py", "--ml"])
            .current_dir(repo())
            .output()
            .expect("python3 runs");
        assert!(
            out.status.success(),
            "generate.py --ml: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    dir
}

/// A PDF with one page per `(media box, crop box, rotate, content)`, with a correct
/// cross-reference table.
fn pdf(pages: &[(&str, Option<&str>, u16, String)]) -> Vec<u8> {
    let mut objs: Vec<String> = vec![
        "<</Type/Catalog/Pages 2 0 R>>".into(),
        format!(
            "<</Type/Pages/Kids[{}]/Count {}>>",
            (0..pages.len())
                .map(|i| format!("{} 0 R", 3 + 2 * i))
                .collect::<Vec<_>>()
                .join(" "),
            pages.len()
        ),
    ];
    for (i, (media, crop, rotate, content)) in pages.iter().enumerate() {
        let crop = crop.map(|c| format!("/CropBox{c}")).unwrap_or_default();
        objs.push(format!(
            "<</Type/Page/Parent 2 0 R/MediaBox{media}{crop}/Rotate {rotate}/Contents {} 0 R>>",
            4 + 2 * i
        ));
        objs.push(format!(
            "<</Length {}>>\nstream\n{content}\nendstream",
            content.len()
        ));
    }
    let mut out = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for (i, o) in objs.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{o}\nendobj\n", i + 1).as_bytes());
    }
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes());
    for off in offsets {
        out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<</Size {}/Root 1 0 R>>\nstartxref\n{xref}\n%%EOF\n",
            objs.len() + 1
        )
        .as_bytes(),
    );
    out
}

/// The geometry the worker gets for a raster.
fn page_of(r: &Raster) -> OcrPage {
    OcrPage {
        page: 0,
        status: 0,
        width: r.width,
        height: r.height,
        dpi: r.dpi,
        rotate: r.rotate,
        crop: r.crop,
        words: vec![],
        lines: vec![],
        rules: vec![],
        boxes: vec![],
    }
}

/// **`SEC-I02`:** every `ml_*` fixture is refused by the raster child with the code its
/// manifest row names, and the control renders. Each guard (pixel cap, image budget,
/// nesting depth) is a separate check in `src/raster.rs`; removing one turns its row red.
#[test]
fn every_ml_hostile_fixture_is_refused_with_its_code() {
    let dir = ml_fixtures();
    let manifest = std::fs::read_to_string(dir.join("manifest.tsv")).unwrap();
    let mut rows = 0;
    for line in manifest.lines().skip(1).filter(|l| !l.trim().is_empty()) {
        let cols: Vec<&str> = line.split('\t').collect();
        let (file, code) = (cols[0], cols[2]);
        let bytes = std::fs::read(dir.join(file)).unwrap();
        let mut doc = Document::open(Path::new(EXE), bytes, RasterLimits::default())
            .unwrap_or_else(|e| panic!("{file}: does not open: {e}"));
        let got = doc.render(0, 150);
        match (code, got) {
            ("-", Ok(r)) => assert!(r.width > 0 && r.dpi == 150, "{file}: {r:?}"),
            ("-", Err(e)) => panic!("{file}: expected to render, got {e}"),
            (code, Err(e)) => assert_eq!(e.code(), code, "{file}: {e}"),
            (code, Ok(r)) => panic!("{file}: expected {code}, rendered {r:?}"),
        }
        assert_eq!(doc.kills(), 0, "{file}: refused, not killed");
        rows += 1;
    }
    assert_eq!(rows, 6);
}

/// A page whose content takes long to render: `n` stroked curves.
fn slow_content(n: usize) -> String {
    let mut c = String::from("0.5 w ");
    for i in 0..n {
        let y = 50 + (i % 700);
        c.push_str(&format!(
            "50 {y} m 200 {} 400 {} 560 {y} c S ",
            y + 40,
            y - 40
        ));
    }
    c
}

/// **The time cap kills the child alone** (review defect 11): the slow page answers
/// `CS-ML-0006`, the next page renders in a fresh child, and after `max_kills` kills the
/// document's later pages are not rendered.
#[test]
fn a_page_over_its_time_kills_the_child_and_the_next_page_still_renders() {
    let fast = "0 g 72 600 m 400 600 l S".to_owned();
    let bytes = pdf(&[
        ("[0 0 612 792]", None, 0, fast),
        ("[0 0 612 792]", None, 0, slow_content(60_000)),
    ]);
    let limits = RasterLimits {
        page_time: Duration::from_millis(1500),
        max_kills: 2,
        ..RasterLimits::default()
    };
    let mut doc = Document::open(Path::new(EXE), bytes, limits).unwrap();
    assert_eq!(doc.pages(), 2);
    let e = doc.render(1, 200).unwrap_err();
    assert_eq!(e, ModeldError::Raster("rasterising took too long"));
    assert_eq!(doc.kills(), 1);
    // A fresh child renders the fast page.
    assert!(doc.render(0, 150).is_ok());
    assert_eq!(doc.render(1, 200).unwrap_err().code(), "CS-ML-0006");
    assert_eq!(doc.kills(), 2);
    // At the kill limit, later pages are not rendered at all.
    let e = doc.render(0, 150).unwrap_err();
    assert_eq!(
        e,
        ModeldError::Raster("too many raster children killed for this document")
    );
}

/// **A child that dies other than by the time cap** (here: its address-space limit) is
/// reported as `CS-ML-0014` and counted; the document carries on in a new child.
#[test]
fn a_child_over_its_memory_limit_is_reported_and_replaced() {
    // 1,470 pt square at 200 DPI is 4,083 px a side: about 67 MB of pixmap alone.
    let big = (
        "[0 0 1470 1470]",
        None,
        0,
        "0 g 72 600 m 400 600 l S".to_owned(),
    );
    let small = ("[0 0 100 100]", None, 0, "0 g 10 50 m 90 50 l S".to_owned());
    let bytes = pdf(&[big, small]);
    let limits = RasterLimits {
        address_space: 100 << 20,
        ..RasterLimits::default()
    };
    let mut doc = Document::open(Path::new(EXE), bytes, limits).unwrap();
    let e = doc.render(0, 200).unwrap_err();
    assert_eq!(e, ModeldError::RasterChild, "{e}");
    assert_eq!(doc.kills(), 1);
    let r = doc.render(1, 100).unwrap();
    assert_eq!((r.width, r.height), (138, 138));
}

/// A request for a page the document lacks, or an unreadable PDF, is refused.
#[test]
fn a_missing_page_or_an_unreadable_pdf_is_refused() {
    let bytes = pdf(&[("[0 0 200 200]", None, 0, String::new())]);
    let mut doc = Document::open(Path::new(EXE), bytes, RasterLimits::default()).unwrap();
    assert_eq!(doc.render(1, 150).unwrap_err().code(), "CS-ML-0006");
    let e = Document::open(
        Path::new(EXE),
        b"not a pdf".to_vec(),
        RasterLimits::default(),
    )
    .unwrap_err();
    assert_eq!(e.code(), "CS-ML-0006", "{e}");
}

/// A page larger than the raster cap renders at a lower resolution, reported.
#[test]
fn a_large_page_renders_at_a_lower_resolution_within_the_cap() {
    // A0 is 2,384 x 3,370 pt: at 150 DPI 4,966 x 7,020 px, over the cap.
    let bytes = pdf(&[("[0 0 2384 3370]", None, 0, String::new())]);
    let r = render_bytes(&bytes, 0, 150).unwrap();
    assert!(r.dpi < 150 && r.dpi >= 50, "{r:?}");
    assert!(u32::from(r.width.max(r.height)) <= 4096);
    assert!(u64::from(r.width) * u64::from(r.height) <= 16_800_000);
}

/// **`ML-02B`:** a rule drawn on a page with a crop box offset and each `/Rotate` is found
/// on the raster and maps back to the PDF user-space line it was drawn as, within 1 pt.
#[test]
fn rules_map_back_to_user_space_within_one_point_under_rotate_and_crop() {
    // Media box 0 0 700 900; crop box offset to (40, 60). The line is horizontal on the
    // displayed page: in user space it is horizontal for 0 and 180, vertical for 90 and
    // 270.
    let crop = "[40 60 652 852]";
    let cases: [(u16, Point, Point); 4] = [
        (0, (120.0, 300.0), (420.0, 300.0)),
        (90, (300.0, 200.0), (300.0, 500.0)),
        (180, (150.0, 400.0), (450.0, 400.0)),
        (270, (500.0, 250.0), (500.0, 550.0)),
    ];
    for dpi in [100, 150, 200] {
        for (rotate, a, b) in cases {
            let content = format!("0 g 1 w 0 J {} {} m {} {} l S", a.0, a.1, b.0, b.1);
            let bytes = pdf(&[("[0 0 700 900]", Some(crop), rotate, content)]);
            let r = render_bytes(&bytes, 0, dpi).unwrap();
            assert_eq!(r.rotate, rotate);
            assert_eq!(r.crop, [40.0, 60.0, 652.0, 852.0]);
            let found = find(&r);
            assert_eq!(found.rules.len(), 1, "rotate {rotate} at {dpi}: {found:?}");
            let [x0, y0, x1, y1] = found.rules[0];
            let mid = (y0 + y1) / 2.0;
            let page = page_of(&r);
            let mut ends = [page.to_user((x0, mid)), page.to_user((x1, mid))];
            // The rule's ends in user space, in the same order as the drawn ends.
            if (ends[0].0 - a.0).abs() + (ends[0].1 - a.1).abs()
                > (ends[1].0 - a.0).abs() + (ends[1].1 - a.1).abs()
            {
                ends.swap(0, 1);
            }
            for (got, want) in ends.iter().zip([a, b]) {
                assert!(
                    (got.0 - want.0).abs() <= 1.0 && (got.1 - want.1).abs() <= 1.0,
                    "rotate {rotate} at {dpi} DPI: {got:?} for {want:?}"
                );
            }
        }
    }
}

/// A field's drawn evidence in the truth file, displayed page space: `[x, y, w, h]`.
fn truth_fields(json: &serde_json::Value) -> Vec<(u64, String, [f32; 4])> {
    let mut out = Vec::new();
    for p in json["pages"].as_array().unwrap() {
        let page = p["page"].as_u64().unwrap();
        for f in p["fields"].as_array().unwrap() {
            let r: Vec<f32> = f["rect"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_f64().unwrap() as f32)
                .collect();
            out.push((
                page,
                f["drawn"].as_str().unwrap().to_owned(),
                [r[0], r[1], r[2], r[3]],
            ));
        }
    }
    out
}

/// Whether a found rule (displayed space, points) sits under a field rectangle: within
/// 4 pt of the edge it stands on and covering at least half its width.
fn rule_matches(rule: [f32; 4], field: [f32; 4], upside_down: bool) -> bool {
    let [fx, fy, fw, fh] = field;
    let [x0, y0, x1, y1] = rule;
    let overlap = (x1.min(fx + fw) - x0.max(fx)).max(0.0);
    // On a page scanned upside down the field stands on its line from below.
    let edge = if upside_down { fy } else { fy + fh };
    ((y0 + y1) / 2.0 - edge).abs() <= 4.0 && overlap >= 0.5 * fw
}

/// Whether a found box (displayed space) is the field's box: intersection over union at
/// least 0.5.
fn box_matches(found: [f32; 4], field: [f32; 4]) -> bool {
    let [fx, fy, fw, fh] = field;
    let [x0, y0, x1, y1] = found;
    let iw = (x1.min(fx + fw) - x0.max(fx)).max(0.0);
    let ih = (y1.min(fy + fh) - y0.max(fy)).max(0.0);
    let inter = iw * ih;
    let union = (x1 - x0) * (y1 - y0) + fw * fh - inter;
    union > 0.0 && inter / union >= 0.5
}

fn to_displayed(page: &OcrPage, r: [f32; 4]) -> [f32; 4] {
    let (a, b) = page.to_displayed((r[0], r[1]));
    let (c, d) = page.to_displayed((r[2], r[3]));
    [a.min(c), b.min(d), a.max(c), b.max(d)]
}

/// **`ML-02B` on the synthetic scans:** the drawn evidence of the fields (rules,
/// underscore runs, boxes) is found on each scan at its own resolution. The recall per
/// file is printed; the bound is the measured floor (docs/33 §15 records it).
#[test]
fn rules_and_boxes_are_found_on_the_synthetic_scans() {
    let truth_dir = repo().join("fixtures/ml/truth");
    let (mut hit, mut total) = (0usize, 0usize);
    let mut names: Vec<_> = std::fs::read_dir(repo().join("fixtures/ml/scans"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    names.sort();
    for scan in names {
        let stem = scan.file_stem().unwrap().to_str().unwrap().to_owned();
        let json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(truth_dir.join(format!("{stem}.json"))).unwrap(),
        )
        .unwrap();
        let dpi = u16::try_from(json["image"]["dpi"].as_u64().unwrap())
            .unwrap()
            .min(200);
        let bytes = std::fs::read(&scan).unwrap();
        let fields = truth_fields(&json);
        let upside_down = json["degradation"]["rotated_180"].as_bool().unwrap();
        let pages = json["pages"].as_array().unwrap().len();
        let (mut file_hit, mut file_total) = (0, 0);
        for index in 0..pages {
            let r = render_bytes(&bytes, index, dpi).unwrap();
            let page = page_of(&r);
            let Found { rules, boxes } = find(&r);
            let rules: Vec<_> = rules.iter().map(|x| to_displayed(&page, *x)).collect();
            let boxes: Vec<_> = boxes.iter().map(|x| to_displayed(&page, *x)).collect();
            for (_, drawn, rect) in fields.iter().filter(|f| f.0 == index as u64) {
                let ok = match drawn.as_str() {
                    "box" => boxes.iter().any(|b| box_matches(*b, *rect)),
                    _ => rules.iter().any(|x| rule_matches(*x, *rect, upside_down)),
                };
                file_total += 1;
                file_hit += usize::from(ok);
                if !ok {
                    eprintln!("  missed {drawn} at {rect:?} on {stem} page {index}");
                }
            }
        }
        eprintln!("ML-02B {stem}: {file_hit}/{file_total} drawn fields found");
        hit += file_hit;
        total += file_total;
    }
    let recall = hit as f64 / total as f64;
    eprintln!("ML-02B all scans: {hit}/{total} = {:.1}%", recall * 100.0);
    assert!(total > 50, "{total}");
    assert!(recall >= 0.97, "rule and box recall {recall:.3}");
}
