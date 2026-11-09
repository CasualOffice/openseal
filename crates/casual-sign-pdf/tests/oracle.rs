//! `lopdf` as a differential oracle (ADR-005): on valid documents both readers must
//! agree on the page count and every page's (inherited) MediaBox.
// Test code: a panic is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use casual_sign_pdf::{Limits, admit_strict};
use common::{classic, never, pages, stream, xref_stream_file, zlib};

/// lopdf's view: per page, the MediaBox found on the page or its nearest ancestor.
fn lopdf_boxes(bytes: &[u8]) -> Vec<[f64; 4]> {
    let doc = lopdf::Document::load_mem(bytes).expect("lopdf opens the file");
    let mut out = Vec::new();
    for (_, id) in doc.get_pages() {
        let mut node = doc.get_object(id).unwrap().as_dict().unwrap();
        let mut found = None;
        for _ in 0..64 {
            if let Ok(mb) = node.get(b"MediaBox") {
                let (_, mb) = doc.dereference(mb).unwrap();
                let a = mb.as_array().unwrap();
                let n: Vec<f64> = a
                    .iter()
                    .map(|o| doc.dereference(o).unwrap().1.as_float().unwrap() as f64)
                    .collect();
                found = Some([
                    n[0].min(n[2]),
                    n[1].min(n[3]),
                    n[0].max(n[2]),
                    n[1].max(n[3]),
                ]);
                break;
            }
            match node.get(b"Parent").and_then(|p| p.as_reference()) {
                Ok(p) => node = doc.get_object(p).unwrap().as_dict().unwrap(),
                Err(_) => break,
            }
        }
        out.push(found.unwrap_or([0.0, 0.0, 612.0, 792.0]));
    }
    out
}

fn ours(bytes: &[u8]) -> Vec<[f64; 4]> {
    let a = admit_strict(bytes, &Limits::default(), &never).unwrap();
    assert_eq!(a.report.page_count as usize, a.report.pages.len());
    a.report
        .pages
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

fn agree(name: &str, bytes: &[u8]) {
    let theirs = lopdf_boxes(bytes);
    let mine = ours(bytes);
    assert_eq!(mine.len(), theirs.len(), "{name}: page count");
    for (i, (m, t)) in mine.iter().zip(&theirs).enumerate() {
        for k in 0..4 {
            // lopdf reads reals as f32.
            assert!(
                (m[k] - t[k]).abs() < 1e-3,
                "{name}: page {i} MediaBox {m:?} vs {t:?}"
            );
        }
    }
}

#[test]
fn agrees_with_lopdf_on_valid_hostile_controls() {
    if !common::ensure_hostile() {
        return;
    }
    let mut n = 0;
    for row in common::manifest() {
        // Structurally valid rows: the controls and the active-content files.
        if row[3] == "open" || row[3] == "open+remove" {
            let bytes = std::fs::read(common::hostile_dir().join(&row[0])).unwrap();
            agree(&row[0], &bytes);
            n += 1;
        }
    }
    assert!(n >= 7, "{n} files compared");
}

#[test]
fn agrees_with_lopdf_on_built_documents() {
    agree("classic, 7 pages", &classic(&pages(7), ""));

    let objs = vec![
        (1, b"<</Type/Catalog/Pages 2 0 R>>".to_vec()),
        (4, stream("/Filter/FlateDecode", &zlib(b"BT ET"))),
    ];
    let compressed = vec![
        (
            2,
            b"<</Type/Pages/Kids[3 0 R 7 0 R]/MediaBox[0 0 595.28 841.89]>>".to_vec(),
        ),
        (3, b"<</Type/Page/Parent 2 0 R/Contents 4 0 R>>".to_vec()),
        (
            7,
            b"<</Type/Pages/Parent 2 0 R/Kids[6 0 R]/MediaBox[100 100 -50 -50]>>".to_vec(),
        ),
        (6, b"<</Type/Page/Parent 7 0 R>>".to_vec()),
    ];
    agree(
        "xref stream, object stream, inheritance",
        &xref_stream_file(&objs, &compressed, 5),
    );

    let base = classic(&pages(2), "");
    let upd = common::append_update(
        &base,
        &[(
            3,
            b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 300 300]>>".to_vec(),
        )],
        7,
    );
    agree("incremental update", &upd);
}
