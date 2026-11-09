//! A tiny PDF builder for the stage 1C tests (after `casual-sign-pdf`'s test helper).

// Not every test binary uses every helper.
#![allow(dead_code)]
// Test code: a panic is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use casual_sign_fields::text::PageText;
use casual_sign_fields::{PageGeometry, Point, extract_text};
use casual_sign_pdf::{Limits, admit};

pub fn never() -> bool {
    false
}

/// An uncompressed stream object body.
pub fn stream(dict: &str, data: &[u8]) -> Vec<u8> {
    let mut v = format!("<<{dict}/Length {}>>\nstream\n", data.len()).into_bytes();
    v.extend_from_slice(data);
    v.extend_from_slice(b"\nendstream");
    v
}

/// A file with a classic xref. Object 1 is the root.
pub fn classic(objs: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut out = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n".to_vec();
    let mut offs = std::collections::BTreeMap::new();
    for (n, body) in objs {
        offs.insert(*n, out.len());
        out.extend_from_slice(format!("{n} 0 obj\n").as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    let size = offs.keys().max().unwrap() + 1;
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {size}\n0000000000 65535 f \n").as_bytes());
    for n in 1..size {
        match offs.get(&n) {
            Some(o) => out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes()),
            None => out.extend_from_slice(b"0000000000 65535 f \n"),
        }
    }
    out.extend_from_slice(
        format!("trailer\n<</Size {size}/Root 1 0 R>>\nstartxref\n{xref}\n%%EOF\n").as_bytes(),
    );
    out
}

/// One page: catalog 1 (with `catalog_extra`), pages 2, page 3 (with `page_extra`,
/// `/Resources` from `resources`), content 4; `extra` objects numbered from 5.
pub fn one_page(
    catalog_extra: &str,
    page_extra: &str,
    resources: &str,
    content: &[u8],
    extra: Vec<(u32, Vec<u8>)>,
) -> Vec<u8> {
    let mut objs = vec![
        (
            1,
            format!("<</Type/Catalog/Pages 2 0 R{catalog_extra}>>").into_bytes(),
        ),
        (2, b"<</Type/Pages/Kids[3 0 R]/Count 1>>".to_vec()),
        (
            3,
            format!(
                "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]{page_extra}/Resources<<{resources}>>/Contents 4 0 R>>"
            )
            .into_bytes(),
        ),
        (4, stream("", content)),
    ];
    objs.extend(extra);
    classic(&objs)
}

/// Write `bytes` to `$T1C_DUMP_DIR/name` when that variable is set (for the pypdf check).
pub fn dump(name: &str, bytes: &[u8]) {
    if let Some(dir) = std::env::var_os("T1C_DUMP_DIR") {
        let dir = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(name), bytes).unwrap();
    }
}

pub fn pages_with(bytes: &[u8], limits: &Limits) -> Vec<PageText> {
    let mut a = admit(bytes, limits, &never).unwrap();
    let pages = a.report.pages.clone();
    extract_text(&mut a.document, &pages, &never).unwrap()
}

pub fn pages(name: &str, bytes: &[u8]) -> Vec<PageText> {
    dump(name, bytes);
    pages_with(bytes, &Limits::default())
}

/// A font whose glyphs are all 500/1000 em wide except A (600) and B (700), with
/// ascent 0.8 and descent -0.2: easy arithmetic.
pub fn test_font() -> Vec<u8> {
    b"<</Type/Font/Subtype/TrueType/BaseFont/TestSans/FirstChar 65/LastChar 66/Widths[600 700]/Encoding/WinAnsiEncoding/FontDescriptor<</Type/FontDescriptor/FontName/TestSans/Ascent 800/Descent -200/MissingWidth 500/Flags 32>>>>".to_vec()
}

pub fn close(a: Point, b: Point) -> bool {
    (a.x - b.x).abs() <= 0.5 && (a.y - b.y).abs() <= 0.5
}

#[track_caller]
pub fn assert_near(got: Point, want: (f64, f64)) {
    assert!(
        close(got, Point::new(want.0, want.1)),
        "got ({:.3}, {:.3}), want {want:?}",
        got.x,
        got.y
    );
}

pub fn letter() -> PageGeometry {
    PageGeometry::new(
        casual_sign_pdf::Rect {
            llx: 0.0,
            lly: 0.0,
            urx: 612.0,
            ury: 792.0,
        },
        0,
        1.0,
    )
}
