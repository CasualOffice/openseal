//! Builders for the stage 1E tests: small PDFs in every rotation, crop and user unit,
//! fields of every type, captures, and a dump for the independent render check.

// Not every test binary uses every helper.
#![allow(dead_code)]
// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use casual_sign_flatten::{Art, Capture, Ink, InkPoint};
use casual_sign_model::{
    Field, FieldOptions, FieldType, FieldValue, Format, Id, Placement, Points, Text,
};
use casual_sign_pdf::{Limits, NormalizeOptions, OutputXref, admit, normalize};
use rust_decimal::Decimal;

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
    let mut offs = BTreeMap::new();
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

/// A page's geometry for the matrix of cases.
#[derive(Debug, Clone, Copy)]
pub struct PageCase {
    pub rotate: i64,
    /// Crop box, or `None` for the media box.
    pub crop: Option<[f64; 4]>,
    pub user_unit: f64,
}

impl PageCase {
    pub fn name(&self) -> String {
        format!(
            "rot{}-{}-uu{}",
            self.rotate,
            if self.crop.is_some() {
                "crop"
            } else {
                "nocrop"
            },
            self.user_unit
        )
    }

    /// Displayed size in points.
    pub fn displayed(&self) -> (f64, f64) {
        let [x0, y0, x1, y1] = self.crop.unwrap_or([0.0, 0.0, 612.0, 792.0]);
        let (w, h) = ((x1 - x0) * self.user_unit, (y1 - y0) * self.user_unit);
        if self.rotate % 180 == 0 {
            (w, h)
        } else {
            (h, w)
        }
    }
}

/// Every rotation, with and without an offset crop box, and a user unit of 1 and 1.5.
pub fn cases() -> Vec<PageCase> {
    let mut out = Vec::new();
    for rotate in [0, 90, 180, 270] {
        for crop in [None, Some([36.0, 72.0, 576.0, 756.0])] {
            for user_unit in [1.0, 1.5] {
                out.push(PageCase {
                    rotate,
                    crop,
                    user_unit,
                });
            }
        }
    }
    out
}

/// A blank one-page document in `case`'s geometry, with `extra_page` in the page and
/// `catalog_extra` in the catalog; `extra` objects from 5.
pub fn page_pdf(
    case: &PageCase,
    catalog_extra: &str,
    page_extra: &str,
    extra: Vec<(u32, Vec<u8>)>,
) -> Vec<u8> {
    let crop = case
        .crop
        .map(|[a, b, c, d]| format!("/CropBox[{a} {b} {c} {d}]"))
        .unwrap_or_default();
    let uu = if case.user_unit == 1.0 {
        String::new()
    } else {
        format!("/UserUnit {}", case.user_unit)
    };
    let mut objs = vec![
        (
            1,
            format!("<</Type/Catalog/Pages 2 0 R{catalog_extra}>>").into_bytes(),
        ),
        (2, b"<</Type/Pages/Kids[3 0 R]/Count 1>>".to_vec()),
        (
            3,
            format!(
                "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]{crop}/Rotate {}{uu}{page_extra}/Resources<<>>/Contents 4 0 R>>",
                case.rotate
            )
            .into_bytes(),
        ),
        // Unbalanced on purpose: a `q` without its `Q` must not shift our marks.
        (4, stream("", b"q 2 0 0 2 0 0 cm\n")),
    ];
    objs.extend(extra);
    classic(&objs)
}

/// `bytes` normalized, as the bytes delivered to signers would be.
pub fn delivered(bytes: &[u8]) -> Vec<u8> {
    let mut a = admit(bytes, &Limits::default(), &never).unwrap();
    normalize(
        &mut a,
        &NormalizeOptions::with_xref(OutputXref::Stream),
        &never,
    )
    .unwrap()
    .bytes
}

pub fn pts(v: f64) -> Points {
    Points::new(Decimal::try_from(v).unwrap().round_dp(4)).unwrap()
}

pub fn id(s: &str) -> Id {
    Id::new(s).unwrap()
}

pub fn field(name: &str, t: FieldType, page: u32, r: [f64; 4]) -> Field {
    let p = Placement::new(page, pts(r[0]), pts(r[1]), pts(r[2]), pts(r[3])).unwrap();
    Field::new(id(name), id("doc"), t, p)
}

pub fn text(s: &str) -> FieldValue {
    FieldValue::Text(Text::new(s).unwrap())
}

pub fn choice(s: &str) -> FieldValue {
    FieldValue::Choice(Text::new(s).unwrap())
}

pub fn options(list: &[&str]) -> FieldOptions {
    FieldOptions::new(list.iter().map(|s| Text::new(*s).unwrap()).collect()).unwrap()
}

/// A wavy signature of `n` points over one stroke.
pub fn ink(n: usize) -> Ink {
    let pts = (0..n)
        .map(|i| {
            let t = i as f64 / n.max(2) as f64;
            InkPoint {
                x: t * 300.0,
                y: 60.0 + 40.0 * (t * 12.0).sin(),
            }
        })
        .collect();
    Ink {
        strokes: vec![
            pts,
            vec![
                InkPoint { x: 20.0, y: 110.0 },
                InkPoint { x: 280.0, y: 115.0 },
            ],
        ],
        color: None,
    }
}

pub fn capture(art: Art) -> Capture {
    Capture {
        art,
        signed_by: Some("Ada Lovelace".to_owned()),
        reason: Some("Approval".to_owned()),
    }
}

/// A `w` × `h` RGBA PNG: a dark bar on transparency.
pub fn png(w: u32, h: u32) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut e = png::Encoder::new(&mut out, w, h);
        e.set_color(png::ColorType::Rgba);
        e.set_depth(png::BitDepth::Eight);
        let mut wr = e.write_header().unwrap();
        let mut data = vec![0u8; (w * h * 4) as usize];
        for y in 0..h {
            for x in 0..w {
                let i = ((y * w + x) * 4) as usize;
                let inside = y > h / 4 && y < h - h / 4 && x > w / 8 && x < w - w / 8;
                if inside {
                    data[i..i + 4].copy_from_slice(&[10, 60, 10, 255]);
                }
            }
        }
        wr.write_image_data(&data).unwrap();
    }
    out
}

pub fn data(name: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name);
    std::fs::read(p).unwrap()
}

pub fn format() -> Format {
    Format::default()
}

/// Where the render check reads: `$FLATTEN_DUMP_DIR`, when set.
pub fn dump_dir() -> Option<PathBuf> {
    std::env::var_os("FLATTEN_DUMP_DIR").map(PathBuf::from)
}

pub fn dump(name: &str, bytes: &[u8]) {
    if let Some(dir) = dump_dir() {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(name), bytes).unwrap();
    }
}

/// JSON string escaping for the manifest.
pub fn js(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// A sample value for every converted field: text, the box checked, the first option,
/// a drawn signature.
pub fn fill_all(
    conv: &casual_sign_fields::Conversion,
) -> (BTreeMap<Id, FieldValue>, BTreeMap<Id, Capture>) {
    let mut values = BTreeMap::new();
    let mut caps = BTreeMap::new();
    caps.insert(id("cap-sig"), capture(Art::Drawn(ink(120))));
    for c in &conv.fields {
        let f = &c.field;
        let v = match f.field_type {
            FieldType::Checkbox => FieldValue::Checked(true),
            FieldType::RadioGroup | FieldType::Dropdown => match f.options.as_slice().first() {
                Some(o) => FieldValue::Choice(o.clone()),
                None => continue,
            },
            FieldType::Signature => FieldValue::Signature(id("cap-sig")),
            _ => text("Sample 42"),
        };
        values.insert(f.id.clone(), v);
    }
    (values, caps)
}

/// Mint ids `f0`, `f1`, … for a conversion.
pub fn minter() -> impl FnMut() -> Id {
    let mut n = 0u32;
    move || {
        n += 1;
        id(&format!("f{n}"))
    }
}
