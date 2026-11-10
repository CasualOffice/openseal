//! Flatten and fill real AcroForm documents from the corpus (`T-1E`, `FILL-01`).
//!
//! ```sh
//! cargo run -p casual-sign-flatten --example flatten_corpus -- \
//!     <corpus files dir> fixtures/corpus/manifest.tsv <out dir> [count]
//! ```
//!
//! Takes the first `count` (default 20) files the manifest marks `acroform` and not
//! `signed`, `certified`, `encrypted` or `usage-rights` (a usage-rights dictionary is a
//! signature over the form). Each is normalized as on delivery, its form converted,
//! every field given a sample value, then flattened and filled in place. Outputs and a
//! `manifest-corpus.json` for `tools/check_render.py` (first pages) go to the out dir;
//! a line per file and a summary go to stdout. A panic is caught and counted: there
//! must be none.

// A tool, not product code: a failure is reported by name and the run continues.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};

use casual_sign_fields::{Conversion, DisplayRect, convert_acroform};
use casual_sign_flatten::{
    Art, Capture, FlattenInput, FlattenOptions, FontSet, FormMode, Ink, InkPoint, flatten,
};
use casual_sign_model::{FieldType, FieldValue, Id, Text};
use casual_sign_pdf::{Limits, NormalizeOptions, Object, OutputXref, admit, normalize};

fn never() -> bool {
    false
}

fn js(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let _ = write!(o, "\\u{:04x}", c as u32);
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn ink() -> Ink {
    let pts = (0..80)
        .map(|i| {
            let t = f64::from(i) / 80.0;
            InkPoint {
                x: t * 300.0,
                y: 60.0 + 40.0 * (t * 12.0).sin(),
            }
        })
        .collect();
    Ink {
        strokes: vec![pts],
        color: None,
    }
}

const SAMPLE: &str = "Sample 42";

fn values(conv: &Conversion) -> BTreeMap<Id, FieldValue> {
    let mut out = BTreeMap::new();
    for c in &conv.fields {
        let f = &c.field;
        let v = match f.field_type {
            FieldType::Checkbox => FieldValue::Checked(true),
            FieldType::RadioGroup | FieldType::Dropdown => match f.options.as_slice().first() {
                Some(o) => FieldValue::Choice(o.clone()),
                None => continue,
            },
            FieldType::Signature => FieldValue::Signature(Id::new("cap").unwrap()),
            _ => FieldValue::Text(Text::new(SAMPLE).unwrap()),
        };
        out.insert(f.id.clone(), v);
    }
    out
}

/// What happened to one file.
struct Outcome {
    line: String,
    entries: Vec<String>,
    ok: bool,
}

fn entry(
    name: &str,
    input: &str,
    output: &str,
    size: (f64, f64),
    fields: &[(String, DisplayRect, &str)],
    fill: Option<&[(String, String)]>,
) -> String {
    let f: Vec<String> = fields
        .iter()
        .map(|(id, r, ink)| {
            format!(
                "{{\"id\":{},\"rect\":[{},{},{},{}],\"ink\":{ink}}}",
                js(id),
                r.x,
                r.y,
                r.width,
                r.height
            )
        })
        .collect();
    let extra = match fill {
        Some(v) => {
            let vals: Vec<String> = v
                .iter()
                .map(|(k, v)| format!("{}:{}", js(k), js(v)))
                .collect();
            format!(",\"fill\":true,\"values\":{{{}}}", vals.join(","))
        }
        None => String::new(),
    };
    format!(
        "{{\"name\":{},\"in\":{},\"out\":{},\"size\":[{},{}],\"fields\":[{}],\"texts\":[],\"corpus\":true{extra}}}",
        js(name),
        js(input),
        js(output),
        size.0,
        size.1,
        f.join(",")
    )
}

fn one(path: &Path, out: &Path, name: &str) -> Result<Outcome, String> {
    let raw = std::fs::read(path).map_err(|e| format!("read: {e}"))?;
    let mut a = admit(&raw, &Limits::default(), &never).map_err(|e| format!("admit: {e}"))?;
    let delivered = normalize(
        &mut a,
        &NormalizeOptions::with_xref(OutputXref::Stream),
        &never,
    )
    .map_err(|e| format!("normalize: {e}"))?
    .bytes;
    let mut a =
        admit(&delivered, &Limits::default(), &never).map_err(|e| format!("re-admit: {e}"))?;
    let report = a.report.clone();
    let mut n = 0u32;
    let mut next = || {
        n += 1;
        Id::new(format!("f{n}")).unwrap()
    };
    let conv = convert_acroform(
        &mut a.document,
        &report,
        &Id::new("doc").unwrap(),
        &mut next,
        &never,
    )
    .map_err(|e| format!("convert: {e}"))?;
    let vals = values(&conv);
    let caps = BTreeMap::from([(
        Id::new("cap").unwrap(),
        Capture {
            art: Art::Drawn(ink()),
            signed_by: Some("Sample Signer".to_owned()),
            reason: None,
        },
    )]);
    let fields: Vec<_> = conv.fields.iter().map(|c| c.field.clone()).collect();
    let input = FlattenInput {
        fields: &fields,
        values: &vals,
        captures: &caps,
        envelope_id: Some("ENV-CORPUS"),
        acroform: Some(&conv),
    };
    let fonts = FontSet::bundled();
    let flat = flatten(&mut a, &input, &fonts, &FlattenOptions::default(), &never)
        .map_err(|e| format!("flatten: {e}"))?;
    if !flat.bytes.starts_with(&delivered) {
        return Err("flatten: prefix violated".to_owned());
    }
    let mut a = admit(&delivered, &Limits::default(), &never).unwrap();
    let mut options = FlattenOptions::default();
    options.mode = FormMode::FillInPlace;
    let filled =
        flatten(&mut a, &input, &fonts, &options, &never).map_err(|e| format!("fill: {e}"))?;
    if !filled.bytes.starts_with(&delivered) {
        return Err("fill: prefix violated".to_owned());
    }
    // Re-admission: flattened has no live field; filled keeps every field.
    let b = admit(&flat.bytes, &Limits::default(), &never)
        .map_err(|e| format!("re-admit flattened: {e}"))?;
    let c = admit(&filled.bytes, &Limits::default(), &never)
        .map_err(|e| format!("re-admit filled: {e}"))?;
    let live_after_flat = b.report.fields.len();
    let kept_after_fill = c.report.fields.len() == report.fields.len();

    std::fs::write(out.join(format!("{name}.in.pdf")), &delivered).unwrap();
    std::fs::write(out.join(format!("{name}.flat.pdf")), &flat.bytes).unwrap();
    std::fs::write(out.join(format!("{name}.fill.pdf")), &filled.bytes).unwrap();

    // First page: the fields with a value there.
    let size = report.pages.first().map_or((612.0, 792.0), |p| {
        casual_sign_fields::PageGeometry::from_page(p).displayed_size()
    });
    let mut on_first: Vec<(String, DisplayRect, &str)> = fields
        .iter()
        .filter(|f| f.placement.page() == 1 && vals.contains_key(&f.id))
        .map(|f| {
            (
                f.id.as_str().to_owned(),
                DisplayRect::from_placement(&f.placement),
                "true",
            )
        })
        .collect();
    // Every widget on the first page: flattening removes it, so a viewer's own drawing
    // of it may change there (ink not asserted: "null").
    if let Some(p) = report.pages.first() {
        let g = casual_sign_fields::PageGeometry::from_page(p);
        let mut d = admit(&delivered, &Limits::default(), &never).unwrap();
        if let Ok(Object::Dictionary(page)) = d.document.object(p.object, &never)
            && let Some(annots) = page.get(b"Annots").cloned()
            && let Ok(Object::Array(items)) = d.document.resolve(&annots, &never)
        {
            for item in items {
                let Ok(o) = d.document.resolve(&item, &never) else {
                    continue;
                };
                let Some(a) = o.dict() else { continue };
                if a.name(b"Subtype") != Some(b"Widget") {
                    continue;
                }
                let Some(Object::Array(r)) = a.get(b"Rect") else {
                    continue;
                };
                let n: Vec<f64> = r.iter().filter_map(Object::as_f64).collect();
                if let [x0, y0, x1, y1] = n.as_slice() {
                    let rect = casual_sign_pdf::Rect {
                        llx: x0.min(*x1),
                        lly: y0.min(*y1),
                        urx: x0.max(*x1),
                        ury: y0.max(*y1),
                    };
                    on_first.push(("widget".to_owned(), g.rect_to_displayed(&rect), "null"));
                }
            }
        }
    }
    let text_values: Vec<(String, String)> = conv
        .fields
        .iter()
        .filter(|c| c.field.field_type == FieldType::Text && c.field.placement.page() == 1)
        .filter_map(|c| {
            let obj = c.object?;
            let f = report.fields.iter().find(|f| f.object == Some(obj))?;
            matches!(f.field_type, casual_sign_pdf::FieldType::Text)
                .then(|| (f.name.clone(), SAMPLE.to_owned()))
        })
        .collect();
    let entries = vec![
        entry(
            &format!("{name}-flat"),
            &format!("{name}.in.pdf"),
            &format!("{name}.flat.pdf"),
            size,
            &on_first,
            None,
        ),
        entry(
            &format!("{name}-fill"),
            &format!("{name}.in.pdf"),
            &format!("{name}.fill.pdf"),
            size,
            &on_first,
            Some(&text_values),
        ),
    ];
    let r = &flat.report;
    let line = format!(
        "ok   {name}: {} pdf fields, {} converted ({} skipped, {} lossy); flattened: {} drawn, {} not drawn, {} shrunk, {} overflow, {} widgets removed, {} appearances kept, {} live fields after; filled: {} in place, {} drawn, fields kept {}",
        report.fields.len(),
        conv.fields.len(),
        conv.skipped.len(),
        conv.lossy.len(),
        r.drawn.len(),
        r.not_drawn.len(),
        r.shrunk.len(),
        r.overflow.len(),
        r.widgets_removed,
        r.appearances_kept,
        live_after_flat,
        filled.report.filled.len(),
        filled.report.drawn.len(),
        kept_after_fill
    );
    Ok(Outcome {
        line,
        entries,
        ok: live_after_flat == 0 && kept_after_fill,
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (dir, manifest, out) = (
        PathBuf::from(&args[1]),
        PathBuf::from(&args[2]),
        PathBuf::from(&args[3]),
    );
    let count: usize = args.get(4).map_or(20, |c| c.parse().unwrap());
    std::fs::create_dir_all(&out).unwrap();
    let tsv = std::fs::read_to_string(manifest).unwrap();
    let mut picked = Vec::new();
    for line in tsv.lines().skip(1) {
        let cols: Vec<&str> = line.split('\t').collect();
        let (Some(file), Some(features)) = (cols.first(), cols.get(9)) else {
            continue;
        };
        let feats: Vec<&str> = features.split(',').collect();
        let excluded = ["signed", "certified", "encrypted", "usage-rights"];
        if feats.contains(&"acroform") && !feats.iter().any(|f| excluded.contains(f)) {
            picked.push((*file).to_owned());
        }
        if picked.len() == count {
            break;
        }
    }
    // Panics are caught and counted; keep the default hook from printing each.
    std::panic::set_hook(Box::new(|_| {}));
    let (mut ok, mut failed, mut panics) = (0, 0, 0);
    let mut entries = Vec::new();
    for file in &picked {
        let name = file.trim_end_matches(".pdf");
        let r = catch_unwind(AssertUnwindSafe(|| one(&dir.join(file), &out, name)));
        match r {
            Ok(Ok(o)) => {
                println!("{}", o.line);
                entries.extend(o.entries);
                if o.ok {
                    ok += 1;
                } else {
                    failed += 1;
                    println!(
                        "     {name}: live fields after flattening, or fields lost by filling"
                    );
                }
            }
            Ok(Err(reason)) => {
                failed += 1;
                println!("FAIL {name}: {reason}");
            }
            Err(_) => {
                panics += 1;
                println!("PANIC {name}");
            }
        }
    }
    std::fs::write(
        out.join("manifest-corpus.json"),
        format!("[\n{}\n]\n", entries.join(",\n")),
    )
    .unwrap();
    println!(
        "{} files: {ok} flattened and filled, {failed} failed, {panics} panics",
        picked.len()
    );
}
