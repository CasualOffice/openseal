//! Flattening (`T-1E`, docs/30 §7): the prefix invariant, determinism, every field type
//! in every rotation × crop × user unit, images, ink, fonts, and refusals.
//!
//! With `FLATTEN_DUMP_DIR` set, each output and its input are written there with a
//! `manifest.json` for `tools/check_render.py`, which renders them with PDFium and
//! extracts their text with pypdf (an independent renderer and reader).

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::collections::BTreeMap;

use casual_sign_flatten::{Art, Capture, FlattenInput, FlattenOptions, FontSet, NotDrawn, flatten};
use casual_sign_model::{
    Align, DateFormat, Field, FieldType, FieldValue, FontFamily, Format, Id, Rgb,
};
use casual_sign_pdf::{Limits, Object, admit, admit_strict};
use common::*;

const ENVELOPE: &str = "ENV-2026-0001";

/// One field of the sample set: the field, its value, whether it leaves ink, and the
/// text a reader should extract.
struct Sample {
    field: Field,
    value: Option<FieldValue>,
    ink: bool,
    text: Option<&'static str>,
}

fn sample(
    name: &str,
    t: FieldType,
    r: [f64; 4],
    value: Option<FieldValue>,
    ink: bool,
    text: Option<&'static str>,
) -> Sample {
    Sample {
        field: field(name, t, 1, r),
        value,
        ink,
        text,
    }
}

fn with_format(mut s: Sample, f: Format) -> Sample {
    s.field.format = Some(f);
    s
}

/// Every field type, with captures.
fn samples() -> (Vec<Sample>, BTreeMap<Id, Capture>) {
    let mut caps = BTreeMap::new();
    caps.insert(id("cap-drawn"), capture(Art::Drawn(ink(200))));
    caps.insert(
        id("cap-initials"),
        capture(Art::Typed {
            text: "AL".to_owned(),
            style: 0,
        }),
    );
    caps.insert(id("cap-png"), capture(Art::Image(png(60, 30))));
    caps.insert(
        id("cap-typed"),
        capture(Art::Typed {
            text: "Ada Lovelace".to_owned(),
            style: 1,
        }),
    );
    caps.insert(id("cap-exif"), capture(Art::Image(data("stamp-exif6.jpg"))));
    caps.insert(id("cap-cmyk"), capture(Art::Image(data("stamp-cmyk.jpg"))));
    caps.insert(id("cap-gray"), capture(Art::Image(data("stamp-gray.jpg"))));
    caps.insert(id("cap-rgb"), capture(Art::Image(data("stamp-rgb.jpg"))));
    let sig = |s: &str| Some(FieldValue::Signature(id(s)));
    let mut radio = sample(
        "radio",
        FieldType::RadioGroup,
        [40.0, 160.0, 140.0, 60.0],
        Some(choice("Beta")),
        true,
        Some("Beta"),
    );
    radio.field.options = options(&["Alpha", "Beta", "Gamma"]);
    let mut dropdown = sample(
        "dropdown",
        FieldType::Dropdown,
        [200.0, 160.0, 140.0, 24.0],
        Some(choice("Germany")),
        true,
        Some("Germany"),
    );
    dropdown.field.options = options(&["Germany", "France"]);
    let v = vec![
        sample(
            "name",
            FieldType::Name,
            [40.0, 40.0, 200.0, 24.0],
            Some(text("Ada Lovelace")),
            true,
            Some("Ada Lovelace"),
        ),
        with_format(
            sample(
                "email",
                FieldType::EmailAddress,
                [260.0, 40.0, 220.0, 24.0],
                Some(text("ada@example.org")),
                true,
                Some("ada@example.org"),
            ),
            Format {
                font_family: Some(FontFamily::Courier),
                align: Some(Align::Right),
                color: Some(Rgb([200, 0, 0])),
                ..Format::default()
            },
        ),
        with_format(
            sample(
                "note",
                FieldType::Text,
                [40.0, 80.0, 200.0, 60.0],
                Some(text(
                    "This longer value wraps across several lines inside its box, \
                     and an extraordinarilylongwordthatcannotfitonaline breaks.",
                )),
                true,
                Some("wraps"),
            ),
            Format {
                font_family: Some(FontFamily::Times),
                ..Format::default()
            },
        ),
        with_format(
            sample(
                "ssn",
                FieldType::Ssn,
                [260.0, 80.0, 120.0, 24.0],
                Some(text("123-45-6789")),
                true,
                None,
            ),
            Format {
                mask: true,
                ..Format::default()
            },
        ),
        sample(
            "agree",
            FieldType::Checkbox,
            [400.0, 80.0, 20.0, 20.0],
            Some(FieldValue::Checked(true)),
            true,
            None,
        ),
        radio,
        dropdown,
        with_format(
            sample(
                "signed-on",
                FieldType::DateSigned,
                [360.0, 160.0, 140.0, 24.0],
                Some(text("2026-11-10")),
                true,
                Some("10 Nov 2026"),
            ),
            Format {
                date_format: Some(DateFormat::DMmmYyyy),
                ..Format::default()
            },
        ),
        sample(
            "sig-drawn",
            FieldType::Signature,
            [40.0, 240.0, 200.0, 70.0],
            sig("cap-drawn"),
            true,
            Some("Signed by: Ada Lovelace"),
        ),
        sample(
            "initials",
            FieldType::Initials,
            [260.0, 240.0, 100.0, 50.0],
            sig("cap-initials"),
            true,
            Some("AL"),
        ),
        sample(
            "stamp-png",
            FieldType::Stamp,
            [380.0, 240.0, 120.0, 60.0],
            sig("cap-png"),
            true,
            None,
        ),
        sample(
            "sig-typed",
            FieldType::Signature,
            [40.0, 330.0, 220.0, 70.0],
            sig("cap-typed"),
            true,
            Some("Reason: Approval"),
        ),
        sample(
            "stamp-exif",
            FieldType::Stamp,
            [280.0, 330.0, 80.0, 80.0],
            sig("cap-exif"),
            true,
            None,
        ),
        sample(
            "envelope",
            FieldType::EnvelopeId,
            [380.0, 330.0, 140.0, 20.0],
            None,
            true,
            Some(ENVELOPE),
        ),
        with_format(
            sample(
                "amount",
                FieldType::Number,
                [380.0, 360.0, 60.0, 20.0],
                Some(text("1234567.89")),
                true,
                Some("1234567.89"),
            ),
            Format {
                font_size: Some(pts(20.0)),
                ..Format::default()
            },
        ),
        sample(
            "upload",
            FieldType::Attachment,
            [40.0, 420.0, 40.0, 20.0],
            Some(FieldValue::Attachment(id("file-1"))),
            false,
            None,
        ),
        sample(
            "unchecked",
            FieldType::Checkbox,
            [100.0, 420.0, 20.0, 20.0],
            Some(FieldValue::Checked(false)),
            false,
            None,
        ),
        sample(
            "stamp-cmyk",
            FieldType::Stamp,
            [140.0, 420.0, 80.0, 40.0],
            sig("cap-cmyk"),
            true,
            None,
        ),
        sample(
            "stamp-gray",
            FieldType::Stamp,
            [240.0, 420.0, 80.0, 40.0],
            sig("cap-gray"),
            true,
            None,
        ),
        sample(
            "link",
            FieldType::Hyperlink,
            [340.0, 420.0, 160.0, 20.0],
            Some(text("https://example.org")),
            true,
            Some("https://example.org"),
        ),
        sample(
            "stamp-rgb",
            FieldType::Stamp,
            [40.0, 470.0, 80.0, 40.0],
            sig("cap-rgb"),
            true,
            None,
        ),
        sample(
            "drawing",
            FieldType::Drawing,
            [140.0, 470.0, 100.0, 40.0],
            sig("cap-drawn"),
            true,
            None,
        ),
    ];
    (v, caps)
}

fn run(
    base: &[u8],
    fields: &[Field],
    values: &BTreeMap<Id, FieldValue>,
    caps: &BTreeMap<Id, Capture>,
    options: &FlattenOptions,
) -> Result<casual_sign_flatten::Flattened, casual_sign_flatten::FlattenError> {
    let mut a = admit(base, &Limits::default(), &never).unwrap();
    let input = FlattenInput {
        fields,
        values,
        captures: caps,
        envelope_id: Some(ENVELOPE),
        acroform: None,
    };
    flatten(&mut a, &input, &FontSet::bundled(), options, &never)
}

fn values_of(s: &[Sample]) -> BTreeMap<Id, FieldValue> {
    s.iter()
        .filter_map(|s| s.value.clone().map(|v| (s.field.id.clone(), v)))
        .collect()
}

#[test]
fn every_field_type_in_every_rotation_crop_and_user_unit() {
    let (samples, caps) = samples();
    let fields: Vec<Field> = samples.iter().map(|s| s.field.clone()).collect();
    let values = values_of(&samples);
    let mut manifest = Vec::new();
    for case in cases() {
        let base = delivered(&page_pdf(&case, "", "", Vec::new()));
        let out = run(&base, &fields, &values, &caps, &FlattenOptions::default()).unwrap();
        // The prefix invariant (docs/30 §1).
        assert!(out.bytes.starts_with(&base), "{}", case.name());
        // Re-admitted strictly: one more revision, same pages.
        let a = admit_strict(&out.bytes, &Limits::default(), &never).unwrap();
        assert_eq!(a.report.revisions.len(), 2);
        assert_eq!(a.report.page_count, 1);
        let r = &out.report;
        assert_eq!(
            r.not_drawn,
            vec![
                (id("upload"), NotDrawn::NoVisual),
                (id("unchecked"), NotDrawn::NoValue)
            ]
        );
        assert_eq!(r.drawn.len(), samples.len() - 2);
        assert!(r.shrunk.contains(&id("amount")), "{:?}", r.shrunk);
        assert_eq!(r.images, 5);
        // Sans, Serif, Mono and both script faces.
        assert_eq!(r.fonts.len(), 5, "{:?}", r.fonts);
        assert!(
            r.fonts
                .iter()
                .all(|f| f.base_font.len() > 7 && f.base_font.as_bytes()[6] == b'+')
        );
        let name = case.name();
        dump(&format!("{name}.in.pdf"), &base);
        dump(&format!("{name}.out.pdf"), &out.bytes);
        let (w, h) = case.displayed();
        let fields_json: Vec<String> = samples
            .iter()
            .map(|s| {
                let p = &s.field.placement;
                let f = |v: casual_sign_model::Points| v.get().to_string();
                format!(
                    "{{\"id\":{},\"rect\":[{},{},{},{}],\"ink\":{}}}",
                    js(s.field.id.as_str()),
                    f(p.x()),
                    f(p.y()),
                    f(p.width()),
                    f(p.height()),
                    s.ink
                )
            })
            .collect();
        let texts: Vec<String> = samples.iter().filter_map(|s| s.text).map(js).collect();
        manifest.push(format!(
            "{{\"name\":{},\"in\":{},\"out\":{},\"size\":[{w},{h}],\"fields\":[{}],\"texts\":[{}]}}",
            js(&name),
            js(&format!("{name}.in.pdf")),
            js(&format!("{name}.out.pdf")),
            fields_json.join(","),
            texts.join(",")
        ));
    }
    if dump_dir().is_some() {
        dump(
            "manifest.json",
            format!("[\n{}\n]\n", manifest.join(",\n")).as_bytes(),
        );
    }
}

#[test]
fn the_same_input_gives_the_same_bytes() {
    let (samples, caps) = samples();
    let fields: Vec<Field> = samples.iter().map(|s| s.field.clone()).collect();
    let values = values_of(&samples);
    let base = delivered(&page_pdf(&cases()[5], "", "", Vec::new()));
    let a = run(&base, &fields, &values, &caps, &FlattenOptions::default()).unwrap();
    let b = run(&base, &fields, &values, &caps, &FlattenOptions::default()).unwrap();
    assert_eq!(a.bytes, b.bytes);
}

#[test]
fn the_output_starts_with_the_delivered_bytes_for_a_classic_xref_too() {
    // Not normalized: a classic table, so the update appends a table.
    let base = page_pdf(&cases()[0], "", "", Vec::new());
    let f = field("n", FieldType::Text, 1, [10.0, 10.0, 100.0, 20.0]);
    let values = BTreeMap::from([(id("n"), text("x"))]);
    let out = run(
        &base,
        &[f],
        &values,
        &BTreeMap::new(),
        &FlattenOptions::default(),
    )
    .unwrap();
    assert!(out.bytes.starts_with(&base));
    let tail = String::from_utf8_lossy(&out.bytes[base.len()..]).into_owned();
    assert!(
        tail.contains("\nxref\n") || tail.starts_with("xref\n"),
        "{tail}"
    );
}

#[test]
fn text_is_embedded_as_a_subset_with_widths_and_to_unicode() {
    let base = delivered(&page_pdf(&cases()[0], "", "", Vec::new()));
    let f = field("n", FieldType::Text, 1, [10.0, 10.0, 200.0, 20.0]);
    let values = BTreeMap::from([(id("n"), text("Zoë"))]);
    let out = run(
        &base,
        &[f],
        &values,
        &BTreeMap::new(),
        &FlattenOptions::default(),
    )
    .unwrap();
    let mut a = admit(&out.bytes, &Limits::default(), &never).unwrap();
    let mut found = (false, false, false);
    let nums: Vec<u32> = a.document.object_numbers().collect();
    for n in nums {
        let o = a.document.object(n, &never).unwrap();
        let Some(d) = o.dict() else { continue };
        if d.name(b"Subtype") == Some(b"Type0") {
            found.0 = d.get(b"ToUnicode").is_some();
        }
        if d.name(b"Subtype") == Some(b"CIDFontType2") {
            found.1 = matches!(d.get(b"W"), Some(Object::Array(w)) if w.len() == 6);
        }
        if let Some(Object::Reference(r)) = d.get(b"FontFile2") {
            let program = a.document.decode_stream(r.num, &never).unwrap();
            // A subset: far smaller than the 400 KB face.
            found.2 = program.len() < 60_000;
        }
    }
    assert_eq!(found, (true, true, true));
}

#[test]
fn a_character_in_no_bundled_face_is_cs_flt_0001_not_a_panic_or_a_gap() {
    let base = delivered(&page_pdf(&cases()[0], "", "", Vec::new()));
    let f = field("n", FieldType::Text, 1, [10.0, 10.0, 200.0, 20.0]);
    let values = BTreeMap::from([(id("n"), text("契約"))]);
    let e = run(
        &base,
        &[f],
        &values,
        &BTreeMap::new(),
        &FlattenOptions::default(),
    )
    .unwrap_err();
    assert_eq!(e.code(), "CS-FLT-0001");
}

#[test]
fn a_value_that_does_not_suit_its_field_is_refused() {
    let base = delivered(&page_pdf(&cases()[0], "", "", Vec::new()));
    let f = field("n", FieldType::Text, 1, [10.0, 10.0, 200.0, 20.0]);
    let values = BTreeMap::from([(id("n"), FieldValue::Checked(true))]);
    let e = run(
        &base,
        std::slice::from_ref(&f),
        &values,
        &BTreeMap::new(),
        &FlattenOptions::default(),
    );
    assert_eq!(e.unwrap_err().code(), "CS-FLD-0002");
    let s = field("s", FieldType::Signature, 1, [10.0, 10.0, 200.0, 20.0]);
    let values = BTreeMap::from([(id("s"), FieldValue::Signature(id("missing")))]);
    let e = run(
        &base,
        &[s],
        &values,
        &BTreeMap::new(),
        &FlattenOptions::default(),
    );
    assert_eq!(e.unwrap_err().code(), "CS-FLD-0005");
    let off = field("o", FieldType::Text, 2, [10.0, 10.0, 200.0, 20.0]);
    let values = BTreeMap::from([(id("o"), text("x"))]);
    let e = run(
        &base,
        &[off],
        &values,
        &BTreeMap::new(),
        &FlattenOptions::default(),
    );
    assert_eq!(e.unwrap_err().code(), "CS-FLD-0004");
}

#[test]
fn jpeg_metadata_is_dropped_and_its_orientation_applied() {
    let base = delivered(&page_pdf(&cases()[0], "", "", Vec::new()));
    let f = field("s", FieldType::Stamp, 1, [10.0, 10.0, 100.0, 100.0]);
    let values = BTreeMap::from([(id("s"), FieldValue::Signature(id("c")))]);
    let raw = data("stamp-exif6.jpg");
    assert!(raw.windows(4).any(|w| w == b"Exif"));
    let caps = BTreeMap::from([(id("c"), capture(Art::Image(raw)))]);
    let out = run(&base, &[f], &values, &caps, &FlattenOptions::default()).unwrap();
    let tail = &out.bytes[base.len()..];
    assert!(
        !tail.windows(4).any(|w| w == b"Exif"),
        "EXIF reached the PDF"
    );
    // Orientation 6: the image's unit square is turned a quarter.
    let mut a = admit(&out.bytes, &Limits::default(), &never).unwrap();
    let nums: Vec<u32> = a.document.object_numbers().collect();
    let mut turned = false;
    for n in nums {
        if let Ok(Object::Stream(s)) = a.document.object(n, &never)
            && s.dict.name(b"Subtype") == Some(b"Form")
        {
            let ops = a.document.decode_stream(n, &never).unwrap();
            turned |= String::from_utf8_lossy(&ops).contains("0 -1 1 0 0 1 cm");
        }
    }
    assert!(turned);
}

/// The baselines (`Tm` y, in the field's own box) of the text drawn in `out`'s forms.
fn baselines(out: &[u8]) -> Vec<f64> {
    let mut a = admit(out, &Limits::default(), &never).unwrap();
    let nums: Vec<u32> = a.document.object_numbers().collect();
    let mut ys = Vec::new();
    for n in nums {
        if let Ok(Object::Stream(s)) = a.document.object(n, &never)
            && s.dict.name(b"Subtype") == Some(b"Form")
        {
            let ops = a.document.decode_stream(n, &never).unwrap();
            for line in String::from_utf8_lossy(&ops).lines() {
                let w: Vec<&str> = line.split_whitespace().collect();
                if w.len() == 7 && w[6] == "Tm" {
                    ys.push(w[5].parse::<f64>().unwrap());
                }
            }
        }
    }
    ys
}

#[test]
fn a_multi_line_text_field_draws_each_line_from_the_top_of_its_box() {
    // FG-057 (S1-01): the signer's line breaks are kept, one baseline per line, and a
    // multi-line box is read from its top even when the value is one line, as the
    // signer saw it in the ceremony's text area.
    let base = delivered(&page_pdf(&cases()[0], "", "", Vec::new()));
    let multi = |name: &str| {
        let mut f = field(name, FieldType::Text, 1, [40.0, 40.0, 200.0, 120.0]);
        f.format = Some(Format {
            multiline: true,
            ..Format::default()
        });
        f
    };
    let three = BTreeMap::from([(id("m"), text("Line one\nLine two\r\nLine three"))]);
    let out = run(
        &base,
        &[multi("m")],
        &three,
        &BTreeMap::new(),
        &FlattenOptions::default(),
    )
    .unwrap();
    let ys = baselines(&out.bytes);
    assert_eq!(ys.len(), 3, "one baseline per line: {ys:?}");
    assert!(ys.windows(2).all(|p| p[0] > p[1]), "lines run down: {ys:?}");
    assert!(ys[0] > 90.0, "the first line is at the top: {ys:?}");

    let one = BTreeMap::from([(id("m"), text("Only line"))]);
    let out = run(
        &base,
        &[multi("m")],
        &one,
        &BTreeMap::new(),
        &FlattenOptions::default(),
    )
    .unwrap();
    let ys = baselines(&out.bytes);
    assert_eq!(ys.len(), 1, "{ys:?}");
    assert!(
        ys[0] > 90.0,
        "a one-line value in a multi-line box sits at its top: {ys:?}"
    );

    // A single-line box keeps its one line in the middle.
    let single = field("s", FieldType::Text, 1, [40.0, 40.0, 200.0, 120.0]);
    let one = BTreeMap::from([(id("s"), text("Only line"))]);
    let out = run(
        &base,
        &[single],
        &one,
        &BTreeMap::new(),
        &FlattenOptions::default(),
    )
    .unwrap();
    let ys = baselines(&out.bytes);
    assert!(ys.len() == 1 && ys[0] < 70.0, "{ys:?}");
}
