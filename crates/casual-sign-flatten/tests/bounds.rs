//! Every bound of flattening (docs/21): crossed by one gives its code, met exactly is
//! drawn. Each test was seen failing with its guard removed (`T-1E` report).

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

use casual_sign_flatten::limits::{
    MAX_FIELDS_PER_PAGE, MAX_IMAGE_BYTES, MAX_IMAGE_SIDE, MAX_INK_POINTS, MAX_TEXT_BYTES,
};
use casual_sign_flatten::{
    Art, Capture, FlattenError, FlattenInput, FlattenOptions, Flattened, FontSet, Ink, InkPoint,
    flatten,
};
use casual_sign_model::{Field, FieldType, FieldValue, Id};
use casual_sign_pdf::{Limits, admit};
use common::*;

fn base() -> Vec<u8> {
    delivered(&page_pdf(&cases()[0], "", "", Vec::new()))
}

fn sign_with(art: Art, signed_by: Option<String>) -> Result<Flattened, FlattenError> {
    let base = base();
    let mut a = admit(&base, &Limits::default(), &never).unwrap();
    let f = field("s", FieldType::Signature, 1, [10.0, 10.0, 200.0, 60.0]);
    let values = BTreeMap::from([(id("s"), FieldValue::Signature(id("c")))]);
    let caps = BTreeMap::from([(
        id("c"),
        Capture {
            art,
            signed_by,
            reason: None,
        },
    )]);
    let input = FlattenInput {
        fields: std::slice::from_ref(&f),
        values: &values,
        captures: &caps,
        envelope_id: None,
        acroform: None,
    };
    flatten(
        &mut a,
        &input,
        &FontSet::bundled(),
        &FlattenOptions::default(),
        &never,
    )
}

#[test]
fn an_image_wider_than_the_cap_is_cs_flt_0002() {
    let e = sign_with(Art::Image(png(MAX_IMAGE_SIDE + 1, 1)), None).unwrap_err();
    assert_eq!(e.code(), "CS-FLT-0002");
    sign_with(Art::Image(png(MAX_IMAGE_SIDE, 1)), None).unwrap();
}

#[test]
fn an_image_taller_than_the_cap_is_cs_flt_0002() {
    let e = sign_with(Art::Image(png(1, MAX_IMAGE_SIDE + 1)), None).unwrap_err();
    assert_eq!(e.code(), "CS-FLT-0002");
}

#[test]
fn an_upload_over_five_mib_is_cs_flt_0002_before_any_decoding() {
    let mut big = png(4, 4);
    big.resize(MAX_IMAGE_BYTES + 1, 0);
    let e = sign_with(Art::Image(big), None).unwrap_err();
    assert_eq!(e.code(), "CS-FLT-0002");
}

#[test]
fn an_undecodable_image_is_cs_flt_0003() {
    let mut bad = png(8, 8);
    let n = bad.len();
    bad.truncate(n - 20);
    let e = sign_with(Art::Image(bad), None).unwrap_err();
    assert_eq!(e.code(), "CS-FLT-0003");
    let e = sign_with(Art::Image(b"GIF89a....".to_vec()), None).unwrap_err();
    assert_eq!(e.code(), "CS-FLT-0003");
}

fn ink_of(points: usize) -> Ink {
    let half = points / 2;
    let stroke = |n: usize, y: f64| -> Vec<InkPoint> {
        (0..n)
            .map(|i| InkPoint {
                x: i as f64,
                y: y + (i % 7) as f64,
            })
            .collect()
    };
    Ink {
        strokes: vec![stroke(half, 0.0), stroke(points - half, 20.0)],
        color: None,
    }
}

#[test]
fn a_drawn_signature_over_the_point_cap_is_cs_fld_0002() {
    let e = sign_with(Art::Drawn(ink_of(MAX_INK_POINTS + 1)), None).unwrap_err();
    assert_eq!(e.code(), "CS-FLD-0002");
    assert!(
        matches!(e, FlattenError::TooManyPoints { points, .. } if points == MAX_INK_POINTS + 1)
    );
    sign_with(Art::Drawn(ink_of(MAX_INK_POINTS)), None).unwrap();
}

#[test]
fn a_typed_signature_over_the_text_cap_is_cs_fld_0002() {
    let long = "a".repeat(MAX_TEXT_BYTES + 1);
    let e = sign_with(
        Art::Typed {
            text: long,
            style: 0,
        },
        None,
    )
    .unwrap_err();
    assert_eq!(e.code(), "CS-FLD-0002");
    let at_cap = "a".repeat(MAX_TEXT_BYTES);
    sign_with(
        Art::Typed {
            text: at_cap,
            style: 0,
        },
        None,
    )
    .unwrap();
}

#[test]
fn a_signer_name_over_the_text_cap_is_cs_fld_0002() {
    let e = sign_with(Art::Drawn(ink_of(10)), Some("n".repeat(MAX_TEXT_BYTES + 1))).unwrap_err();
    assert_eq!(e.code(), "CS-FLD-0002");
}

#[test]
fn more_fields_on_a_page_than_the_cap_is_cs_flt_0004() {
    let base = base();
    let make = |n: usize| -> Vec<Field> {
        (0..n)
            .map(|i| {
                field(
                    &format!("f{i}"),
                    FieldType::Text,
                    1,
                    [10.0, 10.0, 20.0, 10.0],
                )
            })
            .collect()
    };
    let values: BTreeMap<Id, FieldValue> = BTreeMap::new();
    let caps = BTreeMap::new();
    let run = |fields: &[Field]| {
        let mut a = admit(&base, &Limits::default(), &never).unwrap();
        let input = FlattenInput {
            fields,
            values: &values,
            captures: &caps,
            envelope_id: None,
            acroform: None,
        };
        flatten(
            &mut a,
            &input,
            &FontSet::bundled(),
            &FlattenOptions::default(),
            &never,
        )
    };
    let e = run(&make(MAX_FIELDS_PER_PAGE + 1)).unwrap_err();
    assert_eq!(e.code(), "CS-FLT-0004");
    run(&make(MAX_FIELDS_PER_PAGE)).unwrap();
}

#[test]
fn cancellation_stops_the_read() {
    let base = delivered(&page_pdf(
        &cases()[0],
        "/AcroForm<</Fields[]>>",
        "",
        Vec::new(),
    ));
    let mut a = admit(&base, &Limits::default(), &never).unwrap();
    let f = field("n", FieldType::Text, 1, [10.0, 10.0, 100.0, 20.0]);
    let values = BTreeMap::from([(id("n"), text("x"))]);
    let caps = BTreeMap::new();
    let input = FlattenInput {
        fields: std::slice::from_ref(&f),
        values: &values,
        captures: &caps,
        envelope_id: None,
        acroform: None,
    };
    let stop = || true;
    let e = flatten(
        &mut a,
        &input,
        &FontSet::bundled(),
        &FlattenOptions::default(),
        &stop,
    )
    .unwrap_err();
    assert_eq!(e.code(), "CS-PDF-0013");
}
