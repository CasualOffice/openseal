//! Field auto-detection (docs/30 §5, `WEB-06`): underscore lines with labels beside,
//! under and over them, colon labels with blank space, painted rules and boxes, existing
//! form fields, a page with no cues, a rotated page, the 500-suggestion cap, and one
//! real form from the corpus when it is downloaded.

// Tests may unwrap, index and panic (CLAUDE.md): a failure here is the test failing.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::panic
)]

mod pdf;

use std::path::PathBuf;

use casual_sign_fields::{
    DetectedField, DetectedSource, Detection, MAX_DETECTED_FIELDS, PageText, convert_acroform,
    detect_fields, extract_text,
};
use casual_sign_model::{FieldType, Id};
use casual_sign_pdf::{Limits, admit};
use pdf::{never, one_page, pages};

const COURIER: &[u8] = b"<</Type/Font/Subtype/Type1/BaseFont/Courier>>";

fn page_with(name: &str, page_extra: &str, content: &[u8]) -> Vec<PageText> {
    let bytes = one_page(
        "",
        page_extra,
        "/Font<</F1 5 0 R>>",
        content,
        vec![(5, COURIER.to_vec())],
    );
    pages(name, &bytes)
}

fn detect(name: &str, content: &[u8]) -> Detection {
    detect_fields(&page_with(name, "", content), &[])
}

fn f64_of(d: rust_decimal::Decimal) -> f64 {
    d.to_string().parse().unwrap()
}

fn kinds(d: &Detection) -> Vec<(FieldType, DetectedSource)> {
    d.fields.iter().map(|f| (f.field_type, f.source)).collect()
}

fn rect(f: &DetectedField) -> (f64, f64, f64, f64) {
    let p = f.placement;
    (
        f64_of(p.x().get()),
        f64_of(p.y().get()),
        f64_of(p.width().get()),
        f64_of(p.height().get()),
    )
}

#[track_caller]
fn near(got: f64, want: f64) {
    assert!((got - want).abs() < 0.6, "got {got}, want {want}");
}

#[test]
fn an_underscore_line_after_a_signature_label_is_a_signature_sitting_on_the_line() {
    // Courier 10 pt: 6 pt a glyph, ascent 6.29, descent 1.57; baseline at y 92 displayed.
    let d = detect(
        "detect-signature.pdf",
        b"BT /F1 10 Tf 72 700 Td (Signature: ____________) Tj ET",
    );
    assert_eq!(
        kinds(&d),
        [(FieldType::Signature, DetectedSource::Underline)]
    );
    let f = &d.fields[0];
    assert_eq!(f.placement.page(), 1);
    assert_eq!(f.confidence, 90);
    assert_eq!(f.label.as_deref(), Some("Signature:"));
    let (x, y, w, h) = rect(f);
    near(x, 72.0 + 11.0 * 6.0);
    near(w, 12.0 * 6.0);
    near(h, 30.0);
    // The bottom sits on the underscores' descent line.
    near(y + h, 92.0 + 1.57);
    assert!(!d.truncated);
}

#[test]
fn date_name_initials_title_and_company_labels_set_the_kind() {
    let d = detect(
        "detect-kinds.pdf",
        b"BT /F1 10 Tf 72 700 Td (Date signed ________) Tj \
          0 -40 Td (Print name: ____________________) Tj \
          0 -40 Td (Initials ______) Tj \
          0 -40 Td (Title ______________) Tj \
          0 -40 Td (Company name ______________) Tj \
          0 -40 Td (Sign here ______________) Tj ET",
    );
    assert_eq!(
        kinds(&d),
        [
            (FieldType::DateSigned, DetectedSource::Underline),
            (FieldType::Name, DetectedSource::Underline),
            (FieldType::Initials, DetectedSource::Underline),
            (FieldType::Title, DetectedSource::Underline),
            (FieldType::Company, DetectedSource::Underline),
            (FieldType::Signature, DetectedSource::Underline),
        ]
    );
    // Date at most 100 wide, initials at most 60 wide.
    let (_, _, w, h) = rect(&d.fields[0]);
    near(w, 48.0);
    near(h, 18.0);
    let (_, _, w, h) = rect(&d.fields[2]);
    near(w, 36.0);
    near(h, 30.0);
}

#[test]
fn a_label_under_or_over_a_line_names_it_and_an_unlabelled_line_is_text() {
    let d = detect(
        "detect-under.pdf",
        b"BT /F1 10 Tf 300 700 Td (______________________) Tj \
          0 -12 Td (Signature of applicant) Tj ET \
          BT /F1 10 Tf 72 500 Td (________________) Tj ET",
    );
    let mut want = vec![
        (FieldType::Signature, DetectedSource::Underline),
        (FieldType::Text, DetectedSource::Underline),
    ];
    assert_eq!(kinds(&d), want);
    assert_eq!(d.fields[0].confidence, 80);
    assert_eq!(d.fields[1].confidence, 40);
    assert_eq!(d.fields[1].label, None);
    // Over: a label just above the line.
    let d = detect(
        "detect-over.pdf",
        b"BT /F1 10 Tf 300 712 Td (Date) Tj 0 -12 Td (__________) Tj ET",
    );
    want = vec![(FieldType::DateSigned, DetectedSource::Underline)];
    assert_eq!(kinds(&d), want);
}

#[test]
fn a_colon_label_with_blank_space_after_it_is_a_field_there() {
    let d = detect(
        "detect-colon.pdf",
        b"BT /F1 10 Tf 72 700 Td (Company:) Tj 0 -40 Td (Name: John) Tj ET",
    );
    // "Name: John" has no blank space: nothing.
    assert_eq!(kinds(&d), [(FieldType::Company, DetectedSource::Label)]);
    let f = &d.fields[0];
    assert_eq!(f.confidence, 60);
    let (x, _, w, h) = rect(f);
    near(x, 72.0 + 8.0 * 6.0 + 4.0);
    near(w, 200.0);
    near(h, 18.0);
}

#[test]
fn labelled_painted_rules_and_boxes_are_fields_and_unlabelled_or_underlining_ones_are_not() {
    let d = detect(
        "detect-shapes.pdf",
        b"BT /F1 10 Tf 72 602 Td (Sign here) Tj ET \
          0.5 w 140 600 m 340 600 l S \
          BT /F1 10 Tf 72 545 Td (Title) Tj ET \
          72 500 200 30 re S \
          30 400 m 580 400 l S \
          BT /F1 10 Tf 72 302 Td (Name underlined) Tj ET \
          72 300 90 0.8 re f \
          72 200 m 300 200 l h W n",
    );
    assert_eq!(
        kinds(&d),
        [
            (FieldType::Signature, DetectedSource::Underline),
            (FieldType::Title, DetectedSource::Box),
        ]
    );
    let (x, y, w, h) = rect(&d.fields[0]);
    near(x, 140.0);
    near(w, 200.0);
    near(y + h, 192.0);
    assert_eq!(d.fields[0].confidence, 70);
    let (x, y, w, h) = rect(&d.fields[1]);
    near(x, 72.0);
    near(y, 792.0 - 530.0);
    near(w, 200.0);
    near(h, 30.0);
}

#[test]
fn a_page_with_no_cues_suggests_nothing() {
    let d = detect(
        "detect-none.pdf",
        b"BT /F1 10 Tf 72 700 Td (Hello world. This agreement is made today.) Tj ET \
          72 650 m 540 650 l S",
    );
    assert_eq!(d, Detection::default());
}

#[test]
fn existing_form_fields_are_suggested_and_a_text_cue_on_one_is_dropped() {
    let w = "/Type/Annot/Subtype/Widget/P 3 0 R";
    let extra = vec![
        (5, COURIER.to_vec()),
        (
            10,
            format!("<</FT/Sig/T(sig1){w}/Rect[138 690 210 720]>>").into_bytes(),
        ),
    ];
    let bytes = one_page(
        "/AcroForm<</Fields[10 0 R]>>",
        "/Annots[10 0 R]",
        "/Font<</F1 5 0 R>>",
        b"BT /F1 10 Tf 72 700 Td (Signature: ____________) Tj ET \
          BT /F1 10 Tf 72 600 Td (Date: ________) Tj ET",
        extra,
    );
    let mut a = admit(&bytes, &Limits::default(), &never).unwrap();
    let pages_info = a.report.pages.clone();
    let text = extract_text(&mut a.document, &pages_info, &never).unwrap();
    let mut n = 0;
    let mut next = || {
        n += 1;
        Id::new(format!("f{n}")).unwrap()
    };
    let conv = convert_acroform(
        &mut a.document,
        &a.report,
        &Id::new("doc").unwrap(),
        &mut next,
        &never,
    )
    .unwrap();
    let d = detect_fields(&text, &conv.fields);
    assert_eq!(
        kinds(&d),
        [
            (FieldType::Signature, DetectedSource::AcroForm),
            (FieldType::DateSigned, DetectedSource::Underline),
        ]
    );
    assert_eq!(d.fields[0].confidence, 100);
    assert_eq!(d.fields[0].label.as_deref(), Some("sig1"));
}

#[test]
fn a_rotated_page_gives_rectangles_in_its_displayed_space() {
    let p = page_with(
        "detect-rotated.pdf",
        "/Rotate 90",
        b"BT /F1 10 Tf 72 700 Td (Signature: ____________) Tj ET",
    );
    let d = detect_fields(&p, &[]);
    assert_eq!(
        kinds(&d),
        [(FieldType::Signature, DetectedSource::Underline)]
    );
    let (x, y, w, h) = rect(&d.fields[0]);
    // Displayed 792 × 612; every suggestion lies on it.
    assert!(x >= 0.0 && y >= 0.0 && x + w <= 792.0 + 0.01 && y + h <= 612.0 + 0.01);
}

#[test]
fn suggestions_stop_at_the_cap_and_say_so() {
    // 17 columns × 36 rows of unlabelled lines: 612 lines, none overlapping.
    let mut content = b"BT /F1 6 Tf".to_vec();
    for col in 0..17 {
        for row in 0..36 {
            let x = 20 + col * 34;
            let y = 760 - row * 20;
            content.extend_from_slice(format!(" 1 0 0 1 {x} {y} Tm (____) Tj").as_bytes());
        }
    }
    content.extend_from_slice(b" ET");
    let d = detect("detect-cap.pdf", &content);
    assert_eq!(d.fields.len(), MAX_DETECTED_FIELDS);
    assert!(d.truncated);
    // Kept in order: page, top to bottom, left to right.
    let ys: Vec<f64> = d.fields.iter().map(|f| rect(f).1).collect();
    assert!(ys.windows(2).all(|w| w[0] <= w[1]));
}

fn corpus_dir() -> PathBuf {
    std::env::var_os("OPENSEAL_CORPUS_DIR").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/corpus/files"),
        PathBuf::from,
    )
}

#[test]
fn a_real_form_with_signature_lines_gets_signature_and_date_suggestions() {
    // FEC Form 1 (public domain, US government): no form fields, its certification
    // ends in signature and date lines.
    let path = corpus_dir().join("fec-form1.pdf");
    let Ok(bytes) = std::fs::read(&path) else {
        eprintln!(
            "SKIPPED: {} not downloaded (fixtures/corpus/fetch.py)",
            path.display()
        );
        return;
    };
    let mut a = admit(&bytes, &Limits::default(), &never).unwrap();
    let pages_info = a.report.pages.clone();
    let text = extract_text(&mut a.document, &pages_info, &never).unwrap();
    let d = detect_fields(&text, &[]);
    for f in &d.fields {
        eprintln!(
            "{} {:?} {:?} {:?} {}",
            f.placement.page(),
            f.field_type,
            f.source,
            f.label,
            f.confidence
        );
    }
    assert!(
        d.fields
            .iter()
            .any(|f| f.field_type == FieldType::Signature),
        "no signature suggested"
    );
    assert!(
        d.fields
            .iter()
            .any(|f| f.field_type == FieldType::DateSigned),
        "no date suggested"
    );
    assert!(d.fields.len() <= MAX_DETECTED_FIELDS);
}
