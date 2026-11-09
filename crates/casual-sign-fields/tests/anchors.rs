//! Anchors and text tags (docs/30 §5): each option, matches across runs, units,
//! absence, the 500-match cap, and malformed tags.

// Tests may unwrap, index and panic (CLAUDE.md): a failure here is the test failing.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::panic
)]

mod pdf;

use casual_sign_fields::{
    AnchorMatch, AnchorSpec, AnchorUnits, MAX_ANCHOR_MATCHES, PlaceError, TagProblem, place_anchor,
    scan_tags,
};
use casual_sign_model::{FieldType, Points};
use pdf::{one_page, pages};
use rust_decimal::Decimal;

const COURIER: &[u8] = b"<</Type/Font/Subtype/Type1/BaseFont/Courier>>";

fn doc(name: &str, content: &[u8]) -> Vec<casual_sign_fields::PageText> {
    let bytes = one_page(
        "",
        "",
        "/Font<</F1 5 0 R>>",
        content,
        vec![(5, COURIER.to_vec())],
    );
    pages(name, &bytes)
}

fn sample() -> Vec<casual_sign_fields::PageText> {
    doc(
        "anchors.pdf",
        b"BT /F1 10 Tf 100 700 Td (Please Sign) Tj (ature here) Tj \
          0 -20 Td (sign) Tj 30 0 Td (HERE) Tj \
          -30 -20 Td (designer) Tj ET",
    )
}

fn spec(text: &str) -> AnchorSpec {
    AnchorSpec {
        text: text.to_string(),
        offset_x: Decimal::ZERO,
        offset_y: Decimal::ZERO,
        units: AnchorUnits::Points,
        ignore_if_absent: false,
        case_sensitive: false,
        whole_word: false,
        matching: AnchorMatch::All,
        width: Points::new(Decimal::from(100)).unwrap(),
        height: Points::new(Decimal::from(20)).unwrap(),
    }
}

fn dec(s: &str) -> Decimal {
    s.parse().unwrap()
}

#[test]
fn a_match_across_show_operators_places_the_field_at_its_top_left() {
    let p = sample();
    assert_eq!(p[0].text(), "Please Signature here sign HERE designer");
    let s = AnchorSpec {
        case_sensitive: true,
        ..spec("Signature")
    };
    let m = place_anchor(&p, &s, 0).unwrap();
    assert_eq!(m.len(), 1);
    // "Please " is 7 Courier glyphs of 6 pt; Courier ascent 629, descent -157.
    let r = m[0].text_rect;
    assert!((r.x - 142.0).abs() < 0.5 && (r.width - 54.0).abs() < 0.5);
    assert!((r.y - (92.0 - 6.29)).abs() < 0.5 && (r.height - 7.86).abs() < 0.5);
    let pl = m[0].placement;
    assert_eq!(pl.page(), 1);
    assert_eq!(pl.x().get(), dec("142"));
    assert_eq!(pl.y().get(), dec("85.71"));
    assert_eq!(pl.width().get(), Decimal::from(100));
}

#[test]
fn inferred_spaces_and_case_folding_match_words_split_by_positioning() {
    let p = sample();
    let m = place_anchor(&p, &spec("SIGN   here"), 0).unwrap();
    assert_eq!(m.len(), 1);
    assert!((m[0].text_rect.x - 100.0).abs() < 0.5);
    // The match spans the gap: from "sign" to the end of "HERE" at 130 + 24.
    assert!((m[0].text_rect.right() - 154.0).abs() < 0.5);
}

#[test]
fn case_whole_word_and_first_options_select_matches() {
    let p = sample();
    let all = |s: AnchorSpec| place_anchor(&p, &s, 0).unwrap().len();
    assert_eq!(all(spec("sign")), 3);
    assert_eq!(
        all(AnchorSpec {
            case_sensitive: true,
            ..spec("sign")
        }),
        2
    );
    assert_eq!(
        all(AnchorSpec {
            whole_word: true,
            ..spec("sign")
        }),
        1
    );
    let first = place_anchor(
        &p,
        &AnchorSpec {
            matching: AnchorMatch::First,
            ..spec("sign")
        },
        0,
    )
    .unwrap();
    assert_eq!(first.len(), 1);
    assert!((first[0].text_rect.x - 142.0).abs() < 0.5);
}

#[test]
fn offsets_are_converted_from_each_unit() {
    let p = sample();
    let base = place_anchor(&p, &spec("designer"), 0).unwrap()[0].placement;
    let cases = [
        (AnchorUnits::Points, "36", "-10", 36.0, -10.0),
        (AnchorUnits::Inches, "1", "0.5", 72.0, 36.0),
        (AnchorUnits::Millimetres, "25.4", "0", 72.0, 0.0),
        (AnchorUnits::Centimetres, "2.54", "-1", 72.0, -72.0 / 2.54),
        (AnchorUnits::Pixels, "96", "48", 72.0, 36.0),
    ];
    let f = |d: Decimal| f64::try_from(d).unwrap();
    for (units, ox, oy, dx, dy) in cases {
        let s = AnchorSpec {
            units,
            offset_x: dec(ox),
            offset_y: dec(oy),
            ..spec("designer")
        };
        let m = place_anchor(&p, &s, 0).unwrap()[0].placement;
        assert!(
            (f(m.x().get()) - f(base.x().get()) - dx).abs() < 1e-3,
            "{units:?}"
        );
        assert!(
            (f(m.y().get()) - f(base.y().get()) - dy).abs() < 1e-3,
            "{units:?}"
        );
    }
}

#[test]
fn an_absent_anchor_is_an_error_unless_ignorable() {
    let p = sample();
    let e = place_anchor(&p, &spec("countersign"), 7).unwrap_err();
    assert_eq!(e, PlaceError::AnchorNotFound { anchor: 7 });
    assert_eq!(e.code(), "CS-FLD-0010");
    assert!(!e.to_string().contains("countersign"));
    let s = AnchorSpec {
        ignore_if_absent: true,
        ..spec("countersign")
    };
    assert!(place_anchor(&p, &s, 7).unwrap().is_empty());
}

#[test]
fn unusable_anchor_text_and_off_page_offsets_are_refused() {
    let p = sample();
    let e = place_anchor(&p, &spec(" \t "), 1).unwrap_err();
    assert_eq!(
        (e.code(), e),
        ("CS-FLD-0002", PlaceError::AnchorText { anchor: 1 })
    );
    let long = "x".repeat(casual_sign_fields::MAX_ANCHOR_CHARS + 1);
    assert!(matches!(
        place_anchor(&p, &spec(&long), 1),
        Err(PlaceError::AnchorText { .. })
    ));
    let s = AnchorSpec {
        offset_x: dec("600"),
        ..spec("designer")
    };
    let e = place_anchor(&p, &s, 1).unwrap_err();
    assert_eq!(
        (e.code(), e),
        ("CS-FLD-0004", PlaceError::OutsidePage { page: 1 })
    );
}

fn repeated(n: usize) -> Vec<casual_sign_fields::PageText> {
    let mut content = b"BT /F1 2 Tf 10 780 Td".to_vec();
    for i in 0..n {
        if i % 40 == 0 {
            content.extend_from_slice(b" 0 -3 Td");
        }
        content.extend_from_slice(b" (mark ) Tj");
    }
    content.extend_from_slice(b" ET");
    doc(&format!("repeat_{n}.pdf"), &content)
}

#[test]
fn matches_are_capped_at_500_per_string() {
    let ok = place_anchor(&repeated(MAX_ANCHOR_MATCHES), &spec("mark"), 3).unwrap();
    assert_eq!(ok.len(), MAX_ANCHOR_MATCHES);
    let e = place_anchor(&repeated(MAX_ANCHOR_MATCHES + 1), &spec("mark"), 3).unwrap_err();
    assert_eq!(
        e,
        PlaceError::TooManyMatches {
            anchor: 3,
            limit: 500
        }
    );
    assert_eq!(e.code(), "CS-FLD-0010");
}

// ----- text tags --------------------------------------------------------------------

fn tags_doc() -> Vec<casual_sign_fields::PageText> {
    doc(
        "tags.pdf",
        b"BT /F1 10 Tf 100 700 Td ({{s:client}}) Tj \
          0 -20 Td ({{text:client:req:company_name:150x20}}) Tj \
          0 -20 Td ({{date_si) Tj (gned: ceo }}) Tj \
          0 -20 Td ({{bogus:secret_value}}) Tj \
          0 -20 Td ({{s:client) Tj \
          0 -20 Td ({{s:a:b:c:d}}) Tj ET",
    )
}

#[test]
fn well_formed_tags_become_placed_fields() {
    let scan = scan_tags(&tags_doc());
    assert_eq!(scan.tags.len(), 3);
    let t = &scan.tags[0];
    assert_eq!(t.field_type, FieldType::Signature);
    assert_eq!(t.recipient.as_str(), "client");
    assert!(!t.required && t.label.is_none());
    // Twelve Courier glyphs at 6 pt; the placement is the tag's rectangle.
    assert!((t.tag_rect.x - 100.0).abs() < 0.5 && (t.tag_rect.width - 72.0).abs() < 0.5);
    assert_eq!(t.placement.x().get(), Decimal::from(100));
    assert_eq!(t.placement.width().get(), Decimal::from(72));

    let t = &scan.tags[1];
    assert_eq!(t.field_type, FieldType::Text);
    assert!(t.required);
    assert_eq!(t.label.as_ref().unwrap().as_str(), "company_name");
    // The size replaces the tag's; the top-left stays.
    assert_eq!(t.placement.width().get(), Decimal::from(150));
    assert_eq!(t.placement.height().get(), Decimal::from(20));
    assert!((t.tag_rect.y - (112.0 - 6.29)).abs() < 0.5);

    // A tag split across two show operators, with spaces inside.
    let t = &scan.tags[2];
    assert_eq!(t.field_type, FieldType::DateSigned);
    assert_eq!(t.recipient.as_str(), "ceo");
}

#[test]
fn malformed_tags_report_page_and_position_never_text() {
    let scan = scan_tags(&tags_doc());
    let problems: Vec<(TagProblem, f64)> = scan
        .errors
        .iter()
        .map(|e| match e {
            PlaceError::TagMalformed {
                page,
                x,
                y,
                problem,
                ..
            } => {
                assert_eq!(*page, 1);
                assert!((x - 100.0).abs() < 0.5);
                assert_eq!(e.code(), "CS-FLD-0011");
                assert!(!e.to_string().contains("secret"));
                (*problem, *y)
            }
            other => panic!("unexpected {other:?}"),
        })
        .collect();
    let kinds: Vec<TagProblem> = problems.iter().map(|p| p.0).collect();
    assert_eq!(
        kinds,
        vec![
            TagProblem::UnknownType,
            TagProblem::Unterminated,
            TagProblem::TooManyParts
        ]
    );
    // Lines 4, 5 and 6: baselines 640, 620, 600, tops 6.29 above.
    for ((_, y), base) in problems.iter().zip([640.0, 620.0, 600.0]) {
        assert!((y - (792.0 - base - 6.29)).abs() < 0.5, "{y}");
    }
}

#[test]
fn an_unclosed_tag_at_the_end_and_full_width_braces() {
    // NFKC turns full-width braces into ASCII ones.
    let bytes = one_page(
        "",
        "",
        "/Font<</F1 5 0 R/F2 8 0 R>>",
        b"BT /F1 10 Tf 100 700 Td <0001000100020003000400050005> Tj /F2 10 Tf 0 -20 Td ({{s:x) Tj ET",
        nfkc_font(),
    );
    let scan = scan_tags(&pages("tags_fullwidth.pdf", &bytes));
    assert_eq!(scan.tags.len(), 1);
    assert_eq!(scan.tags[0].field_type, FieldType::Signature);
    assert!(matches!(
        scan.errors.as_slice(),
        [PlaceError::TagMalformed {
            problem: TagProblem::Unterminated,
            ..
        }]
    ));
}

/// A Type 0 font whose ToUnicode maps 1 to U+FF5B (full-width `{`), 5 to U+FF5D, and 2–4
/// to `s`, `:`, `x`; object 8 is Courier for the second line.
fn nfkc_font() -> Vec<(u32, Vec<u8>)> {
    let cmap = b"1 begincodespacerange <0000> <FFFF> endcodespacerange
5 beginbfchar <0001> <FF5B> <0005> <FF5D> <0002> <0073> <0003> <003A> <0004> <0078> endbfchar";
    vec![
        (5, b"<</Type/Font/Subtype/Type0/BaseFont/T/Encoding/Identity-H/DescendantFonts[6 0 R]/ToUnicode 7 0 R>>".to_vec()),
        (6, b"<</Type/Font/Subtype/CIDFontType2/BaseFont/T/DW 600>>".to_vec()),
        (7, pdf::stream("", cmap)),
        (8, COURIER.to_vec()),
    ]
}
