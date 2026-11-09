//! Text extraction with positions (docs/30 §5): strings and quads on hand-built PDFs,
//! asserted within 0.5 pt, and every bound seen to stop extraction with its code.

// Tests may unwrap, index and panic (CLAUDE.md): a failure here is the test failing.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::panic
)]

mod pdf;

use casual_sign_fields::text::{MAX_GLYPHS_PER_PAGE, MAX_XOBJECT_DEPTH, TextIssue};
use casual_sign_pdf::{Limits, admit};
use pdf::{assert_near, never, one_page, pages, pages_with, stream, test_font};

#[test]
fn simple_font_widths_place_each_glyph() {
    let bytes = one_page(
        "",
        "",
        "/Font<</F1 5 0 R>>",
        b"BT /F1 10 Tf 100 700 Td (AB C) Tj ET",
        vec![(5, test_font())],
    );
    let p = pages("simple_widths.pdf", &bytes);
    let run = &p[0].runs[0];
    assert_eq!(run.text, "AB C");
    // A 6 pt, B 7 pt, space and C MissingWidth 5 pt; baseline at 792 - 700 = 92.
    let xs: Vec<f64> = run.glyphs.iter().map(|g| g.origin.x).collect();
    assert_eq!(xs, vec![100.0, 106.0, 113.0, 118.0]);
    assert_near(run.quad.ll, (100.0, 94.0));
    assert_near(run.quad.ur, (123.0, 84.0));
    assert!((run.size - 10.0).abs() < 1e-9);
    assert!(!p[0].fallback_widths());
}

#[test]
fn standard_14_fonts_without_widths_use_the_afm_metrics() {
    let bytes = one_page(
        "",
        "",
        "/Font<</F1 5 0 R/F2 6 0 R>>",
        b"BT /F1 12 Tf 72 700 Td (Hello) Tj /F2 10 Tf 0 -20 Td (AV) Tj ET",
        vec![
            (
                5,
                b"<</Type/Font/Subtype/Type1/BaseFont/Helvetica/Encoding/WinAnsiEncoding>>"
                    .to_vec(),
            ),
            (
                6,
                b"<</Type/Font/Subtype/Type1/BaseFont/Times-Roman>>".to_vec(),
            ),
        ],
    );
    let p = pages("standard14.pdf", &bytes);
    let hello = &p[0].runs[0];
    assert_eq!(hello.text, "Hello");
    // H 722, e 556, l 222, l 222, o 556 = 2278/1000 em at 12 pt; ascent 718, descent -207.
    assert_near(hello.quad.lr, (72.0 + 27.336, 92.0 + 2.484));
    assert_near(hello.quad.ul, (72.0, 92.0 - 8.616));
    let av = &p[0].runs[1];
    assert_eq!(av.text, "AV");
    // Times-Roman A 722, V 722.
    assert_near(av.quad.lr, (72.0 + 14.44, 112.0 + 2.17));
    assert!(!p[0].fallback_widths());
}

#[test]
fn a_font_with_no_metrics_is_flagged_and_uses_the_fallback_width() {
    let bytes = one_page(
        "",
        "",
        "/Font<</F1 5 0 R>>",
        b"BT /F1 10 Tf 0 0 Td (xy) Tj ET",
        vec![(5, b"<</Type/Font/Subtype/Type1/BaseFont/Mystery>>".to_vec())],
    );
    let p = pages("fallback.pdf", &bytes);
    assert_eq!(p[0].runs[0].text, "xy");
    assert_near(p[0].runs[0].glyphs[1].origin, (5.0, 792.0));
    assert!(p[0].fallback_widths());
    let f = p[0]
        .findings
        .iter()
        .find(|f| f.issue == TextIssue::FallbackWidths)
        .unwrap();
    assert_eq!((f.code, f.object), ("CS-PDF-0102", Some(5)));
}

#[test]
fn differences_map_glyph_names_to_unicode() {
    let bytes = one_page(
        "",
        "",
        "/Font<</F1 5 0 R>>",
        b"BT /F1 10 Tf 10 10 Td (ABC) Tj ET",
        vec![(
            5,
            b"<</Type/Font/Subtype/Type1/BaseFont/Helvetica/Encoding<</BaseEncoding/WinAnsiEncoding/Differences[65/eacute/uni20AC]>>>>".to_vec(),
        )],
    );
    assert_eq!(pages("differences.pdf", &bytes)[0].runs[0].text, "é€C");
}

fn type0() -> Vec<(u32, Vec<u8>)> {
    let cmap = b"/CIDInit /ProcSet findresource begin 12 dict begin begincmap
/CMapName /Test-UCS def 1 begincodespacerange <0000> <FFFF> endcodespacerange
2 beginbfchar <0001> <0048> <0002> <0069> endbfchar
1 beginbfrange <000A> <000C> <0078> endbfrange
endcmap CMapName currentdict /CMap defineresource pop end end";
    vec![
        (
            5,
            b"<</Type/Font/Subtype/Type0/BaseFont/TestCID/Encoding/Identity-H/DescendantFonts[6 0 R]/ToUnicode 7 0 R>>".to_vec(),
        ),
        (
            6,
            b"<</Type/Font/Subtype/CIDFontType2/BaseFont/TestCID/CIDSystemInfo<</Registry(Adobe)/Ordering(Identity)/Supplement 0>>/DW 1000/W[1[500 600] 10 12 250]>>".to_vec(),
        ),
        (7, stream("", cmap)),
    ]
}

#[test]
fn type0_fonts_read_w_and_to_unicode() {
    let bytes = one_page(
        "",
        "",
        "/Font<</F2 5 0 R>>",
        b"BT /F2 20 Tf 50 500 Td <00010002000A000B0003> Tj ET",
        type0(),
    );
    let p = pages("type0.pdf", &bytes);
    let run = &p[0].runs[0];
    // Code 3 maps to nothing: it keeps its place but adds no text.
    assert_eq!(run.text, "Hixy");
    let xs: Vec<f64> = run.glyphs.iter().map(|g| g.origin.x).collect();
    assert_eq!(xs, vec![50.0, 60.0, 72.0, 77.0, 82.0]);
    assert_near(run.quad.lr, (102.0, 292.0 + 4.0));
}

#[test]
fn tj_kerning_moves_glyphs_and_a_wide_gap_reads_as_a_space() {
    let bytes = one_page(
        "",
        "",
        "/Font<</F1 5 0 R>>",
        b"BT /F1 10 Tf 100 700 Td [(A) -1000 (B) 500 (C)] TJ ET",
        vec![(5, b"<</Type/Font/Subtype/Type1/BaseFont/Courier>>".to_vec())],
    );
    let p = pages("kerning.pdf", &bytes);
    let run = &p[0].runs[0];
    assert_eq!(run.text, "ABC");
    let xs: Vec<f64> = run.glyphs.iter().map(|g| g.origin.x).collect();
    // Courier 600; -1000 moves right one em; 500 moves left half an em.
    assert_eq!(xs, vec![100.0, 116.0, 117.0]);
    assert_eq!(p[0].text(), "A BC");
}

#[test]
fn form_xobjects_apply_their_matrix_and_own_resources() {
    let form = stream(
        "/Type/XObject/Subtype/Form/BBox[0 0 500 500]/Matrix[2 0 0 2 0 0]/Resources<</Font<</F1 6 0 R>>>>",
        b"BT /F1 10 Tf 10 20 Td (A) Tj ET",
    );
    let bytes = one_page(
        "",
        "",
        "/XObject<</X1 5 0 R>>",
        b"q 1 0 0 1 100 100 cm /X1 Do Q",
        vec![
            (5, form),
            (6, b"<</Type/Font/Subtype/Type1/BaseFont/Courier>>".to_vec()),
        ],
    );
    let p = pages("form.pdf", &bytes);
    let g = &p[0].runs[0].glyphs[0];
    assert_eq!(p[0].runs[0].text, "A");
    assert_near(g.origin, (120.0, 792.0 - 140.0));
    assert_near(g.end, (132.0, 792.0 - 140.0));
    assert!((p[0].runs[0].size - 20.0).abs() < 1e-9);
}

#[test]
fn rotated_and_cropped_pages_give_displayed_positions() {
    // Rotate 90, crop origin (50, 40), UserUnit 2.
    let bytes = one_page(
        "",
        "/Rotate 90/CropBox[50 40 562 752]/UserUnit 2",
        "/Font<</F1 5 0 R>>",
        b"BT /F1 10 Tf 100 700 Td (AB) Tj ET",
        vec![(5, b"<</Type/Font/Subtype/Type1/BaseFont/Courier>>".to_vec())],
    );
    let p = pages("rotated.pdf", &bytes);
    let run = &p[0].runs[0];
    assert_eq!(run.text, "AB");
    // px = 100 - 50 = 50, py = 752 - 700 = 52; turned 90° clockwise: (h - py, px) × 2,
    // with h = 712: (660, 50) × 2.
    assert_near(run.glyphs[0].origin, (1320.0, 100.0));
    // Text runs down the displayed page: the next glyph is 6 user units, 12 pt, lower.
    assert_near(run.glyphs[1].origin, (1320.0, 112.0));
    assert_eq!(p[0].geometry.displayed_size(), (1424.0, 1024.0));
}

#[test]
fn text_state_operators_shape_the_positions() {
    // Tz 50 halves advances, Tc adds 1 per glyph, Tw adds 3 per space, Ts raises,
    // TL/T*/'/" move to the next line.
    let content = b"BT /F1 10 Tf 14 TL 50 Tz 1 Tc 3 Tw 5 Ts 100 700 Td (A A) Tj \
        100 Tz 0 Tc 0 Tw 0 Ts T* (B) Tj (C) ' 2 1 (D) \" ET";
    let bytes = one_page(
        "",
        "",
        "/Font<</F1 5 0 R>>",
        content,
        vec![(5, b"<</Type/Font/Subtype/Type1/BaseFont/Courier>>".to_vec())],
    );
    let p = pages("textstate.pdf", &bytes);
    let r = &p[0].runs;
    let xs: Vec<f64> = r[0].glyphs.iter().map(|g| g.origin.x).collect();
    // (6 + 1) × 0.5 = 3.5 per glyph, + 3 × 0.5 = 1.5 more after the space.
    assert_eq!(xs, vec![100.0, 103.5, 108.5]);
    assert_near(r[0].glyphs[0].origin, (100.0, 92.0 - 5.0));
    assert_eq!(r[1].text, "B");
    assert_near(r[1].glyphs[0].origin, (100.0, 106.0));
    assert_eq!(r[2].text, "C");
    assert_near(r[2].glyphs[0].origin, (100.0, 120.0));
    assert_eq!(r[3].text, "D");
    assert_near(r[3].glyphs[0].origin, (100.0, 134.0));
    assert_eq!(p[0].text(), "A A B C D");
}

#[test]
fn q_and_q_restore_the_ctm() {
    let bytes = one_page(
        "",
        "",
        "/Font<</F1 5 0 R>>",
        b"q 2 0 0 2 0 0 cm BT /F1 10 Tf 10 10 Td (A) Tj ET Q BT /F1 10 Tf 10 10 Td (B) Tj ET Q Q",
        vec![(5, b"<</Type/Font/Subtype/Type1/BaseFont/Courier>>".to_vec())],
    );
    let p = pages("qq.pdf", &bytes);
    assert_near(p[0].runs[0].glyphs[0].origin, (20.0, 772.0));
    assert_near(p[0].runs[1].glyphs[0].origin, (10.0, 782.0));
}

#[test]
fn inline_images_and_marked_content_are_stepped_over() {
    let bytes = one_page(
        "",
        "",
        "/Font<</F1 5 0 R>>",
        b"/P <</MCID 0>> BDC BI /W 1 /H 1 /BPC 8 /CS /G ID \xffEI)( EI EMC BT /F1 10 Tf 10 10 Td (ok) Tj ET",
        vec![(5, b"<</Type/Font/Subtype/Type1/BaseFont/Courier>>".to_vec())],
    );
    assert_eq!(pages("inline.pdf", &bytes)[0].text(), "ok");
}

// ----- bounds ---------------------------------------------------------------------

#[test]
fn the_content_operator_limit_stops_the_page_with_cs_pdf_0013() {
    let mut content = b"BT /F1 10 Tf".to_vec();
    for i in 0..100 {
        content.extend_from_slice(format!(" 0 -1 Td ({i}) Tj").as_bytes());
    }
    content.extend_from_slice(b" ET");
    let bytes = one_page(
        "",
        "",
        "/Font<</F1 5 0 R>>",
        &content,
        vec![(5, b"<</Type/Font/Subtype/Type1/BaseFont/Courier>>".to_vec())],
    );
    let limits = Limits {
        max_content_ops: 50,
        ..Limits::default()
    };
    let p = pages_with(&bytes, &limits);
    let f = p[0]
        .findings
        .iter()
        .find(|f| f.issue == TextIssue::ContentOps)
        .expect("content-operator finding");
    assert_eq!(f.code, "CS-PDF-0013");
    assert!(p[0].truncated());
    // BT, Tf, then Td/Tj pairs: the 51st operator stops the page.
    assert_eq!(p[0].operators, 51);
    assert_eq!(p[0].runs.len(), 24);
}

#[test]
fn the_hostile_two_million_operator_fixture_is_stopped() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/hostile/content_ops_2m.pdf"
    );
    let Ok(bytes) = std::fs::read(path) else {
        eprintln!("SKIPPED: run python3 -I fixtures/tools/generate.py for {path}");
        return;
    };
    // Each `Tj` shows one glyph, so the glyph cap is met first under default limits.
    let p = pages_with(&bytes, &Limits::default());
    assert!(p[0].truncated());
    assert!(p[0].findings.iter().all(|f| f.code == "CS-PDF-0013"));
    assert_eq!(p[0].runs.len(), MAX_GLYPHS_PER_PAGE);
    // With the glyph cap out of reach, the operator limit stops it.
    let limits = Limits {
        max_content_ops: 400_000,
        ..Limits::default()
    };
    let p = pages_with(&bytes, &limits);
    assert!(
        p[0].findings
            .iter()
            .any(|f| f.issue == TextIssue::ContentOps && f.code == "CS-PDF-0013")
    );
    assert_eq!(p[0].operators, 400_001);
}

fn nested_forms(n: u32, self_loop: bool) -> Vec<u8> {
    // Form k (object 5 + k) shows "Lk" and invokes form k+1.
    let mut extra = vec![(
        4 + n + 1,
        b"<</Type/Font/Subtype/Type1/BaseFont/Courier>>".to_vec(),
    )];
    for k in 1..=n {
        let next = if self_loop { k } else { k + 1 };
        let body = format!("BT /F1 10 Tf 10 {} Td (L{k}) Tj ET /X Do", 10 * k);
        extra.push((
            4 + k,
            stream(
                &format!(
                    "/Type/XObject/Subtype/Form/BBox[0 0 600 800]/Resources<</Font<</F1 {} 0 R>>/XObject<</X {} 0 R>>>>",
                    4 + n + 1,
                    4 + next
                ),
                body.as_bytes(),
            ),
        ));
    }
    one_page("", "", "/XObject<</X 5 0 R>>", b"/X Do", extra)
}

#[test]
fn form_xobjects_nest_at_most_eight_deep() {
    let p = pages("forms_deep.pdf", &nested_forms(10, false));
    let texts: Vec<&str> = p[0].runs.iter().map(|r| r.text.as_str()).collect();
    assert_eq!(texts.len(), MAX_XOBJECT_DEPTH);
    assert_eq!(texts.last(), Some(&"L8"));
    let f = p[0]
        .findings
        .iter()
        .find(|f| f.issue == TextIssue::XObjectDepth)
        .expect("depth finding");
    assert_eq!((f.code, f.object), ("CS-PDF-0004", Some(4 + 9)));
}

#[test]
fn a_form_that_invokes_itself_runs_once() {
    let p = pages("forms_cycle.pdf", &nested_forms(1, true));
    assert_eq!(p[0].runs.len(), 1);
    assert!(
        p[0].findings
            .iter()
            .any(|f| f.issue == TextIssue::XObjectCycle && f.code == "CS-PDF-0004")
    );
}

#[test]
fn glyphs_per_page_are_capped() {
    let mut content = b"BT /F1 1 Tf (".to_vec();
    content.extend(std::iter::repeat_n(b'a', MAX_GLYPHS_PER_PAGE + 1));
    content.extend_from_slice(b") Tj (b) Tj ET");
    let bytes = one_page(
        "",
        "",
        "/Font<</F1 5 0 R>>",
        &content,
        vec![(5, b"<</Type/Font/Subtype/Type1/BaseFont/Courier>>".to_vec())],
    );
    let p = pages_with(&bytes, &Limits::default());
    assert_eq!(p[0].runs.len(), 1);
    assert_eq!(p[0].runs[0].glyphs.len(), MAX_GLYPHS_PER_PAGE);
    assert!(
        p[0].findings
            .iter()
            .any(|f| f.issue == TextIssue::Glyphs && f.code == "CS-PDF-0013")
    );
}

#[test]
fn cancellation_ends_the_extraction() {
    let mut content = b"BT /F1 10 Tf".to_vec();
    content.extend(std::iter::repeat_n(b" (a) Tj".as_slice(), 10_000).flatten());
    content.extend_from_slice(b" ET");
    let bytes = one_page(
        "",
        "",
        "/Font<</F1 5 0 R>>",
        &content,
        vec![(5, b"<</Type/Font/Subtype/Type1/BaseFont/Courier>>".to_vec())],
    );
    let mut a = admit(&bytes, &Limits::default(), &never).unwrap();
    let pages = a.report.pages.clone();
    let stop = || true;
    let e = casual_sign_fields::extract_text(&mut a.document, &pages, &stop).unwrap_err();
    assert_eq!(e.code(), "CS-PDF-0013");
}

#[test]
fn damaged_content_never_panics() {
    // Every prefix of a content stream that uses every operator.
    let full: &[u8] = b"q 1 0 0 1 5 5 cm BT /F1 10 Tf 14 TL 1 Tc 2 Tw 90 Tz 1 Ts 1 0 0 1 9 9 Tm \
        (a\\(\\)) Tj [(b) -20 <0063>] TJ T* (d) ' 1 2 (e) \" 3 4 TD 5 6 Td ET /X Do Q";
    for cut in 0..full.len() {
        let bytes = one_page(
            "",
            "",
            "/Font<</F1 5 0 R>>/XObject<</X 4 0 R>>",
            &full[..cut],
            vec![(5, test_font())],
        );
        let _ = pages_with(&bytes, &Limits::default());
    }
}
