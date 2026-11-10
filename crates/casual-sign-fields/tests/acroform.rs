//! AcroForm conversion (docs/30 §3): each widget type, flags, options, max length, and
//! what cannot be mapped.

// Tests may unwrap, index and panic (CLAUDE.md): a failure here is the test failing.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::panic
)]

mod pdf;

use casual_sign_fields::{Unmapped, convert_acroform};
use casual_sign_model::{FieldType, Id, LengthRule, ValidationRule};
use casual_sign_pdf::{Limits, admit};
use pdf::{dump, never, one_page};
use rust_decimal::Decimal;

fn form(page_extra: &str) -> Vec<u8> {
    let w = "/Type/Annot/Subtype/Widget/P 3 0 R";
    let extra = vec![
        (
            10,
            format!("<</FT/Tx/T(Company Name)/Ff 2/MaxLen 40{w}/Rect[100 600 300 620]>>")
                .into_bytes(),
        ),
        (
            11,
            format!("<</FT/Btn/T(agree)/Ff 1{w}/Rect[100 500 112 512]>>").into_bytes(),
        ),
        (
            12,
            b"<</FT/Btn/Ff 49152/T(choice)/Kids[16 0 R 17 0 R]>>".to_vec(),
        ),
        (
            13,
            format!(
                "<</FT/Ch/Ff 393216/T(country)/Opt[(US)[(de)(Germany)](US)]{w}/Rect[100 400 200 420]>>"
            )
            .into_bytes(),
        ),
        (
            14,
            format!("<</FT/Sig/T(sig1){w}/Rect[300 100 500 150]>>").into_bytes(),
        ),
        (
            15,
            format!("<</FT/Btn/Ff 65536/T(btn){w}/Rect[10 10 50 30]>>").into_bytes(),
        ),
        (
            16,
            format!("<</Parent 12 0 R{w}/Rect[100 300 110 310]/AP<</N<</one 20 0 R/Off 20 0 R>>>>>>")
                .into_bytes(),
        ),
        (
            17,
            format!("<</Parent 12 0 R{w}/Rect[150 300 160 310]/AP<</N<</two 20 0 R/Off 20 0 R>>>>>>")
                .into_bytes(),
        ),
        (
            18,
            format!("<</FT/Tx/T(off page){w}/Rect[700 900 720 920]>>").into_bytes(),
        ),
        (20, pdf::stream("/Type/XObject/Subtype/Form/BBox[0 0 10 10]", b"")),
    ];
    one_page(
        "/AcroForm<</Fields[10 0 R 11 0 R 12 0 R 13 0 R 14 0 R 15 0 R 18 0 R]>>",
        &format!("{page_extra}/Annots[10 0 R 11 0 R 13 0 R 14 0 R 15 0 R 16 0 R 17 0 R 18 0 R]"),
        "",
        b"",
        extra,
    )
}

fn convert(bytes: &[u8]) -> casual_sign_fields::Conversion {
    let mut a = admit(bytes, &Limits::default(), &never).unwrap();
    let mut n = 0;
    let mut next = || {
        n += 1;
        Id::new(format!("f{n}")).unwrap()
    };
    convert_acroform(
        &mut a.document,
        &a.report,
        &Id::new("doc").unwrap(),
        &mut next,
        &never,
    )
    .unwrap()
}

fn d(n: i64) -> Decimal {
    Decimal::from(n)
}

#[test]
fn each_widget_type_maps_with_its_flags_and_rectangle() {
    let bytes = form("");
    dump("acroform.pdf", &bytes);
    let c = convert(&bytes);
    let kinds: Vec<FieldType> = c.fields.iter().map(|f| f.field.field_type).collect();
    assert_eq!(
        kinds,
        vec![
            FieldType::Text,
            FieldType::Checkbox,
            FieldType::RadioGroup,
            FieldType::Dropdown,
            FieldType::Signature
        ]
    );
    let text = &c.fields[0].field;
    assert_eq!(text.id.as_str(), "f1");
    assert_eq!(text.document_id.as_str(), "doc");
    assert_eq!(text.label.as_ref().unwrap().as_str(), "Company Name");
    assert!(text.required && !text.read_only);
    assert_eq!(
        text.validation.as_ref().unwrap().rule,
        ValidationRule::Length(LengthRule::new(None, Some(40)).unwrap())
    );
    // Rect [100 600 300 620] on a 792-high page: top-left (100, 172), 200 × 20.
    let p = text.placement;
    assert_eq!(
        (
            p.page(),
            p.x().get(),
            p.y().get(),
            p.width().get(),
            p.height().get()
        ),
        (1, d(100), d(172), d(200), d(20))
    );
    assert_eq!(c.fields[0].object, Some(10));

    let check = &c.fields[1].field;
    assert!(check.read_only && !check.required);

    let radio = &c.fields[2].field;
    let opts: Vec<&str> = radio
        .options
        .as_slice()
        .iter()
        .map(|o| o.as_str())
        .collect();
    assert_eq!(opts, vec!["one", "two"]);
    // The two buttons' bounding box: x 100–160, y 792-310 = 482 to 492.
    assert_eq!(
        (
            radio.placement.x().get(),
            radio.placement.y().get(),
            radio.placement.width().get()
        ),
        (d(100), d(482), d(60))
    );

    let combo = &c.fields[3].field;
    let opts: Vec<&str> = combo
        .options
        .as_slice()
        .iter()
        .map(|o| o.as_str())
        .collect();
    assert_eq!(opts, vec!["US", "Germany"]);
    assert!(combo.allow_custom);

    assert_eq!(c.fields[4].field.field_type, FieldType::Signature);
}

#[test]
fn what_cannot_be_mapped_is_reported() {
    let c = convert(&form(""));
    let skipped: Vec<(Option<u32>, Unmapped)> =
        c.skipped.iter().map(|s| (s.object, s.reason)).collect();
    assert!(skipped.contains(&(Some(15), Unmapped::PushButton)));
    assert!(skipped.contains(&(Some(18), Unmapped::NoArea)));
    let lossy: Vec<(Option<u32>, Unmapped)> =
        c.lossy.iter().map(|s| (s.object, s.reason)).collect();
    assert_eq!(lossy, vec![(Some(13), Unmapped::Options)]);
}

#[test]
fn widgets_on_rotated_pages_are_placed_in_displayed_space() {
    let c = convert(&form("/Rotate 90"));
    let p = c.fields[0].field.placement;
    // Rotate 90 turns the page clockwise: displayed (x, y) = (user y, user x) here, so
    // Rect [100 600 300 620] covers displayed x 600–620, y 100–300.
    assert_eq!(
        (p.x().get(), p.y().get(), p.width().get(), p.height().get()),
        (d(600), d(100), d(20), d(200))
    );
}

/// One radio group (object 12) whose kids (16, 17, …) carry the given `/AP` entries,
/// with `group_extra` (an `/Opt`, say) on the field.
fn radio_group(group_extra: &str, kids_ap: &[&str]) -> Vec<u8> {
    let w = "/Type/Annot/Subtype/Widget/P 3 0 R";
    let kids: Vec<String> = (0..kids_ap.len())
        .map(|i| format!("{} 0 R", 16 + i))
        .collect();
    let mut extra = vec![
        (
            12,
            format!(
                "<</FT/Btn/Ff 49152/T(choice){group_extra}/Kids[{}]>>",
                kids.join(" ")
            )
            .into_bytes(),
        ),
        (
            20,
            pdf::stream("/Type/XObject/Subtype/Form/BBox[0 0 10 10]", b""),
        ),
    ];
    for (i, ap) in kids_ap.iter().enumerate() {
        let x = 100 + 20 * i;
        extra.push((
            u32::try_from(16 + i).unwrap(),
            format!(
                "<</Parent 12 0 R{w}/Rect[{x} 300 {} 310]/AS/Off{ap}>>",
                x + 10
            )
            .into_bytes(),
        ));
    }
    one_page(
        "/AcroForm<</Fields[12 0 R]>>",
        &format!("/Annots[{}]", kids.join(" ")),
        "",
        b"",
        extra,
    )
}

fn radio_options(bytes: &[u8]) -> Vec<String> {
    let c = convert(bytes);
    assert_eq!(c.fields.len(), 1, "{c:?}");
    c.fields[0]
        .field
        .options
        .as_slice()
        .iter()
        .map(|o| o.as_str().to_owned())
        .collect()
}

#[test]
fn radio_state_names_in_pdfdocencoding_or_utf8_become_their_characters() {
    // FLD-RADIO-NAME: ed-fafsa-2324 names a state `First bachelor` 0x90 `s degree`;
    // 0x90 is U+2019 in PDFDocEncoding. A UTF-8 name stays UTF-8.
    let bytes = radio_group(
        "",
        &[
            "/AP<</N<</First#20bachelor#90s#20degree 20 0 R/Off 20 0 R>>>>",
            "/AP<</N<</Caf#e9 20 0 R/Off 20 0 R>>>>",
            "/AP<</N<</Gr#c3#bc#c3#9fe 20 0 R/Off 20 0 R>>>>",
        ],
    );
    assert_eq!(
        radio_options(&bytes),
        vec![
            "First bachelor\u{2019}s degree",
            "Caf\u{e9}",
            "Gr\u{fc}\u{df}e"
        ]
    );
}

#[test]
fn a_radio_button_with_no_on_state_still_has_an_option() {
    // FLD-RADIO-NOOPT: ed-fafsa-2425 has buttons whose `/AP /N` is `<<>>` and `/D`
    // holds only `/Off`, and no `/Opt`. Each still needs a state to be chosen.
    let bytes = radio_group(
        "",
        &[
            "/AP<</N<</Yes 20 0 R>>>>",
            "/AP<</N<<>>/D<</Off 20 0 R>>>>",
            "",
        ],
    );
    assert_eq!(radio_options(&bytes), vec!["Yes", "1", "2"]);
}

#[test]
fn radio_options_come_from_opt_and_shared_states_are_one_option() {
    // `/Opt` gives each kid's export value, kids named by index (§12.7.5.2.4).
    let bytes = radio_group(
        "/Opt[(Married)(Single)(Single)]",
        &[
            "/AP<</N<</0 20 0 R/Off 20 0 R>>>>",
            "/AP<</N<</1 20 0 R/Off 20 0 R>>>>",
            "/AP<</N<</2 20 0 R/Off 20 0 R>>>>",
        ],
    );
    assert_eq!(
        radio_options(&bytes),
        vec!["Married", "Single", "Single (2)"]
    );
    // Kids sharing a state turn on together: one option.
    let bytes = radio_group(
        "",
        &[
            "/AP<</N<</Yes 20 0 R/Off 20 0 R>>>>",
            "/AP<</N<</Yes 20 0 R/Off 20 0 R>>>>",
            "/AP<</N<</No 20 0 R/Off 20 0 R>>>>",
        ],
    );
    assert_eq!(radio_options(&bytes), vec!["Yes", "No"]);
}

/// Two pages: catalog 1 (with `catalog_extra`), pages 2, page 3 (`/Annots` from
/// `annots1`), page 5 (`/Annots` from `annots2`), contents 4; `extra` from 10.
fn two_pages(
    catalog_extra: &str,
    annots1: &str,
    annots2: &str,
    extra: Vec<(u32, Vec<u8>)>,
) -> Vec<u8> {
    let page = |annots: &str| {
        format!(
            "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Annots[{annots}]/Resources<<>>/Contents 4 0 R>>"
        )
        .into_bytes()
    };
    let mut objs = vec![
        (
            1,
            format!("<</Type/Catalog/Pages 2 0 R{catalog_extra}>>").into_bytes(),
        ),
        (2, b"<</Type/Pages/Kids[3 0 R 5 0 R]/Count 2>>".to_vec()),
        (3, page(annots1)),
        (4, pdf::stream("", b"")),
        (5, page(annots2)),
    ];
    objs.extend(extra);
    pdf::classic(&objs)
}

#[test]
fn a_widget_without_p_is_on_the_page_whose_annots_lists_it() {
    // PDF-WID-01: 1997-era forms (irs-f1040-1997) give widgets no `/P`; viewers find
    // the page by its `/Annots`. One field on each page, neither with `/P`.
    let w = "/Type/Annot/Subtype/Widget";
    let bytes = two_pages(
        "/AcroForm<</Fields[10 0 R 11 0 R]>>",
        "10 0 R",
        "11 0 R",
        vec![
            (
                10,
                format!("<</FT/Tx/T(first){w}/Rect[100 600 300 620]>>").into_bytes(),
            ),
            (
                11,
                format!("<</FT/Btn/T(second){w}/Rect[100 500 112 512]>>").into_bytes(),
            ),
        ],
    );
    dump("acroform-no-p.pdf", &bytes);
    let c = convert(&bytes);
    assert!(c.skipped.is_empty(), "{:?}", c.skipped);
    let pages: Vec<(FieldType, u32)> = c
        .fields
        .iter()
        .map(|f| (f.field.field_type, f.field.placement.page()))
        .collect();
    assert_eq!(pages, vec![(FieldType::Text, 1), (FieldType::Checkbox, 2)]);
}
