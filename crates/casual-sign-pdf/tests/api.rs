//! The API stage 1C needed and duplicated in `casual-sign-fields` (`PDF-API-01`): the
//! content-stream tokenizer, text-string decoding, inherited page resources, and the
//! field flags, lengths, options and appearance states in the admission report.
// Test code: a panic is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use casual_sign_pdf::{
    ChoiceOption, ContentLexer, ContentToken, FieldType, Limits, Object, Operand, admit,
    admit_strict, decode_text_string,
};
use common::{classic, never, pages, stream, zlib};

#[test]
fn text_strings_decode_from_each_encoding() {
    assert_eq!(decode_text_string(b"Caf\xe9 \x80"), "Caf\u{e9} \u{2022}");
    assert_eq!(
        decode_text_string(&[0xFE, 0xFF, 0x04, 0x14, 0x00, 0x21]),
        "\u{414}!"
    );
    assert_eq!(decode_text_string(b"\xEF\xBB\xBFok"), "ok");
}

#[test]
fn page_resources_and_attributes_are_inherited_through_parents() {
    let objs = vec![
        (1, b"<</Type/Catalog/Pages 2 0 R>>".to_vec()),
        (
            2,
            b"<</Type/Pages/Kids[3 0 R]/Count 1/Resources<</Font<</F1 6 0 R>>>>/MediaBox[0 0 300 400]/Rotate 90>>"
                .to_vec(),
        ),
        (
            3,
            b"<</Type/Pages/Parent 2 0 R/Kids[4 0 R]/Count 1>>".to_vec(),
        ),
        (
            4,
            b"<</Type/Page/Parent 3 0 R/Contents 5 0 R>>".to_vec(),
        ),
        (5, stream("", b"BT /F1 9 Tf (x) Tj ET")),
        (6, b"<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>".to_vec()),
    ];
    let bytes = classic(&objs, "");
    let mut a = admit_strict(&bytes, &Limits::default(), &never).unwrap();
    let page = a.report.pages[0].object;
    let res = a.document.page_resources(page, &never).unwrap();
    let font = res.get(b"Font").unwrap();
    assert!(matches!(font, Object::Dictionary(d) if d.contains(b"F1")));
    assert_eq!(
        a.document
            .inherited_page_attribute(page, b"Rotate", &never)
            .unwrap(),
        Some(Object::Integer(90))
    );
    assert_eq!(
        a.document
            .inherited_page_attribute(page, b"CropBox", &never)
            .unwrap(),
        None
    );
    // A page's own value wins; a /Parent loop ends the walk.
    let mut objs = objs;
    objs[3].1 = b"<</Type/Page/Parent 3 0 R/Contents 5 0 R/Resources<<>>>>".to_vec();
    objs[2].1 = b"<</Type/Pages/Parent 3 0 R/Kids[4 0 R]/Count 1>>".to_vec();
    objs[0].1 = b"<</Type/Catalog/Pages 3 0 R>>".to_vec();
    let bytes = classic(&objs, "");
    let mut a = admit(&bytes, &Limits::default(), &never).unwrap();
    let page = a.report.pages[0].object;
    assert!(a.document.page_resources(page, &never).unwrap().is_empty());
    assert_eq!(
        a.document
            .inherited_page_attribute(page, b"MediaBox", &never)
            .unwrap(),
        None
    );
}

#[test]
fn the_content_lexer_reads_a_page_through_the_reader() {
    let mut objs = pages(1);
    objs[3].1 = stream(
        "/Filter/FlateDecode",
        &zlib(b"q BT /F1 12 Tf 72 720 Td [(Hel) -20 (lo)] TJ ET BI /W 1 /H 1 /BPC 8 /CS /G ID \xff EI Q"),
    );
    let bytes = classic(&objs, "");
    let mut a = admit_strict(&bytes, &Limits::default(), &never).unwrap();
    let data = a.document.decode_stream(4, &never).unwrap();
    let tokens: Vec<ContentToken<'_>> = ContentLexer::new(&data, &Limits::default())
        .collect::<Result<_, _>>()
        .unwrap();
    let ops: Vec<&[u8]> = tokens
        .iter()
        .filter_map(|t| match t {
            ContentToken::Operator(o) => Some(*o),
            _ => None,
        })
        .collect();
    assert_eq!(
        ops,
        vec![&b"q"[..], b"BT", b"Tf", b"Td", b"TJ", b"ET", b"Q"]
    );
    assert!(tokens.iter().any(|t| matches!(
        t,
        ContentToken::InlineImage { data, .. } if *data == b"\xff"
    )));
    assert!(tokens.contains(&ContentToken::Operand(Operand::Array(vec![
        Operand::String(b"Hel".to_vec()),
        Operand::Integer(-20),
        Operand::String(b"lo".to_vec()),
    ]))));
}

#[test]
fn fields_carry_flags_lengths_options_and_appearance_states() {
    let mut objs = pages(1);
    objs[0].1 =
        b"<</Type/Catalog/Pages 2 0 R/AcroForm<</Fields[10 0 R 11 0 R 12 0 R 13 0 R]>>>>".to_vec();
    objs.extend([
        // A text field inheriting /Ff and /MaxLen from its parent.
        (
            10,
            b"<</T(parent)/FT/Tx/Ff 2/MaxLen 9/Kids[20 0 R]>>".to_vec(),
        ),
        (
            20,
            b"<</T(child)/Parent 10 0 R/Rect[0 0 10 10]/P 3 0 R>>".to_vec(),
        ),
        // A combo box with plain and pair options.
        (
            11,
            b"<</T(combo)/FT/Ch/Ff 393216/Opt[(One)[(2)(Two)]<FEFF0414>]/Rect[0 0 10 10]>>"
                .to_vec(),
        ),
        // A check box with an on state.
        (
            12,
            b"<</T(check)/FT/Btn/Rect[0 0 10 10]/AP<</N<</Yes 30 0 R/Off 30 0 R>>>>>>".to_vec(),
        ),
        // A radio group with two buttons.
        (
            13,
            b"<</T(radio)/FT/Btn/Ff 49152/Kids[31 0 R 32 0 R]>>".to_vec(),
        ),
        (30, stream("/BBox[0 0 10 10]", b"")),
        (
            31,
            b"<</Parent 13 0 R/Rect[0 0 5 5]/AP<</N<</A 30 0 R/Off 30 0 R>>>>>>".to_vec(),
        ),
        (
            32,
            b"<</Parent 13 0 R/Rect[5 5 9 9]/AP<</N<</Off 30 0 R/B 30 0 R>>>>>>".to_vec(),
        ),
    ]);
    let bytes = classic(&objs, "");
    let a = admit_strict(&bytes, &Limits::default(), &never).unwrap();
    let f = &a.report.fields;
    assert_eq!(f[0].name, "parent.child");
    assert_eq!(f[0].field_type, FieldType::Text);
    assert_eq!(f[0].flags, 2);
    assert_eq!(f[0].max_len, Some(9));
    assert_eq!(f[1].field_type, FieldType::Choice);
    assert_eq!(f[1].flags, 393_216);
    assert_eq!(
        f[1].options,
        vec![
            ChoiceOption {
                export: "One".into(),
                display: "One".into()
            },
            ChoiceOption {
                export: "2".into(),
                display: "Two".into()
            },
            ChoiceOption {
                export: "\u{414}".into(),
                display: "\u{414}".into()
            },
        ]
    );
    assert_eq!(f[2].widgets[0].appearance_states, vec!["Yes".to_string()]);
    assert_eq!(f[3].field_type, FieldType::Radio);
    let states: Vec<&str> = f[3]
        .widgets
        .iter()
        .flat_map(|w| w.appearance_states.iter().map(String::as_str))
        .collect();
    assert_eq!(states, vec!["A", "B"]);
}
