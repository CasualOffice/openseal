//! A document's own form (docs/30 §7, `FILL-01`): removed when flattened, with frames
//! and unconverted appearances kept; filled in place and still fillable otherwise.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use casual_sign_fields::{DisplayRect, PageGeometry, convert_acroform};
use casual_sign_flatten::{FlattenInput, FlattenOptions, FontSet, FormMode, flatten};
use casual_sign_pdf::{Limits, Object, admit, admit_strict};
use common::*;

/// A one-page form: text (with frame), check box, radio pair, combo with an
/// export/display pair, comb text, a multiline text, a signature and a push button.
fn form_pdf(case: &PageCase) -> Vec<u8> {
    let w = "/Type/Annot/Subtype/Widget/P 3 0 R/F 4";
    let ap_on = stream(
        "/Type/XObject/Subtype/Form/BBox[0 0 12 12]",
        b"0 0 1 rg 2 2 8 8 re f",
    );
    let ap_off = stream("/Type/XObject/Subtype/Form/BBox[0 0 12 12]", b"");
    let button = stream(
        "/Type/XObject/Subtype/Form/BBox[0 0 60 20]",
        b"0.2 0.6 0.2 rg 0 0 60 20 re f",
    );
    let extra = vec![
        (
            5,
            b"<</Fields[10 0 R 11 0 R 12 0 R 13 0 R 14 0 R 15 0 R 18 0 R 19 0 R]/DA(/Helv 0 Tf 0 g)/NeedAppearances false/DR<</Font<</Helv 30 0 R>>>>>>".to_vec(),
        ),
        (
            10,
            format!("<</FT/Tx/T(company)/DA(/Helv 10 Tf 0 0 1 rg){w}/Rect[100 650 300 670]/MK<</BC[0 0 0]/BG[0.9 0.9 1]>>>>")
                .into_bytes(),
        ),
        (
            11,
            format!("<</FT/Btn/T(agree){w}/Rect[100 600 112 612]/AS/Off/AP<</N<</Yes 20 0 R/Off 21 0 R>>>>/MK<</BC[0 0 0]>>>>")
                .into_bytes(),
        ),
        (12, b"<</FT/Btn/Ff 49152/T(pick)/Kids[16 0 R 17 0 R]>>".to_vec()),
        (
            13,
            format!("<</FT/Ch/Ff 131072/T(country)/Opt[(US)[(de)(Germany)]]/DA(/Cour 9 Tf 0 g){w}/Rect[100 500 250 520]>>")
                .into_bytes(),
        ),
        (
            14,
            format!("<</FT/Sig/T(sign){w}/Rect[300 300 500 360]>>").into_bytes(),
        ),
        (
            15,
            format!("<</FT/Btn/Ff 65536/T(print){w}/Rect[400 700 460 720]/AP<</N 22 0 R>>>>")
                .into_bytes(),
        ),
        (
            16,
            format!("<</Parent 12 0 R{w}/Rect[100 550 112 562]/AP<</N<</one 20 0 R/Off 21 0 R>>>>/AS/Off>>")
                .into_bytes(),
        ),
        (
            17,
            format!("<</Parent 12 0 R{w}/Rect[150 550 162 562]/AP<</N<</two 20 0 R/Off 21 0 R>>>>/AS/Off>>")
                .into_bytes(),
        ),
        (
            18,
            format!("<</FT/Tx/T(zip)/Ff 16777216/MaxLen 5/DA(/Helv 12 Tf 0 g){w}/Rect[100 450 200 470]/MK<</BC[0.5 0.5 0.5]>>>>")
                .into_bytes(),
        ),
        (
            19,
            format!("<</FT/Tx/T(notes)/Ff 4096/DA(/TiRo 0 Tf 0 g){w}/Rect[300 400 500 470]/MK<</R 90/BC[1 0 0]>>>>")
                .into_bytes(),
        ),
        (20, ap_on),
        (21, ap_off),
        (22, button),
        (
            30,
            b"<</Type/Font/Subtype/Type1/BaseFont/Helvetica/Encoding/WinAnsiEncoding>>".to_vec(),
        ),
    ];
    page_pdf(
        case,
        "/AcroForm 5 0 R",
        "/Annots[10 0 R 11 0 R 16 0 R 17 0 R 13 0 R 14 0 R 15 0 R 18 0 R 19 0 R]",
        extra,
    )
}

fn manifest_entry(
    name: &str,
    case: &PageCase,
    rects: &[(String, DisplayRect, bool)],
    texts: &[&str],
    fill: Option<&[(&str, &str)]>,
) -> String {
    let (w, h) = case.displayed();
    let fields: Vec<String> = rects
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
    let texts: Vec<String> = texts.iter().map(|t| js(t)).collect();
    let fill = match fill {
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
        "{{\"name\":{},\"in\":{},\"out\":{},\"size\":[{w},{h}],\"fields\":[{}],\"texts\":[{}]{fill}}}",
        js(name),
        js(&format!("{name}.in.pdf")),
        js(&format!("{name}.out.pdf")),
        fields.join(","),
        texts.join(",")
    )
}

#[test]
fn a_converted_form_is_flattened_and_removed_or_filled_in_place() {
    let mut manifest = Vec::new();
    let cases: Vec<PageCase> = cases().into_iter().filter(|c| c.user_unit == 1.0).collect();
    for case in &cases {
        let base = delivered(&form_pdf(case));
        let mut a = admit(&base, &Limits::default(), &never).unwrap();
        let fields_before = a.report.fields.len();
        assert_eq!(fields_before, 8);
        let report = a.report.clone();
        let conv =
            convert_acroform(&mut a.document, &report, &id("doc"), &mut minter(), &never).unwrap();
        // Text, check box, radio group, combo, signature, zip, notes; not the button.
        assert_eq!(conv.fields.len(), 7, "{:?}", conv.skipped);
        let (values, caps) = fill_all(&conv);
        let fields: Vec<_> = conv.fields.iter().map(|c| c.field.clone()).collect();
        let input = FlattenInput {
            fields: &fields,
            values: &values,
            captures: &caps,
            envelope_id: Some("ENV-1"),
            acroform: Some(&conv),
        };
        let g = PageGeometry::from_page(&report.pages[0]);
        let button = g.rect_to_displayed(&casual_sign_pdf::Rect {
            llx: 400.0,
            lly: 700.0,
            urx: 460.0,
            ury: 720.0,
        });
        let rects: Vec<(String, DisplayRect, bool)> = fields
            .iter()
            .map(|f| {
                (
                    f.label.as_ref().map_or("?", |l| l.as_str()).to_owned(),
                    DisplayRect::from_placement(&f.placement),
                    true,
                )
            })
            .collect();

        // Flattened: the form is gone, frames and the button's look stay.
        let flat = flatten(
            &mut a,
            &input,
            &FontSet::bundled(),
            &FlattenOptions::default(),
            &never,
        )
        .unwrap();
        assert!(flat.bytes.starts_with(&base));
        assert!(flat.report.acroform_removed);
        assert_eq!(flat.report.widgets_removed, 9);
        assert_eq!(flat.report.appearances_kept, 1);
        assert_eq!(flat.report.drawn.len(), 7, "{:?}", flat.report.not_drawn);
        let b = admit_strict(&flat.bytes, &Limits::default(), &never).unwrap();
        assert!(b.report.fields.is_empty(), "no live field remains");
        let name = format!("form-flat-{}", case.name());
        dump(&format!("{name}.in.pdf"), &base);
        dump(&format!("{name}.out.pdf"), &flat.bytes);
        let mut flat_rects = rects.clone();
        // The button looks the same before and after: no change expected there.
        flat_rects.push(("print".to_owned(), button, false));
        manifest.push(manifest_entry(
            &name,
            case,
            &flat_rects,
            &["Sample42", "US"],
            None,
        ));

        // Filled in place: still a form, with our values and appearances.
        let mut a = admit(&base, &Limits::default(), &never).unwrap();
        let mut options = FlattenOptions::default();
        options.mode = FormMode::FillInPlace;
        let filled = flatten(&mut a, &input, &FontSet::bundled(), &options, &never).unwrap();
        assert!(filled.bytes.starts_with(&base));
        assert!(!filled.report.acroform_removed);
        // Six filled; the signature is drawn into the page.
        assert_eq!(filled.report.filled.len(), 6, "{:?}", filled.report);
        assert_eq!(filled.report.drawn.len(), 1);
        let mut b = admit_strict(&filled.bytes, &Limits::default(), &never).unwrap();
        assert_eq!(b.report.fields.len(), fields_before, "fields still listed");
        let root = b.document.trailer().get(b"Root").unwrap().as_ref().unwrap();
        let cat = b.document.object(root.num, &never).unwrap();
        let form = b
            .document
            .resolve(cat.get(b"AcroForm").unwrap(), &never)
            .unwrap();
        assert_eq!(form.get(b"NeedAppearances"), Some(&Object::Bool(false)));
        let company = b.document.object(10, &never);
        // Object numbers are renumbered by normalization: find the field by name.
        let _ = company;
        let name = format!("form-fill-{}", case.name());
        dump(&format!("{name}.in.pdf"), &base);
        dump(&format!("{name}.out.pdf"), &filled.bytes);
        let mut fill_rects = rects.clone();
        fill_rects.push(("print".to_owned(), button, false));
        manifest.push(manifest_entry(
            &name,
            case,
            &fill_rects,
            &[],
            Some(&[
                ("company", "Sample 42"),
                ("agree", "/Yes"),
                ("pick", "/one"),
                ("country", "US"),
                ("zip", "Sample 42"),
                ("notes", "Sample 42"),
            ]),
        ));
    }
    if dump_dir().is_some() {
        // Written beside the main manifest, which the other test owns.
        dump(
            "manifest-form.json",
            format!("[\n{}\n]\n", manifest.join(",\n")).as_bytes(),
        );
    }
}

#[test]
fn a_check_box_with_several_on_states_turns_on_only_the_chosen_one() {
    let w = "/Type/Annot/Subtype/Widget/P 3 0 R/F 4";
    let on = stream(
        "/Type/XObject/Subtype/Form/BBox[0 0 12 12]",
        b"0 g 2 2 8 8 re f",
    );
    let extra = vec![
        (5, b"<</Fields[10 0 R]/DA(/Helv 0 Tf 0 g)>>".to_vec()),
        (10, b"<</FT/Btn/T(group)/Kids[11 0 R 12 0 R]>>".to_vec()),
        (
            11,
            format!("<</Parent 10 0 R{w}/Rect[100 600 112 612]/AS/Off/AP<</N<</A 20 0 R/Off 20 0 R>>>>>>")
                .into_bytes(),
        ),
        (
            12,
            format!("<</Parent 10 0 R{w}/Rect[100 580 112 592]/AS/Off/AP<</N<</B 20 0 R/Off 20 0 R>>>>>>")
                .into_bytes(),
        ),
        (20, on),
    ];
    let base = delivered(&page_pdf(
        &cases()[0],
        "/AcroForm 5 0 R",
        "/Annots[11 0 R 12 0 R]",
        extra,
    ));
    let mut a = admit(&base, &Limits::default(), &never).unwrap();
    let report = a.report.clone();
    let conv =
        convert_acroform(&mut a.document, &report, &id("doc"), &mut minter(), &never).unwrap();
    let (values, caps) = fill_all(&conv);
    let fields: Vec<_> = conv.fields.iter().map(|c| c.field.clone()).collect();
    let input = FlattenInput {
        fields: &fields,
        values: &values,
        captures: &caps,
        envelope_id: None,
        acroform: Some(&conv),
    };
    let mut options = FlattenOptions::default();
    options.mode = FormMode::FillInPlace;
    let out = flatten(&mut a, &input, &FontSet::bundled(), &options, &never).unwrap();
    let mut b = admit_strict(&out.bytes, &Limits::default(), &never).unwrap();
    let widgets: Vec<u32> = b.report.fields[0]
        .widgets
        .iter()
        .map(|w| w.object.unwrap())
        .collect();
    let states: Vec<Option<Vec<u8>>> = widgets
        .iter()
        .map(|n| {
            b.document
                .object(*n, &never)
                .unwrap()
                .dict()
                .and_then(|d| d.name(b"AS"))
                .map(<[u8]>::to_vec)
        })
        .collect();
    assert_eq!(states, vec![Some(b"A".to_vec()), Some(b"Off".to_vec())]);
}

/// A radio group (object 10) with `group_extra` on the field and kids 11, 12, … with
/// the given `/AP` entries, delivered.
fn radio_doc(group_extra: &str, kids_ap: &[&str]) -> Vec<u8> {
    let w = "/Type/Annot/Subtype/Widget/P 3 0 R/F 4";
    let kids: Vec<String> = (0..kids_ap.len())
        .map(|i| format!("{} 0 R", 11 + i))
        .collect();
    let on = stream(
        "/Type/XObject/Subtype/Form/BBox[0 0 12 12]",
        b"0 g 2 2 8 8 re f",
    );
    let mut extra = vec![
        (5, b"<</Fields[10 0 R]/DA(/Helv 0 Tf 0 g)>>".to_vec()),
        (
            10,
            format!(
                "<</FT/Btn/Ff 49152/T(group){group_extra}/Kids[{}]>>",
                kids.join(" ")
            )
            .into_bytes(),
        ),
        (30, on),
    ];
    for (i, ap) in kids_ap.iter().enumerate() {
        let y = 600 - 20 * i;
        extra.push((
            u32::try_from(11 + i).unwrap(),
            format!(
                "<</Parent 10 0 R{w}/Rect[100 {y} 112 {}]/AS/Off{ap}>>",
                y + 12
            )
            .into_bytes(),
        ));
    }
    delivered(&page_pdf(
        &cases()[0],
        "/AcroForm 5 0 R",
        &format!("/Annots[{}]", kids.join(" ")),
        extra,
    ))
}

/// Fill the group in place with each of its options in turn, and flatten with each:
/// returns, per option, `/V` and every widget's `/AS` and normal-appearance keys.
#[allow(clippy::type_complexity)] // A table of what each fill wrote.
fn radio_fills(base: &[u8]) -> Vec<(String, Vec<u8>, Vec<(Vec<u8>, Vec<Vec<u8>>)>)> {
    let mut out = Vec::new();
    let mut a = admit(base, &Limits::default(), &never).unwrap();
    let report = a.report.clone();
    let conv =
        convert_acroform(&mut a.document, &report, &id("doc"), &mut minter(), &never).unwrap();
    let fields: Vec<_> = conv.fields.iter().map(|c| c.field.clone()).collect();
    assert_eq!(fields.len(), 1);
    let caps = std::collections::BTreeMap::new();
    for option in fields[0].options.as_slice() {
        let values = std::collections::BTreeMap::from([(
            fields[0].id.clone(),
            casual_sign_model::FieldValue::Choice(option.clone()),
        )]);
        let input = FlattenInput {
            fields: &fields,
            values: &values,
            captures: &caps,
            envelope_id: None,
            acroform: Some(&conv),
        };
        let mut a = admit(base, &Limits::default(), &never).unwrap();
        let flat = flatten(
            &mut a,
            &input,
            &FontSet::bundled(),
            &FlattenOptions::default(),
            &never,
        )
        .unwrap_or_else(|e| panic!("flatten {}: {e}", option.as_str()));
        assert_eq!(flat.report.drawn, vec![fields[0].id.clone()]);
        // The button is drawn, not the option's text: no face is embedded.
        assert!(
            flat.report.fonts.is_empty(),
            "flatten {} drew text",
            option.as_str()
        );
        let mut a = admit(base, &Limits::default(), &never).unwrap();
        let mut options = FlattenOptions::default();
        options.mode = FormMode::FillInPlace;
        let filled = flatten(&mut a, &input, &FontSet::bundled(), &options, &never)
            .unwrap_or_else(|e| panic!("fill {}: {e}", option.as_str()));
        let mut b = admit_strict(&filled.bytes, &Limits::default(), &never).unwrap();
        let f = b.report.fields[0].clone();
        let v = b
            .document
            .object(f.object.unwrap(), &never)
            .unwrap()
            .dict()
            .and_then(|d| d.name(b"V"))
            .map(<[u8]>::to_vec)
            .unwrap_or_default();
        let mut widgets = Vec::new();
        for w in &f.widgets {
            let d = b.document.object(w.object.unwrap(), &never).unwrap();
            let d = d.dict().unwrap().clone();
            let state = d.name(b"AS").map(<[u8]>::to_vec).unwrap_or_default();
            let ap = b.document.resolve(d.get(b"AP").unwrap(), &never).unwrap();
            let n = b.document.resolve(ap.get(b"N").unwrap(), &never).unwrap();
            let keys = match n {
                Object::Dictionary(n) => n.iter().map(|(k, _)| k.to_vec()).collect(),
                _ => Vec::new(),
            };
            widgets.push((state, keys));
        }
        out.push((option.as_str().to_owned(), v, widgets));
    }
    out
}

#[test]
fn radio_states_named_in_pdfdocencoding_fill_and_flatten_with_their_own_bytes() {
    // FLD-RADIO-NAME (ed-fafsa-2324): the state `First bachelor` 0x90 `s degree` is
    // offered as "First bachelor’s degree" and written back as its own bytes; flattening
    // draws the button, not the option's text.
    let base = radio_doc(
        "",
        &[
            "/AP<</N<</First#20bachelor#90s#20degree 30 0 R/Off 30 0 R>>>>",
            "/AP<</N<</Caf#e9 30 0 R>>>>",
        ],
    );
    let name = b"First bachelor\x90s degree".to_vec();
    let off = b"Off".to_vec();
    let rows = radio_fills(&base);
    assert_eq!(
        rows,
        vec![
            (
                "First bachelor\u{2019}s degree".to_owned(),
                name.clone(),
                vec![
                    (name.clone(), vec![name.clone(), off.clone()]),
                    (off.clone(), vec![b"Caf\xe9".to_vec()]),
                ]
            ),
            (
                "Caf\u{e9}".to_owned(),
                b"Caf\xe9".to_vec(),
                vec![
                    (off.clone(), vec![name.clone(), off.clone()]),
                    (b"Caf\xe9".to_vec(), vec![b"Caf\xe9".to_vec()]),
                ]
            ),
        ]
    );
}

#[test]
fn radio_buttons_without_an_on_state_or_with_opt_fill_and_flatten() {
    // FLD-RADIO-NOOPT (ed-fafsa-2425): a button whose `/AP /N` is empty gets a minted
    // state, its position, and an appearance drawn for it when chosen.
    let base = radio_doc(
        "",
        &[
            "/AP<</N<</Yes 30 0 R/Off 30 0 R>>>>",
            "/AP<</N<<>>/D<</Off 30 0 R>>>>",
        ],
    );
    let (yes, one, off) = (b"Yes".to_vec(), b"1".to_vec(), b"Off".to_vec());
    assert_eq!(
        radio_fills(&base),
        vec![
            (
                "Yes".to_owned(),
                yes.clone(),
                vec![
                    (yes.clone(), vec![yes.clone(), off.clone()]),
                    (off.clone(), vec![]),
                ]
            ),
            (
                "1".to_owned(),
                one.clone(),
                vec![
                    (off.clone(), vec![yes.clone(), off.clone()]),
                    (one.clone(), vec![one.clone(), off.clone()]),
                ]
            ),
        ]
    );
    // `/Opt`: the export values are offered; the kids' index states are written.
    let base = radio_doc(
        "/Opt[(Married)(Single)]",
        &[
            "/AP<</N<</0 30 0 R/Off 30 0 R>>>>",
            "/AP<</N<</1 30 0 R/Off 30 0 R>>>>",
        ],
    );
    let rows = radio_fills(&base);
    let written: Vec<(String, Vec<u8>)> = rows.into_iter().map(|(o, v, _)| (o, v)).collect();
    assert_eq!(
        written,
        vec![
            ("Married".to_owned(), b"0".to_vec()),
            ("Single".to_owned(), b"1".to_vec())
        ]
    );
}

/// A radio group (object 10) with one button on each of two pages (11 on page 1, state
/// `one`; 12 on page 2, state `two`, its on appearance object 30), delivered.
fn radio_two_pages() -> Vec<u8> {
    let w = "/Type/Annot/Subtype/Widget/F 4";
    let page = |annots: &str| {
        format!(
            "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Annots[{annots}]/Resources<<>>/Contents 4 0 R>>"
        )
        .into_bytes()
    };
    let on = |n: &str| {
        stream(
            "/Type/XObject/Subtype/Form/BBox[0 0 12 12]",
            format!("0 g 2 2 {n} 8 re f").as_bytes(),
        )
    };
    delivered(&classic(&[
        (
            1,
            b"<</Type/Catalog/Pages 2 0 R/AcroForm<</Fields[10 0 R]>>>>".to_vec(),
        ),
        (2, b"<</Type/Pages/Kids[3 0 R 6 0 R]/Count 2>>".to_vec()),
        (3, page("11 0 R")),
        (4, stream("", b"")),
        (6, page("12 0 R")),
        (
            10,
            b"<</FT/Btn/Ff 49152/T(group)/Kids[11 0 R 12 0 R]>>".to_vec(),
        ),
        (
            11,
            format!("<</Parent 10 0 R{w}/P 3 0 R/Rect[100 600 112 612]/AS/Off/AP<</N<</one 29 0 R/Off 31 0 R>>>>>>")
                .into_bytes(),
        ),
        (
            12,
            format!("<</Parent 10 0 R{w}/P 6 0 R/Rect[100 300 112 312]/AS/Off/AP<</N<</two 30 0 R/Off 31 0 R>>>>>>")
                .into_bytes(),
        ),
        (29, on("7")),
        (30, on("8")),
        (31, stream("/Type/XObject/Subtype/Form/BBox[0 0 12 12]", b"")),
    ]))
}

#[test]
fn a_radio_group_across_pages_is_chosen_once_and_drawn_on_the_chosen_page() {
    // ACRO-02: the group is a field on each page, linked by label; choosing `two` on
    // page 1's field turns on page 2's button, drawn once, and fills `/V` once.
    let base = radio_two_pages();
    let mut a = admit(&base, &Limits::default(), &never).unwrap();
    let report = a.report.clone();
    let conv =
        convert_acroform(&mut a.document, &report, &id("doc"), &mut minter(), &never).unwrap();
    let fields: Vec<_> = conv.fields.iter().map(|c| c.field.clone()).collect();
    assert_eq!(
        fields
            .iter()
            .map(|f| f.placement.page())
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    // What completion hands flattening: the linked value on both fields.
    let chosen = std::collections::BTreeMap::from([(fields[0].id.clone(), choice("two"))]);
    let values = casual_sign_fields::evaluate_envelope(&fields, &chosen).values;
    assert_eq!(values.len(), 2);
    let caps = std::collections::BTreeMap::new();
    let input = FlattenInput {
        fields: &fields,
        values: &values,
        captures: &caps,
        envelope_id: None,
        acroform: Some(&conv),
    };
    let flat = flatten(
        &mut a,
        &input,
        &FontSet::bundled(),
        &FlattenOptions::default(),
        &never,
    )
    .unwrap();
    dump("radio-two-pages.out.pdf", &flat.bytes);
    assert_eq!(flat.report.drawn.len(), 2);
    let mut b = admit_strict(&flat.bytes, &Limits::default(), &never).unwrap();
    // Which appearance objects each page now invokes.
    let mut invoked = Vec::new();
    for p in b.report.pages.clone() {
        let page = b.document.object(p.object, &never).unwrap();
        let res = b
            .document
            .resolve(page.get(b"Resources").unwrap(), &never)
            .unwrap();
        let mut refs: Vec<u32> = Vec::new();
        if let Some(x) = res.get(b"XObject")
            && let Object::Dictionary(x) = b.document.resolve(x, &never).unwrap()
        {
            refs = x
                .iter()
                .filter_map(|(_, v)| v.as_ref().map(|r| r.num))
                .collect();
        }
        invoked.push(refs.len());
    }
    // Delivery renumbers objects; what counts is one invocation, on page 2.
    assert_eq!(invoked, vec![0, 1]);
}
