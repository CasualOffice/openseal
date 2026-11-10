//! What the signer sees is what is sealed (`FLT-03`, SEC-S03): optional content
//! flattened to its default visibility, annotations flattened or removed; and a
//! converted checkbox drawn with its own on appearance (`FLT-04`).
//!
//! Each document draws marker words; [`shown`] collects every string the flattened
//! page can still draw (page content and every form it reaches), which must be exactly
//! the visible ones. `tools/check_layers.py` checks the same with PDFium.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::collections::{BTreeMap, BTreeSet};

use casual_sign_fields::convert_acroform;
use casual_sign_flatten::limits::{MAX_VE_DEPTH, MAX_VE_TERMS};
use casual_sign_flatten::{
    FlattenError, FlattenInput, FlattenOptions, Flattened, FontSet, FormMode, flatten,
};
use casual_sign_model::FieldValue;
use casual_sign_pdf::{ContentLexer, ContentToken, Document, Limits, Object, Operand, admit};
use common::*;

/// Strings drawn by `data` and, through `Do`, by the forms in `res`. `strict`: no
/// optional content marker may be left either.
fn strings(
    doc: &mut Document<'_>,
    data: &[u8],
    res: &casual_sign_pdf::Dictionary,
    strict: bool,
    seen: &mut BTreeSet<u32>,
    out: &mut Vec<String>,
) {
    let xobjects = match res.get(b"XObject") {
        Some(v) => doc.resolve(v, &never).unwrap().dict().cloned().unwrap(),
        None => casual_sign_pdf::Dictionary::new(),
    };
    let mut last: Vec<Operand> = Vec::new();
    for tok in ContentLexer::new(data, &Limits::default()) {
        match tok.unwrap() {
            ContentToken::Operand(o) => last.push(o),
            ContentToken::Operator(op) => {
                match op {
                    b"Tj" | b"'" | b"\"" => {
                        if let Some(Operand::String(s)) = last.last() {
                            out.push(String::from_utf8_lossy(s).into_owned());
                        }
                    }
                    b"TJ" => {
                        if let Some(Operand::Array(a)) = last.last() {
                            let s: Vec<u8> = a
                                .iter()
                                .filter_map(Operand::as_string)
                                .flatten()
                                .copied()
                                .collect();
                            out.push(String::from_utf8_lossy(&s).into_owned());
                        }
                    }
                    b"Do" => {
                        let name = last.last().and_then(Operand::as_name).unwrap().to_vec();
                        let r = xobjects.get(&name).and_then(Object::as_ref).unwrap();
                        if seen.insert(r.num) {
                            let Object::Stream(s) = doc.object(r.num, &never).unwrap() else {
                                panic!("not a stream")
                            };
                            // With no configuration left, a viewer would decide on its
                            // own (PDFium takes every group as on).
                            assert!(
                                !strict || s.dict.get(b"OC").is_none(),
                                "XObject {} keeps /OC",
                                r.num
                            );
                            let inner = match s.dict.get(b"Resources") {
                                Some(v) => doc.resolve(v, &never).unwrap().dict().cloned().unwrap(),
                                None => res.clone(),
                            };
                            let bytes = doc.decode_stream(r.num, &never).unwrap();
                            strings(doc, &bytes, &inner, strict, seen, out);
                            seen.remove(&r.num);
                        }
                    }
                    b"BDC" => {
                        let tag = last.iter().rev().nth(1).and_then(Operand::as_name);
                        assert!(
                            !strict || tag != Some(&b"OC"[..]),
                            "an /OC marker with properties left"
                        );
                    }
                    _ => {}
                }
                last.clear();
            }
            _ => last.clear(),
        }
    }
}

/// Every string the first page of `bytes` draws, and its annotations' object
/// numbers. Optional content must be gone, so nothing drawn is conditional.
fn shown(bytes: &[u8]) -> (Vec<String>, Vec<u32>) {
    shown_with(bytes, true)
}

/// As [`shown`]; `strict` also requires every optional content marker gone.
fn shown_with(bytes: &[u8], strict: bool) -> (Vec<String>, Vec<u32>) {
    let mut a = admit(bytes, &Limits::default(), &never).unwrap();
    let doc = &mut a.document;
    let root = doc.trailer().get(b"Root").unwrap().as_ref().unwrap();
    let cat = doc.object(root.num, &never).unwrap();
    assert!(cat.get(b"OCProperties").is_none(), "optional content left");
    let page_num = a.report.pages[0].object;
    let page = doc
        .object(page_num, &never)
        .unwrap()
        .dict()
        .cloned()
        .unwrap();
    let res = doc.page_resources(page_num, &never).unwrap();
    let mut data = Vec::new();
    let contents = doc.resolve(page.get(b"Contents").unwrap(), &never).unwrap();
    let list = match contents {
        Object::Array(a) => a,
        _ => vec![page.get(b"Contents").unwrap().clone()],
    };
    for c in list {
        data.extend(doc.decode_stream(c.as_ref().unwrap().num, &never).unwrap());
        data.push(b'\n');
    }
    let mut out = Vec::new();
    strings(doc, &data, &res, strict, &mut BTreeSet::new(), &mut out);
    let annots = match page.get(b"Annots") {
        Some(v) => match doc.resolve(v, &never).unwrap() {
            Object::Array(a) => a.iter().filter_map(Object::as_ref).map(|r| r.num).collect(),
            _ => Vec::new(),
        },
        None => Vec::new(),
    };
    (out, annots)
}

const FONT: &str = "<</Type/Font/Subtype/Type1/BaseFont/Helvetica/Encoding/WinAnsiEncoding>>";

/// A text line at `y` drawing `word`.
fn line(y: u32, word: &str) -> String {
    format!("BT /F1 11 Tf 72 {y} Td ({word}) Tj ET\n")
}

/// A form drawing `word` at its origin in red.
fn form(extra: &str, word: &str) -> Vec<u8> {
    stream(
        &format!(
            "/Type/XObject/Subtype/Form/BBox[0 0 200 20]/Resources<</Font<</F1 5 0 R>>>>{extra}"
        ),
        format!("1 0 0 rg BT /F1 11 Tf 2 5 Td ({word}) Tj ET").as_bytes(),
    )
}

/// Words the layered document shows by default, and those it hides.
const SHOWN: [&str; 11] = [
    "FORMPLAIN",
    "INTENTSHOWN",
    "BASE",
    "ONTEXT",
    "ANYOFFVIS",
    "ALLONVIS",
    "VEVIS",
    "NESTEDON",
    "FORMON",
    "ANNOTSHOWN",
    "STAMPON",
];
const HIDDEN: [&str; 13] = [
    "SPANINNER",
    "SPANAFTER",
    "OFFTEXT",
    "ALLONHID",
    "ANYOFFHID",
    "VEHID",
    "NESTEDOFF",
    "FORMOFF",
    "FORMINNEROFF",
    "ANNOTHIDDEN",
    "ANNOTNOVIEW",
    "STAMPOFF",
    "ANNOTOC",
];

/// One page with optional content of every kind and annotations of every kind.
///
/// Groups: 10 on, 11 off (in `/OFF`), 12 on, 13 off but for the Design intent only
/// (so it has no effect: its content shows). Membership dictionaries 20 to 25.
fn layered() -> Vec<u8> {
    let mut content = String::new();
    content.push_str(&line(740, "BASE"));
    content.push_str(&format!("/OC /On BDC\n{}EMC\n", line(720, "ONTEXT")));
    content.push_str(&format!(
        "/OC /Off BDC\n{}0 0 1 rg 300 600 50 50 re f\nEMC\n",
        line(700, "OFFTEXT")
    ));
    for (y, name, word) in [
        (680, "AnyOffVis", "ANYOFFVIS"),
        (660, "AllOnHid", "ALLONHID"),
        (640, "AllOnVis", "ALLONVIS"),
        (620, "AnyOffHid", "ANYOFFHID"),
        (600, "VeHid", "VEHID"),
        (580, "VeVis", "VEVIS"),
    ] {
        content.push_str(&format!("/OC /{name} BDC\n{}EMC\n", line(y, word)));
    }
    content.push_str(&format!(
        "/OC /On BDC\n/OC /Off BDC\n{}EMC\n{}EMC\n",
        line(560, "NESTEDOFF"),
        line(540, "NESTEDON")
    ));
    // Marked content inside a hidden section does not end it.
    content.push_str(&format!(
        "/OC /Off BDC\n/Span <</ActualText (x)>> BDC\n{}EMC\n{}EMC\n",
        line(400, "SPANINNER"),
        line(380, "SPANAFTER")
    ));
    content.push_str("q 1 0 0 1 72 500 cm /FmOff Do Q\n");
    content.push_str("q 1 0 0 1 72 480 cm /FmOn Do Q\n");
    // A visible form whose content does not change: it only loses its `/OC`.
    content.push_str("q 1 0 0 1 72 460 cm /FmPlain Do Q\n");
    // Design-only group 13 is listed in OFF but its intent is not the configuration's.
    content.push_str(&format!(
        "/OC /IntentOff BDC\n{}EMC\n",
        line(420, "INTENTSHOWN")
    ));

    let ap = |word: &str| form("", word);
    let objs = vec![
        (
            1,
            b"<</Type/Catalog/Pages 2 0 R/OCProperties<</OCGs[10 0 R 11 0 R 12 0 R 13 0 R]/D<</Order[10 0 R 11 0 R]/OFF[11 0 R 13 0 R]>>>>>>".to_vec(),
        ),
        (2, b"<</Type/Pages/Kids[3 0 R]/Count 1>>".to_vec()),
        (
            3,
            b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<</Font<</F1 5 0 R>>/Properties<</On 10 0 R/Off 11 0 R/AnyOffVis 20 0 R/AllOnHid 21 0 R/AllOnVis 22 0 R/AnyOffHid 23 0 R/VeHid 24 0 R/VeVis 25 0 R/IntentOff 13 0 R>>/XObject<</FmOff 30 0 R/FmOn 31 0 R/FmPlain 32 0 R>>>>/Contents 4 0 R/Annots[40 0 R 42 0 R 43 0 R 44 0 R 45 0 R 46 0 R 47 0 R 48 0 R]>>".to_vec(),
        ),
        (4, stream("", content.as_bytes())),
        (5, FONT.as_bytes().to_vec()),
        (10, b"<</Type/OCG/Name(on)>>".to_vec()),
        (11, b"<</Type/OCG/Name(off)>>".to_vec()),
        (12, b"<</Type/OCG/Name(on too)>>".to_vec()),
        (13, b"<</Type/OCG/Name(design)/Intent/Design>>".to_vec()),
        (20, b"<</Type/OCMD/OCGs[10 0 R 11 0 R]/P/AnyOff>>".to_vec()),
        (21, b"<</Type/OCMD/OCGs[10 0 R 11 0 R]/P/AllOn>>".to_vec()),
        (22, b"<</Type/OCMD/OCGs[10 0 R 12 0 R]/P/AllOn>>".to_vec()),
        (23, b"<</Type/OCMD/OCGs[10 0 R 12 0 R]/P/AnyOff>>".to_vec()),
        // The expression wins over the policy, which alone would show it.
        (
            24,
            b"<</Type/OCMD/OCGs[10 0 R]/P/AnyOn/VE[/And 10 0 R [/Not 12 0 R]]>>".to_vec(),
        ),
        (
            25,
            b"<</Type/OCMD/OCGs[11 0 R]/P/AllOn/VE[/Or 11 0 R [/Not [/And 11 0 R 12 0 R]]]>>"
                .to_vec(),
        ),
        (30, form("/OC 11 0 R", "FORMOFF")),
        (32, form("/OC 22 0 R", "FORMPLAIN")),
        (
            31,
            stream(
                "/Type/XObject/Subtype/Form/BBox[0 0 300 20]/OC 10 0 R/Resources<</Font<</F1 5 0 R>>/Properties<</Hide 11 0 R>>>>",
                b"BT /F1 11 Tf 2 5 Td (FORMON) Tj ET /OC /Hide BDC BT /F1 11 Tf 100 5 Td (FORMINNEROFF) Tj ET EMC",
            ),
        ),
        // A square with an appearance and a pop-up: drawn, both removed.
        (
            40,
            b"<</Type/Annot/Subtype/Square/Rect[300 300 500 320]/F 4/AP<</N 41 0 R>>/Popup 42 0 R>>"
                .to_vec(),
        ),
        (41, ap("ANNOTSHOWN")),
        (
            42,
            b"<</Type/Annot/Subtype/Popup/Rect[400 400 500 450]/Parent 40 0 R/Open true>>".to_vec(),
        ),
        // Hidden, and NoView (but printable): the signer never saw them.
        (
            43,
            b"<</Type/Annot/Subtype/FreeText/Rect[300 260 500 280]/F 2/AP<</N 49 0 R>>>>".to_vec(),
        ),
        (
            44,
            b"<</Type/Annot/Subtype/FreeText/Rect[300 240 500 260]/F 36/AP<</N 50 0 R>>>>".to_vec(),
        ),
        // A stamp with appearance states: the one `/AS` names is drawn.
        (
            45,
            b"<</Type/Annot/Subtype/Stamp/Rect[300 200 500 220]/F 4/AS/On/AP<</N<</On 51 0 R/Off 52 0 R>>>>>>"
                .to_vec(),
        ),
        // A link and a note without an appearance stay.
        (
            46,
            b"<</Type/Annot/Subtype/Link/Rect[72 100 200 120]/Border[0 0 0]/Dest[3 0 R/Fit]>>"
                .to_vec(),
        ),
        (
            47,
            b"<</Type/Annot/Subtype/Text/Rect[72 60 92 80]/Contents(note)>>".to_vec(),
        ),
        // In hidden optional content: removed.
        (
            48,
            b"<</Type/Annot/Subtype/Square/Rect[300 160 500 180]/OC 11 0 R/AP<</N 53 0 R>>>>"
                .to_vec(),
        ),
        (49, ap("ANNOTHIDDEN")),
        (50, ap("ANNOTNOVIEW")),
        (51, ap("STAMPON")),
        (52, ap("STAMPOFF")),
        (53, ap("ANNOTOC")),
    ];
    classic(&objs)
}

fn flatten_plain(base: &[u8], options: &FlattenOptions) -> Result<Flattened, FlattenError> {
    let mut a = admit(base, &Limits::default(), &never).unwrap();
    let values = BTreeMap::new();
    let caps = BTreeMap::new();
    let input = FlattenInput {
        fields: &[],
        values: &values,
        captures: &caps,
        envelope_id: None,
        acroform: None,
    };
    flatten(&mut a, &input, &FontSet::bundled(), options, &never)
}

#[test]
fn optional_content_is_flattened_to_its_default_visibility() {
    let base = delivered(&layered());
    let out = flatten_plain(&base, &FlattenOptions::default()).unwrap();
    assert!(out.bytes.starts_with(&base));
    dump("layers.in.pdf", &base);
    dump("layers.out.pdf", &out.bytes);
    assert!(out.report.optional_content_flattened);
    let (words, _) = shown(&out.bytes);
    for w in [
        "BASE",
        "ONTEXT",
        "ANYOFFVIS",
        "ALLONVIS",
        "VEVIS",
        "NESTEDON",
        "FORMON",
    ] {
        assert!(words.iter().any(|s| s == w), "{w} should show: {words:?}");
    }
    for w in [
        "OFFTEXT",
        "ALLONHID",
        "ANYOFFHID",
        "VEHID",
        "NESTEDOFF",
        "FORMOFF",
        "FORMINNEROFF",
    ] {
        assert!(
            !words.iter().any(|s| s == w),
            "{w} should be hidden: {words:?}"
        );
    }
    // A group whose intent is not the configuration's has no effect.
    assert!(words.iter().any(|s| s == "INTENTSHOWN"), "{words:?}");
    // Seven hidden sections: off, AllOnHid, AnyOffHid, VeHid, nested, span, the form's.
    assert_eq!(out.report.hidden_sections, 7, "{:?}", out.report);
    // Everything the layered page shows, and nothing else (annotations included).
    for w in SHOWN {
        assert!(words.iter().any(|s| s == w), "{w} should show: {words:?}");
    }
    for w in HIDDEN {
        assert!(!words.iter().any(|s| s == w), "{w} should not: {words:?}");
    }
    if dump_dir().is_some() {
        let list = |l: &[&str]| l.iter().map(|w| js(w)).collect::<Vec<_>>().join(",");
        dump(
            "layers.json",
            format!(
                // PDFium draws an annotation whatever its `/OC` says (the square of
                // object 48), so its rendering of the input is not compared there.
                "[{{\"in\":\"layers.in.pdf\",\"out\":\"layers.out.pdf\",\"shown\":[{}],\"hidden\":[{}],\"ignore\":[[300,160,500,180]]}},\n\
                 {{\"in\":\"layers-base-off.in.pdf\",\"out\":\"layers-base-off.out.pdf\",\"shown\":[\"TURNEDON\"],\"hidden\":[\"BASEOFF\"]}}]\n",
                list(&SHOWN),
                list(&HIDDEN)
            )
            .as_bytes(),
        );
    }
}

#[test]
fn annotations_are_drawn_from_their_appearance_or_removed_when_unseen() {
    let base = delivered(&layered());
    let out = flatten_plain(&base, &FlattenOptions::default()).unwrap();
    let (words, annots) = shown(&out.bytes);
    for w in ["ANNOTSHOWN", "STAMPON"] {
        assert!(words.iter().any(|s| s == w), "{w} should show: {words:?}");
    }
    for w in ["ANNOTHIDDEN", "ANNOTNOVIEW", "STAMPOFF", "ANNOTOC"] {
        assert!(
            !words.iter().any(|s| s == w),
            "{w} should be gone: {words:?}"
        );
    }
    assert_eq!(out.report.annotations_flattened, 2, "{:?}", out.report);
    // Hidden, NoView, in hidden optional content, and the flattened square's pop-up.
    assert_eq!(out.report.annotations_removed, 4, "{:?}", out.report);
    // The link and the note without an appearance.
    assert_eq!(out.report.annotations_kept, 2, "{:?}", out.report);
    assert_eq!(annots.len(), 2);
    let mut b = admit(&out.bytes, &Limits::default(), &never).unwrap();
    let kinds: Vec<Vec<u8>> = annots
        .iter()
        .map(|n| {
            b.document
                .object(*n, &never)
                .unwrap()
                .dict()
                .and_then(|d| d.name(b"Subtype"))
                .unwrap()
                .to_vec()
        })
        .collect();
    assert_eq!(kinds, vec![b"Link".to_vec(), b"Text".to_vec()]);
}

#[test]
fn a_document_without_optional_content_keeps_its_markers_untouched() {
    // `/OC` with no `/OCProperties` has no effect: nothing is removed.
    let objs = vec![
        (1, b"<</Type/Catalog/Pages 2 0 R>>".to_vec()),
        (2, b"<</Type/Pages/Kids[3 0 R]/Count 1>>".to_vec()),
        (
            3,
            b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<</Font<</F1 5 0 R>>/Properties<</Off 11 0 R>>>>/Contents 4 0 R>>".to_vec(),
        ),
        (
            4,
            stream("", format!("/OC /Off BDC\n{}EMC\n", line(700, "STAYS")).as_bytes()),
        ),
        (5, FONT.as_bytes().to_vec()),
        (11, b"<</Type/OCG/Name(off)>>".to_vec()),
    ];
    let base = delivered(&classic(&objs));
    let out = flatten_plain(&base, &FlattenOptions::default()).unwrap();
    assert!(!out.report.optional_content_flattened);
    let (words, _) = shown_with(&out.bytes, false);
    assert_eq!(words, vec!["STAYS".to_owned()]);
}

#[test]
fn base_state_off_shows_only_groups_turned_on() {
    let objs = vec![
        (
            1,
            b"<</Type/Catalog/Pages 2 0 R/OCProperties<</OCGs[10 0 R 11 0 R]/D<</BaseState/OFF/ON[10 0 R]>>>>>>".to_vec(),
        ),
        (2, b"<</Type/Pages/Kids[3 0 R]/Count 1>>".to_vec()),
        (
            3,
            b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<</Font<</F1 5 0 R>>/Properties<</A 10 0 R/B 11 0 R>>>>/Contents 4 0 R>>".to_vec(),
        ),
        (
            4,
            stream(
                "",
                format!(
                    "/OC /A BDC\n{}EMC\n/OC /B BDC\n{}EMC\n",
                    line(700, "TURNEDON"),
                    line(680, "BASEOFF")
                )
                .as_bytes(),
            ),
        ),
        (5, FONT.as_bytes().to_vec()),
        (10, b"<</Type/OCG/Name(a)>>".to_vec()),
        (11, b"<</Type/OCG/Name(b)>>".to_vec()),
    ];
    let base = delivered(&classic(&objs));
    let out = flatten_plain(&base, &FlattenOptions::default()).unwrap();
    dump("layers-base-off.in.pdf", &base);
    dump("layers-base-off.out.pdf", &out.bytes);
    let (words, _) = shown(&out.bytes);
    assert_eq!(words, vec!["TURNEDON".to_owned()]);
}

/// A membership dictionary whose expression is `depth` `/Not`s deep, or a chain of
/// `/And`s sharing one array twice per level (`2^levels` terms).
fn expression_doc(ve: &str, extra: Vec<(u32, Vec<u8>)>) -> Vec<u8> {
    let mut objs = vec![
        (
            1,
            b"<</Type/Catalog/Pages 2 0 R/OCProperties<</OCGs[10 0 R]/D<<>>>>>>".to_vec(),
        ),
        (2, b"<</Type/Pages/Kids[3 0 R]/Count 1>>".to_vec()),
        (
            3,
            b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<</Font<</F1 5 0 R>>/Properties<</M 20 0 R>>>>/Contents 4 0 R>>".to_vec(),
        ),
        (
            4,
            stream("", format!("/OC /M BDC\n{}EMC\n", line(700, "DEEP")).as_bytes()),
        ),
        (5, FONT.as_bytes().to_vec()),
        (10, b"<</Type/OCG/Name(a)>>".to_vec()),
        (20, format!("<</Type/OCMD/OCGs[10 0 R]/VE {ve}>>").into_bytes()),
    ];
    objs.extend(extra);
    delivered(&classic(&objs))
}

fn nots(n: usize) -> String {
    let mut ve = "10 0 R".to_owned();
    for _ in 0..n {
        ve = format!("[/Not {ve}]");
    }
    ve
}

#[test]
fn a_visibility_expression_over_its_depth_is_refused() {
    // MAX_VE_DEPTH nested `/Not`s around the group: at the bound, read (even: shown).
    let at = expression_doc(&nots(MAX_VE_DEPTH), Vec::new());
    let out = flatten_plain(&at, &FlattenOptions::default()).unwrap();
    assert_eq!(shown(&out.bytes).0, vec!["DEEP".to_owned()]);
    // One more: refused with its code.
    let over = expression_doc(&nots(MAX_VE_DEPTH + 1), Vec::new());
    let code = flatten_plain(&over, &FlattenOptions::default())
        .err()
        .map(|e| e.code());
    assert_eq!(code, Some("CS-FLT-0006"));
}

#[test]
fn a_visibility_expression_sharing_arrays_is_bounded_by_its_terms() {
    // Array 100 + k is [/And (101+k) (101+k)]: 2^levels terms from a few objects.
    let levels = 20u32;
    let mut extra = Vec::new();
    for k in 0..levels {
        extra.push((
            100 + k,
            format!("[/And {0} 0 R {0} 0 R]", 101 + k).into_bytes(),
        ));
    }
    extra.push((100 + levels, b"[/Or 10 0 R]".to_vec()));
    let doc = expression_doc("100 0 R", extra);
    let code = flatten_plain(&doc, &FlattenOptions::default())
        .err()
        .map(|e| e.code());
    assert_eq!(code, Some("CS-FLT-0006"));
    assert!(2usize.pow(levels) > MAX_VE_TERMS);
}

#[test]
fn a_malformed_expression_falls_back_to_the_policy() {
    // `/Not` with two operands is malformed: `/P` decides. AnyOn (the default) over an
    // on group shows; AllOff hides.
    let doc = expression_doc("[/Not 10 0 R 10 0 R]", Vec::new());
    let out = flatten_plain(&doc, &FlattenOptions::default()).unwrap();
    assert_eq!(shown(&out.bytes).0, vec!["DEEP".to_owned()]);
    let doc = expression_doc("[/Not 10 0 R 10 0 R]/P/AllOff", Vec::new());
    let out = flatten_plain(&doc, &FlattenOptions::default()).unwrap();
    assert!(shown(&out.bytes).0.is_empty());
    // A well-formed expression wins over that policy: [/Not [/Not on]] shows.
    let doc = expression_doc("[/Not [/Not 10 0 R]]/P/AllOff", Vec::new());
    let out = flatten_plain(&doc, &FlattenOptions::default()).unwrap();
    assert_eq!(shown(&out.bytes).0, vec!["DEEP".to_owned()]);
}

#[test]
fn a_checkbox_flattens_with_its_own_on_appearance() {
    // FLT-04: a box whose on state draws a cross keeps its cross.
    let cross = stream(
        "/Type/XObject/Subtype/Form/BBox[0 0 12 12]",
        b"0 0 1 RG 1.5 w 2 2 m 10 10 l S 2 10 m 10 2 l S",
    );
    let w = "/Type/Annot/Subtype/Widget/P 3 0 R/F 4";
    let extra = vec![
        (5, b"<</Fields[10 0 R 11 0 R]/DA(/Helv 0 Tf 0 g)>>".to_vec()),
        (
            10,
            format!("<</FT/Btn/T(cross){w}/Rect[100 600 112 612]/AS/Off/AP<</N<</Yes 20 0 R/Off 21 0 R>>>>>>")
                .into_bytes(),
        ),
        // No appearance at all: our checkmark.
        (11, format!("<</FT/Btn/T(plain){w}/Rect[100 560 112 572]>>").into_bytes()),
        (20, cross),
        (21, stream("/Type/XObject/Subtype/Form/BBox[0 0 12 12]", b"")),
    ];
    let base = delivered(&page_pdf(
        &cases()[0],
        "/AcroForm 5 0 R",
        "/Annots[10 0 R 11 0 R]",
        extra,
    ));
    let mut a = admit(&base, &Limits::default(), &never).unwrap();
    let report = a.report.clone();
    let conv =
        convert_acroform(&mut a.document, &report, &id("doc"), &mut minter(), &never).unwrap();
    assert_eq!(conv.fields.len(), 2);
    // The cross's object number after normalization.
    let cross_widget = report.fields[0].widgets[0].object.unwrap();
    let wd = a.document.object(cross_widget, &never).unwrap();
    let ap = a.document.resolve(wd.get(b"AP").unwrap(), &never).unwrap();
    let n = a.document.resolve(ap.get(b"N").unwrap(), &never).unwrap();
    let on = n.get(b"Yes").and_then(Object::as_ref).unwrap().num;

    let values: BTreeMap<_, _> = conv
        .fields
        .iter()
        .map(|c| (c.field.id.clone(), FieldValue::Checked(true)))
        .collect();
    let fields: Vec<_> = conv.fields.iter().map(|c| c.field.clone()).collect();
    let caps = BTreeMap::new();
    let input = FlattenInput {
        fields: &fields,
        values: &values,
        captures: &caps,
        envelope_id: None,
        acroform: Some(&conv),
    };
    let out = flatten(
        &mut a,
        &input,
        &FontSet::bundled(),
        &FlattenOptions::default(),
        &never,
    )
    .unwrap();
    assert_eq!(out.report.drawn.len(), 2);
    dump("checkbox-cross.in.pdf", &base);
    dump("checkbox-cross.out.pdf", &out.bytes);
    dump(
        "checkbox.json",
        b"[{\"out\":\"checkbox-cross.out.pdf\",\"rect\":[100,600,112,612]}]\n",
    );
    // The page invokes the box's own cross; the plain box gets one new form (ours).
    let mut b = admit(&out.bytes, &Limits::default(), &never).unwrap();
    let page = b.report.pages[0].object;
    let res = b.document.page_resources(page, &never).unwrap();
    let x = b
        .document
        .resolve(res.get(b"XObject").unwrap(), &never)
        .unwrap();
    let invoked: Vec<u32> = x
        .dict()
        .unwrap()
        .iter()
        .filter_map(|(_, v)| v.as_ref())
        .map(|r| r.num)
        .collect();
    assert!(invoked.contains(&on), "own cross not drawn: {invoked:?}");
    let ours: Vec<Vec<u8>> = invoked
        .iter()
        .filter(|n| **n != on)
        .map(|n| b.document.decode_stream(*n, &never).unwrap())
        .collect();
    // Frames of the converted widgets have nothing to draw (no /MK); only the
    // fallback checkmark is ours.
    assert_eq!(ours.len(), 1, "{invoked:?}");
    assert!(String::from_utf8_lossy(&ours[0]).contains("1 J 1 j"));
}

#[test]
fn filling_in_place_keeps_hidden_widgets_hidden() {
    // A widget in hidden optional content stays in the form but is marked Hidden,
    // since `/OCProperties` goes.
    let w = "/Type/Annot/Subtype/Widget/P 3 0 R/F 4";
    let extra = vec![
        (5, b"<</Fields[10 0 R]/DA(/Helv 0 Tf 0 g)>>".to_vec()),
        (
            10,
            format!("<</FT/Tx/T(name){w}/OC 11 0 R/Rect[100 600 200 620]>>").into_bytes(),
        ),
        (11, b"<</Type/OCG/Name(off)>>".to_vec()),
    ];
    let base = delivered(&page_pdf(
        &cases()[0],
        "/AcroForm 5 0 R/OCProperties<</OCGs[11 0 R]/D<</OFF[11 0 R]>>>>",
        "/Annots[10 0 R]",
        extra,
    ));
    let mut options = FlattenOptions::default();
    options.mode = FormMode::FillInPlace;
    let out = flatten_plain(&base, &options).unwrap();
    let mut b = admit(&out.bytes, &Limits::default(), &never).unwrap();
    let widget = b.report.fields[0].widgets[0].object.unwrap();
    let d = b.document.object(widget, &never).unwrap();
    assert_eq!(d.get(b"F").and_then(Object::as_i64), Some(6));
    assert!(d.get(b"OC").is_none());
}

#[test]
fn a_group_or_configuration_with_no_readable_intent_takes_view() {
    for (config, group) in [
        ("", "/Intent[]"),
        ("/Intent[]", ""),
        ("/Intent 7", "/Intent/View"),
    ] {
        let objs = vec![
            (
                1,
                format!("<</Type/Catalog/Pages 2 0 R/OCProperties<</OCGs[11 0 R]/D<</OFF[11 0 R]{config}>>>>>>")
                    .into_bytes(),
            ),
            (2, b"<</Type/Pages/Kids[3 0 R]/Count 1>>".to_vec()),
            (
                3,
                b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<</Font<</F1 5 0 R>>/Properties<</Off 11 0 R>>>>/Contents 4 0 R>>".to_vec(),
            ),
            (
                4,
                stream("", format!("/OC /Off BDC\n{}EMC\n", line(700, "OFF")).as_bytes()),
            ),
            (5, FONT.as_bytes().to_vec()),
            (11, format!("<</Type/OCG/Name(off){group}>>").into_bytes()),
        ];
        let base = delivered(&classic(&objs));
        let out = flatten_plain(&base, &FlattenOptions::default()).unwrap();
        assert!(shown(&out.bytes).0.is_empty(), "{config} {group}");
    }
}

#[test]
fn a_certified_document_filled_in_place_keeps_its_layers_and_annotations() {
    // DocMDP 2 permits filling and signing only: flattening a layer or an annotation
    // would break the certification, so both stay as certified.
    let objs = vec![
        (
            1,
            b"<</Type/Catalog/Pages 2 0 R/Perms<</DocMDP 10 0 R>>/OCProperties<</OCGs[11 0 R]/D<</OFF[11 0 R]>>>>>>".to_vec(),
        ),
        (2, b"<</Type/Pages/Kids[3 0 R]/Count 1>>".to_vec()),
        (
            3,
            b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<</Font<</F1 5 0 R>>/Properties<</Off 11 0 R>>>>/Contents 4 0 R/Annots[40 0 R]>>".to_vec(),
        ),
        (
            4,
            stream("", format!("/OC /Off BDC\n{}EMC\n", line(700, "LAYER")).as_bytes()),
        ),
        (5, FONT.as_bytes().to_vec()),
        (
            10,
            b"<</Type/Sig/Filter/Adobe.PPKLite/SubFilter/ETSI.CAdES.detached/ByteRange[0 1 2 3]/Contents<00>/Reference[<</Type/SigRef/TransformMethod/DocMDP/TransformParams<</P 2/V/1.2>>>>]>>".to_vec(),
        ),
        (11, b"<</Type/OCG/Name(off)>>".to_vec()),
        (
            40,
            b"<</Type/Annot/Subtype/Square/Rect[300 300 500 320]/AP<</N 41 0 R>>>>".to_vec(),
        ),
        (41, form("", "SQUARE")),
    ];
    let base = classic(&objs);
    let mut options = FlattenOptions::default();
    options.mode = FormMode::FillInPlace;
    let out = flatten_plain(&base, &options).unwrap();
    assert!(out.report.layers_kept_as_certified);
    assert!(!out.report.optional_content_flattened);
    assert_eq!(out.report.annotations_flattened, 0);
    // Flattening it is refused by the writer, as before (CS-WRT, DocMDP).
    let e = flatten_plain(&base, &FlattenOptions::default()).err();
    assert!(e.is_some_and(|e| e.code().starts_with("CS-WRT")));
}
