//! Normalization (`T-1B`, docs/30 §3, SEC-P06 to SEC-P08, SEC-P11): each removal kind
//! from a hand-built file and, where one exists, from its `active_*` fixture. Every
//! output is admitted again, strictly, and must show none of what was removed.
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
    ActionKind, AdmissionReport, FindingKind, Limits, NormalizationReport, NormalizeOptions,
    Object, OutputXref, Removal, admit, admit_strict, normalize,
};
use common::{classic, never, stream};

/// A one-page file: catalog 1 (with `cat`), pages 2, page 3 (with `page`), content 4,
/// and `extra` objects.
fn doc(cat: &str, page: &str, extra: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut objs = vec![
        (
            1,
            format!("<</Type/Catalog/Pages 2 0 R{cat}>>").into_bytes(),
        ),
        (2, b"<</Type/Pages/Kids[3 0 R]/Count 1>>".to_vec()),
        (
            3,
            format!("<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R{page}>>")
                .into_bytes(),
        ),
        (4, stream("", b"BT /F1 12 Tf 72 720 Td (Hi) Tj ET")),
    ];
    objs.extend(extra.iter().cloned());
    classic(&objs, "")
}

type Geometry = Vec<([f64; 4], [f64; 4], u16, f64)>;

fn geometry_of(pages: &[casual_sign_pdf::PageInfo]) -> Geometry {
    let r = |r: casual_sign_pdf::Rect| [r.llx, r.lly, r.urx, r.ury];
    pages
        .iter()
        .map(|p| (r(p.media_box), r(p.crop_box), p.rotate, p.user_unit))
        .collect()
}

/// Page geometry, without object numbers (which normalization changes).
fn geometry(report: &AdmissionReport) -> Geometry {
    geometry_of(&report.pages)
}

/// Normalize in both xref forms; both outputs admit strictly and classify alike.
fn run(bytes: &[u8]) -> (NormalizationReport, AdmissionReport) {
    let mut results = Vec::new();
    for form in [OutputXref::Stream, OutputXref::Table] {
        let mut a = admit(bytes, &Limits::default(), &never).unwrap();
        let pages = a.report.pages.clone();
        let n = normalize(&mut a, &NormalizeOptions::with_xref(form), &never).unwrap();
        let out = admit_strict(&n.bytes, &Limits::default(), &never)
            .unwrap_or_else(|e| panic!("{form:?} output refused: {e}"))
            .report;
        assert!(!out.repaired);
        assert_eq!(
            geometry(&out),
            geometry_of(&pages),
            "{form:?}: geometry changed"
        );
        results.push((n.report, out));
    }
    let (table_n, table_out) = results.pop().unwrap();
    let (stream_n, stream_out) = results.pop().unwrap();
    assert_eq!(table_n, stream_n);
    assert_eq!(table_out.actions, stream_out.actions);
    assert_eq!(table_out.findings, stream_out.findings);
    (stream_n, stream_out)
}

fn removed(n: &NormalizationReport, code: &str, kind: FindingKind) -> Vec<Removal> {
    n.removed
        .iter()
        .filter(|r| r.code == code && r.kind == kind)
        .copied()
        .collect()
}

/// Nothing of 0103, 0104 or 0105 remains, and no action runs or is not a URI.
fn assert_clean(out: &AdmissionReport) {
    for code in ["CS-PDF-0103", "CS-PDF-0104", "CS-PDF-0105"] {
        assert!(!out.has_code(code), "{code} left: {:?}", out.findings);
    }
    assert!(
        out.actions
            .iter()
            .all(|a| a.kind == ActionKind::Uri && !a.automatic),
        "actions left: {:?}",
        out.actions
    );
    assert!(out.embedded_files.is_empty());
    assert!(out.rich_media.is_empty());
    assert!(out.external_streams.is_empty());
    assert!(!out.has_xfa);
}

// ----- actions (SEC-P06) ------------------------------------------------------------

#[test]
fn open_action_javascript_is_removed() {
    let (n, out) = run(&doc(
        "/OpenAction<</S/JavaScript/JS(app.alert\\(1\\))>>",
        "",
        &[],
    ));
    let r = removed(
        &n,
        "CS-PDF-0103",
        FindingKind::Action(ActionKind::JavaScript),
    );
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].object, Some(1));
    assert_clean(&out);
}

#[test]
fn additional_actions_are_removed_wherever_they_are() {
    let field = b"<</Type/Annot/Subtype/Widget/FT/Tx/T(a)/Rect[0 0 10 10]/P 3 0 R\
/AA<</K<</S/SubmitForm/F<</FS/URL/F(https://x.invalid/)>>>>/Fo 11 0 R>>>>"
        .to_vec();
    let bytes = doc(
        "/AcroForm<</Fields[10 0 R]>>/AA<</WC<</S/JavaScript/JS(x)>>>>",
        "/Annots[10 0 R]/AA<</O<</S/Launch/F(calc.exe)>>>>",
        &[(10, field), (11, b"<</S/ImportData/F(x.fdf)>>".to_vec())],
    );
    let (n, out) = run(&bytes);
    assert_eq!(
        removed(
            &n,
            "CS-PDF-0103",
            FindingKind::Action(ActionKind::SubmitForm)
        )[0]
        .object,
        Some(10)
    );
    assert_eq!(
        removed(
            &n,
            "CS-PDF-0103",
            FindingKind::Action(ActionKind::ImportData)
        )[0]
        .object,
        Some(10)
    );
    assert_eq!(
        removed(&n, "CS-PDF-0103", FindingKind::Action(ActionKind::Launch))[0].object,
        Some(3)
    );
    assert_eq!(
        removed(
            &n,
            "CS-PDF-0103",
            FindingKind::Action(ActionKind::JavaScript)
        )[0]
        .object,
        Some(1)
    );
    assert_clean(&out);
    // The field itself stays.
    assert_eq!(out.fields.len(), 1);
}

#[test]
fn launch_import_goto_r_and_goto_e_on_links_are_removed_and_the_links_kept() {
    let link = |a: &str| format!("<</Type/Annot/Subtype/Link/Rect[0 0 10 10]/A {a}>>").into_bytes();
    let bytes = doc(
        "",
        "/Annots[10 0 R 11 0 R 12 0 R 13 0 R]",
        &[
            (10, link("<</S/Launch/F(calc.exe)>>")),
            (11, link("14 0 R")),
            (12, link("<</S/GoToR/F(other.pdf)/D[0/Fit]>>")),
            (13, link("<</S/GoToE/T<</R/C/N(a)>>/D[0/Fit]>>")),
            (14, b"<</S/ImportData/F(x.fdf)>>".to_vec()),
        ],
    );
    let (n, out) = run(&bytes);
    assert_eq!(
        removed(&n, "CS-PDF-0103", FindingKind::Action(ActionKind::Launch))[0].object,
        Some(10)
    );
    assert_eq!(
        removed(
            &n,
            "CS-PDF-0103",
            FindingKind::Action(ActionKind::ImportData)
        )[0]
        .object,
        Some(14)
    );
    assert_eq!(
        removed(
            &n,
            "CS-PDF-0105",
            FindingKind::ExternalReference(ActionKind::GoToR)
        )[0]
        .object,
        Some(12)
    );
    assert_eq!(
        removed(
            &n,
            "CS-PDF-0105",
            FindingKind::ExternalReference(ActionKind::GoToE)
        )[0]
        .object,
        Some(13)
    );
    assert_clean(&out);
    // The catalog, pages, page, content and the four links; object 14 is gone.
    assert_eq!(n.objects_written, 4 + 4);
}

#[test]
fn javascript_name_tree_is_removed() {
    let bytes = doc(
        "/Names<</JavaScript 10 0 R>>",
        "",
        &[
            (10, b"<</Names[(a) 11 0 R]>>".to_vec()),
            (11, b"<</S/JavaScript/JS(app.alert\\(1\\))>>".to_vec()),
        ],
    );
    let (n, out) = run(&bytes);
    let r = removed(
        &n,
        "CS-PDF-0103",
        FindingKind::Action(ActionKind::JavaScript),
    );
    assert!(r.iter().any(|r| r.object == Some(1) && !r.unreachable));
    assert_clean(&out);
    assert_eq!(n.objects_written, 4);
}

#[test]
fn uri_on_open_is_removed_and_uri_on_a_link_is_kept() {
    let bytes = doc(
        "/OpenAction<</S/URI/URI(https://attacker.invalid/track)>>",
        "/Annots[10 0 R]",
        &[(
            10,
            b"<</Type/Annot/Subtype/Link/Rect[0 0 10 10]/A<</S/URI/URI(https://example.com/)>>>>"
                .to_vec(),
        )],
    );
    let (n, out) = run(&bytes);
    assert_eq!(
        removed(
            &n,
            "CS-PDF-0105",
            FindingKind::ExternalReference(ActionKind::Uri)
        )[0]
        .object,
        Some(1)
    );
    assert_clean(&out);
    assert_eq!(out.actions.len(), 1, "the link's URI stays");
    assert!(!out.actions[0].automatic);
}

#[test]
fn catalog_carrying_an_action_is_cleaned_not_dropped() {
    let (n, out) = run(&doc("/S/JavaScript/JS(x)", "", &[]));
    assert!(
        !removed(
            &n,
            "CS-PDF-0103",
            FindingKind::Action(ActionKind::JavaScript)
        )
        .is_empty()
    );
    assert_clean(&out);
    assert_eq!(out.page_count, 1);
}

#[test]
fn actions_in_unreachable_objects_are_dropped_and_listed() {
    let bytes = doc(
        "",
        "",
        &[
            (30, b"<</S/JavaScript/JS(x)>>".to_vec()),
            (31, b"(spare)".to_vec()),
        ],
    );
    let (n, out) = run(&bytes);
    let r = removed(
        &n,
        "CS-PDF-0103",
        FindingKind::Action(ActionKind::JavaScript),
    );
    assert_eq!(r.len(), 1);
    assert!(r[0].unreachable);
    assert_eq!(r[0].object, Some(30));
    assert_eq!(n.unreachable_dropped, 2);
    assert_clean(&out);
}

// ----- embedded files, RichMedia, 3D (SEC-P08) --------------------------------------

#[test]
fn embedded_files_their_name_tree_and_attachments_are_removed() {
    let bytes = doc(
        "/Names<</EmbeddedFiles<</Names[(a.exe) 10 0 R]>>>>/AF[10 0 R]",
        "/Annots[12 0 R]",
        &[
            (10, b"<</Type/Filespec/F(a.exe)/EF<</F 11 0 R>>>>".to_vec()),
            (11, stream("/Type/EmbeddedFile", b"MZ not really")),
            (
                12,
                b"<</Type/Annot/Subtype/FileAttachment/Rect[0 0 10 10]/FS 13 0 R>>".to_vec(),
            ),
            (13, b"<</Type/Filespec/F(b.exe)/EF<</F 11 0 R>>>>".to_vec()),
        ],
    );
    let (n, out) = run(&bytes);
    let r = removed(&n, "CS-PDF-0104", FindingKind::EmbeddedFile);
    let objects: Vec<_> = r.iter().filter_map(|r| r.object).collect();
    assert!(objects.contains(&1), "name tree: {r:?}");
    assert!(objects.contains(&10), "file specification: {r:?}");
    assert!(objects.contains(&12), "attachment annotation: {r:?}");
    assert_clean(&out);
    assert_eq!(n.objects_written, 4);
}

#[test]
fn rich_media_and_3d_annotations_are_removed() {
    let bytes = doc(
        "",
        "/Annots[10 0 R 11 0 R]",
        &[
            (
                10,
                b"<</Type/Annot/Subtype/RichMedia/Rect[0 0 10 10]/RichMediaContent<</Type/RichMediaContent>>>>"
                    .to_vec(),
            ),
            (
                11,
                b"<</Type/Annot/Subtype/3D/Rect[0 0 10 10]/3DD 12 0 R>>".to_vec(),
            ),
            (12, stream("/Type/3D/Subtype/U3D", b"not a model")),
        ],
    );
    let (n, out) = run(&bytes);
    let objects: Vec<_> = removed(&n, "CS-PDF-0104", FindingKind::RichMedia)
        .iter()
        .filter_map(|r| r.object)
        .collect();
    assert!(
        objects.contains(&10) && objects.contains(&11),
        "{objects:?}"
    );
    assert_clean(&out);
}

// ----- external references (SEC-P07) ------------------------------------------------

#[test]
fn external_stream_data_is_removed_and_the_stream_kept_empty() {
    let mut objs = vec![(
        10,
        stream(
            "/Type/XObject/Subtype/Image/Width 1/Height 1/BitsPerComponent 8/ColorSpace/DeviceGray/F(http://x.invalid/a.jpg)/FFilter/DCTDecode",
            b"",
        ),
    )];
    objs.push((11, b"<</XObject<</Im0 10 0 R>>>>".to_vec()));
    let (n, out) = run(&doc("", "/Resources 11 0 R", &objs));
    let r = removed(&n, "CS-PDF-0105", FindingKind::ExternalStream);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].object, Some(10));
    assert_clean(&out);
    assert_eq!(
        n.objects_written, 6,
        "the image stays, without its external data"
    );
}

// ----- XFA --------------------------------------------------------------------------

#[test]
fn xfa_is_removed_and_static_fields_kept() {
    let bytes = doc(
        "/AcroForm 10 0 R",
        "/Annots[11 0 R]",
        &[
            (10, b"<</Fields[11 0 R]/XFA 12 0 R>>".to_vec()),
            (
                11,
                b"<</Type/Annot/Subtype/Widget/FT/Tx/T(name)/Rect[0 0 100 20]/P 3 0 R>>".to_vec(),
            ),
            (12, stream("", b"<xdp:xdp/>")),
        ],
    );
    let before = admit(&bytes, &Limits::default(), &never).unwrap().report;
    assert!(before.has_xfa);
    let (n, out) = run(&bytes);
    assert_eq!(
        removed(&n, "CS-PDF-0103", FindingKind::Xfa)[0].object,
        Some(10)
    );
    assert_clean(&out);
    assert_eq!(out.fields.len(), 1);
    assert_eq!(out.fields[0].name, "name");
}

// ----- what stays -------------------------------------------------------------------

#[test]
fn optional_content_is_kept_and_reported() {
    let bytes = doc(
        "/OCProperties<</OCGs[10 0 R]/D<</ON[10 0 R]>>>>",
        "",
        &[(10, b"<</Type/OCG/Name(Layer)>>".to_vec())],
    );
    let (n, out) = run(&bytes);
    assert!(n.optional_content_kept);
    assert!(out.has_optional_content);
    assert!(out.has_code("CS-PDF-0108"));
}

#[test]
fn objects_are_renumbered_breadth_first_from_the_trailer() {
    let bytes = classic(
        &[
            (7, b"<</Type/Catalog/Pages 9 0 R/Outlines 40 0 R>>".to_vec()),
            (9, b"<</Type/Pages/Kids[20 0 R]/Count 1>>".to_vec()),
            (
                20,
                b"<</Type/Page/Parent 9 0 R/MediaBox[0 0 100 100]>>".to_vec(),
            ),
            (40, b"<</Type/Outlines/Count 0>>".to_vec()),
            (50, b"<</Producer(test)>>".to_vec()),
            (60, b"(unreachable)".to_vec()),
        ],
        "/Info 50 0 R",
    )
    .replace_root(7);
    let mut a = admit(&bytes, &Limits::default(), &never).unwrap();
    let n = normalize(&mut a, &NormalizeOptions::default(), &never).unwrap();
    assert_eq!(
        n.report.renumbered,
        vec![(7, 1), (50, 2), (9, 3), (40, 4), (20, 5)]
    );
    assert_eq!(n.report.unreachable_dropped, 1);
    // Deterministic: the same input gives the same bytes.
    let mut b = admit(&bytes, &Limits::default(), &never).unwrap();
    let again = normalize(&mut b, &NormalizeOptions::default(), &never).unwrap();
    assert_eq!(n.bytes, again.bytes);
    // Normalizing the output again changes nothing but nothing is lost either.
    let mut c = admit_strict(&n.bytes, &Limits::default(), &never).unwrap();
    let twice = normalize(&mut c, &NormalizeOptions::default(), &never).unwrap();
    assert_eq!(twice.bytes, n.bytes);
}

#[test]
fn reference_chains_collapse_and_duplicate_keys_keep_the_last() {
    let bytes = doc(
        "/Lang 10 0 R",
        "/MediaBox[0 0 1 1]",
        &[(10, b"11 0 R".to_vec()), (11, b"(en)".to_vec())],
    );
    let (n, out) = run(&bytes);
    assert_eq!(out.pages[0].media_box.urx, 1.0);
    // Object 10 (a bare reference) is not written; 11 is.
    assert!(!n.report_has_old(10));
    assert!(n.report_has_old(11));
}

trait OldNumbers {
    fn report_has_old(&self, old: u32) -> bool;
}
impl OldNumbers for NormalizationReport {
    fn report_has_old(&self, old: u32) -> bool {
        self.renumbered.iter().any(|(o, _)| *o == old)
    }
}

trait ReplaceRoot {
    fn replace_root(self, root: u32) -> Vec<u8>;
}
impl ReplaceRoot for Vec<u8> {
    /// `common::classic` names object 1 as the root; point it at `root` instead.
    fn replace_root(self, root: u32) -> Vec<u8> {
        let s = String::from_utf8_lossy(&self).into_owned();
        s.replace("/Root 1 0 R", &format!("/Root {root} 0 R"))
            .into_bytes()
    }
}

#[test]
fn signed_input_is_refused() {
    let bytes = doc(
        "/Perms<</DocMDP 10 0 R>>",
        "",
        &[(
            10,
            b"<</Type/Sig/Filter/Adobe.PPKLite/SubFilter/adbe.pkcs7.detached/ByteRange[0 1 2 3]/Contents<00>>>"
                .to_vec(),
        )],
    );
    let mut a = admit(&bytes, &Limits::default(), &never).unwrap();
    let e = normalize(&mut a, &NormalizeOptions::default(), &never).unwrap_err();
    assert_eq!(e.code(), "CS-PDF-0014");
    // Print to new takes it (tests/normalize_print.rs, NORM-02).
}

#[test]
fn cancellation_stops_normalization() {
    let bytes = doc("", "", &[]);
    let mut a = admit(&bytes, &Limits::default(), &never).unwrap();
    let e = normalize(&mut a, &NormalizeOptions::default(), &|| true).unwrap_err();
    assert_eq!(e.code(), "CS-PDF-0013");
}

// ----- the active_* fixtures --------------------------------------------------------

#[test]
fn active_fixtures_are_cleaned() {
    if !common::ensure_hostile() {
        return;
    }
    let cases: &[(&str, &str, FindingKind)] = &[
        (
            "active_openaction_js.pdf",
            "CS-PDF-0103",
            FindingKind::Action(ActionKind::JavaScript),
        ),
        (
            "active_launch.pdf",
            "CS-PDF-0103",
            FindingKind::Action(ActionKind::Launch),
        ),
        (
            "active_uri_on_open.pdf",
            "CS-PDF-0105",
            FindingKind::ExternalReference(ActionKind::Uri),
        ),
        (
            "active_submitform.pdf",
            "CS-PDF-0103",
            FindingKind::Action(ActionKind::SubmitForm),
        ),
        (
            "active_embedded_file.pdf",
            "CS-PDF-0104",
            FindingKind::EmbeddedFile,
        ),
        ("active_xfa.pdf", "CS-PDF-0103", FindingKind::Xfa),
        (
            "active_richmedia.pdf",
            "CS-PDF-0104",
            FindingKind::RichMedia,
        ),
        ("active_3d.pdf", "CS-PDF-0104", FindingKind::RichMedia),
        (
            "active_external_stream.pdf",
            "CS-PDF-0105",
            FindingKind::ExternalStream,
        ),
        (
            "active_gotor.pdf",
            "CS-PDF-0105",
            FindingKind::ExternalReference(ActionKind::GoToR),
        ),
        (
            "active_gotoe.pdf",
            "CS-PDF-0105",
            FindingKind::ExternalReference(ActionKind::GoToE),
        ),
        (
            "active_importdata.pdf",
            "CS-PDF-0103",
            FindingKind::Action(ActionKind::ImportData),
        ),
        (
            "active_js_nametree.pdf",
            "CS-PDF-0103",
            FindingKind::Action(ActionKind::JavaScript),
        ),
    ];
    for (file, code, kind) in cases {
        let bytes = std::fs::read(common::hostile_dir().join(file)).unwrap();
        let before = admit(&bytes, &Limits::default(), &never).unwrap().report;
        assert!(before.has_code(code), "{file}: fixture lacks {code}");
        let (n, out) = run(&bytes);
        assert!(
            !removed(&n, code, *kind).is_empty(),
            "{file}: {code} {kind:?} not listed in {:?}",
            n.removed
        );
        assert_clean(&out);
    }
}

#[test]
fn a_javascript_action_without_a_type_is_removed_whole() {
    // `/JS` with no `/S`: still JavaScript to a viewer that runs it.
    let bytes = doc(
        "",
        "/Annots[10 0 R]",
        &[
            (
                10,
                b"<</Type/Annot/Subtype/Link/Rect[0 0 10 10]/A 11 0 R>>".to_vec(),
            ),
            (11, b"<</JS(app.alert\\(1\\))>>".to_vec()),
        ],
    );
    let (n, out) = run(&bytes);
    let r = removed(
        &n,
        "CS-PDF-0103",
        FindingKind::Action(ActionKind::JavaScript),
    );
    assert_eq!(r[0].object, Some(11));
    assert!(n.report_has_old(10));
    assert!(!n.report_has_old(11), "the action object is not written");
    assert_clean(&out);
}

#[test]
fn page_tree_counts_are_rewritten_to_the_pages_present() {
    // /Count says 7; one kid is not a dictionary and one is missing: two pages remain.
    let bytes = classic(
        &[
            (1, b"<</Type/Catalog/Pages 2 0 R>>".to_vec()),
            (
                2,
                b"<</Type/Pages/Kids[3 0 R 5 0 R 6 0 R 9 0 R]/Count 7>>".to_vec(),
            ),
            (
                3,
                b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>".to_vec(),
            ),
            (5, b"42".to_vec()),
            (
                6,
                b"<</Type/Pages/Parent 2 0 R/Kids[7 0 R]/Count 3>>".to_vec(),
            ),
            (
                7,
                b"<</Type/Page/Parent 6 0 R/MediaBox[0 0 100 100]>>".to_vec(),
            ),
        ],
        "",
    );
    let before = admit(&bytes, &Limits::default(), &never).unwrap().report;
    assert_eq!(before.page_count, 2);
    let mut a = admit(&bytes, &Limits::default(), &never).unwrap();
    let n = normalize(&mut a, &NormalizeOptions::default(), &never).unwrap();
    let mut out = admit_strict(&n.bytes, &Limits::default(), &never).unwrap();
    assert_eq!(out.report.page_count, 2);
    let root = out.document.trailer().get(b"Root").cloned().unwrap();
    let cat = out.document.resolve(&root, &never).unwrap();
    let pages = out
        .document
        .resolve(cat.get(b"Pages").unwrap(), &never)
        .unwrap();
    assert_eq!(pages.get(b"Count"), Some(&Object::Integer(2)));
    match pages.get(b"Kids") {
        Some(Object::Array(k)) => assert_eq!(k.len(), 2),
        other => panic!("{other:?}"),
    }
    let lopdf = lopdf::Document::load_mem(&n.bytes).unwrap();
    assert_eq!(lopdf.get_pages().len(), 2);
}

#[test]
fn unreadable_page_content_is_dropped_and_reported() {
    // Found by the normalize fuzz target: page content that is a dictionary, not a
    // stream (`stream` keyword missing), and a content array naming a number. The
    // default reader reports both (CS-PDF-0102); the output must not carry them.
    let bytes = classic(
        &[
            (1, b"<</Type/Catalog/Pages 2 0 R>>".to_vec()),
            (2, b"<</Type/Pages/Kids[3 0 R 6 0 R]/Count 2>>".to_vec()),
            (
                3,
                b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R>>".to_vec(),
            ),
            (4, b"<</Filter/FlateDecode/Length 43>>\nstr1".to_vec()),
            (
                6,
                b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents[7 0 R 8 0 R]>>".to_vec(),
            ),
            (7, b"42".to_vec()),
            (8, stream("", b"0 0 m 1 1 l S")),
        ],
        "",
    );
    assert!(admit_strict(&bytes, &Limits::default(), &never).is_err());
    let before = admit(&bytes, &Limits::default(), &never).unwrap().report;
    assert!(before.has_code("CS-PDF-0102"));
    let (n, out) = run(&bytes);
    let objects: Vec<_> = removed(&n, "CS-PDF-0102", FindingKind::ObjectUnreadable)
        .iter()
        .filter_map(|r| r.object)
        .collect();
    assert!(objects.contains(&4) && objects.contains(&7), "{objects:?}");
    assert_eq!(out.page_count, 2);
    assert!(!out.has_code("CS-PDF-0102"));
}

#[test]
fn page_tree_objects_carrying_active_keys_are_cleaned_not_dropped() {
    // Found by the normalize fuzz target: a page with no /Type and an /EF key (the
    // reader takes it for a page; normalization dropped it as an embedded file), and
    // a node with an action's /S.
    let bytes = classic(
        &[
            (1, b"<</Type/Catalog/Pages 2 0 R>>".to_vec()),
            (2, b"<</Kids[3 0 R]/S/Launch/F(calc.exe)>>".to_vec()),
            // An /EF array is a usage-rights name list, not a file (`PDF-REAL-02`); the
            // fuzz input's /EF is kept as a dictionary so the page still carries one.
            (3, b"<</EF<</F 0 0 R>>/MediaBox[0 0 200 200]>>".to_vec()),
        ],
        "",
    );
    let (n, out) = run(&bytes);
    assert_eq!(out.page_count, 1);
    assert_eq!(out.pages[0].media_box.urx, 200.0);
    assert!(!removed(&n, "CS-PDF-0104", FindingKind::EmbeddedFile).is_empty());
    assert!(!removed(&n, "CS-PDF-0103", FindingKind::Action(ActionKind::Launch)).is_empty());
    assert_clean(&out);
}

#[test]
fn page_tree_references_to_bare_references_stay_unreadable() {
    // Found by the normalize fuzz target: a kid whose object is `1 0 R` (the reader
    // takes a kid one hop only, so it is no page) became the catalog itself once the
    // chain collapsed, and the catalog counted as a second page. Content behind such a
    // reference is unreadable to the reader too.
    let bytes = classic(
        &[
            (1, b"<</Type/Catalog/Pages 2 0 R>>".to_vec()),
            (2, b"<</Type/Pages/Kids[5 0 R 3 0 R]/Count 2>>".to_vec()),
            (
                3,
                b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents[6 0 R 4 0 R]>>".to_vec(),
            ),
            (4, stream("", b"0 0 m 1 1 l S")),
            (5, b"1 0 R".to_vec()),
            (6, b"4 0 R".to_vec()),
        ],
        "",
    );
    let before = admit(&bytes, &Limits::default(), &never).unwrap().report;
    assert_eq!(before.page_count, 1);
    let (n, out) = run(&bytes);
    assert_eq!(out.page_count, 1);
    let objects: Vec<_> = removed(&n, "CS-PDF-0102", FindingKind::ObjectUnreadable)
        .iter()
        .filter_map(|r| r.object)
        .collect();
    assert!(objects.contains(&5) && objects.contains(&6), "{objects:?}");
}

#[test]
fn a_catalog_without_a_type_behind_a_reference_is_cleaned_not_dropped() {
    let bytes = classic(
        &[
            (1, b"<</Pages 2 0 R/JS(app.alert\\(1\\))>>".to_vec()),
            (2, b"<</Type/Pages/Kids[3 0 R]/Count 1>>".to_vec()),
            (
                3,
                b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>".to_vec(),
            ),
            (5, b"1 0 R".to_vec()),
        ],
        "",
    )
    .replace_root(5);
    let (n, out) = run(&bytes);
    assert_eq!(out.page_count, 1);
    assert_eq!(
        removed(
            &n,
            "CS-PDF-0103",
            FindingKind::Action(ActionKind::JavaScript)
        )[0]
        .object,
        Some(1)
    );
    assert_clean(&out);
}

#[test]
fn direct_page_tree_dictionaries_carrying_active_keys_are_cleaned_not_dropped() {
    // Found by the normalize fuzz target: /Pages is a direct dictionary that the
    // reader takes for the one page, carrying /S /SubmitForm; and a direct kid typed
    // as an embedded file.
    let bytes = classic(
        &[(
            1,
            b"<</Type/Catalog/Pages<</Kids[<</Type/EmbeddedFile/MediaBox[0 0 50 50]>>]\
/S/SubmitForm/F(https://x.invalid/)>>>>"
                .to_vec(),
        )],
        "",
    );
    let before = admit(&bytes, &Limits::default(), &never).unwrap().report;
    assert_eq!(before.page_count, 1);
    let (n, out) = run(&bytes);
    assert_eq!(out.page_count, 1);
    assert_eq!(out.pages[0].media_box.urx, 50.0);
    assert!(
        !removed(
            &n,
            "CS-PDF-0103",
            FindingKind::Action(ActionKind::SubmitForm)
        )
        .is_empty()
    );
    assert!(!removed(&n, "CS-PDF-0104", FindingKind::EmbeddedFile).is_empty());
    assert_clean(&out);
}
