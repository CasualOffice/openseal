//! Print to new and attachments (`NORM-02`, docs/30 §2–3): a signed document written
//! as a new, unsigned one with its signature fields' appearances kept for flattening,
//! and embedded files extracted for separate admission when asked.
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
    FieldType, FindingKind, Limits, MAX_ATTACHMENTS, NormalizeOptions, Normalized, OutputXref,
    SignatureKind, admit, admit_strict, normalize,
};
use common::{classic, never, stream};

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// A one-page document certified at DocMDP P1, with an approval signature field
/// `Approver` whose widget draws a blue box, a DSS and `/SigFlags`.
fn certified() -> Vec<u8> {
    classic(
        &[
            (
                1,
                b"<</Type/Catalog/Pages 2 0 R/AcroForm<</Fields[10 0 R]/SigFlags 3>>\
/Perms<</DocMDP 11 0 R>>/DSS 14 0 R>>"
                    .to_vec(),
            ),
            (2, b"<</Type/Pages/Kids[3 0 R]/Count 1>>".to_vec()),
            (
                3,
                b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Annots[10 0 R]>>"
                    .to_vec(),
            ),
            (4, stream("", b"BT /F1 12 Tf 72 720 Td (Hi) Tj ET")),
            (
                10,
                b"<</Type/Annot/Subtype/Widget/FT/Sig/T(Approver)/F 4/Rect[100 100 300 150]\
/P 3 0 R/V 11 0 R/AP<</N 12 0 R>>>>"
                    .to_vec(),
            ),
            (
                11,
                b"<</Type/Sig/Filter/Adobe.PPKLite/SubFilter/ETSI.CAdES.detached\
/ByteRange[0 10 20 30]/Contents<0000>/Reference[<</Type/SigRef/TransformMethod/DocMDP\
/TransformParams<</Type/TransformParams/P 1/V/1.2>>>>]>>"
                    .to_vec(),
            ),
            (
                12,
                stream(
                    "/Type/XObject/Subtype/Form/BBox[0 0 200 50]",
                    b"0 0 1 rg 0 0 200 50 re f",
                ),
            ),
            (14, b"<</Certs[]/OCSPs[]/CRLs[]>>".to_vec()),
        ],
        "",
    )
}

fn print(bytes: &[u8], keep_attachments: bool) -> Normalized {
    let mut a = admit(bytes, &Limits::default(), &never).unwrap();
    let opts = NormalizeOptions {
        print_to_new: true,
        keep_attachments,
        ..NormalizeOptions::with_xref(OutputXref::Table)
    };
    normalize(&mut a, &opts, &never).unwrap()
}

#[test]
fn a_certified_document_prints_to_a_new_unsigned_one() {
    let bytes = certified();
    let input = admit(&bytes, &Limits::default(), &never).unwrap().report;
    assert!(input.is_signed());
    assert_eq!(input.docmdp, Some(1));

    let n = print(&bytes, false);
    let out = admit_strict(&n.bytes, &Limits::default(), &never)
        .unwrap()
        .report;
    assert!(!out.is_signed(), "still signed: {:?}", out.signatures);
    assert_eq!(out.docmdp, None);
    assert!(!out.has_perms);
    assert!(out.signatures.is_empty());
    for gone in [
        &b"/ByteRange"[..],
        b"/Perms",
        b"/DSS",
        b"/SigFlags",
        b"/DocMDP",
    ] {
        assert!(
            !contains(&n.bytes, gone),
            "{} left",
            String::from_utf8_lossy(gone)
        );
    }
    // The signature field and its appearance stay, for flattening into the page.
    assert_eq!(out.fields.len(), 1);
    assert_eq!(out.fields[0].field_type, FieldType::Signature);
    assert!(contains(&n.bytes, b"0 0 1 rg 0 0 200 50 re f"));
    assert_eq!(out.page_count, 1);

    let conv = &n.report.signatures_converted;
    assert_eq!(conv.len(), 1, "{conv:?}");
    assert_eq!(conv[0].field, Some(10));
    assert_eq!(conv[0].field_name.as_deref(), Some("Approver"));
    assert_eq!(conv[0].value, Some(11));
    assert_eq!(conv[0].kind, SignatureKind::Certification);
    assert_eq!(conv[0].sub_filter.as_deref(), Some("ETSI.CAdES.detached"));
    let codes: Vec<_> = n
        .report
        .removed
        .iter()
        .filter(|r| r.code == "CS-PDF-0111" && r.kind == FindingKind::Signatures)
        .filter_map(|r| r.object)
        .collect();
    assert!(
        codes.contains(&1),
        "/Perms and /DSS of the catalog: {codes:?}"
    );
    assert!(codes.contains(&11), "the signature value: {codes:?}");
}

#[test]
fn without_print_to_new_the_signed_document_is_still_refused() {
    let bytes = certified();
    let mut a = admit(&bytes, &Limits::default(), &never).unwrap();
    let e = normalize(&mut a, &NormalizeOptions::default(), &never).unwrap_err();
    assert_eq!(e.code(), "CS-PDF-0014");
}

#[test]
fn an_unsigned_document_prints_to_new_with_nothing_converted() {
    let bytes = classic(
        &[
            (1, b"<</Type/Catalog/Pages 2 0 R>>".to_vec()),
            (2, b"<</Type/Pages/Kids[3 0 R]/Count 1>>".to_vec()),
            (
                3,
                b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 10 10]>>".to_vec(),
            ),
        ],
        "",
    );
    let n = print(&bytes, false);
    assert!(n.report.signatures_converted.is_empty());
    assert!(n.attachments.is_empty());
}

/// Embedded files named by a file specification in the name tree and by an attachment
/// annotation, one stream shared.
fn with_attachments(extra: usize) -> Vec<u8> {
    let mut names = String::from("(a.pdf) 10 0 R");
    let mut objs = vec![
        (2, b"<</Type/Pages/Kids[3 0 R]/Count 1>>".to_vec()),
        (
            3,
            b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Annots[12 0 R]>>".to_vec(),
        ),
        (
            10,
            b"<</Type/Filespec/F(a.pdf)/UF(\xfe\xff\x00a\x00.\x00p\x00d\x00f)/EF<</F 11 0 R>>>>"
                .to_vec(),
        ),
        (11, stream("/Type/EmbeddedFile", b"%PDF-1.4 not really")),
        (
            12,
            b"<</Type/Annot/Subtype/FileAttachment/Rect[0 0 10 10]/FS 13 0 R>>".to_vec(),
        ),
        (13, b"<</Type/Filespec/F(b.txt)/EF<</F 11 0 R>>>>".to_vec()),
    ];
    for i in 0..extra {
        let num = u32::try_from(100 + 2 * i).unwrap();
        names.push_str(&format!(" (x{i}) {num} 0 R"));
        objs.push((
            num,
            format!("<</Type/Filespec/F(x{i})/EF<</F {} 0 R>>>>", num + 1).into_bytes(),
        ));
        objs.push((
            num + 1,
            stream("/Type/EmbeddedFile", format!("file {i}").as_bytes()),
        ));
    }
    objs.insert(
        0,
        (
            1,
            format!("<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles<</Names[{names}]>>>>>>")
                .into_bytes(),
        ),
    );
    classic(&objs, "")
}

#[test]
fn embedded_files_are_extracted_only_when_asked() {
    let bytes = with_attachments(0);
    let mut a = admit(&bytes, &Limits::default(), &never).unwrap();
    let plain = normalize(&mut a, &NormalizeOptions::default(), &never).unwrap();
    assert!(plain.attachments.is_empty());

    let mut a = admit(&bytes, &Limits::default(), &never).unwrap();
    let opts = NormalizeOptions {
        keep_attachments: true,
        ..NormalizeOptions::default()
    };
    let n = normalize(&mut a, &opts, &never).unwrap();
    assert_eq!(n.attachments.len(), 1, "one stream, two specifications");
    assert_eq!(n.attachments[0].object, 11);
    assert_eq!(n.attachments[0].name.as_deref(), Some("a.pdf"));
    assert_eq!(n.attachments[0].data, b"%PDF-1.4 not really");
    assert_eq!(n.report.attachments_dropped, 0);
    // Removed from the document all the same.
    let out = admit_strict(&n.bytes, &Limits::default(), &never)
        .unwrap()
        .report;
    assert!(out.embedded_files.is_empty());
    assert_eq!(n.bytes, plain.bytes);
}

#[test]
fn attachments_are_bounded() {
    let bytes = with_attachments(MAX_ATTACHMENTS);
    let mut a = admit(&bytes, &Limits::default(), &never).unwrap();
    let opts = NormalizeOptions {
        keep_attachments: true,
        ..NormalizeOptions::default()
    };
    let n = normalize(&mut a, &opts, &never).unwrap();
    assert_eq!(n.attachments.len(), MAX_ATTACHMENTS);
    assert_eq!(n.report.attachments_dropped, 1);
}
