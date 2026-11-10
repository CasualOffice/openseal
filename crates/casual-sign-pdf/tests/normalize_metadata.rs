//! Document metadata that is not an XMP packet (`NORM-03`, docs/30 §3): wrapped when
//! its root is `rdf:RDF`, dropped when it is not XML, not a stream, or declares a
//! DOCTYPE; an XMP packet is kept as stored. pyHanko refuses any later catalog update
//! (a B-LT seal's DSS) while the catalog's `/Metadata` is not one.
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
    FindingKind, Limits, MetadataFix, MetadataProblem, MetadataRepair, NormalizeOptions,
    Normalized, Object, OutputXref, admit, admit_strict, normalize,
};
use common::{classic, never, stream, zlib};

const RDF: &[u8] = b"<?xpacket begin='' id='W5M0MpCehiHzreSzNTczkc9d'?>\n\
<rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>\
<rdf:Description about='' xmlns:pdf='http://ns.adobe.com/pdf/1.3/' pdf:Producer='Acrobat Distiller 3.01'/>\
</rdf:RDF>\n<?xpacket end='r'?>";

const PACKET: &[u8] = b"<?xpacket begin='' id='W5M0MpCehiHzreSzNTczkc9d'?>\
<x:xmpmeta xmlns:x='adobe:ns:meta/'><rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'/>\
</x:xmpmeta><?xpacket end='w'?>";

/// A one-page file whose catalog has `/Metadata` `meta` and object 5 `five`.
fn doc(meta: &str, five: Option<Vec<u8>>) -> Vec<u8> {
    let mut objs = vec![
        (
            1,
            format!("<</Type/Catalog/Pages 2 0 R/Metadata {meta}>>").into_bytes(),
        ),
        (2, b"<</Type/Pages/Kids[3 0 R]/Count 1>>".to_vec()),
        (
            3,
            b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>".to_vec(),
        ),
    ];
    if let Some(f) = five {
        objs.push((5, f));
    }
    classic(&objs, "")
}

fn run(bytes: &[u8]) -> (Normalized, Option<Vec<u8>>) {
    let mut a = admit(bytes, &Limits::default(), &never).unwrap();
    let n = normalize(
        &mut a,
        &NormalizeOptions::with_xref(OutputXref::Table),
        &never,
    )
    .unwrap();
    let mut out = admit_strict(&n.bytes, &Limits::default(), &never).unwrap();
    let doc = &mut out.document;
    let root = doc.trailer().get(b"Root").cloned().unwrap();
    let Object::Dictionary(cat) = doc.resolve(&root, &never).unwrap() else {
        panic!("no catalog");
    };
    let meta = match cat.get(b"Metadata") {
        Some(Object::Reference(r)) => Some(doc.decode_stream(r.num, &never).unwrap()),
        None => None,
        Some(other) => panic!("/Metadata left as {other:?}"),
    };
    (n, meta)
}

fn dropped(n: &Normalized, why: MetadataProblem, object: Option<u32>) {
    assert_eq!(
        n.report.metadata,
        Some(MetadataRepair {
            object,
            fix: MetadataFix::Dropped(why)
        })
    );
    assert!(
        n.report
            .removed
            .iter()
            .any(|r| r.code == "CS-PDF-0110" && r.kind == FindingKind::Metadata),
        "{:?}",
        n.report.removed
    );
}

#[test]
fn rdf_root_metadata_is_wrapped_in_xmpmeta() {
    let bytes = doc(
        "5 0 R",
        Some(stream(
            "/Type/Metadata/Subtype/XML/Filter/FlateDecode",
            &zlib(RDF),
        )),
    );
    let (n, meta) = run(&bytes);
    assert_eq!(
        n.report.metadata,
        Some(MetadataRepair {
            object: Some(5),
            fix: MetadataFix::Wrapped
        })
    );
    let meta = meta.expect("metadata kept");
    let text = String::from_utf8(meta).unwrap();
    assert!(text.starts_with("<?xpacket begin="), "{text}");
    assert!(text.contains("<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\n<rdf:RDF"));
    assert!(text.contains("pdf:Producer='Acrobat Distiller 3.01'"));
    assert!(text.trim_end().ends_with("<?xpacket end=\"r\"?>"));
    assert!(n.report.removed.iter().all(|r| r.code != "CS-PDF-0110"));
}

#[test]
fn an_xmp_packet_is_kept_as_it_is() {
    let bytes = doc("5 0 R", Some(stream("/Type/Metadata/Subtype/XML", PACKET)));
    let (n, meta) = run(&bytes);
    assert_eq!(n.report.metadata, None);
    assert_eq!(meta.as_deref(), Some(PACKET));
}

#[test]
fn metadata_that_is_not_xml_is_dropped() {
    let bytes = doc(
        "5 0 R",
        Some(stream(
            "/Type/Metadata/Subtype/XML",
            b"Title: not XML at all",
        )),
    );
    let (n, meta) = run(&bytes);
    assert_eq!(meta, None);
    dropped(&n, MetadataProblem::NotXml, Some(5));
}

#[test]
fn metadata_with_a_doctype_is_dropped() {
    let bytes = doc(
        "5 0 R",
        Some(stream(
            "/Type/Metadata/Subtype/XML",
            b"<!DOCTYPE x:xmpmeta [<!ENTITY e 'x'>]><x:xmpmeta xmlns:x='adobe:ns:meta/'>&e;</x:xmpmeta>",
        )),
    );
    let (n, meta) = run(&bytes);
    assert_eq!(meta, None);
    dropped(&n, MetadataProblem::Doctype, Some(5));
}

#[test]
fn metadata_that_is_not_a_stream_is_dropped() {
    let (n, meta) = run(&doc("<</Type/Metadata>>", None));
    assert_eq!(meta, None);
    dropped(&n, MetadataProblem::NotStream, None);
    // A reference to nothing (the corpus's wmc-design_with_fontforge_en_.pdf).
    let (n, meta) = run(&doc("9 0 R", None));
    assert_eq!(meta, None);
    dropped(&n, MetadataProblem::NotStream, Some(9));
}

#[test]
fn other_xml_is_dropped() {
    let bytes = doc(
        "5 0 R",
        Some(stream(
            "/Type/Metadata/Subtype/XML",
            b"<x:xapmeta xmlns:x='adobe:ns:meta/'/>",
        )),
    );
    let (n, meta) = run(&bytes);
    assert_eq!(meta, None);
    dropped(&n, MetadataProblem::NotXmp, Some(5));
}
