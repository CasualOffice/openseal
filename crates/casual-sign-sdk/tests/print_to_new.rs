//! Print to new through the facade (`NORM-02`, docs/30 §2): a document certified at
//! DocMDP P1, which no later signature may follow, becomes a new, unsigned document with
//! the certification's visible appearance drawn into the page, and is then filled,
//! flattened, completed and sealed as any other. And `NORM-03` end to end: metadata
//! whose root is `rdf:RDF` is wrapped when the document is prepared, and the document
//! seals at B-LT.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    missing_docs
)]

#[path = "../../casual-sign-seal/tests/common/mod.rs"]
mod common;
mod support;

use casual_sign_pdf::{Object, Rect, admit};
use casual_sign_sdk::{
    Credentials, DocMdp, Engine, FontSet, Hash256, Limits, MetadataFix, NoRevocation, NoTimestamps,
    PdfSignatureKind, PrepareOptions, Profile, SealKind,
};
use casual_sign_seal::{Appearance, Visible};
use support::{Class, Options, run_with};

const BLUE_BOX: &[u8] = b"0 0 1 rg 0 0 200 50 re f";

fn engine() -> Engine {
    Engine::new(Limits::default(), FontSet::bundled())
}

fn never() -> bool {
    false
}

/// A one-page document certified at P1 by a visible signature `Certifier` drawing a
/// blue box at (72, 100).
fn certified_p1(e: &Engine) -> Vec<u8> {
    let base = e
        .prepare(&common::one_page("Agreement"), &Credentials::default())
        .unwrap();
    let mut req = e.seal_request(Profile::BaselineB, "Certifier", common::SIGNING_TIME);
    req.kind = SealKind::Certification { docmdp: DocMdp::P1 };
    req.trust = support::trust_store();
    req.visible = Some(Visible {
        page: 0,
        rect: Rect {
            llx: 72.0,
            lly: 100.0,
            urx: 272.0,
            ury: 150.0,
        },
        appearance: Appearance::Content {
            content: BLUE_BOX.to_vec(),
            resources: None,
        },
    });
    e.seal(
        &base.bytes,
        &req,
        &common::p256(),
        &NoTimestamps,
        &NoRevocation,
    )
    .unwrap()
    .bytes
}

/// Every decoded stream of `bytes`.
fn streams(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut a = admit(bytes, &Limits::default(), &never).unwrap();
    let nums: Vec<u32> = a.document.object_numbers().collect();
    nums.into_iter()
        .filter_map(|n| match a.document.object(n, &never) {
            Ok(Object::Stream(_)) => a.document.decode_stream(n, &never).ok(),
            _ => None,
        })
        .collect()
}

fn has(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn stream(dict: &str, data: &[u8]) -> Vec<u8> {
    let mut v = format!("<< {dict} /Length {} >>\nstream\n", data.len()).into_bytes();
    v.extend_from_slice(data);
    v.extend_from_slice(b"\nendstream");
    v
}

#[test]
fn a_p1_certified_document_prints_to_a_new_one_with_its_signature_drawn() {
    let e = engine();
    let certified = certified_p1(&e);
    assert_eq!(e.keep_signed(&certified).unwrap_err().code(), "CS-WRT-0004");
    assert_eq!(
        e.prepare(&certified, &Credentials::default())
            .unwrap_err()
            .code(),
        "CS-PDF-0014"
    );

    let d = e
        .prepare_from_signed(&certified, &Credentials::default())
        .unwrap();
    let printed = d.printed.as_ref().expect("a print-to-new record");
    assert_eq!(printed.original, Hash256::digest(&certified));
    assert_eq!(printed.docmdp, Some(1));
    assert_eq!(printed.signatures.len(), 1);
    assert_eq!(
        printed.signatures[0].field_name.as_deref(),
        Some("Certifier")
    );
    assert_eq!(printed.signatures[0].kind, PdfSignatureKind::Certification);
    assert_eq!(printed.appearances_drawn, 1);
    assert_eq!(d.hash, Hash256::digest(&d.bytes));

    // A new document: one revision, unsigned, no form, no /Perms.
    let out = e.admit(&d.bytes, &Credentials::default()).unwrap();
    assert!(!out.is_signed());
    assert_eq!(out.revisions.len(), 1);
    assert!(out.fields.is_empty());
    assert!(out.signatures.is_empty());
    assert!(!out.has_perms);
    assert_eq!(out.page_count, 1);
    // The signature's appearance is page content now: its stream is there, invoked
    // from a content stream the flattening added.
    let all = streams(&d.bytes);
    assert!(all.iter().any(|s| has(s, BLUE_BOX)), "appearance kept");
    assert!(
        all.iter().any(|s| has(s, b" Do") && has(s, b" cm")),
        "drawn into the page"
    );
}

#[test]
fn a_printed_document_is_filled_flattened_and_sealed() {
    let e = engine();
    let certified = certified_p1(&e);
    let opts = Options {
        print_to_new: true,
        ..Options::default()
    };
    let r = run_with(&e, "certified.pdf", &certified, opts);
    assert_eq!(r.failure, None, "{:?}", r.steps);
    assert_eq!(r.class, Some(Class::Printed));
    assert_eq!(
        r.steps,
        [
            "admit",
            "print-to-new",
            "fill",
            "flatten",
            "certificate",
            "seal",
            "verify"
        ]
    );
    assert!(r.prefix);
    let report = r.online.unwrap();
    assert_eq!(report.signatures.len(), 1, "only our seal");
    assert!(report.all_passed());
    // Off by default: the gate keeps the exclusion it has.
    let r = run_with(&e, "certified.pdf", &certified, Options::default());
    assert_eq!(r.failure.as_deref(), Some("keep-signed CS-WRT-0004"));
}

#[test]
fn attachments_are_admitted_on_their_own() {
    let e = engine();
    let inner = common::one_page("Attached");
    let mut objs = vec![
        b"<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [(inner.pdf) 4 0 R (notes.txt) 6 0 R] >> >> >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>".to_vec(),
        b"<< /Type /Filespec /F (inner.pdf) /EF << /F 5 0 R >> >>".to_vec(),
    ];
    objs.push(stream("/Type /EmbeddedFile", &inner));
    objs.push(b"<< /Type /Filespec /F (notes.txt) /EF << /F 7 0 R >> >>".to_vec());
    objs.push(stream("/Type /EmbeddedFile", b"plain text"));
    let bytes = common::classic_pdf(&objs);

    let plain = e.prepare(&bytes, &Credentials::default()).unwrap();
    assert!(plain.attachments.is_empty());
    let d = e
        .prepare_with(
            &bytes,
            &Credentials::default(),
            &PrepareOptions::normalize(true),
        )
        .unwrap();
    assert_eq!(d.bytes, plain.bytes, "removed from the document either way");
    assert_eq!(d.attachments.len(), 2);
    let pdf = &d.attachments[0];
    assert_eq!(pdf.name.as_deref(), Some("inner.pdf"));
    assert_eq!(pdf.sha256, Hash256::digest(&inner));
    let delivered = pdf.outcome.as_ref().expect("the PDF admits");
    assert_eq!(delivered.admission.page_count, 1);
    let text = &d.attachments[1];
    assert_eq!(text.name.as_deref(), Some("notes.txt"));
    assert_eq!(text.outcome.as_ref().unwrap_err(), &"CS-PDF-0005");
}

#[test]
fn rdf_metadata_is_wrapped_and_the_document_seals_at_b_lt() {
    let e = engine();
    let rdf = b"<?xpacket begin='' id='W5M0MpCehiHzreSzNTczkc9d'?>\
<rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>\
<rdf:Description about='' xmlns:pdf='http://ns.adobe.com/pdf/1.3/' pdf:Producer='Distiller'/>\
</rdf:RDF><?xpacket end='r'?>";
    let content = b"BT /F1 24 Tf 72 720 Td (Old) Tj ET";
    let bytes = common::classic_pdf(&[
        b"<< /Type /Catalog /Pages 2 0 R /Metadata 6 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>".to_vec(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec(),
        stream("", content),
        stream("/Type /Metadata /Subtype /XML", rdf),
    ]);
    let d = e.prepare(&bytes, &Credentials::default()).unwrap();
    let fix = d.normalization.as_ref().unwrap().metadata.unwrap();
    assert_eq!(fix.fix, MetadataFix::Wrapped);
    assert!(
        streams(&d.bytes)
            .iter()
            .any(|s| s.starts_with(b"<?xpacket") && has(s, b"<x:xmpmeta")),
        "the packet"
    );
    let opts = Options {
        profile: Profile::BaselineLt,
        ..Options::default()
    };
    let r = run_with(&e, "rdf.pdf", &bytes, opts);
    assert_eq!(r.failure, None, "{:?}", r.steps);
}
