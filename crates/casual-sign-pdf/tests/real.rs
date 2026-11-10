//! Constructs found in real files that the reader once refused (`PDF-REAL-01` to `03`).
//! Each test builds the construct in a small file, so it runs without the corpus.
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
    FindingKind, Limits, NormalizeOptions, SignatureKind, admit, admit_strict, normalize,
};
use common::{classic, never, pages, zlib};

/// One page, an AcroForm with a signed approval field.
fn signed_objects() -> Vec<(u32, Vec<u8>)> {
    let mut objs = pages(1);
    objs[0].1 = b"<</Type/Catalog/Pages 2 0 R/AcroForm 10 0 R>>".to_vec();
    objs.extend([
        (10, b"<</Fields[11 0 R]/SigFlags 3>>".to_vec()),
        (
            11,
            b"<</FT/Sig/T(sig)/V 12 0 R/Rect[0 0 0 0]/Subtype/Widget/P 3 0 R>>".to_vec(),
        ),
        (
            12,
            b"<</Type/Sig/SubFilter/adbe.pkcs7.detached/ByteRange[0 1 2 3]/Contents<00>>>".to_vec(),
        ),
    ]);
    objs
}

/// `PDF-REAL-01`: iText writes `0000000000 65536 n` for object numbers it never used
/// (the GPO certified CFR files). A generation above 65,535 names no object: the entry
/// is free, and the signed file is read without repair.
#[test]
fn generation_65536_entries_are_free_not_damage() {
    let objs = signed_objects();
    // Numbers 5 to 9 are unused; write two of them as iText does.
    let mut bytes = classic(&objs, "");
    let free = b"0000000000 65535 f \n";
    let xref = bytes.windows(6).rposition(|w| w == b"\nxref\n").unwrap();
    let mut changed = 0;
    let mut i = xref;
    while changed < 3 && i + free.len() <= bytes.len() {
        if &bytes[i..i + free.len()] == free {
            // The first is object 0's entry, which stays.
            if changed > 0 {
                bytes[i..i + free.len()].copy_from_slice(b"0000000000 65536 n \n");
            }
            changed += 1;
        }
        i += 1;
    }
    assert_eq!(bytes.windows(7).filter(|w| w == b"65536 n").count(), 2);
    for a in [
        admit_strict(&bytes, &Limits::default(), &never).unwrap(),
        admit(&bytes, &Limits::default(), &never).unwrap(),
    ] {
        assert!(!a.report.repaired, "read without repair");
        assert_eq!(a.report.signatures.len(), 1);
        assert_eq!(a.report.signatures[0].value, Some(12));
        assert_eq!(a.report.page_count, 1);
    }
}

/// `PDF-REAL-02`: LiveCycle's hybrid update lists its own xref stream at offset 0 in
/// that stream (`irs-f1040-2009`). Offset 0 is the header, never an object: the entry
/// is free, as a classic `n` entry at 0 is, and nothing needs repair.
#[test]
fn xref_stream_entry_at_offset_zero_is_free_not_damage() {
    let base = classic(&signed_objects(), "");
    let prev = {
        let s = String::from_utf8_lossy(&base[base.len() - 30..]).into_owned();
        s.rsplit("startxref")
            .next()
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .to_string()
    };
    let mut out = base.clone();
    let stm_pos = out.len();
    // One row for object 16 (the stream itself): type 1, offset 0, generation 0.
    let rows = zlib(&[1, 0, 0, 0, 0]);
    out.extend_from_slice(
        format!(
            "16 0 obj\n<</Type/XRef/Size 1/Index[16 1]/W[1 3 1]/Filter/FlateDecode/Length {}>>\nstream\n",
            rows.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(&rows);
    out.extend_from_slice(b"\nendstream\nendobj\n");
    let xref = out.len();
    out.extend_from_slice(
        format!(
            "xref\n0 0\ntrailer\n<</Size 17/Root 1 0 R/Prev {prev}/XRefStm {stm_pos}>>\nstartxref\n{xref}\n%%EOF\n"
        )
        .as_bytes(),
    );
    for a in [
        admit_strict(&out, &Limits::default(), &never).unwrap(),
        admit(&out, &Limits::default(), &never).unwrap(),
    ] {
        assert!(!a.report.repaired, "read without repair");
        assert_eq!(a.report.revisions.len(), 2);
        assert_eq!(a.report.signatures.len(), 1);
    }
}

/// `PDF-REAL-02`: usage-rights transform parameters carry `/EF` as an array of rights
/// names. That is not an embedded file.
#[test]
fn usage_rights_ef_array_is_not_an_embedded_file() {
    let mut objs = pages(1);
    objs[0].1 = b"<</Type/Catalog/Pages 2 0 R/Perms<</UR3 10 0 R>>>>".to_vec();
    objs.push((
        10,
        b"<</Type/Sig/Filter/Adobe.PPKLite/SubFilter/adbe.pkcs7.detached/ByteRange[0 1 2 3]/Contents<00>/Reference[<</Type/SigRef/TransformMethod/UR3/TransformParams<</Type/TransformParams/V/2.2/EF[/Create/Delete]/Form[/FillIn]>>>>]>>".to_vec(),
    ));
    let bytes = classic(&objs, "");
    let a = admit_strict(&bytes, &Limits::default(), &never).unwrap();
    assert!(a.report.embedded_files.is_empty());
    assert!(
        !a.report
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::EmbeddedFile)
    );
}

/// A one-page file whose only signature is a usage-rights one (`/Perms /UR3`), plus
/// `extra` objects and catalog entries.
fn usage_rights_only(catalog_extra: &str, extra: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut objs = pages(1);
    objs[0].1 =
        format!("<</Type/Catalog/Pages 2 0 R/Perms<</UR3 10 0 R>>{catalog_extra}>>").into_bytes();
    objs.push((
        10,
        b"<</Type/Sig/Filter/Adobe.PPKLite/SubFilter/adbe.pkcs7.detached/ByteRange[0 1 2 3]/Contents<00>/Reference[<</Type/SigRef/TransformMethod/UR3/TransformParams<</Type/TransformParams/V/2.2/Form[/FillIn]>>>>]>>".to_vec(),
    ));
    objs.extend_from_slice(extra);
    classic(&objs, "")
}

fn break_xref(bytes: &[u8]) -> Vec<u8> {
    [&bytes[..bytes.len() - 25], b"garbage\n"].concat()
}

/// `PDF-REAL-02` decision (docs/30 §2): usage-rights signatures alone do not make a
/// document signed, so a damaged one is repaired, not refused; the report still lists
/// the usage-rights signature, under its own finding.
#[test]
fn usage_rights_alone_do_not_make_a_document_signed() {
    let bytes = usage_rights_only("", &[]);
    let whole = admit_strict(&bytes, &Limits::default(), &never)
        .unwrap()
        .report;
    assert!(!whole.is_signed());
    assert!(whole.has_perms);
    assert_eq!(whole.signatures.len(), 1);
    assert_eq!(whole.signatures[0].kind, SignatureKind::UsageRights);
    assert_eq!(whole.signatures[0].value, Some(10));
    assert!(
        whole
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::UsageRights
                && f.code == "CS-PDF-0107"
                && f.object == Some(10))
    );
    assert!(
        !whole
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::Signatures)
    );

    let broken = break_xref(&bytes);
    let repaired = admit(&broken, &Limits::default(), &never)
        .expect("a usage-rights-only file is repaired, not refused")
        .report;
    assert!(repaired.repaired);
    assert_eq!(repaired.signatures.len(), 1);
    assert_eq!(repaired.signatures[0].kind, SignatureKind::UsageRights);
    assert_ne!(
        admit_strict(&broken, &Limits::default(), &never)
            .unwrap_err()
            .code(),
        "CS-PDF-0014"
    );
}

/// The same file with an approval signature as well is signed, and refused when
/// damaged (`CS-PDF-0014`).
#[test]
fn usage_rights_with_an_approval_signature_are_signed() {
    let bytes = usage_rights_only(
        "/AcroForm 11 0 R",
        &[
            (11, b"<</Fields[12 0 R]>>".to_vec()),
            (12, b"<</FT/Sig/T(s)/V 13 0 R/Rect[0 0 0 0]>>".to_vec()),
            (
                13,
                b"<</Type/Sig/SubFilter/ETSI.CAdES.detached/ByteRange[0 1 2 3]/Contents<00>>>"
                    .to_vec(),
            ),
        ],
    );
    let r = admit_strict(&bytes, &Limits::default(), &never)
        .unwrap()
        .report;
    assert!(r.is_signed());
    let kinds: Vec<SignatureKind> = r.signatures.iter().map(|s| s.kind).collect();
    assert!(kinds.contains(&SignatureKind::Approval));
    assert!(kinds.contains(&SignatureKind::UsageRights));
    assert_eq!(
        admit(&break_xref(&bytes), &Limits::default(), &never)
            .unwrap_err()
            .code(),
        "CS-PDF-0014"
    );
}

/// Normalization removes usage rights and says so (docs/30 §3).
#[test]
fn normalization_removes_usage_rights() {
    let bytes = usage_rights_only("", &[]);
    let mut a = admit(&bytes, &Limits::default(), &never).unwrap();
    let n = normalize(&mut a, &NormalizeOptions::default(), &never).unwrap();
    assert!(
        n.report
            .removed
            .iter()
            .any(|r| r.kind == FindingKind::UsageRights && r.code == "CS-PDF-0107")
    );
    let out = admit_strict(&n.bytes, &Limits::default(), &never)
        .unwrap()
        .report;
    assert!(!out.has_perms);
    assert!(out.signatures.is_empty());
    assert!(!out.has_code("CS-PDF-0107"));
}

/// `PDF-REAL-03` (`pysamples-unreadablemetadata`): the second half of the file is
/// zeroed, taking the page tree's root and the XMP metadata with it. The recovering
/// reader takes the pages from the page objects, reports the lost tree and metadata,
/// and normalization writes a new tree over the same pages. Strict reading refuses.
#[test]
fn unreadable_page_tree_root_and_metadata_are_recovered() {
    let mut objs = pages(3);
    objs[0].1 = b"<</Type/Catalog/Pages 2 0 R/Metadata 20 0 R>>".to_vec();
    // Page sizes differ so order and geometry are checked.
    for (i, w) in [(2usize, 300), (4, 400), (6, 500)] {
        objs[i].1 = format!(
            "<</Type/Page/Parent 2 0 R/MediaBox[0 0 {w} 792]/Contents {} 0 R>>",
            objs[i].0 + 1
        )
        .into_bytes();
    }
    objs.push((20, common::stream("/Type/Metadata/Subtype/XML", b"<x/>")));
    let mut bytes = classic(&objs, "");
    // Zero the tree root (object 2) and the metadata (object 20), as the file has.
    for num in [2u32, 20] {
        let head = format!("\n{num} 0 obj");
        let at = bytes
            .windows(head.len())
            .position(|w| w == head.as_bytes())
            .unwrap()
            + 1;
        let end = at + bytes[at..].windows(6).position(|w| w == b"endobj").unwrap() + 6;
        bytes[at..end].fill(0);
    }
    assert!(admit_strict(&bytes, &Limits::default(), &never).is_err());
    let mut a = admit(&bytes, &Limits::default(), &never).unwrap();
    let r = a.report.clone();
    assert_eq!(r.page_count, 3);
    let widths: Vec<f64> = r.pages.iter().map(|p| p.media_box.urx).collect();
    assert_eq!(widths, vec![300.0, 400.0, 500.0]);
    assert!(r.repaired);
    assert!(
        r.findings
            .iter()
            .any(|f| f.kind == FindingKind::PageTreeRebuilt && f.code == "CS-PDF-0101")
    );
    assert!(
        r.findings
            .iter()
            .any(|f| f.kind == FindingKind::ObjectUnreadable
                && f.code == "CS-PDF-0102"
                && f.object == Some(20))
    );
    let n = normalize(&mut a, &NormalizeOptions::default(), &never).unwrap();
    let out = admit_strict(&n.bytes, &Limits::default(), &never)
        .unwrap()
        .report;
    assert!(!out.repaired);
    let widths: Vec<f64> = out.pages.iter().map(|p| p.media_box.urx).collect();
    assert_eq!(widths, vec![300.0, 400.0, 500.0]);
}
