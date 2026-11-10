//! Certificates for 1, 3 and 25 recipients, standalone and appended; what our own reader
//! sees in them. The PDFs are left in `target/certificate-out/` for the independent
//! checks (pypdf text and attachment extraction, pypdfium2 rendering).

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::path::PathBuf;

use casual_sign_audit::{VerifyOptions, verify_trail};
use casual_sign_certificate::{
    CertificateOptions, DisclosurePlacement, EmailMask, PageSize, append_certificate,
    render_certificate,
};
use casual_sign_flatten::FontSet;
use casual_sign_pdf::{Document, FindingKind, Limits, Object, admit, admit_strict};
use common::*;

/// The embedded files' decoded bytes, found by our reader.
fn embedded(doc: &mut Document<'_>, objects: &[u32]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for &n in objects {
        let Ok(v) = doc.object(n, &never) else {
            continue;
        };
        if v.get(b"Type").and_then(Object::as_name) == Some(b"EmbeddedFile") {
            out.push(doc.decode_stream(n, &never).unwrap());
        }
    }
    out
}

fn options(mask: EmailMask) -> CertificateOptions {
    let mut o = CertificateOptions::default();
    o.email_mask = mask;
    o
}

#[test]
fn certificates_for_1_3_and_25_recipients() {
    let fonts = FontSet::bundled();
    let dir = out_dir("standalone");
    for (n, mask) in [
        (1, EmailMask::Show),
        (3, EmailMask::Partial),
        (25, EmailMask::Show),
    ] {
        let (chain, delivered) = chain(n);
        let input = input(&chain, delivered, n);
        let r = render_certificate(&input, &fonts, &options(mask)).unwrap();
        let again = render_certificate(&input, &fonts, &options(mask)).unwrap();
        assert_eq!(r.bytes, again.bytes, "deterministic");
        assert_eq!(
            r.lines_shrunk, 0,
            "line breaking measures the bundled faces"
        );

        // Our reader admits it, strictly; the trail shows as an embedded file.
        let a = admit_strict(&r.bytes, &Limits::default(), &never).unwrap();
        assert_eq!(a.report.page_count as usize, r.pages);
        assert!(
            a.report
                .findings
                .iter()
                .any(|f| f.kind == FindingKind::EmbeddedFile)
        );
        // The stream, its file specification, and the catalog that names the tree.
        assert_eq!(a.report.embedded_files.len(), 3);
        assert!(a.report.has_code("CS-PDF-0104"));
        let mut a = admit(&r.bytes, &Limits::default(), &never).unwrap();
        let files = embedded(&mut a.document, &a.report.embedded_files.clone());
        assert_eq!(files.len(), 1);
        assert_eq!(files[0], chain.to_trail_json().unwrap());
        let report = verify_trail(
            &files[0],
            &VerifyOptions {
                expected_head: chain.head(),
                ..VerifyOptions::default()
            },
        );
        assert!(report.is_valid(), "{report:?}");

        if n == 25 {
            assert!(r.pages >= 8, "25 recipients span pages: {}", r.pages);
        }
        let file = dir.join(format!("certificate-{n}.pdf"));
        std::fs::write(&file, &r.bytes).unwrap();
        std::fs::write(
            dir.join(format!("certificate-{n}.json")),
            chain.to_trail_json().unwrap(),
        )
        .unwrap();
        // What the independent check must find in the text.
        let mut expect = vec![chain.head().unwrap().to_string(), delivered.hex()];
        for i in 0..n {
            expect.push(name(i));
            expect.push(match mask {
                EmailMask::Partial => {
                    let e = email(i);
                    let (local, domain) = e.split_once('@').unwrap();
                    format!("{}***@{domain}", &local[..1])
                }
                _ => email(i),
            });
        }
        std::fs::write(
            dir.join(format!("certificate-{n}.expect")),
            expect.join("\n"),
        )
        .unwrap();
        eprintln!(
            "certificate {n} recipients: {} pages, {} bytes",
            r.pages,
            r.bytes.len()
        );
    }
}

#[test]
fn letter_inline_disclosure_and_other_formats() {
    let fonts = FontSet::bundled();
    let (chain, delivered) = chain(2);
    let input = input(&chain, delivered, 2);
    let mut o = options(EmailMask::Hidden);
    o.page = PageSize::Letter;
    o.disclosure = DisclosurePlacement::Inline;
    o.date_format = casual_sign_model::DateFormat::DMmmYyyy;
    o.utc_offset_minutes = 330;
    o.zone_label = Some("Asia/Kolkata".into());
    let r = render_certificate(&input, &fonts, &o).unwrap();
    let a = admit_strict(&r.bytes, &Limits::default(), &never).unwrap();
    assert_eq!(a.report.pages[0].media_box.urx, 612.0);
    std::fs::write(
        out_dir("standalone").join("certificate-letter.pdf"),
        &r.bytes,
    )
    .unwrap();
}

#[test]
fn input_errors_carry_codes() {
    let fonts = FontSet::bundled();
    let (chain, delivered) = chain(1);
    let mut bad = input(&chain, delivered, 1);
    bad.envelope.id = "another".into();
    assert_eq!(
        render_certificate(&bad, &fonts, &CertificateOptions::default())
            .unwrap_err()
            .code(),
        "CS-AUD-0020"
    );
    let mut bad = input(&chain, delivered, 1);
    bad.envelope.subject = "x".repeat(4_001);
    assert_eq!(
        render_certificate(&bad, &fonts, &CertificateOptions::default())
            .unwrap_err()
            .code(),
        "CS-AUD-0020"
    );
    let mut bad = input(&chain, delivered, 1);
    bad.recipients[0].party.name = "名前".into();
    assert_eq!(
        render_certificate(&bad, &fonts, &CertificateOptions::default())
            .unwrap_err()
            .code(),
        "CS-FLT-0001",
        "a character no bundled face has"
    );
}

/// Corpus files to append to: unsigned, unencrypted, without embedded files.
fn corpus() -> Option<(PathBuf, Vec<&'static str>)> {
    let dir = std::env::var_os("OPENSEAL_CORPUS_DIR")
        .map_or_else(|| repo_root().join("fixtures/corpus/files"), PathBuf::from);
    dir.is_dir().then(|| {
        (
            dir,
            vec![
                "arxiv-0807.2521v1.pdf",
                "arxiv-2501.17879v1.pdf",
                "arxiv-2510.18036v1.pdf",
                "bls-handbook.pdf",
                "cdc-mm6001.pdf",
                "cms-1500.pdf",
                "dol-wh380e.pdf",
                "fop-pdf-complete.pdf",
                "fema-are-you-ready.pdf",
                "copyright-circ66.pdf",
            ],
        )
    })
}

#[test]
fn appended_to_corpus_documents() {
    let Some((dir, files)) = corpus() else {
        eprintln!("SKIPPED: corpus absent; set OPENSEAL_CORPUS_DIR");
        return;
    };
    let fonts = FontSet::bundled();
    let out = out_dir("appended");
    let (chain, delivered) = chain(3);
    let input = input(&chain, delivered, 3);
    let mut done = 0;
    for f in files {
        let bytes = std::fs::read(dir.join(f)).unwrap();
        let mut a = admit(&bytes, &Limits::default(), &never).unwrap();
        let before = a.report.page_count as usize;
        let r = match append_certificate(&mut a, &input, &fonts, &CertificateOptions::default()) {
            Ok(r) => r,
            Err(e) => panic!("{f}: {e}"),
        };
        assert!(r.bytes.starts_with(&bytes), "{f}: prefix invariant");
        assert_eq!(r.first_page, before);
        let b = admit(&r.bytes, &Limits::default(), &never).unwrap();
        assert_eq!(b.report.page_count as usize, before + r.pages_added, "{f}");
        assert!(!b.report.repaired, "{f}");
        assert_eq!(
            b.report.revisions.len(),
            a.report.revisions.len() + 1,
            "{f}: one update"
        );
        let mut b = b;
        let files = embedded(&mut b.document, &b.report.embedded_files.clone());
        assert_eq!(files, [chain.to_trail_json().unwrap()], "{f}");
        std::fs::write(out.join(f), &r.bytes).unwrap();
        eprintln!(
            "{f}: {before} + {} pages, {} -> {} bytes",
            r.pages_added,
            bytes.len(),
            r.bytes.len()
        );
        done += 1;
    }
    std::fs::write(out.join("trail.json"), chain.to_trail_json().unwrap()).unwrap();
    assert_eq!(done, 10);
}

#[test]
fn appending_twice_is_refused() {
    let fonts = FontSet::bundled();
    let (chain, delivered) = chain(1);
    let input = input(&chain, delivered, 1);
    let first = render_certificate(&input, &fonts, &CertificateOptions::default()).unwrap();
    let mut a = admit(&first.bytes, &Limits::default(), &never).unwrap();
    let e = append_certificate(&mut a, &input, &fonts, &CertificateOptions::default()).unwrap_err();
    assert_eq!(e.code(), "CS-AUD-0022");
}
