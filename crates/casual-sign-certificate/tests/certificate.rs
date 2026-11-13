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

use casual_sign_audit::{EventData, Personal, VerifyOptions, verify_trail};
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

/// Signer attachments are listed by recipient, field, kind, size and SHA-256 (WEB-06),
/// and their bounds are checked; with none, the section is absent.
#[test]
fn signer_attachments_are_listed_by_hash() {
    let fonts = FontSet::bundled();
    let (chain, delivered) = chain(1);
    let text = |inp: &casual_sign_certificate::CertificateInput<'_>| {
        let r = render_certificate(inp, &fonts, &CertificateOptions::default()).unwrap();
        let mut a = admit(&r.bytes, &Limits::default(), &never).unwrap();
        let pages = a.report.pages.clone();
        casual_sign_fields::extract_text(&mut a.document, &pages, &never)
            .unwrap()
            .iter()
            .flat_map(|p| p.runs.iter().map(|r| r.text.clone()))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let mut with = input(&chain, delivered, 1);
    let sha = casual_sign_audit::Hash256::digest(b"the attached file");
    with.attachments = vec![casual_sign_certificate::AttachmentRow {
        recipient: with.recipients[0].party.name.clone(),
        field: "proof_of_address".into(),
        media_type: "application/pdf".into(),
        bytes: 1234,
        sha256: sha,
    }];
    let shown = text(&with);
    assert!(shown.contains("Signer attachments"), "{shown}");
    assert!(shown.contains("proof_of_address"), "{shown}");
    assert!(shown.contains("1234 bytes"), "{shown}");
    let hex = sha.hex();
    assert!(
        shown.replace(' ', "").contains(&hex[..16]),
        "the hash is printed: {shown}"
    );
    assert!(!text(&input(&chain, delivered, 1)).contains("Signer attachments"));
    with.attachments[0].field = "x".repeat(4_001);
    assert_eq!(
        render_certificate(&with, &fonts, &CertificateOptions::default())
            .unwrap_err()
            .code(),
        "CS-AUD-0020"
    );
}

/// An envelope that ended without completing (UXW-30) gets an envelope certificate that
/// says how it ended, who ended it, when and why, and never claims completion; without
/// an ending the certificate is one of completion, as before.
#[test]
fn an_ended_envelope_certificate_says_how_it_ended_and_never_claims_completion() {
    let fonts = FontSet::bundled();
    let (chain, delivered) = chain(2);
    let render = |inp: &casual_sign_certificate::CertificateInput<'_>| {
        let r = render_certificate(inp, &fonts, &CertificateOptions::default()).unwrap();
        let mut a = admit(&r.bytes, &Limits::default(), &never).unwrap();
        let pages = a.report.pages.clone();
        let text = casual_sign_fields::extract_text(&mut a.document, &pages, &never)
            .unwrap()
            .iter()
            .flat_map(|p| p.runs.iter().map(|r| r.text.clone()))
            .collect::<Vec<_>>()
            .join(" ");
        (r.bytes, text)
    };
    let (_, done) = render(&input(&chain, delivered, 2));
    assert!(done.contains("Certificate of Completion"), "{done}");
    assert!(!done.contains("not completed"), "{done}");

    for (kind, by, reason, outcome, last) in [
        (
            casual_sign_certificate::EndKind::Declined,
            Some(name(1)),
            Some("Terms changed"),
            format!("Declined by {}", name(1)),
            EventData::EnvelopeDeclined {
                recipient_id: id("rcp-1"),
            },
        ),
        (
            casual_sign_certificate::EndKind::Voided,
            Some("Sam Sender".to_owned()),
            Some("Replaced by a new version"),
            "Voided by Sam Sender".to_owned(),
            EventData::EnvelopeVoided {
                reason: Personal("Replaced by a new version".to_owned()),
            },
        ),
        (
            casual_sign_certificate::EndKind::Expired,
            None,
            None,
            "Expired".to_owned(),
            EventData::EnvelopeExpired {},
        ),
    ] {
        let (chain, delivered, at) = chain_ending(2, last);
        let mut ended = input(&chain, delivered, 2);
        ended.envelope.status = outcome.split(' ').next().unwrap().to_owned();
        ended.ending = Some(casual_sign_certificate::Ending {
            kind,
            at,
            by,
            reason: reason.map(str::to_owned),
        });
        let (bytes, text) = render(&ended);
        assert_eq!(bytes, render(&ended).0, "deterministic");
        assert!(!text.contains("Certificate of Completion"), "{text}");
        assert!(
            text.contains("Envelope Certificate (not completed)"),
            "{text}"
        );
        assert!(
            text.contains(&format!("it was {}", kind.as_str())),
            "{text}"
        );
        assert!(text.contains(&outcome), "{text}");
        assert!(text.contains("Not completed"), "{text}");
        assert!(text.contains("were not sealed"), "{text}");
        if let Some(why) = reason {
            assert!(text.contains(why), "{text}");
        }
        // The PDF's own title says the same.
        let needle = b"Envelope Certificate";
        assert!(bytes.windows(needle.len()).any(|w| w == needle));
        assert!(!bytes.windows(25).any(|w| w == b"Certificate of Completion"));
        std::fs::write(
            out_dir("standalone").join(format!("certificate-{}.pdf", kind.as_str())),
            &bytes,
        )
        .unwrap();
    }
    let (declined, delivered, at) = chain_ending(
        2,
        EventData::EnvelopeDeclined {
            recipient_id: id("rcp-1"),
        },
    );
    let mut bad = input(&declined, delivered, 2);
    bad.ending = Some(casual_sign_certificate::Ending {
        kind: casual_sign_certificate::EndKind::Declined,
        at,
        by: None,
        reason: Some("x".repeat(4_001)),
    });
    assert_eq!(
        render_certificate(&bad, &fonts, &CertificateOptions::default())
            .unwrap_err()
            .code(),
        "CS-AUD-0020"
    );
}

/// The ending is the chain's, not the caller's word (UXW-30): a certificate of
/// completion for a chain that ended, an ending for a chain that completed, or an
/// ending of another kind or time than the chain's are each refused.
#[test]
fn a_certificate_refuses_an_ending_the_chain_does_not_record() {
    use casual_sign_certificate::{EndKind, Ending};
    let fonts = FontSet::bundled();
    let refused = |inp: &casual_sign_certificate::CertificateInput<'_>| {
        render_certificate(inp, &fonts, &CertificateOptions::default())
            .map(|_| ())
            .map_err(|e| (e.code(), e.to_string()))
    };
    let ending = |kind, at| {
        Some(Ending {
            kind,
            at,
            by: None,
            reason: None,
        })
    };
    let (declined, delivered, at) = chain_ending(
        2,
        EventData::EnvelopeDeclined {
            recipient_id: id("rcp-1"),
        },
    );
    let expected = Err((
        "CS-AUD-0020",
        "CS-AUD-0020: certificate input: ending".to_owned(),
    ));
    // A declined chain called complete.
    let mut inp = input(&declined, delivered, 2);
    assert_eq!(refused(&inp), expected, "no ending for a declined chain");
    // Another kind, or another time.
    inp.ending = ending(EndKind::Voided, at);
    assert_eq!(refused(&inp), expected, "a void the chain does not record");
    inp.ending = ending(EndKind::Declined, t(1));
    assert_eq!(refused(&inp), expected, "a time the chain does not record");
    inp.ending = ending(EndKind::Declined, at);
    assert_eq!(refused(&inp), Ok(()), "the chain's own ending");
    // A chain that reached completion has no ending.
    let (done, delivered) = chain(2);
    let mut inp = input(&done, delivered, 2);
    assert_eq!(refused(&inp), Ok(()));
    inp.ending = ending(EndKind::Expired, at);
    assert_eq!(refused(&inp), expected, "an ending for a completed chain");
}

#[test]
fn locations_at_their_longest_fit_the_layout() {
    use casual_sign_audit::{FallbackReason, Location, MAX_DATABASE_BYTES, MAX_PLACE_BYTES};
    let fonts = FontSet::bundled();
    let (chain, delivered) = chain(3);
    let mut long = input(&chain, delivered, 3);
    let place = |c: char| c.to_string().repeat(MAX_PLACE_BYTES);
    let words = "Llanfairpwllgwyngyll ".repeat(MAX_PLACE_BYTES / 21);
    let db = "GeoIP2-City-Enterprise ".repeat(MAX_DATABASE_BYTES / 23);
    long.recipients[0].location = Some(
        Location::device(-89.999_95, -179.999_95, 20_037_509.0)
            .unwrap()
            .with_place(Some("GB"), Some(&words), Some(&place('W')))
            .unwrap(),
    );
    long.recipients[1].location = Some(
        Location::ip(
            FallbackReason::Unavailable,
            db.trim_end(),
            89.123_456_789,
            179.987_654_321,
        )
        .unwrap()
        .with_place(Some("NZ"), Some(&place('m')), Some(words.trim_end()))
        .unwrap(),
    );
    long.recipients[2].location =
        Some(Location::ip_unresolved(FallbackReason::Declined, Some(db.trim_end())).unwrap());
    let r = render_certificate(&long, &fonts, &CertificateOptions::default()).unwrap();
    assert_eq!(
        r.lines_shrunk, 0,
        "line breaking measures the location rows"
    );
    let a = admit_strict(&r.bytes, &Limits::default(), &never).unwrap();
    assert_eq!(a.report.page_count as usize, r.pages);
    // More rows than without locations, never fewer pages.
    let mut bare = input(&chain, delivered, 3);
    for rec in &mut bare.recipients {
        rec.location = None;
    }
    let b = render_certificate(&bare, &fonts, &CertificateOptions::default()).unwrap();
    assert!(r.pages >= b.pages);
    assert!(r.bytes != b.bytes, "the location rows are drawn");
    std::fs::write(
        out_dir("standalone").join("certificate-long-locations.pdf"),
        &r.bytes,
    )
    .unwrap();

    // A place in a script no bundled face has fails like a name does, until FLT-01.
    let mut cjk = input(&chain, delivered, 1);
    cjk.recipients[0].location = Some(
        Location::ip(
            FallbackReason::Declined,
            "GeoLite2-City 2026-11-04",
            35.68,
            139.69,
        )
        .unwrap()
        .with_place(Some("JP"), None, Some("東京"))
        .unwrap(),
    );
    assert_eq!(
        render_certificate(&cjk, &fonts, &CertificateOptions::default())
            .unwrap_err()
            .code(),
        "CS-FLT-0001"
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

/// A one-page file whose page tree root carries inheritable `/Rotate`, `/CropBox`,
/// `/MediaBox` and `/Resources`.
fn inheriting_pdf() -> Vec<u8> {
    let objs: [&[u8]; 4] = [
        b"<</Type/Catalog/Pages 2 0 R>>",
        b"<</Type/Pages/Kids[3 0 R]/Count 1/Rotate 90/MediaBox[0 0 400 500]/CropBox[10 10 200 200]/Resources<</Font<</F1 5 0 R>>>>>>",
        b"<</Type/Page/Parent 2 0 R/Contents 4 0 R>>",
        b"<</Length 0>>\nstream\n\nendstream",
    ];
    let mut out = b"%PDF-1.7\n".to_vec();
    let mut offs = Vec::new();
    for (i, body) in objs.iter().enumerate() {
        offs.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref = out.len();
    out.extend_from_slice(b"xref\n0 5\n0000000000 65535 f \n");
    for o in offs {
        out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!("trailer\n<</Size 5/Root 1 0 R>>\nstartxref\n{xref}\n%%EOF\n").as_bytes(),
    );
    out
}

#[test]
fn appended_pages_inherit_nothing_from_the_document() {
    let fonts = FontSet::bundled();
    let (chain, delivered) = chain(1);
    let input = input(&chain, delivered, 1);
    let bytes = inheriting_pdf();
    let mut a = admit(&bytes, &Limits::default(), &never).unwrap();
    assert_eq!(a.report.pages[0].rotate, 90);
    let r = append_certificate(&mut a, &input, &fonts, &CertificateOptions::default()).unwrap();
    let b = admit_strict(&r.bytes, &Limits::default(), &never).unwrap();
    assert_eq!(b.report.page_count, 1 + r.pages_added as u32);
    for p in &b.report.pages[1..] {
        assert_eq!(p.rotate, 0);
        assert_eq!((p.media_box.urx, p.media_box.ury), (595.28, 841.89));
        assert_eq!(p.crop_box, p.media_box);
    }
    std::fs::write(out_dir("appended-inherit").join("inherit.pdf"), &r.bytes).unwrap();
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
