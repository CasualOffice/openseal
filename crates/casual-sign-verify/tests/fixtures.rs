//! The verifier over `fixtures/signed/` (made by `gen.py`, cross-checked there with pyHanko
//! and EU DSS): every manifest row's verdict, each check's failure on its own mutation,
//! and the revision classes (docs/31 §7, SEC-S01, SEC-S02).
// Tests may unwrap, index, panic and do plain arithmetic on their own fixtures (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use std::path::PathBuf;
use std::time::Duration;

use casual_sign_verify::{
    Check, Disallowed, Indication, ModificationClass, SignatureKind, SubIndication, TimeSource,
    TrustStore, VerificationReport, VerifyOptions, verify,
};

const AT: Duration = Duration::from_secs(1_796_083_200); // 2026-12-01T00:00:00Z

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/signed")
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(dir().join(name)).unwrap()
}

fn trust() -> TrustStore {
    let mut t = TrustStore::new();
    t.add_anchor(&read("trust-root.der")).unwrap();
    t
}

fn check(bytes: &[u8]) -> VerificationReport {
    verify(bytes, &trust(), &VerifyOptions::at(AT))
}

fn verdict(i: &Indication) -> String {
    match i {
        Indication::TotalPassed => "TOTAL_PASSED".into(),
        Indication::TotalFailed(r) | Indication::Indeterminate(r) => {
            format!("{}:{}", i.name(), r.sub.name())
        }
    }
}

#[test]
fn every_manifest_row_matches() {
    let manifest = std::fs::read_to_string(dir().join("manifest.tsv")).unwrap();
    let mut wrong = Vec::new();
    let mut rows = 0;
    for line in manifest.lines().skip(1).filter(|l| !l.trim().is_empty()) {
        let f: Vec<&str> = line.split('\t').collect();
        let (file, sig, want) = (f[0], f[1].parse::<usize>().unwrap(), f[2]);
        let report = check(&read(file));
        let got = report
            .signatures
            .get(sig)
            .map_or("missing".to_string(), |s| verdict(&s.indication));
        if got != want {
            wrong.push(format!("{file}#{sig}: got {got}, manifest {want}"));
        }
        rows += 1;
    }
    assert!(rows >= 28, "manifest has {rows} rows");
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

fn first(bytes: &[u8]) -> casual_sign_verify::SignatureReport {
    check(bytes).signatures.into_iter().next().unwrap()
}

fn sub(s: &casual_sign_verify::SignatureReport) -> Option<SubIndication> {
    s.indication.reason().map(|r| r.sub)
}

/// The `/Contents` hex of the last signature: (start, end) of the hex digits.
fn contents_hex(bytes: &[u8]) -> (usize, usize) {
    let s = String::from_utf8_lossy(bytes);
    let at = s.rfind("/ByteRange").unwrap();
    let nums: Vec<usize> = s[at..]
        .split(|c: char| !c.is_ascii_digit())
        .filter(|t| !t.is_empty())
        .take(4)
        .map(|t| t.parse().unwrap())
        .collect();
    (nums[1] + 1, nums[2] - 1)
}

/// Flip one hex digit of `/Contents` at `pos` from the end of its non-zero part.
fn flip_contents_from_end(bytes: &[u8], back: usize) -> Vec<u8> {
    let (start, end) = contents_hex(bytes);
    let hex = &bytes[start..end];
    let last = hex.iter().rposition(|&b| b != b'0').unwrap();
    let pos = start + last - back;
    let mut out = bytes.to_vec();
    out[pos] = if out[pos] == b'1' { b'2' } else { b'1' };
    out
}

#[test]
fn intact_long_term_signature_passes_every_check() {
    let s = first(&read("b-lt.pdf"));
    assert_eq!(s.indication, Indication::TotalPassed);
    let c = s.checks;
    for (name, ch) in [
        ("byte_range", c.byte_range),
        ("digest", c.digest),
        ("signature", c.signature),
        ("timestamp", c.timestamp),
        ("chain", c.chain),
        ("revocation", c.revocation),
        ("modifications", c.modifications),
    ] {
        assert_eq!(ch, Check::Passed, "{name}");
    }
    assert_eq!(s.time_source, TimeSource::SignatureTimestamp);
    assert!(s.timestamp.is_some());
}

#[test]
fn byte_range_rules() {
    for f in ["br-not-zero.pdf", "br-gap.pdf"] {
        let s = first(&read(f));
        assert_eq!(sub(&s), Some(SubIndication::FormatFailure), "{f}");
        assert!(matches!(s.checks.byte_range, Check::Failed(_)), "{f}");
    }
}

#[test]
fn digest_failure_in_each_range() {
    for f in ["flip-range1.pdf", "flip-range2.pdf"] {
        let s = first(&read(f));
        assert!(matches!(s.indication, Indication::TotalFailed(_)), "{f}");
        assert_eq!(sub(&s), Some(SubIndication::HashFailure), "{f}");
    }
}

#[test]
fn signature_value_failure() {
    // B-B: the CMS ends with the ECDSA signature value; flip a digit near its end.
    let s = first(&flip_contents_from_end(&read("b-b.pdf"), 3));
    assert_eq!(sub(&s), Some(SubIndication::SigCryptoFailure));
    assert_eq!(s.checks.digest, Check::Passed);
}

#[test]
fn signature_timestamp_failure() {
    // B-T: the CMS ends with the timestamp token, which ends with the TSA's signature.
    let s = first(&flip_contents_from_end(&read("b-t.pdf"), 3));
    assert_eq!(sub(&s), Some(SubIndication::SigConstraintsFailure));
    assert!(matches!(s.checks.timestamp, Check::Failed(_)));
    assert_eq!(s.checks.signature, Check::Passed);
    assert!(s.timestamp.is_none());
}

#[test]
fn document_timestamp_failure() {
    let mut r = check(&flip_contents_from_end(&read("b-lta.pdf"), 3));
    let ts = r.signatures.pop().unwrap();
    assert_eq!(ts.kind, SignatureKind::DocumentTimestamp);
    assert!(matches!(ts.indication, Indication::TotalFailed(_)));
    assert_eq!(sub(&ts), Some(SubIndication::SigCryptoFailure));
}

#[test]
fn chain_failures() {
    assert_eq!(
        sub(&first(&read("untrusted.pdf"))),
        Some(SubIndication::NoCertificateChainFound)
    );
    // Same root name, other key: only the certificate signature check refuses it.
    assert_eq!(
        sub(&first(&read("impostor.pdf"))),
        Some(SubIndication::NoCertificateChainFound)
    );
    assert_eq!(
        sub(&first(&read("expired.pdf"))),
        Some(SubIndication::OutOfBoundsNoPoe)
    );
    // An empty trust store: integrity still checked, no chain.
    let s = verify(
        &read("b-lt.pdf"),
        &TrustStore::new(),
        &VerifyOptions::at(AT),
    );
    let s = &s.signatures[0];
    assert_eq!(sub(s), Some(SubIndication::NoCertificateChainFound));
    assert_eq!(s.checks.digest, Check::Passed);
    assert_eq!(s.checks.signature, Check::Passed);
}

#[test]
fn revocation_failures() {
    assert_eq!(
        sub(&first(&read("revoked.pdf"))),
        Some(SubIndication::RevokedNoPoe)
    );
    // Without DSS data the same signer is TRY_LATER; supplied answers do not invent any.
    assert_eq!(sub(&first(&read("b-t.pdf"))), Some(SubIndication::TryLater));
}

fn classes(file: &str) -> Vec<ModificationClass> {
    let s = first(&read(file));
    s.modifications_after
        .iter()
        .flat_map(|r| r.classes.iter().copied())
        .collect()
}

#[test]
fn permitted_revision_classes() {
    use ModificationClass::*;
    assert!(classes("b-lt.pdf").contains(&DssUpdate));
    assert!(classes("b-lta.pdf").contains(&DocumentTimestamp));
    assert!(classes("fill-under-p2.pdf").contains(&FormFill));
    assert!(classes("annot-under-p3.pdf").contains(&Annotation));
    assert!(classes("two-approvals.pdf").contains(&Signature));
    for f in [
        "b-lt.pdf",
        "b-lta.pdf",
        "fill-under-p2.pdf",
        "annot-under-p3.pdf",
        "two-approvals.pdf",
        "certified-p1.pdf",
    ] {
        assert!(
            !classes(f).iter().any(|c| matches!(c, Disallowed(_))),
            "{f}: {:?}",
            classes(f)
        );
    }
}

#[test]
fn disallowed_revision_classes() {
    let deny = |f: &str| -> Vec<Disallowed> {
        classes(f)
            .into_iter()
            .filter_map(|c| match c {
                ModificationClass::Disallowed(d) => Some(d),
                _ => None,
            })
            .collect()
    };
    assert!(deny("fill-under-p1.pdf").contains(&Disallowed::NotPermitted(1)));
    assert!(deny("annot-under-p2.pdf").contains(&Disallowed::NotPermitted(2)));
    assert!(deny("isa-content.pdf").contains(&Disallowed::ObjectChanged(5)));
    assert!(deny("shadow-hide.pdf").contains(&Disallowed::ObjectChanged(7)));
    assert!(deny("shadow-hide-xref.pdf").contains(&Disallowed::ObjectChanged(7)));
    assert!(deny("shadow-replace.pdf").contains(&Disallowed::ObjectChanged(4)));
    assert!(deny("shadow-hide-and-replace.pdf").contains(&Disallowed::CatalogChanged));
    assert!(deny("shadow-hide-mediabox.pdf").contains(&Disallowed::PageChanged(3)));
    for f in [
        "fill-under-p1.pdf",
        "annot-under-p2.pdf",
        "isa-content.pdf",
        "shadow-hide.pdf",
        "shadow-hide-xref.pdf",
        "shadow-replace.pdf",
        "shadow-hide-and-replace.pdf",
        "shadow-hide-mediabox.pdf",
    ] {
        let s = first(&read(f));
        assert_eq!(sub(&s), Some(SubIndication::DisallowedModification), "{f}");
        assert_eq!(
            s.checks.signature,
            Check::Passed,
            "{f}: integrity is intact"
        );
    }
}

/// The code of a failed check, `None` when it did not fail.
fn failed(c: Check) -> Option<&'static str> {
    match c {
        Check::Failed(r) => Some(r.code),
        Check::NotRun | Check::Passed => None,
    }
}

#[test]
fn signature_wrapping_is_caught_by_the_check_it_targets() {
    // VER-03 (Phase 1 exit item 4): each fixture keeps the signed bytes and a valid CMS
    // somewhere, so a verifier that only hashes the ByteRange would pass it.
    let deny = |f: &str| -> Vec<Disallowed> {
        classes(f)
            .into_iter()
            .filter_map(|c| match c {
                ModificationClass::Disallowed(d) => Some(d),
                _ => None,
            })
            .collect()
    };
    // Second range moved to the end: the gap is more than /Contents (SEC-S02).
    // A duplicated revision without /Prev: the signed bytes end no revision the reader knows.
    for f in ["wrap-moved-range.pdf", "wrap-duplicate-revision.pdf"] {
        let s = first(&read(f));
        assert_eq!(sub(&s), Some(SubIndication::FormatFailure), "{f}");
        assert_eq!(failed(s.checks.byte_range), Some("CS-VER-0001"), "{f}");
        assert_eq!(s.checks.digest, Check::NotRun, "{f}");
    }
    // A moved signature dictionary: integrity holds, the later revision does not.
    for f in ["wrap-moved-dict.pdf", "wrap-moved-dict-only.pdf"] {
        let s = first(&read(f));
        assert_eq!(sub(&s), Some(SubIndication::DisallowedModification), "{f}");
        assert_eq!(s.checks.signature, Check::Passed, "{f}");
        assert_eq!(failed(s.checks.modifications), Some("CS-VER-0007"), "{f}");
    }
    let sig_dict = first(&read("wrap-moved-dict-only.pdf")).value.unwrap();
    assert_eq!(
        deny("wrap-moved-dict-only.pdf"),
        vec![Disallowed::SignatureChanged(sig_dict)]
    );
    assert!(deny("wrap-moved-dict.pdf").contains(&Disallowed::ObjectChanged(5)));
    // An extra SignerInfo, or eContent present: the CMS is refused before any digest
    // it carries is believed.
    for f in ["wrap-cms-two-signers.pdf", "wrap-cms-econtent.pdf"] {
        let s = first(&read(f));
        assert_eq!(sub(&s), Some(SubIndication::FormatFailure), "{f}");
        assert_eq!(failed(s.checks.signature), Some("CS-VER-0003"), "{f}");
    }
}

#[test]
fn unsigned_trailing_revision_leaves_document_uncovered() {
    let r = check(&read("isa-content.pdf"));
    assert!(!r.covered_by_last_signature);
    assert!(!r.all_passed());
    // pyHanko appends a DSS update after the document timestamp; B-B is a single revision.
    assert!(check(&read("b-b.pdf")).covered_by_last_signature);
}

#[test]
fn proof_of_existence_from_a_later_document_timestamp() {
    // In B-LTA the signature is judged at its own timestamp, the earlier proof.
    let r = check(&read("b-lta.pdf"));
    assert_eq!(r.signatures[0].time_source, TimeSource::SignatureTimestamp);
    assert_eq!(r.signatures[1].kind, SignatureKind::DocumentTimestamp);
}

#[test]
fn hostile_inputs_do_not_panic() {
    let base = read("b-lta.pdf");
    let mut seed: u64 = 0x1234_5678;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for _ in 0..300 {
        let mut b = base.clone();
        for _ in 0..1 + next() % 4 {
            let i = (next() as usize) % b.len();
            b[i] = next() as u8;
        }
        if next() % 5 == 0 {
            b.truncate((next() as usize) % b.len());
        }
        let _ = check(&b);
    }
    let _ = check(b"");
    let _ = check(b"%PDF-1.7\n");
}
