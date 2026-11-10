//! Rung 1 over the committed `fixtures/sealed` (pyHanko and EU DSS are rungs 2 and 3,
//! `tools/verify-sealed.py fixtures/sealed --dss openseal-eu-dss`): every signature of
//! every file gives the verdict the manifest's `ours` column names, at 2026-12-01 with
//! the committed trust root, and the last signature or a DSS ends the file.
// Test code: a panic is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::path::PathBuf;
use std::time::Duration;

use casual_sign_verify::{Indication, TrustStore, VerifyOptions, verify};

/// 2026-12-01T00:00:00Z.
const VALIDATION_TIME: Duration = Duration::from_secs(1_796_083_200);

#[test]
fn committed_seals_match_their_manifest() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/sealed");
    let mut trust = TrustStore::new();
    trust
        .add_anchor(&std::fs::read(dir.join("trust-root.der")).unwrap())
        .unwrap();
    let manifest = std::fs::read_to_string(dir.join("manifest.tsv")).unwrap();
    let mut lines = manifest.lines();
    let head: Vec<&str> = lines.next().unwrap().split('\t').collect();
    assert_eq!(head, ["file", "expect", "why", "level", "ours"]);
    let mut files = 0;
    let mut signatures = 0;
    for line in lines.filter(|l| !l.trim().is_empty()) {
        let cols: Vec<&str> = line.split('\t').collect();
        let (file, level, want) = (cols[0], cols[3], cols[4]);
        let bytes = std::fs::read(dir.join(file)).unwrap();
        let report = verify(&bytes, &trust, &VerifyOptions::at(VALIDATION_TIME));
        assert!(report.error.is_none(), "{file}");
        assert!(!report.signatures.is_empty(), "{file}");
        for (i, s) in report.signatures.iter().enumerate() {
            let got = match s.indication {
                Indication::TotalPassed => "TOTAL_PASSED".to_string(),
                Indication::TotalFailed(r) | Indication::Indeterminate(r) => {
                    format!("{}:{}", s.indication.name(), r.sub.name())
                }
            };
            assert_eq!(got, want, "{file} signature {i}");
            signatures += 1;
        }
        // B-LT ends with an unsigned DSS revision; every other level ends signed.
        assert_eq!(report.covered_by_last_signature, level != "B-LT", "{file}");
        files += 1;
    }
    assert!(files >= 18, "{files} files");
    assert!(signatures >= 27, "{signatures} signatures");
}
