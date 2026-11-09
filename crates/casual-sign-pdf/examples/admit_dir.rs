//! Admit every PDF in a folder, in both modes, and print one TSV line per file, then a
//! summary. The evidence for Phase 1's first exit item (docs/06): every corpus PDF is
//! admitted or refused with a coded reason, with no panic or hang.
//!
//!     cargo run --release -p casual-sign-pdf --example admit_dir -- fixtures/corpus/files
#![allow(
    // A command-line tool over files we fetched, not the product's input path.
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use casual_sign_pdf::{Limits, admit, admit_strict};
use std::collections::BTreeMap;
use std::time::Instant;

fn main() {
    let dir = std::env::args().nth(1).expect("usage: admit_dir <folder>");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .expect("readable folder")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("pdf")))
        .collect();
    files.sort();
    let limits = Limits::default();
    let never = || false;
    let mut outcomes: BTreeMap<String, u32> = BTreeMap::new();
    let mut codes: BTreeMap<&'static str, u32> = BTreeMap::new();
    let mut slowest = (0u128, String::new());
    println!("file\tdefault\tstrict\tpages\trepaired\tfindings\tms");
    for path in &files {
        let bytes = std::fs::read(path).unwrap();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let t = Instant::now();
        let (default, pages, repaired, findings) = match admit(&bytes, &limits, &never) {
            Ok(a) => {
                for f in &a.report.findings {
                    *codes.entry(f.code).or_default() += 1;
                }
                ("ok".to_string(), a.report.page_count, a.report.repaired, a.report.findings.len())
            }
            Err(e) => (e.code().to_string(), 0, false, 0),
        };
        let strict = match admit_strict(&bytes, &limits, &never) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.code().to_string(),
        };
        let ms = t.elapsed().as_millis();
        if ms > slowest.0 {
            slowest = (ms, name.clone());
        }
        *outcomes.entry(format!("default {default}")).or_default() += 1;
        *outcomes.entry(format!("strict {strict}")).or_default() += 1;
        println!("{name}\t{default}\t{strict}\t{pages}\t{repaired}\t{findings}\t{ms}");
    }
    eprintln!("files: {}", files.len());
    for (k, v) in &outcomes {
        eprintln!("  {k}: {v}");
    }
    eprintln!("findings by code:");
    for (k, v) in &codes {
        eprintln!("  {k}: {v}");
    }
    eprintln!("slowest: {} ms ({})", slowest.0, slowest.1);
}
