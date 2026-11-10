//! Print one TSV line per signature for every PDF given (files or directories).
//!
//!     cargo run -p casual-sign-verify --example verify_dir -- [--root ROOT.der] [--at UNIX_SECS] PATH...
//!
//! Used by `fixtures/signed/gen.py --check` and for corpus runs. With no `--root` the
//! trust store is empty. Columns: file, index, kind, indication, sub-indication, code,
//! covers whole file, modification classes after the signature.

use std::path::{Path, PathBuf};
use std::time::Duration;

use casual_sign_verify::{Indication, TrustStore, VerifyOptions, verify};

fn files(p: &Path, out: &mut Vec<PathBuf>) {
    if p.is_dir() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(p)
            .map(|d| d.filter_map(|e| e.ok().map(|e| e.path())).collect())
            .unwrap_or_default();
        entries.sort();
        for e in entries {
            files(&e, out);
        }
    } else if p.extension().is_some_and(|e| e.eq_ignore_ascii_case("pdf")) {
        out.push(p.to_path_buf());
    }
}

fn main() {
    let mut trust = TrustStore::new();
    let mut at = Duration::from_secs(1_796_083_200); // 2026-12-01T00:00:00Z
    let mut paths = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--root" => {
                let p = args.next().unwrap_or_default();
                let der = std::fs::read(&p).unwrap_or_default();
                if trust.add_anchor(&der).is_err() {
                    eprintln!("verify_dir: {p}: not a DER certificate");
                    std::process::exit(2);
                }
            }
            "--at" => {
                let s = args.next().unwrap_or_default();
                at = Duration::from_secs(s.parse().unwrap_or(0));
            }
            p => files(Path::new(p), &mut paths),
        }
    }
    let options = VerifyOptions::at(at);
    println!("file\tindex\tkind\tindication\tsubindication\tcode\twhole\tmodifications");
    for p in paths {
        let name = p.display().to_string();
        let Ok(bytes) = std::fs::read(&p) else {
            println!("{name}\t-\t-\tUNREADABLE\t-\t-\t-\t-");
            continue;
        };
        let report = verify(&bytes, &trust, &options);
        if let Some(e) = report.error {
            println!("{name}\t-\t-\tERROR\t-\t{}\t-\t-", e.code);
            continue;
        }
        if report.signatures.is_empty() {
            println!("{name}\t-\t-\tNO_SIGNATURE\t-\t-\t-\t-");
        }
        for (i, s) in report.signatures.iter().enumerate() {
            let (sub, code) = match s.indication {
                Indication::TotalPassed => ("-", "-"),
                Indication::TotalFailed(r) | Indication::Indeterminate(r) => (r.sub.name(), r.code),
            };
            let mods: Vec<String> = s
                .modifications_after
                .iter()
                .map(|m| format!("r{}:{:?}", m.revision, m.classes))
                .collect();
            println!(
                "{name}\t{i}\t{:?}\t{}\t{sub}\t{code}\t{}\t{}",
                s.kind,
                s.indication.name(),
                s.covers_whole_document,
                if mods.is_empty() {
                    "-".to_string()
                } else {
                    mods.join(" ")
                }
            );
        }
    }
}
