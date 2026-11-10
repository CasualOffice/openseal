//! The Phase 1 gate run, our side (`P1-GATE-01`, docs/06 Phase 1 exit item 2).
//!
//! ```sh
//! cargo run --release -p casual-sign-sdk --example pipeline_corpus -- \
//!     <corpus files dir> fixtures/corpus/manifest.tsv <out dir> [--print-to-new]
//!     [--level B-T|B-LT] [file ...]
//! ```
//!
//! `--print-to-new` prints signed input certified at DocMDP P1 to a new document
//! (`NORM-02`) and runs it as unsigned input (class `printed`) instead of refusing to
//! keep it; `--level B-LT` seals at B-LT (a DSS revision after the seal, `NORM-03`).
//! Both are off by default: the gate run is B-T with the exclusion rule.
//!
//! For every file of the manifest (or those named), through the facade: admit with the
//! corpus's published passwords; normalize (signed input is kept as it is); convert the
//! AcroForm and fill every field with a value of its type, or place one text field by
//! geometry; flatten; append the certificate of completion with a small audit chain;
//! seal at PAdES B-T with the throwaway test PKI and an in-process TSA; verify with our
//! verifier offline and with the PKI's CRLs supplied. Signed input is sealed by
//! appending a second signature (docs/30 §2). The prefix invariant is checked after
//! every step. See `tests/support/mod.rs`.
//!
//! Writes to the out dir: each sealed file, `manifest.tsv` and `trust-root.pem` in
//! `fixtures/sealed`'s format (so `tools/verify-sealed.py`'s checks run over them;
//! `tools/pipeline-corpus.py` drives both), and `ours.tsv` with one row per file. A
//! panic is caught and recorded: there must be none.

// A tool, not product code: a failure is reported by name and the run continues.
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
#[path = "../tests/support/mod.rs"]
mod support;

use std::fmt::Write as _;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::time::Instant;

use casual_sign_sdk::{Engine, FontSet, Limits, Profile, VerificationReport};

fn verdict(r: Option<&VerificationReport>) -> String {
    let Some(r) = r else { return "-".into() };
    if let Some(e) = r.error {
        return format!("ERROR:{}", e.code);
    }
    r.signatures
        .iter()
        .map(|s| match s.indication.reason() {
            None => s.indication.name().to_owned(),
            Some(why) => format!("{}:{}", s.indication.name(), why.sub.name()),
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn main() {
    let mut opts = support::Options::default();
    let mut args: Vec<String> = Vec::new();
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--print-to-new" => opts.print_to_new = true,
            "--level" => {
                opts.profile = match it.next().as_deref() {
                    Some("B-T") => Profile::BaselineT,
                    Some("B-LT") => Profile::BaselineLt,
                    other => panic!("--level B-T or B-LT, not {other:?}"),
                }
            }
            _ => args.push(a),
        }
    }
    let level = if opts.profile == Profile::BaselineLt {
        "B-LT"
    } else {
        "B-T"
    };
    let (files, manifest, out) = (
        PathBuf::from(&args[0]),
        PathBuf::from(&args[1]),
        PathBuf::from(&args[2]),
    );
    let only: Vec<&String> = args[3..].iter().collect();
    std::fs::create_dir_all(&out).unwrap();
    let engine = Engine::new(Limits::default(), FontSet::bundled());
    let text = std::fs::read_to_string(&manifest).unwrap();
    let names: Vec<String> = text
        .lines()
        .skip(1)
        .filter_map(|l| l.split('\t').next().map(str::to_owned))
        .filter(|n| only.is_empty() || only.contains(&n))
        .collect();
    std::panic::set_hook(Box::new(|_| {}));
    let mut rows = String::from(
        "file\tclass\tsteps\tfields\tfilled\tours_offline\tours\tprefix\tms\tfailure\n",
    );
    let mut sealed_manifest = String::from("file\texpect\twhy\tlevel\tclass\n");
    let (mut passed, mut failed, mut refused, mut panics) = (0, 0, 0, 0);
    for name in &names {
        let Ok(bytes) = std::fs::read(files.join(name)) else {
            let _ = writeln!(rows, "{name}\tmissing\t-\t0\t0\t-\t-\t-\t0\tnot fetched");
            continue;
        };
        let start = Instant::now();
        let r = catch_unwind(AssertUnwindSafe(|| {
            support::run_with(&engine, name, &bytes, opts)
        }));
        let ms = start.elapsed().as_millis();
        let Ok(r) = r else {
            panics += 1;
            let _ = writeln!(rows, "{name}\tPANIC\t-\t0\t0\t-\t-\t-\t{ms}\tpanic");
            println!("{name}\tPANIC");
            continue;
        };
        let class = match r.class {
            Some(c) => c.name(),
            None => "refused",
        };
        if r.class.is_none() {
            refused += 1;
        } else if r.failure.is_none() {
            passed += 1;
        } else {
            failed += 1;
        }
        if let Some(b) = &r.sealed {
            std::fs::write(out.join(name), b).unwrap();
            let _ = writeln!(
                sealed_manifest,
                "{name}\tintact\tP1-GATE-01 {class}\t{level}\t{class}"
            );
        }
        let line = format!(
            "{name}\t{class}\t{}\t{}\t{}\t{}\t{}\t{}\t{ms}\t{}",
            r.steps.join(","),
            r.fields.0,
            r.fields.1,
            verdict(r.offline.as_ref()),
            verdict(r.online.as_ref()),
            if r.prefix { "ok" } else { "VIOLATED" },
            r.failure.as_deref().unwrap_or("-"),
        );
        println!("{line}");
        rows.push_str(&line);
        rows.push('\n');
    }
    std::fs::write(out.join("ours.tsv"), rows).unwrap();
    std::fs::write(out.join("manifest.tsv"), sealed_manifest).unwrap();
    std::fs::write(out.join("trust-root.pem"), common::root_pem()).unwrap();
    println!(
        "pipeline_corpus: {} files: {passed} passed (ours), {failed} failed, {refused} refused at admission, {panics} panics",
        names.len()
    );
}
