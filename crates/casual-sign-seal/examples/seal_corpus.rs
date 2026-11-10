//! Seal real documents from the corpus at PAdES B-LT (`T-1G`).
//!
//! ```sh
//! cargo run -p casual-sign-seal --example seal_corpus -- \
//!     <corpus files dir> fixtures/corpus/manifest.tsv <out dir> [count]
//! ```
//!
//! Takes `count` (default 30) files spread evenly over those the manifest does not mark
//! `signed`, `certified`, `encrypted` or `usage-rights`. Each is admitted, normalized as on
//! delivery, given a text field value flattened onto page 1 with `casual-sign-flatten`,
//! then sealed at B-LT with the throwaway test PKI (`tests/common`) and verified with
//! our verifier; the delivered (normalized) bytes must prefix the output. Outputs go to
//! the out dir with a `manifest.tsv` and `trust-root.pem` in `fixtures/sealed`'s format,
//! so `tools/verify-sealed.py <out dir>` runs pyHanko over them. A line per file and a
//! summary go to stdout; a panic is caught and counted: there must be none.

// A tool, not product code: a failure is reported by name and the run continues.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    missing_docs
)]

#[path = "../tests/common/mod.rs"]
mod common;

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;

use casual_sign_flatten::{FlattenInput, FlattenOptions, FontSet, flatten};
use casual_sign_model::{Field, FieldType, FieldValue, Id, Placement, Points, Text};
use casual_sign_pdf::{Limits, NormalizeOptions, OutputXref, admit, normalize};
use casual_sign_seal::{Profile, SealRequest, seal};
use casual_sign_verify::{VerifyOptions, verify};
use common::*;
use rust_decimal::Decimal;

fn never() -> bool {
    false
}

fn pts(v: i64) -> Points {
    Points::new(Decimal::from(v)).unwrap()
}

/// Flatten one text field onto page 1 (top-left, 300x20 points).
fn flattened(normalized: &[u8], fonts: &FontSet) -> Result<Vec<u8>, String> {
    let mut a = admit(normalized, &Limits::default(), &never).map_err(|e| e.code().to_string())?;
    let field = Field::new(
        Id::new("note").unwrap(),
        Id::new("doc").unwrap(),
        FieldType::Text,
        Placement::new(1, pts(36), pts(36), pts(300), pts(20)).unwrap(),
    );
    let fields = vec![field];
    let mut values = BTreeMap::new();
    values.insert(
        Id::new("note").unwrap(),
        FieldValue::Text(Text::new("Sealed by the OpenSeal corpus run").unwrap()),
    );
    let captures = BTreeMap::new();
    let input = FlattenInput {
        fields: &fields,
        values: &values,
        captures: &captures,
        envelope_id: None,
        acroform: None,
    };
    flatten(&mut a, &input, fonts, &FlattenOptions::default(), &never)
        .map(|f| f.bytes)
        .map_err(|e| e.code().to_string())
}

enum Outcome {
    Sealed(Vec<u8>),
    Skipped(String),
    Failed(String),
}

fn run(bytes: &[u8], fonts: &FontSet) -> (Outcome, bool) {
    let Ok(mut a) = admit(bytes, &Limits::default(), &never) else {
        return (Outcome::Skipped("not admitted".into()), false);
    };
    let normalized = match normalize(
        &mut a,
        &NormalizeOptions::with_xref(OutputXref::Stream),
        &never,
    ) {
        Ok(n) => n.bytes,
        Err(e) => return (Outcome::Skipped(format!("normalize {}", e.code())), false),
    };
    let (delivered, flat) = match flattened(&normalized, fonts) {
        Ok(f) => (f, true),
        Err(code) => {
            eprintln!("  flatten skipped: {code}");
            (normalized.clone(), false)
        }
    };
    let mut r = SealRequest::new(Profile::BaselineLt, "OpenSealCorpus", SIGNING_TIME);
    r.reason = Some("Corpus run".into());
    r.trust = trust();
    let tsa = TestTsa::new(SIGNING_TIME);
    match seal(&delivered, &r, &p256(), &tsa, &TestRevocation::default()) {
        Ok(s) => {
            if !s.bytes.starts_with(&delivered) || !s.bytes.starts_with(&normalized) {
                return (Outcome::Failed("prefix".into()), flat);
            }
            let report = verify(&s.bytes, &trust(), &VerifyOptions::at(VALIDATION_TIME));
            if !report
                .signatures
                .iter()
                .all(|s| s.indication == casual_sign_verify::Indication::TotalPassed)
            {
                return (Outcome::Failed("ours".into()), flat);
            }
            (Outcome::Sealed(s.bytes), flat)
        }
        Err(e) => (Outcome::Failed(e.to_string()), flat),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (files, manifest, out) = (
        PathBuf::from(&args[0]),
        PathBuf::from(&args[1]),
        PathBuf::from(&args[2]),
    );
    let count: usize = args.get(3).map_or(30, |c| c.parse().unwrap());
    std::fs::create_dir_all(&out).unwrap();
    let fonts = FontSet::bundled();
    let text = std::fs::read_to_string(&manifest).unwrap();
    let mut picked = Vec::new();
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split('\t').collect();
        let features = cols.get(9).copied().unwrap_or("-");
        if ["signed", "certified", "encrypted", "usage-rights"]
            .iter()
            .any(|f| features.split(',').any(|x| x == *f))
        {
            continue;
        }
        picked.push(cols[0].to_string());
    }
    // Evenly spaced over the manifest, so every producer and feature mix is sampled.
    let step = (picked.len() / count.max(1)).max(1);
    let picked: Vec<String> = picked.into_iter().step_by(step).take(count).collect();
    let (mut sealed, mut skipped, mut failed, mut panics, mut flat) = (0, 0, 0, 0, 0);
    let mut rows = String::from("file\texpect\twhy\tlevel\tours\n");
    for name in &picked {
        let bytes = std::fs::read(files.join(name)).unwrap();
        match catch_unwind(AssertUnwindSafe(|| run(&bytes, &fonts))) {
            Ok((outcome, f)) => {
                flat += usize::from(f);
                match outcome {
                    Outcome::Sealed(b) => {
                        sealed += 1;
                        std::fs::write(out.join(name), &b).unwrap();
                        rows.push_str(&format!(
                            "{name}\tintact\tcorpus, flattened={f}\tB-LT\tTOTAL_PASSED\n"
                        ));
                        println!("{name}\tsealed\tflattened={f}\t{} bytes", b.len());
                    }
                    Outcome::Skipped(why) => {
                        skipped += 1;
                        println!("{name}\tskipped\t{why}");
                    }
                    Outcome::Failed(why) => {
                        failed += 1;
                        println!("{name}\tFAILED\t{why}");
                    }
                }
            }
            Err(_) => {
                panics += 1;
                println!("{name}\tPANIC");
            }
        }
    }
    std::fs::write(out.join("manifest.tsv"), rows).unwrap();
    std::fs::write(out.join("trust-root.pem"), root_pem()).unwrap();
    println!(
        "seal_corpus: {} files: {sealed} sealed (B-LT, ours TOTAL_PASSED), {flat} with a flattened field, {skipped} skipped, {failed} failed, {panics} panics",
        picked.len()
    );
}
