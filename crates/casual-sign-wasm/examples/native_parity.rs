//! The native half of the WASM parity check (`WASM-01`, Phase 1 exit item 6): runs each
//! job of a job file through the same [`casual_sign_wasm::api`] functions the WASM module
//! exports, and prints one line per job: `{"id", "len", "sha256"}` of the canonical JSON.
//! `tools/wasm-parity.mjs` writes the job file, runs this, runs the module in Node, and
//! compares. With `--dump ID` it prints that job's whole output instead.
//!
//!     cargo run --release -p casual-sign-wasm --features parity --example native_parity -- JOBS.json [--dump ID]
//!
//! A job is `{"id", "fn", "file"?, "trust"?, "anchors"?, "fields"?, "values"?}`; `fn` is
//! `admit`, `extract_text`, `place_anchor`, `verify`, `evaluate_envelope` or
//! `parity_cases`, and the string members are passed through unchanged.

// A developer tool over its own job file: it may exit on a bad one (CLAUDE.md: tests and
// tools may unwrap).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::io::Write as _;

use serde_json::Value;
use sha2::{Digest, Sha256};

fn arg<'a>(job: &'a Value, key: &str) -> &'a str {
    job.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn run(job: &Value) -> String {
    let read = || std::fs::read(arg(job, "file")).expect("job file readable");
    match arg(job, "fn") {
        "admit" => casual_sign_wasm::api::admit(&read()),
        "extract_text" => casual_sign_wasm::api::extract_text(&read()),
        "place_anchor" => casual_sign_wasm::api::place_anchor(&read(), arg(job, "anchors")),
        "verify" => casual_sign_wasm::api::verify(&read(), arg(job, "trust")),
        "evaluate_envelope" => {
            casual_sign_wasm::api::evaluate(arg(job, "fields"), arg(job, "values"))
        }
        "parity_cases" => casual_sign_wasm::parity_cases(),
        other => panic!("native_parity: unknown fn {other:?}"),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let jobs: Vec<Value> =
        serde_json::from_slice(&std::fs::read(&args[0]).expect("job file")).expect("job JSON");
    let dump = args
        .iter()
        .position(|a| a == "--dump")
        .map(|i| args[i + 1].clone());
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for job in &jobs {
        let id = arg(job, "id");
        if dump.as_deref().is_some_and(|d| d != id) {
            continue;
        }
        let answer = run(job);
        if dump.is_some() {
            out.write_all(answer.as_bytes()).unwrap();
            return;
        }
        let digest = Sha256::digest(answer.as_bytes());
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        let line = serde_json::json!({ "id": id, "len": answer.len(), "sha256": hex });
        writeln!(out, "{line}").unwrap();
    }
}
