//! ASVS-08 (ASVS 1.7.1): the worker binary's own failures are JSON lines on standard
//! error, and a malformed pseudonym key stops it (`CS-LOG-0001`), as the server and
//! the console.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::process::Command;

use serde_json::Value;

const EXE: &str = env!("CARGO_BIN_EXE_casual-sign-worker");

/// Run the binary with only `env` set (and `args`); whether it succeeded, and its
/// standard error as JSON lines (a line that is not one fails the test).
fn run(args: &[&str], env: &[(&str, &str)]) -> (bool, Vec<Value>) {
    let out = Command::new(EXE)
        .args(args)
        .env_clear()
        .envs(env.iter().copied())
        .output()
        .unwrap();
    let err = String::from_utf8(out.stderr).unwrap();
    let lines = err
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let v: Value = serde_json::from_str(l)
                .unwrap_or_else(|_| panic!("not a JSON line on standard error: {l}"));
            assert_eq!(v["service"], "worker", "{l}");
            assert!(v["ts"].is_string() && v["level"].is_string(), "{l}");
            v
        })
        .collect();
    (out.status.success(), lines)
}

fn event<'a>(lines: &'a [Value], name: &str) -> &'a Value {
    lines
        .iter()
        .find(|l| l["event"] == name)
        .unwrap_or_else(|| panic!("no {name} line: {lines:?}"))
}

#[test]
fn a_startup_failure_is_a_json_line_with_its_code() {
    let (ok, lines) = run(&[], &[]);
    assert!(!ok);
    let f = event(&lines, "start_failed");
    assert_eq!(f["level"], "ERROR");
    assert!(f["code"].as_str().unwrap().starts_with("CS-"), "{f}");
}

#[test]
fn a_malformed_pseudonym_key_stops_the_worker() {
    let (ok, lines) = run(&[], &[("OPENSEAL_LOG_PSEUDONYM_KEY", "not-a-key")]);
    assert!(!ok);
    assert_eq!(event(&lines, "start_failed")["code"], "CS-LOG-0001");
}
