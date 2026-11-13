//! ASVS-08: a malformed pseudonym key stops the model service (`CS-LOG-0001`), as the
//! server and the console, with a JSON line saying so.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::process::Command;

use serde_json::Value;

const EXE: &str = env!("CARGO_BIN_EXE_casual-sign-modeld");

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
            assert_eq!(v["service"], "modeld", "{l}");
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
fn a_malformed_pseudonym_key_stops_modeld() {
    let (ok, lines) = run(&[], &[("OPENSEAL_LOG_PSEUDONYM_KEY", "not-a-key")]);
    assert!(!ok);
    assert_eq!(event(&lines, "start_failed")["code"], "CS-LOG-0001");
}
