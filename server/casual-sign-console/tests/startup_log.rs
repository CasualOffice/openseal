//! ASVS-08 (ASVS 1.7.1): the console binary's own failures are JSON lines on standard
//! error, like everything else it writes.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::process::Command;

use serde_json::Value;

const EXE: &str = env!("CARGO_BIN_EXE_casual-sign-console");

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
            assert_eq!(v["service"], "console", "{l}");
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
fn a_startup_failure_and_a_usage_error_are_json_lines() {
    let (ok, lines) = run(&[], &[]);
    assert!(!ok);
    assert_eq!(event(&lines, "start_failed")["level"], "ERROR");
    let (ok, lines) = run(&["no-such-command"], &[]);
    assert!(!ok);
    assert!(
        event(&lines, "start_failed")["error"]
            .as_str()
            .unwrap()
            .starts_with("usage:")
    );
}
