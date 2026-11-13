//! ASVS-08 (ASVS 1.7.1): what the server binary writes before it serves is the same JSON
//! line as everything else, so a collector parsing JSON lines keeps the lines that say
//! a development key is in use or that the server did not start: a startup failure
//! (`start_failed`), the development token and second-factor keys
//! (`development_token_key`, `development_mfa_key`), and a malformed pseudonym key
//! (`CS-LOG-0001`).

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::process::Command;

use serde_json::Value;

const EXE: &str = env!("CARGO_BIN_EXE_casual-sign-server");

/// Run the server with only `env` set; its exit success and its standard error as JSON
/// lines (a line that is not one fails the test).
fn run(env: &[(&str, &str)]) -> (bool, Vec<Value>) {
    let out = Command::new(EXE)
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
            assert_eq!(v["service"], "server", "{l}");
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
fn a_startup_failure_is_a_json_line() {
    let (ok, lines) = run(&[]);
    assert!(!ok);
    let f = event(&lines, "start_failed");
    assert_eq!(f["level"], "ERROR");
    assert_eq!(f["error"], "OPENSEAL_DATABASE_URL is not set");
}

/// Past the database (which needs one): the development keys are announced as JSON
/// warnings, and a malformed pseudonym key stops the server with `CS-LOG-0001`.
#[test]
fn development_keys_and_a_malformed_pseudonym_key_are_json_lines() {
    let Ok(url) = std::env::var("OPENSEAL_TEST_DATABASE_URL") else {
        eprintln!("SKIPPED: OPENSEAL_TEST_DATABASE_URL is not set");
        return;
    };
    let blobs = std::env::temp_dir().join(format!("seclog-start-{}", std::process::id()));
    std::fs::create_dir_all(&blobs).unwrap();
    let blob_dir = blobs.to_str().unwrap();
    let base = [
        ("OPENSEAL_DATABASE_URL", url.as_str()),
        ("OPENSEAL_DEV_INSECURE_KEY", "1"),
        ("OPENSEAL_BLOB_DIR", blob_dir),
    ];

    // A GeoIP file that does not exist stops the server after both keys are drawn.
    let mut env = base.to_vec();
    env.push(("OPENSEAL_GEOIP_DB", "/nonexistent/openseal-seclog.mmdb"));
    let (ok, lines) = run(&env);
    assert!(!ok);
    for name in ["development_token_key", "development_mfa_key"] {
        let w = event(&lines, name);
        assert_eq!(w["level"], "WARN", "{w}");
        assert_eq!(w["note"], "never in production", "{w}");
    }
    assert!(
        event(&lines, "start_failed")["error"]
            .as_str()
            .unwrap()
            .starts_with("OPENSEAL_GEOIP_DB")
    );

    // A pseudonym key that is not 32 bytes as base64.
    let mut env = base.to_vec();
    env.push(("OPENSEAL_LOG_PSEUDONYM_KEY", "not-a-key"));
    let (ok, lines) = run(&env);
    assert!(!ok);
    assert_eq!(event(&lines, "start_failed")["code"], "CS-LOG-0001");
    let _ = std::fs::remove_dir_all(&blobs);
}
