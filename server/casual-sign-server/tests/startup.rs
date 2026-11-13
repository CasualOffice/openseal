//! The server binary refuses an `http` public URL outside development before it touches
//! the database (`ASVS-19`, `HRD-06`), and refuses to start without the key that seals
//! staff second factors outside development (`ASVS-31`).

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(clippy::unwrap_used, clippy::panic)]

use std::process::Command;

const SERVER: &str = env!("CARGO_BIN_EXE_casual-sign-server");

/// 32 bytes as base64.
const MFA_KEY: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";

fn start(public_url: &str, development: bool) -> String {
    start_with(public_url, development, Some(MFA_KEY))
}

fn start_with(public_url: &str, development: bool, mfa_key: Option<&str>) -> String {
    let mut c = Command::new(SERVER);
    c.env_clear()
        .env("OPENSEAL_PUBLIC_URL", public_url)
        // Not a URL: a run that gets past the public URL check stops here at once.
        .env("OPENSEAL_DATABASE_URL", "not a database url");
    if development {
        c.env("OPENSEAL_DEV_INSECURE_KEY", "1");
    }
    if let Some(k) = mfa_key {
        c.env("OPENSEAL_MFA_KEY", k);
    }
    let out = c.output().unwrap();
    assert!(!out.status.success());
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn a_plain_http_public_url_is_refused_outside_development() {
    let refused = "OPENSEAL_PUBLIC_URL must be https outside development";
    assert!(start("http://sign.example.com", false).contains(refused));
    for (url, development) in [
        ("https://sign.example.com", false),
        ("http://localhost:8080", false),
        ("http://sign.example.com", true),
    ] {
        let err = start(url, development);
        assert!(!err.contains(refused), "{url}: {err}");
        assert!(err.contains("CS-DB-0001"), "{url}: {err}");
    }
}

#[test]
fn no_second_factor_key_is_refused_outside_development() {
    // Administrators owe a second factor by default: without the sealing key none could
    // enrol, so the server does not start (ASVS-31).
    let refused = "OPENSEAL_MFA_KEY is not set";
    let err = start_with("https://sign.example.com", false, None);
    assert!(err.contains(refused), "{err}");
    assert!(!err.contains("CS-DB-0001"), "{err}");
    // Development draws a throwaway key; a set key is taken. Both reach the database.
    for (development, key) in [(true, None), (false, Some(MFA_KEY))] {
        let err = start_with("https://sign.example.com", development, key);
        assert!(!err.contains(refused), "{err}");
        assert!(err.contains("CS-DB-0001"), "{err}");
    }
    let err = start_with("https://sign.example.com", false, Some("short"));
    assert!(err.contains("OPENSEAL_MFA_KEY"), "{err}");
}
