//! The server binary refuses an `http` public URL outside development before it touches
//! the database (`ASVS-19`, `HRD-06`).

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(clippy::unwrap_used, clippy::panic)]

use std::process::Command;

const SERVER: &str = env!("CARGO_BIN_EXE_casual-sign-server");

fn start(public_url: &str, development: bool) -> String {
    let mut c = Command::new(SERVER);
    c.env_clear()
        .env("OPENSEAL_PUBLIC_URL", public_url)
        // Not a URL: a run that gets past the public URL check stops here at once.
        .env("OPENSEAL_DATABASE_URL", "not a database url");
    if development {
        c.env("OPENSEAL_DEV_INSECURE_KEY", "1");
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
