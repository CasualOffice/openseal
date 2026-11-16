//! The worker's security configuration is hashed at start and checked against the
//! operator's manifest before anything else is read (ASVS 14.1.5, `ASVS-24`, `HRD-06`):
//! every setting that decides where tokens, mail and keys go is in it.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(clippy::unwrap_used, clippy::panic)]

use std::process::Command;

const WORKER: &str = env!("CARGO_BIN_EXE_casual-sign-worker");

/// **HRD-06 review:** the base URL signer invitation links (bearer tokens) point at, and
/// the SMTP port and user, and the document bucket, are in the manifest, so a changed value on restart is refused
/// rather than sending tokens or mail somewhere else unnoticed.
#[test]
fn the_manifest_covers_the_link_host_and_the_mail_relay() {
    let names = [
        "OPENSEAL_BASE_URL",
        "OPENSEAL_SMTP_HOST",
        "OPENSEAL_SMTP_PORT",
        "OPENSEAL_SMTP_USER",
        "OPENSEAL_SMTP_SECURITY",
        "OPENSEAL_KEYD_ALIAS",
        "OPENSEAL_S3_BUCKET",
    ];
    let mut c = Command::new(WORKER);
    c.arg("config-manifest").env_clear();
    for n in names {
        c.env(n, "x");
    }
    let out = c.output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let manifest = String::from_utf8(out.stdout).unwrap();
    for n in names {
        assert!(manifest.contains(&format!("  {n}\n")), "{n}: {manifest}");
    }
}
