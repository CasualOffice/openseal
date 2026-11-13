//! During a seal key rotation keyd serves the next key beside the current one
//! (`OPENSEAL_KEYD_NEXT_*`, `CON-10`, docs/65 §Rotation), so the worker can move to the
//! new alias at its start without a keyd restart. Development file keys stand in for
//! the HSM's.

// Test code: a panic is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use std::io::{BufRead as _, BufReader};
use std::process::{Command, Stdio};

use casual_sign_crypto::KeyProvider as _;
use casual_sign_keyd::RemoteKey;
use common::*;
use rcgen::{CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256};

const KEYD: &str = env!("CARGO_BIN_EXE_casual-sign-keyd");

/// A keyd process, killed when the test ends, failed or not.
struct Killed(std::process::Child);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A key PEM and its chain PEM (leaf named `cn`, then the seal root).
fn seal_key(pki: &Pki, cn: &str) -> (String, String) {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(DnType::CommonName, cn);
    p.is_ca = IsCa::ExplicitNoCa;
    p.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::ContentCommitment,
    ];
    let cert = p.signed_by(&key, &pki.seal_ca).unwrap();
    (
        key.serialize_pem(),
        format!("{}{}", cert.pem(), pki.seal_ca.pem()),
    )
}

#[test]
fn keyd_serves_the_next_key_beside_the_current_one() {
    let pki = Pki::new();
    let dir = scratch("keyd-two-keys");
    let (tls_cert, tls_key, _) = pki.server_identity();
    let worker = pki.client_identity("worker");
    let (old_key, old_chain) = seal_key(&pki, "seal 2026");
    let (new_key, new_chain) = seal_key(&pki, "seal 2027");
    for (name, text) in [
        ("tls.pem", tls_cert.as_str()),
        ("tls.key", tls_key.as_str()),
        ("ca.pem", &pki.tls_ca.pem()),
        ("allow", &format!("{} worker\n", worker.2)),
        ("old.key", &old_key),
        ("old.pem", &old_chain),
        ("new.key", &new_key),
        ("new.pem", &new_chain),
    ] {
        std::fs::write(dir.join(name), text).unwrap();
    }
    let mut child = Killed(
        Command::new(KEYD)
            .env_clear()
            .env("OPENSEAL_DEV_INSECURE_KEY", "1")
            .env("OPENSEAL_KEYD_LISTEN", "127.0.0.1:0")
            .env("OPENSEAL_KEYD_TLS_CERT", dir.join("tls.pem"))
            .env("OPENSEAL_KEYD_TLS_KEY", dir.join("tls.key"))
            .env("OPENSEAL_KEYD_CLIENT_CA", dir.join("ca.pem"))
            .env("OPENSEAL_KEYD_ALLOW_LIST", dir.join("allow"))
            .env("OPENSEAL_KEYD_OPLOG", dir.join("oplog"))
            .env("OPENSEAL_KEYD_ALIAS", "platform")
            .env("OPENSEAL_KEYD_FILE_KEY", dir.join("old.key"))
            .env("OPENSEAL_KEYD_CHAIN", dir.join("old.pem"))
            .env("OPENSEAL_KEYD_NEXT_ALIAS", "platform-2027")
            .env("OPENSEAL_KEYD_NEXT_FILE_KEY", dir.join("new.key"))
            .env("OPENSEAL_KEYD_NEXT_CHAIN", dir.join("new.pem"))
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut lines = BufReader::new(child.0.stderr.take().unwrap()).lines();
    let addr = loop {
        let line = lines.next().expect("keyd exited").unwrap();
        // keyd's lines are JSON (ASVS-08): `"event":"serving"` with `alias` and `listen`.
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        if v["event"] == "serving" {
            assert_eq!(v["alias"], "platform and platform-2027", "{line}");
            break v["listen"].as_str().unwrap().to_owned();
        }
    };
    let keyd = RunningKeyd {
        addr,
        oplog: dir.join("oplog"),
    };
    let subject = |alias: &str| {
        let key = RemoteKey::connect(endpoint(&pki, &keyd, Some(&worker)), alias).unwrap();
        key.certificate_chain()[0]
            .tbs_certificate()
            .subject()
            .to_string()
    };
    let (old, new) = (subject("platform"), subject("platform-2027"));
    drop(child);
    assert!(old.contains("seal 2026"), "{old}");
    assert!(new.contains("seal 2027"), "{new}");
}

#[test]
fn the_next_alias_must_differ_from_the_current_one() {
    let out = Command::new(KEYD)
        .env_clear()
        .env("OPENSEAL_KEYD_ALIAS", "platform")
        .env("OPENSEAL_KEYD_NEXT_ALIAS", "platform")
        .output()
        .unwrap();
    assert!(!out.status.success());
    // Fails on its TLS settings first unless they are given; what matters is that the
    // same alias twice can never start. Its own refusal is checked with TLS in place.
    let pki = Pki::new();
    let dir = scratch("keyd-two-keys-same");
    let (tls_cert, tls_key, _) = pki.server_identity();
    std::fs::write(dir.join("tls.pem"), tls_cert).unwrap();
    std::fs::write(dir.join("tls.key"), tls_key).unwrap();
    std::fs::write(dir.join("ca.pem"), pki.tls_ca.pem()).unwrap();
    std::fs::write(dir.join("allow"), "ab12 worker\n").unwrap();
    let out = Command::new(KEYD)
        .env_clear()
        .env("OPENSEAL_KEYD_TLS_CERT", dir.join("tls.pem"))
        .env("OPENSEAL_KEYD_TLS_KEY", dir.join("tls.key"))
        .env("OPENSEAL_KEYD_CLIENT_CA", dir.join("ca.pem"))
        .env("OPENSEAL_KEYD_ALLOW_LIST", dir.join("allow"))
        .env("OPENSEAL_KEYD_OPLOG", dir.join("oplog"))
        .env("OPENSEAL_KEYD_ALIAS", "platform")
        .env("OPENSEAL_KEYD_NEXT_ALIAS", "platform")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("OPENSEAL_KEYD_NEXT_ALIAS"), "{err}");
}
