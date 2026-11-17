//! `KEYD-02` (`SEC-S05`, ADR-036): a keyd configured with the seal token key signs only
//! for a request carrying the database's token for its envelope. A request without one,
//! with one for another envelope, an expired one or one minted under another key is
//! refused `CS-KEY-0015`, recorded in the operation log and logged as `key.use` refused;
//! a request with a valid token signs.
// Test code: a panic is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use casual_sign_keyd::{
    DevKeyConsent, DigestSigner, FileKey, KeydLimits, RemoteKey, SealTokenKey, digest_for, oplog,
};
use casual_sign_seclog::{SecurityLog, Service};
use common::*;
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};

const ENVELOPE: &str = "0193a000-0000-7000-8000-000000000002";
const OTHER: &str = "0193a000-0000-7000-8000-000000000003";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// **A digest for an envelope that owes no seal is refused:** without a token, with
/// another envelope's, an expired one or a forged one, keyd answers `CS-KEY-0015` and
/// records it; with the database's token for the envelope it signs.
#[test]
fn keyd_signs_only_for_an_envelope_with_its_seal_token() {
    let pki = Pki::new();
    let dir = scratch("keyd-seal-token");
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = pki.signer("KEYD-02 signer", &key);
    let file_key = FileKey::load(
        DevKeyConsent::from_env_value(Some("1")).unwrap(),
        key.serialize_pem().as_bytes(),
        vec![cert, pki.seal_root()],
        None,
    )
    .unwrap();
    let worker = pki.client_identity("worker");
    let (log, mem) = SecurityLog::memory(Service::Keyd);
    let token_key = [0x5a; 32];
    let keyd = start_keyd_full(
        &pki,
        vec![("platform", Arc::new(file_key) as Arc<dyn DigestSigner>)],
        &[&worker.2],
        &[],
        KeydLimits::default(),
        &dir,
        Some(log),
        Some(SealTokenKey::new(&token_key).unwrap()),
    );
    let db = SealTokenKey::new(&token_key).unwrap();
    let remote = RemoteKey::connect(endpoint(&pki, &keyd, Some(&worker)), "platform")
        .unwrap()
        .for_envelope(ENVELOPE)
        .unwrap();
    let d = digest_for(DigestSigner::algorithm(&remote), b"attrs");
    let refused = |k: &RemoteKey, why: &str| {
        assert_eq!(
            k.sign_digest(&d).unwrap_err().code(),
            "CS-KEY-0015",
            "{why}"
        );
    };

    refused(&remote, "no token");
    refused(
        &remote.clone().with_seal_token(db.mint(OTHER, now() + 600)),
        "another envelope's token",
    );
    refused(
        &remote.clone().with_seal_token(db.mint(ENVELOPE, now() - 1)),
        "an expired token",
    );
    refused(
        &remote.clone().with_seal_token(
            SealTokenKey::new(&[0x5b; 32])
                .unwrap()
                .mint(ENVELOPE, now() + 600),
        ),
        "a token under another key",
    );
    let valid = remote
        .clone()
        .with_seal_token(db.mint(ENVELOPE, now() + 600));
    assert!(valid.sign_digest(&d).is_ok(), "the envelope's token signs");

    let records = oplog::read_range(&keyd.oplog, 1, 64, u64::MAX).unwrap();
    let signs: Vec<(&str, &str)> = records
        .iter()
        .filter(|r| r.op == "sign")
        .map(|r| (r.envelope.as_str(), r.outcome.as_str()))
        .collect();
    assert_eq!(
        signs,
        [
            (ENVELOPE, "CS-KEY-0015"),
            (ENVELOPE, "CS-KEY-0015"),
            (ENVELOPE, "CS-KEY-0015"),
            (ENVELOPE, "CS-KEY-0015"),
            (ENVELOPE, "ok"),
        ]
    );
    // ASVS-08: each refusal is a `key.use` failure with the code and the envelope.
    let lines = mem.json();
    let uses: Vec<_> = lines
        .iter()
        .filter(|l| l["kind"] == "key.use" && l["op"] == "sign")
        .collect();
    assert_eq!(uses.len(), 5, "{lines:?}");
    for l in &uses[..4] {
        assert_eq!(l["outcome"], "failure");
        assert_eq!(l["code"], "CS-KEY-0015");
        assert_eq!(l["envelope_id"], ENVELOPE);
        assert_eq!(l["principal"], format!("caller:{}", worker.2));
    }
    assert_eq!(uses[4]["outcome"], "success");
}

/// Without the token key keyd signs as before, with or without a token (a deployment not
/// yet configured; keyd warns at start).
#[test]
fn keyd_without_the_token_key_signs_with_or_without_a_token() {
    let pki = Pki::new();
    let dir = scratch("keyd-no-seal-token");
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = pki.signer("KEYD-02 unenforced", &key);
    let file_key = FileKey::load(
        DevKeyConsent::from_env_value(Some("1")).unwrap(),
        key.serialize_pem().as_bytes(),
        vec![cert, pki.seal_root()],
        None,
    )
    .unwrap();
    let worker = pki.client_identity("worker");
    let keyd = start_keyd(
        &pki,
        vec![("platform", Arc::new(file_key) as Arc<dyn DigestSigner>)],
        &[&worker.2],
        KeydLimits::default(),
        &dir,
    );
    let remote = RemoteKey::connect(endpoint(&pki, &keyd, Some(&worker)), "platform")
        .unwrap()
        .for_envelope(ENVELOPE)
        .unwrap();
    let d = digest_for(DigestSigner::algorithm(&remote), b"attrs");
    remote.sign_digest(&d).unwrap();
    let token = SealTokenKey::new(&[1; 32])
        .unwrap()
        .mint(ENVELOPE, now() + 600);
    remote.with_seal_token(token).sign_digest(&d).unwrap();
}

/// A keyd process, killed when the test ends, failed or not.
struct Killed(std::process::Child);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The keyd binary takes the token key from `OPENSEAL_KEYD_SEAL_TOKEN_KEY_FILE` and then
/// refuses a signature without a token; without the setting it warns
/// `seal_token_not_enforced` at start.
#[test]
fn the_binary_enforces_the_token_key_from_its_file_and_warns_without_one() {
    use std::io::{BufRead as _, BufReader};
    use std::process::{Command, Stdio};

    let pki = Pki::new();
    let dir = scratch("keyd-seal-token-binary");
    let (tls_cert, tls_key, _) = pki.server_identity();
    let worker = pki.client_identity("worker");
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name
        .push(rcgen::DnType::CommonName, "KEYD-02 binary");
    p.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::ContentCommitment,
    ];
    let cert = p.signed_by(&key, &pki.seal_ca).unwrap();
    let chain = format!("{}{}", cert.pem(), pki.seal_ca.pem());
    for (name, text) in [
        ("tls.pem", tls_cert.as_str()),
        ("tls.key", tls_key.as_str()),
        ("ca.pem", &pki.tls_ca.pem()),
        ("allow", &format!("{} worker\n", worker.2)),
        ("seal.key", &key.serialize_pem()),
        ("seal.pem", &chain),
        ("token-key", &format!("{}\n", "5a".repeat(32))),
    ] {
        std::fs::write(dir.join(name), text).unwrap();
    }
    let start = |with_key: bool, oplog: &str| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_casual-sign-keyd"));
        cmd.env_clear()
            .envs(std::env::var_os("SystemRoot").map(|v| ("SystemRoot", v)))
            .env("OPENSEAL_DEV_INSECURE_KEY", "1")
            .env("OPENSEAL_KEYD_LISTEN", "127.0.0.1:0")
            .env("OPENSEAL_KEYD_TLS_CERT", dir.join("tls.pem"))
            .env("OPENSEAL_KEYD_TLS_KEY", dir.join("tls.key"))
            .env("OPENSEAL_KEYD_CLIENT_CA", dir.join("ca.pem"))
            .env("OPENSEAL_KEYD_ALLOW_LIST", dir.join("allow"))
            .env("OPENSEAL_KEYD_OPLOG", dir.join(oplog))
            .env("OPENSEAL_KEYD_FILE_KEY", dir.join("seal.key"))
            .env("OPENSEAL_KEYD_CHAIN", dir.join("seal.pem"))
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        if with_key {
            cmd.env("OPENSEAL_KEYD_SEAL_TOKEN_KEY_FILE", dir.join("token-key"));
        }
        let mut child = Killed(cmd.spawn().unwrap());
        let mut lines = BufReader::new(child.0.stderr.take().unwrap()).lines();
        let mut seen = Vec::new();
        loop {
            let Some(line) = lines.next() else {
                panic!("keyd exited before serving: {seen:#?}");
            };
            let line = line.unwrap();
            seen.push(line.clone());
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };
            if v["event"] == "serving" {
                let addr = v["listen"].as_str().unwrap().to_owned();
                return (child, addr, seen);
            }
        }
    };

    let (child, addr, seen) = start(true, "oplog-enforced");
    assert!(
        !seen.iter().any(|l| l.contains("seal_token_not_enforced")),
        "{seen:#?}"
    );
    let keyd = RunningKeyd {
        addr,
        oplog: dir.join("oplog-enforced"),
    };
    let remote = RemoteKey::connect(endpoint(&pki, &keyd, Some(&worker)), "platform")
        .unwrap()
        .for_envelope(ENVELOPE)
        .unwrap();
    let d = digest_for(DigestSigner::algorithm(&remote), b"attrs");
    assert_eq!(remote.sign_digest(&d).unwrap_err().code(), "CS-KEY-0015");
    let token = SealTokenKey::new(&[0x5a; 32])
        .unwrap()
        .mint(ENVELOPE, now() + 600);
    remote.with_seal_token(token).sign_digest(&d).unwrap();
    drop(child);

    let (child, _, seen) = start(false, "oplog-open");
    drop(child);
    assert!(
        seen.iter()
            .any(|l| l.contains(r#""event":"seal_token_not_enforced""#)),
        "{seen:#?}"
    );
}
