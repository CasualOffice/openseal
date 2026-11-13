//! ASVS-08 (ASVS 9.2.5): the worker logs a back end it cannot reach or that refuses it
//! as `transport.backend_failed` with the code: keyd unreachable at connection, keyd
//! refusing a signature, and a time-stamping authority not answering. Every kind the
//! worker emits (`Kind::emitted_by(Worker)`) is shown, and no line carries the TSA's
//! URL, keyd's address or a digest.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

#[path = "../../casual-sign-keyd/tests/common/mod.rs"]
mod keyd_common;

use std::collections::BTreeSet;
use std::sync::Arc;

use casual_sign_keyd::{DevKeyConsent, DigestSigner, FileKey, KeydLimits};
use casual_sign_sdk::KeyProvider as _;
use casual_sign_seclog::{Kind, SecurityLog, Service};
use keyd_common::{Pki, endpoint, scratch, start_keyd};
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};

#[test]
fn every_worker_security_event_is_emitted_with_its_code_and_no_address() {
    let (log, mem) = SecurityLog::memory(Service::Worker);
    casual_sign_worker::set_security_log(log);

    // A TSA that does not answer: the next would be tried; logged by index.
    let tsa_url = "http://127.0.0.1:1/tsa-secret-path";
    let tsa = (casual_sign_worker::tsa::http_tsa(vec![tsa_url.into()]))();
    assert!(tsa.timestamp(b"request").is_err());

    // keyd: a signature refused (over its rate), then keyd not reachable at all.
    let pki = Pki::new();
    let dir = scratch("worker-seclog");
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = pki.signer("ASVS-08 dev key", &key);
    let file_key = FileKey::load(
        DevKeyConsent::from_env_value(Some("1")).unwrap(),
        key.serialize_pem().as_bytes(),
        vec![cert, pki.seal_root()],
        None,
    )
    .unwrap();
    let id = pki.client_identity("worker");
    let keyd = start_keyd(
        &pki,
        vec![("platform", Arc::new(file_key) as Arc<dyn DigestSigner>)],
        &[&id.2],
        KeydLimits {
            signatures_per_minute: 0,
            ..KeydLimits::default()
        },
        &dir,
    );
    let ep = endpoint(&pki, &keyd, Some(&id));
    let remote = casual_sign_worker::seal::connect_keyd(ep.clone(), "platform").unwrap();
    assert!(remote.sign(b"signed attributes").is_err());
    let mut gone = ep;
    gone.addr = "127.0.0.1:1".into();
    let e = casual_sign_worker::seal::connect_keyd(gone, "platform").unwrap_err();
    assert_eq!(e.code(), "CS-KEY-0011");

    let lines = mem.json();
    let seen: BTreeSet<&str> = lines
        .iter()
        .filter(|l| l["event"] == "security")
        .filter_map(|l| l["kind"].as_str())
        .collect();
    for k in Kind::emitted_by(Service::Worker) {
        assert!(seen.contains(k.as_str()), "not emitted: {k:?} in {lines:?}");
    }
    let failed: Vec<_> = lines
        .iter()
        .filter(|l| l["kind"] == Kind::BackendFailed.as_str())
        .collect();
    let tsa_line = failed.iter().find(|l| l["backend"] == "tsa").unwrap();
    assert_eq!(tsa_line["code"], "CS-WRK-0018");
    assert_eq!(tsa_line["index"], 0);
    assert_eq!(tsa_line["reason"], "connect");
    let keyd_codes: BTreeSet<&str> = failed
        .iter()
        .filter(|l| l["backend"] == "keyd")
        .map(|l| l["code"].as_str().unwrap())
        .collect();
    assert!(keyd_codes.contains("CS-KEY-0011"), "{keyd_codes:?}");
    assert!(
        keyd_codes.len() >= 2,
        "the refused signature too: {keyd_codes:?}"
    );
    for raw in mem.lines() {
        assert!(raw.contains(r#""service":"worker""#), "{raw}");
        assert!(
            !raw.contains("127.0.0.1") && !raw.contains("tsa-secret-path"),
            "{raw}"
        );
        assert!(!raw.contains(&keyd.addr), "{raw}");
    }
}
