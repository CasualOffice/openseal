//! ASVS-08: keyd's security events. Every kind keyd emits (`Kind::emitted_by(Keyd)`) is
//! written by a real mTLS call: a signature and a chain (`key.use`), a signature over
//! the rate (`access.rate_limited`), a signing caller asking an admin operation
//! (`access.denied`), a caller off the allow list and one without a certificate
//! (`transport.caller_refused`). Callers are named by certificate fingerprint; no line
//! carries the digest signed, an address or the certificate's subject.

// Test code: a panic is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::collections::BTreeSet;
use std::sync::Arc;

use casual_sign_keyd::{
    AdminClient, DevKeyConsent, DigestSigner, FileKey, KeydLimits, RemoteKey, digest_for,
};
use casual_sign_seclog::{Kind, SecurityLog, Service};
use common::*;
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};

#[test]
fn every_keyd_security_event_is_emitted_naming_callers_by_fingerprint_only() {
    let pki = Pki::new();
    let dir = scratch("keyd-seclog");
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = pki.signer("ASVS-08 keyd signer", &key);
    let file_key = FileKey::load(
        DevKeyConsent::from_env_value(Some("1")).unwrap(),
        key.serialize_pem().as_bytes(),
        vec![cert, pki.seal_root()],
        None,
    )
    .unwrap();
    let worker = pki.client_identity("worker-subject-name");
    let (log, mem) = SecurityLog::memory(Service::Keyd);
    let keyd = start_keyd_logged(
        &pki,
        vec![("platform", Arc::new(file_key) as Arc<dyn DigestSigner>)],
        &[&worker.2],
        &[],
        KeydLimits {
            signatures_per_minute: 1,
            ..KeydLimits::default()
        },
        &dir,
        Some(log),
    );
    let envelope = casual_sign_seclog::Uuid::from_u128(0x0193_0000_0000_7000_8000_0000_0000_0008);
    let remote = RemoteKey::connect(endpoint(&pki, &keyd, Some(&worker)), "platform")
        .unwrap()
        .for_envelope(&envelope.to_string())
        .unwrap();
    let d = digest_for(DigestSigner::algorithm(&remote), b"attrs");
    remote.sign_digest(&d).unwrap();
    assert!(remote.sign_digest(&d).is_err(), "over the rate");
    // A signing caller asking an admin operation.
    assert!(
        AdminClient::new(endpoint(&pki, &keyd, Some(&worker)))
            .list_keys()
            .is_err()
    );
    // Off the allow list; no certificate at all.
    let stranger = pki.client_identity("stranger");
    assert!(RemoteKey::connect(endpoint(&pki, &keyd, Some(&stranger)), "platform").is_err());
    assert!(RemoteKey::connect(endpoint(&pki, &keyd, None), "platform").is_err());
    // keyd answers on its own threads; the last refusal may still be in flight.
    for _ in 0..50 {
        if mem
            .lines()
            .iter()
            .filter(|l| l.contains("transport.caller_refused"))
            .count()
            >= 2
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    let lines = mem.json();
    let seen: BTreeSet<&str> = lines.iter().filter_map(|l| l["kind"].as_str()).collect();
    for k in Kind::emitted_by(Service::Keyd) {
        assert!(seen.contains(k.as_str()), "not emitted: {k:?} in {lines:?}");
    }
    let sign = lines
        .iter()
        .find(|l| l["kind"] == "key.use" && l["op"] == "sign" && l["outcome"] == "success")
        .unwrap();
    assert_eq!(sign["principal"], format!("caller:{}", worker.2));
    assert_eq!(sign["alias"], "platform");
    assert_eq!(sign["envelope_id"], envelope.to_string());
    let refused: Vec<_> = lines
        .iter()
        .filter(|l| l["kind"] == "transport.caller_refused")
        .collect();
    assert!(
        refused
            .iter()
            .any(|l| l["principal"] == format!("caller:{}", stranger.2)
                && l["code"] == "CS-KEY-0001")
    );
    assert!(refused.iter().any(|l| l["reason"] == "handshake"));
    let digest_hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
    for raw in mem.lines() {
        assert!(raw.contains(r#""service":"keyd""#), "{raw}");
        assert!(!raw.contains(&digest_hex), "the digest: {raw}");
        assert!(
            !raw.contains("127.0.0.1") && !raw.contains(&keyd.addr),
            "{raw}"
        );
        assert!(!raw.contains("worker-subject-name"), "{raw}");
    }
}
