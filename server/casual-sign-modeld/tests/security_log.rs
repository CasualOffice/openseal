//! ASVS-08: modeld's security events. Every kind modeld emits
//! (`Kind::emitted_by(Modeld)`) is written by a real mTLS call: a caller off the allow
//! list (named by certificate fingerprint, `CS-ML-0015`) and one with no certificate
//! (the handshake). No line carries an address or the certificate's subject.
#![cfg(feature = "server")]
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

use casual_sign_modeld::ModeldLimits;
use casual_sign_seclog::{Kind, SecurityLog, Service};
use common::*;

#[test]
fn every_modeld_security_event_is_emitted_naming_callers_by_fingerprint_only() {
    let pki = Pki::new();
    let worker = pki.client_identity("worker");
    let (log, mem) = SecurityLog::memory(Service::Modeld);
    let modeld = start_modeld_with(
        &pki,
        &pki.server_identity(),
        &[&worker.2],
        ModeldLimits::default(),
        "modeld-seclog",
        test_bundle("modeld-seclog-bundle"),
        |s| s.with_security_log(log),
    );
    let stranger = pki.client_identity("stranger-subject-name");
    assert!(
        client(&pki.tls_ca.pem(), &modeld, Some(&stranger))
            .info(&call())
            .is_err()
    );
    assert!(
        client(&pki.tls_ca.pem(), &modeld, None)
            .info(&call())
            .is_err()
    );
    // modeld answers on its own threads; the handshake's refusal may still be in flight.
    for _ in 0..50 {
        if mem.lines().len() >= 2 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    let lines = mem.json();
    let seen: BTreeSet<&str> = lines.iter().filter_map(|l| l["kind"].as_str()).collect();
    for k in Kind::emitted_by(Service::Modeld) {
        assert!(seen.contains(k.as_str()), "not emitted: {k:?} in {lines:?}");
    }
    assert!(
        lines.iter().any(
            |l| l["principal"] == format!("caller:{}", stranger.2) && l["code"] == "CS-ML-0015"
        )
    );
    assert!(lines.iter().any(|l| l["reason"] == "handshake"));
    for raw in mem.lines() {
        assert!(raw.contains(r#""service":"modeld""#), "{raw}");
        assert!(
            !raw.contains("127.0.0.1") && !raw.contains(&modeld.addr),
            "{raw}"
        );
        assert!(!raw.contains("stranger-subject-name"), "{raw}");
    }
}
