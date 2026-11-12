//! modeld over mTLS (ML-09; `SEC-I12`): who is refused, what INFO answers, what the op log
//! records (counts and ids, never text), busy slots, and ops not yet built. The refusal
//! tests are keyd's (`server/casual-sign-keyd/tests/mtls.rs`), plus a wrong server
//! certificate.
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

use casual_sign_modeld::wire::{EmbedKind, SpanRequest};
use casual_sign_modeld::{ModeldError, ModeldLimits, oplog};
use common::*;

fn setup(name: &str) -> (Pki, RunningModeld, Identity) {
    let pki = Pki::new();
    let worker = pki.client_identity("worker");
    let modeld = start_modeld(
        &pki,
        &pki.server_identity(),
        &[&worker.2],
        ModeldLimits::default(),
        name,
    );
    (pki, modeld, worker)
}

/// **INFO returns the bundle id** and each installed model's hash, and the op log
/// records the call by caller, account and job.
#[test]
fn info_returns_the_bundle_id() {
    let (pki, modeld, worker) = setup("modeld-info");
    let c = client(&pki.tls_ca.pem(), &modeld, Some(&worker));
    let info = c.info(&call()).unwrap();
    assert_eq!(info.bundle_id, modeld.bundle_id);
    assert_eq!(info.bundle_id.len(), 64);
    assert_eq!(info.runtime, "none");
    let ids: Vec<&str> = info.models.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(ids, ["det", "rec"]);
    let det = sha_hex(b"synthetic detector bytes");
    assert_eq!(casual_sign_modeld::oplog::hex(&info.models[0].1), det);

    let log = std::fs::read_to_string(&modeld.oplog).unwrap();
    let f: Vec<&str> = log.lines().next().unwrap().split('\t').collect();
    assert_eq!(f[2], worker.2, "caller fingerprint");
    assert_eq!(&f[3..6], ["info", "acc-0001", "job-0001"]);
    assert_eq!(f[9], "ok");
    assert_eq!(f[10], modeld.bundle_id);
    assert_eq!(oplog::verify(&modeld.oplog).unwrap().0, 1);
}

/// **A client without a certificate never completes the handshake.**
#[test]
fn a_client_without_a_certificate_is_refused() {
    let (pki, modeld, _) = setup("modeld-nocert");
    let err = client(&pki.tls_ca.pem(), &modeld, None)
        .info(&call())
        .unwrap_err();
    assert_eq!(err.code(), "CS-ML-0008", "{err}");
}

/// **A client certificate from another CA never completes the handshake.**
#[test]
fn a_client_with_an_untrusted_certificate_is_refused() {
    let (pki, modeld, _) = setup("modeld-rogue-client");
    let rogue = pki.rogue_client_identity("worker");
    let err = client(&pki.tls_ca.pem(), &modeld, Some(&rogue))
        .info(&call())
        .unwrap_err();
    assert_eq!(err.code(), "CS-ML-0008", "{err}");
}

/// **A server certificate the worker does not trust is refused by the worker**: nothing
/// is sent to an impostor modeld.
#[test]
fn a_server_with_an_untrusted_certificate_is_refused() {
    let pki = Pki::new();
    let worker = pki.client_identity("worker");
    let modeld = start_modeld(
        &pki,
        &pki.rogue_server_identity(),
        &[&worker.2],
        ModeldLimits::default(),
        "modeld-rogue-server",
    );
    let err = client(&pki.tls_ca.pem(), &modeld, Some(&worker))
        .info(&call())
        .unwrap_err();
    assert_eq!(err.code(), "CS-ML-0008", "{err}");
    let log = std::fs::read_to_string(&modeld.oplog).unwrap_or_default();
    assert!(log.is_empty(), "nothing reached the service: {log}");
}

/// **A certificate from the right CA but not on the allow list is refused and
/// recorded.**
#[test]
fn a_client_not_on_the_allow_list_is_refused_and_logged() {
    let (pki, modeld, _) = setup("modeld-notlisted");
    let stranger = pki.client_identity("stranger");
    let err = client(&pki.tls_ca.pem(), &modeld, Some(&stranger))
        .info(&call())
        .unwrap_err();
    assert_eq!(err, ModeldError::NotAuthorized, "{err}");
    let log = std::fs::read_to_string(&modeld.oplog).unwrap();
    assert!(
        log.contains(&format!(
            "\t{}\tconnect\t-\t-\t0\t0\t0\tCS-ML-0015\t",
            stranger.2
        )),
        "{log}"
    );
}

/// Every op whose model is not built yet answers `CS-ML-0010`, and the op log records
/// it by code. **No text sent reaches the log** (a first, narrow `SEC-I05` check; piece M
/// runs it over every output stream).
#[test]
fn ops_not_built_answer_not_installed_and_log_no_text() {
    let (pki, modeld, worker) = setup("modeld-notinstalled");
    let c = client(&pki.tls_ca.pem(), &modeld, Some(&worker));
    let marker = "ZQXMARKER-Ana-Synthetic-Person";
    let span = || SpanRequest {
        text: format!("Agreement with {marker}."),
        labels: vec!["ZQXLABEL party".into()],
        threshold: 5_000,
    };
    let pdf = b"%PDF-1.7 ZQXMARKER".to_vec();
    let results = [
        c.ocr(&call(), pdf.clone(), vec![0], 150, vec!["latin".into()])
            .map(|_| ()),
        c.hash(&call(), pdf, vec![0]).map(|_| ()),
        c.embed(&call(), EmbedKind::Passage, vec![marker.into()])
            .map(|_| ()),
        c.entities(&call(), span()).map(|_| ()),
        c.personal(&call(), span()).map(|_| ()),
    ];
    for r in results {
        assert_eq!(r.unwrap_err(), ModeldError::NotInstalled);
    }
    let log = std::fs::read_to_string(&modeld.oplog).unwrap();
    assert_eq!(log.lines().count(), 5, "{log}");
    assert!(log.lines().all(|l| l.contains("\tCS-ML-0010\t")), "{log}");
    assert!(
        log.lines()
            .next()
            .unwrap()
            .contains("\tocr\tacc-0001\tjob-0001\t1\t0\t")
    );
    assert!(!log.contains("ZQXMARKER"), "{log}");
    assert!(!log.contains("ZQXLABEL"), "labels are not logged: {log}");
}

/// When every slot is taken, an op is answered busy (`CS-ML-0009`, transient); INFO
/// takes no slot.
#[test]
fn ops_are_refused_busy_when_no_slot_is_free() {
    let pki = Pki::new();
    let worker = pki.client_identity("worker");
    let modeld = start_modeld(
        &pki,
        &pki.server_identity(),
        &[&worker.2],
        ModeldLimits {
            slots: 0,
            ..ModeldLimits::default()
        },
        "modeld-busy",
    );
    let c = client(&pki.tls_ca.pem(), &modeld, Some(&worker));
    let err = c
        .embed(&call(), EmbedKind::Query, vec!["q".into()])
        .unwrap_err();
    assert_eq!(err, ModeldError::Busy);
    assert!(err.is_transient());
    assert!(c.info(&call()).is_ok());
}

/// A request over a bound is refused by the client before anything is sent.
#[test]
fn a_request_over_a_bound_is_never_sent() {
    let (pki, modeld, worker) = setup("modeld-bounds");
    let c = client(&pki.tls_ca.pem(), &modeld, Some(&worker));
    let err = c
        .embed(&call(), EmbedKind::Query, vec!["q".into(); 65])
        .unwrap_err();
    assert_eq!(err.code(), "CS-ML-0004");
    let mut bad = call();
    bad.account = "acc 1".into();
    assert_eq!(c.info(&bad).unwrap_err().code(), "CS-ML-0004");
    let log = std::fs::read_to_string(&modeld.oplog).unwrap();
    assert!(log.is_empty(), "nothing was sent: {log}");
}
