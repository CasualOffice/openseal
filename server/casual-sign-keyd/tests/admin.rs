//! keyd's admin interface (docs/23 §5.4, `CON-06`): a second allow-list whose callers
//! get the read-only `list-keys`, `oplog-head`, `oplog-range` and `health`, and nothing
//! else; a signing caller cannot call them (`CS-CON-0008`, recorded either way).
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

use casual_sign_crypto::KeyProvider;
use casual_sign_keyd::{
    AdminClient, AllowList, DevKeyConsent, DigestSigner, FileKey, KeyService, KeydLimits, OpLog,
    RemoteKey, oplog,
};
use common::*;
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};

fn file_key(pki: &Pki) -> FileKey {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = pki.signer("CON-06 seal key", &key);
    FileKey::load(
        DevKeyConsent::from_env_value(Some("1")).unwrap(),
        key.serialize_pem().as_bytes(),
        vec![cert, pki.seal_root()],
        None,
    )
    .unwrap()
}

struct Setup {
    pki: Pki,
    keyd: RunningKeyd,
    worker: (String, String, String),
    console: (String, String, String),
}

fn setup(name: &str) -> Setup {
    let pki = Pki::new();
    let dir = scratch(name);
    let worker = pki.client_identity("worker");
    let console = pki.client_identity("console");
    let keyd = start_keyd_with_admin(
        &pki,
        vec![(
            "platform",
            Arc::new(file_key(&pki)) as Arc<dyn DigestSigner>,
        )],
        &[&worker.2],
        &[&console.2],
        KeydLimits::default(),
        &dir,
    );
    Setup {
        pki,
        keyd,
        worker,
        console,
    }
}

/// **The admin client reads keys, the log and health; it cannot sign or fetch a chain;
/// a signing client cannot call an admin operation.** Both refusals are `CS-CON-0008` and
/// recorded in keyd's log.
#[test]
fn an_admin_client_cannot_sign_and_a_signing_client_cannot_list() {
    let s = setup("keyd-admin-split");
    let admin = AdminClient::new(endpoint(&s.pki, &s.keyd, Some(&s.console)));

    // The admin client reads.
    let keys = admin.list_keys().unwrap();
    assert_eq!(keys.len(), 1);
    let k = &keys[0];
    assert_eq!(k.alias, "platform");
    assert_eq!(k.backend, "file-dev");
    assert!(k.development);
    assert_eq!(k.certs.len(), 2, "signer and root");
    assert_eq!(k.not_before, 1_767_225_600, "2026-01-01");
    assert_eq!(k.not_after, 2_398_377_600, "2046-01-01");
    assert!(k.subject.contains("CN=CON-06 seal key"), "{}", k.subject);
    assert!(k.issuer.contains("CN=T-2E Seal Root"), "{}", k.issuer);
    let health = admin.health().unwrap();
    assert_eq!(health.keys.len(), 1);
    assert!(health.keys[0].ok);
    assert_eq!(health.keys[0].backend, "file-dev");

    // The admin client cannot sign, nor fetch a chain to sign with.
    let err =
        RemoteKey::connect(endpoint(&s.pki, &s.keyd, Some(&s.console)), "platform").unwrap_err();
    assert_eq!(err.code(), "CS-CON-0008", "{err}");

    // A signing client signs, and cannot list, read the log or ask for health.
    let remote =
        RemoteKey::connect(endpoint(&s.pki, &s.keyd, Some(&s.worker)), "platform").unwrap();
    let signed = remote
        .for_envelope("env-1")
        .unwrap()
        .sign(b"attributes")
        .unwrap();
    assert!(!signed.as_bytes().is_empty());
    let wrong = AdminClient::new(endpoint(&s.pki, &s.keyd, Some(&s.worker)));
    assert_eq!(wrong.list_keys().unwrap_err().code(), "CS-CON-0008");
    assert_eq!(wrong.oplog_head().unwrap_err().code(), "CS-CON-0008");
    assert_eq!(wrong.oplog_range(1, 10).unwrap_err().code(), "CS-CON-0008");
    assert_eq!(wrong.health().unwrap_err().code(), "CS-CON-0008");

    // Every call is in the log, the refusals with their code, and the chain verifies.
    let (seq, hash) = admin.oplog_head().unwrap();
    let (count, head) = oplog::verify(&s.keyd.oplog).unwrap();
    assert_eq!(seq, count);
    assert_eq!(hash, head);
    let records = admin.oplog_range(1, 100).unwrap();
    // The range call is recorded before it is answered, so it reads itself.
    assert_eq!(records.len() as u64, seq + 1);
    let ops: Vec<(&str, &str, &str)> = records
        .iter()
        .map(|r| (r.op.as_str(), r.caller.as_str(), r.outcome.as_str()))
        .collect();
    let (c, w) = (s.console.2.as_str(), s.worker.2.as_str());
    assert_eq!(
        ops,
        [
            ("list-keys", c, "ok"),
            ("health", c, "ok"),
            ("chain", c, "CS-CON-0008"),
            ("chain", w, "ok"),
            ("sign", w, "ok"),
            ("list-keys", w, "CS-CON-0008"),
            ("oplog-head", w, "CS-CON-0008"),
            ("oplog-range", w, "CS-CON-0008"),
            ("health", w, "CS-CON-0008"),
            ("oplog-head", c, "ok"),
            ("oplog-range", c, "ok"),
        ]
    );
    let sign = &records[4];
    assert_eq!(sign.envelope, "env-1");
    assert_eq!(sign.digest.len(), 64, "a SHA-256 digest, hex");
    // A range from the middle starts there.
    let tail = admin.oplog_range(10, 5).unwrap();
    assert_eq!(tail.first().map(|r| r.seq), Some(10));
}

/// A caller off both lists is still `CS-KEY-0001` for an admin operation.
#[test]
fn a_caller_on_neither_list_is_not_authorized() {
    let s = setup("keyd-admin-stranger");
    let stranger = s.pki.client_identity("stranger");
    let client = AdminClient::new(endpoint(&s.pki, &s.keyd, Some(&stranger)));
    assert_eq!(client.list_keys().unwrap_err().code(), "CS-KEY-0001");
}

/// One certificate cannot be on both lists.
#[test]
fn a_fingerprint_on_both_lists_is_refused_at_start() {
    let pki = Pki::new();
    let dir = scratch("keyd-admin-both");
    let c = pki.client_identity("both");
    let mut sign = AllowList::new();
    sign.allow(&c.2, "w");
    let mut admin = AllowList::new();
    admin.allow(&c.2, "c");
    let log = OpLog::open(&dir.join("log.tsv")).unwrap();
    let err = KeyService::new(sign, log, KeydLimits::default())
        .with_admin(admin)
        .unwrap_err();
    assert_eq!(err.code(), "CS-KEY-0010");
}
