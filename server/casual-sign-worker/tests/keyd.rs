//! The seal job through keyd (docs/31 §5): the worker seals with keyd's `RemoteKey`
//! over mTLS; keyd serves a development file key, says so, and every seal then carries
//! the development `/Reason`. keyd's operation log records the signature against the
//! envelope id.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;
#[path = "../../casual-sign-keyd/tests/common/mod.rs"]
mod keyd_common;

use std::sync::Arc;
use std::time::Duration;

use casual_sign_keyd::{DEV_REASON, DevKeyConsent, DigestSigner, FileKey, KeydLimits, RemoteKey};
use casual_sign_model::EnvelopeStatus;
use casual_sign_worker::seal::SealKey;
use common::Env;
use keyd_common::{Pki, endpoint, scratch, start_keyd};
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_seal_goes_through_keyd_with_the_development_reason() {
    let Some(env) = Env::new("seal_through_keyd").await else {
        return;
    };
    let pki = Pki::new();
    let dir = scratch("worker-keyd");
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = pki.signer("T-2D worker dev key", &key);
    let file_key = FileKey::load(
        DevKeyConsent::from_env_value(Some("1")).unwrap(),
        key.serialize_pem().as_bytes(),
        vec![cert, pki.seal_root()],
        None,
    )
    .unwrap();
    let worker_id = pki.client_identity("worker");
    let keyd = start_keyd(
        &pki,
        vec![("platform", Arc::new(file_key) as Arc<dyn DigestSigner>)],
        &[&worker_id.2],
        KeydLimits::default(),
        &dir,
    );
    let remote = RemoteKey::connect(endpoint(&pki, &keyd, Some(&worker_id)), "platform").unwrap();
    assert!(DigestSigner::is_development(&remote));
    *env.key.lock().unwrap() = Some(SealKey::Remote(remote));
    env.anchors
        .lock()
        .unwrap()
        .push(keyd_common::der(&pki.seal_root()));

    let ids = env.draft(vec![]).await;
    env.send(ids).await;
    env.run().await;
    env.sign(ids, ids.r1, ids.f1, "Ada Lovelace").await;
    env.run().await;
    env.sign(ids, ids.r2, ids.f2, "Grace Hopper").await;
    env.run().await;
    assert_eq!(env.state(ids.env).await.status, EnvelopeStatus::Completed);

    let sealed = env.sealed_bytes(ids.env).await;
    // /Reason is not ASCII (an em dash): written as UTF-16BE hex.
    let mut reason = String::from("<FEFF");
    for unit in DEV_REASON.encode_utf16() {
        reason.push_str(&format!("{unit:04X}"));
    }
    reason.push('>');
    assert!(
        sealed[0]
            .windows(reason.len())
            .any(|w| w == reason.as_bytes()),
        "the development reason is written"
    );
    // Verified against keyd's seal root (and the test TSA's).
    let mut trust = common::pki::trust();
    trust
        .add_anchor(&keyd_common::der(&pki.seal_root()))
        .unwrap();
    let report = env.engine.verify(
        &sealed[0],
        &trust,
        &env.engine.verify_options(Duration::from_millis(
            u64::try_from(env.clock.ms()).unwrap(),
        )),
    );
    casual_sign_worker::seal::check_verified(&report, casual_sign_sdk::Profile::BaselineT).unwrap();
    // keyd logged one signature, against the envelope.
    let log = std::fs::read_to_string(&keyd.oplog).unwrap();
    let signs: Vec<&str> = log.lines().filter(|l| l.contains("\tsign\t")).collect();
    assert_eq!(signs.len(), 1, "{log}");
    assert!(signs[0].contains(&ids.env.hyphenated().to_string()));
}
