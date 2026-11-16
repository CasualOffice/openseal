//! An alias whose signer certificate has expired, or is not yet valid, is refused for
//! sealing (docs/23 §5.4, `CON-08`): keyd answers `CS-CON-0006` and records the refusal,
//! while a valid alias on the same keyd still signs.
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

use casual_sign_keyd::{
    DevKeyConsent, DigestSigner, FileKey, KeydLimits, RemoteKey, digest_for, oplog,
};
use common::*;
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};

fn key_valid(pki: &Pki, cn: &str, from: (i32, u8, u8), to: (i32, u8, u8)) -> Arc<dyn DigestSigner> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = pki.signer_valid(cn, &key, from, to);
    Arc::new(
        FileKey::load(
            DevKeyConsent::from_env_value(Some("1")).unwrap(),
            key.serialize_pem().as_bytes(),
            vec![cert, pki.seal_root()],
            None,
        )
        .unwrap(),
    )
}

/// **An expired alias is refused (`CS-CON-0006`), recorded in keyd's log; so is one not
/// yet valid; a current alias signs.**
#[test]
fn an_expired_alias_is_refused_for_sealing() {
    let pki = Pki::new();
    let dir = scratch("keyd-expired-alias");
    let worker = pki.client_identity("worker");
    let keyd = start_keyd(
        &pki,
        vec![
            (
                "current",
                key_valid(&pki, "current", (2026, 1, 1), (2046, 1, 1)),
            ),
            (
                "expired",
                key_valid(&pki, "expired", (2025, 1, 1), (2026, 1, 1)),
            ),
            (
                "future",
                key_valid(&pki, "future", (2045, 1, 1), (2046, 1, 1)),
            ),
        ],
        &[&worker.2],
        KeydLimits::default(),
        &dir,
    );
    let ep = endpoint(&pki, &keyd, Some(&worker));
    let digest = digest_for(
        casual_sign_crypto::SignatureAlgorithm::EcdsaP256Sha256,
        b"x",
    );

    let current = RemoteKey::connect(ep.clone(), "current").unwrap();
    assert!(
        current.sign_digest(&digest).is_ok(),
        "a current alias signs"
    );

    // The chain is still served (the console and an operator can see why); the signature
    // is not.
    let expired = RemoteKey::connect(ep.clone(), "expired").unwrap();
    let err = expired.sign_digest(&digest).unwrap_err();
    assert_eq!(err.code(), "CS-CON-0006");
    let future = RemoteKey::connect(ep, "future").unwrap();
    assert_eq!(
        future.sign_digest(&digest).unwrap_err().code(),
        "CS-CON-0006"
    );

    let records = oplog::read_range(&keyd.oplog, 1, 64, u64::MAX).unwrap();
    let signs: Vec<(&str, &str)> = records
        .iter()
        .filter(|r| r.op == "sign")
        .map(|r| (r.alias.as_str(), r.outcome.as_str()))
        .collect();
    assert_eq!(
        signs,
        [
            ("current", "ok"),
            ("expired", "CS-CON-0006"),
            ("future", "CS-CON-0006")
        ]
    );
}
