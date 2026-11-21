//! ADR-047 §3.5, `RSP-02` acceptance (4): an ASP request-signing key (alias `asp-*`)
//! signs only with the database's ASP token for an open eSign session. No token,
//! another session's, an expired one, one under another key, and a seal token are each
//! refused `CS-KEY-0015` and recorded; a keyd without the ASP token key never signs
//! with an ASP key; an ASP token never opens the platform seal key.
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
    AspTokenKey, DevKeyConsent, DigestSigner, FileKey, RemoteKey, SealTokenKey, digest_for, oplog,
};
use common::*;
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};

const SESSION: &str = "0193a000-0000-7000-8000-0000000000e1";
const OTHER: &str = "0193a000-0000-7000-8000-0000000000e2";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn file_key(pki: &Pki, name: &str) -> Arc<dyn DigestSigner> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = pki.signer(name, &key);
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

#[test]
fn the_asp_key_signs_only_with_the_databases_asp_token_for_the_session() {
    let pki = Pki::new();
    let dir = scratch("keyd-asp-token");
    let worker = pki.client_identity("worker");
    let seal = [0x5a; 32];
    let asp = [0x6b; 32];
    let keyd = start_keyd_asp(
        &pki,
        vec![
            ("platform", file_key(&pki, "seal")),
            ("asp-test", file_key(&pki, "ASP")),
        ],
        &[&worker.2],
        &dir,
        SealTokenKey::new(&seal).unwrap(),
        Some(AspTokenKey::new(&asp).unwrap()),
    );
    let db_asp = AspTokenKey::new(&asp).unwrap();
    let db_seal = SealTokenKey::new(&seal).unwrap();
    let ep = || endpoint(&pki, &keyd, Some(&worker));
    let asp_key = RemoteKey::connect(ep(), "asp-test")
        .unwrap()
        .for_envelope(SESSION)
        .unwrap();
    let d = digest_for(DigestSigner::algorithm(&asp_key), b"signed info");
    let refused = |k: &RemoteKey, why: &str| {
        assert_eq!(
            k.sign_digest(&d).unwrap_err().code(),
            "CS-KEY-0015",
            "{why}"
        );
    };
    refused(&asp_key, "no token");
    refused(
        &asp_key
            .clone()
            .with_seal_token(db_asp.mint(OTHER, now() + 600)),
        "another session's token",
    );
    refused(
        &asp_key
            .clone()
            .with_seal_token(db_asp.mint(SESSION, now() - 1)),
        "an expired token",
    );
    refused(
        &asp_key.clone().with_seal_token(
            AspTokenKey::new(&[0x6c; 32])
                .unwrap()
                .mint(SESSION, now() + 600),
        ),
        "a token under another key",
    );
    refused(
        &asp_key
            .clone()
            .with_seal_token(db_seal.mint(SESSION, now() + 600)),
        "a seal token",
    );
    // The platform seal key never takes an ASP token.
    let seal_key = RemoteKey::connect(ep(), "platform")
        .unwrap()
        .for_envelope(SESSION)
        .unwrap();
    refused(
        &seal_key
            .clone()
            .with_seal_token(db_asp.mint(SESSION, now() + 600)),
        "an ASP token on the seal key",
    );
    assert!(
        asp_key
            .clone()
            .with_seal_token(db_asp.mint(SESSION, now() + 600))
            .sign_digest(&d)
            .is_ok(),
        "the session's ASP token signs"
    );
    let records = oplog::read_range(&keyd.oplog, 1, 64, u64::MAX).unwrap();
    let outcomes: Vec<(&str, &str)> = records
        .iter()
        .filter(|r| r.op == "sign")
        .map(|r| (r.alias.as_str(), r.outcome.as_str()))
        .collect();
    assert_eq!(outcomes.len(), 7, "every attempt recorded: {outcomes:?}");
    assert_eq!(outcomes.iter().filter(|(_, o)| *o == "ok").count(), 1);
}

#[test]
fn without_the_asp_token_key_an_asp_key_never_signs() {
    let pki = Pki::new();
    let dir = scratch("keyd-asp-none");
    let worker = pki.client_identity("worker");
    let keyd = start_keyd_asp(
        &pki,
        vec![("asp-test", file_key(&pki, "ASP"))],
        &[&worker.2],
        &dir,
        SealTokenKey::new(&[0x5a; 32]).unwrap(),
        None,
    );
    let k = RemoteKey::connect(endpoint(&pki, &keyd, Some(&worker)), "asp-test")
        .unwrap()
        .for_envelope(SESSION)
        .unwrap()
        .with_seal_token(
            AspTokenKey::new(&[0x6b; 32])
                .unwrap()
                .mint(SESSION, now() + 600),
        );
    let d = digest_for(DigestSigner::algorithm(&k), b"x");
    assert_eq!(k.sign_digest(&d).unwrap_err().code(), "CS-KEY-0015");
}
