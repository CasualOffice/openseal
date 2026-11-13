//! Keys in the console (`CON-06`, docs/23 §5.4): the console reads a real keyd through
//! its admin interface with an identity on keyd's admin allow-list, and shows each key's
//! certificates, validity and status, keyd's operation log and keyd's health. The same
//! console configured with a signing identity is refused (`CS-CON-0008`): the signing and
//! admin identities are disjoint, and the admin one cannot sign.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    missing_docs
)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use casual_sign_console::Config;
use casual_sign_console::crypto::sha256;
use casual_sign_keyd::{
    AdminClient, AllowList, DevKeyConsent, DigestSigner, Endpoint, FileKey, KeyService, Keyd,
    KeydLimits, OpLog, RemoteKey, certificates, client_tls, fingerprint, server_tls,
};
use casual_sign_keyd_client::hex;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};

const OWNER: &str = "owner@ops.example";
const PASSWORD: &str = "correct horse battery staple";

fn ca(cn: &str) -> CertifiedIssuer<'static, KeyPair> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(DnType::CommonName, cn);
    p.not_before = rcgen::date_time_ymd(2026, 1, 1);
    p.not_after = rcgen::date_time_ymd(2046, 1, 1);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    CertifiedIssuer::self_signed(p, key).unwrap()
}

/// (certificate PEM, key PEM, fingerprint).
fn tls_entity(
    issuer: &CertifiedIssuer<'static, KeyPair>,
    server: bool,
) -> (String, String, String) {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let names = if server {
        vec!["localhost".to_owned()]
    } else {
        Vec::new()
    };
    let mut p = CertificateParams::new(names).unwrap();
    p.not_before = rcgen::date_time_ymd(2026, 1, 1);
    p.not_after = rcgen::date_time_ymd(2046, 1, 1);
    p.extended_key_usages = vec![if server {
        ExtendedKeyUsagePurpose::ServerAuth
    } else {
        ExtendedKeyUsagePurpose::ClientAuth
    }];
    let cert = p.signed_by(&key, issuer).unwrap();
    (cert.pem(), key.serialize_pem(), fingerprint(cert.der()))
}

struct Pki {
    tls_ca: CertifiedIssuer<'static, KeyPair>,
    keyd_addr: String,
    worker: (String, String, String),
    console: (String, String, String),
    leaf_der: Vec<u8>,
}

/// A keyd on a loopback port with one development key whose certificate expires on
/// 2027-03-01 (44 whole days after the test clock's 2027-01-15T08:00Z), the worker on its signing
/// list and the console on its admin list.
fn start_keyd() -> Pki {
    let tls_ca = ca("CON-06 TLS root");
    let seal_ca = ca("CON-06 seal root");
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(DnType::CommonName, "CON-06 seal");
    p.not_before = rcgen::date_time_ymd(2026, 1, 1);
    p.not_after = rcgen::date_time_ymd(2027, 3, 1);
    p.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::ContentCommitment,
    ];
    let leaf = p.signed_by(&key, &seal_ca).unwrap();
    let leaf_der = leaf.der().to_vec();
    let file_key = FileKey::load(
        DevKeyConsent::from_env_value(Some("1")).unwrap(),
        key.serialize_pem().as_bytes(),
        certificates(format!("{}{}", leaf.pem(), seal_ca.pem()).as_bytes()).unwrap(),
        None,
    )
    .unwrap();
    let (server_cert, server_key, _) = tls_entity(&tls_ca, true);
    let worker = tls_entity(&tls_ca, false);
    let console = tls_entity(&tls_ca, false);
    let mut allow = AllowList::new();
    allow.allow(&worker.2, "worker");
    let mut admin = AllowList::new();
    admin.allow(&console.2, "console");
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("console-keys-{}", uuid::Uuid::now_v7().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut service = KeyService::new(
        allow,
        OpLog::open(&dir.join("oplog.tsv")).unwrap(),
        KeydLimits::default(),
    )
    .with_admin(admin)
    .unwrap();
    service
        .add_key("platform", Arc::new(file_key) as Arc<dyn DigestSigner>)
        .unwrap();
    let tls = server_tls(
        server_cert.as_bytes(),
        server_key.as_bytes(),
        tls_ca.pem().as_bytes(),
    )
    .unwrap();
    let keyd = Keyd::bind("127.0.0.1:0", tls, service).unwrap();
    let keyd_addr = keyd.local_addr().unwrap().to_string();
    std::thread::spawn(move || keyd.serve());
    Pki {
        tls_ca,
        keyd_addr,
        worker,
        console,
        leaf_der,
    }
}

fn endpoint(pki: &Pki, who: &(String, String, String)) -> Endpoint {
    Endpoint {
        addr: pki.keyd_addr.clone(),
        server_name: "localhost".into(),
        tls: client_tls(
            pki.tls_ca.pem().as_bytes(),
            Some((who.0.as_bytes(), who.1.as_bytes())),
        )
        .unwrap(),
        timeout: Duration::from_secs(10),
    }
}

fn config(pki: &Pki, who: &(String, String, String)) -> Config {
    Config {
        keyd: Some(AdminClient::new(endpoint(pki, who))),
        ..Config::default()
    }
}

/// **The Keys page reads keyd with the admin identity; the console cannot sign with it;
/// a console given a signing identity instead is refused (`CS-CON-0008`).**
#[tokio::test]
async fn the_console_reads_keys_through_the_admin_identity_and_cannot_sign_with_it() {
    let Some(db) =
        common::fresh("the_console_reads_keys_through_the_admin_identity_and_cannot_sign_with_it")
            .await
    else {
        return;
    };
    let pki = start_keyd();
    let c = common::console_with(&db, config(&pki, &pki.console));
    let seed = c.bootstrap(OWNER, PASSWORD).await;
    let s = c.sign_in(OWNER, PASSWORD, &seed).await;

    let r = c.call(&s, "GET", "/console/v1/keys", None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text);
    let v = r.json();
    assert_eq!(v["configured"], true);
    let k = &v["keys"][0];
    assert_eq!(k["alias"], "platform");
    assert_eq!(k["backend"], "file-dev");
    assert_eq!(k["algorithm"], "ecdsa-p256-sha256");
    assert_eq!(k["development"], true);
    assert_eq!(k["status"], "expiring", "{k}");
    assert_eq!(k["days_left"], 44, "whole days from 2027-01-15T08:00Z");
    assert_eq!(k["not_after"], "2027-03-01T00:00:00Z");
    assert_eq!(k["sha256"], hex(&sha256(&pki.leaf_der)));
    assert_eq!(k["chain"].as_array().unwrap().len(), 2);
    assert!(k["subject"].as_str().unwrap().contains("CN=CON-06 seal"));
    assert!(!r.text.contains("PRIVATE KEY"), "no key material");

    let h = c.call(&s, "GET", "/console/v1/health", None).await;
    assert_eq!(h.json()["keyd"]["status"], "up", "{}", h.text);
    assert_eq!(h.json()["keyd"]["keys"][0]["ok"], true);

    let log = c
        .call(&s, "GET", "/console/v1/keys/log?limit=50", None)
        .await;
    assert_eq!(log.status, StatusCode::OK, "{}", log.text);
    let records = log.json()["records"].as_array().unwrap().clone();
    assert!(
        records
            .iter()
            .all(|r| r["caller"] == pki.console.2.as_str()),
        "only the console has called: {records:?}"
    );
    let ops: Vec<&str> = records.iter().map(|r| r["op"].as_str().unwrap()).collect();
    assert_eq!(ops, ["list-keys", "oplog-head", "health", "oplog-range"]);
    let bad = c
        .call(&s, "GET", "/console/v1/keys/log?limit=257", None)
        .await;
    assert_eq!(bad.code(), "CS-CON-0010");

    // The console's identity cannot sign: keyd refuses a chain to it.
    let err = RemoteKey::connect(endpoint(&pki, &pki.console), "platform").unwrap_err();
    assert_eq!(err.code(), "CS-CON-0008");

    // A console wrongly given the worker's signing identity is refused by keyd.
    // (Same database, so the same session.)
    let wrong = common::console_with(&db, config(&pki, &pki.worker));
    let s2 = s;
    let r = wrong.call(&s2, "GET", "/console/v1/keys", None).await;
    assert_eq!(r.status, StatusCode::BAD_GATEWAY, "{}", r.text);
    assert_eq!(r.code(), "CS-CON-0008");
    let h = wrong.call(&s2, "GET", "/console/v1/health", None).await;
    assert_eq!(h.json()["keyd"]["status"], "down");
    assert_eq!(h.json()["keyd"]["code"], "CS-CON-0008");
    db.drop().await;
}

/// Without a keyd address the page says so instead of failing.
#[tokio::test]
async fn without_keyd_the_keys_page_says_not_configured() {
    let Some(db) = common::fresh("without_keyd_the_keys_page_says_not_configured").await else {
        return;
    };
    let c = common::console(&db);
    let seed = c.bootstrap(OWNER, PASSWORD).await;
    let s = c.sign_in(OWNER, PASSWORD, &seed).await;
    let r = c.call(&s, "GET", "/console/v1/keys", None).await;
    assert_eq!(r.json()["configured"], false);
    let h = c.call(&s, "GET", "/console/v1/health", None).await;
    assert_eq!(h.json()["keyd"]["status"], "not_configured");
    db.drop().await;
}
