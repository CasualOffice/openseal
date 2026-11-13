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
use casual_sign_platform_store::sqlx;
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

/// **`CON-08` acceptance: a signer certificate near expiry raises an alert, once per
/// threshold.** keyd's key expires 2027-03-01; at the test clock (44 days before) the
/// scan raises the 90-day alert, a second scan raises nothing, 20 days later the 30-day
/// one, then the 7-day one, and the expired one after `notAfter`.
#[tokio::test]
async fn a_certificate_near_expiry_raises_one_alert_per_threshold() {
    let Some(db) = common::fresh("a_certificate_near_expiry_raises_one_alert_per_threshold").await
    else {
        return;
    };
    let pki = start_keyd();
    let c = common::console_with(&db, config(&pki, &pki.console));
    let seed = c.bootstrap(OWNER, PASSWORD).await;
    let s = c.sign_in(OWNER, PASSWORD, &seed).await;
    let scan = async |c: &common::Console, s: &common::Session| {
        let r = c
            .call(s, "POST", "/console/v1/keys/expiry-scan", None)
            .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text);
        r.json()["raised"].clone()
    };
    assert_eq!(
        scan(&c, &s).await,
        serde_json::json!([{ "alias": "platform", "days": 90 }])
    );
    assert_eq!(scan(&c, &s).await, serde_json::json!([]), "raised once");
    let alerts = c.call(&s, "GET", "/console/v1/alerts", None).await.json();
    let a = &alerts["alerts"][0];
    assert_eq!(a["code"], "CS-CON-0018");
    assert_eq!(a["source"], "certificate_expiry_scan");
    assert_eq!(a["subject"]["alias"], "platform");
    assert_eq!(a["subject"]["days"], 90);
    assert_eq!(a["subject"]["sha256"], hex(&sha256(&pki.leaf_der)));
    assert_eq!(alerts["alerts"].as_array().unwrap().len(), 1);

    // The scan needs a fresh session each time the clock jumps past the idle limit.
    c.clock.advance(20 * 86_400);
    let s = c.sign_in(OWNER, PASSWORD, &seed).await;
    assert_eq!(
        scan(&c, &s).await,
        serde_json::json!([{ "alias": "platform", "days": 30 }])
    );
    c.clock.advance(18 * 86_400);
    let s = c.sign_in(OWNER, PASSWORD, &seed).await;
    assert_eq!(
        scan(&c, &s).await,
        serde_json::json!([{ "alias": "platform", "days": 7 }])
    );
    c.clock.advance(7 * 86_400);
    let s = c.sign_in(OWNER, PASSWORD, &seed).await;
    assert_eq!(
        scan(&c, &s).await,
        serde_json::json!([{ "alias": "platform", "days": 0 }]),
        "expired"
    );
    db.drop().await;
}

/// **`CON-09` acceptance: an injected unmatched signature alerts; a lost-lease retry is
/// listed as orphaned, not alerted.** keyd signs three digests: one the worker recorded
/// (matched), one for the same envelope that was not recorded (the envelope sealed with
/// the other: an orphaned retry), and one for an envelope with no seal record (alert). A
/// seal record with no keyd signature also alerts. The next run judges nothing twice.
#[tokio::test]
async fn reconciliation_alerts_unmatched_signatures_and_lists_orphaned_retries() {
    let Some(db) =
        common::fresh("reconciliation_alerts_unmatched_signatures_and_lists_orphaned_retries")
            .await
    else {
        return;
    };
    let seeded = db.seed().await;
    let pki = start_keyd();
    let c = common::console_with(&db, config(&pki, &pki.console));
    let seed = c.bootstrap(OWNER, PASSWORD).await;
    let s = c.sign_in(OWNER, PASSWORD, &seed).await;

    let env = seeded.envelope;
    let stranger = uuid::Uuid::now_v7();
    let key = RemoteKey::connect(endpoint(&pki, &pki.worker), "platform").unwrap();
    let alg = DigestSigner::algorithm(&key);
    let mut digests = Vec::new();
    for (e, data) in [
        (env, &b"sealed"[..]),
        (env, &b"lost lease"[..]),
        (stranger, &b"forged"[..]),
    ] {
        let k = key.for_envelope(&e.hyphenated().to_string()).unwrap();
        let d = casual_sign_keyd::digest_for(alg, data);
        k.sign_digest(&d).unwrap();
        digests.push(d);
    }
    // The worker's record of the first, and a record keyd never signed.
    let rogue = casual_sign_keyd::digest_for(alg, b"never signed");
    for d in [&digests[0], &rogue] {
        sqlx::query(
            "INSERT INTO seal_signatures (account_id, envelope_id, digest, alias, at) \
             VALUES ($1, $2, $3, 'platform', '2027-01-01T00:00:00Z')",
        )
        .bind(seeded.workspace)
        .bind(env)
        .bind(d.as_slice())
        .execute(&db.owner)
        .await
        .unwrap();
    }

    let r = c.call(&s, "POST", "/console/v1/reconciliation", None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text);
    let run = r.json()["run"].clone();
    assert_eq!(run["signatures"], 3, "{run}");
    assert_eq!(run["matched"], 1, "{run}");
    assert_eq!(run["unmatched"], 2, "{run}");
    let orphaned = run["orphaned"].as_array().unwrap();
    assert_eq!(orphaned.len(), 1, "{run}");
    assert_eq!(orphaned[0]["envelope_id"], env.to_string());

    let alerts = c.call(&s, "GET", "/console/v1/alerts", None).await.json();
    let mut found: Vec<(String, String)> = alerts["alerts"]
        .as_array()
        .unwrap()
        .iter()
        .inspect(|a| {
            assert_eq!(a["code"], "CS-CON-0009");
            assert_eq!(a["source"], "reconciliation");
        })
        .map(|a| {
            (
                a["subject"]["direction"].as_str().unwrap().to_owned(),
                a["subject"]["envelope_id"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    found.sort();
    assert_eq!(
        found,
        [
            ("seal_without_signature".to_owned(), env.to_string()),
            ("signature_without_seal".to_owned(), stranger.to_string()),
        ],
        "the orphaned retry is not alerted"
    );
    let log = c.call(&s, "GET", "/console/v1/operator-log", None).await;
    assert!(
        log.text.contains("operator.reconciliation.mismatch"),
        "{}",
        log.text
    );

    // The next run starts where this one stopped and judges nothing twice.
    let again = c.call(&s, "POST", "/console/v1/reconciliation", None).await;
    let run2 = again.json()["run"].clone();
    assert_eq!(run2["from_seq"], run["next_seq"], "{run2}");
    assert_eq!(run2["unmatched"], 0, "{run2}");
    let listed = c.call(&s, "GET", "/console/v1/reconciliation", None).await;
    assert_eq!(listed.json()["runs"].as_array().unwrap().len(), 2);
    db.drop().await;
}
