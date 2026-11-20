//! VS-06D (`UXW-20`, docs/32 §6): `GET /envelopes/{id}/evidence-package` answers one ZIP
//! with each document (as sealed, or as it ended), the certificate, the audit trail as
//! `GET …/audit` gives it and a manifest naming every other entry's SHA-256. The ZIP is
//! read back with an independent reader (the `zip` crate); every entry's hash must be
//! the manifest's, the trail must end with the export (`envelope.exported`, recorded),
//! and its head must be the manifest's `chain_head`. An envelope in flight is `409`
//! with nothing recorded; one whose certificate is not made yet is `409` and asks the
//! worker for it; another account's id is `404`.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::too_many_lines
)]

mod common;

use std::io::Read as _;

use axum::http::StatusCode;
use casual_sign_audit::Hash256;
use casual_sign_store::blob::BlobStore as _;
use common::Rls;
use common::flow::{jobs, ok, sent};
use common::harness::{Api, Auth, pdf};
use serde_json::{Value, json};

async fn audit(api: &Api, auth: &Auth, id: &str) -> Value {
    ok(
        api.call(
            "GET",
            &format!("/api/v1/envelopes/{id}/audit"),
            auth,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "audit",
    )
}

/// Every entry of the archive, by name, read with the `zip` crate.
fn unzip(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    (0..z.len())
        .map(|i| {
            let mut f = z.by_index(i).unwrap();
            let mut out = Vec::new();
            f.read_to_end(&mut out).unwrap();
            (f.name().unwrap().into_owned(), out)
        })
        .collect()
}

async fn package(rls: Rls) {
    let Some(api) = Api::new(&format!("evidence_package_{rls:?}"), rls).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let b = api.tenant("bravo").await;
    let env = sent(&api, &a, 1, &[]).await;
    let id = env["id"].as_str().unwrap().to_owned();
    let path = format!("/api/v1/envelopes/{id}/evidence-package");

    // In flight: no package, nothing recorded.
    let before = audit(&api, &a.auth, &id).await["items"]
        .as_array()
        .unwrap()
        .len();
    let r = api.call("GET", &path, &a.auth, None, &[]).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.json());
    assert_eq!(r.code(), "CS-WF-0001");
    ok(
        api.call(
            "POST",
            &format!("/api/v1/envelopes/{id}/void"),
            &a.auth,
            Some(json!({"reason": "Wrong party"})),
            &[],
        )
        .await,
        StatusCode::OK,
        "void",
    );
    // Ended, its certificate not made yet: 409, and the worker is asked for it.
    let r = api.call("GET", &path, &a.auth, None, &[]).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.json());
    assert_eq!(r.code(), "CS-API-0009");
    assert!(
        jobs(&api, &id)
            .await
            .contains(&"seal_ended_certificate".to_owned())
    );
    let trail = audit(&api, &a.auth, &id).await;
    let n = trail["items"].as_array().unwrap().len();
    assert_eq!(n, before + 1, "only envelope.voided was added");

    // The worker's result, stored as it stores it (worker tests make and seal it).
    let cert = pdf(1);
    let blobs = casual_sign_store::blob::FsBlobStore::new(api.blob_dir.clone()).unwrap();
    let key = blobs.put(&cert).await.unwrap();
    let mut tx = api
        .db
        .store
        .for_account(a.boot.account)
        .begin()
        .await
        .unwrap();
    tx.envelopes()
        .set_certificate(casual_sign_store::EnvelopeId(id.parse().unwrap()), &key.0)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // Another account: 404, before anything.
    let r = api.call("GET", &path, &b.auth, None, &[]).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    let r = api.call("GET", &path, &a.auth, None, &[]).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    assert_eq!(r.headers["content-type"], "application/zip");
    assert!(
        r.headers["content-disposition"]
            .to_str()
            .unwrap()
            .contains(&format!("evidence-{id}.zip"))
    );
    let entries = unzip(&r.body);
    let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        [
            "manifest.json",
            "documents/01-w.pdf",
            "certificate.pdf",
            "audit-trail.json"
        ]
    );
    let manifest: Value = serde_json::from_slice(&entries[0].1).unwrap();
    assert_eq!(manifest["format"], "openseal.evidence-package");
    assert_eq!(manifest["envelope_id"], id.as_str());
    assert_eq!(manifest["status"], "voided");
    let listed = manifest["entries"].as_array().unwrap();
    assert_eq!(listed.len(), 3);
    for (e, (name, bytes)) in listed.iter().zip(&entries[1..]) {
        assert_eq!(e["path"], name.as_str());
        assert_eq!(e["sha256"], Hash256::digest(bytes).hex(), "{name}");
        assert_eq!(e["size"], bytes.len(), "{name}");
    }
    assert_eq!(listed[0]["kind"], "document");
    assert_eq!(listed[0]["sealed"], false, "a voided document as it ended");
    assert!(entries[1].1.starts_with(b"%PDF-"));
    assert_eq!(entries[2].1, cert, "the stored certificate, unchanged");
    // The trail is the API's, ending with this export; its head is the manifest's.
    let trail: Value = serde_json::from_slice(&entries[3].1).unwrap();
    let items = trail["items"].as_array().unwrap();
    assert_eq!(items.last().unwrap()["type"], "envelope.exported");
    assert_eq!(trail["chain_head"], manifest["chain_head"]);
    assert_eq!(trail["chain_head"], items.last().unwrap()["hash"]);
    let now = audit(&api, &a.auth, &id).await;
    assert_eq!(now["items"].as_array().unwrap().len(), n + 1);
    assert_eq!(now["chain_head"], manifest["chain_head"]);
    let by = &now["items"].as_array().unwrap().last().unwrap()["event"]["data"]["by"];
    assert!(by.is_string(), "the member who exported it: {by}");
    api.db.drop().await;
}

#[tokio::test]
async fn an_ended_envelopes_evidence_package_holds_every_entry_with_its_hash_and_is_recorded() {
    package(Rls::On).await;
}

#[tokio::test]
async fn the_evidence_package_stays_in_the_account_with_row_level_security_disabled() {
    package(Rls::Off).await;
}
