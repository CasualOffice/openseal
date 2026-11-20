//! FG-013, ADR-043: sign on paper. On an envelope with `allow_sign_on_paper`, a signer
//! uploads the scan of what they printed and signed by hand (`POST /s/{token}/paper`):
//! admitted like any upload, added to the envelope as a fixed document (so the seal
//! covers it), and recorded as `recipient.signed_on_paper` binding the documents printed
//! and the scan's SHA-256, then `recipient.completed`; routing moves on. Off, it is
//! `409 CS-WF-0012` with nothing recorded; anything but a PDF is `422`; a second upload
//! is refused.

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

use axum::http::StatusCode;
use casual_sign_audit::Hash256;
use common::Rls;
use common::flow::{b64, invite, ok, open, sign};
use common::harness::{Api, Auth, Tenant, pdf, png};
use serde_json::{Value, json};

/// A sent envelope of one document and two signers in sequence, with sign on paper
/// `allowed` or not.
async fn envelope(api: &Api, t: &Tenant, allowed: bool) -> Value {
    let recipients: Vec<Value> = (1..=2)
        .map(|n| {
            json!({"ref": format!("s{n}"), "type": "signer", "name": format!("S{n}"),
                "email": format!("s{n}@example.test"), "routing_order": n})
        })
        .collect();
    let fields: Vec<Value> = (1..=2)
        .map(|n| {
            json!({"recipient": format!("s{n}"), "document": 0, "type": "signature", "page": 1,
                "x": 72, "y": 100 * n, "width": 180, "height": 40, "required": true})
        })
        .collect();
    ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            &t.auth,
            Some(json!({
                "subject": "Paper", "status": "sent",
                "signing_options": {"allow_sign_on_paper": allowed},
                "documents": [{"name": "p.pdf", "content_base64": b64(&pdf(2))}],
                "recipients": recipients, "fields": fields,
            })),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "create",
    )
}

async fn trail(api: &Api, t: &Tenant, id: &str) -> Vec<Value> {
    ok(
        api.call(
            "GET",
            &format!("/api/v1/envelopes/{id}/audit"),
            &t.auth,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "audit",
    )["items"]
        .as_array()
        .unwrap()
        .clone()
}

async fn paper(rls: Rls) {
    let Some(api) = Api::new(&format!("sign_on_paper_{rls:?}"), rls).await else {
        return;
    };
    let a = api.tenant("alpha").await;

    // Off: refused, nothing recorded.
    let off = envelope(&api, &a, false).await;
    let oid = off["id"].as_str().unwrap();
    let token = invite(&api, &a, oid, off["recipients"][0]["id"].as_str().unwrap()).await;
    let (_, bound) = open(&api, &token).await;
    let h: Vec<(&str, &str)> = bound.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let before = trail(&api, &a, oid).await.len();
    let r = api
        .call(
            "POST",
            &format!("/s/{token}/paper"),
            &Auth::None,
            Some(json!({"content_base64": b64(&pdf(1))})),
            &h,
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.json());
    assert_eq!(r.code(), "CS-WF-0012");
    assert_eq!(trail(&api, &a, oid).await.len(), before);
    assert_eq!(
        ok(
            api.call(
                "GET",
                &format!("/api/v1/envelopes/{oid}"),
                &a.auth,
                None,
                &[]
            )
            .await,
            StatusCode::OK,
            "get"
        )["documents"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // On.
    let env = envelope(&api, &a, true).await;
    let id = env["id"].as_str().unwrap().to_owned();
    let delivered = env["documents"][0]["delivered_sha256"].clone();
    let token = invite(&api, &a, &id, env["recipients"][0]["id"].as_str().unwrap()).await;
    let (view, bound) = open(&api, &token).await;
    assert_eq!(
        view["envelope"]["signing_options"]["allow_sign_on_paper"],
        true
    );
    let h: Vec<(&str, &str)> = bound.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let path = format!("/s/{token}/paper");
    // Not a PDF.
    let r = api
        .call(
            "POST",
            &path,
            &Auth::None,
            Some(json!({"content_base64": b64(&png())})),
            &h,
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{:?}", r.json());
    let scan = pdf(3);
    ok(
        api.call(
            "POST",
            &path,
            &Auth::None,
            Some(json!({"content_base64": b64(&scan)})),
            &h,
        )
        .await,
        StatusCode::OK,
        "paper",
    );
    let got = ok(
        api.call(
            "GET",
            &format!("/api/v1/envelopes/{id}"),
            &a.auth,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "get",
    );
    let docs = got["documents"].as_array().unwrap();
    assert_eq!(docs.len(), 2);
    assert_eq!(docs[1]["name"], "Signed on paper.pdf");
    assert_eq!(docs[1]["fixed"], true);
    let scan_hash = Hash256::digest(&scan);
    assert_eq!(docs[1]["upload_sha256"], json!(scan_hash));
    assert_eq!(got["recipients"][0]["status"], "completed");
    let items = trail(&api, &a, &id).await;
    let types: Vec<&str> = items.iter().map(|e| e["type"].as_str().unwrap()).collect();
    let at = types
        .iter()
        .position(|t| *t == "recipient.signed_on_paper")
        .expect("recorded");
    assert_eq!(
        &types[at - 3..at + 2],
        [
            "document.added",
            "document.admitted",
            "document.fixed",
            "recipient.signed_on_paper",
            "recipient.completed"
        ]
    );
    let data = &items[at]["event"]["data"];
    assert_eq!(data["upload_hash"], json!(scan_hash));
    assert_eq!(data["document_id"], docs[1]["id"]);
    assert_eq!(data["documents"][0]["hash"], delivered);
    assert_eq!(data["documents"].as_array().unwrap().len(), 1);
    // Done: a second upload is refused.
    let r = api
        .call(
            "POST",
            &path,
            &Auth::None,
            Some(json!({"content_base64": b64(&scan)})),
            &h,
        )
        .await;
    assert!(r.status.is_client_error(), "{:?}", r.status);
    // The next signer signs electronically; the envelope completes with the scan.
    let token2 = invite(&api, &a, &id, env["recipients"][1]["id"].as_str().unwrap()).await;
    sign(&api, &token2, &[]).await;
    let got = ok(
        api.call(
            "GET",
            &format!("/api/v1/envelopes/{id}"),
            &a.auth,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "get",
    );
    assert_eq!(got["status"], "completing");
    api.db.drop().await;
}

#[tokio::test]
async fn a_signer_signs_on_paper_with_the_scan_admitted_added_and_recorded() {
    paper(Rls::On).await;
}

#[tokio::test]
async fn sign_on_paper_stays_in_the_account_with_row_level_security_disabled() {
    paper(Rls::Off).await;
}
