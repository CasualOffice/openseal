//! Correcting a sent envelope's documents (`VS-06`, docs/24 §6, `UXW-19`): the editor's
//! Correct mode adds a document and fields on it through the draft endpoints, which on
//! a sent envelope run the engine's `Correct`; a document added is acted on only by
//! those with fields on it; removing a document a signer finished on sends them back to
//! sign again, the earlier signing staying in the chain.

#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::indexing_slicing
)]

mod common;

use axum::http::StatusCode;
use common::Rls;
use common::flow::{b64, invite, ok, sent, sign};
use common::harness::{Api, pdf};
use serde_json::{Value, json};

fn status_of(e: &Value, rec: &str) -> String {
    e["recipients"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == rec)
        .unwrap()["status"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn documents_are_added_and_removed_while_sent_and_a_signer_on_a_removed_one_signs_again() {
    let Some(api) = Api::new("correct_documents", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let k = &a.auth;
    let e = sent(&api, &a, 2, &[]).await;
    let id = e["id"].as_str().unwrap().to_owned();
    let base = format!("/api/v1/envelopes/{id}");
    let r1 = e["recipients"][0]["id"].as_str().unwrap().to_owned();
    let r2 = e["recipients"][1]["id"].as_str().unwrap().to_owned();
    let first_doc = e["documents"][0]["id"].as_str().unwrap().to_owned();
    let t1 = invite(&api, &a, &id, &r1).await;
    sign(&api, &t1, &[]).await;

    // A document added while sent, with a field for the second signer on it.
    let added = ok(
        api.call(
            "POST",
            &format!("{base}/documents"),
            k,
            Some(json!({"name": "annex.pdf", "content_base64": b64(&pdf(1))})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "add a document while sent",
    );
    let annex = added["id"].as_str().unwrap().to_owned();
    ok(
        api.call(
            "POST",
            &format!("{base}/fields"),
            k,
            Some(
                json!({"items": [{"recipient_id": r2, "document_id": annex, "type": "initials",
                "page": 1, "x": 72, "y": 100, "width": 60, "height": 30, "required": true}]}),
            ),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "a field on it",
    );
    let now = ok(
        api.call("GET", &base, k, None, &[]).await,
        StatusCode::OK,
        "get",
    );
    assert_eq!(now["status"], "sent");
    assert_eq!(now["documents"].as_array().unwrap().len(), 2);
    // Signer 1 had no field on the annex: their signing stands.
    assert_eq!(status_of(&now, &r1), "completed");

    // Removing the document signer 1 finished on sends them back to sign.
    let etag = api.call("GET", &base, k, None, &[]).await.etag();
    let r = api
        .call(
            "DELETE",
            &format!("{base}/documents/{first_doc}"),
            k,
            None,
            &[("if-match", &etag)],
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.json());
    let now = ok(
        api.call("GET", &base, k, None, &[]).await,
        StatusCode::OK,
        "get",
    );
    assert_eq!(now["documents"].as_array().unwrap().len(), 1);
    assert_ne!(status_of(&now, &r1), "completed", "signer 1 acts again");

    // Every correction is in the chain, the first signing too.
    let audit = ok(
        api.call("GET", &format!("{base}/audit"), k, None, &[])
            .await,
        StatusCode::OK,
        "audit",
    );
    let types: Vec<&str> = audit["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["type"].as_str().unwrap())
        .collect();
    assert!(
        types.iter().filter(|t| **t == "envelope.corrected").count() >= 3,
        "{types:?}"
    );
    assert!(types.contains(&"recipient.signed"), "{types:?}");
}
