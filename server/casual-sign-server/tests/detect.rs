//! Field auto-detection through the API (WEB-06): `POST …/documents/{doc}/detect-fields`
//! suggests fields from the document's lines and labels in the field endpoints'
//! geometry, and a suggestion posted back with a recipient becomes a field where it was
//! suggested. Another account's document is `404`.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use axum::http::StatusCode;
use common::Rls;
use common::flow::{b64, ok};
use common::harness::{Api, text_pdf};
use serde_json::{Value, json};

#[tokio::test]
async fn suggestions_come_from_labels_and_lines_and_post_back_as_fields() {
    let Some(api) = Api::new("detect_fields", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let b = api.tenant("beta").await;
    let content = "BT /F1 11 Tf 72 640 Td (Signature: ____________________) Tj ET \
                   BT /F1 11 Tf 72 600 Td (Date: ______________) Tj ET \
                   BT /F1 11 Tf 72 560 Td (Print name: ____________________) Tj ET \
                   BT /F1 11 Tf 72 400 Td (Nothing to sign here at all.) Tj ET";
    let e = ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            &a.auth,
            Some(json!({"subject": "d", "documents": [{"name": "d.pdf", "content_base64": b64(&text_pdf(content))}],
                "recipients": [{"type": "signer", "name": "S", "email": "s@example.test"}]})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "draft",
    );
    let id = e["id"].as_str().unwrap();
    let doc = e["documents"][0]["id"].as_str().unwrap();
    let rid = e["recipients"][0]["id"].as_str().unwrap();
    let path = format!("/api/v1/envelopes/{id}/documents/{doc}/detect-fields");
    let found = ok(
        api.call("POST", &path, &a.auth, None, &[]).await,
        StatusCode::OK,
        "detect",
    );
    let items = found["items"].as_array().unwrap();
    let types: Vec<&str> = items.iter().map(|f| f["type"].as_str().unwrap()).collect();
    assert_eq!(types, ["signature", "date_signed", "name"], "{found}");
    assert_eq!(found["truncated"], false);
    // Displayed space, origin top-left: the signature line is at 792 − 640 = 152 from
    // the top, so the field sits above it, on the page, to the right of the label.
    let sig = &items[0];
    let num = |v: &Value| v.as_str().unwrap().parse::<f64>().unwrap();
    assert_eq!(sig["page"], 1);
    assert!(
        num(&sig["y"]) < 152.0 && num(&sig["y"]) + num(&sig["height"]) > 140.0,
        "{sig}"
    );
    assert!(num(&sig["x"]) > 72.0, "{sig}");
    assert_eq!(sig["source"], "underline");
    assert_eq!(sig["cue"], "Signature:", "{sig}");

    // A suggestion posted back with a recipient is a field at the same place.
    let mut field = sig.clone();
    let o = field.as_object_mut().unwrap();
    for k in ["source", "confidence", "cue"] {
        o.remove(k);
    }
    o.insert("recipient_id".into(), json!(rid));
    let added = ok(
        api.call(
            "POST",
            &format!("/api/v1/envelopes/{id}/fields"),
            &a.auth,
            Some(json!({ "items": [field] })),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "add suggested field",
    );
    let placed = &added["items"][0]["placement"];
    assert_eq!(placed["x"], sig["x"], "{added}");
    assert_eq!(placed["y"], sig["y"], "{added}");

    // Another account cannot ask.
    let other = api.call("POST", &path, &b.auth, None, &[]).await;
    assert_eq!(
        (other.status, other.code().as_str()),
        (StatusCode::NOT_FOUND, "CS-API-0002")
    );
}
