//! Downloading a document in progress (WEB-06): `content?version=current` answers a
//! preview of the values completed so far with a not-signed banner on every page, made
//! on request and never stored; the delivered document is untouched; a recipient's
//! values in progress are not shown; the download is in the chain with the hash of the
//! bytes served. A recipient who has finished downloads the same through
//! `GET /s/{token}/document`, and one who has not is refused.

#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

mod common;

use axum::http::StatusCode;
use casual_sign_audit::Hash256;
use common::Rls;
use common::flow::{invite, ok, open, sent, sign};
use common::harness::{Api, Auth};
use serde_json::{Value, json};
use sqlx::Row;

/// Every page's text, joined.
fn text_of(pdf: &[u8]) -> String {
    let never = || false;
    let mut a = casual_sign_pdf::admit(pdf, &casual_sign_pdf::Limits::default(), &never).unwrap();
    let pages = a.report.pages.clone();
    casual_sign_fields::extract_text(&mut a.document, &pages, &never)
        .unwrap()
        .iter()
        .map(|p| {
            p.runs
                .iter()
                .map(|r| r.text.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn field_of(e: &Value, recipient: &str, ty: &str) -> String {
    e["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["recipient_id"] == recipient && f["type"] == ty)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn versions(api: &Api) -> i64 {
    sqlx::query("SELECT count(*) FROM document_versions")
        .fetch_one(&api.db.admin)
        .await
        .unwrap()
        .get::<i64, _>(0)
}

#[tokio::test]
async fn an_envelope_in_progress_downloads_as_a_marked_preview() {
    let Some(api) = Api::new("preview_current", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let k = &a.auth;
    let extra = [
        json!({"recipient": "s1", "document": 0, "type": "company", "page": 1, "x": 72, "y": 300, "width": 200, "height": 20}),
        json!({"recipient": "s2", "document": 0, "type": "text", "page": 2, "x": 72, "y": 300, "width": 200, "height": 20}),
    ];
    let e = sent(&api, &a, 2, &extra).await;
    let id = e["id"].as_str().unwrap().to_owned();
    let doc = e["documents"][0]["id"].as_str().unwrap().to_owned();
    let (r1, r2) = (
        e["recipients"][0]["id"].as_str().unwrap().to_owned(),
        e["recipients"][1]["id"].as_str().unwrap().to_owned(),
    );
    let base = format!("/api/v1/envelopes/{id}");
    let delivered = api
        .call(
            "GET",
            &format!("{base}/documents/{doc}/content"),
            k,
            None,
            &[],
        )
        .await
        .body
        .to_vec();
    let stored_before = versions(&api).await;

    // Signer 1 finishes with a company name; signer 2 types a value and stops.
    let company = field_of(&e, &r1, "company");
    let t1 = invite(&api, &a, &id, &r1).await;
    let (_, h1) = sign(&api, &t1, &[(company, json!({"text": "Acme Holdings"}))]).await;
    let t2 = invite(&api, &a, &id, &r2).await;
    let (_, h2) = open(&api, &t2).await;
    let h2: Vec<(&str, &str)> = h2.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let typed = field_of(&e, &r2, "text");
    ok(
        api.call(
            "PUT",
            &format!("/s/{t2}/fields/{typed}"),
            &Auth::None,
            Some(json!({"value": {"text": "Draft words"}})),
            &h2,
        )
        .await,
        StatusCode::OK,
        "fill in progress",
    );

    let r = api
        .call(
            "GET",
            &format!("{base}/documents/{doc}/content?version=current"),
            k,
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    assert_eq!(r.headers["x-openseal-document"], "preview");
    assert_eq!(r.headers["content-type"], "application/pdf");
    let preview = r.body.to_vec();
    // An incremental update of the delivered bytes, which stay as they were.
    assert!(preview.starts_with(&delivered) && preview.len() > delivered.len());
    let text = text_of(&preview);
    assert_eq!(
        text.matches("PREVIEW").count(),
        2,
        "a banner a page: {text}"
    );
    assert!(text.contains("NOT SIGNED"), "{text}");
    assert!(text.contains("Acme Holdings"), "{text}");
    assert!(
        !text.contains("Draft words"),
        "a value in progress shown: {text}"
    );
    // Nothing stored; the delivered document is still what signers saw.
    assert_eq!(versions(&api).await, stored_before);
    let again = api
        .call(
            "GET",
            &format!("{base}/documents/{doc}/content"),
            k,
            None,
            &[],
        )
        .await;
    assert_eq!(again.body.to_vec(), delivered);
    // The download is in the chain with the hash of the bytes served.
    let audit = ok(
        api.call("GET", &format!("{base}/audit"), k, None, &[])
            .await,
        StatusCode::OK,
        "audit",
    );
    let served = Hash256::digest(&preview).hex();
    assert!(
        audit["items"].as_array().unwrap().iter().any(|ev| {
            ev["type"] == "document.downloaded"
                && ev["event"]["data"]["document"]["hash"]
                    .as_str()
                    .is_some_and(|h| h.ends_with(&served))
        }),
        "{audit}"
    );

    // Signer 1 (finished) downloads the preview through their link; signer 2 (not
    // finished) and another browser are refused.
    let h1: Vec<(&str, &str)> = h1.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let mine = api
        .call("GET", &format!("/s/{t1}/document"), &Auth::None, None, &h1)
        .await;
    assert_eq!(mine.status, StatusCode::OK, "{:?}", mine.json());
    assert_eq!(mine.headers["x-openseal-document"], "preview");
    assert!(text_of(&mine.body).contains("Acme Holdings"));
    let early = api
        .call("GET", &format!("/s/{t2}/document"), &Auth::None, None, &h2)
        .await;
    assert_eq!(
        (early.status, early.code().as_str()),
        (StatusCode::CONFLICT, "CS-API-0009")
    );
    let stranger = api
        .call("GET", &format!("/s/{t1}/document"), &Auth::None, None, &[])
        .await;
    assert_eq!(stranger.status, StatusCode::FORBIDDEN);
    let downloads = ok(
        api.call("GET", &format!("{base}/audit"), k, None, &[])
            .await,
        StatusCode::OK,
        "audit",
    )["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|ev| ev["type"] == "document.downloaded")
        .count();
    // The two delivered-copy downloads, the preview, and the signer's.
    assert_eq!(downloads, 4);
}
