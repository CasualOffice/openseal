//! WF-02 on the server: a document hidden from a recipient is never listed to them nor
//! served (`404`, as a document that does not exist), and their view and download name
//! only what they may see; a sender schedules a draft to send itself
//! (`PUT /envelopes/{id}/schedule`), cannot edit it while scheduled (`409 CS-WF-0022`),
//! and cancels the schedule (`DELETE`).

#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::indexing_slicing
)]

mod common;

use axum::http::StatusCode;
use common::Rls;
use common::flow::{b64, invite, ok, open};
use common::harness::{Api, Auth, pdf};
use serde_json::{Value, json};
use sqlx::Row;

async fn call(
    api: &Api,
    method: &str,
    path: &str,
    h: &[(&'static str, String)],
) -> common::harness::Resp {
    let h: Vec<(&str, &str)> = h.iter().map(|(k, v)| (*k, v.as_str())).collect();
    api.call(method, path, &Auth::None, None, &h).await
}

#[tokio::test]
async fn a_hidden_document_is_neither_listed_nor_served_to_that_recipient() {
    let Some(api) = Api::new("visibility_hidden", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let e = ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            &a.auth,
            Some(json!({
                "subject": "WF-02", "status": "sent",
                "documents": [
                    {"name": "terms.pdf", "content_base64": b64(&pdf(1))},
                    {"name": "pricing.pdf", "content_base64": b64(&pdf(2))},
                ],
                "recipients": [
                    {"ref": "s1", "type": "signer", "name": "Sig One",
                     "email": "one@example.test", "excluded_documents": [1]},
                    {"ref": "s2", "type": "signer", "name": "Sig Two",
                     "email": "two@example.test"},
                ],
                "fields": [
                    {"recipient": "s1", "document": 0, "type": "signature", "page": 1,
                     "x": 72, "y": 100, "width": 180, "height": 40, "required": true},
                    {"recipient": "s2", "document": 1, "type": "signature", "page": 1,
                     "x": 72, "y": 100, "width": 180, "height": 40, "required": true},
                ],
            })),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "create",
    );
    let env = e["id"].as_str().unwrap().to_owned();
    let terms = e["documents"][0]["id"].as_str().unwrap().to_owned();
    let pricing = e["documents"][1]["id"].as_str().unwrap().to_owned();
    let s1 = e["recipients"][0]["id"].as_str().unwrap().to_owned();
    let s2 = e["recipients"][1]["id"].as_str().unwrap().to_owned();
    assert_eq!(e["recipients"][0]["excluded_documents"], json!([pricing]));

    // s1 sees the terms only.
    let token = invite(&api, &a, &env, &s1).await;
    let (view, h) = open(&api, &token).await;
    let listed: Vec<&Value> = view["envelope"]["documents"]
        .as_array()
        .unwrap()
        .iter()
        .collect();
    assert_eq!(listed.len(), 1, "{view}");
    assert_eq!(listed[0]["id"], json!(terms));
    let r = call(
        &api,
        "GET",
        &format!("/s/{token}/documents/{terms}/content"),
        &h,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let r = call(
        &api,
        "GET",
        &format!("/s/{token}/documents/{pricing}/content"),
        &h,
    )
    .await;
    assert_eq!(
        r.status,
        StatusCode::NOT_FOUND,
        "the hidden document was served"
    );
    assert!(!r.body.starts_with(b"%PDF-"));
    let h2: Vec<(&str, &str)> = h.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let r = api
        .call(
            "POST",
            &format!("/s/{token}/documents/{pricing}/viewed"),
            &Auth::None,
            Some(json!({"pages_seen": [1]})),
            &h2,
        )
        .await;
    assert_eq!(
        r.status,
        StatusCode::NOT_FOUND,
        "a view of the hidden document recorded"
    );

    // s2 sees both.
    let token2 = invite(&api, &a, &env, &s2).await;
    let (view2, h2) = open(&api, &token2).await;
    assert_eq!(view2["envelope"]["documents"].as_array().unwrap().len(), 2);
    let r = call(
        &api,
        "GET",
        &format!("/s/{token2}/documents/{pricing}/content"),
        &h2,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    api.db.drop().await;
}

#[tokio::test]
async fn a_scheduled_draft_waits_for_its_time_and_cannot_be_edited() {
    let Some(api) = Api::new("schedule_send", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let e = ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            &a.auth,
            Some(json!({
                "subject": "WF-02",
                "documents": [{"name": "d.pdf", "content_base64": b64(&pdf(1))}],
                "recipients": [{"ref": "s1", "type": "signer", "name": "Sig One",
                    "email": "one@example.test"}],
                "fields": [{"recipient": "s1", "document": 0, "type": "signature", "page": 1,
                    "x": 72, "y": 100, "width": 180, "height": 40, "required": true}],
            })),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "create",
    );
    let env = e["id"].as_str().unwrap().to_owned();
    let base = format!("/api/v1/envelopes/{env}");
    // Not after now: refused.
    let r = api
        .call(
            "PUT",
            &format!("{base}/schedule"),
            &a.auth,
            Some(json!({"send_at": "2026-11-10T10:00:00Z"})),
            &[],
        )
        .await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::UNPROCESSABLE_ENTITY, "CS-WF-0023".to_owned())
    );
    let s = ok(
        api.call(
            "PUT",
            &format!("{base}/schedule"),
            &a.auth,
            Some(json!({"send_at": "2026-11-12T10:00:00Z"})),
            &[],
        )
        .await,
        StatusCode::OK,
        "schedule",
    );
    assert_eq!(s["status"], "draft");
    assert_eq!(s["send_at"], "2026-11-12T10:00:00.000Z");
    let timers: Vec<String> =
        sqlx::query("SELECT kind FROM jobs WHERE envelope_id = $1::uuid AND kind = 'timer'")
            .bind(&env)
            .fetch_all(&api.db.admin)
            .await
            .unwrap()
            .iter()
            .map(|r| r.get::<String, _>(0))
            .collect();
    assert_eq!(timers.len(), 1, "the send timer is enqueued");

    let etag = api.call("GET", &base, &a.auth, None, &[]).await.etag();
    let r = api
        .call(
            "PATCH",
            &base,
            &a.auth,
            Some(json!({"subject": "Changed"})),
            &[("if-match", &etag)],
        )
        .await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::CONFLICT, "CS-WF-0022".to_owned())
    );

    let u = ok(
        api.call("DELETE", &format!("{base}/schedule"), &a.auth, None, &[])
            .await,
        StatusCode::OK,
        "unschedule",
    );
    assert!(u["send_at"].is_null());
    let etag = api.call("GET", &base, &a.auth, None, &[]).await.etag();
    let r = api
        .call(
            "PATCH",
            &base,
            &a.auth,
            Some(json!({"subject": "Changed"})),
            &[("if-match", &etag)],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    api.db.drop().await;
}
