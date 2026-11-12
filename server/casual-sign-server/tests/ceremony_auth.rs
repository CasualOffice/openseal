//! SEC-CER-01: a signing link alone never yields the document. A recipient whose sender
//! requires an access code or an emailed one-time code is refused the document
//! (`GET /s/{token}/documents/{doc}/content`, `403 CS-AUTH-0003`), and their view
//! names no document and no field, until they have passed every authentication they
//! need, as history and the disclosure are; afterwards both are served, the document
//! once they have also consented to the account's disclosure when it requires one.

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
use common::harness::{Api, Auth, Resp, Tenant, pdf};
use serde_json::{Value, json};

/// A sent envelope with one signer who must pass `auth`; answers the document's id and
/// the signer's link.
async fn sent(api: &Api, t: &Tenant, auth: Value) -> (String, String) {
    let mut signer = json!({"ref": "s1", "type": "signer", "name": "Sig One",
        "email": "one@example.test", "routing_order": 1, "auth": auth});
    if auth.as_array().unwrap().contains(&json!("access_code")) {
        signer["access_code"] = json!("right-4711");
    }
    let e = ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            &t.auth,
            Some(json!({
                "subject": "SEC-CER-01", "status": "sent",
                "documents": [{"name": "d.pdf", "content_base64": b64(&pdf(1))}],
                "recipients": [signer],
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
    let doc = e["documents"][0]["id"].as_str().unwrap().to_owned();
    let rec = e["recipients"][0]["id"].as_str().unwrap().to_owned();
    (doc, invite(api, t, &env, &rec).await)
}

type Headers = Vec<(&'static str, String)>;

async fn call(api: &Api, method: &str, path: &str, h: &Headers, body: Option<Value>) -> Resp {
    let h: Vec<(&str, &str)> = h.iter().map(|(k, v)| (*k, v.as_str())).collect();
    api.call(method, path, &Auth::None, body, &h).await
}

#[tokio::test]
async fn the_document_is_refused_until_the_access_code_is_passed() {
    let Some(api) = Api::new("ceremony_auth_code", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let (doc, token) = sent(&api, &a, json!(["access_code"])).await;
    let content = format!("/s/{token}/documents/{doc}/content");
    let (view, h) = open(&api, &token).await;
    assert_eq!(view["auth_required"], json!(["access_code"]));

    // The intercepted link, in the browser it bound, before the code.
    let r = call(&api, "GET", &content, &h, None).await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::FORBIDDEN, "CS-AUTH-0003".to_owned()),
        "the document before the access code"
    );
    assert!(!r.body.starts_with(b"%PDF-"));
    // The view names no document and no field before the code.
    assert_eq!(view["envelope"]["documents"], json!([]), "{view}");
    assert_eq!(view["fields"], json!([]), "{view}");
    // A wrong code changes nothing.
    let wrong = call(
        &api,
        "POST",
        &format!("/s/{token}/authenticate"),
        &h,
        Some(json!({"method": "access_code", "code": "wrong"})),
    )
    .await;
    assert_eq!(wrong.status, StatusCode::FORBIDDEN);
    assert_eq!(wrong.json()["envelope"]["documents"], json!([]));
    let r = call(&api, "GET", &content, &h, None).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    // After the code: the view lists the document and field, and the document is served.
    let v = ok(
        call(
            &api,
            "POST",
            &format!("/s/{token}/authenticate"),
            &h,
            Some(json!({"method": "access_code", "code": "right-4711"})),
        )
        .await,
        StatusCode::OK,
        "authenticate",
    );
    assert_eq!(v["envelope"]["documents"][0]["id"], json!(doc), "{v}");
    assert_eq!(v["fields"].as_array().unwrap().len(), 1, "{v}");
    let r = call(&api, "GET", &content, &h, None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.starts_with(b"%PDF-"));
    api.db.drop().await;
}

#[tokio::test]
async fn the_document_is_refused_until_the_disclosure_is_accepted() {
    let Some(api) = Api::new("ceremony_auth_consent", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let mut policy = serde_json::to_value(casual_sign_workflow::Policy::default()).unwrap();
    policy["ersd"] = json!({"version": "2026-1",
        "hash": casual_sign_audit::Hash256::digest(b"disclosure").to_string()});
    ok(
        api.call(
            "PATCH",
            "/api/v1/accounts/me",
            &a.auth,
            Some(json!({"settings": {"workflow_policy": policy}})),
            &[],
        )
        .await,
        StatusCode::OK,
        "policy",
    );
    let (doc, token) = sent(&api, &a, json!(["access_code"])).await;
    let content = format!("/s/{token}/documents/{doc}/content");
    let (_, h) = open(&api, &token).await;
    let r = call(&api, "GET", &content, &h, None).await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::FORBIDDEN, "CS-AUTH-0003".to_owned())
    );
    ok(
        call(
            &api,
            "POST",
            &format!("/s/{token}/authenticate"),
            &h,
            Some(json!({"method": "access_code", "code": "right-4711"})),
        )
        .await,
        StatusCode::OK,
        "authenticate",
    );
    let r = call(&api, "GET", &content, &h, None).await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::FORBIDDEN, "CS-AUTH-0005".to_owned()),
        "the document before consent"
    );
    ok(
        call(
            &api,
            "POST",
            &format!("/s/{token}/consent"),
            &h,
            Some(json!({"ersd_version": "2026-1"})),
        )
        .await,
        StatusCode::OK,
        "consent",
    );
    let r = call(&api, "GET", &content, &h, None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.starts_with(b"%PDF-"));
    api.db.drop().await;
}

#[tokio::test]
async fn the_document_is_refused_until_the_emailed_code_is_passed() {
    let Some(api) = Api::new("ceremony_auth_otp", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let (doc, token) = sent(&api, &a, json!(["email_otp"])).await;
    let (view, h) = open(&api, &token).await;
    assert_eq!(view["auth_required"], json!(["email_otp"]));
    let r = call(
        &api,
        "GET",
        &format!("/s/{token}/documents/{doc}/content"),
        &h,
        None,
    )
    .await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::FORBIDDEN, "CS-AUTH-0003".to_owned()),
        "the document before the emailed code"
    );
    assert_eq!(view["envelope"]["documents"], json!([]), "{view}");
    assert_eq!(view["fields"], json!([]), "{view}");
    api.db.drop().await;
}

#[tokio::test]
async fn a_recipient_without_a_code_is_served_the_document_on_opening() {
    let Some(api) = Api::new("ceremony_auth_none", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let (doc, token) = sent(&api, &a, json!([])).await;
    let (view, h) = open(&api, &token).await;
    assert_eq!(view["envelope"]["documents"][0]["id"], json!(doc), "{view}");
    let r = call(
        &api,
        "GET",
        &format!("/s/{token}/documents/{doc}/content"),
        &h,
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.starts_with(b"%PDF-"));
    api.db.drop().await;
}
