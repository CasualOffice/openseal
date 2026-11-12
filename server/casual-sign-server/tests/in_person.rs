//! UXW-36: `POST /envelopes/{id}/recipients/{r}/host`. A member who may send hosts an
//! in-person signer: the engine records `recipient.in_person_hosted` with the member as
//! host, and the one-time link it returns acts as that member hosting the signer, so
//! the signer completes through the ceremony and every step names the host as actor.
//! Another account's staff, a key without `envelopes:send`, a signer who is not in
//! person, a superseded link and a disabled host are refused.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

mod common;

use axum::http::StatusCode;
use common::Rls;
use common::flow::{b64, invite, jobs, ok, sign};
use common::harness::{Api, Auth, Tenant, ceremony_path, pdf};
use serde_json::{Value, json};

/// A sent envelope with one in-person signer (`ip`) holding one required signature
/// field, then a remote signer (`s2`).
async fn sent(api: &Api, t: &Tenant) -> Value {
    ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            &t.auth,
            Some(json!({
                "subject": "UXW-36", "status": "sent",
                "documents": [{"name": "w.pdf", "content_base64": b64(&pdf(2))}],
                "recipients": [
                    {"ref": "ip", "type": "in_person_signer", "name": "Walk In",
                        "email": "walkin@example.test", "routing_order": 1},
                    {"ref": "s2", "type": "signer", "name": "Remote",
                        "email": "remote@example.test", "routing_order": 2},
                ],
                "fields": [
                    {"recipient": "ip", "document": 0, "type": "signature", "page": 1,
                        "x": 72, "y": 100, "width": 180, "height": 40, "required": true},
                    {"recipient": "s2", "document": 0, "type": "signature", "page": 1,
                        "x": 72, "y": 200, "width": 180, "height": 40, "required": true},
                ],
            })),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "create sent envelope",
    )
}

async fn host(api: &Api, auth: &Auth, env: &str, rec: &str) -> common::harness::Resp {
    api.call(
        "POST",
        &format!("/api/v1/envelopes/{env}/recipients/{rec}/host"),
        auth,
        None,
        &[],
    )
    .await
}

fn token_of(view: &Value) -> String {
    ceremony_path(view["url"].as_str().unwrap())
        .strip_prefix("/s/")
        .unwrap()
        .to_owned()
}

async fn audit(api: &Api, t: &Tenant, env: &str) -> Vec<Value> {
    ok(
        api.call(
            "GET",
            &format!("/api/v1/envelopes/{env}/audit"),
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

#[tokio::test]
async fn a_hosted_in_person_signer_completes_through_the_api() {
    let Some(api) = Api::new("in_person_completes", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let e = sent(&api, &a).await;
    let env = e["id"].as_str().unwrap();
    let ip = e["recipients"][0]["id"].as_str().unwrap();
    let s2 = e["recipients"][1]["id"].as_str().unwrap();

    // Before hosting, the signer's own emailed link cannot act for them.
    let emailed = invite(&api, &a, env, ip).await;
    let r = api
        .call(
            "POST",
            &format!("/s/{emailed}/session"),
            &Auth::None,
            Some(json!({})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{:?}", r.json());

    let view = ok(
        host(&api, &a.auth, env, ip).await,
        StatusCode::CREATED,
        "host",
    );
    assert!(
        view["url"]
            .as_str()
            .unwrap()
            .starts_with("https://sign.example.test/s/")
    );
    assert!(view["expires_at"].is_string());
    // Hosting revoked every earlier link of the signer.
    let r = api
        .call(
            "POST",
            &format!("/s/{emailed}/session"),
            &Auth::None,
            Some(json!({})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{:?}", r.json());

    let (done, _) = sign(&api, &token_of(&view), &[]).await;
    assert_eq!(done["recipient"]["status"], "completed");

    // The routing moves on to the remote signer, who completes the envelope.
    let link = invite(&api, &a, env, s2).await;
    sign(&api, &link, &[]).await;
    let got = ok(
        api.call(
            "GET",
            &format!("/api/v1/envelopes/{env}"),
            &a.auth,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "get",
    );
    // Every recipient finished: the seal job completes it.
    assert_eq!(got["status"], "completing");
    assert!(jobs(&api, env).await.iter().any(|k| k == "seal_envelope"));

    // The chain names the host on the hosting and as the actor of the signer's steps.
    let admin = a.boot.admin.to_string();
    let items = audit(&api, &a, env).await;
    let hosted = items
        .iter()
        .find(|i| i["type"] == "recipient.in_person_hosted")
        .expect("recipient.in_person_hosted");
    assert_eq!(hosted["event"]["data"]["recipient_id"], ip);
    assert_eq!(hosted["event"]["data"]["host_user_id"], admin.as_str());
    assert_eq!(hosted["event"]["actor"]["kind"], "user");
    assert_eq!(hosted["event"]["actor"]["id"], admin.as_str());
    let signed = items
        .iter()
        .find(|i| i["type"] == "recipient.signed" && i["event"]["data"]["recipient_id"] == ip)
        .expect("recipient.signed by the in-person signer");
    assert_eq!(signed["event"]["actor"]["kind"], "user");
    assert_eq!(signed["event"]["actor"]["id"], admin.as_str());
    assert_eq!(signed["event"]["context"]["auth"][0], "account_login");
    api.db.drop().await;
}

#[tokio::test]
async fn hosting_is_refused_to_other_accounts_keys_without_send_and_remote_signers() {
    let Some(api) = Api::new("in_person_refused", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let b = api.tenant("bravo").await;
    let e = sent(&api, &a).await;
    let env = e["id"].as_str().unwrap();
    let ip = e["recipients"][0]["id"].as_str().unwrap();
    let s2 = e["recipients"][1]["id"].as_str().unwrap();

    // Another account's administrator: the envelope does not exist for them.
    let r = host(&api, &b.auth, env, ip).await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::NOT_FOUND, "CS-API-0002"),
        "{:?}",
        r.json()
    );

    // A key of this account without `envelopes:send`.
    let k = ok(
        api.call(
            "POST",
            "/api/v1/api-clients",
            &a.auth,
            Some(json!({"name": "read", "kind": "api_key", "scopes": ["envelopes:read"]})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "read key",
    );
    let read = Auth::Bearer(k["key"].as_str().unwrap().to_owned());
    let r = host(&api, &read, env, ip).await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::FORBIDDEN, "CS-AUTH-0006")
    );

    // A remote signer is not hosted.
    let r = host(&api, &a.auth, env, s2).await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::CONFLICT, "CS-WF-0001"),
        "{:?}",
        r.json()
    );
    // None of the refusals recorded a hosting.
    assert!(
        !audit(&api, &a, env)
            .await
            .iter()
            .any(|i| i["type"] == "recipient.in_person_hosted")
    );

    // Hosting again supersedes the first link; the second works until its host is
    // disabled.
    let first = ok(host(&api, &a.auth, env, ip).await, StatusCode::CREATED, "1");
    let second = ok(host(&api, &a.auth, env, ip).await, StatusCode::CREATED, "2");
    let r = api
        .call(
            "POST",
            &format!("/s/{}/session", token_of(&first)),
            &Auth::None,
            Some(json!({})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{:?}", r.json());
    let path = format!("/s/{}/session", token_of(&second));
    let r = api
        .call("POST", &path, &Auth::None, Some(json!({})), &[])
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let cookie = common::harness::ceremony_cookie(&r);
    sqlx::query("UPDATE account_memberships SET disabled_at = now() WHERE user_id = $1")
        .bind(a.boot.admin.0)
        .execute(&api.db.admin)
        .await
        .unwrap();
    let r = api
        .call(
            "GET",
            &format!("/s/{}", token_of(&second)),
            &Auth::None,
            None,
            &[("cookie", &cookie)],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{:?}", r.json());
    api.db.drop().await;
}
