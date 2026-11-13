//! UXW-31..33, UXW-37..39: the calls the web app made only against its mock until now.
//! Webhooks are edited, paused, tested and delivered again through the worker's queue,
//! with the SSRF refusal kept; a member reads and changes their own profile, and a
//! password change needs the current one and ends their other sessions; a password reset
//! answers alike for any address, records a hashed, single-use, expiring link and queues
//! its email; sign-in lists no SSO providers until SSO exists.

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
use base64::Engine as _;
use casual_sign_store::PasswordResetId;
use common::Rls;
use common::harness::{Api, Auth, PASSWORD, png, session_of};
use serde_json::json;
use sqlx::Row;

const NEW: &str = "a brand new passphrase";

async fn login(api: &Api, email: &str, password: &str) -> Option<Auth> {
    let r = api
        .call(
            "POST",
            "/api/v1/auth/login",
            &Auth::None,
            Some(json!({"email": email, "password": password})),
            &[],
        )
        .await;
    (r.status == StatusCode::OK).then(|| session_of(&r))
}

async fn alive(api: &Api, s: &Auth) -> bool {
    api.call("GET", "/api/v1/auth/session", s, None, &[])
        .await
        .status
        == StatusCode::OK
}

async fn jobs(api: &Api, kind: &str) -> i64 {
    sqlx::query("SELECT count(*) FROM jobs WHERE kind = $1")
        .bind(kind)
        .fetch_one(&api.db.admin)
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
async fn webhooks_are_edited_tested_and_delivered_again_through_the_worker() {
    let Some(api) = Api::new("self_service_webhooks", Rls::On).await else {
        return;
    };
    let t = api.tenant("alpha").await;
    let k = &t.auth;
    let r = api
        .call("POST", "/api/v1/webhooks", k, Some(json!({"url": "https://hooks.example.com/os", "event_types": ["envelope.completed"], "secret_refs": ["primary"]})), &[])
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.json());
    let w = r.json()["id"].as_str().unwrap().to_owned();
    let path = format!("/api/v1/webhooks/{w}");

    // UXW-31: edit, and refuse a URL that is not public HTTPS (SEC-W01).
    let r = api
        .call(
            "PATCH",
            &path,
            k,
            Some(
                json!({"url": "https://hooks.example.com/v2", "event_types": ["envelope.voided"]}),
            ),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    assert_eq!(r.json()["url"], "https://hooks.example.com/v2");
    assert_eq!(r.json()["event_types"], json!(["envelope.voided"]));
    for url in ["http://hooks.example.com/x", "https://127.0.0.1/x"] {
        let r = api
            .call("PATCH", &path, k, Some(json!({"url": url})), &[])
            .await;
        assert_eq!(r.code(), "CS-API-0013", "{url}");
    }
    let r = api
        .call(
            "PATCH",
            &path,
            k,
            Some(json!({"event_types": ["no.such"]})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);

    // UXW-32: a test event is recorded and queued for the worker.
    let before = jobs(&api, "send_webhook_delivery").await;
    let r = api
        .call("POST", &format!("{path}/test"), k, None, &[])
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.json());
    assert_eq!(r.json()["event_type"], "webhook.test");
    assert_eq!(r.json()["status"], "pending");
    let d = r.json()["id"].as_str().unwrap().to_owned();
    assert_eq!(jobs(&api, "send_webhook_delivery").await, before + 1);
    let r = api
        .call("GET", &format!("{path}/deliveries"), k, None, &[])
        .await;
    assert!(
        r.json()["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["id"] == d.as_str()),
        "{:?}",
        r.json()
    );

    // UXW-33: deliver it again; another account's subscription, or a delivery of
    // another subscription, is not found.
    sqlx::query("UPDATE webhook_deliveries SET status = 'failed' WHERE id = $1")
        .bind(uuid::Uuid::parse_str(&d).unwrap())
        .execute(&api.db.admin)
        .await
        .unwrap();
    let again = format!("{path}/deliveries/{d}/redeliver");
    let r = api.call("POST", &again, k, None, &[]).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.json());
    assert_eq!(r.json()["status"], "pending");
    assert_eq!(jobs(&api, "send_webhook_delivery").await, before + 2);
    let bravo = api.tenant("bravo").await;
    let r = api.call("POST", &again, &bravo.auth, None, &[]).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    // The SSRF refusal stays: a stored URL that is no longer acceptable is refused.
    sqlx::query("UPDATE webhook_subscriptions SET url = 'https://10.0.0.1/x' WHERE id = $1")
        .bind(uuid::Uuid::parse_str(&w).unwrap())
        .execute(&api.db.admin)
        .await
        .unwrap();
    for p in [again.clone(), format!("{path}/test")] {
        let r = api.call("POST", &p, k, None, &[]).await;
        assert_eq!(r.code(), "CS-API-0013", "{p}");
    }

    // Paused: nothing is sent.
    let r = api
        .call("PATCH", &path, k, Some(json!({"active": false})), &[])
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    for p in [again, format!("{path}/test")] {
        let r = api.call("POST", &p, k, None, &[]).await;
        assert_eq!(
            (r.status, r.code()),
            (StatusCode::CONFLICT, "CS-API-0009".into()),
            "{p}"
        );
    }
    api.db.drop().await;
}

#[tokio::test]
async fn a_member_changes_their_own_profile_and_password() {
    let Some(api) = Api::new("self_service_profile", Rls::On).await else {
        return;
    };
    let t = api.tenant("alpha").await;
    let s = login(&api, &t.email, PASSWORD).await.unwrap();
    let other = login(&api, &t.email, PASSWORD).await.unwrap();
    let r = api.call("GET", "/api/v1/users/me", &s, None, &[]).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let me = r.json();
    assert_eq!(me["email"], t.email.as_str());
    assert_eq!(
        me["notifications"],
        json!({"completed": true, "declined": true, "viewed": false})
    );
    assert_eq!(me["signature"], json!(null));

    let mark = base64::engine::general_purpose::STANDARD.encode(png());
    let r = api
        .call("PATCH", "/api/v1/users/me", &s, Some(json!({"name": "Ada Admin", "notifications": {"viewed": true}, "signature": {"image_base64": mark}})), &[])
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let r = api.call("GET", "/api/v1/users/me", &s, None, &[]).await;
    assert_eq!(r.json()["name"], "Ada Admin");
    assert_eq!(r.json()["notifications"]["viewed"], true);
    assert_eq!(r.json()["notifications"]["completed"], true);
    assert_eq!(r.json()["signature"]["image_base64"], mark.as_str());
    let r = api
        .call(
            "PATCH",
            "/api/v1/users/me",
            &s,
            Some(json!({"signature": null})),
            &[],
        )
        .await;
    assert_eq!(r.json()["signature"], json!(null));
    for bad in [
        json!({"signature": {"image_base64": "bm90IGFuIGltYWdl"}}),
        json!({"notifications": {"spam": true}}),
        json!({"email": "x@y.example"}),
    ] {
        let r = api
            .call("PATCH", "/api/v1/users/me", &s, Some(bad.clone()), &[])
            .await;
        assert!(r.status.is_client_error(), "{bad}: {:?}", r.status);
    }
    // An API key cannot change the user's password or name.
    let r = api
        .call(
            "PATCH",
            "/api/v1/users/me",
            &t.auth,
            Some(json!({"password": NEW, "current_password": PASSWORD})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);

    // The password: the current one is required, and other sessions end.
    let r = api
        .call(
            "PATCH",
            "/api/v1/users/me",
            &s,
            Some(json!({"password": NEW, "current_password": "wrong password!"})),
            &[],
        )
        .await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::UNAUTHORIZED, "CS-AUTH-0007".into())
    );
    assert!(alive(&api, &other).await);
    let r = api
        .call(
            "PATCH",
            "/api/v1/users/me",
            &s,
            Some(json!({"password": NEW, "current_password": PASSWORD})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    assert!(alive(&api, &s).await, "the changing session stays");
    assert!(!alive(&api, &other).await, "other sessions end");
    assert!(login(&api, &t.email, PASSWORD).await.is_none());
    assert!(login(&api, &t.email, NEW).await.is_some());
    api.db.drop().await;
}

#[tokio::test]
async fn a_password_reset_answers_alike_and_its_link_works_once() {
    let Some(api) = Api::new("self_service_reset", Rls::On).await else {
        return;
    };
    let t = api.tenant("alpha").await;
    let s = login(&api, &t.email, PASSWORD).await.unwrap();
    let reset = |email: String| {
        let api = &api;
        async move {
            api.call(
                "POST",
                "/api/v1/auth/password-reset",
                &Auth::None,
                Some(json!({"email": email})),
                &[],
            )
            .await
        }
    };
    // No enumeration: the same answer for an address with and without an account.
    let known = reset(t.email.to_uppercase()).await;
    let unknown = reset("nobody@alpha.example.test".into()).await;
    assert_eq!(known.status, StatusCode::ACCEPTED);
    assert_eq!((known.status, &known.body), (unknown.status, &unknown.body));
    let rows: Vec<(uuid::Uuid, Option<Vec<u8>>)> =
        sqlx::query_as("SELECT id, token_sha256 FROM password_resets")
            .fetch_all(&api.db.admin)
            .await
            .unwrap();
    assert_eq!(rows.len(), 1, "one reset, for the known address only");
    assert_eq!(rows[0].1, None, "no token before the worker sends it");
    assert_eq!(jobs(&api, "send_password_reset").await, 1);
    // A second request within the minute sends nothing more.
    assert_eq!(reset(t.email.clone()).await.status, StatusCode::ACCEPTED);
    assert_eq!(jobs(&api, "send_password_reset").await, 1);
    // The reset and its job are one statement (SEC-A13: no extra round trip for a known
    // address): a job that cannot be queued records no reset either.
    let other = api.tenant("bravo").await;
    let now = common::harness::start();
    let mut bad = casual_sign_host::jobs::password_reset_job(
        casual_sign_store::JobId(uuid::Uuid::now_v7()),
        uuid::Uuid::now_v7(),
        now,
    );
    bad.kind = "Not A Kind".into();
    let refused = api
        .db
        .store
        .entry_points()
        .request_password_reset(
            &other.email.to_lowercase(),
            PasswordResetId(uuid::Uuid::now_v7()),
            &bad,
            now,
        )
        .await;
    assert!(refused.is_err(), "{refused:?}");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM password_resets")
        .fetch_one(&api.db.admin)
        .await
        .unwrap();
    assert_eq!(n, 1, "no reset without its job");

    // The worker's part: only the token's hash is stored, with an hour's expiry.
    let token = "test-reset-token-0123456789abcdefghijklmnop";
    let now = common::harness::start();
    let mut tx = api
        .db
        .store
        .for_account(t.boot.account)
        .begin()
        .await
        .unwrap();
    assert!(
        tx.users()
            .set_password_reset_token(
                PasswordResetId(rows[0].0),
                &casual_sign_audit::Hash256::digest(token.as_bytes()).0,
                now + time::Duration::hours(1),
                now,
            )
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();

    let confirm = |token: &str| {
        api.call(
            "POST",
            "/api/v1/auth/password-reset/confirm",
            &Auth::None,
            Some(json!({"token": token, "password": NEW})),
            &[],
        )
    };
    let r = confirm("wrong-token").await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::UNAUTHORIZED, "CS-AUTH-0002".into())
    );
    let r = confirm(token).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    assert!(!alive(&api, &s).await, "sessions end with a reset");
    assert!(login(&api, &t.email, NEW).await.is_some());
    // Single use.
    let r = confirm(token).await;
    assert_eq!(r.code(), "CS-AUTH-0002");
    api.db.drop().await;
}

#[tokio::test]
async fn an_expired_reset_link_is_refused() {
    let Some(api) = Api::new("self_service_reset_expiry", Rls::On).await else {
        return;
    };
    let t = api.tenant("alpha").await;
    let r = api
        .call(
            "POST",
            "/api/v1/auth/password-reset",
            &Auth::None,
            Some(json!({"email": t.email})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    let id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM password_resets")
        .fetch_one(&api.db.admin)
        .await
        .unwrap();
    let token = "expired-reset-token-0123456789abcdefghij";
    let now = common::harness::start();
    let mut tx = api
        .db
        .store
        .for_account(t.boot.account)
        .begin()
        .await
        .unwrap();
    tx.users()
        .set_password_reset_token(
            PasswordResetId(id),
            &casual_sign_audit::Hash256::digest(token.as_bytes()).0,
            now + time::Duration::hours(1),
            now,
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    api.clock.advance(std::time::Duration::from_secs(3601));
    let r = api
        .call(
            "POST",
            "/api/v1/auth/password-reset/confirm",
            &Auth::None,
            Some(json!({"token": token, "password": NEW})),
            &[],
        )
        .await;
    assert_eq!(r.code(), "CS-AUTH-0002");
    assert!(login(&api, &t.email, PASSWORD).await.is_some());
    api.db.drop().await;
}

#[tokio::test]
async fn sign_in_lists_no_sso_providers_yet() {
    let Some(api) = Api::new("self_service_providers", Rls::On).await else {
        return;
    };
    let r = api
        .call("GET", "/api/v1/auth/providers", &Auth::None, None, &[])
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json(), json!({"items": []}));
    api.db.drop().await;
}
