//! UXW-32, UXW-33 and UXW-38 through the worker. A password reset asked through the API
//! is emailed by the worker; an email the mail server refused for now is sent again with
//! a fresh link, the link works once and ends the user's other sessions. A test event and
//! a redelivery the server queues are signed and sent to the subscription, the same
//! event id each time, and recorded; a paused subscription sends nothing, and a URL the
//! SSRF policy refuses fails without a retry.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines
)]

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use casual_sign_server::{AppState, Blobs, Config, JwtKeys};
use casual_sign_store::repo::webhooks::Delivery;
use casual_sign_store::{JobId, WebhookDeliveryId, WebhookSubscriptionId};
use casual_sign_worker::JobOutcome;
use common::{Env, SECRET, TestClock};
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use tower::ServiceExt as _;
use uuid::Uuid;

const PASSWORD: &str = "reset test password 2026";
const NEW: &str = "a new long passphrase";
const ADMIN: &str = "admin@reset.example.test";

#[derive(Debug)]
struct Shared(Arc<TestClock>);

impl casual_sign_server::Clock for Shared {
    fn now(&self) -> time::OffsetDateTime {
        casual_sign_worker::Clock::now(self.0.as_ref())
    }
}

struct Resp {
    status: StatusCode,
    cookie: Option<String>,
    body: Vec<u8>,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

async fn call(
    app: &axum::Router,
    method: &str,
    path: &str,
    cookie: Option<&str>,
    body: Option<Value>,
) -> Resp {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(c) = cookie {
        req = req.header("cookie", c);
    }
    let body = match body {
        Some(v) => {
            req = req.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&v).unwrap())
        }
        None => Body::empty(),
    };
    let mut req = req.body(body).unwrap();
    let peer: SocketAddr = "198.51.100.79:40000".parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(peer));
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let cookie = resp
        .headers()
        .get("set-cookie")
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned());
    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    Resp {
        status,
        cookie,
        body,
    }
}

async fn login(app: &axum::Router, password: &str) -> Resp {
    call(
        app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(json!({"email": ADMIN, "password": password})),
    )
    .await
}

/// The token of a reset link (`…/#/reset-password?token=…`).
fn reset_token(mail: &common::Mail) -> String {
    let body = mail.body();
    let key = "reset-password?token=";
    let at = body.find(key).expect("a reset link");
    body[at + key.len()..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reset_email_refused_for_now_is_sent_again_and_its_link_works_once() {
    let Some(env) = Env::new("self_service_reset").await else {
        return;
    };
    let st = AppState::new(
        env.db.store.clone(),
        Blobs::Fs(Arc::new(env.blob_store())),
        JwtKeys::generate().unwrap(),
        Arc::new(Shared(Arc::clone(&env.clock))),
        Config {
            public_url: "https://sign.example.test".into(),
            ..Config::default()
        },
    )
    .unwrap();
    let app = casual_sign_server::app(st);
    let org = env.db.organization("Resets").await;
    casual_sign_server::bootstrap_workspace(&env.db.store, org, "Resets", ADMIN, "Admin", PASSWORD)
        .await
        .unwrap();
    let before = login(&app, PASSWORD).await;
    assert_eq!(before.status, StatusCode::OK);
    let old_session = before.cookie.unwrap();

    // The mail server refuses the first attempt for now: the job is retried.
    env.smtp.tempfail.lock().unwrap().push(ADMIN.to_owned());
    let r = call(
        &app,
        "POST",
        "/api/v1/auth/password-reset",
        None,
        Some(json!({"email": ADMIN})),
    )
    .await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    let out = env.run().await;
    assert!(
        out.iter()
            .any(|(k, o)| k == "send_password_reset" && matches!(o, JobOutcome::Retry(_))),
        "{out:?}"
    );
    assert!(env.smtp.to(ADMIN).is_empty());

    // Accepted on the next attempt, with a link that works.
    env.smtp.tempfail.lock().unwrap().clear();
    env.clock.advance(Duration::from_secs(600));
    let out = env.run().await;
    assert!(out.iter().all(|(_, o)| *o == JobOutcome::Done), "{out:?}");
    let mails = env.smtp.to(ADMIN);
    assert_eq!(
        mails.len(),
        1,
        "the reset email is sent again after a refusal"
    );
    let token = reset_token(&mails[0]);
    let stored: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM password_resets WHERE token_sha256 = sha256(convert_to($1, 'UTF8'))",
    )
    .bind(&token)
    .fetch_one(&env.db.admin)
    .await
    .unwrap();
    assert_eq!(stored, 1, "only the link's hash is stored");

    let confirm = |t: String, p: &'static str| {
        let app = app.clone();
        async move {
            call(
                &app,
                "POST",
                "/api/v1/auth/password-reset/confirm",
                None,
                Some(json!({"token": t, "password": p})),
            )
            .await
        }
    };
    let ok = confirm(token.clone(), NEW).await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.json());
    let again = confirm(token, "another long passphrase").await;
    assert_eq!(
        (again.status, again.json()["code"].clone()),
        (StatusCode::UNAUTHORIZED, json!("CS-AUTH-0002"))
    );
    assert_eq!(
        call(
            &app,
            "GET",
            "/api/v1/auth/session",
            Some(&old_session),
            None
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED,
        "a reset ends the user's sessions"
    );
    assert_eq!(login(&app, PASSWORD).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(login(&app, NEW).await.status, StatusCode::OK);
}

/// Record a delivery and queue its job, as `POST /webhooks/{id}/test` and
/// `…/redeliver` do (the server refuses the loopback receiver's URL, SEC-W01).
async fn queue(env: &Env, sub: Uuid, delivery: Option<&Delivery>) -> Delivery {
    let mut tx = env.db.store.for_account(env.account).begin().await.unwrap();
    let d = if let Some(d) = delivery {
        tx.webhooks().requeue(d.id).await.unwrap();
        d.clone()
    } else {
        let event = Uuid::now_v7();
        let d = Delivery {
            id: WebhookDeliveryId(Uuid::now_v7()),
            subscription_id: WebhookSubscriptionId(sub),
            event_id: event,
            event_type: "webhook.test".into(),
            payload: json!({"id": event.to_string(), "type": "webhook.test",
                "account_id": env.account.0.to_string(), "data": {"subscription_id": sub.to_string()}}),
            status: "pending".into(),
            attempts: 0,
            last_status_code: None,
        };
        tx.webhooks().record_delivery(&d).await.unwrap();
        d
    };
    let job = casual_sign_host::jobs::webhook_delivery_job(
        JobId(Uuid::now_v7()),
        d.id.0,
        casual_sign_worker::Clock::now(env.clock.as_ref()),
    );
    tx.jobs().enqueue(&job).await.unwrap();
    tx.commit().await.unwrap();
    d
}

async fn status(env: &Env, d: &Delivery) -> (String, i32) {
    sqlx::query_as("SELECT status, attempts FROM webhook_deliveries WHERE id = $1")
        .bind(d.id.0)
        .fetch_one(&env.db.admin)
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_test_event_and_a_redelivery_are_signed_sent_and_recorded() {
    let Some(env) = Env::new("self_service_webhooks").await else {
        return;
    };
    let sub = env.subscribe(&["envelope.completed"]).await;
    let d = queue(&env, sub, None).await;
    let out = env.run().await;
    assert!(out.iter().all(|(_, o)| *o == JobOutcome::Done), "{out:?}");
    let got = env.hook.requests();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].headers["webhook-id"], d.event_id.to_string());
    let ts: i64 = got[0].headers["webhook-timestamp"].parse().unwrap();
    let key = casual_sign_worker::webhook::secret_key(SECRET).unwrap();
    let want =
        casual_sign_worker::webhook::signature(&[key], &d.event_id.to_string(), ts, &got[0].body);
    assert_eq!(got[0].headers["webhook-signature"], want);
    assert_eq!(status(&env, &d).await, ("delivered".into(), 1));

    // Delivered again: the same event id and body, recorded as a second attempt.
    queue(&env, sub, Some(&d)).await;
    env.run().await;
    let got = env.hook.requests();
    assert_eq!(got.len(), 2);
    assert_eq!(got[1].headers["webhook-id"], d.event_id.to_string());
    assert_eq!(got[1].body, got[0].body);
    assert_eq!(status(&env, &d).await, ("delivered".into(), 2));

    // Paused meanwhile: nothing is sent.
    let mut tx = env.db.store.for_account(env.account).begin().await.unwrap();
    tx.webhooks()
        .update(WebhookSubscriptionId(sub), None, None, Some(false))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    queue(&env, sub, Some(&d)).await;
    env.run().await;
    assert_eq!(env.hook.requests().len(), 2);

    // Resumed, but the receiver's address is not allowed: failed, not retried (SEC-W01).
    let mut tx = env.db.store.for_account(env.account).begin().await.unwrap();
    tx.webhooks()
        .update(WebhookSubscriptionId(sub), None, None, Some(true))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    env.allow_loopback.store(false, Ordering::SeqCst);
    let d2 = queue(&env, sub, None).await;
    let out = env.run().await;
    assert!(out.iter().all(|(_, o)| *o == JobOutcome::Done), "{out:?}");
    assert_eq!(env.hook.requests().len(), 2);
    assert_eq!(status(&env, &d2).await.0, "failed");
}
