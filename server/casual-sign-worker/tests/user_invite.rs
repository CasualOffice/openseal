//! User invitations through the API server and the worker (WEB-06): an administrator
//! adds a member by email, the worker mails a one-time link, the member sets a password
//! with it and logs in; the link works once; sending again retires the earlier link;
//! disabling the member ends their session and refuses their login in this account;
//! enabling restores it; an administrator changes a member's profile but not their own.

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

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use casual_sign_server::{AppState, Blobs, Config, JwtKeys};
use casual_sign_worker::JobOutcome;
use common::{Env, TestClock};
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use tower::ServiceExt as _;

const PASSWORD: &str = "invitation test password 2026";
const NEW: &str = "a new long passphrase";

#[derive(Debug)]
struct Shared(Arc<TestClock>);

impl casual_sign_server::Clock for Shared {
    fn now(&self) -> time::OffsetDateTime {
        casual_sign_worker::Clock::now(self.0.as_ref())
    }
}

struct Http {
    app: axum::Router,
    cookie: Option<String>,
    csrf: Option<String>,
}

struct Resp {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: Vec<u8>,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

impl Http {
    async fn call(&self, method: &str, path: &str, body: Option<Value>) -> Resp {
        let mut req = Request::builder().method(method).uri(path);
        if let Some(c) = &self.cookie {
            req = req.header("cookie", c.as_str());
        }
        if let Some(t) = &self.csrf {
            req = req.header("x-csrf-token", t.as_str());
        }
        let body = match body {
            Some(v) => {
                req = req.header("content-type", "application/json");
                Body::from(serde_json::to_vec(&v).unwrap())
            }
            None => Body::empty(),
        };
        let mut req = req.body(body).unwrap();
        let peer: SocketAddr = "198.51.100.78:40000".parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        Resp {
            status,
            headers,
            body,
        }
    }

    async fn ok(&self, method: &str, path: &str, body: Option<Value>, want: StatusCode) -> Value {
        let r = self.call(method, path, body).await;
        assert_eq!(
            r.status,
            want,
            "{method} {path}: {}",
            String::from_utf8_lossy(&r.body)
        );
        r.json()
    }
}

/// The token of a user invitation's link (`…/#/accept-invite?token=…`).
fn invite_token(mail: &common::Mail) -> String {
    let body = mail.body();
    let key = "accept-invite?token=";
    let at = body.find(key).expect("an invitation link");
    body[at + key.len()..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect()
}

fn anon(app: &axum::Router) -> Http {
    Http {
        app: app.clone(),
        cookie: None,
        csrf: None,
    }
}

async fn login(app: &axum::Router, email: &str, password: &str) -> Resp {
    anon(app)
        .call(
            "POST",
            "/api/v1/auth/login",
            Some(json!({"email": email, "password": password})),
        )
        .await
}

fn session(app: &axum::Router, r: &Resp) -> Http {
    let set = r.headers["set-cookie"].to_str().unwrap();
    Http {
        app: app.clone(),
        cookie: Some(set.split(';').next().unwrap().to_owned()),
        csrf: Some(r.json()["csrf_token"].as_str().unwrap().to_owned()),
    }
}

async fn accept(app: &axum::Router, token: &str, password: &str) -> Resp {
    anon(app)
        .call(
            "POST",
            "/api/v1/auth/accept-invite",
            Some(json!({"token": token, "password": password})),
        )
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invited_user_sets_a_password_once_and_can_be_disabled() {
    let Some(env) = Env::new("user_invite").await else {
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
    // `Env` already made an organization; this workspace gets one of its own.
    let org = env.db.organization("Invites").await;
    casual_sign_server::bootstrap_workspace(
        &env.db.store,
        org,
        "Invites",
        "admin@inv.example.test",
        "Admin",
        PASSWORD,
    )
    .await
    .unwrap();
    let admin = session(&app, &login(&app, "admin@inv.example.test", PASSWORD).await);

    let u = admin
        .ok(
            "POST",
            "/api/v1/users",
            Some(
                json!({"email": "new@inv.example.test", "name": "New Person",
                "profile": "sender", "invite": true}),
            ),
            StatusCode::CREATED,
        )
        .await;
    assert_eq!(u["invitation"], "pending", "{u}");
    let uid = u["id"].as_str().unwrap().to_owned();
    // No password yet: no login.
    assert_eq!(
        login(&app, "new@inv.example.test", NEW).await.status,
        StatusCode::UNAUTHORIZED
    );
    let out = env.run().await;
    assert!(out.iter().all(|(_, o)| *o == JobOutcome::Done), "{out:?}");
    let mails = env.smtp.to("new@inv.example.test");
    assert_eq!(mails.len(), 1);
    assert!(mails[0].body().contains("/#/accept-invite?token="));
    let first = invite_token(&mails[0]);
    // Only the token's hash is stored.
    let stored: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM user_invitations \
         WHERE token_sha256 = sha256(convert_to($1, 'UTF8'))",
    )
    .bind(&first)
    .fetch_one(&env.db.admin)
    .await
    .unwrap();
    assert_eq!(stored, 1);

    // Sending again retires the first link.
    let again = admin
        .ok(
            "POST",
            &format!("/api/v1/users/{uid}/invite"),
            None,
            StatusCode::ACCEPTED,
        )
        .await;
    assert_eq!(again["invitation"], "pending");
    env.run().await;
    let mails = env.smtp.to("new@inv.example.test");
    assert_eq!(mails.len(), 2);
    let second = invite_token(&mails[1]);
    assert_ne!(first, second);
    let old = accept(&app, &first, NEW).await;
    assert_eq!(
        (old.status, old.json()["code"].clone()),
        (StatusCode::UNAUTHORIZED, json!("CS-AUTH-0002"))
    );
    assert_eq!(
        accept(&app, &second, "short").await.status,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let ok = accept(&app, &second, NEW).await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.json());
    assert_eq!(ok.json()["user_id"], uid.as_str());
    // Once only.
    assert_eq!(
        accept(&app, &second, "another long passphrase")
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    let member = login(&app, "new@inv.example.test", NEW).await;
    assert_eq!(member.status, StatusCode::OK, "{:?}", member.json());
    let me = session(&app, &member);
    me.ok("GET", "/api/v1/envelopes", None, StatusCode::OK)
        .await;
    let got = admin
        .ok("GET", &format!("/api/v1/users/{uid}"), None, StatusCode::OK)
        .await;
    assert_eq!(got["invitation"], "accepted");

    // Profile change; then disable: the session ends and login is refused; enable.
    let viewer = admin
        .ok(
            "PATCH",
            &format!("/api/v1/users/{uid}"),
            Some(json!({"profile": "viewer"})),
            StatusCode::OK,
        )
        .await;
    assert_ne!(viewer["permission_profile_id"], u["permission_profile_id"]);
    let off = admin
        .ok(
            "PATCH",
            &format!("/api/v1/users/{uid}"),
            Some(json!({"disabled": true})),
            StatusCode::OK,
        )
        .await;
    assert_eq!(off["disabled"], true);
    assert_eq!(
        me.call("GET", "/api/v1/envelopes", None).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        login(&app, "new@inv.example.test", NEW).await.status,
        StatusCode::UNAUTHORIZED
    );
    let resend = admin
        .call("POST", &format!("/api/v1/users/{uid}/invite"), None)
        .await;
    assert_eq!(resend.status, StatusCode::UNPROCESSABLE_ENTITY);
    admin
        .ok(
            "PATCH",
            &format!("/api/v1/users/{uid}"),
            Some(json!({"disabled": false})),
            StatusCode::OK,
        )
        .await;
    assert_eq!(
        login(&app, "new@inv.example.test", NEW).await.status,
        StatusCode::OK
    );
    // An administrator cannot disable themselves.
    let me_id = admin
        .ok("GET", "/api/v1/auth/session", None, StatusCode::OK)
        .await["user_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let selfish = admin
        .call(
            "PATCH",
            &format!("/api/v1/users/{me_id}"),
            Some(json!({"disabled": true})),
        )
        .await;
    assert_eq!(selfish.status, StatusCode::UNPROCESSABLE_ENTITY);
}
