//! ASVS-04 through the API server and the worker: a user is emailed exactly once each
//! time their password is set from an invitation, changed by themselves or by an
//! administrator, or reset, and when a second factor is added; a change refused (a wrong
//! current password) sends nothing; and no notice carries the password, a link token,
//! the factor's secret or a recovery code.

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
use casual_sign_server::{AppState, Blobs, Config, JwtKeys, totp};
use casual_sign_worker::JobOutcome;
use common::{Env, TestClock};
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use tower::ServiceExt as _;

const PASSWORD: &str = "notice test password 2026";
const ADMIN: &str = "admin@notice.example.test";
const USER: &str = "kim@notice.example.test";
const SET: &str = "kim sets this passphrase";
const OWN: &str = "kim changes it to this one";
const BY_ADMIN: &str = "the administrator chose this";
const RESET: &str = "kim resets it to this one";

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
        let peer: SocketAddr = "198.51.100.81:40000".parse().unwrap();
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

    async fn ok(&self, method: &str, path: &str, body: Option<Value>) -> Value {
        let r = self.call(method, path, body).await;
        assert!(
            r.status.is_success(),
            "{method} {path}: {} {}",
            r.status,
            String::from_utf8_lossy(&r.body)
        );
        r.json()
    }
}

fn anon(app: &axum::Router) -> Http {
    Http {
        app: app.clone(),
        cookie: None,
        csrf: None,
    }
}

async fn session(app: &axum::Router, email: &str, password: &str) -> Http {
    let r = anon(app)
        .call(
            "POST",
            "/api/v1/auth/login",
            Some(json!({"email": email, "password": password})),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let set = r.headers["set-cookie"].to_str().unwrap();
    Http {
        app: app.clone(),
        cookie: Some(set.split(';').next().unwrap().to_owned()),
        csrf: Some(r.json()["csrf_token"].as_str().unwrap().to_owned()),
    }
}

/// The token after `key` in a mail's body (`…?token=…`).
fn token(mail: &common::Mail, key: &str) -> String {
    let body = mail.body();
    let at = body.find(key).expect("a link");
    body[at + key.len()..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect()
}

/// Run the worker; then the mails `USER` got since `seen`, which must all be notices.
async fn notices(env: &Env, seen: &mut usize) -> Vec<String> {
    let out = env.run().await;
    assert!(out.iter().all(|(_, o)| *o == JobOutcome::Done), "{out:?}");
    let mails = env.smtp.to(USER);
    let new: Vec<String> = mails[*seen..].iter().map(common::Mail::body).collect();
    *seen = mails.len();
    new
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_password_or_factor_change_emails_the_user_one_notice_without_secrets() {
    let Some(env) = Env::new("security_notice").await else {
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
    st.set_mfa_key(common::mfa_key());
    let app = casual_sign_server::app(st);
    let org = env.db.organization("Notices").await;
    casual_sign_server::bootstrap_workspace(
        &env.db.store,
        org,
        "Notices",
        ADMIN,
        "Admin",
        PASSWORD,
    )
    .await
    .unwrap();
    let admin = session(&app, ADMIN, PASSWORD).await;
    // An administrator owes a second factor by default (ASVS-31): enrolled at once,
    // which tells the administrator, not the user.
    common::pass_factor(
        &app,
        admin.cookie.as_deref().unwrap(),
        admin.csrf.as_deref().unwrap(),
        env.clock.ms(),
    )
    .await
    .expect("the administrator enrols");

    // Set from an invitation.
    let u = admin
        .ok(
            "POST",
            "/api/v1/users",
            Some(json!({"email": USER, "name": "Kim", "profile": "sender", "invite": true})),
        )
        .await;
    let uid = u["id"].as_str().unwrap().to_owned();
    env.run().await;
    let invitation = env.smtp.to(USER);
    assert_eq!(invitation.len(), 1);
    let mut seen = invitation.len();
    let link = token(&invitation[0], "accept-invite?token=");
    anon(&app)
        .ok(
            "POST",
            "/api/v1/auth/accept-invite",
            Some(json!({"token": link, "password": SET})),
        )
        .await;
    let got = notices(&env, &mut seen).await;
    assert_eq!(got.len(), 1, "one notice for a password set: {got:?}");
    assert!(
        got[0].contains("A password was set for your account"),
        "{}",
        got[0]
    );
    assert!(!got[0].contains(SET) && !got[0].contains(&link));

    // Changed by the user; a refused change sends nothing.
    let kim = session(&app, USER, SET).await;
    let wrong = kim
        .call(
            "PATCH",
            "/api/v1/users/me",
            Some(json!({"password": OWN, "current_password": "not the password"})),
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert!(
        notices(&env, &mut seen).await.is_empty(),
        "a refused change sends nothing"
    );
    kim.ok(
        "PATCH",
        "/api/v1/users/me",
        Some(json!({"password": OWN, "current_password": SET})),
    )
    .await;
    let got = notices(&env, &mut seen).await;
    assert_eq!(got.len(), 1, "one notice for a change: {got:?}");
    assert!(
        got[0].contains("The password of your account was changed"),
        "{}",
        got[0]
    );
    assert!(!got[0].contains(OWN) && !got[0].contains(SET));

    // Changed by an administrator.
    admin
        .ok(
            "PATCH",
            &format!("/api/v1/users/{uid}"),
            Some(json!({"password": BY_ADMIN})),
        )
        .await;
    let got = notices(&env, &mut seen).await;
    assert_eq!(
        got.len(),
        1,
        "one notice for an administrator's change: {got:?}"
    );
    assert!(got[0].contains("The password of your account was changed"));
    assert!(!got[0].contains(BY_ADMIN));

    // Reset: the reset link, then one notice once it is used.
    anon(&app)
        .ok(
            "POST",
            "/api/v1/auth/password-reset",
            Some(json!({"email": USER})),
        )
        .await;
    let got = notices(&env, &mut seen).await;
    assert_eq!(got.len(), 1, "the reset link only");
    let reset = got[0]
        .split("reset-password?token=")
        .nth(1)
        .unwrap()
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect::<String>();
    anon(&app)
        .ok(
            "POST",
            "/api/v1/auth/password-reset/confirm",
            Some(json!({"token": reset, "password": RESET})),
        )
        .await;
    let got = notices(&env, &mut seen).await;
    assert_eq!(got.len(), 1, "one notice for a reset: {got:?}");
    assert!(got[0].contains("was reset with a link"), "{}", got[0]);
    assert!(!got[0].contains(RESET) && !got[0].contains(&reset));

    // A second factor added.
    let kim = session(&app, USER, RESET).await;
    let e = kim.ok("POST", "/api/v1/auth/mfa/totp/enrol", None).await;
    let secret = e["secret"].as_str().unwrap().to_owned();
    let seed = unbase32(&secret);
    let now = casual_sign_worker::Clock::now(env.clock.as_ref()).unix_timestamp();
    let code = totp::code(&seed, totp::step_at(now));
    let c = kim
        .ok(
            "POST",
            "/api/v1/auth/mfa/totp/confirm",
            Some(json!({"code": code})),
        )
        .await;
    let got = notices(&env, &mut seen).await;
    assert_eq!(got.len(), 1, "one notice for a factor added: {got:?}");
    assert!(got[0].contains("authenticator app was added"), "{}", got[0]);
    assert!(!got[0].contains(&secret));
    for r in c["recovery_codes"].as_array().unwrap() {
        assert!(!got[0].contains(r.as_str().unwrap()));
    }
    // Only the user is told of their factor; the administrator only of their own.
    let to_admin = env.smtp.to(ADMIN);
    assert_eq!(to_admin.len(), 1, "only the user is told");
    assert!(to_admin[0].body().contains("authenticator app was added"));
}

/// RFC 4648 base32 (no padding) back to bytes, for the secret the enrolment shows.
fn unbase32(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => unreachable!("not base32"),
        };
        buf = (buf << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buf >> bits) & 0xff).unwrap());
        }
    }
    out
}
