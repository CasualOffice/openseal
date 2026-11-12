//! Email one-time code authentication (SEC-A02) through the API server and the worker:
//! a sender requires `email_otp`; the signer asks for a code (`POST /s/{token}/otp`),
//! the worker draws it, stores only its Argon2id hash and emails it; the signer enters
//! it (`POST /s/{token}/otp/verify`). Shown: resends are limited; an expired code, a
//! superseded code and a replayed (used) code are refused; a wrong code five times locks
//! the recipient and revokes the link; the chain records challenged, failed and passed;
//! and the code is never in the chain, a job, a job step or any log line, in clear.
//!
//! Needs `OPENSEAL_TEST_DATABASE_URL`; without it the test prints a note and passes
//! vacuously, as the store's tests do.

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

use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use casual_sign_server::{AppState, Blobs, Config, JwtKeys};
use common::{Env, TestClock};
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use tower::ServiceExt as _;

const PASSWORD: &str = "one-time code password 2026";

#[derive(Debug)]
struct Shared(Arc<TestClock>);

impl casual_sign_server::Clock for Shared {
    fn now(&self) -> time::OffsetDateTime {
        casual_sign_worker::Clock::now(self.0.as_ref())
    }
}

/// Every log line of this test binary, at TRACE.
#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl Write for Logs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
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

/// Open the signing link in `email`'s invitation in a new browser.
async fn open(env: &Env, app: &axum::Router, email: &str) -> (Http, String, Value) {
    let mails = env.smtp.to(email);
    let token = mails[0].token().expect("a signing link");
    let s = format!("/s/{token}");
    let mut c = Http {
        app: app.clone(),
        cookie: None,
        csrf: None,
    };
    let opened = c
        .call("POST", &format!("{s}/session"), Some(json!({})))
        .await;
    assert_eq!(opened.status, StatusCode::OK, "{:?}", opened.json());
    let set = opened.headers["set-cookie"].to_str().unwrap();
    c.cookie = Some(set.split(';').next().unwrap().to_owned());
    let view = opened.json();
    (c, s, view)
}

/// The code in the latest one-time code email to `email`, and how many there were.
fn code_in(env: &Env, email: &str) -> (String, usize) {
    let mails: Vec<_> = env
        .smtp
        .to(email)
        .into_iter()
        .filter(|m| m.body().contains("Your code: "))
        .collect();
    let body = mails.last().expect("a code email").body();
    let code = body
        .split("Your code: ")
        .nth(1)
        .unwrap()
        .chars()
        .take(6)
        .collect::<String>();
    assert!(code.bytes().all(|b| b.is_ascii_digit()) && code.len() == 6);
    (code, mails.len())
}

fn events(chain: &Value, recipient: &str, kind: &str) -> usize {
    chain["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| {
            e["type"] == kind
                && e["event"]["data"]["recipient_id"] == recipient
                && e["event"]["data"]["method"] == "email_otp"
        })
        .count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_emailed_one_time_code_authenticates_once_and_locks_after_wrong_tries() {
    let logs = Logs::default();
    let sink = logs.clone();
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::TRACE)
        .with_ansi(false)
        .with_writer(move || sink.clone())
        .try_init();
    let Some(env) = Env::new("email_otp").await else {
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
    let org = env.db.organization("Codes").await;
    casual_sign_server::bootstrap_workspace(
        &env.db.store,
        org,
        "Codes",
        "admin@otp.example.test",
        "Admin",
        PASSWORD,
    )
    .await
    .unwrap();
    let mut staff = Http {
        app: app.clone(),
        cookie: None,
        csrf: None,
    };
    let login = staff
        .call(
            "POST",
            "/api/v1/auth/login",
            Some(json!({"email": "admin@otp.example.test", "password": PASSWORD})),
        )
        .await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.json());
    let set = login.headers["set-cookie"].to_str().unwrap();
    staff.cookie = Some(set.split(';').next().unwrap().to_owned());
    staff.csrf = Some(login.json()["csrf_token"].as_str().unwrap().to_owned());
    // The account locks a recipient after five failed attempts.
    let mut policy = serde_json::to_value(casual_sign_workflow::Policy::default()).unwrap();
    policy["max_auth_attempts"] = json!(5);
    staff
        .ok(
            "PATCH",
            "/api/v1/accounts/me",
            Some(json!({"settings": {"workflow_policy": policy}})),
            StatusCode::OK,
        )
        .await;

    // A recipient requiring a code must have an email address.
    let no_email = staff
        .call(
            "POST",
            "/api/v1/envelopes",
            Some(json!({"subject": "x", "recipients": [
                {"type": "signer", "name": "No Mail", "auth": ["email_otp"], "delivery": "none"}]})),
        )
        .await;
    assert_eq!(
        no_email.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{:?}",
        no_email.json()
    );

    let pdf = base64::engine::general_purpose::STANDARD.encode(&env.original);
    let sig = |r: &str, y: u32| {
        json!({"recipient": r, "document": 0, "type": "signature", "page": 1,
               "x": 72, "y": y, "width": 180, "height": 40, "required": true})
    };
    let e = staff
        .ok(
            "POST",
            "/api/v1/envelopes",
            Some(json!({
                "subject": "Code-protected agreement", "status": "sent",
                "documents": [{"name": "nda.pdf", "content_base64": pdf}],
                "recipients": [
                    {"ref": "a", "type": "signer", "name": "Ada Lovelace", "email": "ada@otp.example.test", "auth": ["email_otp"]},
                    {"ref": "g", "type": "signer", "name": "Grace Hopper", "email": "grace@otp.example.test", "auth": ["email_otp"]},
                ],
                "fields": [sig("a", 100), sig("g", 160)],
            })),
            StatusCode::CREATED,
        )
        .await;
    let id = e["id"].as_str().unwrap().to_owned();
    assert_eq!(e["recipients"][0]["auth"], json!(["email_otp"]), "{e}");
    let ada_id = e["recipients"][0]["id"].as_str().unwrap().to_owned();
    let grace_id = e["recipients"][1]["id"].as_str().unwrap().to_owned();
    env.run().await;

    // Ada: the page asks for a code; asking sends one, once per 30 seconds.
    let (ada, s, view) = open(&env, &app, "ada@otp.example.test").await;
    assert_eq!(view["auth_required"], json!(["email_otp"]), "{view}");
    ada.ok(
        "POST",
        &format!("{s}/otp"),
        Some(json!({})),
        StatusCode::ACCEPTED,
    )
    .await;
    let again = ada.call("POST", &format!("{s}/otp"), Some(json!({}))).await;
    assert_eq!(again.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(again.json()["code"], "CS-API-0003");
    assert!(again.headers.contains_key("retry-after"));
    env.run().await;
    let (first, n) = code_in(&env, "ada@otp.example.test");
    assert_eq!(n, 1, "one code sent");
    let mut codes = vec![first.clone()];

    // Only its Argon2id hash is stored, and one code is open.
    let stored: Vec<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT code_hash, closed_reason FROM recipient_otp_codes WHERE recipient_id = $1::uuid",
    )
    .bind(&ada_id)
    .fetch_all(&env.db.admin)
    .await
    .unwrap();
    assert_eq!(stored.len(), 1);
    assert!(stored[0].0.as_deref().unwrap().starts_with("$argon2id$"));
    assert!(!stored[0].0.as_deref().unwrap().contains(&first));

    // Expired after 10 minutes: refused.
    env.clock.advance(Duration::from_secs(601));
    let late = ada
        .call(
            "POST",
            &format!("{s}/otp/verify"),
            Some(json!({"code": first})),
        )
        .await;
    assert_eq!(late.status, StatusCode::FORBIDDEN, "{:?}", late.json());
    assert_eq!(late.json()["auth_required"], json!(["email_otp"]));

    // A new code supersedes the first: the first no longer works.
    ada.ok(
        "POST",
        &format!("{s}/otp"),
        Some(json!({})),
        StatusCode::ACCEPTED,
    )
    .await;
    env.run().await;
    let (second, n) = code_in(&env, "ada@otp.example.test");
    assert_eq!(n, 2);
    codes.push(second.clone());
    if second != first {
        let old = ada
            .call(
                "POST",
                &format!("{s}/otp/verify"),
                Some(json!({"code": first})),
            )
            .await;
        assert_eq!(old.status, StatusCode::FORBIDDEN);
    }
    let passed = ada
        .ok(
            "POST",
            &format!("{s}/otp/verify"),
            Some(json!({"code": second})),
            StatusCode::OK,
        )
        .await;
    assert_eq!(passed["auth_required"], json!([]), "{passed}");
    // Replaying the used code is refused.
    let replay = ada
        .call(
            "POST",
            &format!("{s}/otp/verify"),
            Some(json!({"code": second})),
        )
        .await;
    assert_eq!(replay.status, StatusCode::FORBIDDEN);
    // Asking for another once authenticated is refused.
    let more = ada.call("POST", &format!("{s}/otp"), Some(json!({}))).await;
    assert_eq!(more.status, StatusCode::CONFLICT);

    // Grace: five wrong codes lock her and revoke the link.
    let (grace, g, _) = open(&env, &app, "grace@otp.example.test").await;
    grace
        .ok(
            "POST",
            &format!("{g}/otp"),
            Some(json!({})),
            StatusCode::ACCEPTED,
        )
        .await;
    env.run().await;
    let (right, _) = code_in(&env, "grace@otp.example.test");
    codes.push(right.clone());
    let wrong = if right == "000000" {
        "000001"
    } else {
        "000000"
    };
    for attempt in 1..=5 {
        let r = grace
            .call(
                "POST",
                &format!("{g}/otp/verify"),
                Some(json!({"code": wrong})),
            )
            .await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "attempt {attempt}");
    }
    let after = grace
        .call(
            "POST",
            &format!("{g}/otp/verify"),
            Some(json!({"code": right})),
        )
        .await;
    assert_ne!(after.status, StatusCode::OK, "{:?}", after.json());
    assert_eq!(
        after.status,
        StatusCode::UNAUTHORIZED,
        "the link is revoked: {:?}",
        after.json()
    );
    let open_codes: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM recipient_otp_codes WHERE recipient_id = $1::uuid \
         AND closed_at IS NULL",
    )
    .bind(&grace_id)
    .fetch_one(&env.db.admin)
    .await
    .unwrap();
    assert_eq!(open_codes, 0, "the locked recipient's code is closed");

    // The chain: challenged, failed, passed, with the method; never the code.
    let chain = staff
        .ok(
            "GET",
            &format!("/api/v1/envelopes/{id}/audit"),
            None,
            StatusCode::OK,
        )
        .await;
    assert_eq!(events(&chain, &ada_id, "recipient.auth_challenged"), 2);
    assert_eq!(events(&chain, &ada_id, "recipient.auth_passed"), 1);
    assert_eq!(events(&chain, &ada_id, "recipient.auth_failed"), 3);
    assert_eq!(events(&chain, &grace_id, "recipient.auth_failed"), 5);
    let canonical: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT canonical FROM audit_events WHERE envelope_id = $1::uuid")
            .bind(&id)
            .fetch_all(&env.db.admin)
            .await
            .unwrap();
    let jobs: Vec<String> = sqlx::query_scalar("SELECT payload::text FROM jobs")
        .fetch_all(&env.db.admin)
        .await
        .unwrap();
    let steps: Vec<String> = sqlx::query_scalar("SELECT detail::text FROM job_steps")
        .fetch_all(&env.db.admin)
        .await
        .unwrap();
    let logged = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    for code in &codes {
        for c in &canonical {
            assert!(
                !String::from_utf8_lossy(c).contains(&format!("\"{code}\"")),
                "a code in the chain"
            );
        }
        assert!(
            !jobs.iter().any(|j| j.contains(code.as_str())),
            "a code in a job"
        );
        assert!(
            !steps.iter().any(|j| j.contains(code.as_str())),
            "a code in a step"
        );
        assert!(!logged.contains(code.as_str()), "a code in the log");
    }
}
