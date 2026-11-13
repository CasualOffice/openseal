//! One-time codes by SMS and by voice call (slice 5, VS-05; SEC-A02) through the API
//! server and the worker: a sender requires `sms_otp` or `voice_otp` of a recipient with
//! a phone number; the signer asks for a code (`POST /s/{token}/otp {method}`), the
//! worker draws it, stores only its Argon2id hash and sends it through the `Messenger`
//! to the recipient's number; the signer enters it (`POST /s/{token}/otp/verify`).
//! Shown: such a recipient needs an E.164 number; without a provider the job dies
//! `CS-WRK-0013` and nothing is sent; with one, the SMS code passes `sms_otp` once (a
//! replay fails) and the voice code, read digit by digit, passes `voice_otp`; a code
//! entered as another method's fails; the chain records each method; and no code is
//! in the chain, a job, a job step or any log line.
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

/// What the worker's messenger was asked to send: (channel, number, text).
#[derive(Debug, Default)]
struct Phone(Mutex<Vec<(&'static str, String, String)>>);

impl casual_sign_worker::messenger::Messenger for Phone {
    fn send(&self, t: &casual_sign_worker::messenger::Text) -> casual_sign_worker::Result<()> {
        self.0
            .lock()
            .unwrap()
            .push((t.channel.as_str(), t.to.clone(), t.body.clone()));
        Ok(())
    }
}

/// The six digits in the latest `channel` message to `to`, and how many there were.
fn code_to(phone: &Phone, channel: &str, to: &str) -> (String, usize) {
    let sent = phone.0.lock().unwrap();
    let mine: Vec<_> = sent
        .iter()
        .filter(|(c, n, _)| *c == channel && n == to)
        .collect();
    let text = &mine.last().expect("a code message").2;
    let after = text.split("code is ").nth(1).unwrap();
    let code: String = after.chars().filter(char::is_ascii_digit).take(6).collect();
    assert_eq!(code.len(), 6, "{text}");
    (code, mine.len())
}

fn events(chain: &Value, recipient: &str, kind: &str, method: &str) -> usize {
    chain["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| {
            e["type"] == kind
                && e["event"]["data"]["recipient_id"] == recipient
                && e["event"]["data"]["method"] == method
        })
        .count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sms_and_voice_codes_authenticate_through_the_messenger() {
    let logs = Logs::default();
    let sink = logs.clone();
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::TRACE)
        .with_ansi(false)
        .with_writer(move || sink.clone())
        .try_init();
    let Some(env) = Env::new("sms_otp").await else {
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
    let org = env.db.organization("Phones").await;
    casual_sign_server::bootstrap_workspace(
        &env.db.store,
        org,
        "Phones",
        "admin@sms.example.test",
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
            Some(json!({"email": "admin@sms.example.test", "password": PASSWORD})),
        )
        .await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.json());
    let set = login.headers["set-cookie"].to_str().unwrap();
    staff.cookie = Some(set.split(';').next().unwrap().to_owned());
    staff.csrf = Some(login.json()["csrf_token"].as_str().unwrap().to_owned());
    // An administrator owes a second factor by default (ASVS-31).
    common::pass_factor(
        &staff.app,
        staff.cookie.as_deref().unwrap(),
        staff.csrf.as_deref().unwrap(),
        env.clock.ms(),
    )
    .await;

    // A code by SMS or voice needs an E.164 number: none, or a local one, is refused.
    for (method, phone) in [("sms_otp", None), ("voice_otp", Some("020 7946 0000"))] {
        let mut r = json!({"type": "signer", "name": "No Phone", "email": "np@sms.example.test",
                           "auth": [method], "delivery": "none"});
        if let Some(p) = phone {
            r["phone"] = json!(p);
        }
        let refused = staff
            .call(
                "POST",
                "/api/v1/envelopes",
                Some(json!({"subject": "x", "recipients": [r]})),
            )
            .await;
        assert_eq!(
            refused.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{method}: {:?}",
            refused.json()
        );
    }

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
                "subject": "Phone-protected agreement", "status": "sent",
                "documents": [{"name": "nda.pdf", "content_base64": pdf}],
                "recipients": [
                    {"ref": "a", "type": "signer", "name": "Ada Lovelace", "email": "ada@sms.example.test",
                     "phone": "+44 20 7946 0001", "auth": ["sms_otp"]},
                    {"ref": "g", "type": "signer", "name": "Grace Hopper", "email": "grace@sms.example.test",
                     "phone": "+1 (202) 555-0172", "auth": ["voice_otp"]},
                ],
                "fields": [sig("a", 100), sig("g", 160)],
            })),
            StatusCode::CREATED,
        )
        .await;
    let id = e["id"].as_str().unwrap().to_owned();
    assert_eq!(e["recipients"][0]["auth"], json!(["sms_otp"]), "{e}");
    let ada_id = e["recipients"][0]["id"].as_str().unwrap().to_owned();
    let grace_id = e["recipients"][1]["id"].as_str().unwrap().to_owned();
    env.run().await;

    // Ada asks for an SMS code with no provider configured: the job dies CS-WRK-0013
    // before a code is drawn, and nothing is sent.
    let (ada, s, view) = open(&env, &app, "ada@sms.example.test").await;
    assert_eq!(view["auth_required"], json!(["sms_otp"]), "{view}");
    // Not an email code: she has none to ask for.
    let wrong_kind = ada.call("POST", &format!("{s}/otp"), Some(json!({}))).await;
    assert_eq!(
        wrong_kind.status,
        StatusCode::CONFLICT,
        "{:?}",
        wrong_kind.json()
    );
    assert_eq!(wrong_kind.json()["code"], "CS-API-0014");
    ada.ok(
        "POST",
        &format!("{s}/otp"),
        Some(json!({"method": "sms_otp"})),
        StatusCode::ACCEPTED,
    )
    .await;
    let ran = env.run().await;
    assert!(
        ran.iter().any(|(k, o)| k == "send_email_otp"
            && *o == casual_sign_worker::JobOutcome::Dead("CS-WRK-0013".into())),
        "{ran:?}"
    );
    let unsent: Option<String> = sqlx::query_scalar(
        "SELECT code_hash FROM recipient_otp_codes WHERE recipient_id = $1::uuid",
    )
    .bind(&ada_id)
    .fetch_one(&env.db.admin)
    .await
    .unwrap();
    assert!(unsent.is_none(), "no code drawn without a provider");

    // With a provider: the code goes to her number by SMS, and only its hash is stored.
    let phone = Arc::new(Phone::default());
    *env.messenger.lock().unwrap() =
        Some(Arc::clone(&phone) as Arc<dyn casual_sign_worker::messenger::Messenger>);
    env.clock.advance(Duration::from_secs(31));
    ada.ok(
        "POST",
        &format!("{s}/otp"),
        Some(json!({"method": "sms_otp"})),
        StatusCode::ACCEPTED,
    )
    .await;
    env.run().await;
    let (sms, n) = code_to(&phone, "sms", "+442079460001");
    assert_eq!(n, 1);
    let mut codes = vec![sms.clone()];
    let stored: (Option<String>, String) = sqlx::query_as(
        "SELECT code_hash, channel FROM recipient_otp_codes WHERE recipient_id = $1::uuid \
         AND closed_at IS NULL",
    )
    .bind(&ada_id)
    .fetch_one(&env.db.admin)
    .await
    .unwrap();
    assert!(stored.0.as_deref().unwrap().starts_with("$argon2id$"));
    assert_eq!(stored.1, "sms");
    let passed = ada
        .ok(
            "POST",
            &format!("{s}/otp/verify"),
            Some(json!({"code": sms, "method": "sms_otp"})),
            StatusCode::OK,
        )
        .await;
    assert_eq!(passed["auth_required"], json!([]), "{passed}");
    let replay = ada
        .call(
            "POST",
            &format!("{s}/otp/verify"),
            Some(json!({"code": sms, "method": "sms_otp"})),
        )
        .await;
    assert_eq!(replay.status, StatusCode::FORBIDDEN);

    // Grace: a voice call reads her code; entered as an email code it fails, as a
    // voice code it passes.
    let (grace, g, view) = open(&env, &app, "grace@sms.example.test").await;
    assert_eq!(view["auth_required"], json!(["voice_otp"]), "{view}");
    grace
        .ok(
            "POST",
            &format!("{g}/otp"),
            Some(json!({"method": "voice_otp"})),
            StatusCode::ACCEPTED,
        )
        .await;
    env.run().await;
    let (voice, _) = code_to(&phone, "voice", "+12025550172");
    codes.push(voice.clone());
    let mismatched = grace
        .call(
            "POST",
            &format!("{g}/otp/verify"),
            Some(json!({"code": voice, "method": "email_otp"})),
        )
        .await;
    assert_eq!(mismatched.status, StatusCode::FORBIDDEN);
    let passed = grace
        .ok(
            "POST",
            &format!("{g}/otp/verify"),
            Some(json!({"code": voice})),
            StatusCode::OK,
        )
        .await;
    assert_eq!(passed["auth_required"], json!([]), "{passed}");

    // The chain names each method; no code is anywhere in clear.
    let chain = staff
        .ok(
            "GET",
            &format!("/api/v1/envelopes/{id}/audit"),
            None,
            StatusCode::OK,
        )
        .await;
    assert_eq!(
        events(&chain, &ada_id, "recipient.auth_challenged", "sms_otp"),
        2
    );
    assert_eq!(
        events(&chain, &ada_id, "recipient.auth_passed", "sms_otp"),
        1
    );
    assert_eq!(
        events(&chain, &ada_id, "recipient.auth_failed", "sms_otp"),
        1
    );
    assert_eq!(
        events(&chain, &grace_id, "recipient.auth_passed", "voice_otp"),
        1
    );
    assert_eq!(
        events(&chain, &grace_id, "recipient.auth_failed", "voice_otp"),
        1
    );
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
        assert!(!logged.contains("2079460001"), "a number in the log");
    }
}
