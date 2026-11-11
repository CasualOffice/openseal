//! Phase 2 exit item 1 without Compose: a two-signer envelope created through the API
//! server (`casual-sign-server`'s router, in process), invited by the worker by email,
//! signed through the server's ceremony with the links from those emails, sealed by the
//! worker's seal job, and `completed`; then the sealed PDF, the certificate of
//! completion and the combined PDF are downloaded through the API and each is checked
//! by our verifier and by pyHanko (`tools/verify-sealed.py`, when
//! `OPENSEAL_VERIFY_PYTHON` names a Python with pyHanko). Server and worker share one
//! database, one blob store and one clock, and record through the one decide-and-record
//! path (`casual-sign-host`).
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

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use casual_sign_sdk::Profile;
use casual_sign_server::{AppState, Blobs, Config, JwtKeys};
use casual_sign_worker::JobOutcome;
use common::{Env, TestClock, pki};
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use tower::ServiceExt as _;

const PASSWORD: &str = "end-to-end password 2026";

/// The worker's test clock, as the server reads time.
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
    async fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        extra: &[(&str, &str)],
    ) -> Resp {
        let mut req = Request::builder().method(method).uri(path);
        if let Some(c) = &self.cookie {
            req = req.header("cookie", c.as_str());
        }
        if let Some(t) = &self.csrf {
            req = req.header("x-csrf-token", t.as_str());
        }
        for (k, v) in extra {
            req = req.header(*k, *v);
        }
        let body = match body {
            Some(v) => {
                req = req.header("content-type", "application/json");
                Body::from(serde_json::to_vec(&v).unwrap())
            }
            None => Body::empty(),
        };
        let mut req = req.body(body).unwrap();
        let peer: SocketAddr = "198.51.100.77:40000".parse().unwrap();
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
        let r = self.call(method, path, body, &[]).await;
        assert_eq!(
            r.status,
            want,
            "{method} {path}: {}",
            String::from_utf8_lossy(&r.body)
        );
        r.json()
    }
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// A one-pixel PNG.
fn png() -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")
        .unwrap()
}

/// Sign as the recipient whose invitation went to `email`: open the link from the
/// email, view, adopt, finish with the adopted signature in `field`.
async fn sign(env: &Env, app: &axum::Router, email: &str, field: &str) -> (Http, String) {
    let mails = env.smtp.to(email);
    assert_eq!(mails.len(), 1, "one invitation to {email}");
    let token = mails[0].token().expect("a signing link");
    let s = format!("/s/{token}");
    let mut c = Http {
        app: app.clone(),
        cookie: None,
        csrf: None,
    };
    let opened = c
        .call("POST", &format!("{s}/session"), Some(json!({})), &[])
        .await;
    assert_eq!(opened.status, StatusCode::OK, "{:?}", opened.json());
    let set = opened.headers["set-cookie"].to_str().unwrap();
    c.cookie = Some(set.split(';').next().unwrap().to_owned());
    let view = opened.json();
    let doc = view["envelope"]["documents"][0]["id"].as_str().unwrap();
    c.ok(
        "POST",
        &format!("{s}/documents/{doc}/viewed"),
        Some(json!({"pages_seen": [1]})),
        StatusCode::OK,
    )
    .await;
    let adopted = c
        .ok(
            "POST",
            &format!("{s}/adopt"),
            Some(json!({"mark": "signature", "method": "draw", "image_base64": b64(&png())})),
            StatusCode::OK,
        )
        .await;
    let capture = adopted["adoption_id"].as_str().unwrap();
    c.ok(
        "POST",
        &format!("{s}/finish"),
        Some(json!({"values": [{"field": field, "value": {"signature": capture}}]})),
        StatusCode::OK,
    )
    .await;
    (c, s)
}

/// Our verifier at B-T, with the test PKI's CRLs.
fn ours(env: &Env, bytes: &[u8]) {
    let mut options = env.engine.verify_options(std::time::Duration::from_millis(
        u64::try_from(env.clock.ms()).unwrap(),
    ));
    options.crls = vec![pki::pki().root_crl.clone(), pki::pki().inter_crl.clone()];
    let report = env.engine.verify(bytes, &pki::trust(), &options);
    casual_sign_worker::seal::check_verified(&report, Profile::BaselineT).unwrap();
    assert!(report.all_passed(), "with CRLs supplied every check passes");
    assert!(report.covered_by_last_signature);
}

/// Write `files` with a manifest and the seal root, then run pyHanko over them.
fn pyhanko(dir: &Path, files: &[(&str, &[u8])]) {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();
    let mut manifest = String::from("file\texpect\twhy\tlevel\n");
    for (name, bytes) in files {
        std::fs::write(dir.join(name), bytes).unwrap();
        manifest.push_str(&format!("{name}\tintact\tT-2C/T-2D end to end\tB-T\n"));
    }
    std::fs::write(dir.join("manifest.tsv"), manifest).unwrap();
    std::fs::write(dir.join("trust-root.pem"), pki::root_pem()).unwrap();
    let Ok(python) = std::env::var("OPENSEAL_VERIFY_PYTHON") else {
        eprintln!(
            "NOTE: OPENSEAL_VERIFY_PYTHON is not set; pyHanko not run over {}",
            dir.display()
        );
        return;
    };
    let out = std::process::Command::new(python)
        .arg("-I")
        .arg(common::repo_root().join("tools/verify-sealed.py"))
        .arg(dir)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    eprintln!(
        "pyHanko (tools/verify-sealed.py {}):\n{text}",
        dir.display()
    );
    assert!(out.status.success(), "pyHanko disagreed:\n{text}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_and_worker_take_two_signers_to_completed_with_a_verified_seal() {
    let Some(env) = Env::new("end_to_end_api_worker").await else {
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
    casual_sign_server::bootstrap(
        &env.db.store,
        "End to End",
        "admin@e2e.example.test",
        "Admin",
        PASSWORD,
    )
    .await
    .unwrap();

    // Staff: log in, create and send in one call.
    let mut staff = Http {
        app: app.clone(),
        cookie: None,
        csrf: None,
    };
    let login = staff
        .call(
            "POST",
            "/api/v1/auth/login",
            Some(json!({"email": "admin@e2e.example.test", "password": PASSWORD})),
            &[],
        )
        .await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.json());
    let set = login.headers["set-cookie"].to_str().unwrap();
    staff.cookie = Some(set.split(';').next().unwrap().to_owned());
    staff.csrf = Some(login.json()["csrf_token"].as_str().unwrap().to_owned());
    let sig = |r: &str, y: u32| {
        json!({"recipient": r, "document": 0, "type": "signature", "page": 1,
               "x": 72, "y": y, "width": 180, "height": 40, "required": true})
    };
    let e = staff
        .ok(
            "POST",
            "/api/v1/envelopes",
            Some(json!({
                "subject": "Master services agreement", "status": "sent",
                "documents": [{"name": "msa.pdf", "content_base64": b64(&env.original)}],
                "recipients": [
                    {"ref": "a", "type": "signer", "name": "Ada Lovelace", "email": "ada@e2e.example.test", "routing_order": 1},
                    {"ref": "g", "type": "signer", "name": "Grace Hopper", "email": "grace@e2e.example.test", "routing_order": 2},
                ],
                "fields": [sig("a", 100), sig("g", 160)],
            })),
            StatusCode::CREATED,
        )
        .await;
    let id = e["id"].as_str().unwrap().to_owned();
    let doc = e["documents"][0]["id"].as_str().unwrap().to_owned();
    let field_of = |rid: &Value| {
        e["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["recipient_id"] == *rid)
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let f_ada = field_of(&e["recipients"][0]["id"]);
    let f_grace = field_of(&e["recipients"][1]["id"]);
    let base = format!("/api/v1/envelopes/{id}");

    // Before the seal, the sealed outputs are not there.
    for path in [
        format!("{base}/certificate"),
        format!("{base}/documents/combined"),
        format!("{base}/documents/{doc}/content?version=sealed"),
    ] {
        let r = staff.call("GET", &path, None, &[]).await;
        assert_eq!(r.status, StatusCode::CONFLICT, "{path}");
    }

    // The worker invites the first signer only; they sign through the API.
    let out = env.run().await;
    assert!(out.iter().all(|(_, o)| *o == JobOutcome::Done), "{out:?}");
    assert!(env.smtp.to("grace@e2e.example.test").is_empty());
    let (ada, ada_link) = sign(&env, &app, "ada@e2e.example.test", &f_ada).await;
    // Then the second.
    let out = env.run().await;
    assert!(out.iter().all(|(_, o)| *o == JobOutcome::Done), "{out:?}");
    sign(&env, &app, "grace@e2e.example.test", &f_grace).await;
    let mid = staff.ok("GET", &base, None, StatusCode::OK).await;
    assert_eq!(mid["status"], "completing");
    // The worker seals, verifies and completes.
    let out = env.run().await;
    assert!(out.iter().all(|(_, o)| *o == JobOutcome::Done), "{out:?}");
    let done = staff.ok("GET", &base, None, StatusCode::OK).await;
    assert_eq!(done["status"], "completed", "{done}");

    // Download through the API; each verifies with ours and with pyHanko.
    let get = |path: String| {
        let staff = &staff;
        async move {
            let r = staff.call("GET", &path, None, &[]).await;
            assert_eq!(r.status, StatusCode::OK, "{path}");
            assert_eq!(r.headers["content-type"], "application/pdf");
            r.body
        }
    };
    let sealed = get(format!("{base}/documents/{doc}/content?version=sealed")).await;
    let certificate = get(format!("{base}/certificate")).await;
    let combined = get(format!("{base}/documents/combined")).await;
    assert_eq!(
        combined, sealed,
        "one document: the combined PDF is the sealed one"
    );
    assert!(certificate.starts_with(b"%PDF-"));
    // WEB-06: once sealed, "current" is the sealed document, for staff and for a
    // signer who finished, through their own link.
    let current = get(format!("{base}/documents/{doc}/content?version=current")).await;
    assert_eq!(current, sealed);
    let mine = ada
        .call("GET", &format!("{ada_link}/document"), None, &[])
        .await;
    assert_eq!(mine.status, StatusCode::OK, "{:?}", mine.json());
    assert_eq!(mine.headers["x-openseal-document"], "sealed");
    assert_eq!(mine.body, sealed);
    // The sealed document served is the one the chain records.
    let audit = staff
        .ok("GET", &format!("{base}/audit"), None, StatusCode::OK)
        .await;
    let sealed_event = audit["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["type"] == "document.sealed")
        .expect("document.sealed");
    assert_eq!(
        sealed_event["event"]["data"]["sealed_hash"],
        serde_json::to_value(casual_sign_audit::Hash256::digest(&sealed)).unwrap(),
        "{sealed_event}"
    );
    ours(&env, &sealed);
    ours(&env, &certificate);
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("end-to-end-sealed");
    pyhanko(
        &dir,
        &[
            ("sealed-bt.pdf", &sealed),
            ("certificate-bt.pdf", &certificate),
        ],
    );

    // The downloads are in the chain.
    let audit = staff
        .ok("GET", &format!("{base}/audit"), None, StatusCode::OK)
        .await;
    let types: Vec<&str> = audit["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["type"].as_str().unwrap())
        .collect();
    assert!(types.contains(&"certificate.downloaded"), "{types:?}");
    assert!(types.contains(&"document.downloaded"), "{types:?}");
    assert!(env.alerts.0.lock().unwrap().is_empty());
}
