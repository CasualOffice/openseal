//! `SEC-U02` (PLAN-04, docs/23 §7.3): plan enforcement never stalls evidence. An envelope
//! is sent within its organization's plan; then the quota is zeroed by an override, the
//! organization is suspended by the platform and the workspace archived. A new send is
//! refused (`CS-PLAN-0005`), but the sent envelope is still invited, signed through the
//! server's ceremony, sealed by the worker and completed, and the sealed PDF verifies with
//! our verifier and, when `OPENSEAL_VERIFY_PYTHON` names one, with pyHanko.
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
    // WEB-06: a required attachment field is filled by uploading a file.
    for f in view["fields"].as_array().unwrap() {
        if f["type"] == "attachment" {
            let fid = f["id"].as_str().unwrap();
            c.ok(
                "PUT",
                &format!("{s}/fields/{fid}/attachment"),
                Some(json!({"content_base64": b64(&png())})),
                StatusCode::OK,
            )
            .await;
        }
    }
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

const T0: time::OffsetDateTime = time::macros::datetime!(2020-01-01 00:00 UTC);

/// Run `sql` as the owner with `binds` (uuids), as the console's definer functions would.
async fn owner(env: &Env, sql: &str, binds: &[uuid::Uuid]) {
    let mut q = sqlx::query(sqlx::AssertSqlSafe(sql.to_owned()));
    for b in binds {
        q = q.bind(*b);
    }
    q.execute(&env.db.admin).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sent_envelope_completes_with_a_verified_seal_after_quota_suspension_and_archive() {
    let Some(env) = Env::new("plan_enforcement_never_stalls_evidence").await else {
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
    let org = env.db.organization("Plans").await;
    let boot = casual_sign_server::bootstrap_workspace(
        &env.db.store,
        org,
        "Plans",
        "admin@plans.example.test",
        "Admin",
        PASSWORD,
    )
    .await
    .unwrap();

    // A plan allowing one envelope a month across the organization, assigned to it.
    let (op, plan) = (uuid::Uuid::now_v7(), uuid::Uuid::now_v7());
    owner(
        &env,
        "INSERT INTO platform.operators (id, email, roles, created_at) \
         VALUES ($1, 'op@ops.example', ARRAY['operator'], 'epoch')",
        &[op],
    )
    .await;
    owner(
        &env,
        "INSERT INTO platform.plans (id, key, version, name, created_by, created_at) \
         VALUES ($1, 'team', 1, 'Team', $2, 'epoch')",
        &[plan, op],
    )
    .await;
    owner(
        &env,
        "INSERT INTO platform.plan_quotas (plan_id, meter, \"limit\", period, enforcement, level) \
         VALUES ($1, 'envelopes_sent', 1, 'month', 'hard', 'organization')",
        &[plan],
    )
    .await;
    sqlx::query(
        "INSERT INTO platform.plan_assignments (id, organization_id, plan_id, starts_at, assigned_by, assigned_at) \
         VALUES ($1, $2, $3, $4, $5, $4)",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(org.0)
    .bind(plan)
    .bind(T0)
    .bind(op)
    .execute(&env.db.admin)
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
            Some(json!({"email": "admin@plans.example.test", "password": PASSWORD})),
            &[],
        )
        .await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.json());
    let set = login.headers["set-cookie"].to_str().unwrap();
    staff.cookie = Some(set.split(';').next().unwrap().to_owned());
    staff.csrf = Some(login.json()["csrf_token"].as_str().unwrap().to_owned());
    let body = || {
        json!({
            "subject": "Order form", "status": "sent",
            "documents": [{"name": "order.pdf", "content_base64": b64(&env.original)}],
            "recipients": [{"ref": "a", "type": "signer", "name": "Ada Lovelace",
                "email": "ada@plans.example.test", "routing_order": 1}],
            "fields": [{"recipient": "a", "document": 0, "type": "signature", "page": 1,
                "x": 72, "y": 100, "width": 180, "height": 40, "required": true}],
        })
    };
    let e = staff
        .ok(
            "POST",
            "/api/v1/envelopes",
            Some(body()),
            StatusCode::CREATED,
        )
        .await;
    let id = e["id"].as_str().unwrap().to_owned();
    let doc = e["documents"][0]["id"].as_str().unwrap().to_owned();
    let field = e["fields"][0]["id"].as_str().unwrap().to_owned();
    let base = format!("/api/v1/envelopes/{id}");

    // The quota is spent: a second send is refused with its meter, limit and usage.
    let refused = staff
        .call("POST", "/api/v1/envelopes", Some(body()), &[])
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    let p = refused.json();
    assert_eq!(p["code"], "CS-PLAN-0002", "{p}");
    assert_eq!(
        (&p["meter"], &p["limit"], &p["used"]),
        (&json!("envelopes_sent"), &json!(1), &json!(1)),
        "{p}"
    );
    assert!(p["period_end"].is_string(), "{p}");

    // Then the quota is zeroed, the organization suspended and the workspace archived.
    sqlx::query(
        "INSERT INTO platform.plan_overrides (id, organization_id, key, value, reason, operator_id, created_at) \
         VALUES ($1, $2, 'quota.envelopes_sent.organization.limit', '0', 'test', $3, $4)",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(org.0)
    .bind(op)
    .bind(T0)
    .execute(&env.db.admin)
    .await
    .unwrap();
    owner(
        &env,
        "UPDATE organizations SET status = 'suspended' WHERE id = $1",
        &[org.0],
    )
    .await;
    owner(
        &env,
        "UPDATE accounts SET status = 'archived' WHERE id = $1",
        &[boot.account.0],
    )
    .await;
    let refused = staff
        .call("POST", "/api/v1/envelopes", Some(body()), &[])
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(
        refused.json()["code"],
        "CS-PLAN-0005",
        "{:?}",
        refused.json()
    );

    // The sent envelope still goes all the way: invited, signed, sealed, completed.
    let out = env.run().await;
    assert!(out.iter().all(|(_, o)| *o == JobOutcome::Done), "{out:?}");
    sign(&env, &app, "ada@plans.example.test", &field).await;
    let out = env.run().await;
    assert!(out.iter().all(|(_, o)| *o == JobOutcome::Done), "{out:?}");
    let done = staff.ok("GET", &base, None, StatusCode::OK).await;
    assert_eq!(done["status"], "completed", "{done}");
    let sealed = staff
        .call(
            "GET",
            &format!("{base}/documents/{doc}/content?version=sealed"),
            None,
            &[],
        )
        .await;
    assert_eq!(sealed.status, StatusCode::OK);
    ours(&env, &sealed.body);
    pyhanko(
        &Path::new(env!("CARGO_TARGET_TMPDIR")).join("plan-enforcement-sealed"),
        &[("sealed-bt.pdf", &sealed.body)],
    );
}
