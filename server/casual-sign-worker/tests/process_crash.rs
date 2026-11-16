//! Phase 2 exit item 2 on real processes (`P2-CRASH`): the API server and worker
//! binaries run as child processes against PostgreSQL 17, an in-process SMTP sink, an
//! HTTPS webhook receiver, keyd over mTLS and an RFC 3161 TSA over HTTP; each is
//! killed with `SIGKILL` at an effect boundary (`OPENSEAL_CRASH_AT`, the test-only
//! `crash-points` feature) and started again. After each:
//!
//! - **no partial state**: a server killed before its decision committed left nothing;
//! - **no audit event lost or doubled**: the stored chain verifies
//!   (`casual-sign-audit`'s verifier, through the store) and holds each event once;
//! - **a retry gives the same result**: the same `Idempotency-Key` answers as the
//!   first request would have, replayed by the engine, not applied twice;
//! - **at most the documented duplicates**: only the at-least-once window repeats an
//!   email or webhook, with the same `Message-ID` or `webhook-id`;
//! - **never `completed` without a verified seal**: the stored sealed PDF passes our
//!   verifier and pyHanko (`OPENSEAL_VERIFY_PYTHON`).
//!
//! **Failure recovery (`HRD-01`)**, at the end: a worker stopped mid-seal past its
//! lease while another takes over, keyd unavailable while sealing, PostgreSQL lost
//! mid-ceremony and mid-seal (TCP gates in front of both; with
//! `OPENSEAL_CHAOS_PG_CONTAINER` the container is restarted too: run that test alone),
//! and the blob store refusing writes; each envelope ends archived and sealed once.
//!
//! Needs `OPENSEAL_TEST_DATABASE_URL` and binaries built with the feature:
//! `cargo build -p casual-sign-server --features crash-points` (the worker binary is
//! this package's own, built with the feature by `cargo test --features crash-points`).
// Kills its children with SIGKILL and reads their exit signals: Unix only.
#![cfg(unix)]
#![cfg(feature = "crash-points")]
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
#[path = "../../casual-sign-keyd/tests/common/mod.rs"]
mod keyd_common;

use std::collections::BTreeMap;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use casual_sign_keyd::{DevKeyConsent, DigestSigner, FileKey, KeydLimits};
use casual_sign_sdk::{Engine, FontSet, Limits, Profile};
use casual_sign_store::repo::webhooks::Subscription;
use casual_sign_store::{AccountId, EnvelopeId, WebhookSubscriptionId};
use common::{Hook, Rls, Smtp, TestDb, fresh, pki};
use keyd_common::{Pki, RunningKeyd, scratch, start_keyd};
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};
use serde_json::{Value, json};
use uuid::Uuid;

const PASSWORD: &str = "process crash password 2026";
const ADMIN: &str = "admin@crash.example.test";

// ------------------------------------------------------------------ infrastructure

/// An RFC 3161 TSA over plain HTTP on a loopback port: the test PKI's TSA, stamping
/// the wall-clock time (the worker binary reads the system clock).
fn start_tsa() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        use std::io::{BufRead, BufReader, Read, Write};
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            let mut reader = BufReader::new(conn.try_clone().unwrap());
            let mut len = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                let l = line.trim_end().to_ascii_lowercase();
                if l.is_empty() {
                    break;
                }
                if let Some(v) = l.strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; len];
            if reader.read_exact(&mut body).is_err() {
                continue;
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap();
            let tsa = pki::TestTsa::new(now);
            let answer = casual_sign_sdk::TimestampSource::timestamp(&tsa, &body);
            let (status, bytes) = match answer {
                Ok(b) => ("200 OK", b),
                Err(_) => ("500 Internal Server Error", Vec::new()),
            };
            let head = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/timestamp-reply\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                bytes.len()
            );
            let _ = conn.write_all(head.as_bytes());
            let _ = conn.write_all(&bytes);
        }
    });
    format!("http://{addr}/")
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn pem(label: &str, der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

fn server_bin() -> PathBuf {
    if let Ok(p) = std::env::var("OPENSEAL_SERVER_BIN") {
        return PathBuf::from(p);
    }
    Path::new(env!("CARGO_BIN_EXE_casual-sign-worker")).with_file_name(format!(
        "casual-sign-server{}",
        std::env::consts::EXE_SUFFIX
    ))
}

/// The worker binary: `OPENSEAL_WORKER_BIN` (a copy, where another build may replace
/// the one in a shared target directory), else this package's own.
fn worker_bin() -> PathBuf {
    std::env::var("OPENSEAL_WORKER_BIN").map_or_else(
        |_| PathBuf::from(env!("CARGO_BIN_EXE_casual-sign-worker")),
        PathBuf::from,
    )
}

/// A response: status and JSON body.
#[derive(Debug)]
struct Resp {
    status: u16,
    body: Value,
    headers: BTreeMap<String, String>,
}

/// One HTTP client identity: a cookie and, for staff, a CSRF token.
#[derive(Debug, Clone, Default)]
struct Who {
    cookie: Option<String>,
    csrf: Option<String>,
}

/// The whole stack: database, sinks, keyd, TSA, and the two binaries as children.
struct Stack {
    db: TestDb,
    account: AccountId,
    smtp: Smtp,
    hook: Hook,
    _keyd: RunningKeyd,
    server_env: Vec<(String, String)>,
    worker_env: Vec<(String, String)>,
    base: String,
    server: Option<Child>,
    worker: Option<Child>,
    agent: ureq::Agent,
    staff: Who,
    dir: PathBuf,
    /// Worker crash points still to arm (the seeded run), in order.
    worker_kills: Vec<String>,
    /// How many times a worker was found dead and restarted.
    worker_restarts: usize,
    /// The gate both binaries reach PostgreSQL through (`HRD-01`: an outage cuts it).
    db_gate: Gate,
    /// The gate the worker reaches keyd through (`HRD-01`: keyd unavailable).
    keyd_gate: Gate,
    /// The filesystem blob store's root.
    blobs: PathBuf,
    /// keyd's test PKI (`HRD-01`: a worker misconfigured against it).
    keyd_pki: Pki,
}

impl Drop for Stack {
    fn drop(&mut self) {
        for c in [self.server.as_mut(), self.worker.as_mut()]
            .into_iter()
            .flatten()
        {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

async fn app_url(db: &TestDb, gate: &Gate) -> String {
    let name: String = sqlx::query_scalar::<_, String>("SELECT current_database()")
        .fetch_one(&db.admin)
        .await
        .unwrap();
    let host = &gate.addr;
    format!("postgres://openseal_app_test:openseal-app-test-only@{host}/{name}")
}

/// Where the test database listens (`host:port` of `OPENSEAL_TEST_DATABASE_URL`).
fn db_host() -> String {
    let base = std::env::var(common::db::ENV).unwrap();
    let rest = base.split_once('@').unwrap().1;
    rest.split('/').next().unwrap().to_owned()
}

impl Stack {
    async fn new(test: &str) -> Option<Self> {
        let db = fresh(test, Rls::On).await?;
        let dir = scratch(&format!("process-crash-{test}"));
        let blobs = dir.join("blobs");
        std::fs::create_dir_all(&blobs).unwrap();

        // keyd with a development file key under its own seal root.
        let kpki = Pki::new();
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = kpki.signer("P2-CRASH seal key", &key);
        let file_key = FileKey::load(
            DevKeyConsent::from_env_value(Some("1")).unwrap(),
            key.serialize_pem().as_bytes(),
            vec![cert, kpki.seal_root()],
            None,
        )
        .unwrap();
        let worker_id = kpki.client_identity("worker");
        let keyd = start_keyd(
            &kpki,
            vec![("platform", Arc::new(file_key) as Arc<dyn DigestSigner>)],
            &[&worker_id.2],
            KeydLimits::default(),
            &dir,
        );
        let write = |name: &str, text: &str| {
            let p = dir.join(name);
            std::fs::write(&p, text).unwrap();
            p.display().to_string()
        };
        let keyd_ca = write("keyd-ca.pem", &kpki.tls_ca.pem());
        let client_cert = write("worker.pem", &worker_id.0);
        let client_key = write("worker-key.pem", &worker_id.1);
        let anchors = write(
            "anchors.pem",
            &format!("{}{}", pki::root_pem(), kpki.seal_root_pem()),
        );
        let smtp = Smtp::start();
        let hook = Hook::start();
        let hook_ca = write("hook-ca.pem", &pem("CERTIFICATE", &hook.ca_der));
        let tsa = start_tsa();
        let jwt = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .unwrap()
            .serialize_pem();
        let port = free_port();
        let base = format!("http://127.0.0.1:{port}");
        let db_gate = Gate::start(db_host());
        let keyd_gate = Gate::start(keyd.addr.clone());
        let db_url = app_url(&db, &db_gate).await;
        let s = |k: &str, v: &str| (k.to_owned(), v.to_owned());
        let blob_dir = blobs.display().to_string();
        let server_env = vec![
            s("OPENSEAL_DATABASE_URL", &db_url),
            s("OPENSEAL_JWT_SIGNING_KEY", &jwt),
            s("OPENSEAL_BLOB_DIR", &blob_dir),
            s("OPENSEAL_LISTEN", &format!("127.0.0.1:{port}")),
            s("OPENSEAL_PUBLIC_URL", &base),
            s("OPENSEAL_DEV_INSECURE_KEY", "1"),
            // A fixed key, so an enrolled second factor survives the server's restarts
            // (ASVS-31: the administrator below owes one by default).
            s(
                "OPENSEAL_MFA_KEY",
                "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
            ),
            s("RUST_LOG", "warn"),
        ];
        let worker_env = vec![
            s("OPENSEAL_DATABASE_URL", &db_url),
            s("OPENSEAL_BLOB_DIR", &blob_dir),
            s("OPENSEAL_WORKER_NAME", "crash-worker"),
            s("OPENSEAL_BASE_URL", &base),
            s("OPENSEAL_MAIL_FROM", "no-reply@crash.example.test"),
            s("OPENSEAL_MAIL_DOMAIN", "crash.example.test"),
            s("OPENSEAL_ABUSE", "abuse@crash.example.test"),
            s("OPENSEAL_SMTP_HOST", "127.0.0.1"),
            s("OPENSEAL_SMTP_PORT", &smtp.port.to_string()),
            s("OPENSEAL_SMTP_SECURITY", "plain"),
            s("OPENSEAL_TSA_URLS", &tsa),
            s("OPENSEAL_TRUST_ANCHORS", &anchors),
            s("OPENSEAL_KEYD_ADDR", &keyd_gate.addr),
            s("OPENSEAL_KEYD_SERVER_NAME", "localhost"),
            s("OPENSEAL_KEYD_CA", &keyd_ca),
            s("OPENSEAL_KEYD_CLIENT_CERT", &client_cert),
            s("OPENSEAL_KEYD_CLIENT_KEY", &client_key),
            s("OPENSEAL_WEBHOOK_ALLOW", "127.0.0.0/8"),
            s("OPENSEAL_WEBHOOK_EXTRA_ROOTS", &hook_ca),
            s("WH_SECRET", common::SECRET),
            s("OPENSEAL_SEAL_NAME", "OpenSeal crash test"),
        ];
        let b = casual_sign_server::bootstrap(&db.store, "Crash", ADMIN, "Admin", PASSWORD)
            .await
            .unwrap();
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(60)))
            .build()
            .into();
        let mut stack = Self {
            db,
            account: b.account,
            smtp,
            hook,
            _keyd: keyd,
            server_env,
            worker_env,
            base,
            server: None,
            worker: None,
            agent,
            staff: Who::default(),
            dir,
            worker_kills: Vec::new(),
            worker_restarts: 0,
            db_gate,
            keyd_gate,
            blobs,
            keyd_pki: kpki,
        };
        stack.probe_features();
        stack.start_server(None);
        stack.start_worker(None);
        let login = stack.call(
            &Who::default(),
            "POST",
            "/api/v1/auth/login",
            Some(json!({"email": ADMIN, "password": PASSWORD})),
            &[],
        );
        assert_eq!(login.status, 200, "{login:?}");
        stack.staff = Who {
            cookie: Some(
                login.headers["set-cookie"]
                    .split(';')
                    .next()
                    .unwrap()
                    .to_owned(),
            ),
            csrf: Some(login.body["csrf_token"].as_str().unwrap().to_owned()),
        };
        stack.enrol_factor();
        Some(stack)
    }

    /// The administrator owes a second factor by default (ASVS-31): enrol one through
    /// the API, as an authenticator app would answer, so the staff session passes it.
    fn enrol_factor(&self) {
        let r = self.call(&self.staff, "GET", "/api/v1/auth/session", None, &[]);
        assert_eq!(r.status, 200, "{r:?}");
        if r.body["second_factor"] != "enrol" {
            return;
        }
        let r = self.call(
            &self.staff,
            "POST",
            "/api/v1/auth/mfa/totp/enrol",
            None,
            &[],
        );
        assert_eq!(r.status, 200, "{r:?}");
        let seed = common::unbase32(r.body["secret"].as_str().unwrap());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let code = casual_sign_server::totp::code(
            &seed,
            casual_sign_server::totp::step_at(i64::try_from(now).unwrap()),
        );
        let r = self.call(
            &self.staff,
            "POST",
            "/api/v1/auth/mfa/totp/confirm",
            Some(json!({"code": code})),
            &[],
        );
        assert_eq!(r.status, 200, "{r:?}");
    }

    /// Both binaries die at `startup` when built with the feature; otherwise this
    /// test would pass without crashing anything.
    fn probe_features(&self) {
        for (bin, env) in [
            (server_bin(), &self.server_env),
            (worker_bin(), &self.worker_env),
        ] {
            let st = Command::new(&bin)
                .envs(env.iter().cloned())
                .env("OPENSEAL_CRASH_AT", "startup")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap_or_else(|e| panic!("{}: {e}", bin.display()));
            assert_eq!(
                st.signal(),
                Some(9),
                "{} was not built with --features crash-points",
                bin.display()
            );
        }
    }

    fn spawn(&self, bin: &Path, env: &[(String, String)], crash: Option<&str>, log: &str) -> Child {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join(log))
            .unwrap();
        let mut c = Command::new(bin);
        c.envs(env.iter().cloned())
            .env_remove("OPENSEAL_CRASH_AT")
            .stdout(Stdio::null())
            .stderr(log);
        if let Some(at) = crash {
            c.env("OPENSEAL_CRASH_AT", at);
        }
        c.spawn().unwrap()
    }

    fn start_server(&mut self, crash: Option<&str>) {
        if let Some(mut c) = self.server.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        self.server = Some(self.spawn(&server_bin(), &self.server_env, crash, "server.log"));
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let r = self
                .agent
                .get(format!("{}/.well-known/jwks.json", self.base))
                .call();
            if matches!(&r, Ok(r) if r.status() == 200) {
                return;
            }
            assert!(Instant::now() < deadline, "the server did not start");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Stop the worker (SIGKILL), so jobs wait until the next one starts.
    fn stop_worker(&mut self) {
        if let Some(mut c) = self.worker.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    fn start_worker(&mut self, crash: Option<&str>) {
        self.stop_worker();
        let bin = worker_bin();
        self.worker = Some(self.spawn(&bin, &self.worker_env, crash, "worker.log"));
    }

    /// Wait for a child that should have killed itself; asserts it died of SIGKILL.
    fn expect_killed(child: &mut Option<Child>, what: &str) {
        let c = child.as_mut().unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(st) = c.try_wait().unwrap() {
                assert_eq!(st.signal(), Some(9), "{what} ended otherwise: {st:?}");
                *child = None;
                return;
            }
            assert!(
                Instant::now() < deadline,
                "{what} did not reach its crash point"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn call(
        &self,
        who: &Who,
        method: &str,
        path: &str,
        body: Option<Value>,
        extra: &[(&str, &str)],
    ) -> Resp {
        let url = format!("{}{path}", self.base);
        let mut req = ureq::http::Request::builder().method(method).uri(&url);
        if let Some(c) = &who.cookie {
            req = req.header("cookie", c.as_str());
        }
        if let Some(t) = &who.csrf {
            req = req.header("x-csrf-token", t.as_str());
        }
        for (k, v) in extra {
            req = req.header(*k, *v);
        }
        let bytes = match body {
            Some(v) => {
                req = req.header("content-type", "application/json");
                serde_json::to_vec(&v).unwrap()
            }
            None => Vec::new(),
        };
        let mut r = self
            .agent
            .run(req.body(bytes).unwrap())
            .unwrap_or_else(|e| panic!("{method} {path}: {e}"));
        let headers = r
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap_or("").to_owned()))
            .collect();
        let status = r.status().as_u16();
        let body = r
            .body_mut()
            .with_config()
            .limit(64 << 20)
            .read_to_vec()
            .unwrap();
        Resp {
            status,
            body: serde_json::from_slice(&body).unwrap_or(Value::Null),
            headers,
        }
    }

    /// A request the server dies in the middle of: no answer comes back.
    fn call_dies(
        &self,
        who: &Who,
        method: &str,
        path: &str,
        body: Option<Value>,
        extra: &[(&str, &str)],
    ) {
        let url = format!("{}{path}", self.base);
        let mut req = ureq::http::Request::builder().method(method).uri(&url);
        if let Some(c) = &who.cookie {
            req = req.header("cookie", c.as_str());
        }
        if let Some(t) = &who.csrf {
            req = req.header("x-csrf-token", t.as_str());
        }
        for (k, v) in extra {
            req = req.header(*k, *v);
        }
        let bytes = body.map_or_else(Vec::new, |v| serde_json::to_vec(&v).unwrap());
        let req = req
            .header("content-type", "application/json")
            .body(bytes)
            .unwrap();
        let r = self.agent.run(req);
        assert!(
            r.is_err(),
            "{method} {path} answered: {:?}",
            r.map(|r| r.status())
        );
    }

    async fn sql(&self, q: &str) {
        sqlx::query(sqlx::AssertSqlSafe(q.to_owned()))
            .execute(&self.db.admin)
            .await
            .unwrap();
    }

    async fn scalar(&self, q: &str) -> i64 {
        sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(q.to_owned()))
            .fetch_one(&self.db.admin)
            .await
            .unwrap()
    }

    /// Every due job done (none queued and due, none running); a worker found dead is
    /// restarted past its leases, with the next seeded crash point armed, if any.
    async fn idle(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(180);
        let mut quiet = 0;
        loop {
            if let Some(c) = self.worker.as_mut()
                && let Some(st) = c.try_wait().unwrap()
            {
                assert_eq!(st.signal(), Some(9), "the worker ended otherwise: {st:?}");
                self.worker = None;
                self.after_worker_crash().await;
                let next = self.worker_kills.pop();
                self.start_worker(next.as_deref());
                self.worker_restarts += 1;
            }
            let busy = self
                .scalar(
                    "SELECT count(*) FROM jobs WHERE (status = 'queued' AND run_at <= now()) \
                     OR status = 'running'",
                )
                .await;
            quiet = if busy == 0 { quiet + 1 } else { 0 };
            if quiet >= 3 {
                return;
            }
            assert!(Instant::now() < deadline, "jobs still busy: {busy}");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// A dead worker's leases lapse (as 300 s later).
    async fn after_worker_crash(&self) {
        self.sql(
            "UPDATE jobs SET locked_until = now() - interval '1 second' WHERE status = 'running'",
        )
        .await;
    }

    /// Kill the worker at `at`, wait for it, restart it past its leases, run to idle.
    async fn worker_crash(&mut self, at: &str) {
        self.start_worker(Some(at));
        Self::expect_killed(&mut self.worker, at);
        self.after_worker_crash().await;
        self.start_worker(None);
        self.idle().await;
    }

    /// The stored chain verified by the store (`CS-DB-0005` otherwise) and its types.
    async fn events(&self, env: &str) -> Vec<String> {
        let id = EnvelopeId(Uuid::parse_str(env).unwrap());
        let mut tx = self
            .db
            .store
            .for_account(self.account)
            .begin()
            .await
            .unwrap();
        let chain = tx.audit().chain(id).await.expect("the chain verifies");
        let events = tx.audit().events(id).await.unwrap();
        tx.commit().await.unwrap();
        assert_eq!(chain.len(), events.len());
        events.into_iter().map(|e| e.event_type).collect()
    }

    async fn count(&self, env: &str, ty: &str) -> usize {
        self.events(env).await.iter().filter(|t| *t == ty).count()
    }

    fn get(&self, env: &str) -> Value {
        let r = self.call(
            &self.staff,
            "GET",
            &format!("/api/v1/envelopes/{env}"),
            None,
            &[],
        );
        assert_eq!(r.status, 200, "{r:?}");
        r.body
    }

    /// A two-signer envelope; sent unless `draft`.
    fn create(&self, n: usize, draft: bool) -> (String, Vec<String>, Vec<String>) {
        let tag = Uuid::now_v7().simple().to_string();
        let original = common::valid_pdf();
        let mut recipients = Vec::new();
        let mut fields = Vec::new();
        for i in 0..n {
            recipients.push(json!({"ref": format!("r{i}"), "type": "signer",
                "name": format!("Signer {i}"), "email": format!("s{i}-{tag}@crash.example.test"),
                "routing_order": i + 1}));
            fields.push(json!({"recipient": format!("r{i}"), "document": 0, "type": "signature",
                "page": 1, "x": 72, "y": 100 + 60 * i, "width": 180, "height": 40, "required": true}));
        }
        let mut body = json!({
            "subject": "Crash test agreement",
            "documents": [{"name": "a.pdf",
                "content_base64": base64::engine::general_purpose::STANDARD.encode(&original)}],
            "recipients": recipients, "fields": fields,
        });
        if !draft {
            body["status"] = json!("sent");
        }
        let e = self.call(&self.staff, "POST", "/api/v1/envelopes", Some(body), &[]);
        assert_eq!(e.status, 201, "{e:?}");
        let e = e.body;
        let emails = (0..n)
            .map(|i| format!("s{i}-{tag}@crash.example.test"))
            .collect();
        let field_ids = e["recipients"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                e["fields"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|f| f["recipient_id"] == r["id"])
                    .unwrap()["id"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        (e["id"].as_str().unwrap().to_owned(), emails, field_ids)
    }

    /// Open the signing link emailed to `email` and adopt a signature; returns the
    /// session, the link and the finish body.
    fn open(&self, email: &str, field: &str) -> (Who, String, Value) {
        let mails = self.smtp.to(email);
        assert!(!mails.is_empty(), "an invitation to {email}");
        let ids: Vec<String> = mails.iter().map(common::Mail::message_id).collect();
        assert!(
            ids.iter().all(|i| *i == ids[0]),
            "repeats share a Message-ID"
        );
        let token = mails.last().unwrap().token().expect("a signing link");
        let s = format!("/s/{token}");
        let opened = self.call(
            &Who::default(),
            "POST",
            &format!("{s}/session"),
            Some(json!({})),
            &[],
        );
        assert_eq!(opened.status, 200, "{opened:?}");
        let who = Who {
            cookie: Some(
                opened.headers["set-cookie"]
                    .split(';')
                    .next()
                    .unwrap()
                    .to_owned(),
            ),
            csrf: None,
        };
        let doc = opened.body["envelope"]["documents"][0]["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let v = self.call(
            &who,
            "POST",
            &format!("{s}/documents/{doc}/viewed"),
            Some(json!({"pages_seen": [1]})),
            &[],
        );
        assert_eq!(v.status, 200, "{v:?}");
        let png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";
        let a = self.call(
            &who,
            "POST",
            &format!("{s}/adopt"),
            Some(json!({"mark": "signature", "method": "draw", "image_base64": png})),
            &[],
        );
        assert_eq!(a.status, 200, "{a:?}");
        let capture = a.body["adoption_id"].as_str().unwrap().to_owned();
        let finish = json!({"values": [{"field": field, "value": {"signature": capture}}]});
        (who, s, finish)
    }

    fn sign(&self, email: &str, field: &str) {
        let (who, s, finish) = self.open(email, field);
        let r = self.call(&who, "POST", &format!("{s}/finish"), Some(finish), &[]);
        assert_eq!(r.status, 200, "{r:?}");
    }

    /// The stored sealed PDF of `env`: our verifier at B-T, then pyHanko.
    async fn verified_seal(&self, env: &str, label: &str) {
        let e = self.get(env);
        assert_eq!(e["status"], "completed", "{e}");
        let doc = e["documents"][0]["id"].as_str().unwrap();
        let path = format!("/api/v1/envelopes/{env}/documents/{doc}/content?version=sealed");
        let url = format!("{}{path}", self.base);
        let mut req = ureq::http::Request::builder().method("GET").uri(&url);
        req = req.header("cookie", self.staff.cookie.as_deref().unwrap());
        let mut r = self.agent.run(req.body(Vec::new()).unwrap()).unwrap();
        assert_eq!(r.status(), 200);
        let sealed = r
            .body_mut()
            .with_config()
            .limit(64 << 20)
            .read_to_vec()
            .unwrap();
        let events = self.events(env).await;
        for once in [
            "document.sealed",
            "envelope.completed",
            "envelope.completing",
        ] {
            assert_eq!(
                events.iter().filter(|t| *t == once).count(),
                1,
                "{once}: {events:?}"
            );
        }
        let engine = Engine::new(Limits::default(), FontSet::bundled());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        let mut options = engine.verify_options(now);
        options.crls = vec![pki::pki().root_crl.clone(), pki::pki().inter_crl.clone()];
        let mut trust = pki::trust();
        let anchors = std::fs::read(self.dir.join("anchors.pem")).unwrap();
        for c in casual_sign_keyd::certificates(&anchors).unwrap() {
            let _ = trust.add_anchor(&der::Encode::to_der(&c).unwrap());
        }
        let report = engine.verify(&sealed, &trust, &options);
        casual_sign_worker::seal::check_verified(&report, Profile::BaselineT)
            .unwrap_or_else(|e| panic!("{label}: our verifier refused the stored seal: {e}"));
        // pyHanko, against both roots.
        let dir = self.dir.join(format!("sealed-{label}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("sealed-bt.pdf"), &sealed).unwrap();
        std::fs::write(
            dir.join("manifest.tsv"),
            "file\texpect\twhy\tlevel\nsealed-bt.pdf\tintact\tP2-CRASH\tB-T\n",
        )
        .unwrap();
        std::fs::write(dir.join("trust-root.pem"), anchors).unwrap();
        let Ok(python) = std::env::var("OPENSEAL_VERIFY_PYTHON") else {
            eprintln!("NOTE: OPENSEAL_VERIFY_PYTHON is not set; pyHanko not run");
            return;
        };
        let out = Command::new(python)
            .arg("-I")
            .arg(common::repo_root().join("tools/verify-sealed.py"))
            .arg(&dir)
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "{label}: pyHanko disagreed:\n{text}");
    }

    async fn subscribe(&self) {
        let mut tx = self
            .db
            .store
            .for_account(self.account)
            .begin()
            .await
            .unwrap();
        tx.webhooks()
            .subscribe(&Subscription {
                id: WebhookSubscriptionId(Uuid::now_v7()),
                envelope_id: None,
                url: self.hook.url.clone(),
                event_types: vec!["envelope.sent".into()],
                secret_refs: vec!["WH_SECRET".into()],
                active: true,
            })
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
}

// ------------------------------------------------------------------ the server

/// What a server crash test runs: an operation set up on a fresh envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Send,
    Finish,
    Decline,
    Void,
    Correct,
}

impl Op {
    fn command(self) -> &'static str {
        match self {
            Self::Send => "Send",
            Self::Finish => "Finish",
            Self::Decline => "Decline",
            Self::Void => "Void",
            Self::Correct => "Correct",
        }
    }

    fn route(self) -> &'static str {
        match self {
            Self::Send => "/send",
            Self::Finish => "/finish",
            Self::Decline => "/decline",
            Self::Void => "/void",
            Self::Correct => "/correct",
        }
    }

    /// The event the operation records exactly once.
    fn event(self) -> &'static str {
        match self {
            Self::Send => "envelope.sent",
            Self::Finish => "recipient.signed",
            Self::Decline => "recipient.declined",
            Self::Void => "envelope.voided",
            Self::Correct => "envelope.corrected",
        }
    }
}

/// Run `op` on a fresh envelope with the server killed at `at`; restart; retry.
async fn server_case(st: &mut Stack, op: Op, at: &str) {
    let label = format!("{op:?} {at}");
    let (env, emails, fields) = st.create(2, op == Op::Send);
    st.idle().await;
    let base = format!("/api/v1/envelopes/{env}");
    // The request, as (who, path, body, headers).
    let key = format!("crash-{}", Uuid::now_v7().simple());
    let (who, path, body, idem) = match op {
        Op::Send => (st.staff.clone(), format!("{base}/send"), None, true),
        Op::Void => (
            st.staff.clone(),
            format!("{base}/void"),
            Some(json!({"reason": "crash test"})),
            true,
        ),
        Op::Correct => {
            let e = st.get(&env);
            let r = &e["recipients"][1];
            let spec = json!({"id": r["id"], "type": "signer", "routing_order": 2,
                "name": "Signer 1 corrected", "email": emails[1]});
            (
                st.staff.clone(),
                format!("{base}/correct"),
                Some(json!({"changes": [{"op": "update_recipient", "recipient": spec}]})),
                true,
            )
        }
        Op::Finish => {
            let (who, s, finish) = st.open(&emails[0], &fields[0]);
            (who, format!("{s}/finish"), Some(finish), false)
        }
        Op::Decline => {
            let (who, s, _) = st.open(&emails[0], &fields[0]);
            (
                who,
                format!("{s}/decline"),
                Some(json!({"reason": "crash test"})),
                false,
            )
        }
    };
    // A correction names the version it corrects (428 otherwise).
    let etag = st
        .call(&st.staff, "GET", &base, None, &[])
        .headers
        .get("etag")
        .cloned()
        .unwrap_or_default();
    let mut headers: Vec<(&str, &str)> = if idem {
        vec![("idempotency-key", key.as_str())]
    } else {
        vec![]
    };
    if op == Op::Correct {
        headers.push(("if-match", etag.as_str()));
    }
    let before = st.events(&env).await;
    let before_state = st.get(&env)["status"].clone();

    st.start_server(Some(at));
    st.call_dies(&who, "POST", &path, body.clone(), &headers);
    Stack::expect_killed(&mut st.server, &label);
    let after_crash = st.events(&env).await;
    if at.starts_with("before_commit") {
        assert_eq!(
            after_crash, before,
            "{label}: partial state after a crash before commit"
        );
    } else {
        assert_eq!(
            after_crash.iter().filter(|t| *t == op.event()).count()
                - before.iter().filter(|t| *t == op.event()).count(),
            1,
            "{label}: committed once before the crash"
        );
    }
    st.start_server(None);
    // The dead request's key is held "in progress"; five minutes on, a retry takes it.
    st.sql("UPDATE idempotency_keys SET created_at = created_at - interval '10 minutes' WHERE status = 102")
        .await;
    let retry = st.call(&who, "POST", &path, body.clone(), &headers);
    let committed = !at.starts_with("before_commit");
    if committed && !idem {
        // A ceremony request carries no key: the retry finds the act done.
        assert!(
            retry.status == 200
                || retry.status == 409
                || retry.status == 401
                || retry.status == 403,
            "{label}: retry {retry:?}"
        );
    } else {
        assert_eq!(retry.status, 200, "{label}: retry {retry:?}");
        if idem {
            let again = st.call(&who, "POST", &path, body, &headers);
            assert_eq!(again.status, 200, "{label}");
            assert_eq!(again.body, retry.body, "{label}: a replay answers the same");
        }
    }
    st.idle().await;
    let events = st.events(&env).await;
    assert_eq!(
        events.iter().filter(|t| *t == op.event()).count()
            - before.iter().filter(|t| *t == op.event()).count(),
        1,
        "{label}: {events:?}"
    );
    let _ = before_state;
    // Every job of the envelope's effects ran once.
    let dead = st
        .scalar("SELECT count(*) FROM jobs WHERE status = 'dead'")
        .await;
    assert_eq!(dead, 0, "{label}: a job dead-lettered");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn killing_the_server_at_every_commit_boundary_loses_nothing() {
    let Some(mut st) = Stack::new("proc_crash_server").await else {
        return;
    };
    for op in [Op::Send, Op::Finish, Op::Decline, Op::Void, Op::Correct] {
        for at in [
            format!("before_commit:{}", op.command()),
            format!("after_commit:{}", op.route()),
        ] {
            server_case(&mut st, op, &at).await;
        }
    }
}

// ------------------------------------------------------------------ the worker

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn killing_the_worker_at_every_effect_boundary_loses_nothing() {
    let Some(mut st) = Stack::new("proc_crash_worker").await else {
        return;
    };
    // Invitation email at each boundary: one email, two only in the at-least-once
    // window, with the same Message-ID.
    for (b, window) in [
        ("Claimed", false),
        ("EmailSent", true),
        ("Recorded", false),
        ("BeforeCommit", false),
    ] {
        st.stop_worker();
        let (env, emails, _) = st.create(2, true);
        let at = format!("worker:{b}:send_invitation");
        st.call(
            &st.staff.clone(),
            "POST",
            &format!("/api/v1/envelopes/{env}/send"),
            None,
            &[],
        );
        st.worker_crash(&at).await;
        let mails = st.smtp.to(&emails[0]);
        assert_eq!(mails.len(), if window { 2 } else { 1 }, "{at}");
        assert_eq!(
            mails.first().unwrap().message_id(),
            mails.last().unwrap().message_id(),
            "{at}"
        );
        assert_eq!(st.count(&env, "invitation.sent").await, 1, "{at}");
    }
    // Webhook delivery at each boundary: one delivery per webhook-id, a repeat only in
    // the window.
    st.subscribe().await;
    for (b, window) in [
        ("Claimed", false),
        ("WebhookAnswered", true),
        ("Recorded", false),
    ] {
        st.stop_worker();
        let before = st.hook.requests().len();
        let (env, _, _) = st.create(2, true);
        st.call(
            &st.staff.clone(),
            "POST",
            &format!("/api/v1/envelopes/{env}/send"),
            None,
            &[],
        );
        let at = format!("worker:{b}:deliver_webhook");
        st.worker_crash(&at).await;
        let got: Vec<String> = st.hook.requests()[before..]
            .iter()
            .map(|r| r.headers["webhook-id"].clone())
            .collect();
        assert_eq!(got.len(), if window { 2 } else { 1 }, "{at}: {got:?}");
        assert!(got.iter().all(|g| *g == got[0]), "{at}: {got:?}");
        assert_eq!(st.count(&env, "envelope.sent").await, 1);
    }
    // The seal at each boundary, through keyd: completed once, on a verified seal.
    for b in ["Claimed", "Sealed", "Recorded", "BeforeCommit"] {
        st.start_worker(None);
        let (env, emails, fields) = st.create(2, false);
        st.idle().await;
        st.sign(&emails[0], &fields[0]);
        st.idle().await;
        st.stop_worker();
        st.sign(&emails[1], &fields[1]);
        assert_eq!(st.get(&env)["status"], "completing");
        let at = format!("worker:{b}:seal_envelope");
        st.start_worker(Some(&at));
        Stack::expect_killed(&mut st.worker, &at);
        let e = st.get(&env);
        assert_eq!(
            e["status"], "completing",
            "{at}: completed by a dead worker"
        );
        assert_eq!(st.count(&env, "envelope.completed").await, 0, "{at}");
        st.after_worker_crash().await;
        st.start_worker(None);
        st.idle().await;
        st.verified_seal(&env, b).await;
    }
    let dead = st
        .scalar("SELECT count(*) FROM jobs WHERE status = 'dead'")
        .await;
    assert_eq!(dead, 0);
}

// ------------------------------------------------------------------ seeded

/// A small deterministic generator (SplitMix64), so a failing seed reproduces.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn pick<'a>(&mut self, of: &[&'a str]) -> &'a str {
        of[usize::try_from(self.next() % of.len() as u64).unwrap()]
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_two_signer_envelope_completes_through_seeded_random_kills() {
    let Some(mut st) = Stack::new("proc_crash_seeded").await else {
        return;
    };
    let seed = std::env::var("OPENSEAL_CRASH_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_261_112_u64);
    eprintln!("seed {seed} (OPENSEAL_CRASH_SEED reproduces it)");
    let mut rng = Rng(seed);
    let email = ["Claimed", "EmailSent", "Recorded", "BeforeCommit"];
    let seal = ["Claimed", "Sealed", "Recorded", "BeforeCommit"];
    // A seeded boundary in each invitation and in the seal, in the order the jobs run;
    // `idle` arms each after the previous one killed the worker.
    let mut kills: Vec<String> = vec![
        format!("worker:{}:send_invitation", rng.pick(&email)),
        format!("worker:{}:send_invitation", rng.pick(&email)),
        format!("worker:{}:seal_envelope", rng.pick(&seal)),
    ];
    kills.reverse();
    eprintln!("worker kills: {kills:?}");
    let first = kills.pop();
    st.worker_kills = kills;
    st.start_worker(first.as_deref());

    let (env, emails, fields) = st.create(2, true);
    let key = format!("seeded-{seed}");
    let send = format!("/api/v1/envelopes/{env}/send");
    let at = rng
        .pick(&["before_commit:Send", "after_commit:/send"])
        .to_owned();
    eprintln!("server kill at {at}");
    st.start_server(Some(&at));
    st.call_dies(
        &st.staff.clone(),
        "POST",
        &send,
        None,
        &[("idempotency-key", &key)],
    );
    Stack::expect_killed(&mut st.server, &at);
    st.start_server(None);
    st.sql("UPDATE idempotency_keys SET created_at = created_at - interval '10 minutes' WHERE status = 102")
        .await;
    let r = st.call(
        &st.staff.clone(),
        "POST",
        &send,
        None,
        &[("idempotency-key", &key)],
    );
    assert_eq!(r.status, 200, "{r:?}");
    for i in 0..2 {
        st.idle().await;
        let (who, s, finish) = st.open(&emails[i], &fields[i]);
        let at = rng
            .pick(&["before_commit:Finish", "after_commit:/finish", "none:"])
            .to_owned();
        eprintln!("signer {i}: server kill at {at}");
        if at != "none:" {
            st.start_server(Some(&at));
            st.call_dies(
                &who,
                "POST",
                &format!("{s}/finish"),
                Some(finish.clone()),
                &[],
            );
            Stack::expect_killed(&mut st.server, &at);
            st.start_server(None);
        }
        if at != "after_commit:/finish" {
            let r = st.call(&who, "POST", &format!("{s}/finish"), Some(finish), &[]);
            assert_eq!(r.status, 200, "{r:?}");
        }
    }
    // Run to idle: `idle` restarts the worker after each armed kill.
    st.idle().await;
    eprintln!("worker restarts: {}", st.worker_restarts);
    let events = st.events(&env).await;
    assert_eq!(
        events.iter().filter(|t| *t == "recipient.signed").count(),
        2,
        "{events:?}"
    );
    assert_eq!(
        events.iter().filter(|t| *t == "envelope.sent").count(),
        1,
        "{events:?}"
    );
    st.verified_seal(&env, "seeded").await;
    let dead = st
        .scalar("SELECT count(*) FROM jobs WHERE status = 'dead'")
        .await;
    assert_eq!(dead, 0);
}

// ------------------------------------------------------------------ HRD-01 chaos

/// A TCP gate in front of a dependency (PostgreSQL, keyd): it forwards every connection
/// while up; [`Gate::cut`] tears down every open connection (as a restart of the
/// dependency does: each in-flight transaction is lost and rolled back by the server)
/// and refuses new ones until [`Gate::restore`].
struct Gate {
    addr: String,
    up: Arc<std::sync::atomic::AtomicBool>,
    conns: Arc<std::sync::Mutex<Vec<std::net::TcpStream>>>,
}

impl Gate {
    fn start(target: String) -> Self {
        use std::sync::atomic::Ordering;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let up = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let conns: Arc<std::sync::Mutex<Vec<std::net::TcpStream>>> = Arc::default();
        let (u, c) = (Arc::clone(&up), Arc::clone(&conns));
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(client) = conn else { continue };
                if !u.load(Ordering::SeqCst) {
                    let _ = client.shutdown(std::net::Shutdown::Both);
                    continue;
                }
                let Ok(server) = std::net::TcpStream::connect(&target) else {
                    let _ = client.shutdown(std::net::Shutdown::Both);
                    continue;
                };
                {
                    let mut list = c.lock().unwrap();
                    list.push(client.try_clone().unwrap());
                    list.push(server.try_clone().unwrap());
                }
                for (mut from, mut to) in [
                    (client.try_clone().unwrap(), server.try_clone().unwrap()),
                    (server, client),
                ] {
                    std::thread::spawn(move || {
                        let _ = std::io::copy(&mut from, &mut to);
                        let _ = from.shutdown(std::net::Shutdown::Both);
                        let _ = to.shutdown(std::net::Shutdown::Both);
                    });
                }
            }
        });
        Self { addr, up, conns }
    }

    /// Every open connection torn down; new ones refused.
    fn cut(&self) {
        self.up.store(false, std::sync::atomic::Ordering::SeqCst);
        for s in self.conns.lock().unwrap().drain(..) {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
    }

    /// Connections forwarded again.
    fn restore(&self) {
        self.up.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// A child killed when dropped (a stopped worker must not outlive a failed test).
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Send `sig` (`STOP`, `CONT`) to a child.
fn signal(child: &Child, sig: &str) {
    let st = Command::new("kill")
        .arg(format!("-{sig}"))
        .arg(child.id().to_string())
        .status()
        .unwrap();
    assert!(st.success(), "kill -{sig}");
}

fn wait_file(path: &Path, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(120);
    while !path.exists() {
        assert!(Instant::now() < deadline, "{what}: not reached");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Files under `dir`, recursively.
fn count_files(dir: &Path) -> usize {
    std::fs::read_dir(dir).map_or(0, |rd| {
        rd.flatten()
            .map(|e| {
                let p = e.path();
                if p.is_dir() { count_files(&p) } else { 1 }
            })
            .sum()
    })
}

impl Stack {
    /// A fresh directory a held worker signals through.
    fn hold_dir(&self, name: &str) -> PathBuf {
        let d = self.dir.join(format!("hold-{name}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Start a worker (logging to `log`) that holds at `at` until `dir/release` exists.
    fn start_worker_held(&mut self, at: &str, dir: &Path, log: &str) {
        self.stop_worker();
        let bin = worker_bin();
        let mut env = self.worker_env.clone();
        env.push(("OPENSEAL_HOLD_AT".into(), at.into()));
        env.push(("OPENSEAL_HOLD_DIR".into(), dir.display().to_string()));
        self.worker = Some(self.spawn(&bin, &env, None, log));
    }

    /// Whether `log` holds `needle`: `"event key=value …"` matches a JSON line (ASVS-08)
    /// with that `event` and those fields; anything else is a plain substring.
    fn log_has(&self, log: &str, needle: &str) -> bool {
        let Ok(text) = std::fs::read_to_string(self.dir.join(log)) else {
            return false;
        };
        let mut words = needle.split(' ');
        let event = words.next().unwrap_or_default();
        let fields: Vec<(&str, &str)> = words.filter_map(|w| w.split_once('=')).collect();
        let json = text.lines().any(|l| {
            serde_json::from_str::<serde_json::Value>(l)
                .is_ok_and(|v| v["event"] == event && fields.iter().all(|(k, want)| v[*k] == *want))
        });
        json || text.contains(needle)
    }

    fn wait_log(&self, log: &str, needle: &str) {
        let deadline = Instant::now() + Duration::from_secs(120);
        while !self.log_has(log, needle) {
            assert!(Instant::now() < deadline, "{log}: no {needle:?}");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    async fn wait_sql(&self, q: &str, want: i64, what: &str) {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let got = self.scalar(q).await;
            if got == want {
                return;
            }
            assert!(Instant::now() < deadline, "{what}: {got}, not {want}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Every queued job due now (the engine's 60 s seal retry, a back-off).
    async fn make_due(&self) {
        self.sql("UPDATE jobs SET run_at = now() WHERE status = 'queued'")
            .await;
    }

    /// The worker process is alive (it did not exit on an unavailable dependency).
    fn worker_alive(&mut self, what: &str) {
        let st = self.worker.as_mut().unwrap().try_wait().unwrap();
        assert!(st.is_none(), "{what}: the worker exited: {st:?}");
    }

    /// One signer who must pass an access code: sent, the invitation delivered, then
    /// the worker stopped and the signer authenticated and signed, so the envelope
    /// stands `completing` with its seal job queued.
    async fn completing(&mut self) -> String {
        let tag = Uuid::now_v7().simple().to_string();
        let email = format!("a-{tag}@crash.example.test");
        let body = json!({
            "subject": "Chaos test agreement", "status": "sent",
            "documents": [{"name": "a.pdf",
                "content_base64": base64::engine::general_purpose::STANDARD.encode(common::valid_pdf())}],
            "recipients": [{"ref": "r0", "type": "signer", "name": "Signer A", "email": email,
                "routing_order": 1, "auth": ["access_code"], "access_code": "chaos-4711"}],
            "fields": [{"recipient": "r0", "document": 0, "type": "signature",
                "page": 1, "x": 72, "y": 100, "width": 180, "height": 40, "required": true}],
        });
        let e = self.call(&self.staff, "POST", "/api/v1/envelopes", Some(body), &[]);
        assert_eq!(e.status, 201, "{e:?}");
        let env = e.body["id"].as_str().unwrap().to_owned();
        let field = e.body["fields"][0]["id"].as_str().unwrap().to_owned();
        if self.worker.is_none() {
            self.start_worker(None);
        }
        self.idle().await;
        self.stop_worker();
        let (who, s, finish) = self.authenticate_and_adopt(&email, &field);
        let r = self.call(&who, "POST", &format!("{s}/finish"), Some(finish), &[]);
        assert_eq!(r.status, 200, "{r:?}");
        assert_eq!(self.get(&env)["status"], "completing");
        self.not_served(&env, "before the seal");
        env
    }

    /// Open the emailed link, pass the access code, view and adopt; as [`Stack::open`].
    fn authenticate_and_adopt(&self, email: &str, field: &str) -> (Who, String, Value) {
        let mails = self.smtp.to(email);
        let token = mails
            .last()
            .expect("an invitation")
            .token()
            .expect("a link");
        let s = format!("/s/{token}");
        let opened = self.call(
            &Who::default(),
            "POST",
            &format!("{s}/session"),
            Some(json!({})),
            &[],
        );
        assert_eq!(opened.status, 200, "{opened:?}");
        let who = Who {
            cookie: Some(
                opened.headers["set-cookie"]
                    .split(';')
                    .next()
                    .unwrap()
                    .to_owned(),
            ),
            csrf: None,
        };
        let wrong = self.call(
            &who,
            "POST",
            &format!("{s}/authenticate"),
            Some(json!({"method": "access_code", "code": "wrong"})),
            &[],
        );
        assert_ne!(wrong.status, 200, "a wrong code is refused");
        let v = self.call(
            &who,
            "POST",
            &format!("{s}/authenticate"),
            Some(json!({"method": "access_code", "code": "chaos-4711"})),
            &[],
        );
        assert_eq!(v.status, 200, "{v:?}");
        let doc = v.body["envelope"]["documents"][0]["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let seen = self.call(
            &who,
            "POST",
            &format!("{s}/documents/{doc}/viewed"),
            Some(json!({"pages_seen": [1]})),
            &[],
        );
        assert_eq!(seen.status, 200, "{seen:?}");
        let png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";
        let a = self.call(
            &who,
            "POST",
            &format!("{s}/adopt"),
            Some(json!({"mark": "signature", "method": "draw", "image_base64": png})),
            &[],
        );
        assert_eq!(a.status, 200, "{a:?}");
        let capture = a.body["adoption_id"].as_str().unwrap().to_owned();
        let finish = json!({"values": [{"field": field, "value": {"signature": capture}}]});
        (who, s, finish)
    }

    /// The status of a GET as staff.
    fn status_of(&self, path: &str) -> u16 {
        self.call(&self.staff, "GET", path, None, &[]).status
    }

    /// Nothing sealed is served: no sealed version, no certificate, and the envelope
    /// is not `completed`.
    fn not_served(&self, env: &str, what: &str) {
        let e = self.get(env);
        assert_ne!(e["status"], "completed", "{what}");
        let doc = e["documents"][0]["id"].as_str().unwrap();
        for path in [
            format!("/api/v1/envelopes/{env}/documents/{doc}/content?version=sealed"),
            format!("/api/v1/envelopes/{env}/certificate"),
        ] {
            let st = self.status_of(&path);
            assert!(
                (400..500).contains(&st),
                "{what}: {path} answered {st} before the seal"
            );
        }
    }

    /// The archive of a completed envelope: the sealed PDF verified by ours and pyHanko
    /// (with `document.sealed`, `envelope.completing` and `envelope.completed` once in a
    /// chain that verifies), the certificate and the audit trail served, exactly one
    /// sealed version per document, and no job dead.
    async fn archived(&self, env: &str, label: &str) {
        self.verified_seal(env, label).await;
        for path in [
            format!("/api/v1/envelopes/{env}/certificate"),
            format!("/api/v1/envelopes/{env}/audit"),
        ] {
            assert_eq!(self.status_of(&path), 200, "{label}: {path}");
        }
        let sealed = self
            .scalar(&format!(
                "SELECT count(*) FROM document_versions v JOIN documents d ON d.id = v.document_id \
                 WHERE d.envelope_id = '{env}' AND v.kind = 'sealed'"
            ))
            .await;
        assert_eq!(sealed, 1, "{label}: sealed versions");
        let dead = self
            .scalar("SELECT count(*) FROM jobs WHERE status = 'dead'")
            .await;
        assert_eq!(dead, 0, "{label}: a job dead-lettered");
    }

    fn seal_jobs(env: &str, cond: &str) -> String {
        format!(
            "SELECT count(*) FROM jobs WHERE kind = 'seal_envelope' AND envelope_id = '{env}' AND {cond}"
        )
    }
}

/// HRD-01: a worker frozen mid-seal (`SIGSTOP`: a pause, a partition) past its lease
/// while a second worker takes the job over. When the first wakes and stores its seal
/// it holds no lease: it must write nothing, and the second seals once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_worker_frozen_mid_seal_past_its_lease_writes_nothing_and_the_seal_happens_once() {
    let Some(mut st) = Stack::new("hrd01_frozen").await else {
        return;
    };
    let env = st.completing().await;
    let at = "worker:Sealed:seal_envelope";
    // Worker A seals and stands before storing; frozen there, its lease lapses.
    let dir_a = st.hold_dir("a");
    st.start_worker_held(at, &dir_a, "worker-a.log");
    wait_file(&dir_a.join("reached"), "worker A");
    let a = KillOnDrop(st.worker.take().unwrap());
    signal(&a.0, "STOP");
    st.after_worker_crash().await;
    // Worker B takes the job over and seals; it stands before storing too.
    let dir_b = st.hold_dir("b");
    st.start_worker_held(at, &dir_b, "worker-b.log");
    wait_file(&dir_b.join("reached"), "worker B");
    // A wakes and tries to store its seal under the lease it lost.
    signal(&a.0, "CONT");
    std::fs::write(dir_a.join("release"), b"").unwrap();
    st.wait_log("worker-a.log", "job_failed kind=seal_envelope");
    let stored = st
        .scalar(&format!(
            "SELECT count(*) FROM job_steps s JOIN jobs j ON j.id = s.job_id \
             WHERE j.envelope_id = '{env}' AND s.step = 'seal.stored'"
        ))
        .await;
    assert_eq!(stored, 0, "a worker that lost its lease recorded a seal");
    st.not_served(&env, "after the stale worker");
    drop(a);
    // B stores and completes, on its first attempt.
    std::fs::write(dir_b.join("release"), b"").unwrap();
    st.idle().await;
    st.archived(&env, "frozen").await;
    let attempts = st
        .scalar(&format!(
            "SELECT attempts::bigint FROM jobs WHERE kind = 'seal_envelope' AND envelope_id = '{env}'"
        ))
        .await;
    assert_eq!(attempts, 2, "A's attempt and B's, no retry");
}

/// HRD-01: keyd unavailable while sealing. The envelope stays `completing` (nothing
/// served, no `envelope.completed`), the engine schedules a new seal job each time, a
/// worker started meanwhile stays up and runs its other jobs, and once keyd is back the
/// envelope completes once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keyd_unavailable_while_sealing_keeps_the_envelope_completing_until_it_returns() {
    let Some(mut st) = Stack::new("hrd01_keyd").await else {
        return;
    };
    let env = st.completing().await;
    // A worker that reached keyd at its start; keyd goes away before the seal.
    st.sql(&format!(
        "UPDATE jobs SET run_at = now() + interval '1 hour' \
         WHERE kind = 'seal_envelope' AND envelope_id = '{env}'"
    ))
    .await;
    st.start_worker(None);
    st.idle().await;
    st.keyd_gate.cut();
    st.make_due().await;
    st.wait_sql(
        &Stack::seal_jobs(&env, "status = 'done'"),
        1,
        "the first seal attempt",
    )
    .await;
    st.idle().await;
    assert!(
        st.log_has("worker.log", "seal_failed code=CS-SEAL-0001"),
        "the key provider's failure alerted"
    );
    // A worker started while keyd is down must not exit over it.
    st.start_worker(None);
    st.idle().await;
    st.worker_alive("keyd down at start");
    st.not_served(&env, "keyd down");
    assert_eq!(st.count(&env, "envelope.completed").await, 0);
    assert_eq!(
        st.scalar(&Stack::seal_jobs(&env, "status = 'queued'"))
            .await,
        1,
        "a new seal job scheduled"
    );
    // Other work goes on meanwhile: another envelope's invitation is sent.
    let (other, emails, _) = st.create(1, false);
    st.idle().await;
    assert_eq!(
        st.smtp.to(&emails[0]).len(),
        1,
        "an invitation while keyd is down"
    );
    assert_eq!(st.count(&other, "invitation.sent").await, 1);
    // Still down at the retry (from the worker that never reached keyd), then back.
    st.make_due().await;
    st.wait_sql(
        &Stack::seal_jobs(&env, "status = 'done'"),
        2,
        "the second seal attempt",
    )
    .await;
    st.idle().await;
    st.not_served(&env, "keyd still down");
    st.keyd_gate.restore();
    st.make_due().await;
    st.idle().await;
    st.worker_alive("after keyd returned");
    st.archived(&env, "keyd").await;
}

/// HRD-01: a worker whose keyd settings are wrong does not start, even though keyd
/// unreachable lets it start: keyd's CA not the configured one, keyd's certificate
/// not under the configured name, or this worker's client certificate from another
/// CA. Each is a TLS refusal (`CS-KEY-0013`), a misconfiguration no retry cures, and
/// the worker exits non-zero at start naming it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_worker_misconfigured_against_keyd_exits_at_start() {
    let Some(mut st) = Stack::new("hrd01_keyd_config").await else {
        return;
    };
    st.stop_worker();
    let write = |name: &str, text: &str| {
        let p = st.dir.join(name);
        std::fs::write(&p, text).unwrap();
        p.display().to_string()
    };
    let other_ca = write("other-ca.pem", &Pki::new().tls_ca.pem());
    let rogue = st.keyd_pki.rogue_client_identity("worker");
    let rogue_cert = write("rogue.pem", &rogue.0);
    let rogue_key = write("rogue-key.pem", &rogue.1);
    let cases: [(&str, Vec<(&str, String)>); 3] = [
        ("wrong-ca", vec![("OPENSEAL_KEYD_CA", other_ca)]),
        (
            "wrong-name",
            vec![("OPENSEAL_KEYD_SERVER_NAME", "keyd.elsewhere.test".into())],
        ),
        (
            "untrusted-client",
            vec![
                ("OPENSEAL_KEYD_CLIENT_CERT", rogue_cert),
                ("OPENSEAL_KEYD_CLIENT_KEY", rogue_key),
            ],
        ),
    ];
    for (name, changes) in cases {
        let mut env = st.worker_env.clone();
        for (k, v) in changes {
            env.iter_mut().find(|(ek, _)| ek == k).unwrap().1 = v;
        }
        let log = format!("worker-{name}.log");
        let mut child = KillOnDrop(st.spawn(&worker_bin(), &env, None, &log));
        let deadline = Instant::now() + Duration::from_secs(60);
        let status = loop {
            if let Some(s) = child.0.try_wait().unwrap() {
                break s;
            }
            assert!(
                Instant::now() < deadline,
                "{name}: the worker started against a keyd that refuses it"
            );
            std::thread::sleep(Duration::from_millis(50));
        };
        assert!(!status.success(), "{name}: exited {status:?}");
        assert!(st.log_has(&log, "CS-KEY-0013"), "{name}: the code named");
        assert!(
            !st.log_has(&log, "keyd_unavailable"),
            "{name}: taken for an outage"
        );
    }
}

/// HRD-01: a database failure on a seal job's last attempt while it reads the job's
/// steps (before anything is sealed) hands over to a new seal job instead of
/// dead-lettering it with the envelope `completing`. The failure is a lock timeout:
/// the worker runs with `lock_timeout` 2 s while the test holds `job_steps` locked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_database_failure_on_the_last_seal_attempt_hands_over_to_a_new_seal_job() {
    let Some(mut st) = Stack::new("hrd01_last_attempt").await else {
        return;
    };
    let env = st.completing().await;
    st.sql(&format!(
        "UPDATE jobs SET attempts = max_attempts - 1, run_at = now() \
         WHERE kind = 'seal_envelope' AND envelope_id = '{env}' AND status = 'queued'"
    ))
    .await;
    let normal = st.worker_env.clone();
    for (k, v) in &mut st.worker_env {
        if k == "OPENSEAL_DATABASE_URL" {
            v.push_str("?options[lock_timeout]=2000");
        }
    }
    let dir = st.hold_dir("last");
    st.start_worker_held("worker:Claimed:seal_envelope", &dir, "worker-last.log");
    st.worker_env = normal;
    wait_file(&dir.join("reached"), "the held worker");
    let mut lock = st.db.admin.begin().await.unwrap();
    sqlx::query("LOCK TABLE job_steps IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *lock)
        .await
        .unwrap();
    std::fs::write(dir.join("release"), b"").unwrap();
    // The job's end touches only `jobs` and the envelope: it is written in the lock.
    st.wait_sql(
        &Stack::seal_jobs(&env, "status IN ('done', 'dead')"),
        1,
        "the last attempt",
    )
    .await;
    lock.rollback().await.unwrap();
    assert_eq!(
        st.scalar(&Stack::seal_jobs(&env, "status = 'dead'")).await,
        0,
        "the seal job died with the envelope completing"
    );
    assert_eq!(
        st.scalar(&Stack::seal_jobs(&env, "status = 'queued'"))
            .await,
        1,
        "a new seal job scheduled"
    );
    assert!(
        st.log_has("worker-last.log", "seal_failed"),
        "the handover alerted"
    );
    st.not_served(&env, "after the last attempt");
    st.start_worker(None);
    st.make_due().await;
    st.idle().await;
    st.archived(&env, "last attempt").await;
}

/// The test database: cut at the gate; with `OPENSEAL_CHAOS_PG_CONTAINER` (a container
/// this test may restart, run alone) PostgreSQL itself is restarted inside the cut.
async fn database_outage(st: &Stack) {
    st.db_gate.cut();
    if let Ok(name) = std::env::var("OPENSEAL_CHAOS_PG_CONTAINER") {
        let ok = Command::new("docker")
            .args(["restart", "-t", "1", &name])
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(ok.success(), "docker restart {name}");
        let deadline = Instant::now() + Duration::from_secs(60);
        while !Command::new("docker")
            .args(["exec", &name, "pg_isready", "-U", "postgres", "-q"])
            .status()
            .unwrap()
            .success()
        {
            assert!(Instant::now() < deadline, "PostgreSQL did not come back");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}

/// HRD-01: PostgreSQL lost mid-ceremony and mid-seal. Requests during the outage get a
/// problem answer and the server stays up; the signer's retry afterwards signs once; the
/// worker whose seal was interrupted stores nothing, its job is claimed again once its
/// lease lapses, and the envelope completes once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_database_outage_mid_ceremony_and_mid_seal_recovers_without_a_double_seal() {
    let Some(mut st) = Stack::new("hrd01_database").await else {
        return;
    };
    // Mid-ceremony: the finish lands in the outage.
    let (env, emails, fields) = st.create(2, false);
    st.idle().await;
    let (who, s, finish) = st.open(&emails[0], &fields[0]);
    database_outage(&st).await;
    let r = st.call(
        &who,
        "POST",
        &format!("{s}/finish"),
        Some(finish.clone()),
        &[],
    );
    assert!(r.status >= 500, "a finish in the outage answered {r:?}");
    let r = st.call(
        &st.staff,
        "GET",
        &format!("/api/v1/envelopes/{env}"),
        None,
        &[],
    );
    assert!(
        r.status >= 500,
        "a read in the outage answered {}",
        r.status
    );
    assert!(
        st.server.as_mut().unwrap().try_wait().unwrap().is_none(),
        "the server exited in the outage"
    );
    st.db_gate.restore();
    let deadline = Instant::now() + Duration::from_secs(60);
    while st.status_of(&format!("/api/v1/envelopes/{env}")) != 200 {
        assert!(Instant::now() < deadline, "the server did not recover");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let r = st.call(&who, "POST", &format!("{s}/finish"), Some(finish), &[]);
    assert_eq!(r.status, 200, "the retry after the outage: {r:?}");
    assert_eq!(st.count(&env, "recipient.signed").await, 1);
    // The worker rode the outage out.
    st.idle().await;
    st.worker_alive("after the ceremony outage");
    // Mid-seal: the worker has sealed and stands before storing when the database goes.
    st.stop_worker();
    st.sign(&emails[1], &fields[1]);
    assert_eq!(st.get(&env)["status"], "completing");
    let dir = st.hold_dir("db");
    st.start_worker_held("worker:Sealed:seal_envelope", &dir, "worker-db.log");
    wait_file(&dir.join("reached"), "the held worker");
    database_outage(&st).await;
    std::fs::write(dir.join("release"), b"").unwrap();
    st.wait_log("worker-db.log", "job_failed kind=seal_envelope");
    st.db_gate.restore();
    st.worker_alive("the database outage");
    // The job runs again: once its lease lapses if its failure could not be recorded
    // (300 s), after its back-off if it was recorded once the database returned
    // (30 s or more); here both at once.
    st.after_worker_crash().await;
    st.make_due().await;
    st.idle().await;
    st.archived(&env, "database").await;
}

/// HRD-01: the object store refuses writes while sealing. The sealed bytes never land,
/// nothing is served, the envelope stays `completing`; a job that reaches its last
/// attempt hands over to a new seal job rather than dying; once the store takes writes
/// again the envelope completes once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_object_store_refusing_writes_leaves_nothing_served_and_the_seal_recovers() {
    use std::os::unix::fs::PermissionsExt as _;
    let Some(mut st) = Stack::new("hrd01_blobs").await else {
        return;
    };
    let env = st.completing().await;
    let blobs_before = count_files(&st.blobs);
    let tmp = st.blobs.join("tmp");
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o555)).unwrap();
    st.start_worker(None);
    st.wait_sql(
        &Stack::seal_jobs(
            &env,
            "last_error_code = 'CS-BLOB-0001' AND status = 'queued'",
        ),
        1,
        "a refused write",
    )
    .await;
    st.not_served(&env, "the store refusing writes");
    assert_eq!(count_files(&st.blobs), blobs_before, "a sealed blob landed");
    assert_eq!(st.count(&env, "document.sealed").await, 0);
    // A long outage: the job reaches its last attempt.
    st.sql(&format!(
        "UPDATE jobs SET attempts = max_attempts - 1, run_at = now() \
         WHERE kind = 'seal_envelope' AND envelope_id = '{env}' AND status = 'queued'"
    ))
    .await;
    st.wait_sql(
        &Stack::seal_jobs(&env, "status IN ('done', 'dead')"),
        1,
        "the last attempt",
    )
    .await;
    st.idle().await;
    assert_eq!(
        st.scalar(&Stack::seal_jobs(&env, "status = 'dead'")).await,
        0,
        "the seal job died with the envelope completing"
    );
    assert_eq!(
        st.scalar(&Stack::seal_jobs(&env, "status = 'queued'"))
            .await,
        1,
        "a new seal job scheduled"
    );
    st.not_served(&env, "after the last attempt");
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
    st.make_due().await;
    st.idle().await;
    st.archived(&env, "blobs").await;
}
