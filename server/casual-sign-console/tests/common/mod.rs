//! Test harness: a fresh database per test on the PostgreSQL that
//! `OPENSEAL_TEST_DATABASE_URL` names (a superuser URL). Every migration in `migrations/`
//! is applied as that superuser (the owner); the console under test connects as a LOGIN
//! role that is a member of `openseal_console` only, so its grants apply exactly as in
//! production. Without the variable each database test prints a note and passes
//! vacuously; CI sets it.
//!
//! Tenant data is seeded as the owner with recognisable personal data and content, so the
//! isolation tests can look for it in every console response.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    dead_code,
    missing_docs,
    missing_debug_implementations
)]

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use casual_sign_console::crypto::{MfaKey, random_secret, sha256};
use casual_sign_console::{AppState, Clock, Config};
use casual_sign_platform_store::sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use casual_sign_platform_store::sqlx::{self, ConnectOptions, Executor};
use casual_sign_platform_store::{NewOperator, PlatformStore};
use http_body_util::BodyExt;
use serde_json::Value;
use time::OffsetDateTime;
use tower::ServiceExt;
use uuid::Uuid;

pub const ENV: &str = "OPENSEAL_TEST_DATABASE_URL";
const CONSOLE_LOGIN: &str = "openseal_console_test";
const CONSOLE_PASSWORD: &str = "openseal-console-test-only";

/// Personal data and content seeded into the tenant tables; none may appear in any
/// console response.
pub const SEEDED_SECRETS: &[&str] = &[
    "alice.seed@example.test",
    "Alice Seedperson",
    "bob.recipient@example.test",
    "Bob Recipientname",
    "Secret merger subject",
    "Confidential message body",
    "+15550001111",
    "argon2-not-a-real-hash-seed",
];

pub struct TestDb {
    pub owner: PgPool,
    pub console: PgPool,
    name: String,
    server: PgConnectOptions,
}

pub fn server_url(test: &str) -> Option<String> {
    match std::env::var(ENV) {
        Ok(u) if !u.is_empty() => Some(u),
        _ => {
            eprintln!("SKIPPED {test}: set {ENV} to a PostgreSQL superuser URL to run it");
            None
        }
    }
}

fn migrations() -> Vec<(String, String)> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "sql"))
        .collect();
    files.sort();
    files
        .into_iter()
        .map(|p| {
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                std::fs::read_to_string(&p).unwrap(),
            )
        })
        .collect()
}

/// A fresh, migrated database with the console's login role, or `None`.
pub async fn fresh(test: &str) -> Option<TestDb> {
    let url = server_url(test)?;
    let server: PgConnectOptions = url
        .parse::<PgConnectOptions>()
        .unwrap()
        .disable_statement_logging();
    let maint = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(server.clone())
        .await
        .unwrap();
    let name = format!("openseal_c_{}", Uuid::now_v7().simple());
    maint
        .execute(sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "CREATE DATABASE {name}"
        ))))
        .await
        .unwrap();
    maint.close().await;
    let owner = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(server.clone().database(&name))
        .await
        .unwrap();
    for (file, sql) in migrations() {
        if let Err(e) = owner.execute(sqlx::raw_sql(sqlx::AssertSqlSafe(sql))).await {
            panic!("migration {file}: {e}");
        }
    }
    let create = format!(
        "DO $$ BEGIN CREATE ROLE {CONSOLE_LOGIN} LOGIN PASSWORD '{CONSOLE_PASSWORD}' IN ROLE openseal_console; \
         EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$"
    );
    owner
        .execute(sqlx::raw_sql(sqlx::AssertSqlSafe(create)))
        .await
        .unwrap();
    let console = PgPool::connect_lazy_with(
        server
            .clone()
            .database(&name)
            .username(CONSOLE_LOGIN)
            .password(CONSOLE_PASSWORD),
    );
    Some(TestDb {
        owner,
        console,
        name,
        server,
    })
}

/// Ids of the seeded tenant.
#[derive(Debug, Clone, Copy)]
pub struct Seed {
    pub org: Uuid,
    pub workspace: Uuid,
    pub user: Uuid,
    pub envelope: Uuid,
    pub job: Uuid,
}

impl TestDb {
    /// One organization with one workspace, an owner, a template, a sent envelope with a
    /// recipient, and a dead job whose payload names the recipient.
    pub async fn seed(&self) -> Seed {
        let s = Seed {
            org: Uuid::now_v7(),
            workspace: Uuid::now_v7(),
            user: Uuid::now_v7(),
            envelope: Uuid::now_v7(),
            job: Uuid::now_v7(),
        };
        let profile = Uuid::now_v7();
        let sql = format!(
            "INSERT INTO organizations (id, name) VALUES ('{org}', 'Acme Seed Org');
             INSERT INTO accounts (id, name, organization_id) VALUES ('{ws}', 'Acme Seed Workspace', '{org}');
             INSERT INTO permission_profiles (id, account_id, name, kind) VALUES ('{pp}', '{ws}', 'Administrator', 'admin');
             INSERT INTO users (id, email, email_normalized, name, login_kind, password_hash)
               VALUES ('{u}', 'alice.seed@example.test', 'alice.seed@example.test', 'Alice Seedperson', 'local', 'argon2-not-a-real-hash-seed');
             INSERT INTO account_memberships (account_id, user_id, permission_profile_id) VALUES ('{ws}', '{u}', '{pp}');
             INSERT INTO organization_admins (organization_id, user_id, role, created_at) VALUES ('{org}', '{u}', 'owner', now());
             INSERT INTO templates (id, account_id, owner_user_id, name) VALUES ('{t}', '{ws}', '{u}', 'Seed template');
             INSERT INTO envelopes (id, account_id, sender_user_id, status, subject, message)
               VALUES ('{e}', '{ws}', '{u}', 'sent', 'Secret merger subject', 'Confidential message body');
             INSERT INTO recipients (id, account_id, envelope_id, routing_order, type, name, email, phone)
               VALUES ('{r}', '{ws}', '{e}', 1, 'signer', 'Bob Recipientname', 'bob.recipient@example.test', '+15550001111');
             INSERT INTO jobs (id, account_id, envelope_id, kind, idempotency_key, payload, status, run_at, attempts, last_error_code, finished_at)
               VALUES ('{j}', '{ws}', '{e}', 'send_invitation', 'seed-1', '{{\"to\": \"bob.recipient@example.test\"}}'::jsonb, 'dead', now(), 15, 'CS-MAIL-0001', now());
             INSERT INTO jobs (id, account_id, kind, idempotency_key, status, run_at)
               VALUES ('{j2}', '{ws}', 'deliver_webhook', 'seed-2', 'queued', now() - interval '90 seconds');",
            org = s.org,
            ws = s.workspace,
            pp = profile,
            u = s.user,
            t = Uuid::now_v7(),
            e = s.envelope,
            r = Uuid::now_v7(),
            j = s.job,
            j2 = Uuid::now_v7(),
        );
        self.owner
            .execute(sqlx::raw_sql(sqlx::AssertSqlSafe(sql)))
            .await
            .unwrap();
        s
    }

    pub async fn drop(self) {
        self.owner.close().await;
        self.console.close().await;
        let maint = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(self.server.clone())
            .await
            .unwrap();
        maint
            .execute(sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                self.name
            ))))
            .await
            .unwrap();
        maint.close().await;
    }
}

/// A clock the test moves.
#[derive(Debug, Clone)]
pub struct TestClock(pub Arc<Mutex<OffsetDateTime>>);

impl TestClock {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(
            OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
        )))
    }
    pub fn advance(&self, secs: i64) {
        let mut t = self.0.lock().unwrap();
        *t += time::Duration::seconds(secs);
    }
    pub fn get(&self) -> OffsetDateTime {
        *self.0.lock().unwrap()
    }
}

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        self.get()
    }
}

pub const MFA_KEY: [u8; 32] = [42u8; 32];

/// The console app over the test database.
pub struct Console {
    pub app: axum::Router,
    pub clock: TestClock,
    pub store: PlatformStore,
}

pub fn console(db: &TestDb) -> Console {
    console_with(db, Config::default())
}

/// The console app over the test database with `config`.
pub fn console_with(db: &TestDb, config: Config) -> Console {
    let clock = TestClock::new();
    let store = PlatformStore::new(db.console.clone());
    let state = AppState::new(
        store.clone(),
        MfaKey::new(&MFA_KEY).unwrap(),
        Arc::new(clock.clone()),
        config,
    )
    .unwrap();
    Console {
        app: casual_sign_console::app(state),
        clock,
        store,
    }
}

/// A response: status, headers and body (JSON when it parses).
#[derive(Debug)]
pub struct Resp {
    pub status: StatusCode,
    pub headers: axum::http::HeaderMap,
    pub text: String,
}

impl Resp {
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.text).unwrap_or(Value::Null)
    }
    pub fn code(&self) -> String {
        self.json()["code"].as_str().unwrap_or("").to_owned()
    }
}

/// A browser-like session: the cookie and CSRF token once signed in.
#[derive(Debug, Clone, Default)]
pub struct Session {
    pub cookie: Option<String>,
    pub csrf: Option<String>,
}

impl Console {
    pub async fn call(&self, s: &Session, method: &str, path: &str, body: Option<Value>) -> Resp {
        let mut req = Request::builder().method(method).uri(path);
        if let Some(c) = &s.cookie {
            req = req.header(header::COOKIE, format!("__Host-os_op={c}"));
        }
        if let Some(t) = &s.csrf {
            req = req.header("x-csrf-token", t);
        }
        let req = match body {
            Some(b) => req
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(b.to_string()))
                .unwrap(),
            None => req.body(Body::empty()).unwrap(),
        };
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        Resp {
            status,
            headers,
            text: String::from_utf8_lossy(&bytes).into_owned(),
        }
    }

    /// The current TOTP code of a seed, after moving the clock to a fresh time step.
    pub fn next_code(&self, seed: &[u8]) -> String {
        self.clock.advance(30);
        let step = casual_sign_console::totp::step_at(self.clock.get().unix_timestamp());
        casual_sign_console::totp::code(seed, step)
    }

    /// A new operator with `roles` created directly (bootstrap for the first), enrolled
    /// through the API with `password`; their TOTP seed.
    pub async fn enrol(&self, token: &str, password: &str) -> Vec<u8> {
        let none = Session::default();
        let r = self
            .call(
                &none,
                "POST",
                "/console/v1/auth/enrolment/begin",
                Some(serde_json::json!({"token": token})),
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text);
        let uri = r.json()["otpauth_uri"].as_str().unwrap().to_owned();
        let secret = uri
            .split("secret=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap()
            .to_owned();
        let seed = base32_decode(&secret);
        let code = self.next_code(&seed);
        let r = self
            .call(
                &none,
                "POST",
                "/console/v1/auth/enrolment/finish",
                Some(serde_json::json!({"token": token, "password": password, "code": code})),
            )
            .await;
        assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.text);
        seed
    }

    /// Sign in with password only: a session that still needs its second factor.
    pub async fn password_only(&self, email: &str, password: &str) -> Session {
        let r = self
            .call(
                &Session::default(),
                "POST",
                "/console/v1/auth/login",
                Some(serde_json::json!({"email": email, "password": password})),
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text);
        let cookie = r.headers[header::SET_COOKIE].to_str().unwrap().to_owned();
        assert!(cookie.starts_with("__Host-os_op="));
        assert!(
            cookie.contains("Secure")
                && cookie.contains("HttpOnly")
                && cookie.contains("SameSite=Strict")
        );
        let token = cookie
            .trim_start_matches("__Host-os_op=")
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        Session {
            cookie: Some(token),
            csrf: Some(r.json()["csrf_token"].as_str().unwrap().to_owned()),
        }
    }

    /// Sign in fully: password then TOTP.
    pub async fn sign_in(&self, email: &str, password: &str, seed: &[u8]) -> Session {
        let s = self.password_only(email, password).await;
        let code = self.next_code(seed);
        let r = self
            .call(
                &s,
                "POST",
                "/console/v1/auth/totp",
                Some(serde_json::json!({"code": code})),
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text);
        s
    }

    /// Bootstrap the first platform owner and enrol them; their seed.
    pub async fn bootstrap(&self, email: &str, password: &str) -> Vec<u8> {
        let token = random_secret().unwrap();
        let now = self.clock.get();
        let new = NewOperator {
            id: Uuid::now_v7(),
            email,
            enrolment_sha256: sha256(token.as_bytes()),
            enrolment_expires: now + time::Duration::hours(24),
        };
        let mut tx = self.store.begin().await.unwrap();
        assert!(tx.bootstrap_operator(&new, now).await.unwrap());
        tx.commit().await.unwrap();
        self.enrol(&token, password).await
    }
}

/// RFC 4648 base32 decoding (test side, to read the enrolment URI).
pub fn base32_decode(s: &str) -> Vec<u8> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits = 0;
    for c in s.bytes() {
        let v = A.iter().position(|x| *x == c).unwrap() as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    out
}
