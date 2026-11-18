//! Rotations that need the server itself (docs/65 §Rotation):
//!
//! - `HRD-12`: the second-factor key. With the new key as `OPENSEAL_MFA_KEY` and the old
//!   one as `OPENSEAL_MFA_PREVIOUS_KEY`, a staff seed sealed under the old key still
//!   verifies, and ends under the new key: on use, or by `casual-sign-server
//!   mfa-reseal` for users who do not sign in; a server with the new key alone then
//!   verifies every one of them.
//! - `HRD-11`: a stopping replica drains. The ops listener's `GET /readyz` answers `503`
//!   for `OPENSEAL_DRAIN_SECONDS` while every API request is still served, so the proxy
//!   in front of two replicas moves new requests to the other before this one stops
//!   taking connections.

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

use std::io::{Read as _, Write as _};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use base64::Engine as _;
use casual_sign_server::{Clock as _, MfaKey, totp};
use common::Rls;
use common::harness::{Api, Auth, MFA_KEY, PASSWORD, session_of};
use serde_json::json;

const SERVER: &str = env!("CARGO_BIN_EXE_casual-sign-server");
const NEW_KEY: [u8; 32] = [9u8; 32];
const THIRD_KEY: [u8; 32] = [3u8; 32];

fn b64(k: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(k)
}

fn run(args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(SERVER);
    cmd.env_clear().args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

async fn sealed_seed(api: &Api, email: &str) -> Vec<u8> {
    sqlx::query_scalar("SELECT totp_seed_sealed FROM users WHERE email = $1")
        .bind(email)
        .fetch_one(&api.db.admin)
        .await
        .unwrap()
}

/// Sign `email` in and pass the second factor with a TOTP code from its seed (never a
/// recovery code, which would not touch the seed): the clock moves to a fresh step
/// first, so every call proves the seed again.
async fn sign_in_with_code(api: &Api, email: &str) -> StatusCode {
    api.clock.advance(Duration::from_secs(30));
    let r = api
        .call(
            "POST",
            "/api/v1/auth/login",
            &Auth::None,
            Some(json!({"email": email, "password": PASSWORD})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let s = session_of(&r);
    let seed = api.factors.lock().unwrap()[email].seed.clone();
    let step = totp::step_at(api.clock.now().unix_timestamp());
    let r = api
        .call(
            "POST",
            "/api/v1/auth/mfa/verify",
            &s,
            Some(json!({"code": totp::code(&seed, step)})),
            &[],
        )
        .await;
    r.status
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_factor_seeds_under_the_old_key_still_verify_and_end_under_the_new_one() {
    let Some(mut api) = Api::new("rotation_mfa_key", Rls::On).await else {
        return;
    };
    // Two administrators enrol under the old key (the harness's MFA_KEY).
    let t = api.tenant("rotate").await;
    let r = api
        .call(
            "POST",
            "/api/v1/users",
            &t.auth,
            Some(
                json!({"email": "idle@rotate.example.test", "name": "Idle Admin",
                        "profile": "admin", "password": PASSWORD}),
            ),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.json());
    let idle = "idle@rotate.example.test";
    api.login(idle, PASSWORD).await;
    let active_old = sealed_seed(&api, &t.email).await;
    let idle_old = sealed_seed(&api, idle).await;

    // The key rotated: the new key alone would lock both out.
    api.restart_with(MfaKey::new(&NEW_KEY).unwrap());
    assert_eq!(
        sign_in_with_code(&api, &t.email).await,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a seed under the old key opened under the new key alone"
    );
    // The database re-seals a confirmed factor only for a session that passed it: a
    // signed-in session that owes the factor cannot swap the seed (as the server's role).
    let r = api
        .call(
            "POST",
            "/api/v1/auth/login",
            &Auth::None,
            Some(json!({"email": t.email, "password": PASSWORD})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let session: uuid::Uuid = sqlx::query_scalar(
        "SELECT s.id FROM staff_sessions s JOIN users u ON u.id = s.user_id \
         WHERE u.email = $1 AND s.mfa_at IS NULL ORDER BY s.created_at DESC LIMIT 1",
    )
    .bind(&t.email)
    .fetch_one(&api.db.admin)
    .await
    .unwrap();
    let mut tx = api.db.app.begin().await.unwrap();
    sqlx::query("SELECT set_config('openseal.account_id', $1, true)")
        .bind(t.boot.account.0.to_string())
        .execute(&mut *tx)
        .await
        .unwrap();
    let swapped: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT openseal_reseal_own_totp($1, $2, $3, $4)")
            .bind(session)
            .bind(&active_old)
            .bind(vec![0u8; 40])
            .bind(api.clock.now())
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(swapped, None, "a session owing the factor re-sealed it");
    assert_eq!(sealed_seed(&api, &t.email).await, active_old);

    // With the old key as the previous one, the seed verifies, and is re-sealed on use.
    api.restart_with(
        MfaKey::new(&NEW_KEY)
            .unwrap()
            .with_previous(&MFA_KEY)
            .unwrap(),
    );
    assert_eq!(sign_in_with_code(&api, &t.email).await, StatusCode::OK);
    let active_new = sealed_seed(&api, &t.email).await;
    assert_ne!(active_new, active_old, "the seed was not re-sealed on use");
    assert_eq!(
        sealed_seed(&api, idle).await,
        idle_old,
        "a seed not used is unchanged"
    );

    // `mfa-reseal` moves the seed of the user who has not signed in, as the owner.
    let owner = api.db.owner_url();
    let (new, old) = (b64(&NEW_KEY), b64(&MFA_KEY));
    let env = [
        ("OPENSEAL_MIGRATE_DATABASE_URL", owner.as_str()),
        ("OPENSEAL_MFA_KEY", new.as_str()),
        ("OPENSEAL_MFA_PREVIOUS_KEY", old.as_str()),
    ];
    let o = run(&["mfa-reseal"], &env);
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(
        out.trim(),
        "mfa seeds: resealed=1 current=1 changed=0 unopened=0"
    );
    assert_ne!(sealed_seed(&api, idle).await, idle_old);
    // Again: nothing left under the old key.
    let o = run(&["mfa-reseal"], &env);
    assert_eq!(
        String::from_utf8_lossy(&o.stdout).trim(),
        "mfa seeds: resealed=0 current=2 changed=0 unopened=0"
    );

    // The previous key retired: both verify under the new key alone.
    api.restart_with(MfaKey::new(&NEW_KEY).unwrap());
    assert_eq!(sign_in_with_code(&api, &t.email).await, StatusCode::OK);
    assert_eq!(sign_in_with_code(&api, idle).await, StatusCode::OK);

    // A seed that opens under neither key fails the command, naming no seed.
    let third = b64(&THIRD_KEY);
    let o = run(
        &["mfa-reseal"],
        &[
            ("OPENSEAL_MIGRATE_DATABASE_URL", owner.as_str()),
            ("OPENSEAL_MFA_KEY", third.as_str()),
        ],
    );
    assert!(!o.status.success());
    assert_eq!(
        String::from_utf8_lossy(&o.stdout).trim(),
        "mfa seeds: resealed=0 current=0 changed=0 unopened=2"
    );
    api.db.drop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_enrolment_begun_under_the_old_key_is_confirmed_under_the_new_one() {
    let Some(mut api) = Api::new("rotation_mfa_enrol", Rls::On).await else {
        return;
    };
    let (_, email) = api.bare_tenant("enrol").await;
    let r = api
        .call(
            "POST",
            "/api/v1/auth/login",
            &Auth::None,
            Some(json!({"email": email, "password": PASSWORD})),
            &[],
        )
        .await;
    let s = session_of(&r);
    let r = api
        .call("POST", "/api/v1/auth/mfa/totp/enrol", &s, None, &[])
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let seed = common::harness::unbase32(r.json()["secret"].as_str().unwrap());
    let begun = sealed_seed(&api, &email).await;

    api.restart_with(
        MfaKey::new(&NEW_KEY)
            .unwrap()
            .with_previous(&MFA_KEY)
            .unwrap(),
    );
    let step = totp::step_at(api.clock.now().unix_timestamp());
    let r = api
        .call(
            "POST",
            "/api/v1/auth/mfa/totp/confirm",
            &s,
            Some(json!({"code": totp::code(&seed, step)})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    assert_ne!(sealed_seed(&api, &email).await, begun);
    api.factors.lock().unwrap().insert(
        email.clone(),
        common::harness::Factor {
            seed,
            recovery: Vec::new(),
            last_step: Some(step),
        },
    );
    api.restart_with(MfaKey::new(&NEW_KEY).unwrap());
    assert_eq!(sign_in_with_code(&api, &email).await, StatusCode::OK);
    api.db.drop().await;
}

/// The ops listener's answer to `GET path` (`CON-05`), in process.
async fn ops(api: &Api, path: &str) -> (StatusCode, String) {
    use tower::ServiceExt as _;
    let r = casual_sign_server::ops_app(api.st.clone())
        .oneshot(
            axum::http::Request::get(path)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let cache = r.headers()["cache-control"].to_str().unwrap().to_owned();
    (r.status(), cache)
}

#[tokio::test]
async fn a_draining_server_is_not_ready_but_still_serves() {
    let Some(api) = Api::new("rotation_drain", Rls::On).await else {
        return;
    };
    assert_eq!(
        ops(&api, "/readyz").await,
        (StatusCode::NO_CONTENT, "no-store".into())
    );
    assert_eq!(ops(&api, "/livez").await.0, StatusCode::NO_CONTENT);
    api.st.set_draining();
    assert_eq!(
        ops(&api, "/readyz").await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(ops(&api, "/livez").await.0, StatusCode::NO_CONTENT);
    let r = api
        .call("GET", "/.well-known/jwks.json", &Auth::None, None, &[])
        .await;
    assert_eq!(
        r.status,
        StatusCode::OK,
        "a draining server refused a request"
    );
    api.db.drop().await;
}

#[tokio::test]
async fn a_server_whose_database_does_not_answer_is_not_ready() {
    use std::sync::Arc;
    use tower::ServiceExt as _;
    // A pool to a port nothing listens on: every ping fails.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(Duration::from_secs(2))
        .connect_lazy("postgres://nobody:nothing@127.0.0.1:1/none")
        .unwrap();
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("ready-db-{}", uuid::Uuid::now_v7()));
    let st = casual_sign_server::AppState::new(
        casual_sign_store::Store::from_pool(pool),
        casual_sign_server::Blobs::Fs(Arc::new(
            casual_sign_store::blob::FsBlobStore::new(dir.clone()).unwrap(),
        )),
        casual_sign_server::JwtKeys::generate().unwrap(),
        Arc::new(casual_sign_server::ManualClock::at(common::harness::start())),
        casual_sign_server::Config::default(),
    )
    .unwrap();
    for (path, want) in [
        ("/readyz", StatusCode::SERVICE_UNAVAILABLE),
        ("/livez", StatusCode::NO_CONTENT),
    ] {
        let r = casual_sign_server::ops_app(st.clone())
            .oneshot(
                axum::http::Request::get(path)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), want, "{path}");
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// One plain HTTP GET to one of the server's ports: the status, or `None` when nothing answers.
fn get(port: u16, path: &str) -> Option<u16> {
    let mut c = std::net::TcpStream::connect(("127.0.0.1", port)).ok()?;
    c.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    write!(
        c,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut head = [0u8; 12];
    c.read_exact(&mut head).ok()?;
    std::str::from_utf8(&head[9..12]).ok()?.parse().ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_sigint_the_server_drains_then_stops() {
    let Some(api) = Api::new("rotation_drain_process", Rls::On).await else {
        return;
    };
    let free = || {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    };
    let (port, ops_port) = (free(), free());
    let blobs = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("drain-{}", uuid::Uuid::now_v7()));
    let mut child = Command::new(SERVER)
        .env_clear()
        .env("OPENSEAL_DATABASE_URL", api.db.app_url())
        .env("OPENSEAL_DEV_INSECURE_KEY", "1")
        .env("OPENSEAL_PUBLIC_URL", "http://127.0.0.1")
        .env("OPENSEAL_BLOB_DIR", &blobs)
        .env("OPENSEAL_LISTEN", format!("127.0.0.1:{port}"))
        .env("OPENSEAL_OPS_LISTEN", format!("127.0.0.1:{ops_port}"))
        .env("OPENSEAL_DRAIN_SECONDS", "3")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while get(ops_port, "/readyz") != Some(204) {
        assert!(Instant::now() < deadline, "the server never became ready");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let signalled = Instant::now();
    let kill = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(kill.success());
    let deadline = Instant::now() + Duration::from_secs(2);
    while get(ops_port, "/readyz") != Some(503) {
        assert!(
            Instant::now() < deadline,
            "readyz did not turn 503 on SIGINT"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Draining: not ready, yet every other request is still served.
    assert_eq!(get(port, "/.well-known/jwks.json"), Some(200));
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        assert!(
            signalled.elapsed() < Duration::from_secs(20),
            "the server did not stop after draining"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert!(status.success(), "{status}");
    assert!(
        signalled.elapsed() >= Duration::from_secs(3),
        "stopped after {:?}, before the drain ended",
        signalled.elapsed()
    );
    assert_eq!(get(port, "/.well-known/jwks.json"), None);
    assert_eq!(get(ops_port, "/readyz"), None);
    let _ = std::fs::remove_dir_all(blobs);
    api.db.drop().await;
}
