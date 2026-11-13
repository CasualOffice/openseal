//! The worker time-stamps with the TSAs the console configured (`CON-07`, docs/23 §5.4):
//! the enabled rows of `platform.tsa_endpoints`, read through `openseal_tsa_endpoints()`,
//! replace `OPENSEAL_TSA_URLS` (here unreachable), and each database URL passes the
//! `SEC-W01` address policy again when it is used (`SEC-X06`).
//!
//! Needs `OPENSEAL_TEST_DATABASE_URL`; without it each test passes vacuously.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use casual_sign_model::EnvelopeStatus;
use casual_sign_sdk::{Profile, TimestampSource};
use casual_sign_worker::tsa::TsaDirectory;
use casual_sign_worker::webhook::{IpRange, SsrfPolicy};
use common::{Env, pki};
use uuid::Uuid;

/// An RFC 3161 TSA over plain HTTP on loopback, answering with the test PKI's TSA.
fn http_tsa(start: Duration) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/tsr", listener.local_addr().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    std::thread::spawn(move || {
        let tsa = pki::TestTsa::new(start);
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut len = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                let lower = line.to_ascii_lowercase();
                if let Some(v) = lower.strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
                if line == "\r\n" {
                    break;
                }
            }
            let mut body = vec![0u8; len];
            reader.read_exact(&mut body).unwrap();
            counted.fetch_add(1, Ordering::SeqCst);
            let answer = tsa.timestamp(&body).unwrap();
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/timestamp-reply\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                answer.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&answer);
        }
    });
    (url, calls)
}

/// A TSA endpoint row as two key custodians would leave it (written here as the owner).
async fn configure(env: &Env, url: &str) {
    let op = Uuid::now_v7();
    let req = Uuid::now_v7();
    let admin = &env.db.admin;
    sqlx::query(
        "INSERT INTO platform.operators (id, email, roles, created_at) \
         VALUES ($1, 'custodian@ops.example', ARRAY['key_custodian'], now())",
    )
    .bind(op)
    .execute(admin)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO platform.approval_requests (id, requester, action, payload_sha256, target, created_at, expires_at) \
         VALUES ($1, $2, 'tsa.set', sha256('x'::bytea), $3, now(), now() + interval '1 hour')",
    )
    .bind(req)
    .bind(op)
    .bind(Uuid::now_v7())
    .execute(admin)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO platform.tsa_endpoints (id, url, priority, enabled, changed_at, approval) \
         VALUES ($1, $2, 10, true, now(), $3)",
    )
    .bind(Uuid::now_v7())
    .bind(url)
    .bind(req)
    .execute(admin)
    .await
    .unwrap();
}

/// Sign a two-signer envelope through; the final status.
async fn complete(env: &Env) -> EnvelopeStatus {
    let ids = env.draft(vec![]).await;
    env.send(ids).await;
    env.run().await;
    env.sign(ids, ids.r1, ids.f1, "Ada Lovelace").await;
    env.run().await;
    env.sign(ids, ids.r2, ids.f2, "Grace Hopper").await;
    env.run().await;
    let s = env.state(ids.env).await.status;
    if s == EnvelopeStatus::Completed {
        let sealed = env.sealed_bytes(ids.env).await;
        let mut options = env.engine.verify_options(Duration::from_millis(
            u64::try_from(env.clock.ms()).unwrap(),
        ));
        options.crls = vec![pki::pki().root_crl.clone(), pki::pki().inter_crl.clone()];
        let report = env.engine.verify(&sealed[0], &pki::trust(), &options);
        casual_sign_worker::seal::check_verified(&report, Profile::BaselineT).unwrap();
    }
    s
}

fn directory(allow_loopback: bool) -> Arc<TsaDirectory> {
    let policy = SsrfPolicy {
        allow: if allow_loopback {
            vec![IpRange::parse("127.0.0.0/8").unwrap()]
        } else {
            Vec::new()
        },
    };
    // The environment's TSA is unreachable: only the database's can time-stamp.
    TsaDirectory::new(
        vec!["http://127.0.0.1:9/unreachable".into()],
        policy,
        Duration::from_secs(60),
    )
}

/// **A seal uses the database's TSA**, not `OPENSEAL_TSA_URLS`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_seal_time_stamps_with_the_tsa_in_the_database() {
    let Some(env) = Env::new("a_seal_time_stamps_with_the_tsa_in_the_database").await else {
        return;
    };
    let start = Duration::from_millis(u64::try_from(env.clock.ms()).unwrap() + 1000);
    let (url, calls) = http_tsa(start);
    configure(&env, &url).await;
    *env.tsa_directory.lock().unwrap() = Some(directory(true));
    assert_eq!(complete(&env).await, EnvelopeStatus::Completed);
    assert!(
        calls.load(Ordering::SeqCst) >= 1,
        "the database's TSA answered"
    );
}

/// **`SEC-X06` at use:** a database TSA on an address the policy refuses is never
/// contacted, so the seal waits rather than time-stamping there.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_database_tsa_on_a_refused_address_is_not_contacted() {
    let Some(env) = Env::new("a_database_tsa_on_a_refused_address_is_not_contacted").await else {
        return;
    };
    let start = Duration::from_millis(u64::try_from(env.clock.ms()).unwrap() + 1000);
    let (url, calls) = http_tsa(start);
    configure(&env, &url).await;
    *env.tsa_directory.lock().unwrap() = Some(directory(false));
    assert_ne!(complete(&env).await, EnvelopeStatus::Completed);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
