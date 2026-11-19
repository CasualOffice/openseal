//! Sandbox workspaces in the worker (ADR-041, `VS-08D`): every email says it is a
//! sandbox test; a sandbox envelope is sealed with the sandbox key only, its `/Reason`
//! saying it is not for agreements, and waits unsealed (`CS-WRK-0020`) while no sandbox
//! key is configured: never sealed with the platform key.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use casual_sign_model::EnvelopeStatus;
use casual_sign_worker::seal::SealKey;
use common::{CountingKey, Env};

/// A header's text, its RFC 2047 encoded words decoded.
fn subject(m: &common::Mail) -> String {
    use base64::Engine as _;
    m.header("Subject")
        .unwrap()
        .split_whitespace()
        .map(|w| {
            match w
                .strip_prefix("=?UTF-8?B?")
                .and_then(|w| w.strip_suffix("?="))
            {
                Some(b) => {
                    String::from_utf8(base64::engine::general_purpose::STANDARD.decode(b).unwrap())
                        .unwrap()
                }
                None => w.to_owned(),
            }
        })
        .collect()
}

fn has(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sandbox_envelope_is_sealed_with_the_sandbox_key_only_and_its_emails_say_so() {
    let Some(env) = Env::sandbox("sandbox_seal").await else {
        return;
    };
    let ids = env.draft(vec![]).await;
    env.send(ids).await;
    env.run().await;
    let mail = env.smtp.to(&env.email_of(ids.r1));
    assert_eq!(mail.len(), 1);
    assert!(
        subject(&mail[0]).starts_with("[Sandbox] Please review and sign"),
        "{}",
        subject(&mail[0])
    );
    assert!(mail[0].body().contains("SANDBOX: NOT FOR AGREEMENTS"));

    env.sign(ids, ids.r1, ids.f1, "Ada Lovelace").await;
    env.run().await;
    env.sign(ids, ids.r2, ids.f2, "Grace Hopper").await;
    // No sandbox key: the seal waits, and the platform key signs nothing.
    env.run().await;
    let state = env.state(ids.env).await;
    assert_eq!(state.status, EnvelopeStatus::Completing);
    assert_eq!(env.signatures.load(Ordering::SeqCst), 0, "the platform key");
    assert_eq!(env.count(ids.env, "document.sealed").await, 0);
    let alerts = env.alerts.0.lock().unwrap().clone();
    assert!(alerts.iter().any(|a| a.code == "CS-WRK-0020"), "{alerts:?}");

    // With the sandbox key, the retried seal completes with it.
    let sandbox_count = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&sandbox_count);
    *env.sandbox_key.lock().unwrap() = Some(SealKey::Local {
        provider: Arc::new(move || {
            Box::new(CountingKey::new(common::pki::rsa(), Arc::clone(&count)))
        }),
        development: false,
    });
    env.clock.advance(Duration::from_secs(24 * 3600));
    env.run().await;
    let state = env.state(ids.env).await;
    assert_eq!(state.status, EnvelopeStatus::Completed);
    assert_eq!(env.signatures.load(Ordering::SeqCst), 0, "the platform key");
    assert_eq!(sandbox_count.load(Ordering::SeqCst), 2, "the sandbox key");
    let sealed = env.sealed_bytes(ids.env).await;
    assert!(has(&sealed[0], b"Sandbox: not for agreements"));
    // Completion copies say it too.
    let done: Vec<_> = env
        .smtp
        .to(&env.email_of(ids.r1))
        .into_iter()
        .filter(|m| m.body().contains("All parties have completed"))
        .collect();
    assert_eq!(done.len(), 1);
    assert!(done[0].body().starts_with("SANDBOX: NOT FOR AGREEMENTS"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_workspace_that_is_not_a_sandbox_never_uses_the_sandbox_key() {
    let Some(env) = Env::new("sandbox_key_unused").await else {
        return;
    };
    let sandbox_count = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&sandbox_count);
    *env.sandbox_key.lock().unwrap() = Some(SealKey::Local {
        provider: Arc::new(move || {
            Box::new(CountingKey::new(common::pki::rsa(), Arc::clone(&count)))
        }),
        development: false,
    });
    let ids = env.draft(vec![]).await;
    env.send(ids).await;
    env.run().await;
    let mail = env.smtp.to(&env.email_of(ids.r1));
    assert!(
        !subject(&mail[0]).contains("[Sandbox]"),
        "{}",
        subject(&mail[0])
    );
    assert!(!mail[0].body().contains("SANDBOX"));
    env.sign(ids, ids.r1, ids.f1, "Ada Lovelace").await;
    env.run().await;
    env.sign(ids, ids.r2, ids.f2, "Grace Hopper").await;
    env.run().await;
    assert_eq!(env.state(ids.env).await.status, EnvelopeStatus::Completed);
    assert_eq!(sandbox_count.load(Ordering::SeqCst), 0);
    assert_eq!(env.signatures.load(Ordering::SeqCst), 2);
    assert!(!has(
        &env.sealed_bytes(ids.env).await[0],
        b"Sandbox: not for agreements"
    ));
}
