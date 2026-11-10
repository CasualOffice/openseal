//! Crash tests (stage 2D gate, Phase 2 exit item 2): a worker stopped dead at every
//! effect boundary, its runtime dropped (its connections close, its transaction rolls
//! back, its lease stays until it lapses), then a new worker started. After each:
//!
//! - **no audit event is lost or doubled**: the stored chain verifies and holds each
//!   expected event exactly once;
//! - **no email or webhook is duplicated beyond the documented at-least-once window**:
//!   only a crash between the external act and its record repeats it, and the repeat
//!   carries the same `Message-ID` or `webhook-id`, so receivers collapse it;
//! - **an envelope is never `completed` without a verified seal**, and a seal recorded
//!   before a crash is not made again.
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

use std::sync::atomic::Ordering;
use std::time::Duration;

use casual_sign_model::{EnvelopeStatus, ReminderPolicy};
use casual_sign_worker::{Boundary, JobOutcome};
use casual_sign_workflow::Change;
use common::{Env, Ids};

async fn sent(env: &Env) -> Ids {
    let ids = env.draft(vec![]).await;
    env.send(ids).await;
    ids
}

async fn completing(env: &Env) -> Ids {
    let ids = sent(env).await;
    env.run().await;
    env.sign(ids, ids.r1, ids.f1, "Ada Lovelace").await;
    env.run().await;
    let a = env.sign(ids, ids.r2, ids.f2, "Grace Hopper").await;
    assert_eq!(a.state.status, EnvelopeStatus::Completing);
    ids
}

/// Crash once at `at` in a job of `kind`, restart past the lease, run to idle.
async fn crash_and_restart(env: &Env, at: Boundary, kind: &'static str) {
    let r = env.incarnation(Some((at, kind))).await;
    assert!(r.is_err(), "the worker did not reach {at:?} in {kind}");
    env.after_crash();
    let out = env.run().await;
    assert!(
        out.iter().all(|(_, o)| *o == JobOutcome::Done),
        "after restart: {out:?}"
    );
}

async fn invitation_after(at: Boundary, test: &str) -> Option<(Env, Ids)> {
    let env = Env::new(test).await?;
    let ids = sent(&env).await;
    crash_and_restart(&env, at, "send_invitation").await;
    assert_eq!(env.count(ids.env, "invitation.sent").await, 1);
    assert_eq!(env.job_count("send_invitation", "done").await, 1);
    Some((env, ids))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crash_after_claim_sends_the_invitation_once() {
    let Some((env, ids)) = invitation_after(Boundary::Claimed, "crash_inv_claimed").await else {
        return;
    };
    assert_eq!(env.smtp.to(&env.email_of(ids.r1)).len(), 1);
}

/// The at-least-once window: the SMTP server accepted, the worker died before
/// recording it. The re-run sends again, with the same Message-ID.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crash_after_sending_repeats_with_the_same_message_id() {
    let Some((env, ids)) = invitation_after(Boundary::EmailSent, "crash_inv_sent").await else {
        return;
    };
    let mails = env.smtp.to(&env.email_of(ids.r1));
    assert_eq!(mails.len(), 2, "documented at-least-once repeat");
    assert_eq!(mails[0].message_id(), mails[1].message_id());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crash_after_recording_the_send_does_not_send_again() {
    let Some((env, ids)) = invitation_after(Boundary::Recorded, "crash_inv_recorded").await else {
        return;
    };
    assert_eq!(env.smtp.to(&env.email_of(ids.r1)).len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crash_before_the_result_commits_does_not_send_again() {
    let Some((env, ids)) =
        invitation_after(Boundary::BeforeCommit, "crash_inv_before_commit").await
    else {
        return;
    };
    assert_eq!(env.smtp.to(&env.email_of(ids.r1)).len(), 1);
}

async fn seal_after(at: Boundary, test: &str, seals: usize) {
    let Some(env) = Env::new(test).await else {
        return;
    };
    let ids = completing(&env).await;
    let r = env.incarnation(Some((at, "seal_envelope"))).await;
    assert!(r.is_err());
    // Dead worker: whatever it did, the envelope is not completed.
    assert_eq!(
        env.state(ids.env).await.status,
        EnvelopeStatus::Completing,
        "completed before the result committed"
    );
    assert_eq!(env.count(ids.env, "envelope.completed").await, 0);
    env.after_crash();
    let out = env.run().await;
    assert!(out.iter().all(|(_, o)| *o == JobOutcome::Done), "{out:?}");
    let state = env.state(ids.env).await;
    assert_eq!(state.status, EnvelopeStatus::Completed);
    for ty in [
        "document.flattened",
        "document.sealed",
        "envelope.completed",
        "envelope.completing",
        "recipient.signed",
    ] {
        let want = if ty == "recipient.signed" { 2 } else { 1 };
        assert_eq!(env.count(ids.env, ty).await, want, "{ty}");
    }
    // Each seal run signs the document and the standalone certificate.
    assert_eq!(
        env.signatures.load(Ordering::SeqCst),
        seals * 2,
        "keyd signatures"
    );
    // The stored seal is the one the chain names, and it verifies.
    let sealed = env.sealed_bytes(ids.env).await;
    assert_eq!(sealed.len(), 1);
    let report = env.engine.verify(
        &sealed[0],
        &common::pki::trust(),
        &env.engine.verify_options(Duration::from_millis(
            u64::try_from(env.clock.ms()).unwrap(),
        )),
    );
    casual_sign_worker::seal::check_verified(&report, casual_sign_sdk::Profile::BaselineT).unwrap();
    // Completion copies went once each.
    for r in [ids.r1, ids.r2] {
        let n = env
            .smtp
            .to(&env.email_of(r))
            .iter()
            .filter(|m| m.body().contains("All parties have completed"))
            .count();
        assert_eq!(n, 1);
    }
}

/// keyd signed, nothing stored: the re-run seals again (a second keyd signature, which
/// keyd's log shows; `KEYD-03` reconciles), and completes once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crash_after_sealing_before_storing_seals_again_and_completes_once() {
    seal_after(Boundary::Sealed, "crash_seal_sealed", 2).await;
}

/// Sealed, stored and recorded; the result did not commit: the re-run does not seal
/// again and completes once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crash_after_storing_the_seal_does_not_seal_again() {
    seal_after(Boundary::Recorded, "crash_seal_recorded", 1).await;
}

/// `SealSucceeded` applied inside the open transaction, then the crash: nothing of it
/// is visible, and the re-run completes once without sealing again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crash_with_the_result_uncommitted_completes_once() {
    seal_after(Boundary::BeforeCommit, "crash_seal_before_commit", 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crash_after_claiming_the_seal_job_seals_once() {
    seal_after(Boundary::Claimed, "crash_seal_claimed", 1).await;
}

async fn webhook_after(at: Boundary, test: &str, deliveries: usize) {
    let Some(env) = Env::new(test).await else {
        return;
    };
    env.subscribe(&["envelope.sent"]).await;
    let ids = sent(&env).await;
    crash_and_restart(&env, at, "deliver_webhook").await;
    let reqs = env.hook.requests();
    assert_eq!(reqs.len(), deliveries);
    let first = &reqs[0].headers["webhook-id"];
    assert!(reqs.iter().all(|r| &r.headers["webhook-id"] == first));
    let bodies: Vec<_> = reqs.iter().map(|r| r.body.clone()).collect();
    assert!(bodies.windows(2).all(|w| w[0] == w[1]), "same payload");
    // `Send` emits `envelope.sent` and `recipient.sent`; both jobs finish, only the
    // subscribed one delivers.
    assert_eq!(env.job_count("deliver_webhook", "done").await, 2);
    assert_eq!(env.job_count("deliver_webhook", "queued").await, 0);
    assert_eq!(env.count(ids.env, "envelope.sent").await, 1);
}

/// Mid-webhook: the receiver answered, the worker died before recording it. Redelivered
/// with the same `webhook-id` and body (at-least-once; receivers dedupe on the id).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crash_mid_webhook_redelivers_with_the_same_id() {
    webhook_after(Boundary::WebhookAnswered, "crash_hook_answered", 2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crash_after_recording_the_webhook_does_not_redeliver() {
    webhook_after(Boundary::Recorded, "crash_hook_recorded", 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crash_after_claiming_the_webhook_delivers_once() {
    webhook_after(Boundary::Claimed, "crash_hook_claimed", 1).await;
}

/// A reminder timer fires through the engine; a crash with `TimerDue` uncommitted
/// leaves no event, and the re-run reminds once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crash_in_a_timer_reminds_once() {
    let Some(env) = Env::new("crash_timer").await else {
        return;
    };
    let ids = env
        .draft(vec![Change::SetReminders {
            reminders: ReminderPolicy::new(1, 2).unwrap(),
        }])
        .await;
    env.send(ids).await;
    env.run().await;
    assert_eq!(env.smtp.to(&env.email_of(ids.r1)).len(), 1);
    env.clock.advance(Duration::from_secs(86_400 + 60));
    crash_and_restart(&env, Boundary::BeforeCommit, "timer").await;
    assert_eq!(env.count(ids.env, "reminder.sent").await, 1);
    let mails = env.smtp.to(&env.email_of(ids.r1));
    assert_eq!(mails.len(), 2, "the invitation and one reminder");
    assert!(mails[1].body().contains("This is a reminder"));
}

/// A receiver failing is retried with back-off; the delivery log keeps every attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failing_receiver_is_retried_with_backoff() {
    let Some(env) = Env::new("failing_receiver").await else {
        return;
    };
    env.subscribe(&["envelope.sent"]).await;
    env.hook.status.store(503, Ordering::SeqCst);
    let ids = sent(&env).await;
    let out = env.run().await;
    assert!(
        out.iter()
            .any(|(k, o)| k == "deliver_webhook" && *o == JobOutcome::Retry("CS-WRK-0009".into())),
        "{out:?}"
    );
    assert_eq!(env.job_count("deliver_webhook", "queued").await, 1);
    // Not due again until the back-off passes.
    assert!(env.run().await.is_empty());
    env.hook.status.store(204, Ordering::SeqCst);
    env.clock.advance(Duration::from_secs(60));
    env.run().await;
    assert_eq!(env.job_count("deliver_webhook", "done").await, 2);
    assert_eq!(env.job_count("deliver_webhook", "queued").await, 0);
    assert_eq!(env.hook.requests().len(), 2);
    let log: Vec<(String, i32, Option<i32>)> =
        sqlx::query_as("SELECT status, attempts, last_status_code FROM webhook_deliveries")
            .fetch_all(&env.db.admin)
            .await
            .unwrap();
    assert_eq!(log, vec![("delivered".to_owned(), 2, Some(204))]);
    assert_eq!(env.count(ids.env, "envelope.sent").await, 1);
}

/// A job no retry can cure is dead at once, with an operator alert.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_job_is_dead_lettered_with_an_alert() {
    let Some(env) = Env::new("malformed_job").await else {
        return;
    };
    let ids = env.draft(vec![]).await;
    sqlx::query(
        "INSERT INTO jobs (id, account_id, envelope_id, kind, idempotency_key, payload, run_at) \
         VALUES ($1, $2, $3, 'timer', 'bad', '{\"nope\": 1}'::jsonb, to_timestamp(0))",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(env.account.0)
    .bind(ids.env)
    .execute(&env.db.admin)
    .await
    .unwrap();
    let out = env.run().await;
    assert_eq!(
        out,
        vec![("timer".into(), JobOutcome::Dead("CS-WRK-0004".into()))]
    );
    let alerts = env.alerts.0.lock().unwrap().clone();
    assert_eq!(alerts.len(), 1);
    assert_eq!(
        (alerts[0].kind.as_str(), alerts[0].code.as_str()),
        ("job_dead", "CS-WRK-0004")
    );
}
