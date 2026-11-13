//! VS-02 (expiry and warning, FG-095), through the workflow, the store and the worker:
//! an envelope sent with an expiry and an account warning of one day emails the
//! recipient whose turn it is a warning with a fresh link the day before, then expires
//! when the time comes; the sender and the recipient whose turn it was are told.
//!
//! Needs `OPENSEAL_TEST_DATABASE_URL`; without it the test prints a note and passes
//! vacuously, as the store's tests do.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::time::Duration;

use casual_sign_audit::Timestamp;
use casual_sign_model::EnvelopeStatus;
use casual_sign_store::EnvelopeId;
use casual_sign_worker::apply;
use casual_sign_workflow::{Change, Command, Policy};
use common::Env;

const DAY: Duration = Duration::from_secs(86_400);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_envelope_warns_the_day_before_and_expires_on_time() {
    let Some(env) = Env::new("expiry_warns_and_expires").await else {
        return;
    };
    let at = Timestamp::from_unix_millis(env.clock.ms() + 3 * 86_400_000).unwrap();
    let ids = env
        .draft(vec![Change::SetExpiry {
            expires_at: Some(at),
        }])
        .await;
    // Sent under an account policy that warns one day before (the API reads it from
    // `settings.workflow_policy`).
    let mut ctx = env.ctx(env.as_sender());
    ctx.policy = Policy {
        expiry_warning_days: 1,
        ..Policy::default()
    };
    apply(
        &env.db.store,
        env.account,
        EnvelopeId(ids.env),
        &Command::Send,
        &ctx,
    )
    .await
    .unwrap();
    env.run().await;
    let first = env.email_of(ids.r1);
    assert_eq!(env.smtp.to(&first).len(), 1, "the invitation");

    // Day 1: nothing due yet.
    env.clock.advance(DAY + Duration::from_secs(60));
    env.run().await;
    assert_eq!(env.smtp.to(&first).len(), 1);

    // Day 2: the warning, to the signer whose turn it is (not the second, still waiting).
    env.clock.advance(DAY);
    env.run().await;
    let mails = env.smtp.to(&first);
    assert_eq!(mails.len(), 2, "the invitation and the warning");
    assert!(
        mails[1].body().contains("expire soon"),
        "{}",
        mails[1].body()
    );
    assert!(mails[1].token().is_some(), "a fresh link");
    assert!(env.smtp.to(&env.email_of(ids.r2)).is_empty());
    assert_eq!(env.state(ids.env).await.status, EnvelopeStatus::Sent);

    // Day 3: expired.
    env.clock.advance(DAY);
    env.run().await;
    assert_eq!(env.state(ids.env).await.status, EnvelopeStatus::Expired);
    assert_eq!(env.count(ids.env, "envelope.expired").await, 1);
    // The sender and the recipient whose turn it was are told, once each; the second
    // signer, never reached, hears nothing.
    let told: Vec<Vec<String>> = env
        .smtp
        .mails()
        .into_iter()
        .filter(|m| m.body().contains("expired before every recipient"))
        .map(|m| m.to)
        .collect();
    assert_eq!(told.len(), 2, "{told:?}");
    assert!(told.iter().any(|to| to.contains(&first)), "{told:?}");
    assert!(env.smtp.to(&env.email_of(ids.r2)).is_empty());
}
