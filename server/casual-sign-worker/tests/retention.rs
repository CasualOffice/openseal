//! ASVS-18 (ASVS 8.3.8, docs/32 §7): the daily retention job, through the workflow, the
//! store and the worker on PostgreSQL. It purges only the envelopes of a class with a
//! rule, once the rule has expired them; never one under legal hold or one in flight;
//! each purge appends `envelope.purged` naming the rule and leaves a tombstone; the
//! audit chains still verify and sealed bytes are untouched; a second run purges
//! nothing more. Ended staff sessions go under the `sessions` rule, with an admin event.
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

use std::sync::atomic::Ordering;
use std::time::Duration;

use casual_sign_model::EnvelopeStatus;
use casual_sign_store::repo::privacy::DataClass;
use casual_sign_store::repo::sessions::{LoginMethod, NewSession};
use casual_sign_store::{EnvelopeId, StaffSessionId, Store};
use casual_sign_workflow::Command;
use common::{Env, text};
use time::OffsetDateTime;
use uuid::Uuid;

const DAY: Duration = Duration::from_secs(86_400);

async fn set_rule(env: &Env, class: DataClass, days: Option<i32>) {
    let mut tx = env.db.store.for_account(env.account).begin().await.unwrap();
    tx.privacy().set_rule(class, days, now(env)).await.unwrap();
    tx.commit().await.unwrap();
}

async fn hold(env: &Env, e: Uuid, on: bool) {
    let mut tx = env.db.store.for_account(env.account).begin().await.unwrap();
    tx.privacy()
        .set_legal_hold(EnvelopeId(e), on, now(env))
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

fn now(env: &Env) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(env.clock.ms()) * 1_000_000).unwrap()
}

/// Rows of `table` naming envelope `e` (the owner role, for counting).
async fn rows(env: &Env, table: &str, e: Uuid) -> i64 {
    let sql = match table {
        "recipients" => "SELECT count(*) FROM recipients WHERE envelope_id = $1",
        "documents" => "SELECT count(*) FROM documents WHERE envelope_id = $1",
        "fields" => "SELECT count(*) FROM fields WHERE envelope_id = $1",
        "field_values" => "SELECT count(*) FROM field_values WHERE envelope_id = $1",
        "recipient_tokens" => "SELECT count(*) FROM recipient_tokens WHERE envelope_id = $1",
        _ => panic!("{table}"),
    };
    sqlx::query_scalar::<_, i64>(sql)
        .bind(e)
        .fetch_one(&env.db.admin)
        .await
        .unwrap()
}

async fn tombstone_policy(env: &Env, e: Uuid) -> Option<String> {
    sqlx::query_scalar::<_, String>("SELECT policy FROM envelope_tombstones WHERE envelope_id = $1")
        .bind(e)
        .fetch_optional(&env.db.admin)
        .await
        .unwrap()
}

/// The `envelope.purged` events' policies, from the verified chain.
async fn purge_policies(env: &Env, e: Uuid) -> Vec<String> {
    let mut tx = env.db.store.for_account(env.account).begin().await.unwrap();
    let events = tx.audit().events(EnvelopeId(e)).await.unwrap();
    tx.audit().chain(EnvelopeId(e)).await.unwrap();
    tx.commit().await.unwrap();
    events
        .into_iter()
        .filter(|ev| ev.event_type == "envelope.purged")
        .map(|ev| {
            let v: serde_json::Value = serde_json::from_slice(&ev.canonical).unwrap();
            v["data"]["policy"].as_str().unwrap().to_owned()
        })
        .collect()
}

async fn void(env: &Env, e: Uuid) {
    env.apply(
        e,
        env.as_sender(),
        Command::Void {
            reason: text("Wrong counterparty"),
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retention_purges_only_expired_records_of_a_ruled_class_and_keeps_held_and_live_ones() {
    let Some(env) = Env::new("retention_purges_expired_records").await else {
        return;
    };
    env.retention.store(true, Ordering::SeqCst);

    // A completed, sealed envelope.
    let done = env.draft(vec![]).await;
    env.send(done).await;
    env.run().await;
    env.sign(done, done.r1, done.f1, "Ada Lovelace").await;
    env.run().await;
    env.sign(done, done.r2, done.f2, "Grace Hopper").await;
    env.run().await;
    assert_eq!(env.state(done.env).await.status, EnvelopeStatus::Completed);
    let sealed_before = env.sealed_bytes(done.env).await;
    assert!(!sealed_before.is_empty());

    // A draft, two voided envelopes (one to be held) and one still out for signing.
    let draft = env.draft(vec![]).await;
    let voided = env.draft(vec![]).await;
    env.send(voided).await;
    void(&env, voided.env).await;
    let held = env.draft(vec![]).await;
    env.send(held).await;
    void(&env, held.env).await;
    let live = env.draft(vec![]).await;
    env.send(live).await;
    env.run().await;
    hold(&env, held.env, true).await;
    assert!(rows(&env, "recipients", voided.env).await > 0);
    assert!(rows(&env, "documents", voided.env).await > 0);

    // A staff session that ended, and one still live.
    let ended = StaffSessionId(Uuid::now_v7());
    let open = StaffSessionId(Uuid::now_v7());
    {
        let mut tx = env.db.store.for_account(env.account).begin().await.unwrap();
        for (sid, ttl) in [(ended, 3600_i64), (open, 400 * 86_400)] {
            tx.sessions()
                .create(&NewSession {
                    id: sid,
                    user_id: env.sender,
                    token_sha256: [sid.0.as_bytes()[15]; 32],
                    csrf_sha256: [7u8; 32],
                    method: LoginMethod::Password,
                    created_at: now(&env),
                    expires_at: now(&env) + time::Duration::seconds(ttl),
                    last_seen_at: now(&env),
                    reauth_at: None,
                    client_label: None,
                })
                .await
                .unwrap();
        }
        tx.commit().await.unwrap();
    }

    // Rules: drafts 10 days, ended envelopes 30 days, ended sessions 1 day; completed
    // envelopes keep no rule (kept for ever).
    set_rule(&env, DataClass::Draft, Some(10)).await;
    set_rule(&env, DataClass::Ended, Some(30)).await;
    set_rule(&env, DataClass::Sessions, Some(1)).await;

    // Day 11: only the draft has expired.
    env.clock.advance(11 * DAY);
    env.run().await;
    assert!(env.state(draft.env).await.purged, "the draft");
    assert!(!env.state(voided.env).await.purged, "ended, 11 days");
    assert_eq!(purge_policies(&env, draft.env).await, ["retention.draft"]);
    assert_eq!(
        tombstone_policy(&env, draft.env).await.as_deref(),
        Some("retention.draft")
    );

    // Day 32: the voided envelope too; the held one, the live one and the completed one
    // stay.
    env.clock.advance(21 * DAY);
    env.run().await;
    assert!(env.state(voided.env).await.purged, "the voided envelope");
    assert_eq!(purge_policies(&env, voided.env).await, ["retention.ended"]);
    assert_eq!(
        tombstone_policy(&env, voided.env).await.as_deref(),
        Some("retention.ended")
    );
    for t in ["recipients", "documents", "fields", "recipient_tokens"] {
        assert_eq!(rows(&env, t, voided.env).await, 0, "{t} of the purged");
    }
    let s = env.state(voided.env).await;
    assert!(
        s.recipients
            .iter()
            .all(|r| r.spec.email.get().as_str().is_empty())
    );
    assert!(s.subject.get().as_str().is_empty());
    for (what, e) in [
        ("held", held.env),
        ("live", live.env),
        ("completed", done.env),
    ] {
        assert!(!env.state(e).await.purged, "{what}");
        assert!(purge_policies(&env, e).await.is_empty(), "{what}");
        assert!(rows(&env, "recipients", e).await > 0, "{what}");
    }
    assert_eq!(env.state(live.env).await.status, EnvelopeStatus::Sent);

    // The ended session went, with an admin event; the live one stays.
    let sessions: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM staff_sessions")
        .fetch_all(&env.db.admin)
        .await
        .unwrap();
    assert_eq!(sessions, [open.0]);
    let purged_events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM admin_events WHERE action = 'retention.sessions_purged'",
    )
    .fetch_one(&env.db.admin)
    .await
    .unwrap();
    assert_eq!(purged_events, 1);

    // A second run, days later, purges nothing twice.
    env.clock.advance(2 * DAY);
    env.run().await;
    assert_eq!(purge_policies(&env, draft.env).await.len(), 1);
    assert_eq!(purge_policies(&env, voided.env).await.len(), 1);

    // Released, the held envelope goes at the next day's run.
    hold(&env, held.env, false).await;
    env.clock.advance(DAY);
    env.run().await;
    assert_eq!(purge_policies(&env, held.env).await, ["retention.ended"]);

    // The sealed bytes are untouched, and every chain and admin log still verifies.
    assert_eq!(env.sealed_bytes(done.env).await, sealed_before);
    let report = Store::from_pool(env.db.admin.clone())
        .verify_evidence()
        .await
        .unwrap();
    assert!(report.envelopes >= 5, "{report:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_completed_envelope_is_purged_by_its_rule_with_its_chain_kept_whole() {
    let Some(env) = Env::new("retention_purges_a_completed_envelope").await else {
        return;
    };
    env.retention.store(true, Ordering::SeqCst);
    let done = env.draft(vec![]).await;
    env.send(done).await;
    env.run().await;
    env.sign(done, done.r1, done.f1, "Ada Lovelace").await;
    env.run().await;
    env.sign(done, done.r2, done.f2, "Grace Hopper").await;
    env.run().await;
    assert_eq!(env.state(done.env).await.status, EnvelopeStatus::Completed);
    let events_before = env.events(done.env).await;
    let head_before: Vec<u8> = sqlx::query_scalar("SELECT chain_head FROM envelopes WHERE id = $1")
        .bind(done.env)
        .fetch_one(&env.db.admin)
        .await
        .unwrap();

    set_rule(&env, DataClass::Completed, Some(365)).await;
    env.clock.advance(364 * DAY);
    env.run().await;
    assert!(!env.state(done.env).await.purged, "day 364");
    env.clock.advance(2 * DAY);
    env.run().await;
    assert!(env.state(done.env).await.purged, "day 366");

    // The chain kept every earlier event and gained exactly `envelope.purged`; the
    // tombstone holds the head as of the purge and the sealed document's hash.
    let after = env.events(done.env).await;
    assert_eq!(after[..events_before.len()], events_before[..]);
    assert_eq!(&after[events_before.len()..], ["envelope.purged"]);
    let (head, count, sealed): (Vec<u8>, i64, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT chain_head, event_count, sealed_sha256 FROM envelope_tombstones \
         WHERE envelope_id = $1",
    )
    .bind(done.env)
    .fetch_one(&env.db.admin)
    .await
    .unwrap();
    assert_eq!(count, i64::try_from(after.len()).unwrap());
    assert_ne!(head, head_before, "the head after envelope.purged");
    assert!(sealed.is_some(), "the sealed document's hash");
    for t in ["recipients", "documents", "fields", "field_values"] {
        assert_eq!(rows(&env, t, done.env).await, 0, "{t}");
    }
    let cert: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT certificate_sha256 FROM envelopes WHERE id = $1")
            .bind(done.env)
            .fetch_one(&env.db.admin)
            .await
            .unwrap();
    assert!(cert.is_none());
    Store::from_pool(env.db.admin.clone())
        .verify_evidence()
        .await
        .unwrap();
}
