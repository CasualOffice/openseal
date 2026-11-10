//! Migration 0008 (stage 2D): the engine's envelope state, the job step ledger and the
//! job heartbeat. Round trips, optimistic concurrency, insert-only steps, and every
//! method refusing another account's ids, with row-level security on and off.

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

use common::world::{self, now};
use common::{Rls, fresh};

#[tokio::test]
async fn state_round_trips_with_revisions_and_steps_are_insert_only() {
    let Some(db) = fresh("state_round_trips", Rls::On).await else {
        return;
    };
    let w = world::seed(&db.store, "alpha").await;
    let t = db.store.for_account(w.account);
    let mut tx = t.begin().await.unwrap();
    assert!(
        tx.workflow_states()
            .get(w.envelope)
            .await
            .unwrap()
            .is_none()
    );
    let s1 = serde_json::json!({"status": "draft"});
    tx.workflow_states()
        .insert(w.envelope, &s1, now())
        .await
        .unwrap();
    tx.commit().await.unwrap();
    // An error aborts a PostgreSQL transaction: the duplicate gets one of its own.
    let mut tx = t.begin().await.unwrap();
    assert_eq!(
        tx.workflow_states()
            .insert(w.envelope, &s1, now())
            .await
            .unwrap_err()
            .code(),
        "CS-DB-0006"
    );
    drop(tx);

    let mut tx = t.begin().await.unwrap();
    let got = tx
        .workflow_states()
        .get_for_update(w.envelope)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((got.state.clone(), got.revision), (s1, 1));
    let s2 = serde_json::json!({"status": "sent"});
    let r2 = tx
        .workflow_states()
        .update(w.envelope, 1, &s2, now())
        .await
        .unwrap();
    assert_eq!(r2, 2);
    tx.commit().await.unwrap();
    let mut tx = t.begin().await.unwrap();
    // A writer holding revision 1 lost the race.
    assert_eq!(
        tx.workflow_states()
            .update(w.envelope, 1, &s2, now())
            .await
            .unwrap_err()
            .code(),
        "CS-DB-0007"
    );
    drop(tx);
    let mut tx = t.begin().await.unwrap();
    // Debug never prints the state.
    let dbg = format!("{:?}", tx.workflow_states().get(w.envelope).await.unwrap());
    assert!(!dbg.contains("sent"), "{dbg}");

    // Steps: recorded once, never changed.
    let detail = serde_json::json!({"message_id": "x"});
    assert!(
        tx.job_steps()
            .record(w.job, "email.sent", &detail, now())
            .await
            .unwrap()
    );
    assert!(
        !tx.job_steps()
            .record(w.job, "email.sent", &serde_json::json!({"other": 1}), now())
            .await
            .unwrap()
    );
    let steps = tx.job_steps().list(w.job).await.unwrap();
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0].detail, detail);
    assert_eq!(
        tx.job_steps()
            .record(w.job, "Bad Step", &detail, now())
            .await
            .unwrap_err()
            .code(),
        "CS-DB-0008"
    );
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn job_step_rows_cannot_be_updated_by_the_application_role() {
    let Some(db) = fresh("job_step_rows_cannot_be_updated", Rls::On).await else {
        return;
    };
    let w = world::seed(&db.store, "alpha").await;
    let t = db.store.for_account(w.account);
    let mut tx = t.begin().await.unwrap();
    tx.job_steps()
        .record(w.job, "seal.sealed", &serde_json::json!({}), now())
        .await
        .unwrap();
    tx.commit().await.unwrap();
    // The application role has SELECT and INSERT only on job_steps.
    let err = sqlx::query("UPDATE job_steps SET detail = '{}'::jsonb")
        .execute(&db.app)
        .await
        .unwrap_err();
    let code = err
        .as_database_error()
        .and_then(|d| d.code())
        .unwrap()
        .into_owned();
    assert_eq!(code, "42501", "insufficient privilege");
}

#[tokio::test]
async fn heartbeat_extends_only_the_holders_lease() {
    let Some(db) = fresh("heartbeat_extends_only_the_holders_lease", Rls::On).await else {
        return;
    };
    let w = world::seed(&db.store, "alpha").await;
    let lease = uuid::Uuid::new_v4();
    let claimed = db
        .store
        .entry_points()
        .claim_jobs(
            "w1",
            &["send_invitation"],
            10,
            now(),
            Duration::from_secs(30),
            lease,
        )
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1);
    let t = db.store.for_account(w.account);
    let mut tx = t.begin().await.unwrap();
    let later = now() + time::Duration::seconds(600);
    tx.jobs().heartbeat(w.job, lease, later).await.unwrap();
    assert_eq!(
        tx.jobs()
            .heartbeat(w.job, uuid::Uuid::new_v4(), later)
            .await
            .unwrap_err()
            .code(),
        "CS-DB-0003"
    );
    tx.commit().await.unwrap();
    // The lease that would have lapsed at now + 30 s now holds past it.
    let again = db
        .store
        .entry_points()
        .claim_jobs(
            "w2",
            &["send_invitation"],
            10,
            now() + time::Duration::seconds(60),
            Duration::from_secs(30),
            uuid::Uuid::new_v4(),
        )
        .await
        .unwrap();
    assert!(again.is_empty());
    // Dead-lettering needs the lease too.
    let mut tx = t.begin().await.unwrap();
    assert_eq!(
        tx.jobs()
            .bury(w.job, uuid::Uuid::new_v4(), now(), "CS-WRK-0005")
            .await
            .unwrap_err()
            .code(),
        "CS-DB-0003"
    );
    drop(tx);
    let mut tx = t.begin().await.unwrap();
    tx.jobs()
        .bury(w.job, lease, now(), "CS-WRK-0005")
        .await
        .unwrap();
    let st = tx.jobs().get(w.job).await.unwrap().unwrap();
    assert_eq!(
        (st.status.as_str(), st.last_error_code.as_deref()),
        ("dead", Some("CS-WRK-0005"))
    );
    tx.commit().await.unwrap();
}

async fn new_methods_refuse_another_accounts_ids(rls: Rls) {
    let Some(db) = fresh(&format!("new_methods_refuse_cross_tenant_{rls:?}"), rls).await else {
        return;
    };
    let a = world::seed(&db.store, "alpha").await;
    let b = world::seed(&db.store, "bravo").await;
    // A's rows.
    let ta = db.store.for_account(a.account);
    let mut tx = ta.begin().await.unwrap();
    tx.workflow_states()
        .insert(a.envelope, &serde_json::json!({"a": 1}), now())
        .await
        .unwrap();
    tx.job_steps()
        .record(a.job, "email.sent", &serde_json::json!({}), now())
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let lease = uuid::Uuid::new_v4();
    db.store
        .entry_points()
        .claim_jobs(
            "w",
            &["send_invitation"],
            10,
            now(),
            Duration::from_secs(30),
            lease,
        )
        .await
        .unwrap();

    // B, given A's ids.
    let tb = db.store.for_account(b.account);
    let mut tx = tb.begin().await.unwrap();
    assert!(
        tx.workflow_states()
            .get(a.envelope)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        tx.workflow_states()
            .get_for_update(a.envelope)
            .await
            .unwrap()
            .is_none()
    );
    assert!(tx.job_steps().list(a.job).await.unwrap().is_empty());
    tx.commit().await.unwrap();
    for what in ["insert", "update", "record", "heartbeat", "bury"] {
        let mut tx = tb.begin().await.unwrap();
        let r = match what {
            "insert" => tx
                .workflow_states()
                .insert(a.envelope, &serde_json::json!({"b": 1}), now())
                .await
                .map(|()| 0),
            "update" => {
                tx.workflow_states()
                    .update(a.envelope, 1, &serde_json::json!({"b": 1}), now())
                    .await
            }
            "record" => tx
                .job_steps()
                .record(a.job, "webhook.sent", &serde_json::json!({}), now())
                .await
                .map(i64::from),
            "heartbeat" => tx.jobs().heartbeat(a.job, lease, now()).await.map(|()| 0),
            _ => tx
                .jobs()
                .bury(a.job, lease, now(), "CS-WRK-0004")
                .await
                .map(|()| 0),
        };
        let e = r.expect_err(what);
        assert!(
            matches!(e.code(), "CS-DB-0003" | "CS-DB-0008" | "CS-DB-0009"),
            "{what}: {e}"
        );
        drop(tx);
    }
    // A's rows are as they were.
    let mut tx = ta.begin().await.unwrap();
    let s = tx.workflow_states().get(a.envelope).await.unwrap().unwrap();
    assert_eq!((s.state, s.revision), (serde_json::json!({"a": 1}), 1));
    assert_eq!(tx.job_steps().list(a.job).await.unwrap().len(), 1);
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn new_methods_refuse_another_accounts_ids_with_rls() {
    new_methods_refuse_another_accounts_ids(Rls::On).await;
}

#[tokio::test]
async fn new_methods_refuse_another_accounts_ids_by_the_repository_alone() {
    new_methods_refuse_another_accounts_ids(Rls::Off).await;
}
