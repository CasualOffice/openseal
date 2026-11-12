//! The audit table is append-only (docs/32 §1, docs/22 §9): UPDATE, DELETE and TRUNCATE
//! are refused by trigger for the owner and by missing privileges for the application
//! role; an insert that does not extend the chain is refused by the database itself.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use casual_sign_audit::Hash256;
use casual_sign_store::EnvelopeId;
use common::world::{self, events};
use common::{Rls, fresh};
use sqlx::{Executor, PgPool};

fn sqlstate(err: &sqlx::Error) -> Option<String> {
    err.as_database_error()
        .and_then(|e| e.code())
        .map(|c| c.into_owned())
}

/// Run `sql` as the application role in `account`'s transaction.
async fn as_app(app: &PgPool, account: uuid::Uuid, sql: &str) -> Result<u64, sqlx::Error> {
    let mut tx = app.begin().await?;
    sqlx::query("SELECT set_config('openseal.account_id', $1, true)")
        .bind(account.to_string())
        .execute(&mut *tx)
        .await?;
    let n = tx
        .execute(sqlx::raw_sql(sqlx::AssertSqlSafe(sql.to_owned())))
        .await?
        .rows_affected();
    tx.commit().await?;
    Ok(n)
}

#[tokio::test]
async fn appended_events_read_back_as_a_verified_chain_and_set_the_envelope_head() {
    let Some(db) = fresh("appended_events_read_back", Rls::On).await else {
        return;
    };
    let w = world::seed(&db, "alpha").await;
    let mut tx = db.store.for_account(w.account).begin().await.unwrap();
    // The seed appended two; append a third that continues them.
    let all = events(w.envelope, 3);
    let h = tx.audit().append(w.envelope, &all[2]).await.unwrap();
    let chain = tx.audit().chain(w.envelope).await.unwrap();
    assert_eq!(chain.len(), 3);
    assert_eq!(chain.head(), Some(h));
    assert_eq!(tx.audit().head(w.envelope).await.unwrap(), Some((2, h)));
    let e = tx.envelopes().get(w.envelope).await.unwrap().unwrap();
    assert_eq!(e.chain_head, Some(*h.as_bytes()));
    let stored = tx.audit().events(w.envelope).await.unwrap();
    assert_eq!(stored[1].event_type, "envelope.sent");
    assert_eq!(stored[2].prev, Some(stored[1].hash));
    assert_eq!(Hash256::digest(&stored[2].canonical), h);
    tx.commit().await.unwrap();
    db.drop().await;
}

#[tokio::test]
async fn an_event_that_does_not_extend_the_chain_is_refused() {
    let Some(db) = fresh("an_event_that_does_not_extend_the_chain", Rls::On).await else {
        return;
    };
    let w = world::seed(&db, "alpha").await;
    let t = db.store.for_account(w.account);
    let all = events(w.envelope, 4);
    // A replay of an existing event, a gap, and an event for another envelope.
    for (what, envelope, event) in [
        ("replay of seq 1", w.envelope, all[1].clone()),
        ("seq 3 skipping 2", w.envelope, all[3].clone()),
        (
            "event of another envelope",
            EnvelopeId(world::id()),
            all[2].clone(),
        ),
    ] {
        let mut tx = t.begin().await.unwrap();
        let err = tx.audit().append(envelope, &event).await.unwrap_err();
        assert!(
            matches!(err.code(), "CS-DB-0005" | "CS-DB-0006"),
            "{what}: {err}"
        );
    }
    // The database recomputes the hash: a row whose hash is not SHA-256 of its bytes is
    // refused even when written by raw SQL.
    let err = as_app(
        &db.app,
        w.account.0,
        &format!(
            "INSERT INTO audit_events (account_id, envelope_id, seq, prev_hash, hash, event_type, at, canonical) \
             SELECT account_id, envelope_id, 2, hash, '\\x{}', 'envelope.voided', now(), '\\x7b7d' \
             FROM audit_events WHERE envelope_id = '{}' AND seq = 1",
            "00".repeat(32),
            w.envelope
        ),
    )
    .await
    .unwrap_err();
    assert_eq!(sqlstate(&err).as_deref(), Some("OS002"), "{err}");
    // And a correctly hashed row whose prev is not the head.
    let err = as_app(
        &db.app,
        w.account.0,
        &format!(
            "INSERT INTO audit_events (account_id, envelope_id, seq, prev_hash, hash, event_type, at, canonical) \
             VALUES ('{}', '{}', 2, '\\x{}', sha256('\\x7b7d'), 'envelope.voided', now(), '\\x7b7d')",
            w.account,
            w.envelope,
            "11".repeat(32)
        ),
    )
    .await
    .unwrap_err();
    assert_eq!(sqlstate(&err).as_deref(), Some("OS002"), "{err}");
    let mut tx = t.begin().await.unwrap();
    assert_eq!(tx.audit().chain(w.envelope).await.unwrap().len(), 2);
    db.drop().await;
}

/// UPDATE, DELETE and TRUNCATE on the audit chain and on tombstones: refused by trigger
/// for the owner (a superuser here, the strongest role short of disabling triggers), and
/// refused for the application role, by privilege and by trigger.
#[tokio::test]
async fn update_delete_and_truncate_of_audit_events_are_refused_for_owner_and_app_role() {
    for rls in [Rls::On, Rls::Off] {
        let Some(db) = fresh("update_delete_and_truncate_of_audit_events", rls).await else {
            return;
        };
        let w = world::seed(&db, "alpha").await;
        db.admin
            .execute(sqlx::raw_sql(sqlx::AssertSqlSafe(
                format!(
                    "INSERT INTO envelope_tombstones (account_id, envelope_id, chain_head, event_count, purged_at, policy) \
                     VALUES ('{}', '{}', '\\x{}', 2, now(), 'test')",
                    w.account,
                    world::id(),
                    "22".repeat(32)
                )))
            )
            .await
            .unwrap();
        for table in ["audit_events", "envelope_tombstones"] {
            for sql in [
                format!("UPDATE {table} SET account_id = account_id"),
                format!("DELETE FROM {table}"),
                format!("TRUNCATE {table}"),
                format!("TRUNCATE {table} CASCADE"),
            ] {
                let owner = db
                    .admin
                    .execute(sqlx::raw_sql(sqlx::AssertSqlSafe(sql.clone())))
                    .await
                    .unwrap_err();
                assert_eq!(
                    sqlstate(&owner).as_deref(),
                    Some("OS001"),
                    "owner: {sql}: {owner}"
                );
                assert!(owner.to_string().contains("CS-DB-0004"), "{owner}");
                let app = as_app(&db.app, w.account.0, &sql).await.unwrap_err();
                assert_eq!(
                    sqlstate(&app).as_deref(),
                    Some("42501"),
                    "app role: {sql}: {app}"
                );
            }
        }
        // A cascade from the tables evidence references reaches the trigger too.
        for sql in ["TRUNCATE envelopes CASCADE", "TRUNCATE accounts CASCADE"] {
            let owner = db.admin.execute(sqlx::raw_sql(sql)).await.unwrap_err();
            assert_eq!(
                sqlstate(&owner).as_deref(),
                Some("OS001"),
                "owner: {sql}: {owner}"
            );
        }
        // Deleting the envelope that owns evidence is refused by the reference.
        let err = db
            .admin
            .execute(sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                "DELETE FROM envelopes WHERE id = '{}'",
                w.envelope
            ))))
            .await
            .unwrap_err();
        assert_eq!(sqlstate(&err).as_deref(), Some("23503"), "{err}");
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events")
            .fetch_one(&db.admin)
            .await
            .unwrap();
        assert_eq!(n, 2);
        db.drop().await;
    }
}

/// With the trigger dropped, the application role is still refused by privilege alone:
/// the two controls are independent.
#[tokio::test]
async fn the_app_role_is_refused_by_privilege_even_without_the_trigger() {
    let Some(db) = fresh("the_app_role_is_refused_by_privilege", Rls::On).await else {
        return;
    };
    let w = world::seed(&db, "alpha").await;
    db.admin
        .execute("DROP TRIGGER audit_events_no_update_delete ON audit_events; DROP TRIGGER audit_events_no_truncate ON audit_events")
        .await
        .unwrap();
    for sql in [
        "UPDATE audit_events SET event_type = 'x'",
        "DELETE FROM audit_events",
        "TRUNCATE audit_events",
    ] {
        let app = as_app(&db.app, w.account.0, sql).await.unwrap_err();
        assert_eq!(sqlstate(&app).as_deref(), Some("42501"), "{sql}: {app}");
    }
    db.drop().await;
}
