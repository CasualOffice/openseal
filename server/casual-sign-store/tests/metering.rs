//! PLAN-03 (docs/23 §7.2): usage metering. Every counted change is one append-only
//! `usage_ledger` row keyed by its source, so a retried job or a decision recorded again
//! counts once; the workspace counter and the organization counter move in the same
//! transaction, so each equals the sum of its ledger column at both levels. Gauges
//! (`seats`, `storage_bytes`, `workspaces`) are kept by the database in the transaction
//! of the change; the application counts counter meters only.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use casual_sign_audit::Personal;
use casual_sign_store::repo::accounts::{PermissionProfile, ProfileKind};
use casual_sign_store::{
    AccountId, DocumentVersionId, Meter, OrganizationId, PermissionProfileId, StoreError,
};
use common::world::{World, id, new_version, now, seed};
use common::{Rls, TestDb, fresh};
use sqlx::Row;
use uuid::Uuid;

/// The workspace counter of `meter` (summed over periods), 0 when absent.
async fn ws(db: &TestDb, acct: AccountId, meter: &str) -> i64 {
    sqlx::query(
        "SELECT COALESCE(sum(value), 0)::bigint FROM usage_counters \
         WHERE account_id = $1 AND meter = $2",
    )
    .bind(acct.0)
    .bind(meter)
    .fetch_one(&db.admin)
    .await
    .unwrap()
    .get(0)
}

/// The organization counter of `meter` (summed over periods), 0 when absent.
async fn org(db: &TestDb, o: OrganizationId, meter: &str) -> i64 {
    sqlx::query(
        "SELECT COALESCE(sum(value), 0)::bigint FROM org_usage_counters \
         WHERE organization_id = $1 AND meter = $2",
    )
    .bind(o.0)
    .bind(meter)
    .fetch_one(&db.admin)
    .await
    .unwrap()
    .get(0)
}

/// Every counter, at both levels, equals the sum of its ledger column for its meter and
/// period; and no ledger sum lacks its counter.
async fn counters_equal_ledger_sums(db: &TestDb) {
    let ws_off: i64 = sqlx::query(
        "SELECT count(*) FROM ( \
           SELECT account_id, meter, period_start, sum(quantity) AS v FROM usage_ledger \
            GROUP BY 1, 2, 3) l \
         FULL JOIN usage_counters c USING (account_id, meter, period_start) \
         WHERE COALESCE(l.v, 0) <> COALESCE(c.value, 0)",
    )
    .fetch_one(&db.admin)
    .await
    .unwrap()
    .get(0);
    assert_eq!(ws_off, 0, "a workspace counter differs from its ledger sum");
    let org_off: i64 = sqlx::query(
        "SELECT count(*) FROM ( \
           SELECT a.organization_id, l.meter, l.period_start, sum(l.org_quantity) AS v \
             FROM usage_ledger l JOIN accounts a ON a.id = l.account_id GROUP BY 1, 2, 3) l \
         FULL JOIN org_usage_counters c USING (organization_id, meter, period_start) \
         WHERE COALESCE(l.v, 0) <> COALESCE(c.value, 0)",
    )
    .fetch_one(&db.admin)
    .await
    .unwrap()
    .get(0);
    assert_eq!(
        org_off, 0,
        "an organization counter differs from its ledger sum"
    );
}

async fn record(db: &TestDb, w: &World, meter: Meter, source: Uuid) -> Result<bool, StoreError> {
    let mut tx = db.store.for_account(w.account).begin().await.unwrap();
    let counted = tx.record_usage(meter, 1, now(), "envelope", source).await?;
    tx.commit().await.unwrap();
    Ok(counted)
}

#[tokio::test]
async fn a_retried_source_counts_once_at_both_levels() {
    let Some(db) = fresh("a_retried_source_counts_once_at_both_levels", Rls::On).await else {
        return;
    };
    let w = seed(&db, "a").await;
    let b = seed(&db, "b").await;
    assert!(
        record(&db, &w, Meter::EnvelopesSent, w.envelope.0)
            .await
            .unwrap()
    );
    // The same decision recorded again, as a retried job would: not counted.
    assert!(
        !record(&db, &w, Meter::EnvelopesSent, w.envelope.0)
            .await
            .unwrap()
    );
    assert!(record(&db, &w, Meter::EnvelopesSent, id()).await.unwrap());
    // Another workspace's same source id is its own.
    assert!(
        record(&db, &b, Meter::EnvelopesSent, w.envelope.0)
            .await
            .unwrap()
    );
    assert_eq!(ws(&db, w.account, "envelopes_sent").await, 2);
    assert_eq!(org(&db, w.organization, "envelopes_sent").await, 2);
    assert_eq!(ws(&db, b.account, "envelopes_sent").await, 1);
    // A rolled-back transaction leaves no count.
    let mut tx = db.store.for_account(w.account).begin().await.unwrap();
    assert!(
        tx.record_usage(Meter::EnvelopesSent, 1, now(), "envelope", id())
            .await
            .unwrap()
    );
    tx.rollback().await.unwrap();
    assert_eq!(ws(&db, w.account, "envelopes_sent").await, 2);
    counters_equal_ledger_sums(&db).await;
    db.drop().await;
}

#[tokio::test]
async fn the_application_cannot_count_a_gauge_or_write_the_tables() {
    let Some(db) = fresh(
        "the_application_cannot_count_a_gauge_or_write_the_tables",
        Rls::On,
    )
    .await
    else {
        return;
    };
    let w = seed(&db, "a").await;
    for gauge in [Meter::Seats, Meter::StorageBytes, Meter::Workspaces] {
        let err = record(&db, &w, gauge, id()).await.unwrap_err();
        assert_eq!(err.code(), "CS-DB-0008", "{gauge:?}");
    }
    for table in ["usage_ledger", "usage_counters", "org_usage_counters"] {
        let sql = format!("UPDATE {table} SET period_start = period_start");
        let err = sqlx::query(sqlx::AssertSqlSafe(sql))
            .execute(&db.app)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("permission denied"),
            "{table}: {err}"
        );
    }
    counters_equal_ledger_sums(&db).await;
    db.drop().await;
}

#[tokio::test]
async fn storage_counts_a_blob_once_per_workspace() {
    let Some(db) = fresh("storage_counts_a_blob_once_per_workspace", Rls::On).await else {
        return;
    };
    // The seed writes one document version (1234 bytes) and one template document (99).
    let w = seed(&db, "a").await;
    assert_eq!(ws(&db, w.account, "storage_bytes").await, 1234 + 99);
    // A second version naming the same blob adds nothing.
    let mut tx = db.store.for_account(w.account).begin().await.unwrap();
    tx.documents()
        .add_version(&new_version(DocumentVersionId(id()), w.document))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(ws(&db, w.account, "storage_bytes").await, 1234 + 99);
    assert_eq!(org(&db, w.organization, "storage_bytes").await, 1234 + 99);
    counters_equal_ledger_sums(&db).await;
    db.drop().await;
}

#[tokio::test]
async fn seats_are_distinct_identities_across_the_organization() {
    let Some(db) = fresh(
        "seats_are_distinct_identities_across_the_organization",
        Rls::On,
    )
    .await
    else {
        return;
    };
    let w = seed(&db, "a").await;
    assert_eq!(ws(&db, w.account, "seats").await, 1);
    assert_eq!(org(&db, w.organization, "seats").await, 1);
    assert_eq!(org(&db, w.organization, "workspaces").await, 1);

    // The same person joins a second workspace of the organization as a sender.
    let second = db.workspace(w.organization, "a2").await;
    assert_eq!(org(&db, w.organization, "workspaces").await, 2);
    let senders = PermissionProfileId(id());
    let mut tx = db.store.for_account(second).begin().await.unwrap();
    tx.users()
        .create_profile(&PermissionProfile {
            id: senders,
            name: "Senders".into(),
            kind: ProfileKind::Sender,
            permissions: vec!["send".into()],
        })
        .await
        .unwrap();
    tx.users()
        .add_existing_member(w.user, &Personal("a@example.test".into()), senders)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(ws(&db, w.account, "seats").await, 1);
    assert_eq!(ws(&db, second, "seats").await, 1);
    assert_eq!(org(&db, w.organization, "seats").await, 1, "one identity");

    // Disabled in the first workspace: that workspace's seat goes, the organization's
    // stays while the second still holds one.
    let mut tx = db.store.for_account(w.account).begin().await.unwrap();
    tx.users().set_disabled(w.user, Some(now())).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(ws(&db, w.account, "seats").await, 0);
    assert_eq!(org(&db, w.organization, "seats").await, 1);
    let mut tx = db.store.for_account(second).begin().await.unwrap();
    tx.users().set_disabled(w.user, Some(now())).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(org(&db, w.organization, "seats").await, 0);
    counters_equal_ledger_sums(&db).await;
    db.drop().await;
}

#[tokio::test]
async fn an_archived_workspace_leaves_the_workspaces_gauge() {
    let Some(db) = fresh("an_archived_workspace_leaves_the_workspaces_gauge", Rls::On).await else {
        return;
    };
    let o = db.organization("acme").await;
    let _kept = db.workspace(o, "kept").await;
    let mut tx = db.store.for_organization(o).begin().await.unwrap();
    let archived = tx
        .create_workspace(AccountId(id()), "archived", &common::builtin_profiles())
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(org(&db, o, "workspaces").await, 2);
    let mut tx = db.store.for_organization(o).begin().await.unwrap();
    tx.archive_workspace(&archived).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(org(&db, o, "workspaces").await, 1);
    assert_eq!(ws(&db, archived.account_id(), "workspaces").await, 0);
    counters_equal_ledger_sums(&db).await;
    db.drop().await;
}
