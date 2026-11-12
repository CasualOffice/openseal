//! Migrations apply from empty, a second run is a no-op, edits and unknown versions are
//! refused, and the catalog shows every tenant table carrying the docs/22 §9 rules.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use casual_sign_store::{MIGRATIONS, Store};
use common::{Rls, fresh, server_url};
use sqlx::{Executor, Row};

#[tokio::test]
async fn migrations_apply_from_empty_then_a_second_run_applies_nothing() {
    let Some(url) = server_url("migrations_apply_from_empty") else {
        return;
    };
    let db = common::empty(&url).await;
    let owner = Store::from_pool(db.admin.clone());
    let first = owner.migrate().await.unwrap();
    let all: Vec<i64> = MIGRATIONS.iter().map(|m| m.version).collect();
    assert_eq!(first.applied, all);
    assert!(first.already.is_empty());
    let second = owner.migrate().await.unwrap();
    assert!(
        second.applied.is_empty(),
        "a second run applied {:?}",
        second.applied
    );
    assert_eq!(second.already, all);
    // Versions are dense from 1.
    assert_eq!(
        all,
        (1..=i64::try_from(all.len()).unwrap()).collect::<Vec<_>>()
    );
    db.drop().await;
}

#[tokio::test]
async fn an_edited_applied_migration_is_refused() {
    let Some(db) = fresh("an_edited_applied_migration_is_refused", Rls::On).await else {
        return;
    };
    db.admin
        .execute("UPDATE openseal_schema_migrations SET sha256 = '\\x00' WHERE version = 3")
        .await
        .unwrap();
    let err = Store::from_pool(db.admin.clone())
        .migrate()
        .await
        .unwrap_err();
    assert_eq!(err.code(), "CS-DB-0002");
    db.drop().await;
}

#[tokio::test]
async fn a_database_newer_than_the_build_is_refused() {
    let Some(db) = fresh("a_database_newer_than_the_build_is_refused", Rls::On).await else {
        return;
    };
    db.admin
        .execute("INSERT INTO openseal_schema_migrations (version, name, sha256) VALUES (9999, 'x', '\\x00')")
        .await
        .unwrap();
    let err = Store::from_pool(db.admin.clone())
        .migrate()
        .await
        .unwrap_err();
    assert_eq!(err.code(), "CS-DB-0011");
    db.drop().await;
}

/// Every table in `public` except the migration ledger is a tenant table (or `accounts`
/// and `users`, scoped by id and membership), with RLS on, a policy, `account_id NOT
/// NULL`, an index leading with it, and no TRUNCATE for the application role.
#[tokio::test]
async fn every_tenant_table_has_rls_a_policy_a_not_null_account_id_and_a_leading_index() {
    let Some(db) = fresh("every_tenant_table_has_rls", Rls::On).await else {
        return;
    };
    let tables: Vec<String> = sqlx::query(
        "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname <> 'openseal_schema_migrations' \
         ORDER BY 1",
    )
    .fetch_all(&db.admin)
    .await
    .unwrap()
    .iter()
    .map(|r| r.get(0))
    .collect();
    // Pinned: a new table must be looked at here, not just pass by default. 0008 added
    // `envelope_states` and `job_steps` (stage 2D), both tenant tables; 0009 added
    // `idempotency_keys` and `staff_sessions` (stage 2C); 0010 `user_invitations` (WEB-06);
    // 0012 `recipient_otp_codes` (SEC-A02), a tenant table; 0014 `organizations`,
    // `org_permission_sets` and `organization_admins` (ORG-02), organization tables
    // checked by `organizations.rs` instead of the account rules below.
    assert_eq!(tables.len(), 45, "{tables:?}");
    const ORG: &[&str] = &[
        "organizations",
        "org_permission_sets",
        "organization_admins",
    ];
    let mut problems = Vec::new();
    for t in &tables {
        let row = sqlx::query(
            "SELECT c.relrowsecurity, \
               (SELECT count(*) FROM pg_policies p WHERE p.schemaname = 'public' AND p.tablename = $1), \
               (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'account_id' AND NOT a.attisdropped), \
               EXISTS (SELECT 1 FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0] \
                       WHERE i.indrelid = c.oid AND a.attname = 'account_id'), \
               has_table_privilege('openseal_app', c.oid, 'TRUNCATE') \
             FROM pg_class c WHERE c.oid = ('public.' || $1)::regclass",
        )
        .bind(t)
        .fetch_one(&db.admin)
        .await
        .unwrap();
        let rls: bool = row.get(0);
        let policies: i64 = row.get(1);
        let not_null: Option<bool> = row.get(2);
        let leading: bool = row.get(3);
        let truncate: bool = row.get(4);
        if !rls {
            problems.push(format!("{t}: RLS off"));
        }
        if policies == 0 {
            problems.push(format!("{t}: no policy"));
        }
        if truncate {
            problems.push(format!("{t}: app role may TRUNCATE"));
        }
        if t != "accounts" && t != "users" && !ORG.contains(&t.as_str()) {
            if not_null != Some(true) {
                problems.push(format!("{t}: account_id missing or nullable"));
            }
            if !leading {
                problems.push(format!("{t}: no index leading with account_id"));
            }
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
    db.drop().await;
}

/// The application role may only read and insert evidence, and may not touch the
/// migration ledger.
#[tokio::test]
async fn the_application_role_cannot_change_evidence_or_the_ledger() {
    let Some(db) = fresh("the_application_role_cannot_change_evidence", Rls::On).await else {
        return;
    };
    for (table, privilege, allowed) in [
        ("audit_events", "SELECT", true),
        ("audit_events", "INSERT", true),
        ("audit_events", "UPDATE", false),
        ("audit_events", "DELETE", false),
        ("audit_events", "TRUNCATE", false),
        ("envelope_tombstones", "UPDATE", false),
        ("envelope_tombstones", "DELETE", false),
        ("accounts", "DELETE", false),
        ("accounts", "INSERT", false),
        ("accounts", "UPDATE", false),
        ("organizations", "INSERT", false),
        ("organizations", "DELETE", false),
        ("users", "DELETE", false),
        ("openseal_schema_migrations", "SELECT", false),
        ("openseal_schema_migrations", "INSERT", false),
    ] {
        let has: bool = sqlx::query_scalar("SELECT has_table_privilege('openseal_app', $1, $2)")
            .bind(table)
            .bind(privilege)
            .fetch_one(&db.admin)
            .await
            .unwrap();
        assert_eq!(has, allowed, "{privilege} on {table}");
    }
    // The role bypasses nothing.
    let bypass: bool = sqlx::query_scalar(
        "SELECT rolbypassrls OR rolsuper FROM pg_roles WHERE rolname = 'openseal_app'",
    )
    .fetch_one(&db.admin)
    .await
    .unwrap();
    assert!(!bypass);
    db.drop().await;
}
