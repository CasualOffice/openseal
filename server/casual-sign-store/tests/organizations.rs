//! ORG-02 (ADR-028, docs/23 §2.1, §2.2): organizations above accounts.
//!
//! - The `public` catalog tests 1 to 6 of docs/23 §2.1.
//! - `SEC-O01`: organization scope reads no content table, and only its own
//!   organization's workspaces, members and users, read-only; with another
//!   organization's ids it finds nothing.
//! - `SEC-O10`: a workspace never changes organization; the application cannot insert an
//!   account; a `WorkspaceOf` proof is re-checked.
//! - The migration on a database at 0013 holding an account with no admin.
//! - Bootstrap, workspace creation and archiving, the login password read, and the
//!   workspaces a session can switch to.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use casual_sign_audit::{Hash256, Personal};
use casual_sign_store::repo::accounts::{LoginKind, NewUser};
use casual_sign_store::repo::sessions::{LoginMethod, NewSession};
use casual_sign_store::*;
use common::world::{self, World, hash, id, now};
use common::{Rls, TestDb, builtin_profiles, fresh};
use sqlx::{Executor, PgPool, Row};

/// The SQLSTATE of a failed statement.
fn sqlstate(err: &sqlx::Error) -> String {
    err.as_database_error()
        .and_then(|e| e.code())
        .map(|c| c.into_owned())
        .unwrap_or_default()
}

/// Tables in `public` (the migration ledger aside) with column `col`.
async fn tables_with(admin: &PgPool, col: &str) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
         JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = $1 AND NOT a.attisdropped \
         WHERE n.nspname = 'public' AND c.relkind = 'r' ORDER BY 1",
    )
    .bind(col)
    .fetch_all(admin)
    .await
    .unwrap()
}

/// `(policy name, command, qual, with_check)` of every policy on `table`.
async fn policies(admin: &PgPool, table: &str) -> Vec<(String, String, String, String)> {
    sqlx::query(
        "SELECT policyname::text, cmd::text, coalesce(qual, ''), coalesce(with_check, '') \
         FROM pg_policies WHERE schemaname = 'public' AND tablename = $1 ORDER BY 1",
    )
    .bind(table)
    .fetch_all(admin)
    .await
    .unwrap()
    .iter()
    .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
    .collect()
}

/// Organization tables: declared through `openseal_org_table` (`organizations` by hand,
/// keyed on `id`).
const ORG_TABLES: &[&str] = &["org_permission_sets", "organization_admins"];

// Catalog tests (docs/23 §2.1) -----------------------------------------------------------

/// 1. Every `public` table with `account_id` has `tenant_isolation` and only it, except
/// `account_memberships` (one extra `FOR SELECT` organization policy); `accounts`, keyed
/// on `id`, likewise.
#[tokio::test]
async fn catalog_1_account_tables_keep_exactly_the_tenant_policy() {
    let Some(db) = fresh("catalog_1", Rls::On).await else {
        return;
    };
    let mut tables = tables_with(&db.admin, "account_id").await;
    tables.push("accounts".into());
    assert!(tables.len() > 35, "{tables:?}");
    let mut problems = Vec::new();
    for t in &tables {
        let names: Vec<String> = policies(&db.admin, t)
            .await
            .into_iter()
            .map(|p| p.0)
            .collect();
        let expected: &[&str] = match t.as_str() {
            "accounts" | "account_memberships" => &["organization_scope", "tenant_isolation"],
            _ => &["tenant_isolation"],
        };
        if names != expected {
            problems.push(format!("{t}: {names:?}"));
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
    db.drop().await;
}

/// 2. No policy on a `public` table outside the organization tables mentions
/// `openseal_current_org` except the named organization-scope ones, and each of those is
/// `FOR SELECT`.
#[tokio::test]
async fn catalog_2_organization_policies_on_account_tables_are_select_only() {
    let Some(db) = fresh("catalog_2", Rls::On).await else {
        return;
    };
    let rows = sqlx::query(
        "SELECT tablename::text, policyname::text, cmd::text FROM pg_policies \
         WHERE schemaname = 'public' \
           AND (coalesce(qual, '') || coalesce(with_check, '')) LIKE '%openseal_current_org%' \
         ORDER BY 1, 2",
    )
    .fetch_all(&db.admin)
    .await
    .unwrap();
    let mut seen = Vec::new();
    for r in &rows {
        let (t, p, cmd): (String, String, String) = (r.get(0), r.get(1), r.get(2));
        if t == "organizations" || ORG_TABLES.contains(&t.as_str()) {
            continue;
        }
        assert_eq!(cmd, "SELECT", "{t}.{p} is {cmd}");
        seen.push(format!("{t}.{p}"));
    }
    assert_eq!(
        seen,
        [
            "account_memberships.organization_scope",
            "accounts.organization_scope",
            "users.organization_scope"
        ],
    );
    db.drop().await;
}

/// 3. Every `public` table with `organization_id`, `accounts` excepted, is declared
/// through `openseal_org_table`: RLS on, exactly one policy `organization_isolation` on
/// `organization_id = openseal_current_org()` for every command, NOT NULL, an index
/// leading with it, and no TRUNCATE for the application role. `organizations` has the
/// same policy on `id`.
#[tokio::test]
async fn catalog_3_organization_tables_are_declared_through_the_helper() {
    let Some(db) = fresh("catalog_3", Rls::On).await else {
        return;
    };
    let mut tables = tables_with(&db.admin, "organization_id").await;
    tables.retain(|t| t != "accounts");
    assert_eq!(tables, ORG_TABLES);
    let mut problems = Vec::new();
    for t in &tables {
        let p = policies(&db.admin, t).await;
        let want = vec![(
            "organization_isolation".to_owned(),
            "ALL".to_owned(),
            "(organization_id = openseal_current_org())".to_owned(),
            "(organization_id = openseal_current_org())".to_owned(),
        )];
        if p != want {
            problems.push(format!("{t}: {p:?}"));
        }
        let row = sqlx::query(
            "SELECT c.relrowsecurity, \
               (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'organization_id'), \
               EXISTS (SELECT 1 FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0] \
                       WHERE i.indrelid = c.oid AND a.attname = 'organization_id'), \
               has_table_privilege('openseal_app', c.oid, 'TRUNCATE') \
             FROM pg_class c WHERE c.oid = ('public.' || $1)::regclass",
        )
        .bind(t)
        .fetch_one(&db.admin)
        .await
        .unwrap();
        let (rls, not_null, leading, truncate): (bool, bool, bool, bool) =
            (row.get(0), row.get(1), row.get(2), row.get(3));
        if !(rls && not_null && leading && !truncate) {
            problems.push(format!(
                "{t}: rls {rls} not_null {not_null} leading {leading} truncate {truncate}"
            ));
        }
    }
    let orgs = policies(&db.admin, "organizations").await;
    let names: Vec<(&str, &str)> = orgs.iter().map(|p| (p.0.as_str(), p.1.as_str())).collect();
    assert_eq!(
        names,
        [
            ("organization_isolation", "ALL"),
            ("workspace_reads_its_organization", "SELECT")
        ]
    );
    assert_eq!(orgs[0].2, "(id = openseal_current_org())");
    assert!(problems.is_empty(), "{problems:#?}");
    db.drop().await;
}

/// 4. Setting both scopes makes `openseal_current_org()` NULL: an account scope never also
/// reads as an organization scope.
#[tokio::test]
async fn catalog_4_both_settings_make_the_organization_null() {
    let Some(db) = fresh("catalog_4", Rls::On).await else {
        return;
    };
    let w = world::seed(&db, "alpha").await;
    let mut conn = db.app.begin().await.unwrap();
    for (key, val) in [
        ("openseal.organization_id", w.organization.0),
        ("openseal.account_id", w.account.0),
    ] {
        sqlx::query("SELECT set_config($1, $2, true)")
            .bind(key)
            .bind(val.to_string())
            .execute(&mut *conn)
            .await
            .unwrap();
    }
    let org: Option<uuid::Uuid> = sqlx::query_scalar("SELECT openseal_current_org()")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert_eq!(org, None);
    // So the organization tables show nothing, and accounts only through the account.
    let admins: i64 = sqlx::query_scalar("SELECT count(*) FROM organization_admins")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert_eq!(admins, 0);
    conn.rollback().await.unwrap();
    // The organization alone does read as one.
    let mut conn = db.app.begin().await.unwrap();
    sqlx::query("SELECT set_config('openseal.organization_id', $1, true)")
        .bind(w.organization.0.to_string())
        .execute(&mut *conn)
        .await
        .unwrap();
    let org: Option<uuid::Uuid> = sqlx::query_scalar("SELECT openseal_current_org()")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert_eq!(org, Some(w.organization.0));
    conn.rollback().await.unwrap();
    db.drop().await;
}

/// 5 and `SEC-O10`. The application role has no INSERT on `accounts`, UPDATE only on
/// `name`, `settings` and `data_region`, and no SELECT on `users.password_hash`. An
/// UPDATE of `accounts.organization_id` is refused for the application role (42501,
/// `CS-DB-0009`) and for the owner role (`OS004`, `CS-DB-0013`).
#[tokio::test]
async fn catalog_5_accounts_and_password_hashes_are_out_of_the_applications_reach() {
    let Some(db) = fresh("catalog_5", Rls::On).await else {
        return;
    };
    let a = world::seed(&db, "alpha").await;
    let b = world::seed(&db, "bravo").await;
    let col = |c: &'static str, p: &'static str| {
        let admin = db.admin.clone();
        async move {
            sqlx::query_scalar::<_, bool>("SELECT has_column_privilege('openseal_app', $1, $2, $3)")
                .bind(if c == "password_hash" {
                    "users"
                } else {
                    "accounts"
                })
                .bind(c)
                .bind(p)
                .fetch_one(&admin)
                .await
                .unwrap()
        }
    };
    let insert: bool =
        sqlx::query_scalar("SELECT has_table_privilege('openseal_app', 'accounts', 'INSERT')")
            .fetch_one(&db.admin)
            .await
            .unwrap();
    assert!(!insert, "openseal_app may INSERT into accounts");
    for c in [
        "id",
        "organization_id",
        "status",
        "admin_chain_head",
        "created_at",
    ] {
        assert!(
            !col(c, "UPDATE").await,
            "openseal_app may UPDATE accounts.{c}"
        );
    }
    for c in ["name", "settings", "data_region"] {
        assert!(
            col(c, "UPDATE").await,
            "openseal_app may not UPDATE accounts.{c}"
        );
    }
    assert!(!col("password_hash", "SELECT").await);

    // In account scope: the app cannot move its workspace, nor insert another one.
    let mut conn = db.app.begin().await.unwrap();
    sqlx::query("SELECT set_config('openseal.account_id', $1, true)")
        .bind(a.account.0.to_string())
        .execute(&mut *conn)
        .await
        .unwrap();
    let err = sqlx::query("UPDATE accounts SET organization_id = $1 WHERE id = $2")
        .bind(b.organization.0)
        .bind(a.account.0)
        .execute(&mut *conn)
        .await
        .unwrap_err();
    assert_eq!(sqlstate(&err), "42501", "{err}");
    conn.rollback().await.unwrap();
    let mut conn = db.app.begin().await.unwrap();
    sqlx::query("SELECT set_config('openseal.account_id', $1, true)")
        .bind(a.account.0.to_string())
        .execute(&mut *conn)
        .await
        .unwrap();
    let err = sqlx::query("INSERT INTO accounts (id, organization_id, name) VALUES ($1, $2, 'x')")
        .bind(a.account.0)
        .bind(a.organization.0)
        .execute(&mut *conn)
        .await
        .unwrap_err();
    assert_eq!(sqlstate(&err), "42501", "{err}");
    conn.rollback().await.unwrap();
    // Nor read a password hash directly.
    let mut conn = db.app.begin().await.unwrap();
    sqlx::query("SELECT set_config('openseal.account_id', $1, true)")
        .bind(a.account.0.to_string())
        .execute(&mut *conn)
        .await
        .unwrap();
    let err = sqlx::query("SELECT password_hash FROM users")
        .execute(&mut *conn)
        .await
        .unwrap_err();
    assert_eq!(sqlstate(&err), "42501", "{err}");
    conn.rollback().await.unwrap();

    // The owner role is refused by the trigger.
    let err = sqlx::query("UPDATE accounts SET organization_id = $1 WHERE id = $2")
        .bind(b.organization.0)
        .bind(a.account.0)
        .execute(&db.admin)
        .await
        .unwrap_err();
    assert_eq!(sqlstate(&err), "OS004", "{err}");
    // An update that leaves it as it was passes (name only).
    sqlx::query(
        "UPDATE accounts SET organization_id = organization_id, name = 'alpha2' WHERE id = $1",
    )
    .bind(a.account.0)
    .execute(&db.admin)
    .await
    .unwrap();
    let org: uuid::Uuid = sqlx::query_scalar("SELECT organization_id FROM accounts WHERE id = $1")
        .bind(a.account.0)
        .fetch_one(&db.admin)
        .await
        .unwrap();
    assert_eq!(org, a.organization.0);
    db.drop().await;
}

/// The members, login ability and owned functions of `openseal_org_mover`.
async fn mover(admin: &PgPool) -> (bool, i64, Vec<String>) {
    let login: bool =
        sqlx::query_scalar("SELECT rolcanlogin FROM pg_roles WHERE rolname = 'openseal_org_mover'")
            .fetch_one(admin)
            .await
            .unwrap();
    let members: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_auth_members WHERE roleid = 'openseal_org_mover'::regrole",
    )
    .fetch_one(admin)
    .await
    .unwrap();
    let owns: Vec<String> = sqlx::query_scalar(
        "SELECT n.nspname || '.' || p.proname FROM pg_proc p \
         JOIN pg_namespace n ON n.oid = p.pronamespace \
         WHERE p.proowner = 'openseal_org_mover'::regrole ORDER BY 1",
    )
    .fetch_all(admin)
    .await
    .unwrap();
    (login, members, owns)
}

fn mover_holds(m: &(bool, i64, Vec<String>)) {
    let (login, members, owns) = m;
    assert!(!login, "openseal_org_mover can log in");
    assert_eq!(*members, 0, "openseal_org_mover has members");
    assert!(
        owns.is_empty() || owns == &["platform.apply_link_workspaces".to_owned()],
        "openseal_org_mover owns {owns:?}"
    );
}

/// 6. `openseal_org_mover` cannot log in, has no members, and owns no function (or, from
/// ORG-20, only `platform.apply_link_workspaces`).
#[tokio::test]
async fn catalog_6_the_org_mover_role_is_inert() {
    let Some(db) = fresh("catalog_6", Rls::On).await else {
        return;
    };
    mover_holds(&mover(&db.admin).await);
    db.drop().await;
}

/// 6, on a migrator that is not a superuser but has CREATEROLE, owning its database: the
/// migrations apply and the role stays inert, given `openseal_org_mover` was created by a
/// superuser first (as the earlier migration of this cluster did); otherwise migration
/// 0014 refuses to finish (docs/23 §2.1 As built).
#[tokio::test]
async fn catalog_6_holds_on_a_non_superuser_createrole_migrator() {
    let Some(first) = fresh("catalog_6_non_superuser", Rls::On).await else {
        return;
    };
    let url = common::server_url("catalog_6_non_superuser").unwrap();
    let server: sqlx::postgres::PgConnectOptions = url.parse().unwrap();
    let role = format!("openseal_migrator_{}", uuid::Uuid::new_v4().simple());
    let dbname = format!("openseal_m_{}", uuid::Uuid::new_v4().simple());
    let maint = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(server.clone())
        .await
        .unwrap();
    maint
        .execute(sqlx::AssertSqlSafe(format!(
            "CREATE ROLE {role} LOGIN CREATEROLE PASSWORD 'migrator-test-only'"
        )))
        .await
        .unwrap();
    maint
        .execute(sqlx::AssertSqlSafe(format!(
            "CREATE DATABASE {dbname} OWNER {role}"
        )))
        .await
        .unwrap();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            server
                .clone()
                .database(&dbname)
                .username(&role)
                .password("migrator-test-only"),
        )
        .await
        .unwrap();
    let report = Store::from_pool(pool.clone()).migrate().await.unwrap();
    assert_eq!(report.applied.len(), MIGRATIONS.len());
    pool.close().await;
    let check = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(server.clone().database(&dbname))
        .await
        .unwrap();
    mover_holds(&mover(&check).await);
    check.close().await;
    maint
        .execute(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE {dbname} WITH (FORCE)"
        )))
        .await
        .unwrap();
    maint
        .execute(sqlx::AssertSqlSafe(format!(
            "DROP OWNED BY {role} CASCADE; DROP ROLE {role}"
        )))
        .await
        .unwrap();
    maint.close().await;
    first.drop().await;
}

// SEC-O01: organization scope reaches no content ----------------------------------------

/// Organization A's scope, through raw SQL as the application role (bypassing the
/// repository): every content table returns no row; `accounts`, `account_memberships`,
/// `users` and the organization tables return exactly A's; nothing is writable through
/// the `FOR SELECT` organization policies.
async fn organization_scope_reaches_no_content(rls: Rls) {
    let Some(db) = fresh(
        &format!("organization_scope_reaches_no_content_{rls:?}"),
        rls,
    )
    .await
    else {
        return;
    };
    let a = world::seed(&db, "alpha").await;
    let b = world::seed(&db, "bravo").await;
    // A second workspace in A's organization, with its own content.
    let a2 = db.workspace(a.organization, "alpha-two").await;
    let _ = a2;
    for w in [&a, &b] {
        sqlx::query(
            "INSERT INTO organization_admins (organization_id, user_id, role, created_at) \
             VALUES ($1, $2, 'owner', now())",
        )
        .bind(w.organization.0)
        .bind(w.user.0)
        .execute(&db.admin)
        .await
        .unwrap();
    }
    if rls == Rls::On {
        let tables = common::rls_tables(&db.admin).await;
        let reach: &[&str] = &[
            "accounts",
            "account_memberships",
            "users",
            "organizations",
            "organization_admins",
            "org_permission_sets",
        ];
        for t in &tables {
            let truth_sql = match t.as_str() {
                "accounts" => "SELECT count(*) FROM accounts WHERE organization_id = $1".to_owned(),
                "account_memberships" => {
                    "SELECT count(*) FROM account_memberships m JOIN accounts a ON a.id = m.account_id \
                     WHERE a.organization_id = $1"
                        .to_owned()
                }
                "users" => "SELECT count(*) FROM users u WHERE EXISTS (SELECT 1 FROM account_memberships m \
                            JOIN accounts a ON a.id = m.account_id WHERE m.user_id = u.id AND a.organization_id = $1)"
                    .to_owned(),
                "organizations" => "SELECT count(*) FROM organizations WHERE id = $1".to_owned(),
                _ if reach.contains(&t.as_str()) => {
                    format!("SELECT count(*) FROM {t} WHERE organization_id = $1")
                }
                _ => "SELECT 0::bigint WHERE $1::uuid IS NOT NULL".to_owned(),
            };
            let truth: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(truth_sql))
                .bind(a.organization.0)
                .fetch_one(&db.admin)
                .await
                .unwrap();
            let mut conn = db.app.begin().await.unwrap();
            sqlx::query("SELECT set_config('openseal.organization_id', $1, true)")
                .bind(a.organization.0.to_string())
                .execute(&mut *conn)
                .await
                .unwrap();
            let seen: i64 =
                sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {t}")))
                    .fetch_one(&mut *conn)
                    .await
                    .unwrap();
            conn.rollback().await.unwrap();
            assert_eq!(
                seen, truth,
                "{t}: organization scope shows {seen} rows, expected {truth}"
            );
            if !reach.contains(&t.as_str()) {
                assert_eq!(seen, 0, "{t}: content visible in organization scope");
            }
        }
        // The SELECT-only policies admit no write.
        let mut conn = db.app.begin().await.unwrap();
        sqlx::query("SELECT set_config('openseal.organization_id', $1, true)")
            .bind(a.organization.0.to_string())
            .execute(&mut *conn)
            .await
            .unwrap();
        for sql in [
            "UPDATE accounts SET name = 'renamed'",
            "UPDATE account_memberships SET disabled_at = now()",
            "UPDATE users SET name = 'renamed'",
            "DELETE FROM account_memberships",
        ] {
            let hit = sqlx::query(sql).execute(&mut *conn).await.unwrap();
            assert_eq!(hit.rows_affected(), 0, "{sql}");
        }
        conn.rollback().await.unwrap();
    }

    // Through the store: A's organization finds none of B's ids.
    let mut tx = db
        .store
        .for_organization(a.organization)
        .begin()
        .await
        .unwrap();
    assert_eq!(tx.organization().await.unwrap().id, a.organization);
    assert!(tx.workspace(b.account).await.unwrap().is_none());
    let names: Vec<String> = tx
        .workspaces()
        .await
        .unwrap()
        .into_iter()
        .map(|w| w.name)
        .collect();
    assert_eq!(names, ["alpha", "alpha-two"]);
    let fake = tx.workspace(a.account).await.unwrap().unwrap();
    assert_eq!(fake.organization_id(), a.organization);
    // Archiving another organization's workspace is not possible: no proof for it.
    tx.rollback().await.unwrap();
    let mut tx = db
        .store
        .for_organization(b.organization)
        .begin()
        .await
        .unwrap();
    assert!(tx.workspace(a.account).await.unwrap().is_none());
    let err = tx.archive_workspace(&fake).await.unwrap_err();
    assert_eq!(err.code(), "CS-DB-0003");
    tx.rollback().await.unwrap();
    assert_untouched(&db, &a, &b).await;
    db.drop().await;
}

async fn assert_untouched(db: &TestDb, a: &World, b: &World) {
    for w in [a, b] {
        let (name, status): (String, String) =
            sqlx::query_as("SELECT name, status FROM accounts WHERE id = $1")
                .bind(w.account.0)
                .fetch_one(&db.admin)
                .await
                .unwrap();
        assert!(name == "alpha" || name == "bravo");
        assert_eq!(status, "active");
    }
}

#[tokio::test]
async fn organization_scope_reaches_no_content_with_rls() {
    organization_scope_reaches_no_content(Rls::On).await;
}

#[tokio::test]
async fn organization_scope_reaches_no_content_without_rls() {
    organization_scope_reaches_no_content(Rls::Off).await;
}

/// `SEC-O10`: a proof taken before the workspace was re-linked to another organization
/// (only ORG-20's operator link may; simulated here by the owner with the trigger off)
/// opens nothing after it.
#[tokio::test]
async fn a_workspace_proof_is_checked_again_when_used() {
    let Some(db) = fresh("a_workspace_proof_is_checked_again", Rls::On).await else {
        return;
    };
    let a = world::seed(&db, "alpha").await;
    let b = world::seed(&db, "bravo").await;
    let mut tx = db
        .store
        .for_organization(a.organization)
        .begin()
        .await
        .unwrap();
    let proof = tx.workspace(a.account).await.unwrap().unwrap();
    tx.commit().await.unwrap();
    // Before: the proof opens A's workspace, and only it.
    let mut w = db.store.for_workspace_of(&proof).await.unwrap();
    assert_eq!(w.account_id(), a.account);
    assert_eq!(
        w.account().get().await.unwrap().organization_id,
        a.organization
    );
    w.rollback().await.unwrap();
    db.admin
        .execute(sqlx::AssertSqlSafe(format!(
            "ALTER TABLE accounts DISABLE TRIGGER accounts_organization_fixed; \
             UPDATE accounts SET organization_id = '{}' WHERE id = '{}'; \
             ALTER TABLE accounts ENABLE TRIGGER accounts_organization_fixed",
            b.organization.0, a.account.0
        )))
        .await
        .unwrap();
    let err = db.store.for_workspace_of(&proof).await.unwrap_err();
    assert_eq!(err.code(), "CS-DB-0003");
    // And A's organization no longer finds it.
    let mut tx = db
        .store
        .for_organization(a.organization)
        .begin()
        .await
        .unwrap();
    assert!(tx.workspace(a.account).await.unwrap().is_none());
    db.drop().await;
}

// Workspaces ------------------------------------------------------------------------------

#[tokio::test]
async fn an_organization_creates_and_archives_its_workspaces_only() {
    let Some(db) = fresh("an_organization_creates_and_archives", Rls::On).await else {
        return;
    };
    let a = world::seed(&db, "alpha").await;
    let profiles = builtin_profiles();
    let ws = AccountId(id());
    let mut tx = db
        .store
        .for_organization(a.organization)
        .begin()
        .await
        .unwrap();
    let proof = tx.create_workspace(ws, "Sales", &profiles).await.unwrap();
    tx.commit().await.unwrap();
    // It is a workspace of A's organization, with its built-in profiles.
    let mut w = db.store.for_workspace_of(&proof).await.unwrap();
    let acct = w.account().get().await.unwrap();
    assert_eq!(
        (acct.organization_id, acct.status, acct.name.as_str()),
        (a.organization, WorkspaceStatus::Active, "Sales")
    );
    assert_eq!(
        acct.settings["builtin_profiles"]["admin"],
        profiles.admin.to_string()
    );
    for (p, kind) in [
        (profiles.admin, "admin"),
        (profiles.sender, "sender"),
        (profiles.viewer, "viewer"),
    ] {
        assert_eq!(
            w.users().profile(p).await.unwrap().unwrap().kind.as_str(),
            kind
        );
    }
    w.rollback().await.unwrap();
    // Outside organization scope (none, or an account's) the function creates nothing.
    for scope in [None, Some(a.account)] {
        let mut conn = db.app.begin().await.unwrap();
        if let Some(acct) = scope {
            sqlx::query("SELECT set_config('openseal.account_id', $1, true)")
                .bind(acct.0.to_string())
                .execute(&mut *conn)
                .await
                .unwrap();
        }
        let created: bool =
            sqlx::query_scalar("SELECT openseal_create_workspace($1, 'x', $2, $3, $4)")
                .bind(id())
                .bind(id())
                .bind(id())
                .bind(id())
                .fetch_one(&mut *conn)
                .await
                .unwrap();
        assert!(!created, "{scope:?}");
        conn.rollback().await.unwrap();
    }
    // Archive.
    let mut tx = db
        .store
        .for_organization(a.organization)
        .begin()
        .await
        .unwrap();
    tx.archive_workspace(&proof).await.unwrap();
    tx.commit().await.unwrap();
    let mut w = db.store.for_workspace_of(&proof).await.unwrap();
    assert_eq!(
        w.account().get().await.unwrap().status,
        WorkspaceStatus::Archived
    );
    w.rollback().await.unwrap();
    // A suspended organization creates none.
    sqlx::query("UPDATE organizations SET status = 'suspended' WHERE id = $1")
        .bind(a.organization.0)
        .execute(&db.admin)
        .await
        .unwrap();
    let mut tx = db
        .store
        .for_organization(a.organization)
        .begin()
        .await
        .unwrap();
    let err = tx
        .create_workspace(AccountId(id()), "More", &builtin_profiles())
        .await
        .unwrap_err();
    assert_eq!(err.code(), "CS-DB-0003");
    db.drop().await;
}

fn admin_user(id: UserId, tag: &str) -> NewUser {
    NewUser {
        id,
        email: Personal(format!("{tag}@example.test")),
        email_normalized: Personal(format!("{tag}@example.test")),
        name: Personal(format!("Admin {tag}")),
        login_kind: LoginKind::Local,
        idp: None,
    }
}

#[tokio::test]
async fn bootstrap_makes_the_first_organization_and_its_owner_once() {
    let Some(db) = fresh("bootstrap_makes_the_first_organization", Rls::On).await else {
        return;
    };
    let org = OrganizationId(id());
    let account = AccountId(id());
    let profiles = builtin_profiles();
    let admin = UserId(id());
    let mut tx = db
        .store
        .bootstrap_organization(org, account, "First", &profiles)
        .await
        .unwrap();
    tx.users()
        .create_member(&admin_user(admin, "first"), profiles.admin)
        .await
        .unwrap();
    tx.account().make_first_owner(admin, now()).await.unwrap();
    tx.commit().await.unwrap();
    let role: String = sqlx::query_scalar(
        "SELECT role FROM organization_admins WHERE organization_id = $1 AND user_id = $2",
    )
    .bind(org.0)
    .bind(admin.0)
    .fetch_one(&db.admin)
    .await
    .unwrap();
    assert_eq!(role, "owner");
    // A second owner through the bootstrap door is refused.
    let mut tx = db.store.for_account(account).begin().await.unwrap();
    let other = UserId(id());
    tx.users()
        .create_member(&admin_user(other, "second"), profiles.admin)
        .await
        .unwrap();
    assert_eq!(
        tx.account()
            .make_first_owner(other, now())
            .await
            .unwrap_err()
            .code(),
        "CS-DB-0003"
    );
    drop(tx);
    // A second bootstrap is refused, and leaves nothing behind.
    let err = db
        .store
        .bootstrap_organization(
            OrganizationId(id()),
            AccountId(id()),
            "Second",
            &builtin_profiles(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), "CS-DB-0006");
    let orgs: i64 = sqlx::query_scalar("SELECT count(*) FROM organizations")
        .fetch_one(&db.admin)
        .await
        .unwrap();
    assert_eq!(orgs, 1);
    // A bootstrap outside the account scope it names is refused too.
    let empty = fresh("bootstrap_makes_the_first_organization_2", Rls::On)
        .await
        .unwrap();
    let created: bool =
        sqlx::query_scalar("SELECT openseal_bootstrap_organization($1, $2, 'x', $3, $4, $5)")
            .bind(id())
            .bind(id())
            .bind(id())
            .bind(id())
            .bind(id())
            .fetch_one(&empty.app)
            .await
            .unwrap();
    assert!(!created);
    empty.drop().await;
    db.drop().await;
}

/// The ORG-02 review probe: an organization that already exists without an owner (the
/// state the backfill leaves for an account with no admin, or a console-created one
/// before its owner is named) is not claimable through the bootstrap door by one of its
/// workspace admins, through the store or by calling the function directly. Owners of
/// such an organization are named through the console (docs/23 §5.1).
#[tokio::test]
async fn bootstrap_owner_refuses_an_organization_made_before_this_transaction() {
    let Some(db) = fresh("bootstrap_owner_refuses_an_older_org", Rls::On).await else {
        return;
    };
    let (org, account) = db.account("ownerless").await;
    let admin_profile: uuid::Uuid = sqlx::query_scalar(
        "SELECT id FROM permission_profiles WHERE account_id = $1 AND kind = 'admin'",
    )
    .bind(account.0)
    .fetch_one(&db.admin)
    .await
    .unwrap();
    let admin = UserId(id());
    let mut tx = db.store.for_account(account).begin().await.unwrap();
    tx.users()
        .create_member(
            &admin_user(admin, "ownerless"),
            PermissionProfileId(admin_profile),
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    // Through the store.
    let mut tx = db.store.for_account(account).begin().await.unwrap();
    assert_eq!(
        tx.account()
            .make_first_owner(admin, now())
            .await
            .unwrap_err()
            .code(),
        "CS-DB-0003"
    );
    drop(tx);
    // Directly, as the application role in the workspace's scope.
    let mut conn = db.app.begin().await.unwrap();
    sqlx::query("SELECT set_config('openseal.account_id', $1, true)")
        .bind(account.0.to_string())
        .execute(&mut *conn)
        .await
        .unwrap();
    let done: bool = sqlx::query_scalar("SELECT openseal_bootstrap_owner($1, now())")
        .bind(admin.0)
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert!(!done, "an existing ownerless organization was claimed");
    conn.commit().await.unwrap();
    let owners: i64 =
        sqlx::query_scalar("SELECT count(*) FROM organization_admins WHERE organization_id = $1")
            .bind(org.0)
            .fetch_one(&db.admin)
            .await
            .unwrap();
    assert_eq!(owners, 0);
    db.drop().await;
}

/// The deferred last-owner constraint: removing or demoting the only enabled owner of an
/// active organization fails at commit (`CS-ORG-0008`).
#[tokio::test]
async fn an_active_organization_keeps_an_enabled_owner() {
    let Some(db) = fresh("an_active_organization_keeps_an_owner", Rls::On).await else {
        return;
    };
    let a = world::seed(&db, "alpha").await;
    sqlx::query(
        "INSERT INTO organization_admins (organization_id, user_id, role, created_at) \
         VALUES ($1, $2, 'owner', now())",
    )
    .bind(a.organization.0)
    .bind(a.user.0)
    .execute(&db.admin)
    .await
    .unwrap();
    for sql in [
        "DELETE FROM organization_admins",
        "UPDATE organization_admins SET role = 'admin'",
    ] {
        let mut conn = db.app.begin().await.unwrap();
        sqlx::query("SELECT set_config('openseal.organization_id', $1, true)")
            .bind(a.organization.0.to_string())
            .execute(&mut *conn)
            .await
            .unwrap();
        let hit = sqlx::query(sql).execute(&mut *conn).await.unwrap();
        assert_eq!(hit.rows_affected(), 1, "{sql}");
        let err = conn.commit().await.unwrap_err();
        assert_eq!(sqlstate(&err), "23514", "{sql}: {err}");
        assert_eq!(
            err.as_database_error().and_then(|e| e.constraint()),
            Some(LAST_OWNER_CONSTRAINT),
            "{sql}"
        );
    }
    // With a second enabled owner, one may go.
    let second = UserId(id());
    let mut tx = db.store.for_account(a.account).begin().await.unwrap();
    tx.users()
        .create_member(&admin_user(second, "second"), a.profile)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let mut conn = db.app.begin().await.unwrap();
    sqlx::query("SELECT set_config('openseal.organization_id', $1, true)")
        .bind(a.organization.0.to_string())
        .execute(&mut *conn)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO organization_admins (organization_id, user_id, role, created_at) \
         VALUES ($1, $2, 'owner', now())",
    )
    .bind(a.organization.0)
    .bind(second.0)
    .execute(&mut *conn)
    .await
    .unwrap();
    sqlx::query("DELETE FROM organization_admins WHERE user_id = $1")
        .bind(a.user.0)
        .execute(&mut *conn)
        .await
        .unwrap();
    conn.commit().await.unwrap();
    // A disabled identity does not count as an owner.
    sqlx::query("UPDATE users SET disabled_at = now() WHERE id = $1")
        .bind(second.0)
        .execute(&db.admin)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO organization_admins (organization_id, user_id, role, created_at) \
         VALUES ($1, $2, 'owner', now())",
    )
    .bind(a.organization.0)
    .bind(a.user.0)
    .execute(&db.admin)
    .await
    .unwrap();
    let mut conn = db.app.begin().await.unwrap();
    sqlx::query("SELECT set_config('openseal.organization_id', $1, true)")
        .bind(a.organization.0.to_string())
        .execute(&mut *conn)
        .await
        .unwrap();
    sqlx::query("DELETE FROM organization_admins WHERE user_id = $1")
        .bind(a.user.0)
        .execute(&mut *conn)
        .await
        .unwrap();
    let err = conn.commit().await.unwrap_err();
    assert_eq!(sqlstate(&err), "23514", "{err}");
    db.drop().await;
}

// Sessions and login --------------------------------------------------------------------

async fn session(db: &TestDb, account: AccountId, user: UserId, tag: &str) {
    let mut tx = db.store.for_account(account).begin().await.unwrap();
    tx.sessions()
        .create(&NewSession {
            id: StaffSessionId(id()),
            user_id: user,
            token_sha256: hash(tag),
            csrf_sha256: hash(&format!("csrf-{tag}")),
            method: LoginMethod::Password,
            created_at: now(),
            expires_at: now() + time::Duration::hours(8),
        })
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn a_session_lists_the_workspaces_its_user_can_switch_to() {
    let Some(db) = fresh("a_session_lists_the_workspaces", Rls::On).await else {
        return;
    };
    let a = world::seed(&db, "alpha").await;
    let b = world::seed(&db, "bravo").await;
    let c = world::seed(&db, "charlie").await;
    // A's user is also a member of B, and of C but disabled there.
    for (w, disabled) in [(&b, false), (&c, true)] {
        let mut tx = db.store.for_account(w.account).begin().await.unwrap();
        tx.users()
            .add_existing_member(a.user, &Personal("alpha@example.test".into()), w.profile)
            .await
            .unwrap();
        if disabled {
            tx.users().set_disabled(a.user, Some(now())).await.unwrap();
        }
        tx.commit().await.unwrap();
    }
    session(&db, a.account, a.user, "s-alpha").await;
    let got = db
        .store
        .entry_points()
        .user_workspaces(&hash("s-alpha"), now())
        .await
        .unwrap();
    let ids: Vec<(AccountId, &str, OrganizationId)> = got
        .iter()
        .map(|w| {
            (
                w.account_id,
                w.organization_name.as_str(),
                w.organization_id,
            )
        })
        .collect();
    assert_eq!(
        ids,
        [
            (a.account, "alpha", a.organization),
            (b.account, "bravo", b.organization)
        ]
    );
    // A dead or unknown session lists nothing.
    let none = db
        .store
        .entry_points()
        .user_workspaces(&hash("s-alpha"), now() + time::Duration::days(1))
        .await
        .unwrap();
    assert!(none.is_empty());
    let none = db
        .store
        .entry_points()
        .user_workspaces(&hash("nobody"), now())
        .await
        .unwrap();
    assert!(none.is_empty());
    db.drop().await;
}

#[tokio::test]
async fn the_login_password_hash_is_read_only_for_an_enabled_member_of_the_scope() {
    let Some(db) = fresh("the_login_password_hash_is_read_only", Rls::On).await else {
        return;
    };
    let a = world::seed(&db, "alpha").await;
    let b = world::seed(&db, "bravo").await;
    let mut tx = db.store.for_account(a.account).begin().await.unwrap();
    tx.users()
        .set_password_hash(a.user, &Personal("$argon2id$a".into()))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let mut tx = db.store.for_account(a.account).begin().await.unwrap();
    assert_eq!(
        tx.users().password_hash(a.user).await.unwrap().map(|p| p.0),
        Some("$argon2id$a".to_owned())
    );
    tx.rollback().await.unwrap();
    // B's scope, naming A's account, reads nothing.
    let mut conn = db.app.begin().await.unwrap();
    sqlx::query("SELECT set_config('openseal.account_id', $1, true)")
        .bind(b.account.0.to_string())
        .execute(&mut *conn)
        .await
        .unwrap();
    let phc: Option<String> = sqlx::query_scalar("SELECT openseal_login_password_hash($1, $2)")
        .bind(a.user.0)
        .bind(a.account.0)
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert_eq!(phc, None);
    conn.rollback().await.unwrap();
    // A disabled member's hash is not read.
    let mut tx = db.store.for_account(a.account).begin().await.unwrap();
    tx.users().set_disabled(a.user, Some(now())).await.unwrap();
    assert!(tx.users().password_hash(a.user).await.unwrap().is_none());
    db.drop().await;
}

// The migration on an existing database -------------------------------------------------

/// A database at 0013 (before organizations) with three accounts: one with an enabled
/// admin, one with no admin, and one whose only admin is disabled there. Migration 0014
/// gives each an organization with its own UUID and name, owners only where an enabled
/// admin was, and leaves the accounts' content and isolation as they were.
#[tokio::test]
async fn a_database_with_an_account_without_admin_migrates() {
    let Some(url) = common::server_url("a_database_with_an_account_without_admin_migrates") else {
        return;
    };
    let db = common::empty(&url).await;
    // Apply 0001 to 0013 as the runner does, recording each in the ledger.
    for m in MIGRATIONS.iter().filter(|m| m.version <= 13) {
        let mut tx = db.admin.begin().await.unwrap();
        tx.execute(sqlx::raw_sql(sqlx::AssertSqlSafe(m.sql)))
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO openseal_schema_migrations (version, name, sha256) VALUES ($1, $2, $3)",
        )
        .bind(m.version)
        .bind(m.name)
        .bind(Hash256::digest(m.sql.as_bytes()).as_bytes().as_slice())
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    let accounts = [id(), id(), id()];
    let users = [id(), id(), id()];
    for (i, (acct, user)) in accounts.iter().zip(users).enumerate() {
        let admin_profile = id();
        let sender_profile = id();
        let script = format!(
            "INSERT INTO accounts (id, name) VALUES ('{acct}', 'acct{i}');\
             INSERT INTO permission_profiles (id, account_id, name, kind) VALUES \
               ('{admin_profile}', '{acct}', 'Administrator', 'admin'), \
               ('{sender_profile}', '{acct}', 'Sender', 'sender');\
             INSERT INTO users (id, email, email_normalized, name, login_kind) VALUES \
               ('{user}', 'u{i}@example.test', 'u{i}@example.test', 'U{i}', 'local');\
             INSERT INTO account_memberships (account_id, user_id, permission_profile_id, disabled_at) \
               VALUES ('{acct}', '{user}', '{}', {});",
            if i == 1 {
                sender_profile
            } else {
                admin_profile
            },
            if i == 2 { "now()" } else { "NULL" },
        );
        db.admin
            .execute(sqlx::raw_sql(sqlx::AssertSqlSafe(script)))
            .await
            .unwrap();
    }
    let report = Store::from_pool(db.admin.clone()).migrate().await.unwrap();
    assert_eq!(report.applied, vec![14]);
    for (i, acct) in accounts.iter().enumerate() {
        let (org, oname, ostatus): (uuid::Uuid, String, String) = sqlx::query_as(
            "SELECT a.organization_id, o.name, o.status FROM accounts a \
             JOIN organizations o ON o.id = a.organization_id WHERE a.id = $1",
        )
        .bind(acct)
        .fetch_one(&db.admin)
        .await
        .unwrap();
        assert_eq!(
            (org, oname.as_str(), ostatus.as_str()),
            (*acct, format!("acct{i}").as_str(), "active")
        );
        let owners: Vec<uuid::Uuid> = sqlx::query_scalar(
            "SELECT user_id FROM organization_admins WHERE organization_id = $1 AND role = 'owner'",
        )
        .bind(acct)
        .fetch_all(&db.admin)
        .await
        .unwrap();
        let want: Vec<uuid::Uuid> = if i == 0 { vec![users[0]] } else { vec![] };
        assert_eq!(owners, want, "account {i}");
    }
    db.drop().await;
}

/// The seeded worlds of the isolation suites are workspaces of distinct organizations.
#[tokio::test]
async fn seeded_accounts_are_workspaces_of_their_own_organizations() {
    let Some(db) = fresh("seeded_accounts_are_workspaces", Rls::On).await else {
        return;
    };
    let a: World = world::seed(&db, "alpha").await;
    let mut tx = db.store.for_account(a.account).begin().await.unwrap();
    let acct = tx.account().get().await.unwrap();
    assert_eq!(acct.organization_id, a.organization);
    // The workspace reads its own organization's row, and only it.
    let mut conn = db.app.begin().await.unwrap();
    sqlx::query("SELECT set_config('openseal.account_id', $1, true)")
        .bind(a.account.0.to_string())
        .execute(&mut *conn)
        .await
        .unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM organizations")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert_eq!(n, 1);
    conn.rollback().await.unwrap();
    tx.rollback().await.unwrap();
    db.drop().await;
}
