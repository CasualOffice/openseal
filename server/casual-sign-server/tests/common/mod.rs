//! Test harness (the database part copied from casual-sign-store's tests/common at
//! T-2B, unchanged but for this note and the `server` module): a fresh database per test on the PostgreSQL that
//! `OPENSEAL_TEST_DATABASE_URL` names (a superuser URL, for example
//! `postgres://postgres:pw@127.0.0.1:55432/postgres`). Migrations run as that superuser
//! (the owner); the store under test connects as a LOGIN role that is a member of
//! `openseal_app`, so row-level security and the app role's grants apply exactly as in
//! production. Without the variable, every database test prints a note and passes
//! vacuously; CI sets it (docs/22 §As built).

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    dead_code
)]

pub mod harness;

use casual_sign_store::Store;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{ConnectOptions, Executor, PgPool, Row};

/// The variable naming the test server.
pub const ENV: &str = "OPENSEAL_TEST_DATABASE_URL";

const APP_LOGIN: &str = "openseal_app_test";
const APP_PASSWORD: &str = "openseal-app-test-only";

/// One test's database.
pub struct TestDb {
    /// Superuser (owner) pool on the test database.
    pub admin: PgPool,
    /// Application-role pool on the test database.
    pub app: PgPool,
    /// The store under test, as the application role.
    pub store: Store,
    name: String,
    server: PgConnectOptions,
}

/// Whether row-level security stays on for the test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rls {
    /// As migrated: the second line in place.
    On,
    /// Disabled on every table, so only the repository isolates.
    Off,
}

/// The server URL, or `None` with a note on stderr.
pub fn server_url(test: &str) -> Option<String> {
    match std::env::var(ENV) {
        Ok(u) if !u.is_empty() => Some(u),
        _ => {
            eprintln!("SKIPPED {test}: set {ENV} to a PostgreSQL superuser URL to run it");
            None
        }
    }
}

/// A fresh, migrated database, or `None` when no server is configured.
pub async fn fresh(test: &str, rls: Rls) -> Option<TestDb> {
    let url = server_url(test)?;
    let db = empty(&url).await;
    let report = Store::from_pool(db.admin.clone()).migrate().await.unwrap();
    assert_eq!(report.applied.len(), casual_sign_store::MIGRATIONS.len());
    // The login role is cluster-wide and concurrent tests race to create it; it inherits
    // the application role's grants and, owning nothing, is subject to row-level security.
    let create = format!(
        "DO $$ BEGIN CREATE ROLE {APP_LOGIN} LOGIN PASSWORD '{APP_PASSWORD}' IN ROLE openseal_app; \
         EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$"
    );
    db.admin
        .execute(sqlx::raw_sql(sqlx::AssertSqlSafe(create)))
        .await
        .unwrap();
    if rls == Rls::Off {
        disable_rls(&db.admin).await;
    }
    Some(db)
}

/// A fresh database with nothing applied.
pub async fn empty(url: &str) -> TestDb {
    let server: PgConnectOptions = url.parse().unwrap();
    let server = server.disable_statement_logging();
    let maint = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(server.clone())
        .await
        .unwrap();
    let name = format!("openseal_t_{}", uuid::Uuid::now_v7().simple());
    maint
        .execute(sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "CREATE DATABASE {name}"
        ))))
        .await
        .unwrap();
    maint.close().await;
    let admin = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(server.clone().database(&name))
        .await
        .unwrap();
    TestDb {
        app: PgPool::connect_lazy_with(app_options(&server, &name)),
        store: Store::from_pool(PgPool::connect_lazy_with(app_options(&server, &name))),
        admin,
        name,
        server,
    }
}

fn app_options(server: &PgConnectOptions, db: &str) -> PgConnectOptions {
    server
        .clone()
        .database(db)
        .username(APP_LOGIN)
        .password(APP_PASSWORD)
}

/// Turn row-level security off on every table that has it.
pub async fn disable_rls(admin: &PgPool) {
    let tables = rls_tables(admin).await;
    assert!(
        tables.len() > 30,
        "expected every tenant table, found {}",
        tables.len()
    );
    for t in tables {
        admin
            .execute(sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                "ALTER TABLE {t} DISABLE ROW LEVEL SECURITY"
            ))))
            .await
            .unwrap();
    }
}

/// Tables in `public` with row-level security enabled.
pub async fn rls_tables(admin: &PgPool) -> Vec<String> {
    sqlx::query(
        "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relrowsecurity ORDER BY 1",
    )
    .fetch_all(admin)
    .await
    .unwrap()
    .iter()
    .map(|r| r.get::<String, _>(0))
    .collect()
}

impl TestDb {
    /// Drop the database.
    pub async fn drop(self) {
        self.admin.close().await;
        self.app.close().await;
        let maint = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(self.server.clone())
            .await
            .unwrap();
        maint
            .execute(sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                self.name
            ))))
            .await
            .unwrap();
        maint.close().await;
    }
}
