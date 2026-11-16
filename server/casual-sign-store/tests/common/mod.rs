//! Test harness: a fresh database per test on the PostgreSQL that
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

pub mod world;

use casual_sign_store::{AccountId, BuiltinProfiles, OrganizationId, PermissionProfileId, Store};
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
    let name = format!("openseal_t_{}", uuid::Uuid::new_v4().simple());
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

/// Fresh ids for a workspace's three built-in profiles.
pub fn builtin_profiles() -> BuiltinProfiles {
    BuiltinProfiles {
        admin: PermissionProfileId(uuid::Uuid::now_v7()),
        sender: PermissionProfileId(uuid::Uuid::now_v7()),
        viewer: PermissionProfileId(uuid::Uuid::now_v7()),
    }
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
    /// The URL of this database for another login, as a deployment's secret file holds it.
    pub fn url_as(&self, user: &str, password: &str) -> String {
        app_options(&self.server, &self.name)
            .username(user)
            .password(password)
            .to_url_lossy()
            .to_string()
    }

    /// This database's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// A new organization, made as the platform console will make one: by the owner
    /// role, since the application role cannot (docs/23 §5.3).
    pub async fn organization(&self, name: &str) -> OrganizationId {
        let id = OrganizationId(uuid::Uuid::now_v7());
        sqlx::query("INSERT INTO organizations (id, name) VALUES ($1, $2)")
            .bind(id.0)
            .bind(name)
            .execute(&self.admin)
            .await
            .unwrap();
        id
    }

    /// A new workspace, through the application's organization scope, of a new
    /// organization of its own.
    pub async fn account(&self, name: &str) -> (OrganizationId, AccountId) {
        let org = self.organization(name).await;
        let account = self.workspace(org, name).await;
        (org, account)
    }

    /// A new workspace of `org`, through the application's organization scope.
    pub async fn workspace(&self, org: OrganizationId, name: &str) -> AccountId {
        let account = AccountId(uuid::Uuid::now_v7());
        let mut tx = self.store.for_organization(org).begin().await.unwrap();
        tx.create_workspace(account, name, &builtin_profiles())
            .await
            .unwrap();
        tx.commit().await.unwrap();
        account
    }

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

/// Append a well-formed event to the admin log of the organization `org` from a raw
/// application-role transaction scoped to it, as a repository would (ORG-05): tests that
/// change organization tables with raw SQL need one, or the commit is refused
/// (`admin_change_has_event`).
pub async fn org_event(conn: &mut sqlx::PgConnection, org: OrganizationId) {
    let (seq, prev): (i64, Option<Vec<u8>>) =
        sqlx::query_as("SELECT next_seq, head FROM openseal_admin_chain_tip()")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
    let prev_json = prev.as_ref().map_or("null".to_owned(), |p| {
        format!(
            "\"{}\"",
            p.iter().map(|b| format!("{b:02x}")).collect::<String>()
        )
    });
    let canonical = format!(
        "{{\"action\":\"test.change\",\"at\":1,\"organization\":\"{}\",\"prev\":{prev_json},\"seq\":{seq}}}",
        org.0
    )
    .into_bytes();
    let hash = casual_sign_audit::Hash256::digest(&canonical)
        .as_bytes()
        .to_vec();
    sqlx::query(
        "INSERT INTO org_admin_events (organization_id, seq, prev_hash, hash, action, at, canonical) \
         VALUES ($1, $2, $3, $4, 'test.change', 'epoch'::timestamptz + interval '1 millisecond', $5)",
    )
    .bind(org.0)
    .bind(seq)
    .bind(prev)
    .bind(hash)
    .bind(canonical)
    .execute(&mut *conn)
    .await
    .unwrap();
}
