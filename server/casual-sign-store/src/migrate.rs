//! Forward-only, numbered migrations (CLAUDE.md §SQL; files in `migrations/`).
//!
//! Each migration runs in its own transaction and is recorded with the SHA-256 of its
//! text. Running again applies only what is missing; an applied migration whose text
//! changed is refused (`CS-DB-0002`), as is a database carrying a migration this build
//! does not know (`CS-DB-0011`). A session advisory lock serializes concurrent migrators.
//!
//! This runner, rather than sqlx's `migrate` feature, records each file's SHA-256 and
//! refuses an edited or unknown migration (docs/22 §As built).

use casual_sign_audit::Hash256;
use sqlx::{Connection, PgPool};

use crate::error::{Result, StoreError, db};

/// One migration: its number, file name and SQL.
#[derive(Debug, Clone, Copy)]
pub struct Migration {
    /// The number, dense from 1.
    pub version: i64,
    /// The file name.
    pub name: &'static str,
    /// The SQL text.
    pub sql: &'static str,
}

macro_rules! migration {
    ($v:literal, $file:literal) => {
        Migration {
            version: $v,
            name: $file,
            sql: include_str!(concat!("../../../migrations/", $file)),
        }
    };
}

/// Every migration, in order.
pub const MIGRATIONS: &[Migration] = &[
    migration!(1, "0001_roles_and_tenancy.sql"),
    migration!(2, "0002_accounts_and_identity.sql"),
    migration!(3, "0003_templates.sql"),
    migration!(4, "0004_envelopes.sql"),
    migration!(5, "0005_audit_events.sql"),
    migration!(6, "0006_links_and_webhooks.sql"),
    migration!(7, "0007_jobs_and_entry_points.sql"),
    migration!(8, "0008_workflow_state_and_job_steps.sql"),
    migration!(9, "0009_api_server.sql"),
    migration!(10, "0010_user_invitations.sql"),
    migration!(11, "0011_envelope_lists.sql"),
    migration!(12, "0012_email_otp.sql"),
    migration!(13, "0013_shared_user_guard.sql"),
    migration!(14, "0014_organizations.sql"),
    migration!(15, "0015_in_person_hosting.sql"),
    migration!(16, "0016_platform_schema.sql"),
    migration!(17, "0017_operators.sql"),
    migration!(18, "0018_console_organization_writes.sql"),
    migration!(19, "0019_console_approvals.sql"),
    migration!(20, "0020_admin_events.sql"),
    migration!(21, "0021_ml_analysis.sql"),
    migration!(22, "0022_folders_and_deleted.sql"),
    // 23 is reserved by a row merging separately.
    migration!(24, "0024_plans.sql"),
    migration!(25, "0025_metering.sql"),
    migration!(26, "0026_console_org_events.sql"),
];

/// The migration ledger. Also the first statement of migration 0001.
const LEDGER: &str = "CREATE TABLE IF NOT EXISTS openseal_schema_migrations (
    version     bigint PRIMARY KEY,
    name        text NOT NULL,
    sha256      bytea NOT NULL,
    applied_at  timestamptz NOT NULL DEFAULT now())";

/// `pg_advisory_lock` key: "OSEALMIG" read as an integer.
const LOCK_KEY: i64 = 0x4F53_4541_4C4D_4947;

/// What a run did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MigrationReport {
    /// Versions applied by this run, in order.
    pub applied: Vec<i64>,
    /// Versions found already applied (and unchanged).
    pub already: Vec<i64>,
}

/// Apply every missing migration. Needs a role that may create tables and roles (the
/// schema owner), not the application role.
///
/// # Errors
///
/// `CS-DB-0002` a migration failed or an applied one was edited; `CS-DB-0011` the
/// database is ahead of this build; `CS-DB-0001` the database is unreachable.
pub async fn migrate(pool: &PgPool) -> Result<MigrationReport> {
    let mut conn = pool.acquire().await.map_err(db)?;
    sqlx::query!("SELECT pg_advisory_lock($1)", LOCK_KEY)
        .execute(&mut *conn)
        .await
        .map_err(db)?;
    let outcome = run(&mut conn).await;
    let unlocked = sqlx::query!("SELECT pg_advisory_unlock($1)", LOCK_KEY)
        .fetch_one(&mut *conn)
        .await
        .map_err(db);
    let report = outcome?;
    unlocked?;
    Ok(report)
}

async fn run(conn: &mut sqlx::PgConnection) -> Result<MigrationReport> {
    // DDL is not a checkable query; the same statement opens migration 0001, so the
    // ledger exists in every migrated database (and in the one the offline cache is
    // prepared against).
    sqlx::raw_sql(LEDGER)
        .execute(&mut *conn)
        .await
        .map_err(db)?;
    let applied: Vec<(i64, Vec<u8>)> =
        sqlx::query!("SELECT version, sha256 FROM openseal_schema_migrations ORDER BY version")
            .fetch_all(&mut *conn)
            .await
            .map_err(db)?
            .into_iter()
            .map(|r| (r.version, r.sha256))
            .collect();
    let mut report = MigrationReport::default();
    for (version, sha) in &applied {
        let Some(m) = MIGRATIONS.iter().find(|m| m.version == *version) else {
            return Err(StoreError::SchemaAhead { version: *version });
        };
        if Hash256::digest(m.sql.as_bytes()).as_bytes().as_slice() != sha.as_slice() {
            return Err(StoreError::Migration { version: *version });
        }
        report.already.push(*version);
    }
    for m in MIGRATIONS {
        if report.already.contains(&m.version) {
            continue;
        }
        let failed = |_| StoreError::Migration { version: m.version };
        let mut tx = conn.begin().await.map_err(db)?;
        sqlx::raw_sql(m.sql)
            .execute(&mut *tx)
            .await
            .map_err(failed)?;
        let sha = Hash256::digest(m.sql.as_bytes());
        sqlx::query!(
            "INSERT INTO openseal_schema_migrations (version, name, sha256) VALUES ($1, $2, $3)",
            m.version,
            m.name,
            sha.as_bytes().as_slice(),
        )
        .execute(&mut *tx)
        .await
        .map_err(failed)?;
        tx.commit().await.map_err(failed)?;
        report.applied.push(m.version);
    }
    Ok(report)
}
