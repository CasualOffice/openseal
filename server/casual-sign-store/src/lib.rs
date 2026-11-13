//! OpenSeal persistence (stage 2B, docs/22): the PostgreSQL schema as numbered,
//! forward-only migrations (`migrations/`), the tenancy-scoped repository, the
//! append-only audit table, and a content-addressed, write-once blob store.
//!
//! **Tenancy (ADR-013).** Every tenant table carries `account_id`. The only door to them
//! is [`Store::for_account`] → [`Tenant::begin`] → [`TenantTx`], whose repositories bind
//! the transaction's account into every statement; no repository takes an account id
//! from its caller, and none has an unscoped variant. The same transaction sets
//! `openseal.account_id`, which the row-level security policy of every tenant table
//! checks: the second line. Composite foreign keys `(account_id, parent_id)` make a row
//! referencing another account's row impossible in the database itself. The only
//! cross-account reads are the [`EntryPoints`] (secret hash → ids, and the job claim).
//!
//! **Organizations (ADR-028).** Every account is a workspace of one organization.
//! [`Store::for_organization`] → [`OrgScope::begin`] → [`OrgTx`] reaches organization
//! tables and, read-only, its workspaces' rows; it sees no content table. It writes to a
//! workspace only through [`Store::for_workspace_of`] with a [`WorkspaceOf`] proof.
//!
//! **Evidence (docs/32).** The audit table is append-only three ways: the application
//! role has only `SELECT` and `INSERT`; triggers refuse `UPDATE`, `DELETE` and
//! `TRUNCATE` for every role; and an insert trigger recomputes each event's SHA-256 from
//! its canonical bytes and refuses one that does not extend its envelope's chain.
//!
//! **Admin logs (ORG-05).** Every settings, member, profile, workspace and organization
//! change appends a hash-chained admin event in its own transaction (`admin_events` per
//! workspace, `org_admin_events` per organization); the repositories append them, and the
//! database refuses to commit such a change without one.
//!
//! **Queries.** Compile-time checked `sqlx::query!` / `query_as!` with bound parameters
//! only (ADR-014). The offline cache in `.sqlx/` lets `SQLX_OFFLINE=true` builds check
//! every statement without a database; `sqlx-prepare.sh --check` proves the cache still
//! matches the migrations. Only the migration files themselves run as unchecked DDL.
//!
//! **Errors** are [`StoreError`] with `CS-DB-*` and `CS-BLOB-*` codes (docs/20); no
//! message carries a database error's text, which can quote personal data.

mod admin_log;
mod error;
mod ids;
mod migrate;
mod org;
mod store;

pub mod blob;
pub mod repo;

pub use admin_log::{
    ADMIN_EVENT_CONSTRAINT, ADMIN_EVENT_VERSION, ActorKind, AdminActor,
    MAX_PAGE as ADMIN_EVENTS_MAX_PAGE, StoredAdminEvent, verify_admin_chain,
};
pub use error::{Result, StoreError};
pub use ids::*;
pub use migrate::{MIGRATIONS, Migration, MigrationReport, migrate};
pub use org::{
    BuiltinProfiles, LAST_OWNER_CONSTRAINT, OrgScope, OrgTx, Organization, OrganizationStatus,
    Workspace, WorkspaceOf, WorkspaceStatus,
};
pub use store::{
    ClaimedJob, EntryPoints, RecipientTokenTarget, StaffSessionTarget, Store, Tenant, TenantTx,
    UserWorkspace,
};
