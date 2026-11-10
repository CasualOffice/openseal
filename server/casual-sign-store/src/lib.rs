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
//! **Evidence (docs/32).** The audit table is append-only three ways: the application
//! role has only `SELECT` and `INSERT`; triggers refuse `UPDATE`, `DELETE` and
//! `TRUNCATE` for every role; and an insert trigger recomputes each event's SHA-256 from
//! its canonical bytes and refuses one that does not extend its envelope's chain.
//!
//! **Queries.** Runtime-checked `sqlx::query` with bound parameters only; never string
//! interpolation of a value. Compile-time `query!` would need a live database or a
//! committed offline cache at build time (docs/22 §As built).
//!
//! **Errors** are [`StoreError`] with `CS-DB-*` and `CS-BLOB-*` codes (docs/20); no
//! message carries a database error's text, which can quote personal data.

mod error;
mod ids;
mod migrate;
mod store;

pub mod blob;
pub mod repo;

pub use error::{Result, StoreError};
pub use ids::*;
pub use migrate::{MIGRATIONS, Migration, MigrationReport, migrate};
pub use store::{ClaimedJob, EntryPoints, RecipientTokenTarget, Store, Tenant, TenantTx};
