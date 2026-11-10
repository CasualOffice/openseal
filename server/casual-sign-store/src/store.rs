//! The store, its tenancy-scoped transactions, and the few entry points that find an
//! account from a secret (docs/22 §9, ADR-013).
//!
//! **The only way to reach a tenant table is [`Store::for_account`] →
//! [`Tenant::begin`] → a [`TenantTx`]**, whose repositories bind the transaction's account
//! into every statement and never take an account id from their caller. The transaction
//! also sets `openseal.account_id` for its own duration, so PostgreSQL's row-level
//! security policies apply the same filter a second time: a repository bug is caught by
//! RLS, and an RLS gap by the repository (both are tested separately).

use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Postgres, Row, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{Result, StoreError, db};
use crate::ids::{AccountId, ApiClientId, EnvelopeId, JobId, RecipientId, SigningLinkId, UserId};
use crate::migrate::{MigrationReport, migrate};

/// A PostgreSQL-backed store. Cheap to clone (a pool handle).
#[derive(Debug, Clone)]
pub struct Store {
    pool: PgPool,
}

impl Store {
    /// Connect with at most `max_connections` pooled connections. The URL's role should
    /// be the application role (`openseal_app` or a member of it), never the owner.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001` when the URL is malformed or the database is unreachable.
    pub async fn connect(url: &str, max_connections: u32) -> Result<Self> {
        let options: PgConnectOptions = url.parse().map_err(|_| StoreError::Unavailable)?;
        let pool = PgPoolOptions::new()
            .max_connections(max_connections.max(1))
            .acquire_timeout(Duration::from_secs(10))
            .connect_with(options)
            .await
            .map_err(db)?;
        Ok(Self { pool })
    }

    /// A store over an existing pool.
    #[must_use]
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Apply missing migrations (see [`migrate`]). Call with an owner-role store.
    ///
    /// # Errors
    ///
    /// As [`migrate`].
    pub async fn migrate(&self) -> Result<MigrationReport> {
        migrate(&self.pool).await
    }

    /// The tenancy scope for `account`: the only door to tenant tables.
    #[must_use]
    pub fn for_account(&self, account: AccountId) -> Tenant<'_> {
        Tenant {
            store: self,
            account,
        }
    }

    /// Create an account. The insert runs with `openseal.account_id` set to the new id,
    /// so the row-level security policy (`id = current account`) admits it.
    ///
    /// # Errors
    ///
    /// `CS-DB-0006` when the id exists; `CS-DB-0008` for an empty or overlong name.
    pub async fn create_account(&self, id: AccountId, name: &str) -> Result<()> {
        let mut tx = self.for_account(id).begin().await?;
        sqlx::query("INSERT INTO accounts (id, name) VALUES ($1, $2)")
            .bind(id.0)
            .bind(name)
            .execute(tx.conn())
            .await
            .map_err(db)?;
        tx.commit().await
    }

    /// The cross-account entry points: secret → ids, and the job queue's claim.
    #[must_use]
    pub fn entry_points(&self) -> EntryPoints<'_> {
        EntryPoints { store: self }
    }
}

/// The scope of one account. Obtain with [`Store::for_account`].
#[derive(Debug, Clone, Copy)]
pub struct Tenant<'s> {
    store: &'s Store,
    account: AccountId,
}

impl Tenant<'_> {
    /// The account.
    #[must_use]
    pub fn account_id(&self) -> AccountId {
        self.account
    }

    /// Begin a transaction scoped to this account. Every repository is reached through
    /// it, and nothing is written until [`TenantTx::commit`] (docs/24 §1: state, events
    /// and jobs are written in one transaction).
    ///
    /// # Errors
    ///
    /// `CS-DB-0001` when no connection is available.
    pub async fn begin(&self) -> Result<TenantTx> {
        let mut tx = self.store.pool.begin().await.map_err(db)?;
        sqlx::query("SELECT set_config('openseal.account_id', $1, true)")
            .bind(self.account.0.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        Ok(TenantTx {
            tx,
            account: self.account,
        })
    }
}

/// A database transaction bound to one account. Dropping it without
/// [`TenantTx::commit`] rolls back.
#[derive(Debug)]
pub struct TenantTx {
    tx: Transaction<'static, Postgres>,
    account: AccountId,
}

impl TenantTx {
    /// The account every statement in this transaction is bound to.
    #[must_use]
    pub fn account_id(&self) -> AccountId {
        self.account
    }

    /// The account's UUID, for binding.
    pub(crate) fn acct(&self) -> Uuid {
        self.account.0
    }

    /// The connection, for repositories in this crate only.
    pub(crate) fn conn(&mut self) -> &mut sqlx::PgConnection {
        &mut self.tx
    }

    /// Commit.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001` or the error a deferred constraint raised.
    pub async fn commit(self) -> Result<()> {
        self.tx.commit().await.map_err(db)
    }

    /// Roll back explicitly (dropping does the same).
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn rollback(self) -> Result<()> {
        self.tx.rollback().await.map_err(db)
    }
}

/// Where a recipient token leads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecipientTokenTarget {
    /// The account.
    pub account_id: AccountId,
    /// The envelope.
    pub envelope_id: EnvelopeId,
    /// The recipient.
    pub recipient_id: RecipientId,
}

/// A job handed to a worker. Finish it with `TenantTx::jobs().complete` or `fail` in its
/// own account, using the same lease token.
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimedJob {
    /// The job.
    pub id: JobId,
    /// Its account: open `Store::for_account(account_id)` to work on it.
    pub account_id: AccountId,
    /// Its envelope, when it has one.
    pub envelope_id: Option<EnvelopeId>,
    /// Its kind.
    pub kind: String,
    /// Its payload (ids and parameters; may reference personal data by id only).
    pub payload: serde_json::Value,
    /// Attempts so far, this one included.
    pub attempts: i32,
}

/// The cross-account entry points. Each takes a secret's SHA-256 (never the secret) or a
/// supplied lease token and returns ids; each is a `SECURITY DEFINER` function in
/// migration 0007 that the application role may only execute.
#[derive(Debug, Clone, Copy)]
pub struct EntryPoints<'s> {
    store: &'s Store,
}

impl EntryPoints<'_> {
    /// The recipient an unexpired, unrevoked invitation token names (SEC-A01).
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn resolve_recipient_token(
        &self,
        token_sha256: &[u8; 32],
        now: OffsetDateTime,
    ) -> Result<Option<RecipientTokenTarget>> {
        let row = sqlx::query("SELECT * FROM openseal_resolve_recipient_token($1, $2)")
            .bind(token_sha256.as_slice())
            .bind(now)
            .fetch_optional(&self.store.pool)
            .await
            .map_err(db)?;
        row.map(|r| {
            Ok(RecipientTokenTarget {
                account_id: AccountId(r.try_get("account_id").map_err(db)?),
                envelope_id: EnvelopeId(r.try_get("envelope_id").map_err(db)?),
                recipient_id: RecipientId(r.try_get("recipient_id").map_err(db)?),
            })
        })
        .transpose()
    }

    /// The API client an unexpired, unrevoked key's hash names (SEC-A10).
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn resolve_api_key(
        &self,
        secret_sha256: &[u8; 32],
        now: OffsetDateTime,
    ) -> Result<Option<(AccountId, ApiClientId)>> {
        let row = sqlx::query("SELECT * FROM openseal_resolve_api_key($1, $2)")
            .bind(secret_sha256.as_slice())
            .bind(now)
            .fetch_optional(&self.store.pool)
            .await
            .map_err(db)?;
        row.map(|r| {
            Ok((
                AccountId(r.try_get("account_id").map_err(db)?),
                ApiClientId(r.try_get("api_client_id").map_err(db)?),
            ))
        })
        .transpose()
    }

    /// The signing link an active link token's hash names (docs/24 §9).
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn resolve_signing_link(
        &self,
        token_sha256: &[u8; 32],
        now: OffsetDateTime,
    ) -> Result<Option<(AccountId, SigningLinkId)>> {
        let row = sqlx::query("SELECT * FROM openseal_resolve_signing_link($1, $2)")
            .bind(token_sha256.as_slice())
            .bind(now)
            .fetch_optional(&self.store.pool)
            .await
            .map_err(db)?;
        row.map(|r| {
            Ok((
                AccountId(r.try_get("account_id").map_err(db)?),
                SigningLinkId(r.try_get("signing_link_id").map_err(db)?),
            ))
        })
        .transpose()
    }

    /// The enabled user a normalized email, or an identity provider's issuer and subject,
    /// names, with each account they belong to (login, docs/22 §8).
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn resolve_user_login(
        &self,
        email_normalized: Option<&str>,
        idp: Option<(&str, &str)>,
    ) -> Result<Vec<(UserId, AccountId)>> {
        let rows = sqlx::query("SELECT * FROM openseal_resolve_user_login($1, $2, $3)")
            .bind(email_normalized)
            .bind(idp.map(|(i, _)| i))
            .bind(idp.map(|(_, s)| s))
            .fetch_all(&self.store.pool)
            .await
            .map_err(db)?;
        rows.into_iter()
            .map(|r| {
                Ok((
                    UserId(r.try_get("user_id").map_err(db)?),
                    AccountId(r.try_get("account_id").map_err(db)?),
                ))
            })
            .collect()
    }

    /// Claim up to `max` due jobs of `kinds` under a lease of `lease` from `now`. A job
    /// whose lease lapsed (its worker died) is claimed again. `lease_token` is supplied
    /// randomness; finishing a job requires it.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn claim_jobs(
        &self,
        worker: &str,
        kinds: &[&str],
        max: u32,
        now: OffsetDateTime,
        lease: Duration,
        lease_token: Uuid,
    ) -> Result<Vec<ClaimedJob>> {
        let rows = sqlx::query("SELECT * FROM openseal_claim_jobs($1, $2, $3, $4, $5, $6)")
            .bind(worker)
            .bind(kinds)
            .bind(i32::try_from(max).unwrap_or(i32::MAX))
            .bind(now)
            .bind(i32::try_from(lease.as_secs()).unwrap_or(i32::MAX))
            .bind(lease_token)
            .fetch_all(&self.store.pool)
            .await
            .map_err(db)?;
        rows.into_iter()
            .map(|r| {
                Ok(ClaimedJob {
                    id: JobId(r.try_get("id").map_err(db)?),
                    account_id: AccountId(r.try_get("account_id").map_err(db)?),
                    envelope_id: r
                        .try_get::<Option<Uuid>, _>("envelope_id")
                        .map_err(db)?
                        .map(EnvelopeId),
                    kind: r.try_get("kind").map_err(db)?,
                    payload: r.try_get("payload").map_err(db)?,
                    attempts: r.try_get("attempts").map_err(db)?,
                })
            })
            .collect()
    }
}
