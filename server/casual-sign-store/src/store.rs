//! The store, its tenancy-scoped transactions, and the few entry points that find an
//! account from a secret (docs/22 §9, ADR-013).
//!
//! **The only way to reach a tenant table is [`Store::for_account`] →
//! [`Tenant::begin`] → a [`TenantTx`]**, whose repositories bind the transaction's account
//! into every statement and never take an account id from their caller. The transaction
//! also sets `openseal.account_id` for its own duration, so PostgreSQL's row-level
//! security policies apply the same filter a second time: a repository bug is caught by
//! RLS, and an RLS gap by the repository (both are tested separately).
//!
//! Accounts are workspaces of an organization (ADR-028). The application cannot insert
//! one: [`Store::bootstrap_organization`] makes the first, and an organization
//! transaction (`crate::org`) the rest, each through a `SECURITY DEFINER` function.

use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{Result, StoreError, db};
use crate::ids::{
    AccountId, ApiClientId, EnvelopeId, JobId, RecipientId, SigningLinkId, StaffSessionId, UserId,
};
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

    /// The pool, for the organization scope in this crate.
    pub(crate) fn pool(&self) -> &PgPool {
        &self.pool
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
        sqlx::query!(
            "SELECT set_config('openseal.account_id', $1, true)",
            self.account.0.to_string()
        )
        .fetch_one(&mut *tx)
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
    /// Bind an open transaction, whose `openseal.account_id` is already `account`, as
    /// that account's transaction ([`crate::OrgTx::into_workspace`]).
    pub(crate) fn bound(tx: Transaction<'static, Postgres>, account: AccountId) -> Self {
        Self { tx, account }
    }

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

/// A workspace a signed-in person can switch to (docs/23 §2.3): metadata only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserWorkspace {
    /// The workspace.
    pub account_id: AccountId,
    /// Its name.
    pub account_name: String,
    /// `active` or `archived`.
    pub account_status: crate::org::WorkspaceStatus,
    /// Its organization.
    pub organization_id: crate::ids::OrganizationId,
    /// Its organization's name.
    pub organization_name: String,
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

/// A live staff session a cookie names (migration 0008).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaffSessionTarget {
    /// The account it is for.
    pub account_id: AccountId,
    /// The session.
    pub session_id: StaffSessionId,
    /// The member.
    pub user_id: UserId,
    /// SHA-256 of its CSRF token.
    pub csrf_sha256: [u8; 32],
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
        let row = sqlx::query!(
            r#"SELECT account_id AS "account_id!", envelope_id AS "envelope_id!",
                      recipient_id AS "recipient_id!"
                 FROM openseal_resolve_recipient_token($1, $2)"#,
            token_sha256.as_slice(),
            now
        )
        .fetch_optional(&self.store.pool)
        .await
        .map_err(db)?;
        Ok(row.map(|r| RecipientTokenTarget {
            account_id: AccountId(r.account_id),
            envelope_id: EnvelopeId(r.envelope_id),
            recipient_id: RecipientId(r.recipient_id),
        }))
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
        let row = sqlx::query!(
            r#"SELECT account_id AS "account_id!", api_client_id AS "api_client_id!"
                 FROM openseal_resolve_api_key($1, $2)"#,
            secret_sha256.as_slice(),
            now
        )
        .fetch_optional(&self.store.pool)
        .await
        .map_err(db)?;
        Ok(row.map(|r| (AccountId(r.account_id), ApiClientId(r.api_client_id))))
    }

    /// The live session a staff cookie's hash names, while its user is enabled and
    /// still a member (docs/40 §2).
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0010` for an unreadable row.
    pub async fn resolve_staff_session(
        &self,
        token_sha256: &[u8; 32],
        now: OffsetDateTime,
    ) -> Result<Option<StaffSessionTarget>> {
        let row = sqlx::query!(
            r#"SELECT account_id AS "account_id!", session_id AS "session_id!",
                      user_id AS "user_id!", csrf_sha256 AS "csrf_sha256!"
                 FROM openseal_resolve_staff_session($1, $2)"#,
            token_sha256.as_slice(),
            now
        )
        .fetch_optional(&self.store.pool)
        .await
        .map_err(db)?;
        row.map(|r| {
            Ok(StaffSessionTarget {
                account_id: AccountId(r.account_id),
                session_id: StaffSessionId(r.session_id),
                user_id: UserId(r.user_id),
                csrf_sha256: crate::repo::hash32(r.csrf_sha256, "csrf_sha256")?,
            })
        })
        .transpose()
    }

    /// The open user invitation a link token's hash names (WEB-06): sent, unexpired,
    /// not accepted or revoked, its member enabled. Answers the account, the invitation
    /// and the user.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn resolve_user_invitation(
        &self,
        token_sha256: &[u8; 32],
        now: OffsetDateTime,
    ) -> Result<Option<(AccountId, crate::ids::UserInvitationId, UserId)>> {
        let row = sqlx::query!(
            r#"SELECT account_id AS "account_id!", invitation_id AS "invitation_id!",
                      user_id AS "user_id!"
                 FROM openseal_resolve_user_invitation($1, $2)"#,
            token_sha256.as_slice(),
            now
        )
        .fetch_optional(&self.store.pool)
        .await
        .map_err(db)?;
        Ok(row.map(|r| {
            (
                AccountId(r.account_id),
                crate::ids::UserInvitationId(r.invitation_id),
                UserId(r.user_id),
            )
        }))
    }

    /// Every workspace the user of a live staff session belongs to, enabled there, with
    /// its organization (switching, docs/23 §2.3). The user comes from the session's
    /// hash, never from an id the caller names. Empty for a session that is not live.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0010` for an unreadable row.
    pub async fn user_workspaces(
        &self,
        session_token_sha256: &[u8; 32],
        now: OffsetDateTime,
    ) -> Result<Vec<UserWorkspace>> {
        let rows = sqlx::query!(
            r#"SELECT account_id AS "account_id!", account_name AS "account_name!",
                      account_status AS "account_status!", organization_id AS "organization_id!",
                      organization_name AS "organization_name!"
                 FROM openseal_user_workspaces($1, $2)"#,
            session_token_sha256.as_slice(),
            now
        )
        .fetch_all(&self.store.pool)
        .await
        .map_err(db)?;
        rows.into_iter()
            .map(|r| {
                Ok(UserWorkspace {
                    account_id: AccountId(r.account_id),
                    account_name: r.account_name,
                    account_status: crate::org::WorkspaceStatus::parse(
                        &r.account_status,
                        "account_status",
                    )?,
                    organization_id: crate::ids::OrganizationId(r.organization_id),
                    organization_name: r.organization_name,
                })
            })
            .collect()
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
        let row = sqlx::query!(
            r#"SELECT account_id AS "account_id!", signing_link_id AS "signing_link_id!"
                 FROM openseal_resolve_signing_link($1, $2)"#,
            token_sha256.as_slice(),
            now
        )
        .fetch_optional(&self.store.pool)
        .await
        .map_err(db)?;
        Ok(row.map(|r| (AccountId(r.account_id), SigningLinkId(r.signing_link_id))))
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
        let rows = sqlx::query!(
            r#"SELECT user_id AS "user_id!", account_id AS "account_id!"
                 FROM openseal_resolve_user_login($1, $2, $3)"#,
            email_normalized,
            idp.map(|(i, _)| i),
            idp.map(|(_, s)| s)
        )
        .fetch_all(&self.store.pool)
        .await
        .map_err(db)?;
        Ok(rows
            .into_iter()
            .map(|r| (UserId(r.user_id), AccountId(r.account_id)))
            .collect())
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
        let kinds: Vec<String> = kinds.iter().map(|k| (*k).to_owned()).collect();
        let rows = sqlx::query!(
            r#"SELECT id AS "id!", account_id AS "account_id!", envelope_id, kind AS "kind!",
                      payload AS "payload!", attempts AS "attempts!"
                 FROM openseal_claim_jobs($1, $2, $3, $4, $5, $6)"#,
            worker,
            &kinds,
            i32::try_from(max).unwrap_or(i32::MAX),
            now,
            i32::try_from(lease.as_secs()).unwrap_or(i32::MAX),
            lease_token
        )
        .fetch_all(&self.store.pool)
        .await
        .map_err(db)?;
        Ok(rows
            .into_iter()
            .map(|r| ClaimedJob {
                id: JobId(r.id),
                account_id: AccountId(r.account_id),
                envelope_id: r.envelope_id.map(EnvelopeId),
                kind: r.kind,
                payload: r.payload,
                attempts: r.attempts,
            })
            .collect())
    }
}
