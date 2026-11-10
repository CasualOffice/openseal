//! The job queue, this account's side (ADR-012, docs/24 §1 effects, §7 timers).
//! Enqueueing is idempotent on `(account, idempotency_key)`; claiming across accounts is
//! `EntryPoints::claim_jobs`; finishing requires the claim's lease token.

use time::OffsetDateTime;
use uuid::Uuid;

use super::affected;
use crate::error::{Result, db};
use crate::ids::{EnvelopeId, JobId};
use crate::store::TenantTx;

/// A job to enqueue.
#[derive(Debug, Clone, PartialEq)]
pub struct NewJob {
    /// Host-minted id.
    pub id: JobId,
    /// Envelope, when the job concerns one.
    pub envelope_id: Option<EnvelopeId>,
    /// Kind (`[a-z][a-z0-9_]*`).
    pub kind: String,
    /// Idempotency key, for example `"{envelope}:{effect}"`.
    pub idempotency_key: String,
    /// Parameters (ids, never personal data in clear).
    pub payload: serde_json::Value,
    /// Due time.
    pub run_at: OffsetDateTime,
    /// Attempts before the job is dead.
    pub max_attempts: i32,
}

/// A job's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobState {
    /// `queued`, `running`, `done` or `dead`.
    pub status: String,
    /// Attempts so far.
    pub attempts: i32,
    /// Next due time.
    pub run_at: OffsetDateTime,
    /// Last failure's code.
    pub last_error_code: Option<String>,
}

/// The job queue for this account. Reached through `TenantTx::jobs`.
#[derive(Debug)]
pub struct Jobs<'t> {
    pub(crate) tx: &'t mut TenantTx,
}

impl Jobs<'_> {
    /// Enqueue, unless a job with the same idempotency key exists; returns whether this
    /// call inserted it.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` an envelope of another account or a malformed kind.
    pub async fn enqueue(&mut self, j: &NewJob) -> Result<bool> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "INSERT INTO jobs (id, account_id, envelope_id, kind, idempotency_key, payload, run_at, \
             max_attempts) VALUES ($2, $1, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (account_id, idempotency_key) DO NOTHING",
            acct,
            j.id.0,
            j.envelope_id.map(|e| e.0),
            j.kind,
            j.idempotency_key,
            &j.payload,
            j.run_at,
            j.max_attempts
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(done.rows_affected() == 1)
    }

    /// A job of this account.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn get(&mut self, id: JobId) -> Result<Option<JobState>> {
        let acct = self.tx.acct();
        let row = sqlx::query_as!(
            JobState,
            "SELECT status, attempts, run_at, last_error_code FROM jobs WHERE account_id = $1 AND id = $2",
            acct,
            id.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(row)
    }

    /// Mark a claimed job done.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when this account has no running job with that lease.
    pub async fn complete(
        &mut self,
        id: JobId,
        lease_token: Uuid,
        now: OffsetDateTime,
    ) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE jobs SET status = 'done', finished_at = $4, lease_token = NULL, locked_until = NULL \
             WHERE account_id = $1 AND id = $2 AND lease_token = $3 AND status = 'running'",
            acct,
            id.0,
            lease_token,
            now
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        affected(done.rows_affected(), "job")
    }

    /// Extend a claimed job's lease to `until` (a heartbeat), so a long job is not
    /// claimed again while its worker lives.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when this account has no running job with that lease (it lapsed and
    /// another worker took it, or it finished).
    pub async fn heartbeat(
        &mut self,
        id: JobId,
        lease_token: Uuid,
        until: OffsetDateTime,
    ) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE jobs SET locked_until = $4 \
             WHERE account_id = $1 AND id = $2 AND lease_token = $3 AND status = 'running'",
            acct,
            id.0,
            lease_token,
            until
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        affected(done.rows_affected(), "job")
    }

    /// Dead-letter a claimed job at once: its failure is one no retry can cure (a
    /// malformed payload, a refused address). It stays visible with its code.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when this account has no running job with that lease.
    pub async fn bury(
        &mut self,
        id: JobId,
        lease_token: Uuid,
        now: OffsetDateTime,
        error_code: &str,
    ) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE jobs SET status = 'dead', finished_at = $4, last_error_code = $5, \
               lease_token = NULL, locked_until = NULL \
             WHERE account_id = $1 AND id = $2 AND lease_token = $3 AND status = 'running'",
            acct,
            id.0,
            lease_token,
            now,
            error_code
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        affected(done.rows_affected(), "job")
    }

    /// Record a claimed job's failure: queued again for `retry_at`, or dead once its
    /// attempts are spent.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when this account has no running job with that lease.
    pub async fn fail(
        &mut self,
        id: JobId,
        lease_token: Uuid,
        retry_at: OffsetDateTime,
        error_code: &str,
    ) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE jobs SET status = CASE WHEN attempts >= max_attempts THEN 'dead' ELSE 'queued' END, \
               run_at = $4, last_error_code = $5, lease_token = NULL, locked_until = NULL \
             WHERE account_id = $1 AND id = $2 AND lease_token = $3 AND status = 'running'",
            acct,
            id.0,
            lease_token,
            retry_at,
            error_code
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        affected(done.rows_affected(), "job")
    }
}
