//! The workflow engine's envelope state and the worker's per-job step ledger (migration
//! 0008, stage 2D).
//!
//! The store keeps the engine's `EnvelopeState` as the JSON the engine serializes; it
//! does not interpret it (this crate does not depend on `casual-sign-workflow`). Every
//! write carries the revision it read: a writer that lost a race is told so
//! (`CS-DB-0007`) and decides again on the fresh state.
//!
//! A job step records something a job did outside the database, the moment it did it, so
//! a re-run after a crash skips it. Steps are insert-only.

use time::OffsetDateTime;

use crate::error::{Result, StoreError, db};
use crate::ids::{EnvelopeId, JobId};
use crate::store::TenantTx;

/// An envelope's stored engine state.
#[derive(Clone, PartialEq)]
pub struct StoredState {
    /// The engine's `EnvelopeState` as JSON (personal data: never log).
    pub state: serde_json::Value,
    /// The row's revision, to pass back to [`WorkflowStates::update`].
    pub revision: i64,
}

impl core::fmt::Debug for StoredState {
    /// The revision only: the state holds personal data (SEC-D01).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoredState")
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

/// The engine states of this account's envelopes. Reached through
/// `TenantTx::workflow_states`.
#[derive(Debug)]
pub struct WorkflowStates<'t> {
    pub(crate) tx: &'t mut TenantTx,
}

impl WorkflowStates<'_> {
    /// The state of an envelope of this account, locked for update until the
    /// transaction ends, so two writers of one envelope take turns.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn get_for_update(&mut self, envelope: EnvelopeId) -> Result<Option<StoredState>> {
        let acct = self.tx.acct();
        let row = sqlx::query!(
            "SELECT state, revision FROM envelope_states \
             WHERE account_id = $1 AND envelope_id = $2 FOR UPDATE",
            acct,
            envelope.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(row.map(|r| StoredState {
            state: r.state,
            revision: r.revision,
        }))
    }

    /// The state of an envelope of this account, without a lock.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn get(&mut self, envelope: EnvelopeId) -> Result<Option<StoredState>> {
        let acct = self.tx.acct();
        let row = sqlx::query!(
            "SELECT state, revision FROM envelope_states \
             WHERE account_id = $1 AND envelope_id = $2",
            acct,
            envelope.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(row.map(|r| StoredState {
            state: r.state,
            revision: r.revision,
        }))
    }

    /// Store the first state of an envelope of this account (its envelope row must
    /// exist); its revision is 1.
    ///
    /// # Errors
    ///
    /// `CS-DB-0006` when it already has one; `CS-DB-0008` an envelope of another account
    /// or a state that is not a JSON object.
    pub async fn insert(
        &mut self,
        envelope: EnvelopeId,
        state: &serde_json::Value,
        now: OffsetDateTime,
    ) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "INSERT INTO envelope_states (account_id, envelope_id, state, revision, updated_at) \
             VALUES ($1, $2, $3, 1, $4)",
            acct,
            envelope.0,
            state,
            now
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// Replace the state if it is still at `revision`; returns the new revision.
    ///
    /// # Errors
    ///
    /// `CS-DB-0007` a stale revision; `CS-DB-0003` no state for that envelope in this
    /// account.
    pub async fn update(
        &mut self,
        envelope: EnvelopeId,
        revision: i64,
        state: &serde_json::Value,
        now: OffsetDateTime,
    ) -> Result<i64> {
        let acct = self.tx.acct();
        let new = sqlx::query_scalar!(
            "UPDATE envelope_states SET state = $4, revision = revision + 1, updated_at = $5 \
             WHERE account_id = $1 AND envelope_id = $2 AND revision = $3 RETURNING revision",
            acct,
            envelope.0,
            revision,
            state,
            now
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        if let Some(r) = new {
            return Ok(r);
        }
        if self.get(envelope).await?.is_some() {
            Err(StoreError::StaleVersion {
                entity: "envelope state",
            })
        } else {
            Err(StoreError::NotFound {
                entity: "envelope state",
            })
        }
    }
}

/// A recorded job step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobStep {
    /// What was done (`[a-z][a-z0-9_.:-]{0,127}`).
    pub step: String,
    /// Ids, hashes and codes recorded with it.
    pub detail: serde_json::Value,
    /// When.
    pub at: OffsetDateTime,
}

/// The step ledger of this account's jobs. Reached through `TenantTx::job_steps`.
#[derive(Debug)]
pub struct JobSteps<'t> {
    pub(crate) tx: &'t mut TenantTx,
}

impl JobSteps<'_> {
    /// Record `step` of a job of this account, unless it is recorded already; returns
    /// whether this call recorded it. An existing step is never changed.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` a job of another account, a malformed step name or a detail that is
    /// not a JSON object.
    pub async fn record(
        &mut self,
        job: JobId,
        step: &str,
        detail: &serde_json::Value,
        at: OffsetDateTime,
    ) -> Result<bool> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "INSERT INTO job_steps (account_id, job_id, step, detail, at) VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (account_id, job_id, step) DO NOTHING",
            acct,
            job.0,
            step,
            detail,
            at
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(done.rows_affected() == 1)
    }

    /// The steps a job of this account has recorded, in the order recorded.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn list(&mut self, job: JobId) -> Result<Vec<JobStep>> {
        let acct = self.tx.acct();
        let rows = sqlx::query_as!(
            JobStep,
            "SELECT step, detail, at FROM job_steps WHERE account_id = $1 AND job_id = $2 \
             ORDER BY at, step",
            acct,
            job.0
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(rows)
    }
}
