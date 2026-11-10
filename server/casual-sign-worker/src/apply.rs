//! Decide and record in one transaction: the worker's face of
//! [`mod@casual_sign_host::apply`], the one path the API server uses too (docs/24 §1).
//!
//! The worker feeds its results back through here (`InvitationDispatched`, `TimerDue`,
//! `SealSucceeded`, ...) with command ids derived from the job (`job-<uuid>`), so a job
//! that runs again after a crash re-applies the same command id and the engine answers
//! `replayed`: no event is written twice.

use casual_sign_audit::Timestamp;
use casual_sign_model::Id;
use casual_sign_store::{AccountId, EnvelopeId, JobId, Store, TenantTx};
use casual_sign_workflow::{Command, Context, Effect, EffectKind, EnvelopeState};
use time::OffsetDateTime;
use uuid::Uuid;

pub use casual_sign_host::Applied;
pub use casual_sign_host::ids::system_context;
pub use casual_sign_host::jobs::EffectJob;

use crate::error::{Result, WorkerError};

/// The UUID an engine id names ([`casual_sign_host::ids::uuid_of`]).
///
/// # Errors
///
/// `CS-WRK-0003`.
pub fn uuid_of(id: &Id, what: &'static str) -> Result<Uuid> {
    Ok(casual_sign_host::ids::uuid_of(id, what)?)
}

/// The engine id of a database UUID.
///
/// # Errors
///
/// `CS-WRK-0003` (never, for a UUID).
pub fn id_of(u: Uuid, what: &'static str) -> Result<Id> {
    Ok(casual_sign_host::ids::id_of(u, what)?)
}

/// The command id a job feeds its result under: the same on every run of the job.
///
/// # Errors
///
/// `CS-WRK-0003` (never, for a UUID).
pub fn job_command_id(job: JobId) -> Result<Id> {
    Ok(casual_sign_host::ids::job_command_id(job)?)
}

/// A database time as the engine's.
///
/// # Errors
///
/// `CS-WRK-0001` for a time outside the engine's range.
pub fn ts(t: OffsetDateTime) -> Result<Timestamp> {
    Ok(casual_sign_host::ids::ts(t)?)
}

/// The engine's time as the database's.
///
/// # Errors
///
/// `CS-WRK-0001` (never, for a timestamp the engine accepted).
pub fn odt(t: Timestamp) -> Result<OffsetDateTime> {
    Ok(casual_sign_host::ids::odt(t)?)
}

/// Load an envelope's engine state, without a lock.
///
/// # Errors
///
/// `CS-WRK-0002` for a state that does not read back; the store's codes.
pub async fn load_state(tx: &mut TenantTx, envelope: EnvelopeId) -> Result<Option<EnvelopeState>> {
    match tx.workflow_states().get(envelope).await? {
        Some(s) => serde_json::from_value(s.state)
            .map(Some)
            .map_err(|_| WorkerError::StateUnreadable),
        None => Ok(None),
    }
}

/// [`casual_sign_host::apply_in`]: decide `command` and record the decision in `tx`.
///
/// # Errors
///
/// The engine's refusal (`CS-WF-*`, ...), `CS-WRK-0001` to `0003`, or the store's codes.
pub async fn apply_in(
    tx: &mut TenantTx,
    envelope: EnvelopeId,
    command: &Command,
    ctx: &Context,
) -> Result<Applied> {
    Ok(casual_sign_host::apply_in(tx, envelope, command, ctx).await?)
}

/// [`apply_in`] in a transaction of its own, committed.
///
/// # Errors
///
/// As [`apply_in`].
pub async fn apply(
    store: &Store,
    account: AccountId,
    envelope: EnvelopeId,
    command: &Command,
    ctx: &Context,
) -> Result<Applied> {
    Ok(casual_sign_host::apply(store, account, envelope, command, ctx).await?)
}

/// Whether an effect is one the worker does nothing for at run time beyond the engine's
/// own guard. `Cancel` names timers and seal jobs; the engine answers a cancelled timer
/// with a no-op and refuses a cancelled seal job's result, and the seal job checks
/// before it seals, so `Cancel` itself enqueues nothing.
#[must_use]
pub fn is_cancel(effect: &Effect) -> bool {
    matches!(effect.kind, EffectKind::Cancel { .. })
}
