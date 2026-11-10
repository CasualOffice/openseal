//! The command pipeline (docs/24 §1, ADR-011): the server's face of
//! [`mod@casual_sign_host::apply`], the one decide-and-record path the worker uses too.
//! Load the envelope's state (locked), run `casual_sign_workflow::decide`, and in the
//! caller's one transaction write the new state and its projection, append the events
//! to the hash chain (`PendingEvent::into_audit`, ADR-010), revoke the tokens the
//! decision revokes and enqueue the other effects as jobs (the contract is
//! [`casual_sign_host::jobs`]). Nothing is acknowledged before the transaction commits.

use casual_sign_audit::{Context as RequestContext, Timestamp};
use casual_sign_model::Id;
use casual_sign_store::{AccountId, ApiClientId, EnvelopeId, TenantTx};
use casual_sign_workflow::{Command, Context, EnvelopeState, Policy, Principal as WfPrincipal};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::ApiError;

/// An envelope loaded for a command, locked until the transaction ends.
#[derive(Debug, Clone)]
pub(crate) struct Loaded {
    /// Its id.
    pub id: EnvelopeId,
    /// The engine's state and the state row's revision.
    pub inner: casual_sign_host::Loaded,
    /// The engine's state (a copy of `inner.state`, kept current by [`run`]).
    pub state: EnvelopeState,
    /// The API client that created it, if one did (WF-05).
    pub host_client: Option<ApiClientId>,
}

/// The engine id of a UUID.
pub(crate) fn eid(u: Uuid) -> Result<Id, ApiError> {
    Id::new(u.to_string()).map_err(|_| ApiError::internal("id"))
}

/// The UUID of an engine id the server minted.
pub(crate) fn uid(id: &Id) -> Result<Uuid, ApiError> {
    Uuid::parse_str(id.as_str()).map_err(|_| ApiError::internal("id"))
}

/// Milliseconds as the engine's timestamp.
pub(crate) fn ts(t: OffsetDateTime) -> Result<Timestamp, ApiError> {
    let ms = i64::try_from(t.unix_timestamp_nanos() / 1_000_000)
        .map_err(|_| ApiError::internal("time"))?;
    Timestamp::from_unix_millis(ms).ok_or_else(|| ApiError::internal("time"))
}

/// The envelope's state, or `None` when this account has no such envelope.
pub(crate) async fn load(tx: &mut TenantTx, id: EnvelopeId) -> Result<Option<Loaded>, ApiError> {
    let Some(inner) = casual_sign_host::load_for_update(tx, id).await? else {
        return Ok(None);
    };
    let host_client = tx.envelopes().host_client(id).await?;
    Ok(Some(Loaded {
        id,
        state: inner.state.clone(),
        inner,
        host_client,
    }))
}

/// The account's workflow policy: `settings.workflow_policy`, or the defaults.
pub(crate) async fn policy(tx: &mut TenantTx) -> Result<Policy, ApiError> {
    let acct = tx.account().get().await?;
    Ok(acct
        .settings
        .get("workflow_policy")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default())
}

/// Ids for a request's commands: `<seed>-<n>`.
#[derive(Debug)]
pub(crate) struct Commands {
    seed: String,
    next: u32,
    pub now: OffsetDateTime,
    pub request: RequestContext,
    pub policy: Policy,
}

impl Commands {
    pub(crate) fn new(
        seed: Option<String>,
        now: OffsetDateTime,
        request: RequestContext,
        policy: Policy,
    ) -> Self {
        Self {
            seed: seed.unwrap_or_else(|| Uuid::now_v7().simple().to_string()),
            next: 0,
            now,
            request,
            policy,
        }
    }

    /// The context of the next command.
    pub(crate) fn ctx(
        &mut self,
        principal: WfPrincipal,
        expected_version: Option<u64>,
    ) -> Result<Context, ApiError> {
        let id = format!("{}-{}", self.seed, self.next);
        self.next = self.next.saturating_add(1);
        Ok(Context {
            command_id: Id::new(id).map_err(|_| ApiError::internal("command id"))?,
            now: ts(self.now)?,
            principal,
            request: self.request.clone(),
            expected_version,
            policy: self.policy.clone(),
        })
    }
}

/// Create an envelope with `Command::Create`, recording the API client that created
/// it, if one did.
pub(crate) async fn create(
    tx: &mut TenantTx,
    account: AccountId,
    env: EnvelopeId,
    command: &Command,
    ctx: &Context,
    host_client: Option<ApiClientId>,
) -> Result<Loaded, ApiError> {
    let _ = account;
    let applied = casual_sign_host::apply_loaded(tx, env, None, command, ctx).await?;
    if let Some(client) = host_client {
        tx.envelopes().set_host_client(env, client).await?;
    }
    // Lock the new row for the rest of the request's commands.
    let inner = casual_sign_host::load_for_update(tx, env)
        .await?
        .ok_or_else(|| ApiError::internal("state"))?;
    debug_assert_eq!(inner.state.version, applied.state.version);
    Ok(Loaded {
        id: env,
        state: inner.state.clone(),
        inner,
        host_client,
    })
}

/// Run a command on a loaded envelope; returns whether it was a replay (nothing
/// written).
pub(crate) async fn run(
    tx: &mut TenantTx,
    loaded: &mut Loaded,
    command: &Command,
    ctx: &Context,
) -> Result<bool, ApiError> {
    let applied =
        casual_sign_host::apply_loaded(tx, loaded.id, Some(&mut loaded.inner), command, ctx)
            .await?;
    if !applied.replayed {
        loaded.state = loaded.inner.state.clone();
    }
    Ok(applied.replayed)
}
