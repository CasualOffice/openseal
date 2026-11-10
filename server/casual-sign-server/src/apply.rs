//! The command pipeline (docs/24 §1, ADR-011): load the envelope's state, run
//! `casual_sign_workflow::decide`, and in the caller's one transaction write the new
//! state and its projection, append the events to the hash chain
//! (`PendingEvent::into_audit`, ADR-010) and enqueue the effects as jobs. Nothing is
//! acknowledged before the transaction commits.
//!
//! **Jobs.** Each effect becomes one row of `jobs`: `kind` is the effect's kind
//! (`send_invitation`, `seal_envelope`, `schedule`, ...), `idempotency_key` is
//! `<envelope>:<command id>:<index>` (the effect id, so a replayed decision names the
//! same job), `payload` is `{"envelope_id": ..., "effect": <the Effect as JSON>}`, and
//! `run_at` is the effect's due time (`Schedule.at`, `SealEnvelope.not_before`) or now.
//! `RevokeTokens` is performed here, in the same transaction, rather than queued: a
//! voided or reassigned recipient's link must stop working when the answer is given.

use casual_sign_audit::{Context as RequestContext, Timestamp};
use casual_sign_model::{
    Delivery as MDelivery, EnvelopeStatus as MStatus, Id, RecipientStatus as MRStatus,
    RecipientType as MRType, SealProfile as MSeal,
};
use casual_sign_store::repo::envelopes::{
    EnvelopeStatus, NewEnvelope, Projection, RoutingMode, SealProfile,
};
use casual_sign_store::repo::jobs::NewJob;
use casual_sign_store::repo::recipients::{Delivery, NewRecipient, RecipientStatus, RecipientType};
use casual_sign_store::{AccountId, ApiClientId, EnvelopeId, JobId, RecipientId, TenantTx, UserId};
use casual_sign_workflow::{
    Command, Context, EffectKind, EnvelopeState, Policy, Principal as WfPrincipal, decide,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::ApiError;

/// An envelope loaded for a command, locked until the transaction ends.
#[derive(Debug, Clone)]
pub(crate) struct Loaded {
    /// Its id.
    pub id: EnvelopeId,
    /// The engine's state.
    pub state: EnvelopeState,
    /// The row version the next save must name.
    pub row_version: i32,
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

/// The engine's timestamp as a database time.
pub(crate) fn odt(t: Timestamp) -> Result<OffsetDateTime, ApiError> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(t.unix_millis()).saturating_mul(1_000_000))
        .map_err(|_| ApiError::internal("time"))
}

/// The envelope's state, or `None` when this account has no such envelope.
pub(crate) async fn load(tx: &mut TenantTx, id: EnvelopeId) -> Result<Option<Loaded>, ApiError> {
    let Some(s) = tx.envelopes().load_state(id).await? else {
        return Ok(None);
    };
    let state: EnvelopeState =
        serde_json::from_value(s.state).map_err(|_| ApiError::internal("state"))?;
    Ok(Some(Loaded {
        id,
        state,
        row_version: s.row_version,
        host_client: s.host_client_id,
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

fn status(s: MStatus) -> EnvelopeStatus {
    match s {
        MStatus::Draft => EnvelopeStatus::Draft,
        MStatus::Sent => EnvelopeStatus::Sent,
        MStatus::Delivered => EnvelopeStatus::Delivered,
        MStatus::Completing => EnvelopeStatus::Completing,
        MStatus::Completed => EnvelopeStatus::Completed,
        MStatus::Declined => EnvelopeStatus::Declined,
        MStatus::Voided => EnvelopeStatus::Voided,
        MStatus::Expired => EnvelopeStatus::Expired,
    }
}

fn seal(s: MSeal) -> SealProfile {
    match s {
        MSeal::PadesBT => SealProfile::PadesBT,
        MSeal::PadesBLt => SealProfile::PadesBLt,
        MSeal::PadesBLta => SealProfile::PadesBLta,
    }
}

fn rtype(t: MRType) -> RecipientType {
    match t {
        MRType::Signer => RecipientType::Signer,
        MRType::InPersonSigner => RecipientType::InPersonSigner,
        MRType::Approver => RecipientType::Approver,
        MRType::Viewer => RecipientType::Viewer,
        MRType::Cc => RecipientType::Cc,
        MRType::Editor => RecipientType::Editor,
        MRType::Intermediary => RecipientType::Intermediary,
        MRType::Agent => RecipientType::Agent,
        MRType::Witness => RecipientType::Witness,
        MRType::Seal => RecipientType::Seal,
        MRType::Notary => RecipientType::Notary,
    }
}

fn rstatus(s: MRStatus) -> RecipientStatus {
    match s {
        MRStatus::Created => RecipientStatus::Created,
        MRStatus::Sent => RecipientStatus::Sent,
        MRStatus::Delivered => RecipientStatus::Delivered,
        MRStatus::Authenticated => RecipientStatus::Authenticated,
        MRStatus::Completed => RecipientStatus::Completed,
        MRStatus::Declined => RecipientStatus::Declined,
        MRStatus::AutoResponded => RecipientStatus::AutoResponded,
        MRStatus::Reassigned => RecipientStatus::Reassigned,
    }
}

fn delivery(d: MDelivery) -> Delivery {
    match d {
        MDelivery::Email => Delivery::Email,
        MDelivery::Sms => Delivery::Sms,
        MDelivery::None => Delivery::None,
    }
}

fn projection(s: &EnvelopeState) -> Result<Projection, ApiError> {
    let ended = s.ended_at.map(odt).transpose()?;
    let j = |v: Result<serde_json::Value, _>| v.map_err(|_| ApiError::internal("projection"));
    Ok(Projection {
        status: status(s.status),
        subject: casual_sign_audit::Personal(s.subject.0.as_str().to_owned()),
        message: casual_sign_audit::Personal(s.message.0.as_str().to_owned()),
        expires_at: s.expires_at.map(odt).transpose()?,
        reminder_policy: j(serde_json::to_value(s.reminders))?,
        signing_options: j(serde_json::to_value(s.options))?,
        seal_profile: seal(s.seal_profile),
        sent_at: s.sent_at.map(odt).transpose()?,
        completed_at: if s.status == MStatus::Completed {
            ended
        } else {
            None
        },
        voided_at: if s.status == MStatus::Voided {
            ended
        } else {
            None
        },
        void_reason: s
            .void_reason
            .as_ref()
            .map(|r| casual_sign_audit::Personal(r.0.as_str().to_owned())),
    })
}

async fn project_recipients(
    tx: &mut TenantTx,
    env: EnvelopeId,
    s: &EnvelopeState,
) -> Result<(), ApiError> {
    let mut keep = Vec::with_capacity(s.recipients.len());
    for r in &s.recipients {
        let id = RecipientId(uid(r.id())?);
        keep.push(id);
        let email = r.spec.email.0.as_str();
        let n = NewRecipient {
            id,
            envelope_id: env,
            routing_order: i32::try_from(r.spec.routing_order.get()).unwrap_or(i32::MAX),
            kind: rtype(r.spec.rtype),
            role_name: None,
            name: casual_sign_audit::Personal(r.spec.name.0.as_str().to_owned()),
            email: (!email.is_empty()).then(|| casual_sign_audit::Personal(email.to_owned())),
            phone: r
                .spec
                .phone
                .as_ref()
                .map(|p| casual_sign_audit::Personal(p.0.as_str().to_owned())),
            delivery: delivery(r.spec.delivery),
            embedded_client_user_id: r
                .spec
                .embedded_client_user_id
                .as_ref()
                .map(|e| e.as_str().to_owned()),
            language: None,
        };
        let reason = r
            .declined_reason
            .as_ref()
            .map(|d| casual_sign_audit::Personal(d.0.as_str().to_owned()));
        tx.recipients()
            .upsert(&n, rstatus(r.status), reason.as_ref())
            .await?;
    }
    tx.recipients().prune(env, &keep).await?;
    Ok(())
}

/// Write a decided state, its events and its effects. `prev_row` is `None` for a new
/// envelope.
async fn persist(
    tx: &mut TenantTx,
    env: EnvelopeId,
    prev_row: Option<i32>,
    host_client: Option<ApiClientId>,
    d: casual_sign_workflow::Decision,
    now: OffsetDateTime,
) -> Result<(EnvelopeState, i32), ApiError> {
    let json = serde_json::to_value(&d.state).map_err(|_| ApiError::internal("state"))?;
    let row = match prev_row {
        None => {
            let s = &d.state;
            tx.envelopes()
                .insert_with_state(
                    &NewEnvelope {
                        id: env,
                        sender_user_id: UserId(uid(&s.sender_user_id)?),
                        subject: casual_sign_audit::Personal(s.subject.0.as_str().to_owned()),
                        message: casual_sign_audit::Personal(s.message.0.as_str().to_owned()),
                        routing_mode: RoutingMode::Mixed,
                        expires_at: None,
                        reminder_policy: serde_json::json!({}),
                        signing_options: serde_json::json!({}),
                        seal_profile: seal(s.seal_profile),
                        completion_delivery: serde_json::json!({}),
                        template_ids: Vec::new(),
                    },
                    host_client,
                    &json,
                )
                .await?;
            1
        }
        Some(v) => {
            tx.envelopes()
                .save_state(env, v, &projection(&d.state)?, &json)
                .await?
        }
    };
    project_recipients(tx, env, &d.state).await?;
    let mut chain = tx.audit().chain(env).await?;
    for pending in d.events {
        let event = pending.into_audit(&chain);
        tx.audit().append(env, &event).await?;
        chain
            .append(event)
            .map_err(|_| ApiError::internal("chain"))?;
    }
    for effect in d.effects {
        let effect_json =
            serde_json::to_value(&effect).map_err(|_| ApiError::internal("effect"))?;
        let kind = effect_json
            .get("kind")
            .and_then(|k| k.get("kind"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("effect")
            .to_owned();
        let run_at = match &effect.kind {
            EffectKind::Schedule { at, .. } => odt(*at)?,
            EffectKind::SealEnvelope {
                not_before: Some(at),
            } => odt(*at)?,
            EffectKind::RevokeTokens { recipient } => {
                tx.recipients()
                    .revoke_tokens(RecipientId(uid(recipient)?), now)
                    .await?;
                continue;
            }
            _ => now,
        };
        tx.jobs()
            .enqueue(&NewJob {
                id: JobId(Uuid::now_v7()),
                envelope_id: Some(env),
                kind,
                idempotency_key: format!("{env}:{}:{}", effect.id.command, effect.id.index),
                payload: serde_json::json!({ "envelope_id": env.to_string(), "effect": effect_json }),
                run_at,
                max_attempts: 15,
            })
            .await?;
    }
    Ok((d.state, row))
}

/// Create an envelope with `Command::Create`.
pub(crate) async fn create(
    tx: &mut TenantTx,
    account: AccountId,
    env: EnvelopeId,
    command: &Command,
    ctx: &Context,
    host_client: Option<ApiClientId>,
    now: OffsetDateTime,
) -> Result<Loaded, ApiError> {
    let _ = account;
    let d = decide(None, command, ctx)?;
    let (state, row_version) = persist(tx, env, None, host_client, d, now).await?;
    Ok(Loaded {
        id: env,
        state,
        row_version,
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
    now: OffsetDateTime,
) -> Result<bool, ApiError> {
    let d = decide(Some(&loaded.state), command, ctx)?;
    if d.replayed {
        return Ok(true);
    }
    let (state, row) = persist(
        tx,
        loaded.id,
        Some(loaded.row_version),
        loaded.host_client,
        d,
        now,
    )
    .await?;
    loaded.state = state;
    loaded.row_version = row;
    Ok(false)
}
