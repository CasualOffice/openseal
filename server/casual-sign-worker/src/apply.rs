//! Decide and record in one transaction (docs/24 §1): load the engine state, call
//! [`casual_sign_workflow::decide`], then write the new state, append the events to the
//! chain, bring the relational rows the API reads into line, and enqueue every effect as
//! a job, all in the caller's [`TenantTx`]. Nothing is visible until it commits.
//!
//! The worker feeds its results back through here (`InvitationDispatched`, `TimerDue`,
//! `SealSucceeded`, ...) with command ids derived from the job (`job-<uuid>`), so a job
//! that runs again after a crash re-applies the same command id and the engine answers
//! `replayed`: no event is written twice.

use casual_sign_audit::{Chain, Timestamp};
use casual_sign_model::{EnvelopeStatus as ModelStatus, Id};
use casual_sign_store::repo::documents::Document;
use casual_sign_store::repo::envelopes::{
    EnvelopeStatus, NewEnvelope, RoutingMode, SealProfile as StoreProfile, Transition,
};
use casual_sign_store::repo::recipients::{
    Delivery as StoreDelivery, NewRecipient, RecipientStatus as StoreRecipientStatus,
    RecipientType as StoreRecipientType,
};
use casual_sign_store::{DocumentId, EnvelopeId, JobId, RecipientId, TenantTx, UserId};
use casual_sign_workflow::{
    Command, Context, Effect, EffectKind, EnvelopeState, Policy, Principal, decide,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{Result, WorkerError};
use crate::jobs;

/// What [`apply`] did.
#[derive(Debug, Clone)]
pub struct Applied {
    /// The command id was applied before: nothing was written.
    pub replayed: bool,
    /// Audit events appended.
    pub events: usize,
    /// Jobs enqueued (an effect already enqueued is not counted).
    pub jobs: usize,
    /// The envelope's state after the command.
    pub state: EnvelopeState,
}

/// The UUID an engine id names. Engine ids of envelopes, recipients, documents and
/// users are the database's UUIDs in their canonical hyphenated form.
///
/// # Errors
///
/// `CS-WRK-0003` for anything else.
pub fn uuid_of(id: &Id, what: &'static str) -> Result<Uuid> {
    let u = Uuid::parse_str(id.as_str()).map_err(|_| WorkerError::NotUuid { what })?;
    if u.hyphenated().to_string() == id.as_str() {
        Ok(u)
    } else {
        Err(WorkerError::NotUuid { what })
    }
}

/// The engine id of a database UUID.
///
/// # Errors
///
/// `CS-WRK-0003` (never, for a UUID: its hyphenated form is a valid id).
pub fn id_of(u: Uuid, what: &'static str) -> Result<Id> {
    Id::new(u.hyphenated().to_string()).map_err(|_| WorkerError::NotUuid { what })
}

/// The command id a job feeds its result under: the same on every run of the job.
///
/// # Errors
///
/// `CS-WRK-0003` (never, for a UUID).
pub fn job_command_id(job: JobId) -> Result<Id> {
    Id::new(format!("job-{}", job.0.simple())).map_err(|_| WorkerError::NotUuid { what: "job" })
}

/// A database time as the engine's.
///
/// # Errors
///
/// `CS-WRK-0001` for a time outside the engine's range (never from a sane clock).
pub fn ts(t: OffsetDateTime) -> Result<Timestamp> {
    let ms = t.unix_timestamp_nanos() / 1_000_000;
    i64::try_from(ms)
        .ok()
        .and_then(Timestamp::from_unix_millis)
        .ok_or(WorkerError::Config { setting: "clock" })
}

/// The engine's time as the database's.
///
/// # Errors
///
/// `CS-WRK-0001` (never, for a timestamp the engine accepted).
pub fn odt(t: Timestamp) -> Result<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(t.unix_millis()).saturating_mul(1_000_000))
        .map_err(|_| WorkerError::Config { setting: "clock" })
}

/// A context for a command the platform issues (a job's result, a timer).
#[must_use]
pub fn system_context(command_id: Id, now: Timestamp, policy: Policy) -> Context {
    Context {
        command_id,
        now,
        principal: Principal::System,
        request: casual_sign_audit::Context::default(),
        expected_version: None,
        policy,
    }
}

/// The payload of a job made from an effect: everything a job needs to find its work,
/// ids only (the effect itself carries ids and parameters, never personal data).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectJob {
    /// The envelope.
    pub envelope_id: Uuid,
    /// The effect.
    pub effect: Effect,
    /// When the decision that produced it was taken (milliseconds since the epoch): the
    /// event time webhooks report.
    pub decided_at: i64,
    /// The envelope's version after that decision (webhooks carry it so receivers can
    /// drop stale events, docs/40 §4).
    pub version: u64,
    /// The envelope's status after that decision.
    pub status: ModelStatus,
}

fn wire<T: Serialize>(v: &T) -> String {
    match serde_json::to_value(v) {
        Ok(serde_json::Value::String(s)) => s,
        _ => String::new(),
    }
}

fn store_status(s: ModelStatus) -> Option<EnvelopeStatus> {
    Some(match wire(&s).as_str() {
        "draft" => EnvelopeStatus::Draft,
        "sent" => EnvelopeStatus::Sent,
        "delivered" => EnvelopeStatus::Delivered,
        "completing" => EnvelopeStatus::Completing,
        "completed" => EnvelopeStatus::Completed,
        "declined" => EnvelopeStatus::Declined,
        "voided" => EnvelopeStatus::Voided,
        "expired" => EnvelopeStatus::Expired,
        _ => return None,
    })
}

fn store_recipient_status<T: Serialize>(s: &T) -> Option<StoreRecipientStatus> {
    Some(match wire(s).as_str() {
        "created" => StoreRecipientStatus::Created,
        "sent" => StoreRecipientStatus::Sent,
        "delivered" => StoreRecipientStatus::Delivered,
        "authenticated" => StoreRecipientStatus::Authenticated,
        "completed" => StoreRecipientStatus::Completed,
        "declined" => StoreRecipientStatus::Declined,
        "auto_responded" => StoreRecipientStatus::AutoResponded,
        "reassigned" => StoreRecipientStatus::Reassigned,
        _ => return None,
    })
}

fn store_recipient_type<T: Serialize>(t: &T) -> Option<StoreRecipientType> {
    Some(match wire(t).as_str() {
        "signer" => StoreRecipientType::Signer,
        "in_person_signer" => StoreRecipientType::InPersonSigner,
        "approver" => StoreRecipientType::Approver,
        "viewer" => StoreRecipientType::Viewer,
        "cc" => StoreRecipientType::Cc,
        "editor" => StoreRecipientType::Editor,
        "intermediary" => StoreRecipientType::Intermediary,
        "agent" => StoreRecipientType::Agent,
        "witness" => StoreRecipientType::Witness,
        "seal" => StoreRecipientType::Seal,
        "notary" => StoreRecipientType::Notary,
        _ => return None,
    })
}

fn store_delivery<T: Serialize>(d: &T) -> StoreDelivery {
    match wire(d).as_str() {
        "sms" => StoreDelivery::Sms,
        "none" => StoreDelivery::None,
        _ => StoreDelivery::Email,
    }
}

fn store_profile<T: Serialize>(p: &T) -> StoreProfile {
    match wire(p).as_str() {
        "pades-b-lt" => StoreProfile::PadesBLt,
        "pades-b-lta" => StoreProfile::PadesBLta,
        _ => StoreProfile::PadesBT,
    }
}

fn json<T: Serialize>(v: &T) -> serde_json::Value {
    match serde_json::to_value(v) {
        Ok(v @ serde_json::Value::Object(_)) => v,
        _ => serde_json::json!({}),
    }
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

/// Decide `command` for `envelope` and record the decision in `tx`: state, events,
/// relational rows and jobs. The caller commits (with whatever else belongs in the same
/// transaction, such as finishing the job whose result this is).
///
/// # Errors
///
/// The engine's refusal (`CS-WF-*`, ...), `CS-WRK-0002`/`-0003`, or the store's codes.
/// On error nothing should be committed: drop the transaction.
pub async fn apply_in(
    tx: &mut TenantTx,
    envelope: EnvelopeId,
    command: &Command,
    ctx: &Context,
) -> Result<Applied> {
    let stored = tx.workflow_states().get_for_update(envelope).await?;
    let (prev, revision) = match stored {
        Some(s) => (
            Some(
                serde_json::from_value::<EnvelopeState>(s.state)
                    .map_err(|_| WorkerError::StateUnreadable)?,
            ),
            Some(s.revision),
        ),
        None => (None, None),
    };
    let decision = decide(prev.as_ref(), command, ctx)?;
    if decision.replayed {
        return Ok(Applied {
            replayed: true,
            events: 0,
            jobs: 0,
            state: decision.state,
        });
    }
    let state = decision.state;
    if prev.is_none() {
        insert_envelope_row(tx, envelope, &state).await?;
    }

    // Events, chained on what is stored (the store re-verifies the chain as it reads).
    let mut chain: Chain = tx.audit().chain(envelope).await?;
    let events = decision.events.len();
    for pending in decision.events {
        let event = pending.into_audit(&chain);
        tx.audit().append(envelope, &event).await?;
        chain
            .append(event)
            .map_err(|e| WorkerError::Pipeline { code: e.code() })?;
    }

    // The state, at the revision read.
    let now = odt(ctx.now)?;
    let value = serde_json::to_value(&state).map_err(|_| WorkerError::StateUnreadable)?;
    match revision {
        Some(r) => {
            tx.workflow_states()
                .update(envelope, r, &value, now)
                .await?;
        }
        None => tx.workflow_states().insert(envelope, &value, now).await?,
    }

    project(tx, envelope, prev.as_ref(), &state, now).await?;

    // Effects as jobs, keyed by (envelope, effect id): a decision re-run names the
    // same jobs and the queue keeps one of each.
    let mut enqueued: usize = 0;
    for effect in decision.effects {
        if let Some(job) = jobs::job_for(envelope, &effect, &state, ctx.now)?
            && tx.jobs().enqueue(&job).await?
        {
            enqueued = enqueued.saturating_add(1);
        }
    }
    Ok(Applied {
        replayed: false,
        events,
        jobs: enqueued,
        state,
    })
}

/// [`apply_in`] in a transaction of its own, committed.
///
/// # Errors
///
/// As [`apply_in`].
pub async fn apply(
    store: &casual_sign_store::Store,
    account: casual_sign_store::AccountId,
    envelope: EnvelopeId,
    command: &Command,
    ctx: &Context,
) -> Result<Applied> {
    let mut tx = store.for_account(account).begin().await?;
    let applied = apply_in(&mut tx, envelope, command, ctx).await?;
    if !applied.replayed {
        tx.commit().await?;
    }
    Ok(applied)
}

async fn insert_envelope_row(
    tx: &mut TenantTx,
    envelope: EnvelopeId,
    state: &EnvelopeState,
) -> Result<()> {
    let row = NewEnvelope {
        id: envelope,
        sender_user_id: UserId(uuid_of(&state.sender_user_id, "user")?),
        subject: casual_sign_audit::Personal(state.subject.get().as_str().to_owned()),
        message: casual_sign_audit::Personal(state.message.get().as_str().to_owned()),
        routing_mode: RoutingMode::Mixed,
        expires_at: state.expires_at.map(odt).transpose()?,
        reminder_policy: json(&state.reminders),
        signing_options: json(&state.options),
        seal_profile: store_profile(&state.seal_profile),
        completion_delivery: serde_json::json!({}),
        template_ids: Vec::new(),
    };
    tx.envelopes().insert(&row).await?;
    Ok(())
}

/// Bring the relational rows the API lists and searches into line with the engine's
/// state: the envelope's status (and a draft's subject and message), each recipient's
/// row and status, each document's row. Recipient and document rows are written when
/// missing; their personal data is copied from the state the engine checked.
async fn project(
    tx: &mut TenantTx,
    envelope: EnvelopeId,
    prev: Option<&EnvelopeState>,
    state: &EnvelopeState,
    now: OffsetDateTime,
) -> Result<()> {
    let Some(row) = tx.envelopes().get(envelope).await? else {
        return Err(WorkerError::Store(
            casual_sign_store::StoreError::NotFound { entity: "envelope" },
        ));
    };
    let mut version = row.version;
    if row.status == EnvelopeStatus::Draft
        && state.status == ModelStatus::Draft
        && (row.subject.get() != state.subject.get().as_str()
            || row.message.get() != state.message.get().as_str())
    {
        version = tx
            .envelopes()
            .update_draft(
                envelope,
                version,
                &casual_sign_audit::Personal(state.subject.get().as_str().to_owned()),
                &casual_sign_audit::Personal(state.message.get().as_str().to_owned()),
            )
            .await?;
    }
    if let Some(status) = store_status(state.status)
        && status != row.status
    {
        tx.envelopes()
            .transition(
                envelope,
                version,
                &Transition {
                    status,
                    at: now,
                    void_reason: state
                        .void_reason
                        .as_ref()
                        .map(|r| casual_sign_audit::Personal(r.get().as_str().to_owned())),
                },
            )
            .await?;
    }

    // Recipients.
    let existing = tx.recipients().list(envelope).await?;
    for r in &state.recipients {
        let rid = RecipientId(uuid_of(r.id(), "recipient")?);
        let row = existing.iter().find(|x| x.recipient.id == rid);
        let status = store_recipient_status(&r.status);
        match row {
            None => {
                let email = r.spec.email.get().as_str();
                tx.recipients()
                    .insert(&NewRecipient {
                        id: rid,
                        envelope_id: envelope,
                        routing_order: i32::try_from(r.spec.routing_order.get()).unwrap_or(1),
                        kind: store_recipient_type(&r.spec.rtype)
                            .ok_or(WorkerError::StateUnreadable)?,
                        role_name: None,
                        name: casual_sign_audit::Personal(r.spec.name.get().as_str().to_owned()),
                        email: (!email.is_empty())
                            .then(|| casual_sign_audit::Personal(email.to_owned())),
                        phone: r
                            .spec
                            .phone
                            .as_ref()
                            .map(|p| casual_sign_audit::Personal(p.get().as_str().to_owned())),
                        delivery: store_delivery(&r.spec.delivery),
                        embedded_client_user_id: r
                            .spec
                            .embedded_client_user_id
                            .as_ref()
                            .map(|e| e.as_str().to_owned()),
                        language: None,
                    })
                    .await?;
                if let Some(s) = status
                    && s != StoreRecipientStatus::Created
                {
                    tx.recipients().set_status(rid, s, None).await?;
                }
            }
            Some(row) => {
                if let Some(s) = status
                    && s != row.status
                {
                    let reason = r
                        .declined_reason
                        .as_ref()
                        .map(|x| casual_sign_audit::Personal(x.get().as_str().to_owned()));
                    tx.recipients().set_status(rid, s, reason.as_ref()).await?;
                }
            }
        }
    }

    // Documents: rows for documents the state has; a draft's removed ones go.
    let docs = tx.documents().list(envelope).await?;
    for (ord, d) in state.documents.iter().enumerate() {
        let did = DocumentId(uuid_of(d.id(), "document")?);
        if !docs.iter().any(|x| x.id == did) {
            tx.documents()
                .insert(&Document {
                    id: did,
                    envelope_id: envelope,
                    ord: i32::try_from(ord).unwrap_or(i32::MAX),
                    name: d.spec.name.get().as_str().to_owned(),
                })
                .await?;
        }
    }
    if state.status == ModelStatus::Draft && prev.is_some() {
        for row in docs {
            let keep = state
                .documents
                .iter()
                .any(|d| uuid_of(d.id(), "document").ok() == Some(row.id.0));
            if !keep {
                tx.documents().delete_from_draft(row.id).await?;
            }
        }
    }
    Ok(())
}

/// Whether an effect is one the worker does nothing for at run time beyond the engine's
/// own guard. `Cancel` names timers and seal jobs; the engine answers a cancelled timer
/// with a no-op and refuses a cancelled seal job's result, and the seal job checks
/// before it seals, so `Cancel` itself enqueues nothing.
#[must_use]
pub fn is_cancel(effect: &Effect) -> bool {
    matches!(effect.kind, EffectKind::Cancel { .. })
}
