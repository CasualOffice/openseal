//! Decide and record in one transaction (docs/24 §1): load the engine state, call
//! [`casual_sign_workflow::decide`], then write the new state, append the events to the
//! chain, bring the relational rows the API reads into line, revoke tokens and enqueue
//! every other effect as a job, all in the caller's [`TenantTx`]. Nothing is visible
//! until it commits.
//!
//! The API server records requests through here; the worker feeds its results back
//! through here (`InvitationDispatched`, `TimerDue`, `SealSucceeded`, ...) with command
//! ids derived from the job (`job-<uuid>`), so a job that runs again after a crash
//! re-applies the same command id and the engine answers `replayed`: no event is
//! written twice.
//!
//! **Concurrency.** The state row is read `FOR UPDATE`: two writers of one envelope
//! take turns, and the state is written back at the revision read (`CS-DB-0007`
//! otherwise).

use casual_sign_audit::{Chain, EventData, Personal};
use casual_sign_model::{
    Delivery as MDelivery, EnvelopeStatus as MStatus, RecipientStatus as MRStatus,
    RecipientType as MRType, SealProfile as MSeal,
};
use casual_sign_store::repo::documents::Document;
use casual_sign_store::repo::envelopes::{
    EnvelopeStatus, NewEnvelope, Projection, RoutingMode, SealProfile,
};
use casual_sign_store::repo::recipients::{Delivery, NewRecipient, RecipientStatus, RecipientType};
use casual_sign_store::{
    AccountId, DocumentId, EnvelopeId, Meter, RecipientId, Store, StoreError, TenantTx, UserId,
};
use casual_sign_workflow::{Command, Context, EffectKind, EnvelopeState, decide};

use crate::error::{HostError, Result};
use crate::ids::{odt, uuid_of};
use crate::jobs;
use time::OffsetDateTime;

/// An envelope's engine state, read with its row locked until the transaction ends.
#[derive(Clone)]
pub struct Loaded {
    /// The envelope.
    pub id: EnvelopeId,
    /// The engine's state.
    pub state: EnvelopeState,
    /// The state row's revision, which the next write names.
    pub revision: i64,
}

impl core::fmt::Debug for Loaded {
    /// Ids only: the state holds personal data (`SEC-D01`).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Loaded")
            .field("id", &self.id)
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

/// What a command did.
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

/// The engine state of an envelope of this account, its row locked until the
/// transaction ends; `None` when the account has none.
///
/// # Errors
///
/// `CS-WRK-0002` for a state that does not read back; the store's codes.
pub async fn load_for_update(tx: &mut TenantTx, envelope: EnvelopeId) -> Result<Option<Loaded>> {
    let Some(s) = tx.workflow_states().get_for_update(envelope).await? else {
        return Ok(None);
    };
    let state =
        serde_json::from_value::<EnvelopeState>(s.state).map_err(|_| HostError::StateUnreadable)?;
    Ok(Some(Loaded {
        id: envelope,
        state,
        revision: s.revision,
    }))
}

/// Decide `command` for `envelope` and record the decision in `tx`: state, events,
/// relational rows, token revocations and jobs. The caller commits (with whatever else
/// belongs in the same transaction, such as finishing the job whose result this is).
///
/// # Errors
///
/// The engine's refusal (`CS-WF-*`, ...), `CS-WRK-0001` to `0003`, or the store's codes.
/// On error nothing should be committed: drop the transaction.
pub async fn apply_in(
    tx: &mut TenantTx,
    envelope: EnvelopeId,
    command: &Command,
    ctx: &Context,
) -> Result<Applied> {
    let mut loaded = load_for_update(tx, envelope).await?;
    apply_loaded(tx, envelope, loaded.as_mut(), command, ctx).await
}

/// [`apply_in`] on a state this transaction already loaded with [`load_for_update`]
/// (`None` for an envelope not yet created). On success `loaded`, if given, holds the
/// new state and revision.
///
/// # Errors
///
/// As [`apply_in`].
pub async fn apply_loaded(
    tx: &mut TenantTx,
    envelope: EnvelopeId,
    loaded: Option<&mut Loaded>,
    command: &Command,
    ctx: &Context,
) -> Result<Applied> {
    let prev = loaded.as_ref().map(|l| &l.state);
    let decision = decide(prev, command, ctx)?;
    if decision.replayed {
        return Ok(Applied {
            replayed: true,
            events: 0,
            jobs: 0,
            state: decision.state,
        });
    }
    let state = decision.state;
    let now = odt(ctx.now)?;
    if prev.is_none() {
        insert_envelope_row(tx, envelope, &state).await?;
    }

    // Events, chained on what is stored (the store re-verifies the chain as it reads).
    let mut chain: Chain = tx.audit().chain(envelope).await?;
    let events = decision.events.len();
    for pending in decision.events {
        let event = pending.into_audit(&chain);
        tx.audit().append(envelope, &event).await?;
        // `envelope.sent` is metered in the deciding transaction, once per envelope
        // (docs/23 §7.2): a correction or resend that sends again is not counted twice.
        if matches!(event.data, EventData::EnvelopeSent { .. }) {
            tx.record_usage(Meter::EnvelopesSent, 1, now, "envelope", envelope.0)
                .await?;
        }
        chain
            .append(event)
            .map_err(|e| HostError::Chain { code: e.code() })?;
    }

    // The state, at the revision read.
    let value = serde_json::to_value(&state).map_err(|_| HostError::StateUnreadable)?;
    let revision = match &loaded {
        Some(l) => {
            tx.workflow_states()
                .update(envelope, l.revision, &value, now)
                .await?
        }
        None => {
            tx.workflow_states().insert(envelope, &value, now).await?;
            1
        }
    };

    // An access (a download, the sender viewing) is recorded but changes nothing: the
    // envelope's last change stays (WEB-08).
    let changed = (!matches!(command, Command::RecordAccess { .. })).then_some(now);
    project(tx, envelope, &state, changed).await?;

    // Effects: tokens revoked here, the rest as jobs keyed by (envelope, effect id): a
    // decision recorded again names the same jobs and the queue keeps one of each.
    let mut enqueued: usize = 0;
    for effect in decision.effects {
        if let EffectKind::RevokeTokens { recipient } = &effect.kind {
            tx.recipients()
                .revoke_tokens(RecipientId(uuid_of(recipient, "recipient")?), now)
                .await?;
            continue;
        }
        if let Some(job) = jobs::job_for(envelope, &effect, &state, ctx.now)?
            && tx.jobs().enqueue(&job).await?
        {
            enqueued = enqueued.saturating_add(1);
        }
    }
    // An envelope that ends without completing gets its envelope certificate (UXW-30),
    // made and sealed by the worker as a completed one's is; keyed by the envelope, so
    // it is queued once whatever records the end.
    let ended = |s: MStatus| matches!(s, MStatus::Declined | MStatus::Voided | MStatus::Expired);
    if ended(state.status)
        && !prev.is_some_and(|p| ended(p.status))
        && tx
            .jobs()
            .enqueue(&jobs::ended_certificate_job(
                casual_sign_store::JobId(uuid::Uuid::new_v4()),
                envelope,
                now,
            ))
            .await?
    {
        enqueued = enqueued.saturating_add(1);
    }
    if let Some(l) = loaded {
        l.state = state.clone();
        l.revision = revision;
    }
    // Everything is written in the caller's transaction; nothing is committed yet.
    crate::crash::before_commit(command);
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
    store: &Store,
    account: AccountId,
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

fn json<T: serde::Serialize>(v: &T) -> serde_json::Value {
    match serde_json::to_value(v) {
        Ok(v @ serde_json::Value::Object(_)) => v,
        _ => serde_json::json!({}),
    }
}

fn text(s: &str) -> Personal<String> {
    Personal(s.to_owned())
}

/// The envelope columns the API lists and searches, as the state has them.
fn projection(s: &EnvelopeState, changed: Option<OffsetDateTime>) -> Result<Projection> {
    let ended = s.ended_at.map(odt).transpose()?;
    Ok(Projection {
        status: status(s.status),
        subject: text(s.subject.get().as_str()),
        message: text(s.message.get().as_str()),
        expires_at: s.expires_at.map(odt).transpose()?,
        reminder_policy: json(&s.reminders),
        signing_options: json(&s.options),
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
        void_reason: s.void_reason.as_ref().map(|r| text(r.get().as_str())),
        updated_at: changed,
        deleted_at: s.deleted_at.map(odt).transpose()?,
    })
}

async fn insert_envelope_row(
    tx: &mut TenantTx,
    envelope: EnvelopeId,
    state: &EnvelopeState,
) -> Result<()> {
    let row = NewEnvelope {
        id: envelope,
        sender_user_id: UserId(uuid_of(&state.sender_user_id, "user")?),
        subject: text(state.subject.get().as_str()),
        message: text(state.message.get().as_str()),
        routing_mode: RoutingMode::Mixed,
        expires_at: state.expires_at.map(odt).transpose()?,
        reminder_policy: json(&state.reminders),
        signing_options: json(&state.options),
        seal_profile: seal(state.seal_profile),
        completion_delivery: serde_json::json!({}),
        template_ids: Vec::new(),
    };
    tx.envelopes().insert(&row).await?;
    Ok(())
}

/// Bring the relational rows the API lists and searches into line with the engine's
/// state (docs/22 §10): the envelope's columns, each recipient's row (a draft's removed
/// recipients go), each document's row (written when missing). A document removed from
/// a draft keeps its row: its versions are write-once records of what was uploaded, and
/// the engine's state, not the table, says which documents the envelope has. Personal
/// data is copied from the state the engine checked.
async fn project(
    tx: &mut TenantTx,
    envelope: EnvelopeId,
    state: &EnvelopeState,
    changed: Option<OffsetDateTime>,
) -> Result<()> {
    let Some(row) = tx.envelopes().get(envelope).await? else {
        return Err(HostError::Store(StoreError::NotFound {
            entity: "envelope",
        }));
    };
    tx.envelopes()
        .project(envelope, row.version, &projection(state, changed)?)
        .await?;

    // Recipients. A purged state (a deleted draft) has no names left to project: its
    // rows go rather than being overwritten with blanks the table refuses (WEB-08;
    // rows something still references stay for the purge job).
    let mut keep = Vec::with_capacity(state.recipients.len());
    let live = if state.purged {
        &[][..]
    } else {
        &state.recipients[..]
    };
    for r in live {
        let id = RecipientId(uuid_of(r.id(), "recipient")?);
        keep.push(id);
        let email = r.spec.email.get().as_str();
        let n = NewRecipient {
            id,
            envelope_id: envelope,
            routing_order: i32::try_from(r.spec.routing_order.get()).unwrap_or(i32::MAX),
            kind: rtype(r.spec.rtype),
            role_name: None,
            name: text(r.spec.name.get().as_str()),
            email: (!email.is_empty()).then(|| text(email)),
            phone: r.spec.phone.as_ref().map(|p| text(p.get().as_str())),
            delivery: delivery(r.spec.delivery),
            embedded_client_user_id: r
                .spec
                .embedded_client_user_id
                .as_ref()
                .map(|e| e.as_str().to_owned()),
            language: None,
        };
        let reason = r.declined_reason.as_ref().map(|d| text(d.get().as_str()));
        tx.recipients()
            .upsert(&n, rstatus(r.status), reason.as_ref())
            .await?;
    }
    tx.recipients().prune(envelope, &keep).await?;

    // Documents: rows for documents the state has (the API server writes a document's
    // row and versions as it admits the upload, before the command names it).
    let docs = tx.documents().list(envelope).await?;
    let mut next_ord = docs
        .iter()
        .map(|d| d.ord)
        .max()
        .map_or(0, |m| m.saturating_add(1));
    for d in &state.documents {
        let did = DocumentId(uuid_of(d.id(), "document")?);
        if !docs.iter().any(|x| x.id == did) {
            tx.documents()
                .insert(&Document {
                    id: did,
                    envelope_id: envelope,
                    ord: next_ord,
                    name: d.spec.name.get().as_str().to_owned(),
                })
                .await?;
            next_ord = next_ord.saturating_add(1);
        }
    }
    Ok(())
}
