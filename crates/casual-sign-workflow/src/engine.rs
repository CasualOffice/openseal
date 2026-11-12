//! `decide`: the command function (docs/24 §1, ADR-011).

use std::collections::BTreeSet;

use casual_sign_audit::{
    Actor, ActorKind, AuthMethod, Channel, DocumentHash, EventData, FallbackReason, Hash256,
    LocationSource, MarkKind, Personal, Timestamp,
};
use casual_sign_fields::{Issue, Values, evaluate_envelope, validate};
use casual_sign_model::{
    Delivery, EnvelopeStatus, FieldType, FieldValue, Id, RecipientStatus, RecipientType, Text,
};

use crate::changes::{Scope, apply_changes};
use crate::command::{
    Access, Command, Context, Decision, FieldEntry, PendingEvent, Principal, ReassignTo,
    SealedDocument, limits,
};
use crate::date::format_date;
use crate::effect::{
    Alert, Effect, EffectId, EffectKind, InvitationKind, Notice, Timer, WebhookTopic,
};
use crate::error::{ObjectKind, SealFault, WorkflowError};
use crate::state::{
    Bookkeeping, ConsentRecord, EnvelopeState, Fields, RecipientState, ScheduledTimer,
};
use crate::validate::violations;

const MS_PER_DAY: i64 = 86_400_000;

/// What one decision accumulates.
pub(crate) struct Out<'c> {
    pub(crate) ctx: &'c Context,
    actor: Actor,
    pub(crate) events: Vec<PendingEvent>,
    pub(crate) effects: Vec<Effect>,
}

impl<'c> Out<'c> {
    fn new(ctx: &'c Context, actor: Actor) -> Self {
        Self {
            ctx,
            actor,
            events: Vec::new(),
            effects: Vec::new(),
        }
    }

    /// An event by the command's actor.
    pub(crate) fn event(&mut self, data: EventData) {
        self.events.push(PendingEvent {
            at: self.ctx.now,
            actor: self.actor.clone(),
            context: self.ctx.request.clone(),
            data,
        });
    }

    /// An event the platform records as a consequence (routing, completion).
    pub(crate) fn system_event(&mut self, data: EventData) {
        self.events.push(PendingEvent {
            at: self.ctx.now,
            actor: Actor::system(),
            context: casual_sign_audit::Context::default(),
            data,
        });
    }

    /// An effect; returns its id.
    pub(crate) fn effect(&mut self, kind: EffectKind) -> EffectId {
        let id = EffectId {
            command: self.ctx.command_id.clone(),
            index: u32::try_from(self.effects.len()).unwrap_or(u32::MAX),
        };
        self.effects.push(Effect {
            id: id.clone(),
            kind,
        });
        id
    }

    fn webhook(&mut self, topic: WebhookTopic, recipient: Option<&Id>) {
        self.effect(EffectKind::DeliverWebhook {
            topic,
            recipient: recipient.cloned(),
        });
    }
}

/// Decides `command` against `state` (`None` only for [`Command::Create`]).
///
/// Pure: no clock, no I/O, no randomness; the same inputs give the same decision. The
/// server writes [`Decision::state`], appends [`Decision::events`] and enqueues
/// [`Decision::effects`] in one transaction. A command id applied before with the same
/// command gives a [`Decision::replayed`] decision with no events or effects.
///
/// # Errors
///
/// A [`WorkflowError`] with a stable `CS-WF-*`, `CS-AUTH-*` or `CS-FLD-*` code; nothing
/// is to be written.
pub fn decide(
    state: Option<&EnvelopeState>,
    command: &Command,
    ctx: &Context,
) -> Result<Decision, WorkflowError> {
    let fingerprint = fingerprint(command)?;
    let Some(state) = state else {
        return create(command, ctx, fingerprint);
    };
    if let Some(seen) = state.book.applied.get(&ctx.command_id) {
        return if *seen == fingerprint {
            Ok(Decision {
                state: state.clone(),
                events: Vec::new(),
                effects: Vec::new(),
                replayed: true,
            })
        } else {
            Err(WorkflowError::CommandIdReused)
        };
    }
    if state.book.applied.len() >= limits::MAX_COMMANDS {
        return Err(WorkflowError::CommandLogFull {
            limit: limits::MAX_COMMANDS,
        });
    }
    if state.purged {
        return Err(not_allowed(command, state));
    }
    if let Some(expected) = ctx.expected_version
        && expected != state.version
    {
        return Err(WorkflowError::StaleVersion {
            expected,
            actual: state.version,
        });
    }

    let mut next = state.clone();
    let mut out = Out::new(ctx, actor_for(&ctx.principal, state));
    apply(&mut next, command, &mut out)?;
    if next.status.is_in_flight() {
        advance(&mut next, &mut out)?;
    }
    check_location(state, ctx, &out.events)?;
    if next.observable() != state.observable() {
        next.version = state.version.saturating_add(1);
    }
    next.book
        .applied
        .insert(ctx.command_id.clone(), fingerprint);
    Ok(Decision {
        state: next,
        events: out.events,
        effects: out.effects,
        replayed: false,
    })
}

/// The recipient whose action `data` records, for the events that must carry a location
/// when the envelope captures it: delivered, viewed, signed, approved, declined.
fn action_recipient(data: &EventData) -> Option<&Id> {
    match data {
        EventData::RecipientDelivered { recipient_id }
        | EventData::RecipientViewedDocument { recipient_id, .. }
        | EventData::RecipientSigned { recipient_id, .. }
        | EventData::RecipientApproved { recipient_id, .. }
        | EventData::RecipientDeclined { recipient_id, .. } => Some(recipient_id),
        _ => None,
    }
}

/// GEO-01: the request's location fits the envelope's `capture_location`, and every
/// recipient action carries one when it is on. A missing device location never blocks
/// signing: the server then supplies an IP approximation with the reason (declined,
/// unavailable), and that satisfies this check (docs/24 §3).
fn check_location(
    state: &EnvelopeState,
    ctx: &Context,
    events: &[PendingEvent],
) -> Result<(), WorkflowError> {
    let capture_location = state.options.capture_location;
    let Some(location) = ctx.request.location.as_ref().map(Personal::get) else {
        if capture_location
            && let Some(recipient) = events.iter().find_map(|e| action_recipient(&e.data))
        {
            return Err(WorkflowError::LocationRequired {
                recipient: recipient.clone(),
            });
        }
        return Ok(());
    };
    let fits = match location.source() {
        LocationSource::Device { .. } => capture_location,
        LocationSource::Ip { reason, .. } => {
            (*reason == FallbackReason::NotRequested) != capture_location
        }
    };
    if fits {
        Ok(())
    } else {
        Err(WorkflowError::LocationInconsistent { capture_location })
    }
}

/// SHA-256 of the command's canonical JSON (RFC 8785).
fn fingerprint(command: &Command) -> Result<Hash256, WorkflowError> {
    canonical_hash(command)
}

/// SHA-256 of a value's canonical JSON (RFC 8785): how field values are hashed in
/// `recipient.field_completed` and `recipient.signed`.
///
/// # Errors
///
/// `CS-WF-0018` when the value cannot be put in canonical form.
pub fn canonical_hash<T: serde::Serialize>(value: &T) -> Result<Hash256, WorkflowError> {
    let bytes = serde_json::to_vec(value).map_err(|_| WorkflowError::Encoding)?;
    let tree = casual_sign_audit::json::parse(&bytes, 64).map_err(|_| WorkflowError::Encoding)?;
    let canonical = casual_sign_audit::jcs::to_vec(&tree).map_err(|_| WorkflowError::Encoding)?;
    Ok(Hash256::digest(&canonical))
}

fn actor_for(principal: &Principal, state: &EnvelopeState) -> Actor {
    let mut actor = Actor::system();
    match principal {
        Principal::Sender { user_id } => {
            actor.kind = ActorKind::Sender;
            actor.id = Some(user_id.clone());
        }
        Principal::Admin { user_id } | Principal::InPersonHost { user_id } => {
            actor.kind = ActorKind::User;
            actor.id = Some(user_id.clone());
        }
        Principal::Host { client_id } => {
            actor.kind = ActorKind::Host;
            actor.id = Some(client_id.clone());
        }
        Principal::Recipient { recipient_id } => {
            actor.kind = ActorKind::Recipient;
            actor.id = Some(recipient_id.clone());
            if let Some(r) = state.recipient(recipient_id) {
                actor.name = Some(Personal(r.spec.name.0.as_str().to_owned()));
                actor.email = Some(Personal(r.spec.email.0.as_str().to_owned()));
            }
        }
        Principal::System => {}
    }
    actor
}

fn not_allowed(command: &Command, state: &EnvelopeState) -> WorkflowError {
    WorkflowError::NotAllowed {
        command: command.name(),
        status: state.status,
    }
}

fn not_permitted(command: &Command) -> WorkflowError {
    WorkflowError::NotPermitted {
        command: command.name(),
    }
}

fn create(
    command: &Command,
    ctx: &Context,
    fingerprint: Hash256,
) -> Result<Decision, WorkflowError> {
    let Command::Create {
        envelope_id,
        account_id,
        sender_user_id,
        subject,
        message,
    } = command
    else {
        return Err(WorkflowError::Unknown {
            kind: ObjectKind::Envelope,
            id: None,
        });
    };
    match &ctx.principal {
        Principal::Sender { user_id } if user_id == sender_user_id => {}
        Principal::Admin { .. } | Principal::Host { .. } => {}
        _ => return Err(not_permitted(command)),
    }
    let mut book = Bookkeeping::default();
    book.applied.insert(ctx.command_id.clone(), fingerprint);
    let state = EnvelopeState {
        id: envelope_id.clone(),
        account_id: account_id.clone(),
        sender_user_id: sender_user_id.clone(),
        status: EnvelopeStatus::Draft,
        version: 0,
        subject: subject.clone(),
        message: message.clone(),
        documents: Vec::new(),
        recipients: Vec::new(),
        fields: Fields::default(),
        expires_at: None,
        reminders: casual_sign_model::ReminderPolicy::none(),
        options: casual_sign_model::SigningOptions::default(),
        seal_profile: casual_sign_model::SealProfile::default(),
        created_at: ctx.now,
        sent_at: None,
        ended_at: None,
        void_reason: None,
        sealed: Vec::new(),
        purged: false,
        deleted_at: None,
        book,
    };
    let mut out = Out::new(ctx, actor_for(&ctx.principal, &state));
    out.event(EventData::EnvelopeCreated {
        subject_hash: Hash256::digest(subject.0.as_str().as_bytes()),
    });
    Ok(Decision {
        state,
        events: out.events,
        effects: out.effects,
        replayed: false,
    })
}

// Authorization and gates ---------------------------------------------------------------

fn authorize_sender(s: &EnvelopeState, cmd: &Command, ctx: &Context) -> Result<(), WorkflowError> {
    match &ctx.principal {
        Principal::Sender { user_id } if *user_id == s.sender_user_id => Ok(()),
        Principal::Admin { .. } => Ok(()),
        _ => Err(not_permitted(cmd)),
    }
}

fn authorize_system(cmd: &Command, ctx: &Context) -> Result<(), WorkflowError> {
    if ctx.principal == Principal::System {
        Ok(())
    } else {
        Err(not_permitted(cmd))
    }
}

fn rec<'a>(s: &'a EnvelopeState, id: &Id) -> Result<(usize, &'a RecipientState), WorkflowError> {
    s.recipients
        .iter()
        .enumerate()
        .find(|(_, r)| r.id() == id)
        .ok_or_else(|| WorkflowError::Unknown {
            kind: ObjectKind::Recipient,
            id: Some(id.clone()),
        })
}

pub(crate) fn rec_mut(
    s: &mut EnvelopeState,
    index: usize,
) -> Result<&mut RecipientState, WorkflowError> {
    s.recipients.get_mut(index).ok_or(WorkflowError::Unknown {
        kind: ObjectKind::Recipient,
        id: None,
    })
}

/// The principal may act for the recipient: the recipient, their embedding host, or
/// their in-person host.
fn authorize_recipient(
    r: &RecipientState,
    cmd: &Command,
    ctx: &Context,
) -> Result<(), WorkflowError> {
    let ok = match &ctx.principal {
        Principal::Recipient { recipient_id } => {
            recipient_id == r.id() && r.spec.rtype != RecipientType::InPersonSigner
        }
        Principal::Host { .. } => r.spec.embedded_client_user_id.is_some(),
        Principal::InPersonHost { user_id } => r.in_person_host.as_ref() == Some(user_id),
        _ => false,
    };
    if ok { Ok(()) } else { Err(not_permitted(cmd)) }
}

fn recipient_refused(cmd: &Command, r: &RecipientState) -> WorkflowError {
    WorkflowError::NotAllowedForRecipient {
        command: cmd.name(),
        recipient: r.id().clone(),
        status: r.status,
    }
}

/// The envelope is in flight and routing has reached the recipient, who has not
/// finished.
fn gate_active(s: &EnvelopeState, r: &RecipientState, cmd: &Command) -> Result<(), WorkflowError> {
    if !s.status.is_in_flight() {
        return Err(not_allowed(cmd, s));
    }
    if r.status == RecipientStatus::Created {
        return Err(WorkflowError::NotYourTurn {
            recipient: r.id().clone(),
        });
    }
    if !r.status.is_active() {
        return Err(recipient_refused(cmd, r));
    }
    Ok(())
}

/// Active and has opened the link.
fn gate_opened(s: &EnvelopeState, r: &RecipientState, cmd: &Command) -> Result<(), WorkflowError> {
    gate_active(s, r, cmd)?;
    if r.status.has_opened() {
        Ok(())
    } else {
        Err(recipient_refused(cmd, r))
    }
}

/// Opened, not locked, every authentication requirement passed, and hosted when in
/// person.
fn gate_in(s: &EnvelopeState, r: &RecipientState, cmd: &Command) -> Result<(), WorkflowError> {
    gate_opened(s, r, cmd)?;
    if r.auth_locked {
        return Err(WorkflowError::AuthLocked {
            recipient: r.id().clone(),
        });
    }
    if !r.auth_satisfied() {
        return Err(WorkflowError::AuthRequired {
            recipient: r.id().clone(),
        });
    }
    if r.spec.rtype == RecipientType::InPersonSigner && r.in_person_host.is_none() {
        return Err(recipient_refused(cmd, r));
    }
    Ok(())
}

/// In, and has accepted the current disclosure when the account requires one (FR-04).
fn gate_ready(
    s: &EnvelopeState,
    r: &RecipientState,
    cmd: &Command,
    ctx: &Context,
) -> Result<(), WorkflowError> {
    gate_in(s, r, cmd)?;
    if let Some(ersd) = &ctx.policy.ersd {
        let ok = r
            .consent
            .as_ref()
            .is_some_and(|c| c.ersd_version == ersd.version && c.ersd_hash == ersd.hash);
        if !ok {
            return Err(WorkflowError::ConsentRequired {
                recipient: r.id().clone(),
            });
        }
    }
    Ok(())
}

// Dispatch ----------------------------------------------------------------------------

fn apply(s: &mut EnvelopeState, cmd: &Command, out: &mut Out<'_>) -> Result<(), WorkflowError> {
    let ctx = out.ctx;
    match cmd {
        Command::Create { .. } => Err(not_allowed(cmd, s)),
        Command::Edit { changes } => {
            authorize_sender(s, cmd, ctx)?;
            if s.status != EnvelopeStatus::Draft {
                return Err(not_allowed(cmd, s));
            }
            let report = apply_changes(s, changes, Scope::Draft, out)?;
            if !report.changed.is_empty() {
                out.event(EventData::EnvelopeCorrected {
                    changed: report.changed,
                });
            }
            Ok(())
        }
        Command::Send => send(s, cmd, out),
        Command::DeleteDraft => {
            authorize_sender(s, cmd, ctx)?;
            if s.status != EnvelopeStatus::Draft {
                return Err(not_allowed(cmd, s));
            }
            out.event(EventData::EnvelopePurged {
                policy: "draft_deleted".to_owned(),
            });
            out.effect(EffectKind::DeleteDraft);
            scrub(s);
            Ok(())
        }
        Command::DeleteEnded => {
            authorize_sender(s, cmd, ctx)?;
            let ended = matches!(
                s.status,
                EnvelopeStatus::Declined | EnvelopeStatus::Voided | EnvelopeStatus::Expired
            );
            if !ended || s.purged || s.deleted_at.is_some() {
                return Err(not_allowed(cmd, s));
            }
            out.event(EventData::EnvelopeDeleted {});
            s.deleted_at = Some(ctx.now);
            Ok(())
        }
        Command::Correct { changes } => correct(s, cmd, changes, out),
        Command::Void { reason } => {
            authorize_sender(s, cmd, ctx)?;
            if !s.status.is_in_flight() {
                return Err(not_allowed(cmd, s));
            }
            out.event(EventData::EnvelopeVoided {
                reason: Personal(reason.0.as_str().to_owned()),
            });
            s.void_reason = Some(reason.clone());
            end(
                s,
                EnvelopeStatus::Voided,
                Notice::Voided,
                WebhookTopic::EnvelopeVoided,
                out,
            );
            Ok(())
        }
        Command::Resend { recipients } => resend(s, cmd, recipients, out),
        Command::Remind => {
            authorize_sender(s, cmd, ctx)?;
            if !s.status.is_in_flight() {
                return Err(not_allowed(cmd, s));
            }
            remind_all(s, out);
            Ok(())
        }
        Command::OpenLink { recipient } => open_link(s, cmd, recipient, out),
        Command::ChallengeAuth { recipient, method } => {
            let (_, r) = rec(s, recipient)?;
            authorize_recipient_or_system(r, cmd, ctx)?;
            gate_opened(s, r, cmd)?;
            if r.auth_locked {
                return Err(WorkflowError::AuthLocked {
                    recipient: recipient.clone(),
                });
            }
            if !r.spec.auth.contains(method) {
                return Err(recipient_refused(cmd, r));
            }
            out.event(EventData::RecipientAuthChallenged {
                recipient_id: recipient.clone(),
                method: *method,
            });
            Ok(())
        }
        Command::AuthResult {
            recipient,
            method,
            passed,
        } => auth_result(s, cmd, recipient, *method, *passed, out),
        Command::HostAssertAuth { recipient, claim } => {
            let (i, r) = rec(s, recipient)?;
            if !matches!(ctx.principal, Principal::Host { .. })
                || r.spec.embedded_client_user_id.is_none()
            {
                return Err(not_permitted(cmd));
            }
            gate_opened(s, r, cmd)?;
            out.event(EventData::AuthAssertedByHost {
                recipient_id: recipient.clone(),
                host_claim: Personal(claim.0.as_str().to_owned()),
            });
            pass_auth(s, i, AuthMethod::HostAsserted, out)
        }
        Command::Consent {
            recipient,
            ersd_version,
            ersd_hash,
        } => {
            let (i, r) = rec(s, recipient)?;
            authorize_recipient(r, cmd, ctx)?;
            gate_in(s, r, cmd)?;
            if let Some(e) = &ctx.policy.ersd
                && (e.version != *ersd_version || e.hash != *ersd_hash)
            {
                return Err(WorkflowError::ConsentRequired {
                    recipient: recipient.clone(),
                });
            }
            out.event(EventData::RecipientConsented {
                recipient_id: recipient.clone(),
                ersd_version: ersd_version.as_str().to_owned(),
                ersd_hash: *ersd_hash,
            });
            rec_mut(s, i)?.consent = Some(ConsentRecord {
                ersd_version: ersd_version.clone(),
                ersd_hash: *ersd_hash,
            });
            Ok(())
        }
        Command::WithdrawConsent { recipient } => {
            let (i, r) = rec(s, recipient)?;
            authorize_recipient(r, cmd, ctx)?;
            // In, as for consenting and declining (SEC-CER-01): consent outlives a
            // correction that clears the authentication, and withdrawing it declines,
            // so a link alone must not withdraw it.
            gate_in(s, r, cmd)?;
            let Some(consent) = r.consent.clone() else {
                return Err(recipient_refused(cmd, r));
            };
            let required = r.is_required();
            out.event(EventData::RecipientConsentWithdrawn {
                recipient_id: recipient.clone(),
                ersd_version: consent.ersd_version.as_str().to_owned(),
            });
            rec_mut(s, i)?.consent = None;
            if required {
                // Withdrawal is a right (ESIGN §7001(c)(1)(B)): it declines regardless of
                // `allow_decline`.
                decline_inner(s, i, None, out)?;
            }
            Ok(())
        }
        Command::HostInPerson { recipient } => {
            let (i, r) = rec(s, recipient)?;
            let host = match &ctx.principal {
                Principal::InPersonHost { user_id } => user_id.clone(),
                Principal::Sender { user_id } if *user_id == s.sender_user_id => user_id.clone(),
                _ => return Err(not_permitted(cmd)),
            };
            if r.spec.rtype != RecipientType::InPersonSigner {
                return Err(recipient_refused(cmd, r));
            }
            gate_active(s, r, cmd)?;
            out.event(EventData::RecipientInPersonHosted {
                recipient_id: recipient.clone(),
                host_user_id: host.clone(),
            });
            rec_mut(s, i)?.in_person_host = Some(host);
            Ok(())
        }
        Command::ViewDocument {
            recipient,
            document,
            hash,
            pages_seen,
        } => view_document(s, cmd, recipient, document, *hash, pages_seen, out),
        Command::AdoptSignature {
            recipient,
            mark,
            method,
            image_hash,
        } => {
            let (i, r) = rec(s, recipient)?;
            authorize_recipient(r, cmd, ctx)?;
            gate_ready(s, r, cmd, ctx)?;
            if !r.spec.rtype.signs() {
                return Err(recipient_refused(cmd, r));
            }
            out.event(EventData::RecipientSignatureAdopted {
                recipient_id: recipient.clone(),
                mark: *mark,
                method: *method,
                image_hash: *image_hash,
            });
            let r = rec_mut(s, i)?;
            if !r.adopted.contains(mark) {
                r.adopted.push(*mark);
            }
            Ok(())
        }
        Command::CompleteField { recipient, entry } => {
            let (i, r) = rec(s, recipient)?;
            authorize_recipient(r, cmd, ctx)?;
            gate_ready(s, r, cmd, ctx)?;
            complete_field(s, i, entry, out)
        }
        Command::Finish { recipient, values } => finish(s, cmd, recipient, values, out),
        Command::Approve { recipient } => {
            let (i, r) = rec(s, recipient)?;
            authorize_recipient(r, cmd, ctx)?;
            gate_ready(s, r, cmd, ctx)?;
            if r.spec.rtype != RecipientType::Approver {
                return Err(recipient_refused(cmd, r));
            }
            // An approver's own data fields obey their rules too. `recipient.approved`
            // has no member for value hashes; each value's hash is in its
            // `recipient.field_completed` event.
            check_own_fields(s, recipient)?;
            let documents: Vec<DocumentHash> = s.documents.iter().map(|d| d.hash()).collect();
            out.event(EventData::RecipientApproved {
                recipient_id: recipient.clone(),
                documents: documents.clone(),
            });
            complete_recipient(s, i, documents, out)
        }
        Command::Decline { recipient, reason } => {
            let (i, r) = rec(s, recipient)?;
            authorize_recipient(r, cmd, ctx)?;
            gate_in(s, r, cmd)?;
            if !r.is_required() {
                return Err(recipient_refused(cmd, r));
            }
            if !s.options.allow_decline {
                return Err(WorkflowError::OptionDisabled {
                    option: "allow_decline",
                });
            }
            decline_inner(s, i, reason.clone(), out)
        }
        Command::Reassign {
            recipient,
            to,
            reason,
        } => reassign(s, cmd, recipient, to, reason.as_ref(), out),
        Command::FinishLater { recipient } => {
            let (i, r) = rec(s, recipient)?;
            authorize_recipient(r, cmd, ctx)?;
            gate_in(s, r, cmd)?;
            if !s.options.allow_finish_later {
                return Err(WorkflowError::OptionDisabled {
                    option: "allow_finish_later",
                });
            }
            out.event(EventData::RecipientFinishLater {
                recipient_id: recipient.clone(),
            });
            rec_mut(s, i)?.finish_later = true;
            Ok(())
        }
        Command::RecipientEdit { recipient, changes } => {
            let (i, r) = rec(s, recipient)?;
            authorize_recipient(r, cmd, ctx)?;
            gate_ready(s, r, cmd, ctx)?;
            if !r.spec.rtype.edits_recipients() {
                return Err(recipient_refused(cmd, r));
            }
            let scope = Scope::Recipient {
                index: i,
                rtype: r.spec.rtype,
                order: r.spec.routing_order,
            };
            let report = apply_changes(s, changes, scope, out)?;
            let found = violations(s, &ctx.policy, ctx.now, false);
            if !found.is_empty() {
                return Err(WorkflowError::Invalid { violations: found });
            }
            if !report.changed.is_empty() {
                out.event(EventData::EnvelopeCorrected {
                    changed: report.changed,
                });
                out.webhook(WebhookTopic::EnvelopeCorrected, None);
            }
            Ok(())
        }
        Command::InvitationDispatched { recipient, channel } => {
            authorize_system(cmd, ctx)?;
            rec(s, recipient)?;
            out.event(EventData::InvitationSent {
                recipient_id: recipient.clone(),
                channel: *channel,
            });
            Ok(())
        }
        Command::ReminderDispatched { recipient, channel } => {
            authorize_system(cmd, ctx)?;
            rec(s, recipient)?;
            out.event(EventData::ReminderSent {
                recipient_id: recipient.clone(),
                channel: *channel,
            });
            Ok(())
        }
        Command::InvitationBounced { recipient, channel } => {
            authorize_system(cmd, ctx)?;
            let (i, r) = rec(s, recipient)?;
            out.event(EventData::InvitationBounced {
                recipient_id: recipient.clone(),
                channel: *channel,
            });
            if s.status.is_in_flight() && r.status == RecipientStatus::Sent {
                rec_mut(s, i)?.status = RecipientStatus::AutoResponded;
                out.effect(EffectKind::NotifySender {
                    notice: Notice::Bounced,
                    recipient: Some(recipient.clone()),
                });
                out.webhook(WebhookTopic::RecipientAutoResponded, Some(recipient));
            }
            Ok(())
        }
        Command::TimerDue { timer } => {
            authorize_system(cmd, ctx)?;
            timer_due(s, timer, out)
        }
        Command::Expire => {
            authorize_system(cmd, ctx)?;
            expire_if_due(s, out);
            Ok(())
        }
        Command::SealSucceeded { job, documents } => seal_succeeded(s, cmd, job, documents, out),
        Command::SealFailed { job, code } => {
            authorize_system(cmd, ctx)?;
            if s.status != EnvelopeStatus::Completing {
                return Err(not_allowed(cmd, s));
            }
            if s.book.seal_job.as_ref() != Some(job) {
                return Err(WorkflowError::SealNotProven {
                    fault: SealFault::UnknownJob,
                });
            }
            out.effect(EffectKind::AlertOperator {
                alert: Alert::SealFailed,
                code: code.clone(),
            });
            let not_before = add_ms(ctx.now, i64::from(ctx.policy.seal_retry_ms))?;
            let id = out.effect(EffectKind::SealEnvelope {
                not_before: Some(not_before),
            });
            s.book.seal_job = Some(id);
            Ok(())
        }
        Command::RecordAccess { access } => record_access(s, cmd, access, out),
        Command::Purge { policy } => {
            match ctx.principal {
                Principal::System | Principal::Admin { .. } => {}
                _ => return Err(not_permitted(cmd)),
            }
            if !s.status.is_terminal() {
                return Err(not_allowed(cmd, s));
            }
            out.event(EventData::EnvelopePurged {
                policy: policy.as_str().to_owned(),
            });
            cancel_pending(s, out);
            out.effect(EffectKind::PurgeData {
                policy: policy.clone(),
            });
            out.webhook(WebhookTopic::EnvelopePurged, None);
            scrub(s);
            Ok(())
        }
    }
}

fn authorize_recipient_or_system(
    r: &RecipientState,
    cmd: &Command,
    ctx: &Context,
) -> Result<(), WorkflowError> {
    if ctx.principal == Principal::System {
        Ok(())
    } else {
        authorize_recipient(r, cmd, ctx)
    }
}

/// Removes personal data and values, keeping ids, statuses and hashes (the tombstone's
/// substance, docs/32 §7).
fn scrub(s: &mut EnvelopeState) {
    let empty = || Personal(Text::default());
    s.purged = true;
    s.subject = empty();
    s.message = empty();
    s.void_reason = None;
    for r in &mut s.recipients {
        r.spec.name = empty();
        r.spec.email = empty();
        r.spec.phone = None;
        r.declined_reason = None;
    }
    for d in &mut s.documents {
        d.spec.name = empty();
    }
    for f in &mut s.fields.0 {
        f.value = None;
        f.default = None;
    }
    s.book.scheduled.clear();
    s.book.seal_job = None;
}

// Time --------------------------------------------------------------------------------

fn add_ms(at: Timestamp, ms: i64) -> Result<Timestamp, WorkflowError> {
    at.unix_millis()
        .checked_add(ms)
        .and_then(Timestamp::from_unix_millis)
        .ok_or(WorkflowError::TimeOutOfRange)
}

fn add_days(at: Timestamp, days: u16) -> Result<Timestamp, WorkflowError> {
    let ms = i64::from(days)
        .checked_mul(MS_PER_DAY)
        .ok_or(WorkflowError::TimeOutOfRange)?;
    add_ms(at, ms)
}

fn schedule(s: &mut EnvelopeState, timer: Timer, at: Timestamp, out: &mut Out<'_>) {
    let id = out.effect(EffectKind::Schedule { timer, at });
    s.book.scheduled.push(ScheduledTimer { id, timer, at });
}

/// Cancels every pending timer and seal job.
fn cancel_pending(s: &mut EnvelopeState, out: &mut Out<'_>) {
    let pending = s.pending_effects();
    if !pending.is_empty() {
        out.effect(EffectKind::Cancel { effects: pending });
    }
    s.book.scheduled.clear();
    s.book.seal_job = None;
}

/// Cancels the timers of one kind.
fn cancel_timers(s: &mut EnvelopeState, kinds: &[Timer], out: &mut Out<'_>) {
    let (gone, kept): (Vec<_>, Vec<_>) = s
        .book
        .scheduled
        .drain(..)
        .partition(|t| kinds.contains(&t.timer));
    s.book.scheduled = kept;
    if !gone.is_empty() {
        out.effect(EffectKind::Cancel {
            effects: gone.into_iter().map(|t| t.id).collect(),
        });
    }
}

/// Schedules expiry, its warning and the next reminder from the current settings.
pub(crate) fn schedule_timers(
    s: &mut EnvelopeState,
    kinds: &[Timer],
    out: &mut Out<'_>,
) -> Result<(), WorkflowError> {
    let now = out.ctx.now;
    if kinds.contains(&Timer::Expiry)
        && let Some(at) = s.expires_at
    {
        schedule(s, Timer::Expiry, at, out);
        let warn = out.ctx.policy.expiry_warning_days;
        if warn > 0 {
            let ms = i64::from(warn)
                .checked_mul(MS_PER_DAY)
                .ok_or(WorkflowError::TimeOutOfRange)?;
            if let Some(w) = at
                .unix_millis()
                .checked_sub(ms)
                .and_then(Timestamp::from_unix_millis)
                && w > now
            {
                schedule(s, Timer::ExpiryWarning, w, out);
            }
        }
    }
    if kinds.contains(&Timer::Reminder) {
        let first = s.reminders.first_after_days();
        let every = s.reminders.then_every_days();
        let base = s.sent_at.unwrap_or(now);
        let mut next = None;
        if first > 0 {
            let at = add_days(base, first)?;
            if at > now {
                next = Some(at);
            }
        }
        if next.is_none() && every > 0 && first > 0 {
            next = Some(add_days(now, every)?);
        }
        if let Some(at) = next {
            schedule(s, Timer::Reminder, at, out);
        }
    }
    Ok(())
}

fn channel(delivery: Delivery) -> Channel {
    match delivery {
        Delivery::Email => Channel::Email,
        Delivery::Sms => Channel::Sms,
        Delivery::None => Channel::Link,
    }
}

// Routing -------------------------------------------------------------------------------

/// Routing after every change of an in-flight envelope (docs/24 §4): recipients whose
/// turn no longer holds go back to `created`; recipients whose turn holds are invited
/// (carbon copies complete at once); when every required recipient has completed the
/// envelope moves to `completing`; `delivered` is recomputed.
pub(crate) fn advance(s: &mut EnvelopeState, out: &mut Out<'_>) -> Result<(), WorkflowError> {
    // Out of turn: back to created, tokens revoked.
    for i in 0..s.recipients.len() {
        let active = s.recipients.get(i).is_some_and(|r| r.status.is_active());
        if active && !s.turn_reached(i) {
            let r = rec_mut(s, i)?;
            r.status = RecipientStatus::Created;
            r.auth_passed.clear();
            let id = r.id().clone();
            out.effect(EffectKind::RevokeTokens { recipient: id });
        }
    }
    // In turn: invite, in routing order then the order added.
    let mut order: Vec<usize> = (0..s.recipients.len()).collect();
    order.sort_by_key(|&i| s.recipients.get(i).map(|r| r.spec.routing_order));
    for i in order {
        let created = s
            .recipients
            .get(i)
            .is_some_and(|r| r.status == RecipientStatus::Created);
        if !created || !s.turn_reached(i) {
            continue;
        }
        let now = out.ctx.now;
        let r = rec_mut(s, i)?;
        let id = r.id().clone();
        let ch = channel(r.spec.delivery);
        if r.spec.rtype == RecipientType::Cc {
            r.status = RecipientStatus::Completed;
            r.completed_at = Some(now);
            out.effect(EffectKind::SendInvitation {
                recipient: id.clone(),
                channel: ch,
                invitation: InvitationKind::Copy,
            });
            out.system_event(EventData::RecipientCompleted { recipient_id: id });
        } else {
            r.status = RecipientStatus::Sent;
            out.effect(EffectKind::SendInvitation {
                recipient: id.clone(),
                channel: ch,
                invitation: InvitationKind::Act,
            });
            out.webhook(WebhookTopic::RecipientSent, Some(&id));
        }
    }
    // Complete.
    let required: Vec<&RecipientState> = s.recipients.iter().filter(|r| r.is_required()).collect();
    if !required.is_empty()
        && required
            .iter()
            .all(|r| r.status == RecipientStatus::Completed)
    {
        s.status = EnvelopeStatus::Completing;
        out.system_event(EventData::EnvelopeCompleting {});
        cancel_pending(s, out);
        let job = out.effect(EffectKind::SealEnvelope { not_before: None });
        s.book.seal_job = Some(job);
        out.webhook(WebhookTopic::EnvelopeCompleting, None);
        return Ok(());
    }
    // Delivered: every recipient routing has reached has opened (docs/24 §2).
    let all_opened = s
        .recipients
        .iter()
        .filter(|r| {
            !matches!(
                r.status,
                RecipientStatus::Created | RecipientStatus::Reassigned
            )
        })
        .all(|r| {
            matches!(
                r.status,
                RecipientStatus::Delivered
                    | RecipientStatus::Authenticated
                    | RecipientStatus::Completed
            )
        });
    let status = if all_opened {
        EnvelopeStatus::Delivered
    } else {
        EnvelopeStatus::Sent
    };
    if status != s.status {
        s.status = status;
        if status == EnvelopeStatus::Delivered {
            out.webhook(WebhookTopic::EnvelopeDelivered, None);
        }
    }
    Ok(())
}

/// Ends the envelope: status, time, every pending effect cancelled, every active
/// recipient's tokens revoked and notified, the sender notified.
fn end(
    s: &mut EnvelopeState,
    status: EnvelopeStatus,
    notice: Notice,
    topic: WebhookTopic,
    out: &mut Out<'_>,
) {
    s.status = status;
    s.ended_at = Some(out.ctx.now);
    cancel_pending(s, out);
    let active: Vec<Id> = s
        .recipients
        .iter()
        .filter(|r| r.status.is_active())
        .map(|r| r.id().clone())
        .collect();
    for id in &active {
        out.effect(EffectKind::RevokeTokens {
            recipient: id.clone(),
        });
    }
    // Who hears: active recipients, and on a decline those who already completed.
    let mut told = active;
    if notice == Notice::Declined {
        told.extend(
            s.recipients
                .iter()
                .filter(|r| r.status == RecipientStatus::Completed && r.spec.rtype.signs())
                .map(|r| r.id().clone()),
        );
    }
    if !told.is_empty() {
        out.effect(EffectKind::NotifyRecipients {
            recipients: told,
            notice,
        });
    }
    out.effect(EffectKind::NotifySender {
        notice,
        recipient: None,
    });
    out.webhook(topic, None);
}

// Sender commands -----------------------------------------------------------------------

fn send(s: &mut EnvelopeState, cmd: &Command, out: &mut Out<'_>) -> Result<(), WorkflowError> {
    let ctx = out.ctx;
    authorize_sender(s, cmd, ctx)?;
    if s.status != EnvelopeStatus::Draft {
        return Err(not_allowed(cmd, s));
    }
    let found = violations(s, &ctx.policy, ctx.now, true);
    if !found.is_empty() {
        return Err(WorkflowError::Invalid { violations: found });
    }
    s.status = EnvelopeStatus::Sent;
    s.sent_at = Some(ctx.now);
    out.event(EventData::EnvelopeSent {
        recipients: u32::try_from(s.recipients.len()).unwrap_or(u32::MAX),
        documents: u32::try_from(s.documents.len()).unwrap_or(u32::MAX),
    });
    for d in &mut s.documents {
        d.fixed = true;
        out.event(EventData::DocumentFixed {
            document_id: d.spec.id.clone(),
            delivered_hash: d.spec.delivered_hash,
            pages: d.spec.pages,
        });
    }
    out.webhook(WebhookTopic::EnvelopeSent, None);
    schedule_timers(s, &[Timer::Expiry, Timer::Reminder], out)
}

fn correct(
    s: &mut EnvelopeState,
    cmd: &Command,
    changes: &[crate::command::Change],
    out: &mut Out<'_>,
) -> Result<(), WorkflowError> {
    let ctx = out.ctx;
    authorize_sender(s, cmd, ctx)?;
    if !s.status.is_in_flight() {
        return Err(not_allowed(cmd, s));
    }
    let report = apply_changes(s, changes, Scope::Correct, out)?;
    let found = violations(s, &ctx.policy, ctx.now, report.expiry_changed);
    if !found.is_empty() {
        return Err(WorkflowError::Invalid { violations: found });
    }
    // Completed recipients who acted on a replaced or removed document, or whose own
    // fields changed, act again (docs/24 §6); the earlier act stays in the chain.
    let mut redo: BTreeSet<Id> = report.redo.clone();
    for r in &s.recipients {
        if r.status == RecipientStatus::Completed
            && r.is_required()
            && r.acted_documents
                .iter()
                .any(|d| report.touched_documents.contains(&d.document_id))
        {
            redo.insert(r.id().clone());
        }
    }
    let mut notified = Vec::new();
    for i in 0..s.recipients.len() {
        let r = rec_mut(s, i)?;
        let id = r.id().clone();
        let again = redo.contains(&id) && r.status == RecipientStatus::Completed && r.is_required();
        let readdressed = report.readdressed.contains(&id) && r.status.is_active();
        if again || readdressed {
            if r.status.is_active() {
                out.effect(EffectKind::RevokeTokens {
                    recipient: id.clone(),
                });
            }
            r.status = RecipientStatus::Created;
            r.completed_at = None;
            r.acted_documents.clear();
            r.auth_passed.clear();
            notified.push(id);
        }
    }
    if !notified.is_empty() {
        out.effect(EffectKind::NotifyRecipients {
            recipients: notified,
            notice: Notice::Corrected,
        });
    }
    if report.expiry_changed {
        cancel_timers(s, &[Timer::Expiry, Timer::ExpiryWarning], out);
        schedule_timers(s, &[Timer::Expiry], out)?;
    }
    if report.reminders_changed {
        cancel_timers(s, &[Timer::Reminder], out);
        schedule_timers(s, &[Timer::Reminder], out)?;
    }
    if !report.changed.is_empty() {
        out.event(EventData::EnvelopeCorrected {
            changed: report.changed,
        });
        out.webhook(WebhookTopic::EnvelopeCorrected, None);
    }
    Ok(())
}

fn resend(
    s: &mut EnvelopeState,
    cmd: &Command,
    recipients: &[Id],
    out: &mut Out<'_>,
) -> Result<(), WorkflowError> {
    authorize_sender(s, cmd, out.ctx)?;
    if !s.status.is_in_flight() {
        return Err(not_allowed(cmd, s));
    }
    let targets: Vec<usize> = if recipients.is_empty() {
        (0..s.recipients.len())
            .filter(|&i| s.recipients.get(i).is_some_and(|r| r.status.is_active()))
            .collect()
    } else {
        let mut v = Vec::new();
        for id in recipients {
            let (i, r) = rec(s, id)?;
            if !r.status.is_active() {
                return Err(recipient_refused(cmd, r));
            }
            v.push(i);
        }
        v
    };
    let mut changed = Vec::new();
    for i in targets {
        let r = rec_mut(s, i)?;
        let id = r.id().clone();
        if r.status == RecipientStatus::AutoResponded {
            r.status = RecipientStatus::Sent;
            changed.push(format!("recipients.{id}.status"));
        }
        if r.auth_locked || r.auth_failures > 0 {
            r.auth_locked = false;
            r.auth_failures = 0;
            changed.push(format!("recipients.{id}.auth_lock"));
        }
        let ch = channel(r.spec.delivery);
        out.effect(EffectKind::SendInvitation {
            recipient: id,
            channel: ch,
            invitation: InvitationKind::Act,
        });
    }
    if !changed.is_empty() {
        out.event(EventData::EnvelopeCorrected { changed });
    }
    Ok(())
}

fn remind_all(s: &EnvelopeState, out: &mut Out<'_>) {
    for r in s
        .recipients
        .iter()
        .filter(|r| r.status.is_active() && r.is_required())
    {
        out.effect(EffectKind::SendReminder {
            recipient: r.id().clone(),
            channel: channel(r.spec.delivery),
        });
    }
}

// Recipient commands ----------------------------------------------------------------------

fn open_link(
    s: &mut EnvelopeState,
    cmd: &Command,
    recipient: &Id,
    out: &mut Out<'_>,
) -> Result<(), WorkflowError> {
    let (i, r) = rec(s, recipient)?;
    authorize_recipient(r, cmd, out.ctx)?;
    gate_active(s, r, cmd)?;
    out.event(EventData::RecipientDelivered {
        recipient_id: recipient.clone(),
    });
    let r = rec_mut(s, i)?;
    if matches!(
        r.status,
        RecipientStatus::Sent | RecipientStatus::AutoResponded
    ) {
        r.status = if r.auth_satisfied() && !r.spec.auth.is_empty() {
            RecipientStatus::Authenticated
        } else {
            RecipientStatus::Delivered
        };
        out.webhook(WebhookTopic::RecipientDelivered, Some(recipient));
    }
    Ok(())
}

fn auth_result(
    s: &mut EnvelopeState,
    cmd: &Command,
    recipient: &Id,
    method: AuthMethod,
    passed: bool,
    out: &mut Out<'_>,
) -> Result<(), WorkflowError> {
    let ctx = out.ctx;
    let (i, r) = rec(s, recipient)?;
    authorize_recipient_or_system(r, cmd, ctx)?;
    gate_opened(s, r, cmd)?;
    if r.auth_locked {
        return Err(WorkflowError::AuthLocked {
            recipient: recipient.clone(),
        });
    }
    if !r.spec.auth.contains(&method) {
        return Err(recipient_refused(cmd, r));
    }
    if passed {
        out.event(EventData::RecipientAuthPassed {
            recipient_id: recipient.clone(),
            method,
        });
        return pass_auth(s, i, method, out);
    }
    let r = rec_mut(s, i)?;
    r.auth_failures = r.auth_failures.saturating_add(1);
    let attempt = r.auth_failures;
    out.event(EventData::RecipientAuthFailed {
        recipient_id: recipient.clone(),
        method,
        attempt,
    });
    if attempt >= ctx.policy.max_auth_attempts.max(1) {
        r.auth_locked = true;
        out.effect(EffectKind::RevokeTokens {
            recipient: recipient.clone(),
        });
        out.effect(EffectKind::NotifySender {
            notice: Notice::AuthLocked,
            recipient: Some(recipient.clone()),
        });
        out.webhook(WebhookTopic::RecipientAuthLocked, Some(recipient));
    }
    Ok(())
}

fn pass_auth(
    s: &mut EnvelopeState,
    i: usize,
    method: AuthMethod,
    _out: &mut Out<'_>,
) -> Result<(), WorkflowError> {
    let r = rec_mut(s, i)?;
    if !r.auth_passed.contains(&method) {
        r.auth_passed.push(method);
    }
    if r.auth_satisfied() && r.status == RecipientStatus::Delivered && !r.spec.auth.is_empty() {
        r.status = RecipientStatus::Authenticated;
    }
    Ok(())
}

fn view_document(
    s: &mut EnvelopeState,
    cmd: &Command,
    recipient: &Id,
    document: &Id,
    hash: Hash256,
    pages_seen: &[u32],
    out: &mut Out<'_>,
) -> Result<(), WorkflowError> {
    let ctx = out.ctx;
    let (i, r) = rec(s, recipient)?;
    authorize_recipient(r, cmd, ctx)?;
    gate_ready(s, r, cmd, ctx)?;
    let d = s.document(document).ok_or_else(|| WorkflowError::Unknown {
        kind: ObjectKind::Document,
        id: Some(document.clone()),
    })?;
    let pages = d.spec.pages;
    let mismatch = || WorkflowError::DocumentMismatch {
        document: document.clone(),
    };
    if d.spec.delivered_hash != hash {
        return Err(mismatch());
    }
    let seen: BTreeSet<u32> = pages_seen.iter().copied().collect();
    if seen.iter().any(|&p| p == 0 || p > pages) {
        return Err(mismatch());
    }
    out.event(EventData::RecipientViewedDocument {
        recipient_id: recipient.clone(),
        document: d.hash(),
        pages_seen: seen.iter().copied().collect(),
    });
    let to_end = seen.contains(&pages);
    let r = rec_mut(s, i)?;
    if to_end {
        r.viewed_to_end.insert(document.clone());
    }
    // A viewer completes by viewing every document to the end (docs/24 §3).
    let viewer_done = r.spec.rtype == RecipientType::Viewer && viewed_all(s, i);
    if viewer_done {
        let documents = s.documents.iter().map(|d| d.hash()).collect();
        complete_recipient(s, i, documents, out)?;
    }
    Ok(())
}

fn viewed_all(s: &EnvelopeState, i: usize) -> bool {
    s.recipients
        .get(i)
        .is_some_and(|r| s.documents.iter().all(|d| r.viewed_to_end.contains(d.id())))
}

fn field_index(s: &EnvelopeState, id: &Id) -> Result<usize, WorkflowError> {
    s.fields
        .0
        .iter()
        .position(|f| f.id == *id)
        .ok_or_else(|| WorkflowError::Unknown {
            kind: ObjectKind::Field,
            id: Some(id.clone()),
        })
}

fn complete_field(
    s: &mut EnvelopeState,
    i: usize,
    entry: &FieldEntry,
    out: &mut Out<'_>,
) -> Result<(), WorkflowError> {
    let r = s.recipients.get(i).ok_or(WorkflowError::Unknown {
        kind: ObjectKind::Recipient,
        id: None,
    })?;
    let rid = r.id().clone();
    let fi = field_index(s, &entry.field)?;
    let field = s.fields.0.get(fi).ok_or(WorkflowError::Unknown {
        kind: ObjectKind::Field,
        id: Some(entry.field.clone()),
    })?;
    let editable = field.recipient_id.as_ref() == Some(&rid)
        && field.field_type.takes_input()
        && !field.read_only
        && !field.locked;
    if !editable {
        return Err(WorkflowError::FieldNotEditable {
            field: entry.field.clone(),
        });
    }
    let value = &entry.value.0;
    if let FieldValue::Signature(_) = value {
        let mark = match field.field_type {
            FieldType::Signature => Some(MarkKind::Signature),
            FieldType::Initials => Some(MarkKind::Initials),
            _ => None,
        };
        if let Some(mark) = mark
            && !r.adopted.contains(&mark)
        {
            return Err(WorkflowError::NotAdopted { mark });
        }
    }
    validate(field, value).map_err(|error| WorkflowError::Fields {
        issues: vec![Issue {
            field_id: entry.field.clone(),
            error,
        }],
    })?;
    let value_hash = canonical_hash(value)?;
    out.event(EventData::RecipientFieldCompleted {
        recipient_id: rid,
        field_id: entry.field.clone(),
        value_hash,
    });
    if let Some(f) = s.fields.0.get_mut(fi) {
        f.value = Some(value.clone());
    }
    Ok(())
}

fn finish(
    s: &mut EnvelopeState,
    cmd: &Command,
    recipient: &Id,
    values: &[FieldEntry],
    out: &mut Out<'_>,
) -> Result<(), WorkflowError> {
    let ctx = out.ctx;
    let (i, r) = rec(s, recipient)?;
    authorize_recipient(r, cmd, ctx)?;
    gate_ready(s, r, cmd, ctx)?;
    let rtype = r.spec.rtype;
    match rtype {
        RecipientType::Approver | RecipientType::Cc => Err(recipient_refused(cmd, r)),
        RecipientType::Viewer => {
            if !viewed_all(s, i) {
                return Err(WorkflowError::NotViewed {
                    recipient: recipient.clone(),
                });
            }
            let documents = s.documents.iter().map(|d| d.hash()).collect();
            complete_recipient(s, i, documents, out)
        }
        RecipientType::Agent | RecipientType::Intermediary => {
            // Every later recipient must now be reachable.
            let order = r.spec.routing_order;
            if let Some(later) = s.recipients.iter().find(|q| {
                q.spec.routing_order > order
                    && q.status == RecipientStatus::Created
                    && !has_address(q)
            }) {
                return Err(WorkflowError::Unreachable {
                    recipient: later.id().clone(),
                });
            }
            let documents = s.documents.iter().map(|d| d.hash()).collect();
            complete_recipient(s, i, documents, out)
        }
        _ => sign(s, i, values, out),
    }
}

pub(crate) fn has_address(r: &RecipientState) -> bool {
    match r.spec.delivery {
        Delivery::Email => !r.spec.email.0.is_empty(),
        Delivery::Sms => r.spec.phone.as_ref().is_some_and(|p| !p.0.is_empty()),
        Delivery::None => true,
    }
}

/// A signer type finishes: values set, auto-filled and stamped, every field rule re-run
/// on the server (docs/24 §5), then `recipient.signed` and `recipient.completed`.
fn sign(
    s: &mut EnvelopeState,
    i: usize,
    values: &[FieldEntry],
    out: &mut Out<'_>,
) -> Result<(), WorkflowError> {
    let ctx = out.ctx;
    for entry in values {
        complete_field(s, i, entry, out)?;
    }
    let r = s.recipients.get(i).ok_or(WorkflowError::Unknown {
        kind: ObjectKind::Recipient,
        id: None,
    })?;
    let rid = r.id().clone();
    let name = r.spec.name.0.clone();
    let email = r.spec.email.0.clone();
    let offset = r.spec.time_zone_offset_minutes;
    let recipient_format = r.spec.date_format;
    let adopted_signature = r.adopted.contains(&MarkKind::Signature);
    let envelope_id = Text::new(s.id.as_str())?;

    // Auto-fill and stamp this recipient's server-filled fields.
    let mut has_signature_field = false;
    for f in s
        .fields
        .0
        .iter_mut()
        .filter(|f| f.recipient_id.as_ref() == Some(&rid))
    {
        match f.field_type {
            FieldType::Signature => has_signature_field = true,
            FieldType::DateSigned => {
                let format = f
                    .format
                    .as_ref()
                    .and_then(|x| x.date_format)
                    .or(recipient_format)
                    .unwrap_or(ctx.policy.date_format);
                let text =
                    format_date(ctx.now, offset, format).ok_or(WorkflowError::TimeOutOfRange)?;
                f.value = Some(FieldValue::Text(Text::new(text)?));
            }
            FieldType::Name if f.value.is_none() && !name.is_empty() => {
                f.value = Some(FieldValue::Text(name.clone()));
            }
            FieldType::Email if f.value.is_none() && !email.is_empty() => {
                f.value = Some(FieldValue::Text(email.clone()));
            }
            FieldType::EnvelopeId => f.value = Some(FieldValue::Text(envelope_id.clone())),
            _ => {}
        }
    }
    // A signer with no signature field still adopts one (free-form signing): intent.
    if !has_signature_field && !adopted_signature {
        return Err(WorkflowError::NotAdopted {
            mark: MarkKind::Signature,
        });
    }

    let field_value_hashes = check_own_fields(s, &rid)?;
    let payments: Vec<Id> = s
        .fields
        .0
        .iter()
        .filter(|f| f.field_type == FieldType::Payment && field_value_hashes.contains_key(&f.id))
        .map(|f| f.id.clone())
        .collect();
    let documents: Vec<DocumentHash> = s.documents.iter().map(|d| d.hash()).collect();
    out.event(EventData::RecipientSigned {
        recipient_id: rid.clone(),
        documents: documents.clone(),
        field_value_hashes,
    });
    for field in payments {
        out.effect(EffectKind::ChargePayment {
            recipient: rid.clone(),
            field,
        });
    }
    complete_recipient(s, i, documents, out)
}

/// Re-runs every field rule on the server (docs/24 §5) and keeps the issues on the
/// recipient's own fields; drops the values of their hidden fields; returns the hash of
/// each of their values.
fn check_own_fields(
    s: &mut EnvelopeState,
    rid: &Id,
) -> Result<std::collections::BTreeMap<Id, Hash256>, WorkflowError> {
    let outcome = evaluate_envelope(&s.fields.0, &Values::new());
    let mine: BTreeSet<Id> = s
        .fields
        .0
        .iter()
        .filter(|f| f.recipient_id.as_ref() == Some(rid))
        .map(|f| f.id.clone())
        .collect();
    let issues: Vec<Issue> = outcome
        .issues
        .into_iter()
        .filter(|x| mine.contains(&x.field_id))
        .collect();
    if !issues.is_empty() {
        return Err(WorkflowError::Fields { issues });
    }
    // A hidden field's value is dropped (docs/24 §5).
    for f in s.fields.0.iter_mut() {
        if mine.contains(&f.id) && outcome.dropped.contains(&f.id) {
            f.value = None;
        }
    }
    let mut hashes = std::collections::BTreeMap::new();
    for f in s.fields.0.iter().filter(|f| mine.contains(&f.id)) {
        if let Some(v) = &f.value {
            hashes.insert(f.id.clone(), canonical_hash(v)?);
        }
    }
    Ok(hashes)
}

fn complete_recipient(
    s: &mut EnvelopeState,
    i: usize,
    documents: Vec<DocumentHash>,
    out: &mut Out<'_>,
) -> Result<(), WorkflowError> {
    let now = out.ctx.now;
    let r = rec_mut(s, i)?;
    let id = r.id().clone();
    r.status = RecipientStatus::Completed;
    r.completed_at = Some(now);
    r.acted_documents = documents;
    r.finish_later = false;
    out.event(EventData::RecipientCompleted {
        recipient_id: id.clone(),
    });
    out.webhook(WebhookTopic::RecipientCompleted, Some(&id));
    Ok(())
}

fn decline_inner(
    s: &mut EnvelopeState,
    i: usize,
    reason: Option<Personal<Text>>,
    out: &mut Out<'_>,
) -> Result<(), WorkflowError> {
    let r = rec_mut(s, i)?;
    let id = r.id().clone();
    out.event(EventData::RecipientDeclined {
        recipient_id: id.clone(),
        reason: reason.as_ref().map(|t| Personal(t.0.as_str().to_owned())),
    });
    out.event(EventData::EnvelopeDeclined {
        recipient_id: id.clone(),
    });
    r.status = RecipientStatus::Declined;
    r.declined_reason = reason;
    out.effect(EffectKind::RevokeTokens {
        recipient: id.clone(),
    });
    out.webhook(WebhookTopic::RecipientDeclined, Some(&id));
    end(
        s,
        EnvelopeStatus::Declined,
        Notice::Declined,
        WebhookTopic::EnvelopeDeclined,
        out,
    );
    Ok(())
}

fn reassign(
    s: &mut EnvelopeState,
    cmd: &Command,
    recipient: &Id,
    to: &ReassignTo,
    reason: Option<&Personal<Text>>,
    out: &mut Out<'_>,
) -> Result<(), WorkflowError> {
    let ctx = out.ctx;
    let (i, r) = rec(s, recipient)?;
    authorize_recipient(r, cmd, ctx)?;
    gate_in(s, r, cmd)?;
    if !r.is_required() {
        return Err(recipient_refused(cmd, r));
    }
    if !s.options.allow_reassign {
        return Err(WorkflowError::OptionDisabled {
            option: "allow_reassign",
        });
    }
    if s.recipient(&to.id).is_some() {
        return Err(WorkflowError::DuplicateId {
            kind: ObjectKind::Recipient,
            id: to.id.clone(),
        });
    }
    if s.recipients.len() >= ctx.policy.max_recipients.min(limits::MAX_RECIPIENTS) {
        return Err(WorkflowError::Invalid {
            violations: vec![crate::error::Violation {
                object: None,
                problem: crate::error::Problem::TooMany {
                    what: "recipients",
                    count: s.recipients.len().saturating_add(1),
                    limit: ctx.policy.max_recipients.min(limits::MAX_RECIPIENTS),
                },
            }],
        });
    }
    let mut spec = r.spec.clone();
    spec.id = to.id.clone();
    spec.name = to.name.clone();
    spec.email = to.email.clone();
    spec.phone = to.phone.clone();
    if let Some(d) = to.delivery {
        spec.delivery = d;
    }
    spec.embedded_client_user_id = None;
    let mut new = RecipientState::new(spec);
    new.reassigned_from = Some(recipient.clone());
    if !has_address(&new) {
        return Err(WorkflowError::Unreachable {
            recipient: to.id.clone(),
        });
    }
    out.event(EventData::RecipientReassigned {
        recipient_id: recipient.clone(),
        to_recipient_id: to.id.clone(),
        reason: reason.map(|t| Personal(t.0.as_str().to_owned())),
    });
    for f in s.fields.0.iter_mut() {
        if f.recipient_id.as_ref() == Some(recipient) {
            f.recipient_id = Some(to.id.clone());
            f.value = None;
        }
    }
    let old = rec_mut(s, i)?;
    old.status = RecipientStatus::Reassigned;
    old.reassigned_to = Some(to.id.clone());
    out.effect(EffectKind::RevokeTokens {
        recipient: recipient.clone(),
    });
    out.webhook(WebhookTopic::RecipientReassigned, Some(recipient));
    let at = i.checked_add(1).unwrap_or(i).min(s.recipients.len());
    s.recipients.insert(at, new);
    Ok(())
}

// System commands -------------------------------------------------------------------------

fn timer_due(
    s: &mut EnvelopeState,
    timer: &EffectId,
    out: &mut Out<'_>,
) -> Result<(), WorkflowError> {
    // A timer no longer pending (fired, cancelled, or the envelope moved on) is a no-op
    // with no event (docs/24 §7).
    let Some(pos) = s.book.scheduled.iter().position(|t| t.id == *timer) else {
        return Ok(());
    };
    let t = s.book.scheduled.remove(pos);
    if !s.status.is_in_flight() {
        return Ok(());
    }
    match t.timer {
        Timer::Reminder => {
            remind_all(s, out);
            let every = s.reminders.then_every_days();
            if every > 0 {
                let at = add_days(out.ctx.now, every)?;
                schedule(s, Timer::Reminder, at, out);
            }
        }
        Timer::Expiry => expire_if_due(s, out),
        Timer::ExpiryWarning => {
            for r in s
                .recipients
                .iter()
                .filter(|r| r.status.is_active() && r.is_required())
            {
                out.effect(EffectKind::SendExpiryWarning {
                    recipient: r.id().clone(),
                    channel: channel(r.spec.delivery),
                });
            }
        }
    }
    Ok(())
}

fn expire_if_due(s: &mut EnvelopeState, out: &mut Out<'_>) {
    let due = s.expires_at.is_some_and(|at| at <= out.ctx.now);
    if s.status.is_in_flight() && due {
        out.event(EventData::EnvelopeExpired {});
        end(
            s,
            EnvelopeStatus::Expired,
            Notice::Expired,
            WebhookTopic::EnvelopeExpired,
            out,
        );
    }
}

fn seal_succeeded(
    s: &mut EnvelopeState,
    cmd: &Command,
    job: &EffectId,
    documents: &[SealedDocument],
    out: &mut Out<'_>,
) -> Result<(), WorkflowError> {
    authorize_system(cmd, out.ctx)?;
    if s.status != EnvelopeStatus::Completing {
        return Err(not_allowed(cmd, s));
    }
    let fault = |fault| WorkflowError::SealNotProven { fault };
    if s.book.seal_job.as_ref() != Some(job) {
        return Err(fault(SealFault::UnknownJob));
    }
    // Every document exactly once, verified, sealed from the bytes delivered.
    let mut seen = BTreeSet::new();
    for d in documents {
        let Some(doc) = s.document(&d.document_id) else {
            return Err(fault(SealFault::UnexpectedDocument));
        };
        if !seen.insert(d.document_id.clone()) {
            return Err(fault(SealFault::UnexpectedDocument));
        }
        if !d.verified {
            return Err(fault(SealFault::NotVerified));
        }
        if d.delivered_hash != doc.spec.delivered_hash {
            return Err(fault(SealFault::InputMismatch));
        }
        if d.profile != s.seal_profile {
            return Err(fault(SealFault::WrongProfile));
        }
    }
    if seen.len() != s.documents.len() {
        return Err(fault(SealFault::MissingDocument));
    }
    let mut sealed = Vec::new();
    for d in documents {
        out.event(EventData::DocumentFlattened {
            document_id: d.document_id.clone(),
            flattened_hash: d.flattened_hash,
        });
        out.event(EventData::DocumentSealed {
            document_id: d.document_id.clone(),
            sealed_hash: d.sealed_hash,
            profile: d.profile.as_str().to_owned(),
            certificate_fingerprint: d.certificate_fingerprint,
            tsa_time: d.tsa_time,
        });
        sealed.push(DocumentHash {
            document_id: d.document_id.clone(),
            hash: d.sealed_hash,
        });
    }
    out.event(EventData::EnvelopeCompleted {
        sealed: sealed.clone(),
    });
    s.sealed = sealed;
    s.status = EnvelopeStatus::Completed;
    s.ended_at = Some(out.ctx.now);
    s.book.seal_job = None;
    let copies: Vec<Id> = s
        .recipients
        .iter()
        .filter(|r| r.status == RecipientStatus::Completed)
        .map(|r| r.id().clone())
        .collect();
    out.effect(EffectKind::SendCompletionCopies { recipients: copies });
    out.effect(EffectKind::NotifySender {
        notice: Notice::Completed,
        recipient: None,
    });
    out.webhook(WebhookTopic::EnvelopeCompleted, None);
    Ok(())
}

fn record_access(
    s: &EnvelopeState,
    cmd: &Command,
    access: &Access,
    out: &mut Out<'_>,
) -> Result<(), WorkflowError> {
    let ctx = out.ctx;
    let allowed = match &ctx.principal {
        Principal::Sender { user_id } => *user_id == s.sender_user_id,
        Principal::Admin { .. } | Principal::Host { .. } => true,
        Principal::Recipient { recipient_id } => s
            .recipient(recipient_id)
            .is_some_and(|r| r.status != RecipientStatus::Created),
        Principal::InPersonHost { .. } | Principal::System => false,
    };
    if !allowed {
        return Err(not_permitted(cmd));
    }
    match access {
        Access::SenderViewed => {
            if !matches!(
                ctx.principal,
                Principal::Sender { .. } | Principal::Admin { .. }
            ) {
                return Err(not_permitted(cmd));
            }
            out.event(EventData::EnvelopeViewedBySender {});
        }
        Access::DocumentDownloaded { document, hash } => {
            if s.document(document).is_none() {
                return Err(WorkflowError::Unknown {
                    kind: ObjectKind::Document,
                    id: Some(document.clone()),
                });
            }
            out.event(EventData::DocumentDownloaded {
                document: DocumentHash {
                    document_id: document.clone(),
                    hash: *hash,
                },
            });
        }
        Access::CertificateDownloaded { hash } => {
            out.event(EventData::CertificateDownloaded { hash: *hash });
        }
        Access::AttachmentDownloaded { field, hash } => {
            // Only the file the field's value names: the value is the file's SHA-256.
            let names = s.fields.0.iter().any(|f| {
                f.id == *field
                    && matches!(&f.value, Some(FieldValue::Attachment(a)) if a.as_str() == hash.hex())
            });
            if !names {
                return Err(WorkflowError::Unknown {
                    kind: ObjectKind::Field,
                    id: Some(field.clone()),
                });
            }
            out.event(EventData::AttachmentDownloaded {
                field_id: field.clone(),
                hash: *hash,
            });
        }
    }
    Ok(())
}
