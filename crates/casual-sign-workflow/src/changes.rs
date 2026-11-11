//! Edits to an envelope: a draft's, a correction's (docs/24 §6) and an editor's, agent's
//! or intermediary's edit of later recipients (docs/24 §3).

use std::collections::BTreeSet;

use casual_sign_audit::EventData;
use casual_sign_model::{EnvelopeStatus, Field, Id, RecipientStatus, RecipientType, RoutingOrder};

use crate::command::{Change, limits};
use crate::effect::EffectKind;
use crate::engine::Out;
use crate::error::{ObjectKind, Problem, Violation, WorkflowError};
use crate::state::{DocumentState, EnvelopeState, RecipientSpec, RecipientState};

/// Who is editing, which bounds what may change.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Scope {
    /// The sender, on a draft: anything.
    Draft,
    /// The sender, correcting a sent envelope: recipients not yet completed, their
    /// fields, documents, reminders and expiry.
    Correct,
    /// A recipient who edits later recipients.
    Recipient {
        /// Their position.
        index: usize,
        /// Their type.
        rtype: RecipientType,
        /// Their routing order.
        order: RoutingOrder,
    },
}

impl Scope {
    fn command(self) -> &'static str {
        match self {
            Self::Draft => "edit",
            Self::Correct => "correct",
            Self::Recipient { .. } => "recipient_edit",
        }
    }

    fn denied(self) -> WorkflowError {
        WorkflowError::NotPermitted {
            command: self.command(),
        }
    }
}

/// What a set of changes did, for the correction's impact.
#[derive(Debug, Default)]
pub(crate) struct ChangeReport {
    /// Paths changed, for `envelope.corrected`.
    pub(crate) changed: Vec<String>,
    /// Documents replaced or removed.
    pub(crate) touched_documents: BTreeSet<Id>,
    /// Completed recipients whose own fields changed: they act again.
    pub(crate) redo: BTreeSet<Id>,
    /// Active recipients whose address, delivery or authentication changed: re-invited.
    pub(crate) readdressed: BTreeSet<Id>,
    /// The expiry changed.
    pub(crate) expiry_changed: bool,
    /// The reminders changed.
    pub(crate) reminders_changed: bool,
}

fn too_many(what: &'static str, count: usize, limit: usize) -> WorkflowError {
    WorkflowError::Invalid {
        violations: vec![Violation {
            object: None,
            problem: Problem::TooMany { what, count, limit },
        }],
    }
}

fn unknown(kind: ObjectKind, id: &Id) -> WorkflowError {
    WorkflowError::Unknown {
        kind,
        id: Some(id.clone()),
    }
}

fn refused(scope: Scope, r: &RecipientState) -> WorkflowError {
    WorkflowError::NotAllowedForRecipient {
        command: scope.command(),
        recipient: r.id().clone(),
        status: r.status,
    }
}

/// A recipient no correction may change: completed, declined or handed over.
fn settled(r: &RecipientState) -> bool {
    matches!(
        r.status,
        RecipientStatus::Completed | RecipientStatus::Declined | RecipientStatus::Reassigned
    )
}

/// In a recipient's edit, the target must come later in routing and not be reached yet.
fn later_and_unreached(order: RoutingOrder, r: &RecipientState) -> bool {
    r.spec.routing_order > order && r.status == RecipientStatus::Created
}

/// May this scope touch a field owned by `owner`? Records a completed owner for redo.
fn check_field_owner(
    s: &EnvelopeState,
    scope: Scope,
    owner: Option<&Id>,
    report: &mut ChangeReport,
) -> Result<(), WorkflowError> {
    let Some(owner) = owner else {
        // A field without a recipient is a send violation, reported there.
        return match scope {
            Scope::Recipient { .. } => Err(scope.denied()),
            _ => Ok(()),
        };
    };
    let Some(r) = s.recipient(owner) else {
        return match scope {
            Scope::Recipient { .. } => Err(scope.denied()),
            _ => Ok(()),
        };
    };
    match scope {
        Scope::Draft => Ok(()),
        Scope::Correct => {
            match r.status {
                RecipientStatus::Completed => {
                    report.redo.insert(owner.clone());
                }
                RecipientStatus::Declined | RecipientStatus::Reassigned => {
                    return Err(refused(scope, r));
                }
                _ => {}
            }
            Ok(())
        }
        Scope::Recipient {
            index,
            rtype,
            order,
        } => {
            let own = s.recipients.get(index).is_some_and(|me| me.id() == owner);
            if rtype == RecipientType::Editor && (own || later_and_unreached(order, r)) {
                Ok(())
            } else {
                Err(scope.denied())
            }
        }
    }
}

/// Applies `changes` in order. On error nothing is kept (the caller drops the state).
pub(crate) fn apply_changes(
    s: &mut EnvelopeState,
    changes: &[Change],
    scope: Scope,
    out: &mut Out<'_>,
) -> Result<ChangeReport, WorkflowError> {
    if changes.len() > limits::MAX_CHANGES {
        return Err(too_many("changes", changes.len(), limits::MAX_CHANGES));
    }
    let policy = &out.ctx.policy;
    let max_recipients = policy.max_recipients.min(limits::MAX_RECIPIENTS);
    let max_fields = policy.max_fields.min(limits::MAX_FIELDS);
    let max_documents = policy.max_documents.min(limits::MAX_DOCUMENTS);
    let sender_only = |scope: Scope| match scope {
        Scope::Recipient { .. } => Err(scope.denied()),
        _ => Ok(()),
    };
    let mut report = ChangeReport::default();
    for change in changes {
        match change {
            Change::AddRecipient { recipient } => {
                if let Scope::Recipient { rtype, order, .. } = scope
                    && (!matches!(rtype, RecipientType::Editor | RecipientType::Intermediary)
                        || recipient.routing_order <= order)
                {
                    return Err(scope.denied());
                }
                if s.recipient(&recipient.id).is_some() {
                    return Err(WorkflowError::DuplicateId {
                        kind: ObjectKind::Recipient,
                        id: recipient.id.clone(),
                    });
                }
                if s.recipients.len() >= max_recipients {
                    return Err(too_many(
                        "recipients",
                        s.recipients.len().saturating_add(1),
                        max_recipients,
                    ));
                }
                s.recipients.push(RecipientState::new(recipient.clone()));
                report.changed.push(format!("recipients.{}", recipient.id));
            }
            Change::UpdateRecipient { recipient } => {
                let i = s
                    .recipient_index(&recipient.id)
                    .ok_or_else(|| unknown(ObjectKind::Recipient, &recipient.id))?;
                let existing = s
                    .recipients
                    .get(i)
                    .ok_or_else(|| unknown(ObjectKind::Recipient, &recipient.id))?;
                let old = existing.spec.clone();
                match scope {
                    Scope::Draft => {}
                    Scope::Correct => {
                        if settled(existing) || old.rtype != recipient.rtype {
                            return Err(refused(scope, existing));
                        }
                    }
                    Scope::Recipient { rtype, order, .. } => {
                        if !later_and_unreached(order, existing) {
                            return Err(scope.denied());
                        }
                        if allowed_update(rtype, &old, recipient) != *recipient {
                            return Err(scope.denied());
                        }
                    }
                }
                // A new address, delivery or authentication requirement: a link sent
                // under the old ones is revoked and a new one sent (WEB-06), so no
                // session opened before carries the recipient past the new checks.
                let readdress = old.email != recipient.email
                    || old.phone != recipient.phone
                    || old.delivery != recipient.delivery
                    || old.auth != recipient.auth;
                if readdress && existing.status.is_active() {
                    report.readdressed.insert(recipient.id.clone());
                }
                if let Some(r) = s.recipients.get_mut(i) {
                    r.spec = recipient.clone();
                }
                report.changed.push(format!("recipients.{}", recipient.id));
            }
            Change::RemoveRecipient { id } => {
                let i = s
                    .recipient_index(id)
                    .ok_or_else(|| unknown(ObjectKind::Recipient, id))?;
                let r = s
                    .recipients
                    .get(i)
                    .ok_or_else(|| unknown(ObjectKind::Recipient, id))?;
                match scope {
                    Scope::Draft => {}
                    Scope::Correct => {
                        if settled(r) {
                            return Err(refused(scope, r));
                        }
                    }
                    Scope::Recipient { rtype, order, .. } => {
                        if rtype != RecipientType::Editor || !later_and_unreached(order, r) {
                            return Err(scope.denied());
                        }
                    }
                }
                if r.status.is_active() {
                    out.effect(EffectKind::RevokeTokens {
                        recipient: id.clone(),
                    });
                }
                s.recipients.remove(i);
                s.fields.0.retain(|f| f.recipient_id.as_ref() != Some(id));
                report.changed.push(format!("recipients.{id}"));
            }
            Change::AddField { field } => {
                let field: &Field = &field.0;
                check_field_owner(s, scope, field.recipient_id.as_ref(), &mut report)?;
                if s.fields.0.iter().any(|f| f.id == field.id) {
                    return Err(WorkflowError::DuplicateId {
                        kind: ObjectKind::Field,
                        id: field.id.clone(),
                    });
                }
                if s.fields.0.len() >= max_fields {
                    return Err(too_many(
                        "fields",
                        s.fields.0.len().saturating_add(1),
                        max_fields,
                    ));
                }
                s.fields.0.push(field.clone());
                report.changed.push(format!("fields.{}", field.id));
            }
            Change::UpdateField { field } => {
                let field: &Field = &field.0;
                let i = s
                    .fields
                    .0
                    .iter()
                    .position(|f| f.id == field.id)
                    .ok_or_else(|| unknown(ObjectKind::Field, &field.id))?;
                let old_owner = s.fields.0.get(i).and_then(|f| f.recipient_id.clone());
                check_field_owner(s, scope, old_owner.as_ref(), &mut report)?;
                check_field_owner(s, scope, field.recipient_id.as_ref(), &mut report)?;
                if let Some(slot) = s.fields.0.get_mut(i) {
                    *slot = field.clone();
                }
                report.changed.push(format!("fields.{}", field.id));
            }
            Change::RemoveField { id } => {
                let i = s
                    .fields
                    .0
                    .iter()
                    .position(|f| f.id == *id)
                    .ok_or_else(|| unknown(ObjectKind::Field, id))?;
                let owner = s.fields.0.get(i).and_then(|f| f.recipient_id.clone());
                check_field_owner(s, scope, owner.as_ref(), &mut report)?;
                s.fields.0.remove(i);
                report.changed.push(format!("fields.{id}"));
            }
            Change::AddDocument { document } => {
                sender_only(scope)?;
                if s.document(&document.id).is_some() {
                    return Err(WorkflowError::DuplicateId {
                        kind: ObjectKind::Document,
                        id: document.id.clone(),
                    });
                }
                if s.documents.len() >= max_documents {
                    return Err(too_many(
                        "documents",
                        s.documents.len().saturating_add(1),
                        max_documents,
                    ));
                }
                let fixed = s.status != EnvelopeStatus::Draft;
                out.event(EventData::DocumentAdded {
                    document_id: document.id.clone(),
                    upload_hash: document.upload_hash,
                    bytes: document.bytes,
                });
                if let Some((report_hash, findings)) = document.admission {
                    out.event(EventData::DocumentAdmitted {
                        document_id: document.id.clone(),
                        report_hash,
                        findings,
                    });
                }
                if fixed {
                    out.event(EventData::DocumentFixed {
                        document_id: document.id.clone(),
                        delivered_hash: document.delivered_hash,
                        pages: document.pages,
                    });
                }
                s.documents.push(DocumentState {
                    spec: document.clone(),
                    fixed,
                });
                report.changed.push(format!("documents.{}", document.id));
            }
            Change::RemoveDocument { id } => {
                sender_only(scope)?;
                let i = s
                    .documents
                    .iter()
                    .position(|d| d.id() == id)
                    .ok_or_else(|| unknown(ObjectKind::Document, id))?;
                s.documents.remove(i);
                s.fields.0.retain(|f| f.document_id != *id);
                report.touched_documents.insert(id.clone());
                report.changed.push(format!("documents.{id}"));
            }
            Change::ReplaceDocument { document } => {
                sender_only(scope)?;
                let d = s
                    .documents
                    .iter_mut()
                    .find(|d| d.spec.id == document.id)
                    .ok_or_else(|| unknown(ObjectKind::Document, &document.id))?;
                out.event(EventData::DocumentAdded {
                    document_id: document.id.clone(),
                    upload_hash: document.upload_hash,
                    bytes: document.bytes,
                });
                if let Some((report_hash, findings)) = document.admission {
                    out.event(EventData::DocumentAdmitted {
                        document_id: document.id.clone(),
                        report_hash,
                        findings,
                    });
                }
                if d.fixed {
                    out.event(EventData::DocumentReplaced {
                        document_id: document.id.clone(),
                        previous_hash: d.spec.delivered_hash,
                        delivered_hash: document.delivered_hash,
                    });
                }
                d.spec = document.clone();
                report.touched_documents.insert(document.id.clone());
                report.changed.push(format!("documents.{}", document.id));
            }
            Change::SetSubject { subject } => {
                sender_only(scope)?;
                s.subject = subject.clone();
                report.changed.push("subject".to_owned());
            }
            Change::SetMessage { message } => {
                sender_only(scope)?;
                s.message = message.clone();
                report.changed.push("message".to_owned());
            }
            Change::SetExpiry { expires_at } => {
                sender_only(scope)?;
                s.expires_at = *expires_at;
                report.expiry_changed = true;
                report.changed.push("expires_at".to_owned());
            }
            Change::SetReminders { reminders } => {
                sender_only(scope)?;
                s.reminders = *reminders;
                report.reminders_changed = true;
                report.changed.push("reminders".to_owned());
            }
            Change::SetSigningOptions { options } => {
                sender_only(scope)?;
                s.options = *options;
                report.changed.push("signing_options".to_owned());
            }
            Change::SetSealProfile { profile } => {
                if !matches!(scope, Scope::Draft) {
                    return Err(WorkflowError::NotAllowed {
                        command: scope.command(),
                        status: s.status,
                    });
                }
                s.seal_profile = *profile;
                report.changed.push("seal_profile".to_owned());
            }
        }
    }
    Ok(report)
}

/// The update a recipient of `rtype` may make: `wanted`'s members it may change, the
/// rest kept from `old`. An agent names people; an intermediary also sets their
/// authentication; an editor changes anything but the id and type.
fn allowed_update(
    rtype: RecipientType,
    old: &RecipientSpec,
    wanted: &RecipientSpec,
) -> RecipientSpec {
    let mut next = old.clone();
    next.name = wanted.name.clone();
    next.email = wanted.email.clone();
    next.phone = wanted.phone.clone();
    next.delivery = wanted.delivery;
    match rtype {
        RecipientType::Agent => {}
        RecipientType::Intermediary => next.auth = wanted.auth.clone(),
        _ => {
            next = wanted.clone();
            next.id = old.id.clone();
            next.rtype = old.rtype;
        }
    }
    next
}
