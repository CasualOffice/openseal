//! What must hold before an envelope is sent or a correction saved (`CS-WF-0004`):
//! `Envelope::validate_for_send` of docs/22 §10, returning every violation.

use casual_sign_audit::Timestamp;
use casual_sign_fields::check_for_send;
use casual_sign_model::{FieldType, RecipientType};

use crate::command::{Policy, limits};
use crate::engine::has_address;
use crate::error::{Problem, Violation};
use crate::state::EnvelopeState;

/// Whether a recipient of `rtype` may hold a field of `ft`.
fn field_allowed(rtype: RecipientType, ft: FieldType) -> bool {
    let display = matches!(ft, FieldType::Note | FieldType::Hyperlink);
    if rtype.signs() {
        return true;
    }
    match rtype {
        // Approvers approve or decline and may fill data, but never sign.
        RecipientType::Approver => !matches!(
            ft,
            FieldType::Signature | FieldType::Initials | FieldType::Stamp | FieldType::DateSigned
        ),
        _ => display,
    }
}

/// Every violation of `s` as it stands. `check_expiry` also refuses an expiry not after
/// `now` (at send, and when a correction sets one).
pub(crate) fn violations(
    s: &EnvelopeState,
    policy: &Policy,
    now: Timestamp,
    check_expiry: bool,
) -> Vec<Violation> {
    let mut v = Vec::new();
    let mut push = |object: Option<&casual_sign_model::Id>, problem| {
        v.push(Violation {
            object: object.cloned(),
            problem,
        });
    };
    if s.documents.is_empty() {
        push(None, Problem::NoDocuments);
    }
    let limits = [
        (
            "recipients",
            s.recipients.len(),
            policy.max_recipients.min(limits::MAX_RECIPIENTS),
        ),
        (
            "fields",
            s.fields.0.len(),
            policy.max_fields.min(limits::MAX_FIELDS),
        ),
        (
            "documents",
            s.documents.len(),
            policy.max_documents.min(limits::MAX_DOCUMENTS),
        ),
    ];
    for (what, count, limit) in limits {
        if count > limit {
            push(None, Problem::TooMany { what, count, limit });
        }
    }
    if !s.recipients.iter().any(|r| r.is_required()) {
        push(None, Problem::NoActingRecipient);
    }
    for d in &s.documents {
        if d.spec.pages == 0 || d.spec.pages > limits::MAX_PAGES {
            push(Some(d.id()), Problem::DocumentPages);
        }
    }
    for r in &s.recipients {
        // Someone earlier may supply the address (agent, intermediary, editor).
        let supplied = s.recipients.iter().any(|q| {
            q.spec.rtype.edits_recipients() && q.spec.routing_order < r.spec.routing_order
        });
        let needs = (r.status == casual_sign_model::RecipientStatus::Created && !supplied)
            || r.status.is_active();
        if needs && !has_address(r) {
            push(Some(r.id()), Problem::MissingAddress);
        }
        if let Some(w) = &r.spec.witness_for
            && !s.recipient(w).is_some_and(|q| q.spec.rtype.signs())
        {
            push(Some(r.id()), Problem::UnknownWitnessed);
        }
    }
    for f in &s.fields.0 {
        let Some(rid) = &f.recipient_id else {
            push(Some(&f.id), Problem::FieldWithoutRecipient);
            continue;
        };
        match s.recipient(rid) {
            None => push(Some(&f.id), Problem::FieldOnUnknownRecipient),
            Some(r) if !field_allowed(r.spec.rtype, f.field_type) => {
                push(Some(&f.id), Problem::FieldNotAllowedForType);
            }
            Some(_) => {}
        }
        match s.document(&f.document_id) {
            None => push(Some(&f.id), Problem::FieldOnUnknownDocument),
            Some(d) if f.placement.page() > d.spec.pages => {
                push(Some(&f.id), Problem::PageOutOfRange);
            }
            Some(_) => {}
        }
    }
    for issue in check_for_send(&s.fields.0) {
        push(Some(&issue.field_id), Problem::Field(issue.error));
    }
    if check_expiry && s.expires_at.is_some_and(|at| at <= now) {
        push(None, Problem::ExpiryInPast);
    }
    v
}
