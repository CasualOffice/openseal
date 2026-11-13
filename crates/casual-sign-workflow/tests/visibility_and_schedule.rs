//! Document visibility per recipient and scheduled sending (`WF-02`, docs/24 §2, §4),
//! each through the harness, which checks every invariant after every accepted command.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use casual_sign_audit::{ActorKind, EventData};
use casual_sign_model::{EnvelopeStatus, RecipientStatus, RecipientType};
use casual_sign_workflow::{
    Change, Command, Decision, EffectKind, Principal, Problem, Timer, WorkflowError, limits,
};
use common::*;

use RecipientType::{Signer, Viewer};

fn code<T: core::fmt::Debug>(r: Result<T, WorkflowError>) -> &'static str {
    r.unwrap_err().code()
}

fn problems(r: Result<Decision, WorkflowError>) -> Vec<Problem> {
    match r.unwrap_err() {
        WorkflowError::Invalid { violations } => {
            violations.into_iter().map(|v| v.problem).collect()
        }
        e => panic!("not a violation list: {e}"),
    }
}

fn hidden(
    mut r: casual_sign_workflow::RecipientSpec,
    docs: &[&str],
) -> casual_sign_workflow::RecipientSpec {
    r.excluded_documents = docs.iter().map(|d| id(d)).collect();
    r
}

/// A draft with `doc-1` and `doc-2`, r1 hidden `doc-2`, r2 seeing both; each signer
/// with a signature field on `doc-1`.
fn two_documents(hx: &mut Harness, r2_type: RecipientType) {
    hx.draft(&[
        hidden(recipient("r1", Signer, 1), &["doc-2"]),
        recipient("r2", r2_type, 2),
    ]);
    hx.ok(
        sender(),
        Command::Edit {
            changes: vec![Change::AddDocument {
                document: document("doc-2", 2, 3),
            }],
        },
    );
}

fn timer_of(d: &Decision, which: Timer) -> casual_sign_workflow::EffectId {
    d.effects
        .iter()
        .find(|e| matches!(e.kind, EffectKind::Schedule { timer, .. } if timer == which))
        .map(|e| e.id.clone())
        .expect("timer scheduled")
}

// Document visibility -------------------------------------------------------------------

#[test]
fn a_signer_records_only_the_documents_they_may_see() {
    let mut hx = Harness::new();
    two_documents(&mut hx, Signer);
    hx.send();
    let d = hx.sign("r1");
    let signed = d
        .events
        .iter()
        .find_map(|e| match &e.data {
            EventData::RecipientSigned { documents, .. } => Some(documents.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        signed
            .iter()
            .map(|d| d.document_id.as_str())
            .collect::<Vec<_>>(),
        ["doc-1"]
    );
    let r1 = hx.state().recipient(&id("r1")).unwrap();
    assert_eq!(r1.acted_documents, signed);
    // r2 sees both and records both.
    let d = hx.sign("r2");
    assert!(d.events.iter().any(|e| matches!(
        &e.data,
        EventData::RecipientSigned { documents, .. } if documents.len() == 2
    )));
}

#[test]
fn a_hidden_document_cannot_be_viewed_by_that_recipient() {
    let mut hx = Harness::new();
    two_documents(&mut hx, Signer);
    hx.send();
    hx.get_ready("r1");
    let delivered = hx
        .state()
        .document(&id("doc-2"))
        .unwrap()
        .spec
        .delivered_hash;
    let view = Command::ViewDocument {
        recipient: id("r1"),
        document: id("doc-2"),
        hash: delivered,
        pages_seen: vec![1],
    };
    let err = hx.run(as_recipient("r1"), view).unwrap_err();
    assert_eq!(err.code(), "CS-WF-0021");
    assert!(matches!(err, WorkflowError::DocumentHidden { .. }));
}

#[test]
fn a_viewer_completes_on_viewing_every_document_they_may_see() {
    let mut hx = Harness::new();
    hx.draft(&[
        recipient("r1", Signer, 1),
        hidden(recipient("v1", Viewer, 1), &["doc-2"]),
    ]);
    hx.ok(
        sender(),
        Command::Edit {
            changes: vec![Change::AddDocument {
                document: document("doc-2", 2, 3),
            }],
        },
    );
    hx.send();
    hx.get_ready("v1");
    let delivered = hx
        .state()
        .document(&id("doc-1"))
        .unwrap()
        .spec
        .delivered_hash;
    hx.ok(
        as_recipient("v1"),
        Command::ViewDocument {
            recipient: id("v1"),
            document: id("doc-1"),
            hash: delivered,
            pages_seen: vec![1, 2],
        },
    );
    assert_eq!(hx.rstatus("v1"), RecipientStatus::Completed);
}

#[test]
fn send_refuses_visibility_that_cannot_hold() {
    // A field on a document hidden from its recipient.
    let mut hx = Harness::new();
    hx.draft(&[
        hidden(recipient("r1", Signer, 1), &["doc-1"]),
        recipient("r2", Signer, 1),
    ]);
    hx.ok(
        sender(),
        Command::Edit {
            changes: vec![Change::AddDocument {
                document: document("doc-2", 2, 1),
            }],
        },
    );
    let err = hx.run(sender(), Command::Send).unwrap_err();
    let WorkflowError::Invalid { violations } = err else {
        panic!("not invalid");
    };
    let hidden_field = violations
        .iter()
        .find(|v| v.problem == Problem::FieldOnHiddenDocument)
        .expect("field on a hidden document refused");
    assert_eq!(hidden_field.code(), "CS-WF-0021");
    assert_eq!(hidden_field.object, Some(id("sig-r1")));

    // Hidden every document, or a document the envelope does not have.
    let mut hx = Harness::new();
    hx.create();
    hx.ok(
        sender(),
        Command::Edit {
            changes: vec![
                Change::AddDocument {
                    document: document("doc-1", 1, 1),
                },
                Change::AddRecipient {
                    recipient: hidden(recipient("v1", Viewer, 1), &["doc-1", "doc-9"]),
                },
                Change::AddRecipient {
                    recipient: recipient("r2", Signer, 1),
                },
            ],
        },
    );
    let found = problems(hx.run(sender(), Command::Send));
    assert!(found.contains(&Problem::NoVisibleDocument), "{found:?}");
    assert!(
        found.contains(&Problem::ExcludedUnknownDocument),
        "{found:?}"
    );
}

#[test]
fn replacing_a_document_a_completed_signer_never_saw_leaves_them_completed() {
    let mut hx = Harness::new();
    two_documents(&mut hx, Signer);
    hx.send();
    hx.sign("r1");
    hx.ok(
        sender(),
        Command::Correct {
            changes: vec![Change::ReplaceDocument {
                document: document("doc-2", 7, 3),
            }],
        },
    );
    assert_eq!(hx.rstatus("r1"), RecipientStatus::Completed);
    // Replacing the one they saw sends them back.
    hx.ok(
        sender(),
        Command::Correct {
            changes: vec![Change::ReplaceDocument {
                document: document("doc-1", 8, 2),
            }],
        },
    );
    assert_ne!(hx.rstatus("r1"), RecipientStatus::Completed);
}

#[test]
fn removing_a_document_drops_it_from_every_exclusion() {
    let mut hx = Harness::new();
    two_documents(&mut hx, Signer);
    hx.ok(
        sender(),
        Command::Edit {
            changes: vec![Change::RemoveDocument { id: id("doc-2") }],
        },
    );
    let r1 = hx.state().recipient(&id("r1")).unwrap();
    assert!(r1.spec.excluded_documents.is_empty());
    hx.send();
}

// Scheduled sending ---------------------------------------------------------------------

fn sendable(hx: &mut Harness) {
    hx.draft(&[recipient("r1", Signer, 1)]);
}

#[test]
fn a_scheduled_draft_sends_itself_when_its_time_comes() {
    let mut hx = Harness::new();
    sendable(&mut hx);
    let d = hx.ok(sender(), Command::ScheduleSend { at: Some(t(DAY)) });
    assert_eq!(hx.state().send_at, Some(t(DAY)));
    assert_eq!(hx.status(), EnvelopeStatus::Draft);
    assert!(d.events.iter().any(|e| matches!(
        &e.data,
        EventData::EnvelopeCorrected { changed } if changed == &["send_at"]
    )));
    let timer = timer_of(&d, Timer::ScheduledSend);
    assert!(d.effects.iter().any(|e| matches!(
        e.kind,
        EffectKind::Schedule { timer: Timer::ScheduledSend, at } if at == t(DAY)
    )));

    // A scheduled draft is not edited: it sends as it was scheduled.
    let edit = Command::Edit {
        changes: vec![Change::SetSubject {
            subject: text("Other"),
        }],
    };
    assert_eq!(code(hx.run(sender(), edit)), "CS-WF-0022");

    hx.now = DAY;
    let d = hx.ok(Principal::System, Command::TimerDue { timer });
    assert_eq!(hx.status(), EnvelopeStatus::Sent);
    assert_eq!(hx.state().send_at, None);
    assert_eq!(hx.state().sent_at, Some(t(DAY)));
    let sent = d
        .events
        .iter()
        .find(|e| matches!(e.data, EventData::EnvelopeSent { .. }))
        .expect("envelope.sent");
    assert_eq!(sent.actor.kind, ActorKind::System);
    assert_eq!(hx.rstatus("r1"), RecipientStatus::Sent);
}

#[test]
fn a_schedule_must_be_ahead_within_a_year_and_before_expiry() {
    let mut hx = Harness::new();
    sendable(&mut hx);
    hx.now = DAY;
    for at in [t(0), t(DAY)] {
        assert_eq!(
            code(hx.run(sender(), Command::ScheduleSend { at: Some(at) })),
            "CS-WF-0023"
        );
    }
    let year = i64::from(limits::MAX_SCHEDULE_DAYS) * DAY;
    assert_eq!(
        code(hx.run(
            sender(),
            Command::ScheduleSend {
                at: Some(t(DAY + year + 1))
            }
        )),
        "CS-WF-0023"
    );
    hx.ok(
        sender(),
        Command::ScheduleSend {
            at: Some(t(DAY + year)),
        },
    );
    hx.ok(sender(), Command::ScheduleSend { at: None });
    hx.ok(
        sender(),
        Command::Edit {
            changes: vec![Change::SetExpiry {
                expires_at: Some(t(3 * DAY)),
            }],
        },
    );
    assert_eq!(
        code(hx.run(
            sender(),
            Command::ScheduleSend {
                at: Some(t(3 * DAY))
            }
        )),
        "CS-WF-0023"
    );
    hx.ok(
        sender(),
        Command::ScheduleSend {
            at: Some(t(2 * DAY)),
        },
    );
}

#[test]
fn only_a_sendable_draft_is_scheduled() {
    let mut hx = Harness::new();
    hx.create();
    assert_eq!(
        code(hx.run(sender(), Command::ScheduleSend { at: Some(t(DAY)) })),
        "CS-WF-0004"
    );
    // Not the sender: not permitted.
    let mut hx = Harness::new();
    sendable(&mut hx);
    assert_eq!(
        code(hx.run(
            as_recipient("r1"),
            Command::ScheduleSend { at: Some(t(DAY)) }
        )),
        "CS-WF-0003"
    );
}

#[test]
fn cancelling_a_schedule_drops_its_timer_and_frees_the_draft() {
    let mut hx = Harness::new();
    sendable(&mut hx);
    let d = hx.ok(sender(), Command::ScheduleSend { at: Some(t(DAY)) });
    let timer = timer_of(&d, Timer::ScheduledSend);
    let d = hx.ok(sender(), Command::ScheduleSend { at: None });
    assert!(d.effects.iter().any(|e| matches!(
        &e.kind,
        EffectKind::Cancel { effects } if effects.contains(&timer)
    )));
    assert_eq!(hx.state().send_at, None);
    hx.ok(
        sender(),
        Command::Edit {
            changes: vec![Change::SetSubject {
                subject: text("Other"),
            }],
        },
    );
    // The old timer, if it still fires, does nothing.
    hx.now = DAY;
    let d = hx.ok(Principal::System, Command::TimerDue { timer });
    assert!(d.events.is_empty());
    assert_eq!(hx.status(), EnvelopeStatus::Draft);
}

#[test]
fn sending_by_hand_or_deleting_drops_the_schedule() {
    let mut hx = Harness::new();
    sendable(&mut hx);
    let d = hx.ok(sender(), Command::ScheduleSend { at: Some(t(DAY)) });
    let timer = timer_of(&d, Timer::ScheduledSend);
    let d = hx.send();
    assert!(d.effects.iter().any(|e| matches!(
        &e.kind,
        EffectKind::Cancel { effects } if effects.contains(&timer)
    )));
    assert_eq!(hx.state().send_at, None);

    let mut hx = Harness::new();
    sendable(&mut hx);
    let d = hx.ok(sender(), Command::ScheduleSend { at: Some(t(DAY)) });
    let timer = timer_of(&d, Timer::ScheduledSend);
    let d = hx.ok(sender(), Command::DeleteDraft);
    assert!(d.effects.iter().any(|e| matches!(
        &e.kind,
        EffectKind::Cancel { effects } if effects.contains(&timer)
    )));
}

#[test]
fn a_schedule_that_can_no_longer_send_is_dropped_and_recorded() {
    let mut hx = Harness::new();
    hx.draft(&[recipient("r1", Signer, 1), recipient("r2", Signer, 1)]);
    let d = hx.ok(sender(), Command::ScheduleSend { at: Some(t(DAY)) });
    let timer = timer_of(&d, Timer::ScheduledSend);
    // The account's limit fell below the envelope meanwhile.
    hx.policy.max_recipients = 1;
    hx.now = DAY;
    let d = hx.ok(Principal::System, Command::TimerDue { timer });
    assert_eq!(hx.status(), EnvelopeStatus::Draft);
    assert_eq!(hx.state().send_at, None);
    let e = d
        .events
        .iter()
        .find(|e| matches!(&e.data, EventData::EnvelopeCorrected { changed } if changed == &["send_at"]))
        .expect("dropped schedule recorded");
    assert_eq!(e.actor.kind, ActorKind::System);
}
