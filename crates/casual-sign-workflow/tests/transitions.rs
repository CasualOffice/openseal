//! One test per transition of docs/24, each through the harness, which checks every
//! invariant after every accepted command.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use casual_sign_audit::{AdoptionMethod, AuthMethod, Channel, EventData, MarkKind, Personal};
use casual_sign_model::{
    Delivery, EnvelopeStatus, FieldType, FieldValue, RecipientStatus, RecipientType,
    ReminderPolicy, SigningOptions, Text,
};
use casual_sign_workflow::{
    Access, Change, Command, Decision, EffectKind, Ersd, FieldEntry, InvitationKind, Principal,
    ReassignTo, SealFault, Timer, WorkflowError, decide,
};
use common::*;

use RecipientType::{Agent, Approver, Cc, Editor, InPersonSigner, Signer, Viewer};

fn invited(d: &Decision) -> Vec<String> {
    d.effects
        .iter()
        .filter_map(|e| match &e.kind {
            EffectKind::SendInvitation { recipient, .. } => Some(recipient.to_string()),
            _ => None,
        })
        .collect()
}

fn types(d: &Decision) -> Vec<String> {
    d.events.iter().map(|e| serde_type_name(&e.data)).collect()
}

fn code<T: core::fmt::Debug>(r: Result<T, WorkflowError>) -> &'static str {
    r.unwrap_err().code()
}

fn entry(fid: &str, value: FieldValue) -> FieldEntry {
    FieldEntry {
        field: id(fid),
        value: Personal(value),
    }
}

fn txt(s: &str) -> FieldValue {
    FieldValue::Text(Text::new(s).unwrap())
}

// Create, edit, send ------------------------------------------------------------------

#[test]
fn create_records_envelope_created_and_needs_no_state() {
    let mut hx = Harness::new();
    hx.create();
    assert_eq!(hx.status(), EnvelopeStatus::Draft);
    assert_eq!(hx.event_types, ["envelope.created"]);
    // Create on an existing envelope is not allowed; anything else without a state is
    // an unknown envelope.
    let c = Command::Create {
        envelope_id: id("env-1"),
        account_id: id("acct-1"),
        sender_user_id: id("sender"),
        subject: text("s"),
        message: text("m"),
    };
    assert_eq!(code(hx.run(sender(), c)), "CS-WF-0001");
    let ctx = hx.ctx(sender());
    assert_eq!(code(decide(None, &Command::Send, &ctx)), "CS-WF-0008");
}

#[test]
fn create_by_another_user_is_not_permitted() {
    let mut hx = Harness::new();
    let c = Command::Create {
        envelope_id: id("env-1"),
        account_id: id("acct-1"),
        sender_user_id: id("someone-else"),
        subject: text("s"),
        message: text("m"),
    };
    assert_eq!(code(hx.run(sender(), c)), "CS-WF-0003");
}

#[test]
fn draft_edits_record_uploads_and_changes() {
    let mut hx = Harness::new();
    hx.draft(&[recipient("r1", Signer, 1)]);
    assert_eq!(
        hx.event_types,
        [
            "envelope.created",
            "document.added",
            "document.admitted",
            "envelope.corrected"
        ]
    );
    // Duplicate ids are refused.
    let dup = Command::Edit {
        changes: vec![Change::AddRecipient {
            recipient: recipient("r1", Signer, 1),
        }],
    };
    assert_eq!(code(hx.run(sender(), dup)), "CS-WF-0010");
}

#[test]
fn send_refuses_an_invalid_envelope_with_every_violation() {
    let mut hx = Harness::new();
    hx.create();
    let err = hx.run(sender(), Command::Send).unwrap_err();
    assert_eq!(err.code(), "CS-WF-0004");
    let WorkflowError::Invalid { violations } = err else {
        panic!()
    };
    assert_eq!(violations.len(), 2, "no documents and no acting recipient");

    // Only a carbon copy, a field on a missing document, a viewer with a text field.
    hx.ok(
        sender(),
        Command::Edit {
            changes: vec![
                Change::AddDocument {
                    document: document("doc-1", 1, 1),
                },
                Change::AddRecipient {
                    recipient: recipient("cc", Cc, 1),
                },
                Change::AddRecipient {
                    recipient: recipient("v", Viewer, 1),
                },
                add_field(field("f1", "doc-9", "v", FieldType::Text, false)),
            ],
        },
    );
    let WorkflowError::Invalid { violations } = hx.run(sender(), Command::Send).unwrap_err() else {
        panic!()
    };
    let codes: Vec<_> = violations.iter().map(|v| v.code()).collect();
    assert!(codes.contains(&"CS-WF-0008"), "{codes:?}");
    assert!(codes.contains(&"CS-WF-0004"), "{codes:?}");
}

#[test]
fn send_fixes_documents_invites_the_first_step_and_schedules_timers() {
    let mut hx = Harness::new();
    hx.draft(&[recipient("r1", Signer, 1), recipient("r2", Signer, 2)]);
    hx.ok(
        sender(),
        Command::Edit {
            changes: vec![
                Change::SetExpiry {
                    expires_at: Some(t(10 * DAY)),
                },
                Change::SetReminders {
                    reminders: ReminderPolicy::new(2, 1).unwrap(),
                },
            ],
        },
    );
    let d = hx.send();
    assert_eq!(types(&d), ["envelope.sent", "document.fixed"]);
    assert_eq!(invited(&d), ["r1"]);
    assert_eq!(hx.status(), EnvelopeStatus::Sent);
    assert_eq!(hx.rstatus("r2"), RecipientStatus::Created);
    let timers: Vec<_> = hx.state().book.scheduled.iter().map(|t| t.timer).collect();
    assert_eq!(timers, [Timer::Expiry, Timer::Reminder]);
    assert!(hx.state().documents[0].fixed);
    // Not twice.
    assert_eq!(code(hx.run(sender(), Command::Send)), "CS-WF-0001");
}

#[test]
fn delete_draft_purges_it_and_nothing_follows() {
    let mut hx = Harness::new();
    hx.draft(&[recipient("r1", Signer, 1)]);
    let d = hx.ok(sender(), Command::DeleteDraft);
    assert_eq!(types(&d), ["envelope.purged"]);
    assert!(d.effects.iter().any(|e| e.kind == EffectKind::DeleteDraft));
    assert!(hx.state().purged);
    assert_eq!(code(hx.run(sender(), Command::Send)), "CS-WF-0001");
}

#[test]
fn delete_ended_takes_only_an_envelope_that_ended_without_completing_and_purges_nothing() {
    let mut hx = Harness::new();
    hx.draft(&[recipient("r1", Signer, 1)]);
    assert_eq!(code(hx.run(sender(), Command::DeleteEnded)), "CS-WF-0001");
    hx.send();
    assert_eq!(code(hx.run(sender(), Command::DeleteEnded)), "CS-WF-0001");
    hx.ok(sender(), Command::Void { reason: text("x") });
    assert_eq!(
        code(hx.run(as_recipient("r1"), Command::DeleteEnded)),
        "CS-WF-0003"
    );
    let d = hx.ok(sender(), Command::DeleteEnded);
    assert_eq!(types(&d), ["envelope.deleted"]);
    assert!(d.effects.is_empty());
    let s = hx.state();
    assert!(s.deleted_at.is_some() && !s.purged);
    assert_eq!(s.status, EnvelopeStatus::Voided);
    assert!(!s.recipients[0].spec.email.0.is_empty(), "nothing scrubbed");
    assert_eq!(code(hx.run(sender(), Command::DeleteEnded)), "CS-WF-0001");
    // An attachment download must name a file a field's value names.
    let c = Command::RecordAccess {
        access: Access::AttachmentDownloaded {
            field: id("sig-r1"),
            hash: h(3),
        },
    };
    assert_eq!(code(hx.run(sender(), c)), "CS-WF-0008");
}

// Routing -----------------------------------------------------------------------------

#[test]
fn sequential_routing_invites_each_step_after_the_last_completes() {
    let mut hx = Harness::new();
    hx.draft(&[recipient("r1", Signer, 1), recipient("r2", Signer, 2)]);
    hx.send();
    // r2 cannot act before their turn.
    assert_eq!(
        code(hx.run(
            as_recipient("r2"),
            Command::OpenLink {
                recipient: id("r2")
            }
        )),
        "CS-WF-0007"
    );
    let d = hx.sign("r1");
    assert_eq!(invited(&d), ["r2"]);
    assert_eq!(hx.rstatus("r2"), RecipientStatus::Sent);
    let d = hx.sign("r2");
    assert_eq!(hx.status(), EnvelopeStatus::Completing);
    assert!(types(&d).contains(&"envelope.completing".to_owned()));
    assert!(
        d.effects
            .iter()
            .any(|e| matches!(e.kind, EffectKind::SealEnvelope { .. }))
    );
}

#[test]
fn parallel_routing_invites_everyone_at_one_order() {
    let mut hx = Harness::new();
    hx.draft(&[recipient("a", Signer, 1), recipient("b", Signer, 1)]);
    let d = hx.send();
    assert_eq!(invited(&d), ["a", "b"]);
    hx.sign("b");
    assert_eq!(hx.status(), EnvelopeStatus::Sent);
    hx.sign("a");
    assert_eq!(hx.status(), EnvelopeStatus::Completing);
}

#[test]
fn mixed_routing_waits_for_every_required_recipient_of_lower_orders() {
    let mut hx = Harness::new();
    hx.draft(&[
        recipient("a1", Signer, 1),
        recipient("a2", Approver, 1),
        recipient("cc", Cc, 2),
        recipient("b", Signer, 3),
    ]);
    let d = hx.send();
    assert_eq!(invited(&d), ["a1", "a2"]);
    hx.sign("a1");
    assert_eq!(hx.rstatus("b"), RecipientStatus::Created);
    hx.get_ready("a2");
    let d = hx.ok(
        as_recipient("a2"),
        Command::Approve {
            recipient: id("a2"),
        },
    );
    assert_eq!(
        types(&d),
        [
            "recipient.approved",
            "recipient.completed",
            "recipient.completed"
        ],
        "the approver, then the carbon copy reached and completed"
    );
    // The carbon copy gets a copy and does not block order 3.
    assert_eq!(invited(&d), ["cc", "b"]);
    assert!(d.effects.iter().any(|e| matches!(
        e.kind,
        EffectKind::SendInvitation {
            invitation: InvitationKind::Copy,
            ..
        }
    )));
    assert_eq!(hx.rstatus("cc"), RecipientStatus::Completed);
    hx.sign("b");
    assert_eq!(hx.status(), EnvelopeStatus::Completing);
}

#[test]
fn delivered_means_everyone_reached_has_opened() {
    let mut hx = Harness::new();
    hx.draft(&[
        recipient("a", Signer, 1),
        recipient("b", Signer, 1),
        recipient("c", Signer, 2),
    ]);
    hx.send();
    hx.ok(as_recipient("a"), Command::OpenLink { recipient: id("a") });
    assert_eq!(hx.status(), EnvelopeStatus::Sent);
    hx.ok(as_recipient("b"), Command::OpenLink { recipient: id("b") });
    assert_eq!(hx.status(), EnvelopeStatus::Delivered);
    hx.sign("a");
    hx.sign("b");
    // c is reached and has not opened.
    assert_eq!(hx.status(), EnvelopeStatus::Sent);
    hx.ok(as_recipient("c"), Command::OpenLink { recipient: id("c") });
    assert_eq!(hx.status(), EnvelopeStatus::Delivered);
}

// Authentication and consent -----------------------------------------------------------

#[test]
fn authentication_gates_signing_and_locks_after_failures() {
    let mut hx = Harness::new();
    hx.draft(&[auth(&[AuthMethod::SmsOtp], recipient("r1", Signer, 1))]);
    hx.send();
    let r1 = || as_recipient("r1");
    hx.ok(
        r1(),
        Command::OpenLink {
            recipient: id("r1"),
        },
    );
    let adopt = Command::AdoptSignature {
        recipient: id("r1"),
        mark: MarkKind::Signature,
        method: AdoptionMethod::Draw,
        image_hash: h(1),
    };
    assert_eq!(code(hx.run(r1(), adopt.clone())), "CS-AUTH-0003");
    hx.ok(
        r1(),
        Command::ChallengeAuth {
            recipient: id("r1"),
            method: AuthMethod::SmsOtp,
        },
    );
    let fail = Command::AuthResult {
        recipient: id("r1"),
        method: AuthMethod::SmsOtp,
        passed: false,
    };
    hx.ok(r1(), fail.clone());
    hx.ok(r1(), fail.clone());
    let d = hx.ok(r1(), fail.clone());
    assert!(hx.state().recipient(&id("r1")).unwrap().auth_locked);
    assert!(
        d.effects
            .iter()
            .any(|e| matches!(e.kind, EffectKind::RevokeTokens { .. }))
    );
    assert_eq!(code(hx.run(r1(), fail)), "CS-AUTH-0004");
    // A method not required is refused.
    let other = Command::AuthResult {
        recipient: id("r1"),
        method: AuthMethod::Kba,
        passed: true,
    };
    assert_eq!(code(hx.run(r1(), other)), "CS-AUTH-0004");
    // The sender's resend unlocks.
    let d = hx.ok(sender(), Command::Resend { recipients: vec![] });
    assert_eq!(types(&d), ["envelope.corrected"]);
    assert_eq!(invited(&d), ["r1"]);
    hx.ok(
        r1(),
        Command::AuthResult {
            recipient: id("r1"),
            method: AuthMethod::SmsOtp,
            passed: true,
        },
    );
    assert_eq!(hx.rstatus("r1"), RecipientStatus::Authenticated);
    hx.ok(r1(), adopt);
}

#[test]
fn consent_to_the_current_disclosure_is_needed_before_viewing() {
    let mut hx = Harness::new();
    hx.policy.ersd = Some(Ersd {
        version: Text::new("v2").unwrap(),
        hash: h(77),
    });
    hx.draft(&[recipient("r1", Signer, 1)]);
    hx.send();
    let r1 = || as_recipient("r1");
    hx.ok(
        r1(),
        Command::OpenLink {
            recipient: id("r1"),
        },
    );
    let view = Command::ViewDocument {
        recipient: id("r1"),
        document: id("doc-1"),
        hash: h(101),
        pages_seen: vec![1, 2],
    };
    assert_eq!(code(hx.run(r1(), view.clone())), "CS-AUTH-0005");
    let old = Command::Consent {
        recipient: id("r1"),
        ersd_version: Text::new("v1").unwrap(),
        ersd_hash: h(76),
    };
    assert_eq!(code(hx.run(r1(), old)), "CS-AUTH-0005");
    hx.ok(
        r1(),
        Command::Consent {
            recipient: id("r1"),
            ersd_version: Text::new("v2").unwrap(),
            ersd_hash: h(77),
        },
    );
    let d = hx.ok(r1(), view);
    assert_eq!(types(&d), ["recipient.viewed_document"]);
}

#[test]
fn withdrawing_consent_declines() {
    let mut hx = Harness::new();
    hx.policy.ersd = Some(Ersd {
        version: Text::new("v1").unwrap(),
        hash: h(1),
    });
    hx.draft(&[recipient("r1", Signer, 1)]);
    hx.send();
    hx.get_ready("r1");
    let d = hx.ok(
        as_recipient("r1"),
        Command::WithdrawConsent {
            recipient: id("r1"),
        },
    );
    assert_eq!(
        types(&d),
        [
            "recipient.consent_withdrawn",
            "recipient.declined",
            "envelope.declined"
        ]
    );
    assert_eq!(hx.status(), EnvelopeStatus::Declined);
}

/// SEC-CER-01: consent outlives a correction that sends a new link and clears the
/// authentication passed under the old one. Whoever holds the new link must pass the
/// access code again before withdrawing consent (which declines the envelope), as for
/// declining itself.
#[test]
fn withdrawing_consent_needs_the_authentication_first() {
    let mut hx = Harness::new();
    hx.policy.ersd = Some(Ersd {
        version: Text::new("v1").unwrap(),
        hash: h(1),
    });
    hx.draft(&[auth(&[AuthMethod::AccessCode], recipient("r1", Signer, 1))]);
    hx.send();
    hx.get_ready("r1");
    let mut moved = auth(&[AuthMethod::AccessCode], recipient("r1", Signer, 1));
    moved.email = text("moved@example.test");
    hx.ok(
        sender(),
        Command::Correct {
            changes: vec![Change::UpdateRecipient { recipient: moved }],
        },
    );
    assert!(hx.state().recipient(&id("r1")).unwrap().consent.is_some());
    hx.ok(
        as_recipient("r1"),
        Command::OpenLink {
            recipient: id("r1"),
        },
    );
    let e = hx
        .run(
            as_recipient("r1"),
            Command::WithdrawConsent {
                recipient: id("r1"),
            },
        )
        .unwrap_err();
    assert!(matches!(e, WorkflowError::AuthRequired { .. }), "{e:?}");
    assert_eq!(hx.status(), EnvelopeStatus::Delivered);
    hx.ok(
        as_recipient("r1"),
        Command::AuthResult {
            recipient: id("r1"),
            method: AuthMethod::AccessCode,
            passed: true,
        },
    );
    hx.ok(
        as_recipient("r1"),
        Command::WithdrawConsent {
            recipient: id("r1"),
        },
    );
    assert_eq!(hx.status(), EnvelopeStatus::Declined);
}

#[test]
fn host_asserted_authentication_is_recorded_for_embedded_signers() {
    let mut hx = Harness::new();
    let mut r = auth(&[AuthMethod::HostAsserted], recipient("r1", Signer, 1));
    r.embedded_client_user_id = Some(id("crm-user-7"));
    r.delivery = Delivery::None;
    hx.draft(&[r]);
    let d = hx.send();
    assert!(d.effects.iter().any(|e| matches!(
        e.kind,
        EffectKind::SendInvitation {
            channel: Channel::Link,
            ..
        }
    )));
    let host = || Principal::Host {
        client_id: id("crm"),
    };
    hx.ok(
        host(),
        Command::OpenLink {
            recipient: id("r1"),
        },
    );
    // Only a host may assert.
    let assert_cmd = Command::HostAssertAuth {
        recipient: id("r1"),
        claim: text("SSO session 42"),
    };
    assert_eq!(
        code(hx.run(as_recipient("r1"), assert_cmd.clone())),
        "CS-WF-0003"
    );
    let d = hx.ok(host(), assert_cmd);
    assert_eq!(types(&d), ["auth.asserted_by_host"]);
    assert_eq!(hx.rstatus("r1"), RecipientStatus::Authenticated);
}

// Signing -----------------------------------------------------------------------------

#[test]
fn a_signature_value_needs_the_mark_adopted() {
    let mut hx = Harness::new();
    hx.draft(&[recipient("r1", Signer, 1)]);
    hx.send();
    hx.get_ready("r1");
    let c = Command::CompleteField {
        recipient: id("r1"),
        entry: entry("sig-r1", FieldValue::Signature(id("img"))),
    };
    assert_eq!(code(hx.run(as_recipient("r1"), c)), "CS-WF-0013");
    // Free-form signing (no signature field) still needs an adopted signature.
    let mut hx = Harness::new();
    hx.draft(&[recipient("r1", Approver, 1), recipient("r2", Signer, 1)]);
    hx.ok(
        sender(),
        Command::Edit {
            changes: vec![Change::RemoveField { id: id("sig-r2") }],
        },
    );
    hx.send();
    hx.get_ready("r2");
    let finish = Command::Finish {
        recipient: id("r2"),
        values: vec![],
    };
    assert_eq!(code(hx.run(as_recipient("r2"), finish)), "CS-WF-0013");
}

#[test]
fn finish_reruns_every_field_rule_and_stamps_server_values() {
    let mut hx = Harness::new();
    hx.draft(&[recipient("r1", Signer, 1), recipient("r2", Signer, 2)]);
    hx.ok(
        sender(),
        Command::Edit {
            changes: vec![
                add_field(field("company", "doc-1", "r1", FieldType::Text, true)),
                add_field(field("when", "doc-1", "r1", FieldType::DateSigned, false)),
                add_field(field("who", "doc-1", "r1", FieldType::Name, false)),
                add_field(field("theirs", "doc-1", "r2", FieldType::Text, true)),
            ],
        },
    );
    hx.send();
    hx.get_ready("r1");
    let r1 = || as_recipient("r1");
    hx.ok(
        r1(),
        Command::AdoptSignature {
            recipient: id("r1"),
            mark: MarkKind::Signature,
            method: AdoptionMethod::Upload,
            image_hash: h(3),
        },
    );
    // Another recipient's field is not editable.
    let theirs = Command::CompleteField {
        recipient: id("r1"),
        entry: entry("theirs", txt("x")),
    };
    assert_eq!(code(hx.run(r1(), theirs)), "CS-WF-0016");
    // Missing required text: the server says so with the field code.
    let sig = entry("sig-r1", FieldValue::Signature(id("img")));
    let finish = Command::Finish {
        recipient: id("r1"),
        values: vec![sig.clone()],
    };
    assert_eq!(code(hx.run(r1(), finish)), "CS-FLD-0001");
    hx.now = DAY / 2;
    let d = hx.ok(
        r1(),
        Command::Finish {
            recipient: id("r1"),
            values: vec![sig, entry("company", txt("Acme"))],
        },
    );
    assert_eq!(
        types(&d),
        [
            "recipient.field_completed",
            "recipient.field_completed",
            "recipient.signed",
            "recipient.completed"
        ]
    );
    let fields = &hx.state().fields.0;
    let value = |fid: &str| {
        fields
            .iter()
            .find(|f| f.id == id(fid))
            .unwrap()
            .value
            .clone()
    };
    assert_eq!(value("when"), Some(txt("2026-11-10")));
    assert_eq!(value("who"), Some(txt("Name r1")));
    let EventData::RecipientSigned {
        field_value_hashes, ..
    } = &d.events[2].data
    else {
        panic!()
    };
    assert_eq!(
        field_value_hashes.len(),
        4,
        "signature, company, date, name"
    );
}

#[test]
fn approvers_approve_and_never_sign() {
    let mut hx = Harness::new();
    hx.draft(&[recipient("ap", Approver, 1)]);
    hx.send();
    hx.get_ready("ap");
    let finish = Command::Finish {
        recipient: id("ap"),
        values: vec![],
    };
    assert_eq!(code(hx.run(as_recipient("ap"), finish)), "CS-WF-0001");
    let adopt = Command::AdoptSignature {
        recipient: id("ap"),
        mark: MarkKind::Signature,
        method: AdoptionMethod::Draw,
        image_hash: h(1),
    };
    assert_eq!(code(hx.run(as_recipient("ap"), adopt)), "CS-WF-0001");
    hx.ok(
        as_recipient("ap"),
        Command::Approve {
            recipient: id("ap"),
        },
    );
    assert_eq!(hx.status(), EnvelopeStatus::Completing);
}

#[test]
fn viewers_complete_by_viewing_every_document_to_the_end() {
    let mut hx = Harness::new();
    hx.draft(&[recipient("v", Viewer, 1)]);
    hx.ok(
        sender(),
        Command::Edit {
            changes: vec![Change::AddDocument {
                document: document("doc-2", 2, 3),
            }],
        },
    );
    hx.send();
    hx.get_ready("v");
    let v = || as_recipient("v");
    let finish = Command::Finish {
        recipient: id("v"),
        values: vec![],
    };
    assert_eq!(code(hx.run(v(), finish)), "CS-WF-0014");
    let wrong = Command::ViewDocument {
        recipient: id("v"),
        document: id("doc-1"),
        hash: h(1),
        pages_seen: vec![2],
    };
    assert_eq!(code(hx.run(v(), wrong)), "CS-WF-0015");
    let past_end = Command::ViewDocument {
        recipient: id("v"),
        document: id("doc-1"),
        hash: h(101),
        pages_seen: vec![3],
    };
    assert_eq!(code(hx.run(v(), past_end)), "CS-WF-0015");
    hx.ok(
        v(),
        Command::ViewDocument {
            recipient: id("v"),
            document: id("doc-1"),
            hash: h(101),
            pages_seen: vec![1, 2],
        },
    );
    assert_eq!(hx.rstatus("v"), RecipientStatus::Delivered);
    let d = hx.ok(
        v(),
        Command::ViewDocument {
            recipient: id("v"),
            document: id("doc-2"),
            hash: h(102),
            pages_seen: vec![3],
        },
    );
    assert!(types(&d).contains(&"recipient.completed".to_owned()));
    assert_eq!(hx.status(), EnvelopeStatus::Completing);
}

#[test]
fn in_person_signers_are_hosted_by_a_staff_user() {
    let mut hx = Harness::new();
    hx.draft(&[recipient("ip", InPersonSigner, 1)]);
    hx.send();
    // The signer's own link does not work for an in-person signer.
    assert_eq!(
        code(hx.run(
            as_recipient("ip"),
            Command::OpenLink {
                recipient: id("ip")
            }
        )),
        "CS-WF-0003"
    );
    let host = Principal::InPersonHost {
        user_id: id("clerk"),
    };
    let d = hx.ok(
        host,
        Command::HostInPerson {
            recipient: id("ip"),
        },
    );
    assert_eq!(types(&d), ["recipient.in_person_hosted"]);
    hx.sign("ip");
    assert_eq!(hx.status(), EnvelopeStatus::Completing);
    let actor = &hx.chain.events().last().unwrap().event.actor;
    assert_eq!(actor.id, None, "completing is the platform's");
}

// Decline, reassign, finish later -------------------------------------------------------

#[test]
fn decline_ends_the_envelope_and_cancels_everything_pending() {
    let mut hx = Harness::new();
    hx.draft(&[recipient("r1", Signer, 1), recipient("r2", Signer, 2)]);
    hx.ok(
        sender(),
        Command::Edit {
            changes: vec![
                Change::SetExpiry {
                    expires_at: Some(t(5 * DAY)),
                },
                Change::SetReminders {
                    reminders: ReminderPolicy::new(1, 1).unwrap(),
                },
            ],
        },
    );
    hx.send();
    hx.sign("r1");
    hx.get_ready("r2");
    let pending = hx.state().pending_effects();
    assert_eq!(pending.len(), 2);
    let d = hx.ok(
        as_recipient("r2"),
        Command::Decline {
            recipient: id("r2"),
            reason: Some(text("terms")),
        },
    );
    assert_eq!(types(&d), ["recipient.declined", "envelope.declined"]);
    assert_eq!(hx.status(), EnvelopeStatus::Declined);
    assert!(d.effects.iter().any(|e| e.kind
        == EffectKind::Cancel {
            effects: pending.clone()
        }));
    // r1, who signed, hears of it.
    assert!(d.effects.iter().any(|e| matches!(
        &e.kind,
        EffectKind::NotifyRecipients { recipients, .. } if recipients.contains(&id("r1"))
    )));
    // The old timers are now no-ops with no event.
    hx.now = 5 * DAY;
    let d = hx.ok(
        Principal::System,
        Command::TimerDue {
            timer: pending[0].clone(),
        },
    );
    assert!(d.events.is_empty() && d.effects.is_empty());
    // Nothing moves a declined envelope.
    assert_eq!(
        code(hx.run(sender(), Command::Void { reason: text("x") })),
        "CS-WF-0001"
    );
}

#[test]
fn signing_options_can_turn_off_decline_reassign_and_finish_later() {
    let mut hx = Harness::new();
    hx.draft(&[recipient("r1", Signer, 1)]);
    hx.ok(
        sender(),
        Command::Edit {
            changes: vec![Change::SetSigningOptions {
                options: SigningOptions {
                    allow_reassign: false,
                    allow_decline: false,
                    allow_finish_later: false,
                    capture_location: false,
                },
            }],
        },
    );
    hx.send();
    hx.get_ready("r1");
    let r1 = || as_recipient("r1");
    let decline = Command::Decline {
        recipient: id("r1"),
        reason: None,
    };
    let later = Command::FinishLater {
        recipient: id("r1"),
    };
    let reassign = Command::Reassign {
        recipient: id("r1"),
        to: ReassignTo {
            id: id("r9"),
            name: text("New"),
            email: text("new@example.test"),
            phone: None,
            delivery: None,
        },
        reason: None,
    };
    for c in [decline, later, reassign] {
        assert_eq!(code(hx.run(r1(), c)), "CS-WF-0012");
    }
}

#[test]
fn finish_later_is_recorded() {
    let mut hx = Harness::new();
    hx.draft(&[recipient("r1", Signer, 1)]);
    hx.send();
    hx.get_ready("r1");
    let d = hx.ok(
        as_recipient("r1"),
        Command::FinishLater {
            recipient: id("r1"),
        },
    );
    assert_eq!(types(&d), ["recipient.finish_later"]);
    assert!(hx.state().recipient(&id("r1")).unwrap().finish_later);
    hx.sign("r1");
    assert!(!hx.state().recipient(&id("r1")).unwrap().finish_later);
}

#[test]
fn reassign_hands_over_at_the_same_routing_order() {
    let mut hx = Harness::new();
    hx.draft(&[recipient("r1", Signer, 1), recipient("r2", Signer, 2)]);
    hx.send();
    hx.get_ready("r1");
    let d = hx.ok(
        as_recipient("r1"),
        Command::Reassign {
            recipient: id("r1"),
            to: ReassignTo {
                id: id("r1b"),
                name: text("Deputy"),
                email: text("deputy@example.test"),
                phone: None,
                delivery: None,
            },
            reason: Some(text("on leave")),
        },
    );
    assert_eq!(types(&d), ["recipient.reassigned"]);
    assert_eq!(invited(&d), ["r1b"]);
    assert_eq!(hx.rstatus("r1"), RecipientStatus::Reassigned);
    assert_eq!(hx.rstatus("r2"), RecipientStatus::Created);
    let sig = hx
        .state()
        .fields
        .0
        .iter()
        .find(|f| f.id == id("sig-r1"))
        .unwrap();
    assert_eq!(sig.recipient_id, Some(id("r1b")));
    hx.sign("r1b");
    assert_eq!(hx.rstatus("r2"), RecipientStatus::Sent);
    hx.sign("r2");
    assert_eq!(hx.status(), EnvelopeStatus::Completing);
}

// Agents, intermediaries, editors --------------------------------------------------------

#[test]
fn an_agent_names_later_recipients_then_completes() {
    let mut hx = Harness::new();
    let mut later = recipient("r2", Signer, 2);
    later.email = text("");
    hx.draft(&[recipient("ag", Agent, 1), later.clone()]);
    hx.send();
    hx.get_ready("ag");
    let ag = || as_recipient("ag");
    let finish = Command::Finish {
        recipient: id("ag"),
        values: vec![],
    };
    assert_eq!(code(hx.run(ag(), finish.clone())), "CS-WF-0005");
    // An agent may not change authentication.
    let mut bad = later.clone();
    bad.email = text("r2@example.test");
    bad.auth = vec![AuthMethod::Kba];
    let edit = |r| Command::RecipientEdit {
        recipient: id("ag"),
        changes: vec![Change::UpdateRecipient { recipient: r }],
    };
    assert_eq!(code(hx.run(ag(), edit(bad))), "CS-WF-0003");
    later.email = text("r2@example.test");
    let d = hx.ok(ag(), edit(later));
    assert_eq!(types(&d), ["envelope.corrected"]);
    let d = hx.ok(ag(), finish);
    assert_eq!(invited(&d), ["r2"]);
}

#[test]
fn an_editor_adds_fields_for_later_recipients_but_not_earlier_ones() {
    let mut hx = Harness::new();
    hx.draft(&[
        recipient("r0", Signer, 1),
        recipient("ed", Editor, 2),
        recipient("r2", Signer, 3),
    ]);
    hx.send();
    hx.sign("r0");
    hx.get_ready("ed");
    let ed = || as_recipient("ed");
    let add = |fid: &str, rid: &str| Command::RecipientEdit {
        recipient: id("ed"),
        changes: vec![add_field(field(fid, "doc-1", rid, FieldType::Text, false))],
    };
    assert_eq!(code(hx.run(ed(), add("x0", "r0"))), "CS-WF-0003");
    hx.ok(ed(), add("x2", "r2"));
    assert!(hx.state().fields.0.iter().any(|f| f.id == id("x2")));
}

// Correct, void, resend, remind ------------------------------------------------------------

#[test]
fn correcting_an_active_recipients_email_revokes_and_reinvites() {
    let mut hx = Harness::new();
    hx.draft(&[recipient("r1", Signer, 1)]);
    hx.send();
    hx.ok(
        as_recipient("r1"),
        Command::OpenLink {
            recipient: id("r1"),
        },
    );
    let mut r = recipient("r1", Signer, 1);
    r.email = text("fixed@example.test");
    let d = hx.ok(
        sender(),
        Command::Correct {
            changes: vec![Change::UpdateRecipient { recipient: r }],
        },
    );
    assert_eq!(types(&d), ["envelope.corrected"]);
    assert_eq!(invited(&d), ["r1"]);
    assert!(d.effects.iter().any(|e| e.kind
        == EffectKind::RevokeTokens {
            recipient: id("r1")
        }));
    assert_eq!(hx.rstatus("r1"), RecipientStatus::Sent);
}

#[test]
fn correcting_an_active_recipients_authentication_revokes_and_reinvites() {
    // WEB-06: a link opened under the old requirements must not carry the recipient
    // past the new ones; the old link is revoked and a new one sent.
    let mut hx = Harness::new();
    hx.draft(&[recipient("r1", Signer, 1), recipient("r2", Signer, 2)]);
    hx.send();
    hx.ok(
        as_recipient("r1"),
        Command::OpenLink {
            recipient: id("r1"),
        },
    );
    let r = auth(&[AuthMethod::SmsOtp], recipient("r1", Signer, 1));
    let d = hx.ok(
        sender(),
        Command::Correct {
            changes: vec![Change::UpdateRecipient { recipient: r }],
        },
    );
    assert_eq!(invited(&d), ["r1"]);
    assert!(d.effects.iter().any(|e| e.kind
        == EffectKind::RevokeTokens {
            recipient: id("r1")
        }));
    assert_eq!(hx.rstatus("r1"), RecipientStatus::Sent);
    // A name change alone keeps the link, and a recipient not yet reached has none.
    let mut renamed = auth(&[AuthMethod::SmsOtp], recipient("r1", Signer, 1));
    renamed.name = text("Renamed");
    let mut later = recipient("r2", Signer, 2);
    later.email = text("later@example.test");
    let d = hx.ok(
        sender(),
        Command::Correct {
            changes: vec![
                Change::UpdateRecipient { recipient: renamed },
                Change::UpdateRecipient { recipient: later },
            ],
        },
    );
    assert!(invited(&d).is_empty());
    assert!(
        !d.effects
            .iter()
            .any(|e| matches!(e.kind, EffectKind::RevokeTokens { .. }))
    );
}

#[test]
fn replacing_a_signed_document_sends_its_signers_back() {
    let mut hx = Harness::new();
    hx.draft(&[recipient("r1", Signer, 1), recipient("r2", Signer, 2)]);
    hx.send();
    hx.sign("r1");
    hx.ok(
        as_recipient("r2"),
        Command::OpenLink {
            recipient: id("r2"),
        },
    );
    let d = hx.ok(
        sender(),
        Command::Correct {
            changes: vec![Change::ReplaceDocument {
                document: document("doc-1", 9, 2),
            }],
        },
    );
    assert_eq!(
        types(&d),
        [
            "document.added",
            "document.admitted",
            "document.replaced",
            "envelope.corrected"
        ]
    );
    // r1 signs again; r2 is no longer in turn and waits.
    assert_eq!(hx.rstatus("r1"), RecipientStatus::Sent);
    assert_eq!(hx.rstatus("r2"), RecipientStatus::Created);
    assert_eq!(invited(&d), ["r1"]);
    hx.sign("r1");
    hx.sign("r2");
    assert_eq!(hx.status(), EnvelopeStatus::Completing);
    // The earlier signing stays in the chain.
    let signed = hx
        .event_types
        .iter()
        .filter(|t| *t == "recipient.signed")
        .count();
    assert_eq!(signed, 3);
}

#[test]
fn correction_cannot_touch_settled_recipients_or_the_seal_profile() {
    let mut hx = Harness::new();
    hx.draft(&[recipient("r1", Signer, 1), recipient("r2", Signer, 2)]);
    hx.send();
    hx.sign("r1");
    let c = Command::Correct {
        changes: vec![Change::RemoveRecipient { id: id("r1") }],
    };
    assert_eq!(code(hx.run(sender(), c)), "CS-WF-0001");
    let c = Command::Correct {
        changes: vec![Change::SetSealProfile {
            profile: casual_sign_model::SealProfile::PadesBLta,
        }],
    };
    assert_eq!(code(hx.run(sender(), c)), "CS-WF-0001");
    // A correction that leaves nobody to act is refused.
    let c = Command::Correct {
        changes: vec![Change::RemoveRecipient { id: id("r2") }],
    };
    let r = hx.run(sender(), c);
    assert!(r.is_ok(), "removing the last open signer completes: {r:?}");
    assert_eq!(hx.status(), EnvelopeStatus::Completing);
}

#[test]
fn void_is_for_sent_envelopes_with_a_reason() {
    let mut hx = Harness::new();
    hx.draft(&[recipient("r1", Signer, 1)]);
    assert_eq!(
        code(hx.run(sender(), Command::Void { reason: text("x") })),
        "CS-WF-0001"
    );
    hx.send();
    assert_eq!(
        code(hx.run(as_recipient("r1"), Command::Void { reason: text("x") })),
        "CS-WF-0003"
    );
    let d = hx.ok(
        Principal::Admin {
            user_id: id("admin"),
        },
        Command::Void {
            reason: text("wrong file"),
        },
    );
    assert_eq!(types(&d), ["envelope.voided"]);
    assert_eq!(hx.status(), EnvelopeStatus::Voided);
    assert!(d.effects.iter().any(|e| e.kind
        == EffectKind::RevokeTokens {
            recipient: id("r1")
        }));
}

#[test]
fn bounce_then_resend() {
    let mut hx = Harness::new();
    hx.draft(&[recipient("r1", Signer, 1)]);
    hx.send();
    let d = hx.ok(
        Principal::System,
        Command::InvitationDispatched {
            recipient: id("r1"),
            channel: Channel::Email,
        },
    );
    assert_eq!(types(&d), ["invitation.sent"]);
    let d = hx.ok(
        Principal::System,
        Command::InvitationBounced {
            recipient: id("r1"),
            channel: Channel::Email,
        },
    );
    assert_eq!(types(&d), ["invitation.bounced"]);
    assert_eq!(hx.rstatus("r1"), RecipientStatus::AutoResponded);
    // Only the system reports deliveries.
    let c = Command::InvitationBounced {
        recipient: id("r1"),
        channel: Channel::Email,
    };
    assert_eq!(code(hx.run(sender(), c)), "CS-WF-0003");
    hx.ok(
        sender(),
        Command::Resend {
            recipients: vec![id("r1")],
        },
    );
    assert_eq!(hx.rstatus("r1"), RecipientStatus::Sent);
}

#[test]
fn reminders_fire_and_reschedule() {
    let mut hx = Harness::new();
    hx.draft(&[recipient("r1", Signer, 1), recipient("r2", Signer, 2)]);
    hx.ok(
        sender(),
        Command::Edit {
            changes: vec![Change::SetReminders {
                reminders: ReminderPolicy::new(2, 3).unwrap(),
            }],
        },
    );
    hx.send();
    let timer = hx.state().book.scheduled[0].clone();
    assert_eq!(timer.at, t(2 * DAY));
    hx.now = 2 * DAY;
    let d = hx.ok(
        Principal::System,
        Command::TimerDue {
            timer: timer.id.clone(),
        },
    );
    assert!(d.events.is_empty());
    let reminded: Vec<_> = d
        .effects
        .iter()
        .filter(|e| matches!(e.kind, EffectKind::SendReminder { .. }))
        .collect();
    assert_eq!(reminded.len(), 1, "only the active recipient");
    assert_eq!(hx.state().book.scheduled[0].at, t(5 * DAY));
    // The same timer again is a no-op.
    let d = hx.ok(Principal::System, Command::TimerDue { timer: timer.id });
    assert!(d.effects.is_empty());
    let d = hx.ok(sender(), Command::Remind);
    assert_eq!(d.effects.len(), 1);
    let d = hx.ok(
        Principal::System,
        Command::ReminderDispatched {
            recipient: id("r1"),
            channel: Channel::Email,
        },
    );
    assert_eq!(types(&d), ["reminder.sent"]);
}

#[test]
fn expiry_fires_only_when_due() {
    let mut hx = Harness::new();
    hx.policy.expiry_warning_days = 1;
    hx.draft(&[recipient("r1", Signer, 1)]);
    hx.ok(
        sender(),
        Command::Edit {
            changes: vec![Change::SetExpiry {
                expires_at: Some(t(3 * DAY)),
            }],
        },
    );
    hx.send();
    let timers = hx.state().book.scheduled.clone();
    assert_eq!(timers[1].timer, Timer::ExpiryWarning);
    assert_eq!(timers[1].at, t(2 * DAY));
    hx.now = DAY;
    let d = hx.ok(Principal::System, Command::Expire);
    assert!(d.events.is_empty(), "not yet due");
    hx.now = 2 * DAY;
    let d = hx.ok(
        Principal::System,
        Command::TimerDue {
            timer: timers[1].id.clone(),
        },
    );
    assert!(
        d.effects
            .iter()
            .any(|e| matches!(e.kind, EffectKind::SendExpiryWarning { .. }))
    );
    hx.now = 3 * DAY;
    let d = hx.ok(
        Principal::System,
        Command::TimerDue {
            timer: timers[0].id.clone(),
        },
    );
    assert_eq!(types(&d), ["envelope.expired"]);
    assert_eq!(hx.status(), EnvelopeStatus::Expired);
    assert!(hx.state().book.scheduled.is_empty());
}

#[test]
fn correcting_the_expiry_replaces_its_timer() {
    let mut hx = Harness::new();
    hx.draft(&[recipient("r1", Signer, 1)]);
    hx.ok(
        sender(),
        Command::Edit {
            changes: vec![Change::SetExpiry {
                expires_at: Some(t(3 * DAY)),
            }],
        },
    );
    hx.send();
    let old = hx.state().book.scheduled[0].id.clone();
    let d = hx.ok(
        sender(),
        Command::Correct {
            changes: vec![Change::SetExpiry {
                expires_at: Some(t(9 * DAY)),
            }],
        },
    );
    assert!(d.effects.iter().any(|e| e.kind
        == EffectKind::Cancel {
            effects: vec![old.clone()]
        }));
    hx.now = 3 * DAY;
    let d = hx.ok(Principal::System, Command::TimerDue { timer: old });
    assert!(d.events.is_empty());
    assert_eq!(hx.status(), EnvelopeStatus::Sent);
    // An expiry in the past is refused.
    let c = Command::Correct {
        changes: vec![Change::SetExpiry {
            expires_at: Some(t(DAY)),
        }],
    };
    assert_eq!(code(hx.run(sender(), c)), "CS-WF-0004");
}

// Sealing ---------------------------------------------------------------------------------

fn completing() -> Harness {
    let mut hx = Harness::new();
    hx.draft(&[recipient("r1", Signer, 1), recipient("cc", Cc, 2)]);
    hx.send();
    hx.sign("r1");
    assert_eq!(hx.status(), EnvelopeStatus::Completing);
    hx
}

#[test]
fn completed_needs_a_verified_seal_of_every_document_as_delivered() {
    let mut hx = completing();
    let job = hx.state().book.seal_job.clone().unwrap();
    let seal = |docs| Command::SealSucceeded {
        job: job.clone(),
        documents: docs,
    };
    let honest = sealed(hx.state());
    let fault = |hx: &mut Harness, c| match hx.run(Principal::System, c).unwrap_err() {
        WorkflowError::SealNotProven { fault } => fault,
        e => panic!("{e}"),
    };
    let mut unverified = honest.clone();
    unverified[0].verified = false;
    assert_eq!(fault(&mut hx, seal(unverified)), SealFault::NotVerified);
    assert_eq!(fault(&mut hx, seal(vec![])), SealFault::MissingDocument);
    let mut other_input = honest.clone();
    other_input[0].delivered_hash = h(1);
    assert_eq!(fault(&mut hx, seal(other_input)), SealFault::InputMismatch);
    let mut twice = honest.clone();
    twice.push(honest[0].clone());
    assert_eq!(fault(&mut hx, seal(twice)), SealFault::UnexpectedDocument);
    let wrong_job = Command::SealSucceeded {
        job: casual_sign_workflow::EffectId {
            command: id("nope"),
            index: 0,
        },
        documents: honest.clone(),
    };
    assert_eq!(fault(&mut hx, wrong_job), SealFault::UnknownJob);
    assert_eq!(code(hx.run(sender(), seal(honest.clone()))), "CS-WF-0003");

    let d = hx.seal();
    assert_eq!(
        types(&d),
        [
            "document.flattened",
            "document.sealed",
            "envelope.completed"
        ]
    );
    assert_eq!(hx.status(), EnvelopeStatus::Completed);
    assert!(d.effects.iter().any(|e| matches!(
        &e.kind,
        EffectKind::SendCompletionCopies { recipients } if recipients.len() == 2
    )));
    // Terminal.
    assert_eq!(code(hx.run(Principal::System, seal(honest))), "CS-WF-0001");
}

#[test]
fn a_failed_seal_is_retried_with_an_alert() {
    let mut hx = completing();
    let job = hx.state().book.seal_job.clone().unwrap();
    let d = hx.ok(
        Principal::System,
        Command::SealFailed {
            job: job.clone(),
            code: Text::new("CS-SEAL-0003").unwrap(),
        },
    );
    assert!(d.events.is_empty());
    assert!(
        d.effects
            .iter()
            .any(|e| matches!(e.kind, EffectKind::AlertOperator { .. }))
    );
    assert_eq!(hx.status(), EnvelopeStatus::Completing);
    let retry = hx.state().book.seal_job.clone().unwrap();
    assert_ne!(retry, job);
    // The old job's late success is refused; the retry's is accepted.
    let late = Command::SealSucceeded {
        job,
        documents: sealed(hx.state()),
    };
    assert_eq!(code(hx.run(Principal::System, late)), "CS-WF-0009");
    hx.seal();
    assert_eq!(hx.status(), EnvelopeStatus::Completed);
}

#[test]
fn completing_cannot_be_voided_or_corrected() {
    let mut hx = completing();
    assert_eq!(
        code(hx.run(sender(), Command::Void { reason: text("x") })),
        "CS-WF-0001"
    );
    let c = Command::Correct { changes: vec![] };
    assert_eq!(code(hx.run(sender(), c)), "CS-WF-0001");
}

// Purge, access, idempotency, concurrency, permissions -----------------------------------------

#[test]
fn purge_is_for_terminal_envelopes_and_scrubs_personal_data() {
    let mut hx = completing();
    let purge = Command::Purge {
        policy: Text::new("retention-7y").unwrap(),
    };
    assert_eq!(code(hx.run(Principal::System, purge.clone())), "CS-WF-0001");
    hx.seal();
    assert_eq!(code(hx.run(sender(), purge.clone())), "CS-WF-0003");
    let d = hx.ok(Principal::System, purge);
    assert_eq!(types(&d), ["envelope.purged"]);
    let s = hx.state();
    assert!(s.purged && s.status == EnvelopeStatus::Completed);
    assert!(s.recipients.iter().all(|r| r.spec.email.0.is_empty()));
    assert!(s.fields.0.iter().all(|f| f.value.is_none()));
    assert!(
        !s.sealed.is_empty(),
        "the sealed hashes are the tombstone's"
    );
    let access = Command::RecordAccess {
        access: Access::SenderViewed,
    };
    assert_eq!(code(hx.run(sender(), access)), "CS-WF-0001");
}

#[test]
fn access_is_recorded_without_changing_the_envelope() {
    let mut hx = completing();
    hx.seal();
    let v = hx.state().version;
    let d = hx.ok(
        sender(),
        Command::RecordAccess {
            access: Access::SenderViewed,
        },
    );
    assert_eq!(types(&d), ["envelope.viewed_by_sender"]);
    let d = hx.ok(
        as_recipient("r1"),
        Command::RecordAccess {
            access: Access::DocumentDownloaded {
                document: id("doc-1"),
                hash: h(220),
            },
        },
    );
    assert_eq!(types(&d), ["document.downloaded"]);
    assert_eq!(hx.state().version, v);
    let c = Command::RecordAccess {
        access: Access::SenderViewed,
    };
    assert_eq!(code(hx.run(as_recipient("r1"), c)), "CS-WF-0003");
}

#[test]
fn a_command_id_applies_once() {
    let mut hx = Harness::new();
    hx.draft(&[recipient("r1", Signer, 1)]);
    let ctx = hx.ctx(sender());
    let first = hx.run_ctx(Command::Send, ctx.clone()).unwrap();
    assert!(!first.replayed);
    let again = decide(hx.state.as_ref(), &Command::Send, &ctx).unwrap();
    assert!(again.replayed && again.events.is_empty() && again.effects.is_empty());
    assert_eq!(&again.state, hx.state());
    let other = Command::Void { reason: text("x") };
    assert_eq!(code(decide(hx.state.as_ref(), &other, &ctx)), "CS-WF-0006");
}

#[test]
fn a_stale_version_is_refused() {
    let mut hx = Harness::new();
    hx.draft(&[recipient("r1", Signer, 1)]);
    let v = hx.state().version;
    let mut ctx = hx.ctx(sender());
    ctx.expected_version = Some(v + 1);
    assert_eq!(code(hx.run_ctx(Command::Send, ctx.clone())), "CS-WF-0002");
    ctx.expected_version = Some(v);
    hx.run_ctx(Command::Send, ctx).unwrap();
    assert_eq!(hx.state().version, v + 1);
}

#[test]
fn nobody_acts_for_someone_else() {
    let mut hx = Harness::new();
    hx.draft(&[recipient("r1", Signer, 1), recipient("r2", Signer, 1)]);
    hx.send();
    let c = Command::OpenLink {
        recipient: id("r1"),
    };
    assert_eq!(code(hx.run(as_recipient("r2"), c.clone())), "CS-WF-0003");
    assert_eq!(code(hx.run(sender(), c.clone())), "CS-WF-0003");
    assert_eq!(code(hx.run(Principal::System, c)), "CS-WF-0003");
    let other_sender = Principal::Sender {
        user_id: id("mallory"),
    };
    assert_eq!(code(hx.run(other_sender, Command::Remind)), "CS-WF-0003");
    let unknown = Command::OpenLink {
        recipient: id("nobody"),
    };
    assert_eq!(code(hx.run(as_recipient("nobody"), unknown)), "CS-WF-0008");
}

#[test]
fn debug_output_carries_no_personal_data() {
    let mut hx = Harness::new();
    hx.draft(&[recipient("r1", Signer, 1)]);
    hx.ok(
        sender(),
        Command::Edit {
            changes: vec![add_field({
                let mut f = field("f", "doc-1", "r1", FieldType::Text, false);
                f.default = Some(txt("SECRET-VALUE"));
                f
            })],
        },
    );
    let dump = format!("{:?}", hx.state());
    for needle in [
        "Name r1",
        "r1@example.test",
        "Please sign",
        "Hello",
        "doc-1.pdf",
        "SECRET",
    ] {
        assert!(!dump.contains(needle), "{needle} in Debug");
    }
    let err = hx
        .run(
            as_recipient("r1"),
            Command::Decline {
                recipient: id("r1"),
                reason: Some(text("PRIVATE")),
            },
        )
        .unwrap_err();
    assert!(!format!("{err} {err:?}").contains("PRIVATE"));
}

#[test]
fn state_round_trips_through_json() {
    let mut hx = completing();
    hx.seal();
    let json = serde_json::to_string(hx.state()).unwrap();
    let back: casual_sign_workflow::EnvelopeState = serde_json::from_str(&json).unwrap();
    assert_eq!(&back, hx.state());
}

#[test]
fn every_chain_the_engine_writes_verifies() {
    let mut hx = completing();
    hx.seal();
    let trail = hx.chain.to_trail_json().unwrap();
    let report = casual_sign_audit::verify_trail(
        &trail,
        &casual_sign_audit::VerifyOptions {
            expected_head: hx.chain.head(),
            ..Default::default()
        },
    );
    assert!(report.is_valid(), "{report:?}");
    assert!(report.unrecognised.is_empty());
}

#[test]
fn reaching_cc_without_acting_recipients_is_refused_at_send() {
    let mut hx = Harness::new();
    hx.draft(&[recipient("cc", Cc, 1)]);
    assert_eq!(code(hx.run(sender(), Command::Send)), "CS-WF-0004");
}

#[test]
fn approving_reruns_the_approvers_own_field_rules() {
    let mut hx = Harness::new();
    hx.draft(&[recipient("ap", Approver, 1)]);
    hx.ok(
        sender(),
        Command::Edit {
            changes: vec![add_field(field("po", "doc-1", "ap", FieldType::Text, true))],
        },
    );
    hx.send();
    hx.get_ready("ap");
    let approve = Command::Approve {
        recipient: id("ap"),
    };
    assert_eq!(
        code(hx.run(as_recipient("ap"), approve.clone())),
        "CS-FLD-0001"
    );
    hx.ok(
        as_recipient("ap"),
        Command::CompleteField {
            recipient: id("ap"),
            entry: entry("po", txt("PO-7")),
        },
    );
    hx.ok(as_recipient("ap"), approve);
    assert_eq!(hx.status(), EnvelopeStatus::Completing);
}
