//! Remote-provider signatures per recipient (ADR-046, `RSP-01`): the signature type on
//! the wire, the send rules, the lock point's frozen layout and the session's rules,
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

use casual_sign_model::{FieldType, RecipientType, SignatureType};
use casual_sign_workflow::{
    Change, Command, Decision, Problem, RecipientSpec, RemoteRule, RemoteSession, WorkflowError,
};
use common::*;

use RecipientType::{Approver, Signer};

fn remote(mut r: RecipientSpec, provider: &str) -> RecipientSpec {
    r.signature = SignatureType::Remote {
        provider_id: id(provider),
    };
    r
}

fn problems(r: Result<Decision, WorkflowError>) -> (String, Vec<(String, Problem)>) {
    let e = r.unwrap_err();
    let code = e.code().to_owned();
    match e {
        WorkflowError::Invalid { violations } => (
            code,
            violations
                .into_iter()
                .map(|v| {
                    (
                        v.object.map(|o| o.as_str().to_owned()).unwrap_or_default(),
                        v.problem,
                    )
                })
                .collect(),
        ),
        e => panic!("not a violation list: {e}"),
    }
}

#[test]
fn a_simple_signature_is_absent_on_the_wire_and_a_remote_one_names_its_provider() {
    let simple = recipient("r1", Signer, 1);
    let v = serde_json::to_value(&simple).unwrap();
    assert!(v.get("signature").is_none(), "{v}");
    let r = remote(recipient("r1", Signer, 1), "csc-demo");
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!(
        v["signature"],
        serde_json::json!({"type": "remote", "provider_id": "csc-demo"})
    );
    let back: RecipientSpec = serde_json::from_value(v).unwrap();
    assert_eq!(back, r);
    // An explicit simple type is accepted and means the default.
    let mut v = serde_json::to_value(&simple).unwrap();
    v["signature"] = serde_json::json!({"type": "simple"});
    let back: RecipientSpec = serde_json::from_value(v).unwrap();
    assert_eq!(back.signature, SignatureType::Simple);
    // Unknown members are refused.
    let mut v = serde_json::to_value(&r).unwrap();
    v["signature"]["pin"] = serde_json::json!("1234");
    assert!(serde_json::from_value::<RecipientSpec>(v).is_err());
}

#[test]
fn two_remote_signers_at_one_routing_order_are_refused_naming_each_other() {
    let mut hx = Harness::new();
    hx.draft(&[
        remote(recipient("r1", Signer, 1), "csc-demo"),
        remote(recipient("r2", Signer, 1), "csc-demo"),
        recipient("r3", Signer, 1),
    ]);
    let (code, found) = problems(hx.run(sender(), Command::Send));
    assert_eq!(code, "CS-RSP-0007");
    assert_eq!(
        found,
        vec![
            (
                "r1".to_owned(),
                Problem::RemoteSignersShareOrder { with: id("r2") }
            ),
            (
                "r2".to_owned(),
                Problem::RemoteSignersShareOrder { with: id("r1") }
            ),
        ]
    );
}

#[test]
fn remote_signers_in_sequence_with_simple_ones_beside_them_send() {
    let mut hx = Harness::new();
    hx.draft(&[
        recipient("r1", Signer, 1),
        remote(recipient("r2", Signer, 2), "csc-demo"),
        recipient("r3", Signer, 2),
        remote(recipient("r4", Signer, 3), "csc-demo"),
    ]);
    hx.send();
}

#[test]
fn a_remote_type_on_a_recipient_who_is_not_a_signer_is_refused() {
    let mut hx = Harness::new();
    hx.draft(&[
        recipient("r1", Signer, 1),
        remote(recipient("r2", Approver, 2), "csc-demo"),
    ]);
    let (code, found) = problems(hx.run(sender(), Command::Send));
    assert_eq!(code, "CS-RSP-0007");
    assert_eq!(found, vec![("r2".to_owned(), Problem::RemoteNotForType)]);
}

#[test]
fn a_remote_rule_beside_another_violation_is_the_general_code() {
    let mut hx = Harness::new();
    hx.draft(&[
        remote(recipient("r1", Signer, 1), "csc-demo"),
        remote(recipient("r2", Signer, 1), "csc-demo"),
    ]);
    hx.ok(
        sender(),
        Command::Edit {
            changes: vec![Change::RemoveDocument { id: id("doc-1") }],
        },
    );
    let (code, _) = problems(hx.run(sender(), Command::Send));
    assert_eq!(code, "CS-WF-0004");
}

/// A sent envelope with r1 (remote, order 1) and r2 (simple, order 2), and `doc-1`
/// locked as at r1's lock point.
fn locked(hx: &mut Harness) {
    hx.draft(&[
        remote(recipient("r1", Signer, 1), "csc-demo"),
        recipient("r2", Signer, 2),
    ]);
    hx.ok(
        sender(),
        Command::Edit {
            changes: vec![Change::AddDocument {
                document: document("doc-2", 2, 1),
            }],
        },
    );
    hx.send();
    hx.state
        .as_mut()
        .unwrap()
        .locked_documents
        .insert(id("doc-1"));
}

fn correct(hx: &mut Harness, change: Change) -> Result<Decision, WorkflowError> {
    hx.run(
        sender(),
        Command::Correct {
            changes: vec![change],
        },
    )
}

fn rule(r: Result<Decision, WorkflowError>) -> RemoteRule {
    match r.unwrap_err() {
        e @ WorkflowError::Remote { .. } => {
            assert_eq!(e.code(), "CS-RSP-0007");
            let WorkflowError::Remote { rule, .. } = e else {
                unreachable!()
            };
            rule
        }
        e => panic!("not a remote rule: {e}"),
    }
}

#[test]
fn after_the_lock_point_a_documents_layout_is_frozen() {
    let mut hx = Harness::new();
    locked(&mut hx);
    let on_locked = field("new-1", "doc-1", "r2", FieldType::Text, false);
    assert_eq!(
        rule(correct(&mut hx, add_field(on_locked))),
        RemoteRule::DocumentLocked
    );
    let mut moved = hx.state().fields.0[1].clone();
    assert_eq!(moved.recipient_id, Some(id("r2")));
    moved.required = false;
    assert_eq!(
        rule(correct(
            &mut hx,
            Change::UpdateField {
                field: casual_sign_audit::Personal(moved)
            }
        )),
        RemoteRule::DocumentLocked
    );
    assert_eq!(
        rule(correct(&mut hx, Change::RemoveField { id: id("sig-r2") })),
        RemoteRule::DocumentLocked
    );
    assert_eq!(
        rule(correct(&mut hx, Change::RemoveDocument { id: id("doc-1") })),
        RemoteRule::DocumentLocked
    );
    assert_eq!(
        rule(correct(
            &mut hx,
            Change::ReplaceDocument {
                document: document("doc-1", 7, 2)
            }
        )),
        RemoteRule::DocumentLocked
    );
    // A document not locked still takes fields, and a later recipient's name may still
    // be corrected (it changes no document's bytes).
    let on_free = field("new-2", "doc-2", "r2", FieldType::Text, false);
    correct(&mut hx, add_field(on_free)).unwrap();
    let mut r2 = hx.state().recipient(&id("r2")).unwrap().spec.clone();
    r2.name = text("Renamed");
    correct(&mut hx, Change::UpdateRecipient { recipient: r2 }).unwrap();
}

#[test]
fn the_signature_type_cannot_change_under_an_open_session() {
    let mut hx = Harness::new();
    locked(&mut hx);
    hx.state.as_mut().unwrap().recipients[0].remote = Some(RemoteSession {
        session: id("sess-1"),
        provider_id: id("csc-demo"),
        started_at: t(0),
        prepared: false,
    });
    let mut r1 = hx.state().recipient(&id("r1")).unwrap().spec.clone();
    r1.signature = SignatureType::Simple;
    assert_eq!(
        rule(correct(
            &mut hx,
            Change::UpdateRecipient {
                recipient: r1.clone()
            }
        )),
        RemoteRule::SignatureTypeInSession
    );
    // Without a session the sender may correct it (ADR-046 §3.12: after failures).
    hx.state.as_mut().unwrap().recipients[0].remote = None;
    correct(&mut hx, Change::UpdateRecipient { recipient: r1 }).unwrap();
}
