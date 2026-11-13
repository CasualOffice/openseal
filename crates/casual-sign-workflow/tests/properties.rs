//! Properties over random envelopes and random command sequences (stage 2A gate).
//!
//! Every accepted command goes through the harness, which asserts every invariant of
//! the engine (tests/common/mod.rs `check_invariants`): no move from a terminal status;
//! `completed` only from a verified seal of every document as delivered; an audit event
//! for every observable change; invitations and active recipients only in routing
//! turn; every pending timer and job cancelled when the envelope is voided, declined or
//! expired; re-applying a command id is a replay with no events or effects; the same
//! inputs give the same decision. The events are appended to a real chain.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::collections::BTreeSet;

use casual_sign_audit::{AdoptionMethod, AuthMethod, Channel, MarkKind, Personal};
use casual_sign_model::{
    EnvelopeStatus, FieldType, FieldValue, RecipientType, ReminderPolicy, Text,
};
use casual_sign_workflow::{
    Access, Change, Command, EffectId, EffectKind, Ersd, FieldEntry, Principal, ReassignTo, decide,
};
use common::*;
use proptest::prelude::*;

/// One recipient of a random envelope.
#[derive(Debug, Clone)]
struct RSpec {
    rtype: u8,
    order: u32,
    auth: bool,
}

/// A random envelope.
#[derive(Debug, Clone)]
struct Config {
    recipients: Vec<RSpec>,
    documents: u8,
    expiry_days: Option<u8>,
    reminders: (u8, u8),
    ersd: bool,
    max_auth_attempts: u32,
}

fn rtype(n: u8) -> RecipientType {
    use RecipientType::*;
    [
        Signer,
        Signer,
        Approver,
        Viewer,
        Cc,
        InPersonSigner,
        Agent,
        Editor,
        Intermediary,
    ][usize::from(n) % 9]
}

/// One abstract step; recipient numbers are taken modulo the current recipients.
#[derive(Debug, Clone)]
enum Act {
    Open(u8),
    Auth(u8, bool),
    Consent(u8),
    Sign(u8),
    Approve(u8),
    ViewAll(u8),
    Decline(u8),
    Reassign(u8),
    FinishLater(u8),
    Void,
    Resend,
    Remind,
    CorrectEmail(u8),
    CorrectReplaceDoc,
    CorrectAddSigner(u8),
    CorrectRemove(u8),
    CorrectOrder(u8, u8),
    Bounce(u8),
    Dispatch(u8),
    Tick(u8),
    TimerDue(u8),
    Expire,
    SealOk,
    SealBad(u8),
    SealFail,
    Purge,
    Access,
    Replay(u8),
    Stranger(u8),
}

fn act() -> impl Strategy<Value = Act> {
    let r = any::<u8>();
    prop_oneof![
        4 => r.prop_map(Act::Open),
        2 => (r, any::<bool>()).prop_map(|(a, b)| Act::Auth(a, b)),
        2 => r.prop_map(Act::Consent),
        8 => r.prop_map(Act::Sign),
        3 => r.prop_map(Act::Approve),
        3 => r.prop_map(Act::ViewAll),
        1 => r.prop_map(Act::Decline),
        1 => r.prop_map(Act::Reassign),
        1 => r.prop_map(Act::FinishLater),
        1 => Just(Act::Void),
        1 => Just(Act::Resend),
        1 => Just(Act::Remind),
        1 => r.prop_map(Act::CorrectEmail),
        1 => Just(Act::CorrectReplaceDoc),
        1 => r.prop_map(Act::CorrectAddSigner),
        1 => r.prop_map(Act::CorrectRemove),
        1 => (r, r).prop_map(|(a, b)| Act::CorrectOrder(a, b)),
        1 => r.prop_map(Act::Bounce),
        1 => r.prop_map(Act::Dispatch),
        2 => r.prop_map(Act::Tick),
        2 => r.prop_map(Act::TimerDue),
        1 => Just(Act::Expire),
        3 => Just(Act::SealOk),
        2 => r.prop_map(Act::SealBad),
        1 => Just(Act::SealFail),
        1 => Just(Act::Purge),
        1 => Just(Act::Access),
        2 => r.prop_map(Act::Replay),
        1 => r.prop_map(Act::Stranger),
    ]
}

fn config() -> impl Strategy<Value = Config> {
    (
        prop::collection::vec(
            (any::<u8>(), 1u32..=3, any::<bool>()).prop_map(|(t, o, a)| RSpec {
                rtype: t,
                order: o,
                auth: a,
            }),
            1..=5,
        ),
        1u8..=2,
        prop::option::of(1u8..=10),
        (0u8..=3, 0u8..=3),
        any::<bool>(),
        1u32..=3,
    )
        .prop_map(
            |(recipients, documents, expiry_days, reminders, ersd, max_auth_attempts)| Config {
                recipients,
                documents,
                expiry_days,
                reminders,
                ersd,
                max_auth_attempts,
            },
        )
}

/// Builds and sends the configured envelope. Sending may be refused (say, only carbon
/// copies); the sequence then runs against the draft.
fn setup(c: &Config) -> Harness {
    let mut hx = Harness::new();
    hx.policy.max_auth_attempts = c.max_auth_attempts;
    hx.policy.expiry_warning_days = 1;
    if c.ersd {
        hx.policy.ersd = Some(Ersd {
            version: Text::new("v1").unwrap(),
            hash: h(77),
        });
    }
    hx.create();
    let mut changes = Vec::new();
    for d in 0..c.documents {
        changes.push(Change::AddDocument {
            document: document(&format!("doc-{}", d + 1), d + 1, 2),
        });
    }
    for (i, r) in c.recipients.iter().enumerate() {
        let rid = format!("r{i}");
        let mut spec = recipient(&rid, rtype(r.rtype), r.order);
        if r.auth {
            spec.auth = vec![AuthMethod::SmsOtp];
        }
        changes.push(Change::AddRecipient { recipient: spec });
        if rtype(r.rtype).signs() {
            changes.push(add_field(field(
                &format!("sig-{rid}"),
                "doc-1",
                &rid,
                FieldType::Signature,
                true,
            )));
        }
    }
    if let Some(days) = c.expiry_days {
        changes.push(Change::SetExpiry {
            expires_at: Some(t(i64::from(days) * DAY)),
        });
    }
    changes.push(Change::SetReminders {
        reminders: ReminderPolicy::new(u16::from(c.reminders.0), u16::from(c.reminders.1)).unwrap(),
    });
    hx.ok(sender(), Command::Edit { changes });
    let _ = hx.run(sender(), Command::Send);
    hx
}

/// What the interpreter saw across a sequence, for the coverage check.
#[derive(Debug, Default)]
struct Seen {
    timers: Vec<EffectId>,
    statuses: BTreeSet<String>,
    accepted: usize,
}

fn rid_at(hx: &Harness, n: u8) -> Option<String> {
    let s = hx.state.as_ref()?;
    if s.recipients.is_empty() {
        return None;
    }
    let i = usize::from(n) % s.recipients.len();
    Some(s.recipients[i].id().to_string())
}

/// Tries every step a recipient takes up to finishing, ignoring refusals.
fn try_ready(hx: &mut Harness, rid: &str) {
    let r = hx.state().recipient(&id(rid)).unwrap().clone();
    if r.spec.rtype == RecipientType::InPersonSigner && r.in_person_host.is_none() {
        let _ = hx.run(
            Principal::InPersonHost {
                user_id: id("clerk"),
            },
            Command::HostInPerson { recipient: id(rid) },
        );
    }
    let p = hx.principal_for(rid);
    let _ = hx.run(p.clone(), Command::OpenLink { recipient: id(rid) });
    for m in r.spec.auth.clone() {
        let _ = hx.run(
            p.clone(),
            Command::AuthResult {
                recipient: id(rid),
                method: m,
                passed: true,
                identity: None,
            },
        );
    }
    if let Some(e) = hx.policy.ersd.clone() {
        let _ = hx.run(
            p,
            Command::Consent {
                recipient: id(rid),
                ersd_version: e.version,
                ersd_hash: e.hash,
            },
        );
    }
}

fn step(hx: &mut Harness, a: &Act, seen: &mut Seen, salt: &mut u8) {
    let Some(state) = hx.state.clone() else {
        return;
    };
    let rid = |n: u8| rid_at(hx, n);
    let result = match a {
        Act::Open(n) => rid(*n).map(|r| {
            let p = hx.principal_for(&r);
            hx.run(p, Command::OpenLink { recipient: id(&r) })
        }),
        Act::Auth(n, passed) => rid(*n).map(|r| {
            let p = hx.principal_for(&r);
            hx.run(
                p,
                Command::AuthResult {
                    recipient: id(&r),
                    method: AuthMethod::SmsOtp,
                    passed: *passed,
                    identity: None,
                },
            )
        }),
        Act::Consent(n) => rid(*n).map(|r| {
            let p = hx.principal_for(&r);
            hx.run(
                p,
                Command::Consent {
                    recipient: id(&r),
                    ersd_version: Text::new("v1").unwrap(),
                    ersd_hash: h(77),
                },
            )
        }),
        Act::Sign(n) => rid(*n).map(|r| {
            try_ready(hx, &r);
            let p = hx.principal_for(&r);
            let _ = hx.run(
                p.clone(),
                Command::AdoptSignature {
                    recipient: id(&r),
                    mark: MarkKind::Signature,
                    method: AdoptionMethod::Draw,
                    image_hash: h(5),
                },
            );
            let values = hx
                .state()
                .fields
                .0
                .iter()
                .filter(|f| {
                    f.recipient_id.as_ref() == Some(&id(&r)) && f.field_type == FieldType::Signature
                })
                .map(|f| FieldEntry {
                    field: f.id.clone(),
                    value: Personal(FieldValue::Signature(id("img"))),
                })
                .collect();
            hx.run(
                p,
                Command::Finish {
                    recipient: id(&r),
                    values,
                },
            )
        }),
        Act::Approve(n) => rid(*n).map(|r| {
            try_ready(hx, &r);
            let p = hx.principal_for(&r);
            hx.run(p, Command::Approve { recipient: id(&r) })
        }),
        Act::ViewAll(n) => rid(*n).map(|r| {
            try_ready(hx, &r);
            let p = hx.principal_for(&r);
            let docs: Vec<_> = hx
                .state()
                .documents
                .iter()
                .map(|d| (d.spec.id.clone(), d.spec.delivered_hash, d.spec.pages))
                .collect();
            let mut last = None;
            for (doc, hash, pages) in docs {
                last = Some(hx.run(
                    p.clone(),
                    Command::ViewDocument {
                        recipient: id(&r),
                        document: doc,
                        hash,
                        pages_seen: (1..=pages).collect(),
                    },
                ));
            }
            let _ = hx.run(
                p,
                Command::Finish {
                    recipient: id(&r),
                    values: vec![],
                },
            );
            last.unwrap_or_else(|| hx.run(Principal::System, Command::Expire))
        }),
        Act::Decline(n) => rid(*n).map(|r| {
            try_ready(hx, &r);
            let p = hx.principal_for(&r);
            hx.run(
                p,
                Command::Decline {
                    recipient: id(&r),
                    reason: Some(text("no")),
                },
            )
        }),
        Act::Reassign(n) => rid(*n).map(|r| {
            try_ready(hx, &r);
            let p = hx.principal_for(&r);
            *salt = salt.wrapping_add(1);
            hx.run(
                p,
                Command::Reassign {
                    recipient: id(&r),
                    to: ReassignTo {
                        id: id(&format!("ra{salt}")),
                        name: text("Deputy"),
                        email: text("deputy@example.test"),
                        phone: None,
                        delivery: None,
                    },
                    reason: None,
                },
            )
        }),
        Act::FinishLater(n) => rid(*n).map(|r| {
            let p = hx.principal_for(&r);
            hx.run(p, Command::FinishLater { recipient: id(&r) })
        }),
        Act::Void => Some(hx.run(sender(), Command::Void { reason: text("v") })),
        Act::Resend => Some(hx.run(sender(), Command::Resend { recipients: vec![] })),
        Act::Remind => Some(hx.run(sender(), Command::Remind)),
        Act::CorrectEmail(n) => rid(*n).map(|r| {
            let mut spec = hx.state().recipient(&id(&r)).unwrap().spec.clone();
            *salt = salt.wrapping_add(1);
            spec.email = text(&format!("new{salt}@example.test"));
            hx.run(
                sender(),
                Command::Correct {
                    changes: vec![Change::UpdateRecipient { recipient: spec }],
                },
            )
        }),
        Act::CorrectReplaceDoc => {
            *salt = salt.wrapping_add(1);
            Some(hx.run(
                sender(),
                Command::Correct {
                    changes: vec![Change::ReplaceDocument {
                        document: document("doc-1", *salt, 2),
                    }],
                },
            ))
        }
        Act::CorrectAddSigner(o) => {
            *salt = salt.wrapping_add(1);
            let nid = format!("rn{salt}");
            Some(hx.run(
                sender(),
                Command::Correct {
                    changes: vec![
                        Change::AddRecipient {
                            recipient: recipient(
                                &nid,
                                RecipientType::Signer,
                                u32::from(*o % 4) + 1,
                            ),
                        },
                        add_field(field(
                            &format!("sig-{nid}"),
                            "doc-1",
                            &nid,
                            FieldType::Signature,
                            true,
                        )),
                    ],
                },
            ))
        }
        Act::CorrectRemove(n) => rid(*n).map(|r| {
            hx.run(
                sender(),
                Command::Correct {
                    changes: vec![Change::RemoveRecipient { id: id(&r) }],
                },
            )
        }),
        Act::CorrectOrder(n, o) => rid(*n).map(|r| {
            let mut spec = hx.state().recipient(&id(&r)).unwrap().spec.clone();
            spec.routing_order =
                casual_sign_model::RoutingOrder::new(u32::from(*o % 4) + 1).unwrap();
            hx.run(
                sender(),
                Command::Correct {
                    changes: vec![Change::UpdateRecipient { recipient: spec }],
                },
            )
        }),
        Act::Bounce(n) => rid(*n).map(|r| {
            hx.run(
                Principal::System,
                Command::InvitationBounced {
                    recipient: id(&r),
                    channel: Channel::Email,
                },
            )
        }),
        Act::Dispatch(n) => rid(*n).map(|r| {
            hx.run(
                Principal::System,
                Command::InvitationDispatched {
                    recipient: id(&r),
                    channel: Channel::Email,
                },
            )
        }),
        Act::Tick(n) => {
            hx.now += i64::from(*n) * DAY / 8;
            None
        }
        Act::TimerDue(n) => {
            // Any timer ever scheduled, pending or long cancelled.
            if seen.timers.is_empty() {
                None
            } else {
                let timer = seen.timers[usize::from(*n) % seen.timers.len()].clone();
                Some(hx.run(Principal::System, Command::TimerDue { timer }))
            }
        }
        Act::Expire => Some(hx.run(Principal::System, Command::Expire)),
        Act::SealOk => state.book.seal_job.clone().map(|job| {
            hx.run(
                Principal::System,
                Command::SealSucceeded {
                    job,
                    documents: sealed(&state),
                },
            )
        }),
        Act::SealBad(v) => state.book.seal_job.clone().map(|job| {
            let mut docs = sealed(&state);
            let job = match v % 5 {
                0 => {
                    docs[0].verified = false;
                    job
                }
                1 => {
                    docs.pop();
                    job
                }
                2 => {
                    docs[0].delivered_hash = h(3);
                    job
                }
                3 => {
                    docs[0].profile = casual_sign_model::SealProfile::PadesBLta;
                    job
                }
                _ => EffectId {
                    command: id("stale"),
                    index: 0,
                },
            };
            let r = hx.run(
                Principal::System,
                Command::SealSucceeded {
                    job,
                    documents: docs,
                },
            );
            assert!(r.is_err(), "a seal result that proves nothing was accepted");
            r
        }),
        Act::SealFail => state.book.seal_job.clone().map(|job| {
            hx.run(
                Principal::System,
                Command::SealFailed {
                    job,
                    code: Text::new("CS-SEAL-0003").unwrap(),
                },
            )
        }),
        Act::Purge => Some(hx.run(
            Principal::System,
            Command::Purge {
                policy: Text::new("retention").unwrap(),
            },
        )),
        Act::Access => Some(hx.run(
            sender(),
            Command::RecordAccess {
                access: Access::SenderViewed,
            },
        )),
        Act::Replay(k) => {
            if hx.accepted.is_empty() {
                None
            } else {
                let (cmd, ctx) = hx.accepted[usize::from(*k) % hx.accepted.len()].clone();
                let d = decide(hx.state.as_ref(), &cmd, &ctx).expect("a replay is accepted");
                assert!(d.replayed, "{} applied twice", cmd.name());
                assert!(d.events.is_empty() && d.effects.is_empty());
                assert_eq!(hx.state.as_ref(), Some(&d.state));
                None
            }
        }
        Act::Stranger(n) => rid(*n).map(|r| {
            // Someone else acting as this recipient, or a recipient acting as sender.
            let r2 = hx.run(
                as_recipient("intruder"),
                Command::OpenLink { recipient: id(&r) },
            );
            assert!(r2.is_err());
            let r3 = hx.run(as_recipient(&r), Command::Void { reason: text("x") });
            assert!(r3.is_err());
            r3
        }),
    };
    if let Some(Ok(d)) = result {
        seen.accepted += 1;
        for e in &d.effects {
            if matches!(e.kind, EffectKind::Schedule { .. }) {
                seen.timers.push(e.id.clone());
            }
        }
    }
    // Timers scheduled inside helper steps.
    for t in &hx.state().book.scheduled {
        if !seen.timers.contains(&t.id) {
            seen.timers.push(t.id.clone());
        }
    }
    seen.statuses.insert(format!("{:?}", hx.status()));
}

fn run(c: &Config, acts: &[Act]) -> (Harness, Seen) {
    let mut hx = setup(c);
    let mut seen = Seen::default();
    let mut salt = 0u8;
    let first = hx.status();
    let mut terminal: Option<EnvelopeStatus> = None;
    for a in acts {
        step(&mut hx, a, &mut seen, &mut salt);
        // Across the whole sequence: once terminal, always that status.
        if let Some(t) = terminal {
            assert_eq!(hx.status(), t, "left terminal status after {a:?}");
        } else if hx.status().is_terminal() {
            terminal = Some(hx.status());
        }
    }
    let _ = first;
    (hx, seen)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Random envelopes under random command sequences keep every invariant.
    #[test]
    fn random_command_sequences_keep_every_invariant(
        c in config(),
        acts in prop::collection::vec(act(), 0..60),
    ) {
        let (hx, _) = run(&c, &acts);
        // The chain the engine wrote verifies end to end.
        let trail = hx.chain.to_trail_json().unwrap();
        let report = casual_sign_audit::verify_trail(
            &trail,
            &casual_sign_audit::VerifyOptions {
                expected_head: hx.chain.head(),
                ..Default::default()
            },
        );
        prop_assert!(report.is_valid(), "{report:?}");
    }

    /// Driving every recipient in turn always ends `completed`, through `completing`
    /// and a verified seal: the engine does not refuse its own happy path.
    #[test]
    fn every_valid_envelope_can_be_completed(c in config()) {
        let mut hx = setup(&c);
        prop_assume!(hx.status() == EnvelopeStatus::Sent);
        for _round in 0..12 {
            if hx.status() == EnvelopeStatus::Completing {
                break;
            }
            let active: Vec<(String, RecipientType)> = hx
                .state()
                .recipients
                .iter()
                .filter(|r| r.status.is_active())
                .map(|r| (r.id().to_string(), r.spec.rtype))
                .collect();
            let mut salt = 0;
            let mut seen = Seen::default();
            for (i, (_, rt)) in active.iter().enumerate() {
                let n = u8::try_from(
                    hx.state().recipient_index(&id(&active[i].0)).unwrap(),
                )
                .unwrap();
                let a = match rt {
                    RecipientType::Approver => Act::Approve(n),
                    RecipientType::Viewer => Act::ViewAll(n),
                    RecipientType::Agent | RecipientType::Intermediary => Act::ViewAll(n),
                    _ => Act::Sign(n),
                };
                step(&mut hx, &a, &mut seen, &mut salt);
            }
        }
        prop_assert_eq!(hx.status(), EnvelopeStatus::Completing);
        hx.seal();
        prop_assert_eq!(hx.status(), EnvelopeStatus::Completed);
    }
}

/// The random sequences are not vacuous: across seeded runs they reach every status,
/// and most commands are accepted somewhere.
#[test]
fn random_sequences_reach_every_status() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::{Config as PConfig, RngAlgorithm, TestRng, TestRunner};
    let mut runner = TestRunner::new_with_rng(
        PConfig::default(),
        TestRng::from_seed(RngAlgorithm::ChaCha, &[7; 32]),
    );
    let mut statuses = BTreeSet::new();
    let mut accepted = 0;
    for _ in 0..300 {
        let c = config().new_tree(&mut runner).unwrap().current();
        let acts = prop::collection::vec(act(), 20..80)
            .new_tree(&mut runner)
            .unwrap()
            .current();
        let (_, seen) = run(&c, &acts);
        statuses.extend(seen.statuses);
        accepted += seen.accepted;
    }
    for s in [
        "Draft",
        "Sent",
        "Delivered",
        "Completing",
        "Completed",
        "Declined",
        "Voided",
        "Expired",
    ] {
        assert!(
            statuses.contains(s),
            "no sequence reached {s}: {statuses:?}"
        );
    }
    assert!(
        accepted > 2000,
        "only {accepted} top-level commands accepted"
    );
}
