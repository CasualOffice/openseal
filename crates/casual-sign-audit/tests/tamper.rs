//! Every kind of tampering docs/32 §4 names, each caught by its own guard.
//!
//! Each test hides the tampering as well as a forger with database access could (re-
//! linking and re-hashing what follows) except for the one thing that guard checks, and
//! asserts that guard's problem: removing that guard turns the test red.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use casual_sign_audit::json::Value;
use casual_sign_audit::{
    Hash256, HeadSource, ProblemKind, VerifyOptions, verify_chain, verify_trail,
};
use common::*;

fn opts() -> VerifyOptions {
    VerifyOptions::default()
}

fn kinds(events: &[Value], o: &VerifyOptions) -> Vec<(Option<usize>, ProblemKind)> {
    verify_chain(events, o)
        .problems
        .into_iter()
        .map(|p| (p.index, p.kind))
        .collect()
}

#[test]
fn an_untouched_chain_verifies_with_its_head_and_count() {
    let c = chain(1, 40);
    let o = VerifyOptions {
        expected_head: c.head(),
        expected_count: Some(40),
        ..opts()
    };
    let r = verify_chain(&events(&c), &o);
    assert!(r.is_valid(), "{r:?}");
    assert_eq!(r.head, c.head());
    assert_eq!(r.events, 40);
    let r = verify_trail(&c.to_trail_json().unwrap(), &o);
    assert!(r.is_valid(), "{r:?}");
}

#[test]
fn an_edited_event_fails_its_own_hash() {
    // The last event: no later link can notice, only its hash.
    let c = chain(2, 10);
    let mut ev = events(&c);
    let actor = ev[9].get("actor").unwrap().clone();
    let mut actor2 = actor.clone();
    set(&mut actor2, "kind", Value::String("user".into()));
    set(&mut ev[9], "actor", actor2);
    assert_eq!(kinds(&ev, &opts()), [(Some(9), ProblemKind::HashMismatch)]);
}

#[test]
fn an_edited_and_rehashed_event_breaks_the_next_link() {
    let c = chain(3, 10);
    let mut ev = events(&c);
    let mut actor = ev[4].get("actor").unwrap().clone();
    set(&mut actor, "kind", Value::String("user".into()));
    set(&mut ev[4], "actor", actor);
    rehash(&mut ev, 4);
    assert_eq!(kinds(&ev, &opts()), [(Some(5), ProblemKind::PrevMismatch)]);
}

#[test]
fn a_rewritten_chain_is_caught_only_against_the_known_head() {
    let c = chain(4, 12);
    let mut ev = events(&c);
    let mut data = ev[6].get("data").unwrap().clone();
    if let Value::Object(m) = &mut data {
        m.push(("forged".into(), Value::Bool(true)));
    }
    set(&mut ev[6], "data", data);
    relink(&mut ev, 6);
    // Self-consistent: the chain alone cannot tell.
    assert!(verify_chain(&ev, &opts()).is_valid());
    let o = VerifyOptions {
        expected_head: c.head(),
        ..opts()
    };
    assert_eq!(
        kinds(&ev, &o),
        [(None, ProblemKind::HeadMismatch(HeadSource::Expected))]
    );
}

#[test]
fn a_removed_event_leaves_a_seq_gap() {
    let c = chain(5, 10);
    let mut ev = events(&c);
    ev.remove(4);
    relink(&mut ev, 4);
    assert_eq!(
        kinds(&ev, &opts()),
        [(
            Some(4),
            ProblemKind::SeqGap {
                expected: 4,
                found: 5
            }
        )]
    );
}

#[test]
fn a_removed_event_breaks_the_link_when_not_relinked() {
    let c = chain(6, 10);
    let mut ev = events(&c);
    ev.remove(4);
    renumber(&mut ev);
    // Everything re-linked except the gap itself.
    rehash(&mut ev, 4);
    relink(&mut ev, 5);
    assert_eq!(kinds(&ev, &opts()), [(Some(4), ProblemKind::PrevMismatch)]);
}

#[test]
fn events_cut_from_the_end_are_caught_against_the_known_head_and_count() {
    let c = chain(7, 10);
    let mut ev = events(&c);
    ev.truncate(7);
    assert!(verify_chain(&ev, &opts()).is_valid());
    let o = VerifyOptions {
        expected_head: c.head(),
        ..opts()
    };
    assert_eq!(
        kinds(&ev, &o),
        [(None, ProblemKind::HeadMismatch(HeadSource::Expected))]
    );
    let o = VerifyOptions {
        expected_count: Some(10),
        ..opts()
    };
    assert_eq!(
        kinds(&ev, &o),
        [(
            None,
            ProblemKind::CountMismatch {
                expected: 10,
                found: 7
            }
        )]
    );
}

#[test]
fn a_trail_whose_events_were_cut_disagrees_with_its_declared_head() {
    let c = chain(8, 10);
    let mut tree = c.to_value().unwrap();
    let mut ev = events(&c);
    ev.truncate(9);
    set(&mut tree, "events", Value::Array(ev));
    let bytes = casual_sign_audit::jcs::to_vec(&tree).unwrap();
    let r = verify_trail(&bytes, &opts());
    let got: Vec<_> = r.problems.iter().map(|p| p.kind.clone()).collect();
    assert_eq!(got, [ProblemKind::HeadMismatch(HeadSource::Declared)]);
}

#[test]
fn a_removed_first_event_is_not_genesis() {
    let c = chain(9, 10);
    let mut ev = events(&c);
    ev.remove(0);
    set(&mut ev[0], "prev", Value::Null);
    relink(&mut ev, 0);
    assert_eq!(kinds(&ev, &opts()), [(Some(0), ProblemKind::NotGenesis)]);
}

#[test]
fn an_inserted_event_duplicates_a_seq() {
    let c = chain(10, 10);
    let mut ev = events(&c);
    let mut forged = ev[5].clone();
    set(
        &mut forged,
        "type",
        Value::String("recipient.finish_later".into()),
    );
    set(
        &mut forged,
        "data",
        Value::Object(vec![("recipient_id".into(), Value::String("rcp-1".into()))]),
    );
    ev.insert(6, forged);
    relink(&mut ev, 6);
    assert_eq!(
        kinds(&ev, &opts()),
        [(Some(6), ProblemKind::SeqDuplicate { seq: 5 })]
    );
}

#[test]
fn reordered_events_run_seq_backwards() {
    let c = chain(11, 10);
    let mut ev = events(&c);
    // Same times so only order speaks.
    let at = ev[3].get("at").unwrap().clone();
    set(&mut ev[4], "at", at.clone());
    set(&mut ev[5], "at", at.clone());
    set(&mut ev[6], "at", at);
    ev.swap(4, 5);
    relink(&mut ev, 3);
    assert_eq!(
        kinds(&ev, &opts()),
        [
            (
                Some(4),
                ProblemKind::SeqGap {
                    expected: 4,
                    found: 5
                }
            ),
            (
                Some(5),
                ProblemKind::SeqBackwards {
                    expected: 6,
                    found: 4
                }
            ),
            (
                Some(6),
                ProblemKind::SeqGap {
                    expected: 5,
                    found: 6
                }
            ),
        ]
    );
}

#[test]
fn an_event_for_another_envelope_is_foreign() {
    let c = chain(12, 10);
    let mut ev = events(&c);
    set(
        &mut ev[3],
        "envelope_id",
        Value::String("another-envelope".into()),
    );
    relink(&mut ev, 3);
    assert_eq!(kinds(&ev, &opts()), [(Some(3), ProblemKind::WrongEnvelope)]);
    // A caller who knows the envelope sees every event as foreign when the first is.
    let o = VerifyOptions {
        envelope_id: Some(id("another-envelope")),
        ..opts()
    };
    let r = verify_chain(&ev, &o);
    assert_eq!(r.problems.len(), 9, "{r:?}");
}

#[test]
fn time_going_backwards_beyond_the_tolerance_is_caught() {
    let c = chain(13, 10);
    let mut ev = events(&c);
    let prev_at =
        casual_sign_audit::Timestamp::parse(ev[4].get("at").unwrap().as_str().unwrap()).unwrap();
    let back =
        casual_sign_audit::Timestamp::from_unix_millis(prev_at.unix_millis() - 1_001).unwrap();
    set(&mut ev[5], "at", Value::String(back.to_string()));
    // Later events are at or after the event before it, so only this one runs back.
    relink(&mut ev, 5);
    assert_eq!(
        kinds(&ev, &opts()),
        [(Some(5), ProblemKind::TimeBackwards { by_ms: 1_001 })]
    );
    // Within a larger tolerance it passes.
    let o = VerifyOptions {
        time_tolerance_ms: 1_001,
        ..opts()
    };
    assert!(verify_chain(&ev, &o).is_valid());
}

#[test]
fn a_changed_prev_alone_is_a_broken_link() {
    let c = chain(14, 10);
    let mut ev = events(&c);
    set(
        &mut ev[3],
        "prev",
        Value::String(Hash256::digest(b"elsewhere").to_string()),
    );
    relink(&mut ev, 4);
    rehash(&mut ev, 3);
    assert_eq!(kinds(&ev, &opts()), [(Some(3), ProblemKind::PrevMismatch)]);
}

#[test]
fn malformed_and_unknown_events_are_reported_not_panicked_on() {
    let c = chain(15, 5);
    let mut ev = events(&c);
    set(&mut ev[1], "type", Value::String("future.event".into()));
    rehash(&mut ev, 1);
    relink(&mut ev, 2);
    let r = verify_chain(&ev, &opts());
    assert!(r.is_valid(), "an unknown type is noted, not failed: {r:?}");
    assert_eq!(r.unrecognised, [1]);

    let mut ev = events(&c);
    set(&mut ev[2], "type", Value::String("recipient.signed".into()));
    set(&mut ev[2], "data", Value::Object(vec![]));
    rehash(&mut ev, 2);
    relink(&mut ev, 3);
    assert_eq!(
        kinds(&ev, &opts()),
        [(
            Some(2),
            ProblemKind::Malformed(casual_sign_audit::ShapeFault::Data)
        )]
    );

    for junk in [
        &b""[..],
        b"[]",
        b"{}",
        b"{\"events\":7}",
        b"{\"events\":[1,null,{}]}",
    ] {
        let r = verify_trail(junk, &opts());
        assert!(!r.is_valid());
    }
}

#[test]
fn a_trail_from_another_format_or_envelope_is_refused() {
    let c = chain(16, 3);
    let mut tree = c.to_value().unwrap();
    set(&mut tree, "format", Value::String("other".into()));
    let r = verify_trail(&casual_sign_audit::jcs::to_vec(&tree).unwrap(), &opts());
    assert!(!r.is_valid());
    let o = VerifyOptions {
        envelope_id: Some(id("not-this-one")),
        ..opts()
    };
    let r = verify_trail(&c.to_trail_json().unwrap(), &o);
    assert!(r.has(|k| *k == ProblemKind::WrongEnvelope));
}
