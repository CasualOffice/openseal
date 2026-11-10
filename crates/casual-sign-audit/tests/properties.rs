//! Properties over random inputs: canonical JSON is deterministic and independent of
//! member order; every random chain verifies; every single random mutation of a chain is
//! detected against the head the certificate prints.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use casual_sign_audit::json::{Value, parse};
use casual_sign_audit::{Chain, VerifyOptions, jcs, verify_chain, verify_trail};
use common::{Rng, chain, events, rehash, relink, renumber, set};
use proptest::prelude::*;

fn leaf() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<f64>()
            .prop_filter("finite", |f| f.is_finite())
            .prop_map(Value::Number),
        any::<i32>().prop_map(|i| Value::Number(f64::from(i))),
        ".{0,12}".prop_map(Value::String),
        "[\\x00-\\x1f\"\\\\\u{80}-\u{ff}\u{2028}\u{fb33}\u{1f600}]{0,6}".prop_map(Value::String),
    ]
}

fn tree() -> impl Strategy<Value = Value> {
    leaf().prop_recursive(5, 64, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::btree_map(".{0,6}", inner, 0..6)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

/// The same tree with every object's members in an order drawn from `r`.
fn shuffled(v: &Value, r: &mut Rng) -> Value {
    match v {
        Value::Array(a) => Value::Array(a.iter().map(|x| shuffled(x, r)).collect()),
        Value::Object(m) => {
            let mut m: Vec<(String, Value)> =
                m.iter().map(|(k, x)| (k.clone(), shuffled(x, r))).collect();
            for i in (1..m.len()).rev() {
                let j = usize::try_from(r.below(u64::try_from(i + 1).unwrap())).unwrap();
                m.swap(i, j);
            }
            Value::Object(m)
        }
        other => other.clone(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn jcs_is_deterministic_and_member_order_does_not_matter(v in tree(), seed in any::<u64>()) {
        let a = jcs::to_vec(&v).unwrap();
        prop_assert_eq!(&a, &jcs::to_vec(&v).unwrap());
        let mut r = Rng(seed);
        let b = jcs::to_vec(&shuffled(&v, &mut r)).unwrap();
        prop_assert_eq!(&a, &b);
    }

    #[test]
    fn jcs_output_parses_back_to_itself(v in tree()) {
        let a = jcs::to_vec(&v).unwrap();
        let back = parse(&a, 64).unwrap();
        prop_assert_eq!(jcs::to_vec(&back).unwrap(), a);
    }

    #[test]
    fn numbers_round_trip_through_their_canonical_text(bits in any::<u64>()) {
        let x = f64::from_bits(bits);
        prop_assume!(x.is_finite());
        let text = jcs::number(x).unwrap();
        let back: f64 = text.parse().unwrap();
        prop_assert!(back == x, "{} -> {} -> {}", x, text, back);
    }
}

/// One mutation a forger could make, applied to `events`. Returns false when the
/// mutation happened to change nothing (then there is nothing to detect).
fn mutate(events: &mut Vec<Value>, r: &mut Rng) -> bool {
    let n = events.len();
    let i = usize::try_from(r.below(u64::try_from(n).unwrap())).unwrap();
    let before = jcs::to_vec(&Value::Array(events.clone())).unwrap();
    match r.below(9) {
        // Delete an event.
        0 => {
            events.remove(i);
        }
        // Insert a copy of an event anywhere.
        1 => {
            let copy = events[i].clone();
            let at = usize::try_from(r.below(u64::try_from(n + 1).unwrap())).unwrap();
            events.insert(at, copy);
        }
        // Swap two events.
        2 => {
            let j = usize::try_from(r.below(u64::try_from(n).unwrap())).unwrap();
            events.swap(i, j);
        }
        // Edit a leaf somewhere in the event.
        3 => edit_leaf(&mut events[i], r),
        // Edit a leaf, then fix this event's hash.
        4 => {
            edit_leaf(&mut events[i], r);
            rehash(events, i);
        }
        // Edit a leaf, then re-link everything after it.
        5 => {
            edit_leaf(&mut events[i], r);
            relink(events, i);
        }
        // Delete, renumber and re-link everything: a perfect forgery of a shorter chain.
        6 => {
            events.remove(i);
            if let Some(first) = events.first_mut() {
                set(first, "prev", Value::Null);
            }
            renumber(events);
            relink(events, 0);
        }
        // Cut the end.
        7 => events.truncate(i),
        // Add a member to an event and re-link.
        _ => {
            set(&mut events[i], "note", Value::String("added".into()));
            relink(events, i);
        }
    }
    jcs::to_vec(&Value::Array(events.clone())).unwrap() != before
}

/// Change one leaf of `v` (any depth) to a different value.
fn edit_leaf(v: &mut Value, r: &mut Rng) {
    match v {
        Value::Object(m) if !m.is_empty() => {
            let k = usize::try_from(r.below(u64::try_from(m.len()).unwrap())).unwrap();
            edit_leaf(&mut m[k].1, r);
        }
        Value::Array(a) if !a.is_empty() => {
            let k = usize::try_from(r.below(u64::try_from(a.len()).unwrap())).unwrap();
            edit_leaf(&mut a[k], r);
        }
        Value::String(s) => s.push('x'),
        Value::Number(n) => *n += 1.0,
        Value::Bool(b) => *b = !*b,
        Value::Null => *v = Value::Bool(false),
        Value::Object(m) => m.push(("x".into(), Value::Null)),
        Value::Array(a) => a.push(Value::Null),
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1024, ..ProptestConfig::default() })]

    #[test]
    fn every_random_chain_verifies(seed in any::<u64>(), n in 1usize..40) {
        let c = chain(seed, n);
        let o = VerifyOptions { expected_head: c.head(), expected_count: Some(n as u64), ..VerifyOptions::default() };
        let r = verify_chain(&events(&c), &o);
        prop_assert!(r.is_valid(), "{:?}", r);
        let json = c.to_trail_json().unwrap();
        prop_assert!(verify_trail(&json, &o).is_valid());
        let (back, _) = Chain::from_trail_json(&json, &o).unwrap();
        prop_assert_eq!(back.to_trail_json().unwrap(), json);
    }

    #[test]
    fn every_single_mutation_is_detected(seed in any::<u64>(), n in 2usize..30, m in any::<u64>()) {
        let c = chain(seed, n);
        let mut ev = events(&c);
        let mut r = Rng(m);
        prop_assume!(mutate(&mut ev, &mut r));
        let o = VerifyOptions { expected_head: c.head(), ..VerifyOptions::default() };
        let report = verify_chain(&ev, &o);
        prop_assert!(!report.is_valid(), "mutation not detected: {:?}", report);
    }
}
