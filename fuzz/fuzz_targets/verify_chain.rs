//! Bytes into the audit chain verifier (`T-1I`, `F-007`), seeded with trail files. Any
//! panic, hang or out-of-memory is a finding; so is canonical JSON that is not stable
//! under its own parser, or a "valid" report on a chain whose recomputed head differs.
//!
//!   cargo +nightly fuzz run verify_chain fuzz/seeds/verify_chain -- -max_total_time=300 -dict=fuzz/json.dict
#![no_main]

use casual_sign_audit::json::{Value, parse};
use casual_sign_audit::{AuditLimits, VerifyOptions, jcs, verify_chain, verify_trail};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let options = VerifyOptions {
        limits: AuditLimits {
            max_trail_bytes: 1 << 20,
            max_events: 10_000,
            max_depth: 32,
        },
        ..VerifyOptions::default()
    };
    // The trail file as a whole.
    let report = verify_trail(data, &options);
    if report.is_valid() {
        assert!(report.head.is_some() && report.events > 0);
    }
    let Ok(tree) = parse(data, 32) else { return };
    // Canonical form is a fixed point of parse ∘ serialize.
    let canonical = jcs::to_vec(&tree).expect("a parsed tree is writable");
    let again = parse(&canonical, 32).expect("canonical JSON parses");
    assert_eq!(jcs::to_vec(&again).expect("writable"), canonical);
    // A bare array of events, and the trail's own array.
    if let Value::Array(events) = &tree {
        let _ = verify_chain(events, &options);
    }
    if let Some(Value::Array(events)) = tree.get("events") {
        let r = verify_chain(events, &options);
        if r.is_valid() {
            // Valid against its own head.
            let pinned = VerifyOptions {
                expected_head: r.head,
                ..options.clone()
            };
            assert!(verify_chain(events, &pinned).is_valid());
        }
    }
});
