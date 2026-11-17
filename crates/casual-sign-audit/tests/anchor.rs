//! Anchoring (docs/32 §5, `FG-158`): a head anchored mid-chain is proved against the
//! trail the envelope later carries, and a trail that disagrees with the proof fails.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use casual_sign_audit::anchor::{Anchor, AnchorProof};
use casual_sign_audit::json::Value;
use casual_sign_audit::merkle::MerkleTree;
use casual_sign_audit::{Hash256, Timestamp, VerifyOptions, jcs};
use casual_sign_model::Id;

fn proof(heads: &[Hash256], i: usize, seq: u64, envelope: &str) -> AnchorProof {
    let tree = MerkleTree::from_chain_heads(heads);
    AnchorProof {
        envelope_id: Id::new(envelope).unwrap(),
        seq,
        head: heads[i],
        proof: tree.inclusion_proof(i).unwrap(),
        anchor: Anchor {
            id: Id::new("anchor-1").unwrap(),
            period: "2026-11-10".into(),
            tree_size: tree.len() as u64,
            root: tree.root(),
            tsa_time: Timestamp::from_unix_millis(1_794_355_200_000).unwrap(),
            timestamp_token: vec![0x30, 0x00],
        },
    }
}

#[test]
fn a_head_anchored_mid_chain_is_an_event_of_the_later_trail() {
    let full = common::chain(7, 40);
    let trail = full.to_trail_json().unwrap();
    let envelope = full.envelope_id().as_str().to_owned();
    // The chain as it stood when anchored: 25 events; its head is event 24's hash.
    let head_then = full.events()[24].hash;
    let others: Vec<Hash256> = (0..6u8).map(|i| Hash256::digest(&[i])).collect();
    let mut heads = others.clone();
    heads.insert(2, head_then);
    let p = proof(&heads, 2, 24, &envelope);
    p.check_inclusion().unwrap();
    p.check_trail(&trail, &VerifyOptions::default()).unwrap();

    // The proof's seq names another event: mismatch.
    let mut wrong_seq = p.clone();
    wrong_seq.seq = 23;
    assert_eq!(
        wrong_seq
            .check_trail(&trail, &VerifyOptions::default())
            .unwrap_err()
            .code(),
        "CS-AUD-0012"
    );
    // Past the end of the trail.
    let mut past = p.clone();
    past.seq = 40;
    assert_eq!(
        past.check_trail(&trail, &VerifyOptions::default())
            .unwrap_err()
            .code(),
        "CS-AUD-0012"
    );
    // Another envelope's proof.
    let other = proof(&heads, 2, 24, "another-envelope");
    assert_eq!(
        other
            .check_trail(&trail, &VerifyOptions::default())
            .unwrap_err()
            .code(),
        "CS-AUD-0012"
    );
    // A database copy rewritten after anchoring: an earlier event edited and the chain
    // rehashed from there gives a valid trail whose event 24 is no longer the anchored
    // head.
    let mut events = common::events(&full);
    // An event before the anchored one whose time differs from its predecessor's: moved
    // back to that time (still in order), then everything after it relinked.
    let i = (1..24)
        .find(|&i| events[i].get("at") != events[i - 1].get("at"))
        .unwrap();
    let earlier = events[i - 1].get("at").unwrap().clone();
    common::set(&mut events[i], "at", earlier);
    common::relink(&mut events, i);
    let mut tree = full.to_value().unwrap();
    let head = events.last().unwrap().get("hash").unwrap().clone();
    common::set(&mut tree, "head", head);
    common::set(&mut tree, "events", Value::Array(events));
    let rewritten = jcs::to_vec(&tree).unwrap();
    let report = casual_sign_audit::verify_trail(&rewritten, &VerifyOptions::default());
    assert!(report.is_valid(), "{:?}", report.problems);
    assert_eq!(
        p.check_trail(&rewritten, &VerifyOptions::default())
            .unwrap_err()
            .code(),
        "CS-AUD-0012"
    );
}
