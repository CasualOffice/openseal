//! Public anchoring (docs/32 §5, `FG-158`) through the facade: a TSA token over a tree of
//! chain heads, each head's proof verified offline, and every tampering caught.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    missing_docs
)]

#[path = "../../casual-sign-seal/tests/common/mod.rs"]
mod common;

use std::time::Duration;

use casual_sign_sdk::anchor::{
    Anchor, AnchorOutcome, AnchorProof, MerkleTree, anchor_statement, timestamp_statement,
    verify_anchor_proof,
};
use casual_sign_sdk::evidence::Timestamp;
use casual_sign_sdk::model::Id;
use casual_sign_sdk::{Hash256, TrustStore};

/// 2026-11-17T00:10:00Z, inside the test PKI's validity.
const AT: Duration = Duration::from_secs(1_794_874_200);

fn heads(n: u8) -> Vec<Hash256> {
    (0..n).map(|i| Hash256::digest(&[0x5a, i])).collect()
}

/// Anchor `heads` through the in-process TSA; every head's proof file.
fn anchored(heads: &[Hash256]) -> Vec<Vec<u8>> {
    let tree = MerkleTree::from_chain_heads(heads);
    let size = tree.len() as u64;
    let tsa = common::TestTsa::new(AT);
    let token = timestamp_statement(&tsa, &anchor_statement(&tree.root(), size)).unwrap();
    let anchor = Anchor {
        id: Id::new("0193a1b2-0000-7000-8000-00000000a001").unwrap(),
        period: "2026-11-16".into(),
        tree_size: size,
        root: tree.root(),
        tsa_time: Timestamp::from_unix_millis(i64::try_from(token.gen_time.as_millis()).unwrap())
            .unwrap(),
        timestamp_token: token.der,
    };
    (0..heads.len())
        .map(|i| {
            AnchorProof {
                envelope_id: Id::new(format!("env-{i}")).unwrap(),
                seq: 3,
                head: heads[i],
                proof: tree.inclusion_proof(i).unwrap(),
                anchor: anchor.clone(),
            }
            .to_json()
            .unwrap()
        })
        .collect()
}

#[test]
fn anchoring_a_set_of_heads_proves_inclusion_of_each() {
    let hs = heads(9);
    for (i, file) in anchored(&hs).iter().enumerate() {
        let v = verify_anchor_proof(file, None, &common::trust()).unwrap();
        assert_eq!(v.outcome(), AnchorOutcome::Passed, "{i}: {v:?}");
        assert_eq!(v.proof.head, hs[i]);
        assert_eq!(v.timestamp.gen_time, Some(AT));
        // The TSA's name, for "anchored … by <TSA>" (FG-158, the Verify page).
        assert_eq!(v.timestamp.tsa_name.as_deref(), Some("T-1G Test TSA"));
    }
}

#[test]
fn a_tampered_head_fails_the_proof() {
    let hs = heads(9);
    let file = String::from_utf8(anchored(&hs)[4].clone()).unwrap();
    let mut other = hs[4];
    other.0[31] ^= 1;
    let forged = file.replace(&hs[4].to_string(), &other.to_string());
    assert_ne!(forged, file);
    let v = verify_anchor_proof(forged.as_bytes(), None, &common::trust()).unwrap();
    assert_eq!(v.outcome(), AnchorOutcome::Failed);
    assert_eq!(v.inclusion.unwrap_err().code(), "CS-AUD-0009");
}

#[test]
fn a_token_from_another_anchor_fails() {
    // Two anchors; the second's root and statement with the first's token.
    let a = String::from_utf8(anchored(&heads(5))[0].clone()).unwrap();
    let b = String::from_utf8(anchored(&heads(6))[0].clone()).unwrap();
    let token_of = |s: &str| {
        let at = s.find("\"timestamp_token\":\"").unwrap() + 19;
        let end = at + s[at..].find('"').unwrap();
        s[at..end].to_owned()
    };
    let swapped = b.replace(&token_of(&b), &token_of(&a));
    assert_ne!(swapped, b);
    let v = verify_anchor_proof(swapped.as_bytes(), None, &common::trust()).unwrap();
    assert_eq!(v.outcome(), AnchorOutcome::Failed);
    assert!(!v.timestamp.token.passed());
    // A token that does not pass names no TSA.
    assert_eq!(v.timestamp.tsa_name, None);
}

#[test]
fn without_a_trusted_root_the_tsa_is_indeterminate() {
    let file = &anchored(&heads(3))[1];
    let v = verify_anchor_proof(file, None, &TrustStore::new()).unwrap();
    assert!(v.inclusion.is_ok() && v.timestamp.token.passed());
    assert_eq!(v.outcome(), AnchorOutcome::Indeterminate);
}
