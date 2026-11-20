//! Writes `fixtures/anchor/` (`FG-158`, docs/32 §5): an envelope's audit trail, the
//! anchor proof of its last head (a tree of three heads, time-stamped by the in-process
//! test TSA of `casual-sign-seal/tests/common`), and that PKI's root, DER and PEM. The
//! Verify page's tests (`webapp/e2e/verify-anchor.spec.mjs`) and the WASM export's
//! (`casual-sign-wasm/tests/anchor.rs`, `tools/wasm-parity.mjs`) read them.
//!
//!     cargo run -q -p casual-sign-sdk --example gen_anchor -- fixtures/anchor
//!
//! The test PKI's keys are made afresh on each run and never written, so each run writes
//! different bytes; the committed files are one run's. Only the root certificate is kept.
//! No personal data: the events carry system actors and hashes only.

// A developer tool writing fixtures: it may stop on any failure (CLAUDE.md: tests and
// tools may unwrap).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    missing_docs
)]

#[path = "../../casual-sign-seal/tests/common/mod.rs"]
mod common;

use std::path::PathBuf;
use std::time::Duration;

use casual_sign_sdk::Hash256;
use casual_sign_sdk::anchor::{
    Anchor, AnchorOutcome, AnchorProof, MerkleTree, anchor_statement, timestamp_statement,
    verify_anchor_proof,
};
use casual_sign_sdk::evidence::{Actor, Chain, Context, EventData, Timestamp};
use casual_sign_sdk::model::Id;

/// The envelope the fixtures are about.
const ENVELOPE: &str = "0193f000-0000-7000-8000-00000000e001";
/// 2026-11-16T09:00:00Z: the events' day.
const EVENTS_AT: i64 = 1_794_819_600_000;
/// 2026-11-17T00:10:00Z: the anchor's token, after the day closed.
const ANCHORED_AT: Duration = Duration::from_secs(1_794_874_200);

fn main() {
    let out = PathBuf::from(std::env::args().nth(1).expect("usage: gen_anchor OUT_DIR"));
    std::fs::create_dir_all(&out).unwrap();
    let mut chain = Chain::new(Id::new(ENVELOPE).unwrap());
    for (i, data) in [
        EventData::EnvelopeCreated {
            subject_hash: Hash256::digest(b"anchor fixture"),
        },
        EventData::EnvelopeSent {
            recipients: 1,
            documents: 1,
            envelope_id_stamped: false,
        },
        EventData::EnvelopeCompleting {},
    ]
    .into_iter()
    .enumerate()
    {
        let e = chain.next(
            Timestamp::from_unix_millis(EVENTS_AT + i as i64 * 60_000).unwrap(),
            Actor::system(),
            Context::default(),
            data,
        );
        chain.append(e).unwrap();
    }
    let trail = chain.to_trail_json().unwrap();
    let head = chain.head().unwrap();
    let seq = chain.next_seq() - 1;
    let heads = [
        Hash256::digest(b"other-1"),
        head,
        Hash256::digest(b"other-2"),
    ];
    let tree = MerkleTree::from_chain_heads(&heads);
    let size = tree.len() as u64;
    let tsa = common::TestTsa::new(ANCHORED_AT);
    let token = timestamp_statement(&tsa, &anchor_statement(&tree.root(), size)).unwrap();
    let proof = AnchorProof {
        envelope_id: Id::new(ENVELOPE).unwrap(),
        seq,
        head,
        proof: tree.inclusion_proof(1).unwrap(),
        anchor: Anchor {
            id: Id::new("0193f000-0000-7000-8000-00000000a001").unwrap(),
            period: "2026-11-16".into(),
            tree_size: size,
            root: tree.root(),
            tsa_time: Timestamp::from_unix_millis(
                i64::try_from(token.gen_time.as_millis()).unwrap(),
            )
            .unwrap(),
            timestamp_token: token.der,
        },
    }
    .to_json()
    .unwrap();
    // What is written must verify, with the trail, against the root written.
    let v = verify_anchor_proof(&proof, Some(&trail), &common::trust()).unwrap();
    assert_eq!(v.outcome(), AnchorOutcome::Passed, "{v:?}");
    std::fs::write(out.join("audit-trail.json"), &trail).unwrap();
    std::fs::write(out.join("anchor-proof.json"), &proof).unwrap();
    std::fs::write(
        out.join("trust-root.der"),
        common::der_of(&common::pki().root),
    )
    .unwrap();
    std::fs::write(out.join("trust-root.pem"), common::root_pem()).unwrap();
}
