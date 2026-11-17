//! Public anchoring of chain heads (docs/32 §5, `FG-158`): after a day closes the worker
//! anchors every envelope's head of that day once, with a TSA token over the tree; each
//! envelope's proof verifies offline against its trail; a tampered head fails; the job
//! is idempotent and survives a crash at each of its steps.
//!
//! Needs `OPENSEAL_TEST_DATABASE_URL`; without it each test passes vacuously.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use casual_sign_sdk::anchor::{Anchor, AnchorOutcome, verify_anchor_proof};
use casual_sign_store::EnvelopeId;
use casual_sign_worker::anchor::{AnchorSink, SinkFailed, proof_files};
use casual_sign_worker::{Boundary, JobOutcome};
use common::{Env, Ids, pki};

const KIND: &str = "anchor_chain_heads";

/// Lines published, in order.
#[derive(Default)]
struct Lines(Mutex<Vec<Vec<u8>>>);

impl AnchorSink for Lines {
    fn publish(&self, line: &[u8]) -> Result<(), SinkFailed> {
        self.0.lock().unwrap().push(line.to_vec());
        Ok(())
    }
}

/// A world with anchoring on, three envelopes with events on the clock's day (one sent),
/// and the clock moved to ten minutes past that day's end.
async fn day_of_envelopes(test: &str) -> Option<(Env, Vec<Ids>, Arc<Lines>)> {
    let env = Env::new(test).await?;
    env.anchoring.store(true, Ordering::SeqCst);
    let lines = Arc::new(Lines::default());
    *env.anchor_sink.lock().unwrap() = Some(Arc::clone(&lines) as Arc<dyn AnchorSink>);
    let mut all = Vec::new();
    for _ in 0..3 {
        all.push(env.draft(vec![]).await);
    }
    env.send(all[1]).await;
    // Nothing is due during the day itself.
    env.run().await;
    assert_eq!(env.job_count(KIND, "done").await, 0);
    // The clock starts at 12:00 UTC: 12 h 10 min later the day's anchor is due.
    env.clock.advance(Duration::from_secs(12 * 3600 + 10 * 60));
    Some((env, all, lines))
}

async fn anchors(env: &Env) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM chain_anchors")
        .fetch_one(&env.db.admin)
        .await
        .unwrap()
}

async fn proofs(env: &Env, ids: Ids) -> (Vec<Vec<u8>>, Vec<u8>) {
    let mut tx = env.db.store.for_account(env.account).begin().await.unwrap();
    let leaves = tx.anchors().leaves_of(EnvelopeId(ids.env)).await.unwrap();
    let trail = tx
        .audit()
        .chain(EnvelopeId(ids.env))
        .await
        .unwrap()
        .to_trail_json()
        .unwrap();
    tx.commit().await.unwrap();
    (proof_files(EnvelopeId(ids.env), &leaves).unwrap(), trail)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_closed_day_is_anchored_and_each_envelope_proves_its_head() {
    let Some((env, all, lines)) = day_of_envelopes("anchor_day").await else {
        return;
    };
    let out = env.run().await;
    assert!(
        out.iter().any(|(k, o)| k == KIND && *o == JobOutcome::Done),
        "{out:?}"
    );
    assert_eq!(anchors(&env).await, 1);
    // Published once, naming no envelope.
    let published = lines.0.lock().unwrap().clone();
    assert_eq!(published.len(), 1);
    let anchor = Anchor::from_json(&published[0]).unwrap();
    assert_eq!(anchor.tree_size, 3);
    assert_eq!(anchor.period, "2026-11-01");
    let text = String::from_utf8(published[0].clone()).unwrap();
    for ids in &all {
        assert!(!text.contains(&ids.env.to_string()));
    }
    for ids in &all {
        let (files, trail) = proofs(&env, *ids).await;
        assert_eq!(files.len(), 1, "one anchor covers the envelope");
        let v = verify_anchor_proof(&files[0], Some(&trail), &pki::trust()).unwrap();
        assert_eq!(v.outcome(), AnchorOutcome::Passed, "{v:?}");
        assert_eq!(v.proof.anchor, anchor);

        // A tampered head fails the proof.
        let file = String::from_utf8(files[0].clone()).unwrap();
        let head = v.proof.head.to_string();
        let mut other = v.proof.head;
        other.0[0] ^= 0x80;
        let forged = file.replace(&head, &other.to_string());
        assert_ne!(forged, file);
        let bad = verify_anchor_proof(forged.as_bytes(), None, &pki::trust()).unwrap();
        assert_eq!(bad.outcome(), AnchorOutcome::Failed);
        assert_eq!(bad.inclusion.unwrap_err().code(), "CS-AUD-0009");
    }

    // Idempotent: more rounds, and a new worker process, anchor nothing more.
    env.run().await;
    env.clock.advance(Duration::from_secs(3600));
    env.run().await;
    assert_eq!(anchors(&env).await, 1);
    assert_eq!(env.job_count(KIND, "done").await, 1);
    assert_eq!(lines.0.lock().unwrap().len(), 1);

    // An event the next day: the next day's anchor covers the new head only.
    env.sign(all[1], all[1].r1, all[1].f1, "Ada Lovelace").await;
    env.clock.advance(Duration::from_secs(24 * 3600));
    env.run().await;
    assert_eq!(anchors(&env).await, 2);
    let (files, trail) = proofs(&env, all[1]).await;
    assert_eq!(files.len(), 2);
    for f in &files {
        let v = verify_anchor_proof(f, Some(&trail), &pki::trust()).unwrap();
        assert_eq!(v.outcome(), AnchorOutcome::Passed);
    }
    assert_eq!(proofs(&env, all[0]).await.0.len(), 1);
    env.db.drop().await;
}

/// Crash once at `at` in the anchor job, restart past the lease, run to idle: one anchor,
/// one done job, every proof still verifying.
async fn crash_and_restart(at: Boundary, test: &str) -> Option<(Env, Arc<Lines>)> {
    let (env, all, lines) = day_of_envelopes(test).await?;
    let r = env.incarnation(Some((at, KIND))).await;
    assert!(r.is_err(), "the worker did not reach {at:?}");
    env.after_crash();
    let out = env.run().await;
    assert!(
        out.iter().all(|(_, o)| *o == JobOutcome::Done),
        "after restart: {out:?}"
    );
    assert_eq!(anchors(&env).await, 1);
    assert_eq!(env.job_count(KIND, "done").await, 1);
    for ids in &all {
        let (files, trail) = proofs(&env, *ids).await;
        assert_eq!(files.len(), 1);
        let v = verify_anchor_proof(&files[0], Some(&trail), &pki::trust()).unwrap();
        assert_eq!(v.outcome(), AnchorOutcome::Passed);
    }
    Some((env, lines))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crash_after_the_timestamp_stores_one_anchor_on_restart() {
    let Some((env, lines)) = crash_and_restart(Boundary::Recorded, "anchor_crash_token").await
    else {
        return;
    };
    // Nothing was stored before the crash, so one publication.
    assert_eq!(lines.0.lock().unwrap().len(), 1);
    env.db.drop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crash_after_storing_publishes_the_same_anchor_again() {
    let Some((env, lines)) = crash_and_restart(Boundary::BeforeCommit, "anchor_crash_close").await
    else {
        return;
    };
    // Stored and published before the crash; the re-run publishes the same line again
    // (at least once), never a second anchor.
    let published = lines.0.lock().unwrap().clone();
    assert_eq!(published.len(), 2);
    assert_eq!(published[0], published[1]);
    env.db.drop().await;
}
