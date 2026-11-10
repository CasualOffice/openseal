//! A two-signer envelope driven through the workflow and the store to `completed` by
//! the worker: invitations by email with working links, routing, the seal job (fill,
//! flatten, certificate with the trail, PAdES B-T with the test TSA, independent
//! verification), completion copies and signed webhooks. The sealed PDF is checked by
//! our verifier and by pyHanko (`tools/verify-sealed.py`, when `OPENSEAL_VERIFY_PYTHON`
//! names a Python with pyHanko).
//!
//! Needs `OPENSEAL_TEST_DATABASE_URL` (a PostgreSQL 17 superuser URL); without it each
//! test prints a note and passes vacuously, as the store's tests do.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::path::Path;
use std::sync::atomic::Ordering;

use casual_sign_audit::Hash256;
use casual_sign_model::EnvelopeStatus;
use casual_sign_sdk::Profile;
use casual_sign_worker::JobOutcome;
use common::{Env, SECRET, pki};

fn verify_hmac(req: &common::Req) -> bool {
    let id = &req.headers["webhook-id"];
    let ts: i64 = req.headers["webhook-timestamp"].parse().unwrap();
    let key = casual_sign_worker::webhook::secret_key(SECRET).unwrap();
    let want = casual_sign_worker::webhook::signature(&[key], id, ts, &req.body);
    req.headers["webhook-signature"] == want
}

/// Write `files` with a manifest (`level` B-T) and the seal root, then run pyHanko.
fn independent(dir: &Path, files: &[(String, Vec<u8>)]) {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();
    let mut manifest = String::from("file\texpect\twhy\tlevel\n");
    for (name, bytes) in files {
        std::fs::write(dir.join(name), bytes).unwrap();
        manifest.push_str(&format!("{name}\tintact\tT-2D worker seal\tB-T\n"));
    }
    std::fs::write(dir.join("manifest.tsv"), manifest).unwrap();
    std::fs::write(dir.join("trust-root.pem"), pki::root_pem()).unwrap();
    let Ok(python) = std::env::var("OPENSEAL_VERIFY_PYTHON") else {
        eprintln!(
            "NOTE: OPENSEAL_VERIFY_PYTHON is not set; pyHanko not run over {}",
            dir.display()
        );
        return;
    };
    let script = common::repo_root().join("tools/verify-sealed.py");
    let out = std::process::Command::new(python)
        .arg("-I")
        .arg(script)
        .arg(dir)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    eprintln!(
        "pyHanko (tools/verify-sealed.py {}):\n{text}",
        dir.display()
    );
    assert!(out.status.success(), "pyHanko disagreed:\n{text}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_signers_reach_completed_with_a_verified_seal() {
    let Some(env) = Env::new("two_signers_reach_completed").await else {
        return;
    };
    env.subscribe(&["*"]).await;
    let ids = env.draft(vec![]).await;
    env.send(ids).await;
    let out = env.run().await;
    assert!(out.iter().all(|(_, o)| *o == JobOutcome::Done), "{out:?}");

    // The first signer is invited, with a link that resolves to them; the second waits.
    let r1_mail = env.smtp.to(&env.email_of(ids.r1));
    assert_eq!(r1_mail.len(), 1);
    assert!(env.smtp.to(&env.email_of(ids.r2)).is_empty());
    assert_eq!(env.count(ids.env, "invitation.sent").await, 1);
    let token = r1_mail[0].token().unwrap();
    let target = env
        .db
        .store
        .entry_points()
        .resolve_recipient_token(
            Hash256::digest(token.as_bytes()).as_bytes(),
            casual_sign_worker::apply::odt(env.clock.ts()).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(target.recipient_id.0, ids.r1);
    // No document content, and nothing but the template's text and the supplied fields.
    let body = r1_mail[0].body();
    assert!(body.contains("Hello Ada Lovelace"));
    assert!(body.contains("Please sign at your convenience."));
    assert!(!body.contains("%PDF"));

    env.sign(ids, ids.r1, ids.f1, "Ada Lovelace").await;
    env.run().await;
    assert_eq!(env.smtp.to(&env.email_of(ids.r2)).len(), 1);
    let last = env.sign(ids, ids.r2, ids.f2, "Grace Hopper").await;
    assert_eq!(last.state.status, EnvelopeStatus::Completing);
    let out = env.run().await;
    assert!(out.iter().all(|(_, o)| *o == JobOutcome::Done), "{out:?}");

    let state = env.state(ids.env).await;
    assert_eq!(state.status, EnvelopeStatus::Completed);
    for ty in [
        "document.flattened",
        "document.sealed",
        "envelope.completed",
    ] {
        assert_eq!(env.count(ids.env, ty).await, 1, "{ty}");
    }
    assert_eq!(
        env.signatures.load(Ordering::SeqCst),
        1,
        "one document, one seal"
    );

    // Completion copies to both signers, with a link.
    for r in [ids.r1, ids.r2] {
        let mails = env.smtp.to(&env.email_of(r));
        let done: Vec<_> = mails
            .iter()
            .filter(|m| m.body().contains("All parties have completed"))
            .collect();
        assert_eq!(done.len(), 1);
        assert!(done[0].token().is_some());
    }

    // Webhooks: every one signed, ids and statuses only.
    let reqs = env.hook.requests();
    assert!(!reqs.is_empty());
    let mut types = Vec::new();
    for r in &reqs {
        assert!(verify_hmac(r), "signature");
        let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        types.push(v["type"].as_str().unwrap().to_owned());
        let text = String::from_utf8_lossy(&r.body);
        for secret in ["Ada", "Grace", "example.test", "Master services"] {
            assert!(!text.contains(secret), "webhook carries {secret}");
        }
    }
    assert!(types.iter().any(|t| t == "envelope.sent"), "{types:?}");
    assert!(types.iter().any(|t| t == "envelope.completed"), "{types:?}");

    // The sealed PDF: our verifier, then pyHanko.
    let sealed = env.sealed_bytes(ids.env).await;
    assert_eq!(sealed.len(), 1);
    assert!(sealed[0].starts_with(&env.delivered));
    let mut options = env.engine.verify_options(std::time::Duration::from_millis(
        u64::try_from(env.clock.ms()).unwrap(),
    ));
    options.crls = vec![pki::pki().root_crl.clone(), pki::pki().inter_crl.clone()];
    let report = env.engine.verify(&sealed[0], &pki::trust(), &options);
    casual_sign_worker::seal::check_verified(&report, Profile::BaselineT).unwrap();
    assert!(report.all_passed(), "with CRLs supplied every check passes");
    eprintln!(
        "ours: {} signature(s), indication {:?}, covered {}",
        report.signatures.len(),
        report.signatures.last().map(|s| s.indication),
        report.covered_by_last_signature
    );
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("worker-flow-sealed");
    independent(&dir, &[("two-signers-bt.pdf".into(), sealed[0].clone())]);

    // Nothing dead, nothing left.
    assert!(env.alerts.0.lock().unwrap().is_empty());
    for (k, s, _) in env.jobs().await {
        assert_eq!(s, "done", "{k}");
    }
}

/// An envelope is never `completed` without a verified seal: when the stored seal does
/// not verify (here the worker's anchors are gone, so no chain builds), the worker
/// reports `SealFailed`, the operator is alerted, and the envelope stays `completing`
/// with a new seal job scheduled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unverified_seal_never_completes_the_envelope() {
    let Some(env) = Env::new("an_unverified_seal_never_completes").await else {
        return;
    };
    let ids = env.draft(vec![]).await;
    env.send(ids).await;
    env.run().await;
    env.sign(ids, ids.r1, ids.f1, "Ada Lovelace").await;
    env.run().await;
    env.sign(ids, ids.r2, ids.f2, "Grace Hopper").await;
    env.untrusted.store(true, Ordering::SeqCst);
    env.run().await;
    let state = env.state(ids.env).await;
    assert_eq!(state.status, EnvelopeStatus::Completing);
    assert_eq!(env.count(ids.env, "envelope.completed").await, 0);
    assert_eq!(env.count(ids.env, "document.sealed").await, 0);
    let alerts = env.alerts.0.lock().unwrap().clone();
    assert!(
        alerts
            .iter()
            .any(|a| a.kind == "seal_failed" && a.code == "CS-WRK-0012"),
        "{alerts:?}"
    );
    // A new seal job waits for the retry delay.
    assert!(state.book.seal_job.is_some());
    assert_eq!(env.job_count("seal_envelope", "queued").await, 1);
}

/// Invitation to an address the SMTP server refuses permanently is a bounce, fed back
/// as `InvitationBounced`; the sender is told.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_address_is_a_bounce() {
    let Some(env) = Env::new("a_refused_address_is_a_bounce").await else {
        return;
    };
    let ids = env.draft(vec![]).await;
    env.smtp.reject.lock().unwrap().push(env.email_of(ids.r1));
    env.send(ids).await;
    env.run().await;
    assert_eq!(env.count(ids.env, "invitation.bounced").await, 1);
    assert_eq!(env.count(ids.env, "invitation.sent").await, 0);
    let state = env.state(ids.env).await;
    let r1 = state.recipient(&common::id(ids.r1)).unwrap();
    assert_eq!(
        serde_json::to_value(r1.status).unwrap(),
        serde_json::json!("auto_responded")
    );
}
