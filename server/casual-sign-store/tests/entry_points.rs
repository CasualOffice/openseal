//! The cross-account entry points: each secret hash leads to its own account's ids and
//! nothing else; dead secrets lead nowhere; the job queue's claim crosses accounts, but
//! finishing a job needs its account and its lease.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::time::Duration;

use casual_sign_store::*;
use common::world::{self, id, new_job, now};
use common::{Rls, fresh};
use sqlx::Executor;

#[tokio::test]
async fn secrets_resolve_to_their_own_account_and_dead_ones_to_nothing() {
    let Some(db) = fresh("secrets_resolve_to_their_own_account", Rls::On).await else {
        return;
    };
    let a = world::seed(&db.store, "alpha").await;
    let b = world::seed(&db.store, "bravo").await;
    let ep = db.store.entry_points();
    for w in [&a, &b] {
        let t = ep
            .resolve_recipient_token(&w.token_sha256, now())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (t.account_id, t.envelope_id, t.recipient_id),
            (w.account, w.envelope, w.recipient)
        );
        let k = ep
            .resolve_api_key(&w.api_secret_sha256, now())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(k, (w.account, w.api_client));
    }
    let unknown = world::hash("unknown");
    assert!(
        ep.resolve_recipient_token(&unknown, now())
            .await
            .unwrap()
            .is_none()
    );
    assert!(ep.resolve_api_key(&unknown, now()).await.unwrap().is_none());
    // Expired.
    let later = now() + time::Duration::days(31);
    assert!(
        ep.resolve_recipient_token(&a.token_sha256, later)
            .await
            .unwrap()
            .is_none()
    );
    // Revoked.
    let mut tx = db.store.for_account(a.account).begin().await.unwrap();
    assert_eq!(
        tx.recipients()
            .revoke_tokens(a.recipient, now())
            .await
            .unwrap(),
        1
    );
    tx.api_clients().revoke(a.api_client, now()).await.unwrap();
    tx.commit().await.unwrap();
    assert!(
        ep.resolve_recipient_token(&a.token_sha256, now())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        ep.resolve_api_key(&a.api_secret_sha256, now())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        ep.resolve_recipient_token(&b.token_sha256, now())
            .await
            .unwrap()
            .is_some()
    );

    // Login: an email leads to its user and every account they belong to.
    let logins = ep
        .resolve_user_login(Some("alpha@example.test"), None)
        .await
        .unwrap();
    assert_eq!(logins, vec![(a.user, a.account)]);
    let mut tx = db.store.for_account(b.account).begin().await.unwrap();
    tx.users()
        .add_existing_member(
            a.user,
            &casual_sign_audit::Personal("alpha@example.test".into()),
            b.profile,
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let mut logins = ep
        .resolve_user_login(Some("alpha@example.test"), None)
        .await
        .unwrap();
    logins.sort();
    let mut want = vec![(a.user, a.account), (a.user, b.account)];
    want.sort();
    assert_eq!(logins, want);
    assert!(
        ep.resolve_user_login(Some("nobody@example.test"), None)
            .await
            .unwrap()
            .is_empty()
    );

    // Signing links (no repository yet; written by the owner here).
    let link = id();
    db.admin
        .execute(sqlx::raw_sql(sqlx::AssertSqlSafe(
            format!(
                "INSERT INTO signing_links (id, account_id, template_id, owner_user_id, token_sha256, role_id, max_uses, use_count) \
                 VALUES ('{link}', '{}', '{}', '{}', '\\x{}', '{}', 1, 0)",
                a.account,
                a.template,
                a.user,
                casual_sign_audit::Hash256(world::hash("link")).hex(),
                a.role
            )))
        )
        .await
        .unwrap();
    let got = ep
        .resolve_signing_link(&world::hash("link"), now())
        .await
        .unwrap();
    assert_eq!(got, Some((a.account, SigningLinkId(link))));
    db.admin
        .execute(sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "UPDATE signing_links SET use_count = 1 WHERE id = '{link}'"
        ))))
        .await
        .unwrap();
    assert!(
        ep.resolve_signing_link(&world::hash("link"), now())
            .await
            .unwrap()
            .is_none()
    );
    db.drop().await;
}

#[tokio::test]
async fn jobs_are_claimed_across_accounts_but_finished_only_in_their_own_with_the_lease() {
    let Some(db) = fresh("jobs_are_claimed_across_accounts", Rls::On).await else {
        return;
    };
    let a = world::seed(&db.store, "alpha").await;
    let b = world::seed(&db.store, "bravo").await;
    // Enqueueing is idempotent per account.
    let mut tx = db.store.for_account(a.account).begin().await.unwrap();
    assert!(
        !tx.jobs()
            .enqueue(&new_job(JobId(id()), Some(a.envelope), "seed"))
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();

    let ep = db.store.entry_points();
    let lease = id();
    let mut claimed = ep
        .claim_jobs(
            "w1",
            &["send_invitation"],
            10,
            now(),
            Duration::from_secs(60),
            lease,
        )
        .await
        .unwrap();
    claimed.sort_by_key(|j| j.account_id);
    let mut want = vec![(a.account, a.job), (b.account, b.job)];
    want.sort();
    assert_eq!(
        claimed
            .iter()
            .map(|j| (j.account_id, j.id))
            .collect::<Vec<_>>(),
        want
    );
    assert!(claimed.iter().all(|j| j.attempts == 1));
    // Claimed jobs are not claimed again while the lease holds.
    let again = ep
        .claim_jobs(
            "w2",
            &["send_invitation"],
            10,
            now(),
            Duration::from_secs(60),
            id(),
        )
        .await
        .unwrap();
    assert!(again.is_empty());

    // B cannot finish A's job, even with the right lease; A cannot without it.
    let mut tx = db.store.for_account(b.account).begin().await.unwrap();
    assert_eq!(
        tx.jobs()
            .complete(a.job, lease, now())
            .await
            .unwrap_err()
            .code(),
        "CS-DB-0003"
    );
    drop(tx);
    let mut tx = db.store.for_account(a.account).begin().await.unwrap();
    assert_eq!(
        tx.jobs()
            .complete(a.job, id(), now())
            .await
            .unwrap_err()
            .code(),
        "CS-DB-0003"
    );
    tx.jobs().complete(a.job, lease, now()).await.unwrap();
    tx.commit().await.unwrap();

    // B's job fails, is requeued, its lease lapses, and another worker claims it.
    let mut tx = db.store.for_account(b.account).begin().await.unwrap();
    tx.jobs()
        .fail(b.job, lease, now(), "CS-X-0001")
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let st = {
        let mut tx = db.store.for_account(b.account).begin().await.unwrap();
        tx.jobs().get(b.job).await.unwrap().unwrap()
    };
    assert_eq!(
        (
            st.status.as_str(),
            st.attempts,
            st.last_error_code.as_deref()
        ),
        ("queued", 1, Some("CS-X-0001"))
    );
    let lease2 = id();
    let got = ep
        .claim_jobs(
            "w2",
            &["send_invitation"],
            10,
            now(),
            Duration::from_secs(1),
            lease2,
        )
        .await
        .unwrap();
    assert_eq!(got.iter().map(|j| j.id).collect::<Vec<_>>(), vec![b.job]);
    // The worker dies; after the lease, a third worker takes it (attempt 3 of 3).
    let lease3 = id();
    let got = ep
        .claim_jobs(
            "w3",
            &["send_invitation"],
            10,
            now() + time::Duration::seconds(5),
            Duration::from_secs(60),
            lease3,
        )
        .await
        .unwrap();
    assert_eq!(
        got.iter().map(|j| (j.id, j.attempts)).collect::<Vec<_>>(),
        vec![(b.job, 3)]
    );
    // The second worker's lease no longer finishes it; its last failure makes it dead.
    let mut tx = db.store.for_account(b.account).begin().await.unwrap();
    assert!(tx.jobs().complete(b.job, lease2, now()).await.is_err());
    drop(tx);
    let mut tx = db.store.for_account(b.account).begin().await.unwrap();
    tx.jobs()
        .fail(b.job, lease3, now(), "CS-X-0002")
        .await
        .unwrap();
    assert_eq!(tx.jobs().get(b.job).await.unwrap().unwrap().status, "dead");
    tx.commit().await.unwrap();
    let none = ep
        .claim_jobs(
            "w4",
            &["send_invitation"],
            10,
            now() + time::Duration::days(1),
            Duration::from_secs(60),
            id(),
        )
        .await
        .unwrap();
    assert!(none.is_empty());

    // A job whose last attempt's worker died becomes dead at the next claim.
    let last = JobId(id());
    let mut job = new_job(last, None, "one-shot");
    job.max_attempts = 1;
    let mut tx = db.store.for_account(a.account).begin().await.unwrap();
    assert!(tx.jobs().enqueue(&job).await.unwrap());
    tx.commit().await.unwrap();
    let got = ep
        .claim_jobs(
            "w5",
            &["send_invitation"],
            10,
            now(),
            Duration::from_secs(1),
            id(),
        )
        .await
        .unwrap();
    assert_eq!(got.iter().map(|j| j.id).collect::<Vec<_>>(), vec![last]);
    let none = ep
        .claim_jobs(
            "w6",
            &["send_invitation"],
            10,
            now() + time::Duration::minutes(1),
            Duration::from_secs(60),
            id(),
        )
        .await
        .unwrap();
    assert!(none.is_empty());
    let mut tx = db.store.for_account(a.account).begin().await.unwrap();
    assert_eq!(tx.jobs().get(last).await.unwrap().unwrap().status, "dead");
    drop(tx);
    db.drop().await;
}
