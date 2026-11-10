//! The repository methods migration 0009 added for the API server (stage 2C), called
//! with another account's ids, with row-level security on and disabled: each must
//! refuse, find nothing, or change nothing, exactly as `isolation.rs` requires of the
//! others.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use casual_sign_audit::Personal;
use casual_sign_store::repo::envelopes::{Cursor, EnvelopeStatus, Projection, SealProfile};
use casual_sign_store::repo::idempotency::Record;
use casual_sign_store::repo::recipients::RecipientStatus;
use casual_sign_store::repo::sessions::{LoginMethod, NewSession};
use casual_sign_store::*;
use common::world::{self, hash, id, now};
use common::{Rls, fresh};

fn projection(subject: &str) -> Projection {
    Projection {
        status: EnvelopeStatus::Draft,
        subject: Personal(subject.into()),
        message: Personal(String::new()),
        expires_at: None,
        reminder_policy: serde_json::json!({}),
        signing_options: serde_json::json!({}),
        seal_profile: SealProfile::PadesBT,
        sent_at: None,
        completed_at: None,
        voided_at: None,
        void_reason: None,
    }
}

async fn every_server_method_refuses_another_accounts_ids(rls: Rls) {
    let Some(db) = fresh("server_methods_refuse_cross_tenant", rls).await else {
        return;
    };
    let a = world::seed(&db.store, "alpha").await;
    let b = world::seed(&db.store, "bravo").await;

    // A's own: an envelope with engine state, a session, an idempotency record.
    let a_env = EnvelopeId(id());
    let a_session = StaffSessionId(id());
    {
        let mut tx = db.store.for_account(a.account).begin().await.unwrap();
        tx.envelopes()
            .insert(&world::new_envelope(a_env, a.user))
            .await
            .unwrap();
        tx.workflow_states()
            .insert(a_env, &serde_json::json!({"engine": "a"}), now())
            .await
            .unwrap();
        tx.envelopes()
            .set_host_client(a_env, a.api_client)
            .await
            .unwrap();
        tx.sessions()
            .create(&NewSession {
                id: a_session,
                user_id: a.user,
                token_sha256: hash("session-a"),
                csrf_sha256: hash("csrf-a"),
                method: LoginMethod::Password,
                created_at: now(),
                expires_at: now() + time::Duration::hours(8),
            })
            .await
            .unwrap();
        tx.users()
            .set_password_hash(a.user, &Personal("$argon2id$a".into()))
            .await
            .unwrap();
        tx.recipients()
            .set_access_code(a.recipient, id(), &Personal("$argon2id$code-a".into()))
            .await
            .unwrap();
        assert!(
            tx.idempotency()
                .put(
                    &Record {
                        principal: "user:a".into(),
                        key: "k1".into(),
                        request_sha256: hash("req"),
                        status: 201,
                        body: Some(b"{}".to_vec()),
                        created_at: now(),
                    },
                    now() - time::Duration::hours(24),
                )
                .await
                .unwrap()
        );
        tx.commit().await.unwrap();
    }

    let mut tx = db.store.for_account(b.account).begin().await.unwrap();
    // Envelope state: invisible, unwritable, and a B envelope cannot name A's client.
    assert!(tx.envelopes().host_client(a_env).await.unwrap().is_none());
    assert_eq!(
        tx.envelopes()
            .project(a_env, 1, &projection("x"))
            .await
            .unwrap_err()
            .code(),
        "CS-DB-0003"
    );
    assert_eq!(
        tx.envelopes()
            .set_host_client(a_env, b.api_client)
            .await
            .unwrap_err()
            .code(),
        "CS-DB-0003"
    );
    let page = tx.envelopes().page(None, None, None, 100).await.unwrap();
    assert!(
        page.iter().all(|e| e.id != a_env),
        "A's envelope listed for B"
    );
    let page = tx
        .envelopes()
        .page(
            Some(Cursor {
                created_at: now() + time::Duration::days(3650),
                id: a_env,
            }),
            None,
            Some(a.user),
            100,
        )
        .await
        .unwrap();
    assert!(page.is_empty());
    drop(tx);
    let mut tx = db.store.for_account(b.account).begin().await.unwrap();
    let b_env = EnvelopeId(id());
    tx.envelopes()
        .insert(&world::new_envelope(b_env, b.user))
        .await
        .unwrap();
    let err = tx
        .envelopes()
        .set_host_client(b_env, a.api_client)
        .await
        .unwrap_err();
    assert!(
        ["CS-DB-0008", "CS-DB-0009"].contains(&err.code()),
        "{err:?}"
    );
    drop(tx);

    // Recipients: A's recipient through B's envelope or B's account changes nothing.
    let mut tx = db.store.for_account(b.account).begin().await.unwrap();
    let mut n = world::new_recipient(a.recipient, a.envelope);
    n.name = Personal("Mallory".into());
    let err = tx
        .recipients()
        .upsert(&n, RecipientStatus::Completed, None)
        .await
        .unwrap_err();
    assert!(
        ["CS-DB-0006", "CS-DB-0008", "CS-DB-0009"].contains(&err.code()),
        "{err:?}"
    );
    drop(tx);
    let mut tx = db.store.for_account(b.account).begin().await.unwrap();
    assert_eq!(tx.recipients().prune(a.envelope, &[]).await.unwrap(), 0);
    assert!(
        tx.recipients()
            .token(&a.token_sha256)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !tx.recipients()
            .bind_token(a.token, &hash("browser"), now())
            .await
            .unwrap()
    );
    // API clients, users, sessions, idempotency.
    assert!(
        tx.api_clients()
            .list()
            .await
            .unwrap()
            .iter()
            .all(|c| c.id != a.api_client)
    );
    assert!(tx.users().password_hash(a.user).await.unwrap().is_none());
    assert_eq!(
        tx.users()
            .set_password_hash(a.user, &Personal("$argon2id$b".into()))
            .await
            .unwrap_err()
            .code(),
        "CS-DB-0003"
    );
    assert_eq!(
        tx.sessions()
            .revoke(a_session, now())
            .await
            .unwrap_err()
            .code(),
        "CS-DB-0003"
    );
    assert_eq!(tx.sessions().revoke_all(a.user, now()).await.unwrap(), 0);
    assert!(
        tx.idempotency()
            .get("user:a", "k1", now() - time::Duration::hours(24))
            .await
            .unwrap()
            .is_none()
    );
    let err = tx
        .sessions()
        .create(&NewSession {
            id: StaffSessionId(id()),
            user_id: a.user,
            token_sha256: hash("session-b-for-a"),
            csrf_sha256: hash("csrf"),
            method: LoginMethod::Password,
            created_at: now(),
            expires_at: now() + time::Duration::hours(8),
        })
        .await
        .unwrap_err();
    assert!(
        ["CS-DB-0008", "CS-DB-0009"].contains(&err.code()),
        "{err:?}"
    );
    drop(tx);

    // Access codes and finishing an idempotency record.
    let mut tx = db.store.for_account(b.account).begin().await.unwrap();
    assert!(
        tx.recipients()
            .access_code(a.recipient)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        tx.idempotency()
            .finish("user:a", "k1", 500, None)
            .await
            .unwrap_err()
            .code(),
        "CS-DB-0003"
    );
    let err = tx
        .recipients()
        .set_access_code(a.recipient, id(), &Personal("$argon2id$code-b".into()))
        .await
        .unwrap_err();
    assert!(
        ["CS-DB-0008", "CS-DB-0009"].contains(&err.code()),
        "{err:?}"
    );
    drop(tx);

    // B's idempotency record under A's principal and key is B's own, not A's.
    let mut tx = db.store.for_account(b.account).begin().await.unwrap();
    assert!(
        tx.idempotency()
            .put(
                &Record {
                    principal: "user:a".into(),
                    key: "k1".into(),
                    request_sha256: hash("other"),
                    status: 200,
                    body: None,
                    created_at: now(),
                },
                now() - time::Duration::hours(24),
            )
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();

    // A is untouched.
    let mut tx = db.store.for_account(a.account).begin().await.unwrap();
    let s = tx.workflow_states().get(a_env).await.unwrap().unwrap();
    assert_eq!(s.state, serde_json::json!({"engine": "a"}));
    assert_eq!(
        tx.envelopes().host_client(a_env).await.unwrap(),
        Some(a.api_client)
    );
    let r = tx.recipients().get(a.recipient).await.unwrap().unwrap();
    assert_ne!(r.recipient.name.get(), "Mallory");
    let t = tx
        .recipients()
        .token(&a.token_sha256)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(t.session_sha256, None);
    assert_eq!(
        tx.users()
            .password_hash(a.user)
            .await
            .unwrap()
            .unwrap()
            .get(),
        "$argon2id$a"
    );
    let rec = tx
        .idempotency()
        .get("user:a", "k1", now() - time::Duration::hours(24))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rec.request_sha256, hash("req"));
    assert_eq!(rec.status, 201);
    assert_eq!(
        tx.recipients()
            .access_code(a.recipient)
            .await
            .unwrap()
            .unwrap()
            .get(),
        "$argon2id$code-a"
    );
    drop(tx);
    let live = db
        .store
        .entry_points()
        .resolve_staff_session(&hash("session-a"), now())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(live.account_id, a.account);
    assert_eq!(live.session_id, a_session);
    assert_eq!(live.csrf_sha256, hash("csrf-a"));
    db.drop().await;
}

#[tokio::test]
async fn every_server_method_refuses_another_accounts_ids_with_rls() {
    every_server_method_refuses_another_accounts_ids(Rls::On).await;
}

#[tokio::test]
async fn every_server_method_refuses_another_accounts_ids_without_rls() {
    every_server_method_refuses_another_accounts_ids(Rls::Off).await;
}

/// Engine state round-trips, saves only at the version read, and the projection and
/// page follow it; a token binds once; sessions end on revoke, on expiry and when the
/// membership goes.
#[tokio::test]
async fn engine_state_tokens_and_sessions_behave() {
    let Some(db) = fresh("engine_state_tokens_and_sessions", Rls::On).await else {
        return;
    };
    let a = world::seed(&db.store, "alpha").await;
    let env = EnvelopeId(id());
    let mut tx = db.store.for_account(a.account).begin().await.unwrap();
    tx.envelopes()
        .insert(&world::new_envelope(env, a.user))
        .await
        .unwrap();
    tx.workflow_states()
        .insert(env, &serde_json::json!({"v": 0}), now())
        .await
        .unwrap();
    assert_eq!(tx.envelopes().host_client(env).await.unwrap(), None);
    let row_version = tx.envelopes().get(env).await.unwrap().unwrap().version;
    let mut p = projection("Changed");
    p.status = EnvelopeStatus::Voided;
    p.voided_at = Some(now());
    p.void_reason = Some(Personal("why".into()));
    let v = tx.envelopes().project(env, row_version, &p).await.unwrap();
    assert_eq!(v, row_version + 1);
    assert_eq!(
        tx.envelopes()
            .project(env, row_version, &p)
            .await
            .unwrap_err()
            .code(),
        "CS-DB-0007"
    );
    tx.commit().await.unwrap();
    let mut tx = db.store.for_account(a.account).begin().await.unwrap();
    let e = tx.envelopes().get(env).await.unwrap().unwrap();
    assert_eq!(e.status, EnvelopeStatus::Voided);
    assert_eq!(e.subject.get(), "Changed");
    // The page lists only envelopes with engine state (the seeded one has none).
    let page = tx.envelopes().page(None, None, None, 10).await.unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].id, env);
    let after = tx
        .envelopes()
        .page(
            Some(Cursor {
                created_at: page[0].created_at,
                id: page[0].id,
            }),
            None,
            None,
            10,
        )
        .await
        .unwrap();
    assert!(after.is_empty());
    // A token binds once.
    assert!(
        tx.recipients()
            .bind_token(a.token, &hash("browser-1"), now())
            .await
            .unwrap()
    );
    assert!(
        !tx.recipients()
            .bind_token(a.token, &hash("browser-2"), now())
            .await
            .unwrap()
    );
    let t = tx
        .recipients()
        .token(&a.token_sha256)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(t.session_sha256, Some(hash("browser-1")));
    // Upsert updates the projection; prune keeps referenced rows.
    let mut n = world::new_recipient(a.recipient, a.envelope);
    n.routing_order = 7;
    tx.recipients()
        .upsert(&n, RecipientStatus::Delivered, None)
        .await
        .unwrap();
    let extra = RecipientId(id());
    tx.recipients()
        .upsert(
            &world::new_recipient(extra, a.envelope),
            RecipientStatus::Created,
            None,
        )
        .await
        .unwrap();
    assert_eq!(tx.recipients().prune(a.envelope, &[]).await.unwrap(), 1);
    let r = tx.recipients().get(a.recipient).await.unwrap().unwrap();
    assert_eq!(r.recipient.routing_order, 7);
    assert_eq!(r.status, RecipientStatus::Delivered);
    assert!(tx.recipients().get(extra).await.unwrap().is_none());
    // Sessions.
    let sid = StaffSessionId(id());
    tx.sessions()
        .create(&NewSession {
            id: sid,
            user_id: a.user,
            token_sha256: hash("s1"),
            csrf_sha256: hash("c1"),
            method: LoginMethod::Password,
            created_at: now(),
            expires_at: now() + time::Duration::hours(1),
        })
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let ep = db.store.entry_points();
    assert!(
        ep.resolve_staff_session(&hash("s1"), now())
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        ep.resolve_staff_session(&hash("s1"), now() + time::Duration::hours(2))
            .await
            .unwrap()
            .is_none(),
        "expired session resolved"
    );
    let mut tx = db.store.for_account(a.account).begin().await.unwrap();
    tx.sessions().revoke(sid, now()).await.unwrap();
    tx.commit().await.unwrap();
    assert!(
        ep.resolve_staff_session(&hash("s1"), now())
            .await
            .unwrap()
            .is_none(),
        "revoked session resolved"
    );
    db.drop().await;
}
