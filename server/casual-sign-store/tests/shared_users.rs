//! SEC-ID-01: a user who belongs to more than one account. `users` has no account
//! column, so a change to the row (password, name, email, global disabled state) is seen
//! by every account the user belongs to. Another account's administrator must not make
//! it: the store refuses with `CS-DB-0009` (SQLSTATE `OS003`) when the user has a
//! membership outside the acting account, with row-level security on and off, and the
//! `users` update policy refuses it too. The user themselves changes their own row
//! through their live session, and a new password ends their sessions in every account.

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
use casual_sign_store::repo::sessions::{LoginMethod, NewSession};
use casual_sign_store::*;
use common::world::{self, World, hash, id, now};
use common::{Rls, TestDb, fresh};

/// A and B, with A's user also a member of B.
async fn shared(db: &TestDb) -> (World, World) {
    let a = world::seed(db, "alpha").await;
    let b = world::seed(db, "bravo").await;
    let mut tx = db.store.for_account(a.account).begin().await.unwrap();
    tx.users()
        .set_password_hash(a.user, &Personal("$argon2id$a".into()))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let mut tx = db.store.for_account(b.account).begin().await.unwrap();
    tx.users()
        .add_existing_member(a.user, &Personal("alpha@example.test".into()), b.profile)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    (a, b)
}

fn shared_user_refusal() -> StoreError {
    let e = StoreError::Refused {
        sqlstate: "OS003".into(),
    };
    assert!(e.is_shared_user());
    e
}

async fn session(db: &TestDb, account: AccountId, user: UserId, tag: &str) -> StaffSessionId {
    let sid = StaffSessionId(id());
    let mut tx = db.store.for_account(account).begin().await.unwrap();
    tx.sessions()
        .create(&NewSession {
            id: sid,
            user_id: user,
            token_sha256: hash(tag),
            csrf_sha256: hash(&format!("csrf-{tag}")),
            method: LoginMethod::Password,
            created_at: now(),
            expires_at: now() + time::Duration::hours(8),
        })
        .await
        .unwrap();
    tx.commit().await.unwrap();
    sid
}

async fn live(db: &TestDb, tag: &str) -> bool {
    db.store
        .entry_points()
        .resolve_staff_session(&hash(tag), now())
        .await
        .unwrap()
        .is_some()
}

async fn a_view(db: &TestDb, a: &World) -> (String, Option<String>) {
    let mut tx = db.store.for_account(a.account).begin().await.unwrap();
    let m = tx.users().get(a.user).await.unwrap().unwrap();
    let phc = tx.users().password_hash(a.user).await.unwrap().map(|p| p.0);
    (m.name.0, phc)
}

async fn another_account_cannot_change_a_shared_users_row(rls: Rls) {
    let Some(db) = fresh("shared_user_row_refused", rls).await else {
        return;
    };
    let (a, b) = shared(&db).await;
    let before = a_view(&db, &a).await;

    let mut tx = db.store.for_account(b.account).begin().await.unwrap();
    let e = tx
        .users()
        .set_password_hash(a.user, &Personal("$argon2id$b".into()))
        .await
        .unwrap_err();
    assert_eq!(e.code(), "CS-DB-0009", "{e}");
    assert_eq!(e, shared_user_refusal());
    let e = tx
        .users()
        .rename(a.user, &Personal("Taken over".into()))
        .await
        .unwrap_err();
    assert_eq!(e.code(), "CS-DB-0009", "{e}");
    assert_eq!(e, shared_user_refusal());
    // B's own sole member is still B's to change.
    tx.users()
        .rename(b.user, &Personal("Renamed by B".into()))
        .await
        .unwrap();
    tx.users()
        .set_password_hash(b.user, &Personal("$argon2id$b-own".into()))
        .await
        .unwrap();
    tx.commit().await.unwrap();

    assert_eq!(a_view(&db, &a).await, before, "A's user changed from B");
    // Seen from A, where it is a member of B too, A cannot change it either.
    let mut tx = db.store.for_account(a.account).begin().await.unwrap();
    let e = tx
        .users()
        .set_password_hash(a.user, &Personal("$argon2id$a2".into()))
        .await
        .unwrap_err();
    assert_eq!(e, shared_user_refusal());
    drop(tx);
    assert_eq!(a_view(&db, &a).await, before);
    db.drop().await;
}

#[tokio::test]
async fn another_account_cannot_change_a_shared_users_row_rls_on() {
    another_account_cannot_change_a_shared_users_row(Rls::On).await;
}

#[tokio::test]
async fn another_account_cannot_change_a_shared_users_row_rls_off() {
    another_account_cannot_change_a_shared_users_row(Rls::Off).await;
}

/// The second line: an UPDATE the repository did not guard, as the application role in
/// B, changes no row of a user who also belongs to A.
#[tokio::test]
async fn row_level_security_refuses_an_unguarded_update_of_a_shared_user() {
    let Some(db) = fresh("shared_user_rls_update", Rls::On).await else {
        return;
    };
    let (a, b) = shared(&db).await;
    let before = a_view(&db, &a).await;
    let mut conn = db.app.begin().await.unwrap();
    sqlx::query("SELECT set_config('openseal.account_id', $1, true)")
        .bind(b.account.to_string())
        .execute(&mut *conn)
        .await
        .unwrap();
    let done = sqlx::query(
        "UPDATE users SET name = 'x', password_hash = 'y', email = 'z@x.test', \
         disabled_at = now() WHERE id = $1",
    )
    .bind(a.user.0)
    .execute(&mut *conn)
    .await
    .unwrap();
    assert_eq!(done.rows_affected(), 0, "RLS let B update A's user");
    // B's sole member is still updatable through the policy.
    let done = sqlx::query("UPDATE users SET name = 'ok' WHERE id = $1")
        .bind(b.user.0)
        .execute(&mut *conn)
        .await
        .unwrap();
    assert_eq!(done.rows_affected(), 1);
    conn.commit().await.unwrap();
    assert_eq!(a_view(&db, &a).await, before);
    db.drop().await;
}

async fn the_user_changes_their_own_row_and_every_session_ends(rls: Rls) {
    let Some(db) = fresh("shared_user_update_own", rls).await else {
        return;
    };
    let (a, b) = shared(&db).await;
    let in_a = session(&db, a.account, a.user, "s-a").await;
    let in_b = session(&db, b.account, a.user, "s-b").await;
    let b_admin = session(&db, b.account, b.user, "s-b-admin").await;

    let mut tx = db.store.for_account(b.account).begin().await.unwrap();
    // Another member's session, a session of another account, an unknown session: none
    // of them changes A's user.
    for s in [b_admin, in_a, StaffSessionId(id())] {
        let who = tx
            .users()
            .update_own(s, Some(&Personal("Hijack".into())), None, now())
            .await
            .unwrap();
        assert_ne!(who, Some(a.user), "{s:?}");
    }
    // A name alone ends no session.
    assert_eq!(
        tx.users()
            .update_own(in_b, Some(&Personal("Self".into())), None, now())
            .await
            .unwrap(),
        Some(a.user)
    );
    tx.commit().await.unwrap();
    assert!(live(&db, "s-a").await && live(&db, "s-b").await);
    assert_eq!(a_view(&db, &a).await.0, "Self");

    let mut tx = db.store.for_account(b.account).begin().await.unwrap();
    assert_eq!(
        tx.users()
            .update_own(in_b, None, Some(&Personal("$argon2id$self".into())), now())
            .await
            .unwrap(),
        Some(a.user)
    );
    tx.commit().await.unwrap();
    assert_eq!(a_view(&db, &a).await.1.as_deref(), Some("$argon2id$self"));
    assert!(
        !live(&db, "s-a").await,
        "A's session outlived the new password"
    );
    assert!(
        !live(&db, "s-b").await,
        "B's session outlived the new password"
    );
    assert!(live(&db, "s-b-admin").await, "another user's session ended");
    // The ended session can change nothing more.
    let mut tx = db.store.for_account(b.account).begin().await.unwrap();
    assert_eq!(
        tx.users()
            .update_own(in_b, Some(&Personal("Again".into())), None, now())
            .await
            .unwrap(),
        None
    );
    drop(tx);
    db.drop().await;
}

#[tokio::test]
async fn the_user_changes_their_own_row_and_every_session_ends_rls_on() {
    the_user_changes_their_own_row_and_every_session_ends(Rls::On).await;
}

#[tokio::test]
async fn the_user_changes_their_own_row_and_every_session_ends_rls_off() {
    the_user_changes_their_own_row_and_every_session_ends(Rls::Off).await;
}

async fn an_invitation_sets_a_shared_users_password_and_ends_every_session(rls: Rls) {
    let Some(db) = fresh("shared_user_invitation", rls).await else {
        return;
    };
    let (a, b) = shared(&db).await;
    let _ = session(&db, a.account, a.user, "s-a").await;
    let inv = UserInvitationId(id());
    let unsent = UserInvitationId(id());
    let mut tx = db.store.for_account(b.account).begin().await.unwrap();
    tx.users()
        .create_invitation(inv, a.user, b.user, now())
        .await
        .unwrap();
    tx.users()
        .create_invitation(unsent, a.user, b.user, now())
        .await
        .unwrap();
    assert!(
        tx.users()
            .set_invitation_token(inv, &hash("inv"), now() + time::Duration::days(1), now())
            .await
            .unwrap()
    );
    let phc = Personal("$argon2id$invited".to_owned());
    // Never sent: no link, nothing to spend.
    assert_eq!(
        tx.users()
            .accept_invitation_with_password(unsent, &phc, now())
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        tx.users()
            .accept_invitation_with_password(inv, &phc, now())
            .await
            .unwrap(),
        Some(a.user)
    );
    // A second use of the link.
    assert_eq!(
        tx.users()
            .accept_invitation_with_password(inv, &phc, now())
            .await
            .unwrap(),
        None
    );
    let all = tx.users().invitations(a.user).await.unwrap();
    assert!(
        all.iter()
            .all(|i| i.accepted_at.is_some() || i.revoked_at.is_some())
    );
    tx.commit().await.unwrap();
    assert_eq!(
        a_view(&db, &a).await.1.as_deref(),
        Some("$argon2id$invited")
    );
    assert!(
        !live(&db, "s-a").await,
        "A's session outlived the new password"
    );
    db.drop().await;
}

#[tokio::test]
async fn an_invitation_sets_a_shared_users_password_and_ends_every_session_rls_on() {
    an_invitation_sets_a_shared_users_password_and_ends_every_session(Rls::On).await;
}

#[tokio::test]
async fn an_invitation_sets_a_shared_users_password_and_ends_every_session_rls_off() {
    an_invitation_sets_a_shared_users_password_and_ends_every_session(Rls::Off).await;
}
