//! SEC-ID-01: an administrator of one account cannot set the password or name of a user
//! who is also a member of another account (`403 CS-API-0015`); that user's password,
//! name and sessions elsewhere are untouched. The user changing their own password ends
//! their sessions in every account.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::too_many_lines
)]

mod common;

use axum::http::StatusCode;
use casual_sign_audit::Personal;
use casual_sign_store::UserId;
use common::Rls;
use common::harness::{Api, Auth, session_of};
use serde_json::json;

const P1: &str = "first long passphrase";
const P2: &str = "second long passphrase";
const P3: &str = "third long passphrase";
const EMAIL: &str = "shared@alpha.example.test";

async fn login(api: &Api, password: &str, account: &str) -> Option<Auth> {
    let r = api
        .call(
            "POST",
            "/api/v1/auth/login",
            &Auth::None,
            Some(json!({"email": EMAIL, "password": password, "account_id": account})),
            &[],
        )
        .await;
    (r.status == StatusCode::OK).then(|| session_of(&r))
}

async fn alive(api: &Api, s: &Auth) -> bool {
    api.call("GET", "/api/v1/envelopes", s, None, &[])
        .await
        .status
        == StatusCode::OK
}

async fn shared_users(rls: Rls) {
    let Some(api) = Api::new(&format!("shared_users_{rls:?}"), rls).await else {
        return;
    };
    let alpha = api.tenant("alpha").await;
    let bravo = api.tenant("bravo").await;
    let (a_acct, b_acct) = (
        alpha.boot.account.to_string(),
        bravo.boot.account.to_string(),
    );
    // A user of alpha, then (as an accepted invitation would) an administrator of bravo.
    let r = api
        .call(
            "POST",
            "/api/v1/users",
            &alpha.auth,
            Some(json!({"email": EMAIL, "name": "Shared", "profile": "sender", "password": P1})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.json());
    let uid = r.json()["id"].as_str().unwrap().to_owned();
    let user = UserId(uuid::Uuid::parse_str(&uid).unwrap());
    let mut tx = api
        .db
        .store
        .for_account(bravo.boot.account)
        .begin()
        .await
        .unwrap();
    tx.users()
        .add_existing_member(user, &Personal(EMAIL.into()), bravo.boot.profiles[0])
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let in_alpha = login(&api, P1, &a_acct).await.expect("alpha login");

    // Bravo's administrator cannot take the account over, nor rename it.
    let path = format!("/api/v1/users/{uid}");
    for body in [
        json!({"password": P2}),
        json!({"name": "Taken over"}),
        json!({"name": "Taken over", "password": P2}),
    ] {
        let r = api.call("PATCH", &path, &bravo.auth, Some(body), &[]).await;
        assert_eq!(
            (r.status, r.code()),
            (StatusCode::FORBIDDEN, "CS-API-0015".into()),
            "{:?}",
            r.json()
        );
    }
    assert!(alive(&api, &in_alpha).await, "alpha session ended by bravo");
    assert!(
        login(&api, P2, &a_acct).await.is_none(),
        "bravo set the password"
    );
    let r = api.call("GET", &path, &alpha.auth, None, &[]).await;
    assert_eq!(r.json()["name"], "Shared");
    // Seen from alpha, the user is shared too: alpha cannot change it either.
    let r = api
        .call(
            "PATCH",
            &path,
            &alpha.auth,
            Some(json!({"password": P2})),
            &[],
        )
        .await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::FORBIDDEN, "CS-API-0015".into())
    );
    // Profile and disabling stay per account: bravo may still change its own membership.
    let r = api
        .call(
            "PATCH",
            &path,
            &bravo.auth,
            Some(json!({"profile": "admin"})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());

    // A sole member of bravo is still bravo's to change.
    let r = api
        .call(
            "POST",
            "/api/v1/users",
            &bravo.auth,
            Some(json!({"email": "only@bravo.example.test", "name": "Only", "profile": "sender", "password": P1})),
            &[],
        )
        .await;
    let only = r.json()["id"].as_str().unwrap().to_owned();
    let r = api
        .call(
            "PATCH",
            &format!("/api/v1/users/{only}"),
            &bravo.auth,
            Some(json!({"name": "Only renamed", "password": P2})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    assert_eq!(r.json()["name"], "Only renamed");

    // The user changes their own password from bravo: every session ends, alpha's too.
    let in_bravo = login(&api, P1, &b_acct).await.expect("bravo login");
    let r = api
        .call(
            "PATCH",
            &path,
            &in_bravo,
            Some(json!({"password": P3, "name": "Shared Self"})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    assert_eq!(r.json()["name"], "Shared Self");
    assert!(!alive(&api, &in_alpha).await, "alpha session outlived it");
    assert!(!alive(&api, &in_bravo).await, "bravo session outlived it");
    assert!(login(&api, P1, &a_acct).await.is_none());
    assert!(login(&api, P3, &a_acct).await.is_some());
    api.db.drop().await;
}

#[tokio::test]
async fn shared_users_are_changed_only_by_themselves_rls_on() {
    shared_users(Rls::On).await;
}

#[tokio::test]
async fn shared_users_are_changed_only_by_themselves_rls_off() {
    shared_users(Rls::Off).await;
}
