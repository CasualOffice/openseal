//! The two-person rule (`SEC-X08`, docs/23 §5.1): suspending or resuming an organization
//! needs a request, a grant by another operator with a fresh second factor, and an apply
//! by the requester with a fresh second factor, each once; the database refuses every
//! shortcut.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    missing_docs
)]

mod common;

use axum::http::StatusCode;
use casual_sign_platform_store::sqlx;
use common::{Console, Session};
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery staple";

/// The owner and a second operator (role `operator`), both signed in; their seeds.
async fn two_operators(c: &Console) -> (Session, Vec<u8>, Session, Vec<u8>) {
    let owner_seed = c.bootstrap("owner@ops.example", PASSWORD).await;
    let owner = c.sign_in("owner@ops.example", PASSWORD, &owner_seed).await;
    let r = c
        .call(
            &owner,
            "POST",
            "/console/v1/operators",
            Some(json!({"email": "second@ops.example", "roles": ["operator"]})),
        )
        .await;
    let token = r.json()["enrolment_token"].as_str().unwrap().to_owned();
    let second_seed = c.enrol(&token, "second operator pw").await;
    let second = c
        .sign_in("second@ops.example", "second operator pw", &second_seed)
        .await;
    // Signing the owner in again keeps both sessions within their 30-minute idle window
    // and the owner's second factor fresh.
    let owner = c.sign_in("owner@ops.example", PASSWORD, &owner_seed).await;
    (owner, owner_seed, second, second_seed)
}

async fn status(db: &common::TestDb, org: uuid::Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM organizations WHERE id = $1")
        .bind(org)
        .fetch_one(&db.owner)
        .await
        .unwrap()
}

async fn request(c: &Console, s: &Session, action: &str, org: uuid::Uuid) -> String {
    let r = c
        .call(
            s,
            "POST",
            "/console/v1/approvals",
            Some(json!({"action": action, "organization": org})),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text);
    r.json()["id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn suspension_needs_a_second_operator_and_each_approval_works_once() {
    let Some(db) =
        common::fresh("suspension_needs_a_second_operator_and_each_approval_works_once").await
    else {
        return;
    };
    let seed = db.seed().await;
    let c = common::console(&db);
    let (owner, _, second, _) = two_operators(&c).await;
    let org = seed.org;
    let suspend = format!("/console/v1/organizations/{org}/suspend");

    // Without any approval, and with a made-up one.
    let r = c
        .call(
            &owner,
            "POST",
            &suspend,
            Some(json!({"approval": uuid::Uuid::now_v7()})),
        )
        .await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::CONFLICT, "CS-CON-0004"),
        "{}",
        r.text
    );

    // Requested but not granted.
    let id = request(&c, &owner, "organization.suspend", org).await;
    let r = c
        .call(&owner, "POST", &suspend, Some(json!({"approval": id})))
        .await;
    assert_eq!(r.code(), "CS-CON-0004", "ungranted");

    // The requester cannot grant their own request.
    let r = c
        .call(
            &owner,
            "POST",
            &format!("/console/v1/approvals/{id}/grant"),
            None,
        )
        .await;
    assert_eq!(r.code(), "CS-CON-0004", "self-approval");

    // Granted by the second operator.
    let r = c
        .call(
            &second,
            "POST",
            &format!("/console/v1/approvals/{id}/grant"),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.text);

    // The grant does not cover another action or another organization.
    let resume = format!("/console/v1/organizations/{org}/resume");
    let r = c
        .call(&owner, "POST", &resume, Some(json!({"approval": id})))
        .await;
    assert_eq!(r.code(), "CS-CON-0004", "another action");
    let other = uuid::Uuid::now_v7();
    let r = c
        .call(
            &owner,
            "POST",
            &format!("/console/v1/organizations/{other}/suspend"),
            Some(json!({"approval": id})),
        )
        .await;
    assert_eq!(r.code(), "CS-CON-0004", "another organization");
    // Nor another applier.
    let r = c
        .call(&second, "POST", &suspend, Some(json!({"approval": id})))
        .await;
    assert_eq!(r.code(), "CS-CON-0004", "the approver applying");

    // Applied once; a second use is refused.
    let r = c
        .call(&owner, "POST", &suspend, Some(json!({"approval": id})))
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.text);
    assert_eq!(status(&db, org).await, "suspended");
    let r = c
        .call(&owner, "POST", &suspend, Some(json!({"approval": id})))
        .await;
    assert_eq!(r.code(), "CS-CON-0004", "reused approval");

    // Resume through its own request and grant.
    let id2 = request(&c, &owner, "organization.resume", org).await;
    c.call(
        &second,
        "POST",
        &format!("/console/v1/approvals/{id2}/grant"),
        None,
    )
    .await;
    let r = c
        .call(&owner, "POST", &resume, Some(json!({"approval": id2})))
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.text);
    assert_eq!(status(&db, org).await, "active");

    let list = c
        .call(&owner, "GET", "/console/v1/approvals", None)
        .await
        .json();
    let rows = list["approvals"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|a| a["used"] == Value::Bool(true)));
    let log = c
        .call(&owner, "GET", "/console/v1/operator-log?limit=200", None)
        .await;
    for a in [
        "operator.approval.requested",
        "operator.approval.granted",
        "operator.organization.suspended",
        "operator.organization.resumed",
    ] {
        assert!(log.text.contains(a), "missing {a}");
    }
    db.drop().await;
}

#[tokio::test]
async fn sensitive_steps_need_a_second_factor_from_the_last_five_minutes() {
    let Some(db) =
        common::fresh("sensitive_steps_need_a_second_factor_from_the_last_five_minutes").await
    else {
        return;
    };
    let seed = db.seed().await;
    let c = common::console(&db);
    let (owner, owner_seed, second, second_seed) = two_operators(&c).await;
    let org = seed.org;
    let id = request(&c, &owner, "organization.suspend", org).await;

    // Six minutes on, both sessions are live but their second factors are stale.
    c.clock.advance(6 * 60);
    let r = c
        .call(
            &second,
            "POST",
            &format!("/console/v1/approvals/{id}/grant"),
            None,
        )
        .await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::UNAUTHORIZED, "CS-CON-0002"),
        "stale grant"
    );
    let r = c
        .call(
            &owner,
            "POST",
            "/console/v1/approvals",
            Some(json!({"action": "organization.suspend", "organization": org})),
        )
        .await;
    assert_eq!(r.code(), "CS-CON-0002", "stale request");

    // Re-entering the code refreshes it.
    let code = c.next_code(&second_seed);
    let r = c
        .call(
            &second,
            "POST",
            "/console/v1/auth/totp",
            Some(json!({"code": code})),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text);
    let r = c
        .call(
            &second,
            "POST",
            &format!("/console/v1/approvals/{id}/grant"),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.text);
    let r = c
        .call(
            &owner,
            "POST",
            &format!("/console/v1/organizations/{org}/suspend"),
            Some(json!({"approval": id})),
        )
        .await;
    assert_eq!(r.code(), "CS-CON-0002", "stale apply");
    let code = c.next_code(&owner_seed);
    c.call(
        &owner,
        "POST",
        "/console/v1/auth/totp",
        Some(json!({"code": code})),
    )
    .await;
    let r = c
        .call(
            &owner,
            "POST",
            &format!("/console/v1/organizations/{org}/suspend"),
            Some(json!({"approval": id})),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.text);

    // SEC-X08: the console role cannot write the status, or the approval tables, directly.
    for sql in [
        "UPDATE organizations SET status = 'active'",
        "INSERT INTO platform.approval_grants (request_id, approver, mfa_at, granted_at) VALUES (gen_random_uuid(), gen_random_uuid(), now(), now())",
        "INSERT INTO platform.approval_uses (request_id, used_by, used_at) VALUES (gen_random_uuid(), gen_random_uuid(), now())",
    ] {
        let err = sqlx::query(sql).execute(&db.console).await.expect_err(sql);
        let code = err
            .as_database_error()
            .and_then(|d| d.code())
            .unwrap_or_default();
        assert_eq!(code, "42501", "{sql}");
    }
    db.drop().await;
}
