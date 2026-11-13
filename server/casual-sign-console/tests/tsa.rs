//! TSA endpoints in the console (`CON-07`, docs/23 §5.4): a change needs a proposal, a
//! grant by another key custodian and an apply by the proposer, each with a fresh second
//! factor (`SEC-X05`); a proposed URL that resolves to a private, loopback, link-local or
//! metadata address is refused (`SEC-X06`); the console cannot write the table directly.

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
use serde_json::json;

const PASSWORD: &str = "correct horse battery staple";

/// A new operator with `roles`, enrolled and signed in.
async fn operator(c: &Console, owner: &Session, email: &str, roles: &[&str]) -> (Session, Vec<u8>) {
    let r = c
        .call(
            owner,
            "POST",
            "/console/v1/operators",
            Some(json!({"email": email, "roles": roles})),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text);
    let token = r.json()["enrolment_token"].as_str().unwrap().to_owned();
    let seed = c.enrol(&token, PASSWORD).await;
    (c.sign_in(email, PASSWORD, &seed).await, seed)
}

async fn endpoints(db: &common::TestDb) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM platform.tsa_endpoints")
        .fetch_one(&db.owner)
        .await
        .unwrap()
}

/// **`SEC-X05`: one key custodian cannot change the TSAs; `SEC-X06`: a private-address
/// TSA URL is refused.**
#[tokio::test]
async fn a_tsa_change_needs_two_key_custodians_and_a_public_address() {
    let Some(db) =
        common::fresh("a_tsa_change_needs_two_key_custodians_and_a_public_address").await
    else {
        return;
    };
    let c = common::console(&db);
    let owner_seed = c.bootstrap("owner@ops.example", PASSWORD).await;
    let owner = c.sign_in("owner@ops.example", PASSWORD, &owner_seed).await;
    let (_, a_seed) = operator(&c, &owner, "a@ops.example", &["key_custodian"]).await;
    let (_, b_seed) = operator(&c, &owner, "b@ops.example", &["key_custodian"]).await;
    let (_, op_seed) = operator(&c, &owner, "op@ops.example", &["operator"]).await;
    let a = c.sign_in("a@ops.example", PASSWORD, &a_seed).await;
    let propose = |url: &str| json!({"action": "set", "url": url, "priority": 10});

    // Not a key custodian.
    let r = c
        .call(
            &owner,
            "POST",
            "/console/v1/tsa/changes",
            Some(propose("https://1.1.1.1/tsr")),
        )
        .await;
    assert_eq!(r.code(), "CS-CON-0003", "{}", r.text);

    // SEC-X06: private, loopback, link-local and metadata addresses.
    for url in [
        "http://10.0.0.1/tsr",
        "http://127.0.0.1:3180/",
        "http://169.254.169.254/latest/meta-data",
        "https://[::1]/tsr",
        "file:///etc/passwd",
    ] {
        let r = c
            .call(&a, "POST", "/console/v1/tsa/changes", Some(propose(url)))
            .await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (StatusCode::UNPROCESSABLE_ENTITY, "CS-CON-0006"),
            "{url}: {}",
            r.text
        );
        assert_eq!(r.json()["field"], "url");
    }

    // A public one is proposed.
    let r = c
        .call(
            &a,
            "POST",
            "/console/v1/tsa/changes",
            Some(propose("https://1.1.1.1/tsr")),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text);
    let id = r.json()["id"].as_str().unwrap().to_owned();
    let apply = format!("/console/v1/tsa/changes/{id}/apply");
    let grant = format!("/console/v1/tsa/changes/{id}/grant");

    // SEC-X05: the proposer alone cannot apply it, nor approve it.
    let r = c.call(&a, "POST", &apply, None).await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::CONFLICT, "CS-CON-0004"),
        "{}",
        r.text
    );
    let r = c.call(&a, "POST", &grant, None).await;
    assert_eq!(r.code(), "CS-CON-0004", "self-approval");
    // An operator who is not a key custodian cannot approve it, by either route.
    let op = c.sign_in("op@ops.example", PASSWORD, &op_seed).await;
    let r = c.call(&op, "POST", &grant, None).await;
    assert_eq!(r.code(), "CS-CON-0003");
    let r = c
        .call(
            &op,
            "POST",
            &format!("/console/v1/approvals/{id}/grant"),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "{}", r.text);
    let a = c.sign_in("a@ops.example", PASSWORD, &a_seed).await;
    let r = c.call(&a, "POST", &apply, None).await;
    assert_eq!(
        r.code(),
        "CS-CON-0004",
        "an operator's grant does not count"
    );
    assert_eq!(endpoints(&db).await, 0);

    // The second custodian sees what they approve, and approves it.
    let b = c.sign_in("b@ops.example", PASSWORD, &b_seed).await;
    let list = c.call(&b, "GET", "/console/v1/tsa", None).await;
    let change = &list.json()["changes"][0];
    assert_eq!(change["payload"]["url"], "https://1.1.1.1/tsr");
    assert_eq!(change["live"], true);
    let r = c.call(&b, "POST", &grant, None).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.text);

    // A stale second factor is refused; a fresh one applies, once.
    c.clock.advance(6 * 60);
    let r = c.call(&a, "POST", &apply, None).await;
    assert_eq!(r.code(), "CS-CON-0002", "{}", r.text);
    let a = c.sign_in("a@ops.example", PASSWORD, &a_seed).await;
    let r = c.call(&a, "POST", &apply, None).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.text);
    let r = c.call(&a, "POST", &apply, None).await;
    assert_eq!(r.code(), "CS-CON-0004", "spent");
    let list = c.call(&a, "GET", "/console/v1/tsa", None).await;
    let e = &list.json()["endpoints"][0];
    assert_eq!(e["url"], "https://1.1.1.1/tsr");
    assert_eq!(e["priority"], 10);
    assert_eq!(e["enabled"], true);
    assert_eq!(e["approval"], id.as_str());

    // The console role has no direct write, and the stored payload cannot be edited.
    let err = sqlx::query(
        "INSERT INTO platform.tsa_endpoints (id, url, priority, enabled, changed_at, approval) \
         VALUES (gen_random_uuid(), 'http://10.0.0.1/', 1, true, now(), $1::uuid)",
    )
    .bind(&id)
    .execute(&db.console)
    .await
    .unwrap_err();
    assert_eq!(err.as_database_error().unwrap().code().unwrap(), "42501");
    let err = sqlx::query("UPDATE platform.approval_payloads SET payload = '{}'")
        .execute(&db.owner)
        .await
        .unwrap_err();
    assert_eq!(err.as_database_error().unwrap().code().unwrap(), "OS001");

    // Every step is in the operator log.
    let log = c
        .call(&owner, "GET", "/console/v1/operator-log?limit=200", None)
        .await;
    for action in [
        "operator.key_change.requested",
        "operator.key_change.granted",
        "operator.tsa.set",
    ] {
        assert!(log.text.contains(action), "{action}");
    }
    assert!(!log.text.contains("1.1.1.1"), "no URL in the operator log");
    db.drop().await;
}
