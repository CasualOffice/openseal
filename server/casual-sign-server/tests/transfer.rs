//! ORG-09: envelope ownership transfer within a workspace (docs/23 §2.4). A holder of
//! `envelopes.transfer` passes an envelope to another member; the chain records
//! `envelope.transferred {from_user, to_user}` and verifies; the new owner's list shows
//! it; a member without the action is refused; and envelopes never move between
//! workspaces: another workspace as the target, or a member of another workspace as
//! the new owner, is `422 CS-ORG-0009`, and another workspace's envelope is `404`.

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
use common::Rls;
use common::flow::sent;
use common::harness::{Api, PASSWORD, Resp};
use serde_json::{Value, json};

fn is(r: &Resp, status: StatusCode, code: Option<&str>, what: &str) -> Value {
    assert_eq!(r.status, status, "{what}: {:?}", r.json());
    if let Some(c) = code {
        assert_eq!(r.code(), c, "{what}");
    }
    r.json()
}

async fn transfer(rls: Rls) {
    let Some(api) = Api::new(&format!("envelope_transfer_{rls:?}"), rls).await else {
        return;
    };
    let alpha = api.tenant("alpha").await;
    let bravo = api.tenant("bravo").await;
    let key = &alpha.auth;
    let mut ids = Vec::new();
    for email in ["heir@alpha.example.test", "sender@alpha.example.test"] {
        let r = api
            .call(
                "POST",
                "/api/v1/users",
                key,
                Some(
                    json!({"email": email, "name": "Someone", "profile": "sender",
                    "password": PASSWORD}),
                ),
                &[],
            )
            .await;
        ids.push(
            is(&r, StatusCode::CREATED, None, email)["id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    let (heir, other) = (ids[0].clone(), ids[1].clone());
    let sender = api.login("sender@alpha.example.test", PASSWORD).await;
    let heir_s = api.login("heir@alpha.example.test", PASSWORD).await;

    let env = sent(&api, &alpha, 1, &[]).await;
    let id = env["id"].as_str().unwrap().to_owned();
    let from = env["sender_user_id"].as_str().unwrap().to_owned();
    let path = format!("/api/v1/envelopes/{id}/transfer");

    // A sender without `envelopes.transfer` is refused.
    let r = api
        .call("POST", &path, &sender, Some(json!({"to_user": other})), &[])
        .await;
    is(&r, StatusCode::FORBIDDEN, Some("CS-AUTH-0006"), "no action");

    // Envelopes never move between workspaces.
    let r = api
        .call(
            "POST",
            &path,
            key,
            Some(json!({"to_user": heir, "to_workspace": bravo.boot.account.to_string()})),
            &[],
        )
        .await;
    is(
        &r,
        StatusCode::UNPROCESSABLE_ENTITY,
        Some("CS-ORG-0009"),
        "other workspace",
    );
    let r = api
        .call(
            "POST",
            &path,
            key,
            Some(json!({"to_user": bravo.boot.admin.to_string()})),
            &[],
        )
        .await;
    is(
        &r,
        StatusCode::UNPROCESSABLE_ENTITY,
        Some("CS-ORG-0009"),
        "member elsewhere",
    );
    let r = api
        .call(
            "POST",
            &path,
            &bravo.auth,
            Some(json!({"to_user": bravo.boot.admin.to_string()})),
            &[],
        )
        .await;
    is(
        &r,
        StatusCode::NOT_FOUND,
        Some("CS-API-0002"),
        "another workspace's envelope",
    );

    // The heir has nothing yet; then the envelope is theirs.
    let mine = |v: &Value| -> Vec<String> {
        v["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["id"].as_str().unwrap().to_owned())
            .collect()
    };
    let r = api
        .call("GET", "/api/v1/envelopes", &heir_s, None, &[])
        .await;
    assert!(!mine(&is(&r, StatusCode::OK, None, "heir list")).contains(&id));
    let r = api
        .call(
            "POST",
            &path,
            key,
            Some(json!({"to_user": heir, "to_workspace": alpha.boot.account.to_string()})),
            &[],
        )
        .await;
    let e = is(&r, StatusCode::OK, None, "transfer");
    assert_eq!(e["sender_user_id"], heir.as_str());
    let r = api
        .call("GET", "/api/v1/envelopes", &heir_s, None, &[])
        .await;
    assert!(mine(&is(&r, StatusCode::OK, None, "heir list")).contains(&id));
    let r = api
        .call(
            "GET",
            &format!("/api/v1/envelopes/{id}"),
            &heir_s,
            None,
            &[],
        )
        .await;
    is(&r, StatusCode::OK, None, "heir reads it");

    // The chain records it, and verifies with it.
    let r = api
        .call(
            "GET",
            &format!("/api/v1/envelopes/{id}/audit"),
            key,
            None,
            &[],
        )
        .await;
    let trail = is(&r, StatusCode::OK, None, "audit");
    let t = trail["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["type"] == "envelope.transferred")
        .unwrap_or_else(|| panic!("no envelope.transferred in {trail}"));
    assert_eq!(t["event"]["data"]["from_user"], from.as_str());
    assert_eq!(t["event"]["data"]["to_user"], heir.as_str());
    // The stored chain, rebuilt link by link from its bytes, then verified as a trail.
    let env_id = casual_sign_store::EnvelopeId(uuid::Uuid::parse_str(&id).unwrap());
    let mut tx = api
        .db
        .store
        .for_account(alpha.boot.account)
        .begin()
        .await
        .unwrap();
    let chain = tx.audit().chain(env_id).await.unwrap();
    tx.rollback().await.unwrap();
    let report = casual_sign_audit::verify_trail(
        &chain.to_trail_json().unwrap(),
        &casual_sign_audit::VerifyOptions::default(),
    );
    assert!(report.is_valid(), "{report:?}");
    assert!(report.unrecognised.is_empty(), "{report:?}");

    // To the owner it already has is not a transfer.
    let r = api
        .call("POST", &path, key, Some(json!({"to_user": heir})), &[])
        .await;
    is(&r, StatusCode::CONFLICT, None, "same owner");
    api.db.drop().await;
}

#[tokio::test]
async fn envelope_transfer_with_rls() {
    transfer(Rls::On).await;
}

#[tokio::test]
async fn envelope_transfer_without_rls() {
    transfer(Rls::Off).await;
}
