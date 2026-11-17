//! `GET /api/v1/envelopes/{id}/anchor-proof` (`FG-158`, docs/32 §5): the proof file of
//! the envelope's latest anchored chain head, made from the stored leaf as the worker
//! publishes it, for staff who may read the envelope; `404 CS-API-0017` before anything
//! is anchored; `404 CS-API-0002` for another account's envelope or one the member may
//! not see; logged as a document read, not recorded in the chain. Row-level security on
//! and off.

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
use casual_sign_audit::anchor::AnchorProof;
use casual_sign_audit::merkle::MerkleTree;
use casual_sign_audit::{Hash256, VerifyOptions};
use casual_sign_seclog::Kind;
use casual_sign_store::EnvelopeId;
use casual_sign_store::repo::anchors::{HeadToAnchor, NewLeaf, StoredAnchor};
use common::Rls;
use common::flow::{ok, sent};
use common::harness::{Api, Auth, PASSWORD, Tenant, session_of};
use serde_json::{Value, json};
use time::{Date, Month, OffsetDateTime};
use uuid::Uuid;

/// 2026-11-`d`.
fn day(d: u8) -> Date {
    Date::from_calendar_date(2026, Month::November, d).unwrap()
}

/// A member with the sender profile: sees only the envelopes they send.
async fn member(api: &Api, a: &Tenant) -> Auth {
    ok(
        api.call(
            "POST",
            "/api/v1/users",
            &a.auth,
            Some(json!({"email": "sam@alpha.example.test", "name": "Sam", "profile": "sender", "password": PASSWORD})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "user",
    );
    let login = api
        .call(
            "POST",
            "/api/v1/auth/login",
            &Auth::None,
            Some(json!({"email": "sam@alpha.example.test", "password": PASSWORD})),
            &[],
        )
        .await;
    session_of(&login)
}

/// Store an anchor of `period` whose tree is `[filler, head]`, `head` being the
/// envelope's event `seq`, as the anchor job stores it (the token is not checked here:
/// the route serves what is stored).
async fn anchor(api: &Api, t: &Tenant, env: Uuid, period: Date, seq: u64, head: Hash256) {
    let filler = Hash256::digest(period.to_string().as_bytes());
    let tree = MerkleTree::from_chain_heads(&[filler, head]);
    let proof = tree.inclusion_proof(1).unwrap();
    let stored = StoredAnchor {
        id: Uuid::now_v7(),
        period,
        tree_size: 2,
        root: tree.root().0,
        timestamp_token: vec![0x30, 0x03, 0x02, 0x01, 0x01],
        tsa_time: OffsetDateTime::from_unix_timestamp(1_794_874_200).unwrap(),
        created_at: OffsetDateTime::from_unix_timestamp(1_794_874_260).unwrap(),
    };
    let mut tx = api
        .db
        .store
        .for_account(t.boot.account)
        .begin()
        .await
        .unwrap();
    let inserted = tx
        .anchors()
        .insert(
            &stored,
            &[NewLeaf {
                leaf_index: 1,
                head: HeadToAnchor {
                    envelope: EnvelopeId(env),
                    seq,
                    head: head.0,
                },
                path: proof.path.iter().map(|h| h.0).collect(),
            }],
        )
        .await
        .unwrap();
    assert!(inserted);
    tx.commit().await.unwrap();
}

async fn scenario(rls: Rls) {
    let Some(api) = Api::new("anchor_proof", rls).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let b = api.tenant("beta").await;
    let sam = member(&api, &a).await;
    let env = sent(&api, &a, 1, &[]).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let path = format!("/api/v1/envelopes/{env}/anchor-proof");

    // Nothing anchored yet: 404 with its own code, so a client can tell "not yet".
    let r = api.call("GET", &path, &a.auth, None, &[]).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert_eq!(r.code(), "CS-API-0017");

    // Anchor the head as it is now (the last event of the chain).
    let audit = ok(
        api.call(
            "GET",
            &format!("/api/v1/envelopes/{env}/audit"),
            &a.auth,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "audit",
    );
    let last = audit["items"].as_array().unwrap().last().unwrap().clone();
    let seq = last["seq"].as_u64().unwrap();
    let head = Hash256::parse(last["hash"].as_str().unwrap()).unwrap();
    let env_id = Uuid::parse_str(&env).unwrap();
    anchor(&api, &a, env_id, day(16), seq, head).await;
    let events_before = audit["items"].as_array().unwrap().len();

    let r = api.call("GET", &path, &a.auth, None, &[]).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    assert_eq!(r.headers["content-type"], "application/json");
    assert_eq!(
        r.headers["content-disposition"],
        "attachment; filename=\"anchor-proof.json\""
    );
    let proof = AnchorProof::from_json(&r.body).unwrap();
    assert_eq!(proof.envelope_id.as_str(), env);
    assert_eq!(proof.seq, seq);
    assert_eq!(proof.head, head);
    assert_eq!(proof.anchor.period, "2026-11-16");
    proof.check_inclusion().unwrap();
    // The proof binds the envelope's own chain: the stored trail has that head at `seq`.
    let mut tx = api
        .db
        .store
        .for_account(a.boot.account)
        .begin()
        .await
        .unwrap();
    let trail = tx
        .audit()
        .chain(EnvelopeId(env_id))
        .await
        .unwrap()
        .to_trail_json()
        .unwrap();
    tx.commit().await.unwrap();
    proof
        .check_trail(&trail, &VerifyOptions::default())
        .unwrap();
    // Exactly the bytes the worker's proof file has (one code path, casual-sign-host).
    let mut tx = api
        .db
        .store
        .for_account(a.boot.account)
        .begin()
        .await
        .unwrap();
    let leaves = tx.anchors().leaves_of(EnvelopeId(env_id)).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        &r.body[..],
        &casual_sign_host::anchor::proof_file(EnvelopeId(env_id), &leaves[0]).unwrap()[..]
    );

    // A later day's anchor of a later head is the one served.
    let later = Hash256::digest(b"a later head");
    anchor(&api, &a, env_id, day(18), seq + 5, later).await;
    let r = api.call("GET", &path, &a.auth, None, &[]).await;
    assert_eq!(r.status, StatusCode::OK);
    let proof = AnchorProof::from_json(&r.body).unwrap();
    assert_eq!(proof.anchor.period, "2026-11-18");
    assert_eq!(proof.head, later);
    proof.check_inclusion().unwrap();

    // Reading it is not an act on the agreement: the chain did not grow.
    let after = ok(
        api.call(
            "GET",
            &format!("/api/v1/envelopes/{env}/audit"),
            &a.auth,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "audit",
    );
    assert_eq!(after["items"].as_array().unwrap().len(), events_before);

    // Another account, a member who may not see it, an unknown id: 404, as any other
    // envelope route; no credentials: 401.
    for (who, p) in [
        (&b.auth, path.clone()),
        (&sam, path.clone()),
        (
            &a.auth,
            format!("/api/v1/envelopes/{}/anchor-proof", Uuid::now_v7()),
        ),
    ] {
        let r = api.call("GET", &p, who, None, &[]).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{p}");
        assert_eq!(r.code(), "CS-API-0002", "{p}");
    }
    let r = api.call("GET", &path, &Auth::None, None, &[]).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    // A staff read of evidence: in the security log as a document read of the envelope.
    let reads: Vec<Value> = api
        .security
        .json()
        .into_iter()
        .filter(|l| l["event"] == "security" && l["kind"] == Kind::DocumentRead.as_str())
        .filter(|l| l["route"] == "/api/v1/envelopes/{id}/anchor-proof")
        .collect();
    assert!(
        reads.iter().any(|l| l["objects"] == json!([env])),
        "{reads:?}"
    );
}

#[tokio::test]
async fn the_anchor_proof_is_served_to_staff_who_may_read_the_envelope() {
    scenario(Rls::On).await;
}

#[tokio::test]
async fn the_anchor_proof_stays_in_the_account_with_row_level_security_disabled() {
    scenario(Rls::Off).await;
}
