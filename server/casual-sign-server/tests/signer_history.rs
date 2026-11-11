//! The signer's history and reassignment (WEB-07): `GET /s/{token}/history` answers the
//! events this recipient acted in or that concern them and the envelope's milestones,
//! as `{seq, type, at, by}` only, never another recipient's events, identity, address
//! or location, and only after consent; `POST /s/{token}/reassign` hands the part to
//! someone else only when the envelope allows it and the recipient has not finished,
//! revokes the link, queues the new recipient's invitation and records it with the
//! device's location.

#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

mod common;

use axum::http::StatusCode;
use common::Rls;
use common::flow::{b64, invite, jobs, ok, open};
use common::harness::{Api, Auth, Tenant, pdf, png};
use serde_json::{Value, json};

async fn with_disclosure(api: &Api, t: &Tenant) {
    let mut policy = serde_json::to_value(casual_sign_workflow::Policy::default()).unwrap();
    policy["ersd"] = json!({"version": "2026-1", "hash": format!("sha256:{}", "ab".repeat(32))});
    ok(
        api.call(
            "PATCH",
            "/api/v1/accounts/me",
            &t.auth,
            Some(json!({"settings": {"workflow_policy": policy}})),
            &[],
        )
        .await,
        StatusCode::OK,
        "policy",
    );
}

/// A sent envelope: two signers at the same routing order, one signature field each.
async fn two_signers(api: &Api, t: &Tenant, options: Value) -> Value {
    ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            &t.auth,
            Some(json!({
                "subject": "WEB-07", "status": "sent", "signing_options": options,
                "documents": [{"name": "h.pdf", "content_base64": b64(&pdf(1))}],
                "recipients": [
                    {"ref": "s1", "type": "signer", "name": "Sig One", "email": "one@example.test", "routing_order": 1},
                    {"ref": "s2", "type": "signer", "name": "Sig Two", "email": "two@example.test", "routing_order": 1},
                ],
                "fields": [
                    {"recipient": "s1", "document": 0, "type": "signature", "page": 1, "x": 72, "y": 100, "width": 180, "height": 40, "required": true},
                    {"recipient": "s2", "document": 0, "type": "signature", "page": 1, "x": 72, "y": 300, "width": 180, "height": 40, "required": true},
                ],
            })),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "create",
    )
}

type Headers = Vec<(&'static str, String)>;

fn hv(h: &Headers) -> Vec<(&str, &str)> {
    h.iter().map(|(k, v)| (*k, v.as_str())).collect()
}

async fn post(api: &Api, path: &str, h: &Headers, body: Value) -> common::harness::Resp {
    api.call("POST", path, &Auth::None, Some(body), &hv(h))
        .await
}

/// Consent, adopt and finish with the signature, as the recipient behind `s`.
async fn consent_and_sign(api: &Api, s: &str, h: &Headers, view: &Value) {
    ok(
        post(
            api,
            &format!("{s}/consent"),
            h,
            json!({"ersd_version": "2026-1"}),
        )
        .await,
        StatusCode::OK,
        "consent",
    );
    let doc = view["envelope"]["documents"][0]["id"].as_str().unwrap();
    ok(
        post(
            api,
            &format!("{s}/documents/{doc}/viewed"),
            h,
            json!({"pages_seen": [1]}),
        )
        .await,
        StatusCode::OK,
        "viewed",
    );
    let adopted = ok(
        post(
            api,
            &format!("{s}/adopt"),
            h,
            json!({"mark": "signature", "method": "draw", "image_base64": b64(&png())}),
        )
        .await,
        StatusCode::OK,
        "adopt",
    );
    let field = view["fields"][0]["id"].clone();
    ok(
        post(
            api,
            &format!("{s}/finish"),
            h,
            json!({"values": [{"field": field, "value": {"signature": adopted["adoption_id"]}}]}),
        )
        .await,
        StatusCode::OK,
        "finish",
    );
}

async fn history(api: &Api, s: &str, h: &Headers) -> common::harness::Resp {
    api.call("GET", &format!("{s}/history"), &Auth::None, None, &hv(h))
        .await
}

#[tokio::test]
async fn history_shows_own_events_and_milestones_after_consent_and_nothing_of_others() {
    let Some(api) = Api::new("signer_history", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    with_disclosure(&api, &a).await;
    let env = two_signers(&api, &a, json!({})).await;
    let id = env["id"].as_str().unwrap();
    let r1 = env["recipients"][0]["id"].as_str().unwrap();
    let r2 = env["recipients"][1]["id"].as_str().unwrap();

    // Signer 1 opens from one address; before consent the history is refused.
    api.set_peer("198.51.100.7:50000");
    let s1 = format!("/s/{}", invite(&api, &a, id, r1).await);
    let (v1, h1) = open(&api, &s1[3..]).await;
    let early = history(&api, &s1, &h1).await;
    assert_eq!(
        (early.status, early.code().as_str()),
        (StatusCode::FORBIDDEN, "CS-AUTH-0005"),
        "{:?}",
        early.json()
    );
    // Another browser (no cookie) is refused too.
    let elsewhere = history(&api, &s1, &Vec::new()).await;
    assert_eq!(elsewhere.status, StatusCode::FORBIDDEN);
    consent_and_sign(&api, &s1, &h1, &v1).await;

    // Signer 2, from another address, with their location, signs too.
    api.set_peer("203.0.113.9:40000");
    let s2 = format!("/s/{}", invite(&api, &a, id, r2).await);
    let (v2, h2) = open(&api, &s2[3..]).await;
    consent_and_sign(&api, &s2, &h2, &v2).await;

    api.set_peer("198.51.100.7:50000");
    let r = history(&api, &s1, &h1).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let events = r.json()["events"].as_array().unwrap().clone();
    let types: Vec<&str> = events.iter().map(|e| e["type"].as_str().unwrap()).collect();
    for want in [
        "envelope.sent",
        "recipient.delivered",
        "recipient.consented",
        "recipient.signed",
        "envelope.completing",
    ] {
        assert!(types.contains(&want), "{want} missing: {types:?}");
    }
    // Only signer 1's own events and milestones: nothing signer 2 did.
    assert!(
        events
            .iter()
            .all(|e| e["by"] != "recipient" || e["type"].as_str().unwrap().starts_with("envelope.")),
        "{events:?}"
    );
    let own = events
        .iter()
        .filter(|e| e["type"] == "recipient.signed")
        .count();
    assert_eq!(own, 1, "signer 2's signing shown to signer 1: {types:?}");
    assert!(events.iter().all(|e| {
        e.as_object()
            .unwrap()
            .keys()
            .all(|k| ["seq", "type", "at", "by"].contains(&k.as_str()))
    }));
    let body = String::from_utf8_lossy(&r.body).to_string();
    for secret in [
        "two@example.test",
        "Sig Two",
        "203.0.113.9",
        "198.51.100.7",
        "one@example.test",
    ] {
        assert!(!body.contains(secret), "{secret} in the history");
    }
    // Ordered oldest first by sequence.
    let seqs: Vec<u64> = events.iter().map(|e| e["seq"].as_u64().unwrap()).collect();
    assert!(seqs.windows(2).all(|w| w[0] < w[1]), "{seqs:?}");
    api.db.drop().await;
}

#[tokio::test]
async fn reassign_hands_over_only_when_allowed_and_before_finishing() {
    let Some(api) = Api::new("signer_reassign", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    with_disclosure(&api, &a).await;

    // Off for this envelope: refused, nothing changes.
    let off = two_signers(&api, &a, json!({"allow_reassign": false})).await;
    let (oid, or1) = (
        off["id"].as_str().unwrap(),
        off["recipients"][0]["id"].as_str().unwrap(),
    );
    let so = format!("/s/{}", invite(&api, &a, oid, or1).await);
    let (_, ho) = open(&api, &so[3..]).await;
    ok(
        post(
            &api,
            &format!("{so}/consent"),
            &ho,
            json!({"ersd_version": "2026-1"}),
        )
        .await,
        StatusCode::OK,
        "consent",
    );
    let refused = post(
        &api,
        &format!("{so}/reassign"),
        &ho,
        json!({"name": "Deputy", "email": "deputy@example.test"}),
    )
    .await;
    assert_eq!(
        (refused.status, refused.code().as_str()),
        (StatusCode::CONFLICT, "CS-WF-0012")
    );

    // On (the default): signer 1 hands over with a reason and their location.
    let env = two_signers(&api, &a, json!({"capture_location": true})).await;
    let id = env["id"].as_str().unwrap();
    let r1 = env["recipients"][0]["id"].as_str().unwrap();
    let r2 = env["recipients"][1]["id"].as_str().unwrap();
    let s1 = format!("/s/{}", invite(&api, &a, id, r1).await);
    let (_, h1) = open(&api, &s1[3..]).await;
    ok(
        post(
            &api,
            &format!("{s1}/consent"),
            &h1,
            json!({"ersd_version": "2026-1"}),
        )
        .await,
        StatusCode::OK,
        "consent",
    );
    let before = jobs(&api, id).await;
    let done = post(
        &api,
        &format!("{s1}/reassign"),
        &h1,
        json!({"name": "Deputy", "email": "deputy@example.test", "reason": "On leave",
               "location": {"latitude": 51.5, "longitude": -0.12, "accuracy_m": 25}}),
    )
    .await;
    assert_eq!(done.status, StatusCode::OK, "{:?}", done.json());
    // The link is revoked at once.
    let gone = api.call("GET", &s1, &Auth::None, None, &hv(&h1)).await;
    assert_eq!(
        (gone.status, gone.code().as_str()),
        (StatusCode::UNAUTHORIZED, "CS-AUTH-0002")
    );
    // The new recipient, at the same routing order, holds the field and is invited.
    let e = ok(
        api.call(
            "GET",
            &format!("/api/v1/envelopes/{id}"),
            &a.auth,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "get",
    );
    let recips = e["recipients"].as_array().unwrap();
    let old = recips.iter().find(|r| r["id"] == r1).unwrap();
    assert_eq!(old["status"], "reassigned");
    let new = recips
        .iter()
        .find(|r| r["email"] == "deputy@example.test")
        .unwrap();
    assert_eq!(new["reassigned_from"], r1);
    assert_eq!(new["routing_order"], 1);
    assert_eq!(new["status"], "sent");
    let after = jobs(&api, id).await;
    assert_eq!(
        after.iter().filter(|k| *k == "send_invitation").count(),
        before.iter().filter(|k| *k == "send_invitation").count() + 1,
        "{after:?}"
    );
    let audit = ok(
        api.call(
            "GET",
            &format!("/api/v1/envelopes/{id}/audit"),
            &a.auth,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "audit",
    );
    let ev = audit["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["type"] == "recipient.reassigned")
        .unwrap()
        .clone();
    assert_eq!(ev["event"]["data"]["reason"], "On leave");
    assert_eq!(ev["event"]["context"]["location"]["source"], "device");
    // The new recipient's link opens their part.
    let nid = new["id"].as_str().unwrap();
    let sn = format!("/s/{}", invite(&api, &a, id, nid).await);
    let (vn, _) = open(&api, &sn[3..]).await;
    assert_eq!(vn["fields"].as_array().unwrap().len(), 1);

    // A signer who has finished can no longer hand over.
    let s2 = format!("/s/{}", invite(&api, &a, id, r2).await);
    let (v2, h2) = open(&api, &s2[3..]).await;
    consent_and_sign(&api, &s2, &h2, &v2).await;
    let late = post(
        &api,
        &format!("{s2}/reassign"),
        &h2,
        json!({"name": "Late", "email": "late@example.test"}),
    )
    .await;
    assert_eq!(late.status, StatusCode::CONFLICT, "{:?}", late.json());
    api.db.drop().await;
}
