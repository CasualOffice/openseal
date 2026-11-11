//! Correcting a sent envelope (WEB-06, docs/24 §6, DocuSign's "Correct"): change the
//! name, email or authentication of recipients who have not acted, add and remove
//! recipients not yet reached, edit their fields; a recipient whose link changed gets a
//! new invitation and the old link stops working; every correction is in the chain; a
//! recipient who has acted cannot be changed.

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
use common::flow::{invite, jobs, ok, open, sent, sign};
use common::harness::{Api, Auth};
use serde_json::{Value, json};

fn ids(e: &Value, what: &str) -> Vec<String> {
    e[what]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["id"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn a_sent_envelope_is_corrected_and_changed_links_are_reissued() {
    let Some(api) = Api::new("correct_sent", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let k = &a.auth;
    let e = sent(&api, &a, 3, &[]).await;
    let id = e["id"].as_str().unwrap().to_owned();
    let base = format!("/api/v1/envelopes/{id}");
    let r = ids(&e, "recipients");
    let (r1, r2, r3) = (r[0].clone(), r[1].clone(), r[2].clone());
    let invitations = |kinds: &[String]| kinds.iter().filter(|k| *k == "send_invitation").count();
    assert_eq!(invitations(&jobs(&api, &id).await), 1);

    // Signer 1 has opened their link.
    let old = invite(&api, &a, &id, &r1).await;
    open(&api, &old).await;

    // Correct signer 1's email and authentication in one call: the old link is revoked
    // at once and a new invitation is queued.
    let etag = api.call("GET", &base, k, None, &[]).await.etag();
    let spec = json!({"id": r1, "type": "signer", "routing_order": 1, "name": "S1",
        "email": "s1-fixed@example.test", "phone": "+15551234567", "auth": ["sms_otp"]});
    let c = ok(
        api.call(
            "POST",
            &format!("{base}/correct"),
            k,
            Some(json!({"changes": [{"op": "update_recipient", "recipient": spec}]})),
            &[("if-match", &etag)],
        )
        .await,
        StatusCode::OK,
        "correct",
    );
    assert_eq!(c["recipients"][0]["email"], "s1-fixed@example.test");
    let gone = api
        .call("GET", &format!("/s/{old}"), &Auth::None, None, &[])
        .await;
    assert_eq!(
        (gone.status, gone.code().as_str()),
        (StatusCode::UNAUTHORIZED, "CS-AUTH-0002"),
        "the old link is revoked"
    );
    let kinds = jobs(&api, &id).await;
    assert_eq!(invitations(&kinds), 2, "{kinds:?}");
    assert!(kinds.iter().any(|k| k == "notify_recipients"), "{kinds:?}");

    // Back to email only, so the test can sign; then remove signer 3 (not reached),
    // add a signer 4 in their place, and give signer 2 (not reached) a text field,
    // through the per-element endpoints, which correct a sent envelope.
    let etag = api.call("GET", &base, k, None, &[]).await.etag();
    ok(
        api.call(
            "PATCH",
            &format!("{base}/recipients/{r1}"),
            k,
            Some(json!({"auth": [], "name": "S1 Renamed"})),
            &[("if-match", &etag)],
        )
        .await,
        StatusCode::OK,
        "patch recipient while sent",
    );
    let etag = api.call("GET", &base, k, None, &[]).await.etag();
    let del = api
        .call(
            "DELETE",
            &format!("{base}/recipients/{r3}"),
            k,
            None,
            &[("if-match", &etag)],
        )
        .await;
    assert_eq!(del.status, StatusCode::NO_CONTENT, "{:?}", del.json());
    let added = ok(
        api.call(
            "POST",
            &format!("{base}/recipients"),
            k,
            Some(json!({"type": "signer", "name": "S4", "email": "s4@example.test", "routing_order": 3})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "add recipient while sent",
    );
    let r4 = added["items"][0]["id"]
        .as_str()
        .or_else(|| added["id"].as_str())
        .unwrap()
        .to_owned();
    let doc = e["documents"][0]["id"].as_str().unwrap().to_owned();
    ok(
        api.call(
            "POST",
            &format!("{base}/fields"),
            k,
            Some(json!({"items": [
                {"recipient_id": r4, "document_id": doc, "type": "signature", "page": 1, "x": 72, "y": 400, "width": 180, "height": 40, "required": true},
                {"recipient_id": r2, "document_id": doc, "type": "text", "page": 2, "x": 72, "y": 100, "width": 180, "height": 20},
            ]})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "add fields while sent",
    );

    // Signer 1 signs with the new link; afterwards they can no longer be corrected.
    let t1 = invite(&api, &a, &id, &r1).await;
    sign(&api, &t1, &[]).await;
    let etag = api.call("GET", &base, k, None, &[]).await.etag();
    let refused = api
        .call(
            "PATCH",
            &format!("{base}/recipients/{r1}"),
            k,
            Some(json!({"email": "late@example.test"})),
            &[("if-match", &etag)],
        )
        .await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{:?}", refused.json());

    // Every correction is in the chain.
    let audit = ok(
        api.call("GET", &format!("{base}/audit"), k, None, &[])
            .await,
        StatusCode::OK,
        "audit",
    );
    let corrected = audit["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["type"] == "envelope.corrected")
        .count();
    assert!(corrected >= 5, "{corrected} corrections recorded");
    let now = ok(
        api.call("GET", &base, k, None, &[]).await,
        StatusCode::OK,
        "get",
    );
    let statuses: Vec<(&str, &str)> = now["recipients"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r["name"].as_str().unwrap(), r["status"].as_str().unwrap()))
        .collect();
    assert_eq!(
        statuses,
        [
            ("S1 Renamed", "completed"),
            ("S2", "sent"),
            ("S4", "created")
        ]
    );
}
