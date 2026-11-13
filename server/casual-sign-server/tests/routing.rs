//! VS-02 (routing and recipient types), through the HTTP API and the ceremony
//! endpoints on a real database: one envelope of mixed routing (a copy and an agent
//! first, then a signer and an approver in parallel, then a viewer) runs to
//! `completing` with every recipient type acting through its own link. The agent names
//! the later signer through `POST /s/{token}/recipients` (VS-02, FG-024), which only an
//! agent, intermediary or editor may call, only for later recipients not yet reached;
//! the approver approves and the viewer completes by viewing every document to the end.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

mod common;

use axum::http::StatusCode;
use common::Rls;
use common::flow::{b64, invite, ok, open, sign};
use common::harness::{Api, Auth, Tenant, pdf};
use serde_json::{Value, json};

/// A sent envelope: `cc` and agent `ag` at order 1, signer `s1` (no address yet: the
/// agent names them) and approver `ap` at 2, viewer `vw` at 3.
async fn sent(api: &Api, t: &Tenant) -> Value {
    ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            &t.auth,
            Some(json!({
                "subject": "VS-02", "status": "sent",
                "documents": [{"name": "w.pdf", "content_base64": b64(&pdf(2))}],
                "recipients": [
                    {"ref": "cc", "type": "cc", "name": "Copy",
                        "email": "copy@example.test", "routing_order": 1},
                    {"ref": "ag", "type": "agent", "name": "Agent",
                        "email": "agent@example.test", "routing_order": 1},
                    {"ref": "s1", "type": "signer", "name": "Buyer", "routing_order": 2},
                    {"ref": "ap", "type": "approver", "name": "Approver",
                        "email": "approver@example.test", "routing_order": 2},
                    {"ref": "vw", "type": "viewer", "name": "Viewer",
                        "email": "viewer@example.test", "routing_order": 3},
                ],
                "fields": [
                    {"recipient": "s1", "document": 0, "type": "signature", "page": 1,
                        "x": 72, "y": 100, "width": 180, "height": 40, "required": true},
                ],
            })),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "create sent envelope",
    )
}

async fn envelope(api: &Api, t: &Tenant, env: &str) -> Value {
    ok(
        api.call(
            "GET",
            &format!("/api/v1/envelopes/{env}"),
            &t.auth,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "get envelope",
    )
}

fn status_of(e: &Value, id: &str) -> String {
    e["recipients"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == id)
        .unwrap()["status"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn hdr<'a>(bound: &'a [(&'static str, String)]) -> Vec<(&'static str, &'a str)> {
    bound.iter().map(|(k, v)| (*k, v.as_str())).collect()
}

async fn view_all(api: &Api, token: &str, view: &Value, h: &[(&str, &str)]) {
    for d in view["envelope"]["documents"].as_array().unwrap() {
        let doc = d["id"].as_str().unwrap();
        ok(
            api.call(
                "POST",
                &format!("/s/{token}/documents/{doc}/viewed"),
                &Auth::None,
                Some(json!({"pages_seen": [1, 2]})),
                h,
            )
            .await,
            StatusCode::OK,
            "viewed",
        );
    }
}

#[tokio::test]
async fn mixed_routing_runs_every_ready_recipient_type_to_completing() {
    let Some(api) = Api::new("routing_mixed", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let e = sent(&api, &a).await;
    let env = e["id"].as_str().unwrap().to_owned();
    let id = |n: usize| e["recipients"][n]["id"].as_str().unwrap().to_owned();
    let (cc, ag, s1, ap, vw) = (id(0), id(1), id(2), id(3), id(4));

    // Order 1 is the agent's turn (the copy has no action); 2 and 3 wait.
    let got = envelope(&api, &a, &env).await;
    assert_eq!(status_of(&got, &ag), "sent");
    for later in [&s1, &ap, &vw] {
        assert_eq!(status_of(&got, later), "created", "{later} waits");
    }

    // The agent sees the later recipients it may name, and nothing of the copy.
    let agent = invite(&api, &a, &env, &ag).await;
    let (view, bound) = open(&api, &agent).await;
    let h = hdr(&bound);
    let later: Vec<&str> = view["later_recipients"]
        .as_array()
        .expect("an agent's view lists the later recipients")
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    assert_eq!(later, [s1.as_str(), ap.as_str(), vw.as_str()]);

    // Finishing before the signer has an address is refused.
    let r = api
        .call(
            "POST",
            &format!("/s/{agent}/finish"),
            &Auth::None,
            Some(json!({"values": []})),
            &h,
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.json());

    // An agent cannot name a recipient of its own order or earlier.
    let r = api
        .call(
            "POST",
            &format!("/s/{agent}/recipients"),
            &Auth::None,
            Some(json!({"recipients": [{"id": cc, "name": "X", "email": "x@example.test"}]})),
            &h,
        )
        .await;
    assert!(
        r.status == StatusCode::FORBIDDEN || r.status == StatusCode::CONFLICT,
        "{} {:?}",
        r.status,
        r.json()
    );

    let named = ok(
        api.call(
            "POST",
            &format!("/s/{agent}/recipients"),
            &Auth::None,
            Some(json!({"recipients": [
                {"id": s1, "name": "Bea Buyer", "email": "bea@example.test"}
            ]})),
            &h,
        )
        .await,
        StatusCode::OK,
        "agent names the signer",
    );
    let shown = named["later_recipients"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == s1.as_str())
        .unwrap()
        .clone();
    assert_eq!(shown["email"], "bea@example.test");
    assert_eq!(shown["name"], "Bea Buyer");

    let done = ok(
        api.call(
            "POST",
            &format!("/s/{agent}/finish"),
            &Auth::None,
            Some(json!({"values": []})),
            &h,
        )
        .await,
        StatusCode::OK,
        "agent finishes",
    );
    assert_eq!(done["recipient"]["status"], "completed");

    // Order 2 runs in parallel: the signer and the approver are both invited.
    let got = envelope(&api, &a, &env).await;
    assert_eq!(status_of(&got, &s1), "sent");
    assert_eq!(status_of(&got, &ap), "sent");
    assert_eq!(status_of(&got, &vw), "created");

    // A signer or a signer's link is not an approver: `approve` is refused for them.
    let signer = invite(&api, &a, &env, &s1).await;
    let approver = invite(&api, &a, &env, &ap).await;
    let (aview, abound) = open(&api, &approver).await;
    let ah = hdr(&abound);
    view_all(&api, &approver, &aview, &ah).await;
    let r = api
        .call(
            "POST",
            &format!("/s/{approver}/finish"),
            &Auth::None,
            Some(json!({"values": []})),
            &ah,
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "an approver approves");
    let approved = ok(
        api.call(
            "POST",
            &format!("/s/{approver}/approve"),
            &Auth::None,
            Some(json!({})),
            &ah,
        )
        .await,
        StatusCode::OK,
        "approve",
    );
    assert_eq!(approved["recipient"]["status"], "completed");
    sign(&api, &signer, &[]).await;

    // Order 3: the viewer cannot finish before viewing every document.
    let viewer = invite(&api, &a, &env, &vw).await;
    let (vview, vbound) = open(&api, &viewer).await;
    let vh = hdr(&vbound);
    let r = api
        .call(
            "POST",
            &format!("/s/{viewer}/finish"),
            &Auth::None,
            Some(json!({"values": []})),
            &vh,
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "viewer has not viewed");
    // Viewing every page of every document to the end completes the viewer.
    view_all(&api, &viewer, &vview, &vh).await;
    let got = envelope(&api, &a, &env).await;
    assert_eq!(status_of(&got, &vw), "completed");
    assert_eq!(
        got["status"], "completing",
        "every action taken: the seal job runs"
    );
    // A copy is done when its turn comes, without acting (docs/24 §3).
    assert_eq!(status_of(&got, &cc), "completed");
    let buyer = got["recipients"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == s1.as_str())
        .unwrap();
    assert_eq!(buyer["email"], "bea@example.test");
    api.db.drop().await;
}

#[tokio::test]
async fn only_an_agent_names_later_recipients() {
    let Some(api) = Api::new("routing_agent_only", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let e = sent(&api, &a).await;
    let env = e["id"].as_str().unwrap().to_owned();
    let ag = e["recipients"][1]["id"].as_str().unwrap().to_owned();
    let s1 = e["recipients"][2]["id"].as_str().unwrap().to_owned();
    let vw = e["recipients"][4]["id"].as_str().unwrap().to_owned();
    let agent = invite(&api, &a, &env, &ag).await;
    let (_, bound) = open(&api, &agent).await;
    let h = hdr(&bound);

    // An agent may change only names and addresses: unknown members are refused.
    let r = api
        .call(
            "POST",
            &format!("/s/{agent}/recipients"),
            &Auth::None,
            Some(json!({"recipients": [{"id": s1, "type": "cc"}]})),
            &h,
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{:?}", r.json());
    // A bad address is refused.
    let r = api
        .call(
            "POST",
            &format!("/s/{agent}/recipients"),
            &Auth::None,
            Some(json!({"recipients": [{"id": s1, "email": "nope"}]})),
            &h,
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{:?}", r.json());
    // An id that is not in the envelope is not found.
    let r = api
        .call(
            "POST",
            &format!("/s/{agent}/recipients"),
            &Auth::None,
            Some(json!({"recipients": [
                {"id": "00000000-0000-4000-8000-000000000000", "email": "a@example.test"}
            ]})),
            &h,
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "{:?}", r.json());

    // Once the agent has finished, the viewer (not an agent) cannot name anyone.
    ok(
        api.call(
            "POST",
            &format!("/s/{agent}/recipients"),
            &Auth::None,
            Some(json!({"recipients": [{"id": s1, "email": "bea@example.test"}]})),
            &h,
        )
        .await,
        StatusCode::OK,
        "name",
    );
    let r = api
        .call(
            "POST",
            &format!("/s/{agent}/finish"),
            &Auth::None,
            Some(json!({})),
            &h,
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let viewer = invite(&api, &a, &env, &vw).await;
    let (vview, vbound) = open(&api, &viewer).await;
    assert!(
        vview.get("later_recipients").is_none(),
        "only an agent's view lists them"
    );
    let r = api
        .call(
            "POST",
            &format!("/s/{viewer}/recipients"),
            &Auth::None,
            Some(json!({"recipients": [{"id": s1, "email": "z@example.test"}]})),
            &hdr(&vbound),
        )
        .await;
    assert!(
        r.status == StatusCode::FORBIDDEN || r.status == StatusCode::CONFLICT,
        "{} {:?}",
        r.status,
        r.json()
    );
    api.db.drop().await;
}

/// SEC-CER-01: an agent who has not passed their access code learns nothing from
/// `POST /s/{token}/recipients`, not even whether an id exists, and names no one.
#[tokio::test]
async fn an_agent_names_no_one_before_authenticating() {
    let Some(api) = Api::new("routing_agent_auth", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let e = ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            &a.auth,
            Some(json!({
                "subject": "VS-02 auth", "status": "sent",
                "documents": [{"name": "w.pdf", "content_base64": b64(&pdf(1))}],
                "recipients": [
                    {"ref": "ag", "type": "agent", "name": "Agent", "email": "agent@example.test",
                        "routing_order": 1, "auth": ["access_code"], "access_code": "right-4711"},
                    {"ref": "s1", "type": "signer", "name": "Buyer", "routing_order": 2},
                ],
                "fields": [
                    {"recipient": "s1", "document": 0, "type": "signature", "page": 1,
                        "x": 72, "y": 100, "width": 180, "height": 40, "required": true},
                ],
            })),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "create",
    );
    let env = e["id"].as_str().unwrap().to_owned();
    let ag = e["recipients"][0]["id"].as_str().unwrap().to_owned();
    let s1 = e["recipients"][1]["id"].as_str().unwrap().to_owned();
    let agent = invite(&api, &a, &env, &ag).await;
    let (view, bound) = open(&api, &agent).await;
    assert!(view.get("later_recipients").is_none(), "{view}");
    let h = hdr(&bound);
    for id in [s1.as_str(), "00000000-0000-4000-8000-000000000000"] {
        let r = api
            .call(
                "POST",
                &format!("/s/{agent}/recipients"),
                &Auth::None,
                Some(json!({"recipients": [{"id": id, "email": "x@example.test"}]})),
                &h,
            )
            .await;
        assert_eq!(
            (r.status, r.code()),
            (StatusCode::FORBIDDEN, "CS-AUTH-0003".to_owned()),
            "{id}"
        );
    }
    api.db.drop().await;
}
