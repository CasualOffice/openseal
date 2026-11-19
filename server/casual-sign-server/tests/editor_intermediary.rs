//! The editor and intermediary recipient types through the ceremony (`VS-06`, docs/24 §3,
//! DocuSign's "Allow to edit" and "Update recipients"): an editor names a later
//! recipient and then signs their own field; an intermediary updates a later recipient
//! and finishes without signing; the signer they named signs; the envelope completes.
//! Neither may change a recipient routing has already reached.

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
use common::flow::{b64, invite, ok, open, sign};
use common::harness::{Api, Auth, pdf};
use serde_json::{Value, json};

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

#[tokio::test]
async fn an_editor_names_then_signs_and_an_intermediary_updates_then_finishes() {
    let Some(api) = Api::new("editor_intermediary", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let e = ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            &a.auth,
            Some(json!({
                "subject": "VS-06 editor", "status": "sent",
                "documents": [{"name": "w.pdf", "content_base64": b64(&pdf(2))}],
                "recipients": [
                    {"ref": "ed", "type": "editor", "name": "Eda Editor",
                        "email": "editor@example.test", "routing_order": 1},
                    {"ref": "im", "type": "intermediary", "name": "Ian Intermediary",
                        "email": "intermediary@example.test", "routing_order": 2},
                    {"ref": "s1", "type": "signer", "name": "To be named", "routing_order": 3},
                ],
                "fields": [
                    {"recipient": "ed", "document": 0, "type": "signature", "page": 1,
                        "x": 72, "y": 100, "width": 180, "height": 40, "required": true},
                    {"recipient": "s1", "document": 0, "type": "signature", "page": 1,
                        "x": 72, "y": 300, "width": 180, "height": 40, "required": true},
                ],
            })),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "create",
    );
    let env = e["id"].as_str().unwrap().to_owned();
    let base = format!("/api/v1/envelopes/{env}");
    let ed = e["recipients"][0]["id"].as_str().unwrap().to_owned();
    let im = e["recipients"][1]["id"].as_str().unwrap().to_owned();
    let s1 = e["recipients"][2]["id"].as_str().unwrap().to_owned();

    // The editor's view lists the later recipients they may change; they name the signer.
    let editor = invite(&api, &a, &env, &ed).await;
    let (view, bound) = open(&api, &editor).await;
    let later: Vec<&str> = view["later_recipients"]
        .as_array()
        .expect("an editor's view lists later recipients")
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    assert!(later.contains(&s1.as_str()), "{view}");
    ok(
        api.call(
            "POST",
            &format!("/s/{editor}/recipients"),
            &Auth::None,
            Some(json!({"recipients": [{"id": s1, "name": "Bea Buyer", "email": "bea@example.test"}]})),
            &hdr(&bound),
        )
        .await,
        StatusCode::OK,
        "the editor names the signer",
    );
    // Then signs their own field, as a signer does (a fresh link: `sign` binds its own).
    let again = invite(&api, &a, &env, &ed).await;
    sign(&api, &again, &[]).await;
    let now = ok(
        api.call("GET", &base, &a.auth, None, &[]).await,
        StatusCode::OK,
        "get",
    );
    assert_eq!(status_of(&now, &ed), "completed");
    assert_eq!(
        status_of(&now, &im),
        "sent",
        "routing reached the intermediary"
    );

    // The editor, finished, changes nobody any more.
    let r = api
        .call(
            "POST",
            &format!("/s/{editor}/recipients"),
            &Auth::None,
            Some(json!({"recipients": [{"id": s1, "email": "late@example.test"}]})),
            &hdr(&bound),
        )
        .await;
    assert!(r.status.is_client_error(), "{} {:?}", r.status, r.json());

    // The intermediary updates the signer's address and finishes without signing.
    let inter = invite(&api, &a, &env, &im).await;
    let (iview, ibound) = open(&api, &inter).await;
    assert!(iview["later_recipients"].is_array(), "{iview}");
    let h = hdr(&ibound);
    for d in iview["envelope"]["documents"].as_array().unwrap() {
        let doc = d["id"].as_str().unwrap();
        ok(
            api.call(
                "POST",
                &format!("/s/{inter}/documents/{doc}/viewed"),
                &Auth::None,
                Some(json!({"pages_seen": [1, 2]})),
                &h,
            )
            .await,
            StatusCode::OK,
            "viewed",
        );
    }
    ok(
        api.call(
            "POST",
            &format!("/s/{inter}/recipients"),
            &Auth::None,
            Some(json!({"recipients": [{"id": s1, "email": "bea.buyer@example.test"}]})),
            &h,
        )
        .await,
        StatusCode::OK,
        "the intermediary updates the signer",
    );
    ok(
        api.call(
            "POST",
            &format!("/s/{inter}/finish"),
            &Auth::None,
            Some(json!({})),
            &h,
        )
        .await,
        StatusCode::OK,
        "the intermediary finishes",
    );
    let now = ok(
        api.call("GET", &base, &a.auth, None, &[]).await,
        StatusCode::OK,
        "get",
    );
    assert_eq!(status_of(&now, &im), "completed");
    let signer = now["recipients"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == s1)
        .unwrap();
    assert_eq!(signer["name"], "Bea Buyer");
    assert_eq!(signer["email"], "bea.buyer@example.test");
    assert_eq!(signer["status"], "sent");

    // The signer they named signs; the envelope goes on to its seal.
    let t1 = invite(&api, &a, &env, &s1).await;
    sign(&api, &t1, &[]).await;
    let now = ok(
        api.call("GET", &base, &a.auth, None, &[]).await,
        StatusCode::OK,
        "get",
    );
    assert!(
        now["status"] == "completing" || now["status"] == "completed",
        "{}",
        now["status"]
    );
    // The trail says who named whom.
    let audit = ok(
        api.call("GET", &format!("{base}/audit"), &a.auth, None, &[])
            .await,
        StatusCode::OK,
        "audit",
    );
    let types: Vec<&str> = audit["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["type"].as_str().unwrap())
        .collect();
    assert!(types.contains(&"recipient.signed"), "{types:?}");
    api.db.drop().await;
}
