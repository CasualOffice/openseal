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

/// The ids of the fields in a view's `key` list.
fn ids_in(view: &Value, key: &str) -> Vec<String> {
    view[key]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|f| f["id"].as_str().unwrap().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn an_editor_places_and_moves_a_later_signers_fields_then_signs() {
    // VS-06A (DocuSign's "Allow to edit"): during their turn an editor adds a field for
    // a later signer and moves another; the signer acting beside them may not; neither
    // may touch the field of a recipient routing has reached.
    let Some(api) = Api::new("editor_fields", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let e = ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            &a.auth,
            Some(json!({
                "subject": "VS-06A editor fields", "status": "sent",
                "documents": [{"name": "w.pdf", "content_base64": b64(&pdf(2))}],
                "recipients": [
                    {"ref": "ed", "type": "editor", "name": "Eda Editor",
                        "email": "editor@example.test", "routing_order": 1},
                    {"ref": "p1", "type": "signer", "name": "Pat Parallel",
                        "email": "pat@example.test", "routing_order": 1},
                    {"ref": "s2", "type": "signer", "name": "Sam Later",
                        "email": "sam@example.test", "routing_order": 2},
                ],
                "fields": [
                    {"recipient": "ed", "document": 0, "type": "signature", "page": 1,
                        "x": 72, "y": 100, "width": 180, "height": 40, "required": true},
                    {"recipient": "p1", "document": 0, "type": "signature", "page": 1,
                        "x": 72, "y": 200, "width": 180, "height": 40, "required": true},
                    {"recipient": "s2", "document": 0, "type": "signature", "page": 1,
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
    let rid = |i: usize| e["recipients"][i]["id"].as_str().unwrap().to_owned();
    let (ed, p1, s2) = (rid(0), rid(1), rid(2));
    let doc = e["documents"][0]["id"].as_str().unwrap().to_owned();
    let field_of = |r: &str| {
        e["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["recipient_id"] == r)
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let (p1_sig, s2_sig) = (field_of(&p1), field_of(&s2));

    // The editor's view lists the later signer's field as theirs to change, never the
    // parallel signer's (routing has reached them).
    let editor = invite(&api, &a, &env, &ed).await;
    let (view, bound) = open(&api, &editor).await;
    let h = hdr(&bound);
    assert_eq!(ids_in(&view, "editable_fields"), std::slice::from_ref(&s2_sig), "{view}");

    // They add a text field for the later signer and move the signer's signature.
    let added = ok(
        api.call(
            "POST",
            &format!("/s/{editor}/editor/fields"),
            &Auth::None,
            Some(
                json!({"fields": [{"recipient_id": s2, "document_id": doc, "type": "text",
                "page": 1, "x": 300, "y": 300, "width": 120, "height": 24,
                "required": false, "label": "Reference"}]}),
            ),
            &h,
        )
        .await,
        StatusCode::CREATED,
        "the editor adds a field for the later signer",
    );
    assert_eq!(ids_in(&added, "editable_fields").len(), 2, "{added}");
    ok(
        api.call(
            "PATCH",
            &format!("/s/{editor}/editor/fields/{s2_sig}"),
            &Auth::None,
            Some(json!({"x": 320, "y": 500})),
            &h,
        )
        .await,
        StatusCode::OK,
        "the editor moves the later signer's signature",
    );

    // A reached recipient's field is not theirs to change, nor to add: 409.
    for (method, path, body) in [
        (
            "PATCH",
            format!("/s/{editor}/editor/fields/{p1_sig}"),
            json!({"x": 10}),
        ),
        (
            "DELETE",
            format!("/s/{editor}/editor/fields/{p1_sig}"),
            json!({}),
        ),
        (
            "POST",
            format!("/s/{editor}/editor/fields"),
            json!({"fields": [{"recipient_id": p1, "document_id": doc, "type": "text",
                "page": 1, "x": 300, "y": 600, "width": 120, "height": 24}]}),
        ),
    ] {
        let r = api.call(method, &path, &Auth::None, Some(body), &h).await;
        assert_eq!(
            r.status,
            StatusCode::CONFLICT,
            "{method} {path}: {:?}",
            r.json()
        );
        assert_eq!(r.json()["code"], "CS-WF-0001", "{:?}", r.json());
    }

    // The parallel signer is no editor: refused before any id is looked up.
    let pat = invite(&api, &a, &env, &p1).await;
    let (_, pbound) = open(&api, &pat).await;
    let r = api
        .call(
            "PATCH",
            &format!("/s/{pat}/editor/fields/{s2_sig}"),
            &Auth::None,
            Some(json!({"x": 10})),
            &hdr(&pbound),
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.json());

    // What the sender sees now: the field added, the signature moved.
    let now = ok(
        api.call("GET", &base, &a.auth, None, &[]).await,
        StatusCode::OK,
        "get",
    );
    let fields = now["fields"].as_array().unwrap();
    let moved = fields.iter().find(|f| f["id"] == s2_sig.as_str()).unwrap();
    assert_eq!(moved["placement"]["x"], "320", "{moved}");
    assert!(
        fields
            .iter()
            .any(|f| f["recipient_id"] == s2.as_str() && f["type"] == "text"),
        "{now}"
    );

    // The editor and the parallel signer sign; the later signer gets the fields.
    sign(&api, &invite(&api, &a, &env, &ed).await, &[]).await;
    sign(&api, &invite(&api, &a, &env, &p1).await, &[]).await;
    let sam = invite(&api, &a, &env, &s2).await;
    let (sview, _) = open(&api, &sam).await;
    let mine: Vec<&str> = sview["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["type"].as_str().unwrap())
        .collect();
    assert!(
        mine.contains(&"text") && mine.contains(&"signature"),
        "{sview}"
    );
    assert!(
        sview.get("editable_fields").is_none(),
        "only an editor's view lists them"
    );

    // The editor, finished, changes nothing any more.
    let r = api
        .call(
            "DELETE",
            &format!("/s/{editor}/editor/fields/{s2_sig}"),
            &Auth::None,
            Some(json!({})),
            &h,
        )
        .await;
    assert!(r.status.is_client_error(), "{}", r.status);

    // The chain records each change with the editor as actor.
    let audit = ok(
        api.call("GET", &format!("{base}/audit"), &a.auth, None, &[])
            .await,
        StatusCode::OK,
        "audit",
    );
    let corrected: Vec<&Value> = audit["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["type"] == "envelope.corrected" && e["event"]["actor"]["id"] == ed.as_str())
        .collect();
    assert_eq!(corrected.len(), 2, "the add and the move, by the editor");
    api.db.drop().await;
}
