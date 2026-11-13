//! The Inbox, folders, the Deleted view, the list filters and the envelope certificate
//! of an envelope that ended without completing (UXW-01, UXW-02, UXW-03, UXW-30), as
//! `webapp/api.js` calls them: `GET /envelopes?waiting_for=me` and `POST …/sign-link`;
//! `GET`/`POST /folders`, `PATCH`/`DELETE /folders/{id}`, `POST /folders/{id|none}/
//! envelopes`, `GET /envelopes?folder=`; `GET /envelopes?deleted=true`; `?recipient=`
//! and `?date_field=`; `GET …/certificate` of a voided envelope. Access is per member
//! and per account, deny by default.

#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use casual_sign_store::blob::BlobStore as _;
use common::Rls;
use common::flow::{b64, jobs, ok, open};
use common::harness::{Api, Auth, PASSWORD, Tenant, ceremony_path, pdf, session_of};
use serde_json::{Value, json};

const SAM: &str = "sam@alpha.example.test";

/// A member of `a` with the sender profile, signed in: their session and user id.
async fn member(api: &Api, a: &Tenant) -> (Auth, String) {
    let u = ok(
        api.call(
            "POST",
            "/api/v1/users",
            &a.auth,
            Some(json!({"email": SAM, "name": "Sam", "profile": "sender", "password": PASSWORD})),
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
            Some(json!({"email": SAM, "password": PASSWORD})),
            &[],
        )
        .await;
    (session_of(&login), u["id"].as_str().unwrap().to_owned())
}

/// An envelope sent (or a draft) by `auth` to `recipients` (`(type, name, email)`, in
/// routing order), one signature field for each signer. Answers the envelope.
async fn envelope(
    api: &Api,
    auth: &Auth,
    subject: &str,
    send: bool,
    recipients: &[(&str, &str, &str)],
) -> Value {
    let recs: Vec<Value> = recipients
        .iter()
        .enumerate()
        .map(|(i, (t, n, e))| {
            json!({"ref": format!("r{i}"), "type": t, "name": n, "email": e,
                   "routing_order": i + 1})
        })
        .collect();
    let fields: Vec<Value> = recipients
        .iter()
        .enumerate()
        .filter(|(_, (t, _, _))| *t == "signer")
        .map(|(i, _)| {
            json!({"recipient": format!("r{i}"), "document": 0, "type": "signature",
                   "page": 1, "x": 72, "y": 100 + 60 * i, "width": 180, "height": 40,
                   "required": true})
        })
        .collect();
    let e = ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            auth,
            Some(json!({
                "subject": subject, "status": if send { "sent" } else { "draft" },
                "documents": [{"name": "d.pdf", "content_base64": b64(&pdf(1))}],
                "recipients": recs, "fields": fields,
            })),
            &[],
        )
        .await,
        StatusCode::CREATED,
        subject,
    );
    api.clock.advance(Duration::from_secs(60));
    e
}

fn id(v: &Value) -> String {
    v["id"].as_str().unwrap().to_owned()
}

/// The subjects of one page of `query`.
async fn subjects(api: &Api, auth: &Auth, query: &str) -> Vec<String> {
    let page = ok(
        api.call("GET", &format!("/api/v1/envelopes{query}"), auth, None, &[])
            .await,
        StatusCode::OK,
        query,
    );
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["subject"].as_str().unwrap().to_owned())
        .collect()
}

async fn audit_types(api: &Api, t: &Tenant, env: &str) -> Vec<Value> {
    ok(
        api.call(
            "GET",
            &format!("/api/v1/envelopes/{env}/audit"),
            &t.auth,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "audit",
    )["items"]
        .as_array()
        .unwrap()
        .clone()
}

async fn inbox(rls: Rls) {
    let Some(api) = Api::new(&format!("inbox_{rls:?}"), rls).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let b = api.tenant("beta").await;
    let (sam, _) = member(&api, &a).await;
    // Routing has not reached Sam; Sam's turn; Sam a copy; a draft for Sam.
    let later = envelope(
        &api,
        &a.auth,
        "Later",
        true,
        &[
            ("signer", "Lee", "lee@example.test"),
            ("signer", "Sam", SAM),
        ],
    )
    .await;
    let now = envelope(
        &api,
        &a.auth,
        "Now",
        true,
        &[("signer", "Sam", "SAM@Alpha.example.test")],
    )
    .await;
    let copy = envelope(
        &api,
        &a.auth,
        "Copy",
        true,
        &[("signer", "Lee", "lee@example.test"), ("cc", "Sam", SAM)],
    )
    .await;
    envelope(&api, &a.auth, "Draft", false, &[("signer", "Sam", SAM)]).await;

    // Sam sends nothing and may not see every envelope: their lists are empty, but the
    // Inbox has the one waiting for them, with the recipient they are.
    assert!(subjects(&api, &sam, "").await.is_empty());
    let page = ok(
        api.call("GET", "/api/v1/envelopes?waiting_for=me", &sam, None, &[])
            .await,
        StatusCode::OK,
        "inbox",
    );
    let items = page["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{page}");
    assert_eq!(items[0]["id"], now["id"]);
    assert_eq!(items[0]["my_recipient_id"], now["recipients"][0]["id"]);
    // The administrator is no recipient of any.
    assert!(subjects(&api, &a.auth, "?waiting_for=me").await.is_empty());
    // Another account's member sees nothing of it.
    assert!(subjects(&api, &b.auth, "?waiting_for=me").await.is_empty());
    let bad = api
        .call("GET", "/api/v1/envelopes?waiting_for=you", &sam, None, &[])
        .await;
    assert_eq!(bad.status, StatusCode::UNPROCESSABLE_ENTITY);

    // The sign-link: Sam's turn is a link; before it, 409; a copy is no recipient who
    // acts (404, as Sam may not see it); another account's, 404; an API key, 403.
    let later_id = id(&later);
    let r = api
        .call(
            "POST",
            &format!("/api/v1/envelopes/{later_id}/sign-link"),
            &sam,
            None,
            &[],
        )
        .await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::CONFLICT, "CS-WF-0007")
    );
    let r = api
        .call(
            "POST",
            &format!("/api/v1/envelopes/{}/sign-link", id(&copy)),
            &sam,
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let now_id = id(&now);
    let r = api
        .call(
            "POST",
            &format!("/api/v1/envelopes/{now_id}/sign-link"),
            &a.auth,
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "an API key");
    let blogin = api
        .call(
            "POST",
            "/api/v1/auth/login",
            &Auth::None,
            Some(json!({"email": b.email, "password": PASSWORD})),
            &[],
        )
        .await;
    let r = api
        .call(
            "POST",
            &format!("/api/v1/envelopes/{now_id}/sign-link"),
            &session_of(&blogin),
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "another account's");
    let link = ok(
        api.call(
            "POST",
            &format!("/api/v1/envelopes/{now_id}/sign-link"),
            &sam,
            None,
            &[],
        )
        .await,
        StatusCode::CREATED,
        "sign-link",
    );
    assert!(link["expires_at"].is_string());
    let path = ceremony_path(link["url"].as_str().unwrap());
    let token = path.strip_prefix("/s/").unwrap().to_owned();
    let (view, _) = open(&api, &token).await;
    assert_eq!(view["envelope"]["id"], now["id"]);
    // The opening records the member's sign-in, not an emailed link.
    let opened: Vec<Value> = audit_types(&api, &a, &now_id)
        .await
        .into_iter()
        .filter(|e| e["type"] == "recipient.delivered")
        .collect();
    assert_eq!(opened.len(), 1);
    assert_eq!(
        opened[0]["event"]["context"]["auth"][0], "account_login",
        "{}",
        opened[0]
    );
    // Issuing a link changes nothing in the envelope.
    let events = audit_types(&api, &a, &now_id).await.len();
    // A member disabled after asking: their link stops working.
    let link = ok(
        api.call(
            "POST",
            &format!("/api/v1/envelopes/{now_id}/sign-link"),
            &sam,
            None,
            &[],
        )
        .await,
        StatusCode::CREATED,
        "sign-link again",
    );
    assert_eq!(audit_types(&api, &a, &now_id).await.len(), events);
    let sam_id = ok(
        api.call("GET", "/api/v1/users", &a.auth, None, &[]).await,
        StatusCode::OK,
        "users",
    )["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["email"] == SAM)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    ok(
        api.call(
            "PATCH",
            &format!("/api/v1/users/{sam_id}"),
            &a.auth,
            Some(json!({"disabled": true})),
            &[],
        )
        .await,
        StatusCode::OK,
        "disable",
    );
    let path = ceremony_path(link["url"].as_str().unwrap());
    let r = api
        .call(
            "POST",
            &format!("{path}/session"),
            &Auth::None,
            Some(json!({})),
            &[],
        )
        .await;
    assert_eq!(
        r.status,
        StatusCode::UNAUTHORIZED,
        "{}",
        String::from_utf8_lossy(&r.body)
    );
    api.db.drop().await;
}

#[tokio::test]
async fn the_inbox_lists_and_links_only_what_waits_for_the_member_with_rls() {
    inbox(Rls::On).await;
}

#[tokio::test]
async fn the_inbox_lists_and_links_only_what_waits_for_the_member_without_rls() {
    inbox(Rls::Off).await;
}

async fn folders(rls: Rls) {
    let Some(api) = Api::new(&format!("folders_{rls:?}"), rls).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let b = api.tenant("beta").await;
    let (sam, _) = member(&api, &a).await;
    let e1 = envelope(
        &api,
        &a.auth,
        "One",
        true,
        &[("signer", "Lee", "lee@example.test")],
    )
    .await;
    let e2 = envelope(
        &api,
        &a.auth,
        "Two",
        false,
        &[("signer", "Lee", "lee@example.test")],
    )
    .await;
    let (e1, e2) = (id(&e1), id(&e2));

    // Names: trimmed, 1 to 100 characters, unique per member ignoring case.
    let f = ok(
        api.call(
            "POST",
            "/api/v1/folders",
            &a.auth,
            Some(json!({"name": "  Q3  "})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "folder",
    );
    assert_eq!(
        (f["name"].as_str(), f["count"].as_i64()),
        (Some("Q3"), Some(0))
    );
    let fid = id(&f);
    for (body, code) in [
        (json!({"name": "q3"}), "exists"),
        (json!({"name": " "}), "CS-API-0001"),
        (json!({"name": "x".repeat(101)}), "CS-API-0001"),
    ] {
        let r = api
            .call("POST", "/api/v1/folders", &a.auth, Some(body), &[])
            .await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(r.json()["errors"][0]["code"], code);
    }
    let r = api
        .call(
            "POST",
            "/api/v1/folders",
            &a.auth,
            Some(json!({"name": "A", "x": 1})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "unknown member");

    // Filing changes neither the envelope's last change nor its chain.
    let before = ok(
        api.call("GET", "/api/v1/envelopes?folder=none", &a.auth, None, &[])
            .await,
        StatusCode::OK,
        "list",
    )["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["id"] == e1.as_str())
        .unwrap()
        .clone();
    assert!(before["updated_at"].is_string());
    let chain = audit_types(&api, &a, &e1).await.len();
    api.clock.advance(Duration::from_secs(60));
    let moved = ok(
        api.call(
            "POST",
            &format!("/api/v1/folders/{fid}/envelopes"),
            &a.auth,
            Some(json!({"envelope_ids": [e1, e1]})),
            &[],
        )
        .await,
        StatusCode::OK,
        "file",
    );
    assert_eq!(moved["moved"], 1);
    assert_eq!(audit_types(&api, &a, &e1).await.len(), chain);
    let page = ok(
        api.call(
            "GET",
            &format!("/api/v1/envelopes?folder={fid}"),
            &a.auth,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "in folder",
    );
    let items = page["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(
        (items[0]["id"].as_str(), items[0]["folder_id"].as_str()),
        (Some(e1.as_str()), Some(fid.as_str()))
    );
    assert_eq!(items[0]["updated_at"], before["updated_at"]);
    assert_eq!(subjects(&api, &a.auth, "?folder=none").await, vec!["Two"]);
    assert_eq!(
        ok(
            api.call("GET", "/api/v1/folders", &a.auth, None, &[]).await,
            StatusCode::OK,
            "list"
        )["items"][0]["count"],
        1
    );
    let r = api
        .call("GET", "/api/v1/envelopes?folder=nope", &a.auth, None, &[])
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);

    // Another member: no folders of theirs, the administrator's folder is not found,
    // and they may not file what they may not see.
    assert_eq!(
        ok(
            api.call("GET", "/api/v1/folders", &sam, None, &[]).await,
            StatusCode::OK,
            "sam"
        )["items"],
        json!([])
    );
    for (m, p, body) in [
        (
            "PATCH",
            format!("/api/v1/folders/{fid}"),
            Some(json!({"name": "Mine"})),
        ),
        ("DELETE", format!("/api/v1/folders/{fid}"), None),
        (
            "POST",
            format!("/api/v1/folders/{fid}/envelopes"),
            Some(json!({"envelope_ids": [e2]})),
        ),
    ] {
        let r = api.call(m, &p, &sam, body.clone(), &[]).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{m} {p}");
        let r = api.call(m, &p, &b.auth, body, &[]).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "another account: {m} {p}");
    }
    assert!(
        subjects(&api, &sam, &format!("?folder={fid}"))
            .await
            .is_empty()
    );
    assert!(
        subjects(&api, &b.auth, &format!("?folder={fid}"))
            .await
            .is_empty()
    );
    let mine = id(&ok(
        api.call(
            "POST",
            "/api/v1/folders",
            &sam,
            Some(json!({"name": "Q3"})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "the same name, another member",
    ));
    let r = api
        .call(
            "POST",
            &format!("/api/v1/folders/{mine}/envelopes"),
            &sam,
            Some(json!({"envelope_ids": [e1]})),
            &[],
        )
        .await;
    assert_eq!(
        r.status,
        StatusCode::NOT_FOUND,
        "an envelope Sam may not see"
    );
    let r = api
        .call(
            "POST",
            "/api/v1/folders/none/envelopes",
            &b.auth,
            Some(json!({"envelope_ids": [e1]})),
            &[],
        )
        .await;
    assert_eq!(
        r.status,
        StatusCode::NOT_FOUND,
        "another account's envelope"
    );
    for body in [json!({"envelope_ids": []}), json!({"envelope_ids": ["x"]})] {
        let r = api
            .call(
                "POST",
                &format!("/api/v1/folders/{fid}/envelopes"),
                &a.auth,
                Some(body),
                &[],
            )
            .await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    // Rename, unfile, file again, delete: the filing goes with the folder.
    let f = ok(
        api.call(
            "PATCH",
            &format!("/api/v1/folders/{fid}"),
            &a.auth,
            Some(json!({"name": "Q4"})),
            &[],
        )
        .await,
        StatusCode::OK,
        "rename",
    );
    assert_eq!(
        (f["name"].as_str(), f["count"].as_i64()),
        (Some("Q4"), Some(1))
    );
    ok(
        api.call(
            "POST",
            "/api/v1/folders/none/envelopes",
            &a.auth,
            Some(json!({"envelope_ids": [e1]})),
            &[],
        )
        .await,
        StatusCode::OK,
        "unfile",
    );
    assert!(
        subjects(&api, &a.auth, &format!("?folder={fid}"))
            .await
            .is_empty()
    );
    ok(
        api.call(
            "POST",
            &format!("/api/v1/folders/{fid}/envelopes"),
            &a.auth,
            Some(json!({"envelope_ids": [e1, e2]})),
            &[],
        )
        .await,
        StatusCode::OK,
        "file two",
    );
    let r = api
        .call(
            "DELETE",
            &format!("/api/v1/folders/{fid}"),
            &a.auth,
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let page = ok(
        api.call("GET", "/api/v1/envelopes", &a.auth, None, &[])
            .await,
        StatusCode::OK,
        "all",
    );
    assert!(
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["folder_id"].is_null())
    );
    let r = api
        .call(
            "DELETE",
            &format!("/api/v1/folders/{fid}"),
            &a.auth,
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    api.db.drop().await;
}

#[tokio::test]
async fn folders_are_each_members_own_with_rls() {
    folders(Rls::On).await;
}

#[tokio::test]
async fn folders_are_each_members_own_without_rls() {
    folders(Rls::Off).await;
}

/// `?recipient=`, `?date_field=` and the Deleted view (`?deleted=true`).
#[tokio::test]
async fn filters_by_recipient_and_date_field_and_lists_the_deleted() {
    let Some(api) = Api::new("filters_recipient_date_deleted", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let start = {
        use casual_sign_server::Clock as _;
        api.clock.now()
    };
    let rfc = |t: time::OffsetDateTime| {
        t.format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    };
    envelope(
        &api,
        &a.auth,
        "Draft",
        false,
        &[("signer", "Lee", "lee@example.test")],
    )
    .await;
    let lee = envelope(
        &api,
        &a.auth,
        "To Lee",
        true,
        &[("signer", "Lee", "lee@example.test")],
    )
    .await;
    let kim = envelope(
        &api,
        &a.auth,
        "To Kim",
        true,
        &[("signer", "Kim Park", "kim@example.test")],
    )
    .await;

    assert_eq!(
        subjects(&api, &a.auth, "?recipient=KIM%40").await,
        vec!["To Kim"]
    );
    assert_eq!(
        subjects(&api, &a.auth, "?recipient=park").await,
        vec!["To Kim"]
    );
    let mut both = subjects(&api, &a.auth, "?recipient=example.test").await;
    both.sort();
    assert_eq!(both, vec!["Draft", "To Kim", "To Lee"]);
    let long = "x".repeat(201);
    let r = api
        .call(
            "GET",
            &format!("/api/v1/envelopes?recipient={long}"),
            &a.auth,
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);

    // Sent from a minute after the start: the two sent ones; the draft has no sending.
    let from = rfc(start + Duration::from_secs(30));
    let mut sent = subjects(
        &api,
        &a.auth,
        &format!("?date_field=sent_at&from={}", from.replace('+', "%2B")),
    )
    .await;
    sent.sort();
    assert_eq!(sent, vec!["To Kim", "To Lee"]);
    // Created before Kim's (creation is the database's time, not the test clock's).
    let page = ok(
        api.call("GET", "/api/v1/envelopes", &a.auth, None, &[])
            .await,
        StatusCode::OK,
        "all",
    );
    let to = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["subject"] == "To Kim")
        .unwrap()["created_at"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        subjects(
            &api,
            &a.auth,
            &format!("?date_field=created_at&to={}", to.replace('+', "%2B"))
        )
        .await,
        vec!["To Lee", "Draft"]
    );
    assert!(
        subjects(
            &api,
            &a.auth,
            &format!(
                "?date_field=completed_at&from={}",
                rfc(start).replace('+', "%2B")
            )
        )
        .await
        .is_empty()
    );
    let r = api
        .call(
            "GET",
            "/api/v1/envelopes?date_field=voided_at",
            &a.auth,
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);

    // Void and delete Kim's: out of the lists, in the Deleted view.
    let kid = id(&kim);
    ok(
        api.call(
            "POST",
            &format!("/api/v1/envelopes/{kid}/void"),
            &a.auth,
            Some(json!({"reason": "Wrong"})),
            &[],
        )
        .await,
        StatusCode::OK,
        "void",
    );
    let tag = api
        .call(
            "GET",
            &format!("/api/v1/envelopes/{kid}"),
            &a.auth,
            None,
            &[],
        )
        .await
        .etag();
    let r = api
        .call(
            "DELETE",
            &format!("/api/v1/envelopes/{kid}"),
            &a.auth,
            None,
            &[("if-match", &tag)],
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert!(
        !subjects(&api, &a.auth, "")
            .await
            .contains(&"To Kim".to_owned())
    );
    assert_eq!(
        subjects(&api, &a.auth, "?deleted=true").await,
        vec!["To Kim"]
    );
    assert_eq!(
        subjects(&api, &a.auth, "?deleted=true&recipient=lee").await,
        Vec::<String>::new()
    );
    let r = api
        .call("GET", "/api/v1/envelopes?deleted=yes", &a.auth, None, &[])
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    let _ = lee;
    api.db.drop().await;
}

/// A voided envelope's certificate (UXW-30): the end queued the worker's job once;
/// before it ran the answer is 409 and asking again queues nothing more; once the
/// sealed certificate is stored it is served and its download recorded.
#[tokio::test]
async fn a_voided_envelopes_certificate_is_made_by_the_worker_and_served() {
    let Some(api) = Api::new("ended_certificate", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let b = api.tenant("beta").await;
    let e = envelope(
        &api,
        &a.auth,
        "Void me",
        true,
        &[("signer", "Lee", "lee@example.test")],
    )
    .await;
    let eid = id(&e);
    let r = api
        .call(
            "GET",
            &format!("/api/v1/envelopes/{eid}/certificate"),
            &a.auth,
            None,
            &[],
        )
        .await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::CONFLICT, "CS-API-0009"),
        "not ended"
    );
    assert!(
        !jobs(&api, &eid)
            .await
            .iter()
            .any(|k| k == "seal_ended_certificate")
    );
    ok(
        api.call(
            "POST",
            &format!("/api/v1/envelopes/{eid}/void"),
            &a.auth,
            Some(json!({"reason": "Wrong"})),
            &[],
        )
        .await,
        StatusCode::OK,
        "void",
    );
    let queued = |k: &Vec<String>| k.iter().filter(|k| *k == "seal_ended_certificate").count();
    assert_eq!(queued(&jobs(&api, &eid).await), 1, "the end queued it");
    for _ in 0..2 {
        let r = api
            .call(
                "GET",
                &format!("/api/v1/envelopes/{eid}/certificate"),
                &a.auth,
                None,
                &[],
            )
            .await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (StatusCode::CONFLICT, "CS-API-0009")
        );
    }
    assert_eq!(
        queued(&jobs(&api, &eid).await),
        1,
        "asking again queues nothing more"
    );
    // An envelope that ended before the job existed (here: its job removed) gets one
    // when its certificate is asked for.
    sqlx::query(
        "DELETE FROM jobs WHERE envelope_id = $1::uuid AND kind = 'seal_ended_certificate'",
    )
    .bind(&eid)
    .execute(&api.db.admin)
    .await
    .unwrap();
    assert_eq!(queued(&jobs(&api, &eid).await), 0);
    let r = api
        .call(
            "GET",
            &format!("/api/v1/envelopes/{eid}/certificate"),
            &a.auth,
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(queued(&jobs(&api, &eid).await), 1, "asked for, queued");
    // Another account: as missing.
    let r = api
        .call(
            "GET",
            &format!("/api/v1/envelopes/{eid}/certificate"),
            &b.auth,
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    // The worker's result, stored as it stores it (worker tests make and seal it).
    let bytes = pdf(1);
    let blobs = casual_sign_store::blob::FsBlobStore::new(api.blob_dir.clone()).unwrap();
    let key = blobs.put(&bytes).await.unwrap();
    let mut tx = api
        .db
        .store
        .for_account(a.boot.account)
        .begin()
        .await
        .unwrap();
    tx.envelopes()
        .set_certificate(casual_sign_store::EnvelopeId(eid.parse().unwrap()), &key.0)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let r = api
        .call(
            "GET",
            &format!("/api/v1/envelopes/{eid}/certificate"),
            &a.auth,
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body.as_ref(), bytes.as_slice());
    let types: Vec<Value> = audit_types(&api, &a, &eid)
        .await
        .iter()
        .map(|e| e["type"].clone())
        .collect();
    assert_eq!(types.last().unwrap(), "certificate.downloaded");
    api.db.drop().await;
}
