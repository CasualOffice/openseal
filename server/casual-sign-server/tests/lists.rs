//! The envelope lists (WEB-08): `GET /api/v1/envelopes` sorts by subject, status, last
//! change, creation and expiry in either direction with cursors that stay in their
//! sort; filters by a set of statuses, a sender and a last-change range; and never
//! answers another account's envelopes (row-level security on and off).
//! `DELETE /api/v1/envelopes/{id}` removes an envelope that ended without completing
//! from the lists, recorded, keeping its chain and evidence; staff download a signer's
//! attachment with `GET …/attachments/{sha256}`, recorded as `attachment.downloaded`.

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
use common::Rls;
use common::flow::{b64, invite, ok, open};
use common::harness::{Api, Auth, PASSWORD, Tenant, pdf, png, session_of};
use serde_json::{Value, json};

/// A draft with `subject`, or sent when `send`; `extra` merged into the body.
async fn make(api: &Api, auth: &Auth, subject: &str, send: bool, extra: Value) -> String {
    let mut body = json!({
        "subject": subject, "status": if send { "sent" } else { "draft" },
        "documents": [{"name": "l.pdf", "content_base64": b64(&pdf(1))}],
        "recipients": [{"ref": "s", "type": "signer", "name": "Lee", "email": "lee@example.test"}],
        "fields": [{"recipient": "s", "document": 0, "type": "signature", "page": 1,
                    "x": 72, "y": 100, "width": 180, "height": 40, "required": true}],
    });
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    let e = ok(
        api.call("POST", "/api/v1/envelopes", auth, Some(body), &[])
            .await,
        StatusCode::CREATED,
        "create",
    );
    api.clock.advance(Duration::from_secs(60));
    e["id"].as_str().unwrap().to_owned()
}

/// Every page of `query`, `limit` at a time: the subjects in order.
async fn walk(api: &Api, auth: &Auth, query: &str, limit: u32) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut q = format!("/api/v1/envelopes?limit={limit}{query}");
        if let Some(c) = &cursor {
            q.push_str(&format!("&cursor={c}"));
        }
        let page = ok(
            api.call("GET", &q, auth, None, &[]).await,
            StatusCode::OK,
            &q,
        );
        for e in page["items"].as_array().unwrap() {
            out.push(e["subject"].as_str().unwrap().to_owned());
        }
        match page["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_owned()),
            None => break,
        }
        assert!(out.len() < 100, "paging does not end");
    }
    out
}

/// The test clock's time, RFC 3339, for a query string.
fn now(api: &Api) -> String {
    use casual_sign_server::Clock as _;
    api.clock
        .now()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
        .replace('+', "%2B")
}

fn strs(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_owned()).collect()
}

async fn etag(api: &Api, auth: &Auth, id: &str) -> String {
    api.call("GET", &format!("/api/v1/envelopes/{id}"), auth, None, &[])
        .await
        .etag()
}

async fn audit_types(api: &Api, auth: &Auth, id: &str) -> Vec<Value> {
    ok(
        api.call(
            "GET",
            &format!("/api/v1/envelopes/{id}/audit"),
            auth,
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

async fn member(api: &Api, a: &Tenant) -> (Auth, String) {
    let u = ok(
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
    (session_of(&login), u["id"].as_str().unwrap().to_owned())
}

async fn scenario(rls: Rls) {
    let Some(api) = Api::new("lists", rls).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let b = api.tenant("beta").await;
    let k = &a.auth;
    let t0 = now(&api);
    // Created in this order, a minute apart.
    let bravo = make(&api, k, "Bravo", false, json!({})).await;
    let alpha = make(&api, k, "alpha", true, json!({"expires_in_days": 30})).await;
    let charlie = make(&api, k, "Charlie", true, json!({"expires_in_days": 10})).await;
    let t_mid = now(&api);
    let delta = make(&api, k, "delta", false, json!({})).await;
    make(&api, &b.auth, "Beta Only", true, json!({})).await;

    // Creation, newest first by default; any page size gives the same order.
    let newest = strs(&["delta", "Charlie", "alpha", "Bravo"]);
    assert_eq!(walk(&api, k, "", 1).await, newest);
    assert_eq!(walk(&api, k, "", 3).await, newest);
    assert_eq!(
        walk(&api, k, "&sort=created_at&order=asc", 2).await,
        strs(&["Bravo", "alpha", "Charlie", "delta"])
    );
    // Subject, ignoring case, ascending by default.
    assert_eq!(
        walk(&api, k, "&sort=subject", 1).await,
        strs(&["alpha", "Bravo", "Charlie", "delta"])
    );
    assert_eq!(
        walk(&api, k, "&sort=subject&order=desc", 3).await,
        strs(&["delta", "Charlie", "Bravo", "alpha"])
    );
    // Status in lifecycle order (drafts, then sent), ties by id (creation).
    assert_eq!(
        walk(&api, k, "&sort=status", 1).await,
        strs(&["Bravo", "delta", "alpha", "Charlie"])
    );
    // Expiry: soonest first, never expiring last.
    let by_expiry = walk(&api, k, "&sort=expires_at&order=asc", 1).await;
    assert_eq!(&by_expiry[..2], &strs(&["Charlie", "alpha"])[..]);
    // Last change: editing the oldest draft brings it first; a download does not.
    api.clock.advance(Duration::from_secs(600));
    let tag = etag(&api, k, &bravo).await;
    ok(
        api.call(
            "PATCH",
            &format!("/api/v1/envelopes/{bravo}"),
            k,
            Some(json!({"subject": "Bravo"})),
            &[("if-match", &tag)],
        )
        .await,
        StatusCode::OK,
        "patch",
    );
    let doc = ok(
        api.call("GET", &format!("/api/v1/envelopes/{alpha}"), k, None, &[])
            .await,
        StatusCode::OK,
        "get",
    )["documents"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    api.clock.advance(Duration::from_secs(60));
    let dl = api
        .call(
            "GET",
            &format!("/api/v1/envelopes/{alpha}/documents/{doc}/content?version=current"),
            k,
            None,
            &[],
        )
        .await;
    assert_eq!(dl.status, StatusCode::OK);
    assert_eq!(
        walk(&api, k, "&sort=updated_at", 1).await,
        strs(&["Bravo", "delta", "Charlie", "alpha"])
    );
    // Filters: a status set, a last-change range.
    assert_eq!(
        walk(&api, k, "&status=sent,draft&sort=subject", 2).await,
        strs(&["alpha", "Bravo", "Charlie", "delta"])
    );
    assert_eq!(
        walk(&api, k, "&status=sent&sort=subject", 2).await,
        strs(&["alpha", "Charlie"])
    );
    assert_eq!(
        walk(&api, k, &format!("&from={t0}&to={t_mid}&sort=subject"), 5).await,
        strs(&["alpha", "Charlie"])
    );
    assert_eq!(
        walk(&api, k, &format!("&from={t_mid}&sort=subject"), 5).await,
        strs(&["Bravo", "delta"])
    );
    // A cursor of another sort, an unknown sort or order, a bad instant: refused.
    let page = ok(
        api.call(
            "GET",
            "/api/v1/envelopes?limit=1&sort=subject",
            k,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "page",
    );
    let c = page["next_cursor"].as_str().unwrap();
    for bad in [
        format!("/api/v1/envelopes?sort=updated_at&cursor={c}"),
        format!("/api/v1/envelopes?sort=subject&order=desc&cursor={c}"),
        "/api/v1/envelopes?sort=sender_email".to_owned(),
        "/api/v1/envelopes?order=up".to_owned(),
        "/api/v1/envelopes?from=yesterday".to_owned(),
        "/api/v1/envelopes?status=sent,nope".to_owned(),
    ] {
        let r = api.call("GET", &bad, k, None, &[]).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
    }

    // Sender: a member without view_all sees their own, whatever they ask for.
    let (sam, sam_id) = member(&api, &a).await;
    make(&api, &sam, "Sam's", false, json!({})).await;
    assert_eq!(
        walk(&api, k, &format!("&sender={sam_id}"), 5).await,
        strs(&["Sam's"])
    );
    assert_eq!(walk(&api, &sam, "&sender=me", 5).await, strs(&["Sam's"]));
    assert_eq!(walk(&api, &sam, "", 5).await, strs(&["Sam's"]));
    let admin_id = ok(
        api.call("GET", "/api/v1/auth/session", k, None, &[]).await,
        StatusCode::OK,
        "session",
    )["user_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        walk(&api, &sam, &format!("&sender={admin_id}"), 5)
            .await
            .is_empty()
    );

    // Isolation: beta sees only its own, under every sort and filter.
    for q in [
        "",
        "&sort=subject",
        "&sort=status&order=desc",
        "&sort=updated_at&order=asc",
        "&sort=expires_at",
        "&status=sent,draft",
        "&q=a",
    ] {
        assert_eq!(walk(&api, &b.auth, q, 2).await, strs(&["Beta Only"]), "{q}");
    }
    assert_eq!(
        walk(&api, &b.auth, &format!("&sender={admin_id}"), 2).await,
        Vec::<String>::new()
    );

    // Delete: a sent envelope is refused; voided, it leaves the lists, recorded.
    let tag = etag(&api, k, &charlie).await;
    let refused = api
        .call(
            "DELETE",
            &format!("/api/v1/envelopes/{charlie}"),
            k,
            None,
            &[("if-match", &tag)],
        )
        .await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{:?}", refused.json());
    ok(
        api.call(
            "POST",
            &format!("/api/v1/envelopes/{charlie}/void"),
            k,
            Some(json!({"reason": "Superseded"})),
            &[],
        )
        .await,
        StatusCode::OK,
        "void",
    );
    let before = audit_types(&api, k, &charlie).await;
    // Another account cannot delete it.
    let tag = etag(&api, k, &charlie).await;
    let foreign = api
        .call(
            "DELETE",
            &format!("/api/v1/envelopes/{charlie}"),
            &b.auth,
            None,
            &[("if-match", &tag)],
        )
        .await;
    assert_eq!(foreign.status, StatusCode::NOT_FOUND);
    let gone = api
        .call(
            "DELETE",
            &format!("/api/v1/envelopes/{charlie}"),
            k,
            None,
            &[("if-match", &tag)],
        )
        .await;
    assert_eq!(gone.status, StatusCode::NO_CONTENT, "{:?}", gone.json());
    for q in ["", "&sort=subject", "&status=voided", "&q=Charlie"] {
        assert!(
            !walk(&api, k, q, 3).await.contains(&"Charlie".to_owned()),
            "{q}"
        );
    }
    // Still there by id, with every earlier event and one more.
    let kept = ok(
        api.call("GET", &format!("/api/v1/envelopes/{charlie}"), k, None, &[])
            .await,
        StatusCode::OK,
        "kept",
    );
    assert_eq!(kept["status"], "voided");
    let after = audit_types(&api, k, &charlie).await;
    assert_eq!(after.len(), before.len() + 1);
    assert_eq!(&after[..before.len()], &before[..]);
    assert_eq!(after.last().unwrap()["type"], "envelope.deleted");
    let tag = etag(&api, k, &charlie).await;
    let again = api
        .call(
            "DELETE",
            &format!("/api/v1/envelopes/{charlie}"),
            k,
            None,
            &[("if-match", &tag)],
        )
        .await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    // A draft is still deleted as before.
    let tag = etag(&api, k, &delta).await;
    let d = api
        .call(
            "DELETE",
            &format!("/api/v1/envelopes/{delta}"),
            k,
            None,
            &[("if-match", &tag)],
        )
        .await;
    assert_eq!(d.status, StatusCode::NO_CONTENT, "{:?}", d.json());

    attachments(&api, &a, &b, &sam).await;
    api.db.drop().await;
}

async fn attachments(api: &Api, a: &Tenant, b: &Tenant, sam: &Auth) {
    let id = make(
        api,
        &a.auth,
        "With attachment",
        true,
        json!({"fields": [
            {"recipient": "s", "document": 0, "type": "signature", "page": 1,
             "x": 72, "y": 100, "width": 180, "height": 40, "required": true},
            {"recipient": "s", "document": 0, "type": "attachment", "page": 1,
             "x": 72, "y": 300, "width": 120, "height": 30, "required": false, "label": "id_proof"}]}),
    )
    .await;
    let env = ok(
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
    let rid = env["recipients"][0]["id"].as_str().unwrap();
    let field = env["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["type"] == "attachment")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let t = invite(api, a, &id, rid).await;
    let (_, h) = open(api, &t).await;
    let h: Vec<(&str, &str)> = h.iter().map(|(k, v)| (*k, v.as_str())).collect();
    ok(
        api.call(
            "PUT",
            &format!("/s/{t}/fields/{field}/attachment"),
            &Auth::None,
            Some(json!({"content_base64": b64(&png())})),
            &h,
        )
        .await,
        StatusCode::OK,
        "attach",
    );
    let sha = casual_sign_audit::Hash256::digest(&png()).hex();
    let path = format!("/api/v1/envelopes/{id}/attachments/{sha}");
    let got = api.call("GET", &path, &a.auth, None, &[]).await;
    assert_eq!(got.status, StatusCode::OK, "{:?}", got.json());
    assert_eq!(got.headers["content-type"], "image/png");
    assert_eq!(got.headers["content-disposition"], "attachment");
    assert_eq!(&got.body[..], &png()[..]);
    let last = audit_types(api, &a.auth, &id).await.last().unwrap().clone();
    assert_eq!(last["type"], "attachment.downloaded");
    assert_eq!(last["event"]["data"]["field_id"], field.as_str());
    assert_eq!(
        last["event"]["data"]["hash"],
        format!("sha256:{sha}").as_str()
    );
    assert_eq!(last["event"]["actor"]["kind"], "sender");
    // Any other hash, another account, a member who may not see it: 404, not recorded.
    let n = audit_types(api, &a.auth, &id).await.len();
    for (who, p) in [
        (
            &a.auth,
            format!("/api/v1/envelopes/{id}/attachments/{}", "ab".repeat(32)),
        ),
        (
            &a.auth,
            format!("/api/v1/envelopes/{id}/attachments/{}", sha.to_uppercase()),
        ),
        (
            &a.auth,
            format!("/api/v1/envelopes/{id}/attachments/nothex"),
        ),
        (&b.auth, path.clone()),
        (sam, path.clone()),
    ] {
        let r = api.call("GET", &p, who, None, &[]).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{p}");
    }
    assert_eq!(audit_types(api, &a.auth, &id).await.len(), n);
}

#[tokio::test]
async fn lists_sort_filter_delete_and_serve_attachments_within_the_account() {
    scenario(Rls::On).await;
}

#[tokio::test]
async fn lists_stay_in_the_account_with_row_level_security_disabled() {
    scenario(Rls::Off).await;
}
