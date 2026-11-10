//! Contract tests (stage 2C gate): the route table and `api/openapi.yaml` agree,
//! operation by operation and scope by scope; and one scenario against PostgreSQL
//! exercises every operation of the document, including a two-signer sequential
//! envelope signed by both through the ceremony up to its seal job being enqueued.

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

use std::collections::{BTreeMap, BTreeSet};

use axum::body::Body;
use axum::http::StatusCode;
use base64::Engine as _;
use casual_sign_server::{Access, table};
use common::Rls;
use common::harness::{
    Api, Auth, OPENAPI, ceremony_cookie, ceremony_path, openapi_operations, pdf, png, session_of,
};
use serde_json::{Value, json};
use sqlx::Row;

#[test]
fn openapi_and_route_table_name_the_same_operations_and_scopes() {
    let doc = openapi_operations();
    let mut routes = BTreeMap::new();
    for r in table() {
        let perm = match r.access {
            Access::Public => "public".to_owned(),
            Access::Scope(s) => s.to_owned(),
        };
        assert!(
            routes
                .insert((r.method.to_owned(), r.path.to_owned()), perm)
                .is_none(),
            "{} {} twice",
            r.method,
            r.path
        );
    }
    let only_doc: Vec<_> = doc.keys().filter(|k| !routes.contains_key(*k)).collect();
    let only_code: Vec<_> = routes.keys().filter(|k| !doc.contains_key(*k)).collect();
    assert!(
        only_doc.is_empty(),
        "in openapi.yaml, not served: {only_doc:?}"
    );
    assert!(
        only_code.is_empty(),
        "served, not in openapi.yaml: {only_code:?}"
    );
    for (k, perm) in &routes {
        assert_eq!(&doc[k], perm, "x-permission of {k:?}");
    }
    // Every documented operation has an operationId, unique.
    let parsed: Value = serde_norway::from_str(OPENAPI).unwrap();
    let mut ids = BTreeSet::new();
    for item in parsed["paths"].as_object().unwrap().values() {
        for (m, op) in item.as_object().unwrap() {
            if m != "parameters" {
                assert!(ids.insert(op["operationId"].as_str().unwrap().to_owned()));
            }
        }
    }
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

async fn ok(r: common::harness::Resp, want: StatusCode, what: &str) -> Value {
    assert_eq!(
        r.status,
        want,
        "{what}: {}",
        String::from_utf8_lossy(&r.body)
    );
    r.json()
}

/// Mint the invitation token the worker would put in the email (stage 2D sends it).
async fn invite(api: &Api, t: &common::harness::Tenant, env: &str, rec: &str) -> String {
    casual_sign_server::issue_invitation_token(
        &api.st,
        t.boot.account,
        casual_sign_store::EnvelopeId(env.parse().unwrap()),
        casual_sign_store::RecipientId(rec.parse().unwrap()),
        std::time::Duration::from_secs(86_400),
    )
    .await
    .unwrap()
}

/// Open a ceremony: bind the link to "this browser" and answer the cookie.
async fn open(api: &Api, path: &str) -> (Value, Vec<(&'static str, String)>) {
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
        StatusCode::OK,
        "session: {}",
        String::from_utf8_lossy(&r.body)
    );
    let cookie = ceremony_cookie(&r);
    (r.json(), vec![("cookie", cookie)])
}

async fn jobs(api: &Api, env: &str) -> Vec<String> {
    sqlx::query("SELECT kind FROM jobs WHERE envelope_id = $1::uuid ORDER BY created_at, kind")
        .bind(env)
        .fetch_all(&api.db.admin)
        .await
        .unwrap()
        .iter()
        .map(|r| r.get::<String, _>(0))
        .collect()
}

#[tokio::test]
async fn every_operation_and_a_two_signer_envelope_to_its_seal_job() {
    let Some(api) = Api::new("contract_scenario", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let k = &a.auth;

    // Account, session info, policy with a disclosure to consent to.
    ok(
        api.call("GET", "/api/v1/auth/session", k, None, &[]).await,
        StatusCode::OK,
        "session",
    )
    .await;
    ok(
        api.call("GET", "/api/v1/accounts/me", k, None, &[]).await,
        StatusCode::OK,
        "account",
    )
    .await;
    let mut policy = serde_json::to_value(casual_sign_workflow::Policy::default()).unwrap();
    policy["ersd"] = json!({"version": "2026-1", "hash": format!("sha256:{}", "ab".repeat(32))});
    ok(
        api.call(
            "PATCH",
            "/api/v1/accounts/me",
            k,
            Some(json!({"settings": {"workflow_policy": policy}})),
            &[],
        )
        .await,
        StatusCode::OK,
        "patch account",
    )
    .await;

    // Users.
    let u = ok(
        api.call("POST", "/api/v1/users", k, Some(json!({"email": "s@alpha.example.test", "name": "Sam", "profile": "sender", "password": "another long passphrase"})), &[]).await,
        StatusCode::CREATED,
        "create user",
    )
    .await;
    let uid = u["id"].as_str().unwrap().to_owned();
    ok(
        api.call("GET", "/api/v1/users", k, None, &[]).await,
        StatusCode::OK,
        "users",
    )
    .await;
    ok(
        api.call("GET", &format!("/api/v1/users/{uid}"), k, None, &[])
            .await,
        StatusCode::OK,
        "user",
    )
    .await;
    ok(
        api.call(
            "PATCH",
            &format!("/api/v1/users/{uid}"),
            k,
            Some(json!({"name": "Samuel"})),
            &[],
        )
        .await,
        StatusCode::OK,
        "patch user",
    )
    .await;

    // OAuth client, token, JWKS, revocation.
    let oc = ok(
        api.call("POST", "/api/v1/api-clients", k, Some(json!({"name": "integration", "kind": "oauth_app", "scopes": ["envelopes:read", "envelopes:write", "envelopes:send"]})), &[]).await,
        StatusCode::CREATED,
        "oauth client",
    )
    .await;
    let (cid, secret) = (
        oc["client_id"].as_str().unwrap().to_owned(),
        oc["client_secret"].as_str().unwrap().to_owned(),
    );
    ok(
        api.call("GET", "/api/v1/api-clients", k, None, &[]).await,
        StatusCode::OK,
        "clients",
    )
    .await;
    ok(
        api.call("GET", &format!("/api/v1/api-clients/{cid}"), k, None, &[])
            .await,
        StatusCode::OK,
        "client",
    )
    .await;
    let form = format!("grant_type=client_credentials&client_id={cid}&client_secret={secret}");
    let tok = api
        .send(
            "POST",
            "/api/v1/oauth/token",
            &Auth::None,
            Body::from(form),
            &[("content-type", "application/x-www-form-urlencoded")],
        )
        .await;
    let tok = ok(tok, StatusCode::OK, "token").await;
    let bearer = Auth::Bearer(tok["access_token"].as_str().unwrap().to_owned());
    let jwks = ok(
        api.call("GET", "/.well-known/jwks.json", &Auth::None, None, &[])
            .await,
        StatusCode::OK,
        "jwks",
    )
    .await;
    assert_eq!(jwks["keys"][0]["alg"], "ES256");

    // The OAuth client creates an envelope with an embedded signer, and asks for its view.
    let emb = ok(
        api.call("POST", "/api/v1/envelopes", &bearer, Some(json!({
            "subject": "Embedded", "status": "sent",
            "documents": [{"name": "e.pdf", "content_base64": b64(&pdf(1))}],
            "recipients": [{"ref": "s", "type": "signer", "name": "Em Bedded", "email": "em@example.test", "embedded_client_user_id": "host-user-1"}],
            "fields": [{"recipient": "s", "document": 0, "type": "signature", "page": 1, "x": 72, "y": 600, "width": 180, "height": 40, "required": true}],
        })), &[]).await,
        StatusCode::CREATED,
        "embedded envelope",
    )
    .await;
    let emb_id = emb["id"].as_str().unwrap().to_owned();
    let emb_r = emb["recipients"][0]["id"].as_str().unwrap().to_owned();
    let view = ok(
        api.call(
            "POST",
            &format!("/api/v1/envelopes/{emb_id}/views/signing"),
            &bearer,
            Some(json!({"recipient_id": emb_r, "auth_asserted": "host SSO"})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "signing view",
    )
    .await;
    let (_, h) = open(&api, &ceremony_path(view["url"].as_str().unwrap())).await;
    assert!(!h.is_empty());
    ok(
        api.call(
            "DELETE",
            &format!("/api/v1/api-clients/{cid}"),
            k,
            None,
            &[],
        )
        .await,
        StatusCode::NO_CONTENT,
        "revoke",
    )
    .await;
    let after = api
        .call("GET", "/api/v1/envelopes", &bearer, None, &[])
        .await;
    assert_eq!(
        (after.status, after.code().as_str()),
        (StatusCode::UNAUTHORIZED, "CS-AUTH-0002")
    );

    // Templates.
    let t = ok(
        api.call(
            "POST",
            "/api/v1/templates",
            k,
            Some(json!({"name": "NDA", "roles": [{"name": "Client", "type": "signer"}]})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "template",
    )
    .await;
    let tid = t["id"].as_str().unwrap().to_owned();
    ok(
        api.call("GET", "/api/v1/templates", k, None, &[]).await,
        StatusCode::OK,
        "templates",
    )
    .await;
    let tg = api
        .call("GET", &format!("/api/v1/templates/{tid}"), k, None, &[])
        .await;
    let tag = tg.etag();
    ok(tg, StatusCode::OK, "template get").await;
    ok(
        api.call(
            "PATCH",
            &format!("/api/v1/templates/{tid}"),
            k,
            Some(json!({"name": "NDA v2"})),
            &[("if-match", &tag)],
        )
        .await,
        StatusCode::OK,
        "template patch",
    )
    .await;

    // Webhooks.
    let w = ok(
        api.call("POST", "/api/v1/webhooks", k, Some(json!({"url": "https://hooks.example.com/os", "event_types": ["envelope.completed"], "secret_refs": ["primary"]})), &[]).await,
        StatusCode::CREATED,
        "webhook",
    )
    .await;
    let wid = w["id"].as_str().unwrap().to_owned();
    ok(
        api.call("GET", "/api/v1/webhooks", k, None, &[]).await,
        StatusCode::OK,
        "webhooks",
    )
    .await;
    ok(
        api.call("GET", &format!("/api/v1/webhooks/{wid}"), k, None, &[])
            .await,
        StatusCode::OK,
        "webhook get",
    )
    .await;
    ok(
        api.call(
            "GET",
            &format!("/api/v1/webhooks/{wid}/deliveries"),
            k,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "deliveries",
    )
    .await;
    ok(
        api.call("DELETE", &format!("/api/v1/webhooks/{wid}"), k, None, &[])
            .await,
        StatusCode::NO_CONTENT,
        "webhook delete",
    )
    .await;

    // The two-signer sequential envelope, built as a draft and edited per element.
    let e = ok(
        api.call("POST", "/api/v1/envelopes", k, Some(json!({
            "subject": "Please sign: MSA", "message": "Hi",
            "documents": [{"name": "MSA.pdf", "content_base64": b64(&pdf(2))}],
            "recipients": [
                {"ref": "client", "type": "signer", "name": "A. Client", "email": "a@example.test", "routing_order": 1,
                 "auth": ["access_code"], "access_code": "4711-2024"},
                {"ref": "ceo", "type": "signer", "name": "B. Vendor", "email": "b@example.test", "routing_order": 2},
            ],
            "fields": [
                {"recipient": "client", "document": 0, "type": "signature", "page": 1, "x": 72, "y": 640, "width": 180, "height": 40, "required": true},
                {"recipient": "ceo", "document": 0, "type": "signature", "page": 2, "x": 72, "y": 640, "width": 180, "height": 40, "required": true},
            ],
            "reminders": {"first_after_days": 2, "then_every_days": 3},
            "expires_in_days": 30,
        })), &[("idempotency-key", "create-msa-1")]).await,
        StatusCode::CREATED,
        "create",
    )
    .await;
    let id = e["id"].as_str().unwrap().to_owned();
    // A replay answers the same envelope; another body under the key is refused.
    let replay = api
        .call("POST", "/api/v1/envelopes", k, Some(json!({
            "subject": "Please sign: MSA", "message": "Hi",
            "documents": [{"name": "MSA.pdf", "content_base64": b64(&pdf(2))}],
            "recipients": [
                {"ref": "client", "type": "signer", "name": "A. Client", "email": "a@example.test", "routing_order": 1,
                 "auth": ["access_code"], "access_code": "4711-2024"},
                {"ref": "ceo", "type": "signer", "name": "B. Vendor", "email": "b@example.test", "routing_order": 2},
            ],
            "fields": [
                {"recipient": "client", "document": 0, "type": "signature", "page": 1, "x": 72, "y": 640, "width": 180, "height": 40, "required": true},
                {"recipient": "ceo", "document": 0, "type": "signature", "page": 2, "x": 72, "y": 640, "width": 180, "height": 40, "required": true},
            ],
            "reminders": {"first_after_days": 2, "then_every_days": 3},
            "expires_in_days": 30,
        })), &[("idempotency-key", "create-msa-1")])
        .await;
    assert_eq!(replay.status, StatusCode::CREATED);
    assert_eq!(replay.headers["idempotency-replayed"], "true");
    assert_eq!(replay.json()["id"], id.as_str());
    let other = api
        .call(
            "POST",
            "/api/v1/envelopes",
            k,
            Some(json!({"subject": "other"})),
            &[("idempotency-key", "create-msa-1")],
        )
        .await;
    assert_eq!(
        (other.status, other.code().as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, "CS-API-0004")
    );

    let base = format!("/api/v1/envelopes/{id}");
    let client = e["recipients"][0]["id"].as_str().unwrap().to_owned();
    let ceo = e["recipients"][1]["id"].as_str().unwrap().to_owned();
    let doc = e["documents"][0]["id"].as_str().unwrap().to_owned();
    let g = api.call("GET", &base, k, None, &[]).await;
    let mut tag = g.etag();
    ok(g, StatusCode::OK, "get").await;
    let listed = ok(
        api.call("GET", "/api/v1/envelopes?limit=1", k, None, &[])
            .await,
        StatusCode::OK,
        "list",
    )
    .await;
    let cursor = listed["next_cursor"].as_str().unwrap().to_owned();
    let page2 = ok(
        api.call(
            "GET",
            &format!("/api/v1/envelopes?limit=1&cursor={cursor}"),
            k,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "page 2",
    )
    .await;
    assert_ne!(listed["items"][0]["id"], page2["items"][0]["id"]);
    ok(
        api.call("GET", &format!("{base}/status"), k, None, &[])
            .await,
        StatusCode::OK,
        "status",
    )
    .await;
    // A stale If-Match is CS-WF-0002; none is CS-API-0008.
    let none = api
        .call("PATCH", &base, k, Some(json!({"subject": "x"})), &[])
        .await;
    assert_eq!(
        (none.status, none.code().as_str()),
        (StatusCode::PRECONDITION_REQUIRED, "CS-API-0008")
    );
    let p = api
        .call(
            "PATCH",
            &base,
            k,
            Some(json!({"subject": "Please sign: MSA v2"})),
            &[("if-match", &tag)],
        )
        .await;
    let stale_tag = tag.clone();
    ok(p, StatusCode::OK, "patch").await;
    let stale = api
        .call(
            "PATCH",
            &base,
            k,
            Some(json!({"subject": "y"})),
            &[("if-match", &stale_tag)],
        )
        .await;
    assert_eq!(
        (stale.status, stale.code().as_str()),
        (StatusCode::PRECONDITION_FAILED, "CS-WF-0002")
    );

    // Documents: a second one as raw PDF, read, then removed.
    ok(
        api.call("GET", &format!("{base}/documents"), k, None, &[])
            .await,
        StatusCode::OK,
        "documents",
    )
    .await;
    let d2 = api
        .send(
            "POST",
            &format!("{base}/documents?name=Annex.pdf"),
            k,
            Body::from(pdf(1)),
            &[("content-type", "application/pdf")],
        )
        .await;
    tag = d2.etag();
    let d2 = ok(d2, StatusCode::CREATED, "upload").await;
    let d2id = d2["id"].as_str().unwrap().to_owned();
    ok(
        api.call("GET", &format!("{base}/documents/{d2id}"), k, None, &[])
            .await,
        StatusCode::OK,
        "document",
    )
    .await;
    let c = api
        .call(
            "GET",
            &format!("{base}/documents/{doc}/content"),
            k,
            None,
            &[],
        )
        .await;
    assert_eq!(c.status, StatusCode::OK);
    assert!(c.body.starts_with(b"%PDF-"));
    let del = api
        .call(
            "DELETE",
            &format!("{base}/documents/{d2id}"),
            k,
            None,
            &[("if-match", &tag)],
        )
        .await;
    assert_eq!(del.status, StatusCode::NO_CONTENT, "{:?}", del.json());

    // Recipients: add a carbon copy, read, change, remove.
    let tag_now = api.call("GET", &base, k, None, &[]).await.etag();
    let cc = ok(
        api.call("POST", &format!("{base}/recipients"), k, Some(json!({"type": "cc", "name": "Legal", "email": "legal@example.test", "routing_order": 3})), &[("if-match", &tag_now)]).await,
        StatusCode::CREATED,
        "add recipient",
    )
    .await;
    let ccid = cc["items"][0]["id"].as_str().unwrap().to_owned();
    ok(
        api.call("GET", &format!("{base}/recipients"), k, None, &[])
            .await,
        StatusCode::OK,
        "recipients",
    )
    .await;
    let gr = api
        .call("GET", &format!("{base}/recipients/{ccid}"), k, None, &[])
        .await;
    let t2 = gr.etag();
    ok(gr, StatusCode::OK, "recipient").await;
    let pr = api
        .call(
            "PATCH",
            &format!("{base}/recipients/{ccid}"),
            k,
            Some(json!({"name": "Legal Dept"})),
            &[("if-match", &t2)],
        )
        .await;
    let t3 = pr.etag();
    ok(pr, StatusCode::OK, "patch recipient").await;
    let dr = api
        .call(
            "DELETE",
            &format!("{base}/recipients/{ccid}"),
            k,
            None,
            &[("if-match", &t3)],
        )
        .await;
    assert_eq!(dr.status, StatusCode::NO_CONTENT, "{:?}", dr.json());

    // Fields: add a text field, read, change, remove; form data.
    let t4 = api.call("GET", &base, k, None, &[]).await.etag();
    let f = ok(
        api.call("POST", &format!("{base}/fields"), k, Some(json!({"items": [{"recipient": client, "document": doc, "type": "text", "page": 1, "x": 72, "y": 500, "width": 120, "height": 20, "label": "company"}]})), &[("if-match", &t4)]).await,
        StatusCode::CREATED,
        "add field",
    )
    .await;
    let fid = f["items"][0]["id"].as_str().unwrap().to_owned();
    ok(
        api.call(
            "GET",
            &format!("{base}/fields?recipient_id={client}"),
            k,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "fields",
    )
    .await;
    let gf = api
        .call("GET", &format!("{base}/fields/{fid}"), k, None, &[])
        .await;
    let t5 = gf.etag();
    ok(gf, StatusCode::OK, "field").await;
    let pf = api
        .call(
            "PATCH",
            &format!("{base}/fields/{fid}"),
            k,
            Some(json!({"tooltip": "Your company"})),
            &[("if-match", &t5)],
        )
        .await;
    let t6 = pf.etag();
    ok(pf, StatusCode::OK, "patch field").await;
    let df = api
        .call(
            "DELETE",
            &format!("{base}/fields/{fid}"),
            k,
            None,
            &[("if-match", &t6)],
        )
        .await;
    assert_eq!(df.status, StatusCode::NO_CONTENT, "{:?}", df.json());
    ok(
        api.call("GET", &format!("{base}/form-data"), k, None, &[])
            .await,
        StatusCode::OK,
        "form data",
    )
    .await;

    // Send: the first routing step is invited, the second is not.
    let sent = ok(
        api.call("POST", &format!("{base}/send"), k, None, &[])
            .await,
        StatusCode::OK,
        "send",
    )
    .await;
    assert_eq!(sent["status"], "sent");
    assert_eq!(sent["recipients"][0]["status"], "sent");
    assert_eq!(sent["recipients"][1]["status"], "created");
    let kinds = jobs(&api, &id).await;
    assert_eq!(
        kinds.iter().filter(|k| *k == "send_invitation").count(),
        1,
        "{kinds:?}"
    );
    ok(
        api.call(
            "POST",
            &format!("{base}/resend"),
            k,
            Some(json!({"recipient_ids": [client]})),
            &[],
        )
        .await,
        StatusCode::OK,
        "resend",
    )
    .await;
    let t7 = api.call("GET", &base, k, None, &[]).await.etag();
    let mut spec = sent["recipients"][1].clone();
    let corrected = api
        .call("POST", &format!("{base}/correct"), k, Some(json!({"changes": [{"op": "update_recipient", "recipient": {
            "id": spec["id"], "type": "signer", "routing_order": 2, "name": "B. Vendor", "email": "b2@example.test"}}]})), &[("if-match", &t7)])
        .await;
    spec = ok(corrected, StatusCode::OK, "correct").await;
    assert_eq!(spec["recipients"][1]["email"], "b2@example.test");
    for path in [
        format!("{base}/certificate"),
        format!("{base}/documents/combined"),
        format!("{base}/documents/{doc}/content?version=sealed"),
    ] {
        let r = api.call("GET", &path, k, None, &[]).await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (StatusCode::CONFLICT, "CS-API-0009"),
            "{path}"
        );
    }

    // Signer 1: open, read, view, consent, authenticate (wrong, then right), adopt,
    // fill, finish.
    let t1 = invite(&api, &a, &id, &client).await;
    let s1 = format!("/s/{t1}");
    let (v1, h1) = open(&api, &s1).await;
    assert_eq!(v1["recipient"]["status"], "delivered");
    let h1: Vec<(&str, &str)> = h1.iter().map(|(k, v)| (*k, v.as_str())).collect();
    // Another browser (no cookie) is refused.
    let stranger = api.call("GET", &s1, &Auth::None, None, &[]).await;
    assert_eq!(
        (stranger.status, stranger.code().as_str()),
        (StatusCode::FORBIDDEN, "CS-AUTH-0009")
    );
    ok(
        api.call("GET", &s1, &Auth::None, None, &h1).await,
        StatusCode::OK,
        "view",
    )
    .await;
    let pdfb = api
        .call(
            "GET",
            &format!("{s1}/documents/{doc}/content"),
            &Auth::None,
            None,
            &h1,
        )
        .await;
    assert!(pdfb.body.starts_with(b"%PDF-"));
    let wrong = api
        .call(
            "POST",
            &format!("{s1}/authenticate"),
            &Auth::None,
            Some(json!({"method": "access_code", "code": "0000"})),
            &h1,
        )
        .await;
    assert_eq!(wrong.status, StatusCode::FORBIDDEN);
    ok(
        api.call(
            "POST",
            &format!("{s1}/authenticate"),
            &Auth::None,
            Some(json!({"method": "access_code", "code": "4711-2024"})),
            &h1,
        )
        .await,
        StatusCode::OK,
        "auth",
    )
    .await;
    ok(
        api.call(
            "POST",
            &format!("{s1}/consent"),
            &Auth::None,
            Some(json!({"ersd_version": "2026-1", "location": {"declined": true}})),
            &h1,
        )
        .await,
        StatusCode::OK,
        "consent",
    )
    .await;
    ok(
        api.call(
            "POST",
            &format!("{s1}/documents/{doc}/viewed"),
            &Auth::None,
            Some(json!({"pages_seen": [1, 2]})),
            &h1,
        )
        .await,
        StatusCode::OK,
        "viewed",
    )
    .await;
    ok(
        api.call(
            "POST",
            &format!("{s1}/adopt"),
            &Auth::None,
            Some(json!({"mark": "signature", "method": "draw", "image_base64": b64(&png())})),
            &h1,
        )
        .await,
        StatusCode::OK,
        "adopt",
    )
    .await;
    let f1 = e["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["recipient_id"] == client.as_str())
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    ok(
        api.call(
            "PUT",
            &format!("{s1}/fields/{f1}"),
            &Auth::None,
            Some(json!({"value": {"signature": "sig-client"}})),
            &h1,
        )
        .await,
        StatusCode::OK,
        "fill",
    )
    .await;
    ok(
        api.call(
            "POST",
            &format!("{s1}/finish"),
            &Auth::None,
            Some(json!({"location": {"latitude": 51.5, "longitude": -0.12, "accuracy_m": 30}})),
            &h1,
        )
        .await,
        StatusCode::OK,
        "finish 1",
    )
    .await;
    let mid = ok(
        api.call("GET", &base, k, None, &[]).await,
        StatusCode::OK,
        "mid",
    )
    .await;
    assert_eq!(mid["recipients"][0]["status"], "completed");
    assert_eq!(
        mid["recipients"][1]["status"], "sent",
        "routing reached signer 2"
    );

    // Signer 2.
    let t2 = invite(&api, &a, &id, &ceo).await;
    let s2 = format!("/s/{t2}");
    let (_, h2) = open(&api, &s2).await;
    let h2: Vec<(&str, &str)> = h2.iter().map(|(k, v)| (*k, v.as_str())).collect();
    ok(
        api.call(
            "POST",
            &format!("{s2}/consent"),
            &Auth::None,
            Some(json!({"ersd_version": "2026-1"})),
            &h2,
        )
        .await,
        StatusCode::OK,
        "consent 2",
    )
    .await;
    ok(
        api.call(
            "POST",
            &format!("{s2}/documents/{doc}/viewed"),
            &Auth::None,
            Some(json!({"pages_seen": [1, 2]})),
            &h2,
        )
        .await,
        StatusCode::OK,
        "viewed 2",
    )
    .await;
    ok(
        api.call(
            "POST",
            &format!("{s2}/adopt"),
            &Auth::None,
            Some(json!({"mark": "signature", "method": "type", "image_base64": b64(&png())})),
            &h2,
        )
        .await,
        StatusCode::OK,
        "adopt 2",
    )
    .await;
    let f2 = e["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["recipient_id"] == ceo.as_str())
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    ok(
        api.call(
            "POST",
            &format!("{s2}/finish"),
            &Auth::None,
            Some(json!({"values": [{"field": f2, "value": {"signature": "sig-ceo"}}]})),
            &h2,
        )
        .await,
        StatusCode::OK,
        "finish 2",
    )
    .await;
    let done = ok(
        api.call("GET", &base, k, None, &[]).await,
        StatusCode::OK,
        "done",
    )
    .await;
    assert_eq!(done["status"], "completing");
    let kinds = jobs(&api, &id).await;
    assert_eq!(
        kinds.iter().filter(|k| *k == "seal_envelope").count(),
        1,
        "{kinds:?}"
    );
    // A finished link opens nothing more.
    let again = api
        .call(
            "POST",
            &format!("{s2}/finish"),
            &Auth::None,
            Some(json!({})),
            &h2,
        )
        .await;
    assert!(again.status.is_client_error());

    // The chain, re-verified on read, records each step with request context.
    let audit = ok(
        api.call("GET", &format!("{base}/audit"), k, None, &[])
            .await,
        StatusCode::OK,
        "audit",
    )
    .await;
    let types: Vec<&str> = audit["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["type"].as_str().unwrap())
        .collect();
    for want in [
        "envelope.created",
        "envelope.sent",
        "recipient.delivered",
        "recipient.consented",
        "recipient.signature_adopted",
        "recipient.signed",
        "recipient.completed",
        "envelope.completing",
    ] {
        assert!(types.contains(&want), "{want} missing from {types:?}");
    }
    let content = ok(
        api.call(
            "GET",
            &format!("{base}/documents/{doc}/content"),
            k,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "download",
    )
    .await;
    let _ = content;

    // Approve, decline, finish later, reassign, void, delete: on further envelopes.
    let mk = |rs: Value, fs: Value, status: &str| {
        json!({"subject": "More", "status": status,
        "documents": [{"name": "x.pdf", "content_base64": b64(&pdf(1))}], "recipients": rs, "fields": fs})
    };
    let ap = ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            k,
            Some(mk(
                json!([
        {"ref": "ap", "type": "approver", "name": "Ap Prover", "email": "ap@example.test"}]),
                json!([]),
                "sent",
            )),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "approver env",
    )
    .await;
    let tap = invite(
        &api,
        &a,
        ap["id"].as_str().unwrap(),
        ap["recipients"][0]["id"].as_str().unwrap(),
    )
    .await;
    let (_, hap) = open(&api, &format!("/s/{tap}")).await;
    let hap: Vec<(&str, &str)> = hap.iter().map(|(k, v)| (*k, v.as_str())).collect();
    ok(
        api.call(
            "POST",
            &format!("/s/{tap}/consent"),
            &Auth::None,
            Some(json!({"ersd_version": "2026-1"})),
            &hap,
        )
        .await,
        StatusCode::OK,
        "consent ap",
    )
    .await;
    ok(
        api.call(
            "POST",
            &format!("/s/{tap}/approve"),
            &Auth::None,
            Some(json!({})),
            &hap,
        )
        .await,
        StatusCode::OK,
        "approve",
    )
    .await;

    let sig = |r: &str| json!([{"recipient": r, "document": 0, "type": "signature", "page": 1, "x": 72, "y": 600, "width": 180, "height": 40, "required": true}]);
    let de = ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            k,
            Some(mk(
                json!([
        {"ref": "d", "type": "signer", "name": "De Cliner", "email": "d@example.test"}]),
                sig("d"),
                "sent",
            )),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "decline env",
    )
    .await;
    let tde = invite(
        &api,
        &a,
        de["id"].as_str().unwrap(),
        de["recipients"][0]["id"].as_str().unwrap(),
    )
    .await;
    let (_, hde) = open(&api, &format!("/s/{tde}")).await;
    let hde: Vec<(&str, &str)> = hde.iter().map(|(k, v)| (*k, v.as_str())).collect();
    ok(
        api.call(
            "POST",
            &format!("/s/{tde}/consent"),
            &Auth::None,
            Some(json!({"ersd_version": "2026-1"})),
            &hde,
        )
        .await,
        StatusCode::OK,
        "consent d",
    )
    .await;
    ok(
        api.call(
            "POST",
            &format!("/s/{tde}/finish-later"),
            &Auth::None,
            Some(json!({})),
            &hde,
        )
        .await,
        StatusCode::OK,
        "finish later",
    )
    .await;
    ok(
        api.call(
            "POST",
            &format!("/s/{tde}/decline"),
            &Auth::None,
            Some(json!({"reason": "Terms"})),
            &hde,
        )
        .await,
        StatusCode::OK,
        "decline",
    )
    .await;

    let re = ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            k,
            Some(mk(
                json!([
        {"ref": "r", "type": "signer", "name": "Re Assigner", "email": "r@example.test"}]),
                sig("r"),
                "sent",
            )),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "reassign env",
    )
    .await;
    let tre = invite(
        &api,
        &a,
        re["id"].as_str().unwrap(),
        re["recipients"][0]["id"].as_str().unwrap(),
    )
    .await;
    let (_, hre) = open(&api, &format!("/s/{tre}")).await;
    let hre: Vec<(&str, &str)> = hre.iter().map(|(k, v)| (*k, v.as_str())).collect();
    ok(
        api.call(
            "POST",
            &format!("/s/{tre}/consent"),
            &Auth::None,
            Some(json!({"ersd_version": "2026-1"})),
            &hre,
        )
        .await,
        StatusCode::OK,
        "consent r",
    )
    .await;
    ok(
        api.call(
            "POST",
            &format!("/s/{tre}/reassign"),
            &Auth::None,
            Some(json!({"name": "New Person", "email": "new@example.test"})),
            &hre,
        )
        .await,
        StatusCode::OK,
        "reassign",
    )
    .await;
    let reid = re["id"].as_str().unwrap();
    ok(
        api.call(
            "POST",
            &format!("/api/v1/envelopes/{reid}/void"),
            k,
            Some(json!({"reason": "Superseded"})),
            &[],
        )
        .await,
        StatusCode::OK,
        "void",
    )
    .await;
    // The reassigned recipient's link was revoked in the same transaction.
    let revoked = api
        .call("GET", &format!("/s/{tre}"), &Auth::None, None, &hre)
        .await;
    assert_eq!(
        (revoked.status, revoked.code().as_str()),
        (StatusCode::UNAUTHORIZED, "CS-AUTH-0002")
    );

    let dr = ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            k,
            Some(json!({"subject": "Draft"})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "draft",
    )
    .await;
    let drid = dr["id"].as_str().unwrap();
    let dtag = api
        .call("GET", &format!("/api/v1/envelopes/{drid}"), k, None, &[])
        .await
        .etag();
    let gone = api
        .call(
            "DELETE",
            &format!("/api/v1/envelopes/{drid}"),
            k,
            None,
            &[("if-match", &dtag)],
        )
        .await;
    assert_eq!(gone.status, StatusCode::NO_CONTENT, "{:?}", gone.json());

    // Members and sessions last.
    ok(
        api.call("DELETE", &format!("/api/v1/users/{uid}"), k, None, &[])
            .await,
        StatusCode::NO_CONTENT,
        "delete user",
    )
    .await;
    let login = api
        .call(
            "POST",
            "/api/v1/auth/login",
            &Auth::None,
            Some(json!({"email": a.email, "password": common::harness::PASSWORD})),
            &[],
        )
        .await;
    let s = session_of(&login);
    ok(
        api.call("POST", "/api/v1/auth/logout", &s, None, &[]).await,
        StatusCode::NO_CONTENT,
        "logout",
    )
    .await;
    let after = api.call("GET", "/api/v1/auth/session", &s, None, &[]).await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);

    // Every operation of the document was called.
    let called = api.called();
    let missing: Vec<_> = openapi_operations()
        .into_keys()
        .filter(|k| !called.contains(k))
        .collect();
    assert!(missing.is_empty(), "never exercised: {missing:?}");
    api.db.drop().await;
}
