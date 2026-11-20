//! Slice 9, embedding (`VS-09`, docs/40 §5; SEC-A06, SEC-A08): the workspace's list of
//! origins that may frame its views; the signing, prepare and correct view links, each
//! five minutes long and spent once; the pages' `frame-ancestors` naming the host page
//! only; the signing page's binding carried in a header inside another site's frame,
//! for an embedded link only; and a prepare or correct view session that acts on its
//! own envelope, with its editor's operations, and nothing else.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines
)]

mod common;

use axum::body::Body;
use axum::http::StatusCode;
use casual_sign_server::web::WebApp;
use common::Rls;
use common::flow::{b64, ok};
use common::harness::{Api, Auth, Resp, Tenant, ceremony_cookie, ceremony_path, pdf};
use serde_json::{Value, json};

const HOST: &str = "https://host.example";
const BROWSER: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

fn code(r: &Resp) -> (StatusCode, String) {
    (r.status, r.code())
}

fn header<'a>(r: &'a Resp, name: &str) -> &'a str {
    r.headers.get(name).map_or("", |v| v.to_str().unwrap_or(""))
}

fn frame_ancestors(r: &Resp) -> String {
    header(r, "content-security-policy")
        .split(';')
        .map(str::trim)
        .find(|d| d.starts_with("frame-ancestors"))
        .unwrap_or("")
        .to_owned()
}

async fn page(api: &Api, path: &str) -> Resp {
    api.send(
        "GET",
        path,
        &Auth::None,
        Body::empty(),
        &[("accept", BROWSER)],
    )
    .await
}

fn webapp(api: &Api) {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../webapp");
    api.st.set_webapp(WebApp::load(&dir).unwrap());
}

/// A key acting as the tenant's administrator, with the envelope scopes.
async fn host_key(api: &Api, t: &Tenant, name: &str) -> (Auth, String) {
    let k = ok(
        api.call(
            "POST",
            "/api/v1/api-clients",
            &t.auth,
            Some(json!({"name": name, "kind": "api_key",
                "scopes": ["envelopes:read", "envelopes:write", "envelopes:send"]})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "host key",
    );
    (
        Auth::Bearer(k["key"].as_str().unwrap().to_owned()),
        k["id"].as_str().unwrap().to_owned(),
    )
}

async fn allow(api: &Api, t: &Tenant, origins: Value) -> Resp {
    api.call(
        "PATCH",
        "/api/v1/accounts/me",
        &t.auth,
        Some(json!({"settings": {"embedding_origins": origins}})),
        &[],
    )
    .await
}

async fn draft(api: &Api, auth: &Auth, subject: &str) -> Value {
    ok(
        api.call("POST", "/api/v1/envelopes", auth, Some(json!({
            "subject": subject,
            "documents": [{"name": "p.pdf", "content_base64": b64(&pdf(1))}],
            "recipients": [{"ref": "s", "type": "signer", "name": "Pat Prepare", "email": "pat@example.test"}],
            "fields": [{"recipient": "s", "document": 0, "type": "signature", "page": 1, "x": 72, "y": 600, "width": 180, "height": 40, "required": true}],
        })), &[]).await,
        StatusCode::CREATED,
        "draft",
    )
}

#[tokio::test]
async fn an_embedded_signing_view_is_framed_by_its_host_only_and_binds_by_header() {
    let Some(api) = Api::new("embed_signing_view", Rls::On).await else {
        return;
    };
    webapp(&api);
    let a = api.tenant("alpha").await;
    // The list is checked: origins as a browser writes them, distinct, at most twenty.
    for bad in [
        json!("https://host.example"),
        json!(["https://host.example/"]),
        json!(["http://host.example"]),
        json!(["https://HOST.example"]),
        json!([HOST, HOST]),
    ] {
        let r = allow(&api, &a, bad.clone()).await;
        assert_eq!(
            code(&r),
            (StatusCode::UNPROCESSABLE_ENTITY, "CS-API-0001".into()),
            "{bad}"
        );
    }
    let r = allow(&api, &a, json!([HOST, "http://localhost:3000"])).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());

    let (host, _) = host_key(&api, &a, "host").await;
    let e = ok(
        api.call("POST", "/api/v1/envelopes", &host, Some(json!({
            "subject": "Embedded", "status": "sent",
            "documents": [{"name": "e.pdf", "content_base64": b64(&pdf(1))}],
            "recipients": [
                {"ref": "s", "type": "signer", "name": "Em Bedded", "email": "em@example.test", "embedded_client_user_id": "u1", "routing_order": 1},
                {"ref": "w", "type": "in_person_signer", "name": "Walk In", "email": "walk@example.test", "routing_order": 1},
            ],
            "fields": [
                {"recipient": "s", "document": 0, "type": "signature", "page": 1, "x": 72, "y": 600, "width": 180, "height": 40, "required": true},
                {"recipient": "w", "document": 0, "type": "signature", "page": 1, "x": 72, "y": 500, "width": 180, "height": 40, "required": true},
            ],
        })), &[]).await,
        StatusCode::CREATED,
        "embedded envelope",
    );
    let id = e["id"].as_str().unwrap();
    let rid = e["recipients"][0]["id"].as_str().unwrap();
    let path = format!("/api/v1/envelopes/{id}/views/signing");

    // A frame origin or return URL off the list is refused before anything is made.
    for (body, pointer) in [
        (
            json!({"recipient_id": rid, "frame_origin": "https://evil.example"}),
            "/frame_origin",
        ),
        (
            json!({"recipient_id": rid, "frame_origin": "https://host.example/x"}),
            "/frame_origin",
        ),
        (
            json!({"recipient_id": rid, "return_url": "https://evil.example/done"}),
            "/return_url",
        ),
        (
            json!({"recipient_id": rid, "return_url": "javascript:alert(1)"}),
            "/return_url",
        ),
    ] {
        let r = api.call("POST", &path, &host, Some(body), &[]).await;
        assert_eq!(
            code(&r),
            (StatusCode::UNPROCESSABLE_ENTITY, "CS-EMB-0001".into())
        );
        assert_eq!(r.json()["errors"][0]["pointer"], pointer);
    }
    let view = ok(
        api.call(
            "POST",
            &path,
            &host,
            Some(json!({"recipient_id": rid, "frame_origin": HOST,
                "return_url": "https://host.example/back?order=7", "state": "order-7"})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "signing view",
    );
    let link = ceremony_path(view["url"].as_str().unwrap());

    // The page may be framed by the host page only (SEC-A06), and says so without the
    // blanket X-Frame-Options.
    let p = page(&api, &link).await;
    assert_eq!(p.status, StatusCode::OK);
    assert_eq!(frame_ancestors(&p), format!("frame-ancestors {HOST}"));
    assert_eq!(header(&p, "x-frame-options"), "");
    // Any other page is framed by nobody.
    for other in ["/s/not-a-token", "/app.html", "/e/not-a-token"] {
        let p = page(&api, other).await;
        assert_eq!(frame_ancestors(&p), "frame-ancestors 'none'", "{other}");
        assert_eq!(header(&p, "x-frame-options"), "DENY", "{other}");
    }

    // Inside another site's frame the browser sends no first-party cookie: the binding
    // comes back once, in the answer that bound the link, with where events go.
    let s = api
        .call(
            "POST",
            &format!("{link}/session"),
            &Auth::None,
            Some(json!({})),
            &[],
        )
        .await;
    assert_eq!(s.status, StatusCode::OK, "{:?}", s.json());
    let binding = s.json()["binding"].as_str().unwrap().to_owned();
    assert_eq!(
        s.json()["embed"],
        json!({"frame_origin": HOST, "frame_origins": [HOST], "return_url": "https://host.example/back?order=7", "state": "order-7"})
    );
    let with = |b: &str| vec![("x-openseal-binding", b.to_owned())];
    let call = |hs: Vec<(&'static str, String)>| {
        let link = link.clone();
        let api = &api;
        async move {
            let h: Vec<(&str, &str)> = hs.iter().map(|(k, v)| (*k, v.as_str())).collect();
            api.call("GET", &link, &Auth::None, None, &h).await
        }
    };
    let r = call(with(&binding)).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    assert!(
        r.json().get("binding").is_none(),
        "the binding is answered once"
    );
    assert_eq!(
        code(&call(with("not-the-binding")).await),
        (StatusCode::FORBIDDEN, "CS-AUTH-0009".into())
    );
    assert_eq!(
        code(&call(vec![]).await),
        (StatusCode::FORBIDDEN, "CS-AUTH-0009".into())
    );
    // Single use: a second opening, from anywhere, binds nothing.
    let again = api
        .call(
            "POST",
            &format!("{link}/session"),
            &Auth::None,
            Some(json!({})),
            &[],
        )
        .await;
    assert_eq!(code(&again), (StatusCode::FORBIDDEN, "CS-AUTH-0009".into()));

    // Only an embedded link takes the header: an in-person link stays bound by its
    // HttpOnly cookie, and its binding never appears in an answer.
    let w = e["recipients"][1]["id"].as_str().unwrap();
    let hosted = ok(
        api.call(
            "POST",
            &format!("/api/v1/envelopes/{id}/recipients/{w}/host"),
            &a.auth,
            None,
            &[],
        )
        .await,
        StatusCode::CREATED,
        "in person",
    );
    let ip = ceremony_path(hosted["url"].as_str().unwrap());
    let s = api
        .call(
            "POST",
            &format!("{ip}/session"),
            &Auth::None,
            Some(json!({})),
            &[],
        )
        .await;
    assert_eq!(s.status, StatusCode::OK, "{:?}", s.json());
    assert!(s.json().get("binding").is_none());
    assert!(s.json().get("embed").is_none());
    let cookie = ceremony_cookie(&s);
    let secret = cookie.split_once('=').unwrap().1.to_owned();
    let r = api
        .call(
            "GET",
            &ip,
            &Auth::None,
            None,
            &[("x-openseal-binding", &secret)],
        )
        .await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "CS-AUTH-0009".into()));
    let r = api
        .call("GET", &ip, &Auth::None, None, &[("cookie", &cookie)])
        .await;
    assert_eq!(r.status, StatusCode::OK);
    // The in-person page is never framed.
    assert_eq!(
        frame_ancestors(&page(&api, &ip).await),
        "frame-ancestors 'none'"
    );

    // Five minutes: a link not opened in time opens nothing, and its page is not framed.
    let late = ok(
        api.call(
            "POST",
            &path,
            &host,
            Some(json!({"recipient_id": rid, "frame_origin": HOST})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "late view",
    );
    let late = ceremony_path(late["url"].as_str().unwrap());
    api.clock.advance(std::time::Duration::from_secs(301));
    assert_eq!(
        frame_ancestors(&page(&api, &late).await),
        "frame-ancestors 'none'"
    );
    let r = api
        .call(
            "POST",
            &format!("{late}/session"),
            &Auth::None,
            Some(json!({})),
            &[],
        )
        .await;
    assert_eq!(code(&r), (StatusCode::UNAUTHORIZED, "CS-AUTH-0002".into()));

    // An origin removed from the list no longer frames a view made for it.
    let v = ok(
        api.call(
            "POST",
            &path,
            &host,
            Some(json!({"recipient_id": rid, "frame_origin": "http://localhost:3000"})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "view for localhost",
    );
    let v = ceremony_path(v["url"].as_str().unwrap());
    assert_eq!(
        frame_ancestors(&page(&api, &v).await),
        "frame-ancestors http://localhost:3000"
    );
    assert_eq!(allow(&api, &a, json!([HOST])).await.status, StatusCode::OK);
    assert_eq!(
        frame_ancestors(&page(&api, &v).await),
        "frame-ancestors 'none'"
    );
    api.db.drop().await;
}

#[tokio::test]
async fn prepare_and_correct_views_are_spent_once_and_reach_their_envelope_only() {
    let Some(api) = Api::new("embed_editor_views", Rls::On).await else {
        return;
    };
    webapp(&api);
    let a = api.tenant("alpha").await;
    assert_eq!(allow(&api, &a, json!([HOST])).await.status, StatusCode::OK);
    let (host, host_id) = host_key(&api, &a, "host").await;
    let e = draft(&api, &host, "Prepare me").await;
    let id = e["id"].as_str().unwrap().to_owned();
    let other = draft(&api, &host, "Not this one").await;
    let other = other["id"].as_str().unwrap().to_owned();

    let prepare = format!("/api/v1/envelopes/{id}/views/prepare");
    // A staff session is no API client; a draft cannot be corrected.
    let staff = api.login(&a.email, common::harness::PASSWORD).await;
    let r = api
        .call(
            "POST",
            &prepare,
            &staff,
            Some(json!({"frame_origin": HOST})),
            &[],
        )
        .await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "CS-AUTH-0010".into()));
    let r = api
        .call(
            "POST",
            &format!("/api/v1/envelopes/{id}/views/correct"),
            &host,
            None,
            &[],
        )
        .await;
    assert_eq!(code(&r), (StatusCode::CONFLICT, "CS-WF-0001".into()));
    let r = api
        .call(
            "POST",
            &prepare,
            &host,
            Some(json!({"frame_origin": "https://evil.example"})),
            &[],
        )
        .await;
    assert_eq!(
        code(&r),
        (StatusCode::UNPROCESSABLE_ENTITY, "CS-EMB-0001".into())
    );
    // Another workspace's client sees no such envelope.
    let b = api.tenant("beta").await;
    let r = api.call("POST", &prepare, &b.auth, None, &[]).await;
    assert_eq!(code(&r), (StatusCode::NOT_FOUND, "CS-API-0002".into()));

    let v = ok(
        api.call(
            "POST",
            &prepare,
            &host,
            Some(json!({"frame_origin": HOST, "state": "s-1"})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "prepare view",
    );
    let url = v["url"].as_str().unwrap();
    let link = &url[url.find("/e/").unwrap()..];
    let p = page(&api, link).await;
    assert_eq!(p.status, StatusCode::OK);
    assert!(header(&p, "content-type").starts_with("text/html"));
    assert_eq!(frame_ancestors(&p), format!("frame-ancestors {HOST}"));
    assert_eq!(header(&p, "x-frame-options"), "");

    // Spent once.
    let s = ok(
        api.call(
            "POST",
            &format!("{link}/session"),
            &Auth::None,
            Some(json!({})),
            &[],
        )
        .await,
        StatusCode::OK,
        "view session",
    );
    assert_eq!(s["kind"], "prepare");
    assert_eq!(s["envelope_id"], id.as_str());
    assert_eq!(s["embed"]["state"], "s-1");
    let session = Auth::Bearer(s["session"].as_str().unwrap().to_owned());
    assert!(s["session"].as_str().unwrap().starts_with("osv_"));
    let r = api
        .call(
            "POST",
            &format!("{link}/session"),
            &Auth::None,
            Some(json!({})),
            &[],
        )
        .await;
    assert_eq!(code(&r), (StatusCode::UNAUTHORIZED, "CS-AUTH-0002".into()));
    assert_eq!(
        frame_ancestors(&page(&api, link).await),
        "frame-ancestors 'none'"
    );

    // The session reaches its envelope and its editor's operations, nothing else.
    let env = api
        .call(
            "GET",
            &format!("/api/v1/envelopes/{id}"),
            &session,
            None,
            &[],
        )
        .await;
    assert_eq!(env.status, StatusCode::OK, "{:?}", env.json());
    for (method, path) in [
        ("GET", format!("/api/v1/envelopes/{other}")),
        ("GET", "/api/v1/envelopes".to_owned()),
        ("GET", "/api/v1/accounts/me".to_owned()),
        ("GET", "/api/v1/api-clients".to_owned()),
        ("DELETE", format!("/api/v1/envelopes/{id}")),
        ("POST", format!("/api/v1/envelopes/{id}/void")),
        ("POST", format!("/api/v1/envelopes/{id}/views/prepare")),
        ("GET", format!("/api/v1/envelopes/{id}/audit")),
    ] {
        let body = (method == "POST").then(|| json!({}));
        let r = api.call(method, &path, &session, body, &[]).await;
        assert_eq!(
            code(&r),
            (StatusCode::FORBIDDEN, "CS-EMB-0002".into()),
            "{method} {path}"
        );
    }
    // The editor's own work: name the subject, then send.
    let etag = env.etag();
    let r = api
        .call(
            "PATCH",
            &format!("/api/v1/envelopes/{id}"),
            &session,
            Some(json!({"subject": "Prepared in a frame"})),
            &[("if-match", &etag)],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let etag = r.etag();
    let r = api
        .call(
            "POST",
            &format!("/api/v1/envelopes/{id}/send"),
            &session,
            None,
            &[("if-match", &etag)],
        )
        .await;
    assert!(r.status.is_success(), "{:?} {:?}", r.status, r.json());

    // The correct view of the sent envelope: its own operations only.
    let v = ok(
        api.call(
            "POST",
            &format!("/api/v1/envelopes/{id}/views/correct"),
            &host,
            None,
            &[],
        )
        .await,
        StatusCode::CREATED,
        "correct view",
    );
    let url = v["url"].as_str().unwrap();
    let link = &url[url.find("/e/").unwrap()..];
    // Made for no origin: framed by the workspace's list.
    assert_eq!(
        frame_ancestors(&page(&api, link).await),
        format!("frame-ancestors {HOST}")
    );
    let s = ok(
        api.call(
            "POST",
            &format!("{link}/session"),
            &Auth::None,
            Some(json!({})),
            &[],
        )
        .await,
        StatusCode::OK,
        "correct session",
    );
    assert_eq!(s["kind"], "correct");
    let correct = Auth::Bearer(s["session"].as_str().unwrap().to_owned());
    let r = api
        .call(
            "GET",
            &format!("/api/v1/envelopes/{id}"),
            &correct,
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let r = api
        .call(
            "POST",
            &format!("/api/v1/envelopes/{id}/send"),
            &correct,
            None,
            &[],
        )
        .await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "CS-EMB-0002".into()));

    // A link not opened within five minutes opens nothing.
    let o = ok(
        api.call(
            "POST",
            &format!("/api/v1/envelopes/{other}/views/prepare"),
            &host,
            None,
            &[],
        )
        .await,
        StatusCode::CREATED,
        "late prepare",
    );
    let url = o["url"].as_str().unwrap();
    let late = url[url.find("/e/").unwrap()..].to_owned();
    api.clock.advance(std::time::Duration::from_secs(301));
    let r = api
        .call(
            "POST",
            &format!("{late}/session"),
            &Auth::None,
            Some(json!({})),
            &[],
        )
        .await;
    assert_eq!(code(&r), (StatusCode::UNAUTHORIZED, "CS-AUTH-0002".into()));

    // Revoking the client ends its views' sessions at once.
    let r = api
        .call(
            "DELETE",
            &format!("/api/v1/api-clients/{host_id}"),
            &a.auth,
            None,
            &[],
        )
        .await;
    assert!(r.status.is_success(), "{:?}", r.json());
    let r = api
        .call(
            "GET",
            &format!("/api/v1/envelopes/{id}"),
            &correct,
            None,
            &[],
        )
        .await;
    assert_eq!(code(&r), (StatusCode::UNAUTHORIZED, "CS-AUTH-0002".into()));
    api.db.drop().await;
}
