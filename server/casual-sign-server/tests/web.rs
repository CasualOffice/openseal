//! Row WEB-04's contract: the web app served at `/` with its own Content Security
//! Policy and nothing outside it, the signing page at `/s/{token}` for a browser while
//! the API keeps answering JSON there; the `q` search of `GET /envelopes`, inside one
//! account only (row-level security on and off); and the access code patchable on a
//! recipient while the envelope is a draft or being corrected, refused once voided; and
//! a draft's recipient changing type through `PATCH` (row UX-12).

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
use base64::Engine as _;
use casual_sign_server::web::{PAGE_CSP, WebApp};
use common::Rls;
use common::harness::{Api, Auth, Tenant, ceremony_cookie, pdf};
use serde_json::{Value, json};

fn webapp_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../webapp")
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn header<'a>(r: &'a common::harness::Resp, name: &str) -> &'a str {
    r.headers.get(name).map_or("", |v| v.to_str().unwrap_or(""))
}

async fn get(api: &Api, path: &str, accept: &str) -> common::harness::Resp {
    api.send(
        "GET",
        path,
        &Auth::None,
        Body::empty(),
        &[("accept", accept)],
    )
    .await
}

const BROWSER: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

#[test]
fn the_webapp_folder_loads_without_its_tests() {
    let w = WebApp::load(&webapp_dir()).unwrap();
    assert!(w.len() > 50, "{} files", w.len());
    // Any other folder is not the web app.
    assert!(WebApp::load(&webapp_dir().join("vendor")).is_err());
}

#[tokio::test]
async fn the_webapp_is_served_at_the_root_and_the_signing_page_at_a_link() {
    let Some(api) = Api::new("web_static", Rls::On).await else {
        return;
    };
    // Before a web app is configured, the root is the API's 404.
    let none = get(&api, "/", BROWSER).await;
    assert_eq!(none.status, StatusCode::NOT_FOUND);
    api.st.set_webapp(WebApp::load(&webapp_dir()).unwrap());

    let index = get(&api, "/", BROWSER).await;
    assert_eq!(index.status, StatusCode::OK);
    assert_eq!(header(&index, "content-type"), "text/html; charset=utf-8");
    assert_eq!(header(&index, "content-security-policy"), PAGE_CSP);
    assert!(header(&index, "permissions-policy").contains("geolocation=(self)"));
    assert_eq!(header(&index, "x-content-type-options"), "nosniff");
    assert!(String::from_utf8_lossy(&index.body).contains("<!doctype html>"));

    let app = get(&api, "/app.html", BROWSER).await;
    assert_eq!(app.status, StatusCode::OK);
    assert_eq!(header(&app, "cache-control"), "no-cache");

    let js = get(&api, "/api.js", "*/*").await;
    assert_eq!(js.status, StatusCode::OK);
    assert_eq!(
        header(&js, "content-type"),
        "text/javascript; charset=utf-8"
    );
    assert_eq!(header(&js, "cache-control"), "no-cache");
    // Not a page: the API's strict policy, no location.
    assert!(header(&js, "content-security-policy").starts_with("default-src 'none'"));

    let css = get(&api, "/tokens.css", "text/css").await;
    assert_eq!(header(&css, "content-type"), "text/css; charset=utf-8");
    let svg = get(&api, "/assets/mark.svg", "image/*").await;
    assert_eq!(header(&svg, "content-type"), "image/svg+xml");
    let worker = get(&api, "/vendor/pdfjs/pdf.worker.min.mjs", "*/*").await;
    assert_eq!(worker.status, StatusCode::OK);
    assert_eq!(
        header(&worker, "content-type"),
        "text/javascript; charset=utf-8"
    );
    assert_eq!(
        header(&worker, "cache-control"),
        "public, max-age=31536000, immutable"
    );
    let font = get(&api, "/fonts/script/Allura-Regular.ttf", "*/*").await;
    assert_eq!(header(&font, "content-type"), "font/ttf");

    // Nothing outside the web app's own files: tests, manifests, tools, other folders.
    for path in [
        "/e2e/helpers.mjs",
        "/tests/pure.test.mjs",
        "/package.json",
        "/vendor/lucide/build.py",
        "/../Cargo.toml",
        "/%2e%2e/Cargo.toml",
        "/vendor/pdfjs/LICENSE",
        "/nope.js",
    ] {
        let r = get(&api, path, "*/*").await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(
            header(&r, "content-type"),
            "application/problem+json",
            "{path}"
        );
    }
    // Only reads.
    let post = api
        .send("POST", "/app.js", &Auth::None, Body::empty(), &[])
        .await;
    assert_eq!(post.status, StatusCode::NOT_FOUND);

    // A signing link: the page for a browser, whatever the token (it checks nothing);
    // JSON for the web app's own call, which checks the token.
    let page = get(&api, "/s/no-such-token", BROWSER).await;
    assert_eq!(page.status, StatusCode::OK);
    assert_eq!(header(&page, "content-type"), "text/html; charset=utf-8");
    assert_eq!(header(&page, "cache-control"), "no-store");
    assert_eq!(header(&page, "content-security-policy"), PAGE_CSP);
    assert!(String::from_utf8_lossy(&page.body).contains("/sign.js"));
    let json = get(&api, "/s/no-such-token", "application/json").await;
    assert_eq!(json.status, StatusCode::UNAUTHORIZED);
    assert_eq!(header(&json, "content-type"), "application/problem+json");
}

async fn draft(api: &Api, t: &Tenant, subject: &str, people: &[(&str, &str)]) -> String {
    let recipients: Vec<Value> = people
        .iter()
        .enumerate()
        .map(|(i, (name, email))| {
            json!({"ref": format!("r{i}"), "type": "signer", "name": name, "email": email,
                   "routing_order": 1})
        })
        .collect();
    let fields: Vec<Value> = (0..people.len())
        .map(|i| {
            json!({"recipient": format!("r{i}"), "document": 0, "type": "signature", "page": 1,
                   "x": 72, "y": 600, "width": 180, "height": 40, "required": true})
        })
        .collect();
    let r = api
        .call(
            "POST",
            "/api/v1/envelopes",
            &t.auth,
            Some(json!({
                "subject": subject,
                "documents": [{"name": "c.pdf", "content_base64": b64(&pdf(1))}],
                "recipients": recipients,
                "fields": fields,
            })),
            &[],
        )
        .await;
    assert_eq!(
        r.status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&r.body)
    );
    r.json()["id"].as_str().unwrap().to_owned()
}

async fn search(api: &Api, t: &Tenant, q: &str) -> Vec<String> {
    let path = format!(
        "/api/v1/envelopes?q={}",
        q.bytes().map(|b| format!("%{b:02X}")).collect::<String>()
    );
    let r = api.call("GET", &path, &t.auth, None, &[]).await;
    assert_eq!(
        r.status,
        StatusCode::OK,
        "{q}: {}",
        String::from_utf8_lossy(&r.body)
    );
    let mut ids: Vec<String> = r.json()["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["id"].as_str().unwrap().to_owned())
        .collect();
    ids.sort();
    ids
}

async fn search_inside_one_account(rls: Rls) {
    let Some(api) = Api::new("web_search", rls).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let b = api.tenant("bravo").await;
    let lease = draft(
        &api,
        &a,
        "Lease for unit 42",
        &[("Zora Quill", "zora@tenant.example")],
    )
    .await;
    let nda = draft(
        &api,
        &a,
        "Mutual NDA",
        &[("Abe Lincoln", "abe@vendor.example")],
    )
    .await;
    let odd = draft(
        &api,
        &a,
        "100% discount_offer",
        &[("Cy Doe", "cy@vendor.example")],
    )
    .await;
    // Bravo's envelope names nobody of Alpha's.
    let theirs = draft(
        &api,
        &b,
        "Bravo purchase",
        &[("Bo Bravo", "bo@bravo.example")],
    )
    .await;

    let one = |id: &String| vec![id.clone()];
    let mut all = vec![lease.clone(), nda.clone(), odd.clone()];
    all.sort();
    assert_eq!(
        search(&api, &a, "lease").await,
        one(&lease),
        "subject, any case"
    );
    assert_eq!(
        search(&api, &a, "ZORA").await,
        one(&lease),
        "recipient name"
    );
    assert_eq!(
        search(&api, &a, "abe@vendor").await,
        one(&nda),
        "recipient email"
    );
    assert_eq!(search(&api, &a, "vendor.example").await.len(), 2);
    assert_eq!(search(&api, &a, "  ").await, all, "blank is no filter");
    // LIKE's wildcards are matched as themselves.
    assert_eq!(search(&api, &a, "%").await, one(&odd));
    assert_eq!(search(&api, &a, "d_scount").await, Vec::<String>::new());
    assert_eq!(search(&api, &a, "0%%").await, Vec::<String>::new());
    assert_eq!(search(&api, &a, "discount_").await, one(&odd));
    assert_eq!(search(&api, &a, "\\").await, Vec::<String>::new());
    // Another account's envelopes and recipients are never matched, nor listed.
    assert_eq!(search(&api, &b, "zora").await, Vec::<String>::new());
    assert_eq!(search(&api, &b, "lease").await, Vec::<String>::new());
    assert_eq!(search(&api, &b, "example").await, one(&theirs));
    assert_eq!(search(&api, &a, "bravo").await, Vec::<String>::new());
    // Bounded.
    let long = api
        .call(
            "GET",
            &format!("/api/v1/envelopes?q={}", "x".repeat(201)),
            &a.auth,
            None,
            &[],
        )
        .await;
    assert_eq!(
        long.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{:?}",
        long.json()
    );
}

#[tokio::test]
async fn search_matches_subject_and_recipients_inside_one_account_rls_on() {
    search_inside_one_account(Rls::On).await;
}

#[tokio::test]
async fn search_matches_subject_and_recipients_inside_one_account_rls_off() {
    search_inside_one_account(Rls::Off).await;
}

async fn stored_codes(api: &Api, recipient: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM recipient_auth_requirements \
         WHERE recipient_id = $1::uuid AND kind = 'access_code'",
    )
    .bind(recipient)
    .fetch_one(&api.db.admin)
    .await
    .unwrap()
}

#[tokio::test]
async fn an_access_code_is_patchable_on_a_draft_and_in_a_correction_and_refused_once_voided() {
    let Some(api) = Api::new("web_access_code", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let id = draft(&api, &a, "Code later", &[("Ana Code", "ana@example.test")]).await;
    let base = format!("/api/v1/envelopes/{id}");
    let env = api.call("GET", &base, &a.auth, None, &[]).await;
    let rec = env.json()["recipients"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let path = format!("{base}/recipients/{rec}");
    let mut etag = env.etag();
    let patch = |body: Value, etag: String| {
        let api = &api;
        let path = path.clone();
        let auth = a.auth.clone();
        async move {
            api.call("PATCH", &path, &auth, Some(body), &[("if-match", &etag)])
                .await
        }
    };

    // The method needs a code; a code needs the method.
    let r = patch(json!({"auth": ["access_code"]}), etag.clone()).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{:?}", r.json());
    let r = patch(json!({"access_code": "1234"}), etag.clone()).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{:?}", r.json());
    assert_eq!(stored_codes(&api, &rec).await, 0);

    // Both: stored as Argon2id, never returned.
    let r = patch(
        json!({"auth": ["access_code"], "access_code": "first-1111"}),
        etag.clone(),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    assert!(!String::from_utf8_lossy(&r.body).contains("first-1111"));
    assert_eq!(r.json()["auth"], json!(["access_code"]));
    etag = r.etag();
    assert_eq!(stored_codes(&api, &rec).await, 1);
    // Dropping the method deletes the code; adding it again needs a new one.
    let r = patch(json!({"auth": []}), etag.clone()).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    etag = r.etag();
    assert_eq!(stored_codes(&api, &rec).await, 0);
    let r = patch(
        json!({"auth": ["access_code"], "access_code": "first-1111"}),
        etag.clone(),
    )
    .await;
    etag = r.etag();
    // A new code alone replaces the old.
    let r = patch(json!({"access_code": "second-2222"}), etag.clone()).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    etag = r.etag();
    assert_eq!(stored_codes(&api, &rec).await, 1);
    let hash_before: String = sqlx::query_scalar(
        "SELECT access_code_hash FROM recipient_auth_requirements WHERE recipient_id = $1::uuid",
    )
    .bind(&rec)
    .fetch_one(&api.db.admin)
    .await
    .unwrap();
    assert!(hash_before.starts_with("$argon2id$"));

    // Sent: a correction may still change it (as every recipient detail).
    let sent = api
        .call("POST", &format!("{base}/send"), &a.auth, None, &[])
        .await;
    assert_eq!(
        sent.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&sent.body)
    );
    let now = api.call("GET", &base, &a.auth, None, &[]).await.etag();
    let r = patch(json!({"access_code": "third-3333"}), now).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let third: String = sqlx::query_scalar(
        "SELECT access_code_hash FROM recipient_auth_requirements WHERE recipient_id = $1::uuid",
    )
    .bind(&rec)
    .fetch_one(&api.db.admin)
    .await
    .unwrap();
    assert_ne!(hash_before, third);
    let _ = etag;

    // The signer's link takes the patched code, not the earlier one.
    let token = casual_sign_server::issue_invitation_token(
        &api.st,
        a.boot.account,
        casual_sign_store::EnvelopeId(id.parse().unwrap()),
        casual_sign_store::RecipientId(rec.parse().unwrap()),
        std::time::Duration::from_secs(86_400),
    )
    .await
    .unwrap();
    let s = format!("/s/{token}");
    let open = api
        .call(
            "POST",
            &format!("{s}/session"),
            &Auth::None,
            Some(json!({})),
            &[],
        )
        .await;
    assert_eq!(open.status, StatusCode::OK, "{:?}", open.json());
    let cookie = ceremony_cookie(&open);
    let h = [("cookie", cookie.as_str())];
    let auth = |code: &'static str| {
        let api = &api;
        let path = format!("{s}/authenticate");
        async move {
            api.call(
                "POST",
                &path,
                &Auth::None,
                Some(json!({"method": "access_code", "code": code})),
                &h,
            )
            .await
            .status
        }
    };
    assert_eq!(auth("second-2222").await, StatusCode::FORBIDDEN);
    assert_eq!(auth("third-3333").await, StatusCode::OK);

    // Voided: nothing changes any more, and the code stays as it was.
    let voided = api
        .call(
            "POST",
            &format!("{base}/void"),
            &a.auth,
            Some(json!({"reason": "test"})),
            &[],
        )
        .await;
    assert_eq!(
        voided.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&voided.body)
    );
    let now = api.call("GET", &base, &a.auth, None, &[]).await.etag();
    let r = patch(json!({"access_code": "fourth-4444"}), now).await;
    assert!(r.status.is_client_error(), "{:?}", r.json());
    let after: String = sqlx::query_scalar(
        "SELECT access_code_hash FROM recipient_auth_requirements WHERE recipient_id = $1::uuid",
    )
    .bind(&rec)
    .fetch_one(&api.db.admin)
    .await
    .unwrap();
    assert_eq!(third, after);
}

/// The ceremony cookie follows `secure_cookies` as the staff session does: `Secure`
/// unless the operator turned it off for plain-HTTP development, where a browser that
/// refuses `Secure` cookies over `http://localhost` (WebKit) could not keep the link
/// bound and every later call would be `CS-AUTH-0009`.
#[tokio::test]
async fn the_ceremony_cookie_is_secure_unless_the_server_is_plain_http_development() {
    for secure in [true, false] {
        let Some(api) = Api::with("web_ceremony_cookie", Rls::On, |c| {
            c.secure_cookies = secure
        })
        .await
        else {
            return;
        };
        let a = api.tenant("alpha").await;
        let id = draft(&api, &a, "Cookie", &[("Cy Cookie", "cy@example.test")]).await;
        let base = format!("/api/v1/envelopes/{id}");
        let sent = api
            .call("POST", &format!("{base}/send"), &a.auth, None, &[])
            .await;
        assert_eq!(sent.status, StatusCode::OK);
        let env = api.call("GET", &base, &a.auth, None, &[]).await.json();
        let rec = env["recipients"][0]["id"].as_str().unwrap().to_owned();
        let token = casual_sign_server::issue_invitation_token(
            &api.st,
            a.boot.account,
            casual_sign_store::EnvelopeId(id.parse().unwrap()),
            casual_sign_store::RecipientId(rec.parse().unwrap()),
            std::time::Duration::from_secs(86_400),
        )
        .await
        .unwrap();
        let open = api
            .call(
                "POST",
                &format!("/s/{token}/session"),
                &Auth::None,
                Some(json!({})),
                &[],
            )
            .await;
        assert_eq!(open.status, StatusCode::OK);
        let set = header(&open, "set-cookie");
        assert!(
            set.contains("HttpOnly") && set.contains("SameSite=Strict"),
            "{set}"
        );
        assert_eq!(set.contains("Secure"), secure, "{set}");
    }
}

/// Row UX-12: a draft's saved recipient changes type through `PATCH`, and the change
/// is stored (read back after a fresh `GET`); a correction may not change it.
#[tokio::test]
async fn a_drafts_recipient_changes_type_through_patch_and_a_correction_refuses_it() {
    let Some(api) = Api::new("web_recipient_type", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let id = draft(&api, &a, "Type later", &[("Ana Type", "ana@example.test")]).await;
    let base = format!("/api/v1/envelopes/{id}");
    let env = api.call("GET", &base, &a.auth, None, &[]).await;
    let rec = env.json()["recipients"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(env.json()["recipients"][0]["type"], "signer");
    let path = format!("{base}/recipients/{rec}");

    let r = api
        .call(
            "PATCH",
            &path,
            &a.auth,
            Some(json!({"type": "approver"})),
            &[("if-match", &env.etag())],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    assert_eq!(r.json()["type"], "approver");
    let back = api.call("GET", &base, &a.auth, None, &[]).await;
    assert_eq!(back.json()["recipients"][0]["type"], "approver");
    assert_eq!(back.json()["recipients"][0]["id"], rec.as_str());

    // Back to a signer, then sent: a correction keeps the type.
    let r = api
        .call(
            "PATCH",
            &path,
            &a.auth,
            Some(json!({"type": "signer"})),
            &[("if-match", &back.etag())],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let sent = api
        .call("POST", &format!("{base}/send"), &a.auth, None, &[])
        .await;
    assert_eq!(
        sent.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&sent.body)
    );
    let now = api.call("GET", &base, &a.auth, None, &[]).await.etag();
    let r = api
        .call(
            "PATCH",
            &path,
            &a.auth,
            Some(json!({"type": "approver"})),
            &[("if-match", &now)],
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.json());
    let after = api.call("GET", &base, &a.auth, None, &[]).await;
    assert_eq!(after.json()["recipients"][0]["type"], "signer");
}
