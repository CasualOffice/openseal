//! Authentication and authorization (SEC-A05, SEC-A06, SEC-A09, SEC-A10, row WF-05):
//! no credential, a wrong account, a revoked key, an expired or revoked token, a
//! session without its CSRF token, a profile without the scope, another API client
//! acting for an embedding it does not own, wrong passwords, and rate limits are all
//! refused, each with its code; and every response carries the security headers.

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

use axum::body::Body;
use axum::http::StatusCode;
use base64::Engine as _;
use casual_sign_server::{Access, table};
use common::Rls;
use common::harness::{Api, Auth, PASSWORD, pdf, session_of};
use serde_json::json;

fn code(r: &common::harness::Resp) -> (StatusCode, String) {
    (r.status, r.code())
}

#[tokio::test]
async fn every_guarded_route_refuses_a_request_without_credentials() {
    let Some(api) = Api::new("auth_no_credentials", Rls::On).await else {
        return;
    };
    let id = uuid::Uuid::now_v7();
    for r in table() {
        if r.access == Access::Public {
            continue;
        }
        let path = r
            .path
            .replace("{id}", &id.to_string())
            .replace("{doc}", &id.to_string())
            .replace("{r}", &id.to_string())
            .replace("{f}", &id.to_string());
        let resp = api.call(r.method, &path, &Auth::None, None, &[]).await;
        assert_eq!(
            code(&resp),
            (StatusCode::UNAUTHORIZED, "CS-AUTH-0001".into()),
            "{} {}",
            r.method,
            r.path
        );
        assert!(resp.headers.contains_key("www-authenticate"));
        assert_eq!(
            resp.headers["content-type"], "application/problem+json",
            "{}",
            r.path
        );
    }
    // A malformed bearer is the same.
    let r = api
        .call(
            "GET",
            "/api/v1/envelopes",
            &Auth::Bearer("osk_nonsense".into()),
            None,
            &[],
        )
        .await;
    assert_eq!(code(&r), (StatusCode::UNAUTHORIZED, "CS-AUTH-0001".into()));
    let r = api
        .call(
            "GET",
            "/api/v1/envelopes",
            &Auth::Bearer("a.b.c".into()),
            None,
            &[],
        )
        .await;
    assert_eq!(code(&r), (StatusCode::UNAUTHORIZED, "CS-AUTH-0001".into()));
    // Unknown routes and wrong methods are problems too, with security headers.
    let r = api
        .call("GET", "/api/v1/nothing", &Auth::None, None, &[])
        .await;
    assert_eq!(code(&r), (StatusCode::NOT_FOUND, "CS-API-0002".into()));
    for h in [
        "content-security-policy",
        "x-content-type-options",
        "referrer-policy",
        "x-frame-options",
        "strict-transport-security",
        "x-request-id",
    ] {
        assert!(r.headers.contains_key(h), "{h}");
    }
    assert!(
        r.headers["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
    assert_eq!(
        r.json()["request_id"],
        r.headers["x-request-id"].to_str().unwrap()
    );
    let r = api
        .call("PUT", "/api/v1/envelopes", &Auth::None, None, &[])
        .await;
    assert_eq!(
        code(&r),
        (StatusCode::METHOD_NOT_ALLOWED, "CS-API-0012".into())
    );
    api.db.drop().await;
}

#[tokio::test]
async fn wrong_accounts_revoked_keys_expired_tokens_and_missing_csrf_are_refused() {
    let Some(api) = Api::new("auth_refusals", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let b = api.tenant("bravo").await;
    let e = api
        .call(
            "POST",
            "/api/v1/envelopes",
            &a.auth,
            Some(json!({"subject": "A's"})),
            &[],
        )
        .await
        .json();
    let path = format!("/api/v1/envelopes/{}", e["id"].as_str().unwrap());
    // Wrong account: B's valid key on A's envelope.
    let r = api.call("GET", &path, &b.auth, None, &[]).await;
    assert_eq!(code(&r), (StatusCode::NOT_FOUND, "CS-API-0002".into()));

    // Revoked key.
    let k = api
        .call(
            "POST",
            "/api/v1/api-clients",
            &a.auth,
            Some(json!({"name": "k", "kind": "api_key", "scopes": ["envelopes:read"]})),
            &[],
        )
        .await
        .json();
    let key = Auth::Bearer(k["key"].as_str().unwrap().to_owned());
    assert!(k["key"].as_str().unwrap().starts_with("osk_"));
    assert_eq!(
        api.call("GET", &path, &key, None, &[]).await.status,
        StatusCode::OK
    );
    // A read-only key cannot write.
    let r = api
        .call("POST", "/api/v1/envelopes", &key, Some(json!({})), &[])
        .await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "CS-AUTH-0006".into()));
    api.call(
        "DELETE",
        &format!("/api/v1/api-clients/{}", k["id"].as_str().unwrap()),
        &a.auth,
        None,
        &[],
    )
    .await;
    let r = api.call("GET", &path, &key, None, &[]).await;
    assert_eq!(code(&r), (StatusCode::UNAUTHORIZED, "CS-AUTH-0001".into()));

    // An expiring key stops at its expiry.
    let k = api
        .call("POST", "/api/v1/api-clients", &a.auth, Some(json!({"name": "k2", "kind": "api_key", "scopes": ["envelopes:read"], "expires_in_days": 1})), &[])
        .await
        .json();
    let short = Auth::Bearer(k["key"].as_str().unwrap().to_owned());
    assert_eq!(
        api.call("GET", &path, &short, None, &[]).await.status,
        StatusCode::OK
    );

    // Access tokens: valid, then expired after an hour; a revoked client's token dies.
    let oc = api
        .call(
            "POST",
            "/api/v1/api-clients",
            &a.auth,
            Some(json!({"name": "o", "kind": "oauth_app", "scopes": ["envelopes:read"]})),
            &[],
        )
        .await
        .json();
    let basic = base64::engine::general_purpose::STANDARD.encode(format!(
        "{}:{}",
        oc["client_id"].as_str().unwrap(),
        oc["client_secret"].as_str().unwrap()
    ));
    let basic_h = format!("Basic {basic}");
    let tok = |scope: Option<&str>| {
        let body = match scope {
            Some(s) => format!("grant_type=client_credentials&scope={s}"),
            None => "grant_type=client_credentials".to_owned(),
        };
        (body, basic_h.clone())
    };
    let (body, h) = tok(Some("envelopes%3Awrite"));
    let r = api
        .send(
            "POST",
            "/api/v1/oauth/token",
            &Auth::None,
            Body::from(body),
            &[
                ("content-type", "application/x-www-form-urlencoded"),
                ("authorization", &h),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.json()["error"], "invalid_scope");
    let (body, h) = tok(None);
    let r = api
        .send(
            "POST",
            "/api/v1/oauth/token",
            &Auth::None,
            Body::from(body),
            &[
                ("content-type", "application/x-www-form-urlencoded"),
                ("authorization", &h),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let access = Auth::Bearer(r.json()["access_token"].as_str().unwrap().to_owned());
    assert_eq!(
        api.call("GET", &path, &access, None, &[]).await.status,
        StatusCode::OK
    );
    // A wrong secret is invalid_client.
    let bad = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD
            .encode(format!("{}:oss_wrong", oc["client_id"].as_str().unwrap()))
    );
    let r = api
        .send(
            "POST",
            "/api/v1/oauth/token",
            &Auth::None,
            Body::from("grant_type=client_credentials"),
            &[
                ("content-type", "application/x-www-form-urlencoded"),
                ("authorization", &bad),
            ],
        )
        .await;
    assert_eq!(
        (r.status, r.json()["error"].as_str().unwrap()),
        (StatusCode::UNAUTHORIZED, "invalid_client")
    );
    // A token is not an API key, nor the reverse.
    let r = api
        .call(
            "GET",
            &path,
            &Auth::Bearer(oc["client_secret"].as_str().unwrap().to_owned()),
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    api.clock.advance(std::time::Duration::from_secs(3601));
    let r = api.call("GET", &path, &access, None, &[]).await;
    assert_eq!(code(&r), (StatusCode::UNAUTHORIZED, "CS-AUTH-0002".into()));
    api.clock.advance(std::time::Duration::from_secs(86_400));
    let r = api.call("GET", &path, &short, None, &[]).await;
    assert_eq!(
        code(&r),
        (StatusCode::UNAUTHORIZED, "CS-AUTH-0001".into()),
        "expired key"
    );
    let (body, h) = tok(None);
    let r = api
        .send(
            "POST",
            "/api/v1/oauth/token",
            &Auth::None,
            Body::from(body),
            &[
                ("content-type", "application/x-www-form-urlencoded"),
                ("authorization", &h),
            ],
        )
        .await;
    let access = Auth::Bearer(r.json()["access_token"].as_str().unwrap().to_owned());
    api.call(
        "DELETE",
        &format!("/api/v1/api-clients/{}", oc["id"].as_str().unwrap()),
        &a.auth,
        None,
        &[],
    )
    .await;
    let r = api.call("GET", &path, &access, None, &[]).await;
    assert_eq!(
        code(&r),
        (StatusCode::UNAUTHORIZED, "CS-AUTH-0002".into()),
        "revoked client's token"
    );

    // Sessions: wrong password; CSRF; a sender profile cannot administer.
    let r = api
        .call(
            "POST",
            "/api/v1/auth/login",
            &Auth::None,
            Some(json!({"email": a.email, "password": "wrong wrong wrong"})),
            &[],
        )
        .await;
    assert_eq!(code(&r), (StatusCode::UNAUTHORIZED, "CS-AUTH-0007".into()));
    let r = api
        .call(
            "POST",
            "/api/v1/auth/login",
            &Auth::None,
            Some(json!({"email": "nobody@example.test", "password": "wrong wrong wrong"})),
            &[],
        )
        .await;
    assert_eq!(code(&r), (StatusCode::UNAUTHORIZED, "CS-AUTH-0007".into()));
    let login = api
        .call(
            "POST",
            "/api/v1/auth/login",
            &Auth::None,
            Some(json!({"email": a.email, "password": PASSWORD})),
            &[],
        )
        .await;
    let set = login.headers["set-cookie"].to_str().unwrap();
    assert!(
        set.contains("HttpOnly") && set.contains("SameSite=Lax") && set.contains("Secure"),
        "{set}"
    );
    let s = session_of(&login);
    api.pass_factor(&a.email, &s).await;
    let Auth::Session { cookie, .. } = &s else {
        unreachable!()
    };
    let no_csrf = Auth::Session {
        cookie: cookie.clone(),
        csrf: "forged".into(),
    };
    assert_eq!(
        api.call("GET", &path, &no_csrf, None, &[]).await.status,
        StatusCode::OK,
        "reads need no CSRF token"
    );
    let r = api
        .call("POST", "/api/v1/envelopes", &no_csrf, Some(json!({})), &[])
        .await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "CS-AUTH-0008".into()));
    assert_eq!(
        api.call("POST", "/api/v1/envelopes", &s, Some(json!({})), &[])
            .await
            .status,
        StatusCode::CREATED
    );
    api.call("POST", "/api/v1/users", &a.auth, Some(json!({"email": "v@alpha.test", "name": "V", "profile": "sender", "password": "sender long passphrase"})), &[]).await;
    let vl = api
        .call(
            "POST",
            "/api/v1/auth/login",
            &Auth::None,
            Some(json!({"email": "v@alpha.test", "password": "sender long passphrase"})),
            &[],
        )
        .await;
    let v = session_of(&vl);
    let r = api.call("GET", "/api/v1/users", &v, None, &[]).await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "CS-AUTH-0006".into()));
    // A sender does not see another member's envelope.
    let r = api.call("GET", &path, &v, None, &[]).await;
    assert_eq!(code(&r), (StatusCode::NOT_FOUND, "CS-API-0002".into()));
    // A sender cannot mint a key with scopes it lacks.
    let r = api
        .call(
            "POST",
            "/api/v1/api-clients",
            &v,
            Some(json!({"name": "x", "kind": "api_key", "scopes": ["admin:users"]})),
            &[],
        )
        .await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "CS-AUTH-0006".into()));
    api.db.drop().await;
}

#[tokio::test]
async fn only_the_creating_client_opens_an_embedded_signing_view() {
    let Some(api) = Api::new("auth_embedding_owner", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let mk = |name: &str| json!({"name": name, "kind": "api_key", "scopes": ["envelopes:read", "envelopes:write", "envelopes:send"]});
    let k1 = api
        .call(
            "POST",
            "/api/v1/api-clients",
            &a.auth,
            Some(mk("host 1")),
            &[],
        )
        .await
        .json();
    let k2 = api
        .call(
            "POST",
            "/api/v1/api-clients",
            &a.auth,
            Some(mk("host 2")),
            &[],
        )
        .await
        .json();
    let h1 = Auth::Bearer(k1["key"].as_str().unwrap().to_owned());
    let h2 = Auth::Bearer(k2["key"].as_str().unwrap().to_owned());
    let e = api
        .call("POST", "/api/v1/envelopes", &h1, Some(json!({
            "subject": "E", "status": "sent",
            "documents": [{"name": "e.pdf", "content_base64": base64::engine::general_purpose::STANDARD.encode(pdf(1))}],
            "recipients": [{"type": "signer", "name": "Em", "email": "em@example.test", "embedded_client_user_id": "u1"}],
        })), &[])
        .await
        .json();
    let id = e["id"].as_str().unwrap();
    let r_id = e["recipients"][0]["id"].as_str().unwrap();
    let body = json!({"recipient_id": r_id, "auth_asserted": "host SSO"});
    let path = format!("/api/v1/envelopes/{id}/views/signing");
    let audit = format!("/api/v1/envelopes/{id}/audit");
    let trail = || async {
        {
            let r = api.call("GET", &audit, &a.auth, None, &[]).await;
            assert_eq!(r.status, StatusCode::OK);
            r.json()["items"].as_array().unwrap().len()
        }
    };
    let before = trail().await;
    // Another client of the same account, and a staff key that is no client of it.
    let r = api.call("POST", &path, &h2, Some(body.clone()), &[]).await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "CS-AUTH-0010".into()));
    let r = api
        .call("POST", &path, &a.auth, Some(body.clone()), &[])
        .await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "CS-AUTH-0010".into()));
    // An API client of another account, holding the same scopes, is refused as for an
    // envelope that does not exist (WF-05): no view, no host opening, no assertion.
    let b = api.tenant("beta").await;
    let kb = api
        .call(
            "POST",
            "/api/v1/api-clients",
            &b.auth,
            Some(mk("other host")),
            &[],
        )
        .await
        .json();
    let hb = Auth::Bearer(kb["key"].as_str().unwrap().to_owned());
    let r = api.call("POST", &path, &hb, Some(body.clone()), &[]).await;
    assert_eq!(code(&r), (StatusCode::NOT_FOUND, "CS-API-0002".into()));
    // None of the refused requests recorded anything on the envelope.
    assert_eq!(trail().await, before, "a refused host wrote to the trail");
    let r = api.call("POST", &path, &h1, Some(body), &[]).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.json());
    // The view link lives five minutes.
    let url = r.json()["url"].as_str().unwrap().to_owned();
    let p = &url[url.find("/s/").unwrap()..];
    api.clock.advance(std::time::Duration::from_secs(301));
    let late = api
        .call(
            "POST",
            &format!("{p}/session"),
            &Auth::None,
            Some(json!({})),
            &[],
        )
        .await;
    assert_eq!(
        code(&late),
        (StatusCode::UNAUTHORIZED, "CS-AUTH-0002".into())
    );
    api.db.drop().await;
}

#[tokio::test]
async fn rate_limits_answer_429_with_retry_after() {
    let Some(api) = Api::with("auth_rate_limits", Rls::On, |c| {
        // Four: the tenant's session enrols its administrator's factor (ASVS-31) and
        // makes the key in four calls.
        c.rate.api_per_minute = 4;
        c.rate.login_per_minute = 2;
    })
    .await
    else {
        return;
    };
    let a = api.tenant("alpha").await;
    let mut last = None;
    for _ in 0..5 {
        last = Some(
            api.call("GET", "/api/v1/accounts/me", &a.auth, None, &[])
                .await,
        );
    }
    let r = last.unwrap();
    assert_eq!(
        code(&r),
        (StatusCode::TOO_MANY_REQUESTS, "CS-API-0003".into())
    );
    assert!(r.headers.contains_key("retry-after"));
    assert!(
        r.headers["ratelimit-policy"]
            .to_str()
            .unwrap()
            .contains("q=4")
    );
    // Login attempts per name: the tenant's own login used one.
    for _ in 0..2 {
        api.call(
            "POST",
            "/api/v1/auth/login",
            &Auth::None,
            Some(json!({"email": a.email, "password": "x"})),
            &[],
        )
        .await;
    }
    let r = api
        .call(
            "POST",
            "/api/v1/auth/login",
            &Auth::None,
            Some(json!({"email": a.email, "password": PASSWORD})),
            &[],
        )
        .await;
    assert_eq!(
        code(&r),
        (StatusCode::TOO_MANY_REQUESTS, "CS-API-0003".into())
    );
    api.clock.advance(std::time::Duration::from_secs(61));
    let r = api
        .call("GET", "/api/v1/accounts/me", &a.auth, None, &[])
        .await;
    assert_eq!(r.status, StatusCode::OK);
    api.db.drop().await;
}
