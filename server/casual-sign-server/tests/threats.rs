//! Threat controls of docs/07 (`SEC-A*`, row P2-THREATS) that no other test pinned:
//! every scoped route refuses a credential lacking exactly its scope (SEC-A05); every
//! kind of response carries the security headers (SEC-A06); request bodies over a
//! route's limit are refused (SEC-A06, docs/21 §API); an access code locks after the
//! account's attempts, revoking the link, so
//! even the right code then fails (SEC-A03); the ceremony is rate-limited
//! per token and per client address (SEC-A01, SEC-A02); a voided envelope's link
//! opens nothing (SEC-A01); and API keys and signing links are stored only as hashes
//! (SEC-A01, SEC-A10).

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
use casual_sign_server::{Access, SCOPES, table};
use common::Rls;
use common::flow::{invite, ok, open, sent};
use common::harness::{Api, Auth, Resp, session_of};
use serde_json::json;
use sqlx::Row;

fn code(r: &Resp) -> (StatusCode, String) {
    (r.status, r.code())
}

/// Fill a route template with one id everywhere.
fn concrete(path: &str, id: &str) -> String {
    path.replace("{id}", id)
        .replace("{doc}", id)
        .replace("{r}", id)
        .replace("{f}", id)
        .replace("{n}", "1")
}

#[tokio::test]
async fn every_scoped_route_refuses_a_credential_lacking_exactly_its_scope() {
    let Some(api) = Api::new("threat_scopes", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    // One key per scope, holding every other scope.
    let mut without = std::collections::BTreeMap::new();
    for s in SCOPES {
        let others: Vec<&str> = SCOPES.iter().copied().filter(|o| *o != s).collect();
        let k = ok(
            api.call(
                "POST",
                "/api/v1/api-clients",
                &a.auth,
                Some(json!({"name": format!("all but {s}"), "kind": "api_key", "scopes": others})),
                &[],
            )
            .await,
            StatusCode::CREATED,
            "key",
        );
        without.insert(s, Auth::Bearer(k["key"].as_str().unwrap().to_owned()));
    }
    let id = uuid::Uuid::now_v7().to_string();
    let mut checked = 0;
    for r in table() {
        let Access::Scope(scope) = r.access else {
            continue;
        };
        if scope.is_empty() {
            continue;
        }
        let key = without
            .get(scope)
            .unwrap_or_else(|| panic!("{scope} is not in SCOPES"));
        let body = (r.method != "GET" && r.method != "DELETE").then(|| json!({}));
        let resp = api
            .call(r.method, &concrete(r.path, &id), key, body, &[])
            .await;
        assert_eq!(
            code(&resp),
            (StatusCode::FORBIDDEN, "CS-AUTH-0006".into()),
            "{} {} needs {scope}",
            r.method,
            r.path
        );
        checked += 1;
    }
    assert!(checked >= 60, "only {checked} scoped routes");
    api.db.drop().await;
}

/// The headers docs/40 As built promises on every response.
fn assert_security_headers(r: &Resp, what: &str) {
    let h = |n: &str| {
        r.headers
            .get(n)
            .unwrap_or_else(|| panic!("{what}: no {n}"))
            .to_str()
            .unwrap()
            .to_owned()
    };
    assert!(
        h("content-security-policy").contains("frame-ancestors 'none'"),
        "{what}"
    );
    assert!(
        h("content-security-policy").contains("default-src 'none'"),
        "{what}"
    );
    assert_eq!(h("x-content-type-options"), "nosniff", "{what}");
    assert_eq!(h("referrer-policy"), "no-referrer", "{what}");
    assert_eq!(h("x-frame-options"), "DENY", "{what}");
    assert!(
        h("strict-transport-security").starts_with("max-age="),
        "{what}"
    );
    assert_eq!(h("cache-control"), "no-store", "{what}");
    assert!(!h("x-request-id").is_empty(), "{what}");
}

#[tokio::test]
async fn every_kind_of_response_carries_the_security_headers_and_bodies_are_bounded() {
    let Some(api) = Api::with("threat_headers", Rls::On, |c| {
        c.rate.ceremony_per_minute = 2;
    })
    .await
    else {
        return;
    };
    let a = api.tenant("alpha").await;
    let mut seen = Vec::new();
    let r = api
        .call("GET", "/api/v1/accounts/me", &a.auth, None, &[])
        .await;
    assert_eq!(r.status, StatusCode::OK);
    seen.push((r, "200 JSON"));
    let r = api
        .call(
            "POST",
            "/api/v1/envelopes",
            &a.auth,
            Some(json!({"subject": "h"})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED);
    seen.push((r, "201"));
    let login = api
        .call(
            "POST",
            "/api/v1/auth/login",
            &Auth::None,
            Some(json!({"email": a.email, "password": common::harness::PASSWORD})),
            &[],
        )
        .await;
    assert_eq!(login.status, StatusCode::OK);
    let Auth::Session { cookie, .. } = session_of(&login) else {
        unreachable!()
    };
    seen.push((login, "login with a cookie"));
    let r = api
        .call(
            "POST",
            "/api/v1/envelopes",
            &Auth::Session {
                cookie,
                csrf: "forged".into(),
            },
            Some(json!({})),
            &[],
        )
        .await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "CS-AUTH-0008".into()));
    seen.push((r, "403 CSRF"));
    let r = api
        .call("GET", "/api/v1/envelopes", &Auth::None, None, &[])
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    seen.push((r, "401"));
    let r = api
        .call("GET", "/api/v1/nothing", &Auth::None, None, &[])
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    seen.push((r, "404"));
    let r = api
        .call("PUT", "/api/v1/envelopes", &a.auth, None, &[])
        .await;
    assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED);
    seen.push((r, "405"));
    // A body over the route's limit (1 MiB for JSON routes) is refused unread.
    let big = vec![b' '; 1024 * 1024 + 1];
    let r = api
        .send(
            "POST",
            "/api/v1/auth/login",
            &Auth::None,
            Body::from(big),
            &[("content-type", "application/json")],
        )
        .await;
    assert_eq!(
        code(&r),
        (StatusCode::PAYLOAD_TOO_LARGE, "CS-API-0006".into())
    );
    seen.push((r, "413"));
    // Ceremony: a link no one issued, a wrong media type, the rate limit.
    let r = api
        .call("GET", "/s/no-such-token", &Auth::None, None, &[])
        .await;
    assert_eq!(code(&r), (StatusCode::UNAUTHORIZED, "CS-AUTH-0002".into()));
    seen.push((r, "ceremony 401"));
    let r = api
        .send(
            "POST",
            "/s/no-such-token/consent",
            &Auth::None,
            Body::from("x"),
            &[("content-type", "text/plain")],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    seen.push((r, "ceremony 415"));
    let r = api
        .call("GET", "/s/no-such-token", &Auth::None, None, &[])
        .await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    seen.push((r, "ceremony 429"));
    for (r, what) in &seen {
        assert_security_headers(r, what);
    }
    api.db.drop().await;
}

#[tokio::test]
async fn ceremony_calls_are_limited_per_link_and_per_client_address() {
    let Some(api) = Api::with("threat_ceremony_rate", Rls::On, |c| {
        c.rate.ceremony_per_minute = 3;
    })
    .await
    else {
        return;
    };
    // Per link: the fourth call on one token in a minute is refused.
    for _ in 0..3 {
        let r = api.call("GET", "/s/guess-1", &Auth::None, None, &[]).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    let r = api.call("GET", "/s/guess-1", &Auth::None, None, &[]).await;
    assert_eq!(
        code(&r),
        (StatusCode::TOO_MANY_REQUESTS, "CS-API-0003".into())
    );
    assert!(r.headers.contains_key("retry-after"));
    // Per address: guessing many links from one address stops at four times the rate.
    let mut refused = 0;
    for n in 0..12 {
        let r = api
            .call("GET", &format!("/s/guess-n{n}"), &Auth::None, None, &[])
            .await;
        if r.status == StatusCode::TOO_MANY_REQUESTS {
            refused += 1;
        }
    }
    assert!(
        refused >= 3,
        "an address guessing links is limited ({refused})"
    );
    // Another address is not.
    api.set_peer("203.0.113.9:40000");
    let r = api.call("GET", "/s/guess-x", &Auth::None, None, &[]).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    api.db.drop().await;
}

#[tokio::test]
async fn an_access_code_locks_after_the_accounts_attempts_even_for_the_right_code() {
    let Some(api) = Api::new("threat_access_code_lock", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let e = sent(&api, &a, 1, &[]).await;
    let env = e["id"].as_str().unwrap().to_owned();
    let rec = e["recipients"][0]["id"].as_str().unwrap().to_owned();
    let base = format!("/api/v1/envelopes/{env}");
    let etag = api.call("GET", &base, &a.auth, None, &[]).await.etag();
    let r = api
        .call(
            "PATCH",
            &format!("{base}/recipients/{rec}"),
            &a.auth,
            Some(json!({"auth": ["access_code"], "access_code": "right-4711"})),
            &[("if-match", &etag)],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let token = invite(&api, &a, &env, &rec).await;
    let (_, h) = open(&api, &token).await;
    let h: Vec<(&str, &str)> = h.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let try_code = |c: &'static str| {
        let api = &api;
        let path = format!("/s/{token}/authenticate");
        let h = h.clone();
        async move {
            api.call(
                "POST",
                &path,
                &Auth::None,
                Some(json!({"method": "access_code", "code": c})),
                &h,
            )
            .await
        }
    };
    // The account's default is three attempts (docs/24).
    for _ in 0..3 {
        let r = try_code("wrong-0000").await;
        assert_eq!(r.status, StatusCode::FORBIDDEN);
    }
    let r = try_code("right-4711").await;
    assert_eq!(
        code(&r),
        (StatusCode::UNAUTHORIZED, "CS-AUTH-0002".into()),
        "the right code after the lock: the lock revoked the link"
    );
    let failed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE envelope_id = $1::uuid \
         AND event_type = 'recipient.auth_failed'",
    )
    .bind(&env)
    .fetch_one(&api.db.admin)
    .await
    .unwrap();
    assert_eq!(failed, 3, "every failure is evidence");
    api.db.drop().await;
}

#[tokio::test]
async fn a_voided_envelopes_link_opens_nothing() {
    let Some(api) = Api::new("threat_void_link", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let e = sent(&api, &a, 1, &[]).await;
    let env = e["id"].as_str().unwrap().to_owned();
    let rec = e["recipients"][0]["id"].as_str().unwrap().to_owned();
    let token = invite(&api, &a, &env, &rec).await;
    let (_, h) = open(&api, &token).await;
    let h: Vec<(&str, &str)> = h.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let etag = api
        .call(
            "GET",
            &format!("/api/v1/envelopes/{env}"),
            &a.auth,
            None,
            &[],
        )
        .await
        .etag();
    let r = api
        .call(
            "POST",
            &format!("/api/v1/envelopes/{env}/void"),
            &a.auth,
            Some(json!({"reason": "threat test"})),
            &[("if-match", &etag)],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let r = api
        .call("GET", &format!("/s/{token}"), &Auth::None, None, &h)
        .await;
    assert_eq!(code(&r), (StatusCode::UNAUTHORIZED, "CS-AUTH-0002".into()));
    api.db.drop().await;
}

#[tokio::test]
async fn keys_secrets_and_signing_links_are_stored_only_as_hashes() {
    let Some(api) = Api::new("threat_hashed_secrets", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let oc = ok(
        api.call(
            "POST",
            "/api/v1/api-clients",
            &a.auth,
            Some(json!({"name": "o", "kind": "oauth_app", "scopes": ["envelopes:read"]})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "oauth client",
    );
    let e = sent(&api, &a, 1, &[]).await;
    let env = e["id"].as_str().unwrap().to_owned();
    let rec = e["recipients"][0]["id"].as_str().unwrap().to_owned();
    let token = invite(&api, &a, &env, &rec).await;
    let (_, h) = open(&api, &token).await;
    let ceremony = h[0].1.split_once('=').unwrap().1.to_owned();
    let secrets = [
        ("API key", a.key.clone()),
        (
            "client secret",
            oc["client_secret"].as_str().unwrap().to_owned(),
        ),
        ("signing link", token.clone()),
        ("ceremony cookie", ceremony),
    ];
    let tables: Vec<String> = sqlx::query(
        "SELECT quote_ident(table_name) FROM information_schema.tables \
         WHERE table_schema = 'public' AND table_type = 'BASE TABLE'",
    )
    .fetch_all(&api.db.admin)
    .await
    .unwrap()
    .iter()
    .map(|r| r.get::<String, _>(0))
    .collect();
    assert!(tables.len() > 10);
    for (what, secret) in &secrets {
        assert!(secret.len() >= 32, "{what} is long");
        let hex: String = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, secret.as_bytes())
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let mut hashed = 0_i64;
        for t in &tables {
            // The table names come from the catalogue, quoted by quote_ident.
            let q = format!("SELECT count(*) FROM {t} x WHERE x::text LIKE '%' || $1 || '%'");
            let clear: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(q.clone()))
                .bind(secret)
                .fetch_one(&api.db.admin)
                .await
                .unwrap();
            assert_eq!(clear, 0, "{what} in clear in {t}");
            hashed += sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(q.clone()))
                .bind(&hex)
                .fetch_one(&api.db.admin)
                .await
                .unwrap();
        }
        assert!(hashed > 0, "{what} is stored as its SHA-256");
    }
    api.db.drop().await;
}

#[tokio::test]
async fn sign_in_attempts_are_limited_per_client_address_across_names() {
    let Some(api) = Api::with("threat_login_ip", Rls::On, |c| {
        c.rate.login_per_minute = 1;
    })
    .await
    else {
        return;
    };
    // One attempt per name, ten per address: the eleventh name from one address stops.
    let mut last = None;
    for n in 0..11 {
        last = Some(
            api.call(
                "POST",
                "/api/v1/auth/login",
                &Auth::None,
                Some(
                    json!({"email": format!("n{n}@example.test"), "password": "guess guess guess"}),
                ),
                &[],
            )
            .await,
        );
    }
    let r = last.unwrap();
    assert_eq!(
        code(&r),
        (StatusCode::TOO_MANY_REQUESTS, "CS-API-0003".into())
    );
    api.set_peer("203.0.113.9:40000");
    let r = api
        .call(
            "POST",
            "/api/v1/auth/login",
            &Auth::None,
            Some(json!({"email": "fresh@example.test", "password": "guess guess guess"})),
            &[],
        )
        .await;
    assert_eq!(code(&r), (StatusCode::UNAUTHORIZED, "CS-AUTH-0007".into()));
    api.db.drop().await;
}
