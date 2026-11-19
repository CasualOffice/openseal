//! OAuth 2.1 acting for a member (slice 8, `VS-08A`, `VS-08B`; docs/40 §2): the
//! authorization code grant with PKCE through the consent endpoints, rotating refresh
//! tokens with the replay rule, withdrawing a consent, and the RFC 7523 JWT bearer grant
//! of an integration with its own key.

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

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use axum::body::Body;
use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use common::Rls;
use common::harness::{Api, Auth, Resp};
use serde_json::{Value, json};

const REDIRECT: &str = "https://app.example.test/callback";
const VERIFIER: &str = "a-pkce-verifier-of-forty-three-or-more-characters-0123456789";

fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA256,
        verifier.as_bytes(),
    ))
}

fn query_of(url: &str) -> std::collections::BTreeMap<String, String> {
    let q = url.split_once('?').map_or("", |(_, q)| q);
    q.split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.replace("%3A", ":").replace("%2F", "/")))
        .collect()
}

fn authorize_query(client: &str, scope: &str, redirect: &str) -> String {
    format!(
        "response_type=code&client_id={client}&redirect_uri={}&scope={}&state=xyz&code_challenge={}&code_challenge_method=S256",
        redirect.replace(':', "%3A").replace('/', "%2F"),
        scope.replace(':', "%3A").replace(' ', "%20"),
        challenge(VERIFIER)
    )
}

async fn token(api: &Api, body: Value) -> Resp {
    api.call("POST", "/api/v1/oauth/token", &Auth::None, Some(body), &[])
        .await
}

async fn consent(api: &Api, s: &Auth, client: &str, scope: &str, decision: &str) -> Resp {
    api.call(
        "POST",
        "/api/v1/oauth/authorize",
        s,
        Some(json!({
            "response_type": "code", "client_id": client, "redirect_uri": REDIRECT,
            "scope": scope, "state": "xyz", "code_challenge": challenge(VERIFIER),
            "code_challenge_method": "S256", "decision": decision,
        })),
        &[],
    )
    .await
}

fn oauth_code(r: &Resp) -> (StatusCode, String, String) {
    let j = r.json();
    (
        r.status,
        j["error"].as_str().unwrap_or_default().to_owned(),
        j["error_description"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
    )
}

#[tokio::test]
async fn an_app_acts_for_a_member_who_consented_through_the_code_flow() {
    let Some(api) = Api::new("oauth_code_flow", Rls::On).await else {
        return;
    };
    let t = api.tenant("oauthcode").await;
    let s = api.login(&t.email, common::harness::PASSWORD).await;
    // Registration: redirect URIs are https or loopback http, never a fragment.
    let bad = api
        .call(
            "POST",
            "/api/v1/api-clients",
            &s,
            Some(
                json!({"name": "App", "kind": "oauth_app", "scopes": ["envelopes:read"],
                "redirect_uris": ["http://app.example.test/cb"]}),
            ),
            &[],
        )
        .await;
    assert_eq!(bad.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(bad.json()["errors"][0]["pointer"], "/redirect_uris/0");
    let app = api
        .call(
            "POST",
            "/api/v1/api-clients",
            &s,
            Some(json!({"name": "Partner CRM", "kind": "oauth_app",
                "scopes": ["envelopes:read", "envelopes:write"], "redirect_uris": [REDIRECT]})),
            &[],
        )
        .await;
    assert_eq!(app.status, StatusCode::CREATED, "{:?}", app.json());
    let app = app.json();
    assert_eq!(app["redirect_uris"], json!([REDIRECT]));
    let id = app["client_id"].as_str().unwrap().to_owned();
    let secret = app["client_secret"].as_str().unwrap().to_owned();

    // The authorization endpoint hands the request to the web app's consent screen.
    let q = authorize_query(&id, "envelopes:read", REDIRECT);
    let r = api
        .call(
            "GET",
            &format!("/api/v1/oauth/authorize?{q}"),
            &Auth::None,
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(
        r.headers["location"].to_str().unwrap(),
        format!("/app.html#/authorize?{q}")
    );
    // The screen reads the checked request.
    let r = api
        .call(
            "GET",
            &format!("/api/v1/oauth/authorize/request?{q}"),
            &s,
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    assert_eq!(r.json()["client"]["name"], "Partner CRM");
    assert_eq!(r.json()["scopes"], json!(["envelopes:read"]));
    for (query, pointer) in [
        (
            authorize_query(&id, "envelopes:read", "https://evil.example/cb"),
            "/redirect_uri",
        ),
        (authorize_query(&id, "envelopes:send", REDIRECT), "/scope"),
        (q.replace("S256", "plain"), "/code_challenge"),
        (
            authorize_query(
                &uuid::Uuid::now_v7().to_string(),
                "envelopes:read",
                REDIRECT,
            ),
            "/client_id",
        ),
    ] {
        let r = api
            .call(
                "GET",
                &format!("/api/v1/oauth/authorize/request?{query}"),
                &s,
                None,
                &[],
            )
            .await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{pointer}");
        assert_eq!(r.json()["errors"][0]["pointer"], pointer);
    }
    // Only a signed-in member consents: an API key cannot.
    let r = api
        .call(
            "GET",
            &format!("/api/v1/oauth/authorize/request?{q}"),
            &t.auth,
            None,
            &[],
        )
        .await;
    assert_eq!(r.json()["errors"][0]["pointer"], "/credential");

    // Deny: the redirect carries access_denied, state and the issuer.
    let r = consent(&api, &s, &id, "envelopes:read", "deny").await;
    assert_eq!(r.status, StatusCode::OK);
    let to = r.json()["redirect_to"].as_str().unwrap().to_owned();
    assert!(to.starts_with(REDIRECT), "{to}");
    let p = query_of(&to);
    assert_eq!(p["error"], "access_denied");
    assert_eq!(p["state"], "xyz");
    assert!(!p.contains_key("code"));

    // Allow: a one-time code.
    let r = consent(&api, &s, &id, "envelopes:read", "allow").await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let p = query_of(r.json()["redirect_to"].as_str().unwrap());
    assert_eq!(p["state"], "xyz");
    assert_eq!(p["iss"], "https://sign.example.test");
    let code = p["code"].clone();
    // A wrong verifier is refused, and burns the code.
    let r = token(
        &api,
        json!({"grant_type": "authorization_code", "client_id": id,
        "client_secret": secret, "code": code, "redirect_uri": REDIRECT,
        "code_verifier": "x".repeat(43)}),
    )
    .await;
    assert_eq!(
        oauth_code(&r),
        (
            StatusCode::BAD_REQUEST,
            "invalid_grant".into(),
            "CS-AUTH-0014".into()
        )
    );
    let r = token(&api, json!({"grant_type": "authorization_code", "client_id": id,
        "client_secret": secret, "code": code, "redirect_uri": REDIRECT, "code_verifier": VERIFIER}))
    .await;
    assert_eq!(oauth_code(&r).1, "invalid_grant", "a burnt code");

    // A fresh code, exchanged by HTTP Basic and a form body.
    let r = consent(&api, &s, &id, "envelopes:read", "allow").await;
    let code = query_of(r.json()["redirect_to"].as_str().unwrap())["code"].clone();
    let basic = format!("Basic {}", STANDARD.encode(format!("{id}:{secret}")));
    let form = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={}&code_verifier={VERIFIER}",
        REDIRECT.replace(':', "%3A").replace('/', "%2F")
    );
    let r = api
        .send(
            "POST",
            "/api/v1/oauth/token",
            &Auth::None,
            Body::from(form),
            &[
                ("content-type", "application/x-www-form-urlencoded"),
                ("authorization", &basic),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    assert_eq!(r.headers["cache-control"], "no-store");
    let access = Auth::Bearer(r.json()["access_token"].as_str().unwrap().to_owned());
    let refresh = r.json()["refresh_token"].as_str().unwrap().to_owned();
    assert!(refresh.starts_with("osr_"));
    assert_eq!(r.json()["scope"], "envelopes:read");
    // The token acts as the member, within the scope consented to.
    assert_eq!(
        api.call("GET", "/api/v1/envelopes", &access, None, &[])
            .await
            .status,
        StatusCode::OK
    );
    let me = api
        .call("GET", "/api/v1/users/me", &access, None, &[])
        .await;
    assert_eq!(me.json()["email"], t.email);
    let r = api
        .call(
            "POST",
            "/api/v1/envelopes",
            &access,
            Some(json!({"subject": "x"})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // The code is spent.
    let r = token(&api, json!({"grant_type": "authorization_code", "client_id": id,
        "client_secret": secret, "code": code, "redirect_uri": REDIRECT, "code_verifier": VERIFIER}))
    .await;
    assert_eq!(oauth_code(&r).1, "invalid_grant");

    // Refresh rotates; the old token spent again revokes the family.
    let r = token(
        &api,
        json!({"grant_type": "refresh_token", "client_id": id,
        "client_secret": secret, "refresh_token": refresh}),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let next = r.json()["refresh_token"].as_str().unwrap().to_owned();
    assert_ne!(next, refresh);
    let r = token(
        &api,
        json!({"grant_type": "refresh_token", "client_id": id,
        "client_secret": secret, "refresh_token": refresh}),
    )
    .await;
    assert_eq!(
        oauth_code(&r),
        (
            StatusCode::BAD_REQUEST,
            "invalid_grant".into(),
            "CS-AUTH-0014".into()
        )
    );
    let r = token(
        &api,
        json!({"grant_type": "refresh_token", "client_id": id,
        "client_secret": secret, "refresh_token": next}),
    )
    .await;
    assert_eq!(oauth_code(&r).1, "invalid_grant", "the family is revoked");

    // The member sees the app and withdraws consent; the token stops at once.
    let r = api
        .call("GET", "/api/v1/oauth/consents", &s, None, &[])
        .await;
    let items = r.json()["items"].as_array().unwrap().clone();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["client"]["name"], "Partner CRM");
    let cid = items[0]["id"].as_str().unwrap().to_owned();
    let r = api
        .call(
            "DELETE",
            &format!("/api/v1/oauth/consents/{cid}"),
            &s,
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let r = api
        .call("GET", "/api/v1/envelopes", &access, None, &[])
        .await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::UNAUTHORIZED, "CS-AUTH-0002".into())
    );
    let r = api
        .call(
            "DELETE",
            &format!("/api/v1/oauth/consents/{cid}"),
            &s,
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    // The authorization server's metadata.
    let r = api
        .call(
            "GET",
            "/.well-known/oauth-authorization-server",
            &Auth::None,
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(
        r.json()["token_endpoint"],
        "https://sign.example.test/api/v1/oauth/token"
    );
    assert_eq!(
        r.json()["code_challenge_methods_supported"],
        json!(["S256"])
    );
    api.db.drop().await;
}

/// A P-256 key: its PKCS#8 private half, and its public half as a PEM SubjectPublicKeyInfo.
fn p256() -> (Vec<u8>, String) {
    let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
        .unwrap();
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, doc.as_ref()).unwrap();
    let mut spki = hex_bytes("3059301306072a8648ce3d020106082a8648ce3d030107034200");
    spki.extend_from_slice(pair.public_key().as_ref());
    let b64 = STANDARD.encode(&spki);
    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n{}\n-----END PUBLIC KEY-----\n",
        &b64[..64],
        &b64[64..]
    );
    (doc.as_ref().to_vec(), pem)
}

fn hex_bytes(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

fn assertion(pkcs8: &[u8], claims: &Value) -> String {
    let key = jsonwebtoken::EncodingKey::from_ec_der(pkcs8);
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256),
        claims,
        &key,
    )
    .unwrap()
}

#[tokio::test]
async fn a_jwt_integration_acts_for_a_member_who_consented_once() {
    let Some(api) = Api::new("oauth_jwt_grant", Rls::On).await else {
        return;
    };
    let t = api.tenant("oauthjwt").await;
    let s = api.login(&t.email, common::harness::PASSWORD).await;
    let (private, pem) = p256();
    // A private key is never accepted as the integration's key.
    let r = api
        .call(
            "POST",
            "/api/v1/api-clients",
            &s,
            Some(json!({"name": "Back office", "kind": "jwt_integration",
                "scopes": ["envelopes:read"], "redirect_uris": [REDIRECT],
                "public_key": format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----", STANDARD.encode(&private))})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(r.json()["errors"][0]["pointer"], "/public_key");
    let r = api
        .call(
            "POST",
            "/api/v1/api-clients",
            &s,
            Some(json!({"name": "Back office", "kind": "jwt_integration",
                "scopes": ["envelopes:read", "envelopes:write"], "redirect_uris": [REDIRECT],
                "public_key": pem})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.json());
    let j = r.json();
    assert_eq!(j["kind"], "jwt_integration");
    assert_eq!(j["has_public_key"], true);
    assert!(j.get("client_secret").is_none() && j.get("key").is_none());
    let id = j["client_id"].as_str().unwrap().to_owned();
    let user = j["owner_user_id"].as_str().unwrap().to_owned();
    let now = common::harness::start().unix_timestamp();
    let claims = |aud: &str, iat: i64, exp: i64| json!({"iss": id, "sub": user, "aud": aud, "iat": iat, "exp": exp, "scope": "envelopes:read"});
    let grant = |a: String| json!({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": a});
    let good = assertion(
        &private,
        &claims("https://sign.example.test", now, now + 3600),
    );
    // Before the member consents: consent required.
    let r = token(&api, grant(good.clone())).await;
    assert_eq!(
        oauth_code(&r),
        (
            StatusCode::BAD_REQUEST,
            "invalid_grant".into(),
            "CS-AUTH-0005".into()
        )
    );
    let r = consent(&api, &s, &id, "envelopes:read envelopes:write", "allow").await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    // After: a token acting for the member, without a refresh token.
    let r = token(&api, grant(good)).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    assert!(r.json().get("refresh_token").is_none());
    assert_eq!(r.json()["scope"], "envelopes:read");
    let access = Auth::Bearer(r.json()["access_token"].as_str().unwrap().to_owned());
    assert_eq!(
        api.call("GET", "/api/v1/envelopes", &access, None, &[])
            .await
            .status,
        StatusCode::OK
    );
    // The token endpoint's own URL is an audience too.
    let r = token(
        &api,
        grant(assertion(
            &private,
            &claims(
                "https://sign.example.test/api/v1/oauth/token",
                now,
                now + 60,
            ),
        )),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    // Refused: another audience, expired, longer than an hour, another key.
    let (other, _) = p256();
    for (a, what) in [
        (
            assertion(
                &private,
                &claims("https://elsewhere.example", now, now + 60),
            ),
            "audience",
        ),
        (
            assertion(
                &private,
                &claims("https://sign.example.test", now - 120, now - 60),
            ),
            "expired",
        ),
        (
            assertion(
                &private,
                &claims("https://sign.example.test", now, now + 7200),
            ),
            "too long",
        ),
        (
            assertion(&other, &claims("https://sign.example.test", now, now + 60)),
            "another key",
        ),
    ] {
        let r = token(&api, grant(a)).await;
        assert_eq!(
            oauth_code(&r),
            (
                StatusCode::BAD_REQUEST,
                "invalid_grant".into(),
                "CS-AUTH-0014".into()
            ),
            "{what}"
        );
    }
    // A scope beyond the consent.
    let mut c = claims("https://sign.example.test", now, now + 60);
    c["scope"] = json!("envelopes:send");
    let r = token(&api, grant(assertion(&private, &c))).await;
    assert_eq!(oauth_code(&r).1, "invalid_scope");
    // Withdrawn consent ends the token.
    let cid = api
        .call("GET", "/api/v1/oauth/consents", &s, None, &[])
        .await
        .json()["items"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    api.call(
        "DELETE",
        &format!("/api/v1/oauth/consents/{cid}"),
        &s,
        None,
        &[],
    )
    .await;
    let r = api
        .call("GET", "/api/v1/envelopes", &access, None, &[])
        .await;
    assert_eq!(r.code(), "CS-AUTH-0002");
    api.db.drop().await;
}
