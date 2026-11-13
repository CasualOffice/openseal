//! RAUTH-01 (slice 5): a recipient whose sender requires `sso` signs in through one of
//! the operator's OpenID Connect providers. A fake provider on the loopback address
//! answers the token endpoint (checking the PKCE verifier against the challenge the
//! server sent the browser with) and the JWKS. The recipient passes only with an ID token
//! from the named issuer, for this client, unexpired by the server's clock, with this
//! sign-in's nonce and the recipient's verified email; a token from another issuer, an
//! expired one, one for another email, a replayed nonce and a replayed `state` each fail
//! and are counted. A pass records the issuer and the SHA-256 of the subject.

#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::indexing_slicing
)]

mod common;

use std::sync::{Arc, Mutex};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::Rls;
use common::flow::{b64, invite, ok, open};
use common::harness::{Api, Auth, Resp, pdf};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ISSUER: &str = "https://idp.example.test";
const CLIENT: &str = "openseal-signing";
const EMAIL: &str = "one@example.test";

/// What the fake provider answers next, and what it last saw.
#[derive(Default)]
struct Idp {
    /// The ID token the token endpoint answers.
    id_token: Option<String>,
    /// The PKCE challenge the token request's verifier must match.
    challenge: Option<String>,
    /// Token requests whose verifier did not match.
    bad_verifier: u32,
}

/// The fake provider: `POST /token` and `GET /jwks` on 127.0.0.1; answers its base URL.
async fn provider(idp: Arc<Mutex<Idp>>, jwks: Value) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            let idp = idp.clone();
            let jwks = jwks.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let (head, body) = loop {
                    let n = s.read(&mut chunk).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..i]).to_string();
                        let len = head
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        while buf.len() < i + 4 + len {
                            let n = s.read(&mut chunk).await.unwrap();
                            buf.extend_from_slice(&chunk[..n]);
                        }
                        break (head, String::from_utf8_lossy(&buf[i + 4..]).to_string());
                    }
                };
                let (status, answer) = if head.starts_with("GET /jwks") {
                    (200, jwks.to_string())
                } else if head.starts_with("POST /token") {
                    let form: Vec<(String, String)> = body
                        .split('&')
                        .filter_map(|kv| kv.split_once('='))
                        .map(|(k, v)| (k.to_owned(), decode(v)))
                        .collect();
                    let get = |k: &str| {
                        form.iter()
                            .find(|(n, _)| n == k)
                            .map(|(_, v)| v.clone())
                            .unwrap_or_default()
                    };
                    let mut g = idp.lock().unwrap();
                    let verifier = get("code_verifier");
                    let s256 = URL_SAFE_NO_PAD
                        .encode(casual_sign_audit::Hash256::digest(verifier.as_bytes()).as_bytes());
                    if g.challenge.as_deref() != Some(s256.as_str())
                        || get("client_id") != CLIENT
                        || get("client_secret") != "client-secret"
                        || get("grant_type") != "authorization_code"
                    {
                        g.bad_verifier += 1;
                        (400, json!({"error": "invalid_grant"}).to_string())
                    } else {
                        match &g.id_token {
                            Some(t) => (200, json!({"id_token": t, "access_token": "at", "token_type": "Bearer"}).to_string()),
                            None => (400, json!({"error": "invalid_grant"}).to_string()),
                        }
                    }
                } else {
                    (404, "{}".to_owned())
                };
                let r = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                    answer.len()
                );
                let _ = s.write_all(r.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    base
}

fn decode(v: &str) -> String {
    let b = v.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            out.push(
                u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap(), 16).unwrap(),
            );
            i += 3;
        } else {
            out.push(if b[i] == b'+' { b' ' } else { b[i] });
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

/// The provider's signing key: (PKCS#8 for signing, its JWKS).
fn key() -> (Vec<u8>, Value) {
    let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
        .unwrap();
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, doc.as_ref()).unwrap();
    let point = pair.public_key().as_ref();
    let jwks = json!({"keys": [{"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig",
        "kid": "k1", "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
        "y": URL_SAFE_NO_PAD.encode(&point[33..65])}]});
    (doc.as_ref().to_vec(), jwks)
}

fn id_token(pkcs8: &[u8], claims: &Value) -> String {
    let mut h = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    h.kid = Some("k1".into());
    jsonwebtoken::encode(&h, claims, &jsonwebtoken::EncodingKey::from_ec_der(pkcs8)).unwrap()
}

/// A query parameter of `url`.
fn param(url: &str, name: &str) -> String {
    let q = url.split_once('?').unwrap().1;
    q.split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| decode(v))
        .unwrap()
}

type Headers = Vec<(&'static str, String)>;

async fn call(api: &Api, method: &str, path: &str, h: &Headers, body: Option<Value>) -> Resp {
    let h: Vec<(&str, &str)> = h.iter().map(|(k, v)| (*k, v.as_str())).collect();
    api.call(method, path, &Auth::None, body, &h).await
}

/// Start a sign-in; answer (state, nonce) and tell the provider the challenge to expect.
async fn start(api: &Api, token: &str, h: &Headers, idp: &Arc<Mutex<Idp>>) -> (String, String) {
    let v = ok(
        call(
            api,
            "POST",
            &format!("/s/{token}/sso"),
            h,
            Some(json!({"provider": "corp"})),
        )
        .await,
        StatusCode::OK,
        "start",
    );
    let url = v["sso_authorization_url"].as_str().unwrap().to_owned();
    assert!(url.starts_with("http://127.0.0.1:"), "{url}");
    assert_eq!(param(&url, "code_challenge_method"), "S256");
    assert_eq!(
        param(&url, "redirect_uri"),
        "https://sign.example.test/s/oidc"
    );
    idp.lock().unwrap().challenge = Some(param(&url, "code_challenge"));
    (param(&url, "state"), param(&url, "nonce"))
}

async fn finish(api: &Api, token: &str, h: &Headers, state: &str) -> Resp {
    call(
        api,
        "POST",
        &format!("/s/{token}/sso/verify"),
        h,
        Some(json!({"state": state, "code": "the-code"})),
    )
    .await
}

#[tokio::test]
async fn a_signer_passes_sso_only_with_a_valid_token_from_the_named_issuer() {
    let Some(api) = Api::new("ceremony_sso", Rls::On).await else {
        return;
    };
    let (pkcs8, jwks) = key();
    let idp = Arc::new(Mutex::new(Idp::default()));
    let base = provider(idp.clone(), jwks).await;
    let file = json!({"providers": [{"id": "corp", "name": "Example Corp", "issuer": ISSUER,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"), "jwks_uri": format!("{base}/jwks"),
        "client_id": CLIENT, "client_secret": "client-secret"}]});
    api.st.set_recipient_idps(
        casual_sign_server::idp::RecipientIdps::from_json(
            file.to_string().as_bytes(),
            "https://sign.example.test",
        )
        .unwrap(),
    );
    let a = api.tenant("alpha").await;
    // Room for every refusal below before the lockout.
    let mut policy = serde_json::to_value(casual_sign_workflow::Policy::default()).unwrap();
    policy["max_auth_attempts"] = json!(10);
    ok(
        api.call(
            "PATCH",
            "/api/v1/accounts/me",
            &a.auth,
            Some(json!({"settings": {"workflow_policy": policy}})),
            &[],
        )
        .await,
        StatusCode::OK,
        "policy",
    );
    let e = ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            &a.auth,
            Some(json!({
                "subject": "RAUTH-01", "status": "sent",
                "documents": [{"name": "d.pdf", "content_base64": b64(&pdf(1))}],
                "recipients": [{"ref": "s1", "type": "signer", "name": "Sig One",
                    "email": EMAIL, "routing_order": 1, "auth": ["sso"]}],
                "fields": [{"recipient": "s1", "document": 0, "type": "signature", "page": 1,
                    "x": 72, "y": 100, "width": 180, "height": 40, "required": true}],
            })),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "create",
    );
    let env = e["id"].as_str().unwrap().to_owned();
    let rec = e["recipients"][0]["id"].as_str().unwrap().to_owned();
    let token = invite(&api, &a, &env, &rec).await;
    let (view, h) = open(&api, &token).await;
    assert_eq!(view["auth_required"], json!(["sso"]), "{view}");
    assert_eq!(
        view["sso_providers"],
        json!([{"id": "corp", "name": "Example Corp"}])
    );
    assert_eq!(view["envelope"]["documents"], json!([]), "{view}");

    // An unknown provider is refused before anything is recorded.
    let r = call(
        &api,
        "POST",
        &format!("/s/{token}/sso"),
        &h,
        Some(json!({"provider": "other"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);

    let now = common::harness::start().unix_timestamp();
    let claims = |nonce: &str| {
        json!({"iss": ISSUER, "aud": CLIENT, "sub": "user-4711", "exp": now + 3600,
            "iat": now, "nonce": nonce, "email": EMAIL, "email_verified": true})
    };
    let refused = |r: &Resp, what: &str| {
        assert_eq!(
            r.status,
            StatusCode::FORBIDDEN,
            "{what}: {}",
            String::from_utf8_lossy(&r.body)
        );
        assert_eq!(r.json()["envelope"]["documents"], json!([]), "{what}");
    };

    // A token from another issuer.
    let (state, nonce) = start(&api, &token, &h, &idp).await;
    let mut c = claims(&nonce);
    c["iss"] = json!("https://evil.example.test");
    idp.lock().unwrap().id_token = Some(id_token(&pkcs8, &c));
    refused(&finish(&api, &token, &h, &state).await, "another issuer");

    // An expired token, by the server's clock.
    let (state, nonce) = start(&api, &token, &h, &idp).await;
    let mut c = claims(&nonce);
    c["exp"] = json!(now - 3600);
    idp.lock().unwrap().id_token = Some(id_token(&pkcs8, &c));
    refused(&finish(&api, &token, &h, &state).await, "expired");

    // Someone else's verified email.
    let (state, nonce) = start(&api, &token, &h, &idp).await;
    let mut c = claims(&nonce);
    c["email"] = json!("two@example.test");
    idp.lock().unwrap().id_token = Some(id_token(&pkcs8, &c));
    refused(&finish(&api, &token, &h, &state).await, "another email");

    // A replayed nonce: a token minted for an earlier sign-in.
    let (state, own) = start(&api, &token, &h, &idp).await;
    idp.lock().unwrap().id_token = Some(id_token(&pkcs8, &claims(&nonce)));
    refused(&finish(&api, &token, &h, &state).await, "replayed nonce");

    // A replayed state: that sign-in is closed, even with a good token for it.
    idp.lock().unwrap().id_token = Some(id_token(&pkcs8, &claims(&own)));
    refused(&finish(&api, &token, &h, &state).await, "replayed state");

    // The valid sign-in passes, and the document is shown (a minute on: sign-ins are
    // limited to 5 a minute per link).
    api.clock.advance(std::time::Duration::from_secs(61));
    let (state, nonce) = start(&api, &token, &h, &idp).await;
    idp.lock().unwrap().id_token = Some(id_token(&pkcs8, &claims(&nonce)));
    let v = ok(
        finish(&api, &token, &h, &state).await,
        StatusCode::OK,
        "valid",
    );
    assert_eq!(v["auth_required"], json!([]), "{v}");
    assert_eq!(
        v["envelope"]["documents"].as_array().unwrap().len(),
        1,
        "{v}"
    );
    assert!(v.get("sso_providers").is_none(), "{v}");
    assert_eq!(
        idp.lock().unwrap().bad_verifier,
        0,
        "PKCE verifier mismatch"
    );

    // The trail: five failures, then a pass naming the issuer and the subject's hash.
    let audit = ok(
        api.call(
            "GET",
            &format!("/api/v1/envelopes/{env}/audit"),
            &a.auth,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "audit",
    );
    let events = audit["items"].as_array().unwrap();
    let of = |t: &str| events.iter().filter(|e| e["type"] == t).collect::<Vec<_>>();
    assert_eq!(of("recipient.auth_failed").len(), 5, "{audit}");
    let passed = of("recipient.auth_passed");
    assert_eq!(passed.len(), 1, "{audit}");
    let data = &passed[0]["event"]["data"];
    assert_eq!(
        data["identity"],
        json!({"issuer": ISSUER,
            "subject_sha256": casual_sign_audit::Hash256::digest(b"user-4711").to_string()}),
        "{data}"
    );
    // Never the subject itself, nor the token's email.
    let text = data.to_string();
    assert!(
        !text.contains("user-4711") && !text.contains(EMAIL),
        "{text}"
    );
    api.db.drop().await;
}
