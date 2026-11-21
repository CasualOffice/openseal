//! `RSP-01` (ADR-046 §3.4, §3.12): the signer's side of a remote signing session. A
//! remote signer starts (values frozen, a session with a new `state` and PKCE verifier,
//! the browser sent to the provider with scope `service`); the provider's answer is
//! taken once, for the open session's step and `state` only (anything else
//! `409 CS-RSP-0003`, nothing kept), and queues the worker; once the worker has
//! prepared, the signer is shown the exact prepared bytes and authorizes their hashes
//! (scope `credential`, bound to the hashes); a refusal at the provider, a cancel and a
//! session left past its time each fail the session and the signer may start again.
//! The worker's side (the provider calls, embedding, the seal) is the Compose stack's
//! `webapp/e2e/remote-signing.spec.mjs`.

#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::indexing_slicing
)]

mod common;

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use casual_sign_csc::{Catalogue, CscError, ProviderSecretsKey};
use common::Rls;
use common::flow::{b64, invite, jobs, ok, open};
use common::harness::{Api, Auth, Resp, pdf, png};
use serde_json::{Value, json};
use sqlx::Row;

const PEM: &[u8] = b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n";

fn catalogue() -> Catalogue {
    let file = json!({"providers": [{
        "id": "csc-ci", "kind": "csc", "name": "CI provider",
        "base_uri": "https://csc.example.test/csc/v2",
        "authorization_endpoint": "https://csc.example.test/oauth2/authorize",
        "token_endpoint": "https://csc.example.test/oauth2/token",
        "client_id": "openseal", "client_secret_ref": "CSC_SECRET",
        "trust_anchors_file": "/anchors.pem", "accounts": ["*"]}]});
    Catalogue::parse(
        file.to_string().as_bytes(),
        "https://sign.example.test",
        &|_| -> Result<_, CscError> {
            Ok(Some(casual_sign_secrets::Secret::new(
                "operator".to_owned(),
            )))
        },
        &|_| Some(PEM.to_vec()),
    )
    .unwrap()
}

/// The query of a `remote_authorization_url`, after checking where it goes.
fn query(view: &Value) -> std::collections::BTreeMap<String, String> {
    let url = view["remote_authorization_url"].as_str().unwrap();
    let q = url
        .strip_prefix("https://csc.example.test/oauth2/authorize?")
        .expect("the provider's authorization endpoint");
    q.split('&')
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap();
            let v = v.replace('+', " ");
            let v = percent_decode(&v);
            (k.to_owned(), v)
        })
        .collect()
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

fn status(v: &Value) -> (String, Value) {
    (
        v["remote_signing"]["status"]
            .as_str()
            .unwrap_or("")
            .to_owned(),
        v["remote_signing"]["failure"].clone(),
    )
}

fn refused(r: &Resp, code: &str, what: &str) {
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::CONFLICT, code),
        "{what}: {}",
        String::from_utf8_lossy(&r.body)
    );
}

#[tokio::test]
async fn a_remote_signers_session_takes_each_answer_once_and_fails_without_a_fallback() {
    let Some(api) = Api::new("ceremony_rsp", Rls::On).await else {
        return;
    };
    api.st
        .set_signing_providers(catalogue(), ProviderSecretsKey::new(&[7; 32]).unwrap());
    let a = api.tenant("alpha").await;
    ok(
        api.call(
            "PUT",
            "/api/v1/signing-providers/csc-ci",
            &a.auth,
            Some(json!({"enabled": true})),
            &[],
        )
        .await,
        StatusCode::OK,
        "enable",
    );
    let original = pdf(1);
    let env = ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            &a.auth,
            Some(json!({
                "subject": "RSP-01", "status": "sent",
                "documents": [{"name": "d.pdf", "content_base64": b64(&original)}],
                "recipients": [{"ref": "r", "type": "signer", "name": "Remote Signer",
                    "email": "r@example.test", "routing_order": 1,
                    "signature": {"type": "remote", "provider_id": "csc-ci"}}],
                "fields": [{"recipient": "r", "document": 0, "type": "signature", "page": 1,
                    "x": 72, "y": 100, "width": 180, "height": 40, "required": true}],
            })),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "create",
    );
    let eid = env["id"].as_str().unwrap().to_owned();
    let rid = env["recipients"][0]["id"].as_str().unwrap().to_owned();
    let doc = env["documents"][0]["id"].as_str().unwrap().to_owned();
    let token = invite(&api, &a, &eid, &rid).await;
    let (view, bound) = open(&api, &token).await;
    assert_eq!(view["remote_provider_name"], "CI provider");
    let h: Vec<(&str, &str)> = bound.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let s = format!("/s/{token}");
    let call = |method: &'static str, path: String, body: Option<Value>| {
        let h = h.clone();
        let api = &api;
        async move { api.call(method, &path, &Auth::None, body, &h).await }
    };
    ok(
        call(
            "POST",
            format!("{s}/documents/{doc}/viewed"),
            Some(json!({"pages_seen": [1]})),
        )
        .await,
        StatusCode::OK,
        "viewed",
    );
    let adopted = ok(
        call(
            "POST",
            format!("{s}/adopt"),
            Some(json!({"mark": "signature", "method": "draw", "image_base64": b64(&png())})),
        )
        .await,
        StatusCode::OK,
        "adopt",
    );
    let field = view["fields"][0]["id"].as_str().unwrap().to_owned();
    let values = json!({"values": [{"field": field,
        "value": {"signature": adopted["adoption_id"]}}]});
    // A remote signer never finishes with a plain finish (no fallback to simple).
    let plain = call("POST", format!("{s}/finish"), Some(values.clone())).await;
    assert_eq!(plain.status, StatusCode::CONFLICT, "{:?}", plain.json());

    // Start: the browser goes to the provider with scope `service`, a state and PKCE.
    let started = ok(
        call("POST", format!("{s}/remote-signing"), Some(values.clone())).await,
        StatusCode::OK,
        "start",
    );
    assert_eq!(status(&started).0, "authorizing_service");
    let q = query(&started);
    assert_eq!(q["scope"], "service");
    assert_eq!(q["client_id"], "openseal");
    assert_eq!(q["redirect_uri"], "https://sign.example.test/s/rsp");
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(
        URL_SAFE_NO_PAD.decode(&q["code_challenge"]).unwrap().len(),
        32
    );
    let state = q["state"].clone();
    // The state is kept only as its hash; the verifier only sealed.
    let row = sqlx::query(
        "SELECT state_sha256, pkce_sealed FROM remote_signing_sessions WHERE recipient_id = $1::uuid",
    )
    .bind(&rid)
    .fetch_one(&api.db.admin)
    .await
    .unwrap();
    assert_eq!(row.get::<Vec<u8>, _>(0), sha256(state.as_bytes()));
    let sealed: Vec<u8> = row.get(1);
    assert!(
        !sealed
            .windows(16)
            .any(|w| q["code_challenge"].as_bytes().starts_with(w)),
        "the verifier is sealed"
    );
    // Values are frozen; another start while it is open is refused.
    refused(
        &call("POST", format!("{s}/remote-signing"), Some(values.clone())).await,
        "CS-RSP-0007",
        "second start",
    );
    // Prepared bytes only once prepared (none yet: not found).
    let early = call("GET", format!("{s}/remote-signing/documents/{doc}"), None).await;
    assert_eq!(early.status, StatusCode::NOT_FOUND);
    refused(
        &call(
            "POST",
            format!("{s}/remote-signing/authorize"),
            Some(json!({})),
        )
        .await,
        "CS-RSP-0003",
        "authorize before prepared",
    );

    // A code longer than a sealed value can hold is malformed, and spends nothing.
    let long = call(
        "POST",
        format!("{s}/remote-signing/callback"),
        Some(json!({"state": state, "code": "c".repeat(901)})),
    )
    .await;
    assert_eq!(long.status, StatusCode::UNPROCESSABLE_ENTITY, "{:?}", long.json());
    // Another state is refused and spends nothing; the right one queues the worker once.
    refused(
        &call(
            "POST",
            format!("{s}/remote-signing/callback"),
            Some(json!({"state": "not-the-state", "code": "c"})),
        )
        .await,
        "CS-RSP-0003",
        "wrong state",
    );
    let taken = ok(
        call(
            "POST",
            format!("{s}/remote-signing/callback"),
            Some(json!({"state": state, "code": "service-code"})),
        )
        .await,
        StatusCode::OK,
        "callback",
    );
    assert_eq!(status(&taken).0, "preparing");
    assert_eq!(
        jobs(&api, &eid)
            .await
            .iter()
            .filter(|k| *k == "remote_signing")
            .count(),
        1
    );
    let sealed_code: Vec<u8> = sqlx::query(
        "SELECT code_sealed FROM remote_signing_sessions WHERE recipient_id = $1::uuid",
    )
    .bind(&rid)
    .fetch_one(&api.db.admin)
    .await
    .unwrap()
    .get(0);
    assert!(
        !sealed_code
            .windows(b"service-code".len())
            .any(|w| w == b"service-code"),
        "the code is sealed"
    );
    refused(
        &call(
            "POST",
            format!("{s}/remote-signing/callback"),
            Some(json!({"state": state, "code": "service-code"})),
        )
        .await,
        "CS-RSP-0003",
        "replayed state",
    );
    assert_eq!(
        jobs(&api, &eid)
            .await
            .iter()
            .filter(|k| *k == "remote_signing")
            .count(),
        1,
        "a replay queues nothing"
    );

    // What the worker records once prepared (its own test: the Compose stack's spec):
    // here the prepared bytes are the original's blob.
    let base: Vec<u8> = sqlx::query(
        "SELECT sha256 FROM document_versions WHERE document_id = $1::uuid AND kind = 'original'",
    )
    .bind(&doc)
    .fetch_one(&api.db.admin)
    .await
    .unwrap()
    .get(0);
    let hash = sha256(b"signed attributes");
    let prepared = json!({"credential_id": "cred-1", "chain": [], "algorithm": "ecdsa-p256-sha256",
        "signing_time_ms": 0, "documents": [{"document_id": doc,
            "prepared": hex(&base), "to_be_signed": STANDARD.encode(&hash)}]});
    sqlx::query(
        "UPDATE remote_signing_sessions SET status = 'prepared', prepared = $2 WHERE recipient_id = $1::uuid",
    )
    .bind(&rid)
    .bind(&prepared)
    .execute(&api.db.admin)
    .await
    .unwrap();
    let ready = ok(
        call("GET", format!("{s}/remote-signing"), None).await,
        StatusCode::OK,
        "status",
    );
    assert_eq!(status(&ready).0, "prepared");
    assert_eq!(ready["remote_signing"]["documents"], json!([doc]));
    assert_eq!(ready["remote_signing"]["provider"], "CI provider");
    let bytes = call("GET", format!("{s}/remote-signing/documents/{doc}"), None).await;
    assert_eq!(bytes.status, StatusCode::OK);
    assert_eq!(bytes.body, original);
    let other = call(
        "GET",
        format!("{s}/remote-signing/documents/00000000-0000-7000-8000-000000000000"),
        None,
    )
    .await;
    assert_eq!(other.status, StatusCode::NOT_FOUND);

    // Authorize: scope `credential`, bound to the credential and these exact hashes.
    let auth = ok(
        call(
            "POST",
            format!("{s}/remote-signing/authorize"),
            Some(json!({})),
        )
        .await,
        StatusCode::OK,
        "authorize",
    );
    assert_eq!(status(&auth).0, "authorizing_credential");
    let q = query(&auth);
    assert_eq!(q["scope"], "credential");
    assert_eq!(q["credentialID"], "cred-1");
    assert_eq!(q["numSignatures"], "1");
    assert_eq!(q["hashes"], URL_SAFE_NO_PAD.encode(&hash));
    assert_eq!(q["hashAlgorithmOID"], "2.16.840.1.101.3.4.2.1");
    assert_ne!(q["state"], state);

    // A refusal for another state is itself refused: the session stays open.
    refused(
        &call(
            "POST",
            format!("{s}/remote-signing/callback"),
            Some(json!({"state": state, "error": "access_denied"})),
        )
        .await,
        "CS-RSP-0003",
        "refusal with a spent state",
    );
    let still = ok(
        call("GET", format!("{s}/remote-signing"), None).await,
        StatusCode::OK,
        "status",
    );
    assert_eq!(status(&still).0, "authorizing_credential");
    // The signer refuses at the provider: failed `cancelled`, nothing queued.
    let denied = ok(
        call(
            "POST",
            format!("{s}/remote-signing/callback"),
            Some(json!({"state": q["state"], "error": "access_denied"})),
        )
        .await,
        StatusCode::OK,
        "denied",
    );
    assert_eq!(status(&denied), ("failed".into(), json!("cancelled")));
    assert_eq!(
        jobs(&api, &eid)
            .await
            .iter()
            .filter(|k| *k == "remote_signing")
            .count(),
        1
    );
    // Still not finishable another way; start again, then cancel.
    let plain = call("POST", format!("{s}/finish"), Some(values.clone())).await;
    assert_eq!(plain.status, StatusCode::CONFLICT);
    ok(
        call("POST", format!("{s}/remote-signing"), Some(values.clone())).await,
        StatusCode::OK,
        "start again",
    );
    let cancelled = ok(
        call(
            "POST",
            format!("{s}/remote-signing/cancel"),
            Some(json!({})),
        )
        .await,
        StatusCode::OK,
        "cancel",
    );
    assert_eq!(status(&cancelled), ("failed".into(), json!("cancelled")));
    refused(
        &call(
            "POST",
            format!("{s}/remote-signing/cancel"),
            Some(json!({})),
        )
        .await,
        "CS-RSP-0003",
        "cancel twice",
    );

    // A session left past its time (15 minutes by default) fails `expired`; its state
    // no longer works.
    let again = ok(
        call("POST", format!("{s}/remote-signing"), Some(values.clone())).await,
        StatusCode::OK,
        "start a third time",
    );
    let late = query(&again)["state"].clone();
    api.clock.advance(std::time::Duration::from_secs(16 * 60));
    let expired = ok(
        call("GET", format!("{s}/remote-signing"), None).await,
        StatusCode::OK,
        "status after expiry",
    );
    assert_eq!(status(&expired), ("failed".into(), json!("expired")));
    refused(
        &call(
            "POST",
            format!("{s}/remote-signing/callback"),
            Some(json!({"state": late, "code": "late"})),
        )
        .await,
        "CS-RSP-0003",
        "late answer",
    );

    // The trail: each start and each failure, in order.
    let trail = ok(
        api.call(
            "GET",
            &format!("/api/v1/envelopes/{eid}/audit"),
            &a.auth,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "audit",
    );
    let types: Vec<&str> = trail["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["type"].as_str())
        .filter(|t| t.starts_with("recipient.remote"))
        .collect();
    assert_eq!(
        types,
        [
            "recipient.remote_signing_started",
            "recipient.remote_signing_failed",
            "recipient.remote_signing_started",
            "recipient.remote_signing_failed",
            "recipient.remote_signing_started",
            "recipient.remote_signing_failed",
        ]
    );
}

fn sha256(b: &[u8]) -> Vec<u8> {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b)
        .as_ref()
        .to_vec()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A simple signer cannot start a remote session (`409 CS-RSP-0007`).
#[tokio::test]
async fn only_a_remote_signer_with_an_offered_provider_starts() {
    let Some(api) = Api::new("ceremony_rsp_simple", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let env = common::flow::sent(&api, &a, 1, &[]).await;
    let eid = env["id"].as_str().unwrap().to_owned();
    let rid = env["recipients"][0]["id"].as_str().unwrap().to_owned();
    let token = invite(&api, &a, &eid, &rid).await;
    let (_, bound) = open(&api, &token).await;
    let h: Vec<(&str, &str)> = bound.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let r = api
        .call(
            "POST",
            &format!("/s/{token}/remote-signing"),
            &Auth::None,
            Some(json!({})),
            &h,
        )
        .await;
    refused(&r, "CS-RSP-0007", "simple signer");
}
