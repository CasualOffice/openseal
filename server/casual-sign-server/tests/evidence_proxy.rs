//! Evidence capture behind a configured proxy (see `evidence.rs`).

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use axum::http::StatusCode;
use base64::Engine as _;
use casual_sign_server::net::Cidr;
use common::Rls;
use common::harness::{Api, Auth, pdf};
use serde_json::{Value, json};

const UA: &str = "EvidenceBrowser/7.1 (test)";

async fn events(api: &Api, auth: &Auth, env: &str) -> Vec<Value> {
    let a = api
        .call(
            "GET",
            &format!("/api/v1/envelopes/{env}/audit"),
            auth,
            None,
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::OK);
    a.json()["items"].as_array().unwrap().clone()
}

fn context<'a>(events: &'a [Value], kind: &str) -> &'a Value {
    let e = events
        .iter()
        .rev()
        .find(|e| e["type"] == kind)
        .unwrap_or_else(|| panic!("no {kind}"));
    &e["event"]["context"]
}

async fn sent_envelope(api: &Api, auth: &Auth, headers: &[(&str, &str)]) -> (String, String) {
    let e = api
        .call("POST", "/api/v1/envelopes", auth, Some(json!({
            "subject": "Evidence", "status": "sent",
            "documents": [{"name": "e.pdf", "content_base64": base64::engine::general_purpose::STANDARD.encode(pdf(1))}],
            "recipients": [{"ref": "s", "type": "signer", "name": "Ev", "email": "ev@example.test"}],
            "fields": [{"recipient": "s", "document": 0, "type": "signature", "page": 1, "x": 10, "y": 10, "width": 100, "height": 30, "required": true}],
        })), headers)
        .await;
    assert_eq!(e.status, StatusCode::CREATED, "{:?}", e.json());
    let e = e.json();
    (
        e["id"].as_str().unwrap().to_owned(),
        e["recipients"][0]["id"].as_str().unwrap().to_owned(),
    )
}

#[tokio::test]
async fn forwarding_headers_count_only_from_configured_proxies() {
    let Some(api) = Api::with("evidence_trusted", Rls::On, |c| {
        c.trusted_proxies = vec![Cidr::parse("10.0.0.0/8").unwrap()];
    })
    .await
    else {
        return;
    };
    let a = api.tenant("alpha").await;
    // Through the proxy: the right-most hop that is not a proxy, not the left-most claim.
    api.set_peer("10.0.0.5:1234");
    let (env, _) = sent_envelope(
        &api,
        &a.auth,
        &[
            ("user-agent", UA),
            ("x-forwarded-for", "1.2.3.4, 203.0.113.9, 10.0.0.7"),
        ],
    )
    .await;
    let ev = events(&api, &a.auth, &env).await;
    assert_eq!(context(&ev, "envelope.created")["ip"], "203.0.113.9");
    // Straight from the internet, the same header is ignored.
    api.set_peer("192.0.2.200:5555");
    let (env, _) = sent_envelope(&api, &a.auth, &[("x-forwarded-for", "203.0.113.9")]).await;
    let ev = events(&api, &a.auth, &env).await;
    assert_eq!(context(&ev, "envelope.created")["ip"], "192.0.2.200");
    api.db.drop().await;
}
