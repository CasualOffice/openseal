//! Tenant isolation, generated from `api/openapi.yaml` (Phase 2 exit item 3, SEC-A04):
//! every operation with an id in its path is called by account B, holding every scope,
//! with account A's ids, and must answer `404 CS-API-0002`, exactly as for an id that
//! does not exist; then again with B's own envelope and A's document, recipient and
//! field ids. Run with row-level security on, and with it disabled on every table so
//! the server's own scoping stands alone. A's objects are unchanged afterwards.
//!
//! Ceremony paths (`/s/{token}`) carry no account principal: their token names its
//! account (stored hashed, SEC-A01), and are covered by the ceremony tests.

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

use std::collections::BTreeMap;

use axum::http::StatusCode;
use base64::Engine as _;
use common::Rls;
use common::harness::{Api, Auth, Tenant, openapi_operations, pdf};
use serde_json::{Value, json};

/// Every kind of object of one account, by path parameter.
async fn world(api: &Api, t: &Tenant) -> BTreeMap<&'static str, String> {
    let k = &t.auth;
    let e = api
        .call("POST", "/api/v1/envelopes", k, Some(json!({
            "subject": "Secret deal",
            "documents": [{"name": "d.pdf", "content_base64": base64::engine::general_purpose::STANDARD.encode(pdf(1))}],
            "recipients": [{"ref": "s", "type": "signer", "name": "S", "email": "s@example.test"}],
            "fields": [{"recipient": "s", "document": 0, "type": "signature", "page": 1, "x": 10, "y": 10, "width": 100, "height": 30}],
        })), &[])
        .await;
    assert_eq!(e.status, StatusCode::CREATED);
    let e = e.json();
    let user = api
        .call("POST", "/api/v1/users", k, Some(json!({"email": format!("u@{}.test", t.boot.account), "name": "U", "profile": "viewer"})), &[])
        .await
        .json();
    let client = api
        .call(
            "POST",
            "/api/v1/api-clients",
            k,
            Some(json!({"name": "c", "kind": "oauth_app", "scopes": ["envelopes:read"]})),
            &[],
        )
        .await
        .json();
    let template = api
        .call(
            "POST",
            "/api/v1/templates",
            k,
            Some(json!({"name": "T"})),
            &[],
        )
        .await
        .json();
    let hook = api
        .call("POST", "/api/v1/webhooks", k, Some(json!({"url": "https://hooks.example.com/x", "event_types": ["envelope.sent"], "secret_refs": ["k"]})), &[])
        .await
        .json();
    let s = |v: &Value| v.as_str().unwrap().to_owned();
    BTreeMap::from([
        ("envelope", s(&e["id"])),
        ("doc", s(&e["documents"][0]["id"])),
        ("r", s(&e["recipients"][0]["id"])),
        ("f", s(&e["fields"][0]["id"])),
        ("user", s(&user["id"])),
        ("client", s(&client["id"])),
        ("template", s(&template["id"])),
        ("webhook", s(&hook["id"])),
    ])
}

/// The path with `{…}` replaced from `ids`; `{id}` by the collection's object.
fn fill(path: &str, ids: &BTreeMap<&'static str, String>, envelope: &str) -> String {
    let id = if path.starts_with("/api/v1/envelopes/") {
        envelope.to_owned()
    } else if path.starts_with("/api/v1/users/") {
        ids["user"].clone()
    } else if path.starts_with("/api/v1/api-clients/") {
        ids["client"].clone()
    } else if path.starts_with("/api/v1/templates/") {
        ids["template"].clone()
    } else if path.starts_with("/api/v1/webhooks/") {
        ids["webhook"].clone()
    } else {
        panic!("no id kind for {path}")
    };
    path.replace("{id}", &id)
        .replace("{doc}", &ids["doc"])
        .replace("{r}", &ids["r"])
        .replace("{f}", &ids["f"])
}

async fn snapshot(api: &Api, a: &Tenant, ids: &BTreeMap<&'static str, String>) -> Vec<String> {
    let mut out = Vec::new();
    for p in [
        format!("/api/v1/envelopes/{}", ids["envelope"]),
        format!("/api/v1/envelopes/{}/audit", ids["envelope"]),
        format!("/api/v1/users/{}", ids["user"]),
        format!("/api/v1/api-clients/{}", ids["client"]),
        format!("/api/v1/templates/{}", ids["template"]),
        format!("/api/v1/webhooks/{}", ids["webhook"]),
    ] {
        let r = api.call("GET", &p, &a.auth, None, &[]).await;
        assert_eq!(r.status, StatusCode::OK, "{p}");
        out.push(String::from_utf8_lossy(&r.body).into_owned());
    }
    out
}

async fn another_accounts_ids_are_not_found_on_every_operation(rls: Rls) {
    let Some(api) = Api::new("isolation_generated", rls).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let b = api.tenant("bravo").await;
    let ids_a = world(&api, &a).await;
    let ids_b = world(&api, &b).await;
    let before = snapshot(&api, &a, &ids_a).await;
    let mut checked = 0;
    for ((method, path), _) in openapi_operations() {
        if !path.contains('{') || path.starts_with("/s/") {
            continue;
        }
        let mut variants = vec![fill(&path, &ids_a, &ids_a["envelope"])];
        if path.starts_with("/api/v1/envelopes/{id}/")
            && (path.contains("{doc}") || path.contains("{r}") || path.contains("{f}"))
        {
            // B's own envelope, A's sub-object.
            variants.push(fill(&path, &ids_a, &ids_b["envelope"]));
        }
        for concrete in variants {
            let body = (method != "GET" && method != "DELETE").then(|| json!({}));
            let r = api
                .call(&method, &concrete, &b.auth, body, &[("if-match", "\"v0\"")])
                .await;
            assert_eq!(
                (r.status, r.code().as_str()),
                (StatusCode::NOT_FOUND, "CS-API-0002"),
                "{method} {path} as another account ({rls:?}): {}",
                String::from_utf8_lossy(&r.body)
            );
            checked += 1;
        }
    }
    assert!(checked >= 40, "only {checked} operations checked");
    // B's lists show none of A's objects.
    for p in [
        "/api/v1/envelopes",
        "/api/v1/users",
        "/api/v1/api-clients",
        "/api/v1/templates",
        "/api/v1/webhooks",
    ] {
        let r = api.call("GET", p, &b.auth, None, &[]).await;
        let text = String::from_utf8_lossy(&r.body).into_owned();
        for id in ids_a.values() {
            assert!(!text.contains(id.as_str()), "{p} lists A's {id} ({rls:?})");
        }
    }
    assert_eq!(
        snapshot(&api, &a, &ids_a).await,
        before,
        "A changed ({rls:?})"
    );
    let _ = Auth::None;
    api.db.drop().await;
}

#[tokio::test]
async fn another_accounts_ids_are_not_found_with_rls() {
    another_accounts_ids_are_not_found_on_every_operation(Rls::On).await;
}

#[tokio::test]
async fn another_accounts_ids_are_not_found_without_rls() {
    another_accounts_ids_are_not_found_on_every_operation(Rls::Off).await;
}
