//! ERSD-01: `POST /api/v1/ersd-versions {text, language?}` publishes the account's
//! disclosure text with the next version and names it in `workflow_policy.ersd` in one
//! step, so a signer's view then carries `consent_required.url` and `GET
//! /s/{token}/disclosure` serves exactly that text; a new text is a new version the
//! signer must consent to; `GET /api/v1/ersd-versions` answers the current one with its
//! text and the history without; both need `admin:account` and reach only the caller's
//! account; a bad text is refused before anything is written.

// Tests may unwrap and index (CLAUDE.md, Rust); the scenario is one long test.
#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

mod common;

use axum::http::StatusCode;
use casual_sign_audit::Hash256;
use common::Rls;
use common::flow::{b64, invite, ok, open};
use common::harness::{Api, Auth, Tenant, pdf};
use serde_json::{Value, json};
use sqlx::Row;

const FIRST: &str = "First disclosure: paper copies on request; withdraw consent at any time.";
const SECOND: &str = "Second disclosure: the same rights, and a new contact address.";

fn hash_of(text: &str) -> String {
    Hash256::digest(text.as_bytes()).to_string()
}

async fn publish(api: &Api, t: &Tenant, body: Value) -> (StatusCode, Value) {
    let r = api
        .call("POST", "/api/v1/ersd-versions", &t.auth, Some(body), &[])
        .await;
    let v = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
    (r.status, v)
}

/// A sent envelope with one signer; answers its signer's link.
async fn sent(api: &Api, t: &Tenant) -> String {
    let e = ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            &t.auth,
            Some(json!({
                "subject": "ERSD-01", "status": "sent",
                "documents": [{"name": "d.pdf", "content_base64": b64(&pdf(1))}],
                "recipients": [{"ref": "s1", "type": "signer", "name": "Sig One",
                    "email": "one@example.test", "routing_order": 1}],
                "fields": [{"recipient": "s1", "document": 0, "type": "signature", "page": 1,
                    "x": 72, "y": 100, "width": 180, "height": 40, "required": true}],
            })),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "create",
    );
    let env = e["id"].as_str().unwrap();
    let rec = e["recipients"][0]["id"].as_str().unwrap();
    invite(api, t, env, rec).await
}

async fn read_disclosure(api: &Api, token: &str, h: &[(&'static str, String)]) -> Value {
    let hv: Vec<(&str, &str)> = h.iter().map(|(k, v)| (*k, v.as_str())).collect();
    ok(
        api.call(
            "GET",
            &format!("/s/{token}/disclosure"),
            &Auth::None,
            None,
            &hv,
        )
        .await,
        StatusCode::OK,
        "disclosure",
    )
}

#[tokio::test]
async fn publishing_through_the_api_gives_the_signer_the_disclosure_url_and_text() {
    let Some(api) = Api::new("ersd_publish", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;

    // Nothing published: the policy names no disclosure.
    let cur = ok(
        api.call("GET", "/api/v1/ersd-versions", &a.auth, None, &[])
            .await,
        StatusCode::OK,
        "list empty",
    );
    assert_eq!(cur, json!({"current": null, "items": []}));

    let (st, p1) = publish(&api, &a, json!({"text": FIRST})).await;
    assert_eq!(st, StatusCode::CREATED, "{p1}");
    assert_eq!(p1["version"], 1);
    assert_eq!(p1["label"], "1");
    assert_eq!(p1["language"], "en");
    assert_eq!(p1["sha256"], hash_of(FIRST));

    // The policy now names it, and the signer's view carries where to read it.
    let acct = ok(
        api.call("GET", "/api/v1/accounts/me", &a.auth, None, &[])
            .await,
        StatusCode::OK,
        "account",
    );
    assert_eq!(
        acct["settings"]["workflow_policy"]["ersd"],
        json!({"version": "1", "hash": hash_of(FIRST)})
    );
    let token = sent(&api, &a).await;
    let (view, h) = open(&api, &token).await;
    assert_eq!(
        view["consent_required"],
        json!({"version": "1", "sha256": hash_of(FIRST),
            "url": format!("/s/{token}/disclosure")})
    );
    let d = read_disclosure(&api, &token, &h).await;
    assert_eq!(
        d,
        json!({"version": "1", "sha256": hash_of(FIRST), "text": FIRST})
    );

    // A new text is version 2; the same link now asks for consent to it.
    let (st, p2) = publish(&api, &a, json!({"text": SECOND, "language": "en"})).await;
    assert_eq!(st, StatusCode::CREATED, "{p2}");
    assert_eq!(p2["version"], 2);
    let hv: Vec<(&str, &str)> = h.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let view = ok(
        api.call("GET", &format!("/s/{token}"), &Auth::None, None, &hv)
            .await,
        StatusCode::OK,
        "view",
    );
    assert_eq!(
        view["consent_required"],
        json!({"version": "2", "sha256": hash_of(SECOND),
            "url": format!("/s/{token}/disclosure")})
    );
    assert_eq!(read_disclosure(&api, &token, &h).await["text"], SECOND);

    // The Admin screen's read: the current one with its text, the history without.
    let cur = ok(
        api.call("GET", "/api/v1/ersd-versions", &a.auth, None, &[])
            .await,
        StatusCode::OK,
        "list",
    );
    assert_eq!(cur["current"]["label"], "2");
    assert_eq!(cur["current"]["version"], 2);
    assert_eq!(cur["current"]["text"], SECOND);
    let items = cur["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["version"], 2);
    assert_eq!(items[1]["version"], 1);
    assert!(items.iter().all(|i| i.get("text").is_none()), "{cur}");

    // Both rows were written once and never updated; the admin log names each publish
    // without its text.
    let n: i64 = sqlx::query(
        "SELECT count(*) FROM ersd_versions WHERE account_id = $1 AND published_at IS NOT NULL",
    )
    .bind(a.boot.account.0)
    .fetch_one(&api.db.admin)
    .await
    .unwrap()
    .get(0);
    assert_eq!(n, 2);
    let log = ok(
        api.call("GET", "/api/v1/admin-events?limit=100", &a.auth, None, &[])
            .await,
        StatusCode::OK,
        "admin log",
    );
    let published = log["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "ersd.published")
        .count();
    assert_eq!(published, 2, "{log}");
    let text = log.to_string();
    assert!(
        !text.contains("First disclosure") && !text.contains("Second disclosure"),
        "the text was logged"
    );

    // Another account sees none of it.
    let b = api.tenant("bravo").await;
    let cur = ok(
        api.call("GET", "/api/v1/ersd-versions", &b.auth, None, &[])
            .await,
        StatusCode::OK,
        "other account",
    );
    assert_eq!(cur, json!({"current": null, "items": []}));
    api.db.drop().await;
}

#[tokio::test]
async fn a_bad_disclosure_is_refused_before_anything_is_written() {
    let Some(api) = Api::new("ersd_refused", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    for (body, want) in [
        (json!({"text": ""}), StatusCode::UNPROCESSABLE_ENTITY),
        (json!({"text": "   \n "}), StatusCode::UNPROCESSABLE_ENTITY),
        (json!({"text": "a\u{0}b"}), StatusCode::UNPROCESSABLE_ENTITY),
        (
            json!({"text": FIRST, "language": "e"}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            json!({"text": FIRST, "language": "en_GB"}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            json!({"text": FIRST, "extra": 1}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            json!({"text": "x".repeat(100_001)}),
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
    ] {
        let (st, v) = publish(&api, &a, body.clone()).await;
        assert_eq!(st, want, "{body}: {v}");
    }
    let n: i64 = sqlx::query("SELECT count(*) FROM ersd_versions")
        .fetch_one(&api.db.admin)
        .await
        .unwrap()
        .get(0);
    assert_eq!(n, 0);
    let acct = ok(
        api.call("GET", "/api/v1/accounts/me", &a.auth, None, &[])
            .await,
        StatusCode::OK,
        "account",
    );
    assert!(acct["settings"].get("workflow_policy").is_none(), "{acct}");
    api.db.drop().await;
}
