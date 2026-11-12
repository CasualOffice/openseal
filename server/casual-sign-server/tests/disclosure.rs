//! UXW-34: the signer's view names who sent the envelope (`sender {name, email,
//! organisation}`), when it expires (`envelope.expires_at`) and where the disclosure is
//! read (`consent_required.url`); `GET /s/{token}/disclosure` serves the account's
//! published text for the disclosure its policy names, re-checked against the hash
//! consent records, under consent's rules (bound browser, every authentication passed),
//! records nothing, and never answers another link's or another account's text.

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
use common::harness::{Api, Auth, Resp, Tenant, pdf};
use serde_json::{Value, json};
use sqlx::Row;

const ALPHA_TEXT: &str =
    "Alpha disclosure: you may ask for paper copies, and withdraw consent at any time.";
const BRAVO_TEXT: &str = "Bravo disclosure: a different text, in another account.";

fn hash_of(text: &str) -> String {
    Hash256::digest(text.as_bytes()).to_string()
}

/// Publish `text` as the account's disclosure version 1 and name it in the policy as
/// `label`.
async fn publish(api: &Api, t: &Tenant, label: &str, text: &str) {
    sqlx::query(
        "INSERT INTO ersd_versions (id, account_id, version, language, text_sha256, body, published_at) \
         VALUES ($1, $2, 1, 'en', $3, $4, now())",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(t.boot.account.0)
    .bind(Hash256::digest(text.as_bytes()).0.to_vec())
    .bind(text)
    .execute(&api.db.admin)
    .await
    .unwrap();
    name_in_policy(api, t, label, &hash_of(text)).await;
}

async fn name_in_policy(api: &Api, t: &Tenant, label: &str, hash: &str) {
    let mut policy = serde_json::to_value(casual_sign_workflow::Policy::default()).unwrap();
    policy["ersd"] = json!({"version": label, "hash": hash});
    ok(
        api.call(
            "PATCH",
            "/api/v1/accounts/me",
            &t.auth,
            Some(json!({"settings": {"workflow_policy": policy}})),
            &[],
        )
        .await,
        StatusCode::OK,
        "policy",
    );
}

/// A sent envelope with one signer, expiring in 30 days; `auth` their requirements.
/// Answers the envelope and the signer's link.
async fn sent(api: &Api, t: &Tenant, auth: Value) -> (Value, String) {
    let mut signer = json!({"ref": "s1", "type": "signer", "name": "Sig One",
        "email": "one@example.test", "routing_order": 1, "auth": auth});
    if !auth.as_array().unwrap().is_empty() {
        signer["access_code"] = json!("right-4711");
    }
    let e = ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            &t.auth,
            Some(json!({
                "subject": "UXW-34", "status": "sent", "expires_in_days": 30,
                "documents": [{"name": "d.pdf", "content_base64": b64(&pdf(1))}],
                "recipients": [signer],
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
    let token = invite(api, t, &env, &rec).await;
    (e, token)
}

type Headers = Vec<(&'static str, String)>;

async fn get(api: &Api, path: &str, h: &Headers) -> Resp {
    let h: Vec<(&str, &str)> = h.iter().map(|(k, v)| (*k, v.as_str())).collect();
    api.call("GET", path, &Auth::None, None, &h).await
}

async fn events(api: &Api, env: &str) -> i64 {
    sqlx::query("SELECT count(*) FROM audit_events WHERE envelope_id = $1::uuid")
        .bind(env)
        .fetch_one(&api.db.admin)
        .await
        .unwrap()
        .get::<i64, _>(0)
}

fn refused(r: &Resp) -> (StatusCode, String) {
    (r.status, r.code())
}

#[tokio::test]
async fn the_view_names_the_sender_the_expiry_and_where_the_disclosure_is_read() {
    let Some(api) = Api::new("disclosure_view", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    ok(
        api.call(
            "PATCH",
            "/api/v1/accounts/me",
            &a.auth,
            Some(json!({"settings": {"branding": {"name": "Alpha Brand Ltd"}}})),
            &[],
        )
        .await,
        StatusCode::OK,
        "branding",
    );
    publish(&api, &a, "2026-1", ALPHA_TEXT).await;
    let (e, token) = sent(&api, &a, json!([])).await;
    let (view, _) = open(&api, &token).await;
    assert_eq!(
        view["sender"],
        json!({"name": "Admin", "email": a.email, "organisation": "Alpha Brand Ltd"})
    );
    assert_eq!(view["envelope"]["expires_at"], e["expires_at"]);
    assert!(view["envelope"]["expires_at"].is_string(), "{view}");
    assert_eq!(
        view["consent_required"],
        json!({"version": "2026-1", "sha256": hash_of(ALPHA_TEXT),
            "url": format!("/s/{token}/disclosure")})
    );

    // Without a brand name the organisation is the account's name; a policy naming a
    // text the account never published gives no `url` and the endpoint answers 404.
    let b = api.tenant("bravo").await;
    name_in_policy(&api, &b, "2026-9", &hash_of("never published")).await;
    let (_, tb) = sent(&api, &b, json!([])).await;
    let (vb, hb) = open(&api, &tb).await;
    assert_eq!(vb["sender"]["organisation"], "bravo");
    assert_eq!(
        vb["consent_required"],
        json!({"version": "2026-9", "sha256": hash_of("never published")})
    );
    let r = get(&api, &format!("/s/{tb}/disclosure"), &hb).await;
    assert_eq!(refused(&r), (StatusCode::NOT_FOUND, "CS-API-0002".into()));
    api.db.drop().await;
}

#[tokio::test]
async fn the_disclosure_is_served_after_authentication_in_the_bound_browser_and_records_nothing() {
    let Some(api) = Api::new("disclosure_auth", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    publish(&api, &a, "2026-1", ALPHA_TEXT).await;
    let (e, token) = sent(&api, &a, json!(["access_code"])).await;
    let env = e["id"].as_str().unwrap().to_owned();
    let path = format!("/s/{token}/disclosure");
    let (view, h) = open(&api, &token).await;

    // Another browser, then this one before the access code.
    let r = get(&api, &path, &vec![]).await;
    assert_eq!(refused(&r), (StatusCode::FORBIDDEN, "CS-AUTH-0009".into()));
    let r = get(&api, &path, &h).await;
    assert_eq!(refused(&r), (StatusCode::FORBIDDEN, "CS-AUTH-0003".into()));

    let hv: Vec<(&str, &str)> = h.iter().map(|(k, v)| (*k, v.as_str())).collect();
    ok(
        api.call(
            "POST",
            &format!("/s/{token}/authenticate"),
            &Auth::None,
            Some(json!({"method": "access_code", "code": "right-4711"})),
            &hv,
        )
        .await,
        StatusCode::OK,
        "authenticate",
    );
    let before = events(&api, &env).await;
    let d = ok(get(&api, &path, &h).await, StatusCode::OK, "disclosure");
    assert_eq!(
        d,
        json!({"version": "2026-1", "sha256": hash_of(ALPHA_TEXT), "language": "en", "text": ALPHA_TEXT})
    );
    assert_eq!(d["sha256"], view["consent_required"]["sha256"]);
    assert_eq!(
        events(&api, &env).await,
        before,
        "reading it records nothing"
    );

    // What it served is what consent takes.
    ok(
        api.call(
            "POST",
            &format!("/s/{token}/consent"),
            &Auth::None,
            Some(json!({"ersd_version": d["version"]})),
            &hv,
        )
        .await,
        StatusCode::OK,
        "consent",
    );

    // A stored text that no longer hashes to the policy's hash is never served, and the
    // view stops linking to it.
    sqlx::query("UPDATE ersd_versions SET body = body || ' (altered)' WHERE account_id = $1")
        .bind(a.boot.account.0)
        .execute(&api.db.admin)
        .await
        .unwrap();
    let r = get(&api, &path, &h).await;
    assert_eq!(
        refused(&r),
        (StatusCode::INTERNAL_SERVER_ERROR, "CS-API-0010".into())
    );
    let v = ok(
        get(&api, &format!("/s/{token}"), &h).await,
        StatusCode::OK,
        "view",
    );
    assert!(v["consent_required"].get("url").is_none(), "{v}");
    api.db.drop().await;
}

#[tokio::test]
async fn a_link_reads_only_its_own_accounts_disclosure_and_no_other_links_session() {
    let Some(api) = Api::new("disclosure_isolation", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let b = api.tenant("bravo").await;
    publish(&api, &a, "a-1", ALPHA_TEXT).await;
    publish(&api, &b, "b-1", BRAVO_TEXT).await;
    let (_, ta) = sent(&api, &a, json!([])).await;
    let (_, ta2) = sent(&api, &a, json!([])).await;
    let (_, tb) = sent(&api, &b, json!([])).await;
    let (_, ha) = open(&api, &ta).await;
    let (_, ha2) = open(&api, &ta2).await;
    let (_, hb) = open(&api, &tb).await;

    let da = ok(
        get(&api, &format!("/s/{ta}/disclosure"), &ha).await,
        StatusCode::OK,
        "alpha",
    );
    let db = ok(
        get(&api, &format!("/s/{tb}/disclosure"), &hb).await,
        StatusCode::OK,
        "bravo",
    );
    assert_eq!(da["text"], ALPHA_TEXT);
    assert_eq!(db["text"], BRAVO_TEXT);
    assert_eq!(db["version"], "b-1");

    // Another envelope's session (same account, then another account) opens nothing.
    for (token, h) in [(&ta, &ha2), (&ta, &hb), (&tb, &ha)] {
        let r = get(&api, &format!("/s/{token}/disclosure"), h).await;
        assert_eq!(refused(&r), (StatusCode::FORBIDDEN, "CS-AUTH-0009".into()));
        assert!(!String::from_utf8_lossy(&r.body).contains("disclosure:"));
    }
    // A link that resolves to nothing.
    let r = get(&api, &format!("/s/{}/disclosure", "x".repeat(43)), &ha).await;
    assert_eq!(
        refused(&r),
        (StatusCode::UNAUTHORIZED, "CS-AUTH-0002".into())
    );
    api.db.drop().await;
}
