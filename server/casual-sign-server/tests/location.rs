//! Signer location through the ceremony (row GEO-01, docs/32 §2, docs/24 §3): with the
//! envelope's `capture_location` on, every recipient action records a location: the
//! device's fix, else the IP approximation from the GeoIP database with the reason
//! (`declined`, `unavailable`) and the database's name and build date, else the reason
//! alone. Never omitted, so a refusal never blocks signing. With it off, nothing is
//! recorded and the page is told not to ask, whatever the request says. The GeoIP
//! database is built in the test (`common/mmdb.rs`).

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines
)]

mod common;
#[path = "common/mmdb.rs"]
mod mmdb;

use axum::http::StatusCode;
use base64::Engine as _;
use casual_sign_server::geo::GeoIp;
use common::Rls;
use common::harness::{Api, Auth, Tenant, ceremony_cookie, pdf, png};
use serde_json::{Value, json};

const DB: &str = "OpenSeal-Test-City 2026-11-06";

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// A sent one-signer envelope; answers its id, the signer's ceremony path and the
/// signature field's id.
async fn envelope(api: &Api, t: &Tenant, capture: bool) -> (String, String, String) {
    let e = api
        .call("POST", "/api/v1/envelopes", &t.auth, Some(json!({
            "subject": "Where", "status": "sent",
            "signing_options": {"capture_location": capture},
            "documents": [{"name": "w.pdf", "content_base64": b64(&pdf(1))}],
            "recipients": [{"ref": "s", "type": "signer", "name": "Wanda Where", "email": "w@example.test"}],
            "fields": [{"recipient": "s", "document": 0, "type": "signature", "page": 1, "x": 72, "y": 600, "width": 180, "height": 40, "required": true}],
        })), &[])
        .await;
    assert_eq!(e.status, StatusCode::CREATED, "{:?}", e.json());
    let e = e.json();
    // The setting is part of the envelope's API, and absent when off.
    assert_eq!(
        e["signing_options"].get("capture_location"),
        capture.then_some(&Value::Bool(true)),
        "{}",
        e["signing_options"]
    );
    let id = e["id"].as_str().unwrap().to_owned();
    let token = casual_sign_server::issue_invitation_token(
        &api.st,
        t.boot.account,
        casual_sign_store::EnvelopeId(id.parse().unwrap()),
        casual_sign_store::RecipientId(e["recipients"][0]["id"].as_str().unwrap().parse().unwrap()),
        std::time::Duration::from_secs(3600),
    )
    .await
    .unwrap();
    let field = e["fields"][0]["id"].as_str().unwrap().to_owned();
    (id, format!("/s/{token}"), field)
}

async fn post(api: &Api, path: &str, body: Value, cookie: &str) -> Value {
    let r = api
        .call("POST", path, &Auth::None, Some(body), &[("cookie", cookie)])
        .await;
    assert_eq!(r.status, StatusCode::OK, "{path}: {:?}", r.json());
    r.json()
}

async fn open(api: &Api, s: &str, body: Value) -> (Value, String) {
    let r = api
        .call(
            "POST",
            &format!("{s}/session"),
            &Auth::None,
            Some(body),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let cookie = ceremony_cookie(&r);
    (r.json(), cookie)
}

/// The location recorded on the last event of `kind`, or `Value::Null`.
async fn location(api: &Api, t: &Tenant, env: &str, kind: &str) -> Value {
    let a = api
        .call(
            "GET",
            &format!("/api/v1/envelopes/{env}/audit"),
            &t.auth,
            None,
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::OK);
    let items = a.json()["items"].as_array().unwrap().clone();
    let e = items
        .iter()
        .rev()
        .find(|e| e["type"] == kind)
        .unwrap_or_else(|| panic!("no {kind}"));
    e["event"]["context"]
        .get("location")
        .cloned()
        .unwrap_or(Value::Null)
}

/// Sign: view (declined), adopt, finish with the device's fix.
async fn sign(api: &Api, s: &str, cookie: &str, field: &str, env: &Value) {
    let doc = env["envelope"]["documents"][0]["id"].as_str().unwrap();
    post(
        api,
        &format!("{s}/documents/{doc}/viewed"),
        json!({"pages_seen": [1], "location": {"declined": true}}),
        cookie,
    )
    .await;
    post(
        api,
        &format!("{s}/adopt"),
        json!({"mark": "signature", "method": "draw", "image_base64": b64(&png())}),
        cookie,
    )
    .await;
    post(
        api,
        &format!("{s}/finish"),
        json!({"values": [{"field": field, "value": {"signature": "sig-w"}}],
               "location": {"latitude": 48.856_614, "longitude": 2.352_222, "accuracy_m": 14.2}}),
        cookie,
    )
    .await;
}

#[tokio::test]
async fn capture_on_records_the_device_else_the_ip_with_its_reason() {
    let Some(api) = Api::new("location_on", Rls::On).await else {
        return;
    };
    api.st
        .set_geoip(GeoIp::from_bytes(mmdb::test_mmdb()).unwrap());
    let t = api.tenant("alpha").await;

    // An address the database knows.
    api.set_peer("1.2.3.4:5000");
    let (env, s, field) = envelope(&api, &t, true).await;
    let (view, cookie) = open(&api, &s, json!({})).await;
    assert_eq!(view["capture_location"], true, "the page is told to ask");
    // The opening: the page has not asked yet, so the device gave nothing.
    assert_eq!(
        location(&api, &t, &env, "recipient.delivered").await,
        json!({"source": "ip", "reason": "unavailable", "database": DB,
               "latitude": 51.5, "longitude": -0.125, "country": "GB"})
    );
    sign(&api, &s, &cookie, &field, &view).await;
    // The signer declined: the approximation, flagged so.
    assert_eq!(
        location(&api, &t, &env, "recipient.viewed_document").await,
        json!({"source": "ip", "reason": "declined", "database": DB,
               "latitude": 51.5, "longitude": -0.125, "country": "GB"})
    );
    // The device's fix, rounded to 4 places, radius rounded up.
    assert_eq!(
        location(&api, &t, &env, "recipient.signed").await,
        json!({"source": "device", "accuracy_m": 15, "latitude": 48.8566, "longitude": 2.3522})
    );

    // An address the database does not know: the reason and the database, no place.
    api.set_peer("200.1.1.1:5000");
    let (env2, s2, _) = envelope(&api, &t, true).await;
    let (_, c2) = open(&api, &s2, json!({"location": {"declined": true}})).await;
    assert_eq!(
        location(&api, &t, &env2, "recipient.delivered").await,
        json!({"source": "ip", "reason": "declined", "database": DB})
    );
    post(
        &api,
        &format!("{s2}/decline"),
        json!({"reason": "Not here"}),
        &c2,
    )
    .await;
    assert_eq!(
        location(&api, &t, &env2, "recipient.declined").await,
        json!({"source": "ip", "reason": "unavailable", "database": DB})
    );

    // Withdrawing consent records it too (a disclosure to consent to first).
    let mut policy = serde_json::to_value(casual_sign_workflow::Policy::default()).unwrap();
    policy["ersd"] = json!({"version": "2026-1", "hash": format!("sha256:{}", "ab".repeat(32))});
    let p = api
        .call(
            "PATCH",
            "/api/v1/accounts/me",
            &t.auth,
            Some(json!({"settings": {"workflow_policy": policy}})),
            &[],
        )
        .await;
    assert_eq!(p.status, StatusCode::OK, "{:?}", p.json());
    api.set_peer("1.2.3.4:5000");
    let (env3, s3, _) = envelope(&api, &t, true).await;
    let (_, c3) = open(&api, &s3, json!({})).await;
    post(
        &api,
        &format!("{s3}/consent"),
        json!({"ersd_version": "2026-1"}),
        &c3,
    )
    .await;
    post(
        &api,
        &format!("{s3}/withdraw-consent"),
        json!({"location": {"latitude": 1.0, "longitude": 2.0, "accuracy_m": 3}}),
        &c3,
    )
    .await;
    assert_eq!(
        location(&api, &t, &env3, "recipient.declined").await["source"],
        "device"
    );
    api.db.drop().await;
}

#[tokio::test]
async fn capture_on_without_a_database_records_the_reason_alone() {
    let Some(api) = Api::new("location_no_db", Rls::On).await else {
        return;
    };
    let t = api.tenant("alpha").await;
    api.set_peer("1.2.3.4:5000");
    let (env, s, field) = envelope(&api, &t, true).await;
    let (view, cookie) = open(&api, &s, json!({})).await;
    assert_eq!(
        location(&api, &t, &env, "recipient.delivered").await,
        json!({"source": "ip", "reason": "unavailable"})
    );
    sign(&api, &s, &cookie, &field, &view).await;
    assert_eq!(
        location(&api, &t, &env, "recipient.viewed_document").await,
        json!({"source": "ip", "reason": "declined"})
    );
    assert_eq!(
        location(&api, &t, &env, "recipient.signed").await["source"],
        "device"
    );
    api.db.drop().await;
}

#[tokio::test]
async fn capture_off_records_nothing_and_never_asks() {
    let Some(api) = Api::new("location_off", Rls::On).await else {
        return;
    };
    api.st
        .set_geoip(GeoIp::from_bytes(mmdb::test_mmdb()).unwrap());
    let t = api.tenant("alpha").await;
    api.set_peer("1.2.3.4:5000");
    let (env, s, field) = envelope(&api, &t, false).await;
    // A page that sends a location anyway changes nothing.
    let (view, cookie) = open(
        &api,
        &s,
        json!({"location": {"latitude": 1.0, "longitude": 2.0, "accuracy_m": 3}}),
    )
    .await;
    assert_eq!(
        view["capture_location"], false,
        "the page is told not to ask"
    );
    sign(&api, &s, &cookie, &field, &view).await;
    for kind in [
        "recipient.delivered",
        "recipient.viewed_document",
        "recipient.signed",
    ] {
        assert_eq!(
            location(&api, &t, &env, kind).await,
            Value::Null,
            "{kind} carries a location"
        );
    }
    api.db.drop().await;
}
