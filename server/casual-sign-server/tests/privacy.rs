//! ASVS-16 and ASVS-18 (ASVS 8.3.2, 8.3.8) through the router on PostgreSQL: a member's
//! export holds their own data and nothing of another member or workspace, is logged and
//! rate-limited; erasure by the person or an administrator pseudonymises the member,
//! records `member.erased`, and is refused where it would strand the workspace or reach
//! another workspace's member; retention rules, the dry run, legal holds and a purge
//! request answer per object and leave the audit chain verifying.

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

use std::time::Duration;

use axum::http::StatusCode;
use casual_sign_store::EnvelopeId;
use common::Rls;
use common::flow::sent;
use common::harness::{Api, Auth, PASSWORD, Resp, Tenant};
use serde_json::{Value, json};

fn is(r: &Resp, status: StatusCode, code: Option<&str>, what: &str) -> Value {
    assert_eq!(r.status, status, "{what}: {:?}", r.json());
    if let Some(c) = code {
        assert_eq!(r.code(), c, "{what}: {:?}", r.json());
    }
    r.json()
}

async fn member(api: &Api, t: &Tenant, email: &str, profile: &str) -> String {
    let r = api
        .call(
            "POST",
            "/api/v1/users",
            &t.auth,
            Some(json!({"email": email, "name": "Bo Member", "profile": profile, "password": PASSWORD})),
            &[],
        )
        .await;
    is(&r, StatusCode::CREATED, None, "member")["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn admin_actions(api: &Api, t: &Tenant) -> Vec<String> {
    let r = api
        .call("GET", "/api/v1/admin-events?limit=200", &t.auth, None, &[])
        .await;
    is(&r, StatusCode::OK, None, "admin events")["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap().to_owned())
        .collect()
}

async fn chain_verifies(api: &Api, t: &Tenant, env: &str) {
    let mut tx = api
        .db
        .store
        .for_account(t.boot.account)
        .begin()
        .await
        .unwrap();
    tx.audit()
        .chain(EnvelopeId(uuid::Uuid::parse_str(env).unwrap()))
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn an_export_holds_the_callers_own_data_and_nothing_of_another_member_or_workspace() {
    let Some(api) = Api::new("privacy_export", Rls::On).await else {
        return;
    };
    let a = api.tenant("expa").await;
    let b = api.tenant("expb").await;
    let mine = sent(&api, &a, 1, &[]).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let theirs = sent(&api, &b, 1, &[]).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    // Another member of the same workspace, with an envelope of their own.
    member(&api, &a, "bo@expa.example.test", "sender").await;
    let bo = api.login("bo@expa.example.test", PASSWORD).await;
    let bos = api
        .call(
            "POST",
            "/api/v1/envelopes",
            &bo,
            Some(json!({"subject": "Bo's own"})),
            &[],
        )
        .await;
    let bos = is(&bos, StatusCode::CREATED, None, "bo's draft")["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let me = api.login(&a.email, PASSWORD).await;
    let r = api
        .call("GET", "/api/v1/users/me/export", &me, None, &[])
        .await;
    let x = is(&r, StatusCode::OK, None, "export");
    assert_eq!(x["format"], "openseal.personal-data-export");
    assert_eq!(x["user"]["email"], a.email.as_str());
    assert_eq!(x["workspace"]["id"], a.boot.account.0.to_string());
    let ids: Vec<&str> = x["envelopes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, [mine.as_str()]);
    assert_eq!(
        x["envelopes"][0]["links"]["certificate"],
        format!("/api/v1/envelopes/{mine}/certificate")
    );
    assert!(!x["sessions"].as_array().unwrap().is_empty());
    assert!(x["kept"].as_str().unwrap().contains("append-only"));
    let text = String::from_utf8(r.body.to_vec()).unwrap();
    for other in [
        theirs.as_str(),
        bos.as_str(),
        "bo@expa.example.test",
        b.email.as_str(),
    ] {
        assert!(!text.contains(other), "the export names {other}");
    }

    // Logged as a read of personal data, by id only.
    let lines = api.security.json();
    assert!(
        lines
            .iter()
            .any(|l| l["kind"] == "data.document_read" && l["route"] == "/api/v1/users/me/export"),
        "no security event for the export"
    );
    assert!(!api.security.lines().join("\n").contains(&a.email));

    // At most three a minute per user.
    for _ in 0..2 {
        let r = api
            .call("GET", "/api/v1/users/me/export", &me, None, &[])
            .await;
        is(&r, StatusCode::OK, None, "export again");
    }
    let r = api
        .call("GET", "/api/v1/users/me/export", &me, None, &[])
        .await;
    is(&r, StatusCode::TOO_MANY_REQUESTS, None, "fourth export");
    api.clock.advance(Duration::from_secs(61));
    let r = api
        .call("GET", "/api/v1/users/me/export", &bo, None, &[])
        .await;
    let x = is(&r, StatusCode::OK, None, "bo's export");
    let ids: Vec<&str> = x["envelopes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, [bos.as_str()]);
}

#[tokio::test]
async fn a_member_erases_themselves_and_an_administrator_erases_a_member() {
    let Some(api) = Api::new("privacy_erase", Rls::On).await else {
        return;
    };
    let a = api.tenant("era").await;
    let b = api.tenant("erb").await;

    // The workspace's only administrator may not erase themselves.
    let admin = api.login(&a.email, PASSWORD).await;
    let r = api
        .call("DELETE", "/api/v1/users/me", &admin, None, &[])
        .await;
    let p = is(&r, StatusCode::CONFLICT, Some("CS-API-0018"), "last admin");
    assert_eq!(p["detail"], "last administrator");
    // With a second administrator, the first is still the organization's owner, who is
    // removed there first; the second, no organization administrator, may go.
    member(&api, &a, "ad@era.example.test", "admin").await;
    let r = api
        .call("DELETE", "/api/v1/users/me", &admin, None, &[])
        .await;
    let p = is(&r, StatusCode::CONFLICT, Some("CS-API-0018"), "owner");
    assert_eq!(p["detail"], "organization administrator");
    let ad = api.login("ad@era.example.test", PASSWORD).await;
    let r = api.call("DELETE", "/api/v1/users/me", &ad, None, &[]).await;
    is(&r, StatusCode::NO_CONTENT, None, "a second administrator");
    // Never through an API key.
    let r = api
        .call("DELETE", "/api/v1/users/me", &a.auth, None, &[])
        .await;
    is(&r, StatusCode::UNPROCESSABLE_ENTITY, None, "a key");

    // A sender who sent an envelope erases themselves.
    let bo_id = member(&api, &a, "bo@era.example.test", "sender").await;
    let bo = api.login("bo@era.example.test", PASSWORD).await;
    let env = api
        .call(
            "POST",
            "/api/v1/envelopes",
            &bo,
            Some(json!({"subject": "Bo's agreement"})),
            &[],
        )
        .await;
    let env = is(&env, StatusCode::CREATED, None, "bo's draft")["id"]
        .as_str()
        .unwrap()
        .to_owned();
    // Not after the step-up window.
    api.clock.advance(Duration::from_secs(6 * 60));
    let r = api.call("DELETE", "/api/v1/users/me", &bo, None, &[]).await;
    is(&r, StatusCode::FORBIDDEN, Some("CS-AUTH-0013"), "stale");
    let r = api
        .call(
            "POST",
            "/api/v1/auth/reauthenticate",
            &bo,
            Some(json!({"password": PASSWORD})),
            &[],
        )
        .await;
    is(&r, StatusCode::OK, None, "reauthenticate");
    let r = api.call("DELETE", "/api/v1/users/me", &bo, None, &[]).await;
    is(&r, StatusCode::NO_CONTENT, None, "erase me");
    // Their session ended; their sign-in no longer works.
    let r = api.call("GET", "/api/v1/users/me", &bo, None, &[]).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = api
        .call(
            "POST",
            "/api/v1/auth/login",
            &Auth::None,
            Some(json!({"email": "bo@era.example.test", "password": PASSWORD})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // The administrator sees the marker, not the person; the envelope stays, its chain
    // verifies.
    let r = api
        .call("GET", &format!("/api/v1/users/{bo_id}"), &a.auth, None, &[])
        .await;
    let u = is(&r, StatusCode::OK, None, "erased member");
    assert_eq!(u["name"], "Erased user");
    assert!(u["email"].as_str().unwrap().ends_with("@erased.invalid"));
    let r = api
        .call(
            "GET",
            &format!("/api/v1/envelopes/{env}"),
            &a.auth,
            None,
            &[],
        )
        .await;
    is(&r, StatusCode::OK, None, "the envelope stays");
    chain_verifies(&api, &a, &env).await;
    assert!(
        admin_actions(&api, &a)
            .await
            .contains(&"member.erased".to_owned())
    );
    let found: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM users WHERE email_normalized = 'bo@era.example.test'",
    )
    .fetch_one(&api.db.admin)
    .await
    .unwrap();
    assert_eq!(found, 0, "the address is gone");

    // An administrator erases another member.
    let cy_id = member(&api, &a, "cy@era.example.test", "viewer").await;
    let r = api
        .call(
            "POST",
            &format!("/api/v1/users/{cy_id}/erase"),
            &b.auth,
            None,
            &[],
        )
        .await;
    is(
        &r,
        StatusCode::NOT_FOUND,
        None,
        "another workspace's member",
    );
    let cy = api.login("cy@era.example.test", PASSWORD).await;
    let r = api
        .call(
            "POST",
            &format!("/api/v1/users/{cy_id}/erase"),
            &cy,
            None,
            &[],
        )
        .await;
    is(&r, StatusCode::FORBIDDEN, None, "a viewer");
    let admin_id = a.boot.admin.0.to_string();
    let r = api
        .call(
            "POST",
            &format!("/api/v1/users/{admin_id}/erase"),
            &admin,
            None,
            &[],
        )
        .await;
    is(&r, StatusCode::UNPROCESSABLE_ENTITY, None, "oneself");
    let r = api
        .call(
            "POST",
            &format!("/api/v1/users/{cy_id}/erase"),
            &a.auth,
            None,
            &[],
        )
        .await;
    is(&r, StatusCode::NO_CONTENT, None, "erase cy");
    let r = api
        .call(
            "POST",
            &format!("/api/v1/users/{cy_id}/erase"),
            &a.auth,
            None,
            &[],
        )
        .await;
    is(&r, StatusCode::NOT_FOUND, None, "erased already");
    let r = api.call("GET", "/api/v1/users/me", &cy, None, &[]).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "cy's session ended");
    // The erasures are administrative security events, by id.
    let lines = api.security.json();
    assert!(
        lines
            .iter()
            .any(|l| l["kind"] == "admin.change" && l["route"] == "/api/v1/users/{id}/erase")
    );
    assert!(
        lines
            .iter()
            .any(|l| l["kind"] == "admin.change" && l["route"] == "/api/v1/users/me")
    );
}

#[tokio::test]
async fn retention_rules_a_dry_run_holds_and_a_purge_request_answer_per_object() {
    let Some(api) = Api::new("privacy_retention", Rls::On).await else {
        return;
    };
    let a = api.tenant("reta").await;
    let b = api.tenant("retb").await;

    let r = api
        .call("GET", "/api/v1/retention", &a.auth, None, &[])
        .await;
    let x = is(&r, StatusCode::OK, None, "rules");
    for c in ["draft", "ended", "completed", "sessions"] {
        assert!(x["keep_days"][c].is_null(), "{c} is kept by default");
    }
    for bad in [
        json!({"keep_days": {"bogus": 3}}),
        json!({"keep_days": {"ended": 0}}),
        json!({"keep_days": {"ended": 40000}}),
    ] {
        let r = api
            .call("PUT", "/api/v1/retention", &a.auth, Some(bad.clone()), &[])
            .await;
        is(&r, StatusCode::UNPROCESSABLE_ENTITY, None, &bad.to_string());
    }
    let r = api
        .call(
            "PUT",
            "/api/v1/retention",
            &a.auth,
            Some(json!({"keep_days": {"ended": 30, "draft": 90}})),
            &[],
        )
        .await;
    let x = is(&r, StatusCode::OK, None, "set");
    assert_eq!(x["keep_days"]["ended"], 30);
    assert_eq!(x["keep_days"]["draft"], 90);
    assert!(x["keep_days"]["completed"].is_null());
    let r = api
        .call("GET", "/api/v1/retention", &b.auth, None, &[])
        .await;
    assert!(is(&r, StatusCode::OK, None, "b's")["keep_days"]["ended"].is_null());
    assert!(
        admin_actions(&api, &a)
            .await
            .contains(&"retention.rule_set".to_owned())
    );

    // A voided envelope expires after 30 days; the dry run lists it and changes nothing.
    let voided = sent(&api, &a, 1, &[]).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let r = api
        .call(
            "POST",
            &format!("/api/v1/envelopes/{voided}/void"),
            &a.auth,
            Some(json!({"reason": "Wrong party"})),
            &[],
        )
        .await;
    is(&r, StatusCode::OK, None, "void");
    let live = sent(&api, &a, 1, &[]).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    api.clock.advance(Duration::from_secs(31 * 86_400));
    let r = api
        .call("GET", "/api/v1/retention/preview", &a.auth, None, &[])
        .await;
    let p = is(&r, StatusCode::OK, None, "preview");
    assert_eq!(p["counts"]["ended"], 1);
    assert_eq!(p["envelopes"][0]["id"], voided.as_str());
    assert_eq!(p["envelopes"][0]["class"], "ended");
    assert_eq!(p["envelopes"].as_array().unwrap().len(), 1, "{p}");
    let r = api
        .call("GET", "/api/v1/retention/preview", &a.auth, None, &[])
        .await;
    assert_eq!(is(&r, StatusCode::OK, None, "again")["counts"]["ended"], 1);
    let r = api
        .call("GET", "/api/v1/retention/preview", &b.auth, None, &[])
        .await;
    assert_eq!(
        is(&r, StatusCode::OK, None, "b's preview")["counts"]["ended"],
        0
    );

    // A hold keeps it, per object: another workspace cannot hold it.
    let r = api
        .call(
            "PUT",
            &format!("/api/v1/envelopes/{voided}/legal-hold"),
            &b.auth,
            None,
            &[],
        )
        .await;
    is(&r, StatusCode::NOT_FOUND, None, "b holds a's envelope");
    let r = api
        .call(
            "PUT",
            &format!("/api/v1/envelopes/{voided}/legal-hold"),
            &a.auth,
            None,
            &[],
        )
        .await;
    assert_eq!(is(&r, StatusCode::OK, None, "hold")["legal_hold"], true);
    let r = api
        .call("GET", "/api/v1/retention/preview", &a.auth, None, &[])
        .await;
    let p = is(&r, StatusCode::OK, None, "held preview");
    assert_eq!(p["counts"]["ended"], 0);
    assert_eq!(p["held"], 1);
    let r = api
        .call(
            "POST",
            &format!("/api/v1/envelopes/{voided}/purge"),
            &a.auth,
            None,
            &[],
        )
        .await;
    is(&r, StatusCode::CONFLICT, Some("CS-API-0019"), "purge held");
    let r = api
        .call(
            "DELETE",
            &format!("/api/v1/envelopes/{voided}/legal-hold"),
            &a.auth,
            None,
            &[],
        )
        .await;
    assert_eq!(is(&r, StatusCode::OK, None, "release")["legal_hold"], false);
    let actions = admin_actions(&api, &a).await;
    for want in ["envelope.legal_hold_set", "envelope.legal_hold_released"] {
        assert!(actions.contains(&want.to_owned()), "{want}");
    }

    // A purge request: refused in flight and across workspaces; done once otherwise,
    // appending `envelope.purged` with the chain still verifying.
    let r = api
        .call(
            "POST",
            &format!("/api/v1/envelopes/{live}/purge"),
            &a.auth,
            None,
            &[],
        )
        .await;
    is(&r, StatusCode::CONFLICT, Some("CS-WF-0001"), "in flight");
    let r = api
        .call(
            "POST",
            &format!("/api/v1/envelopes/{voided}/purge"),
            &b.auth,
            None,
            &[],
        )
        .await;
    is(&r, StatusCode::NOT_FOUND, None, "b purges a's envelope");
    let r = api
        .call(
            "POST",
            &format!("/api/v1/envelopes/{voided}/purge"),
            &a.auth,
            None,
            &[],
        )
        .await;
    is(&r, StatusCode::ACCEPTED, None, "purge");
    let r = api
        .call(
            "POST",
            &format!("/api/v1/envelopes/{voided}/purge"),
            &a.auth,
            None,
            &[],
        )
        .await;
    is(
        &r,
        StatusCode::CONFLICT,
        Some("CS-WF-0001"),
        "purged already",
    );
    chain_verifies(&api, &a, &voided).await;
    let purged: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE envelope_id = $1::uuid \
         AND event_type = 'envelope.purged'",
    )
    .bind(&voided)
    .fetch_one(&api.db.admin)
    .await
    .unwrap();
    assert_eq!(purged, 1);
    let jobs = common::flow::jobs(&api, &voided).await;
    assert!(jobs.contains(&"purge_data".to_owned()), "{jobs:?}");
    let r = api
        .call("GET", "/api/v1/retention/preview", &a.auth, None, &[])
        .await;
    assert_eq!(is(&r, StatusCode::OK, None, "after")["counts"]["ended"], 0);
}
