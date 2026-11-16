//! ORG-08: the organization policy (docs/23 §3, `SEC-O03`, `SEC-O11`). An owner sets
//! locked and tighten-only keys; a workspace write that changes a locked setting, or
//! sets a tighten-only one looser, is `422 CS-ORG-0002` naming the key; an unrelated
//! edit still saves; the organization's second-factor level applies on the next request
//! without rewriting the workspace; loosening a security key is an owner's alone
//! (`403 CS-ORG-0013`); and an envelope sent before the change is unaffected by it.

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

use axum::http::StatusCode;
use common::Rls;
use common::flow::sent;
use common::harness::{Api, Auth, PASSWORD, Resp};
use serde_json::{Value, json};

fn is(r: &Resp, status: StatusCode, code: Option<&str>, what: &str) -> Value {
    assert_eq!(r.status, status, "{what}: {:?}", r.json());
    if let Some(c) = code {
        assert_eq!(r.code(), c, "{what}");
    }
    r.json()
}

/// A complete workflow policy with `date_format` (the server takes it whole).
fn workflow_policy(date_format: &str) -> Value {
    json!({
        "max_auth_attempts": 3, "max_recipients": 100, "max_fields": 3000,
        "max_documents": 100, "ersd": null, "expiry_warning_days": 0,
        "seal_retry_ms": 60000, "date_format": date_format,
    })
}

async fn patch_settings(api: &Api, auth: &Auth, settings: Value) -> Resp {
    api.call(
        "PATCH",
        "/api/v1/accounts/me",
        auth,
        Some(json!({ "settings": settings })),
        &[],
    )
    .await
}

async fn patch_policy(api: &Api, auth: &Auth, policy: Value) -> Resp {
    api.call(
        "PATCH",
        "/api/v1/organizations/me",
        auth,
        Some(json!({ "policy": policy })),
        &[],
    )
    .await
}

async fn add_user(api: &Api, key: &Auth, email: &str, profile: &str) -> String {
    let r = api
        .call(
            "POST",
            "/api/v1/users",
            key,
            Some(
                json!({"email": email, "name": "Someone", "profile": profile,
                "password": PASSWORD}),
            ),
            &[],
        )
        .await;
    is(&r, StatusCode::CREATED, None, email)["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn organization_policy(rls: Rls) {
    let Some(api) = Api::new(&format!("organization_policy_{rls:?}"), rls).await else {
        return;
    };
    // alpha: the install's organization; its bootstrap admin is its owner.
    let alpha = api.tenant("alpha").await;
    let owner = api.login(&alpha.email, PASSWORD).await;
    let key = &alpha.auth;

    // The workspace's own choices before any organization policy.
    let r = patch_settings(
        &api,
        key,
        json!({"mfa_policy": "optional", "first_reminder_days": 5,
            "workflow_policy": workflow_policy("yyyy_mm_dd"), "branding": {"name": "Alpha"}}),
    )
    .await;
    is(&r, StatusCode::OK, None, "workspace settings");

    // A sender with no factor, and an organization admin who is not an owner.
    let m_email = "member@alpha.example.test";
    add_user(&api, key, m_email, "sender").await;
    let member = api.login(m_email, PASSWORD).await;
    let r = api
        .call("GET", "/api/v1/envelopes", &member, None, &[])
        .await;
    is(&r, StatusCode::OK, None, "member before");
    let a_email = "orgadmin@alpha.example.test";
    let a_id = add_user(&api, key, a_email, "admin").await;
    sqlx::query(
        "INSERT INTO organization_admins (organization_id, user_id, role, created_at) \
         VALUES ($1, $2::uuid, 'admin', now())",
    )
    .bind(alpha.boot.organization.0)
    .bind(&a_id)
    .execute(&api.db.admin)
    .await
    .unwrap();
    let org_admin = api.login(a_email, PASSWORD).await;

    // An envelope sent before the policy changes.
    let env = sent(&api, &alpha, 1, &[]).await;
    let env_id = env["id"].as_str().unwrap();
    let path = format!("/api/v1/envelopes/{env_id}");
    let before = is(
        &api.call("GET", &path, key, None, &[]).await,
        StatusCode::OK,
        None,
        "envelope before",
    );
    let trail = format!("{path}/audit");
    let events_before = is(
        &api.call("GET", &trail, key, None, &[]).await,
        StatusCode::OK,
        None,
        "trail before",
    )["items"]
        .as_array()
        .unwrap()
        .len();

    // An unknown key or a bad value is refused, naming it.
    let r = patch_policy(&api, &owner, json!({"nope": {"value": 1}})).await;
    let p = is(
        &r,
        StatusCode::UNPROCESSABLE_ENTITY,
        Some("CS-API-0001"),
        "unknown key",
    );
    assert!(p.to_string().contains("/policy/nope"), "{p}");
    let r = patch_policy(
        &api,
        &owner,
        json!({"login.mfa_required": {"value": "sometimes"}}),
    )
    .await;
    is(
        &r,
        StatusCode::UNPROCESSABLE_ENTITY,
        Some("CS-API-0001"),
        "bad value",
    );

    // The owner sets the policy: everyone needs a second factor (tighten-only), and the
    // defaults are locked.
    let policy = json!({
        "login.mfa_required": {"value": "everyone"},
        "locale.date_format": {"value": "dd_mm_yyyy", "locked": true},
        "reminders.default": {"value": 2, "locked": true},
        "branding.default_brand": {"value": {"name": "Acme"}, "locked": true},
    });
    let r = patch_policy(&api, &owner, policy).await;
    let o = is(&r, StatusCode::OK, None, "set policy");
    assert_eq!(o["policy"]["login.mfa_required"]["locked"], false);
    assert_eq!(o["policy"]["locale.date_format"]["locked"], true);
    let r = api
        .call("GET", "/api/v1/organizations/me", &owner, None, &[])
        .await;
    assert_eq!(
        is(&r, StatusCode::OK, None, "read policy")["policy"]["reminders.default"]["value"],
        2
    );

    // The organization's level applies on the member's next request, the workspace's
    // own `optional` notwithstanding (and not rewritten).
    let r = api
        .call("GET", "/api/v1/envelopes", &member, None, &[])
        .await;
    is(
        &r,
        StatusCode::FORBIDDEN,
        Some("CS-AUTH-0011"),
        "member after",
    );

    // SEC-O03: each locked setting refuses a change; the tighten-only one refuses looser.
    for (settings, setting) in [
        (json!({"first_reminder_days": 6}), "first_reminder_days"),
        (
            json!({"workflow_policy": workflow_policy("mm_dd_yyyy")}),
            "workflow_policy.date_format",
        ),
        (json!({"branding": {"name": "Other"}}), "branding"),
        (json!({"mfa_policy": "administrators"}), "mfa_policy"),
    ] {
        let r = patch_settings(&api, key, settings).await;
        let p = is(
            &r,
            StatusCode::UNPROCESSABLE_ENTITY,
            Some("CS-ORG-0002"),
            setting,
        );
        assert!(p["detail"].as_str().unwrap().contains(setting), "{p}");
    }
    let r = api.call("GET", "/api/v1/accounts/me", key, None, &[]).await;
    let a = is(&r, StatusCode::OK, None, "account");
    assert_eq!(a["settings"]["first_reminder_days"], 5, "nothing rewritten");
    assert_eq!(a["settings"]["mfa_policy"], "optional", "nothing rewritten");
    let view = &a["organization_policy"]["settings"];
    assert_eq!(view["first_reminder_days"]["locked"], true);
    assert_eq!(view["first_reminder_days"]["value"], 2);
    assert_eq!(view["workflow_policy.date_format"]["value"], "dd_mm_yyyy");
    assert_eq!(view["mfa_policy"]["value"], "everyone");
    assert_eq!(view["mfa_policy"]["from_organization"], true);
    assert_eq!(view["mfa_policy"]["locked"], false);

    // Tightening to the organization's level and an unrelated edit both save; the
    // locked settings travel unchanged (the screens send them back as they are).
    let r = patch_settings(
        &api,
        key,
        json!({"mfa_policy": "everyone", "default_expiry_days": 30, "first_reminder_days": 5,
            "workflow_policy": workflow_policy("yyyy_mm_dd")}),
    )
    .await;
    is(&r, StatusCode::OK, None, "tighter and unrelated");

    // SEC-O11: an admin who is not an owner may tighten or change defaults, never loosen
    // or unlock security. They signed in under the workspace's `optional` and now owe a
    // factor too.
    api.pass_factor(a_email, &org_admin).await;
    let r = patch_policy(
        &api,
        &org_admin,
        json!({
            "login.mfa_required": {"value": "everyone", "locked": true},
            "locale.date_format": {"value": "dd_mm_yyyy", "locked": true},
            "reminders.default": {"value": 3, "locked": true},
            "branding.default_brand": {"value": {"name": "Acme"}, "locked": true},
        }),
    )
    .await;
    is(&r, StatusCode::OK, None, "admin tightens");
    for (loose, what) in [
        (json!({"value": "administrators", "locked": true}), "lower"),
        (json!({"value": "everyone", "locked": false}), "unlock"),
    ] {
        let r = patch_policy(&api, &org_admin, json!({ "login.mfa_required": loose })).await;
        let p = is(&r, StatusCode::FORBIDDEN, Some("CS-ORG-0013"), what);
        assert!(p["detail"].as_str().unwrap().contains("login.mfa_required"));
    }
    let r = patch_policy(&api, &org_admin, json!({})).await;
    is(&r, StatusCode::FORBIDDEN, Some("CS-ORG-0013"), "remove");
    // The owner may loosen.
    let r = patch_policy(&api, &owner, json!({})).await;
    is(&r, StatusCode::OK, None, "owner loosens");

    // Logged in the organization's admin log.
    let r = api
        .call("GET", "/api/v1/organizations/me/audit", &owner, None, &[])
        .await;
    let log = is(&r, StatusCode::OK, None, "audit");
    let changed = log["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "organization.policy_changed")
        .count();
    assert_eq!(changed, 3, "{log}");

    // The envelope sent before every change is exactly as it was.
    let after = is(
        &api.call("GET", &path, key, None, &[]).await,
        StatusCode::OK,
        None,
        "envelope after",
    );
    assert_eq!(after, before);
    let events_after = is(
        &api.call("GET", &trail, key, None, &[]).await,
        StatusCode::OK,
        None,
        "trail after",
    )["items"]
        .as_array()
        .unwrap()
        .len();
    assert_eq!(events_after, events_before);
    api.db.drop().await;
}

#[tokio::test]
async fn organization_policy_with_rls() {
    organization_policy(Rls::On).await;
}

#[tokio::test]
async fn organization_policy_without_rls() {
    organization_policy(Rls::Off).await;
}
