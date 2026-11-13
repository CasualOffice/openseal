//! ORG-04: workspace switching (docs/23 §2.3). A person in two workspaces lists them,
//! switches, and sees only each workspace's envelopes; the old session ends and the new
//! one keeps the sign-in's expiry. `SEC-O05`: a session of workspace A naming B's ids
//! gets 404, a header or parameter naming another workspace changes nothing, and a
//! switch without a membership (or to an id that does not exist) is `403 CS-ORG-0001`.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines
)]

mod common;

use axum::http::StatusCode;
use base64::Engine as _;
use common::Rls;
use common::harness::{Api, Auth, PASSWORD, Resp, pdf, session_of};
use serde_json::{Value, json};

fn is(r: &Resp, status: StatusCode, code: Option<&str>, what: &str) -> Value {
    assert_eq!(r.status, status, "{what}: {:?}", r.json());
    if let Some(c) = code {
        assert_eq!(r.code(), c, "{what}");
    }
    r.json()
}

async fn login(api: &Api, email: &str) -> (Auth, Value) {
    let r = api
        .call(
            "POST",
            "/api/v1/auth/login",
            &Auth::None,
            Some(json!({"email": email, "password": PASSWORD})),
            &[],
        )
        .await;
    let v = is(&r, StatusCode::OK, None, "login");
    // An administrator owes a second factor by default (ASVS-31).
    let s = session_of(&r);
    api.pass_factor(email, &s).await;
    (s, v)
}

async fn create_envelope(api: &Api, s: &Auth, subject: &str) -> String {
    let r = api
        .call(
            "POST",
            "/api/v1/envelopes",
            s,
            Some(json!({
                "subject": subject,
                "documents": [{"name": "d.pdf",
                    "content_base64": base64::engine::general_purpose::STANDARD.encode(pdf(1))}],
                "recipients": [{"ref": "s", "type": "signer", "name": "S",
                    "email": "s@example.test"}],
            })),
            &[],
        )
        .await;
    is(&r, StatusCode::CREATED, None, subject)["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn subjects(api: &Api, s: &Auth, headers: &[(&str, &str)], query: &str) -> Vec<String> {
    let r = api
        .call(
            "GET",
            &format!("/api/v1/envelopes{query}"),
            s,
            None,
            headers,
        )
        .await;
    let mut v: Vec<String> = is(&r, StatusCode::OK, None, "list")["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["subject"].as_str().unwrap().to_owned())
        .collect();
    v.sort();
    v
}

async fn switch(api: &Api, s: &Auth, to: &str) -> Resp {
    api.call(
        "POST",
        "/api/v1/auth/switch",
        s,
        Some(json!({ "account_id": to })),
        &[],
    )
    .await
}

async fn a_user_in_two_workspaces_switches_and_sees_only_each_ones_envelopes(rls: Rls) {
    let Some(api) = Api::new(&format!("workspace_switching_{rls:?}"), rls).await else {
        return;
    };
    let alpha = api.tenant("alpha").await;
    let bravo = api.tenant("bravo").await;
    let a = alpha.boot.account.to_string();
    let (s, first) = login(&api, &alpha.email).await;
    // The organization's owner opens a second workspace and joins it.
    let r = api
        .call(
            "POST",
            "/api/v1/organizations/me/workspaces",
            &s,
            Some(json!({"name": "Legal"})),
            &[],
        )
        .await;
    let w = is(&r, StatusCode::CREATED, None, "create")["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let r = api
        .call(
            "POST",
            &format!("/api/v1/organizations/me/workspaces/{w}/join"),
            &s,
            Some(json!({"profile": "admin"})),
            &[],
        )
        .await;
    is(&r, StatusCode::CREATED, None, "join");
    let in_a = create_envelope(&api, &s, "Alpha deal").await;

    // The listing: both workspaces of the one organization, the session's marked; not
    // bravo's, where this person has no membership.
    let r = api
        .call("GET", "/api/v1/auth/workspaces", &s, None, &[])
        .await;
    let l = is(&r, StatusCode::OK, None, "workspaces");
    assert_eq!(l["current"], a);
    let orgs = l["organizations"].as_array().unwrap();
    assert_eq!(orgs.len(), 1, "{l}");
    assert_eq!(orgs[0]["id"], alpha.boot.organization.to_string());
    let ws: Vec<(String, bool)> = orgs[0]["workspaces"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                x["id"].as_str().unwrap().to_owned(),
                x["current"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(ws, [(w.clone(), false), (a.clone(), true)]);
    // An API key belongs to one workspace: it neither lists nor switches.
    let r = api
        .call("GET", "/api/v1/auth/workspaces", &alpha.auth, None, &[])
        .await;
    is(
        &r,
        StatusCode::UNPROCESSABLE_ENTITY,
        Some("CS-API-0001"),
        "key lists",
    );
    is(
        &switch(&api, &alpha.auth, &w).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        Some("CS-API-0001"),
        "key switches",
    );

    // SEC-O05: no membership in bravo, or no such workspace: the same refusal.
    for (what, to) in [
        ("other organization", bravo.boot.account.to_string()),
        ("unknown", uuid::Uuid::now_v7().to_string()),
    ] {
        is(
            &switch(&api, &s, &to).await,
            StatusCode::FORBIDDEN,
            Some("CS-ORG-0001"),
            what,
        );
    }
    // A switch without the CSRF token is refused.
    let Auth::Session { cookie, .. } = &s else {
        panic!("a session")
    };
    let no_csrf = Auth::Session {
        cookie: cookie.clone(),
        csrf: "wrong".into(),
    };
    is(
        &switch(&api, &no_csrf, &w).await,
        StatusCode::FORBIDDEN,
        Some("CS-AUTH-0008"),
        "csrf",
    );

    // Switch to Legal: a new session there, the old one ended, the same expiry.
    let r = switch(&api, &s, &w).await;
    let sw = is(&r, StatusCode::OK, None, "switch");
    assert_eq!(sw["account_id"], w);
    assert_eq!(sw["expires_at"], first["expires_at"]);
    let s2 = session_of(&r);
    let r = api.call("GET", "/api/v1/auth/session", &s, None, &[]).await;
    is(&r, StatusCode::UNAUTHORIZED, None, "old session");
    is(
        &switch(&api, &s, &w).await,
        StatusCode::UNAUTHORIZED,
        None,
        "old session switches",
    );
    let r = api
        .call("GET", "/api/v1/auth/session", &s2, None, &[])
        .await;
    assert_eq!(is(&r, StatusCode::OK, None, "new session")["account_id"], w);

    // In Legal: none of alpha's envelopes, by list or by id (SEC-O05).
    assert!(subjects(&api, &s2, &[], "").await.is_empty());
    let r = api
        .call("GET", &format!("/api/v1/envelopes/{in_a}"), &s2, None, &[])
        .await;
    is(&r, StatusCode::NOT_FOUND, Some("CS-API-0002"), "alpha's id");
    let in_w = create_envelope(&api, &s2, "Legal matter").await;
    // A header or a parameter naming alpha changes nothing.
    let q = format!("?account_id={a}");
    let h = [
        ("x-account-id", a.as_str()),
        ("x-openseal-account", a.as_str()),
    ];
    assert_eq!(subjects(&api, &s2, &h, &q).await, ["Legal matter"]);

    // And back: only alpha's, and Legal's id is 404.
    let r = switch(&api, &s2, &a).await;
    is(&r, StatusCode::OK, None, "switch back");
    let s3 = session_of(&r);
    assert_eq!(subjects(&api, &s3, &[], "").await, ["Alpha deal"]);
    let r = api
        .call("GET", &format!("/api/v1/envelopes/{in_w}"), &s3, None, &[])
        .await;
    is(&r, StatusCode::NOT_FOUND, Some("CS-API-0002"), "Legal's id");

    // A disabled membership is no membership: Legal disables this person there.
    sqlx::query(
        "UPDATE account_memberships SET disabled_at = now() \
         WHERE account_id = $1::uuid AND user_id = $2",
    )
    .bind(&w)
    .bind(alpha.boot.admin.0)
    .execute(&api.db.admin)
    .await
    .unwrap();
    is(
        &switch(&api, &s3, &w).await,
        StatusCode::FORBIDDEN,
        Some("CS-ORG-0001"),
        "disabled membership",
    );
    let r = api
        .call("GET", "/api/v1/auth/workspaces", &s3, None, &[])
        .await;
    let l = is(&r, StatusCode::OK, None, "after disable");
    assert_eq!(
        l["organizations"][0]["workspaces"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    api.db.drop().await;
}

#[tokio::test]
async fn workspace_switching_with_rls() {
    a_user_in_two_workspaces_switches_and_sees_only_each_ones_envelopes(Rls::On).await;
}

#[tokio::test]
async fn workspace_switching_without_rls() {
    a_user_in_two_workspaces_switches_and_sees_only_each_ones_envelopes(Rls::Off).await;
}
