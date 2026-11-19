//! Sandbox workspaces on the server (ADR-041, `VS-08D`, owner instruction 69): an
//! organization administrator makes a workspace a sandbox at creation and for good; its
//! session, account and signing view say so; its API keys start `osk_test_`; nothing it
//! does is metered; and the database refuses any change of the mark.

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
use base64::Engine as _;
use common::Rls;
use common::harness::{Api, Auth, PASSWORD, pdf, session_of};
use serde_json::{Value, json};

fn ok(r: &common::harness::Resp, want: StatusCode, what: &str) -> Value {
    assert_eq!(
        r.status,
        want,
        "{what}: {}",
        String::from_utf8_lossy(&r.body)
    );
    r.json()
}

async fn sent_envelope(api: &Api, auth: &Auth) -> Value {
    let r = api
        .call(
            "POST",
            "/api/v1/envelopes",
            auth,
            Some(json!({
                "subject": "Sandbox test", "status": "sent",
                "documents": [{"name": "d.pdf", "content_base64": base64::engine::general_purpose::STANDARD.encode(pdf(1))}],
                "recipients": [{"ref": "s", "type": "signer", "name": "Sam", "email": "sam@example.test"}],
                "fields": [{"recipient": "s", "document": 0, "type": "signature", "page": 1, "x": 72, "y": 600, "width": 180, "height": 40}],
            })),
            &[],
        )
        .await;
    ok(&r, StatusCode::CREATED, "envelope")
}

async fn ledger_rows(api: &Api, account: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM usage_ledger WHERE account_id = $1::uuid")
        .bind(account)
        .fetch_one(&api.db.admin)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_sandbox_workspace_is_marked_for_good_keyed_osk_test_and_not_metered() {
    let Some(api) = Api::new("sandbox_workspace", Rls::On).await else {
        return;
    };
    let t = api.tenant("sbx").await;
    let main = t.boot.account.to_string();
    let s = api.login(&t.email, PASSWORD).await;
    // An ordinary workspace is not a sandbox, and its keys are `osk_`.
    let me = ok(
        &api.call("GET", "/api/v1/auth/session", &s, None, &[]).await,
        StatusCode::OK,
        "session",
    );
    assert_eq!(me["sandbox"], false);
    assert!(t.key.starts_with("osk_") && !t.key.starts_with("osk_test_"));

    // The organization's owner makes a sandbox workspace.
    let w = ok(
        &api.call(
            "POST",
            "/api/v1/organizations/me/workspaces",
            &s,
            Some(json!({"name": "Integration tests", "sandbox": true})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "create",
    );
    assert_eq!(w["sandbox"], true);
    let wid = w["id"].as_str().unwrap().to_owned();
    let list = ok(
        &api.call("GET", "/api/v1/organizations/me/workspaces", &s, None, &[])
            .await,
        StatusCode::OK,
        "list",
    );
    let marks: Vec<(String, bool)> = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                x["id"].as_str().unwrap().to_owned(),
                x["sandbox"].as_bool().unwrap(),
            )
        })
        .collect();
    assert!(marks.contains(&(wid.clone(), true)), "{marks:?}");
    assert!(marks.contains(&(main.clone(), false)), "{marks:?}");

    // The mark is fixed: no UPDATE changes it, whoever runs it.
    let refused = sqlx::query("UPDATE accounts SET sandbox = false WHERE id = $1::uuid")
        .bind(&wid)
        .execute(&api.db.admin)
        .await;
    assert!(refused.is_err(), "the sandbox mark changed");
    let refused = sqlx::query("UPDATE accounts SET sandbox = true WHERE id = $1::uuid")
        .bind(&main)
        .execute(&api.db.admin)
        .await;
    assert!(refused.is_err(), "a workspace became a sandbox");

    // In the sandbox: the session and the account say so; keys are `osk_test_`.
    ok(
        &api.call(
            "POST",
            &format!("/api/v1/organizations/me/workspaces/{wid}/join"),
            &s,
            Some(json!({"profile": "admin"})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "join",
    );
    let switched = api
        .call(
            "POST",
            "/api/v1/auth/switch",
            &s,
            Some(json!({"account_id": wid})),
            &[],
        )
        .await;
    ok(&switched, StatusCode::OK, "switch");
    let sb = session_of(&switched);
    api.pass_factor(&t.email, &sb).await;
    let me = ok(
        &api.call("GET", "/api/v1/auth/session", &sb, None, &[])
            .await,
        StatusCode::OK,
        "sandbox session",
    );
    assert_eq!(me["sandbox"], true);
    let acct = ok(
        &api.call("GET", "/api/v1/accounts/me", &sb, None, &[]).await,
        StatusCode::OK,
        "account",
    );
    assert_eq!(acct["sandbox"], true);
    let r = api
        .call(
            "POST",
            "/api/v1/api-clients",
            &sb,
            Some(json!({"name": "ci", "kind": "api_key", "scopes": casual_sign_server::SCOPES})),
            &[],
        )
        .await;
    let key = ok(&r, StatusCode::CREATED, "sandbox key")["key"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(key.starts_with("osk_test_"), "{key}");
    let k = Auth::Bearer(key);

    // An envelope sent with the key: its signing view says it is a sandbox test.
    let before = ledger_rows(&api, &wid).await;
    let env = sent_envelope(&api, &k).await;
    let token = casual_sign_server::issue_invitation_token(
        &api.st,
        casual_sign_store::AccountId(wid.parse().unwrap()),
        casual_sign_store::EnvelopeId(env["id"].as_str().unwrap().parse().unwrap()),
        casual_sign_store::RecipientId(
            env["recipients"][0]["id"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
        ),
        std::time::Duration::from_secs(86_400),
    )
    .await
    .unwrap();
    let view = ok(
        &api.call(
            "POST",
            &format!("/s/{token}/session"),
            &Auth::None,
            Some(json!({})),
            &[],
        )
        .await,
        StatusCode::OK,
        "view",
    );
    assert_eq!(view["sandbox"], true);
    // Nothing the sandbox does is metered; the ordinary workspace is.
    assert_eq!(ledger_rows(&api, &wid).await, 0);
    assert_eq!(before, 0);
    let main_env = sent_envelope(&api, &t.auth).await;
    assert!(ledger_rows(&api, &main).await > 0);
    let token = casual_sign_server::issue_invitation_token(
        &api.st,
        t.boot.account,
        casual_sign_store::EnvelopeId(main_env["id"].as_str().unwrap().parse().unwrap()),
        casual_sign_store::RecipientId(
            main_env["recipients"][0]["id"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
        ),
        std::time::Duration::from_secs(86_400),
    )
    .await
    .unwrap();
    let view = ok(
        &api.call(
            "POST",
            &format!("/s/{token}/session"),
            &Auth::None,
            Some(json!({})),
            &[],
        )
        .await,
        StatusCode::OK,
        "main view",
    );
    assert_eq!(view["sandbox"], false);
    api.db.drop().await;
}
