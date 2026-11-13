//! ASVS-01: staff multi-factor authentication. Under a policy that requires it, an
//! administrator without a second factor reaches nothing of `/api/v1` but the sign-in
//! steps until they enrol; a confirmed factor is owed by every later session; a TOTP
//! code is accepted once (a replay in the same step is refused), and a recovery code is
//! spent when used.

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
use casual_sign_server::Clock as _;
use casual_sign_server::totp;
use common::Rls;
use common::harness::{Api, Auth, PASSWORD, Resp, session_of, unbase32};
use serde_json::json;

fn code(r: &Resp) -> (StatusCode, String) {
    (r.status, r.code())
}

async fn login(api: &Api, email: &str) -> Auth {
    let r = api
        .call(
            "POST",
            "/api/v1/auth/login",
            &Auth::None,
            Some(json!({"email": email, "password": PASSWORD})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    session_of(&r)
}

/// The authenticator's code now, by the server's clock.
fn now_code(api: &Api, seed: &[u8]) -> String {
    totp::code(seed, totp::step_at(api.clock.now().unix_timestamp()))
}

/// A second administrator of an account, made through the API with [`PASSWORD`];
/// answers their user id.
async fn second_admin(api: &Api, auth: &Auth, email: &str) -> String {
    let r = api
        .call(
            "POST",
            "/api/v1/users",
            auth,
            Some(json!({"email": email, "name": "Second Admin", "profile": "admin", "password": PASSWORD})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.json());
    r.json()["id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn a_fresh_accounts_administrator_owes_a_factor_with_no_setting() {
    let Some(api) = Api::new("mfa_default_administrators", Rls::On).await else {
        return;
    };
    // ASVS-31: no `mfa_policy` set, yet the first administrator must enrol first.
    let (_, email) = api.bare_tenant("fresh").await;
    let s = login(&api, &email).await;
    for path in [
        "/api/v1/envelopes",
        "/api/v1/accounts/me",
        "/api/v1/api-clients",
    ] {
        let r = api.call("GET", path, &s, None, &[]).await;
        assert_eq!(
            code(&r),
            (StatusCode::FORBIDDEN, "CS-AUTH-0011".into()),
            "{path}"
        );
        assert_eq!(r.json()["detail"], "enrol", "{path}");
    }
    let r = api.call("GET", "/api/v1/auth/session", &s, None, &[]).await;
    assert_eq!(r.json()["second_factor"], "enrol");
    // Enrolment through the API lets them in, with the setting still unset.
    api.pass_factor(&email, &s).await;
    let r = api.call("GET", "/api/v1/accounts/me", &s, None, &[]).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    assert!(r.json()["settings"].get("mfa_policy").is_none());
    let r = api
        .call(
            "POST",
            "/api/v1/api-clients",
            &s,
            Some(json!({"name": "k", "kind": "api_key", "scopes": casual_sign_server::SCOPES})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.json());
    let key = Auth::Bearer(r.json()["key"].as_str().unwrap().to_owned());

    // A member who is not an administrator is not asked by the default.
    let r = api
        .call(
            "POST",
            "/api/v1/users",
            &key,
            Some(json!({"email": "sender@fresh.example.test", "name": "S", "profile": "sender", "password": PASSWORD})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.json());
    let sender = login(&api, "sender@fresh.example.test").await;
    let r = api
        .call("GET", "/api/v1/envelopes", &sender, None, &[])
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());

    // An account that explicitly chose `optional` keeps it; `null` returns to the
    // default, administrators.
    second_admin(&api, &key, "second@fresh.example.test").await;
    let r = api
        .call(
            "PATCH",
            "/api/v1/accounts/me",
            &key,
            Some(json!({"settings": {"mfa_policy": "optional"}})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let s2 = login(&api, "second@fresh.example.test").await;
    let r = api.call("GET", "/api/v1/envelopes", &s2, None, &[]).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let r = api
        .call(
            "PATCH",
            "/api/v1/accounts/me",
            &key,
            Some(json!({"settings": {"mfa_policy": null}})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let s3 = login(&api, "second@fresh.example.test").await;
    let r = api.call("GET", "/api/v1/envelopes", &s3, None, &[]).await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "CS-AUTH-0011".into()));
    assert_eq!(r.json()["detail"], "enrol");
    api.db.drop().await;
}

#[tokio::test]
async fn without_the_sealing_key_nobody_can_enrol() {
    // Why `casual-sign-server` refuses to start without `OPENSEAL_MFA_KEY` outside
    // development (ASVS-31): administrators owe a factor by default, and without the
    // key none can be enrolled.
    let Some(api) = Api::without_mfa_key("mfa_no_key", Rls::On).await else {
        return;
    };
    let (_, email) = api.bare_tenant("nokey").await;
    let s = login(&api, &email).await;
    let r = api
        .call("POST", "/api/v1/auth/mfa/totp/enrol", &s, None, &[])
        .await;
    assert_eq!(code(&r), (StatusCode::CONFLICT, "CS-API-0009".into()));
    api.db.drop().await;
}

#[tokio::test]
async fn an_administrator_without_a_second_factor_reaches_only_the_sign_in_steps() {
    let Some(api) = Api::new("mfa_admin_must_enrol", Rls::On).await else {
        return;
    };
    let t = api.tenant("mfa").await;
    let r = api
        .call(
            "PATCH",
            "/api/v1/accounts/me",
            &t.auth,
            Some(json!({"settings": {"mfa_policy": "sometimes"}})),
            &[],
        )
        .await;
    assert_eq!(
        code(&r),
        (StatusCode::UNPROCESSABLE_ENTITY, "CS-API-0001".into())
    );
    let r = api
        .call(
            "PATCH",
            "/api/v1/accounts/me",
            &t.auth,
            Some(json!({"settings": {"mfa_policy": "administrators"}})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    // The harness enrolled the first administrator; this one has no factor yet.
    let email = "second@mfa.example.test";
    let admin2 = second_admin(&api, &t.auth, email).await;

    // A password alone: the session must enrol before anything else.
    let s1 = login(&api, email).await;
    let r = api.call("GET", "/api/v1/envelopes", &s1, None, &[]).await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "CS-AUTH-0011".into()));
    assert_eq!(r.json()["detail"], "enrol");
    let r = api.call("GET", "/api/v1/accounts/me", &s1, None, &[]).await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "CS-AUTH-0011".into()));
    let r = api
        .call("GET", "/api/v1/auth/session", &s1, None, &[])
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json()["second_factor"], "enrol");

    // Enrol: a wrong code is refused, the right one confirms and passes the session.
    let r = api
        .call("POST", "/api/v1/auth/mfa/totp/enrol", &s1, None, &[])
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    assert_eq!(r.headers["cache-control"], "no-store");
    let secret = r.json()["secret"].as_str().unwrap().to_owned();
    assert!(
        r.json()["otpauth_uri"]
            .as_str()
            .unwrap()
            .contains(&format!("secret={secret}"))
    );
    assert!(!r.json()["otpauth_uri"].as_str().unwrap().contains('@'));
    let seed = unbase32(&secret);
    let good = now_code(&api, &seed);
    let bad = if good == "000000" { "111111" } else { "000000" };
    let r = api
        .call(
            "POST",
            "/api/v1/auth/mfa/totp/confirm",
            &s1,
            Some(json!({"code": bad})),
            &[],
        )
        .await;
    assert_eq!(code(&r), (StatusCode::UNAUTHORIZED, "CS-AUTH-0012".into()));
    let r = api
        .call(
            "POST",
            "/api/v1/auth/mfa/totp/confirm",
            &s1,
            Some(json!({"code": good})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let recovery: Vec<String> = r.json()["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(recovery.len(), 10);
    let r = api.call("GET", "/api/v1/envelopes", &s1, None, &[]).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    // A confirmed factor cannot be replaced by enrolling again without it.
    let r = api
        .call("POST", "/api/v1/auth/mfa/totp/enrol", &s1, None, &[])
        .await;
    assert_eq!(code(&r), (StatusCode::CONFLICT, "CS-API-0009".into()));

    // The next sign-in owes the factor; the code just used is refused (replayed).
    let s2 = login(&api, email).await;
    let r = api.call("GET", "/api/v1/envelopes", &s2, None, &[]).await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "CS-AUTH-0011".into()));
    assert_eq!(r.json()["detail"], "verify");
    let r = api
        .call(
            "POST",
            "/api/v1/auth/mfa/verify",
            &s2,
            Some(json!({"code": good})),
            &[],
        )
        .await;
    assert_eq!(
        code(&r),
        (StatusCode::UNAUTHORIZED, "CS-AUTH-0012".into()),
        "a replayed code"
    );
    api.clock.advance(Duration::from_secs(30));
    let next = now_code(&api, &seed);
    let r = api
        .call(
            "POST",
            "/api/v1/auth/mfa/verify",
            &s2,
            Some(json!({"code": next})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let r = api.call("GET", "/api/v1/envelopes", &s2, None, &[]).await;
    assert_eq!(r.status, StatusCode::OK);

    // A recovery code passes once, however it is typed; spent, it is refused.
    let s3 = login(&api, email).await;
    let typed = recovery[0].to_lowercase().replace('-', " ");
    let r = api
        .call(
            "POST",
            "/api/v1/auth/mfa/verify",
            &s3,
            Some(json!({"recovery_code": typed})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    assert_eq!(r.json()["recovery_codes_left"], 9);
    let r = api.call("GET", "/api/v1/envelopes", &s3, None, &[]).await;
    assert_eq!(r.status, StatusCode::OK);
    let s4 = login(&api, email).await;
    let r = api
        .call(
            "POST",
            "/api/v1/auth/mfa/verify",
            &s4,
            Some(json!({"recovery_code": recovery[0]})),
            &[],
        )
        .await;
    assert_eq!(
        code(&r),
        (StatusCode::UNAUTHORIZED, "CS-AUTH-0012".into()),
        "a used recovery code"
    );
    let r = api.call("GET", "/api/v1/envelopes", &s4, None, &[]).await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "CS-AUTH-0011".into()));

    // The application role can neither read a factor nor clear one behind the functions'
    // back (as the server runs; RLS off, so only the grant and the trigger stand).
    let read = sqlx::query("SELECT totp_seed_sealed FROM users LIMIT 1")
        .execute(&api.db.app)
        .await;
    assert!(read.is_err(), "the app role read a sealed seed");
    let mut tx = api.db.app.begin().await.unwrap();
    sqlx::query("SELECT set_config('openseal.account_id', $1, true)")
        .bind(t.boot.account.0.to_string())
        .execute(&mut *tx)
        .await
        .unwrap();
    let admin2 = uuid::Uuid::parse_str(&admin2).unwrap();
    let name = sqlx::query("UPDATE users SET name = name WHERE id = $1")
        .bind(admin2)
        .execute(&mut *tx)
        .await
        .unwrap();
    assert_eq!(
        name.rows_affected(),
        1,
        "the row is the app role's to update"
    );
    let clear = sqlx::query(
        "UPDATE users SET totp_last_step = NULL, recovery_code_sha256 = '{}' WHERE id = $1",
    )
    .bind(admin2)
    .execute(&mut *tx)
    .await;
    assert!(clear.is_err(), "the app role cleared a factor");
    drop(tx);

    // The sign-in steps are for sessions; the account's API key is not asked for one.
    let r = api
        .call("POST", "/api/v1/auth/mfa/totp/enrol", &t.auth, None, &[])
        .await;
    assert_eq!(
        code(&r),
        (StatusCode::UNPROCESSABLE_ENTITY, "CS-API-0001".into())
    );
    let r = api
        .call("GET", "/api/v1/envelopes", &t.auth, None, &[])
        .await;
    assert_eq!(r.status, StatusCode::OK);

    // Like every other setting, `null` removes the policy: back to the default.
    let r = api
        .call(
            "PATCH",
            "/api/v1/accounts/me",
            &t.auth,
            Some(json!({"settings": {"mfa_policy": null}})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    api.db.drop().await;
}
