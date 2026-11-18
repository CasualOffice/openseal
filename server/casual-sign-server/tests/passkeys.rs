//! CON-13 and ASVS-32 (ASVS 2.3.2, 2.5.7): staff passkeys as a second factor, and the
//! lost-factor reset.
//!
//! A passkey registered from a software authenticator is the enrolment a policy asks
//! for, passes the sign-in step and step-up, and is listed, renamed and removed only
//! after a re-authentication; a replayed assertion, another purpose's challenge, a wrong
//! origin and a counter that does not move (a clone) are refused; a session that owes a
//! factor cannot add one to get past it; another workspace's user neither sees nor
//! removes it. An administrator who re-authenticated resets a member who lost every
//! factor, recording how their identity was proved: the member's factors and sessions
//! end, they must enrol at their next sign-in, and they are told by email; the user
//! replaces their own TOTP and recovery codes only after proving the current factor.

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
use casual_sign_audit::Personal;
use casual_sign_server::Clock as _;
use casual_sign_server::totp;
use common::Rls;
use common::harness::{Api, Auth, PASSWORD, Resp, session_of, unbase32};
use common::passkey::Soft;
use serde_json::{Value, json};

fn code(r: &Resp) -> (StatusCode, String) {
    (r.status, r.code())
}

/// Sign in with the password only: the session may still owe its factor.
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

async fn options(api: &Api, s: &Auth, purpose: &str) -> Resp {
    api.call(
        "POST",
        "/api/v1/auth/mfa/passkeys/options",
        s,
        Some(json!({"purpose": purpose})),
        &[],
    )
    .await
}

async fn ok_options(api: &Api, s: &Auth, purpose: &str) -> Value {
    let r = options(api, s, purpose).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    r.json()
}

/// Register `soft` from session `s`; answers the server's response.
async fn register(api: &Api, s: &Auth, soft: &Soft, name: &str) -> Resp {
    let o = ok_options(api, s, "register").await;
    api.call(
        "POST",
        "/api/v1/auth/mfa/passkeys",
        s,
        Some(soft.register(&o, name)),
        &[],
    )
    .await
}

/// Pass the sign-in step with `soft`; answers the server's response.
async fn verify(api: &Api, s: &Auth, soft: &Soft) -> Resp {
    let o = ok_options(api, s, "verify").await;
    api.call(
        "POST",
        "/api/v1/auth/mfa/verify",
        s,
        Some(json!({"passkey": soft.assert(&o)})),
        &[],
    )
    .await
}

async fn reauth_with(api: &Api, s: &Auth, soft: &Soft) -> Resp {
    let o = ok_options(api, s, "reauthenticate").await;
    api.call(
        "POST",
        "/api/v1/auth/reauthenticate",
        s,
        Some(json!({"password": PASSWORD, "passkey": soft.assert(&o)})),
        &[],
    )
    .await
}

async fn reaches(api: &Api, s: &Auth) -> StatusCode {
    api.call("GET", "/api/v1/envelopes", s, None, &[])
        .await
        .status
}

/// A member made through the API with [`PASSWORD`]; answers their id.
async fn member(api: &Api, auth: &Auth, email: &str, profile: &str) -> String {
    let r = api
        .call(
            "POST",
            "/api/v1/users",
            auth,
            Some(
                json!({"email": email, "name": "Member", "profile": profile, "password": PASSWORD}),
            ),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.json());
    r.json()["id"].as_str().unwrap().to_owned()
}

/// The notices queued for `user`, oldest first.
async fn notices(api: &Api, user: &str) -> Vec<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT payload ->> 'notice' FROM jobs WHERE kind = 'send_security_notice' \
         AND payload ->> 'user_id' = $1 ORDER BY run_at, id",
    )
    .bind(user)
    .fetch_all(&api.db.admin)
    .await
    .unwrap()
}

#[tokio::test]
async fn a_passkey_enrols_passes_sign_in_and_step_up_and_is_managed_after_step_up() {
    let Some(api) = Api::new("passkey_lifecycle", Rls::On).await else {
        return;
    };
    // An administrator of a fresh workspace owes enrolment (ASVS-31).
    let (_, email) = api.bare_tenant("pk").await;
    let s = login(&api, &email).await;
    assert_eq!(reaches(&api, &s).await, StatusCode::FORBIDDEN);
    let soft = Soft::new();
    let r = register(&api, &s, &soft, "Laptop").await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.json());
    assert_eq!(r.headers["cache-control"], "no-store");
    let first = r.json();
    assert_eq!(first["second_factor"], "passed");
    assert_eq!(first["passkey"]["name"], "Laptop");
    let codes = first["recovery_codes"].as_array().unwrap().clone();
    assert_eq!(codes.len(), 10);
    assert_eq!(reaches(&api, &s).await, StatusCode::OK);
    let me = api
        .call("GET", "/api/v1/auth/session", &s, None, &[])
        .await
        .json();
    assert_eq!(me["factors"]["passkeys"], 1);
    assert_eq!(me["factors"]["totp"], false);
    assert_eq!(me["factors"]["passkeys_available"], true);
    let user = me["user_id"].as_str().unwrap().to_owned();
    assert_eq!(notices(&api, &user).await, ["passkey_added"]);

    // A new sign-in owes the passkey: refused everywhere until it passes.
    let s2 = login(&api, &email).await;
    let r = api.call("GET", "/api/v1/accounts/me", &s2, None, &[]).await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "CS-AUTH-0011".into()));
    assert_eq!(r.json()["detail"], "verify");
    // The options name the credential, for this RP.
    let o = ok_options(&api, &s2, "verify").await;
    assert_eq!(o["public_key"]["rpId"], "sign.example.test");
    assert_eq!(
        o["public_key"]["allowCredentials"][0]["id"],
        common::passkey::b64(&soft.id)
    );
    let answer = soft.assert(&o);
    let r = api
        .call(
            "POST",
            "/api/v1/auth/mfa/verify",
            &s2,
            Some(json!({"passkey": answer})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    assert_eq!(reaches(&api, &s2).await, StatusCode::OK);
    // The same assertion again is refused: its challenge is spent.
    let s3 = login(&api, &email).await;
    let r = api
        .call(
            "POST",
            "/api/v1/auth/mfa/verify",
            &s3,
            Some(json!({"passkey": answer})),
            &[],
        )
        .await;
    assert_eq!(code(&r), (StatusCode::UNAUTHORIZED, "CS-AUTH-0012".into()));
    // A recovery code passes too, once.
    let rc = codes[0].as_str().unwrap();
    let r = api
        .call(
            "POST",
            "/api/v1/auth/mfa/verify",
            &s3,
            Some(json!({"recovery_code": rc})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());

    // Listing needs no step-up; renaming and removing do, once the window has passed.
    let r = api
        .call("GET", "/api/v1/auth/mfa/passkeys", &s2, None, &[])
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let id = r.json()["items"][0]["id"].as_str().unwrap().to_owned();
    assert!(r.json()["items"][0]["last_used_at"].is_string());
    api.clock.advance(Duration::from_secs(6 * 60));
    let path = format!("/api/v1/auth/mfa/passkeys/{id}");
    let r = api
        .call(
            "PATCH",
            &path,
            &s2,
            Some(json!({"name": "Work laptop"})),
            &[],
        )
        .await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "CS-AUTH-0013".into()));
    let r = api.call("DELETE", &path, &s2, None, &[]).await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "CS-AUTH-0013".into()));
    // Step-up with the password alone is refused for a user with a passkey.
    let r = api
        .call(
            "POST",
            "/api/v1/auth/reauthenticate",
            &s2,
            Some(json!({"password": PASSWORD})),
            &[],
        )
        .await;
    assert_eq!(
        code(&r),
        (StatusCode::UNPROCESSABLE_ENTITY, "CS-API-0001".into())
    );
    let r = reauth_with(&api, &s2, &soft).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let r = api
        .call(
            "PATCH",
            &path,
            &s2,
            Some(json!({"name": "Work laptop"})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    assert_eq!(r.json()["name"], "Work laptop");
    // A second passkey, from a session that passed and re-authenticated.
    let other = Soft::new();
    let r = register(&api, &s2, &other, "Phone").await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.json());
    assert!(r.json().get("recovery_codes").is_none(), "codes kept");
    let r = api.call("DELETE", &path, &s2, None, &[]).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.json());
    let r = api
        .call("GET", "/api/v1/auth/mfa/passkeys", &s2, None, &[])
        .await;
    assert_eq!(r.json()["items"].as_array().unwrap().len(), 1);
    assert_eq!(
        notices(&api, &user).await,
        ["passkey_added", "passkey_added", "passkey_removed"]
    );
    // The removed one no longer passes a sign-in; the other does.
    let s4 = login(&api, &email).await;
    let o = ok_options(&api, &s4, "verify").await;
    let r = api
        .call(
            "POST",
            "/api/v1/auth/mfa/verify",
            &s4,
            Some(json!({"passkey": soft.assert(&o)})),
            &[],
        )
        .await;
    assert_eq!(code(&r), (StatusCode::UNAUTHORIZED, "CS-AUTH-0012".into()));
    assert_eq!(verify(&api, &s4, &other).await.status, StatusCode::OK);
}

#[tokio::test]
async fn a_cloned_passkey_another_origin_or_another_purposes_challenge_is_refused() {
    let Some(api) = Api::new("passkey_refusals", Rls::On).await else {
        return;
    };
    let (_, email) = api.bare_tenant("pkr").await;
    let s = login(&api, &email).await;
    let mut soft = Soft::new();
    soft.count = 5;
    let r = register(&api, &s, &soft, "Key").await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.json());

    // The counter did not move past 5: a clone. Refused, and logged as such.
    let s2 = login(&api, &email).await;
    let r = verify(&api, &s2, &soft).await;
    assert_eq!(code(&r), (StatusCode::UNAUTHORIZED, "CS-AUTH-0012".into()));
    assert!(
        api.security
            .lines()
            .iter()
            .any(|l| l.contains("\"auth.mfa\"") && l.contains("\"counter\"")),
        "the clone is logged"
    );
    soft.count = 6;
    assert_eq!(verify(&api, &s2, &soft).await.status, StatusCode::OK);
    // A new minute, so the attempts below stay inside the login rate (docs/21).
    api.clock.advance(Duration::from_secs(61));
    // And a lower one after that is refused again.
    let s3 = login(&api, &email).await;
    soft.count = 6;
    assert_eq!(
        verify(&api, &s3, &soft).await.status,
        StatusCode::UNAUTHORIZED
    );

    // A `reauthenticate` challenge does not answer the sign-in step.
    soft.count = 7;
    let o = ok_options(&api, &s3, "reauthenticate").await;
    let r = api
        .call(
            "POST",
            "/api/v1/auth/mfa/verify",
            &s3,
            Some(json!({"passkey": soft.assert(&o)})),
            &[],
        )
        .await;
    assert_eq!(code(&r), (StatusCode::UNAUTHORIZED, "CS-AUTH-0012".into()));
    // Another origin, another RP id.
    soft.count = 8;
    soft.origin = "https://sign.example.test.evil.test".into();
    assert_eq!(
        verify(&api, &s3, &soft).await.status,
        StatusCode::UNAUTHORIZED
    );
    soft.origin = "https://sign.example.test".into();
    soft.rp_id = "example.test".into();
    assert_eq!(
        verify(&api, &s3, &soft).await.status,
        StatusCode::UNAUTHORIZED
    );
    soft.rp_id = "sign.example.test".into();
    // A challenge expires after five minutes.
    let o = ok_options(&api, &s3, "verify").await;
    api.clock.advance(Duration::from_secs(301));
    let r = api
        .call(
            "POST",
            "/api/v1/auth/mfa/verify",
            &s3,
            Some(json!({"passkey": soft.assert(&o)})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(verify(&api, &s3, &soft).await.status, StatusCode::OK);
    // Registering the same credential twice is refused.
    soft.count = 9;
    assert_eq!(reauth_with(&api, &s3, &soft).await.status, StatusCode::OK);
    let r = register(&api, &s3, &soft, "Again").await;
    assert_eq!(code(&r), (StatusCode::CONFLICT, "CS-API-0009".into()));
}

#[tokio::test]
async fn a_session_that_owes_its_factor_cannot_add_another_to_get_past_it() {
    let Some(api) = Api::new("passkey_no_bypass", Rls::On).await else {
        return;
    };
    // A TOTP user (enrolled by the harness) who has not passed it on a new sign-in.
    let t = api.tenant("nb").await;
    let s = login(&api, &t.email).await;
    let r = options(&api, &s, "register").await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "CS-AUTH-0011".into()));
    let soft = Soft::new();
    let r = api
        .call(
            "POST",
            "/api/v1/auth/mfa/passkeys",
            &s,
            Some(soft.register(&json!({"public_key": {"challenge": "AAAA"}}), "x")),
            &[],
        )
        .await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "CS-AUTH-0011".into()));
    assert_eq!(reaches(&api, &s).await, StatusCode::FORBIDDEN);

    // A passkey user who has not passed it cannot enrol TOTP either.
    let (_, email) = api.bare_tenant("nb2").await;
    let p = login(&api, &email).await;
    assert_eq!(
        register(&api, &p, &soft, "K").await.status,
        StatusCode::CREATED
    );
    let p2 = login(&api, &email).await;
    let r = api
        .call("POST", "/api/v1/auth/mfa/totp/enrol", &p2, None, &[])
        .await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "CS-AUTH-0011".into()));
    assert_eq!(reaches(&api, &p2).await, StatusCode::FORBIDDEN);
    // Once passed and re-authenticated, adding TOTP is allowed.
    assert_eq!(verify(&api, &p2, &soft).await.status, StatusCode::OK);
    let r = api
        .call("POST", "/api/v1/auth/mfa/totp/enrol", &p2, None, &[])
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
}

#[tokio::test]
async fn another_workspaces_user_neither_sees_uses_nor_removes_a_passkey() {
    let Some(api) = Api::new("passkey_isolation", Rls::On).await else {
        return;
    };
    let (_, a) = api.bare_tenant("alpha").await;
    let sa = login(&api, &a).await;
    let soft = Soft::new();
    assert_eq!(
        register(&api, &sa, &soft, "A's key").await.status,
        StatusCode::CREATED
    );
    let id = api
        .call("GET", "/api/v1/auth/mfa/passkeys", &sa, None, &[])
        .await
        .json()["items"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (_, b) = api.bare_tenant("bravo").await;
    let sb = login(&api, &b).await;
    let other = Soft::new();
    assert_eq!(
        register(&api, &sb, &other, "B's key").await.status,
        StatusCode::CREATED
    );
    // B's list and options name only B's credential.
    let r = api
        .call("GET", "/api/v1/auth/mfa/passkeys", &sb, None, &[])
        .await;
    assert_eq!(r.json()["items"].as_array().unwrap().len(), 1);
    assert_ne!(r.json()["items"][0]["id"], id.as_str());
    // A's id answers as missing to B, and A's credential does not pass B's sign-in.
    let r = api
        .call(
            "DELETE",
            &format!("/api/v1/auth/mfa/passkeys/{id}"),
            &sb,
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = api
        .call(
            "PATCH",
            &format!("/api/v1/auth/mfa/passkeys/{id}"),
            &sb,
            Some(json!({"name": "mine"})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let sb2 = login(&api, &b).await;
    assert_eq!(
        verify(&api, &sb2, &soft).await.status,
        StatusCode::UNAUTHORIZED
    );
    // B's administrator cannot reset A's administrator.
    let a_user = api
        .call("GET", "/api/v1/auth/session", &sa, None, &[])
        .await
        .json()["user_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let r = api
        .call(
            "POST",
            &format!("/api/v1/users/{a_user}/second-factor/reset"),
            &sb,
            Some(json!({"identity_verified_by": "in_person"})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // The row lives under A's workspace: the application role sees it from A only.
    for (s, expect) in [(&sb, 0i64), (&sa, 1)] {
        let acct = api
            .call("GET", "/api/v1/auth/session", s, None, &[])
            .await
            .json()["account_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let mut conn = api.db.app.begin().await.unwrap();
        sqlx::query("SELECT set_config('openseal.account_id', $1, true)")
            .bind(&acct)
            .execute(&mut *conn)
            .await
            .unwrap();
        let seen: i64 =
            sqlx::query_scalar("SELECT count(*) FROM staff_passkeys WHERE user_id::text = $1")
                .bind(&a_user)
                .fetch_one(&mut *conn)
                .await
                .unwrap();
        assert_eq!(seen, expect, "{acct}");
        // And may write none.
        let denied = sqlx::query("DELETE FROM staff_passkeys")
            .execute(&mut *conn)
            .await
            .is_err();
        assert!(denied, "the application role deleted a passkey");
    }
}

#[tokio::test]
async fn an_administrator_resets_a_members_lost_factors_after_proving_their_identity() {
    let Some(api) = Api::new("passkey_reset", Rls::On).await else {
        return;
    };
    let t = api.tenant("rs").await;
    let admin = api.login(&t.email, PASSWORD).await;
    let kim = member(&api, &t.auth, "kim@rs.example.test", "sender").await;
    // Kim enrols TOTP and a passkey, then loses both.
    let ks = login(&api, "kim@rs.example.test").await;
    let r = api
        .call("POST", "/api/v1/auth/mfa/totp/enrol", &ks, None, &[])
        .await;
    let seed = unbase32(r.json()["secret"].as_str().unwrap());
    let step = totp::step_at(api.clock.now().unix_timestamp());
    let r = api
        .call(
            "POST",
            "/api/v1/auth/mfa/totp/confirm",
            &ks,
            Some(json!({"code": totp::code(&seed, step)})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let old_code = r.json()["recovery_codes"][0].as_str().unwrap().to_owned();
    assert_eq!(
        register(&api, &ks, &Soft::new(), "Lost").await.status,
        StatusCode::CREATED
    );
    let path = format!("/api/v1/users/{kim}/second-factor/reset");
    let body = json!({"identity_verified_by": "video_call"});

    // Not with an API key; not without a recent re-authentication; not without saying
    // how the identity was proved; never oneself.
    let r = api
        .call("POST", &path, &t.auth, Some(body.clone()), &[])
        .await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "CS-AUTH-0006".into()));
    api.clock.advance(Duration::from_secs(6 * 60));
    let r = api
        .call("POST", &path, &admin, Some(body.clone()), &[])
        .await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "CS-AUTH-0013".into()));
    let f = api.factors.lock().unwrap().get(&t.email).cloned().unwrap();
    let st = totp::step_at(api.clock.now().unix_timestamp());
    let st = if f.last_step.is_some_and(|l| l >= st) {
        st + 1
    } else {
        st
    };
    let r = api
        .call(
            "POST",
            "/api/v1/auth/reauthenticate",
            &admin,
            Some(json!({"password": PASSWORD, "code": totp::code(&f.seed, st)})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let r = api
        .call(
            "POST",
            &path,
            &admin,
            Some(json!({"identity_verified_by": "asked nicely"})),
            &[],
        )
        .await;
    assert_eq!(
        code(&r),
        (StatusCode::UNPROCESSABLE_ENTITY, "CS-API-0001".into())
    );
    let me = api
        .call("GET", "/api/v1/auth/session", &admin, None, &[])
        .await
        .json();
    let own = format!(
        "/api/v1/users/{}/second-factor/reset",
        me["user_id"].as_str().unwrap()
    );
    let r = api
        .call("POST", &own, &admin, Some(body.clone()), &[])
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    // A member who is not an administrator cannot reset anyone.
    let r = api.call("POST", &path, &ks, Some(body.clone()), &[]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{:?}", r.json());

    let r = api
        .call("POST", &path, &admin, Some(body.clone()), &[])
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    assert_eq!(r.json()["removed"], json!({"totp": true, "passkeys": 1}));
    // Kim's sessions ended; the next sign-in must enrol, though senders owe nothing by
    // policy, and the old recovery code is gone with the factors.
    assert_eq!(reaches(&api, &ks).await, StatusCode::UNAUTHORIZED);
    let k2 = login(&api, "kim@rs.example.test").await;
    let r = api.call("GET", "/api/v1/envelopes", &k2, None, &[]).await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "CS-AUTH-0011".into()));
    assert_eq!(r.json()["detail"], "enrol");
    let r = api
        .call(
            "POST",
            "/api/v1/auth/mfa/verify",
            &k2,
            Some(json!({"recovery_code": old_code})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let fresh = Soft::new();
    let r = register(&api, &k2, &fresh, "New").await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.json());
    assert_eq!(r.json()["recovery_codes"].as_array().unwrap().len(), 10);
    assert_eq!(reaches(&api, &k2).await, StatusCode::OK);
    // Enrolled again: the reset no longer forces anything beyond the factor itself.
    let me = api
        .call("GET", "/api/v1/auth/session", &k2, None, &[])
        .await
        .json();
    assert_eq!(me["factors"]["reset_by_admin"], false);

    // Told by email; the administrative log says who, how proved, and what went; the
    // security log has the event.
    let n = notices(&api, &kim).await;
    assert!(n.contains(&"factors_reset".to_owned()), "{n:?}");
    let logged: Vec<String> = sqlx::query_scalar(
        "SELECT convert_from(canonical, 'UTF8') FROM admin_events WHERE action = 'member.factors_reset'",
    )
    .fetch_all(&api.db.admin)
    .await
    .unwrap();
    assert_eq!(logged.len(), 1, "{logged:?}");
    assert!(
        logged[0].contains("video_call") && logged[0].contains(&kim),
        "{}",
        logged[0]
    );
    assert!(
        api.security
            .lines()
            .iter()
            .any(|l| l.contains("\"auth.mfa_remove\"")
                && l.contains("\"admin\"")
                && l.contains("\"success\""))
    );

    // A member of another workspace too is theirs to keep (SEC-ID-01).
    let shared = member(&api, &t.auth, "lee@rs.example.test", "sender").await;
    let other = api.tenant("rs-other").await;
    let mut tx = api
        .db
        .store
        .for_account(other.boot.account)
        .begin()
        .await
        .unwrap();
    tx.users()
        .add_existing_member(
            casual_sign_store::UserId(uuid::Uuid::parse_str(&shared).unwrap()),
            &Personal("lee@rs.example.test".into()),
            other.boot.profiles[0],
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let r = api
        .call(
            "POST",
            &format!("/api/v1/users/{shared}/second-factor/reset"),
            &admin,
            Some(body),
            &[],
        )
        .await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "CS-API-0015".into()));
}

#[tokio::test]
async fn the_user_replaces_their_own_totp_and_recovery_codes_only_after_proving_the_factor() {
    let Some(api) = Api::new("passkey_replace_own", Rls::On).await else {
        return;
    };
    let t = api.tenant("own").await;
    let s = api.login(&t.email, PASSWORD).await;
    api.clock.advance(Duration::from_secs(6 * 60));
    // Without a fresh proof (password and current code): refused.
    let r = api
        .call("DELETE", "/api/v1/auth/mfa/totp", &s, None, &[])
        .await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "CS-AUTH-0013".into()));
    let r = api
        .call("POST", "/api/v1/auth/mfa/recovery-codes", &s, None, &[])
        .await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "CS-AUTH-0013".into()));
    let r = api
        .call(
            "POST",
            "/api/v1/auth/reauthenticate",
            &s,
            Some(json!({"password": PASSWORD})),
            &[],
        )
        .await;
    assert_eq!(
        code(&r),
        (StatusCode::UNPROCESSABLE_ENTITY, "CS-API-0001".into())
    );
    let f = api.factors.lock().unwrap().get(&t.email).cloned().unwrap();
    let r = api
        .call(
            "POST",
            "/api/v1/auth/reauthenticate",
            &s,
            Some(json!({"password": PASSWORD, "recovery_code": f.recovery[0]})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let r = api
        .call("POST", "/api/v1/auth/mfa/recovery-codes", &s, None, &[])
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let new_codes = r.json()["recovery_codes"].as_array().unwrap().clone();
    assert_eq!(new_codes.len(), 10);
    let r = api
        .call("DELETE", "/api/v1/auth/mfa/totp", &s, None, &[])
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.json());
    // With no factor left the administrator must enrol again (ASVS-31), and the codes
    // went with the factor.
    let r = api.call("GET", "/api/v1/accounts/me", &s, None, &[]).await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "CS-AUTH-0011".into()));
    let r = api
        .call(
            "POST",
            "/api/v1/auth/mfa/verify",
            &s,
            Some(json!({"recovery_code": new_codes[1]})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = api
        .call("POST", "/api/v1/auth/mfa/totp/enrol", &s, None, &[])
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let user = api
        .call("GET", "/api/v1/auth/session", &s, None, &[])
        .await
        .json()["user_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let n = notices(&api, &user).await;
    assert!(
        n.ends_with(&[
            "recovery_codes_replaced".to_owned(),
            "factor_removed".to_owned()
        ]),
        "{n:?}"
    );
}
