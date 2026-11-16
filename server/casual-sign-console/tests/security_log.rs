//! ASVS-08: the console's security events. Every kind the console emits
//! (`Kind::emitted_by(Console)`) is written by a real request: enrolment, sign-in refused
//! and passed, the TOTP step passed and replayed (`reason: reused`, ASVS 2.8.5), a change
//! without its CSRF token (403), an operator created (`admin.change`), sign-out, and
//! sign-in over the rate. Operators are named by id or keyed pseudonym; no line carries
//! an e-mail address, a password or a session secret.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::collections::BTreeSet;

use axum::http::StatusCode;
use casual_sign_console::state::Config;
use casual_sign_seclog::{Kind, Service};
use common::{Session, console_with};
use serde_json::{Value, json};

const OWNER: &str = "owner@ops.example";
const PASSWORD: &str = "owner password 1";

#[tokio::test]
async fn every_console_security_event_is_emitted_without_personal_data() {
    let Some(db) = common::fresh("console_security_log").await else {
        return;
    };
    let c = console_with(&db, Config::default());
    let seed = c.bootstrap(OWNER, PASSWORD).await;
    let none = Session::default();

    // A wrong password, then the password and the TOTP step; the same code again on a
    // second session is refused as reused.
    let r = c
        .call(
            &none,
            "POST",
            "/console/v1/auth/login",
            Some(json!({"email": OWNER, "password": "wrong password 9"})),
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let s = c.password_only(OWNER, PASSWORD).await;
    let code = c.next_code(&seed);
    let r = c
        .call(
            &s,
            "POST",
            "/console/v1/auth/totp",
            Some(json!({"code": code})),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text);
    let s2 = c.password_only(OWNER, PASSWORD).await;
    let r = c
        .call(
            &s2,
            "POST",
            "/console/v1/auth/totp",
            Some(json!({"code": code})),
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.text);

    // A change without the CSRF token; then an operator created.
    let no_csrf = Session {
        cookie: s.cookie.clone(),
        csrf: None,
    };
    let r = c
        .call(
            &no_csrf,
            "POST",
            "/console/v1/operators",
            Some(json!({"email": "obs@ops.example", "roles": ["observer"]})),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.text);
    let r = c
        .call(
            &s,
            "POST",
            "/console/v1/operators",
            Some(json!({"email": "obs@ops.example", "roles": ["observer"]})),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text);
    let enrolment = r.json()["enrolment_token"].as_str().unwrap().to_owned();
    let r = c.call(&s, "POST", "/console/v1/auth/logout", None).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.text);

    // Over the sign-in rate for one address (5 a minute).
    let mut limited = false;
    for _ in 0..7 {
        let r = c
            .call(
                &none,
                "POST",
                "/console/v1/auth/login",
                Some(json!({"email": "nobody@ops.example", "password": "x"})),
            )
            .await;
        limited |= r.status == StatusCode::TOO_MANY_REQUESTS;
    }
    assert!(limited);

    let lines = c.security.json();
    let seen: BTreeSet<&str> = lines.iter().filter_map(|l| l["kind"].as_str()).collect();
    for k in Kind::emitted_by(Service::Console) {
        assert!(
            seen.contains(k.as_str()),
            "not emitted: {k:?} in {lines:#?}"
        );
    }
    let of = |kind: Kind| -> Vec<&Value> {
        lines
            .iter()
            .filter(|l| l["kind"] == kind.as_str())
            .collect()
    };
    let owner = of(Kind::SignIn)
        .into_iter()
        .find(|l| l["outcome"] == "success")
        .unwrap()["principal"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(owner.starts_with("operator:"), "{owner}");
    let refused: Vec<&Value> = of(Kind::SignIn)
        .into_iter()
        .filter(|l| l["outcome"] == "failure")
        .collect();
    assert!(
        refused
            .iter()
            .all(|l| l["principal"].as_str().unwrap().starts_with("subject:p1:")),
        "{refused:?}"
    );
    assert!(
        of(Kind::Mfa).iter().any(|l| l["outcome"] == "failure"
            && l["reason"] == "reused"
            && l["principal"] == owner.as_str()),
        "ASVS 2.8.5"
    );
    let denied = of(Kind::Denied);
    assert_eq!(denied[0]["code"], "CS-CON-0013");
    assert_eq!(denied[0]["principal"], owner.as_str());
    assert!(denied[0]["request_id"].is_string());
    let change = of(Kind::AdminChange);
    assert_eq!(change[0]["route"], "/console/v1/operators");
    for raw in c.security.lines() {
        assert!(raw.contains(r#""service":"console""#), "{raw}");
        assert!(!raw.contains('@'), "an e-mail address: {raw}");
        assert!(
            !raw.contains(PASSWORD) && !raw.contains(&enrolment),
            "{raw}"
        );
        for secret in [s.cookie.as_deref(), s.csrf.as_deref()]
            .into_iter()
            .flatten()
        {
            assert!(!raw.contains(secret), "{raw}");
        }
    }
}
