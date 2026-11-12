//! Console API contract tests against PostgreSQL 17: operator enrolment and sign-in with
//! a mandatory second factor, deny-by-default authorization on every route, CSRF, the
//! operator log, the read and write endpoints, and isolation: no console response carries
//! tenant personal data or agreement content (`SEC-X01`, `SEC-X03`, `SEC-X04`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    missing_docs
)]

mod common;

use axum::http::StatusCode;
use casual_sign_platform_store::sqlx;
use common::{Console, Resp, SEEDED_SECRETS, Session};
use serde_json::json;

const OWNER: &str = "owner@ops.example";
const PASSWORD: &str = "correct horse battery staple";

fn concrete(path: &str, id: &str) -> String {
    path.replace("{id}", id)
}

fn assert_clean(r: &Resp, what: &str) {
    for s in SEEDED_SECRETS {
        assert!(
            !r.text.contains(s),
            "{what}: response carries seeded tenant data {s:?}"
        );
    }
}

/// Every non-public route refuses a caller with no session (`CS-CON-0001`) and a caller
/// whose session has only passed the password (`CS-CON-0002`).
#[tokio::test]
async fn every_route_needs_a_session_with_its_second_factor() {
    let Some(db) = common::fresh("every_route_needs_a_session_with_its_second_factor").await else {
        return;
    };
    let seed = db.seed().await;
    let c = common::console(&db);
    c.bootstrap(OWNER, PASSWORD).await;
    let half = c.password_only(OWNER, PASSWORD).await;
    for (method, path, roles) in casual_sign_console::ROUTES {
        if *roles == "public" {
            continue;
        }
        let p = concrete(path, &seed.org.to_string());
        let body = (*method != "GET").then(|| json!({}));
        let r = c.call(&Session::default(), method, &p, body.clone()).await;
        assert_eq!(
            r.status,
            StatusCode::UNAUTHORIZED,
            "{method} {p} without a session"
        );
        assert_eq!(r.code(), "CS-CON-0001", "{method} {p}");
        if *roles == "pending" {
            continue;
        }
        let r = c.call(&half, method, &p, body).await;
        assert_eq!(
            r.status,
            StatusCode::UNAUTHORIZED,
            "{method} {p} password only"
        );
        assert_eq!(r.code(), "CS-CON-0002", "{method} {p} password only");
    }
    db.drop().await;
}

/// Enrolment, sign-in, the second factor's single use, sign-out, and what each records.
#[tokio::test]
async fn operators_enrol_and_sign_in_with_a_single_use_second_factor() {
    let Some(db) =
        common::fresh("operators_enrol_and_sign_in_with_a_single_use_second_factor").await
    else {
        return;
    };
    let c = common::console(&db);
    let seed = c.bootstrap(OWNER, PASSWORD).await;

    // Wrong password, unknown e-mail: the same refusal.
    for (email, pw) in [
        (OWNER, "wrong password here"),
        ("nobody@ops.example", PASSWORD),
    ] {
        let r = c
            .call(
                &Session::default(),
                "POST",
                "/console/v1/auth/login",
                Some(json!({"email": email, "password": pw})),
            )
            .await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (StatusCode::UNAUTHORIZED, "CS-CON-0001")
        );
    }

    // A wrong code, then the right one, then the same code again on a new session.
    let s = c.password_only(OWNER, PASSWORD).await;
    let r = c
        .call(
            &s,
            "POST",
            "/console/v1/auth/totp",
            Some(json!({"code": "000000"})),
        )
        .await;
    assert_eq!(r.code(), "CS-CON-0002");
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
    assert_eq!(r.json()["roles"], json!(["platform_owner"]));
    let me = c.call(&s, "GET", "/console/v1/me", None).await;
    assert_eq!(me.status, StatusCode::OK);
    let again = c.password_only(OWNER, PASSWORD).await;
    let r = c
        .call(
            &again,
            "POST",
            "/console/v1/auth/totp",
            Some(json!({"code": code})),
        )
        .await;
    assert_eq!(r.code(), "CS-CON-0002", "a used code is refused");

    // TOTP without the CSRF token is refused.
    let mut no_csrf = again.clone();
    no_csrf.csrf = None;
    let r = c
        .call(
            &no_csrf,
            "POST",
            "/console/v1/auth/totp",
            Some(json!({"code": c.next_code(&seed)})),
        )
        .await;
    assert_eq!(r.code(), "CS-CON-0013");

    // An enrolment token works once.
    let r = c
        .call(
            &s,
            "POST",
            "/console/v1/operators",
            Some(json!({"email": "obs@ops.example", "roles": ["observer"]})),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text);
    let token = r.json()["enrolment_token"].as_str().unwrap().to_owned();
    c.enrol(&token, "observer password 1").await;
    let r = c
        .call(
            &Session::default(),
            "POST",
            "/console/v1/auth/enrolment/begin",
            Some(json!({"token": token})),
        )
        .await;
    assert_eq!(r.code(), "CS-CON-0001", "a spent enrolment token");

    // Idle for more than 30 minutes ends the session.
    c.clock.advance(31 * 60);
    assert_eq!(
        c.call(&s, "GET", "/console/v1/me", None).await.code(),
        "CS-CON-0001"
    );

    // Sign-out ends it at once.
    let s = c.sign_in(OWNER, PASSWORD, &seed).await;
    assert_eq!(
        c.call(&s, "POST", "/console/v1/auth/logout", None)
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        c.call(&s, "GET", "/console/v1/me", None).await.code(),
        "CS-CON-0001"
    );

    // The log records each step, verifies, and names no e-mail.
    let s = c.sign_in(OWNER, PASSWORD, &seed).await;
    let log = c
        .call(&s, "GET", "/console/v1/operator-log?limit=200", None)
        .await;
    let actions: Vec<String> = log.json()["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap().to_owned())
        .collect();
    for a in [
        "operator.enrolled",
        "operator.sign_in_refused",
        "operator.session_opened",
        "operator.signed_in",
        "operator.operator_created",
        "operator.signed_out",
    ] {
        assert!(actions.iter().any(|x| x == a), "missing {a} in {actions:?}");
    }
    assert!(!log.text.contains(OWNER) && !log.text.contains("obs@ops.example"));
    let v = c
        .call(&s, "GET", "/console/v1/operator-log/verify", None)
        .await;
    assert_eq!(v.json()["verified"], json!(true), "{}", v.text);
    db.drop().await;
}

/// Roles decide, deny by default: an observer reads but cannot write; only a platform
/// owner manages operators; adding a platform owner needs a second operator.
#[tokio::test]
async fn roles_gate_every_write() {
    let Some(db) = common::fresh("roles_gate_every_write").await else {
        return;
    };
    let seed = db.seed().await;
    let c = common::console(&db);
    let owner_seed = c.bootstrap(OWNER, PASSWORD).await;
    let owner = c.sign_in(OWNER, PASSWORD, &owner_seed).await;
    let r = c
        .call(
            &owner,
            "POST",
            "/console/v1/operators",
            Some(json!({"email": "o2@ops.example", "roles": ["platform_owner"]})),
        )
        .await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::CONFLICT, "CS-CON-0004"),
        "{}",
        r.text
    );
    let r = c
        .call(
            &owner,
            "POST",
            "/console/v1/operators",
            Some(json!({"email": "obs@ops.example", "roles": ["observer"]})),
        )
        .await;
    let token = r.json()["enrolment_token"].as_str().unwrap().to_owned();
    let obs_seed = c.enrol(&token, "observer password 1").await;
    let obs = c
        .sign_in("obs@ops.example", "observer password 1", &obs_seed)
        .await;

    let org = seed.org.to_string();
    let ws = seed.workspace.to_string();
    for (method, path, body) in [
        (
            "PATCH",
            format!("/console/v1/organizations/{org}"),
            json!({"name": "X"}),
        ),
        (
            "PATCH",
            format!("/console/v1/workspaces/{ws}"),
            json!({"status": "archived"}),
        ),
        (
            "POST",
            "/console/v1/operators".to_owned(),
            json!({"email": "x@ops.example", "roles": ["observer"]}),
        ),
        ("GET", "/console/v1/operators".to_owned(), json!(null)),
        ("GET", "/console/v1/operator-log".to_owned(), json!(null)),
    ] {
        let body = (method != "GET").then_some(body);
        let r = c.call(&obs, method, &path, body).await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (StatusCode::FORBIDDEN, "CS-CON-0003"),
            "observer {method} {path}"
        );
    }
    for path in [
        format!("/console/v1/organizations/{org}"),
        "/console/v1/health".to_owned(),
    ] {
        assert_eq!(
            c.call(&obs, "GET", &path, None).await.status,
            StatusCode::OK,
            "observer GET {path}"
        );
    }
    // The database re-checks the role: an observer's session cannot run a write function.
    let token_sha = casual_sign_console::crypto::sha256(obs.cookie.as_ref().unwrap().as_bytes());
    let mut tx = c.store.begin().await.unwrap();
    let err = tx
        .rename_organization(&token_sha, seed.org, "X", c.clock.get())
        .await
        .unwrap_err();
    assert_eq!(err.code(), "CS-CON-0003");
    drop(tx);
    db.drop().await;
}

/// Reads and writes of organizations and workspaces, the health page, and the scan: no
/// response carries a seeded e-mail, person, subject, message, phone or password hash.
#[tokio::test]
async fn organizations_workspaces_and_health_carry_no_personal_data_or_content() {
    let Some(db) =
        common::fresh("organizations_workspaces_and_health_carry_no_personal_data_or_content")
            .await
    else {
        return;
    };
    let seed = db.seed().await;
    let c = common::console(&db);
    let owner_seed = c.bootstrap(OWNER, PASSWORD).await;
    let s = c.sign_in(OWNER, PASSWORD, &owner_seed).await;
    let org = seed.org.to_string();
    let ws = seed.workspace.to_string();

    let list = c.call(&s, "GET", "/console/v1/organizations", None).await;
    assert_eq!(list.status, StatusCode::OK);
    let o = &list.json()["organizations"][0];
    assert_eq!(o["name"], json!("Acme Seed Org"));
    assert_eq!(
        o["counts"],
        json!({"workspaces": 1, "members": 1, "envelopes": 1})
    );

    let detail = c
        .call(&s, "GET", &format!("/console/v1/organizations/{org}"), None)
        .await;
    let d = detail.json();
    assert_eq!(d["counts"]["owners"], json!(1));
    assert_eq!(d["workspaces"][0]["id"], json!(ws));
    assert_eq!(d["workspaces"][0]["counts"]["templates"], json!(1));
    assert_eq!(
        d["workspaces"][0]["counts"]["envelopes_in_progress"],
        json!(1)
    );
    let missing = c
        .call(
            &s,
            "GET",
            &format!("/console/v1/organizations/{}", uuid::Uuid::now_v7()),
            None,
        )
        .await;
    assert_eq!(
        (missing.status, missing.code().as_str()),
        (StatusCode::NOT_FOUND, "CS-CON-0011")
    );

    // Writes.
    let r = c
        .call(
            &s,
            "PATCH",
            &format!("/console/v1/organizations/{org}"),
            Some(json!({"name": "Acme Renamed", "data_regions": ["eu", "us"]})),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.text);
    for (body, field) in [
        (json!({"data_regions": ["EU"]}), "data_regions"),
        (json!({"name": ""}), "name"),
        (json!({"policy": {}}), "body"),
    ] {
        let r = c
            .call(
                &s,
                "PATCH",
                &format!("/console/v1/organizations/{org}"),
                Some(body),
            )
            .await;
        assert_eq!(
            (r.status, r.json()["field"].as_str()),
            (StatusCode::UNPROCESSABLE_ENTITY, Some(field)),
            "{}",
            r.text
        );
    }
    let r = c
        .call(
            &s,
            "PATCH",
            &format!("/console/v1/workspaces/{ws}"),
            Some(json!({"data_region": "eu", "status": "archived"})),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.text);
    let r = c
        .call(
            &s,
            "PATCH",
            &format!("/console/v1/workspaces/{ws}"),
            Some(json!({"data_region": "apac"})),
        )
        .await;
    assert_eq!(
        r.json()["field"],
        json!("data_region"),
        "a label the organization does not allow"
    );
    let after = c
        .call(&s, "GET", &format!("/console/v1/organizations/{org}"), None)
        .await
        .json();
    assert_eq!(after["name"], json!("Acme Renamed"));
    assert_eq!(after["data_regions"], json!(["eu", "us"]));
    assert_eq!(after["workspaces"][0]["status"], json!("archived"));
    assert_eq!(after["workspaces"][0]["data_region"], json!("eu"));
    // Without the CSRF token, nothing changes.
    let mut no_csrf = s.clone();
    no_csrf.csrf = Some("wrong".into());
    let r = c
        .call(
            &no_csrf,
            "PATCH",
            &format!("/console/v1/workspaces/{ws}"),
            Some(json!({"status": "active"})),
        )
        .await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::FORBIDDEN, "CS-CON-0013")
    );

    // Health and dead letters.
    let h = c.call(&s, "GET", "/console/v1/health", None).await;
    let hj = h.json();
    assert_eq!(hj["database"]["status"], json!("up"));
    assert_eq!(hj["dead_letters"], json!(1));
    assert_eq!(hj["operator_log"]["verified"], json!(true));
    let queued = hj["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|j| j["status"] == "queued")
        .unwrap();
    assert!(queued["oldest_seconds"].as_i64().unwrap() >= 0);
    let dl = c.call(&s, "GET", "/console/v1/dead-letters", None).await;
    assert_eq!(
        dl.json()["dead_letters"][0]["id"],
        json!(seed.job.to_string())
    );
    assert_eq!(
        dl.json()["dead_letters"][0]["error_code"],
        json!("CS-MAIL-0001")
    );

    // Every event names ids only.
    let log = c
        .call(&s, "GET", "/console/v1/operator-log?limit=200", None)
        .await;
    assert!(
        log.text.contains("operator.organization.renamed")
            && log.text.contains("operator.workspace.archived")
    );
    assert!(
        !log.text.contains("Acme Renamed"),
        "the log never carries an organization name"
    );

    // The scan: every GET route and every response above.
    for r in [&list, &detail, &h, &dl, &log] {
        assert_clean(r, "response");
    }
    for (method, path, _) in casual_sign_console::ROUTES {
        if *method == "GET" {
            let r = c.call(&s, method, &concrete(path, &org), None).await;
            assert_clean(&r, path);
        }
    }
    db.drop().await;
}

/// `SEC-X04`: a row rewritten by someone who can disable triggers (a superuser) is found by
/// verification and by the health page; the console's start-up check refuses it.
#[tokio::test]
async fn a_tampered_operator_log_does_not_verify() {
    let Some(db) = common::fresh("a_tampered_operator_log_does_not_verify").await else {
        return;
    };
    let c: Console = common::console(&db);
    let seed = c.bootstrap(OWNER, PASSWORD).await;
    let s = c.sign_in(OWNER, PASSWORD, &seed).await;
    assert_eq!(c.store.verify_log().await.unwrap().events, 3);
    sqlx::raw_sql(
        "ALTER TABLE platform.operator_events DISABLE TRIGGER USER; \
         UPDATE platform.operator_events SET action = 'operator.signed_up', \
           canonical = convert_to(replace(convert_from(canonical, 'UTF8'), 'signed_in', 'signed_up'), 'UTF8') WHERE seq = 2; \
         ALTER TABLE platform.operator_events ENABLE TRIGGER USER;",
    )
    .execute(&db.owner)
    .await
    .unwrap();
    let err = c.store.verify_log().await.unwrap_err();
    assert_eq!(
        (err.code(), err.to_string().contains("seq 2")),
        ("CS-CON-0007", true),
        "{err}"
    );
    let v = c
        .call(&s, "GET", "/console/v1/operator-log/verify", None)
        .await;
    assert_eq!(
        (v.status, v.code().as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, "CS-CON-0007")
    );
    let h = c.call(&s, "GET", "/console/v1/health", None).await.json();
    assert_eq!(
        h["operator_log"],
        json!({"verified": false, "code": "CS-CON-0007"})
    );
    db.drop().await;
}

/// Sign-in attempts are rate limited per address and per e-mail.
#[tokio::test]
async fn sign_in_is_rate_limited() {
    let Some(db) = common::fresh("sign_in_is_rate_limited").await else {
        return;
    };
    let c = common::console(&db);
    let mut codes = Vec::new();
    for _ in 0..7 {
        let r = c
            .call(
                &Session::default(),
                "POST",
                "/console/v1/auth/login",
                Some(json!({"email": OWNER, "password": "x"})),
            )
            .await;
        codes.push(r.code());
    }
    assert_eq!(codes[..5], ["CS-CON-0001"; 5]);
    assert_eq!(codes[5..], ["CS-CON-0012"; 2]);
    db.drop().await;
}
