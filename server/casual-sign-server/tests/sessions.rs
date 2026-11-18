//! ASVS-06 and ASVS-07: staff session idle timeout and absolute lifetime, a person's
//! list of their own sessions with ending any or all, and step-up re-authentication
//! before sensitive actions. On PostgreSQL through the router (`OPENSEAL_TEST_DATABASE_URL`).

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
use common::harness::{Api, Auth, PASSWORD, Resp, session_of};
use serde_json::{Value, json};

const MIN: u64 = 60;
const FIREFOX: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0";
const SAFARI: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";

fn is(r: &Resp, status: StatusCode, code: Option<&str>, what: &str) -> Value {
    assert_eq!(r.status, status, "{what}: {:?}", r.json());
    if let Some(c) = code {
        assert_eq!(r.code(), c, "{what}: {:?}", r.json());
    }
    r.json()
}

fn advance(api: &Api, secs: u64) {
    api.clock.advance(Duration::from_secs(secs));
}

/// Sign `email` in from a browser named by `ua`, passing any second factor owed.
async fn login_from(api: &Api, email: &str, ua: &str) -> Auth {
    let r = api
        .call(
            "POST",
            "/api/v1/auth/login",
            &Auth::None,
            Some(json!({"email": email, "password": PASSWORD})),
            &[("user-agent", ua)],
        )
        .await;
    is(&r, StatusCode::OK, None, "login");
    let s = session_of(&r);
    api.pass_factor(email, &s).await;
    s
}

async fn get(api: &Api, s: &Auth, path: &str) -> Resp {
    api.call("GET", path, s, None, &[]).await
}

/// A TOTP code for `email` that the server has not seen yet (the harness enrolled it).
fn fresh_code(api: &Api, email: &str) -> String {
    let mut f = api.factors.lock().unwrap();
    let f = f.get_mut(email).expect("enrolled by the harness");
    let now = totp::step_at(api.clock.now().unix_timestamp());
    let step = [now, now + 1]
        .into_iter()
        .find(|s| f.last_step.is_none_or(|l| *s > l))
        .expect("a step not used yet");
    f.last_step = Some(step);
    totp::code(&f.seed, step)
}

async fn reauth(api: &Api, s: &Auth, body: Value) -> Resp {
    api.call("POST", "/api/v1/auth/reauthenticate", s, Some(body), &[])
        .await
}

fn session_ids(list: &Value) -> Vec<(String, bool)> {
    list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                x["id"].as_str().unwrap().to_owned(),
                x["current"].as_bool().unwrap(),
            )
        })
        .collect()
}

#[tokio::test]
async fn an_idle_session_ends_and_activity_keeps_one_until_its_absolute_limit() {
    let Some(api) = Api::new("sessions_idle_and_lifetime", Rls::On).await else {
        return;
    };
    let t = api.tenant("idle").await;
    // Default idle limit, 30 minutes: 29 minutes apart is still in use.
    let s = login_from(&api, &t.email, FIREFOX).await;
    advance(&api, 29 * MIN);
    is(
        &get(&api, &s, "/api/v1/envelopes").await,
        StatusCode::OK,
        None,
        "29 min",
    );
    advance(&api, 30 * MIN);
    let r = get(&api, &s, "/api/v1/envelopes").await;
    is(&r, StatusCode::UNAUTHORIZED, Some("CS-AUTH-0002"), "idle");
    assert_eq!(r.json()["detail"], "idle");

    // Requests every 20 minutes keep a session alive, but never past the absolute
    // limit (8 hours by default).
    let s = login_from(&api, &t.email, FIREFOX).await;
    for _ in 0..23 {
        advance(&api, 20 * MIN);
        is(
            &get(&api, &s, "/api/v1/envelopes").await,
            StatusCode::OK,
            None,
            "active",
        );
    }
    advance(&api, 20 * MIN); // 8 h after sign-in
    let r = get(&api, &s, "/api/v1/envelopes").await;
    is(&r, StatusCode::UNAUTHORIZED, None, "lifetime");
    assert!(
        r.code() == "CS-AUTH-0002" || r.code() == "CS-AUTH-0001",
        "{:?}",
        r.json()
    );

    // The workspace's own idle limit (a security setting, so step-up applies: the API key
    // is not asked) reaches sessions already open.
    let s = login_from(&api, &t.email, FIREFOX).await;
    let r = api
        .call(
            "PATCH",
            "/api/v1/accounts/me",
            &t.auth,
            Some(json!({"settings": {"session_idle": 299}})),
            &[],
        )
        .await;
    is(
        &r,
        StatusCode::UNPROCESSABLE_ENTITY,
        Some("CS-API-0001"),
        "too short",
    );
    let r = api
        .call(
            "PATCH",
            "/api/v1/accounts/me",
            &t.auth,
            Some(json!({"settings": {"session_idle": 600, "session_max_age": 3600}})),
            &[],
        )
        .await;
    is(&r, StatusCode::OK, None, "set limits");
    advance(&api, 9 * MIN);
    is(
        &get(&api, &s, "/api/v1/envelopes").await,
        StatusCode::OK,
        None,
        "9 min",
    );
    advance(&api, 10 * MIN);
    let r = get(&api, &s, "/api/v1/envelopes").await;
    is(
        &r,
        StatusCode::UNAUTHORIZED,
        Some("CS-AUTH-0002"),
        "10 min idle",
    );
    assert_eq!(r.json()["detail"], "idle");
    // A new sign-in lasts the workspace's absolute limit, an hour.
    let s = login_from(&api, &t.email, FIREFOX).await;
    for _ in 0..6 {
        advance(&api, 9 * MIN);
        is(
            &get(&api, &s, "/api/v1/envelopes").await,
            StatusCode::OK,
            None,
            "within the hour",
        );
    }
    advance(&api, 6 * MIN);
    let r = get(&api, &s, "/api/v1/envelopes").await;
    is(&r, StatusCode::UNAUTHORIZED, None, "past the hour");
    api.db.drop().await;
}

#[tokio::test]
async fn the_organizations_stricter_idle_limit_applies_and_a_looser_workspace_one_is_refused() {
    let Some(api) = Api::new("sessions_org_idle", Rls::On).await else {
        return;
    };
    let t = api.tenant("orgidle").await;
    let s = login_from(&api, &t.email, FIREFOX).await;
    let r = api
        .call(
            "PATCH",
            "/api/v1/organizations/me",
            &s,
            Some(json!({"policy": {"session.idle": {"value": 900}}})),
            &[],
        )
        .await;
    is(&r, StatusCode::OK, None, "org policy");
    let r = api
        .call(
            "PATCH",
            "/api/v1/accounts/me",
            &t.auth,
            Some(json!({"settings": {"session_idle": 1200}})),
            &[],
        )
        .await;
    is(
        &r,
        StatusCode::UNPROCESSABLE_ENTITY,
        Some("CS-ORG-0002"),
        "looser",
    );
    advance(&api, 15 * MIN);
    let r = get(&api, &s, "/api/v1/envelopes").await;
    is(
        &r,
        StatusCode::UNAUTHORIZED,
        Some("CS-AUTH-0002"),
        "org idle",
    );
    api.db.drop().await;
}

#[tokio::test]
async fn a_person_lists_their_own_sessions_and_ends_others_after_re_authenticating() {
    let Some(api) = Api::new("sessions_list_and_end", Rls::On).await else {
        return;
    };
    let t = api.tenant("own").await;
    let other = api.tenant("other").await;
    let laptop = login_from(&api, &t.email, FIREFOX).await;
    let phone = login_from(&api, &t.email, SAFARI).await;
    let tablet = login_from(&api, &t.email, SAFARI).await;
    let theirs = login_from(&api, &other.email, FIREFOX).await;

    let l = is(
        &get(&api, &laptop, "/api/v1/auth/sessions").await,
        StatusCode::OK,
        None,
        "list",
    );
    let ids = session_ids(&l);
    // The three, and the one `tenant` signed in with to make its key.
    assert_eq!(ids.len(), 4, "{l}");
    assert_eq!(ids.iter().filter(|(_, c)| *c).count(), 1, "{l}");
    let items = l["items"].as_array().unwrap();
    let mine = items.iter().find(|x| x["current"] == true).unwrap();
    assert_eq!(mine["client"], "Firefox on Linux");
    assert_eq!(mine["workspace"]["id"], t.boot.account.to_string());
    assert!(items.iter().any(|x| x["client"] == "Safari on iOS"));
    // The other user's session is not in it.
    let their_list = is(
        &get(&api, &theirs, "/api/v1/auth/sessions").await,
        StatusCode::OK,
        None,
        "theirs",
    );
    let (their_id, _) = session_ids(&their_list).into_iter().next().unwrap();
    assert!(!ids.iter().any(|(i, _)| *i == their_id));
    let phone_id = session_ids(&is(
        &get(&api, &phone, "/api/v1/auth/sessions").await,
        StatusCode::OK,
        None,
        "phone",
    ))
    .into_iter()
    .find(|(_, c)| *c)
    .unwrap()
    .0;
    // An API key has no sessions.
    let r = get(&api, &t.auth, "/api/v1/auth/sessions").await;
    is(
        &r,
        StatusCode::UNPROCESSABLE_ENTITY,
        Some("CS-API-0001"),
        "key",
    );

    // Signed in a minute ago: ending one is served at once.
    let r = api
        .call(
            "DELETE",
            &format!("/api/v1/auth/sessions/{phone_id}"),
            &laptop,
            None,
            &[],
        )
        .await;
    is(&r, StatusCode::NO_CONTENT, None, "end phone");
    is(
        &get(&api, &phone, "/api/v1/envelopes").await,
        StatusCode::UNAUTHORIZED,
        None,
        "phone ended",
    );
    // Not one's own current session, and never another user's (another workspace's).
    let r = api
        .call(
            "DELETE",
            &format!("/api/v1/auth/sessions/{their_id}"),
            &laptop,
            None,
            &[],
        )
        .await;
    is(
        &r,
        StatusCode::NOT_FOUND,
        Some("CS-API-0002"),
        "another user's",
    );
    is(
        &get(&api, &theirs, "/api/v1/envelopes").await,
        StatusCode::OK,
        None,
        "theirs lives",
    );

    // Six minutes later the window has closed: ending the tablet needs the password
    // again, and the second factor (the administrator has one).
    advance(&api, 6 * MIN);
    let r = api
        .call(
            "POST",
            "/api/v1/auth/sessions/end-others",
            &laptop,
            None,
            &[],
        )
        .await;
    let p = is(&r, StatusCode::FORBIDDEN, Some("CS-AUTH-0013"), "stale");
    assert_eq!(p["detail"], "reauthenticate");
    let r = get(&api, &laptop, "/api/v1/auth/session").await;
    assert_eq!(r.json()["reauthenticated_until"], Value::Null);
    is(
        &reauth(&api, &laptop, json!({"password": "wrong password here"})).await,
        StatusCode::UNAUTHORIZED,
        Some("CS-AUTH-0007"),
        "wrong password",
    );
    is(
        &reauth(&api, &laptop, json!({"password": PASSWORD})).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        Some("CS-API-0001"),
        "factor missing",
    );
    is(
        &reauth(
            &api,
            &laptop,
            json!({"password": PASSWORD, "code": "000000"}),
        )
        .await,
        StatusCode::UNAUTHORIZED,
        Some("CS-AUTH-0012"),
        "wrong code",
    );
    let code = fresh_code(&api, &t.email);
    let r = reauth(&api, &laptop, json!({"password": PASSWORD, "code": code})).await;
    is(&r, StatusCode::OK, None, "reauth");
    // The same code again is refused (single use).
    is(
        &reauth(&api, &laptop, json!({"password": PASSWORD, "code": code})).await,
        StatusCode::UNAUTHORIZED,
        Some("CS-AUTH-0012"),
        "replayed code",
    );
    let r = get(&api, &laptop, "/api/v1/auth/session").await;
    assert!(
        r.json()["reauthenticated_until"].is_string(),
        "{:?}",
        r.json()
    );
    let r = api
        .call(
            "POST",
            "/api/v1/auth/sessions/end-others",
            &laptop,
            None,
            &[],
        )
        .await;
    // The tablet and the harness's own sign-in.
    assert_eq!(is(&r, StatusCode::OK, None, "end others")["ended"], 2);
    is(
        &get(&api, &tablet, "/api/v1/envelopes").await,
        StatusCode::UNAUTHORIZED,
        None,
        "tablet ended",
    );
    is(
        &get(&api, &laptop, "/api/v1/envelopes").await,
        StatusCode::OK,
        None,
        "laptop lives",
    );
    is(
        &get(&api, &theirs, "/api/v1/envelopes").await,
        StatusCode::OK,
        None,
        "theirs still lives",
    );
    let l = is(
        &get(&api, &laptop, "/api/v1/auth/sessions").await,
        StatusCode::OK,
        None,
        "after",
    );
    assert_eq!(session_ids(&l).len(), 1, "{l}");
    api.db.drop().await;
}

#[tokio::test]
async fn sensitive_actions_need_a_recent_re_authentication_from_a_session_only() {
    let Some(api) = Api::new("sessions_step_up", Rls::On).await else {
        return;
    };
    let t = api.tenant("stepup").await;
    let s = login_from(&api, &t.email, FIREFOX).await;
    // A member to change the role of.
    let r = api
        .call(
            "POST",
            "/api/v1/users",
            &t.auth,
            Some(json!({"email": "m@stepup.example.test", "name": "M", "profile": "sender", "password": PASSWORD})),
            &[],
        )
        .await;
    let member = is(&r, StatusCode::CREATED, None, "member")["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let r = api
        .call(
            "POST",
            "/api/v1/webhooks",
            &t.auth,
            Some(json!({"url": "https://hooks.example.com/a", "event_types": ["envelope.sent"], "secret_refs": ["k"]})),
            &[],
        )
        .await;
    let hook = is(&r, StatusCode::CREATED, None, "hook")["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let calls: Vec<(&str, String, Value)> = vec![
        (
            "POST",
            "/api/v1/api-clients".into(),
            json!({"name": "k2", "kind": "api_key", "scopes": ["envelopes:read"]}),
        ),
        (
            "PATCH",
            format!("/api/v1/users/{member}"),
            json!({"profile": "admin"}),
        ),
        (
            "POST",
            "/api/v1/users".into(),
            json!({"email": "a2@stepup.example.test", "name": "A2", "profile": "admin", "password": PASSWORD}),
        ),
        (
            "POST",
            "/api/v1/webhooks".into(),
            json!({"url": "https://hooks.example.com/b", "event_types": ["envelope.sent"], "secret_refs": ["k"]}),
        ),
        (
            "PATCH",
            format!("/api/v1/webhooks/{hook}"),
            json!({"url": "https://hooks.example.com/c"}),
        ),
        (
            "PATCH",
            "/api/v1/accounts/me".into(),
            json!({"settings": {"mfa_policy": "everyone"}}),
        ),
        (
            "PATCH",
            "/api/v1/accounts/me".into(),
            json!({"settings": {"session_idle": 900}}),
        ),
        (
            "PATCH",
            "/api/v1/organizations/me".into(),
            json!({"policy": {"session.idle": {"value": 3600}}}),
        ),
        (
            "POST",
            "/api/v1/permission-profiles".into(),
            json!({"name": "Auditors", "permissions": ["audit.read"]}),
        ),
    ];
    // Stale: every one refused, nothing changed.
    advance(&api, 5 * MIN + 1);
    for (m, p, b) in &calls {
        let r = api.call(m, p, &s, Some(b.clone()), &[]).await;
        is(
            &r,
            StatusCode::FORBIDDEN,
            Some("CS-AUTH-0013"),
            &format!("{m} {p}"),
        );
    }
    let r = get(&api, &t.auth, &format!("/api/v1/users/{member}")).await;
    assert_ne!(r.json()["profile"], "admin", "{:?}", r.json());
    // What is not sensitive is still served.
    is(
        &get(&api, &s, "/api/v1/api-clients").await,
        StatusCode::OK,
        None,
        "read",
    );
    let r = api
        .call(
            "PATCH",
            "/api/v1/accounts/me",
            &s,
            Some(json!({"settings": {"first_reminder_days": 3}})),
            &[],
        )
        .await;
    is(&r, StatusCode::OK, None, "not a security setting");

    // After re-authenticating, every one is served.
    let code = fresh_code(&api, &t.email);
    is(
        &reauth(&api, &s, json!({"password": PASSWORD, "code": code})).await,
        StatusCode::OK,
        None,
        "reauth",
    );
    for (m, p, b) in &calls {
        let r = api.call(m, p, &s, Some(b.clone()), &[]).await;
        assert!(r.status.is_success(), "{m} {p}: {:?}", r.json());
    }
    // An API key is never asked: it is a credential of its own.
    advance(&api, 10 * MIN);
    let r = api
        .call(
            "POST",
            "/api/v1/api-clients",
            &t.auth,
            Some(calls[0].2.clone()),
            &[],
        )
        .await;
    is(&r, StatusCode::CREATED, None, "key");
    api.db.drop().await;
}

#[tokio::test]
async fn a_workspace_switch_carries_the_re_authentication_without_extending_it() {
    let Some(api) = Api::new("sessions_switch_carries", Rls::On).await else {
        return;
    };
    let t = api.tenant("carry").await;
    let s = login_from(&api, &t.email, FIREFOX).await;
    let r = api
        .call(
            "POST",
            "/api/v1/organizations/me/workspaces",
            &s,
            Some(json!({"name": "Legal"})),
            &[],
        )
        .await;
    let w = is(&r, StatusCode::CREATED, None, "ws")["id"]
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
    advance(&api, 3 * MIN);
    let r = api
        .call(
            "POST",
            "/api/v1/auth/switch",
            &s,
            Some(json!({"account_id": w})),
            &[],
        )
        .await;
    is(&r, StatusCode::OK, None, "switch");
    let s2 = session_of(&r);
    // Still within the sign-in's five minutes: served.
    let k = json!({"name": "k", "kind": "api_key", "scopes": ["envelopes:read"]});
    let r = api
        .call("POST", "/api/v1/api-clients", &s2, Some(k.clone()), &[])
        .await;
    is(&r, StatusCode::CREATED, None, "fresh after switch");
    // Two more minutes: the sign-in's window has passed; the switch did not extend it.
    advance(&api, 2 * MIN + 1);
    let r = api
        .call("POST", "/api/v1/api-clients", &s2, Some(k), &[])
        .await;
    is(
        &r,
        StatusCode::FORBIDDEN,
        Some("CS-AUTH-0013"),
        "not extended",
    );
    // The list shows the new session in the new workspace, current.
    let l = is(
        &get(&api, &s2, "/api/v1/auth/sessions").await,
        StatusCode::OK,
        None,
        "list",
    );
    let cur = l["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["current"] == true)
        .unwrap()
        .clone();
    assert_eq!(cur["workspace"]["id"], w);
    assert_eq!(cur["client"], "Firefox on Linux");
    api.db.drop().await;
}
