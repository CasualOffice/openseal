//! Plans in the console (PLAN-02, docs/23 §7.1): `hard` enforcement on an approximate
//! meter is `CS-PLAN-0006` from the console and from the database (SQLSTATE `OS010`) for
//! plans and overrides alike; plan versions, assignments and overrides through the API,
//! with their boundaries and operator events; and the plan rows' immutability.

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
use casual_sign_console::crypto::sha256;
use casual_sign_platform_store::sqlx;
use common::{Console, Session};
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

const OWNER: &str = "owner@ops.example";
const PASSWORD: &str = "correct horse battery staple";

async fn owner(c: &Console) -> Session {
    let seed = c.bootstrap(OWNER, PASSWORD).await;
    c.sign_in(OWNER, PASSWORD, &seed).await
}

fn team(limit_api: &str) -> Value {
    json!({
        "key": "team",
        "name": "Team",
        "entitlements": {"api": true, "bulk_send": false},
        "quotas": [
            {"meter": "envelopes_sent", "limit": 100, "period": "month", "enforcement": "hard", "level": "organization"},
            {"meter": "envelopes_sent", "limit": 40, "period": "month", "enforcement": "hard", "level": "workspace"},
            {"meter": "api_calls", "limit": 1000, "period": "month", "enforcement": limit_api, "level": "organization"},
        ],
        "seat_rule": "can_send",
    })
}

fn sqlstate(err: &sqlx::Error) -> String {
    err.as_database_error()
        .and_then(|d| d.code())
        .map(|c| c.into_owned())
        .unwrap_or_default()
}

#[tokio::test]
async fn hard_on_an_approximate_meter_is_cs_plan_0006_from_the_console_and_the_database() {
    let Some(db) = common::fresh(
        "hard_on_an_approximate_meter_is_cs_plan_0006_from_the_console_and_the_database",
    )
    .await
    else {
        return;
    };
    let seed = db.seed().await;
    let c = common::console(&db);
    let s = owner(&c).await;

    // The console refuses it, naming the field.
    let r = c
        .call(&s, "POST", "/console/v1/plans", Some(team("hard")))
        .await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, "CS-PLAN-0006"),
        "{}",
        r.text
    );
    assert_eq!(r.json()["field"], "quotas");
    let r = c
        .call(&s, "POST", "/console/v1/plans", Some(team("soft")))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text);

    // As an override too.
    let r = c
        .call(
            &s,
            "POST",
            &format!("/console/v1/organizations/{}/plan-overrides", seed.org),
            Some(json!({"key": "quota.api_calls.organization.enforcement", "value": "hard", "reason": "test"})),
        )
        .await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, "CS-PLAN-0006"),
        "{}",
        r.text
    );

    // The database refuses it again for a caller that skips the console's check: the
    // console's own role, with a live session, straight to the definer functions.
    let token = sha256(s.cookie.as_deref().unwrap().as_bytes());
    let now = c.clock.get();
    let err = sqlx::query(
        "SELECT platform.create_plan($1, gen_random_uuid(), 'direct', 'Direct', '{}'::jsonb, $2, 'can_send', $3)",
    )
    .bind(token.as_slice())
    .bind(json!([{"meter": "api_calls", "limit": 5, "period": "month", "enforcement": "hard", "level": "organization"}]))
    .bind(now)
    .execute(&db.console)
    .await
    .expect_err("hard on api_calls through create_plan");
    assert_eq!(sqlstate(&err), "OS010");
    let err = sqlx::query(
        "SELECT platform.set_plan_override($1, gen_random_uuid(), $2, NULL, \
         'quota.api_calls.organization.enforcement', 'hard', 'direct', NULL, $3)",
    )
    .bind(token.as_slice())
    .bind(seed.org)
    .bind(now)
    .execute(&db.console)
    .await
    .expect_err("hard on api_calls through set_plan_override");
    assert_eq!(sqlstate(&err), "OS010");

    // And the tables refuse it for the owner, who bypasses the functions.
    let plan: Uuid = sqlx::query_scalar("SELECT id FROM platform.plans WHERE key = 'team'")
        .fetch_one(&db.owner)
        .await
        .unwrap();
    let err = sqlx::query(
        "INSERT INTO platform.plan_quotas (plan_id, meter, \"limit\", period, enforcement, level) \
         VALUES ($1, 'api_calls', 1, 'month', 'hard', 'workspace')",
    )
    .bind(plan)
    .execute(&db.owner)
    .await
    .expect_err("owner insert");
    assert_eq!(sqlstate(&err), "23514");
    db.drop().await;
}

#[tokio::test]
async fn plans_assignments_and_overrides_through_the_console() {
    let Some(db) = common::fresh("plans_assignments_and_overrides_through_the_console").await
    else {
        return;
    };
    let seed = db.seed().await;
    let c = common::console(&db);
    let s = owner(&c).await;
    let org = seed.org;

    // Two versions of one key, then the catalogue.
    let v1 = c
        .call(&s, "POST", "/console/v1/plans", Some(team("soft")))
        .await;
    assert_eq!(v1.status, StatusCode::CREATED, "{}", v1.text);
    assert_eq!(v1.json()["version"], 1);
    let mut body = team("notify");
    body["name"] = json!("Team 2026");
    let v2 = c.call(&s, "POST", "/console/v1/plans", Some(body)).await;
    assert_eq!(v2.json()["version"], 2);
    let p1 = v1.json()["id"].as_str().unwrap().to_owned();
    let p2 = v2.json()["id"].as_str().unwrap().to_owned();
    let list = c.call(&s, "GET", "/console/v1/plans", None).await;
    assert_eq!(list.status, StatusCode::OK);
    let plans = list.json()["plans"].as_array().unwrap().clone();
    assert_eq!(plans.len(), 2);
    assert_eq!(plans[0]["version"], 2, "newest version first");
    assert_eq!(plans[0]["entitlements"]["api"], true);
    assert_eq!(
        plans[0]["entitlements"]["scim"], false,
        "every feature listed"
    );
    assert!(
        list.json()["catalogue"]["meters"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["name"] == "api_calls" && m["approximate"] == true)
    );

    // No plan yet.
    let path = format!("/console/v1/organizations/{org}/plan");
    let r = c.call(&s, "GET", &path, None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text);
    assert!(r.json()["effective"].is_null());

    // A start in the past, an end before the start, an unknown plan, an unknown org.
    let past = (c.clock.get() - time::Duration::seconds(1))
        .format(&Rfc3339)
        .unwrap();
    let r = c
        .call(
            &s,
            "POST",
            &path,
            Some(json!({"plan": p1, "starts_at": past})),
        )
        .await;
    assert_eq!(r.code(), "CS-PLAN-0006", "{}", r.text);
    let r = c
        .call(&s, "POST", &path, Some(json!({"plan": Uuid::now_v7()})))
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = c
        .call(
            &s,
            "POST",
            &format!("/console/v1/organizations/{}/plan", Uuid::now_v7()),
            Some(json!({"plan": p1})),
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    // Assign v1 now, then v2 from an hour later: at that instant v2 is current.
    let r = c.call(&s, "POST", &path, Some(json!({"plan": p1}))).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text);
    let later = c.clock.get() + time::Duration::hours(1);
    let r = c
        .call(
            &s,
            "POST",
            &path,
            Some(json!({"plan": p2, "starts_at": later.format(&Rfc3339).unwrap()})),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text);
    // Nothing may now start at or before that later one.
    let r = c.call(&s, "POST", &path, Some(json!({"plan": p1}))).await;
    assert_eq!(r.code(), "CS-PLAN-0006", "{}", r.text);
    let r = c.call(&s, "GET", &path, None).await;
    let v = r.json();
    assert_eq!(v["effective"]["version"], 1);
    assert_eq!(v["assignments"].as_array().unwrap().len(), 2);
    assert_eq!(
        v["assignments"][1]["ends_at"],
        json!(later.format(&Rfc3339).unwrap())
    );

    // An override, live until its expiry; a workspace override applies in its workspace
    // only, so the organization's effective plan does not show it.
    let ov = format!("/console/v1/organizations/{org}/plan-overrides");
    let exp = c.clock.get() + time::Duration::minutes(10);
    let r = c
        .call(
            &s,
            "POST",
            &ov,
            Some(json!({"key": "quota.envelopes_sent.organization.limit", "value": "500",
                        "reason": "Pilot extension 7", "expires_at": exp.format(&Rfc3339).unwrap()})),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text);
    let first = r.json()["id"].as_str().unwrap().to_owned();
    let r = c
        .call(
            &s,
            "POST",
            &ov,
            Some(
                json!({"key": "quota.envelopes_sent.workspace.limit", "value": "5",
                        "reason": "Workspace cap", "workspace": seed.workspace}),
            ),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text);
    // A workspace override of an organization-wide key, and a workspace of another
    // organization.
    let r = c
        .call(
            &s,
            "POST",
            &ov,
            Some(json!({"key": "feature.api", "value": "false", "reason": "x", "workspace": seed.workspace})),
        )
        .await;
    assert_eq!(
        (r.code().as_str(), r.json()["field"].as_str()),
        ("CS-PLAN-0006", Some("workspace"))
    );
    let r = c
        .call(
            &s,
            "POST",
            &ov,
            Some(json!({"key": "quota.envelopes_sent.workspace.limit", "value": "5", "reason": "x", "workspace": Uuid::now_v7()})),
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = c
        .call(
            &s,
            "POST",
            &ov,
            Some(json!({"key": "feature.api", "value": "false", "reason": ""})),
        )
        .await;
    assert_eq!(
        (r.code().as_str(), r.json()["field"].as_str()),
        ("CS-CON-0010", Some("reason"))
    );

    let limit = |v: &Value, level: &str| -> u64 {
        v["effective"]["quotas"]
            .as_array()
            .unwrap()
            .iter()
            .find(|q| q["meter"] == "envelopes_sent" && q["level"] == level)
            .unwrap()["limit"]
            .as_u64()
            .unwrap()
    };
    let v = c.call(&s, "GET", &path, None).await.json();
    assert_eq!(limit(&v, "organization"), 500);
    assert_eq!(
        limit(&v, "workspace"),
        40,
        "the workspace override is not the organization's"
    );
    assert_eq!(v["overrides"].as_array().unwrap().len(), 2);
    assert_eq!(v["overrides"][1]["reason"], "Pilot extension 7");

    // At its expiry instant it no longer applies.
    c.clock.advance(600);
    let v = c.call(&s, "GET", &path, None).await.json();
    assert_eq!(limit(&v, "organization"), 100);
    assert_eq!(v["overrides"][1]["live"], false);

    // Expire the workspace one early; archive v2 and it can no longer be assigned.
    let second = v["overrides"][0]["id"].as_str().unwrap().to_owned();
    let r = c
        .call(
            &s,
            "POST",
            &format!("/console/v1/plan-overrides/{second}/expire"),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.text);
    let v = c.call(&s, "GET", &path, None).await.json();
    assert_eq!(v["overrides"][0]["live"], false);
    let r = c
        .call(&s, "POST", &format!("/console/v1/plans/{p2}/archive"), None)
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let other: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (id, name) VALUES (gen_random_uuid(), 'Other Org') RETURNING id",
    )
    .fetch_one(&db.owner)
    .await
    .unwrap();
    let r = c
        .call(
            &s,
            "POST",
            &format!("/console/v1/organizations/{other}/plan"),
            Some(json!({"plan": p2})),
        )
        .await;
    assert_eq!(r.code(), "CS-PLAN-0006", "archived");

    // Every write is in the operator log, by id and code; never a reason.
    let log = c
        .call(&s, "GET", "/console/v1/operator-log?limit=200", None)
        .await;
    for action in [
        "operator.plan.created",
        "operator.plan.assigned",
        "operator.plan.archived",
        "operator.plan_override.set",
        "operator.plan_override.expired",
    ] {
        assert!(log.text.contains(action), "{action} missing");
    }
    assert!(log.text.contains(&first));
    assert!(
        !log.text.contains("Pilot extension"),
        "reasons stay out of the log"
    );

    // An observer reads plans but changes nothing (deny by default, re-checked by the
    // database).
    let r = c
        .call(
            &s,
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
    assert_eq!(
        c.call(&obs, "GET", "/console/v1/plans", None).await.status,
        StatusCode::OK
    );
    assert_eq!(
        c.call(&obs, "GET", &path, None).await.status,
        StatusCode::OK
    );
    let r = c
        .call(&obs, "POST", "/console/v1/plans", Some(team("soft")))
        .await;
    assert_eq!(r.code(), "CS-CON-0003");
    db.drop().await;
}

#[tokio::test]
async fn plan_rows_change_only_as_designed() {
    let Some(db) = common::fresh("plan_rows_change_only_as_designed").await else {
        return;
    };
    let seed = db.seed().await;
    let c = common::console(&db);
    let s = owner(&c).await;
    let p = c
        .call(&s, "POST", "/console/v1/plans", Some(team("soft")))
        .await
        .json()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    c.call(
        &s,
        "POST",
        &format!("/console/v1/organizations/{}/plan", seed.org),
        Some(json!({"plan": p})),
    )
    .await;
    c.call(
        &s,
        "POST",
        &format!("/console/v1/organizations/{}/plan-overrides", seed.org),
        Some(json!({"key": "feature.scim", "value": "true", "reason": "trial"})),
    )
    .await;
    // As the owner (who bypasses the functions and grants): a version, its quotas, an
    // assignment's start, a later end, an override's value, deletes and truncates.
    for sql in [
        "UPDATE platform.plans SET name = 'Renamed'",
        "DELETE FROM platform.plans",
        "UPDATE platform.plan_quotas SET \"limit\" = 1",
        "DELETE FROM platform.plan_entitlements",
        "UPDATE platform.plan_assignments SET starts_at = starts_at - interval '1 day'",
        "UPDATE platform.plan_assignments SET ends_at = NULL",
        "DELETE FROM platform.plan_assignments",
        "UPDATE platform.plan_overrides SET value = 'false'",
        "DELETE FROM platform.plan_overrides",
        "TRUNCATE platform.plan_overrides",
    ] {
        let err = sqlx::query(sql).execute(&db.owner).await.expect_err(sql);
        assert_eq!(sqlstate(&err), "OS001", "{sql}");
    }
    // The console role has no direct write at all.
    for sql in [
        "INSERT INTO platform.plans (id, key, version, name, created_by, created_at) SELECT gen_random_uuid(), 'x', 9, 'x', id, now() FROM platform.operators LIMIT 1",
        "UPDATE platform.plan_overrides SET expires_at = now()",
        "UPDATE platform.plan_assignments SET ends_at = now()",
    ] {
        let err = sqlx::query(sql).execute(&db.console).await.expect_err(sql);
        assert_eq!(sqlstate(&err), "42501", "{sql}");
    }
    db.drop().await;
}
