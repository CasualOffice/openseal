//! PLAN-04 (docs/23 §7.3): the API refuses what the plan does not allow, with problem
//! details carrying the meter, the limit and the usage only: a member who would take a
//! seat past the limit (`CS-PLAN-0003`), a document past the storage limit
//! (`CS-PLAN-0004`). A viewer takes no seat under `can_send`, so adding one is allowed.

#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::indexing_slicing
)]

mod common;

use axum::http::StatusCode;
use common::Rls;
use common::flow::{b64, ok};
use common::harness::{Api, Tenant, pdf};
use serde_json::json;
use uuid::Uuid;

/// Assign `tenant`'s organization a plan with one organization-level `hard` quota.
async fn plan(api: &Api, t: &Tenant, meter: &str, limit: i64) {
    let (op, plan) = (Uuid::now_v7(), Uuid::now_v7());
    sqlx::query(
        "INSERT INTO platform.operators (id, email, roles, created_at) \
         VALUES ($1, 'op@ops.example', ARRAY['operator'], 'epoch')",
    )
    .bind(op)
    .execute(&api.db.admin)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO platform.plans (id, key, version, name, created_by, created_at) \
         VALUES ($1, 'team', 1, 'Team', $2, 'epoch')",
    )
    .bind(plan)
    .bind(op)
    .execute(&api.db.admin)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO platform.plan_quotas (plan_id, meter, \"limit\", period, enforcement, level) \
         VALUES ($1, $2, $3, 'none', 'hard', 'organization')",
    )
    .bind(plan)
    .bind(meter)
    .bind(limit)
    .execute(&api.db.admin)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO platform.plan_assignments (id, organization_id, plan_id, starts_at, assigned_by, assigned_at) \
         VALUES ($1, $2, $3, 'epoch', $4, 'epoch')",
    )
    .bind(Uuid::now_v7())
    .bind(t.boot.organization.0)
    .bind(plan)
    .bind(op)
    .execute(&api.db.admin)
    .await
    .unwrap();
}

#[tokio::test]
async fn a_member_past_the_seat_limit_is_refused_and_a_viewer_is_not() {
    let Some(api) = Api::new("quota_seats", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    plan(&api, &a, "seats", 1).await;
    let user = |email: &str, profile: &str| {
        json!({"email": email, "name": "M", "profile": profile,
               "password": "a long enough passphrase"})
    };
    let r = api
        .call(
            "POST",
            "/api/v1/users",
            &a.auth,
            Some(user("s@alpha.test", "sender")),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let p = r.json();
    assert_eq!(p["code"], "CS-PLAN-0003", "{p}");
    assert_eq!(
        (&p["meter"], &p["limit"], &p["used"]),
        (&json!("seats"), &json!(1), &json!(1)),
        "{p}"
    );
    let viewer = ok(
        api.call(
            "POST",
            "/api/v1/users",
            &a.auth,
            Some(user("v@alpha.test", "viewer")),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "a viewer takes no seat",
    );
    // Re-profiling the viewer to a sender would take a seat.
    let r = api
        .call(
            "PATCH",
            &format!("/api/v1/users/{}", viewer["id"].as_str().unwrap()),
            &a.auth,
            Some(json!({"profile": "sender"})),
            &[],
        )
        .await;
    assert_eq!(r.json()["code"], "CS-PLAN-0003", "{:?}", r.json());
}

#[tokio::test]
async fn a_document_past_the_storage_limit_is_refused() {
    let Some(api) = Api::new("quota_storage", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    plan(&api, &a, "storage_bytes", 100).await;
    let r = api
        .call(
            "POST",
            "/api/v1/envelopes",
            &a.auth,
            Some(json!({
                "subject": "PLAN-04",
                "documents": [{"name": "d.pdf", "content_base64": b64(&pdf(1))}],
            })),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let p = r.json();
    assert_eq!(p["code"], "CS-PLAN-0004", "{p}");
    assert_eq!(
        (&p["meter"], &p["limit"]),
        (&json!("storage_bytes"), &json!(100))
    );
    let none: i64 = sqlx::query_scalar("SELECT count(*) FROM document_versions")
        .fetch_one(&api.db.admin)
        .await
        .unwrap();
    assert_eq!(none, 0, "nothing was stored");
}

#[tokio::test]
async fn a_send_past_the_envelope_quota_is_refused_and_the_draft_stays_a_draft() {
    let Some(api) = Api::new("quota_sends", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    plan(&api, &a, "envelopes_sent", 1).await;
    common::flow::sent(&api, &a, 1, &[]).await;
    let draft = ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            &a.auth,
            Some(json!({
                "subject": "PLAN-04",
                "documents": [{"name": "d.pdf", "content_base64": b64(&pdf(1))}],
                "recipients": [{"ref": "s1", "type": "signer", "name": "S1",
                    "email": "s1@example.test", "routing_order": 1}],
                "fields": [{"recipient": "s1", "document": 0, "type": "signature", "page": 1,
                    "x": 72, "y": 100, "width": 180, "height": 40, "required": true}],
            })),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "a draft is not counted",
    );
    let base = format!("/api/v1/envelopes/{}", draft["id"].as_str().unwrap());
    let r = api
        .call("POST", &format!("{base}/send"), &a.auth, None, &[])
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{:?}", r.json());
    let p = r.json();
    assert_eq!(p["code"], "CS-PLAN-0002", "{p}");
    assert_eq!(
        (&p["meter"], &p["limit"], &p["used"]),
        (&json!("envelopes_sent"), &json!(1), &json!(1)),
        "{p}"
    );
    // A standing quota has no period end.
    assert!(p.get("period_end").is_none(), "{p}");
    let e = ok(
        api.call("GET", &base, &a.auth, None, &[]).await,
        StatusCode::OK,
        "read the draft",
    );
    assert_eq!(e["status"], "draft", "nothing committed: {e}");
}
