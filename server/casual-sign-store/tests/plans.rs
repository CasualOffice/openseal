//! PLAN-02 (docs/23 §7.1): the application reads its organization's plan only through
//! `openseal_effective_plan(now)`, which gives the assignment current at `now` and the
//! overrides live at `now` for the organization and the transaction's own workspace, with
//! no reasons or operator ids; `casual-sign-policy` resolves them. The application has no
//! grant on any `platform` table or function.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use casual_sign_policy::plans::{self, Feature, Level, Meter};
use common::{Rls, TestDb, fresh};
use sqlx::Executor;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const T0: OffsetDateTime = time::macros::datetime!(2026-11-01 00:00 UTC);

/// An operator row, as the console's enrolment would leave one.
async fn operator(db: &TestDb) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO platform.operators (id, email, roles, created_at) VALUES ($1, $2, ARRAY['operator'], $3)",
    )
    .bind(id)
    .bind(format!("op-{}@ops.example", id.simple()))
    .bind(T0)
    .execute(&db.admin)
    .await
    .unwrap();
    id
}

/// A plan with an organization-level and a workspace-level `envelopes_sent` quota, as the
/// owner (the console's definer functions are tested in the console's tests).
async fn plan(db: &TestDb, op: Uuid, key: &str, limit: i64) -> Uuid {
    let id = Uuid::now_v7();
    db.admin
        .execute(
            sqlx::query(
                "INSERT INTO platform.plans (id, key, version, name, created_by, created_at) \
                 VALUES ($1, $2, 1, $2, $3, $4)",
            )
            .bind(id)
            .bind(key)
            .bind(op)
            .bind(T0),
        )
        .await
        .unwrap();
    for (meter, level, lim) in [
        ("envelopes_sent", "organization", limit),
        ("envelopes_sent", "workspace", limit / 2),
    ] {
        sqlx::query(
            "INSERT INTO platform.plan_quotas (plan_id, meter, \"limit\", period, enforcement, level) \
             VALUES ($1, $2, $3, 'month', 'hard', $4)",
        )
        .bind(id)
        .bind(meter)
        .bind(lim)
        .bind(level)
        .execute(&db.admin)
        .await
        .unwrap();
    }
    sqlx::query("INSERT INTO platform.plan_entitlements (plan_id, feature, enabled) VALUES ($1, 'api', true)")
        .bind(id)
        .execute(&db.admin)
        .await
        .unwrap();
    id
}

async fn assign(
    db: &TestDb,
    op: Uuid,
    org: Uuid,
    plan: Uuid,
    starts: OffsetDateTime,
    ends: Option<OffsetDateTime>,
) {
    sqlx::query(
        "INSERT INTO platform.plan_assignments (id, organization_id, plan_id, starts_at, ends_at, assigned_by, assigned_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $4)",
    )
    .bind(Uuid::now_v7())
    .bind(org)
    .bind(plan)
    .bind(starts)
    .bind(ends)
    .bind(op)
    .execute(&db.admin)
    .await
    .unwrap();
}

#[allow(clippy::too_many_arguments)]
async fn set_override(
    db: &TestDb,
    op: Uuid,
    org: Uuid,
    workspace: Option<Uuid>,
    key: &str,
    value: &str,
    expires: Option<OffsetDateTime>,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO platform.plan_overrides (id, organization_id, workspace_id, key, value, reason, expires_at, operator_id, created_at) \
         VALUES ($1, $2, $3, $4, $5, 'Internal note 42', $6, $7, $8)",
    )
    .bind(id)
    .bind(org)
    .bind(workspace)
    .bind(key)
    .bind(value)
    .bind(expires)
    .bind(op)
    .bind(T0)
    .execute(&db.admin)
    .await
    .unwrap();
    id
}

#[tokio::test]
async fn a_workspace_reads_its_organizations_current_plan_and_live_overrides_only() {
    let Some(db) = fresh(
        "a_workspace_reads_its_organizations_current_plan_and_live_overrides_only",
        Rls::On,
    )
    .await
    else {
        return;
    };
    let op = operator(&db).await;
    let (org_a, ws_a) = db.account("A").await;
    let ws_a2 = db.workspace(org_a, "A2").await;
    let (org_b, _) = db.account("B").await;
    let starter = plan(&db, op, "starter", 100).await;
    let team = plan(&db, op, "team", 1000).await;
    let end = T0 + Duration::days(30);
    assign(&db, op, org_a.0, starter, T0, Some(end)).await;
    assign(&db, op, org_a.0, team, end, None).await;
    assign(&db, op, org_b.0, starter, T0, None).await;

    let mine = set_override(
        &db,
        op,
        org_a.0,
        Some(ws_a.0),
        "quota.envelopes_sent.workspace.limit",
        "7",
        None,
    )
    .await;
    let org_wide = set_override(
        &db,
        op,
        org_a.0,
        None,
        "feature.bulk_send",
        "true",
        Some(end),
    )
    .await;
    let sibling = set_override(
        &db,
        op,
        org_a.0,
        Some(ws_a2.0),
        "quota.envelopes_sent.workspace.limit",
        "9",
        None,
    )
    .await;
    let other_org = set_override(&db, op, org_b.0, None, "feature.scim", "true", None).await;

    let read = |now: OffsetDateTime| {
        let store = db.store.clone();
        async move {
            let mut tx = store.for_account(ws_a).begin().await.unwrap();
            let inputs = tx.plan_inputs(now).await.unwrap();
            tx.commit().await.unwrap();
            inputs
        }
    };

    let at = T0 + Duration::days(1);
    let inputs = read(at).await;
    assert_eq!(inputs.organization, org_a.0);
    assert_eq!(inputs.assignments.len(), 1, "the current assignment only");
    let ids: Vec<Uuid> = inputs.overrides.iter().map(|o| o.id).collect();
    assert!(ids.contains(&mine) && ids.contains(&org_wide), "{ids:?}");
    assert!(!ids.contains(&sibling), "another workspace's override");
    assert!(!ids.contains(&other_org), "another organization's override");
    assert!(
        inputs
            .overrides
            .iter()
            .all(|o| o.reason.is_none() && o.operator.is_none()),
        "reasons and operator ids stay in the console"
    );
    let e = plans::effective(&inputs, Some(ws_a.0), at).unwrap();
    assert_eq!(e.key, "starter");
    assert!(e.entitled(Feature::Api) && e.entitled(Feature::BulkSend));
    assert!(!e.entitled(Feature::Scim));
    assert_eq!(
        e.quota(Meter::EnvelopesSent, Level::Workspace)
            .unwrap()
            .limit,
        7
    );
    assert_eq!(
        e.quota(Meter::EnvelopesSent, Level::Organization)
            .unwrap()
            .limit,
        100
    );

    // At the boundary instant the next assignment is current and the expiring override is
    // gone.
    let inputs = read(end).await;
    assert_eq!(inputs.assignments.len(), 1);
    let e = plans::effective(&inputs, Some(ws_a.0), end).unwrap();
    assert_eq!(e.key, "team");
    assert!(!e.entitled(Feature::BulkSend));
    assert!(!inputs.overrides.iter().any(|o| o.id == org_wide));
    let just_before = read(end - Duration::microseconds(1)).await;
    assert_eq!(
        plans::effective(&just_before, Some(ws_a.0), end - Duration::microseconds(1))
            .unwrap()
            .key,
        "starter"
    );

    // Before any assignment: no plan.
    let inputs = read(T0 - Duration::seconds(1)).await;
    assert!(inputs.assignments.is_empty());
    assert!(plans::effective(&inputs, Some(ws_a.0), T0 - Duration::seconds(1)).is_none());
    db.drop().await;
}

#[tokio::test]
async fn the_application_has_no_grant_in_the_platform_schema() {
    let Some(db) = fresh(
        "the_application_has_no_grant_in_the_platform_schema",
        Rls::On,
    )
    .await
    else {
        return;
    };
    for sql in [
        "SELECT 1 FROM platform.plans",
        "SELECT 1 FROM platform.plan_overrides",
        "SELECT 1 FROM platform.plan_assignments",
        "SELECT platform.plan_inputs(gen_random_uuid(), NULL, now(), false)",
    ] {
        let err = sqlx::query(sql).execute(&db.app).await.expect_err(sql);
        let code = err
            .as_database_error()
            .and_then(|d| d.code())
            .unwrap_or_default();
        assert_eq!(code, "42501", "{sql}");
    }
    // Its one door, with no account or organization set, answers nothing.
    let v: Option<serde_json::Value> = sqlx::query_scalar("SELECT openseal_effective_plan(now())")
        .fetch_one(&db.app)
        .await
        .unwrap();
    assert!(v.is_none());
    db.drop().await;
}
