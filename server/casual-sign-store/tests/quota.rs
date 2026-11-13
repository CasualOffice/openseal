//! PLAN-04 (docs/23 §7.3, migration 0028): quota enforcement in the caller's transaction.
//! A `hard` quota is checked by conditional updates of the organization's and the
//! workspace's counters in one definer function, so parallel actions in two workspaces of
//! one organization cannot pass the organization's limit (`SEC-U01`); `soft` and `notify`
//! allow and record; a source counted before is never refused (`SEC-U02`); a suspended
//! organization starts nothing new (`CS-PLAN-0005`); seats are checked under the seat
//! counters' lock.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use casual_sign_audit::Personal;
use casual_sign_store::repo::accounts::{LoginKind, NewUser};
use casual_sign_store::{AccountId, Consumed, Meter, OrganizationId, StoreError, UserId};
use common::world::{World, id, now, seed};
use common::{Rls, TestDb, fresh};
use sqlx::Row;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const T0: OffsetDateTime = time::macros::datetime!(2026-11-01 00:00 UTC);

/// A plan with `quotas` (`meter`, `level`, `limit`, `enforcement`), assigned to `org` from
/// `T0`, as the owner (the console's definer functions are tested in the console).
async fn plan(db: &TestDb, org: OrganizationId, quotas: &[(&str, &str, i64, &str)]) {
    let op = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO platform.operators (id, email, roles, created_at) VALUES ($1, $2, ARRAY['operator'], $3)",
    )
    .bind(op)
    .bind(format!("op-{}@ops.example", op.simple()))
    .bind(T0)
    .execute(&db.admin)
    .await
    .unwrap();
    let plan = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO platform.plans (id, key, version, name, created_by, created_at) \
         VALUES ($1, $2, 1, $2, $3, $4)",
    )
    .bind(plan)
    .bind(format!("p{}", plan.simple()))
    .bind(op)
    .bind(T0)
    .execute(&db.admin)
    .await
    .unwrap();
    for (meter, level, limit, enforcement) in quotas {
        let period = if matches!(*meter, "seats" | "storage_bytes") {
            "none"
        } else {
            "month"
        };
        sqlx::query(
            "INSERT INTO platform.plan_quotas (plan_id, meter, \"limit\", period, enforcement, level) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(plan)
        .bind(meter)
        .bind(limit)
        .bind(period)
        .bind(enforcement)
        .bind(level)
        .execute(&db.admin)
        .await
        .unwrap();
    }
    sqlx::query(
        "INSERT INTO platform.plan_assignments (id, organization_id, plan_id, starts_at, ends_at, assigned_by, assigned_at) \
         VALUES ($1, $2, $3, $4, NULL, $5, $4)",
    )
    .bind(Uuid::now_v7())
    .bind(org.0)
    .bind(plan)
    .bind(T0)
    .bind(op)
    .execute(&db.admin)
    .await
    .unwrap();
}

/// One send counted in its own transaction, committed when allowed.
async fn send(db: &TestDb, ws: AccountId, source: Uuid) -> Result<Consumed, StoreError> {
    let mut tx = db.store.for_account(ws).begin().await.unwrap();
    let r = tx
        .consume_quota(Meter::EnvelopesSent, 1, now(), "envelope", source)
        .await;
    if r.is_ok() {
        tx.commit().await.unwrap();
    }
    r
}

async fn org_counter(db: &TestDb, org: OrganizationId, meter: &str) -> i64 {
    sqlx::query(
        "SELECT COALESCE(sum(value), 0)::bigint FROM org_usage_counters \
         WHERE organization_id = $1 AND meter = $2",
    )
    .bind(org.0)
    .bind(meter)
    .fetch_one(&db.admin)
    .await
    .unwrap()
    .get(0)
}

async fn ws_counter(db: &TestDb, ws: AccountId, meter: &str) -> i64 {
    sqlx::query(
        "SELECT COALESCE(sum(value), 0)::bigint FROM usage_counters \
         WHERE account_id = $1 AND meter = $2",
    )
    .bind(ws.0)
    .bind(meter)
    .fetch_one(&db.admin)
    .await
    .unwrap()
    .get(0)
}

/// Every counter equals the sum of its ledger column at both levels.
async fn counters_equal_ledger_sums(db: &TestDb) {
    let off: i64 = sqlx::query(
        "SELECT (SELECT count(*) FROM ( \
           SELECT account_id, meter, period_start, sum(quantity) AS v FROM usage_ledger GROUP BY 1, 2, 3) l \
           FULL JOIN usage_counters c USING (account_id, meter, period_start) \
           WHERE COALESCE(l.v, 0) <> COALESCE(c.value, 0)) + \
         (SELECT count(*) FROM ( \
           SELECT a.organization_id, l.meter, l.period_start, sum(l.org_quantity) AS v \
             FROM usage_ledger l JOIN accounts a ON a.id = l.account_id GROUP BY 1, 2, 3) l \
           FULL JOIN org_usage_counters c USING (organization_id, meter, period_start) \
           WHERE COALESCE(l.v, 0) <> COALESCE(c.value, 0))",
    )
    .fetch_one(&db.admin)
    .await
    .unwrap()
    .get(0);
    assert_eq!(off, 0, "a counter differs from its ledger sum");
}

fn code(r: &Result<Consumed, StoreError>) -> &'static str {
    match r {
        Ok(_) => "ok",
        Err(e) => e.code(),
    }
}

/// `SEC-U01`: 50 parallel sends against an organization limit of 10, split over two
/// workspaces of one organization: exactly 10 are counted, the rest refused with
/// `CS-PLAN-0002`, and the counters equal the ledger.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_sends_in_two_workspaces_never_pass_the_organization_quota() {
    let Some(db) = fresh(
        "parallel_sends_in_two_workspaces_never_pass_the_organization_quota",
        Rls::On,
    )
    .await
    else {
        return;
    };
    let w = seed(&db, "a").await;
    let second = db.workspace(w.organization, "a2").await;
    plan(
        &db,
        w.organization,
        &[
            ("envelopes_sent", "organization", 10, "hard"),
            ("envelopes_sent", "workspace", 40, "hard"),
        ],
    )
    .await;
    let db = std::sync::Arc::new(db);
    let mut tasks = Vec::new();
    for n in 0..50 {
        let db = std::sync::Arc::clone(&db);
        let ws = if n % 2 == 0 { w.account } else { second };
        tasks.push(tokio::spawn(
            async move { code(&send(&db, ws, id()).await) },
        ));
    }
    let mut ok = 0;
    let mut refused = 0;
    for t in tasks {
        match t.await.unwrap() {
            "ok" => ok += 1,
            "CS-PLAN-0002" => refused += 1,
            other => panic!("unexpected {other}"),
        }
    }
    assert_eq!((ok, refused), (10, 40));
    assert_eq!(org_counter(&db, w.organization, "envelopes_sent").await, 10);
    assert_eq!(
        ws_counter(&db, w.account, "envelopes_sent").await
            + ws_counter(&db, second, "envelopes_sent").await,
        10
    );
    counters_equal_ledger_sums(&db).await;
    let db = std::sync::Arc::try_unwrap(db).ok().unwrap();
    db.drop().await;
}

/// A workspace quota refuses in its own workspace only, with the limit, the usage and the
/// period's end; the refusal leaves no ledger row.
#[tokio::test]
async fn a_workspace_quota_refuses_with_its_limit_usage_and_period_end() {
    let Some(db) = fresh(
        "a_workspace_quota_refuses_with_its_limit_usage_and_period_end",
        Rls::On,
    )
    .await
    else {
        return;
    };
    let w = seed(&db, "a").await;
    let second = db.workspace(w.organization, "a2").await;
    plan(
        &db,
        w.organization,
        &[("envelopes_sent", "workspace", 2, "hard")],
    )
    .await;
    for _ in 0..2 {
        assert_eq!(send(&db, w.account, id()).await.unwrap(), Consumed::Counted);
    }
    let Err(StoreError::Plan(r)) = send(&db, w.account, id()).await else {
        panic!("the third send is refused");
    };
    assert_eq!(r.code, "CS-PLAN-0002");
    assert_eq!(r.meter, Some(Meter::EnvelopesSent));
    assert_eq!((r.limit, r.used), (Some(2), Some(2)));
    let month = time::Date::from_calendar_date(now().year(), now().month(), 1).unwrap();
    let next = month.checked_add(Duration::days(31)).unwrap();
    let next = time::Date::from_calendar_date(next.year(), next.month(), 1).unwrap();
    assert_eq!(r.period_end, Some(next.midnight().assume_utc()));
    // The other workspace has its own.
    assert_eq!(send(&db, second, id()).await.unwrap(), Consumed::Counted);
    assert_eq!(ws_counter(&db, w.account, "envelopes_sent").await, 2);
    assert_eq!(org_counter(&db, w.organization, "envelopes_sent").await, 3);
    counters_equal_ledger_sums(&db).await;
    db.drop().await;
}

/// `SEC-U02` at the store: a source counted before answers `Replayed` with the quota
/// spent and the organization suspended; a new source is refused with `CS-PLAN-0005`.
#[tokio::test]
async fn a_source_counted_before_is_never_refused() {
    let Some(db) = fresh("a_source_counted_before_is_never_refused", Rls::On).await else {
        return;
    };
    let w = seed(&db, "a").await;
    plan(
        &db,
        w.organization,
        &[("envelopes_sent", "organization", 1, "hard")],
    )
    .await;
    let sent = id();
    assert_eq!(send(&db, w.account, sent).await.unwrap(), Consumed::Counted);
    assert_eq!(code(&send(&db, w.account, id()).await), "CS-PLAN-0002");
    assert_eq!(
        send(&db, w.account, sent).await.unwrap(),
        Consumed::Replayed
    );
    sqlx::query("UPDATE organizations SET status = 'suspended' WHERE id = $1")
        .bind(w.organization.0)
        .execute(&db.admin)
        .await
        .unwrap();
    assert_eq!(
        send(&db, w.account, sent).await.unwrap(),
        Consumed::Replayed
    );
    assert_eq!(code(&send(&db, w.account, id()).await), "CS-PLAN-0005");
    assert_eq!(org_counter(&db, w.organization, "envelopes_sent").await, 1);
    counters_equal_ledger_sums(&db).await;
    db.drop().await;
}

/// `soft` allows and records every action's overage; `notify` allows and records only the
/// crossing. No plan: no quota.
#[tokio::test]
async fn soft_records_each_overage_and_notify_records_the_crossing() {
    let Some(db) = fresh(
        "soft_records_each_overage_and_notify_records_the_crossing",
        Rls::On,
    )
    .await
    else {
        return;
    };
    let free = seed(&db, "free").await;
    for _ in 0..5 {
        send(&db, free.account, id()).await.unwrap();
    }
    let w = seed(&db, "a").await;
    plan(
        &db,
        w.organization,
        &[
            ("envelopes_sent", "organization", 2, "soft"),
            ("envelopes_sent", "workspace", 3, "notify"),
        ],
    )
    .await;
    for _ in 0..5 {
        assert_eq!(send(&db, w.account, id()).await.unwrap(), Consumed::Counted);
    }
    let rows = sqlx::query(
        "SELECT level, enforcement, quota_limit, used, overage FROM quota_notices \
         WHERE organization_id = $1 ORDER BY level, used",
    )
    .bind(w.organization.0)
    .fetch_all(&db.admin)
    .await
    .unwrap();
    let got: Vec<(String, String, i64, i64, i64)> = rows
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3), r.get(4)))
        .collect();
    assert_eq!(
        got,
        vec![
            ("organization".into(), "soft".into(), 2, 3, 1),
            ("organization".into(), "soft".into(), 2, 4, 1),
            ("organization".into(), "soft".into(), 2, 5, 1),
            ("workspace".into(), "notify".into(), 3, 4, 0),
        ]
    );
    let none: i64 = sqlx::query("SELECT count(*) FROM quota_notices WHERE organization_id = $1")
        .bind(free.organization.0)
        .fetch_one(&db.admin)
        .await
        .unwrap()
        .get(0);
    assert_eq!(none, 0);
    assert_eq!(
        org_counter(&db, free.organization, "envelopes_sent").await,
        5
    );
    // The application cannot write a notice.
    let denied = sqlx::query(
        "INSERT INTO quota_notices (organization_id, workspace_id, meter, level, enforcement, \
         period_start, quota_limit, used, overage, source_kind, source_id, at) \
         VALUES ($1, $2, 'envelopes_sent', 'workspace', 'soft', now(), 0, 1, 1, 'x', 'y', now())",
    )
    .bind(w.organization.0)
    .bind(w.account.0)
    .execute(&db.app)
    .await;
    assert!(denied.is_err());
    counters_equal_ledger_sums(&db).await;
    db.drop().await;
}

async fn add_member(db: &TestDb, w: &World, n: usize) -> Result<(), StoreError> {
    let mut tx = db.store.for_account(w.account).begin().await.unwrap();
    let lock = tx.gauge_lock(Meter::Seats).await?;
    let user = UserId(id());
    tx.users()
        .create_member(
            &NewUser {
                id: user,
                email: Personal(format!("m{n}@a.example.test")),
                email_normalized: Personal(format!("m{n}@a.example.test")),
                name: Personal(format!("M{n}")),
                login_kind: LoginKind::Local,
                idp: None,
            },
            w.profile,
        )
        .await?;
    tx.gauge_check(lock, now(), "member.add", user.0).await?;
    tx.commit().await?;
    Ok(())
}

/// Seats: parallel additions against an organization limit never pass it
/// (`CS-PLAN-0003`): each is checked under the seat counters' lock.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_member_additions_never_pass_the_seat_limit() {
    let Some(db) = fresh(
        "parallel_member_additions_never_pass_the_seat_limit",
        Rls::On,
    )
    .await
    else {
        return;
    };
    let w = seed(&db, "a").await;
    assert_eq!(org_counter(&db, w.organization, "seats").await, 1);
    plan(&db, w.organization, &[("seats", "organization", 4, "hard")]).await;
    let db = std::sync::Arc::new(db);
    let w = std::sync::Arc::new(w);
    let mut tasks = Vec::new();
    for n in 0..12 {
        let (db, w) = (std::sync::Arc::clone(&db), std::sync::Arc::clone(&w));
        tasks.push(tokio::spawn(async move {
            match add_member(&db, &w, n).await {
                Ok(()) => "ok",
                Err(e) => e.code(),
            }
        }));
    }
    let mut ok = 0;
    for t in tasks {
        match t.await.unwrap() {
            "ok" => ok += 1,
            "CS-PLAN-0003" => {}
            other => panic!("unexpected {other}"),
        }
    }
    assert_eq!(ok, 3, "one seat was held, three were free");
    assert_eq!(org_counter(&db, w.organization, "seats").await, 4);
    counters_equal_ledger_sums(&db).await;
    let db = std::sync::Arc::try_unwrap(db).ok().unwrap();
    db.drop().await;
}
