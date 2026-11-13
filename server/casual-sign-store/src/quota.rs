//! Plan enforcement in the caller's transaction (PLAN-04, docs/23 §7.3, migration 0027).
//!
//! **Counter meters** go through [`TenantTx::consume_quota`]: it resolves the plan in force
//! for this workspace with [`casual_sign_policy::plans::effective`], then calls
//! `openseal_consume_quota`, which appends the ledger row and moves the organization's and
//! the workspace's counters with conditional updates (`value + n <= limit` for a `hard`
//! quota), so parallel actions in two workspaces cannot overshoot an organization quota
//! (`SEC-U01`). A source already counted answers before any check, so recording a sent
//! envelope's events again is never refused (`SEC-U02`).
//!
//! **Gauges** (`seats`, `storage_bytes`) are moved by database triggers in the change's
//! own transaction. [`TenantTx::gauge_lock`] locks their counter rows before the change and
//! [`TenantTx::gauge_check`] refuses after it when the change raised the gauge past a
//! `hard` limit; the caller then drops the transaction.
//!
//! `soft` quotas allow and record the overage, `notify` quotas allow and record the
//! crossing, both in `quota_notices`. No plan assigned means no quota.

use casual_sign_policy::plans::{self, Level, Meter, MeterKind, Quota};
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{Result, StoreError, db};
use crate::store::TenantTx;

/// Why a plan refused an action (docs/20 `CS-PLAN-*`). Carries the meter, limit, usage and
/// the end of the period, never anything else (docs/23 §7.3 "Problem details").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanRefusal {
    /// `CS-PLAN-0002` (period quota), `CS-PLAN-0003` (seats), `CS-PLAN-0004` (storage)
    /// or `CS-PLAN-0005` (organization suspended).
    pub code: &'static str,
    /// The meter, when a quota refused.
    pub meter: Option<Meter>,
    /// The level whose quota refused.
    pub level: Option<Level>,
    /// The limit.
    pub limit: Option<u64>,
    /// What is used of it (before this action).
    pub used: Option<u64>,
    /// When the period ends; `None` for gauges and standing quotas.
    pub period_end: Option<OffsetDateTime>,
}

impl PlanRefusal {
    fn suspended() -> Self {
        Self {
            code: SUSPENDED,
            meter: None,
            level: None,
            limit: None,
            used: None,
            period_end: None,
        }
    }
}

/// `CS-PLAN-0002`: the period's quota is reached.
pub const QUOTA_REACHED: &str = "CS-PLAN-0002";
/// `CS-PLAN-0003`: the seat limit is reached.
pub const SEATS_REACHED: &str = "CS-PLAN-0003";
/// `CS-PLAN-0004`: the storage limit is reached.
pub const STORAGE_REACHED: &str = "CS-PLAN-0004";
/// `CS-PLAN-0005`: the organization is suspended by the platform.
pub const SUSPENDED: &str = "CS-PLAN-0005";

/// What [`TenantTx::consume_quota`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consumed {
    /// Counted now.
    Counted,
    /// This source was counted before: nothing changed and nothing was checked.
    Replayed,
}

/// The counter values a [`TenantTx::gauge_lock`] read, with the rows locked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GaugeLock {
    meter: Meter,
    workspace: i64,
    organization: i64,
}

impl GaugeLock {
    /// The workspace's value when locked.
    #[must_use]
    pub fn workspace(&self) -> i64 {
        self.workspace
    }

    /// The organization's value when locked.
    #[must_use]
    pub fn organization(&self) -> i64 {
        self.organization
    }
}

fn level_json(q: Option<&Quota>) -> Value {
    match q {
        None => Value::Null,
        Some(q) => json!({
            "limit": q.limit,
            "enforcement": q.enforcement.as_str(),
            "period": q.period.as_str(),
        }),
    }
}

/// The quotas on `meter` in force for this workspace at `now`, as the database functions
/// take them. No assignment current: no quota.
fn quota_json(inputs: &plans::PlanInputs, ws: Uuid, meter: Meter, now: OffsetDateTime) -> Value {
    match plans::effective(inputs, Some(ws), now) {
        None => json!({}),
        Some(p) => json!({
            "workspace": level_json(p.quota(meter, Level::Workspace)),
            "organization": level_json(p.quota(meter, Level::Organization)),
        }),
    }
}

fn u64_of(v: &Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_i64().map(|n| n.max(0).unsigned_abs()))
}

/// Read a refusal the database answered.
fn refusal(code: &'static str, meter: Meter, v: &Value) -> Result<PlanRefusal> {
    let level = match v.get("level").and_then(Value::as_str) {
        Some("workspace") => Level::Workspace,
        Some("organization") => Level::Organization,
        _ => return Err(StoreError::Corrupt { column: "quota" }),
    };
    let period_end = match v.get("period_end") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(
            OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
                .map_err(|_| StoreError::Corrupt { column: "quota" })?,
        ),
        Some(_) => return Err(StoreError::Corrupt { column: "quota" }),
    };
    Ok(PlanRefusal {
        code,
        meter: Some(meter),
        level: Some(level),
        limit: v.get("limit").and_then(u64_of),
        used: v.get("used").and_then(u64_of),
        period_end,
    })
}

/// The refusal code of a gauge.
fn gauge_code(meter: Meter) -> &'static str {
    match meter {
        Meter::Seats => SEATS_REACHED,
        Meter::StorageBytes => STORAGE_REACHED,
        _ => QUOTA_REACHED,
    }
}

impl TenantTx {
    /// Count `quantity` of counter meter `meter` for this workspace and its organization,
    /// once per `(source_kind, source_id)`, within the plan's quotas at `at` (docs/23
    /// §7.3). A `hard` quota that the action would pass refuses it
    /// ([`StoreError::Plan`], `CS-PLAN-0002`) and nothing is counted; `soft` and `notify`
    /// quotas allow it and record a notice. A suspended organization refuses
    /// (`CS-PLAN-0005`). A source already counted answers [`Consumed::Replayed`] before
    /// any check.
    ///
    /// # Errors
    ///
    /// [`StoreError::Plan`] as above; `CS-DB-0008` for a gauge, a quantity below 1 or a
    /// malformed source; `CS-DB-0009` outside a workspace scope; `CS-DB-0010` when the
    /// plan or the answer does not read back.
    pub async fn consume_quota(
        &mut self,
        meter: Meter,
        quantity: i64,
        at: OffsetDateTime,
        source_kind: &str,
        source_id: Uuid,
    ) -> Result<Consumed> {
        if meter.kind() == MeterKind::Gauge {
            return Err(StoreError::Constraint {
                constraint: None,
                sqlstate: "23514".into(),
            });
        }
        let inputs = self.plan_inputs(at).await?;
        let quota = quota_json(&inputs, self.acct(), meter, at);
        let v = sqlx::query_scalar!(
            "SELECT openseal_consume_quota($1, $2, $3, $4, $5, $6)",
            meter.as_str(),
            quantity,
            at,
            source_kind,
            source_id.to_string(),
            quota
        )
        .fetch_one(self.conn())
        .await
        .map_err(db)?
        .ok_or(StoreError::Corrupt { column: "quota" })?;
        match v.get("result").and_then(Value::as_str) {
            Some("counted") => Ok(Consumed::Counted),
            Some("replayed") => Ok(Consumed::Replayed),
            Some("suspended") => Err(StoreError::Plan(PlanRefusal::suspended())),
            Some("refused") => Err(StoreError::Plan(refusal(QUOTA_REACHED, meter, &v)?)),
            _ => Err(StoreError::Corrupt { column: "quota" }),
        }
    }

    /// Lock gauge `meter`'s (`seats` or `storage_bytes`) counter rows of this workspace and
    /// its organization until the transaction ends, before a change that may raise it; a
    /// parallel change waits for this transaction. Refuses at once when the organization
    /// is suspended (`CS-PLAN-0005`): no new members or documents.
    ///
    /// # Errors
    ///
    /// [`StoreError::Plan`]; `CS-DB-0008` for another meter; the store's codes.
    pub async fn gauge_lock(&mut self, meter: Meter) -> Result<GaugeLock> {
        if !matches!(meter, Meter::Seats | Meter::StorageBytes) {
            return Err(StoreError::Constraint {
                constraint: None,
                sqlstate: "23514".into(),
            });
        }
        let v = sqlx::query_scalar!("SELECT openseal_quota_gauge_lock($1)", meter.as_str())
            .fetch_one(self.conn())
            .await
            .map_err(db)?
            .ok_or(StoreError::Corrupt { column: "quota" })?;
        if v.get("suspended").and_then(Value::as_bool) == Some(true) {
            return Err(StoreError::Plan(PlanRefusal::suspended()));
        }
        let read = |k: &str| {
            v.get(k)
                .and_then(Value::as_i64)
                .ok_or(StoreError::Corrupt { column: "quota" })
        };
        Ok(GaugeLock {
            meter,
            workspace: read("workspace")?,
            organization: read("organization")?,
        })
    }

    /// After a change made under `lock`: refuse when it raised the gauge past a `hard`
    /// limit of the plan at `at` (`CS-PLAN-0003` seats, `CS-PLAN-0004` storage; drop the
    /// transaction), else record `soft` or `notify` notices. A change that lowered or kept
    /// the gauge is never refused.
    ///
    /// # Errors
    ///
    /// [`StoreError::Plan`]; the store's codes.
    pub async fn gauge_check(
        &mut self,
        lock: GaugeLock,
        at: OffsetDateTime,
        source_kind: &str,
        source_id: Uuid,
    ) -> Result<()> {
        let inputs = self.plan_inputs(at).await?;
        let quota = quota_json(&inputs, self.acct(), lock.meter, at);
        let v = sqlx::query_scalar!(
            "SELECT openseal_quota_gauge_check($1, $2, $3, $4, $5, $6, $7)",
            lock.meter.as_str(),
            lock.workspace,
            lock.organization,
            at,
            source_kind,
            source_id.to_string(),
            quota
        )
        .fetch_one(self.conn())
        .await
        .map_err(db)?
        .ok_or(StoreError::Corrupt { column: "quota" })?;
        match v.get("result").and_then(Value::as_str) {
            Some("counted") => Ok(()),
            Some("refused") => Err(StoreError::Plan(refusal(
                gauge_code(lock.meter),
                lock.meter,
                &v,
            )?)),
            _ => Err(StoreError::Corrupt { column: "quota" }),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_reads_its_level_limit_usage_and_period_end() {
        let r = refusal(
            QUOTA_REACHED,
            Meter::EnvelopesSent,
            &json!({"result": "refused", "level": "organization", "limit": 10, "used": 10,
                    "period_end": "2026-12-01T00:00:00+00:00"}),
        )
        .unwrap();
        assert_eq!(r.level, Some(Level::Organization));
        assert_eq!(r.limit, Some(10));
        assert_eq!(r.used, Some(10));
        assert_eq!(
            r.period_end,
            Some(time::macros::datetime!(2026-12-01 00:00 UTC))
        );
        assert!(refusal(QUOTA_REACHED, Meter::EnvelopesSent, &json!({"level": "x"})).is_err());
    }

    #[test]
    fn gauges_refuse_with_their_own_codes() {
        assert_eq!(gauge_code(Meter::Seats), "CS-PLAN-0003");
        assert_eq!(gauge_code(Meter::StorageBytes), "CS-PLAN-0004");
    }
}
