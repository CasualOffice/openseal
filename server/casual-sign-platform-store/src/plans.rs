//! Plans (PLAN-02, docs/23 §7.1): reads of the `platform` plan tables, and writes through
//! the session-checked definer functions of migration 0024. Validation is
//! `casual-sign-policy`'s; the database checks the same rules again and answers
//! `CS-PLAN-0006` (SQLSTATE `OS010`) to anything that gets past it.

use casual_sign_policy::plans::{Plan, PlanDraft, PlanInputs};
use serde_json::{Map, Value, json};
use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{PlatformError, Result, db};
use crate::store::{PlatformStore, PlatformTx};

/// A plan version with its catalogue facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanRow {
    /// The version.
    pub plan: Plan,
    /// When it was created.
    pub created_at: OffsetDateTime,
    /// When it was archived.
    pub archived_at: Option<OffsetDateTime>,
    /// Organizations it is current for.
    pub organizations: i64,
}

/// A new override (docs/23 §7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewOverride<'a> {
    /// Its id.
    pub id: Uuid,
    /// The organization.
    pub organization: Uuid,
    /// One of its workspaces, for a workspace-level quota only.
    pub workspace: Option<Uuid>,
    /// `feature.<f>`, `quota.<meter>.<level>.limit|enforcement` or `seat_rule`.
    pub key: &'a str,
    /// The value for that key.
    pub value: &'a str,
    /// Why: 1 to 200 characters, kept in the console only.
    pub reason: &'a str,
    /// When it stops applying; `None` for never.
    pub expires_at: Option<OffsetDateTime>,
}

fn corrupt(_: casual_sign_policy::plans::InputsError) -> PlatformError {
    PlatformError::Corrupt { what: "plan" }
}

impl PlatformStore {
    /// Every plan version, by key and newest version first, with how many organizations
    /// it is current for at `now`.
    ///
    /// # Errors
    /// A database error; `CS-DB-0010` for rows this build cannot read.
    pub async fn plans(&self, now: OffsetDateTime) -> Result<Vec<PlanRow>> {
        let rows = sqlx::query(
            "SELECT plan, created_at, archived_at, organizations FROM platform.plans_page($1)",
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter()
            .map(|r| {
                let v: Value = r.try_get("plan").map_err(db)?;
                Ok(PlanRow {
                    plan: Plan::from_json(&v).map_err(corrupt)?,
                    created_at: r.try_get("created_at").map_err(db)?,
                    archived_at: r.try_get("archived_at").map_err(db)?,
                    organizations: r.try_get("organizations").map_err(db)?,
                })
            })
            .collect()
    }

    /// An organization's every assignment and override, with reasons and operators.
    ///
    /// # Errors
    /// A database error; `CS-DB-0010` for rows this build cannot read.
    pub async fn plan_inputs(&self, organization: Uuid, now: OffsetDateTime) -> Result<PlanInputs> {
        let v: Value = sqlx::query_scalar("SELECT platform.plan_inputs($1, NULL, $2, false)")
            .bind(organization)
            .bind(now)
            .fetch_one(&self.pool)
            .await
            .map_err(db)?;
        PlanInputs::from_json(&v).map_err(corrupt)
    }
}

impl PlatformTx {
    /// Store `draft` as the next version of its key; the version number.
    ///
    /// # Errors
    /// `CS-PLAN-0006` for an invalid plan; `CS-CON-0001` to `-0003` for the session.
    pub async fn create_plan(
        &mut self,
        session: &[u8; 32],
        id: Uuid,
        draft: &PlanDraft,
        now: OffsetDateTime,
    ) -> Result<u32> {
        let entitlements: Map<String, Value> = draft
            .entitlements
            .iter()
            .map(|(f, on)| (f.as_str().to_owned(), Value::Bool(*on)))
            .collect();
        let quotas: Vec<Value> = draft
            .quotas
            .iter()
            .map(|q| {
                json!({
                    "meter": q.meter.as_str(),
                    "limit": q.limit,
                    "period": q.period.as_str(),
                    "enforcement": q.enforcement.as_str(),
                    "level": q.level.as_str(),
                })
            })
            .collect();
        let v: i32 =
            sqlx::query_scalar("SELECT platform.create_plan($1, $2, $3, $4, $5, $6, $7, $8)")
                .bind(session.as_slice())
                .bind(id)
                .bind(&draft.key)
                .bind(draft.name.trim())
                .bind(Value::Object(entitlements))
                .bind(Value::Array(quotas))
                .bind(draft.seat_rule.as_str())
                .bind(now)
                .fetch_one(&mut *self.tx)
                .await
                .map_err(db)?;
        u32::try_from(v).map_err(|_| PlatformError::Corrupt { what: "version" })
    }

    /// Archive a plan version; `false` when there is none.
    ///
    /// # Errors
    /// `CS-CON-0001` to `-0003` for the session.
    pub async fn archive_plan(
        &mut self,
        session: &[u8; 32],
        plan: Uuid,
        now: OffsetDateTime,
    ) -> Result<bool> {
        sqlx::query_scalar("SELECT platform.archive_plan($1, $2, $3)")
            .bind(session.as_slice())
            .bind(plan)
            .bind(now)
            .fetch_one(&mut *self.tx)
            .await
            .map_err(db)
    }

    /// Assign `plan` to `organization` from `starts` until `ends`; `false` when either
    /// does not exist.
    ///
    /// # Errors
    /// `CS-PLAN-0006` for an archived plan, a start before `now`, an end not after the
    /// start, or an assignment already starting at or after `starts`.
    #[allow(clippy::too_many_arguments)] // One per column of the assignment.
    pub async fn assign_plan(
        &mut self,
        session: &[u8; 32],
        id: Uuid,
        organization: Uuid,
        plan: Uuid,
        starts: OffsetDateTime,
        ends: Option<OffsetDateTime>,
        now: OffsetDateTime,
    ) -> Result<bool> {
        sqlx::query_scalar("SELECT platform.assign_plan($1, $2, $3, $4, $5, $6, $7)")
            .bind(session.as_slice())
            .bind(id)
            .bind(organization)
            .bind(plan)
            .bind(starts)
            .bind(ends)
            .bind(now)
            .fetch_one(&mut *self.tx)
            .await
            .map_err(db)
    }

    /// Set an override; `false` when the organization does not exist or the workspace is
    /// not one of its own.
    ///
    /// # Errors
    /// `CS-PLAN-0006` for a key, value, scope, reason or expiry the database refuses.
    pub async fn set_plan_override(
        &mut self,
        session: &[u8; 32],
        o: &NewOverride<'_>,
        now: OffsetDateTime,
    ) -> Result<bool> {
        sqlx::query_scalar("SELECT platform.set_plan_override($1, $2, $3, $4, $5, $6, $7, $8, $9)")
            .bind(session.as_slice())
            .bind(o.id)
            .bind(o.organization)
            .bind(o.workspace)
            .bind(o.key)
            .bind(o.value)
            .bind(o.reason)
            .bind(o.expires_at)
            .bind(now)
            .fetch_one(&mut *self.tx)
            .await
            .map_err(db)
    }

    /// Expire an override now; `false` when there is none.
    ///
    /// # Errors
    /// `CS-CON-0001` to `-0003` for the session.
    pub async fn expire_plan_override(
        &mut self,
        session: &[u8; 32],
        id: Uuid,
        now: OffsetDateTime,
    ) -> Result<bool> {
        sqlx::query_scalar("SELECT platform.expire_plan_override($1, $2, $3)")
            .bind(session.as_slice())
            .bind(id)
            .bind(now)
            .fetch_one(&mut *self.tx)
            .await
            .map_err(db)
    }

    /// The organization an override belongs to, read in this transaction (for its event).
    ///
    /// # Errors
    /// A database error.
    pub async fn override_organization(&mut self, id: Uuid) -> Result<Option<Uuid>> {
        sqlx::query_scalar("SELECT organization_id FROM platform.plan_overrides WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *self.tx)
            .await
            .map_err(db)
    }
}
