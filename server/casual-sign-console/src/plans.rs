//! Plans in the console (PLAN-02, docs/23 §7.1, §10): the catalogue of plan versions,
//! creating and archiving versions, an organization's assignments and overrides with its
//! effective plan, assigning a plan, and setting or expiring an override.
//!
//! Every write is validated by `casual-sign-policy` first (`CS-PLAN-0006`, naming the
//! field), then by the definer function, which refuses the same things again (SQLSTATE
//! `OS010`). Operator events carry ids, codes and counts only: never an override's
//! reason.

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use casual_sign_platform_store::{Detail, NewOverride};
use casual_sign_policy::plans::{
    self, EffectivePlan, Enforcement, Feature, Level, Meter, MeterKind, Period, Plan, PlanDraft,
    PlanError, Quota, SeatRule,
};
use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::api::{Body, event, opt_time, rfc3339};
use crate::auth::{AnyOperator, Authed, Operators};
use crate::error::ConsoleError;
use crate::state::AppState;

impl From<PlanError> for ConsoleError {
    fn from(e: PlanError) -> Self {
        Self::PlanInvalid(e.field())
    }
}

fn quota_json(q: &Quota) -> Value {
    json!({
        "meter": q.meter.as_str(),
        "limit": q.limit,
        "period": q.period.as_str(),
        "enforcement": q.enforcement.as_str(),
        "level": q.level.as_str(),
    })
}

fn entitlements_json(e: &BTreeMap<Feature, bool>) -> Value {
    Value::Object(
        Feature::ALL
            .iter()
            .map(|f| {
                (
                    f.as_str().to_owned(),
                    Value::Bool(e.get(f).copied().unwrap_or(false)),
                )
            })
            .collect(),
    )
}

fn plan_json(p: &Plan) -> Value {
    json!({
        "id": p.id,
        "key": p.key,
        "version": p.version,
        "name": p.name,
        "seat_rule": p.seat_rule.as_str(),
        "entitlements": entitlements_json(&p.entitlements),
        "quotas": p.quotas.iter().map(quota_json).collect::<Vec<_>>(),
        "archived": p.archived,
    })
}

fn effective_json(e: &EffectivePlan) -> Value {
    json!({
        "assignment": e.assignment,
        "plan": e.plan,
        "key": e.key,
        "version": e.version,
        "name": e.name,
        "starts_at": rfc3339(e.starts_at),
        "ends_at": opt_time(e.ends_at),
        "seat_rule": e.seat_rule.as_str(),
        "entitlements": entitlements_json(&e.entitlements),
        "quotas": e.quotas.iter().map(quota_json).collect::<Vec<_>>(),
        "applied": e.applied,
        "ignored": e.ignored,
    })
}

/// What the plan form offers: the names this build knows.
fn catalogue() -> Value {
    json!({
        "features": Feature::ALL.iter().map(|f| f.as_str()).collect::<Vec<_>>(),
        "meters": Meter::ALL.iter().map(|m| json!({
            "name": m.as_str(),
            "kind": if m.kind() == MeterKind::Gauge { "gauge" } else { "counter" },
            "approximate": m.is_approximate(),
        })).collect::<Vec<_>>(),
        "periods": Period::ALL.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
        "enforcements": Enforcement::ALL.iter().map(|e| e.as_str()).collect::<Vec<_>>(),
        "levels": Level::ALL.iter().map(|l| l.as_str()).collect::<Vec<_>>(),
        "seat_rules": SeatRule::ALL.iter().map(|r| r.as_str()).collect::<Vec<_>>(),
    })
}

/// `GET /console/v1/plans`: every plan version, by key and newest version first, with the
/// organizations each is current for, and the catalogue of names.
pub async fn plans(
    State(state): State<AppState>,
    _op: Authed<AnyOperator>,
) -> Result<Json<Value>, ConsoleError> {
    let now = state.now();
    let list = state.store().plans(now).await?;
    Ok(Json(json!({
        "plans": list.iter().map(|r| {
            let mut v = plan_json(&r.plan);
            if let Some(o) = v.as_object_mut() {
                o.insert("created_at".into(), rfc3339(r.created_at));
                o.insert("archived_at".into(), opt_time(r.archived_at));
                o.insert("organizations".into(), json!(r.organizations));
            }
            v
        }).collect::<Vec<_>>(),
        "catalogue": catalogue(),
    })))
}

/// One quota in a request.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaBody {
    meter: String,
    limit: u64,
    period: String,
    enforcement: String,
    level: String,
}

/// A new plan version.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanBody {
    key: String,
    name: String,
    #[serde(default)]
    entitlements: BTreeMap<String, bool>,
    #[serde(default)]
    quotas: Vec<QuotaBody>,
    #[serde(default)]
    seat_rule: Option<String>,
}

fn named<T>(parsed: Option<T>, field: &'static str) -> Result<T, ConsoleError> {
    parsed.ok_or(ConsoleError::PlanInvalid(field))
}

impl PlanBody {
    fn draft(self) -> Result<PlanDraft, ConsoleError> {
        let mut entitlements = BTreeMap::new();
        for (name, on) in self.entitlements {
            entitlements.insert(named(Feature::parse(&name), "entitlements")?, on);
        }
        let quotas = self
            .quotas
            .into_iter()
            .map(|q| {
                Ok(Quota {
                    meter: named(Meter::parse(&q.meter), "quotas")?,
                    limit: q.limit,
                    period: named(Period::parse(&q.period), "quotas")?,
                    enforcement: named(Enforcement::parse(&q.enforcement), "quotas")?,
                    level: named(Level::parse(&q.level), "quotas")?,
                })
            })
            .collect::<Result<Vec<_>, ConsoleError>>()?;
        let seat_rule = match self.seat_rule {
            None => SeatRule::CanSend,
            Some(r) => named(SeatRule::parse(&r), "seat_rule")?,
        };
        let draft = PlanDraft {
            key: self.key,
            name: self.name.trim().to_owned(),
            entitlements,
            quotas,
            seat_rule,
        };
        plans::validate_plan(&draft)?;
        Ok(draft)
    }
}

/// `POST /console/v1/plans` (operators): the next version of `key` (1 for a new key).
pub async fn create_plan(
    State(state): State<AppState>,
    op: Authed<Operators>,
    Body(body): Body<PlanBody>,
) -> Result<Response, ConsoleError> {
    let draft = body.draft()?;
    let now = state.now();
    let id = Uuid::now_v7();
    let mut tx = state.store().begin().await?;
    let version = tx.create_plan(&op.token_sha256, id, &draft, now).await?;
    tx.append(
        &event("operator.plan.created", Some(op.id), &op.ctx, now)
            .with("plan", Detail::Id(id))
            .with("key", Detail::Code(draft.key.clone()))
            .with("version", Detail::Count(version)),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "id": id, "key": draft.key, "version": version })),
    )
        .into_response())
}

/// `POST /console/v1/plans/{id}/archive` (operators): no new assignment may name it;
/// current ones continue.
pub async fn archive_plan(
    State(state): State<AppState>,
    op: Authed<Operators>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ConsoleError> {
    let now = state.now();
    let mut tx = state.store().begin().await?;
    if !tx.archive_plan(&op.token_sha256, id, now).await? {
        return Err(ConsoleError::NotFound);
    }
    tx.append(
        &event("operator.plan.archived", Some(op.id), &op.ctx, now).with("plan", Detail::Id(id)),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /console/v1/organizations/{id}/plan`: every assignment and override, and the
/// effective plan for the organization now (workspace overrides are listed, and apply in
/// their workspace only).
pub async fn organization_plan(
    State(state): State<AppState>,
    _op: Authed<AnyOperator>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ConsoleError> {
    let now = state.now();
    if state.store().organization(id).await?.is_none() {
        return Err(ConsoleError::NotFound);
    }
    let inputs = state.store().plan_inputs(id, now).await?;
    let effective = plans::effective(&inputs, None, now);
    let applied: Vec<Uuid> = effective
        .as_ref()
        .map(|e| e.applied.clone())
        .unwrap_or_default();
    Ok(Json(json!({
        "organization": id,
        "at": rfc3339(now),
        "effective": effective.as_ref().map_or(Value::Null, effective_json),
        "assignments": inputs.assignments.iter().rev().map(|a| json!({
            "id": a.id,
            "plan": { "id": a.plan.id, "key": a.plan.key, "version": a.plan.version, "name": a.plan.name },
            "starts_at": rfc3339(a.starts_at),
            "ends_at": opt_time(a.ends_at),
            "current": a.is_current(now),
        })).collect::<Vec<_>>(),
        "overrides": inputs.overrides.iter().rev().map(|o| json!({
            "id": o.id,
            "workspace": o.workspace,
            "key": o.key.to_key(),
            "value": o.value.to_value(),
            "reason": o.reason,
            "expires_at": opt_time(o.expires_at),
            "created_at": rfc3339(o.created_at),
            "live": o.is_live(now),
            "applied": applied.contains(&o.id),
        })).collect::<Vec<_>>(),
    })))
}

fn time_field(
    v: Option<&str>,
    field: &'static str,
) -> Result<Option<OffsetDateTime>, ConsoleError> {
    v.map(|s| OffsetDateTime::parse(s, &Rfc3339).map_err(|_| ConsoleError::Invalid(field)))
        .transpose()
}

/// An assignment.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignBody {
    plan: Uuid,
    #[serde(default)]
    starts_at: Option<String>,
    #[serde(default)]
    ends_at: Option<String>,
}

/// `POST /console/v1/organizations/{id}/plan` (operators): assign a plan version from
/// `starts_at` (default now, never earlier) until `ends_at` (default open-ended); the
/// assignment current then ends at that instant.
pub async fn assign_plan(
    State(state): State<AppState>,
    op: Authed<Operators>,
    Path(org): Path<Uuid>,
    Body(body): Body<AssignBody>,
) -> Result<Response, ConsoleError> {
    let now = state.now();
    let starts = time_field(body.starts_at.as_deref(), "starts_at")?.unwrap_or(now);
    let ends = time_field(body.ends_at.as_deref(), "ends_at")?;
    if starts < now {
        return Err(ConsoleError::PlanInvalid("starts_at"));
    }
    if ends.is_some_and(|e| e <= starts) {
        return Err(ConsoleError::PlanInvalid("ends_at"));
    }
    let id = Uuid::now_v7();
    let mut tx = state.store().begin().await?;
    if !tx
        .assign_plan(&op.token_sha256, id, org, body.plan, starts, ends, now)
        .await?
    {
        return Err(ConsoleError::NotFound);
    }
    tx.append(
        &event("operator.plan.assigned", Some(op.id), &op.ctx, now)
            .with("organization", Detail::Id(org))
            .with("plan", Detail::Id(body.plan))
            .with("assignment", Detail::Id(id)),
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(json!({ "id": id }))).into_response())
}

/// An override.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverrideBody {
    key: String,
    value: String,
    reason: String,
    #[serde(default)]
    workspace: Option<Uuid>,
    #[serde(default)]
    expires_at: Option<String>,
}

/// `POST /console/v1/organizations/{id}/plan-overrides` (operators).
pub async fn set_override(
    State(state): State<AppState>,
    op: Authed<Operators>,
    Path(org): Path<Uuid>,
    Body(body): Body<OverrideBody>,
) -> Result<Response, ConsoleError> {
    let now = state.now();
    let (key, value) = plans::parse_override(body.workspace, &body.key, &body.value)?;
    let reason = body.reason.trim();
    if reason.is_empty() || reason.chars().count() > 200 || reason.chars().any(char::is_control) {
        return Err(ConsoleError::Invalid("reason"));
    }
    let expires = time_field(body.expires_at.as_deref(), "expires_at")?;
    if expires.is_some_and(|e| e <= now) {
        return Err(ConsoleError::PlanInvalid("expires_at"));
    }
    let id = Uuid::now_v7();
    let key = key.to_key();
    let value = value.to_value();
    let mut tx = state.store().begin().await?;
    let found = tx
        .set_plan_override(
            &op.token_sha256,
            &NewOverride {
                id,
                organization: org,
                workspace: body.workspace,
                key: &key,
                value: &value,
                reason,
                expires_at: expires,
            },
            now,
        )
        .await?;
    if !found {
        return Err(ConsoleError::NotFound);
    }
    let mut ev = event("operator.plan_override.set", Some(op.id), &op.ctx, now)
        .with("organization", Detail::Id(org))
        .with("override", Detail::Id(id))
        .with("key", Detail::Code(key))
        .with("value", Detail::Code(value));
    if let Some(w) = body.workspace {
        ev = ev.with("workspace", Detail::Id(w));
    }
    tx.append(&ev).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(json!({ "id": id }))).into_response())
}

/// `POST /console/v1/plan-overrides/{id}/expire` (operators): stop an override now.
pub async fn expire_override(
    State(state): State<AppState>,
    op: Authed<Operators>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ConsoleError> {
    let now = state.now();
    let mut tx = state.store().begin().await?;
    if !tx.expire_plan_override(&op.token_sha256, id, now).await? {
        return Err(ConsoleError::NotFound);
    }
    let org = tx.override_organization(id).await?;
    let mut ev = event("operator.plan_override.expired", Some(op.id), &op.ctx, now)
        .with("override", Detail::Id(id));
    if let Some(o) = org {
        ev = ev.with("organization", Detail::Id(o));
    }
    tx.append(&ev).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
