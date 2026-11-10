//! Templates (docs/22 §7): create with roles, read, list, rename. Template documents,
//! role-bound fields and creating an envelope from a template are slice 3 (listed in
//! the T-2C report as not built).

use axum::body::Bytes;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::Response;
use casual_sign_audit::Personal;
use casual_sign_model::RecipientType as MRType;
use casual_sign_store::repo::recipients::RecipientType;
use casual_sign_store::repo::templates::{Template, TemplateRole};
use casual_sign_store::{TemplateId, TemplateRoleId};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{json, json_tagged, path_id};
use crate::call::Call;
use crate::dto::parse;
use crate::error::ApiError;

fn role_type(t: MRType) -> RecipientType {
    match t {
        MRType::Signer => RecipientType::Signer,
        MRType::InPersonSigner => RecipientType::InPersonSigner,
        MRType::Approver => RecipientType::Approver,
        MRType::Viewer => RecipientType::Viewer,
        MRType::Cc => RecipientType::Cc,
        MRType::Editor => RecipientType::Editor,
        MRType::Intermediary => RecipientType::Intermediary,
        MRType::Agent => RecipientType::Agent,
        MRType::Witness => RecipientType::Witness,
        MRType::Seal => RecipientType::Seal,
        MRType::Notary => RecipientType::Notary,
    }
}

fn template_json(t: &Template, roles: &[TemplateRole]) -> Value {
    json!({
        "id": t.id.to_string(),
        "owner_user_id": t.owner_user_id.to_string(),
        "name": t.name,
        "email_subject": t.email_subject.as_ref().map(Personal::get),
        "email_message": t.email_message.as_ref().map(Personal::get),
        "version": t.version,
        "roles": roles.iter().map(|r| json!({
            "id": r.id.to_string(), "name": r.name, "routing_order": r.routing_order,
            "type": r.kind.as_str(),
        })).collect::<Vec<_>>(),
    })
}

fn etag(t: &Template) -> String {
    format!("\"v{}\"", t.version)
}

/// `GET /templates`.
pub(crate) async fn list(c: Call) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let items: Vec<Value> = tx
        .templates()
        .list()
        .await?
        .iter()
        .map(|t| template_json(t, &[]))
        .collect();
    Ok(json(StatusCode::OK, &json!({ "items": items })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleIn {
    name: String,
    #[serde(default = "one")]
    routing_order: u32,
    #[serde(rename = "type")]
    rtype: MRType,
}

fn one() -> u32 {
    1
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TemplateIn {
    name: String,
    #[serde(default)]
    email_subject: Option<String>,
    #[serde(default)]
    email_message: Option<String>,
    #[serde(default)]
    roles: Vec<RoleIn>,
}

fn name(n: &str, at: &str) -> Result<String, ApiError> {
    let n = n.trim();
    if n.is_empty() || n.chars().count() > 255 {
        return Err(ApiError::invalid(at));
    }
    Ok(n.to_owned())
}

/// `POST /templates`.
pub(crate) async fn create(c: Call, body: Bytes) -> Result<Response, ApiError> {
    let req: TemplateIn = parse(&body)?;
    let t = Template {
        id: TemplateId(Uuid::now_v7()),
        owner_user_id: c.p.user,
        name: name(&req.name, "/name")?,
        email_subject: req
            .email_subject
            .map(|s| crate::dto::subject(&s).map(|t| Personal(t.0.as_str().to_owned())))
            .transpose()?,
        email_message: req
            .email_message
            .map(|s| crate::dto::message(&s).map(|t| Personal(t.0.as_str().to_owned())))
            .transpose()?,
        settings: json!({}),
        matching_rules: json!([]),
        version: 1,
    };
    let mut roles = Vec::new();
    for (i, r) in req.roles.iter().enumerate() {
        if !(1..=999).contains(&r.routing_order) {
            return Err(ApiError::invalid(&format!("/roles/{i}/routing_order")));
        }
        roles.push(TemplateRole {
            id: TemplateRoleId(Uuid::now_v7()),
            template_id: t.id,
            name: name(&r.name, &format!("/roles/{i}/name"))?,
            routing_order: i32::try_from(r.routing_order).unwrap_or(1),
            kind: role_type(r.rtype),
            default_auth: json!([]),
        });
    }
    let mut tx = c.tx().await?;
    tx.templates().insert(&t).await?;
    for r in &roles {
        tx.templates().add_role(r).await?;
    }
    tx.commit().await?;
    Ok(json_tagged(
        StatusCode::CREATED,
        &template_json(&t, &roles),
        &etag(&t),
    ))
}

/// `GET /templates/{id}`.
pub(crate) async fn get(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let id = TemplateId(path_id(&id)?);
    let mut tx = c.tx().await?;
    let t = tx
        .templates()
        .get(id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let roles = tx.templates().roles(id).await?;
    Ok(json_tagged(
        StatusCode::OK,
        &template_json(&t, &roles),
        &etag(&t),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TemplatePatch {
    name: String,
}

/// `PATCH /templates/{id} {name}` with `If-Match`.
pub(crate) async fn patch(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let id = TemplateId(path_id(&id)?);
    let mut tx = c.tx().await?;
    tx.templates()
        .get(id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let v = crate::dto::if_match(&c.headers).ok_or_else(ApiError::precondition_required)??;
    let req: TemplatePatch = parse(&body)?;
    let v = i32::try_from(v).map_err(|_| ApiError::precondition_failed())?;
    tx.templates()
        .rename(id, v, &name(&req.name, "/name")?)
        .await?;
    let t = tx
        .templates()
        .get(id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let roles = tx.templates().roles(id).await?;
    tx.commit().await?;
    Ok(json_tagged(
        StatusCode::OK,
        &template_json(&t, &roles),
        &etag(&t),
    ))
}
