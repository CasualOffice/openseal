//! Templates (docs/22 §7): create with roles, read, list, and (WEB-06) edit: rename and
//! change the email, add and remove documents, add, change and remove roles and
//! role-bound fields, duplicate, delete; and (UXW-02) the Deleted view: a deleted
//! template is kept with everything, listed by `GET /templates?deleted=true`, brought
//! back by `POST …/restore`, and removed for good by deleting it again. Every change raises the template's version
//! (`ETag: "v<n>"`), checked against `If-Match` (required on `PATCH` and `DELETE`,
//! honoured when given on `POST`). Creating an envelope from a template is slice 3.
//!
//! Sharing (UXW-06): a template is its owner's alone until shared with members, groups
//! or the whole account; every call checks on the server what the caller may do with it
//! (deny by default): no access is `404`, as another account's template; using it where
//! editing (or owning) is needed is `403`. Each member stars their own Favourites.

use std::collections::BTreeMap;

use axum::body::Bytes;
use axum::extract::{Path, Query};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use casual_sign_audit::Personal;
use casual_sign_model::{Field, Id, RecipientType as MRType};
use casual_sign_sdk::Credentials;
use casual_sign_store::repo::fields::Rect;
use casual_sign_store::repo::recipients::RecipientType;
use casual_sign_store::repo::templates::{
    ListedTemplate, ShareTarget, Template, TemplateAccess, TemplateDocument, TemplateField,
    TemplateRole, TemplateShare, TemplateView,
};
use casual_sign_store::{
    TemplateDocumentId, TemplateFieldId, TemplateId, TemplateRoleId, TemplateShareId, TenantTx,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::envelopes::{base64, pages_json};
use super::{json, json_tagged, path_id};
use crate::call::Call;
use crate::dto::{DocumentIn, parse};
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

fn role_json(r: &TemplateRole) -> Value {
    json!({
        "id": r.id.to_string(), "name": r.name, "routing_order": r.routing_order,
        "type": r.kind.as_str(),
    })
}

fn document_json(d: &TemplateDocument) -> Value {
    json!({
        "id": d.id.to_string(), "name": d.name, "ord": d.ord, "pages": d.page_count,
        "page_geometry": d.pages, "sha256": casual_sign_audit::Hash256(d.sha256),
    })
}

/// A template field as the API shows it: the model's field, bound to `role_id`.
fn field_json(f: &TemplateField) -> Value {
    let mut v = f.spec.get().clone();
    if let Some(o) = v.as_object_mut() {
        o.remove("recipient_id");
        o.insert("id".into(), json!(f.id.to_string()));
        o.insert(
            "document_id".into(),
            json!(f.template_document_id.to_string()),
        );
        o.insert("role_id".into(), json!(f.role_id.to_string()));
    }
    v
}

fn template_json(
    t: &Template,
    roles: &[TemplateRole],
    docs: Option<&[TemplateDocument]>,
    fields: Option<&[TemplateField]>,
) -> Value {
    let mut v = json!({
        "id": t.id.to_string(),
        "owner_user_id": t.owner_user_id.to_string(),
        "name": t.name,
        "email_subject": t.email_subject.as_ref().map(Personal::get),
        "email_message": t.email_message.as_ref().map(Personal::get),
        "version": t.version,
        "roles": roles.iter().map(role_json).collect::<Vec<_>>(),
    });
    if let Some(o) = v.as_object_mut() {
        if let Some(d) = docs {
            o.insert(
                "documents".into(),
                Value::Array(d.iter().map(document_json).collect()),
            );
        }
        if let Some(f) = fields {
            o.insert(
                "fields".into(),
                Value::Array(f.iter().map(field_json).collect()),
            );
        }
    }
    v
}

fn etag(t: &Template) -> String {
    format!("\"v{}\"", t.version)
}

/// The version `If-Match` names; `required` answers `428` without one.
fn if_match(c: &Call, required: bool) -> Result<Option<i32>, ApiError> {
    match crate::dto::if_match(&c.headers) {
        Some(v) => {
            let v = v?;
            Ok(Some(
                i32::try_from(v).map_err(|_| ApiError::precondition_failed())?,
            ))
        }
        None if required => Err(ApiError::precondition_required()),
        None => Ok(None),
    }
}

/// What the caller may do with template `id` (UXW-06), when it is at least `need`: no
/// access at all is `404` (as another account's template), too little is `403`.
async fn allowed(
    tx: &mut TenantTx,
    c: &Call,
    id: TemplateId,
    need: TemplateAccess,
) -> Result<TemplateAccess, ApiError> {
    match tx.templates().access(id, c.p.user, c.p.admin).await? {
        None => Err(ApiError::not_found()),
        Some(a) if a < need => Err(ApiError::forbidden(match need {
            TemplateAccess::Owner => "template owner",
            _ => "template edit",
        })),
        Some(a) => Ok(a),
    }
}

/// A live template the caller may act on with `need`.
pub(crate) async fn found(
    tx: &mut TenantTx,
    c: &Call,
    id: TemplateId,
    need: TemplateAccess,
) -> Result<Template, ApiError> {
    let t = tx
        .templates()
        .get(id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    allowed(tx, c, id, need).await?;
    Ok(t)
}

/// A template of the Deleted view the caller owns (or administers). The Deleted view is
/// the owner's: to anyone else, a share included, a deleted template is not found.
async fn found_deleted(tx: &mut TenantTx, c: &Call, id: TemplateId) -> Result<Template, ApiError> {
    let t = tx
        .templates()
        .get_deleted(id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    match tx.templates().access(id, c.p.user, c.p.admin).await? {
        Some(TemplateAccess::Owner) => Ok(t),
        _ => Err(ApiError::not_found()),
    }
}

/// `404` (or `403`) before reading a body, so a template the caller cannot reach is not
/// found whatever it sends.
async fn exists(c: &Call, id: TemplateId, need: TemplateAccess) -> Result<(), ApiError> {
    let mut tx = c.tx().await?;
    found(&mut tx, c, id, need).await?;
    tx.commit().await?;
    Ok(())
}

/// The whole template as the API shows it, with its `ETag`, the caller's `access` and
/// whether they starred it.
async fn full(
    tx: &mut TenantTx,
    c: &Call,
    id: TemplateId,
    status: StatusCode,
) -> Result<Response, ApiError> {
    let t = found(tx, c, id, TemplateAccess::Use).await?;
    let access = allowed(tx, c, id, TemplateAccess::Use).await?;
    let favourite = tx.templates().is_favourite(id, c.p.user).await?;
    let roles = tx.templates().roles(id).await?;
    let docs = tx.templates().documents(id).await?;
    let fields = tx.templates().fields(id).await?;
    let mut v = template_json(&t, &roles, Some(&docs), Some(&fields));
    if let Some(o) = v.as_object_mut() {
        o.insert("access".into(), json!(access.as_str()));
        o.insert("favourite".into(), json!(favourite));
    }
    Ok(json_tagged(status, &v, &etag(&t)))
}

/// The query of `GET /templates`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListQuery {
    /// `true`: the Deleted view (UXW-02).
    deleted: Option<String>,
    /// `all` (default), `owned`, `shared` (Shared with me) or `favourites` (UXW-06).
    view: Option<String>,
}

fn listed_json(l: &ListedTemplate) -> Value {
    let mut v = template_json(&l.template, &[], None, None);
    if let Some(o) = v.as_object_mut() {
        o.insert("access".into(), json!(l.access.as_str()));
        o.insert("favourite".into(), json!(l.favourite));
        o.insert("shared".into(), json!(l.shared));
    }
    v
}

/// `GET /templates`: the templates the caller may use, narrowed by `view` (UXW-06); or
/// with `deleted=true` the Deleted view (UXW-02) of the templates the caller owns (every
/// one for an administrator), most recently deleted first.
pub(crate) async fn list(c: Call, Query(q): Query<ListQuery>) -> Result<Response, ApiError> {
    let deleted = match q.deleted.as_deref() {
        None | Some("false") => false,
        Some("true") => true,
        Some(_) => return Err(ApiError::invalid("/query/deleted")),
    };
    let view = match q.view.as_deref() {
        None | Some("all") => TemplateView::All,
        Some("owned") => TemplateView::Owned,
        Some("shared") => TemplateView::SharedWithMe,
        Some("favourites") => TemplateView::Favourites,
        Some(_) => return Err(ApiError::invalid("/query/view")),
    };
    let mut tx = c.tx().await?;
    let items: Vec<Value> = if deleted {
        tx.templates()
            .list_deleted()
            .await?
            .iter()
            .filter(|t| c.p.admin || t.owner_user_id == c.p.user)
            .map(|t| template_json(t, &[], None, None))
            .collect()
    } else {
        tx.templates()
            .list_for(c.p.user, c.p.admin, view)
            .await?
            .iter()
            .map(listed_json)
            .collect()
    };
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

fn subject(s: Option<String>) -> Result<Option<Personal<String>>, ApiError> {
    s.map(|s| crate::dto::subject(&s).map(|t| Personal(t.0.as_str().to_owned())))
        .transpose()
}

fn message(s: Option<String>) -> Result<Option<Personal<String>>, ApiError> {
    s.map(|s| crate::dto::message(&s).map(|t| Personal(t.0.as_str().to_owned())))
        .transpose()
}

fn role_from(
    r: &RoleIn,
    id: TemplateRoleId,
    t: TemplateId,
    at: &str,
) -> Result<TemplateRole, ApiError> {
    if !(1..=999).contains(&r.routing_order) {
        return Err(ApiError::invalid(&format!("{at}/routing_order")));
    }
    Ok(TemplateRole {
        id,
        template_id: t,
        name: name(&r.name, &format!("{at}/name"))?,
        routing_order: i32::try_from(r.routing_order).unwrap_or(1),
        kind: role_type(r.rtype),
        default_auth: json!([]),
    })
}

/// `POST /templates`.
pub(crate) async fn create(c: Call, body: Bytes) -> Result<Response, ApiError> {
    let req: TemplateIn = parse(&body)?;
    let t = Template {
        id: TemplateId(Uuid::now_v7()),
        owner_user_id: c.p.user,
        name: name(&req.name, "/name")?,
        email_subject: subject(req.email_subject)?,
        email_message: message(req.email_message)?,
        settings: json!({}),
        matching_rules: json!([]),
        version: 1,
    };
    let mut roles = Vec::new();
    for (i, r) in req.roles.iter().enumerate() {
        roles.push(role_from(
            r,
            TemplateRoleId(Uuid::now_v7()),
            t.id,
            &format!("/roles/{i}"),
        )?);
    }
    let mut tx = c.tx().await?;
    tx.templates().insert(&t).await?;
    for r in &roles {
        tx.templates().add_role(r).await?;
    }
    tx.commit().await?;
    Ok(json_tagged(
        StatusCode::CREATED,
        &template_json(&t, &roles, Some(&[]), Some(&[])),
        &etag(&t),
    ))
}

/// `GET /templates/{id}`: with its roles, documents and fields.
pub(crate) async fn get(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let id = TemplateId(path_id(&id)?);
    let mut tx = c.tx().await?;
    full(&mut tx, &c, id, StatusCode::OK).await
}

/// A member that is present: `null` is `Some(None)` (clear), absence is `None` (keep).
fn present<'de, D>(d: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(d).map(Some)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TemplatePatch {
    #[serde(default)]
    name: Option<String>,
    #[serde(default, deserialize_with = "present")]
    email_subject: Option<Option<String>>,
    #[serde(default, deserialize_with = "present")]
    email_message: Option<Option<String>>,
}

/// `PATCH /templates/{id} {name?, email_subject?, email_message?}` with `If-Match`.
pub(crate) async fn patch(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let id = TemplateId(path_id(&id)?);
    let mut tx = c.tx().await?;
    let t = found(&mut tx, &c, id, TemplateAccess::Edit).await?;
    let v = if_match(&c, true)?;
    let req: TemplatePatch = parse(&body)?;
    if let Some(n) = &req.name {
        tx.templates()
            .rename(id, v.unwrap_or(t.version), &name(n, "/name")?)
            .await?;
    } else {
        tx.templates().bump(id, v).await?;
    }
    if req.email_subject.is_some() || req.email_message.is_some() {
        let s = match req.email_subject {
            Some(s) => subject(s)?,
            None => t.email_subject.clone(),
        };
        let m = match req.email_message {
            Some(m) => message(m)?,
            None => t.email_message.clone(),
        };
        tx.templates().set_email(id, s.as_ref(), m.as_ref()).await?;
    }
    let r = full(&mut tx, &c, id, StatusCode::OK).await?;
    tx.commit().await?;
    Ok(r)
}

/// `DELETE /templates/{id}` with `If-Match` (UXW-02): a live template moves to the
/// Deleted view, kept with its roles, documents and fields and restorable; a template
/// already there is removed for good, with them. Envelopes made from it are copies and
/// keep everything. `204` either way. Only its owner or an administrator deletes it
/// (UXW-06).
pub(crate) async fn delete(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let id = TemplateId(path_id(&id)?);
    let mut tx = c.tx().await?;
    if tx.templates().get(id).await?.is_some() {
        allowed(&mut tx, &c, id, TemplateAccess::Owner).await?;
        let v = if_match(&c, true)?;
        tx.templates().trash(id, v).await?;
    } else {
        let t = found_deleted(&mut tx, &c, id).await?;
        if if_match(&c, true)?.is_some_and(|v| v != t.version) {
            return Err(casual_sign_store::StoreError::StaleVersion { entity: "template" }.into());
        }
        tx.templates().delete(id).await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /templates/{id}/restore` (UXW-02): a template of the Deleted view back to the
/// list, with everything it had; `200` with the whole template. `If-Match` is honoured
/// when given. A live template, or none, is `404`; so is one the caller does not own
/// (UXW-06), unless an administrator.
pub(crate) async fn restore(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let id = TemplateId(path_id(&id)?);
    let mut tx = c.tx().await?;
    let t = found_deleted(&mut tx, &c, id).await?;
    if !body.iter().all(u8::is_ascii_whitespace) {
        let _: Empty = parse(&body)?;
    }
    if if_match(&c, false)?.is_some_and(|v| v != t.version) {
        return Err(casual_sign_store::StoreError::StaleVersion { entity: "template" }.into());
    }
    tx.templates().restore(id).await?;
    let r = full(&mut tx, &c, id, StatusCode::OK).await?;
    tx.commit().await?;
    Ok(r)
}

/// An empty body, or an empty object.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct DuplicateIn {
    #[serde(default)]
    name: Option<String>,
}

/// `POST /templates/{id}/duplicate {name?}`: a new template, owned by the caller, with
/// copies of the roles, documents (the same stored PDFs) and fields under new ids.
pub(crate) async fn duplicate(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let id = TemplateId(path_id(&id)?);
    exists(&c, id, TemplateAccess::Use).await?;
    let req: DuplicateIn = if body.iter().all(u8::is_ascii_whitespace) {
        DuplicateIn::default()
    } else {
        parse(&body)?
    };
    let mut tx = c.tx().await?;
    let t = found(&mut tx, &c, id, TemplateAccess::Use).await?;
    let copy_name = match &req.name {
        Some(n) => name(n, "/name")?,
        None => format!("Copy of {}", t.name).chars().take(255).collect(),
    };
    let new = Template {
        id: TemplateId(Uuid::now_v7()),
        owner_user_id: c.p.user,
        name: copy_name,
        version: 1,
        ..t
    };
    tx.templates().insert(&new).await?;
    let mut roles = BTreeMap::new();
    for r in tx.templates().roles(id).await? {
        let n = TemplateRole {
            id: TemplateRoleId(Uuid::now_v7()),
            template_id: new.id,
            ..r.clone()
        };
        tx.templates().add_role(&n).await?;
        roles.insert(r.id, n.id);
    }
    let mut docs = BTreeMap::new();
    for d in tx.templates().documents(id).await? {
        let n = TemplateDocument {
            id: TemplateDocumentId(Uuid::now_v7()),
            template_id: new.id,
            ..d.clone()
        };
        tx.templates().add_document(&n).await?;
        docs.insert(d.id, n.id);
    }
    for f in tx.templates().fields(id).await? {
        let (Some(role), Some(doc)) = (roles.get(&f.role_id), docs.get(&f.template_document_id))
        else {
            return Err(ApiError::internal("template field"));
        };
        let fid = TemplateFieldId(Uuid::now_v7());
        let mut spec = f.spec.get().clone();
        if let Some(o) = spec.as_object_mut() {
            o.insert("id".into(), json!(fid.to_string()));
            o.insert("document_id".into(), json!(doc.to_string()));
            o.insert("recipient_id".into(), json!(role.to_string()));
        }
        tx.templates()
            .add_field(&TemplateField {
                id: fid,
                template_id: new.id,
                template_document_id: *doc,
                role_id: *role,
                spec: Personal(spec),
                ..f
            })
            .await?;
    }
    let r = full(&mut tx, &c, new.id, StatusCode::CREATED).await?;
    tx.commit().await?;
    Ok(r)
}

// Sharing and Favourites (UXW-06) ----------------------------------------------------------

/// The most shares one template holds.
const MAX_SHARES: usize = 500;

/// A share as the API shows it: whom it reaches (`user` with their name and email, a
/// `group` with its name, or `account: true`) and `can_edit`.
async fn share_json(tx: &mut TenantTx, s: &TemplateShare) -> Result<Value, ApiError> {
    let mut v = json!({ "id": s.id.to_string(), "can_edit": s.can_edit });
    if let Some(o) = v.as_object_mut() {
        match s.target {
            ShareTarget::User(u) => {
                let m = tx.users().get(u).await?;
                o.insert(
                    "user".into(),
                    json!({
                        "id": u.to_string(),
                        "name": m.as_ref().map(|m| m.name.get().clone()),
                        "email": m.as_ref().map(|m| m.email.get().clone()),
                    }),
                );
            }
            ShareTarget::Group(g) => {
                let name = tx
                    .templates()
                    .groups()
                    .await?
                    .into_iter()
                    .find(|x| x.id == g)
                    .map(|x| x.name);
                o.insert("group".into(), json!({ "id": g.to_string(), "name": name }));
            }
            ShareTarget::Account => {
                o.insert("account".into(), json!(true));
            }
        }
    }
    Ok(v)
}

async fn shares_json(tx: &mut TenantTx, id: TemplateId) -> Result<Value, ApiError> {
    let mut items = Vec::new();
    for s in tx.templates().shares(id).await? {
        items.push(share_json(tx, &s).await?);
    }
    Ok(json!({ "items": items }))
}

/// `GET /templates/{id}/shares`: whom the template is shared with. Its owner's (or an
/// administrator's).
pub(crate) async fn shares(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let id = TemplateId(path_id(&id)?);
    let mut tx = c.tx().await?;
    found(&mut tx, &c, id, TemplateAccess::Owner).await?;
    let v = shares_json(&mut tx, id).await?;
    tx.commit().await?;
    Ok(json(StatusCode::OK, &v))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShareIn {
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    group_id: Option<String>,
    #[serde(default)]
    account: Option<bool>,
    #[serde(default)]
    can_edit: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SharesIn {
    items: Vec<ShareIn>,
}

/// `PUT /templates/{id}/shares {items: [{user_id | email | group_id | account: true,
/// can_edit?}]}`: the whole set of shares, replacing the old. A user is a member of this
/// account (by id or email), a group one of its groups; sharing with the owner, or naming
/// one target twice, is refused (`422`). Its owner's (or an administrator's). Answers the
/// shares as `GET` does.
pub(crate) async fn put_shares(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let id = TemplateId(path_id(&id)?);
    exists(&c, id, TemplateAccess::Owner).await?;
    let req: SharesIn = parse(&body)?;
    if req.items.len() > MAX_SHARES {
        return Err(ApiError::invalid("/items"));
    }
    let mut tx = c.tx().await?;
    let t = found(&mut tx, &c, id, TemplateAccess::Owner).await?;
    let members = if req
        .items
        .iter()
        .any(|s| s.email.is_some() || s.user_id.is_some())
    {
        tx.users().list().await?
    } else {
        Vec::new()
    };
    let groups = if req.items.iter().any(|s| s.group_id.is_some()) {
        tx.templates().groups().await?
    } else {
        Vec::new()
    };
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::with_capacity(req.items.len());
    for (i, s) in req.items.iter().enumerate() {
        let at = format!("/items/{i}");
        let named = [
            s.user_id.is_some(),
            s.email.is_some(),
            s.group_id.is_some(),
            s.account.is_some(),
        ]
        .into_iter()
        .filter(|n| *n)
        .count();
        if named != 1 {
            return Err(ApiError::invalid(&at));
        }
        let target = if let Some(u) = &s.user_id {
            let u = Uuid::parse_str(u).map_err(|_| ApiError::invalid(&format!("{at}/user_id")))?;
            members
                .iter()
                .find(|m| m.user_id.0 == u)
                .map(|m| ShareTarget::User(m.user_id))
                .ok_or_else(|| ApiError::invalid(&format!("{at}/user_id")))?
        } else if let Some(e) = &s.email {
            let e = e.trim();
            if e.len() < 3 || e.len() > 320 {
                return Err(ApiError::invalid(&format!("{at}/email")));
            }
            members
                .iter()
                .find(|m| m.email.get().eq_ignore_ascii_case(e))
                .map(|m| ShareTarget::User(m.user_id))
                .ok_or_else(|| ApiError::invalid(&format!("{at}/email")))?
        } else if let Some(g) = &s.group_id {
            let g = Uuid::parse_str(g).map_err(|_| ApiError::invalid(&format!("{at}/group_id")))?;
            groups
                .iter()
                .find(|x| x.id.0 == g)
                .map(|x| ShareTarget::Group(x.id))
                .ok_or_else(|| ApiError::invalid(&format!("{at}/group_id")))?
        } else if s.account == Some(true) {
            ShareTarget::Account
        } else {
            return Err(ApiError::invalid(&format!("{at}/account")));
        };
        if target == ShareTarget::User(t.owner_user_id) || !seen.insert(target) {
            return Err(ApiError::invalid(&at));
        }
        out.push(TemplateShare {
            id: TemplateShareId(Uuid::now_v7()),
            target,
            can_edit: s.can_edit,
        });
    }
    tx.templates().replace_shares(id, &out).await?;
    let v = shares_json(&mut tx, id).await?;
    tx.commit().await?;
    Ok(json(StatusCode::OK, &v))
}

/// `PUT /templates/{id}/favourite`: star the template for the caller (Favourites); any
/// member who may use it. Idempotent; `204`.
pub(crate) async fn favourite(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    star(c, id, true).await
}

/// `DELETE /templates/{id}/favourite`: unstar it. Idempotent; `204`.
pub(crate) async fn unfavourite(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    star(c, id, false).await
}

async fn star(c: Call, id: String, on: bool) -> Result<Response, ApiError> {
    let id = TemplateId(path_id(&id)?);
    let mut tx = c.tx().await?;
    found(&mut tx, &c, id, TemplateAccess::Use).await?;
    tx.templates().set_favourite(id, c.p.user, on).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `GET /groups`: this account's groups by name with their member counts, for choosing
/// whom to share a template with (UXW-06). Managing groups is `UXW-07`.
pub(crate) async fn groups(c: Call) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let items: Vec<Value> = tx
        .templates()
        .groups()
        .await?
        .iter()
        .map(|g| json!({ "id": g.id.to_string(), "name": g.name, "members": g.members }))
        .collect();
    tx.commit().await?;
    Ok(json(StatusCode::OK, &json!({ "items": items })))
}

// Documents -----------------------------------------------------------------------------

/// `POST /templates/{id}/documents {name, content_base64}`: admitted and normalized as
/// an envelope's upload is (docs/30 §2, §3); the stored PDF is shared by envelopes made
/// from the template.
pub(crate) async fn add_document(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let id = TemplateId(path_id(&id)?);
    // Authorized in a short transaction, ended before the scan: a scan can wait up to
    // its timeout and must not hold a pooled connection meanwhile (ASVS-11).
    let mut tx = c.tx().await?;
    found(&mut tx, &c, id, TemplateAccess::Edit).await?;
    tx.commit().await?;
    let req: DocumentIn = parse(&body)?;
    let docname = name(&req.name, "/name")?;
    let bytes = base64(
        &req.content_base64,
        c.st.config().max_document_bytes,
        "/content_base64",
    )?;
    let v = if_match(&c, false)?;
    // Scanned before it is admitted or stored (ASVS-11).
    crate::scan::screen(
        &c.st,
        c.uploader(),
        casual_sign_store::UploadKind::TemplateDocument,
        vec![("template", id.0.to_string())],
        &bytes,
    )
    .await?;
    let engine = c.st.0.engine.clone();
    let delivered = tokio::task::spawn_blocking(move || {
        match engine.prepare(&bytes, &Credentials::default()) {
            Err(e) if e.code() == "CS-PDF-0014" => engine.keep_signed(&bytes),
            other => other,
        }
    })
    .await
    .map_err(|_| ApiError::internal("admission"))??;
    let pages = delivered.admission.page_count;
    if pages == 0 || pages > casual_sign_workflow::limits::MAX_PAGES {
        return Err(ApiError::invalid("/content_base64"));
    }
    // Authorized again: access may have changed during the scan and the admission.
    let mut tx = c.tx().await?;
    found(&mut tx, &c, id, TemplateAccess::Edit).await?;
    let key = c.st.0.blobs.put(&delivered.bytes).await?;
    let ord = tx
        .templates()
        .documents(id)
        .await?
        .iter()
        .map(|d| d.ord)
        .max()
        .map_or(0, |m| m.saturating_add(1));
    let d = TemplateDocument {
        id: TemplateDocumentId(Uuid::now_v7()),
        template_id: id,
        ord,
        name: docname,
        sha256: key.0,
        byte_len: i64::try_from(delivered.bytes.len()).unwrap_or(i64::MAX),
        page_count: i32::try_from(pages).unwrap_or(i32::MAX),
        pages: pages_json(&delivered.admission),
    };
    tx.templates().bump(id, v).await?;
    let storage = tx
        .gauge_lock(casual_sign_store::Meter::StorageBytes)
        .await?;
    tx.templates().add_document(&d).await?;
    tx.gauge_check(storage, c.st.now(), "template_document", d.id.0)
        .await?;
    // Page hashes for matching uploads (docs/33 §2), only with template matching in
    // effect; otherwise nothing is written (ML-01).
    crate::api::ml::on_template_upload(&c.st, &mut tx, c.p.account, id, d.id, d.sha256).await?;
    let r = full(&mut tx, &c, id, StatusCode::CREATED).await?;
    tx.commit().await?;
    Ok(r)
}

/// `DELETE /templates/{id}/documents/{doc}` with `If-Match`: the document and its fields.
pub(crate) async fn delete_document(
    c: Call,
    Path((id, doc)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let id = TemplateId(path_id(&id)?);
    let doc = TemplateDocumentId(path_id(&doc)?);
    let mut tx = c.tx().await?;
    found(&mut tx, &c, id, TemplateAccess::Edit).await?;
    let v = if_match(&c, true)?;
    tx.templates().bump(id, v).await?;
    tx.ml().forget_template_document(id, doc).await?;
    tx.templates().delete_document(id, doc).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `GET /templates/{id}/documents/{doc}/content`: the stored PDF, for the editor.
pub(crate) async fn document_content(
    c: Call,
    Path((id, doc)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let id = TemplateId(path_id(&id)?);
    let doc = TemplateDocumentId(path_id(&doc)?);
    let mut tx = c.tx().await?;
    // A deleted template's documents are not read either (UXW-02, SEC-A12): the
    // documents query does not look at the template's `deleted_at`.
    found(&mut tx, &c, id, TemplateAccess::Use).await?;
    let d = tx
        .templates()
        .documents(id)
        .await?
        .into_iter()
        .find(|d| d.id == doc)
        .ok_or_else(ApiError::not_found)?;
    tx.commit().await?;
    let bytes =
        c.st.0
            .blobs
            .get(&casual_sign_store::blob::BlobKey(d.sha256))
            .await?;
    let mut r = (StatusCode::OK, bytes).into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/pdf"),
    );
    Ok(r)
}

// Roles ---------------------------------------------------------------------------------

/// `POST /templates/{id}/roles {name, type, routing_order?}`.
pub(crate) async fn add_role(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let id = TemplateId(path_id(&id)?);
    exists(&c, id, TemplateAccess::Edit).await?;
    let req: RoleIn = parse(&body)?;
    let mut tx = c.tx().await?;
    found(&mut tx, &c, id, TemplateAccess::Edit).await?;
    let v = if_match(&c, false)?;
    let r = role_from(&req, TemplateRoleId(Uuid::now_v7()), id, "")?;
    tx.templates().bump(id, v).await?;
    tx.templates().add_role(&r).await?;
    let resp = full(&mut tx, &c, id, StatusCode::CREATED).await?;
    tx.commit().await?;
    Ok(resp)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RolePatch {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    routing_order: Option<u32>,
    #[serde(default, rename = "type")]
    rtype: Option<MRType>,
}

/// `PATCH /templates/{id}/roles/{role} {name?, type?, routing_order?}` with `If-Match`.
pub(crate) async fn patch_role(
    c: Call,
    Path((id, role)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let id = TemplateId(path_id(&id)?);
    let role = TemplateRoleId(path_id(&role)?);
    let mut tx = c.tx().await?;
    found(&mut tx, &c, id, TemplateAccess::Edit).await?;
    let mut r = tx
        .templates()
        .roles(id)
        .await?
        .into_iter()
        .find(|r| r.id == role)
        .ok_or_else(ApiError::not_found)?;
    let v = if_match(&c, true)?;
    let req: RolePatch = parse(&body)?;
    if let Some(n) = &req.name {
        r.name = name(n, "/name")?;
    }
    if let Some(o) = req.routing_order {
        if !(1..=999).contains(&o) {
            return Err(ApiError::invalid("/routing_order"));
        }
        r.routing_order = i32::try_from(o).unwrap_or(1);
    }
    if let Some(t) = req.rtype {
        r.kind = role_type(t);
    }
    tx.templates().bump(id, v).await?;
    tx.templates().update_role(&r).await?;
    let resp = full(&mut tx, &c, id, StatusCode::OK).await?;
    tx.commit().await?;
    Ok(resp)
}

/// `DELETE /templates/{id}/roles/{role}` with `If-Match`: the role and its fields.
pub(crate) async fn delete_role(
    c: Call,
    Path((id, role)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let id = TemplateId(path_id(&id)?);
    let role = TemplateRoleId(path_id(&role)?);
    let mut tx = c.tx().await?;
    found(&mut tx, &c, id, TemplateAccess::Edit).await?;
    let v = if_match(&c, true)?;
    tx.templates().bump(id, v).await?;
    tx.templates().delete_role(id, role).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// Fields --------------------------------------------------------------------------------

/// A template field from the API's field shape (as envelope fields, bound to
/// `role_id` instead of a recipient), checked as the model checks every field and
/// against the template's roles and documents.
fn template_field(
    raw: &Value,
    fid: TemplateFieldId,
    template: TemplateId,
    roles: &[TemplateRole],
    docs: &[TemplateDocument],
    at: &str,
) -> Result<TemplateField, ApiError> {
    let mut raw = raw.clone();
    if let Some(o) = raw.as_object_mut() {
        for k in ["role_id", "role"] {
            if let Some(r) = o.remove(k) {
                o.insert("recipient_id".into(), r);
            }
        }
        if o.contains_key("recipient") {
            return Err(ApiError::invalid(&format!("{at}/recipient")));
        }
    }
    let id = Id::new(fid.to_string()).map_err(|_| ApiError::internal("id"))?;
    let role_of = |s: &str| {
        roles
            .iter()
            .find(|r| r.id.to_string() == s)
            .and_then(|r| Id::new(r.id.to_string()).ok())
    };
    let doc_of = |v: &Value| {
        v.as_str().and_then(|s| {
            docs.iter()
                .find(|d| d.id.to_string() == s)
                .and_then(|d| Id::new(d.id.to_string()).ok())
        })
    };
    let f: Field = crate::dto::field_from(&raw, id, role_of, doc_of, at)?;
    let role = f
        .recipient_id
        .as_ref()
        .and_then(|r| Uuid::parse_str(r.as_str()).ok())
        .map(TemplateRoleId)
        .ok_or_else(|| ApiError::invalid(&format!("{at}/role_id")))?;
    let doc = docs
        .iter()
        .find(|d| d.id.to_string() == f.document_id.as_str())
        .ok_or_else(|| ApiError::invalid(&format!("{at}/document_id")))?;
    let p = f.placement;
    if i64::from(p.page()) > i64::from(doc.page_count) {
        return Err(ApiError::invalid(&format!("{at}/page")));
    }
    let page = i32::try_from(p.page()).map_err(|_| ApiError::invalid(&format!("{at}/page")))?;
    Ok(TemplateField {
        id: fid,
        template_id: template,
        template_document_id: doc.id,
        role_id: role,
        kind: f.field_type,
        rect: Rect {
            page,
            x: p.x().get(),
            y: p.y().get(),
            width: p.width().get(),
            height: p.height().get(),
        },
        required: f.required,
        label: f.label.as_ref().map(|l| l.as_str().to_owned()),
        spec: Personal(serde_json::to_value(&f).map_err(|_| ApiError::internal("field"))?),
    })
}

/// `GET /templates/{id}/fields`.
pub(crate) async fn fields(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let id = TemplateId(path_id(&id)?);
    let mut tx = c.tx().await?;
    let t = found(&mut tx, &c, id, TemplateAccess::Use).await?;
    let items: Vec<Value> = tx
        .templates()
        .fields(id)
        .await?
        .iter()
        .map(field_json)
        .collect();
    Ok(json_tagged(
        StatusCode::OK,
        &json!({ "items": items }),
        &etag(&t),
    ))
}

/// `POST /templates/{id}/fields`: one field, or `{"items": [...]}`.
pub(crate) async fn add_fields(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let id = TemplateId(path_id(&id)?);
    exists(&c, id, TemplateAccess::Edit).await?;
    let raw: Value = parse(&body)?;
    let list: Vec<Value> = match raw.get("items") {
        Some(Value::Array(items)) => items.clone(),
        Some(_) => return Err(ApiError::invalid("/items")),
        None => vec![raw],
    };
    if list.is_empty() || list.len() > casual_sign_workflow::limits::MAX_FIELDS {
        return Err(ApiError::invalid("/items"));
    }
    let mut tx = c.tx().await?;
    found(&mut tx, &c, id, TemplateAccess::Edit).await?;
    let v = if_match(&c, false)?;
    let roles = tx.templates().roles(id).await?;
    let docs = tx.templates().documents(id).await?;
    let existing = tx.templates().fields(id).await?.len();
    if existing.saturating_add(list.len()) > casual_sign_workflow::limits::MAX_FIELDS {
        return Err(ApiError::invalid("/items"));
    }
    let mut made = Vec::new();
    for (i, f) in list.iter().enumerate() {
        made.push(template_field(
            f,
            TemplateFieldId(Uuid::now_v7()),
            id,
            &roles,
            &docs,
            &format!("/items/{i}"),
        )?);
    }
    tx.templates().bump(id, v).await?;
    for f in &made {
        tx.templates().add_field(f).await?;
    }
    let t = found(&mut tx, &c, id, TemplateAccess::Use).await?;
    tx.commit().await?;
    Ok(json_tagged(
        StatusCode::CREATED,
        &json!({ "items": made.iter().map(field_json).collect::<Vec<_>>() }),
        &etag(&t),
    ))
}

/// `PATCH /templates/{id}/fields/{f}` with `If-Match`: members given replace the
/// field's, `null` removes one (the field is checked whole again).
pub(crate) async fn patch_field(
    c: Call,
    Path((id, field)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let id = TemplateId(path_id(&id)?);
    let fid = TemplateFieldId(path_id(&field)?);
    let mut tx = c.tx().await?;
    found(&mut tx, &c, id, TemplateAccess::Edit).await?;
    let current = tx
        .templates()
        .fields(id)
        .await?
        .into_iter()
        .find(|f| f.id == fid)
        .ok_or_else(ApiError::not_found)?;
    let v = if_match(&c, true)?;
    let patch: Value = parse(&body)?;
    let Value::Object(changes) = patch else {
        return Err(ApiError::invalid(""));
    };
    // The current field in the API's shape, flat placement, then the changes on top.
    let mut merged = field_json(&current);
    if let Some(o) = merged.as_object_mut() {
        o.remove("id");
        if let Some(Value::Object(p)) = o.remove("placement") {
            o.extend(p);
        }
        for (k, val) in changes {
            if k == "id" {
                return Err(ApiError::invalid("/id"));
            }
            if k == "placement" {
                if let Value::Object(p) = val {
                    o.extend(p);
                }
                continue;
            }
            // `null` removes a member (a JSON merge, as an envelope field's `PATCH`): how
            // the editor clears a setting (UX-11).
            if val.is_null() {
                o.remove(&k);
            } else {
                o.insert(k, val);
            }
        }
    }
    let roles = tx.templates().roles(id).await?;
    let docs = tx.templates().documents(id).await?;
    let f = template_field(&merged, fid, id, &roles, &docs, "")?;
    tx.templates().bump(id, v).await?;
    tx.templates().replace_field(&f).await?;
    let t = found(&mut tx, &c, id, TemplateAccess::Use).await?;
    tx.commit().await?;
    Ok(json_tagged(StatusCode::OK, &field_json(&f), &etag(&t)))
}

/// `DELETE /templates/{id}/fields/{f}` with `If-Match`.
pub(crate) async fn delete_field(
    c: Call,
    Path((id, field)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let id = TemplateId(path_id(&id)?);
    let fid = TemplateFieldId(path_id(&field)?);
    let mut tx = c.tx().await?;
    found(&mut tx, &c, id, TemplateAccess::Edit).await?;
    let v = if_match(&c, true)?;
    tx.templates().bump(id, v).await?;
    tx.templates().delete_field(id, fid).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
