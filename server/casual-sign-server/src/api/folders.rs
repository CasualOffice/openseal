//! Folders (UXW-02, TSH-03; docs/40 As built): each member's own envelope folders and
//! template folders, and moving envelopes or templates into one or out of all. A folder
//! is its owner's alone: another member's or another account's folder answers as a
//! missing one (`404`), and so does a folder of the other kind. Filing changes the
//! member's own lists only; the envelope or template, its `updated_at` or version and
//! the audit chain are untouched, so nothing here is recorded as evidence.

use axum::body::Bytes;
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use casual_sign_store::repo::folders::{Folder, FolderKind};
use casual_sign_store::repo::templates::TemplateAccess;
use casual_sign_store::{EnvelopeId, FolderEntryId, FolderId, StoreError, TemplateId};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{json, path_id, visible};
use crate::apply::load;
use crate::call::Call;
use crate::dto::parse;
use crate::error::ApiError;

/// The longest folder name, in characters.
pub(crate) const MAX_NAME: usize = 100;
/// The most folders of one kind one member has.
pub(crate) const MAX_FOLDERS: i64 = 500;
/// The most envelopes (or templates) one move names.
pub(crate) const MAX_MOVE: usize = 200;

fn out(f: &Folder) -> Value {
    json!({ "id": f.id.to_string(), "name": f.name.get(), "kind": f.kind.as_str(), "count": f.count })
}

/// A kind as the API names it; absent is `envelopes`.
fn kind_of(s: Option<&str>, at: &str) -> Result<FolderKind, ApiError> {
    s.map_or(Ok(FolderKind::Envelopes), |k| {
        FolderKind::parse(k).ok_or_else(|| ApiError::invalid(at))
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NameIn {
    name: String,
    /// Only on create: `envelopes` (default) or `templates` (TSH-03).
    #[serde(default)]
    kind: Option<String>,
}

/// A folder name: trimmed, 1 to [`MAX_NAME`] characters, no control characters; and the
/// kind the body names.
fn name_of(body: &[u8]) -> Result<(String, Option<String>), ApiError> {
    let req: NameIn = parse(body)?;
    let name = req.name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME || name.chars().any(char::is_control) {
        return Err(ApiError::invalid("/name"));
    }
    Ok((name.to_owned(), req.kind))
}

/// A name the member already uses is `422` with `exists` at `/name`.
fn named(e: StoreError) -> ApiError {
    match e {
        StoreError::Conflict { .. } => ApiError::exists("/name"),
        e => e.into(),
    }
}

/// The query of `GET /folders`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListQuery {
    /// `envelopes` (default) or `templates`.
    kind: Option<String>,
}

/// `GET /folders?kind=`: the caller's folders of that kind, by name, each with how many
/// of the envelopes (or templates) they filed in it are in the lists. A template folder
/// counts only templates the caller may still use (a share taken away hides one).
pub(crate) async fn list(c: Call, Query(q): Query<ListQuery>) -> Result<Response, ApiError> {
    let kind = kind_of(q.kind.as_deref(), "/query/kind")?;
    let mut tx = c.tx().await?;
    let mut folders = tx.folders().list(c.p.user, kind).await?;
    if kind == FolderKind::Templates {
        let usable: Vec<TemplateId> = tx
            .templates()
            .list_for(
                c.p.user,
                c.p.admin,
                casual_sign_store::repo::templates::TemplateView::All,
            )
            .await?
            .iter()
            .map(|l| l.template.id)
            .collect();
        let filings = tx.folders().template_filings(c.p.user).await?;
        for f in &mut folders {
            let n = filings
                .iter()
                .filter(|(t, at)| *at == f.id && usable.contains(t))
                .count();
            f.count = i64::try_from(n).unwrap_or(i64::MAX);
        }
    }
    let items: Vec<Value> = folders.iter().map(out).collect();
    Ok(json(StatusCode::OK, &json!({ "items": items })))
}

/// `POST /folders {name, kind?}`: a new folder of the caller's; `201` with it.
pub(crate) async fn create(c: Call, body: Bytes) -> Result<Response, ApiError> {
    let (name, kind) = name_of(&body)?;
    let kind = kind_of(kind.as_deref(), "/kind")?;
    let mut tx = c.tx().await?;
    if tx.folders().count(c.p.user, kind).await? >= MAX_FOLDERS {
        return Err(ApiError::invalid("/name").detail(format!("at most {MAX_FOLDERS} folders")));
    }
    let id = FolderId(Uuid::now_v7());
    tx.folders()
        .create(c.p.user, id, &name, kind)
        .await
        .map_err(named)?;
    let f = tx
        .folders()
        .get(c.p.user, id, kind)
        .await?
        .ok_or_else(ApiError::not_found)?;
    tx.commit().await?;
    Ok(json(StatusCode::CREATED, &out(&f)))
}

/// One of the caller's folders of `kind` by its path id, or `404`.
async fn own(
    c: &Call,
    tx: &mut casual_sign_store::TenantTx,
    id: &str,
    kind: FolderKind,
) -> Result<Folder, ApiError> {
    let id = FolderId(path_id(id)?);
    tx.folders()
        .get(c.p.user, id, kind)
        .await?
        .ok_or_else(ApiError::not_found)
}

/// One of the caller's folders of either kind by its path id, or `404`.
async fn own_any(
    c: &Call,
    tx: &mut casual_sign_store::TenantTx,
    id: &str,
) -> Result<Folder, ApiError> {
    match own(c, tx, id, FolderKind::Envelopes).await {
        Ok(f) => Ok(f),
        Err(_) => own(c, tx, id, FolderKind::Templates).await,
    }
}

/// `PATCH /folders/{id} {name}`: rename one of the caller's folders.
pub(crate) async fn rename(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let f = own_any(&c, &mut tx, &id).await?;
    let (name, kind) = name_of(&body)?;
    if kind.is_some() {
        return Err(ApiError::invalid("/kind"));
    }
    tx.folders()
        .rename(c.p.user, f.id, &name)
        .await
        .map_err(named)?;
    let f = tx
        .folders()
        .get(c.p.user, f.id, f.kind)
        .await?
        .ok_or_else(ApiError::not_found)?;
    tx.commit().await?;
    Ok(json(StatusCode::OK, &out(&f)))
}

/// `DELETE /folders/{id}`: remove one of the caller's folders; what they filed in it is
/// in no folder again (the envelopes and templates themselves are untouched). `204`.
pub(crate) async fn delete(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let f = own_any(&c, &mut tx, &id).await?;
    tx.folders().delete(c.p.user, f.id).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MoveIn {
    envelope_ids: Vec<String>,
}

/// `POST /folders/{id}/envelopes {envelope_ids}`, or `POST /folders/none/envelopes`:
/// file 1 to [`MAX_MOVE`] envelopes the caller may see in one of their folders, or in
/// none, all or nothing. An envelope the caller may not see, or another account's, is
/// `404` and nothing moves. Answers `{moved}`, how many envelopes are now where asked.
pub(crate) async fn file(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let target = if id == "none" {
        None
    } else {
        Some(own(&c, &mut tx, &id, FolderKind::Envelopes).await?.id)
    };
    let req: MoveIn = parse(&body)?;
    if req.envelope_ids.is_empty() || req.envelope_ids.len() > MAX_MOVE {
        return Err(ApiError::invalid("/envelope_ids"));
    }
    let mut ids: Vec<EnvelopeId> = Vec::with_capacity(req.envelope_ids.len());
    for (i, s) in req.envelope_ids.iter().enumerate() {
        let e = EnvelopeId(
            Uuid::parse_str(s).map_err(|_| ApiError::invalid(&format!("/envelope_ids/{i}")))?,
        );
        if !ids.contains(&e) {
            ids.push(e);
        }
    }
    for e in &ids {
        let l = load(&mut tx, *e).await?.ok_or_else(ApiError::not_found)?;
        if !visible(&c.p, &l.state) {
            return Err(ApiError::not_found());
        }
    }
    let entries: Vec<(FolderEntryId, EnvelopeId)> = ids
        .iter()
        .map(|e| (FolderEntryId(Uuid::now_v7()), *e))
        .collect();
    tx.folders().file(c.p.user, target, &entries).await?;
    tx.commit().await?;
    Ok(json(StatusCode::OK, &json!({ "moved": ids.len() })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MoveTemplatesIn {
    template_ids: Vec<String>,
}

/// `POST /folders/{id}/templates {template_ids}`, or `POST /folders/none/templates`
/// (TSH-03): file 1 to [`MAX_MOVE`] live templates the caller may use in one of their
/// template folders, or in none, all or nothing. A template the caller may not use, or
/// another account's, is `404` and nothing moves; so is an envelope folder. Answers
/// `{moved}`.
pub(crate) async fn file_templates(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let target = if id == "none" {
        None
    } else {
        Some(own(&c, &mut tx, &id, FolderKind::Templates).await?.id)
    };
    let req: MoveTemplatesIn = parse(&body)?;
    if req.template_ids.is_empty() || req.template_ids.len() > MAX_MOVE {
        return Err(ApiError::invalid("/template_ids"));
    }
    let mut ids: Vec<TemplateId> = Vec::with_capacity(req.template_ids.len());
    for (i, s) in req.template_ids.iter().enumerate() {
        let t = TemplateId(
            Uuid::parse_str(s).map_err(|_| ApiError::invalid(&format!("/template_ids/{i}")))?,
        );
        if !ids.contains(&t) {
            ids.push(t);
        }
    }
    for t in &ids {
        super::templates::found(&mut tx, &c, *t, TemplateAccess::Use).await?;
    }
    let entries: Vec<(FolderEntryId, TemplateId)> = ids
        .iter()
        .map(|t| (FolderEntryId(Uuid::now_v7()), *t))
        .collect();
    tx.folders()
        .file_templates(c.p.user, target, &entries)
        .await?;
    tx.commit().await?;
    Ok(json(StatusCode::OK, &json!({ "moved": ids.len() })))
}
