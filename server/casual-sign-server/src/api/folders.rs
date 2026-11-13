//! Folders (UXW-02, docs/40 As built): each member's own envelope folders, and moving
//! envelopes into one or out of all. A folder is its owner's alone: another member's
//! or another account's folder answers as a missing one (`404`). Filing changes the
//! member's own lists only; the envelope, its `updated_at` and its audit chain are
//! untouched, so nothing here is recorded as evidence.

use axum::body::Bytes;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use casual_sign_store::repo::folders::Folder;
use casual_sign_store::{EnvelopeId, FolderEntryId, FolderId, StoreError};
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
/// The most folders one member has.
pub(crate) const MAX_FOLDERS: i64 = 500;
/// The most envelopes one move names.
pub(crate) const MAX_MOVE: usize = 200;

fn out(f: &Folder) -> Value {
    json!({ "id": f.id.to_string(), "name": f.name.get(), "count": f.count })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NameIn {
    name: String,
}

/// A folder name: trimmed, 1 to [`MAX_NAME`] characters, no control characters.
fn name_of(body: &[u8]) -> Result<String, ApiError> {
    let req: NameIn = parse(body)?;
    let name = req.name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME || name.chars().any(char::is_control) {
        return Err(ApiError::invalid("/name"));
    }
    Ok(name.to_owned())
}

/// A name the member already uses is `422` with `exists` at `/name`.
fn named(e: StoreError) -> ApiError {
    match e {
        StoreError::Conflict { .. } => ApiError::exists("/name"),
        e => e.into(),
    }
}

/// `GET /folders`: the caller's folders, by name, each with how many of the envelopes
/// they filed in it are in the lists (not deleted).
pub(crate) async fn list(c: Call) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let items: Vec<Value> = tx.folders().list(c.p.user).await?.iter().map(out).collect();
    Ok(json(StatusCode::OK, &json!({ "items": items })))
}

/// `POST /folders {name}`: a new folder of the caller's; `201` with it.
pub(crate) async fn create(c: Call, body: Bytes) -> Result<Response, ApiError> {
    let name = name_of(&body)?;
    let mut tx = c.tx().await?;
    if tx.folders().count(c.p.user).await? >= MAX_FOLDERS {
        return Err(ApiError::invalid("/name").detail(format!("at most {MAX_FOLDERS} folders")));
    }
    let id = FolderId(Uuid::now_v7());
    tx.folders()
        .create(c.p.user, id, &name)
        .await
        .map_err(named)?;
    let f = tx
        .folders()
        .get(c.p.user, id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    tx.commit().await?;
    Ok(json(StatusCode::CREATED, &out(&f)))
}

/// One of the caller's folders by its path id, or `404`.
async fn own(c: &Call, tx: &mut casual_sign_store::TenantTx, id: &str) -> Result<Folder, ApiError> {
    let id = FolderId(path_id(id)?);
    tx.folders()
        .get(c.p.user, id)
        .await?
        .ok_or_else(ApiError::not_found)
}

/// `PATCH /folders/{id} {name}`: rename one of the caller's folders.
pub(crate) async fn rename(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let f = own(&c, &mut tx, &id).await?;
    let name = name_of(&body)?;
    tx.folders()
        .rename(c.p.user, f.id, &name)
        .await
        .map_err(named)?;
    let f = tx
        .folders()
        .get(c.p.user, f.id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    tx.commit().await?;
    Ok(json(StatusCode::OK, &out(&f)))
}

/// `DELETE /folders/{id}`: remove one of the caller's folders; what they filed in it is
/// in no folder again (the envelopes themselves are untouched). `204`.
pub(crate) async fn delete(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let f = own(&c, &mut tx, &id).await?;
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
        Some(own(&c, &mut tx, &id).await?.id)
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
