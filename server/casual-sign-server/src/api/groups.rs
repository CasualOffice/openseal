//! Admin groups and custom permission profiles (UXW-07; docs/40 As built, docs/22 §8).
//!
//! Groups: an administrator (scope `admin:users`) makes, renames and deletes groups and
//! sets their members; groups are what templates are shared with (UXW-06). Deleting a
//! group removes its template shares with it.
//!
//! Permission profiles: the account's three built-in profiles are fixed; custom ones
//! are made, changed and deleted here, each a set of the scopes of docs/40 §2 and
//! `view_all_envelopes`. A member's profile is read on every request (`auth.rs`
//! `as_member`), so a change applies from the member's next request. Nobody gives more
//! than they hold (`Principal::may_grant`): a profile beyond the caller's own rights
//! cannot be made, changed, deleted or assigned by them. A profile a member holds cannot
//! be deleted (`409 CS-WF-0001`); changing one may take seats and is checked against the
//! plan as re-profiling a member is (PLAN-04).
//!
//! Every change appends its admin event in the same transaction (store `groups.rs`,
//! `accounts.rs`).

use std::collections::BTreeSet;

use axum::body::Bytes;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use casual_sign_store::repo::accounts::{PermissionProfile, ProfileKind};
use casual_sign_store::repo::templates::Group;
use casual_sign_store::{GroupId, Meter, PermissionProfileId, StoreError, UserId};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{json, path_id};
use crate::auth::{SCOPES, VIEW_ALL, profile_scopes};
use crate::call::Call;
use crate::dto::parse;
use crate::error::ApiError;

/// The longest group or profile name, in characters (the database's limit).
const MAX_NAME: usize = 255;

/// A name: trimmed, 1 to [`MAX_NAME`] characters, no control characters.
fn name_of(name: &str) -> Result<String, ApiError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME || name.chars().any(char::is_control) {
        return Err(ApiError::invalid("/name"));
    }
    Ok(name.to_owned())
}

/// A name the account already uses is `422` with `exists` at `/name`.
fn named(e: StoreError) -> ApiError {
    match e {
        StoreError::Conflict { .. } => ApiError::exists("/name"),
        e => e.into(),
    }
}

// Groups --------------------------------------------------------------------------------

fn group_json(g: &Group, users: Option<&[UserId]>) -> Value {
    let mut v = json!({ "id": g.id.to_string(), "name": g.name, "members": g.members });
    if let (Some(users), Some(o)) = (users, v.as_object_mut()) {
        let ids: Vec<String> = users.iter().map(ToString::to_string).collect();
        o.insert("user_ids".into(), json!(ids));
    }
    v
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupIn {
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MembersIn {
    user_ids: Vec<String>,
}

async fn group_out(tx: &mut casual_sign_store::TenantTx, id: GroupId) -> Result<Value, ApiError> {
    let g = tx.groups().get(id).await?.ok_or_else(ApiError::not_found)?;
    let users = tx.groups().members(id).await?;
    Ok(group_json(&g, Some(&users)))
}

/// `POST /groups {name}`: `201` with the new, empty group.
pub(crate) async fn create_group(c: Call, body: Bytes) -> Result<Response, ApiError> {
    let req: GroupIn = parse(&body)?;
    let name = name_of(&req.name)?;
    let mut tx = c.tx().await?;
    let id = GroupId(Uuid::now_v7());
    tx.groups().create(id, &name).await.map_err(named)?;
    let v = group_out(&mut tx, id).await?;
    tx.commit().await?;
    Ok(json(StatusCode::CREATED, &v))
}

/// `GET /groups/{id}`: the group with its members' user ids.
pub(crate) async fn group(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let id = GroupId(path_id(&id)?);
    let mut tx = c.tx().await?;
    let v = group_out(&mut tx, id).await?;
    tx.commit().await?;
    Ok(json(StatusCode::OK, &v))
}

/// `PATCH /groups/{id} {name}`: rename it.
pub(crate) async fn patch_group(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let id = GroupId(path_id(&id)?);
    let mut tx = c.tx().await?;
    // Another account's group is 404 whatever the body (docs/07 §Access).
    tx.groups().get(id).await?.ok_or_else(ApiError::not_found)?;
    let req: GroupIn = parse(&body)?;
    let name = name_of(&req.name)?;
    tx.groups().rename(id, &name).await.map_err(named)?;
    let v = group_out(&mut tx, id).await?;
    tx.commit().await?;
    Ok(json(StatusCode::OK, &v))
}

/// `DELETE /groups/{id}`: `204`; its members' places in it and its template shares go
/// with it.
pub(crate) async fn delete_group(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let id = GroupId(path_id(&id)?);
    let mut tx = c.tx().await?;
    tx.groups().delete(id).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `PUT /groups/{id}/members {user_ids}`: the group's members become exactly these
/// members of the account (`422` at `/user_ids/{i}` for anyone else, or a malformed id).
pub(crate) async fn put_members(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let id = GroupId(path_id(&id)?);
    let mut tx = c.tx().await?;
    tx.groups().get(id).await?.ok_or_else(ApiError::not_found)?;
    let req: MembersIn = parse(&body)?;
    let mut users = BTreeSet::new();
    for (i, u) in req.user_ids.iter().enumerate() {
        let bad = || ApiError::invalid(&format!("/user_ids/{i}"));
        let user = UserId(Uuid::parse_str(u).map_err(|_| bad())?);
        if users.contains(&user) {
            continue;
        }
        tx.users().get(user).await?.ok_or_else(bad)?;
        users.insert(user);
    }
    let users: Vec<UserId> = users.into_iter().collect();
    tx.groups().set_members(id, &users).await?;
    let v = group_out(&mut tx, id).await?;
    tx.commit().await?;
    Ok(json(StatusCode::OK, &v))
}

// Permission profiles -------------------------------------------------------------------

/// What a profile grants, as names: its scopes in docs/40 order, then
/// `view_all_envelopes` when it shows every envelope. A built-in profile's are its
/// kind's; a custom profile's are the ones it stores.
fn grants(p: &PermissionProfile) -> Vec<&'static str> {
    let (scopes, _, view_all) = profile_scopes(p.kind, &p.permissions);
    let mut out: Vec<&'static str> = SCOPES
        .iter()
        .copied()
        .filter(|s| scopes.contains(s))
        .collect();
    if view_all {
        out.push(VIEW_ALL);
    }
    out
}

fn profile_json(p: &PermissionProfile, members: i64) -> Value {
    json!({
        "id": p.id.to_string(),
        "name": p.name,
        "kind": p.kind.as_str(),
        "builtin": p.kind != ProfileKind::Custom,
        "permissions": grants(p),
        "members": members,
    })
}

/// Permissions as sent: each a known name (`422` at `/permissions/{i}` otherwise),
/// stored once each in docs/40 order.
fn permissions_of(sent: &[String]) -> Result<Vec<String>, ApiError> {
    for (i, s) in sent.iter().enumerate() {
        if !SCOPES.contains(&s.as_str()) && s != VIEW_ALL {
            return Err(ApiError::invalid(&format!("/permissions/{i}")));
        }
    }
    Ok(SCOPES
        .iter()
        .copied()
        .chain([VIEW_ALL])
        .filter(|k| sent.iter().any(|s| s == k))
        .map(str::to_owned)
        .collect())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileIn {
    name: String,
    permissions: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfilePatch {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    permissions: Option<Vec<String>>,
}

async fn profile_out(
    tx: &mut casual_sign_store::TenantTx,
    id: PermissionProfileId,
) -> Result<Value, ApiError> {
    let (p, n) = tx
        .users()
        .profiles()
        .await?
        .into_iter()
        .find(|(p, _)| p.id == id)
        .ok_or_else(ApiError::not_found)?;
    Ok(profile_json(&p, n))
}

/// `GET /permission-profiles`: the built-in profiles, then the custom ones by name,
/// each with what it grants and how many members hold it.
pub(crate) async fn profiles(c: Call) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let items: Vec<Value> = tx
        .users()
        .profiles()
        .await?
        .iter()
        .map(|(p, n)| profile_json(p, *n))
        .collect();
    tx.commit().await?;
    Ok(json(StatusCode::OK, &json!({ "items": items })))
}

/// `POST /permission-profiles {name, permissions}`: `201` with the new custom profile.
pub(crate) async fn create_profile(c: Call, body: Bytes) -> Result<Response, ApiError> {
    let req: ProfileIn = parse(&body)?;
    let name = name_of(&req.name)?;
    let permissions = permissions_of(&req.permissions)?;
    c.p.may_grant(ProfileKind::Custom, &permissions)?;
    let mut tx = c.tx().await?;
    let id = PermissionProfileId(Uuid::now_v7());
    tx.users()
        .create_profile(&PermissionProfile {
            id,
            name,
            kind: ProfileKind::Custom,
            permissions,
        })
        .await
        .map_err(named)?;
    let v = profile_out(&mut tx, id).await?;
    tx.commit().await?;
    Ok(json(StatusCode::CREATED, &v))
}

/// `GET /permission-profiles/{id}`.
pub(crate) async fn profile(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let id = PermissionProfileId(path_id(&id)?);
    let mut tx = c.tx().await?;
    let v = profile_out(&mut tx, id).await?;
    tx.commit().await?;
    Ok(json(StatusCode::OK, &v))
}

/// The custom profile `id`: `404` for none, `409 CS-WF-0001` for a built-in one, and
/// `403` when it gives more than the caller holds.
async fn custom(
    c: &Call,
    tx: &mut casual_sign_store::TenantTx,
    id: PermissionProfileId,
) -> Result<PermissionProfile, ApiError> {
    let p = tx
        .users()
        .profile(id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    if p.kind != ProfileKind::Custom {
        return Err(ApiError::wrong_state(
            "a built-in profile cannot be changed",
        ));
    }
    c.p.may_grant(p.kind, &p.permissions)?;
    Ok(p)
}

/// `PATCH /permission-profiles/{id} {name?, permissions?}`: change a custom profile.
/// Its members hold the new permissions from their next request.
pub(crate) async fn patch_profile(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let id = PermissionProfileId(path_id(&id)?);
    let mut tx = c.tx().await?;
    let was = custom(&c, &mut tx, id).await?;
    let req: ProfilePatch = parse(&body)?;
    let name = req.name.as_deref().map(name_of).transpose()?;
    let permissions = req.permissions.as_deref().map(permissions_of).transpose()?;
    let permissions = permissions.unwrap_or(was.permissions);
    c.p.may_grant(ProfileKind::Custom, &permissions)?;
    let name = name.unwrap_or(was.name);
    // Sending may take seats (`openseal_holds_seat`): checked under the seat counters'
    // lock, as re-profiling a member is (PLAN-04, `CS-PLAN-0003`).
    let seats = tx.gauge_lock(Meter::Seats).await?;
    tx.users()
        .update_profile(id, &name, &permissions)
        .await
        .map_err(named)?;
    tx.gauge_check(seats, c.st.now(), "profile.change", id.0)
        .await?;
    let v = profile_out(&mut tx, id).await?;
    tx.commit().await?;
    Ok(json(StatusCode::OK, &v))
}

/// `DELETE /permission-profiles/{id}`: `204`; a profile a member holds is `409
/// CS-WF-0001` (move them to another first).
pub(crate) async fn delete_profile(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let id = PermissionProfileId(path_id(&id)?);
    let mut tx = c.tx().await?;
    custom(&c, &mut tx, id).await?;
    let held = tx
        .users()
        .profiles()
        .await?
        .iter()
        .any(|(p, n)| p.id == id && *n > 0);
    if held {
        return Err(ApiError::wrong_state("members hold this profile"));
    }
    tx.users().delete_profile(id).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
// Tests may unwrap (CLAUDE.md).
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn permissions_are_known_names_stored_once_in_docs_40_order() {
        let sent = vec![
            "view_all_envelopes".to_owned(),
            "templates:read".to_owned(),
            "envelopes:read".to_owned(),
            "templates:read".to_owned(),
        ];
        assert_eq!(
            permissions_of(&sent).unwrap(),
            ["envelopes:read", "templates:read", "view_all_envelopes"]
        );
        let bad = vec!["envelopes:read".to_owned(), "root".to_owned()];
        assert_eq!(permissions_of(&bad).unwrap_err().code(), "CS-API-0001");
    }
}
