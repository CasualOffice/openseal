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
//! than they hold (`authz::grantable`, ORG-07, `403 CS-ORG-0005`): a profile beyond the
//! caller's own rights or group scope, or the profile the caller holds, cannot be made,
//! changed, deleted or assigned by them.
//!
//! A custom profile names scopes, `view_all_envelopes`, or workspace actions of the
//! catalogue (`authz::Action`), and may carry a group scope (`admin_scope_group_ids`,
//! ORG-07): a delegated workspace admin. A group-scoped caller sees and changes only its
//! scope groups, sets their members only to members it administers, creates no group,
//! and sees only profiles whose actions it holds. A profile a member holds cannot
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

use super::admin::{administered, stored_grant};
use super::{json, path_id};
use crate::auth::{SCOPES, VIEW_ALL, profile_grant, profile_scopes};
use crate::authz::{self, Action, Refusal};
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

/// `404` for a group outside a group-scoped caller's scope (ORG-07).
fn group_in_scope(c: &Call, id: GroupId) -> Result<(), ApiError> {
    match &c.p.admin_scope {
        Some(s) if !s.contains(&id) => Err(ApiError::not_found()),
        _ => Ok(()),
    }
}

/// `POST /groups {name}`: `201` with the new, empty group. A group-scoped caller makes
/// none (it would be outside its scope): `403 CS-ORG-0005`.
pub(crate) async fn create_group(c: Call, body: Bytes) -> Result<Response, ApiError> {
    if c.p.admin_scope.is_some() {
        return Err(ApiError::grant_refused(Refusal::Scope.what()));
    }
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
    group_in_scope(&c, id)?;
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
    group_in_scope(&c, id)?;
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
    group_in_scope(&c, id)?;
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
    group_in_scope(&c, id)?;
    let mut tx = c.tx().await?;
    tx.groups().get(id).await?.ok_or_else(ApiError::not_found)?;
    let req: MembersIn = parse(&body)?;
    // A group-scoped caller names only members it already administers, so it cannot
    // pull anyone into its scope (ORG-07).
    let mine = administered(&c, &mut tx).await?;
    let mut users = BTreeSet::new();
    for (i, u) in req.user_ids.iter().enumerate() {
        let bad = || ApiError::invalid(&format!("/user_ids/{i}"));
        let user = UserId(Uuid::parse_str(u).map_err(|_| bad())?);
        if users.contains(&user) {
            continue;
        }
        tx.users().get(user).await?.ok_or_else(bad)?;
        if mine.as_ref().is_some_and(|m| !m.contains(&user)) {
            return Err(bad());
        }
        users.insert(user);
    }
    let users: Vec<UserId> = users.into_iter().collect();
    tx.groups().set_members(id, &users).await?;
    let v = group_out(&mut tx, id).await?;
    tx.commit().await?;
    Ok(json(StatusCode::OK, &v))
}

// Permission profiles -------------------------------------------------------------------

/// What a profile grants, as names: a built-in profile its kind's scopes in docs/40
/// order, then `view_all_envelopes` when it shows every envelope; a custom profile the
/// names it stores.
fn grants(p: &PermissionProfile) -> Vec<String> {
    if p.kind == ProfileKind::Custom {
        return p.permissions.clone();
    }
    let (scopes, _, view_all) = profile_scopes(p.kind, &p.permissions);
    let mut out: Vec<String> = SCOPES
        .iter()
        .filter(|s| scopes.contains(*s))
        .map(|s| (*s).to_owned())
        .collect();
    if view_all {
        out.push(VIEW_ALL.to_owned());
    }
    out
}

/// The profile as the API shows it: also the workspace actions it holds (ORG-07) and
/// its group scope.
fn profile_json(p: &PermissionProfile, members: i64, scope: Option<&[GroupId]>) -> Value {
    let actions: Vec<&str> = authz::profile_actions(p.kind, &p.permissions)
        .into_iter()
        .map(Action::as_str)
        .collect();
    let scope: Option<Vec<String>> = scope.map(|s| s.iter().map(ToString::to_string).collect());
    json!({
        "id": p.id.to_string(),
        "name": p.name,
        "kind": p.kind.as_str(),
        "builtin": p.kind != ProfileKind::Custom,
        "permissions": grants(p),
        "actions": actions,
        "admin_scope_group_ids": scope,
        "members": members,
    })
}

/// Permissions as sent: each a known name, a scope of docs/40 §2,
/// `view_all_envelopes` or a workspace action of the catalogue (`422` at
/// `/permissions/{i}` otherwise), stored once each: scopes in docs/40 order, then
/// `view_all_envelopes`, then actions in catalogue order.
fn permissions_of(sent: &[String]) -> Result<Vec<String>, ApiError> {
    for (i, s) in sent.iter().enumerate() {
        if !SCOPES.contains(&s.as_str()) && s != VIEW_ALL && Action::parse(s).is_none() {
            return Err(ApiError::invalid(&format!("/permissions/{i}")));
        }
    }
    Ok(SCOPES
        .iter()
        .copied()
        .chain([VIEW_ALL])
        .chain(Action::ALL.iter().map(|a| a.as_str()))
        .filter(|k| sent.iter().any(|s| s == k))
        .map(str::to_owned)
        .collect())
}

/// A group scope as sent: each this account's group (`422` at
/// `/admin_scope_group_ids/{i}` otherwise), once each, at least one.
async fn scope_of(
    tx: &mut casual_sign_store::TenantTx,
    sent: &[String],
) -> Result<Vec<GroupId>, ApiError> {
    if sent.is_empty() {
        return Err(ApiError::invalid("/admin_scope_group_ids"));
    }
    let mut out = BTreeSet::new();
    for (i, g) in sent.iter().enumerate() {
        let bad = || ApiError::invalid(&format!("/admin_scope_group_ids/{i}"));
        let id = GroupId(Uuid::parse_str(g).map_err(|_| bad())?);
        tx.groups().get(id).await?.ok_or_else(bad)?;
        out.insert(id);
    }
    Ok(out.into_iter().collect())
}

/// A field that may be absent (`None`), `null` (`Some(None)`) or a value.
fn present<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d).map(Some)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileIn {
    name: String,
    permissions: Vec<String>,
    /// A delegated workspace admin's groups (ORG-07); absent or `null`: the whole
    /// workspace.
    #[serde(default)]
    admin_scope_group_ids: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfilePatch {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    permissions: Option<Vec<String>>,
    /// Absent: unchanged; `null`: the whole workspace; a list: those groups (ORG-07).
    #[serde(default, deserialize_with = "present")]
    admin_scope_group_ids: Option<Option<Vec<String>>>,
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
    let scope = tx.users().profile_scope(id).await?;
    Ok(profile_json(&p, n, scope.as_deref()))
}

/// Whether the caller may see profile `p`: always, but a group-scoped caller only a
/// profile whose actions it holds (docs/23 §2.2).
fn visible(c: &Call, p: &PermissionProfile) -> bool {
    c.p.admin_scope.is_none()
        || (p.kind != ProfileKind::Admin
            && authz::profile_actions(p.kind, &p.permissions).is_subset(&c.p.actions))
}

/// `GET /permission-profiles`: the built-in profiles, then the custom ones by name,
/// each with what it grants and how many members hold it (a group-scoped caller's
/// visible ones only).
pub(crate) async fn profiles(c: Call) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let mut items: Vec<Value> = Vec::new();
    for (p, n) in tx.users().profiles().await? {
        if visible(&c, &p) {
            let scope = tx.users().profile_scope(p.id).await?;
            items.push(profile_json(&p, n, scope.as_deref()));
        }
    }
    tx.commit().await?;
    Ok(json(StatusCode::OK, &json!({ "items": items })))
}

/// `POST /permission-profiles {name, permissions}`: `201` with the new custom profile.
pub(crate) async fn create_profile(c: Call, body: Bytes) -> Result<Response, ApiError> {
    let req: ProfileIn = parse(&body)?;
    let name = name_of(&req.name)?;
    let permissions = permissions_of(&req.permissions)?;
    let mut tx = c.tx().await?;
    let scope = match &req.admin_scope_group_ids {
        Some(s) => Some(scope_of(&mut tx, s).await?),
        None => None,
    };
    let org = super::org::admin_of(&c.st, &c.p).await?;
    c.p.may_grant(
        org.as_ref(),
        &profile_grant(ProfileKind::Custom, &permissions, scope.as_deref()),
    )?;
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
    if let Some(scope) = &scope {
        tx.users().set_profile_scope(id, Some(scope)).await?;
    }
    let v = profile_out(&mut tx, id).await?;
    tx.commit().await?;
    Ok(json(StatusCode::CREATED, &v))
}

/// `GET /permission-profiles/{id}`.
pub(crate) async fn profile(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let id = PermissionProfileId(path_id(&id)?);
    let mut tx = c.tx().await?;
    let p = tx
        .users()
        .profile(id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    if !visible(&c, &p) {
        return Err(ApiError::not_found());
    }
    let v = profile_out(&mut tx, id).await?;
    tx.commit().await?;
    Ok(json(StatusCode::OK, &v))
}

/// The custom profile `id`: `404` for none (or one the caller may not see),
/// `409 CS-WF-0001` for a built-in one, and `403 CS-ORG-0005` when it gives more than
/// the caller holds or is the caller's own.
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
    if !visible(c, &p) {
        return Err(ApiError::not_found());
    }
    if p.kind != ProfileKind::Custom {
        return Err(ApiError::wrong_state(
            "a built-in profile cannot be changed",
        ));
    }
    let mut grant = stored_grant(tx, &p).await?;
    grant.profile = Some(id);
    let org = super::org::admin_of(&c.st, &c.p).await?;
    c.p.may_grant(org.as_ref(), &grant)?;
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
    let scope = match &req.admin_scope_group_ids {
        Some(Some(s)) => Some(scope_of(&mut tx, s).await?),
        Some(None) => None,
        None => tx.users().profile_scope(id).await?,
    };
    let mut grant = profile_grant(ProfileKind::Custom, &permissions, scope.as_deref());
    grant.profile = Some(id);
    let org = super::org::admin_of(&c.st, &c.p).await?;
    c.p.may_grant(org.as_ref(), &grant)?;
    let name = name.unwrap_or(was.name);
    // Sending may take seats (`openseal_holds_seat`): checked under the seat counters'
    // lock, as re-profiling a member is (PLAN-04, `CS-PLAN-0003`).
    let seats = tx.gauge_lock(Meter::Seats).await?;
    // The scope first when it narrows to the whole workspace, last when it is set: the
    // database refuses a scoped profile holding a sensitive action at every step.
    if scope.is_none() {
        tx.users().set_profile_scope(id, None).await?;
    }
    tx.users()
        .update_profile(id, &name, &permissions)
        .await
        .map_err(named)?;
    if let Some(scope) = &scope {
        tx.users().set_profile_scope(id, Some(scope)).await?;
    }
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
