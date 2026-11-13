//! `/organizations/me` (ORG-03, ADR-028, docs/23 §2.2, §6): the caller's organization,
//! its workspaces (create, archive, join), its owners and admins, and its admin log.
//!
//! **The organization comes from the session's workspace**, never from the request
//! (docs/23 §2.3), and the caller's role is read afresh from `organization_admins` on
//! every request (`SEC-O06`): no role, or an action the role does not hold, is
//! `403 CS-AUTH-0006`. Only a staff session reaches these routes; API keys and OAuth
//! clients are per workspace and get organization scopes later (`org:*`, §6).
//!
//! An organization role confers no access to content (`SEC-O07`): every read here is
//! organization metadata, and the one way to agreements is `…/join`, which makes the
//! caller a visible member of that workspace, in its admin log and its organization's.
//! Every change appends its organization event through `OrgTx::admin_event` in the same
//! transaction (ORG-05). Another organization's workspace or admin answers
//! `404 CS-API-0002`, as a missing one does.

use axum::body::Bytes;
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::response::Response;
use casual_sign_store::{
    AccountId, OrgTx, OrganizationAdmin, OrganizationRole, StoreError, UserId, Workspace,
    WorkspaceStatus,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::admin::{AdminEventsQuery, admin_log_response, new_profiles, profile_id};
use super::envelopes::rfc3339;
use super::{json, path_id};
use crate::auth::Credential;
use crate::call::Call;
use crate::dto::parse;
use crate::error::ApiError;

/// The organization actions these routes need (docs/23 §2.2's catalogue).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OrgAction {
    /// Read the organization, its workspaces and its admins (metadata only).
    Read,
    /// `org.settings.update`.
    SettingsUpdate,
    /// `org.admins.manage`: owners and admins (owner only).
    AdminsManage,
    /// `org.workspaces.create`.
    WorkspacesCreate,
    /// `org.workspaces.archive`.
    WorkspacesArchive,
    /// `org.workspaces.join`: owners and admins, never delegated.
    WorkspacesJoin,
    /// `org.audit.read`.
    AuditRead,
}

impl OrgAction {
    /// The catalogue name, as a delegated admin's permission set names it.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Read => "org.read",
            Self::SettingsUpdate => "org.settings.update",
            Self::AdminsManage => "org.admins.manage",
            Self::WorkspacesCreate => "org.workspaces.create",
            Self::WorkspacesArchive => "org.workspaces.archive",
            Self::WorkspacesJoin => "org.workspaces.join",
            Self::AuditRead => "org.audit.read",
        }
    }
}

/// Whether `admin` holds `action`, on `workspace` when the action is about one
/// (docs/23 §2.2's table): an owner every action; an admin all but managing owners and
/// admins; a delegated admin what its set names, within its workspace scope, and never
/// a join or an admin change.
pub(crate) fn holds(
    admin: &OrganizationAdmin,
    action: OrgAction,
    workspace: Option<AccountId>,
) -> bool {
    match admin.role {
        OrganizationRole::Owner => true,
        OrganizationRole::Admin => action != OrgAction::AdminsManage,
        OrganizationRole::Delegated => {
            if matches!(action, OrgAction::WorkspacesJoin | OrgAction::AdminsManage) {
                return false;
            }
            if action == OrgAction::Read {
                return true;
            }
            let named = admin.permissions.iter().any(|p| p == action.as_str());
            let in_scope = match (&admin.workspace_scope, workspace) {
                (Some(scope), Some(w)) => scope.contains(&w),
                _ => true,
            };
            named && in_scope
        }
        // A role this build does not know holds nothing (deny by default).
        _ => false,
    }
}

/// The caller's organization transaction and role, after checking it holds `action`
/// (`None` workspace: the action is not about one; checked again by the handler with
/// the workspace once it is found).
async fn begin(c: &Call, action: OrgAction) -> Result<(OrgTx, OrganizationAdmin), ApiError> {
    if !matches!(c.p.credential, Credential::Session(_)) {
        return Err(ApiError::forbidden("a staff session"));
    }
    let mut ws = c.tx().await?;
    let org = ws.account().get().await?.organization_id;
    ws.rollback().await?;
    let mut tx = c.st.store().for_organization(org).begin().await?;
    tx.act_as(c.actor());
    let admin = tx
        .admin(c.p.user)
        .await?
        .ok_or_else(|| ApiError::forbidden(action.as_str()))?;
    if !holds(&admin, action, None) && !scoped(action) {
        return Err(ApiError::forbidden(action.as_str()));
    }
    Ok((tx, admin))
}

/// Actions a delegated admin may hold for some workspaces only: checked per workspace.
fn scoped(action: OrgAction) -> bool {
    action == OrgAction::WorkspacesArchive
}

/// Commit, serving the last-owner refusal as `CS-ORG-0008`.
async fn commit(tx: OrgTx) -> Result<(), ApiError> {
    tx.commit().await.map_err(|e| {
        if e.is_last_owner() {
            ApiError::last_owner()
        } else {
            e.into()
        }
    })
}

fn workspace_json(w: &Workspace) -> Value {
    json!({ "id": w.id.to_string(), "name": w.name, "status": w.status.as_str() })
}

fn admin_json(a: &OrganizationAdmin) -> Value {
    json!({
        "user_id": a.user_id.to_string(),
        "role": a.role.as_str(),
        "permission_set_id": a.permission_set_id.map(|p| p.to_string()),
        "workspace_scope": a.workspace_scope.as_ref()
            .map(|s| s.iter().map(ToString::to_string).collect::<Vec<_>>()),
        "created_at": rfc3339(a.created_at),
    })
}

fn name_of(name: &str) -> Result<String, ApiError> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > 255 {
        return Err(ApiError::invalid("/name"));
    }
    Ok(n.to_owned())
}

// The organization ------------------------------------------------------------------------

/// `GET /organizations/me`: the caller's organization and their role in it.
pub(crate) async fn organization(c: Call) -> Result<Response, ApiError> {
    let (mut tx, admin) = begin(&c, OrgAction::Read).await?;
    let o = tx.organization().await?;
    tx.commit().await?;
    Ok(json(
        StatusCode::OK,
        &json!({
            "id": o.id.to_string(), "name": o.name, "status": o.status.as_str(),
            "role": admin.role.as_str(), "created_at": rfc3339(o.created_at),
        }),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OrgPatch {
    name: String,
}

/// `PATCH /organizations/me {name}` (`org.settings.update`). Policy is ORG-08's.
pub(crate) async fn patch_organization(c: Call, body: Bytes) -> Result<Response, ApiError> {
    let (mut tx, _) = begin(&c, OrgAction::SettingsUpdate).await?;
    let req: OrgPatch = parse(&body)?;
    let name = name_of(&req.name)?;
    tx.rename(&name).await?;
    let o = tx.organization().await?;
    commit(tx).await?;
    Ok(json(
        StatusCode::OK,
        &json!({ "id": o.id.to_string(), "name": o.name, "status": o.status.as_str() }),
    ))
}

// Workspaces ------------------------------------------------------------------------------

/// `GET /organizations/me/workspaces`.
pub(crate) async fn workspaces(c: Call) -> Result<Response, ApiError> {
    let (mut tx, _) = begin(&c, OrgAction::Read).await?;
    let items: Vec<Value> = tx.workspaces().await?.iter().map(workspace_json).collect();
    tx.commit().await?;
    Ok(json(StatusCode::OK, &json!({ "items": items })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceIn {
    name: String,
}

/// `POST /organizations/me/workspaces {name}` (`org.workspaces.create`): a workspace
/// with its built-in profiles and no member; the creator joins it with `…/join`.
pub(crate) async fn create_workspace(c: Call, body: Bytes) -> Result<Response, ApiError> {
    let (mut tx, _) = begin(&c, OrgAction::WorkspacesCreate).await?;
    let req: WorkspaceIn = parse(&body)?;
    let name = name_of(&req.name)?;
    let id = AccountId(Uuid::now_v7());
    tx.create_workspace(id, &name, &new_profiles()).await?;
    let w = tx
        .workspace_row(id)
        .await?
        .ok_or_else(|| ApiError::internal("workspace"))?;
    commit(tx).await?;
    Ok(json(StatusCode::CREATED, &workspace_json(&w)))
}

/// The workspace `id` of the caller's organization, or 404.
async fn find(tx: &mut OrgTx, id: &str) -> Result<Workspace, ApiError> {
    let id = AccountId(path_id(id)?);
    tx.workspace_row(id).await?.ok_or_else(ApiError::not_found)
}

/// `GET /organizations/me/workspaces/{id}`: metadata only.
pub(crate) async fn workspace(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let (mut tx, _) = begin(&c, OrgAction::Read).await?;
    let w = find(&mut tx, &id).await?;
    tx.commit().await?;
    Ok(json(StatusCode::OK, &workspace_json(&w)))
}

/// `POST /organizations/me/workspaces/{id}/archive` (`org.workspaces.archive`,
/// idempotent).
pub(crate) async fn archive_workspace(
    c: Call,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let (mut tx, admin) = begin(&c, OrgAction::WorkspacesArchive).await?;
    let w = find(&mut tx, &id).await?;
    if !holds(&admin, OrgAction::WorkspacesArchive, Some(w.id)) {
        return Err(ApiError::forbidden(OrgAction::WorkspacesArchive.as_str()));
    }
    let proof = tx.workspace(w.id).await?.ok_or_else(ApiError::not_found)?;
    tx.archive_workspace(&proof).await?;
    let w = tx
        .workspace_row(w.id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    commit(tx).await?;
    Ok(json(StatusCode::OK, &workspace_json(&w)))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JoinIn {
    /// `admin`, `sender`, `viewer` or a profile id of that workspace.
    profile: String,
}

/// `POST /organizations/me/workspaces/{id}/join {profile}` (`org.workspaces.join`,
/// owners and admins only): the caller becomes a member of that workspace. One
/// transaction writes the membership, `member.added` (`via: organization`) in the
/// workspace's log and `org.workspace_joined` in the organization's (`SEC-O07`).
pub(crate) async fn join_workspace(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (mut tx, _) = begin(&c, OrgAction::WorkspacesJoin).await?;
    let w = find(&mut tx, &id).await?;
    let req: JoinIn = parse(&body)?;
    if w.status == WorkspaceStatus::Archived {
        return Err(ApiError::workspace_archived());
    }
    let email = tx
        .member_email(c.p.user)
        .await?
        .ok_or_else(|| ApiError::forbidden(OrgAction::WorkspacesJoin.as_str()))?;
    let proof = tx.workspace(w.id).await?.ok_or_else(ApiError::not_found)?;
    let mut ws = tx.into_workspace(&proof).await?;
    let profile = profile_id(&mut ws, &req.profile).await?;
    ws.users()
        .join_from_organization(c.p.user, &email, profile)
        .await?;
    ws.commit().await?;
    Ok(json(
        StatusCode::CREATED,
        &json!({
            "workspace_id": w.id.to_string(), "user_id": c.p.user.to_string(),
            "permission_profile_id": profile.to_string(),
        }),
    ))
}

// Owners and admins -----------------------------------------------------------------------

/// `GET /organizations/me/admins`.
pub(crate) async fn admins(c: Call) -> Result<Response, ApiError> {
    let (mut tx, _) = begin(&c, OrgAction::Read).await?;
    let items: Vec<Value> = tx.admins().await?.iter().map(admin_json).collect();
    tx.commit().await?;
    Ok(json(StatusCode::OK, &json!({ "items": items })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminIn {
    user_id: String,
    role: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminPatch {
    role: String,
}

/// `owner` or `admin`; a delegated admin needs a permission set (ORG-07).
fn role_of(s: &str) -> Result<OrganizationRole, ApiError> {
    match s {
        "owner" => Ok(OrganizationRole::Owner),
        "admin" => Ok(OrganizationRole::Admin),
        _ => Err(ApiError::invalid("/role")),
    }
}

/// `POST /organizations/me/admins {user_id, role}` (`org.admins.manage`, owner only).
/// The user must be an enabled member of a workspace of this organization
/// (`CS-ORG-0018`, the same for an id the organization cannot see); never oneself
/// (`CS-ORG-0005`).
pub(crate) async fn add_admin(c: Call, body: Bytes) -> Result<Response, ApiError> {
    let (mut tx, _) = begin(&c, OrgAction::AdminsManage).await?;
    let req: AdminIn = parse(&body)?;
    let role = role_of(&req.role)?;
    let user = UserId(Uuid::parse_str(&req.user_id).map_err(|_| ApiError::invalid("/user_id"))?);
    if user == c.p.user {
        return Err(ApiError::grant_refused());
    }
    if tx.member_email(user).await?.is_none() {
        return Err(ApiError::not_an_org_member());
    }
    tx.add_admin(user, role, c.st.now()).await?;
    let a = tx
        .admin(user)
        .await?
        .ok_or_else(|| ApiError::internal("admin"))?;
    commit(tx).await?;
    Ok(json(StatusCode::CREATED, &admin_json(&a)))
}

fn admin_path(user: &str) -> Result<UserId, ApiError> {
    Ok(UserId(path_id(user)?))
}

/// `PATCH /organizations/me/admins/{user} {role}` (owner only; never one's own role).
pub(crate) async fn patch_admin(
    c: Call,
    Path(user): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (mut tx, _) = begin(&c, OrgAction::AdminsManage).await?;
    let user = admin_path(&user)?;
    tx.admin(user).await?.ok_or_else(ApiError::not_found)?;
    let req: AdminPatch = parse(&body)?;
    let role = role_of(&req.role)?;
    if user == c.p.user {
        return Err(ApiError::grant_refused());
    }
    tx.set_admin_role(user, role).await?;
    let a = tx.admin(user).await?.ok_or_else(ApiError::not_found)?;
    commit(tx).await?;
    Ok(json(StatusCode::OK, &admin_json(&a)))
}

/// `DELETE /organizations/me/admins/{user}` (owner only). An owner may resign; the
/// last enabled owner may not (`CS-ORG-0008`).
pub(crate) async fn remove_admin(c: Call, Path(user): Path<String>) -> Result<Response, ApiError> {
    let (mut tx, _) = begin(&c, OrgAction::AdminsManage).await?;
    let user = admin_path(&user)?;
    match tx.remove_admin(user).await {
        Err(StoreError::NotFound { .. }) => return Err(ApiError::not_found()),
        r => r?,
    }
    commit(tx).await?;
    Ok(json(
        StatusCode::OK,
        &json!({ "user_id": user.to_string() }),
    ))
}

// Admin log -------------------------------------------------------------------------------

/// `GET /organizations/me/audit?cursor&limit&format=json|csv&verify=page|full`
/// (`org.audit.read`): the organization's admin log, each page verified as it is read
/// (a broken link is `500 CS-DB-0014`), `verify=full` re-verifying the whole log first,
/// as `GET /admin-events`.
pub(crate) async fn audit(
    c: Call,
    Query(q): Query<AdminEventsQuery>,
) -> Result<Response, ApiError> {
    let (limit, csv, full) = q.read()?;
    let (mut tx, _) = begin(&c, OrgAction::AuditRead).await?;
    if full {
        tx.verified_admin_log().await?;
    }
    let page = tx.verified_admin_events(q.cursor(), limit).await?;
    tx.commit().await?;
    Ok(admin_log_response(&page, limit, csv))
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    fn admin(
        role: OrganizationRole,
        perms: &[&str],
        scope: Option<Vec<AccountId>>,
    ) -> OrganizationAdmin {
        OrganizationAdmin {
            user_id: UserId(Uuid::nil()),
            role,
            permission_set_id: None,
            permissions: perms.iter().map(|p| (*p).to_owned()).collect(),
            workspace_scope: scope,
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn only_owners_manage_admins_and_delegated_admins_never_join() {
        let all = [
            OrgAction::Read,
            OrgAction::SettingsUpdate,
            OrgAction::AdminsManage,
            OrgAction::WorkspacesCreate,
            OrgAction::WorkspacesArchive,
            OrgAction::WorkspacesJoin,
            OrgAction::AuditRead,
        ];
        let owner = admin(OrganizationRole::Owner, &[], None);
        let adm = admin(OrganizationRole::Admin, &[], None);
        let every: Vec<&str> = all.iter().map(|a| a.as_str()).collect();
        let delegated = admin(OrganizationRole::Delegated, &every, None);
        for a in all {
            assert!(holds(&owner, a, None), "{a:?}");
            assert_eq!(holds(&adm, a, None), a != OrgAction::AdminsManage, "{a:?}");
            assert_eq!(
                holds(&delegated, a, None),
                !matches!(a, OrgAction::AdminsManage | OrgAction::WorkspacesJoin),
                "{a:?}"
            );
        }
    }

    #[test]
    fn a_delegated_admin_archives_only_named_actions_within_its_scope() {
        let w = AccountId(Uuid::from_u128(1));
        let other = AccountId(Uuid::from_u128(2));
        let d = admin(
            OrganizationRole::Delegated,
            &["org.workspaces.archive"],
            Some(vec![w]),
        );
        assert!(holds(&d, OrgAction::WorkspacesArchive, Some(w)));
        assert!(!holds(&d, OrgAction::WorkspacesArchive, Some(other)));
        assert!(!holds(&d, OrgAction::WorkspacesCreate, None));
    }
}
