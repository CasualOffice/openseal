//! Organization scope (ORG-02, ADR-028, docs/23 §2.1): the level above accounts.
//!
//! **[`Store::for_organization`] → [`OrgScope::begin`] → an [`OrgTx`]** mirrors the account
//! door. The transaction sets `openseal.organization_id` and never `openseal.account_id`,
//! so `openseal_current_account()` is NULL in it and every content table (envelopes,
//! documents, field values, audit events, …) returns no row. Organization scope reads
//! its own workspaces, their memberships and their users through `FOR SELECT` policies
//! only; it writes to a workspace only through [`Store::for_workspace_of`], an ordinary
//! single-account [`TenantTx`], with a [`WorkspaceOf`] proof that the workspace belongs to
//! the organization. RLS never sees two accounts, or an account and an organization, in
//! one transaction.

use sqlx::{Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use casual_sign_audit::Personal;

use crate::admin_log::{
    AdminActor, AdminChange, Change, Owner, StoredAdminEvent, append_error, seal, stored,
    verify_admin_chain,
};
use crate::error::{Result, StoreError, db};
use crate::ids::{AccountId, OrganizationId, PermissionProfileId, UserId};
use crate::repo::text_enum;
use crate::store::{Store, TenantTx};

text_enum!(
    /// An organization's status (docs/23 §5.3); set by the platform console only.
    OrganizationStatus {
        /// In use.
        Active = "active",
        /// Suspended by the platform: new work refused, sent envelopes continue.
        Suspended = "suspended",
        /// Closed: read-only.
        Closed = "closed",
    }
);

text_enum!(
    /// A workspace's status.
    WorkspaceStatus {
        /// In use.
        Active = "active",
        /// Archived: no new envelopes, members or settings (`CS-ORG-0010`).
        Archived = "archived",
    }
);

text_enum!(
    /// A role in an organization (docs/23 §2.2).
    OrganizationRole {
        /// Every organization action, including managing owners and admins.
        Owner = "owner",
        /// Every organization action but managing owners and admins and the owner-only
        /// configuration.
        Admin = "admin",
        /// Exactly the actions its permission set names, within its workspace scope;
        /// never joins a workspace.
        Delegated = "delegated",
    }
);

/// One administrator of an organization, with the actions its permission set names
/// (delegated admins only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrganizationAdmin {
    /// The user.
    pub user_id: UserId,
    /// Their role.
    pub role: OrganizationRole,
    /// A delegated admin's permission set.
    pub permission_set_id: Option<Uuid>,
    /// The actions of that set (empty for owners and admins).
    pub permissions: Vec<String>,
    /// A delegated admin's workspaces; `None` for every workspace of the organization.
    pub workspace_scope: Option<Vec<AccountId>>,
    /// Since.
    pub created_at: OffsetDateTime,
}

/// An organization's own row.
#[derive(Debug, Clone, PartialEq)]
pub struct Organization {
    /// Its id.
    pub id: OrganizationId,
    /// Its display name.
    pub name: String,
    /// Its status.
    pub status: OrganizationStatus,
    /// Its policy (docs/23 §3).
    pub policy: serde_json::Value,
    /// Created.
    pub created_at: OffsetDateTime,
}

/// A workspace (account) as its organization sees it: metadata only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workspace {
    /// The account.
    pub id: AccountId,
    /// Its display name.
    pub name: String,
    /// Active or archived.
    pub status: WorkspaceStatus,
}

/// The ids of a new workspace's three built-in permission profiles (administrator,
/// sender, viewer), minted by the host: the database takes no randomness of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltinProfiles {
    /// "Administrator", kind `admin`.
    pub admin: PermissionProfileId,
    /// "Sender", kind `sender`.
    pub sender: PermissionProfileId,
    /// "Viewer", kind `viewer`.
    pub viewer: PermissionProfileId,
}

/// Proof, read in an organization transaction, that a workspace belonged to that
/// organization. Only [`OrgTx::workspace`] and [`OrgTx::create_workspace`] make one.
/// [`Store::for_workspace_of`] checks it again in its own transaction, so a proof taken
/// before the workspace was re-linked (ORG-20, the only path that changes a workspace's
/// organization) is useless after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkspaceOf {
    organization: OrganizationId,
    account: AccountId,
}

impl WorkspaceOf {
    /// The organization.
    #[must_use]
    pub fn organization_id(&self) -> OrganizationId {
        self.organization
    }

    /// The workspace.
    #[must_use]
    pub fn account_id(&self) -> AccountId {
        self.account
    }
}

/// The scope of one organization. Obtain with [`Store::for_organization`].
#[derive(Debug, Clone, Copy)]
pub struct OrgScope<'s> {
    store: &'s Store,
    org: OrganizationId,
}

impl OrgScope<'_> {
    /// The organization.
    #[must_use]
    pub fn organization_id(&self) -> OrganizationId {
        self.org
    }

    /// Begin a transaction scoped to this organization.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001` when no connection is available.
    pub async fn begin(&self) -> Result<OrgTx> {
        let mut tx = self.store.pool().begin().await.map_err(db)?;
        sqlx::query!(
            "SELECT set_config('openseal.organization_id', $1, true)",
            self.org.0.to_string()
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
        Ok(OrgTx {
            tx,
            org: self.org,
            actor: None,
        })
    }
}

/// A database transaction bound to one organization. Dropping it without
/// [`OrgTx::commit`] rolls back.
#[derive(Debug)]
pub struct OrgTx {
    tx: Transaction<'static, Postgres>,
    org: OrganizationId,
    actor: Option<AdminActor>,
}

impl OrgTx {
    /// The organization every statement in this transaction is bound to.
    #[must_use]
    pub fn organization_id(&self) -> OrganizationId {
        self.org
    }

    fn org(&self) -> Uuid {
        self.org.0
    }

    /// Who acts in this transaction: every admin event it appends records them, and
    /// [`OrgTx::into_workspace`] carries them on. Without it, events record the server
    /// itself.
    pub fn act_as(&mut self, actor: AdminActor) {
        self.actor = Some(actor);
    }

    fn actor(&self) -> AdminActor {
        self.actor
            .clone()
            .unwrap_or_else(|| AdminActor::system(OffsetDateTime::now_utc()))
    }

    /// The next event of this organization's log for `change`, its head locked.
    async fn next_event(&mut self, change: &AdminChange) -> Result<crate::admin_log::Sealed> {
        let tip =
            sqlx::query!(r#"SELECT next_seq AS "next_seq!", head FROM openseal_admin_chain_tip()"#)
                .fetch_one(&mut *self.tx)
                .await
                .map_err(db)?;
        let actor = self.actor();
        seal(
            Owner::Organization(self.org),
            tip.next_seq,
            tip.head,
            &actor,
            change,
        )
    }

    /// Append `change` to this organization's admin log: every organization change
    /// below writes its event through here, in its own transaction.
    pub(crate) async fn admin_event(&mut self, change: AdminChange) -> Result<()> {
        let e = self.next_event(&change).await?;
        let org = self.org();
        sqlx::query!(
            "INSERT INTO org_admin_events (organization_id, seq, prev_hash, hash, action, at, \
             canonical) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            org,
            e.seq,
            e.prev,
            e.hash,
            e.action,
            e.at,
            e.canonical
        )
        .execute(&mut *self.tx)
        .await
        .map_err(append_error(e.seq))?;
        Ok(())
    }

    /// This organization's admin log, from `after` (exclusive; `None` from the start), at
    /// most `limit` events (1 to [`crate::ADMIN_EVENTS_MAX_PAGE`]), as stored, unverified.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn admin_events(
        &mut self,
        after: Option<u64>,
        limit: i64,
    ) -> Result<Vec<StoredAdminEvent>> {
        let from = after.map_or(Ok(-1), i64::try_from).unwrap_or(i64::MAX);
        self.admin_rows(from, limit.clamp(1, crate::admin_log::MAX_PAGE))
            .await
    }

    async fn admin_rows(&mut self, from: i64, limit: i64) -> Result<Vec<StoredAdminEvent>> {
        let org = self.org();
        let rows = sqlx::query!(
            "SELECT seq, prev_hash, hash, action, at, canonical FROM org_admin_events \
             WHERE organization_id = $1 AND seq > $2 ORDER BY seq LIMIT $3",
            org,
            from,
            limit
        )
        .fetch_all(&mut *self.tx)
        .await
        .map_err(db)?;
        rows.into_iter()
            .map(|r| stored(r.seq, r.prev_hash, r.hash, r.action, r.at, r.canonical))
            .collect()
    }

    async fn admin_head(&mut self) -> Result<Option<Vec<u8>>> {
        let org = self.org();
        sqlx::query_scalar!(
            "SELECT admin_chain_head FROM organizations WHERE id = $1",
            org
        )
        .fetch_one(&mut *self.tx)
        .await
        .map_err(db)
    }

    /// One page of this organization's admin log, verified as it is read, as
    /// [`crate::TenantTx::verified_admin_events`].
    ///
    /// # Errors
    ///
    /// `CS-DB-0014` naming the first event that does not verify; `CS-DB-0010` for an
    /// unreadable row.
    pub async fn verified_admin_events(
        &mut self,
        after: Option<u64>,
        limit: i64,
    ) -> Result<Vec<StoredAdminEvent>> {
        let Some((from, rows)) = crate::admin_log::page_bounds(after, limit) else {
            return Ok(Vec::new());
        };
        let page = self.admin_rows(from, rows).await?;
        let head = self.admin_head().await?;
        let limit =
            usize::try_from(limit.clamp(1, crate::admin_log::MAX_PAGE)).unwrap_or(usize::MAX);
        crate::admin_log::verify_page(after, page, limit, head.as_deref())
    }

    /// This organization's whole admin log, re-verified; the stored head must be the
    /// last event's hash.
    ///
    /// # Errors
    ///
    /// `CS-DB-0014` naming the first event that does not verify.
    pub async fn verified_admin_log(&mut self) -> Result<Vec<StoredAdminEvent>> {
        let mut all = Vec::new();
        let mut after = None;
        loop {
            let page = self.admin_events(after, crate::admin_log::MAX_PAGE).await?;
            let Some(last) = page.last() else { break };
            after = Some(last.seq);
            all.extend(page);
        }
        let head = verify_admin_chain(&all)?;
        let stored = self.admin_head().await?;
        if stored.as_deref() != head.as_ref().map(<[u8; 32]>::as_slice) {
            return Err(StoreError::AdminChainBroken {
                seq: all.last().map_or(0, |e| e.seq),
            });
        }
        Ok(all)
    }

    /// The organization's own row.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when it does not exist; `CS-DB-0010` for an unreadable row.
    pub async fn organization(&mut self) -> Result<Organization> {
        let org = self.org();
        let r = sqlx::query!(
            "SELECT id, name, status, policy, created_at FROM organizations WHERE id = $1",
            org
        )
        .fetch_optional(&mut *self.tx)
        .await
        .map_err(db)?
        .ok_or(StoreError::NotFound {
            entity: "organization",
        })?;
        Ok(Organization {
            id: OrganizationId(r.id),
            name: r.name,
            status: OrganizationStatus::parse(&r.status, "status")?,
            policy: r.policy,
            created_at: r.created_at,
        })
    }

    /// The organization's workspaces, by name.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn workspaces(&mut self) -> Result<Vec<Workspace>> {
        let org = self.org();
        let rows = sqlx::query!(
            "SELECT id, name, status FROM accounts WHERE organization_id = $1 ORDER BY name, id",
            org
        )
        .fetch_all(&mut *self.tx)
        .await
        .map_err(db)?;
        rows.into_iter()
            .map(|r| {
                Ok(Workspace {
                    id: AccountId(r.id),
                    name: r.name,
                    status: WorkspaceStatus::parse(&r.status, "status")?,
                })
            })
            .collect()
    }

    /// A proof that `account` is a workspace of this organization, or `None` for any
    /// other id (another organization's workspace is indistinguishable from none).
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn workspace(&mut self, account: AccountId) -> Result<Option<WorkspaceOf>> {
        let org = self.org();
        let found = sqlx::query_scalar!(
            "SELECT id FROM accounts WHERE id = $1 AND organization_id = $2",
            account.0,
            org
        )
        .fetch_optional(&mut *self.tx)
        .await
        .map_err(db)?;
        Ok(found.map(|_| WorkspaceOf {
            organization: self.org,
            account,
        }))
    }

    /// The workspace `account` of this organization, or `None` for any other id.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn workspace_row(&mut self, account: AccountId) -> Result<Option<Workspace>> {
        let org = self.org();
        let r = sqlx::query!(
            "SELECT id, name, status FROM accounts WHERE id = $1 AND organization_id = $2",
            account.0,
            org
        )
        .fetch_optional(&mut *self.tx)
        .await
        .map_err(db)?;
        r.map(|r| {
            Ok(Workspace {
                id: AccountId(r.id),
                name: r.name,
                status: WorkspaceStatus::parse(&r.status, "status")?,
            })
        })
        .transpose()
    }

    /// Rename the organization, appending `organization.renamed` (old and new name).
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` for an empty or overlong name; `CS-DB-0003` when it does not exist.
    pub async fn rename(&mut self, name: &str) -> Result<()> {
        let org = self.org();
        let old = sqlx::query_scalar!(
            "SELECT name FROM organizations WHERE id = $1 FOR UPDATE",
            org
        )
        .fetch_optional(&mut *self.tx)
        .await
        .map_err(db)?
        .ok_or(StoreError::NotFound {
            entity: "organization",
        })?;
        sqlx::query!(
            "UPDATE organizations SET name = $2 WHERE id = $1",
            org,
            name
        )
        .execute(&mut *self.tx)
        .await
        .map_err(db)?;
        self.admin_event(
            AdminChange::new("organization.renamed")
                .target("organization", org)
                .change(Change::new("name", Some(old.into()), Some(name.into()))),
        )
        .await
    }

    /// The administrator row of `user` in this organization, read afresh (rights are
    /// never cached across requests, `SEC-O06`), or `None` when they hold no role.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn admin(&mut self, user: UserId) -> Result<Option<OrganizationAdmin>> {
        Ok(self.admin_role_rows(Some(user)).await?.into_iter().next())
    }

    /// Every administrator of this organization, owners first.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn admins(&mut self) -> Result<Vec<OrganizationAdmin>> {
        self.admin_role_rows(None).await
    }

    async fn admin_role_rows(&mut self, user: Option<UserId>) -> Result<Vec<OrganizationAdmin>> {
        let org = self.org();
        let rows = sqlx::query!(
            r#"SELECT oa.user_id, oa.role, oa.permission_set_id, oa.workspace_scope, oa.created_at,
                      ps.permissions AS "permissions?"
               FROM organization_admins oa
               LEFT JOIN org_permission_sets ps
                 ON ps.organization_id = oa.organization_id AND ps.id = oa.permission_set_id
               WHERE oa.organization_id = $1 AND ($2::uuid IS NULL OR oa.user_id = $2)
               ORDER BY CASE oa.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END,
                        oa.created_at, oa.user_id"#,
            org,
            user.map(|u| u.0)
        )
        .fetch_all(&mut *self.tx)
        .await
        .map_err(db)?;
        rows.into_iter()
            .map(|r| {
                Ok(OrganizationAdmin {
                    user_id: UserId(r.user_id),
                    role: OrganizationRole::parse(&r.role, "role")?,
                    permission_set_id: r.permission_set_id,
                    permissions: r.permissions.unwrap_or_default(),
                    workspace_scope: r
                        .workspace_scope
                        .map(|s| s.into_iter().map(AccountId).collect()),
                    created_at: r.created_at,
                })
            })
            .collect()
    }

    /// The normalized e-mail of `user` when they are an enabled member of a workspace of
    /// this organization (what an organization administrator must be, docs/23 §2.3), or
    /// `None` for anyone else, another organization's users included.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn member_email(&mut self, user: UserId) -> Result<Option<Personal<String>>> {
        let org = self.org();
        let email = sqlx::query_scalar!(
            "SELECT u.email_normalized FROM users u WHERE u.id = $1 AND u.disabled_at IS NULL \
             AND EXISTS (SELECT 1 FROM account_memberships m JOIN accounts a ON a.id = m.account_id \
                          WHERE m.user_id = u.id AND a.organization_id = $2 \
                            AND m.disabled_at IS NULL)",
            user.0,
            org
        )
        .fetch_optional(&mut *self.tx)
        .await
        .map_err(db)?;
        Ok(email.map(Personal))
    }

    /// Make `user` an owner or admin of this organization, appending
    /// `organization.admin_added`. The database refuses a user who is not an enabled
    /// member of one of its workspaces (`CS-DB-0008`, constraint
    /// `organization_admin_is_a_member`); callers check [`OrgTx::member_email`] first.
    ///
    /// # Errors
    ///
    /// `CS-DB-0006` when they already hold a role; `CS-DB-0008` as above, or for
    /// [`OrganizationRole::Delegated`], which needs a permission set (ORG-07).
    pub async fn add_admin(
        &mut self,
        user: UserId,
        role: OrganizationRole,
        now: OffsetDateTime,
    ) -> Result<()> {
        let org = self.org();
        sqlx::query!(
            "INSERT INTO organization_admins (organization_id, user_id, role, created_at) \
             VALUES ($1, $2, $3, $4)",
            org,
            user.0,
            role.as_str(),
            now
        )
        .execute(&mut *self.tx)
        .await
        .map_err(db)?;
        self.admin_event(
            AdminChange::new("organization.admin_added")
                .target("user", user.0)
                .change(Change::new("role", None, Some(role.as_str().into()))),
        )
        .await
    }

    /// Make an administrator an owner or an admin, appending
    /// `organization.admin_role_changed`; a delegated admin promoted loses its permission
    /// set and workspace scope, which only a delegated role carries. The same role again
    /// changes nothing and appends nothing. Leaving no enabled owner is refused at commit.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when `user` holds no role here; `CS-DB-0008` for
    /// [`OrganizationRole::Delegated`], which needs a permission set (ORG-07).
    pub async fn set_admin_role(&mut self, user: UserId, role: OrganizationRole) -> Result<()> {
        let org = self.org();
        let old = sqlx::query_scalar!(
            "SELECT role FROM organization_admins WHERE organization_id = $1 AND user_id = $2 \
             FOR UPDATE",
            org,
            user.0
        )
        .fetch_optional(&mut *self.tx)
        .await
        .map_err(db)?
        .ok_or(StoreError::NotFound {
            entity: "organization admin",
        })?;
        if old == role.as_str() {
            return Ok(());
        }
        sqlx::query!(
            "UPDATE organization_admins SET role = $3, \
             permission_set_id = CASE WHEN $3 = 'delegated' THEN permission_set_id END, \
             workspace_scope = CASE WHEN $3 = 'delegated' THEN workspace_scope END \
             WHERE organization_id = $1 AND user_id = $2",
            org,
            user.0,
            role.as_str()
        )
        .execute(&mut *self.tx)
        .await
        .map_err(db)?;
        self.admin_event(
            AdminChange::new("organization.admin_role_changed")
                .target("user", user.0)
                .change(Change::new(
                    "role",
                    Some(old.into()),
                    Some(role.as_str().into()),
                )),
        )
        .await
    }

    /// Remove `user`'s role in this organization, appending
    /// `organization.admin_removed`. Leaving no enabled owner is refused at commit.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when `user` holds no role here.
    pub async fn remove_admin(&mut self, user: UserId) -> Result<()> {
        let org = self.org();
        let old = sqlx::query_scalar!(
            "DELETE FROM organization_admins WHERE organization_id = $1 AND user_id = $2 \
             RETURNING role",
            org,
            user.0
        )
        .fetch_optional(&mut *self.tx)
        .await
        .map_err(db)?
        .ok_or(StoreError::NotFound {
            entity: "organization admin",
        })?;
        self.admin_event(
            AdminChange::new("organization.admin_removed")
                .target("user", user.0)
                .change(Change::new("role", Some(old.into()), None)),
        )
        .await
    }

    /// Create a workspace of this organization with its built-in permission profiles.
    /// Its first members are added through [`Store::for_workspace_of`] after commit.
    ///
    /// # Errors
    ///
    /// `CS-DB-0006` when the id or a profile id exists; `CS-DB-0008` for an empty or
    /// overlong name; `CS-DB-0003` when the organization is not active.
    pub async fn create_workspace(
        &mut self,
        id: AccountId,
        name: &str,
        profiles: &BuiltinProfiles,
    ) -> Result<WorkspaceOf> {
        let e = self
            .next_event(
                &AdminChange::new("workspace.created")
                    .target("workspace", id.0)
                    .target("admin_profile", profiles.admin.0)
                    .target("sender_profile", profiles.sender.0)
                    .target("viewer_profile", profiles.viewer.0),
            )
            .await?;
        let created = sqlx::query_scalar!(
            r#"SELECT openseal_create_workspace($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
               AS "created!""#,
            id.0,
            name,
            profiles.admin.0,
            profiles.sender.0,
            profiles.viewer.0,
            e.seq,
            e.prev,
            e.hash,
            e.at,
            e.canonical
        )
        .fetch_one(&mut *self.tx)
        .await
        .map_err(append_error(e.seq))?;
        if created {
            Ok(WorkspaceOf {
                organization: self.org,
                account: id,
            })
        } else {
            Err(StoreError::NotFound {
                entity: "organization",
            })
        }
    }

    /// Archive a workspace of this organization (idempotent).
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when it is not (or no longer) a workspace of this organization.
    pub async fn archive_workspace(&mut self, workspace: &WorkspaceOf) -> Result<()> {
        if workspace.organization != self.org {
            return Err(StoreError::NotFound {
                entity: "workspace",
            });
        }
        let e = self
            .next_event(
                &AdminChange::new("workspace.archived").target("workspace", workspace.account.0),
            )
            .await?;
        let done = sqlx::query_scalar!(
            r#"SELECT openseal_archive_workspace($1, $2, $3, $4, $5, $6) AS "done!""#,
            workspace.account.0,
            e.seq,
            e.prev,
            e.hash,
            e.at,
            e.canonical
        )
        .fetch_one(&mut *self.tx)
        .await
        .map_err(append_error(e.seq))?;
        if done {
            Ok(())
        } else {
            Err(StoreError::NotFound {
                entity: "workspace",
            })
        }
    }

    /// Continue this same transaction as an ordinary single-account transaction on
    /// `workspace`, so what was written in organization scope (a new workspace) and
    /// what follows in the workspace (its first administrator) commit or roll back
    /// together. From here the organization scope is gone: setting the account makes
    /// `openseal_current_org()` NULL. As [`Store::for_workspace_of`], the workspace's
    /// organization is read again and must still be the proof's.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when `workspace` is not a workspace of this organization;
    /// `CS-DB-0001`.
    pub async fn into_workspace(mut self, workspace: &WorkspaceOf) -> Result<TenantTx> {
        if workspace.organization != self.org {
            return Err(StoreError::NotFound {
                entity: "workspace",
            });
        }
        let acct = workspace.account.0;
        sqlx::query!(
            "SELECT set_config('openseal.account_id', $1, true)",
            acct.to_string()
        )
        .fetch_one(&mut *self.tx)
        .await
        .map_err(db)?;
        let org = sqlx::query_scalar!("SELECT organization_id FROM accounts WHERE id = $1", acct)
            .fetch_optional(&mut *self.tx)
            .await
            .map_err(db)?;
        if org == Some(workspace.organization.0) {
            Ok(TenantTx::bound(self.tx, workspace.account, self.actor))
        } else {
            Err(StoreError::NotFound {
                entity: "workspace",
            })
        }
    }

    /// Commit.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001` or the error a deferred constraint raised (`CS-DB-0008`
    /// [`StoreError::is_last_owner`]).
    pub async fn commit(self) -> Result<()> {
        self.tx.commit().await.map_err(db)
    }

    /// Roll back explicitly (dropping does the same).
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn rollback(self) -> Result<()> {
        self.tx.rollback().await.map_err(db)
    }
}

/// The constraint a commit violates when it leaves an active organization with no
/// enabled owner (docs/23 §2.2, `CS-ORG-0008`).
pub const LAST_OWNER_CONSTRAINT: &str = "organization_keeps_an_owner";

impl StoreError {
    /// Whether this refuses a commit that would leave an active organization with no
    /// enabled owner (`CS-ORG-0008` at the API).
    #[must_use]
    pub fn is_last_owner(&self) -> bool {
        matches!(self, Self::Constraint { constraint: Some(c), .. } if c == LAST_OWNER_CONSTRAINT)
    }
}

impl Store {
    /// The organization scope for `org`: the door to organization tables and, read-only,
    /// to its workspaces' rows. The caller must have established that its principal
    /// holds a role in `org` (as for [`Store::for_account`]).
    #[must_use]
    pub fn for_organization(&self, org: OrganizationId) -> OrgScope<'_> {
        OrgScope { store: self, org }
    }

    /// An ordinary single-account transaction on a workspace of an organization: how
    /// organization routes write to a workspace. It first reads the workspace's own
    /// organization in that transaction and refuses when it is no longer the proof's.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` (as for another organization's workspace) when the workspace no
    /// longer belongs to the proof's organization; `CS-DB-0001`.
    pub async fn for_workspace_of(&self, workspace: &WorkspaceOf) -> Result<TenantTx> {
        let mut tx = self.for_account(workspace.account).begin().await?;
        let acct = tx.acct();
        let org = sqlx::query_scalar!("SELECT organization_id FROM accounts WHERE id = $1", acct)
            .fetch_optional(tx.conn())
            .await
            .map_err(db)?;
        if org == Some(workspace.organization.0) {
            Ok(tx)
        } else {
            Err(StoreError::NotFound {
                entity: "workspace",
            })
        }
    }

    /// The first organization and workspace of an install (`casual-sign-server
    /// bootstrap`), with the workspace's built-in profiles. Refused once any
    /// organization exists: later ones come from the platform console (docs/23 §5.3).
    /// Returns the new workspace's transaction, so the first administrator (and
    /// [`crate::repo::accounts::Accounts::make_first_owner`]) commit with it.
    ///
    /// # Errors
    ///
    /// `CS-DB-0006` (constraint `organizations`) when an organization already exists;
    /// `CS-DB-0008` for an empty or overlong name.
    pub async fn bootstrap_organization(
        &self,
        org: OrganizationId,
        account: AccountId,
        name: &str,
        profiles: &BuiltinProfiles,
    ) -> Result<TenantTx> {
        let mut tx = self.for_account(account).begin().await?;
        let created = sqlx::query_scalar!(
            r#"SELECT openseal_bootstrap_organization($1, $2, $3, $4, $5, $6) AS "created!""#,
            org.0,
            account.0,
            name,
            profiles.admin.0,
            profiles.sender.0,
            profiles.viewer.0
        )
        .fetch_one(tx.conn())
        .await
        .map_err(db)?;
        if created {
            tx.org_admin_event(
                AdminChange::new("organization.created")
                    .target("organization", org.0)
                    .target("workspace", account.0),
            )
            .await?;
            Ok(tx)
        } else {
            Err(StoreError::Conflict {
                constraint: "organizations".to_owned(),
            })
        }
    }
}
