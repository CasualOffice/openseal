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

use crate::error::{Result, StoreError, db};
use crate::ids::{AccountId, OrganizationId, PermissionProfileId};
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
        Ok(OrgTx { tx, org: self.org })
    }
}

/// A database transaction bound to one organization. Dropping it without
/// [`OrgTx::commit`] rolls back.
#[derive(Debug)]
pub struct OrgTx {
    tx: Transaction<'static, Postgres>,
    org: OrganizationId,
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
        let created = sqlx::query_scalar!(
            r#"SELECT openseal_create_workspace($1, $2, $3, $4, $5) AS "created!""#,
            id.0,
            name,
            profiles.admin.0,
            profiles.sender.0,
            profiles.viewer.0
        )
        .fetch_one(&mut *self.tx)
        .await
        .map_err(db)?;
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
        let done = sqlx::query_scalar!(
            r#"SELECT openseal_archive_workspace($1) AS "done!""#,
            workspace.account.0
        )
        .fetch_one(&mut *self.tx)
        .await
        .map_err(db)?;
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
            Ok(TenantTx::bound(self.tx, workspace.account))
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
            Ok(tx)
        } else {
            Err(StoreError::Conflict {
                constraint: "organizations".to_owned(),
            })
        }
    }
}
