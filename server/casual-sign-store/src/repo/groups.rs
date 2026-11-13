//! Groups of members (UXW-07; docs/22 §8): made, renamed and deleted by an administrator,
//! and used to share templates (UXW-06). Every change appends its admin event in the
//! same transaction; the database refuses a commit without one (0032).

use super::affected;
use super::templates::Group;
use crate::admin_log::{AdminChange, Change};
use crate::error::{Result, db};
use crate::ids::{GroupId, UserId};
use crate::store::TenantTx;

/// This account's groups and their members. Reached through `TenantTx::groups`.
#[derive(Debug)]
pub struct Groups<'t> {
    pub(crate) tx: &'t mut TenantTx,
}

impl Groups<'_> {
    /// One group with its member count.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn get(&mut self, id: GroupId) -> Result<Option<Group>> {
        let acct = self.tx.acct();
        let row = sqlx::query!(
            "SELECT g.id, g.name, (SELECT count(*) FROM group_members m \
             WHERE m.account_id = $1 AND m.group_id = g.id) AS \"members!\" \
             FROM groups g WHERE g.account_id = $1 AND g.id = $2",
            acct,
            id.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(row.map(|r| Group {
            id: GroupId(r.id),
            name: r.name,
            members: r.members,
        }))
    }

    /// Make a group.
    ///
    /// # Errors
    ///
    /// `CS-DB-0006` when the account has a group of that name.
    pub async fn create(&mut self, id: GroupId, name: &str) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "INSERT INTO groups (id, account_id, name) VALUES ($2, $1, $3)",
            acct,
            id.0,
            name
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        self.tx
            .admin_event(
                AdminChange::new("group.created")
                    .target("group", id.0)
                    .change(Change::new("name", None, Some(name.into()))),
            )
            .await
    }

    /// Rename a group.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` for no such group; `CS-DB-0006` for a name taken.
    pub async fn rename(&mut self, id: GroupId, name: &str) -> Result<()> {
        let acct = self.tx.acct();
        let old = sqlx::query_scalar!(
            "SELECT name FROM groups WHERE account_id = $1 AND id = $2 FOR UPDATE",
            acct,
            id.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?
        .ok_or(crate::error::StoreError::NotFound { entity: "group" })?;
        let done = sqlx::query!(
            "UPDATE groups SET name = $3 WHERE account_id = $1 AND id = $2",
            acct,
            id.0,
            name
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        affected(done.rows_affected(), "group")?;
        self.tx
            .admin_event(
                AdminChange::new("group.renamed")
                    .target("group", id.0)
                    .change(Change::new("name", Some(old.into()), Some(name.into()))),
            )
            .await
    }

    /// Delete a group: its members' places in it and the template shares naming it go
    /// with it (0031, 0032 cascades).
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` for no such group.
    pub async fn delete(&mut self, id: GroupId) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "DELETE FROM groups WHERE account_id = $1 AND id = $2",
            acct,
            id.0
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        affected(done.rows_affected(), "group")?;
        self.tx
            .admin_event(AdminChange::new("group.deleted").target("group", id.0))
            .await
    }

    /// The members of a group, by user id.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn members(&mut self, id: GroupId) -> Result<Vec<UserId>> {
        let acct = self.tx.acct();
        let rows = sqlx::query_scalar!(
            "SELECT user_id FROM group_members WHERE account_id = $1 AND group_id = $2 \
             ORDER BY user_id",
            acct,
            id.0
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(rows.into_iter().map(UserId).collect())
    }

    /// Make `users` the group's members: those not in it are added and those not named
    /// removed, each as its own admin event (`group.member_added`,
    /// `group.member_removed`). Returns how many were added and removed.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` for a user who is not a member of this account.
    pub async fn set_members(&mut self, id: GroupId, users: &[UserId]) -> Result<(usize, usize)> {
        let acct = self.tx.acct();
        let now = self.members(id).await?;
        let want: std::collections::BTreeSet<UserId> = users.iter().copied().collect();
        let had: std::collections::BTreeSet<UserId> = now.into_iter().collect();
        let removed: Vec<UserId> = had.difference(&want).copied().collect();
        let added: Vec<UserId> = want.difference(&had).copied().collect();
        for u in &removed {
            sqlx::query!(
                "DELETE FROM group_members WHERE account_id = $1 AND group_id = $2 \
                 AND user_id = $3",
                acct,
                id.0,
                u.0
            )
            .execute(self.tx.conn())
            .await
            .map_err(db)?;
            self.tx
                .admin_event(
                    AdminChange::new("group.member_removed")
                        .target("group", id.0)
                        .target("user", u.0),
                )
                .await?;
        }
        for u in &added {
            sqlx::query!(
                "INSERT INTO group_members (account_id, group_id, user_id) VALUES ($1, $2, $3)",
                acct,
                id.0,
                u.0
            )
            .execute(self.tx.conn())
            .await
            .map_err(db)?;
            self.tx
                .admin_event(
                    AdminChange::new("group.member_added")
                        .target("group", id.0)
                        .target("user", u.0),
                )
                .await?;
        }
        Ok((added.len(), removed.len()))
    }
}
