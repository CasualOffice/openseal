//! Members' own folders and where they filed envelopes (UXW-02, migration 0022) and
//! templates (TSH-03, migration 0045). Every statement names the member as well as the
//! account: a folder is its owner's alone, and the filing tables' composite references
//! refuse a filing into another member's folder (and, for templates, into a folder of
//! the other kind) even if a caller tried. Filing is a member's view of their lists,
//! not a change of the agreement or the template: nothing here touches an envelope or
//! template row or the audit chain.

use casual_sign_audit::Personal;
use uuid::Uuid;

use super::affected;
use crate::error::{Result, db};
use crate::ids::{EnvelopeId, FolderEntryId, FolderId, TemplateId, UserId};
use crate::store::TenantTx;

/// What a folder holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FolderKind {
    /// Envelopes (UXW-02).
    #[default]
    Envelopes,
    /// Templates (TSH-03).
    Templates,
}

impl FolderKind {
    /// The API's and the table's word for it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Envelopes => "envelopes",
            Self::Templates => "templates",
        }
    }

    /// From the API's word; `None` for any other.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "envelopes" => Some(Self::Envelopes),
            "templates" => Some(Self::Templates),
            _ => None,
        }
    }
}

/// A folder with how many of its owner's filed envelopes (or templates) are in the
/// lists (not deleted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folder {
    /// Host-minted id.
    pub id: FolderId,
    /// Its name as the member typed it (user content: never logged).
    pub name: Personal<String>,
    /// What it holds.
    pub kind: FolderKind,
    /// Envelopes (or templates) filed in it and not deleted.
    pub count: i64,
}

/// Folders of this account. Reached through `TenantTx::folders`.
#[derive(Debug)]
pub struct Folders<'t> {
    pub(crate) tx: &'t mut TenantTx,
}

impl Folders<'_> {
    /// `owner`'s folders of `kind`, by name ignoring case.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn list(&mut self, owner: UserId, kind: FolderKind) -> Result<Vec<Folder>> {
        let acct = self.tx.acct();
        let rows: Vec<(Uuid, String, i64)> = match kind {
            FolderKind::Envelopes => sqlx::query!(
                "SELECT f.id, f.name, \
                   (SELECT count(*) FROM folder_envelopes AS fe JOIN envelopes AS e \
                      ON e.account_id = fe.account_id AND e.id = fe.envelope_id \
                     WHERE fe.account_id = f.account_id AND fe.folder_id = f.id \
                       AND fe.user_id = f.owner_user_id AND e.deleted_at IS NULL) AS \"count!\" \
                 FROM folders AS f \
                 WHERE f.account_id = $1 AND f.owner_user_id = $2 AND f.kind = 'envelopes' \
                 ORDER BY lower(f.name), f.id",
                acct,
                owner.0
            )
            .fetch_all(self.tx.conn())
            .await
            .map_err(db)?
            .into_iter()
            .map(|r| (r.id, r.name, r.count))
            .collect(),
            FolderKind::Templates => sqlx::query!(
                "SELECT f.id, f.name, \
                   (SELECT count(*) FROM folder_templates AS ft JOIN templates AS t \
                      ON t.account_id = ft.account_id AND t.id = ft.template_id \
                     WHERE ft.account_id = f.account_id AND ft.folder_id = f.id \
                       AND ft.user_id = f.owner_user_id AND t.deleted_at IS NULL) AS \"count!\" \
                 FROM folders AS f \
                 WHERE f.account_id = $1 AND f.owner_user_id = $2 AND f.kind = 'templates' \
                 ORDER BY lower(f.name), f.id",
                acct,
                owner.0
            )
            .fetch_all(self.tx.conn())
            .await
            .map_err(db)?
            .into_iter()
            .map(|r| (r.id, r.name, r.count))
            .collect(),
        };
        Ok(rows
            .into_iter()
            .map(|(id, name, count)| Folder {
                id: FolderId(id),
                name: Personal(name),
                kind,
                count,
            })
            .collect())
    }

    /// One of `owner`'s folders of `kind`, or `None` (another member's, another
    /// account's, one of the other kind, or none at all).
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn get(
        &mut self,
        owner: UserId,
        id: FolderId,
        kind: FolderKind,
    ) -> Result<Option<Folder>> {
        Ok(self
            .list(owner, kind)
            .await?
            .into_iter()
            .find(|f| f.id == id))
    }

    /// How many folders of `kind` `owner` has.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn count(&mut self, owner: UserId, kind: FolderKind) -> Result<i64> {
        let acct = self.tx.acct();
        let n = sqlx::query_scalar!(
            "SELECT count(*) AS \"n!\" FROM folders \
             WHERE account_id = $1 AND owner_user_id = $2 AND kind = $3",
            acct,
            owner.0,
            kind.as_str()
        )
        .fetch_one(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(n)
    }

    /// A new folder of `kind` of `owner`.
    ///
    /// # Errors
    ///
    /// `CS-DB-0006` when `owner` has a folder of that kind and name, ignoring case
    /// (`folders_owner_name`); `CS-DB-0008` when `owner` is not a member.
    pub async fn create(
        &mut self,
        owner: UserId,
        id: FolderId,
        name: &str,
        kind: FolderKind,
    ) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "INSERT INTO folders (id, account_id, owner_user_id, kind, name) \
             VALUES ($2, $1, $3, $5, $4)",
            acct,
            id.0,
            owner.0,
            name,
            kind.as_str()
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// Rename one of `owner`'s folders, of either kind.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when it is not theirs; `CS-DB-0006` for a name they already use.
    pub async fn rename(&mut self, owner: UserId, id: FolderId, name: &str) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE folders SET name = $4 \
             WHERE account_id = $1 AND id = $2 AND owner_user_id = $3 \
               AND kind IN ('envelopes', 'templates')",
            acct,
            id.0,
            owner.0,
            name
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        affected(done.rows_affected(), "folder")
    }

    /// Remove one of `owner`'s folders, of either kind; what was filed in it is in no
    /// folder again.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when it is not theirs.
    pub async fn delete(&mut self, owner: UserId, id: FolderId) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "DELETE FROM folders \
             WHERE account_id = $1 AND id = $2 AND owner_user_id = $3 \
               AND kind IN ('envelopes', 'templates')",
            acct,
            id.0,
            owner.0
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        affected(done.rows_affected(), "folder")
    }

    /// File `envelopes` in `owner`'s `folder`, or in none (`None`), replacing where they
    /// were filed. `entries` are the host-minted ids of new filings, one per envelope.
    /// Returns how many envelopes are now where asked.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` when the folder is not `owner`'s or an envelope is not this
    /// account's (the references); `CS-DB-0001`.
    pub async fn file(
        &mut self,
        owner: UserId,
        folder: Option<FolderId>,
        envelopes: &[(FolderEntryId, EnvelopeId)],
    ) -> Result<u64> {
        let acct = self.tx.acct();
        let ids: Vec<Uuid> = envelopes.iter().map(|(_, e)| e.0).collect();
        let done = match folder {
            None => sqlx::query!(
                "DELETE FROM folder_envelopes \
                 WHERE account_id = $1 AND user_id = $2 AND envelope_id = ANY($3)",
                acct,
                owner.0,
                &ids
            )
            .execute(self.tx.conn())
            .await
            .map_err(db)?,
            Some(f) => {
                let entries: Vec<Uuid> = envelopes.iter().map(|(x, _)| x.0).collect();
                sqlx::query!(
                    "INSERT INTO folder_envelopes (id, account_id, user_id, envelope_id, folder_id) \
                     SELECT x.id, $1, $2, x.envelope_id, $3 \
                       FROM unnest($4::uuid[], $5::uuid[]) AS x (id, envelope_id) \
                     ON CONFLICT (account_id, user_id, envelope_id) \
                     DO UPDATE SET folder_id = EXCLUDED.folder_id, filed_at = now()",
                    acct,
                    owner.0,
                    f.0,
                    &entries,
                    &ids
                )
                .execute(self.tx.conn())
                .await
                .map_err(db)?
            }
        };
        Ok(done.rows_affected())
    }

    /// File `templates` in `owner`'s template `folder`, or in none (`None`), replacing
    /// where they were filed. `entries` are the host-minted ids of new filings, one per
    /// template. Returns how many filings were written or removed.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` when the folder is not `owner`'s template folder or a template is
    /// not this account's (the references); `CS-DB-0001`.
    pub async fn file_templates(
        &mut self,
        owner: UserId,
        folder: Option<FolderId>,
        templates: &[(FolderEntryId, TemplateId)],
    ) -> Result<u64> {
        let acct = self.tx.acct();
        let ids: Vec<Uuid> = templates.iter().map(|(_, t)| t.0).collect();
        let done = match folder {
            None => sqlx::query!(
                "DELETE FROM folder_templates \
                 WHERE account_id = $1 AND user_id = $2 AND template_id = ANY($3)",
                acct,
                owner.0,
                &ids
            )
            .execute(self.tx.conn())
            .await
            .map_err(db)?,
            Some(f) => {
                let entries: Vec<Uuid> = templates.iter().map(|(x, _)| x.0).collect();
                sqlx::query!(
                    "INSERT INTO folder_templates (id, account_id, user_id, template_id, folder_id) \
                     SELECT x.id, $1, $2, x.template_id, $3 \
                       FROM unnest($4::uuid[], $5::uuid[]) AS x (id, template_id) \
                     ON CONFLICT (account_id, user_id, template_id) \
                     DO UPDATE SET folder_id = EXCLUDED.folder_id, filed_at = now()",
                    acct,
                    owner.0,
                    f.0,
                    &entries,
                    &ids
                )
                .execute(self.tx.conn())
                .await
                .map_err(db)?
            }
        };
        Ok(done.rows_affected())
    }

    /// Where `owner` filed templates: `(template, folder)` pairs, one per filed template.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn template_filings(&mut self, owner: UserId) -> Result<Vec<(TemplateId, FolderId)>> {
        let acct = self.tx.acct();
        let rows = sqlx::query!(
            "SELECT template_id, folder_id FROM folder_templates \
             WHERE account_id = $1 AND user_id = $2",
            acct,
            owner.0
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(rows
            .into_iter()
            .map(|r| (TemplateId(r.template_id), FolderId(r.folder_id)))
            .collect())
    }
}
