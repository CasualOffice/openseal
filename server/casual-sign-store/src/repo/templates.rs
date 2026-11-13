//! Templates (docs/22 §7): roles, documents and role-bound fields. Envelopes copy from
//! them; nothing references a template after creation except `envelopes.template_ids`.

use casual_sign_audit::Personal;
use casual_sign_model::FieldType;
use uuid::Uuid;

use super::fields::{Rect, field_type_parse, field_type_text};
use super::hash32;
use super::recipients::RecipientType;
use crate::error::{Result, StoreError, db};
use crate::ids::{
    GroupId, TemplateDocumentId, TemplateFieldId, TemplateId, TemplateRoleId, TemplateShareId,
    UserId,
};
use crate::store::TenantTx;

/// A template.
#[derive(Debug, Clone, PartialEq)]
pub struct Template {
    /// Host-minted id.
    pub id: TemplateId,
    /// Owner, a member of this account.
    pub owner_user_id: UserId,
    /// Name.
    pub name: String,
    /// Email subject (may name people).
    pub email_subject: Option<Personal<String>>,
    /// Email message.
    pub email_message: Option<Personal<String>>,
    /// Envelope settings.
    pub settings: serde_json::Value,
    /// Matching rules (slice 3).
    pub matching_rules: serde_json::Value,
    /// Version.
    pub version: i32,
}

/// A template role.
#[derive(Debug, Clone, PartialEq)]
pub struct TemplateRole {
    /// Host-minted id.
    pub id: TemplateRoleId,
    /// Template.
    pub template_id: TemplateId,
    /// Name, unique in the template.
    pub name: String,
    /// Routing order.
    pub routing_order: i32,
    /// Recipient type.
    pub kind: RecipientType,
    /// Default authentication.
    pub default_auth: serde_json::Value,
}

/// A template document.
#[derive(Debug, Clone, PartialEq)]
pub struct TemplateDocument {
    /// Host-minted id.
    pub id: TemplateDocumentId,
    /// Template.
    pub template_id: TemplateId,
    /// Position.
    pub ord: i32,
    /// Display name.
    pub name: String,
    /// SHA-256 of the normalized PDF (its blob key).
    pub sha256: [u8; 32],
    /// Bytes.
    pub byte_len: i64,
    /// Pages.
    pub page_count: i32,
    /// Page geometry.
    pub pages: serde_json::Value,
}

/// A role-bound template field.
#[derive(Debug, Clone, PartialEq)]
pub struct TemplateField {
    /// Host-minted id.
    pub id: TemplateFieldId,
    /// Template.
    pub template_id: TemplateId,
    /// Document.
    pub template_document_id: TemplateDocumentId,
    /// Role.
    pub role_id: TemplateRoleId,
    /// Type.
    pub kind: FieldType,
    /// Placement.
    pub rect: Rect,
    /// Required.
    pub required: bool,
    /// Data label.
    pub label: Option<String>,
    /// The rest of docs/22 §6.
    pub spec: Personal<serde_json::Value>,
}

/// What a member may do with a template (UXW-06), weakest first. Nothing at all is no
/// access, answered as not found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TemplateAccess {
    /// Read it and make envelopes from it: a share without `can_edit`.
    Use,
    /// Also change its documents, roles, fields and message: a share with `can_edit`.
    Edit,
    /// Also delete, restore and share it: its owner or an administrator.
    Owner,
}

impl TemplateAccess {
    /// The API's word for it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Use => "use",
            Self::Edit => "edit",
            Self::Owner => "owner",
        }
    }

    /// From `openseal_template_share_right`'s answer.
    fn from_right(s: Option<&str>) -> Option<Self> {
        match s {
            Some("edit") => Some(Self::Edit),
            Some("use") => Some(Self::Use),
            _ => None,
        }
    }
}

/// Which templates `list_for` answers (UXW-06).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateView {
    /// Every template the member may use.
    All,
    /// The member's own.
    Owned,
    /// Shared with me: another member's templates that a share reaches this member by.
    SharedWithMe,
    /// The member's starred templates.
    Favourites,
}

impl TemplateView {
    fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Owned => "owned",
            Self::SharedWithMe => "shared",
            Self::Favourites => "favourites",
        }
    }
}

/// A template as one member's list shows it.
#[derive(Debug, Clone, PartialEq)]
pub struct ListedTemplate {
    /// The template.
    pub template: Template,
    /// What the member may do with it.
    pub access: TemplateAccess,
    /// Starred by the member.
    pub favourite: bool,
    /// Shared with anyone.
    pub shared: bool,
}

/// Whom a share reaches (exactly one, as the table checks).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ShareTarget {
    /// One member of this account.
    User(UserId),
    /// Every member of a group of this account.
    Group(GroupId),
    /// Every member of this account.
    Account,
}

/// A template's share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemplateShare {
    /// Host-minted id.
    pub id: TemplateShareId,
    /// Whom it reaches.
    pub target: ShareTarget,
    /// Whether they may also edit.
    pub can_edit: bool,
}

/// A group of this account, for choosing whom to share with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// Id.
    pub id: GroupId,
    /// Name.
    pub name: String,
    /// Members.
    pub members: i64,
}

/// Templates of this account. Reached through `TenantTx::templates`.
#[derive(Debug)]
pub struct Templates<'t> {
    pub(crate) tx: &'t mut TenantTx,
}

/// A template row as selected.
struct TemplateRow {
    id: Uuid,
    owner_user_id: Uuid,
    name: String,
    email_subject: Option<String>,
    email_message: Option<String>,
    settings: serde_json::Value,
    matching_rules: serde_json::Value,
    version: i32,
}

impl From<TemplateRow> for Template {
    fn from(r: TemplateRow) -> Self {
        Self {
            id: TemplateId(r.id),
            owner_user_id: UserId(r.owner_user_id),
            name: r.name,
            email_subject: r.email_subject.map(Personal),
            email_message: r.email_message.map(Personal),
            settings: r.settings,
            matching_rules: r.matching_rules,
            version: r.version,
        }
    }
}

impl Templates<'_> {
    /// Create a template.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` an owner who is not a member of this account.
    pub async fn insert(&mut self, t: &Template) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "INSERT INTO templates (id, account_id, owner_user_id, name, email_subject, email_message, \
             settings, matching_rules, version) VALUES ($2, $1, $3, $4, $5, $6, $7, $8, $9)",
            acct,
            t.id.0,
            t.owner_user_id.0,
            t.name,
            t.email_subject.as_ref().map(|s| s.get().as_str()),
            t.email_message.as_ref().map(|s| s.get().as_str()),
            &t.settings,
            &t.matching_rules,
            t.version
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// A template of this account.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn get(&mut self, id: TemplateId) -> Result<Option<Template>> {
        let acct = self.tx.acct();
        let row = sqlx::query_as!(
            TemplateRow,
            "SELECT id, owner_user_id, name, email_subject, email_message, settings, matching_rules, \
             version FROM templates WHERE account_id = $1 AND id = $2 AND deleted_at IS NULL",
            acct,
            id.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(row.map(Template::from))
    }

    /// A template of this account in the Deleted view (UXW-02): deleted, kept, and
    /// restorable.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn get_deleted(&mut self, id: TemplateId) -> Result<Option<Template>> {
        let acct = self.tx.acct();
        let row = sqlx::query_as!(
            TemplateRow,
            "SELECT id, owner_user_id, name, email_subject, email_message, settings, matching_rules, \
             version FROM templates WHERE account_id = $1 AND id = $2 AND deleted_at IS NOT NULL",
            acct,
            id.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(row.map(Template::from))
    }

    /// This account's deleted templates (UXW-02), most recently deleted first.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn list_deleted(&mut self) -> Result<Vec<Template>> {
        let acct = self.tx.acct();
        let rows = sqlx::query_as!(
            TemplateRow,
            "SELECT id, owner_user_id, name, email_subject, email_message, settings, matching_rules, \
             version FROM templates WHERE account_id = $1 AND deleted_at IS NOT NULL \
             ORDER BY deleted_at DESC, id",
            acct
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(rows.into_iter().map(Template::from).collect())
    }

    /// Move a live template to the Deleted view at `version` (UXW-02): it leaves the
    /// list and every read and edit, and keeps its roles, documents and fields for a
    /// restore. Returns the new version.
    ///
    /// # Errors
    ///
    /// `CS-DB-0007` stale version; `CS-DB-0003` no such live template.
    pub async fn trash(&mut self, id: TemplateId, version: Option<i32>) -> Result<i32> {
        let acct = self.tx.acct();
        let new = sqlx::query_scalar!(
            "UPDATE templates SET deleted_at = now(), version = version + 1, updated_at = now() \
             WHERE account_id = $1 AND id = $2 AND deleted_at IS NULL \
             AND ($3::int IS NULL OR version = $3) RETURNING version",
            acct,
            id.0,
            version
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        match new {
            Some(v) => Ok(v),
            None if self.get(id).await?.is_some() => {
                Err(StoreError::StaleVersion { entity: "template" })
            }
            None => Err(StoreError::NotFound { entity: "template" }),
        }
    }

    /// Bring a deleted template back to the list (UXW-02). Returns the new version.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` no such deleted template.
    pub async fn restore(&mut self, id: TemplateId) -> Result<i32> {
        let acct = self.tx.acct();
        sqlx::query_scalar!(
            "UPDATE templates SET deleted_at = NULL, version = version + 1, updated_at = now() \
             WHERE account_id = $1 AND id = $2 AND deleted_at IS NOT NULL RETURNING version",
            acct,
            id.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?
        .ok_or(StoreError::NotFound { entity: "template" })
    }

    /// This account's templates by name.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn list(&mut self) -> Result<Vec<Template>> {
        let acct = self.tx.acct();
        let rows = sqlx::query_as!(
            TemplateRow,
            "SELECT id, owner_user_id, name, email_subject, email_message, settings, matching_rules, \
             version FROM templates WHERE account_id = $1 AND deleted_at IS NULL \
             ORDER BY name, id",
            acct
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(rows.into_iter().map(Template::from).collect())
    }

    /// Rename a template at `version`; returns the new version.
    ///
    /// # Errors
    ///
    /// `CS-DB-0007` stale version; `CS-DB-0003` no such template.
    pub async fn rename(&mut self, id: TemplateId, version: i32, name: &str) -> Result<i32> {
        let acct = self.tx.acct();
        let new = sqlx::query_scalar!(
            "UPDATE templates SET name = $4, version = version + 1, updated_at = now() \
             WHERE account_id = $1 AND id = $2 AND version = $3 AND deleted_at IS NULL \
             RETURNING version",
            acct,
            id.0,
            version,
            name
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        if let Some(v) = new {
            return Ok(v);
        }
        if self.get(id).await?.is_some() {
            Err(StoreError::StaleVersion { entity: "template" })
        } else {
            Err(StoreError::NotFound { entity: "template" })
        }
    }

    /// Add a role.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` when the template is not this account's.
    pub async fn add_role(&mut self, r: &TemplateRole) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "INSERT INTO template_roles (id, account_id, template_id, name, routing_order, \
             recipient_type, default_auth) VALUES ($2, $1, $3, $4, $5, $6, $7)",
            acct,
            r.id.0,
            r.template_id.0,
            r.name,
            r.routing_order,
            r.kind.as_str(),
            &r.default_auth
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// A template's roles in routing order.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn roles(&mut self, template: TemplateId) -> Result<Vec<TemplateRole>> {
        let acct = self.tx.acct();
        let rows = sqlx::query!(
            "SELECT id, template_id, name, routing_order, recipient_type, default_auth \
             FROM template_roles WHERE account_id = $1 AND template_id = $2 ORDER BY routing_order, name",
            acct,
            template.0
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        rows.into_iter()
            .map(|r| {
                Ok(TemplateRole {
                    id: TemplateRoleId(r.id),
                    template_id: TemplateId(r.template_id),
                    name: r.name,
                    routing_order: r.routing_order,
                    kind: RecipientType::parse(&r.recipient_type, "recipient_type")?,
                    default_auth: r.default_auth,
                })
            })
            .collect()
    }

    /// Add a document.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` when the template is not this account's.
    pub async fn add_document(&mut self, d: &TemplateDocument) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "INSERT INTO template_documents (id, account_id, template_id, ord, name, sha256, byte_len, \
             page_count, pages) VALUES ($2, $1, $3, $4, $5, $6, $7, $8, $9)",
            acct,
            d.id.0,
            d.template_id.0,
            d.ord,
            d.name,
            d.sha256.as_slice(),
            d.byte_len,
            d.page_count,
            &d.pages
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// A template's documents in order.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn documents(&mut self, template: TemplateId) -> Result<Vec<TemplateDocument>> {
        let acct = self.tx.acct();
        let rows = sqlx::query!(
            "SELECT id, template_id, ord, name, sha256, byte_len, page_count, pages \
             FROM template_documents WHERE account_id = $1 AND template_id = $2 ORDER BY ord",
            acct,
            template.0
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        rows.into_iter()
            .map(|r| {
                Ok(TemplateDocument {
                    id: TemplateDocumentId(r.id),
                    template_id: TemplateId(r.template_id),
                    ord: r.ord,
                    name: r.name,
                    sha256: hash32(r.sha256, "sha256")?,
                    byte_len: r.byte_len,
                    page_count: r.page_count,
                    pages: r.pages,
                })
            })
            .collect()
    }

    /// Add a role-bound field.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` when the template, document or role is not this account's.
    pub async fn add_field(&mut self, f: &TemplateField) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "INSERT INTO template_fields (id, account_id, template_id, template_document_id, role_id, \
             type, page, x, y, width, height, required, label, spec) \
             VALUES ($2, $1, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
            acct,
            f.id.0,
            f.template_id.0,
            f.template_document_id.0,
            f.role_id.0,
            field_type_text(f.kind)?,
            f.rect.page,
            f.rect.x,
            f.rect.y,
            f.rect.width,
            f.rect.height,
            f.required,
            f.label.as_deref(),
            f.spec.get()
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// A template's fields.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn fields(&mut self, template: TemplateId) -> Result<Vec<TemplateField>> {
        let acct = self.tx.acct();
        let rows = sqlx::query!(
            r#"SELECT id, template_id, template_document_id, role_id, type AS kind, page, x, y,
                      width, height, required, label, spec
                 FROM template_fields WHERE account_id = $1 AND template_id = $2
                ORDER BY template_document_id, page, y, x, id"#,
            acct,
            template.0
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        rows.into_iter()
            .map(|r| {
                Ok(TemplateField {
                    id: TemplateFieldId(r.id),
                    template_id: TemplateId(r.template_id),
                    template_document_id: TemplateDocumentId(r.template_document_id),
                    role_id: TemplateRoleId(r.role_id),
                    kind: field_type_parse(r.kind)?,
                    rect: Rect {
                        page: r.page,
                        x: r.x,
                        y: r.y,
                        width: r.width,
                        height: r.height,
                    },
                    required: r.required,
                    label: r.label,
                    spec: Personal(r.spec),
                })
            })
            .collect()
    }
}

/// Editing (WEB-06): every change raises the template's version, checked against the
/// caller's when it gives one.
impl Templates<'_> {
    /// Raise the version of template `id`, at `version` when given; returns the new one.
    ///
    /// # Errors
    ///
    /// `CS-DB-0007` stale version; `CS-DB-0003` no such template.
    pub async fn bump(&mut self, id: TemplateId, version: Option<i32>) -> Result<i32> {
        let acct = self.tx.acct();
        let new = sqlx::query_scalar!(
            "UPDATE templates SET version = version + 1, updated_at = now() \
             WHERE account_id = $1 AND id = $2 AND ($3::int IS NULL OR version = $3) \
             AND deleted_at IS NULL RETURNING version",
            acct,
            id.0,
            version
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        if let Some(v) = new {
            return Ok(v);
        }
        if self.get(id).await?.is_some() {
            Err(StoreError::StaleVersion { entity: "template" })
        } else {
            Err(StoreError::NotFound { entity: "template" })
        }
    }

    /// Set a template's email subject and message (`None` clears).
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` no such template.
    pub async fn set_email(
        &mut self,
        id: TemplateId,
        subject: Option<&Personal<String>>,
        message: Option<&Personal<String>>,
    ) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE templates SET email_subject = $3, email_message = $4 \
             WHERE account_id = $1 AND id = $2",
            acct,
            id.0,
            subject.map(Personal::get),
            message.map(Personal::get)
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        super::affected(done.rows_affected(), "template")
    }

    /// Change a role's name, routing order, type and default authentication.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` no such role in the template; `CS-DB-0006` a name already used.
    pub async fn update_role(&mut self, r: &TemplateRole) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE template_roles SET name = $4, routing_order = $5, recipient_type = $6, \
             default_auth = $7 WHERE account_id = $1 AND id = $2 AND template_id = $3",
            acct,
            r.id.0,
            r.template_id.0,
            r.name,
            r.routing_order,
            r.kind.as_str(),
            &r.default_auth
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        super::affected(done.rows_affected(), "template role")
    }

    /// Remove a role and the fields bound to it.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` no such role in the template.
    pub async fn delete_role(&mut self, template: TemplateId, role: TemplateRoleId) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "DELETE FROM template_fields WHERE account_id = $1 AND template_id = $2 AND role_id = $3",
            acct,
            template.0,
            role.0
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        let done = sqlx::query!(
            "DELETE FROM template_roles WHERE account_id = $1 AND template_id = $2 AND id = $3",
            acct,
            template.0,
            role.0
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        super::affected(done.rows_affected(), "template role")
    }

    /// Remove a document and the fields on it (its blob stays: write-once).
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` no such document in the template.
    pub async fn delete_document(
        &mut self,
        template: TemplateId,
        document: TemplateDocumentId,
    ) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "DELETE FROM template_fields WHERE account_id = $1 AND template_id = $2 \
             AND template_document_id = $3",
            acct,
            template.0,
            document.0
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        let done = sqlx::query!(
            "DELETE FROM template_documents WHERE account_id = $1 AND template_id = $2 AND id = $3",
            acct,
            template.0,
            document.0
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        super::affected(done.rows_affected(), "template document")
    }

    /// Replace a field (its id names it) within its template.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` no such field; `CS-DB-0008` a document or role of another template.
    pub async fn replace_field(&mut self, f: &TemplateField) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE template_fields SET template_document_id = $4, role_id = $5, type = $6, \
             page = $7, x = $8, y = $9, width = $10, height = $11, required = $12, label = $13, \
             spec = $14 WHERE account_id = $1 AND id = $2 AND template_id = $3",
            acct,
            f.id.0,
            f.template_id.0,
            f.template_document_id.0,
            f.role_id.0,
            field_type_text(f.kind)?,
            f.rect.page,
            f.rect.x,
            f.rect.y,
            f.rect.width,
            f.rect.height,
            f.required,
            f.label.as_deref(),
            f.spec.get()
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        super::affected(done.rows_affected(), "template field")
    }

    /// Remove a field.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` no such field in the template.
    pub async fn delete_field(
        &mut self,
        template: TemplateId,
        field: TemplateFieldId,
    ) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "DELETE FROM template_fields WHERE account_id = $1 AND template_id = $2 AND id = $3",
            acct,
            template.0,
            field.0
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        super::affected(done.rows_affected(), "template field")
    }

    /// Delete a template for good, live or deleted, with its fields, documents, roles
    /// and shares (the API purges only a deleted one, UXW-02). Envelopes made from it
    /// are copies and keep everything.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` no such template.
    pub async fn delete(&mut self, id: TemplateId) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "DELETE FROM template_fields WHERE account_id = $1 AND template_id = $2",
            acct,
            id.0
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        sqlx::query!(
            "DELETE FROM template_documents WHERE account_id = $1 AND template_id = $2",
            acct,
            id.0
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        sqlx::query!(
            "DELETE FROM template_roles WHERE account_id = $1 AND template_id = $2",
            acct,
            id.0
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        sqlx::query!(
            "DELETE FROM template_shares WHERE account_id = $1 AND template_id = $2",
            acct,
            id.0
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        let done = sqlx::query!(
            "DELETE FROM templates WHERE account_id = $1 AND id = $2",
            acct,
            id.0
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        super::affected(done.rows_affected(), "template")
    }
}

/// Sharing and Favourites (UXW-06).
impl Templates<'_> {
    /// What `member` may do with a template of this account, live or deleted: `Owner`
    /// for its owner or an administrator (`admin`), otherwise what its shares give, or
    /// `None` (deny by default).
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn access(
        &mut self,
        id: TemplateId,
        member: UserId,
        admin: bool,
    ) -> Result<Option<TemplateAccess>> {
        let acct = self.tx.acct();
        let row = sqlx::query!(
            "SELECT owner_user_id, openseal_template_share_right($1, id, $3) AS share_right \
             FROM templates WHERE account_id = $1 AND id = $2",
            acct,
            id.0,
            member.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(row.and_then(|r| {
            if admin || r.owner_user_id == member.0 {
                Some(TemplateAccess::Owner)
            } else {
                TemplateAccess::from_right(r.share_right.as_deref())
            }
        }))
    }

    /// The live templates `member` may use, by name, narrowed to `view`.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn list_for(
        &mut self,
        member: UserId,
        admin: bool,
        view: TemplateView,
    ) -> Result<Vec<ListedTemplate>> {
        let acct = self.tx.acct();
        let rows = sqlx::query!(
            "SELECT t.id, t.owner_user_id, t.name, t.email_subject, t.email_message, t.settings, \
             t.matching_rules, t.version, r.share_right, \
             EXISTS (SELECT 1 FROM template_favourites f WHERE f.account_id = $1 \
                     AND f.template_id = t.id AND f.user_id = $2) AS \"favourite!\", \
             EXISTS (SELECT 1 FROM template_shares s WHERE s.account_id = $1 \
                     AND s.template_id = t.id) AS \"shared!\" \
             FROM templates t \
             CROSS JOIN LATERAL (SELECT openseal_template_share_right($1, t.id, $2) AS share_right) r \
             WHERE t.account_id = $1 AND t.deleted_at IS NULL \
             AND ($3 OR t.owner_user_id = $2 OR r.share_right IS NOT NULL) \
             AND CASE $4::text \
                 WHEN 'owned' THEN t.owner_user_id = $2 \
                 WHEN 'shared' THEN t.owner_user_id <> $2 AND r.share_right IS NOT NULL \
                 WHEN 'favourites' THEN EXISTS (SELECT 1 FROM template_favourites f \
                     WHERE f.account_id = $1 AND f.template_id = t.id AND f.user_id = $2) \
                 ELSE true END \
             ORDER BY t.name, t.id",
            acct,
            member.0,
            admin,
            view.as_str()
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(rows
            .into_iter()
            .filter_map(|r| {
                let access = if admin || r.owner_user_id == member.0 {
                    TemplateAccess::Owner
                } else {
                    TemplateAccess::from_right(r.share_right.as_deref())?
                };
                Some(ListedTemplate {
                    template: Template::from(TemplateRow {
                        id: r.id,
                        owner_user_id: r.owner_user_id,
                        name: r.name,
                        email_subject: r.email_subject,
                        email_message: r.email_message,
                        settings: r.settings,
                        matching_rules: r.matching_rules,
                        version: r.version,
                    }),
                    access,
                    favourite: r.favourite,
                    shared: r.shared,
                })
            })
            .collect())
    }

    /// A template's shares, users first, then groups, then the account.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0010` a row with no target.
    pub async fn shares(&mut self, id: TemplateId) -> Result<Vec<TemplateShare>> {
        let acct = self.tx.acct();
        let rows = sqlx::query!(
            "SELECT id, user_id, group_id, whole_account, can_edit FROM template_shares \
             WHERE account_id = $1 AND template_id = $2 \
             ORDER BY whole_account, group_id NULLS FIRST, created_at, id",
            acct,
            id.0
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        rows.into_iter()
            .map(|r| {
                let target = match (r.user_id, r.group_id, r.whole_account) {
                    (Some(u), None, false) => ShareTarget::User(UserId(u)),
                    (None, Some(g), false) => ShareTarget::Group(GroupId(g)),
                    (None, None, true) => ShareTarget::Account,
                    _ => {
                        return Err(StoreError::Corrupt {
                            column: "template_shares",
                        });
                    }
                };
                Ok(TemplateShare {
                    id: TemplateShareId(r.id),
                    target,
                    can_edit: r.can_edit,
                })
            })
            .collect()
    }

    /// Replace a template's shares with `shares` (the whole set, as the share panel
    /// saves it).
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` a user who is not a member, or a group not of this account;
    /// `CS-DB-0006` the same target twice.
    pub async fn replace_shares(&mut self, id: TemplateId, shares: &[TemplateShare]) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "DELETE FROM template_shares WHERE account_id = $1 AND template_id = $2",
            acct,
            id.0
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        for s in shares {
            let (user, group, account) = match s.target {
                ShareTarget::User(u) => (Some(u.0), None, false),
                ShareTarget::Group(g) => (None, Some(g.0), false),
                ShareTarget::Account => (None, None, true),
            };
            sqlx::query!(
                "INSERT INTO template_shares (id, account_id, template_id, user_id, group_id, \
                 whole_account, can_edit) VALUES ($2, $1, $3, $4, $5, $6, $7)",
                acct,
                s.id.0,
                id.0,
                user,
                group,
                account,
                s.can_edit
            )
            .execute(self.tx.conn())
            .await
            .map_err(db)?;
        }
        Ok(())
    }

    /// Star (`on`) or unstar a template for `member`; idempotent.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` not a member, or no such template.
    pub async fn set_favourite(&mut self, id: TemplateId, member: UserId, on: bool) -> Result<()> {
        let acct = self.tx.acct();
        if on {
            sqlx::query!(
                "INSERT INTO template_favourites (account_id, user_id, template_id) \
                 VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                acct,
                member.0,
                id.0
            )
            .execute(self.tx.conn())
            .await
            .map_err(db)?;
        } else {
            sqlx::query!(
                "DELETE FROM template_favourites WHERE account_id = $1 AND user_id = $2 \
                 AND template_id = $3",
                acct,
                member.0,
                id.0
            )
            .execute(self.tx.conn())
            .await
            .map_err(db)?;
        }
        Ok(())
    }

    /// Whether `member` starred a template.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn is_favourite(&mut self, id: TemplateId, member: UserId) -> Result<bool> {
        let acct = self.tx.acct();
        sqlx::query_scalar!(
            "SELECT EXISTS (SELECT 1 FROM template_favourites WHERE account_id = $1 \
             AND user_id = $2 AND template_id = $3) AS \"e!\"",
            acct,
            member.0,
            id.0
        )
        .fetch_one(self.tx.conn())
        .await
        .map_err(db)
    }

    /// This account's groups by name, with their member counts: whom a template can be
    /// shared with.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn groups(&mut self) -> Result<Vec<Group>> {
        let acct = self.tx.acct();
        let rows = sqlx::query!(
            "SELECT g.id, g.name, (SELECT count(*) FROM group_members m \
             WHERE m.account_id = $1 AND m.group_id = g.id) AS \"members!\" \
             FROM groups g WHERE g.account_id = $1 ORDER BY g.name, g.id",
            acct
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(rows
            .into_iter()
            .map(|r| Group {
                id: GroupId(r.id),
                name: r.name,
                members: r.members,
            })
            .collect())
    }
}
