//! Templates (docs/22 §7): roles, documents and role-bound fields. Envelopes copy from
//! them; nothing references a template after creation except `envelopes.template_ids`.

use casual_sign_audit::Personal;
use casual_sign_model::FieldType;
use uuid::Uuid;

use super::fields::{Rect, field_type_parse, field_type_text};
use super::hash32;
use super::recipients::RecipientType;
use crate::error::{Result, StoreError, db};
use crate::ids::{TemplateDocumentId, TemplateFieldId, TemplateId, TemplateRoleId, UserId};
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
             version FROM templates WHERE account_id = $1 AND id = $2",
            acct,
            id.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(row.map(Template::from))
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
             version FROM templates WHERE account_id = $1 ORDER BY name, id",
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
             WHERE account_id = $1 AND id = $2 AND version = $3 RETURNING version",
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
             RETURNING version",
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

    /// Delete a template with its fields, documents, roles and shares. Envelopes made
    /// from it are copies and keep everything.
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
