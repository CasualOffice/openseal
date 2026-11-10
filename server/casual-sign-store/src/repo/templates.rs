//! Templates (docs/22 §7): roles, documents and role-bound fields. Envelopes copy from
//! them; nothing references a template after creation except `envelopes.template_ids`.

use casual_sign_audit::Personal;
use casual_sign_model::FieldType;
use sqlx::postgres::PgRow;

use super::fields::{Rect, field_type_parse, field_type_text};
use super::recipients::RecipientType;
use super::{col, hash_col};
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

fn template(r: &PgRow) -> Result<Template> {
    Ok(Template {
        id: TemplateId(col(r, "id")?),
        owner_user_id: UserId(col(r, "owner_user_id")?),
        name: col(r, "name")?,
        email_subject: col::<Option<String>>(r, "email_subject")?.map(Personal),
        email_message: col::<Option<String>>(r, "email_message")?.map(Personal),
        settings: col(r, "settings")?,
        matching_rules: col(r, "matching_rules")?,
        version: col(r, "version")?,
    })
}

const SELECT: &str = "SELECT id, owner_user_id, name, email_subject, email_message, settings, \
     matching_rules, version FROM templates WHERE account_id = $1";

impl Templates<'_> {
    /// Create a template.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` an owner who is not a member of this account.
    pub async fn insert(&mut self, t: &Template) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query(
            "INSERT INTO templates (id, account_id, owner_user_id, name, email_subject, email_message, \
             settings, matching_rules, version) VALUES ($2, $1, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(acct)
        .bind(t.id.0)
        .bind(t.owner_user_id.0)
        .bind(&t.name)
        .bind(t.email_subject.as_ref().map(|s| s.get().as_str()))
        .bind(t.email_message.as_ref().map(|s| s.get().as_str()))
        .bind(&t.settings)
        .bind(&t.matching_rules)
        .bind(t.version)
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// A template of this account.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn get(&mut self, id: TemplateId) -> Result<Option<Template>> {
        let acct = self.tx.acct();
        let sql = format!("{SELECT} AND id = $2");
        let row = sqlx::query(&sql)
            .bind(acct)
            .bind(id.0)
            .fetch_optional(self.tx.conn())
            .await
            .map_err(db)?;
        row.as_ref().map(template).transpose()
    }

    /// This account's templates by name.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn list(&mut self) -> Result<Vec<Template>> {
        let acct = self.tx.acct();
        let sql = format!("{SELECT} ORDER BY name, id");
        let rows = sqlx::query(&sql)
            .bind(acct)
            .fetch_all(self.tx.conn())
            .await
            .map_err(db)?;
        rows.iter().map(template).collect()
    }

    /// Rename a template at `version`; returns the new version.
    ///
    /// # Errors
    ///
    /// `CS-DB-0007` stale version; `CS-DB-0003` no such template.
    pub async fn rename(&mut self, id: TemplateId, version: i32, name: &str) -> Result<i32> {
        let acct = self.tx.acct();
        let row = sqlx::query(
            "UPDATE templates SET name = $4, version = version + 1, updated_at = now() \
             WHERE account_id = $1 AND id = $2 AND version = $3 RETURNING version",
        )
        .bind(acct)
        .bind(id.0)
        .bind(version)
        .bind(name)
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        if let Some(r) = row {
            return col(&r, "version");
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
        sqlx::query(
            "INSERT INTO template_roles (id, account_id, template_id, name, routing_order, \
             recipient_type, default_auth) VALUES ($2, $1, $3, $4, $5, $6, $7)",
        )
        .bind(acct)
        .bind(r.id.0)
        .bind(r.template_id.0)
        .bind(&r.name)
        .bind(r.routing_order)
        .bind(r.kind.as_str())
        .bind(&r.default_auth)
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
        let rows = sqlx::query(
            "SELECT id, template_id, name, routing_order, recipient_type, default_auth \
             FROM template_roles WHERE account_id = $1 AND template_id = $2 ORDER BY routing_order, name",
        )
        .bind(acct)
        .bind(template.0)
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        rows.iter()
            .map(|r| {
                let kind: String = col(r, "recipient_type")?;
                Ok(TemplateRole {
                    id: TemplateRoleId(col(r, "id")?),
                    template_id: TemplateId(col(r, "template_id")?),
                    name: col(r, "name")?,
                    routing_order: col(r, "routing_order")?,
                    kind: RecipientType::parse(&kind, "recipient_type")?,
                    default_auth: col(r, "default_auth")?,
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
        sqlx::query(
            "INSERT INTO template_documents (id, account_id, template_id, ord, name, sha256, byte_len, \
             page_count, pages) VALUES ($2, $1, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(acct)
        .bind(d.id.0)
        .bind(d.template_id.0)
        .bind(d.ord)
        .bind(&d.name)
        .bind(d.sha256.as_slice())
        .bind(d.byte_len)
        .bind(d.page_count)
        .bind(&d.pages)
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
        let rows = sqlx::query(
            "SELECT id, template_id, ord, name, sha256, byte_len, page_count, pages \
             FROM template_documents WHERE account_id = $1 AND template_id = $2 ORDER BY ord",
        )
        .bind(acct)
        .bind(template.0)
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        rows.iter()
            .map(|r| {
                Ok(TemplateDocument {
                    id: TemplateDocumentId(col(r, "id")?),
                    template_id: TemplateId(col(r, "template_id")?),
                    ord: col(r, "ord")?,
                    name: col(r, "name")?,
                    sha256: hash_col(r, "sha256")?,
                    byte_len: col(r, "byte_len")?,
                    page_count: col(r, "page_count")?,
                    pages: col(r, "pages")?,
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
        sqlx::query(
            "INSERT INTO template_fields (id, account_id, template_id, template_document_id, role_id, \
             type, page, x, y, width, height, required, label, spec) \
             VALUES ($2, $1, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
        )
        .bind(acct)
        .bind(f.id.0)
        .bind(f.template_id.0)
        .bind(f.template_document_id.0)
        .bind(f.role_id.0)
        .bind(field_type_text(f.kind)?)
        .bind(f.rect.page)
        .bind(f.rect.x)
        .bind(f.rect.y)
        .bind(f.rect.width)
        .bind(f.rect.height)
        .bind(f.required)
        .bind(&f.label)
        .bind(f.spec.get())
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
        let rows = sqlx::query(
            "SELECT id, template_id, template_document_id, role_id, type, page, x, y, width, height, \
             required, label, spec FROM template_fields WHERE account_id = $1 AND template_id = $2 \
             ORDER BY template_document_id, page, y, x, id",
        )
        .bind(acct)
        .bind(template.0)
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        rows.iter()
            .map(|r| {
                Ok(TemplateField {
                    id: TemplateFieldId(col(r, "id")?),
                    template_id: TemplateId(col(r, "template_id")?),
                    template_document_id: TemplateDocumentId(col(r, "template_document_id")?),
                    role_id: TemplateRoleId(col(r, "role_id")?),
                    kind: field_type_parse(col(r, "type")?)?,
                    rect: Rect {
                        page: col(r, "page")?,
                        x: col(r, "x")?,
                        y: col(r, "y")?,
                        width: col(r, "width")?,
                        height: col(r, "height")?,
                    },
                    required: col(r, "required")?,
                    label: col(r, "label")?,
                    spec: Personal(col(r, "spec")?),
                })
            })
            .collect()
    }
}
