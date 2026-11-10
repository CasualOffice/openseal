//! Fields placed on documents (docs/22 §6) and the values recipients gave them. Values
//! are document content: wrapped in [`Personal`] so `Debug` never prints them.

use casual_sign_audit::Personal;
use casual_sign_model::FieldType;
use rust_decimal::Decimal;
use sqlx::postgres::PgRow;
use time::OffsetDateTime;

use super::{col, hash_col};
use crate::error::{Result, StoreError, db};
use crate::ids::{DocumentId, EnvelopeId, FieldId, RecipientId};
use crate::store::TenantTx;

/// The stored text of a field type (its serde name, as in the public API).
pub(crate) fn field_type_text(t: FieldType) -> Result<String> {
    match serde_json::to_value(t) {
        Ok(serde_json::Value::String(s)) => Ok(s),
        _ => Err(StoreError::Corrupt { column: "type" }),
    }
}

/// A field type from its stored text.
pub(crate) fn field_type_parse(s: String) -> Result<FieldType> {
    serde_json::from_value(serde_json::Value::String(s))
        .map_err(|_| StoreError::Corrupt { column: "type" })
}

/// Where a field sits: displayed page space, points, origin top-left (ADR-019).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    /// Page, from 1.
    pub page: i32,
    /// Left.
    pub x: Decimal,
    /// Top.
    pub y: Decimal,
    /// Width.
    pub width: Decimal,
    /// Height.
    pub height: Decimal,
}

/// A field on an envelope document.
#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    /// Host-minted id.
    pub id: FieldId,
    /// Envelope.
    pub envelope_id: EnvelopeId,
    /// Document.
    pub document_id: DocumentId,
    /// Recipient it belongs to.
    pub recipient_id: RecipientId,
    /// Type.
    pub kind: FieldType,
    /// Placement.
    pub rect: Rect,
    /// Required.
    pub required: bool,
    /// Read only.
    pub read_only: bool,
    /// Locked.
    pub locked: bool,
    /// Data label.
    pub label: Option<String>,
    /// The rest of docs/22 §6 as the model serializes it (may hold sender-typed defaults:
    /// document content).
    pub spec: Personal<serde_json::Value>,
}

/// A value given to a field.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldValue {
    /// Field.
    pub field_id: FieldId,
    /// Envelope.
    pub envelope_id: EnvelopeId,
    /// Recipient who gave it (or for whom the server stamped it).
    pub recipient_id: RecipientId,
    /// The value (document content).
    pub value: Personal<serde_json::Value>,
    /// SHA-256 of the value as the audit chain records it.
    pub value_sha256: [u8; 32],
    /// When.
    pub set_at: OffsetDateTime,
}

const SELECT: &str = "SELECT id, envelope_id, document_id, recipient_id, type, page, x, y, width, \
     height, required, read_only, locked, label, spec FROM fields WHERE account_id = $1";

fn field(r: &PgRow) -> Result<Field> {
    Ok(Field {
        id: FieldId(col(r, "id")?),
        envelope_id: EnvelopeId(col(r, "envelope_id")?),
        document_id: DocumentId(col(r, "document_id")?),
        recipient_id: RecipientId(col(r, "recipient_id")?),
        kind: field_type_parse(col(r, "type")?)?,
        rect: Rect {
            page: col(r, "page")?,
            x: col(r, "x")?,
            y: col(r, "y")?,
            width: col(r, "width")?,
            height: col(r, "height")?,
        },
        required: col(r, "required")?,
        read_only: col(r, "read_only")?,
        locked: col(r, "locked")?,
        label: col(r, "label")?,
        spec: Personal(col(r, "spec")?),
    })
}

fn value(r: &PgRow) -> Result<FieldValue> {
    Ok(FieldValue {
        field_id: FieldId(col(r, "field_id")?),
        envelope_id: EnvelopeId(col(r, "envelope_id")?),
        recipient_id: RecipientId(col(r, "recipient_id")?),
        value: Personal(col(r, "value")?),
        value_sha256: hash_col(r, "value_sha256")?,
        set_at: col(r, "set_at")?,
    })
}

/// Fields of this account. Reached through `TenantTx::fields`.
#[derive(Debug)]
pub struct Fields<'t> {
    pub(crate) tx: &'t mut TenantTx,
}

impl Fields<'_> {
    /// Place a field.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` when the envelope, document or recipient is not this account's, or
    /// the geometry is out of bounds.
    pub async fn insert(&mut self, f: &Field) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query(
            "INSERT INTO fields (id, account_id, envelope_id, document_id, recipient_id, type, page, \
             x, y, width, height, required, read_only, locked, label, spec) \
             VALUES ($2, $1, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)",
        )
        .bind(acct)
        .bind(f.id.0)
        .bind(f.envelope_id.0)
        .bind(f.document_id.0)
        .bind(f.recipient_id.0)
        .bind(field_type_text(f.kind)?)
        .bind(f.rect.page)
        .bind(f.rect.x)
        .bind(f.rect.y)
        .bind(f.rect.width)
        .bind(f.rect.height)
        .bind(f.required)
        .bind(f.read_only)
        .bind(f.locked)
        .bind(&f.label)
        .bind(f.spec.get())
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// A field of this account.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn get(&mut self, id: FieldId) -> Result<Option<Field>> {
        let acct = self.tx.acct();
        let sql = format!("{SELECT} AND id = $2");
        let row = sqlx::query(&sql)
            .bind(acct)
            .bind(id.0)
            .fetch_optional(self.tx.conn())
            .await
            .map_err(db)?;
        row.as_ref().map(field).transpose()
    }

    /// An envelope's fields.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn list(&mut self, envelope: EnvelopeId) -> Result<Vec<Field>> {
        let acct = self.tx.acct();
        let sql = format!("{SELECT} AND envelope_id = $2 ORDER BY document_id, page, y, x, id");
        let rows = sqlx::query(&sql)
            .bind(acct)
            .bind(envelope.0)
            .fetch_all(self.tx.conn())
            .await
            .map_err(db)?;
        rows.iter().map(field).collect()
    }

    /// Remove a field from an envelope that is still a draft.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when this account has no such field in a draft envelope.
    pub async fn delete_from_draft(&mut self, id: FieldId) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query(
            "DELETE FROM fields f USING envelopes e \
             WHERE f.account_id = $1 AND f.id = $2 AND e.account_id = $1 \
               AND e.id = f.envelope_id AND e.status = 'draft'",
        )
        .bind(acct)
        .bind(id.0)
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        if done.rows_affected() == 0 {
            return Err(StoreError::NotFound { entity: "field" });
        }
        Ok(())
    }

    /// Set (or replace) a field's value. The field must be this account's and belong to
    /// the recipient named.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when this account has no such field for that recipient.
    pub async fn set_value(&mut self, v: &FieldValue) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query(
            "INSERT INTO field_values (field_id, account_id, envelope_id, recipient_id, value, \
             value_sha256, set_at) \
             SELECT f.id, f.account_id, f.envelope_id, f.recipient_id, $5, $6, $7 FROM fields f \
             WHERE f.account_id = $1 AND f.id = $2 AND f.envelope_id = $3 AND f.recipient_id = $4 \
             ON CONFLICT (account_id, field_id) DO UPDATE SET value = EXCLUDED.value, \
               value_sha256 = EXCLUDED.value_sha256, set_at = EXCLUDED.set_at \
             WHERE field_values.account_id = $1",
        )
        .bind(acct)
        .bind(v.field_id.0)
        .bind(v.envelope_id.0)
        .bind(v.recipient_id.0)
        .bind(v.value.get())
        .bind(v.value_sha256.as_slice())
        .bind(v.set_at)
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        if done.rows_affected() == 0 {
            return Err(StoreError::NotFound { entity: "field" });
        }
        Ok(())
    }

    /// A field's value.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn value(&mut self, id: FieldId) -> Result<Option<FieldValue>> {
        let acct = self.tx.acct();
        let row = sqlx::query(
            "SELECT field_id, envelope_id, recipient_id, value, value_sha256, set_at \
             FROM field_values WHERE account_id = $1 AND field_id = $2",
        )
        .bind(acct)
        .bind(id.0)
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        row.as_ref().map(value).transpose()
    }

    /// Every value given on an envelope.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn values(&mut self, envelope: EnvelopeId) -> Result<Vec<FieldValue>> {
        let acct = self.tx.acct();
        let rows = sqlx::query(
            "SELECT field_id, envelope_id, recipient_id, value, value_sha256, set_at \
             FROM field_values WHERE account_id = $1 AND envelope_id = $2 ORDER BY field_id",
        )
        .bind(acct)
        .bind(envelope.0)
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        rows.iter().map(value).collect()
    }
}
