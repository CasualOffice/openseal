//! Fields placed on documents (docs/22 §6) and the values recipients gave them. Values
//! are document content: wrapped in [`Personal`] so `Debug` never prints them.

use casual_sign_audit::Personal;
use casual_sign_model::FieldType;
use rust_decimal::Decimal;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{affected, hash32};
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

/// A field row as selected.
struct FieldRow {
    id: Uuid,
    envelope_id: Uuid,
    document_id: Uuid,
    recipient_id: Uuid,
    kind: String,
    page: i32,
    x: Decimal,
    y: Decimal,
    width: Decimal,
    height: Decimal,
    required: bool,
    read_only: bool,
    locked: bool,
    label: Option<String>,
    spec: serde_json::Value,
}

impl TryFrom<FieldRow> for Field {
    type Error = StoreError;
    fn try_from(r: FieldRow) -> Result<Self> {
        Ok(Self {
            id: FieldId(r.id),
            envelope_id: EnvelopeId(r.envelope_id),
            document_id: DocumentId(r.document_id),
            recipient_id: RecipientId(r.recipient_id),
            kind: field_type_parse(r.kind)?,
            rect: Rect {
                page: r.page,
                x: r.x,
                y: r.y,
                width: r.width,
                height: r.height,
            },
            required: r.required,
            read_only: r.read_only,
            locked: r.locked,
            label: r.label,
            spec: Personal(r.spec),
        })
    }
}

/// A value row as selected.
struct ValueRow {
    field_id: Uuid,
    envelope_id: Uuid,
    recipient_id: Uuid,
    value: serde_json::Value,
    value_sha256: Vec<u8>,
    set_at: OffsetDateTime,
}

impl TryFrom<ValueRow> for FieldValue {
    type Error = StoreError;
    fn try_from(r: ValueRow) -> Result<Self> {
        Ok(Self {
            field_id: FieldId(r.field_id),
            envelope_id: EnvelopeId(r.envelope_id),
            recipient_id: RecipientId(r.recipient_id),
            value: Personal(r.value),
            value_sha256: hash32(r.value_sha256, "value_sha256")?,
            set_at: r.set_at,
        })
    }
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
        sqlx::query!(
            "INSERT INTO fields (id, account_id, envelope_id, document_id, recipient_id, type, page, \
             x, y, width, height, required, read_only, locked, label, spec) \
             VALUES ($2, $1, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)",
            acct,
            f.id.0,
            f.envelope_id.0,
            f.document_id.0,
            f.recipient_id.0,
            field_type_text(f.kind)?,
            f.rect.page,
            f.rect.x,
            f.rect.y,
            f.rect.width,
            f.rect.height,
            f.required,
            f.read_only,
            f.locked,
            f.label.as_deref(),
            f.spec.get()
        )
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
        let row = sqlx::query_as!(
            FieldRow,
            r#"SELECT id, envelope_id, document_id, recipient_id, type AS kind, page, x, y, width,
                      height, required, read_only, locked, label, spec
                 FROM fields WHERE account_id = $1 AND id = $2"#,
            acct,
            id.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        row.map(Field::try_from).transpose()
    }

    /// An envelope's fields.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn list(&mut self, envelope: EnvelopeId) -> Result<Vec<Field>> {
        let acct = self.tx.acct();
        let rows = sqlx::query_as!(
            FieldRow,
            r#"SELECT id, envelope_id, document_id, recipient_id, type AS kind, page, x, y, width,
                      height, required, read_only, locked, label, spec
                 FROM fields WHERE account_id = $1 AND envelope_id = $2
                ORDER BY document_id, page, y, x, id"#,
            acct,
            envelope.0
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        rows.into_iter().map(Field::try_from).collect()
    }

    /// Remove a field from an envelope that is still a draft.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when this account has no such field in a draft envelope.
    pub async fn delete_from_draft(&mut self, id: FieldId) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "DELETE FROM fields f USING envelopes e \
             WHERE f.account_id = $1 AND f.id = $2 AND e.account_id = $1 \
               AND e.id = f.envelope_id AND e.status = 'draft'",
            acct,
            id.0
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        affected(done.rows_affected(), "field")
    }

    /// Set (or replace) a field's value. The field must be this account's and belong to
    /// the recipient named.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when this account has no such field for that recipient.
    pub async fn set_value(&mut self, v: &FieldValue) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "INSERT INTO field_values (field_id, account_id, envelope_id, recipient_id, value, \
             value_sha256, set_at) \
             SELECT f.id, f.account_id, f.envelope_id, f.recipient_id, $5, $6, $7 FROM fields f \
             WHERE f.account_id = $1 AND f.id = $2 AND f.envelope_id = $3 AND f.recipient_id = $4 \
             ON CONFLICT (account_id, field_id) DO UPDATE SET value = EXCLUDED.value, \
               value_sha256 = EXCLUDED.value_sha256, set_at = EXCLUDED.set_at \
             WHERE field_values.account_id = $1",
            acct,
            v.field_id.0,
            v.envelope_id.0,
            v.recipient_id.0,
            v.value.get(),
            v.value_sha256.as_slice(),
            v.set_at
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        affected(done.rows_affected(), "field")
    }

    /// A field's value.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn value(&mut self, id: FieldId) -> Result<Option<FieldValue>> {
        let acct = self.tx.acct();
        let row = sqlx::query_as!(
            ValueRow,
            "SELECT field_id, envelope_id, recipient_id, value, value_sha256, set_at \
             FROM field_values WHERE account_id = $1 AND field_id = $2",
            acct,
            id.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        row.map(FieldValue::try_from).transpose()
    }

    /// Every value given on an envelope.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn values(&mut self, envelope: EnvelopeId) -> Result<Vec<FieldValue>> {
        let acct = self.tx.acct();
        let rows = sqlx::query_as!(
            ValueRow,
            "SELECT field_id, envelope_id, recipient_id, value, value_sha256, set_at \
             FROM field_values WHERE account_id = $1 AND envelope_id = $2 ORDER BY field_id",
            acct,
            envelope.0
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        rows.into_iter().map(FieldValue::try_from).collect()
    }
}
