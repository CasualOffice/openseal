//! Documents and their immutable versions (docs/22 §4). A version's bytes live in the blob
//! store under their SHA-256; the row is the reference.

use sqlx::postgres::PgRow;
use time::OffsetDateTime;

use super::{col, hash_col, text_enum};
use crate::error::{Result, StoreError, db};
use crate::ids::{DocumentId, DocumentVersionId, EnvelopeId};
use crate::store::TenantTx;

text_enum!(
    /// What a document version is (docs/22 §4).
    VersionKind {
        /// As uploaded.
        Original = "original",
        /// Converted and admitted; what signers are shown.
        Normalized = "normalized",
        /// Field values flattened in.
        Flattened = "flattened",
        /// Sealed.
        Sealed = "sealed",
    }
);

/// A document in an envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    /// Id.
    pub id: DocumentId,
    /// Envelope.
    pub envelope_id: EnvelopeId,
    /// Position, from 0.
    pub ord: i32,
    /// Display name; never a path.
    pub name: String,
}

/// A new version of a document.
#[derive(Debug, Clone, PartialEq)]
pub struct NewVersion {
    /// Host-minted id.
    pub id: DocumentVersionId,
    /// Document.
    pub document_id: DocumentId,
    /// Kind.
    pub kind: VersionKind,
    /// SHA-256 of the bytes, which is the blob key.
    pub sha256: [u8; 32],
    /// Length of the bytes.
    pub byte_len: i64,
    /// Pages.
    pub page_count: i32,
    /// Admission report, for `normalized`.
    pub admission_report: Option<serde_json::Value>,
    /// Page geometry.
    pub pages: serde_json::Value,
}

/// A stored version.
#[derive(Debug, Clone, PartialEq)]
pub struct Version {
    /// The version as given.
    pub version: NewVersion,
    /// Recorded.
    pub created_at: OffsetDateTime,
}

/// Documents of this account. Reached through `TenantTx::documents`.
#[derive(Debug)]
pub struct Documents<'t> {
    pub(crate) tx: &'t mut TenantTx,
}

fn document(r: &PgRow) -> Result<Document> {
    Ok(Document {
        id: DocumentId(col(r, "id")?),
        envelope_id: EnvelopeId(col(r, "envelope_id")?),
        ord: col(r, "ord")?,
        name: col(r, "name")?,
    })
}

fn version(r: &PgRow) -> Result<Version> {
    let kind: String = col(r, "kind")?;
    Ok(Version {
        version: NewVersion {
            id: DocumentVersionId(col(r, "id")?),
            document_id: DocumentId(col(r, "document_id")?),
            kind: VersionKind::parse(&kind, "kind")?,
            sha256: hash_col(r, "sha256")?,
            byte_len: col(r, "byte_len")?,
            page_count: col(r, "page_count")?,
            admission_report: col(r, "admission_report")?,
            pages: col(r, "pages")?,
        },
        created_at: col(r, "created_at")?,
    })
}

const VERSION_SELECT: &str = "SELECT id, document_id, kind, sha256, byte_len, page_count, \
     admission_report, pages, created_at FROM document_versions WHERE account_id = $1";

impl Documents<'_> {
    /// Add a document to an envelope of this account.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` when the envelope is not this account's; `CS-DB-0006` duplicate id or
    /// position.
    pub async fn insert(&mut self, d: &Document) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query(
            "INSERT INTO documents (id, account_id, envelope_id, ord, name) VALUES ($2, $1, $3, $4, $5)",
        )
        .bind(acct)
        .bind(d.id.0)
        .bind(d.envelope_id.0)
        .bind(d.ord)
        .bind(&d.name)
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// A document of this account.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn get(&mut self, id: DocumentId) -> Result<Option<Document>> {
        let acct = self.tx.acct();
        let row = sqlx::query(
            "SELECT id, envelope_id, ord, name FROM documents WHERE account_id = $1 AND id = $2",
        )
        .bind(acct)
        .bind(id.0)
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        row.as_ref().map(document).transpose()
    }

    /// An envelope's documents, in order.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn list(&mut self, envelope: EnvelopeId) -> Result<Vec<Document>> {
        let acct = self.tx.acct();
        let rows = sqlx::query(
            "SELECT id, envelope_id, ord, name FROM documents \
             WHERE account_id = $1 AND envelope_id = $2 ORDER BY ord",
        )
        .bind(acct)
        .bind(envelope.0)
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        rows.iter().map(document).collect()
    }

    /// Remove a document from an envelope that is still a draft.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when this account has no such document in a draft envelope;
    /// `CS-DB-0008` while versions or fields still reference it.
    pub async fn delete_from_draft(&mut self, id: DocumentId) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query(
            "DELETE FROM documents d USING envelopes e \
             WHERE d.account_id = $1 AND d.id = $2 AND e.account_id = $1 \
               AND e.id = d.envelope_id AND e.status = 'draft'",
        )
        .bind(acct)
        .bind(id.0)
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        if done.rows_affected() == 0 {
            return Err(StoreError::NotFound { entity: "document" });
        }
        Ok(())
    }

    /// Record a new version of a document of this account. Versions are never changed.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` when the document is not this account's.
    pub async fn add_version(&mut self, v: &NewVersion) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query(
            "INSERT INTO document_versions (id, account_id, document_id, kind, sha256, byte_len, \
             page_count, admission_report, pages) VALUES ($2, $1, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(acct)
        .bind(v.id.0)
        .bind(v.document_id.0)
        .bind(v.kind.as_str())
        .bind(v.sha256.as_slice())
        .bind(v.byte_len)
        .bind(v.page_count)
        .bind(&v.admission_report)
        .bind(&v.pages)
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// A version of this account.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn version(&mut self, id: DocumentVersionId) -> Result<Option<Version>> {
        let acct = self.tx.acct();
        let sql = format!("{VERSION_SELECT} AND id = $2");
        let row = sqlx::query(&sql)
            .bind(acct)
            .bind(id.0)
            .fetch_optional(self.tx.conn())
            .await
            .map_err(db)?;
        row.as_ref().map(version).transpose()
    }

    /// A document's versions, oldest first.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn versions(&mut self, document: DocumentId) -> Result<Vec<Version>> {
        let acct = self.tx.acct();
        let sql = format!("{VERSION_SELECT} AND document_id = $2 ORDER BY created_at, id");
        let rows = sqlx::query(&sql)
            .bind(acct)
            .bind(document.0)
            .fetch_all(self.tx.conn())
            .await
            .map_err(db)?;
        rows.iter().map(version).collect()
    }
}
