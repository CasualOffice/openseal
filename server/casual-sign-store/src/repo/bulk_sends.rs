//! Bulk sends from a template (UXW-04, migration 0004 `bulk_sends` and
//! `bulk_send_rows`): one batch, one row per recipient set, one envelope per sent row.
//! A row's input is personal data (names and email addresses) and is never logged.
//! Rows are claimed one at a time with `FOR UPDATE SKIP LOCKED`, so two callers sending
//! the same batch never send one row twice.

use casual_sign_audit::Personal;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{affected, text_enum};
use crate::error::{Result, db};
use crate::ids::{BulkSendId, BulkSendRowId, EnvelopeId, TemplateId, UserId};
use crate::store::TenantTx;

text_enum! {
    /// Where a bulk send is.
    BulkStatus {
        /// Created; no row sent yet.
        Queued = "queued",
        /// Rows are being sent.
        Sending = "sending",
        /// No row is pending any more.
        Completed = "completed",
        /// Cancelled: the rows still pending were not sent.
        Cancelled = "cancelled",
    }
}

text_enum! {
    /// Where one row of a bulk send is.
    RowStatus {
        /// Valid and not sent yet.
        Pending = "pending",
        /// Its envelope was sent.
        Sent = "sent",
        /// Refused: by the row check before the batch was made, or when it was sent.
        Failed = "failed",
        /// Not sent: the batch was cancelled first.
        Cancelled = "cancelled",
    }
}

/// A bulk send with its row counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkSend {
    /// Host-minted id.
    pub id: BulkSendId,
    /// Who made it.
    pub sender_user_id: UserId,
    /// The template every envelope comes from.
    pub template_id: TemplateId,
    /// Its name as the sender typed it (user content: never logged).
    pub name: Personal<String>,
    /// Where it is.
    pub status: BulkStatus,
    /// How many rows it has.
    pub row_count: i32,
    /// Rows still pending.
    pub pending: i64,
    /// Rows sent.
    pub sent: i64,
    /// Rows failed.
    pub failed: i64,
    /// Rows cancelled.
    pub cancelled: i64,
    /// When it was made.
    pub created_at: OffsetDateTime,
    /// When it completed or was cancelled.
    pub finished_at: Option<OffsetDateTime>,
}

/// One row of a bulk send.
#[derive(Debug, Clone, PartialEq)]
pub struct BulkRow {
    /// Host-minted id.
    pub id: BulkSendRowId,
    /// Its place in the list, from 0.
    pub row_index: i32,
    /// The recipients and the row's problem, as the server wrote them (personal data).
    pub input: Personal<serde_json::Value>,
    /// Where it is.
    pub status: RowStatus,
    /// The envelope sent for it.
    pub envelope_id: Option<EnvelopeId>,
    /// Why it failed: a stable code (docs/20).
    pub error_code: Option<String>,
}

/// A row to store with a new bulk send.
#[derive(Debug, Clone)]
pub struct NewRow {
    /// Host-minted id.
    pub id: BulkSendRowId,
    /// Its place in the list, from 0.
    pub row_index: i32,
    /// The recipients and the row's problem (personal data).
    pub input: Personal<serde_json::Value>,
    /// `Pending` when valid, `Failed` with `error_code` when not.
    pub status: RowStatus,
    /// Why it is refused.
    pub error_code: Option<String>,
}

/// Bulk sends of this account. Reached through `TenantTx::bulk_sends`.
#[derive(Debug)]
pub struct BulkSends<'t> {
    pub(crate) tx: &'t mut TenantTx,
}

struct SendRow {
    id: Uuid,
    sender_user_id: Uuid,
    template_id: Uuid,
    name: String,
    status: String,
    row_count: i32,
    created_at: OffsetDateTime,
    finished_at: Option<OffsetDateTime>,
    pending: i64,
    sent: i64,
    failed: i64,
    cancelled: i64,
}

impl SendRow {
    fn into_send(self) -> Result<BulkSend> {
        Ok(BulkSend {
            id: BulkSendId(self.id),
            sender_user_id: UserId(self.sender_user_id),
            template_id: TemplateId(self.template_id),
            name: Personal(self.name),
            status: BulkStatus::parse(&self.status, "bulk_sends.status")?,
            row_count: self.row_count,
            pending: self.pending,
            sent: self.sent,
            failed: self.failed,
            cancelled: self.cancelled,
            created_at: self.created_at,
            finished_at: self.finished_at,
        })
    }
}

impl BulkSends<'_> {
    /// A new bulk send of `sender` from `template`, with every row; `Queued`.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0008` when the sender is not a member or the template is
    /// not this account's.
    pub async fn create(
        &mut self,
        id: BulkSendId,
        sender: UserId,
        template: TemplateId,
        name: &str,
        rows: &[NewRow],
    ) -> Result<()> {
        let acct = self.tx.acct();
        let count = i32::try_from(rows.len()).unwrap_or(i32::MAX);
        sqlx::query!(
            "INSERT INTO bulk_sends (id, account_id, sender_user_id, template_id, name, status, row_count) \
             VALUES ($2, $1, $3, $4, $5, 'queued', $6)",
            acct,
            id.0,
            sender.0,
            template.0,
            name,
            count
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        for r in rows {
            sqlx::query!(
                "INSERT INTO bulk_send_rows (id, account_id, bulk_send_id, row_index, input, status, error_code) \
                 VALUES ($2, $1, $3, $4, $5, $6, $7)",
                acct,
                r.id.0,
                id.0,
                r.row_index,
                r.input.get(),
                r.status.as_str(),
                r.error_code.as_deref()
            )
            .execute(self.tx.conn())
            .await
            .map_err(db)?;
        }
        Ok(())
    }

    /// One bulk send with its counts, or `None`. `sender`: only this member's.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0010` when a status does not read back.
    pub async fn get(
        &mut self,
        id: BulkSendId,
        sender: Option<UserId>,
    ) -> Result<Option<BulkSend>> {
        Ok(self.list(sender, Some(id), 1).await?.into_iter().next())
    }

    /// Bulk sends, newest first, at most `limit`. `sender`: only this member's.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0010` when a status does not read back.
    pub async fn list(
        &mut self,
        sender: Option<UserId>,
        only: Option<BulkSendId>,
        limit: i64,
    ) -> Result<Vec<BulkSend>> {
        let acct = self.tx.acct();
        let rows = sqlx::query_as!(
            SendRow,
            "SELECT b.id, b.sender_user_id, b.template_id, b.name, b.status, b.row_count, \
                    b.created_at, b.finished_at, \
                    count(r.id) FILTER (WHERE r.status = 'pending') AS \"pending!\", \
                    count(r.id) FILTER (WHERE r.status = 'sent') AS \"sent!\", \
                    count(r.id) FILTER (WHERE r.status = 'failed') AS \"failed!\", \
                    count(r.id) FILTER (WHERE r.status = 'cancelled') AS \"cancelled!\" \
             FROM bulk_sends AS b \
             LEFT JOIN bulk_send_rows AS r ON r.account_id = b.account_id AND r.bulk_send_id = b.id \
             WHERE b.account_id = $1 \
               AND ($2::uuid IS NULL OR b.sender_user_id = $2) \
               AND ($3::uuid IS NULL OR b.id = $3) \
             GROUP BY b.id \
             ORDER BY b.created_at DESC, b.id DESC \
             LIMIT $4",
            acct,
            sender.map(|s| s.0),
            only.map(|b| b.0),
            limit
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        rows.into_iter().map(SendRow::into_send).collect()
    }

    /// Every row of a bulk send, in list order.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0010` when a status does not read back.
    pub async fn rows(&mut self, id: BulkSendId) -> Result<Vec<BulkRow>> {
        let acct = self.tx.acct();
        let rows = sqlx::query!(
            "SELECT id, row_index, input, status, envelope_id, error_code FROM bulk_send_rows \
             WHERE account_id = $1 AND bulk_send_id = $2 ORDER BY row_index",
            acct,
            id.0
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        rows.into_iter()
            .map(|r| {
                Ok(BulkRow {
                    id: BulkSendRowId(r.id),
                    row_index: r.row_index,
                    input: Personal(r.input),
                    status: RowStatus::parse(&r.status, "bulk_send_rows.status")?,
                    envelope_id: r.envelope_id.map(EnvelopeId),
                    error_code: r.error_code,
                })
            })
            .collect()
    }

    /// The first pending row of a bulk send that no other transaction holds, locked
    /// until this transaction ends; `None` when none is left.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0010` when a status does not read back.
    pub async fn claim(&mut self, id: BulkSendId) -> Result<Option<BulkRow>> {
        let acct = self.tx.acct();
        let r = sqlx::query!(
            "SELECT id, row_index, input, status, envelope_id, error_code FROM bulk_send_rows \
             WHERE account_id = $1 AND bulk_send_id = $2 AND status = 'pending' \
             ORDER BY row_index LIMIT 1 FOR UPDATE SKIP LOCKED",
            acct,
            id.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        r.map(|r| {
            Ok(BulkRow {
                id: BulkSendRowId(r.id),
                row_index: r.row_index,
                input: Personal(r.input),
                status: RowStatus::parse(&r.status, "bulk_send_rows.status")?,
                envelope_id: r.envelope_id.map(EnvelopeId),
                error_code: r.error_code,
            })
        })
        .transpose()
    }

    /// A pending row was sent as `envelope`, which now names the bulk send.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0003` when the row is not pending.
    pub async fn sent(
        &mut self,
        id: BulkSendId,
        row: BulkSendRowId,
        envelope: EnvelopeId,
    ) -> Result<()> {
        let acct = self.tx.acct();
        let n = sqlx::query!(
            "UPDATE bulk_send_rows SET status = 'sent', envelope_id = $3 \
             WHERE account_id = $1 AND id = $2 AND status = 'pending'",
            acct,
            row.0,
            envelope.0
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
        affected(n, "bulk_send_row")?;
        let n = sqlx::query!(
            "UPDATE envelopes SET bulk_send_id = $3 WHERE account_id = $1 AND id = $2",
            acct,
            envelope.0,
            id.0
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
        affected(n, "envelope")
    }

    /// A pending row could not be sent: `code` says why.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0003` when the row is not pending.
    pub async fn failed(&mut self, row: BulkSendRowId, code: &str) -> Result<()> {
        let acct = self.tx.acct();
        let n = sqlx::query!(
            "UPDATE bulk_send_rows SET status = 'failed', error_code = $3 \
             WHERE account_id = $1 AND id = $2 AND status = 'pending'",
            acct,
            row.0,
            code
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
        affected(n, "bulk_send_row")
    }

    /// Move a bulk send on: `Sending` while rows are pending, `Completed` (with
    /// `finished_at`) once none is. A cancelled or completed one stays as it is.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn settle(&mut self, id: BulkSendId, now: OffsetDateTime) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "UPDATE bulk_sends SET \
               status = CASE WHEN EXISTS (SELECT 1 FROM bulk_send_rows \
                   WHERE account_id = $1 AND bulk_send_id = $2 AND status = 'pending') \
                 THEN 'sending' ELSE 'completed' END, \
               finished_at = CASE WHEN EXISTS (SELECT 1 FROM bulk_send_rows \
                   WHERE account_id = $1 AND bulk_send_id = $2 AND status = 'pending') \
                 THEN NULL ELSE $3::timestamptz END \
             WHERE account_id = $1 AND id = $2 AND status IN ('queued', 'sending')",
            acct,
            id.0,
            now
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// Cancel a bulk send that is not finished: its pending rows are not sent.
    /// Answers false when it had already completed or been cancelled.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn cancel(&mut self, id: BulkSendId, now: OffsetDateTime) -> Result<bool> {
        let acct = self.tx.acct();
        let n = sqlx::query!(
            "UPDATE bulk_sends SET status = 'cancelled', finished_at = $3 \
             WHERE account_id = $1 AND id = $2 AND status IN ('queued', 'sending')",
            acct,
            id.0,
            now
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
        if n == 0 {
            return Ok(false);
        }
        sqlx::query!(
            "UPDATE bulk_send_rows SET status = 'cancelled' \
             WHERE account_id = $1 AND bulk_send_id = $2 AND status = 'pending'",
            acct,
            id.0
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(true)
    }
}
