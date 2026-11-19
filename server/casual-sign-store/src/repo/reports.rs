//! Workspace reports (`VS-06`, `UXW-25`, docs/96 FG-140; DocuSign's envelope, recipient
//! and usage reports): read-only rows over this account's envelopes created in a
//! window, optionally of one sender, newest first, capped. Envelopes removed from the
//! lists (the Deleted view) and drafts never saved through the engine are left out, as
//! the lists leave them out. Nothing here writes.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{Result, db};
use crate::store::TenantTx;

/// The most rows one report answers (the caller says when it was reached).
pub const MAX_ROWS: u32 = 10_000;

/// Which envelopes a report covers: created in `[from, to)`, of `sender` when given.
#[derive(Debug, Clone, Copy)]
pub struct Window {
    /// Created at or after.
    pub from: OffsetDateTime,
    /// Created before.
    pub to: OffsetDateTime,
    /// One sender's only.
    pub sender: Option<Uuid>,
}

/// One envelope of the envelope report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeRow {
    /// Its id.
    pub id: Uuid,
    /// Its subject (user content: never logged).
    pub subject: String,
    /// Its status.
    pub status: String,
    /// Who sent it.
    pub sender_user_id: Uuid,
    /// When it was created, sent, completed and voided, and when it expires.
    pub created_at: OffsetDateTime,
    /// Sent.
    pub sent_at: Option<OffsetDateTime>,
    /// Completed.
    pub completed_at: Option<OffsetDateTime>,
    /// Voided.
    pub voided_at: Option<OffsetDateTime>,
    /// Expires.
    pub expires_at: Option<OffsetDateTime>,
    /// How many recipients it has.
    pub recipients: i64,
}

/// One recipient of the recipient report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientRow {
    /// The envelope.
    pub envelope_id: Uuid,
    /// The envelope's subject.
    pub subject: String,
    /// The envelope's status.
    pub envelope_status: String,
    /// The recipient's name and email (personal data: never logged).
    pub name: String,
    /// Email.
    pub email: Option<String>,
    /// Type, status and routing order.
    pub rtype: String,
    /// Status.
    pub status: String,
    /// Routing order.
    pub routing_order: i32,
}

/// One sender's line of the usage report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageRow {
    /// The sender.
    pub sender_user_id: Uuid,
    /// Envelopes created in the window.
    pub created: i64,
    /// Of them, sent.
    pub sent: i64,
    /// Completed.
    pub completed: i64,
    /// Declined.
    pub declined: i64,
    /// Voided.
    pub voided: i64,
    /// Expired.
    pub expired: i64,
}

/// Reports of this account. Reached through `TenantTx::reports`.
#[derive(Debug)]
pub struct Reports<'t> {
    pub(crate) tx: &'t mut TenantTx,
}

impl Reports<'_> {
    /// The envelope report: at most `limit` (capped at [`MAX_ROWS`]) envelopes, newest
    /// first.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn envelopes(&mut self, w: Window, limit: u32) -> Result<Vec<EnvelopeRow>> {
        let acct = self.tx.acct();
        let lim = i64::from(limit.min(MAX_ROWS));
        let rows = sqlx::query!(
            "SELECT e.id, e.subject, e.status, e.sender_user_id, e.created_at, e.sent_at, \
                    e.completed_at, e.voided_at, e.expires_at, \
                    (SELECT count(*) FROM recipients AS r \
                      WHERE r.account_id = e.account_id AND r.envelope_id = e.id) AS \"recipients!\" \
               FROM envelopes AS e \
              WHERE e.account_id = $1 AND e.deleted_at IS NULL \
                AND EXISTS (SELECT 1 FROM envelope_states AS s \
                             WHERE s.account_id = e.account_id AND s.envelope_id = e.id) \
                AND e.created_at >= $2 AND e.created_at < $3 \
                AND ($4::uuid IS NULL OR e.sender_user_id = $4) \
              ORDER BY e.created_at DESC, e.id DESC LIMIT $5",
            acct,
            w.from,
            w.to,
            w.sender,
            lim
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(rows
            .into_iter()
            .map(|r| EnvelopeRow {
                id: r.id,
                subject: r.subject,
                status: r.status,
                sender_user_id: r.sender_user_id,
                created_at: r.created_at,
                sent_at: r.sent_at,
                completed_at: r.completed_at,
                voided_at: r.voided_at,
                expires_at: r.expires_at,
                recipients: r.recipients,
            })
            .collect())
    }

    /// The recipient report: the recipients of the window's envelopes, newest envelope
    /// first, in routing order; at most `limit` (capped at [`MAX_ROWS`]).
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn recipients(&mut self, w: Window, limit: u32) -> Result<Vec<RecipientRow>> {
        let acct = self.tx.acct();
        let lim = i64::from(limit.min(MAX_ROWS));
        let rows = sqlx::query!(
            "SELECT e.id AS envelope_id, e.subject, e.status AS envelope_status, r.name, \
                    r.email, r.type AS rtype, r.status, r.routing_order \
               FROM envelopes AS e JOIN recipients AS r \
                 ON r.account_id = e.account_id AND r.envelope_id = e.id \
              WHERE e.account_id = $1 AND e.deleted_at IS NULL \
                AND EXISTS (SELECT 1 FROM envelope_states AS s \
                             WHERE s.account_id = e.account_id AND s.envelope_id = e.id) \
                AND e.created_at >= $2 AND e.created_at < $3 \
                AND ($4::uuid IS NULL OR e.sender_user_id = $4) \
              ORDER BY e.created_at DESC, e.id DESC, r.routing_order, r.id LIMIT $5",
            acct,
            w.from,
            w.to,
            w.sender,
            lim
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(rows
            .into_iter()
            .map(|r| RecipientRow {
                envelope_id: r.envelope_id,
                subject: r.subject,
                envelope_status: r.envelope_status,
                name: r.name,
                email: r.email,
                rtype: r.rtype,
                status: r.status,
                routing_order: r.routing_order,
            })
            .collect())
    }

    /// The usage report: per sender, how many envelopes they created in the window and
    /// how those stand, most created first.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn usage(&mut self, w: Window) -> Result<Vec<UsageRow>> {
        let acct = self.tx.acct();
        let rows = sqlx::query!(
            "SELECT e.sender_user_id, count(*) AS \"created!\", \
                    count(*) FILTER (WHERE e.sent_at IS NOT NULL) AS \"sent!\", \
                    count(*) FILTER (WHERE e.status = 'completed') AS \"completed!\", \
                    count(*) FILTER (WHERE e.status = 'declined') AS \"declined!\", \
                    count(*) FILTER (WHERE e.status = 'voided') AS \"voided!\", \
                    count(*) FILTER (WHERE e.status = 'expired') AS \"expired!\" \
               FROM envelopes AS e \
              WHERE e.account_id = $1 AND e.deleted_at IS NULL \
                AND EXISTS (SELECT 1 FROM envelope_states AS s \
                             WHERE s.account_id = e.account_id AND s.envelope_id = e.id) \
                AND e.created_at >= $2 AND e.created_at < $3 \
                AND ($4::uuid IS NULL OR e.sender_user_id = $4) \
              GROUP BY e.sender_user_id ORDER BY count(*) DESC, e.sender_user_id",
            acct,
            w.from,
            w.to,
            w.sender
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(rows
            .into_iter()
            .map(|r| UsageRow {
                sender_user_id: r.sender_user_id,
                created: r.created,
                sent: r.sent,
                completed: r.completed,
                declined: r.declined,
                voided: r.voided,
                expired: r.expired,
            })
            .collect())
    }
}
