//! Envelopes (docs/22 §3) and their states (docs/24 §2). The store records a state the
//! workflow engine decided; it does not decide transitions. Every change carries the
//! version it read (optimistic concurrency, `CS-DB-0007`).

use casual_sign_audit::Personal;
use sqlx::postgres::PgRow;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{col, opt_hash_col, text_enum};
use crate::error::{Result, StoreError, db};
use crate::ids::{EnvelopeId, TemplateId, UserId};
use crate::store::TenantTx;

text_enum!(
    /// An envelope's state (docs/24 §2).
    EnvelopeStatus {
        /// Being prepared.
        Draft = "draft",
        /// Sent; routing under way.
        Sent = "sent",
        /// Every reached recipient has viewed.
        Delivered = "delivered",
        /// Every required action done; sealing.
        Completing = "completing",
        /// Sealed and verified.
        Completed = "completed",
        /// A recipient declined.
        Declined = "declined",
        /// Voided by the sender or an admin.
        Voided = "voided",
        /// Expired with required actions open.
        Expired = "expired",
    }
);

text_enum!(
    /// How routing orders are used.
    RoutingMode {
        /// One routing order after another.
        Sequential = "sequential",
        /// Everyone at once.
        Parallel = "parallel",
        /// Both, by routing order number.
        Mixed = "mixed",
    }
);

text_enum!(
    /// The PAdES level of the seal (docs/31).
    SealProfile {
        /// Signature with a trusted timestamp (default).
        PadesBT = "pades-b-t",
        /// With long-term validation material.
        PadesBLt = "pades-b-lt",
        /// With an archive timestamp.
        PadesBLta = "pades-b-lta",
    }
);

/// A new draft envelope.
#[derive(Debug, Clone)]
pub struct NewEnvelope {
    /// Host-minted id.
    pub id: EnvelopeId,
    /// Sender, a member of this account.
    pub sender_user_id: UserId,
    /// Email subject (personal data: may name people).
    pub subject: Personal<String>,
    /// Email body (personal data).
    pub message: Personal<String>,
    /// Routing mode.
    pub routing_mode: RoutingMode,
    /// Expiry.
    pub expires_at: Option<OffsetDateTime>,
    /// Reminder policy.
    pub reminder_policy: serde_json::Value,
    /// Signing options.
    pub signing_options: serde_json::Value,
    /// Seal profile.
    pub seal_profile: SealProfile,
    /// Completion delivery.
    pub completion_delivery: serde_json::Value,
    /// Templates this was made from.
    pub template_ids: Vec<TemplateId>,
}

/// An envelope as stored.
#[derive(Debug, Clone, PartialEq)]
pub struct Envelope {
    /// Id.
    pub id: EnvelopeId,
    /// Sender.
    pub sender_user_id: UserId,
    /// State.
    pub status: EnvelopeStatus,
    /// Subject (personal data).
    pub subject: Personal<String>,
    /// Message (personal data).
    pub message: Personal<String>,
    /// Routing mode.
    pub routing_mode: RoutingMode,
    /// Expiry.
    pub expires_at: Option<OffsetDateTime>,
    /// Reminder policy.
    pub reminder_policy: serde_json::Value,
    /// Signing options.
    pub signing_options: serde_json::Value,
    /// Seal profile.
    pub seal_profile: SealProfile,
    /// Completion delivery.
    pub completion_delivery: serde_json::Value,
    /// Templates this was made from.
    pub template_ids: Vec<TemplateId>,
    /// Optimistic-concurrency version.
    pub version: i32,
    /// Hash of the last audit event.
    pub chain_head: Option<[u8; 32]>,
    /// Created.
    pub created_at: OffsetDateTime,
    /// Sent.
    pub sent_at: Option<OffsetDateTime>,
    /// Completed.
    pub completed_at: Option<OffsetDateTime>,
    /// Voided.
    pub voided_at: Option<OffsetDateTime>,
}

/// A state change the workflow engine decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    /// The new state.
    pub status: EnvelopeStatus,
    /// The time to record against it (`sent_at`, `completed_at` or `voided_at`).
    pub at: OffsetDateTime,
    /// The void reason, for `voided`.
    pub void_reason: Option<Personal<String>>,
}

const SELECT: &str = "SELECT id, sender_user_id, status, subject, message, routing_mode, expires_at, \
     reminder_policy, signing_options, seal_profile, completion_delivery, template_ids, version, \
     chain_head, created_at, sent_at, completed_at, voided_at FROM envelopes WHERE account_id = $1";

fn envelope(r: &PgRow) -> Result<Envelope> {
    let status: String = col(r, "status")?;
    let routing: String = col(r, "routing_mode")?;
    let seal: String = col(r, "seal_profile")?;
    let templates: Vec<Uuid> = col(r, "template_ids")?;
    Ok(Envelope {
        id: EnvelopeId(col(r, "id")?),
        sender_user_id: UserId(col(r, "sender_user_id")?),
        status: EnvelopeStatus::parse(&status, "status")?,
        subject: Personal(col(r, "subject")?),
        message: Personal(col(r, "message")?),
        routing_mode: RoutingMode::parse(&routing, "routing_mode")?,
        expires_at: col(r, "expires_at")?,
        reminder_policy: col(r, "reminder_policy")?,
        signing_options: col(r, "signing_options")?,
        seal_profile: SealProfile::parse(&seal, "seal_profile")?,
        completion_delivery: col(r, "completion_delivery")?,
        template_ids: templates.into_iter().map(TemplateId).collect(),
        version: col(r, "version")?,
        chain_head: opt_hash_col(r, "chain_head")?,
        created_at: col(r, "created_at")?,
        sent_at: col(r, "sent_at")?,
        completed_at: col(r, "completed_at")?,
        voided_at: col(r, "voided_at")?,
    })
}

/// Envelopes of this account. Reached through `TenantTx::envelopes`.
#[derive(Debug)]
pub struct Envelopes<'t> {
    pub(crate) tx: &'t mut TenantTx,
}

impl Envelopes<'_> {
    /// Insert a draft.
    ///
    /// # Errors
    ///
    /// `CS-DB-0006` duplicate id; `CS-DB-0008` a sender who is not a member of this
    /// account, or a value out of bounds.
    pub async fn insert(&mut self, e: &NewEnvelope) -> Result<()> {
        let acct = self.tx.acct();
        let templates: Vec<Uuid> = e.template_ids.iter().map(|t| t.0).collect();
        sqlx::query(
            "INSERT INTO envelopes (id, account_id, sender_user_id, status, subject, message, \
             routing_mode, expires_at, reminder_policy, signing_options, seal_profile, \
             completion_delivery, template_ids) \
             VALUES ($2, $1, $3, 'draft', $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(acct)
        .bind(e.id.0)
        .bind(e.sender_user_id.0)
        .bind(e.subject.get())
        .bind(e.message.get())
        .bind(e.routing_mode.as_str())
        .bind(e.expires_at)
        .bind(&e.reminder_policy)
        .bind(&e.signing_options)
        .bind(e.seal_profile.as_str())
        .bind(&e.completion_delivery)
        .bind(&templates)
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// An envelope of this account.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn get(&mut self, id: EnvelopeId) -> Result<Option<Envelope>> {
        let acct = self.tx.acct();
        let sql = format!("{SELECT} AND id = $2");
        let row = sqlx::query(&sql)
            .bind(acct)
            .bind(id.0)
            .fetch_optional(self.tx.conn())
            .await
            .map_err(db)?;
        row.as_ref().map(envelope).transpose()
    }

    /// Envelopes of this account, newest first, optionally of one state, at most `limit`
    /// (capped at 1,000).
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn list(
        &mut self,
        status: Option<EnvelopeStatus>,
        limit: u32,
    ) -> Result<Vec<Envelope>> {
        let acct = self.tx.acct();
        let sql = format!(
            "{SELECT} AND ($2::text IS NULL OR status = $2) ORDER BY created_at DESC, id DESC LIMIT $3"
        );
        let rows = sqlx::query(&sql)
            .bind(acct)
            .bind(status.map(EnvelopeStatus::as_str))
            .bind(i64::from(limit.min(1000)))
            .fetch_all(self.tx.conn())
            .await
            .map_err(db)?;
        rows.iter().map(envelope).collect()
    }

    /// Change a draft's subject and message, if it is still at `version`; returns the
    /// new version.
    ///
    /// # Errors
    ///
    /// `CS-DB-0007` stale version or no longer a draft; `CS-DB-0003` no such envelope.
    pub async fn update_draft(
        &mut self,
        id: EnvelopeId,
        version: i32,
        subject: &Personal<String>,
        message: &Personal<String>,
    ) -> Result<i32> {
        let acct = self.tx.acct();
        let row = sqlx::query(
            "UPDATE envelopes SET subject = $4, message = $5, version = version + 1 \
             WHERE account_id = $1 AND id = $2 AND version = $3 AND status = 'draft' \
             RETURNING version",
        )
        .bind(acct)
        .bind(id.0)
        .bind(version)
        .bind(subject.get())
        .bind(message.get())
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        self.versioned(id, row).await
    }

    /// Record a state change at `version`; returns the new version.
    ///
    /// # Errors
    ///
    /// `CS-DB-0007` stale version; `CS-DB-0003` no such envelope; `CS-DB-0008` an
    /// inconsistent change (voided without a time).
    pub async fn transition(
        &mut self,
        id: EnvelopeId,
        version: i32,
        t: &Transition,
    ) -> Result<i32> {
        let acct = self.tx.acct();
        let row = sqlx::query(
            "UPDATE envelopes SET status = $4, version = version + 1, \
               sent_at = CASE WHEN $4 = 'sent' THEN $5 ELSE sent_at END, \
               completed_at = CASE WHEN $4 = 'completed' THEN $5 ELSE completed_at END, \
               voided_at = CASE WHEN $4 = 'voided' THEN $5 ELSE voided_at END, \
               void_reason = CASE WHEN $4 = 'voided' THEN $6 ELSE void_reason END \
             WHERE account_id = $1 AND id = $2 AND version = $3 RETURNING version",
        )
        .bind(acct)
        .bind(id.0)
        .bind(version)
        .bind(t.status.as_str())
        .bind(t.at)
        .bind(t.void_reason.as_ref().map(|r| r.get().as_str()))
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        self.versioned(id, row).await
    }

    async fn versioned(&mut self, id: EnvelopeId, row: Option<PgRow>) -> Result<i32> {
        if let Some(r) = row {
            return col(&r, "version");
        }
        if self.exists(id).await? {
            Err(StoreError::StaleVersion { entity: "envelope" })
        } else {
            Err(StoreError::NotFound { entity: "envelope" })
        }
    }

    /// Whether this account has the envelope.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn exists(&mut self, id: EnvelopeId) -> Result<bool> {
        let acct = self.tx.acct();
        let row = sqlx::query("SELECT 1 FROM envelopes WHERE account_id = $1 AND id = $2")
            .bind(acct)
            .bind(id.0)
            .fetch_optional(self.tx.conn())
            .await
            .map_err(db)?;
        Ok(row.is_some())
    }
}
