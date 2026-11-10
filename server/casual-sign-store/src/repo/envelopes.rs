//! Envelopes (docs/22 §3) and their states (docs/24 §2). The store records a state the
//! workflow engine decided; it does not decide transitions. Every change carries the
//! version it read (optimistic concurrency, `CS-DB-0007`).

use casual_sign_audit::Personal;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{opt_hash32, text_enum};
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

/// A row as selected; converted to [`Envelope`] after its enumerations are checked.
struct EnvelopeRow {
    id: Uuid,
    sender_user_id: Uuid,
    status: String,
    subject: String,
    message: String,
    routing_mode: String,
    expires_at: Option<OffsetDateTime>,
    reminder_policy: serde_json::Value,
    signing_options: serde_json::Value,
    seal_profile: String,
    completion_delivery: serde_json::Value,
    template_ids: Vec<Uuid>,
    version: i32,
    chain_head: Option<Vec<u8>>,
    created_at: OffsetDateTime,
    sent_at: Option<OffsetDateTime>,
    completed_at: Option<OffsetDateTime>,
    voided_at: Option<OffsetDateTime>,
}

impl TryFrom<EnvelopeRow> for Envelope {
    type Error = StoreError;
    fn try_from(r: EnvelopeRow) -> Result<Self> {
        Ok(Self {
            id: EnvelopeId(r.id),
            sender_user_id: UserId(r.sender_user_id),
            status: EnvelopeStatus::parse(&r.status, "status")?,
            subject: Personal(r.subject),
            message: Personal(r.message),
            routing_mode: RoutingMode::parse(&r.routing_mode, "routing_mode")?,
            expires_at: r.expires_at,
            reminder_policy: r.reminder_policy,
            signing_options: r.signing_options,
            seal_profile: SealProfile::parse(&r.seal_profile, "seal_profile")?,
            completion_delivery: r.completion_delivery,
            template_ids: r.template_ids.into_iter().map(TemplateId).collect(),
            version: r.version,
            chain_head: opt_hash32(r.chain_head, "chain_head")?,
            created_at: r.created_at,
            sent_at: r.sent_at,
            completed_at: r.completed_at,
            voided_at: r.voided_at,
        })
    }
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
        sqlx::query!(
            "INSERT INTO envelopes (id, account_id, sender_user_id, status, subject, message, \
             routing_mode, expires_at, reminder_policy, signing_options, seal_profile, \
             completion_delivery, template_ids) \
             VALUES ($2, $1, $3, 'draft', $4, $5, $6, $7, $8, $9, $10, $11, $12)",
            acct,
            e.id.0,
            e.sender_user_id.0,
            e.subject.get(),
            e.message.get(),
            e.routing_mode.as_str(),
            e.expires_at,
            &e.reminder_policy,
            &e.signing_options,
            e.seal_profile.as_str(),
            &e.completion_delivery,
            &templates
        )
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
        let row = sqlx::query_as!(
            EnvelopeRow,
            "SELECT id, sender_user_id, status, subject, message, routing_mode, expires_at, \
             reminder_policy, signing_options, seal_profile, completion_delivery, template_ids, \
             version, chain_head, created_at, sent_at, completed_at, voided_at \
             FROM envelopes WHERE account_id = $1 AND id = $2",
            acct,
            id.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        row.map(Envelope::try_from).transpose()
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
        let rows = sqlx::query_as!(
            EnvelopeRow,
            "SELECT id, sender_user_id, status, subject, message, routing_mode, expires_at, \
             reminder_policy, signing_options, seal_profile, completion_delivery, template_ids, \
             version, chain_head, created_at, sent_at, completed_at, voided_at \
             FROM envelopes WHERE account_id = $1 AND ($2::text IS NULL OR status = $2) \
             ORDER BY created_at DESC, id DESC LIMIT $3",
            acct,
            status.map(EnvelopeStatus::as_str),
            i64::from(limit.min(1000))
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        rows.into_iter().map(Envelope::try_from).collect()
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
        let new = sqlx::query_scalar!(
            "UPDATE envelopes SET subject = $4, message = $5, version = version + 1 \
             WHERE account_id = $1 AND id = $2 AND version = $3 AND status = 'draft' \
             RETURNING version",
            acct,
            id.0,
            version,
            subject.get(),
            message.get()
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        self.versioned(id, new).await
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
        let new = sqlx::query_scalar!(
            "UPDATE envelopes SET status = $4, version = version + 1, \
               sent_at = CASE WHEN $4 = 'sent' THEN $5 ELSE sent_at END, \
               completed_at = CASE WHEN $4 = 'completed' THEN $5 ELSE completed_at END, \
               voided_at = CASE WHEN $4 = 'voided' THEN $5 ELSE voided_at END, \
               void_reason = CASE WHEN $4 = 'voided' THEN $6 ELSE void_reason END \
             WHERE account_id = $1 AND id = $2 AND version = $3 RETURNING version",
            acct,
            id.0,
            version,
            t.status.as_str(),
            t.at,
            t.void_reason.as_ref().map(|r| r.get().as_str())
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        self.versioned(id, new).await
    }

    async fn versioned(&mut self, id: EnvelopeId, new: Option<i32>) -> Result<i32> {
        if let Some(v) = new {
            return Ok(v);
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
        let row = sqlx::query_scalar!(
            r#"SELECT 1 AS "one!" FROM envelopes WHERE account_id = $1 AND id = $2"#,
            acct,
            id.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(row.is_some())
    }
}

/// The columns of `envelopes` the server projects from the workflow engine's state
/// (migration 0008, docs/22 §10). The state is the authority; these let the account
/// list, filter and page envelopes without decoding it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Projection {
    /// The state's status.
    pub status: EnvelopeStatus,
    /// Email subject.
    pub subject: Personal<String>,
    /// Email message.
    pub message: Personal<String>,
    /// Expiry.
    pub expires_at: Option<OffsetDateTime>,
    /// Reminder policy as the engine serializes it.
    pub reminder_policy: serde_json::Value,
    /// Signing options as the engine serializes them.
    pub signing_options: serde_json::Value,
    /// PAdES level.
    pub seal_profile: SealProfile,
    /// When it was sent.
    pub sent_at: Option<OffsetDateTime>,
    /// When it completed.
    pub completed_at: Option<OffsetDateTime>,
    /// When it was voided (set exactly when the status is `voided`).
    pub voided_at: Option<OffsetDateTime>,
    /// Why it was voided.
    pub void_reason: Option<Personal<String>>,
}

/// Where a page of envelopes resumes: after this creation time and id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    /// Creation time of the last envelope returned.
    pub created_at: OffsetDateTime,
    /// Its id.
    pub id: EnvelopeId,
}

impl Envelopes<'_> {
    /// Record the API client that created an envelope (tracker row WF-05): an embedding
    /// host may act only for the envelopes it created.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` no such envelope; `CS-DB-0008`/`CS-DB-0009` a client of another
    /// account.
    pub async fn set_host_client(
        &mut self,
        id: EnvelopeId,
        client: crate::ids::ApiClientId,
    ) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE envelopes SET host_client_id = $3 WHERE account_id = $1 AND id = $2",
            acct,
            id.0,
            client.0
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        super::affected(done.rows_affected(), "envelope")
    }

    /// The API client that created an envelope of this account, if one did; `None`
    /// also when the account has no such envelope.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn host_client(&mut self, id: EnvelopeId) -> Result<Option<crate::ids::ApiClientId>> {
        let acct = self.tx.acct();
        let row = sqlx::query_scalar!(
            "SELECT host_client_id FROM envelopes WHERE account_id = $1 AND id = $2",
            acct,
            id.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(row.flatten().map(crate::ids::ApiClientId))
    }

    /// Record the sealed certificate of completion's blob. Written once: recording the
    /// same hash again changes nothing (a seal job re-run), a different one is refused.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` no such envelope, or one whose certificate is already another.
    pub async fn set_certificate(&mut self, id: EnvelopeId, sha256: &[u8; 32]) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE envelopes SET certificate_sha256 = $3 WHERE account_id = $1 AND id = $2 \
               AND (certificate_sha256 IS NULL OR certificate_sha256 = $3)",
            acct,
            id.0,
            sha256.as_slice()
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        super::affected(done.rows_affected(), "envelope")
    }

    /// The sealed certificate of completion's blob, once the seal job stored it; `None`
    /// before, and when the account has no such envelope.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0010` for a stored hash that is not 32 bytes.
    pub async fn certificate(&mut self, id: EnvelopeId) -> Result<Option<[u8; 32]>> {
        let acct = self.tx.acct();
        let row = sqlx::query_scalar!(
            "SELECT certificate_sha256 FROM envelopes WHERE account_id = $1 AND id = $2",
            acct,
            id.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        opt_hash32(row.flatten(), "envelopes.certificate_sha256")
    }

    /// Write the projection of the engine's state (docs/22 §10) onto the envelope's
    /// columns, if the row is still at `row_version`; returns the new row version. The
    /// engine state itself lives in `envelope_states`, whose row the caller holds
    /// locked.
    ///
    /// # Errors
    ///
    /// `CS-DB-0007` stale; `CS-DB-0003` no such envelope; `CS-DB-0008` a projection the
    /// table's checks refuse (an overlong subject, voided without a time).
    pub async fn project(
        &mut self,
        id: EnvelopeId,
        row_version: i32,
        p: &Projection,
    ) -> Result<i32> {
        let acct = self.tx.acct();
        let new = sqlx::query_scalar!(
            "UPDATE envelopes SET version = version + 1, status = $4, \
               subject = $5, message = $6, expires_at = $7, reminder_policy = $8, \
               signing_options = $9, seal_profile = $10, sent_at = $11, completed_at = $12, \
               voided_at = $13, void_reason = $14 \
             WHERE account_id = $1 AND id = $2 AND version = $3 RETURNING version",
            acct,
            id.0,
            row_version,
            p.status.as_str(),
            p.subject.get(),
            p.message.get(),
            p.expires_at,
            &p.reminder_policy,
            &p.signing_options,
            p.seal_profile.as_str(),
            p.sent_at,
            p.completed_at,
            p.voided_at,
            p.void_reason.as_ref().map(|r| r.get().as_str())
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        self.versioned(id, new).await
    }

    /// A page of this account's envelopes, newest first, after `after`, optionally of
    /// one status and one sender, at most `limit` (capped at 1,000). Stable under
    /// inserts: new envelopes sort before every cursor already handed out.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn page(
        &mut self,
        after: Option<Cursor>,
        status: Option<EnvelopeStatus>,
        sender: Option<UserId>,
        limit: u32,
    ) -> Result<Vec<Envelope>> {
        let acct = self.tx.acct();
        let rows = sqlx::query_as!(
            EnvelopeRow,
            "SELECT id, sender_user_id, status, subject, message, routing_mode, expires_at, \
             reminder_policy, signing_options, seal_profile, completion_delivery, template_ids, \
             version, chain_head, created_at, sent_at, completed_at, voided_at \
             FROM envelopes AS e WHERE account_id = $1 \
               AND EXISTS (SELECT 1 FROM envelope_states AS s \
                            WHERE s.account_id = e.account_id AND s.envelope_id = e.id) \
               AND ($2::timestamptz IS NULL OR (created_at, id) < ($2, $3::uuid)) \
               AND ($4::text IS NULL OR status = $4) \
               AND ($5::uuid IS NULL OR sender_user_id = $5) \
             ORDER BY created_at DESC, id DESC LIMIT $6",
            acct,
            after.map(|c| c.created_at),
            after.map(|c| c.id.0),
            status.map(EnvelopeStatus::as_str),
            sender.map(|s| s.0),
            i64::from(limit.min(1000))
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        rows.into_iter().map(Envelope::try_from).collect()
    }
}
