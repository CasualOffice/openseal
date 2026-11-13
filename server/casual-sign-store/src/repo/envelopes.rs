//! Envelopes (docs/22 §3) and their states (docs/24 §2). The store records a state the
//! workflow engine decided; it does not decide transitions. Every change carries the
//! version it read (optimistic concurrency, `CS-DB-0007`).

use casual_sign_audit::Personal;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{opt_hash32, text_enum};
use crate::error::{Result, StoreError, db};
use crate::ids::{EnvelopeId, FolderId, RecipientId, TemplateId, UserId};
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
    /// Last change: the last command that changed it (WEB-08).
    pub updated_at: OffsetDateTime,
    /// Removed from the lists (an envelope that ended without completing, WEB-08).
    pub deleted_at: Option<OffsetDateTime>,
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
    updated_at: OffsetDateTime,
    deleted_at: Option<OffsetDateTime>,
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
            updated_at: r.updated_at,
            deleted_at: r.deleted_at,
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
             version, chain_head, created_at, sent_at, completed_at, voided_at, updated_at, \
             deleted_at \
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
             version, chain_head, created_at, sent_at, completed_at, voided_at, updated_at, \
             deleted_at \
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
    /// The time of the command that changed the envelope, as its last change; `None`
    /// keeps the last change (an access such as a download changes nothing, WEB-08).
    pub updated_at: Option<OffsetDateTime>,
    /// When it was removed from the lists (WEB-08).
    pub deleted_at: Option<OffsetDateTime>,
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
               voided_at = $13, void_reason = $14, updated_at = COALESCE($15, updated_at), \
               deleted_at = $16 \
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
            p.void_reason.as_ref().map(|r| r.get().as_str()),
            p.updated_at,
            p.deleted_at
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        self.versioned(id, new).await
    }

    /// A page of this account's envelopes, newest first, after `after`, optionally of
    /// one status and one sender, and matching `search`, at most `limit` (capped at
    /// 1,000): [`Envelopes::search`] in creation order, newest first.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn page(
        &mut self,
        after: Option<Cursor>,
        status: Option<EnvelopeStatus>,
        sender: Option<UserId>,
        search: Option<&str>,
        limit: u32,
    ) -> Result<Vec<Envelope>> {
        let statuses: Vec<EnvelopeStatus> = status.into_iter().collect();
        let filter = ListFilter {
            statuses: &statuses,
            sender,
            search,
            changed_from: None,
            changed_to: None,
            ..ListFilter::default()
        };
        let sort = Sort {
            key: SortKey::Created,
            descending: true,
        };
        let after = after.map(|c| After {
            key: AfterKey::Time(c.created_at),
            id: c.id,
        });
        Ok(self
            .search(&filter, sort, after.as_ref(), limit)
            .await?
            .into_iter()
            .map(|l| l.envelope)
            .collect())
    }

    /// A page of this account's listed envelopes (WEB-08): those with engine state, not
    /// removed from the lists, matching `filter`, in `sort` order with the id as the
    /// tie-break, after `after` (the last of the previous page, in the same sort), at
    /// most `limit` (capped at 1,000). Keyset paging: stable under inserts; every value
    /// is a bound parameter, and each sort is one static query.
    ///
    /// `filter.search` is a text the subject, or a recipient's name or email, contains,
    /// ignoring case (row WEB-04); `%`, `_` and `\` in it are matched as themselves.
    /// Recipients are this account's only, like everything else here. An `after` whose
    /// key is not of the sort's kind matches nothing.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn search(
        &mut self,
        filter: &ListFilter<'_>,
        sort: Sort,
        after: Option<&After>,
        limit: u32,
    ) -> Result<Vec<Listed>> {
        let acct = self.tx.acct();
        let pattern = filter.search.map(like_contains);
        let statuses: Vec<String> = filter
            .statuses
            .iter()
            .map(|s| s.as_str().to_owned())
            .collect();
        let sender = filter.sender.map(|s| s.0);
        let (from, to) = (filter.changed_from, filter.changed_to);
        let recipient = filter.recipient.map(like_contains);
        let date_field = filter.date_field.as_str();
        let member = filter.member.map(|m| m.0);
        let (folder_mode, folder_id) = match filter.folder {
            FolderFilter::Any => ("any", None),
            FolderFilter::None => ("none", None),
            FolderFilter::In(f) => ("in", Some(f.0)),
        };
        let deleted = filter.deleted;
        let waiting = filter.waiting;
        let lim = i64::from(limit.min(1000));
        let after_id = after.map(|a| a.id.0);
        let has = after.is_some();
        let time = match after.map(|a| &a.key) {
            Some(AfterKey::Time(t)) => Some(*t),
            _ => None,
        };
        let text = match after.map(|a| &a.key) {
            Some(AfterKey::Text(t)) => Some(t.clone()),
            _ => None,
        };
        let rank = match after.map(|a| &a.key) {
            Some(AfterKey::Rank(r)) => Some(*r),
            _ => None,
        };
        // One static query per sort key and direction, so each key's index applies.
        macro_rules! q {
            ($key:tt, $cmp:tt, $dir:tt, $after:expr) => {
                sqlx::query_as!(
                    ListRow,
                    "SELECT id, sender_user_id, status, subject, message, routing_mode, \
                     expires_at, reminder_policy, signing_options, seal_profile, \
                     completion_delivery, template_ids, version, chain_head, created_at, \
                     sent_at, completed_at, voided_at, updated_at, deleted_at, \
                     lower(subject) AS \"subject_key!\", \
                     (SELECT fe.folder_id FROM folder_envelopes AS fe \
                       WHERE fe.account_id = e.account_id AND fe.envelope_id = e.id \
                         AND fe.user_id = $13) AS folder_id, \
                     (SELECT r.id FROM recipients AS r JOIN users AS u ON u.id = $13 \
                       WHERE $17::bool AND r.account_id = e.account_id AND r.envelope_id = e.id \
                         AND r.status IN ('sent', 'delivered', 'authenticated', 'auto_responded') \
                         AND r.type NOT IN ('cc', 'in_person_signer') \
                         AND r.embedded_client_user_id IS NULL \
                         AND lower(r.email) = lower(u.email) \
                       ORDER BY r.routing_order, r.id LIMIT 1) AS my_recipient_id \
                     FROM envelopes AS e WHERE account_id = $1 \
                       AND (deleted_at IS NOT NULL) = $16::bool \
                       AND EXISTS (SELECT 1 FROM envelope_states AS s \
                                    WHERE s.account_id = e.account_id AND s.envelope_id = e.id) \
                       AND (cardinality($2::text[]) = 0 OR status = ANY($2)) \
                       AND ($3::uuid IS NULL OR sender_user_id = $3) \
                       AND ($4::text IS NULL OR subject ILIKE $4 ESCAPE '\\' \
                            OR EXISTS (SELECT 1 FROM recipients AS r \
                                       WHERE r.account_id = e.account_id AND r.envelope_id = e.id \
                                         AND (r.name ILIKE $4 ESCAPE '\\' \
                                              OR r.email ILIKE $4 ESCAPE '\\'))) \
                       AND ($11::text IS NULL \
                            OR EXISTS (SELECT 1 FROM recipients AS r \
                                       WHERE r.account_id = e.account_id AND r.envelope_id = e.id \
                                         AND (r.name ILIKE $11 ESCAPE '\\' \
                                              OR r.email ILIKE $11 ESCAPE '\\'))) \
                       AND ($5::timestamptz IS NULL OR (CASE $12::text \
                              WHEN 'created_at' THEN created_at WHEN 'sent_at' THEN sent_at \
                              WHEN 'completed_at' THEN completed_at ELSE updated_at END) >= $5) \
                       AND ($6::timestamptz IS NULL OR (CASE $12::text \
                              WHEN 'created_at' THEN created_at WHEN 'sent_at' THEN sent_at \
                              WHEN 'completed_at' THEN completed_at ELSE updated_at END) < $6) \
                       AND ($14::text = 'any' \
                            OR ($14::text = 'none' AND NOT EXISTS (SELECT 1 FROM folder_envelopes AS fe \
                                  WHERE fe.account_id = e.account_id AND fe.envelope_id = e.id \
                                    AND fe.user_id = $13)) \
                            OR ($14::text = 'in' AND EXISTS (SELECT 1 FROM folder_envelopes AS fe \
                                  WHERE fe.account_id = e.account_id AND fe.envelope_id = e.id \
                                    AND fe.user_id = $13 AND fe.folder_id = $15::uuid))) \
                       AND (NOT $17::bool OR (status IN ('sent', 'delivered') \
                            AND EXISTS (SELECT 1 FROM recipients AS r JOIN users AS u ON u.id = $13 \
                                  WHERE r.account_id = e.account_id AND r.envelope_id = e.id \
                                    AND r.status IN ('sent', 'delivered', 'authenticated', 'auto_responded') \
                                    AND r.type NOT IN ('cc', 'in_person_signer') \
                                    AND r.embedded_client_user_id IS NULL \
                                    AND lower(r.email) = lower(u.email)))) \
                       AND (NOT $7::bool OR ("
                        + $key
                        + ", id) "
                        + $cmp
                        + " ($8, $9::uuid)) ORDER BY "
                        + $key
                        + " "
                        + $dir
                        + ", id "
                        + $dir
                        + " LIMIT $10",
                    acct,
                    &statuses,
                    sender,
                    pattern,
                    from,
                    to,
                    has,
                    $after,
                    after_id,
                    lim,
                    recipient,
                    date_field,
                    member,
                    folder_mode,
                    folder_id,
                    deleted,
                    waiting
                )
                .fetch_all(self.tx.conn())
                .await
            };
        }
        let rows = match (sort.key, sort.descending) {
            (SortKey::Created, true) => q!("created_at", "<", "DESC", time),
            (SortKey::Created, false) => q!("created_at", ">", "ASC", time),
            (SortKey::Updated, true) => q!("updated_at", "<", "DESC", time),
            (SortKey::Updated, false) => q!("updated_at", ">", "ASC", time),
            (SortKey::Expires, true) => q!(
                "COALESCE(expires_at, '9999-12-31T00:00:00Z'::timestamptz)",
                "<",
                "DESC",
                time
            ),
            (SortKey::Expires, false) => q!(
                "COALESCE(expires_at, '9999-12-31T00:00:00Z'::timestamptz)",
                ">",
                "ASC",
                time
            ),
            (SortKey::Subject, true) => q!("lower(subject)", "<", "DESC", text),
            (SortKey::Subject, false) => q!("lower(subject)", ">", "ASC", text),
            (SortKey::Status, true) => q!(
                "(CASE status WHEN 'draft' THEN 0 WHEN 'sent' THEN 1 WHEN 'delivered' THEN 2 \
                 WHEN 'completing' THEN 3 WHEN 'completed' THEN 4 WHEN 'declined' THEN 5 \
                 WHEN 'voided' THEN 6 ELSE 7 END)",
                "<",
                "DESC",
                rank
            ),
            (SortKey::Status, false) => q!(
                "(CASE status WHEN 'draft' THEN 0 WHEN 'sent' THEN 1 WHEN 'delivered' THEN 2 \
                 WHEN 'completing' THEN 3 WHEN 'completed' THEN 4 WHEN 'declined' THEN 5 \
                 WHEN 'voided' THEN 6 ELSE 7 END)",
                ">",
                "ASC",
                rank
            ),
        }
        .map_err(db)?;
        rows.into_iter().map(Listed::try_from).collect()
    }
}

/// What a list sorts by (WEB-08).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortKey {
    /// Creation time.
    Created,
    /// Last change.
    Updated,
    /// Expiry; an envelope that never expires sorts after every date.
    Expires,
    /// Subject, ignoring case.
    Subject,
    /// Status, in lifecycle order: draft, sent, delivered, completing, completed,
    /// declined, voided, expired.
    Status,
}

/// A sort key and direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sort {
    /// The key.
    pub key: SortKey,
    /// Largest first.
    pub descending: bool,
}

/// The expiry an envelope that never expires sorts as: 9999-12-31T00:00:00Z, the
/// query's literal.
#[must_use]
pub fn never_expires() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(253_402_214_400).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

/// The lifecycle rank [`SortKey::Status`] sorts by (the query's `CASE`).
#[must_use]
pub fn status_rank(s: EnvelopeStatus) -> i32 {
    match s {
        EnvelopeStatus::Draft => 0,
        EnvelopeStatus::Sent => 1,
        EnvelopeStatus::Delivered => 2,
        EnvelopeStatus::Completing => 3,
        EnvelopeStatus::Completed => 4,
        EnvelopeStatus::Declined => 5,
        EnvelopeStatus::Voided => 6,
        EnvelopeStatus::Expired => 7,
    }
}

/// The sort value of the last row of a page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AfterKey {
    /// For [`SortKey::Created`], [`SortKey::Updated`] and [`SortKey::Expires`] (with
    /// [`never_expires`] for none).
    Time(OffsetDateTime),
    /// For [`SortKey::Subject`]: the subject as the database lower-cases it
    /// ([`Listed::subject_key`]).
    Text(String),
    /// For [`SortKey::Status`]: [`status_rank`].
    Rank(i32),
}

/// Where a page resumes: after this sort value and id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct After {
    /// The sort value.
    pub key: AfterKey,
    /// The id.
    pub id: EnvelopeId,
}

/// What a list keeps (WEB-08, UXW-01, UXW-02, UXW-03). Empty `statuses` keeps every
/// status; the default keeps every envelope in the lists (not deleted).
#[derive(Debug, Clone, Copy, Default)]
pub struct ListFilter<'a> {
    /// Any of these statuses.
    pub statuses: &'a [EnvelopeStatus],
    /// This sender's only.
    pub sender: Option<UserId>,
    /// Text the subject or a recipient's name or email contains.
    pub search: Option<&'a str>,
    /// `date_field` at or after.
    pub changed_from: Option<OffsetDateTime>,
    /// `date_field` before.
    pub changed_to: Option<OffsetDateTime>,
    /// Text a recipient's name or email contains (UXW-03).
    pub recipient: Option<&'a str>,
    /// Which date `changed_from` and `changed_to` bound (UXW-03); an envelope without
    /// that date (not sent, not completed) is outside any range.
    pub date_field: DateField,
    /// The member whose folders `folder` names, whose filing each row reports, and who
    /// `waiting` means.
    pub member: Option<UserId>,
    /// Where `member` filed it (UXW-02).
    pub folder: FolderFilter,
    /// The Deleted view: only envelopes removed from the lists (UXW-02); otherwise
    /// only those not removed.
    pub deleted: bool,
    /// The Inbox (UXW-01): only sent envelopes in which `member` is, by their email, a
    /// recipient whose turn it is and who acts through a link (not a copy, not an
    /// in-person or embedded signer). Each row reports that recipient.
    pub waiting: bool,
}

/// Which date a list's range bounds (UXW-03).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DateField {
    /// The last change (the default).
    #[default]
    Updated,
    /// Creation.
    Created,
    /// Sending.
    Sent,
    /// Completion.
    Completed,
}

impl DateField {
    /// The column, and the API's spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Updated => "updated_at",
            Self::Created => "created_at",
            Self::Sent => "sent_at",
            Self::Completed => "completed_at",
        }
    }
}

/// Where a list's member filed its envelopes (UXW-02).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FolderFilter {
    /// Wherever, or nowhere.
    #[default]
    Any,
    /// In none of their folders.
    None,
    /// In this folder of theirs (another member's folder matches nothing).
    In(FolderId),
}

/// A listed envelope and its subject sort key.
#[derive(Debug, Clone, PartialEq)]
pub struct Listed {
    /// The envelope.
    pub envelope: Envelope,
    /// The subject as the database lower-cases it: the cursor of a subject sort.
    pub subject_key: Personal<String>,
    /// The folder the filter's member filed it in.
    pub folder: Option<FolderId>,
    /// In the Inbox: the recipient the member is.
    pub my_recipient: Option<RecipientId>,
}

struct ListRow {
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
    updated_at: OffsetDateTime,
    deleted_at: Option<OffsetDateTime>,
    subject_key: String,
    folder_id: Option<Uuid>,
    my_recipient_id: Option<Uuid>,
}

impl TryFrom<ListRow> for Listed {
    type Error = StoreError;
    fn try_from(r: ListRow) -> Result<Self> {
        let envelope = Envelope::try_from(EnvelopeRow {
            id: r.id,
            sender_user_id: r.sender_user_id,
            status: r.status,
            subject: r.subject,
            message: r.message,
            routing_mode: r.routing_mode,
            expires_at: r.expires_at,
            reminder_policy: r.reminder_policy,
            signing_options: r.signing_options,
            seal_profile: r.seal_profile,
            completion_delivery: r.completion_delivery,
            template_ids: r.template_ids,
            version: r.version,
            chain_head: r.chain_head,
            created_at: r.created_at,
            sent_at: r.sent_at,
            completed_at: r.completed_at,
            voided_at: r.voided_at,
            updated_at: r.updated_at,
            deleted_at: r.deleted_at,
        })?;
        Ok(Self {
            envelope,
            subject_key: Personal(r.subject_key),
            folder: r.folder_id.map(FolderId),
            my_recipient: r.my_recipient_id.map(RecipientId),
        })
    }
}

/// A `LIKE` pattern matching any text that contains `s`, with `\`, `%` and `_` in `s`
/// escaped (the query names `\` as the escape character).
pub(crate) fn like_contains(s: &str) -> String {
    let mut p = String::with_capacity(s.len().saturating_add(2));
    p.push('%');
    for c in s.chars() {
        if matches!(c, '\\' | '%' | '_') {
            p.push('\\');
        }
        p.push(c);
    }
    p.push('%');
    p
}
