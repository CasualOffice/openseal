//! Personal-data controls (ASVS-16, ASVS-18; ASVS 8.3.2, 8.3.8; migration 0045): a
//! member's export of their own records, the erasure of a member's identity, account
//! retention rules per data class, legal holds, and what the retention job deletes.
//!
//! **What is never touched.** No statement here updates or deletes an audit event, an
//! admin event or a tombstone (the database refuses it anyway, docs/22 §9). A purge
//! deletes an envelope's relational records and keeps its chain, to which the engine has
//! already appended `envelope.purged` with the rule as its policy, and adds the
//! tombstone of docs/32 §7. Blob bytes are never deleted here: the records naming them
//! go, and the orphaned bytes are the orphan sweep's (`HRD-09`), which must keep a blob
//! any retained record still names (a key is a hash, so two records can share one).

use time::OffsetDateTime;

use super::{affected, text_enum};
use crate::admin_log::{AdminChange, Change};
use crate::error::{Result, StoreError, db};
use crate::ids::{EnvelopeId, TemplateId, UserId};
use crate::repo::accounts::SHARED_USER_SQLSTATE;
use crate::store::TenantTx;

text_enum! {
    /// A class of records a retention rule governs (docs/07 §Data classification).
    DataClass {
        /// Drafts never sent, by their last change.
        Draft = "draft",
        /// Envelopes declined, voided or expired, by their last change.
        Ended = "ended",
        /// Completed envelopes, by their completion.
        Completed = "completed",
        /// Ended staff sessions (revoked or expired), by their end.
        Sessions = "sessions",
    }
}

impl DataClass {
    /// Every class, in the order the API lists them.
    pub const ALL: [Self; 4] = [Self::Draft, Self::Ended, Self::Completed, Self::Sessions];

    /// The class named `s`, if any.
    #[must_use]
    pub fn from_name(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == s)
    }

    /// The purge policy text the engine records in `envelope.purged`.
    #[must_use]
    pub fn policy(self) -> String {
        format!("retention.{}", self.as_str())
    }
}

/// The longest a rule may keep a record: 100 years (the column's check).
pub const MAX_KEEP_DAYS: i32 = 36_500;

/// One account rule: records of `data_class` are kept `keep_days` after their last
/// change, then deleted by the retention job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionRule {
    /// The class.
    pub data_class: DataClass,
    /// Days kept, 1 to [`MAX_KEEP_DAYS`].
    pub keep_days: i32,
    /// When the rule was last set.
    pub updated_at: OffsetDateTime,
}

/// An envelope a rule has expired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    /// The envelope.
    pub envelope: EnvelopeId,
    /// The class whose rule expired it.
    pub class: DataClass,
    /// The time the rule counts from (its last change, or its completion).
    pub since: OffsetDateTime,
}

/// What a dry run of the retention job would delete now: the envelopes (at most the
/// limit asked for) and how many there are of each class, the sessions, and the
/// envelopes a legal hold keeps although a rule has expired them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetentionPreview {
    /// Expired envelopes, oldest first, at most the limit.
    pub envelopes: Vec<Candidate>,
    /// Expired envelopes per class (all of them, not only those listed).
    pub counts: Vec<(DataClass, i64)>,
    /// Ended staff sessions the `sessions` rule has expired.
    pub sessions: i64,
    /// Envelopes a rule has expired that a legal hold keeps.
    pub held: i64,
}

/// One envelope a member sent, for their export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentEnvelope {
    /// The envelope.
    pub id: EnvelopeId,
    /// Its status.
    pub status: String,
    /// Its subject (personal data of the member and the recipients).
    pub subject: String,
    /// Created.
    pub created_at: OffsetDateTime,
    /// Last change.
    pub updated_at: OffsetDateTime,
    /// Completed, when it did.
    pub completed_at: Option<OffsetDateTime>,
    /// Whether it was purged (only ids and statuses remain).
    pub purged: bool,
}

/// One template a member owns, for their export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedTemplate {
    /// The template.
    pub id: TemplateId,
    /// Its name.
    pub name: String,
    /// Created.
    pub created_at: OffsetDateTime,
}

/// The records a purge deleted, per table, for the job's report.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Purged {
    /// Documents and their versions.
    pub documents: u64,
    /// Recipients and what hangs off them (tokens, codes, adoptions, requirements).
    pub recipients: u64,
    /// Fields and their values.
    pub fields: u64,
}

/// Personal-data controls of this account. Reached through `TenantTx::privacy`.
#[derive(Debug)]
pub struct Privacy<'t> {
    pub(crate) tx: &'t mut TenantTx,
}

impl Privacy<'_> {
    // ------------------------------------------------------------------ rules

    /// This account's retention rules, in [`DataClass::ALL`] order; a class without a
    /// rule keeps its records for ever.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0010` for a class the store does not know.
    pub async fn rules(&mut self) -> Result<Vec<RetentionRule>> {
        let acct = self.tx.acct();
        let rows = sqlx::query!(
            "SELECT data_class, keep_days, updated_at FROM retention_rules \
             WHERE account_id = $1",
            acct
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        let mut out = rows
            .into_iter()
            .map(|r| {
                Ok(RetentionRule {
                    data_class: DataClass::parse(&r.data_class, "data_class")?,
                    keep_days: r.keep_days,
                    updated_at: r.updated_at,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        out.sort_by_key(|r| DataClass::ALL.iter().position(|c| *c == r.data_class));
        Ok(out)
    }

    /// Set (`Some(days)`) or remove (`None`) the rule of `class`, with its admin event
    /// (`retention.rule_set`, the old and new days). Returns whether anything changed.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` for days outside 1 to [`MAX_KEEP_DAYS`]; `CS-DB-0001`.
    pub async fn set_rule(
        &mut self,
        class: DataClass,
        keep_days: Option<i32>,
        now: OffsetDateTime,
    ) -> Result<bool> {
        if keep_days.is_some_and(|d| !(1..=MAX_KEEP_DAYS).contains(&d)) {
            return Err(StoreError::Constraint {
                constraint: Some("retention_rules_keep_days_check".into()),
                sqlstate: "23514".into(),
            });
        }
        let acct = self.tx.acct();
        let old = sqlx::query_scalar!(
            "SELECT keep_days FROM retention_rules WHERE account_id = $1 AND data_class = $2 \
             FOR UPDATE",
            acct,
            class.as_str()
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        if old == keep_days {
            return Ok(false);
        }
        match keep_days {
            Some(days) => {
                sqlx::query!(
                    "INSERT INTO retention_rules (account_id, data_class, keep_days, updated_at) \
                     VALUES ($1, $2, $3, $4) ON CONFLICT (account_id, data_class) \
                     DO UPDATE SET keep_days = EXCLUDED.keep_days, updated_at = EXCLUDED.updated_at",
                    acct,
                    class.as_str(),
                    days,
                    now
                )
                .execute(self.tx.conn())
                .await
                .map_err(db)?;
            }
            None => {
                sqlx::query!(
                    "DELETE FROM retention_rules WHERE account_id = $1 AND data_class = $2",
                    acct,
                    class.as_str()
                )
                .execute(self.tx.conn())
                .await
                .map_err(db)?;
            }
        }
        self.tx
            .admin_event(AdminChange::new("retention.rule_set").change(Change::new(
                class.as_str(),
                old.map(serde_json::Value::from),
                keep_days.map(serde_json::Value::from),
            )))
            .await?;
        Ok(true)
    }

    // ------------------------------------------------------------------ holds

    /// Since when `envelope` is under legal hold, if it is.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` for no such envelope here; `CS-DB-0001`.
    pub async fn legal_hold(&mut self, envelope: EnvelopeId) -> Result<Option<OffsetDateTime>> {
        let acct = self.tx.acct();
        let row = sqlx::query_scalar!(
            "SELECT legal_hold_at FROM envelopes WHERE account_id = $1 AND id = $2",
            acct,
            envelope.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        row.ok_or(StoreError::NotFound { entity: "envelope" })
    }

    /// Place (`hold`) or release `envelope`'s legal hold at `now`, with its admin event
    /// (`envelope.legal_hold_set` or `envelope.legal_hold_released`). A hold keeps the
    /// envelope from every retention rule until released; it changes nothing of the
    /// agreement, so it is not an audit event. Returns whether anything changed.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` for no such envelope here; `CS-DB-0001`.
    pub async fn set_legal_hold(
        &mut self,
        envelope: EnvelopeId,
        hold: bool,
        now: OffsetDateTime,
    ) -> Result<bool> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE envelopes SET legal_hold_at = CASE WHEN $3 THEN $4::timestamptz END \
             WHERE account_id = $1 AND id = $2 AND (legal_hold_at IS NULL) = $3",
            acct,
            envelope.0,
            hold,
            now
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        if done.rows_affected() == 0 {
            // Unchanged, or no such envelope.
            self.legal_hold(envelope).await?;
            return Ok(false);
        }
        let action = if hold {
            "envelope.legal_hold_set"
        } else {
            "envelope.legal_hold_released"
        };
        self.tx
            .admin_event(AdminChange::new(action).target("envelope", envelope.0))
            .await?;
        Ok(true)
    }

    // ------------------------------------------------------------------ the job

    /// Envelopes whose class's rule has expired them at `now`, oldest first, at most
    /// `limit`: not under legal hold, not purged, and in a class with a rule. An
    /// envelope in flight (sent, delivered, completing) is in no class.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0010` for a class the store does not know.
    pub async fn expired(&mut self, now: OffsetDateTime, limit: i64) -> Result<Vec<Candidate>> {
        let acct = self.tx.acct();
        let rows = sqlx::query!(
            r#"SELECT e.id, r.data_class, c.since AS "since!"
               FROM envelopes AS e
               CROSS JOIN LATERAL (SELECT
                   CASE WHEN e.status = 'draft' THEN 'draft'
                        WHEN e.status = 'completed' THEN 'completed'
                        WHEN e.status IN ('declined', 'voided', 'expired') THEN 'ended' END AS class,
                   CASE WHEN e.status = 'completed' THEN COALESCE(e.completed_at, e.updated_at)
                        ELSE e.updated_at END AS since) AS c
               JOIN retention_rules AS r
                 ON r.account_id = e.account_id AND r.data_class = c.class
               JOIN envelope_states AS s
                 ON s.account_id = e.account_id AND s.envelope_id = e.id
              WHERE e.account_id = $1 AND e.legal_hold_at IS NULL
                AND COALESCE((s.state ->> 'purged')::boolean, false) = false
                AND c.since + make_interval(days => r.keep_days) <= $2
              ORDER BY c.since, e.id
              LIMIT $3"#,
            acct,
            now,
            limit.clamp(1, 10_000)
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        rows.into_iter()
            .map(|r| {
                Ok(Candidate {
                    envelope: EnvelopeId(r.id),
                    class: DataClass::parse(&r.data_class, "data_class")?,
                    since: r.since,
                })
            })
            .collect()
    }

    /// The retention job's dry run at `now`: what it would delete, and what a hold keeps.
    /// Changes nothing.
    ///
    /// # Errors
    ///
    /// As [`Privacy::expired`].
    pub async fn preview(&mut self, now: OffsetDateTime, limit: i64) -> Result<RetentionPreview> {
        let envelopes = self.expired(now, limit).await?;
        let acct = self.tx.acct();
        let counts = sqlx::query!(
            r#"SELECT r.data_class, count(*) AS "n!",
                      count(*) FILTER (WHERE e.legal_hold_at IS NOT NULL) AS "held!"
               FROM envelopes AS e
               JOIN retention_rules AS r ON r.account_id = e.account_id AND r.data_class =
                   CASE WHEN e.status = 'draft' THEN 'draft'
                        WHEN e.status = 'completed' THEN 'completed'
                        WHEN e.status IN ('declined', 'voided', 'expired') THEN 'ended' END
               JOIN envelope_states AS s ON s.account_id = e.account_id AND s.envelope_id = e.id
              WHERE e.account_id = $1
                AND COALESCE((s.state ->> 'purged')::boolean, false) = false
                AND (CASE WHEN e.status = 'completed' THEN COALESCE(e.completed_at, e.updated_at)
                          ELSE e.updated_at END) + make_interval(days => r.keep_days) <= $2
              GROUP BY r.data_class"#,
            acct,
            now
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        let mut out = RetentionPreview {
            envelopes,
            sessions: self.expired_sessions(now).await?,
            ..RetentionPreview::default()
        };
        for c in DataClass::ALL {
            if let Some(r) = counts.iter().find(|r| r.data_class == c.as_str()) {
                out.counts.push((c, r.n.saturating_sub(r.held)));
                out.held = out.held.saturating_add(r.held);
            } else if c != DataClass::Sessions {
                out.counts.push((c, 0));
            }
        }
        Ok(out)
    }

    /// How many ended staff sessions the `sessions` rule has expired at `now`.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn expired_sessions(&mut self, now: OffsetDateTime) -> Result<i64> {
        let acct = self.tx.acct();
        sqlx::query_scalar!(
            r#"SELECT count(*) AS "n!" FROM staff_sessions AS s
               JOIN retention_rules AS r ON r.account_id = s.account_id AND r.data_class = 'sessions'
              WHERE s.account_id = $1
                AND LEAST(COALESCE(s.revoked_at, s.expires_at), s.expires_at)
                    + make_interval(days => r.keep_days) <= $2"#,
            acct,
            now
        )
        .fetch_one(self.tx.conn())
        .await
        .map_err(db)
    }

    /// Delete the ended staff sessions the `sessions` rule has expired at `now`; returns
    /// how many. A live session never ends this way (it has not ended).
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn purge_sessions(&mut self, now: OffsetDateTime) -> Result<u64> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "DELETE FROM staff_sessions AS s USING retention_rules AS r \
             WHERE s.account_id = $1 AND r.account_id = s.account_id \
               AND r.data_class = 'sessions' \
               AND LEAST(COALESCE(s.revoked_at, s.expires_at), s.expires_at) \
                   + make_interval(days => r.keep_days) <= $2",
            acct,
            now
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(done.rows_affected())
    }

    /// Record `envelope`'s tombstone (docs/32 §7): its chain head and length, the first
    /// sealed document's hash, the purge time and policy. Once: a second call finds it and
    /// changes nothing. Call after `envelope.purged` is in the chain.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` for an envelope without events; `CS-DB-0001`.
    pub async fn tombstone(
        &mut self,
        envelope: EnvelopeId,
        policy: &str,
        now: OffsetDateTime,
    ) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            r#"INSERT INTO envelope_tombstones
                   (account_id, envelope_id, chain_head, event_count, sealed_sha256, purged_at, policy)
               SELECT e.account_id, e.id, e.chain_head,
                      (SELECT count(*) FROM audit_events AS a
                        WHERE a.account_id = e.account_id AND a.envelope_id = e.id),
                      (SELECT v.sha256 FROM document_versions AS v
                         JOIN documents AS d ON d.account_id = v.account_id AND d.id = v.document_id
                        WHERE d.account_id = e.account_id AND d.envelope_id = e.id
                          AND v.kind = 'sealed'
                        ORDER BY d.ord, v.created_at LIMIT 1),
                      $3, left($4, 255)
                 FROM envelopes AS e
                WHERE e.account_id = $1 AND e.id = $2 AND e.chain_head IS NOT NULL
               ON CONFLICT (account_id, envelope_id) DO NOTHING"#,
            acct,
            envelope.0,
            now,
            policy
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        if done.rows_affected() == 0 && !self.has_tombstone(envelope).await? {
            return Err(StoreError::NotFound {
                entity: "audit chain",
            });
        }
        Ok(())
    }

    /// Whether `envelope` has a tombstone.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn has_tombstone(&mut self, envelope: EnvelopeId) -> Result<bool> {
        let acct = self.tx.acct();
        sqlx::query_scalar!(
            r#"SELECT EXISTS (SELECT 1 FROM envelope_tombstones
                               WHERE account_id = $1 AND envelope_id = $2) AS "x!""#,
            acct,
            envelope.0
        )
        .fetch_one(self.tx.conn())
        .await
        .map_err(db)
    }

    /// Delete a purged envelope's relational records that hold personal data or
    /// document content: documents and their versions (the blobs they name become
    /// orphans, `HRD-09`), recipients and everything hanging off them (tokens, one-time
    /// codes, SSO challenges, authentication requirements, adopted signatures), fields
    /// and their values, comments and custom fields; its certificate's key and void
    /// reason; its bulk-send row's input. The envelope row (ids, status, times, chain
    /// head), its workflow state (already scrubbed by the engine), its audit events and
    /// its tombstone stay. Refused unless the envelope's state is purged. Idempotent.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` when the envelope is not purged; `CS-DB-0003` for no such envelope;
    /// `CS-DB-0001`.
    pub async fn purge_records(&mut self, envelope: EnvelopeId) -> Result<Purged> {
        let acct = self.tx.acct();
        let purged = sqlx::query_scalar!(
            r#"SELECT COALESCE((state ->> 'purged')::boolean, false) AS "purged!"
               FROM envelope_states WHERE account_id = $1 AND envelope_id = $2"#,
            acct,
            envelope.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?
        .ok_or(StoreError::NotFound { entity: "envelope" })?;
        if !purged {
            return Err(StoreError::Constraint {
                constraint: Some("envelope_not_purged".into()),
                sqlstate: "23514".into(),
            });
        }
        let e = envelope.0;
        let mut out = Purged::default();
        let c = self.tx.conn();
        let fields = sqlx::query!(
            "DELETE FROM field_values WHERE account_id = $1 AND envelope_id = $2",
            acct,
            e
        )
        .execute(&mut *c)
        .await
        .map_err(db)?
        .rows_affected();
        let fields = fields.saturating_add(
            sqlx::query!(
                "DELETE FROM fields WHERE account_id = $1 AND envelope_id = $2",
                acct,
                e
            )
            .execute(&mut *c)
            .await
            .map_err(db)?
            .rows_affected(),
        );
        out.fields = fields;
        sqlx::query!(
            "DELETE FROM comments WHERE account_id = $1 AND envelope_id = $2",
            acct,
            e
        )
        .execute(&mut *c)
        .await
        .map_err(db)?;
        sqlx::query!(
            "DELETE FROM envelope_custom_fields WHERE account_id = $1 AND envelope_id = $2",
            acct,
            e
        )
        .execute(&mut *c)
        .await
        .map_err(db)?;
        // What hangs off the recipients, then the recipients.
        sqlx::query!(
            "DELETE FROM signature_adoptions AS a USING recipients AS r \
             WHERE a.account_id = $1 AND r.account_id = a.account_id \
               AND r.id = a.recipient_id AND r.envelope_id = $2",
            acct,
            e
        )
        .execute(&mut *c)
        .await
        .map_err(db)?;
        sqlx::query!(
            "DELETE FROM recipient_auth_requirements AS a USING recipients AS r \
             WHERE a.account_id = $1 AND r.account_id = a.account_id \
               AND r.id = a.recipient_id AND r.envelope_id = $2",
            acct,
            e
        )
        .execute(&mut *c)
        .await
        .map_err(db)?;
        sqlx::query!(
            "DELETE FROM recipient_otp_codes AS o USING recipients AS r \
             WHERE o.account_id = $1 AND r.account_id = o.account_id \
               AND r.id = o.recipient_id AND r.envelope_id = $2",
            acct,
            e
        )
        .execute(&mut *c)
        .await
        .map_err(db)?;
        sqlx::query!(
            "DELETE FROM recipient_sso_challenges AS o USING recipients AS r \
             WHERE o.account_id = $1 AND r.account_id = o.account_id \
               AND r.id = o.recipient_id AND r.envelope_id = $2",
            acct,
            e
        )
        .execute(&mut *c)
        .await
        .map_err(db)?;
        sqlx::query!(
            "DELETE FROM recipient_tokens WHERE account_id = $1 AND envelope_id = $2",
            acct,
            e
        )
        .execute(&mut *c)
        .await
        .map_err(db)?;
        // A recipient another recipient was reassigned to is referenced by it: clear the
        // references first.
        sqlx::query!(
            "UPDATE recipients SET reassigned_to = NULL \
             WHERE account_id = $1 AND envelope_id = $2 AND reassigned_to IS NOT NULL",
            acct,
            e
        )
        .execute(&mut *c)
        .await
        .map_err(db)?;
        out.recipients = sqlx::query!(
            "DELETE FROM recipients WHERE account_id = $1 AND envelope_id = $2",
            acct,
            e
        )
        .execute(&mut *c)
        .await
        .map_err(db)?
        .rows_affected();
        sqlx::query!(
            "DELETE FROM document_versions AS v USING documents AS d \
             WHERE v.account_id = $1 AND d.account_id = v.account_id \
               AND d.id = v.document_id AND d.envelope_id = $2",
            acct,
            e
        )
        .execute(&mut *c)
        .await
        .map_err(db)?;
        out.documents = sqlx::query!(
            "DELETE FROM documents WHERE account_id = $1 AND envelope_id = $2",
            acct,
            e
        )
        .execute(&mut *c)
        .await
        .map_err(db)?
        .rows_affected();
        sqlx::query!(
            "UPDATE envelopes SET certificate_sha256 = NULL, void_reason = NULL \
             WHERE account_id = $1 AND id = $2",
            acct,
            e
        )
        .execute(&mut *c)
        .await
        .map_err(db)?;
        sqlx::query!(
            "UPDATE bulk_send_rows SET input = '{}'::jsonb \
             WHERE account_id = $1 AND envelope_id = $2",
            acct,
            e
        )
        .execute(&mut *c)
        .await
        .map_err(db)?;
        Ok(out)
    }

    // ------------------------------------------------------------------ members

    /// The envelopes `user` sent in this account, newest first: the export's list of
    /// their agreements (ids, statuses, subjects and times; the documents and
    /// certificates are fetched through their own routes).
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn sent_by(&mut self, user: UserId) -> Result<Vec<SentEnvelope>> {
        let acct = self.tx.acct();
        let rows = sqlx::query!(
            r#"SELECT e.id, e.status, e.subject, e.created_at, e.updated_at AS "updated_at!",
                      e.completed_at,
                      COALESCE((s.state ->> 'purged')::boolean, false) AS "purged!"
               FROM envelopes AS e
               LEFT JOIN envelope_states AS s ON s.account_id = e.account_id AND s.envelope_id = e.id
              WHERE e.account_id = $1 AND e.sender_user_id = $2
              ORDER BY e.created_at DESC, e.id"#,
            acct,
            user.0
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(rows
            .into_iter()
            .map(|r| SentEnvelope {
                id: EnvelopeId(r.id),
                status: r.status,
                subject: r.subject,
                created_at: r.created_at,
                updated_at: r.updated_at,
                completed_at: r.completed_at,
                purged: r.purged,
            })
            .collect())
    }

    /// The templates `user` owns in this account, by name.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn templates_of(&mut self, user: UserId) -> Result<Vec<OwnedTemplate>> {
        let acct = self.tx.acct();
        let rows = sqlx::query!(
            "SELECT id, name, created_at FROM templates \
             WHERE account_id = $1 AND owner_user_id = $2 ORDER BY lower(name), id",
            acct,
            user.0
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(rows
            .into_iter()
            .map(|r| OwnedTemplate {
                id: TemplateId(r.id),
                name: r.name,
                created_at: r.created_at,
            })
            .collect())
    }

    /// Since when `user`'s identity is erased, if it is.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` for no such member here; `CS-DB-0001`.
    pub async fn erased_at(&mut self, user: UserId) -> Result<Option<OffsetDateTime>> {
        let acct = self.tx.acct();
        sqlx::query_scalar!(
            "SELECT u.erased_at FROM account_memberships AS m JOIN users AS u ON u.id = m.user_id \
             WHERE m.account_id = $1 AND m.user_id = $2",
            acct,
            user.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?
        .ok_or(StoreError::NotFound { entity: "user" })
    }

    /// Erase `user`'s identity at `now` (ASVS-16): their name and email replaced by a
    /// marker, their login binding, password and second factor removed, the user and
    /// their membership disabled; their sessions here, saved signature and initials,
    /// notices, open invitations and password resets deleted; the API clients they own
    /// revoked. The membership row and the user's id stay, because the envelopes they
    /// sent and the admin log name them. One admin event, `member.erased`, records it
    /// with how (`identity: pseudonymised`). Only a member of this account and of no
    /// other (SEC-ID-01).
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when not a member, or already erased; `CS-DB-0009`
    /// ([`StoreError::is_shared_user`]) when also a member of another account;
    /// `CS-DB-0001`.
    pub async fn erase_member(&mut self, user: UserId, now: OffsetDateTime) -> Result<()> {
        let acct = self.tx.acct();
        let erased = sqlx::query_scalar!(
            r#"SELECT openseal_erase_user($1, $2) AS "erased!""#,
            user.0,
            now
        )
        .fetch_one(self.tx.conn())
        .await
        .map_err(db)?;
        if !erased {
            let shared = sqlx::query_scalar!(
                r#"SELECT openseal_user_in_other_account($1) AS "shared!""#,
                user.0
            )
            .fetch_one(self.tx.conn())
            .await
            .map_err(db)?;
            if shared {
                return Err(StoreError::Refused {
                    sqlstate: SHARED_USER_SQLSTATE.to_owned(),
                });
            }
            return affected(0, "user");
        }
        let c = self.tx.conn();
        for q in [
            sqlx::query!(
                "DELETE FROM staff_sessions WHERE account_id = $1 AND user_id = $2",
                acct,
                user.0
            ),
            sqlx::query!(
                "DELETE FROM member_profiles WHERE account_id = $1 AND user_id = $2",
                acct,
                user.0
            ),
            sqlx::query!(
                "DELETE FROM user_invitations WHERE account_id = $1 AND user_id = $2",
                acct,
                user.0
            ),
            sqlx::query!(
                "DELETE FROM password_resets WHERE account_id = $1 AND user_id = $2",
                acct,
                user.0
            ),
        ] {
            q.execute(&mut *c).await.map_err(db)?;
        }
        sqlx::query!(
            "UPDATE api_clients SET revoked_at = COALESCE(revoked_at, $3) \
             WHERE account_id = $1 AND owner_user_id = $2",
            acct,
            user.0,
            now
        )
        .execute(&mut *c)
        .await
        .map_err(db)?;
        self.tx
            .admin_event(
                AdminChange::new("member.erased")
                    .target("user", user.0)
                    .change(Change::new(
                        "identity",
                        None,
                        Some(serde_json::Value::from("pseudonymised")),
                    )),
            )
            .await
    }

    /// How many enabled members of this account hold the built-in administrator
    /// profile, other than `except`: erasing the last one would leave the workspace
    /// without anyone to administer it.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn other_administrators(&mut self, except: UserId) -> Result<i64> {
        let acct = self.tx.acct();
        sqlx::query_scalar!(
            r#"SELECT count(*) AS "n!" FROM account_memberships AS m
               JOIN permission_profiles AS p
                 ON p.account_id = m.account_id AND p.id = m.permission_profile_id
               JOIN users AS u ON u.id = m.user_id
              WHERE m.account_id = $1 AND m.user_id <> $2 AND p.kind = 'admin'
                AND m.disabled_at IS NULL AND u.disabled_at IS NULL"#,
            acct,
            except.0
        )
        .fetch_one(self.tx.conn())
        .await
        .map_err(db)
    }
}
