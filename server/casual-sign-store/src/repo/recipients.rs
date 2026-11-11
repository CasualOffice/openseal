//! Recipients (docs/22 §5, docs/24 §3) and their invitation tokens (docs/22 §2, SEC-A01).

use casual_sign_audit::Personal;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{affected, text_enum};
use crate::error::{Result, StoreError, db};
use crate::ids::{EnvelopeId, RecipientId, RecipientTokenId, UserId};
use crate::store::TenantTx;

text_enum!(
    /// A recipient's type (docs/22 §5).
    RecipientType {
        /// Signs.
        Signer = "signer",
        /// Signs in person, hosted by staff.
        InPersonSigner = "in_person_signer",
        /// Approves or declines.
        Approver = "approver",
        /// Needs to view.
        Viewer = "viewer",
        /// Receives a copy.
        Cc = "cc",
        /// Allowed to edit.
        Editor = "editor",
        /// Updates recipients.
        Intermediary = "intermediary",
        /// Specifies recipients.
        Agent = "agent",
        /// Witnesses.
        Witness = "witness",
        /// Legal-entity seal.
        Seal = "seal",
        /// Notary.
        Notary = "notary",
    }
);

text_enum!(
    /// A recipient's state (docs/24 §3).
    RecipientStatus {
        /// Not yet reached by routing.
        Created = "created",
        /// Invited.
        Sent = "sent",
        /// Opened the link.
        Delivered = "delivered",
        /// Passed authentication.
        Authenticated = "authenticated",
        /// Finished.
        Completed = "completed",
        /// Declined.
        Declined = "declined",
        /// Invitation bounced.
        AutoResponded = "auto_responded",
        /// Replaced by another recipient.
        Reassigned = "reassigned",
    }
);

text_enum!(
    /// How a recipient is reached.
    Delivery {
        /// By email.
        Email = "email",
        /// By SMS.
        Sms = "sms",
        /// Not at all: the integrator's embedded session.
        None = "none",
    }
);

text_enum!(
    /// What an invitation token is for.
    TokenPurpose {
        /// The first invitation.
        Invitation = "invitation",
        /// A reminder (always a new token).
        Reminder = "reminder",
        /// An embedded signing view.
        Embedded = "embedded",
        /// The completed copy.
        CompletedCopy = "completed_copy",
    }
);

/// A new recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRecipient {
    /// Host-minted id.
    pub id: RecipientId,
    /// Envelope.
    pub envelope_id: EnvelopeId,
    /// Routing order, 1 to 999.
    pub routing_order: i32,
    /// Type.
    pub kind: RecipientType,
    /// Template role name.
    pub role_name: Option<String>,
    /// Name (personal data).
    pub name: Personal<String>,
    /// Email (personal data).
    pub email: Option<Personal<String>>,
    /// Phone (personal data).
    pub phone: Option<Personal<String>>,
    /// Delivery.
    pub delivery: Delivery,
    /// Embedded client user id.
    pub embedded_client_user_id: Option<String>,
    /// Language.
    pub language: Option<String>,
}

/// A stored recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipient {
    /// As inserted.
    pub recipient: NewRecipient,
    /// State.
    pub status: RecipientStatus,
    /// Decline reason (personal data).
    pub declined_reason: Option<Personal<String>>,
}

/// A new invitation token: only its hash is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewToken {
    /// Host-minted id.
    pub id: RecipientTokenId,
    /// Envelope.
    pub envelope_id: EnvelopeId,
    /// Recipient.
    pub recipient_id: RecipientId,
    /// SHA-256 of the 256-bit token.
    pub token_sha256: [u8; 32],
    /// Purpose.
    pub purpose: TokenPurpose,
    /// Expiry.
    pub expires_at: OffsetDateTime,
}

/// A row as selected.
struct RecipientRow {
    id: Uuid,
    envelope_id: Uuid,
    routing_order: i32,
    kind: String,
    role_name: Option<String>,
    name: String,
    email: Option<String>,
    phone: Option<String>,
    status: String,
    delivery: String,
    embedded_client_user_id: Option<String>,
    language: Option<String>,
    declined_reason: Option<String>,
}

impl TryFrom<RecipientRow> for Recipient {
    type Error = StoreError;
    fn try_from(r: RecipientRow) -> Result<Self> {
        Ok(Self {
            recipient: NewRecipient {
                id: RecipientId(r.id),
                envelope_id: EnvelopeId(r.envelope_id),
                routing_order: r.routing_order,
                kind: RecipientType::parse(&r.kind, "type")?,
                role_name: r.role_name,
                name: Personal(r.name),
                email: r.email.map(Personal),
                phone: r.phone.map(Personal),
                delivery: Delivery::parse(&r.delivery, "delivery")?,
                embedded_client_user_id: r.embedded_client_user_id,
                language: r.language,
            },
            status: RecipientStatus::parse(&r.status, "status")?,
            declined_reason: r.declined_reason.map(Personal),
        })
    }
}

/// Recipients of this account. Reached through `TenantTx::recipients`.
#[derive(Debug)]
pub struct Recipients<'t> {
    pub(crate) tx: &'t mut TenantTx,
}

impl Recipients<'_> {
    /// Add a recipient to an envelope of this account.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` when the envelope is not this account's, or a value is out of bounds.
    pub async fn insert(&mut self, n: &NewRecipient) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "INSERT INTO recipients (id, account_id, envelope_id, routing_order, type, role_name, \
             name, email, phone, delivery, embedded_client_user_id, language) \
             VALUES ($2, $1, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
            acct,
            n.id.0,
            n.envelope_id.0,
            n.routing_order,
            n.kind.as_str(),
            n.role_name.as_deref(),
            n.name.get(),
            n.email.as_ref().map(|e| e.get().as_str()),
            n.phone.as_ref().map(|p| p.get().as_str()),
            n.delivery.as_str(),
            n.embedded_client_user_id.as_deref(),
            n.language.as_deref()
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// A recipient of this account.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn get(&mut self, id: RecipientId) -> Result<Option<Recipient>> {
        let acct = self.tx.acct();
        let row = sqlx::query_as!(
            RecipientRow,
            r#"SELECT id, envelope_id, routing_order, type AS kind, role_name, name, email, phone,
                      status, delivery, embedded_client_user_id, language, declined_reason
                 FROM recipients WHERE account_id = $1 AND id = $2"#,
            acct,
            id.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        row.map(Recipient::try_from).transpose()
    }

    /// An envelope's recipients in routing order.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn list(&mut self, envelope: EnvelopeId) -> Result<Vec<Recipient>> {
        let acct = self.tx.acct();
        let rows = sqlx::query_as!(
            RecipientRow,
            r#"SELECT id, envelope_id, routing_order, type AS kind, role_name, name, email, phone,
                      status, delivery, embedded_client_user_id, language, declined_reason
                 FROM recipients WHERE account_id = $1 AND envelope_id = $2
                ORDER BY routing_order, created_at, id"#,
            acct,
            envelope.0
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        rows.into_iter().map(Recipient::try_from).collect()
    }

    /// Record a recipient's new state (decided by the workflow engine).
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when this account has no such recipient.
    pub async fn set_status(
        &mut self,
        id: RecipientId,
        status: RecipientStatus,
        declined_reason: Option<&Personal<String>>,
    ) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE recipients SET status = $3, declined_reason = COALESCE($4, declined_reason) \
             WHERE account_id = $1 AND id = $2",
            acct,
            id.0,
            status.as_str(),
            declined_reason.map(|r| r.get().as_str())
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        affected(done.rows_affected(), "recipient")
    }

    /// Store a new invitation token's hash.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` when the recipient or envelope is not this account's; `CS-DB-0006`
    /// for a hash already stored.
    pub async fn issue_token(&mut self, t: &NewToken) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "INSERT INTO recipient_tokens (id, account_id, envelope_id, recipient_id, token_sha256, \
             purpose, expires_at) VALUES ($2, $1, $3, $4, $5, $6, $7)",
            acct,
            t.id.0,
            t.envelope_id.0,
            t.recipient_id.0,
            t.token_sha256.as_slice(),
            t.purpose.as_str(),
            t.expires_at
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// Revoke every live token of a recipient at `at` (docs/24 `RevokeTokens`); returns
    /// how many were revoked.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn revoke_tokens(
        &mut self,
        recipient: RecipientId,
        at: OffsetDateTime,
    ) -> Result<u64> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE recipient_tokens SET revoked_at = $3 \
             WHERE account_id = $1 AND recipient_id = $2 AND revoked_at IS NULL",
            acct,
            recipient.0,
            at
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(done.rows_affected())
    }
}

/// A recipient token as stored (never the token itself).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRecord {
    /// The record's id.
    pub id: RecipientTokenId,
    /// The envelope.
    pub envelope_id: EnvelopeId,
    /// The recipient.
    pub recipient_id: RecipientId,
    /// What it is for.
    pub purpose: TokenPurpose,
    /// SHA-256 of the browser session it was bound to on first use, once bound.
    pub session_sha256: Option<[u8; 32]>,
    /// Expiry.
    pub expires_at: OffsetDateTime,
    /// Revocation, when revoked.
    pub revoked_at: Option<OffsetDateTime>,
}

impl Recipients<'_> {
    /// Write the server's projection of a recipient (migration 0008): update this
    /// account's row of that envelope, or insert it.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` when the envelope is not this account's or a value is out of bounds;
    /// `CS-DB-0006` when the id belongs to another envelope.
    pub async fn upsert(
        &mut self,
        n: &NewRecipient,
        status: RecipientStatus,
        declined_reason: Option<&Personal<String>>,
    ) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE recipients SET routing_order = $4, type = $5, role_name = $6, name = $7, \
               email = $8, phone = $9, delivery = $10, embedded_client_user_id = $11, \
               language = $12, status = $13, declined_reason = $14 \
             WHERE account_id = $1 AND id = $2 AND envelope_id = $3",
            acct,
            n.id.0,
            n.envelope_id.0,
            n.routing_order,
            n.kind.as_str(),
            n.role_name.as_deref(),
            n.name.get(),
            n.email.as_ref().map(|e| e.get().as_str()),
            n.phone.as_ref().map(|p| p.get().as_str()),
            n.delivery.as_str(),
            n.embedded_client_user_id.as_deref(),
            n.language.as_deref(),
            status.as_str(),
            declined_reason.map(|r| r.get().as_str())
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        if done.rows_affected() == 1 {
            return Ok(());
        }
        self.insert(n).await?;
        self.set_status(n.id, status, declined_reason).await
    }

    /// Delete this envelope's recipient rows not in `keep` that no token, recipient,
    /// field or adoption references (a draft's removed recipients); returns how many
    /// went. Rows still referenced stay: the engine's state, not the projection, says
    /// who is a recipient.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn prune(&mut self, envelope: EnvelopeId, keep: &[RecipientId]) -> Result<u64> {
        let acct = self.tx.acct();
        let keep: Vec<Uuid> = keep.iter().map(|r| r.0).collect();
        let done = sqlx::query!(
            "DELETE FROM recipients AS r WHERE r.account_id = $1 AND r.envelope_id = $2 \
               AND NOT (r.id = ANY($3)) \
               AND NOT EXISTS (SELECT 1 FROM recipient_tokens t \
                                WHERE t.account_id = r.account_id AND t.recipient_id = r.id) \
               AND NOT EXISTS (SELECT 1 FROM recipients o \
                                WHERE o.account_id = r.account_id AND o.reassigned_to = r.id) \
               AND NOT EXISTS (SELECT 1 FROM fields f \
                                WHERE f.account_id = r.account_id AND f.recipient_id = r.id) \
               AND NOT EXISTS (SELECT 1 FROM signature_adoptions s \
                                WHERE s.account_id = r.account_id AND s.recipient_id = r.id)",
            acct,
            envelope.0,
            &keep
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(done.rows_affected())
    }

    /// The token record a token's hash names in this account, live or not.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn token(&mut self, token_sha256: &[u8; 32]) -> Result<Option<TokenRecord>> {
        let acct = self.tx.acct();
        let row = sqlx::query!(
            "SELECT id, envelope_id, recipient_id, purpose, session_sha256, expires_at, revoked_at \
             FROM recipient_tokens WHERE account_id = $1 AND token_sha256 = $2",
            acct,
            token_sha256.as_slice()
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        row.map(|r| {
            Ok(TokenRecord {
                id: RecipientTokenId(r.id),
                envelope_id: EnvelopeId(r.envelope_id),
                recipient_id: RecipientId(r.recipient_id),
                purpose: TokenPurpose::parse(&r.purpose, "purpose")?,
                session_sha256: super::opt_hash32(r.session_sha256, "session_sha256")?,
                expires_at: r.expires_at,
                revoked_at: r.revoked_at,
            })
        })
        .transpose()
    }

    /// Bind an unbound token to a browser session's hash at its first use; returns
    /// whether this call bound it (false when it was already bound or is not this
    /// account's).
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn bind_token(
        &mut self,
        token: RecipientTokenId,
        session_sha256: &[u8; 32],
        at: OffsetDateTime,
    ) -> Result<bool> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE recipient_tokens SET session_sha256 = $3, \
               first_used_at = COALESCE(first_used_at, $4) \
             WHERE account_id = $1 AND id = $2 AND session_sha256 IS NULL",
            acct,
            token.0,
            session_sha256.as_slice(),
            at
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(done.rows_affected() == 1)
    }
}

impl Recipients<'_> {
    /// Set a recipient's access code requirement (SEC-A03): `phc` is the code's Argon2id
    /// PHC string, computed by the caller; any earlier code of the recipient is replaced.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` when the recipient is not this account's.
    pub async fn set_access_code(
        &mut self,
        recipient: RecipientId,
        requirement: Uuid,
        phc: &Personal<String>,
    ) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "DELETE FROM recipient_auth_requirements \
             WHERE account_id = $1 AND recipient_id = $2 AND kind = 'access_code'",
            acct,
            recipient.0
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        sqlx::query!(
            "INSERT INTO recipient_auth_requirements (id, account_id, recipient_id, kind, \
             access_code_hash) VALUES ($3, $1, $2, 'access_code', $4)",
            acct,
            recipient.0,
            requirement,
            phc.get()
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// Delete a recipient's access code requirement, when it has one (its method was
    /// removed from the recipient's authentication).
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn clear_access_code(&mut self, recipient: RecipientId) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "DELETE FROM recipient_auth_requirements \
             WHERE account_id = $1 AND recipient_id = $2 AND kind = 'access_code'",
            acct,
            recipient.0
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// The Argon2id PHC string of a recipient's access code, when one is set.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn access_code(
        &mut self,
        recipient: RecipientId,
    ) -> Result<Option<Personal<String>>> {
        let acct = self.tx.acct();
        let row = sqlx::query_scalar!(
            "SELECT access_code_hash FROM recipient_auth_requirements \
             WHERE account_id = $1 AND recipient_id = $2 AND kind = 'access_code'",
            acct,
            recipient.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(row.flatten().map(Personal))
    }

    /// Past recipients of this account for autocomplete (WEB-06): one entry per email
    /// address (compared ignoring case) with the name last used with it, most recently
    /// used first, at most `limit` (1 to 50). `search` is text the name or email
    /// contains, ignoring case, with `%`, `_` and `\` matched as themselves; `sender`
    /// limits the envelopes to that user's (a member without `view_all` sees only the
    /// people they sent to). Personal data: never logged.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn contacts(
        &mut self,
        search: Option<&str>,
        sender: Option<UserId>,
        limit: u32,
    ) -> Result<Vec<Contact>> {
        let acct = self.tx.acct();
        let pattern = search.map(super::envelopes::like_contains);
        let rows = sqlx::query!(
            r#"SELECT name AS "name!", email AS "email!", last_used AS "last_used!" FROM (
                 SELECT DISTINCT ON (lower(r.email)) r.name, r.email, r.created_at AS last_used
                 FROM recipients AS r JOIN envelopes AS e
                   ON e.account_id = r.account_id AND e.id = r.envelope_id
                 WHERE r.account_id = $1 AND r.email IS NOT NULL
                   AND EXISTS (SELECT 1 FROM envelope_states AS s
                                WHERE s.account_id = e.account_id AND s.envelope_id = e.id)
                   AND ($2::uuid IS NULL OR e.sender_user_id = $2)
                   AND ($3::text IS NULL OR r.name ILIKE $3 ESCAPE '\'
                        OR r.email ILIKE $3 ESCAPE '\')
                 ORDER BY lower(r.email), r.created_at DESC, r.id DESC) AS c
               ORDER BY last_used DESC, email LIMIT $4"#,
            acct,
            sender.map(|u| u.0),
            pattern,
            i64::from(limit.clamp(1, 50))
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(rows
            .into_iter()
            .map(|r| Contact {
                name: Personal(r.name),
                email: Personal(r.email),
                last_used: r.last_used,
            })
            .collect())
    }
}

/// A past recipient, for autocomplete (WEB-06).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    /// The name last used with this address (personal data).
    pub name: Personal<String>,
    /// The email address (personal data).
    pub email: Personal<String>,
    /// When it was last used on a recipient.
    pub last_used: OffsetDateTime,
}
