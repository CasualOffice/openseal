//! Recipients (docs/22 §5, docs/24 §3) and their invitation tokens (docs/22 §2, SEC-A01).

use casual_sign_audit::Personal;
use sqlx::postgres::PgRow;
use time::OffsetDateTime;

use super::{col, text_enum};
use crate::error::{Result, StoreError, db};
use crate::ids::{EnvelopeId, RecipientId, RecipientTokenId};
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

const SELECT: &str = "SELECT id, envelope_id, routing_order, type, role_name, name, email, phone, \
     status, delivery, embedded_client_user_id, language, declined_reason FROM recipients \
     WHERE account_id = $1";

fn recipient(r: &PgRow) -> Result<Recipient> {
    let kind: String = col(r, "type")?;
    let status: String = col(r, "status")?;
    let delivery: String = col(r, "delivery")?;
    Ok(Recipient {
        recipient: NewRecipient {
            id: RecipientId(col(r, "id")?),
            envelope_id: EnvelopeId(col(r, "envelope_id")?),
            routing_order: col(r, "routing_order")?,
            kind: RecipientType::parse(&kind, "type")?,
            role_name: col(r, "role_name")?,
            name: Personal(col(r, "name")?),
            email: col::<Option<String>>(r, "email")?.map(Personal),
            phone: col::<Option<String>>(r, "phone")?.map(Personal),
            delivery: Delivery::parse(&delivery, "delivery")?,
            embedded_client_user_id: col(r, "embedded_client_user_id")?,
            language: col(r, "language")?,
        },
        status: RecipientStatus::parse(&status, "status")?,
        declined_reason: col::<Option<String>>(r, "declined_reason")?.map(Personal),
    })
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
        sqlx::query(
            "INSERT INTO recipients (id, account_id, envelope_id, routing_order, type, role_name, \
             name, email, phone, delivery, embedded_client_user_id, language) \
             VALUES ($2, $1, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(acct)
        .bind(n.id.0)
        .bind(n.envelope_id.0)
        .bind(n.routing_order)
        .bind(n.kind.as_str())
        .bind(&n.role_name)
        .bind(n.name.get())
        .bind(n.email.as_ref().map(|e| e.get().as_str()))
        .bind(n.phone.as_ref().map(|p| p.get().as_str()))
        .bind(n.delivery.as_str())
        .bind(&n.embedded_client_user_id)
        .bind(&n.language)
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
        let sql = format!("{SELECT} AND id = $2");
        let row = sqlx::query(&sql)
            .bind(acct)
            .bind(id.0)
            .fetch_optional(self.tx.conn())
            .await
            .map_err(db)?;
        row.as_ref().map(recipient).transpose()
    }

    /// An envelope's recipients in routing order.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn list(&mut self, envelope: EnvelopeId) -> Result<Vec<Recipient>> {
        let acct = self.tx.acct();
        let sql = format!("{SELECT} AND envelope_id = $2 ORDER BY routing_order, created_at, id");
        let rows = sqlx::query(&sql)
            .bind(acct)
            .bind(envelope.0)
            .fetch_all(self.tx.conn())
            .await
            .map_err(db)?;
        rows.iter().map(recipient).collect()
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
        let done = sqlx::query(
            "UPDATE recipients SET status = $3, declined_reason = COALESCE($4, declined_reason) \
             WHERE account_id = $1 AND id = $2",
        )
        .bind(acct)
        .bind(id.0)
        .bind(status.as_str())
        .bind(declined_reason.map(|r| r.get().as_str()))
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        if done.rows_affected() == 0 {
            return Err(StoreError::NotFound {
                entity: "recipient",
            });
        }
        Ok(())
    }

    /// Store a new invitation token's hash.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` when the recipient or envelope is not this account's; `CS-DB-0006`
    /// for a hash already stored.
    pub async fn issue_token(&mut self, t: &NewToken) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query(
            "INSERT INTO recipient_tokens (id, account_id, envelope_id, recipient_id, token_sha256, \
             purpose, expires_at) VALUES ($2, $1, $3, $4, $5, $6, $7)",
        )
        .bind(acct)
        .bind(t.id.0)
        .bind(t.envelope_id.0)
        .bind(t.recipient_id.0)
        .bind(t.token_sha256.as_slice())
        .bind(t.purpose.as_str())
        .bind(t.expires_at)
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
        let done = sqlx::query(
            "UPDATE recipient_tokens SET revoked_at = $3 \
             WHERE account_id = $1 AND recipient_id = $2 AND revoked_at IS NULL",
        )
        .bind(acct)
        .bind(recipient.0)
        .bind(at)
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(done.rows_affected())
    }
}
