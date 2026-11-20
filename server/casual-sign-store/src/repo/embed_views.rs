//! Embedded prepare and correct views (slice 9 `VS-09`, docs/40 §5, migration 0050): a
//! five-minute view link spent once, whose spending makes a view session that acts on
//! one envelope only. Both secrets are stored as their SHA-256 and never read back.

use time::OffsetDateTime;
use uuid::Uuid;

use super::text_enum;
use crate::error::{Result, db};
use crate::ids::{ApiClientId, EnvelopeId, UserId};
use crate::store::TenantTx;

text_enum! {
    /// Which editor a view opens.
    ViewKind {
        /// Add recipients and fields to a draft, then send.
        Prepare = "prepare",
        /// Correct a sent envelope.
        Correct = "correct",
    }
}

/// Where an embedded view's host is and what it is given back (all optional).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EmbedTarget {
    /// The origin of the page that frames the view: its `frame-ancestors`, and the only
    /// origin its events are posted to.
    pub frame_origin: Option<String>,
    /// Where the browser goes when the view ends, with `event` and `state` added.
    pub return_url: Option<String>,
    /// An opaque value the host passed, given back with each event.
    pub return_state: Option<String>,
}

/// A new view link.
#[derive(Debug, Clone)]
pub struct NewView {
    /// Host-minted id.
    pub id: Uuid,
    /// The envelope it opens.
    pub envelope_id: EnvelopeId,
    /// Prepare or correct.
    pub kind: ViewKind,
    /// The API client that asked.
    pub client_id: ApiClientId,
    /// The member the editor acts as (the client's).
    pub user_id: UserId,
    /// SHA-256 of the link's token.
    pub token_sha256: [u8; 32],
    /// When the link stops opening.
    pub expires_at: OffsetDateTime,
    /// Host page, return URL and state.
    pub target: EmbedTarget,
    /// When it was made.
    pub created_at: OffsetDateTime,
}

/// A view as read back: by its spent link, or by its session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct View {
    /// Id.
    pub id: Uuid,
    /// The envelope it acts on, and on no other.
    pub envelope_id: EnvelopeId,
    /// Prepare or correct.
    pub kind: ViewKind,
    /// The API client that asked.
    pub client_id: ApiClientId,
    /// The member it acts as.
    pub user_id: UserId,
    /// Host page, return URL and state.
    pub target: EmbedTarget,
    /// When the view session ends.
    pub session_expires_at: Option<OffsetDateTime>,
}

/// Embedded views of this account. Reached through `TenantTx::embed_views`.
#[derive(Debug)]
pub struct EmbedViews<'t> {
    pub(crate) tx: &'t mut TenantTx,
}

impl EmbedViews<'_> {
    /// Record a new view link.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` for an envelope, client or member of another account.
    pub async fn create(&mut self, v: &NewView) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "INSERT INTO embed_views (id, account_id, envelope_id, kind, client_id, user_id, \
               token_sha256, expires_at, frame_origin, return_url, return_state, created_at) \
             VALUES ($2, $1, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
            acct,
            v.id,
            v.envelope_id.0,
            v.kind.as_str(),
            v.client_id.0,
            v.user_id.0,
            v.token_sha256.as_slice(),
            v.expires_at,
            v.target.frame_origin.as_deref(),
            v.target.return_url.as_deref(),
            v.target.return_state.as_deref(),
            v.created_at
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// A live, unspent link's view, without spending it (to serve its page).
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0010` for an unreadable row.
    pub async fn unspent(
        &mut self,
        token_sha256: &[u8; 32],
        now: OffsetDateTime,
    ) -> Result<Option<View>> {
        let acct = self.tx.acct();
        let r = sqlx::query!(
            "SELECT id, envelope_id, kind, client_id, user_id, frame_origin, return_url, \
               return_state, session_expires_at FROM embed_views \
             WHERE account_id = $1 AND token_sha256 = $2 AND used_at IS NULL AND expires_at > $3",
            acct,
            token_sha256.as_slice(),
            now
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        r.map(|r| {
            Ok(View {
                id: r.id,
                envelope_id: EnvelopeId(r.envelope_id),
                kind: ViewKind::parse(&r.kind, "kind")?,
                client_id: ApiClientId(r.client_id),
                user_id: UserId(r.user_id),
                target: EmbedTarget {
                    frame_origin: r.frame_origin,
                    return_url: r.return_url,
                    return_state: r.return_state,
                },
                session_expires_at: r.session_expires_at,
            })
        })
        .transpose()
    }

    /// Spend a live link once: record its view session's hash and end, and answer the
    /// view. `None` when the link is unknown, expired or already spent; of two callers
    /// racing for one link, exactly one gets the view.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0010` for an unreadable row.
    pub async fn spend(
        &mut self,
        token_sha256: &[u8; 32],
        session_sha256: &[u8; 32],
        now: OffsetDateTime,
        session_expires_at: OffsetDateTime,
    ) -> Result<Option<View>> {
        let acct = self.tx.acct();
        let r = sqlx::query!(
            "UPDATE embed_views SET used_at = $3, session_sha256 = $4, session_expires_at = $5 \
             WHERE account_id = $1 AND token_sha256 = $2 AND used_at IS NULL AND expires_at > $3 \
             RETURNING id, envelope_id, kind, client_id, user_id, frame_origin, return_url, \
               return_state, session_expires_at",
            acct,
            token_sha256.as_slice(),
            now,
            session_sha256.as_slice(),
            session_expires_at
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        r.map(|r| {
            Ok(View {
                id: r.id,
                envelope_id: EnvelopeId(r.envelope_id),
                kind: ViewKind::parse(&r.kind, "kind")?,
                client_id: ApiClientId(r.client_id),
                user_id: UserId(r.user_id),
                target: EmbedTarget {
                    frame_origin: r.frame_origin,
                    return_url: r.return_url,
                    return_state: r.return_state,
                },
                session_expires_at: r.session_expires_at,
            })
        })
        .transpose()
    }

    /// The view a live view session's hash names.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0010` for an unreadable row.
    pub async fn by_session(
        &mut self,
        session_sha256: &[u8; 32],
        now: OffsetDateTime,
    ) -> Result<Option<View>> {
        let acct = self.tx.acct();
        let r = sqlx::query!(
            "SELECT id, envelope_id, kind, client_id, user_id, frame_origin, return_url, \
               return_state, session_expires_at FROM embed_views \
             WHERE account_id = $1 AND session_sha256 = $2 AND session_expires_at > $3",
            acct,
            session_sha256.as_slice(),
            now
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        r.map(|r| {
            Ok(View {
                id: r.id,
                envelope_id: EnvelopeId(r.envelope_id),
                kind: ViewKind::parse(&r.kind, "kind")?,
                client_id: ApiClientId(r.client_id),
                user_id: UserId(r.user_id),
                target: EmbedTarget {
                    frame_origin: r.frame_origin,
                    return_url: r.return_url,
                    return_state: r.return_state,
                },
                session_expires_at: r.session_expires_at,
            })
        })
        .transpose()
    }
}
