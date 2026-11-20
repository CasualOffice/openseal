//! Remote-provider signatures (`RSP-01`, ADR-046 §3.4, §3.11; migration 0051): the
//! providers an account enabled from the operator's catalogue, and each signer's session
//! with a provider. Secrets reach this module only sealed (AES-256-GCM under the provider
//! secrets key, sealed and opened by the host); the OAuth `state` only as SHA-256.

use time::OffsetDateTime;
use uuid::Uuid;

use super::{affected, opt_hash32, text_enum};
use crate::error::{Result, db};
use crate::ids::{EnvelopeId, RecipientId};
use crate::store::TenantTx;

/// A provider this account enabled, and its options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountProvider {
    /// The catalogue's id.
    pub provider_id: String,
    /// Offered to this account's senders.
    pub enabled: bool,
    /// `signatureQualifier` values one of which a credential must state (none: any).
    pub required_qualifiers: Vec<String>,
    /// A certificate name that differs from the recipient's refuses the signature
    /// instead of being recorded (ADR-046 §8 question 5; off by default).
    pub refuse_name_mismatch: bool,
    /// Minutes a session waits for the provider (5 to 60; 15 by default).
    pub session_minutes: i32,
    /// The account's own OAuth client secret, sealed; `None` uses the operator's.
    pub client_secret_sealed: Option<Vec<u8>>,
}

text_enum! {
    /// Where a remote signing session is (ADR-046 §3.4).
    SessionStatus {
        /// Sent to the provider to log in (scope `service`).
        AuthorizingService = "authorizing_service",
        /// Back from the provider; the worker lists credentials and prepares.
        Preparing = "preparing",
        /// More than one eligible credential: the signer chooses.
        Choosing = "choosing",
        /// Prepared: the signer reviews the exact bytes and authorizes.
        Prepared = "prepared",
        /// Sent to the provider to authorize the hashes (scope `credential`).
        AuthorizingCredential = "authorizing_credential",
        /// Back with the credential authorization; the worker signs and embeds.
        Signing = "signing",
        /// Embedded; the recipient completed.
        Completed = "completed",
        /// Failed (`failure` says why); the signer's fields reopen.
        Failed = "failed",
    }
}

/// A remote signing session as stored.
#[derive(Debug, Clone, PartialEq)]
pub struct RemoteSession {
    /// Host-minted id.
    pub id: Uuid,
    /// Its envelope.
    pub envelope_id: EnvelopeId,
    /// Its recipient.
    pub recipient_id: RecipientId,
    /// The catalogue's provider id.
    pub provider_id: String,
    /// Where it is.
    pub status: SessionStatus,
    /// SHA-256 of the current OAuth `state`, until spent.
    pub state_sha256: Option<[u8; 32]>,
    /// The PKCE verifier of the current redirect, sealed, until spent.
    pub pkce_sealed: Option<Vec<u8>>,
    /// The authorization code the provider returned, sealed, until the worker spends it.
    pub code_sealed: Option<Vec<u8>>,
    /// The chosen credential.
    pub credential_id: Option<String>,
    /// The eligible credentials (`credentials/info` as checked: chains, key, qualifier).
    pub credentials: Option<serde_json::Value>,
    /// Per document: the prepared blob, its hashes and ByteRange.
    pub prepared: Option<serde_json::Value>,
    /// Why it failed.
    pub failure: Option<String>,
    /// The provider's own error code, never its message.
    pub provider_code: Option<String>,
    /// When it opened.
    pub created_at: OffsetDateTime,
    /// When it lapses without an answer.
    pub expires_at: OffsetDateTime,
    /// When it closed.
    pub closed_at: Option<OffsetDateTime>,
}

/// Signing providers and remote signing sessions of this account. Reached through
/// `TenantTx::signing`.
#[derive(Debug)]
pub struct Signing<'t> {
    pub(crate) tx: &'t mut TenantTx,
}

struct ProviderRow {
    provider_id: String,
    enabled: bool,
    required_qualifiers: Vec<String>,
    refuse_name_mismatch: bool,
    session_minutes: i32,
    client_secret_sealed: Option<Vec<u8>>,
}

impl From<ProviderRow> for AccountProvider {
    fn from(r: ProviderRow) -> Self {
        Self {
            provider_id: r.provider_id,
            enabled: r.enabled,
            required_qualifiers: r.required_qualifiers,
            refuse_name_mismatch: r.refuse_name_mismatch,
            session_minutes: r.session_minutes,
            client_secret_sealed: r.client_secret_sealed,
        }
    }
}

struct SessionRow {
    id: Uuid,
    envelope_id: Uuid,
    recipient_id: Uuid,
    provider_id: String,
    status: String,
    state_sha256: Option<Vec<u8>>,
    pkce_sealed: Option<Vec<u8>>,
    code_sealed: Option<Vec<u8>>,
    credential_id: Option<String>,
    credentials: Option<serde_json::Value>,
    prepared: Option<serde_json::Value>,
    failure: Option<String>,
    provider_code: Option<String>,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    closed_at: Option<OffsetDateTime>,
}

impl SessionRow {
    fn into_session(self) -> Result<RemoteSession> {
        Ok(RemoteSession {
            id: self.id,
            envelope_id: EnvelopeId(self.envelope_id),
            recipient_id: RecipientId(self.recipient_id),
            provider_id: self.provider_id,
            status: SessionStatus::parse(&self.status, "remote_signing_sessions.status")?,
            state_sha256: opt_hash32(self.state_sha256, "remote_signing_sessions.state_sha256")?,
            pkce_sealed: self.pkce_sealed,
            code_sealed: self.code_sealed,
            credential_id: self.credential_id,
            credentials: self.credentials,
            prepared: self.prepared,
            failure: self.failure,
            provider_code: self.provider_code,
            created_at: self.created_at,
            expires_at: self.expires_at,
            closed_at: self.closed_at,
        })
    }
}

impl Signing<'_> {
    /// Every provider row of this account, by id.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn providers(&mut self) -> Result<Vec<AccountProvider>> {
        let acct = self.tx.acct();
        let rows = sqlx::query_as!(
            ProviderRow,
            "SELECT provider_id, enabled, required_qualifiers, refuse_name_mismatch, \
             session_minutes, client_secret_sealed FROM account_signing_providers \
             WHERE account_id = $1 ORDER BY provider_id",
            acct
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// One provider row of this account.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn provider(&mut self, provider_id: &str) -> Result<Option<AccountProvider>> {
        let acct = self.tx.acct();
        let row = sqlx::query_as!(
            ProviderRow,
            "SELECT provider_id, enabled, required_qualifiers, refuse_name_mismatch, \
             session_minutes, client_secret_sealed FROM account_signing_providers \
             WHERE account_id = $1 AND provider_id = $2",
            acct,
            provider_id
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(row.map(Into::into))
    }

    /// Enable, disable or change a provider's options, with its
    /// `workspace.signing_provider_changed` admin event in the same transaction (ADR-046
    /// §3.11). `client_secret_sealed`: `None` keeps the stored secret, `Some(None)`
    /// removes it, `Some(Some(v))` replaces it; the event records only `"rotated"` or
    /// `"removed"` for it, never a value.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` an option out of its bounds; `CS-DB-0014` when the event cannot be
    /// appended.
    pub async fn put_provider(
        &mut self,
        p: &AccountProvider,
        client_secret_sealed: Option<Option<&[u8]>>,
        now: OffsetDateTime,
    ) -> Result<()> {
        use crate::admin_log::{AdminChange, Change};
        let old = self.provider(&p.provider_id).await?;
        let acct = self.tx.acct();
        let (replace, secret) = match client_secret_sealed {
            None => (false, None),
            Some(v) => (true, v),
        };
        let mut change = AdminChange::new("workspace.signing_provider_changed")
            .target("provider", &p.provider_id);
        let was = |f: &dyn Fn(&AccountProvider) -> serde_json::Value| old.as_ref().map(f);
        for (key, new, before) in [
            (
                "enabled",
                serde_json::json!(p.enabled),
                was(&|o| serde_json::json!(o.enabled)),
            ),
            (
                "required_qualifiers",
                serde_json::json!(p.required_qualifiers),
                was(&|o| serde_json::json!(o.required_qualifiers)),
            ),
            (
                "refuse_name_mismatch",
                serde_json::json!(p.refuse_name_mismatch),
                was(&|o| serde_json::json!(o.refuse_name_mismatch)),
            ),
            (
                "session_minutes",
                serde_json::json!(p.session_minutes),
                was(&|o| serde_json::json!(o.session_minutes)),
            ),
        ] {
            if before.as_ref() != Some(&new) {
                change = change.change(Change::new(key, before, Some(new)));
            }
        }
        if replace {
            let marker = if secret.is_some() {
                "rotated"
            } else {
                "removed"
            };
            change = change.change(Change::new(
                "client_secret",
                None,
                Some(serde_json::json!(marker)),
            ));
        }
        sqlx::query!(
            "INSERT INTO account_signing_providers (account_id, provider_id, enabled, \
             required_qualifiers, refuse_name_mismatch, session_minutes, \
             client_secret_sealed, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $8, $9) \
             ON CONFLICT (account_id, provider_id) DO UPDATE SET enabled = $3, \
             required_qualifiers = $4, refuse_name_mismatch = $5, session_minutes = $6, \
             client_secret_sealed = CASE WHEN $7 THEN $8 \
             ELSE account_signing_providers.client_secret_sealed END, updated_at = $9",
            acct,
            p.provider_id,
            p.enabled,
            &p.required_qualifiers,
            p.refuse_name_mismatch,
            p.session_minutes,
            replace,
            secret,
            now
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        self.tx.admin_event(change).await
    }

    /// Open a session (`authorizing_service`). Fails `CS-DB-0009` when another session
    /// of the envelope is open (one remote session per envelope, ADR-046 §3.4).
    ///
    /// # Errors
    ///
    /// `CS-DB-0009` another session open; `CS-DB-0008` a value out of bounds.
    #[allow(clippy::too_many_arguments)]
    // One row's columns, each a named argument.
    pub async fn open_session(
        &mut self,
        id: Uuid,
        envelope: EnvelopeId,
        recipient: RecipientId,
        provider_id: &str,
        state_sha256: &[u8; 32],
        pkce_sealed: &[u8],
        now: OffsetDateTime,
        expires: OffsetDateTime,
    ) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "INSERT INTO remote_signing_sessions (id, account_id, envelope_id, recipient_id, \
             provider_id, status, state_sha256, pkce_sealed, created_at, expires_at) \
             VALUES ($2, $1, $3, $4, $5, 'authorizing_service', $6, $7, $8, $9)",
            acct,
            id,
            envelope.0,
            recipient.0,
            provider_id,
            &state_sha256[..],
            pkce_sealed,
            now,
            expires
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// A session by id.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0010` a corrupt row.
    pub async fn session(&mut self, id: Uuid) -> Result<Option<RemoteSession>> {
        let acct = self.tx.acct();
        let row = sqlx::query_as!(
            SessionRow,
            "SELECT id, envelope_id, recipient_id, provider_id, status, state_sha256, \
             pkce_sealed, code_sealed, credential_id, credentials, prepared, failure, \
             provider_code, created_at, expires_at, closed_at FROM remote_signing_sessions \
             WHERE account_id = $1 AND id = $2",
            acct,
            id
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        row.map(SessionRow::into_session).transpose()
    }

    /// The recipient's latest session, open or closed.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0010` a corrupt row.
    pub async fn latest_for(&mut self, recipient: RecipientId) -> Result<Option<RemoteSession>> {
        let acct = self.tx.acct();
        let row = sqlx::query_as!(
            SessionRow,
            "SELECT id, envelope_id, recipient_id, provider_id, status, state_sha256, \
             pkce_sealed, code_sealed, credential_id, credentials, prepared, failure, \
             provider_code, created_at, expires_at, closed_at FROM remote_signing_sessions \
             WHERE account_id = $1 AND recipient_id = $2 ORDER BY created_at DESC, id DESC \
             LIMIT 1",
            acct,
            recipient.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        row.map(SessionRow::into_session).transpose()
    }

    /// The open session whose current `state` hashes to `state_sha256`, for the
    /// recipient, still within its time, in `expected` status: its `state` is spent
    /// (cleared) and its PKCE verifier taken out in the same statement, so a replay finds
    /// nothing (ADR-046 §3.13). Returns the session as it was and the sealed verifier.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0010` a corrupt row.
    pub async fn take_state(
        &mut self,
        recipient: RecipientId,
        state_sha256: &[u8; 32],
        expected: SessionStatus,
        code_sealed: &[u8],
        next: SessionStatus,
        now: OffsetDateTime,
    ) -> Result<Option<(Uuid, Vec<u8>)>> {
        let acct = self.tx.acct();
        let row = sqlx::query!(
            "UPDATE remote_signing_sessions AS s SET state_sha256 = NULL, pkce_sealed = NULL, \
             code_sealed = $5, status = $6 \
             FROM (SELECT id, pkce_sealed FROM remote_signing_sessions \
                   WHERE account_id = $1 AND recipient_id = $2 AND state_sha256 = $3 \
                   AND status = $4 AND closed_at IS NULL AND expires_at > $7 \
                   FOR UPDATE) AS old \
             WHERE s.account_id = $1 AND s.id = old.id \
             RETURNING s.id, old.pkce_sealed AS pkce",
            acct,
            recipient.0,
            &state_sha256[..],
            expected.as_str(),
            code_sealed,
            next.as_str(),
            now
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(row.and_then(|r| r.pkce.map(|p| (r.id, p))))
    }

    /// Move an open session on: a new status and, for the next redirect, a new `state`
    /// hash and sealed PKCE verifier (or none), and what the worker recorded.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` no such open session.
    #[allow(clippy::too_many_arguments)]
    // One row's columns, each a named argument.
    pub async fn advance(
        &mut self,
        id: Uuid,
        status: SessionStatus,
        state_sha256: Option<&[u8; 32]>,
        pkce_sealed: Option<&[u8]>,
        credential_id: Option<&str>,
        credentials: Option<&serde_json::Value>,
        prepared: Option<&serde_json::Value>,
    ) -> Result<()> {
        let acct = self.tx.acct();
        let r = sqlx::query!(
            "UPDATE remote_signing_sessions SET status = $3, state_sha256 = $4, \
             pkce_sealed = $5, credential_id = COALESCE($6, credential_id), \
             credentials = COALESCE($7, credentials), prepared = COALESCE($8, prepared) \
             WHERE account_id = $1 AND id = $2 AND closed_at IS NULL",
            acct,
            id,
            status.as_str(),
            state_sha256.map(|s| &s[..]),
            pkce_sealed,
            credential_id,
            credentials,
            prepared
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        affected(r.rows_affected(), "remote_signing_session")
    }

    /// Take the sealed authorization code of an open session in `status` (the worker,
    /// once): it is cleared in the same statement.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn take_code(&mut self, id: Uuid, status: SessionStatus) -> Result<Option<Vec<u8>>> {
        let acct = self.tx.acct();
        let row = sqlx::query!(
            "UPDATE remote_signing_sessions AS s SET code_sealed = NULL \
             FROM (SELECT id, code_sealed FROM remote_signing_sessions \
                   WHERE account_id = $1 AND id = $2 AND status = $3 AND closed_at IS NULL \
                   FOR UPDATE) AS old \
             WHERE s.account_id = $1 AND s.id = old.id RETURNING old.code_sealed",
            acct,
            id,
            status.as_str()
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(row.and_then(|r| r.code_sealed))
    }

    /// Close a session: `completed`, or `failed` with the reason and the provider's code.
    /// Secrets and the `state` are cleared. Returns whether it was open.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` an unknown reason.
    pub async fn close(
        &mut self,
        id: Uuid,
        failure: Option<&str>,
        provider_code: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<bool> {
        let acct = self.tx.acct();
        let status = if failure.is_some() {
            SessionStatus::Failed
        } else {
            SessionStatus::Completed
        };
        let r = sqlx::query!(
            "UPDATE remote_signing_sessions SET status = $3, failure = $4, provider_code = $5, \
             closed_at = $6, state_sha256 = NULL, pkce_sealed = NULL, code_sealed = NULL \
             WHERE account_id = $1 AND id = $2 AND closed_at IS NULL",
            acct,
            id,
            status.as_str(),
            failure,
            provider_code,
            now
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(r.rows_affected() > 0)
    }

    /// Sessions of the envelope still open.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0010` a corrupt row.
    pub async fn open_for(&mut self, envelope: EnvelopeId) -> Result<Vec<RemoteSession>> {
        let acct = self.tx.acct();
        let rows = sqlx::query_as!(
            SessionRow,
            "SELECT id, envelope_id, recipient_id, provider_id, status, state_sha256, \
             pkce_sealed, code_sealed, credential_id, credentials, prepared, failure, \
             provider_code, created_at, expires_at, closed_at FROM remote_signing_sessions \
             WHERE account_id = $1 AND envelope_id = $2 AND closed_at IS NULL",
            acct,
            envelope.0
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        rows.into_iter().map(SessionRow::into_session).collect()
    }
}
