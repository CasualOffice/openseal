//! Staff sessions (docs/40 §2, migration 0008): the cookie's secret and the CSRF token
//! are stored as SHA-256 only. A session is found from its cookie through
//! `EntryPoints::resolve_staff_session`; everything else is this account's side.

use time::OffsetDateTime;

use super::{affected, text_enum};
use crate::error::{Result, db};
use crate::ids::{StaffSessionId, UserId};
use crate::store::TenantTx;

text_enum!(
    /// How a staff user signed in.
    LoginMethod {
        /// A local password (Argon2id).
        Password = "password",
        /// An OpenID Connect provider.
        Oidc = "oidc",
        /// A WebAuthn credential.
        Webauthn = "webauthn",
    }
);

/// A new session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSession {
    /// Host-minted id.
    pub id: StaffSessionId,
    /// The member.
    pub user_id: UserId,
    /// SHA-256 of the cookie's secret.
    pub token_sha256: [u8; 32],
    /// SHA-256 of the CSRF token.
    pub csrf_sha256: [u8; 32],
    /// How they signed in.
    pub method: LoginMethod,
    /// When.
    pub created_at: OffsetDateTime,
    /// Until when.
    pub expires_at: OffsetDateTime,
}

/// A session ended by [`Sessions::take`]: whose it was and how they signed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TakenSession {
    /// The member.
    pub user_id: UserId,
    /// How they signed in.
    pub method: LoginMethod,
    /// When they signed in.
    pub created_at: OffsetDateTime,
    /// Until when the sign-in holds.
    pub expires_at: OffsetDateTime,
}

/// Staff sessions of this account. Reached through `TenantTx::sessions`.
#[derive(Debug)]
pub struct Sessions<'t> {
    pub(crate) tx: &'t mut TenantTx,
}

impl Sessions<'_> {
    /// Start a session for a member of this account.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` when the user is not a member of this account; `CS-DB-0006` for a
    /// duplicate id or token hash.
    pub async fn create(&mut self, s: &NewSession) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "INSERT INTO staff_sessions (id, account_id, user_id, token_sha256, csrf_sha256, \
             method, created_at, expires_at) VALUES ($2, $1, $3, $4, $5, $6, $7, $8)",
            acct,
            s.id.0,
            s.user_id.0,
            s.token_sha256.as_slice(),
            s.csrf_sha256.as_slice(),
            s.method.as_str(),
            s.created_at,
            s.expires_at
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// End a session of this account at `at`.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when this account has no such session.
    pub async fn revoke(&mut self, id: StaffSessionId, at: OffsetDateTime) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE staff_sessions SET revoked_at = COALESCE(revoked_at, $3) \
             WHERE account_id = $1 AND id = $2",
            acct,
            id.0,
            at
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        affected(done.rows_affected(), "session")
    }

    /// End a live session of this account at `at` and answer how it was signed in, so a
    /// workspace switch (docs/23 §2.3) can carry that sign-in, never extend it. Answers
    /// `None` when the session is already ended, so two concurrent switches from one
    /// session cannot both succeed: the row is locked by the update.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0010` for an unreadable method.
    pub async fn take(
        &mut self,
        id: StaffSessionId,
        at: OffsetDateTime,
    ) -> Result<Option<TakenSession>> {
        let acct = self.tx.acct();
        let row = sqlx::query!(
            "UPDATE staff_sessions SET revoked_at = $3 \
             WHERE account_id = $1 AND id = $2 AND revoked_at IS NULL AND expires_at > $3 \
             RETURNING user_id, method, created_at, expires_at",
            acct,
            id.0,
            at
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        row.map(|r| {
            Ok(TakenSession {
                user_id: UserId(r.user_id),
                method: LoginMethod::parse(&r.method, "method")?,
                created_at: r.created_at,
                expires_at: r.expires_at,
            })
        })
        .transpose()
    }

    /// End every session of a member of this account at `at`; returns how many ended.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn revoke_all(&mut self, user: UserId, at: OffsetDateTime) -> Result<u64> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE staff_sessions SET revoked_at = $3 \
             WHERE account_id = $1 AND user_id = $2 AND revoked_at IS NULL",
            acct,
            user.0,
            at
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(done.rows_affected())
    }
}
