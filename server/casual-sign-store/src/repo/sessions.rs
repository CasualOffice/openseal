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
    /// When it passed its second factor, if it did (ASVS-01).
    pub mfa_at: Option<OffsetDateTime>,
}

/// A live session's own user's TOTP factor (ASVS-01, migration 0032).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnTotp {
    /// The user.
    pub user_id: UserId,
    /// The seed, sealed by the server; `None` before enrolment starts.
    pub seed_sealed: Option<Vec<u8>>,
    /// Enrolment is confirmed: every session of this user owes the factor.
    pub confirmed: bool,
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
             RETURNING user_id, method, created_at, expires_at, mfa_at",
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
                mfa_at: r.mfa_at,
            })
        })
        .transpose()
    }

    /// Record that a session of this account passed its second factor at `at`: a
    /// workspace switch carries the sign-in's factor to the new session (ASVS-01).
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when this account has no such session.
    pub async fn set_mfa_at(&mut self, id: StaffSessionId, at: OffsetDateTime) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE staff_sessions SET mfa_at = $3 WHERE account_id = $1 AND id = $2",
            acct,
            id.0,
            at
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        affected(done.rows_affected(), "session")
    }

    /// The live session's own user's TOTP factor; `None` when the session is not live or
    /// its user does not sign in with a local password.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn own_totp(
        &mut self,
        session: StaffSessionId,
        now: OffsetDateTime,
    ) -> Result<Option<OwnTotp>> {
        let row = sqlx::query!(
            r#"SELECT user_id AS "user_id!", seed_sealed, confirmed AS "confirmed!"
                 FROM openseal_own_totp($1, $2)"#,
            session.0,
            now
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(row.map(|r| OwnTotp {
            user_id: UserId(r.user_id),
            seed_sealed: r.seed_sealed,
            confirmed: r.confirmed,
        }))
    }

    /// Start (or restart) the session's own user's TOTP enrolment with `sealed`, only
    /// while no factor is confirmed. `None` when the session is not live or a factor is
    /// already confirmed.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn begin_own_totp(
        &mut self,
        session: StaffSessionId,
        sealed: &[u8],
        now: OffsetDateTime,
    ) -> Result<Option<UserId>> {
        let user = sqlx::query_scalar!(
            "SELECT openseal_begin_own_totp($1, $2, $3)",
            session.0,
            sealed,
            now
        )
        .fetch_one(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(user.map(UserId))
    }

    /// Confirm the session's own user's enrolment: a code for `step` proved the seed
    /// `sealed`; `codes` (ten SHA-256 hashes) become their recovery codes, and the
    /// session has passed the factor. `None` when the enrolment changed meanwhile, was
    /// already confirmed, or the session is not live.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn confirm_own_totp(
        &mut self,
        session: StaffSessionId,
        sealed: &[u8],
        step: i64,
        codes: &[[u8; 32]],
        now: OffsetDateTime,
    ) -> Result<Option<UserId>> {
        let codes: Vec<Vec<u8>> = codes.iter().map(|c| c.to_vec()).collect();
        let user = sqlx::query_scalar!(
            "SELECT openseal_confirm_own_totp($1, $2, $3, $4, $5)",
            session.0,
            sealed,
            step,
            &codes,
            now
        )
        .fetch_one(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(user.map(UserId))
    }

    /// Pass the session's second factor with a code for `step`, only when that step is
    /// later than every step accepted before for the user (a code is single use).
    /// `None` when refused.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn verify_own_totp(
        &mut self,
        session: StaffSessionId,
        step: i64,
        now: OffsetDateTime,
    ) -> Result<Option<UserId>> {
        let user = sqlx::query_scalar!(
            "SELECT openseal_verify_own_totp($1, $2, $3)",
            session.0,
            step,
            now
        )
        .fetch_one(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(user.map(UserId))
    }

    /// Pass the session's second factor with the recovery code whose SHA-256 is
    /// `code_sha256`, spending it. Answers how many codes are left, or `None` when it
    /// is not one of the user's unspent codes.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn use_own_recovery_code(
        &mut self,
        session: StaffSessionId,
        code_sha256: &[u8; 32],
        now: OffsetDateTime,
    ) -> Result<Option<i32>> {
        let left = sqlx::query_scalar!(
            "SELECT openseal_use_own_recovery_code($1, $2, $3)",
            session.0,
            code_sha256.as_slice(),
            now
        )
        .fetch_one(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(left)
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
