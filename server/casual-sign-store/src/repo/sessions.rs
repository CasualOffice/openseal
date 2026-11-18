//! Staff sessions (docs/40 §2, migration 0008): the cookie's secret and the CSRF token
//! are stored as SHA-256 only. A session is found from its cookie through
//! `EntryPoints::resolve_staff_session`; everything else is this account's side.

use time::OffsetDateTime;

use super::{affected, text_enum};
use crate::admin_log::{AdminChange, Change};
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
    /// When it last made a request: its start, or now for a workspace switch (ASVS-06).
    pub last_seen_at: OffsetDateTime,
    /// When its holder last proved the password (and second factor): the sign-in, or
    /// carried by a switch (ASVS-07).
    pub reauth_at: Option<OffsetDateTime>,
    /// A coarse browser and system name ("Firefox on macOS"), from a closed list.
    pub client_label: Option<String>,
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
    /// When its holder last re-authenticated (ASVS-07): a switch carries it.
    pub reauth_at: Option<OffsetDateTime>,
    /// Its browser and system name.
    pub client_label: Option<String>,
}

/// One of a person's own sessions, in any of their workspaces (ASVS-06).
#[derive(Debug, Clone, PartialEq)]
pub struct OwnSession {
    /// The session.
    pub id: StaffSessionId,
    /// Its workspace.
    pub account_id: crate::ids::AccountId,
    /// The workspace's name.
    pub account_name: String,
    /// How it signed in.
    pub method: LoginMethod,
    /// When it signed in.
    pub created_at: OffsetDateTime,
    /// When it last made a request.
    pub last_seen_at: OffsetDateTime,
    /// The sign-in's absolute end, as stored at sign-in.
    pub expires_at: OffsetDateTime,
    /// Its browser and system name.
    pub client_label: Option<String>,
    /// The workspace's settings, for its idle and absolute limits.
    pub settings: serde_json::Value,
    /// The workspace's organization policy, likewise.
    pub organization_policy: serde_json::Value,
}

/// A live session's own user's second factors (ASVS-01, CON-13, migration 0045).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnFactors {
    /// The user.
    pub user_id: UserId,
    /// A confirmed TOTP authenticator.
    pub totp: bool,
    /// How many passkeys.
    pub passkeys: u32,
    /// How many unspent recovery codes.
    pub recovery_codes_left: u32,
    /// An administrator reset their factors and a new one is not enrolled yet.
    pub factor_reset: bool,
}

impl OwnFactors {
    /// Whether the user has any second factor.
    #[must_use]
    pub fn any(&self) -> bool {
        self.totp || self.passkeys > 0
    }
}

/// One of a person's passkeys (CON-13, migration 0045).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Passkey {
    /// Its id.
    pub id: uuid::Uuid,
    /// The WebAuthn credential id.
    pub credential_id: Vec<u8>,
    /// The public key, SubjectPublicKeyInfo DER.
    pub public_key: Vec<u8>,
    /// The COSE algorithm: -7, -8 or -257.
    pub algorithm: i32,
    /// The last signature counter seen.
    pub sign_count: u32,
    /// The person's name for it.
    pub name: String,
    /// The transports the browser reported, as hints for the next ceremony.
    pub transports: Vec<String>,
    /// The authenticator said the credential may be backed up (a synced passkey).
    pub backup_eligible: bool,
    /// When it was registered.
    pub created_at: OffsetDateTime,
    /// When it last passed a factor.
    pub last_used_at: Option<OffsetDateTime>,
}

/// A passkey to register (CON-13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPasskey {
    /// Host-minted id.
    pub id: uuid::Uuid,
    /// The WebAuthn credential id.
    pub credential_id: Vec<u8>,
    /// The public key, SubjectPublicKeyInfo DER.
    pub public_key: Vec<u8>,
    /// The COSE algorithm.
    pub algorithm: i32,
    /// The signature counter at registration.
    pub sign_count: u32,
    /// The person's name for it.
    pub name: String,
    /// The transports the browser reported.
    pub transports: Vec<String>,
    /// Backup eligible.
    pub backup_eligible: bool,
}

/// What an administrator's reset of a member's factors removed (ASVS-32).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactorReset {
    /// A confirmed TOTP authenticator was removed.
    pub had_totp: bool,
    /// How many passkeys were removed.
    pub passkeys: u32,
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
             method, created_at, expires_at, last_seen_at, reauth_at, client_label) \
             VALUES ($2, $1, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
            acct,
            s.id.0,
            s.user_id.0,
            s.token_sha256.as_slice(),
            s.csrf_sha256.as_slice(),
            s.method.as_str(),
            s.created_at,
            s.expires_at,
            s.last_seen_at,
            s.reauth_at,
            s.client_label.as_deref()
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
             RETURNING user_id, method, created_at, expires_at, mfa_at, reauth_at, client_label",
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
                reauth_at: r.reauth_at,
                client_label: r.client_label,
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

    /// Record that a session of this account made a request at `at`: written only when
    /// the stored time is more than 15 seconds older, so an active session costs at most
    /// one write every 15 seconds (ASVS-06, migration 0042).
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn touch(&mut self, id: StaffSessionId, at: OffsetDateTime) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "UPDATE staff_sessions SET last_seen_at = $3 \
             WHERE account_id = $1 AND id = $2 AND revoked_at IS NULL \
               AND last_seen_at < $3::timestamptz - interval '15 seconds'",
            acct,
            id.0,
            at
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// Record that a live session of this account re-authenticated at `at` (ASVS-07).
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when this account has no such live session.
    pub async fn set_reauth_at(&mut self, id: StaffSessionId, at: OffsetDateTime) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE staff_sessions SET reauth_at = $3, last_seen_at = $3 \
             WHERE account_id = $1 AND id = $2 AND revoked_at IS NULL",
            acct,
            id.0,
            at
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        affected(done.rows_affected(), "session")
    }

    /// The live session's own user's unrevoked, unexpired sessions in every workspace
    /// they are a member of (at most 200, most recently active first); the caller applies
    /// each workspace's idle and absolute limits (ASVS-06, migration 0042).
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0010` for an unreadable method.
    pub async fn own_sessions(
        &mut self,
        session: StaffSessionId,
        now: OffsetDateTime,
    ) -> Result<Vec<OwnSession>> {
        let rows = sqlx::query!(
            r#"SELECT session_id AS "session_id!", account_id AS "account_id!",
                      account_name AS "account_name!", method AS "method!",
                      created_at AS "created_at!", last_seen_at AS "last_seen_at!",
                      expires_at AS "expires_at!", client_label,
                      settings AS "settings!", organization_policy AS "organization_policy!"
                 FROM openseal_own_sessions($1, $2)"#,
            session.0,
            now
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        rows.into_iter()
            .map(|r| {
                Ok(OwnSession {
                    id: StaffSessionId(r.session_id),
                    account_id: crate::ids::AccountId(r.account_id),
                    account_name: r.account_name,
                    method: LoginMethod::parse(&r.method, "method")?,
                    created_at: r.created_at,
                    last_seen_at: r.last_seen_at,
                    expires_at: r.expires_at,
                    client_label: r.client_label,
                    settings: r.settings,
                    organization_policy: r.organization_policy,
                })
            })
            .collect()
    }

    /// End the live session's own user's session `target` (in any workspace), or every
    /// other one with `None`; never the calling session, never another user's. Answers how
    /// many ended (ASVS-06).
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn end_own(
        &mut self,
        session: StaffSessionId,
        target: Option<StaffSessionId>,
        now: OffsetDateTime,
    ) -> Result<u64> {
        let n = sqlx::query_scalar!(
            "SELECT openseal_end_own_sessions($1, $2, $3)",
            session.0,
            target.map(|t| t.0),
            now
        )
        .fetch_one(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(u64::try_from(n.unwrap_or(0)).unwrap_or(0))
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

    /// Re-seal the session's own user's TOTP seed under a new second-factor key
    /// (`HRD-12`): replace `old`, the sealed value the server just opened, by `new`. A
    /// confirmed factor is re-sealed only once this session has passed it. `None` when
    /// the seed is no longer `old`, the factor is confirmed and not passed, or the
    /// session is not live.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn reseal_own_totp(
        &mut self,
        session: StaffSessionId,
        old: &[u8],
        new: &[u8],
        now: OffsetDateTime,
    ) -> Result<Option<UserId>> {
        let user = sqlx::query_scalar!(
            "SELECT openseal_reseal_own_totp($1, $2, $3, $4)",
            session.0,
            old,
            new,
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

    /// The live session's own user's second factors; `None` when the session is not live
    /// or its user does not sign in with a local password.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn own_factors(
        &mut self,
        session: StaffSessionId,
        now: OffsetDateTime,
    ) -> Result<Option<OwnFactors>> {
        let row = sqlx::query!(
            r#"SELECT user_id AS "user_id!", totp AS "totp!", passkeys AS "passkeys!",
                      recovery_codes_left AS "recovery_codes_left!",
                      factor_reset AS "factor_reset!"
                 FROM openseal_own_factors($1, $2)"#,
            session.0,
            now
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(row.map(|r| OwnFactors {
            user_id: UserId(r.user_id),
            totp: r.totp,
            passkeys: u32::try_from(r.passkeys).unwrap_or(0),
            recovery_codes_left: u32::try_from(r.recovery_codes_left).unwrap_or(0),
            factor_reset: r.factor_reset,
        }))
    }

    /// The live session's own user's passkeys (at most 10), oldest first; empty when the
    /// session is not live.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn own_passkeys(
        &mut self,
        session: StaffSessionId,
        now: OffsetDateTime,
    ) -> Result<Vec<Passkey>> {
        let rows = sqlx::query!(
            r#"SELECT id AS "id!", credential_id AS "credential_id!", public_key AS "public_key!",
                      algorithm AS "algorithm!", sign_count AS "sign_count!", name AS "name!",
                      transports AS "transports!", backup_eligible AS "backup_eligible!",
                      created_at AS "created_at!", last_used_at
                 FROM openseal_own_passkeys($1, $2)"#,
            session.0,
            now
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(rows
            .into_iter()
            .map(|r| Passkey {
                id: r.id,
                credential_id: r.credential_id,
                public_key: r.public_key,
                algorithm: r.algorithm,
                sign_count: u32::try_from(r.sign_count).unwrap_or(u32::MAX),
                name: r.name,
                transports: r.transports,
                backup_eligible: r.backup_eligible,
                created_at: r.created_at,
                last_used_at: r.last_used_at,
            })
            .collect())
    }

    /// Register a passkey for the live session's own user. `codes` (ten SHA-256 hashes)
    /// become their recovery codes when it is their first factor; answers whether they
    /// did. `None` when refused: the session owes a factor it has not passed, the user
    /// has 10 passkeys, or the credential is registered already.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn add_own_passkey(
        &mut self,
        session: StaffSessionId,
        key: &NewPasskey,
        codes: &[[u8; 32]],
        now: OffsetDateTime,
    ) -> Result<Option<bool>> {
        let codes: Vec<Vec<u8>> = codes.iter().map(|c| c.to_vec()).collect();
        let row = sqlx::query!(
            r#"SELECT user_id AS "user_id!", codes_set AS "codes_set!"
                 FROM openseal_add_own_passkey($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"#,
            session.0,
            key.id,
            &key.credential_id,
            &key.public_key,
            key.algorithm,
            i64::from(key.sign_count),
            &key.name,
            &key.transports,
            key.backup_eligible,
            &codes,
            now
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(row.map(|r| r.codes_set))
    }

    /// Pass the session's second factor with the user's passkey `id`, whose assertion
    /// reported the counter `count`. `None` when it is not theirs, or when the counter
    /// did not move past the stored one (a cloned credential).
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn use_own_passkey(
        &mut self,
        session: StaffSessionId,
        id: uuid::Uuid,
        count: u32,
        now: OffsetDateTime,
    ) -> Result<Option<UserId>> {
        let user = sqlx::query_scalar!(
            "SELECT openseal_use_own_passkey($1, $2, $3, $4)",
            session.0,
            id,
            i64::from(count),
            now
        )
        .fetch_one(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(user.map(UserId))
    }

    /// Rename one of the session's own user's passkeys; `false` when it is not theirs.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn rename_own_passkey(
        &mut self,
        session: StaffSessionId,
        id: uuid::Uuid,
        name: &str,
        now: OffsetDateTime,
    ) -> Result<bool> {
        let done = sqlx::query_scalar!(
            r#"SELECT openseal_rename_own_passkey($1, $2, $3, $4) AS "done!""#,
            session.0,
            id,
            name,
            now
        )
        .fetch_one(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(done)
    }

    /// Remove one of the session's own user's passkeys; `false` when it is not theirs.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn remove_own_passkey(
        &mut self,
        session: StaffSessionId,
        id: uuid::Uuid,
        now: OffsetDateTime,
    ) -> Result<bool> {
        let done = sqlx::query_scalar!(
            r#"SELECT openseal_remove_own_passkey($1, $2, $3) AS "done!""#,
            session.0,
            id,
            now
        )
        .fetch_one(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(done)
    }

    /// Remove the session's own user's TOTP authenticator, to replace it (ASVS-32);
    /// `false` when they have none confirmed.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn remove_own_totp(
        &mut self,
        session: StaffSessionId,
        now: OffsetDateTime,
    ) -> Result<bool> {
        let done = sqlx::query_scalar!(
            r#"SELECT openseal_remove_own_totp($1, $2) AS "done!""#,
            session.0,
            now
        )
        .fetch_one(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(done)
    }

    /// Replace the session's own user's recovery codes with `codes` (ten SHA-256 hashes);
    /// `false` when they have no factor.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn replace_own_recovery_codes(
        &mut self,
        session: StaffSessionId,
        codes: &[[u8; 32]],
        now: OffsetDateTime,
    ) -> Result<bool> {
        let codes: Vec<Vec<u8>> = codes.iter().map(|c| c.to_vec()).collect();
        let done = sqlx::query_scalar!(
            r#"SELECT openseal_replace_own_recovery_codes($1, $2, $3) AS "done!""#,
            session.0,
            &codes,
            now
        )
        .fetch_one(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(done)
    }

    /// An administrator's reset of member `user`'s lost factors (ASVS-32): their TOTP,
    /// recovery codes and passkeys go, and they enrol a new factor at their next sign-in.
    /// `None` when they are not a member of this account, or belong to another too
    /// (SEC-ID-01). `verified_by` is how the administrator proved the person's identity;
    /// it goes into the administrative log with what was removed. The caller ends their
    /// sessions.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn reset_member_factors(
        &mut self,
        user: UserId,
        verified_by: &str,
        now: OffsetDateTime,
    ) -> Result<Option<FactorReset>> {
        let row = sqlx::query!(
            r#"SELECT had_totp AS "had_totp!", passkeys AS "passkeys!"
                 FROM openseal_reset_member_factors($1, $2)"#,
            user.0,
            now
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        let Some(r) = row else {
            return Ok(None);
        };
        let done = FactorReset {
            had_totp: r.had_totp,
            passkeys: u32::try_from(r.passkeys).unwrap_or(0),
        };
        // The administrative log records who reset whose factors, how the person's
        // identity was proved, and what went (ASVS 2.5.7, docs/23 §5).
        self.tx
            .admin_event(
                AdminChange::new("member.factors_reset")
                    .target("user", user.0)
                    .change(Change::new(
                        "identity_verified_by",
                        None,
                        Some(verified_by.into()),
                    ))
                    .change(Change::new(
                        "totp",
                        done.had_totp.then(|| "enrolled".into()),
                        None,
                    ))
                    .change(Change::new(
                        "passkeys",
                        Some(done.passkeys.into()),
                        Some(0.into()),
                    )),
            )
            .await?;
        Ok(Some(done))
    }

    /// Keep `challenge` as the session's one outstanding WebAuthn challenge, for
    /// `purpose` (`register`, `verify` or `reauthenticate`), until `expires_at`. It
    /// replaces any earlier one.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0004` when the session is not live.
    pub async fn set_webauthn_challenge(
        &mut self,
        id: StaffSessionId,
        challenge: &[u8; 32],
        purpose: &str,
        expires_at: OffsetDateTime,
    ) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE staff_sessions SET webauthn_challenge = $3, webauthn_purpose = $4, \
             webauthn_challenge_expires_at = $5 \
             WHERE account_id = $1 AND id = $2 AND revoked_at IS NULL",
            acct,
            id.0,
            challenge.as_slice(),
            purpose,
            expires_at
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        affected(done.rows_affected(), "session")
    }

    /// Spend the session's outstanding WebAuthn challenge: it is cleared whatever it was,
    /// and answered only when it was for `purpose` and has not expired at `now`.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn take_webauthn_challenge(
        &mut self,
        id: StaffSessionId,
        purpose: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Vec<u8>>> {
        let acct = self.tx.acct();
        let row = sqlx::query!(
            r#"WITH old AS (
                   SELECT webauthn_challenge, webauthn_purpose, webauthn_challenge_expires_at
                     FROM staff_sessions WHERE account_id = $1 AND id = $2 FOR UPDATE)
               UPDATE staff_sessions AS s
                  SET webauthn_challenge = NULL, webauthn_purpose = NULL,
                      webauthn_challenge_expires_at = NULL
                 FROM old
                WHERE s.account_id = $1 AND s.id = $2
               RETURNING CASE WHEN old.webauthn_purpose = $3
                               AND old.webauthn_challenge_expires_at > $4
                              THEN old.webauthn_challenge END AS challenge"#,
            acct,
            id.0,
            purpose,
            now
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(row.and_then(|r| r.challenge))
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
