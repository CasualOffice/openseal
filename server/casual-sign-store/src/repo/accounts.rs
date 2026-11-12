//! The account's own row, staff users through memberships, and permission profiles
//! (docs/22 §8).

use casual_sign_audit::Personal;
use time::OffsetDateTime;

use super::{affected, text_enum};
use crate::error::{Result, StoreError, db};
use crate::ids::{
    AccountId, OrganizationId, PermissionProfileId, StaffSessionId, UserId, UserInvitationId,
};
use crate::org::WorkspaceStatus;
use crate::store::TenantTx;

/// The current account's row.
#[derive(Debug, Clone, PartialEq)]
pub struct Account {
    /// Its id.
    pub id: AccountId,
    /// The organization it is a workspace of; never changes (docs/23 §2.1).
    pub organization_id: OrganizationId,
    /// Active or archived.
    pub status: WorkspaceStatus,
    /// Its display name.
    pub name: String,
    /// Settings (docs/22 §8).
    pub settings: serde_json::Value,
    /// Data region tag.
    pub data_region: Option<String>,
    /// Created.
    pub created_at: OffsetDateTime,
}

/// The account's own row. Reached through `TenantTx::account`.
#[derive(Debug)]
pub struct Accounts<'t> {
    pub(crate) tx: &'t mut TenantTx,
}

impl Accounts<'_> {
    /// This transaction's account.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when the account does not exist.
    pub async fn get(&mut self) -> Result<Account> {
        let acct = self.tx.acct();
        let r = sqlx::query!(
            "SELECT id, organization_id, status, name, settings, data_region, created_at \
             FROM accounts WHERE id = $1",
            acct
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?
        .ok_or(StoreError::NotFound { entity: "account" })?;
        Ok(Account {
            id: AccountId(r.id),
            organization_id: OrganizationId(r.organization_id),
            status: WorkspaceStatus::parse(&r.status, "status")?,
            name: r.name,
            settings: r.settings,
            data_region: r.data_region,
            created_at: r.created_at,
        })
    }

    /// Replace this account's settings.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when the account does not exist; `CS-DB-0008` when not an object.
    pub async fn set_settings(&mut self, settings: &serde_json::Value) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE accounts SET settings = $2 WHERE id = $1",
            acct,
            settings
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        affected(done.rows_affected(), "account")
    }

    /// Make `user`, the first administrator of a just-bootstrapped install, the owner of
    /// this account's organization ([`crate::Store::bootstrap_organization`]). Refused
    /// unless this transaction created the organization, it has no administrator yet and
    /// this is its only workspace, and `user` is an enabled member here holding the
    /// built-in admin profile. An organization that already existed without an owner is
    /// never claimable here (docs/23 §5.1).
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when refused.
    pub async fn make_first_owner(&mut self, user: UserId, now: OffsetDateTime) -> Result<()> {
        let done = sqlx::query_scalar!(
            r#"SELECT openseal_bootstrap_owner($1, $2) AS "done!""#,
            user.0,
            now
        )
        .fetch_one(self.tx.conn())
        .await
        .map_err(db)?;
        if done {
            Ok(())
        } else {
            Err(StoreError::NotFound {
                entity: "organization",
            })
        }
    }

    /// The published disclosure (ERSD, docs/22 §1) whose text hashes to `sha256`: the
    /// one the account's workflow policy names, whose hash consent records (UXW-34).
    /// When one text was published under several versions or languages, the highest
    /// version (then the first language) is answered, so the answer is deterministic.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn disclosure(&mut self, sha256: &[u8; 32]) -> Result<Option<Disclosure>> {
        let acct = self.tx.acct();
        let row = sqlx::query!(
            "SELECT version, language, body FROM ersd_versions \
             WHERE account_id = $1 AND text_sha256 = $2 AND published_at IS NOT NULL \
             ORDER BY version DESC, language LIMIT 1",
            acct,
            sha256.as_slice()
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(row.map(|r| Disclosure {
            version: r.version,
            language: r.language,
            body: r.body,
        }))
    }
}

/// A published disclosure's text (`ersd_versions`, docs/22 §1). Immutable once
/// published: a change is a new version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disclosure {
    /// The table's version number (the policy names its own label for it).
    pub version: i32,
    /// Its language tag.
    pub language: String,
    /// The text recipients read; its SHA-256 is what consent records.
    pub body: String,
}

text_enum!(
    /// How a staff user logs in.
    LoginKind {
        /// OpenID Connect.
        Oidc = "oidc",
        /// SAML.
        Saml = "saml",
        /// Local password with TOTP or WebAuthn.
        Local = "local",
    }
);

text_enum!(
    /// A permission profile's kind (docs/22 §8).
    ProfileKind {
        /// Everything.
        Admin = "admin",
        /// Send envelopes.
        Sender = "sender",
        /// Read only.
        Viewer = "viewer",
        /// A custom set of permissions.
        Custom = "custom",
    }
);

/// A new staff user.
#[derive(Debug, Clone)]
pub struct NewUser {
    /// Host-minted id.
    pub id: UserId,
    /// Email as entered (personal data).
    pub email: Personal<String>,
    /// Email normalized for lookup (personal data).
    pub email_normalized: Personal<String>,
    /// Display name (personal data).
    pub name: Personal<String>,
    /// How they log in.
    pub login_kind: LoginKind,
    /// Identity provider issuer and subject, for OIDC and SAML.
    pub idp: Option<(String, String)>,
}

/// A staff user as this account sees them.
#[derive(Debug, Clone, PartialEq)]
pub struct Member {
    /// The user.
    pub user_id: UserId,
    /// Email (personal data).
    pub email: Personal<String>,
    /// Name (personal data).
    pub name: Personal<String>,
    /// Login kind.
    pub login_kind: LoginKind,
    /// Their permission profile in this account.
    pub permission_profile_id: PermissionProfileId,
    /// Disabled, when set.
    pub disabled_at: Option<OffsetDateTime>,
}

/// A permission profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionProfile {
    /// Its id.
    pub id: PermissionProfileId,
    /// Its name.
    pub name: String,
    /// Built in or custom.
    pub kind: ProfileKind,
    /// Granted permissions.
    pub permissions: Vec<String>,
}

/// Staff users through memberships, and permission profiles. Reached through
/// `TenantTx::users`.
#[derive(Debug)]
pub struct Users<'t> {
    pub(crate) tx: &'t mut TenantTx,
}

macro_rules! member {
    ($r:expr) => {{
        let r = $r;
        Ok::<_, StoreError>(Member {
            user_id: UserId(r.id),
            email: Personal(r.email),
            name: Personal(r.name),
            login_kind: LoginKind::parse(&r.login_kind, "login_kind")?,
            permission_profile_id: PermissionProfileId(r.permission_profile_id),
            disabled_at: r.disabled_at,
        })
    }};
}

impl Users<'_> {
    /// Create a permission profile.
    ///
    /// # Errors
    ///
    /// `CS-DB-0006` for a duplicate id or name.
    pub async fn create_profile(&mut self, profile: &PermissionProfile) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "INSERT INTO permission_profiles (id, account_id, name, kind, permissions) \
             VALUES ($2, $1, $3, $4, $5)",
            acct,
            profile.id.0,
            profile.name,
            profile.kind.as_str(),
            &profile.permissions
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// A permission profile of this account.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn profile(&mut self, id: PermissionProfileId) -> Result<Option<PermissionProfile>> {
        let acct = self.tx.acct();
        let row = sqlx::query!(
            "SELECT id, name, kind, permissions FROM permission_profiles \
             WHERE account_id = $1 AND id = $2",
            acct,
            id.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        row.map(|r| {
            Ok(PermissionProfile {
                id: PermissionProfileId(r.id),
                name: r.name,
                kind: ProfileKind::parse(&r.kind, "kind")?,
                permissions: r.permissions,
            })
        })
        .transpose()
    }

    /// Create a user and make them a member of this account with `profile`.
    ///
    /// # Errors
    ///
    /// `CS-DB-0006` when the email or identity is taken; `CS-DB-0008` for a profile of
    /// another account.
    pub async fn create_member(
        &mut self,
        user: &NewUser,
        profile: PermissionProfileId,
    ) -> Result<()> {
        // `users` has no account column: the membership inserted next is what scopes it.
        let (issuer, subject) = match &user.idp {
            Some((i, s)) => (Some(i.as_str()), Some(s.as_str())),
            None => (None, None),
        };
        sqlx::query!(
            "INSERT INTO users (id, email, email_normalized, name, login_kind, idp_issuer, idp_subject) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            user.id.0,
            user.email.get(),
            user.email_normalized.get(),
            user.name.get(),
            user.login_kind.as_str(),
            issuer,
            subject
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        let acct = self.tx.acct();
        sqlx::query!(
            "INSERT INTO account_memberships (account_id, user_id, permission_profile_id) \
             VALUES ($1, $2, $3)",
            acct,
            user.id.0,
            profile.0
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// Make an existing user, of another account, a member of this one. The caller must
    /// present the user's normalized email as well as their id (an accepted invitation
    /// carries both), so an account cannot enrol a stranger by id alone and then read
    /// their row.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when no enabled user has that id and email; `CS-DB-0006` when already
    /// a member; `CS-DB-0008` for a profile of another account.
    pub async fn add_existing_member(
        &mut self,
        user: UserId,
        email_normalized: &Personal<String>,
        profile: PermissionProfileId,
    ) -> Result<()> {
        let added = sqlx::query_scalar!(
            r#"SELECT openseal_add_existing_member($1, $2, $3) AS "added!""#,
            user.0,
            email_normalized.get(),
            profile.0
        )
        .fetch_one(self.tx.conn())
        .await
        .map_err(db)?;
        if added {
            Ok(())
        } else {
            Err(StoreError::NotFound { entity: "user" })
        }
    }

    /// A member of this account.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn get(&mut self, user: UserId) -> Result<Option<Member>> {
        let acct = self.tx.acct();
        let row = sqlx::query!(
            "SELECT u.id, u.email, u.name, u.login_kind, \
             COALESCE(m.disabled_at, u.disabled_at) AS disabled_at, m.permission_profile_id \
             FROM account_memberships m JOIN users u ON u.id = m.user_id \
             WHERE m.account_id = $1 AND m.user_id = $2",
            acct,
            user.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        row.map(|r| member!(r)).transpose()
    }

    /// Every member of this account, by name.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn list(&mut self) -> Result<Vec<Member>> {
        let acct = self.tx.acct();
        let rows = sqlx::query!(
            "SELECT u.id, u.email, u.name, u.login_kind, \
             COALESCE(m.disabled_at, u.disabled_at) AS disabled_at, m.permission_profile_id \
             FROM account_memberships m JOIN users u ON u.id = m.user_id \
             WHERE m.account_id = $1 ORDER BY u.name, u.id",
            acct
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        rows.into_iter().map(|r| member!(r)).collect()
    }

    /// Change a member's name. Only a member of this account, and of no other, can be
    /// changed (SEC-ID-01): the user row is every account's, so a user of several
    /// accounts renames themselves through [`Users::update_own`].
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when not a member; `CS-DB-0009` ([`StoreError::is_shared_user`])
    /// when also a member of another account.
    pub async fn rename(&mut self, user: UserId, name: &Personal<String>) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE users SET name = $3 WHERE id = $2 AND EXISTS (\
             SELECT 1 FROM account_memberships m WHERE m.account_id = $1 AND m.user_id = $2) \
             AND NOT openseal_user_in_other_account($2)",
            acct,
            user.0,
            name.get()
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        self.sole_member_written(user, done.rows_affected()).await
    }

    /// Remove a member from this account (the user remains for their other accounts).
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when not a member; `CS-DB-0008` when rows still reference them.
    pub async fn remove_member(&mut self, user: UserId) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "DELETE FROM account_memberships WHERE account_id = $1 AND user_id = $2",
            acct,
            user.0
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        affected(done.rows_affected(), "user")
    }
}

impl Users<'_> {
    /// A member's Argon2id PHC string, for checking a local login. Only this method
    /// reads it, and only for an enabled member of this account: the application role
    /// cannot select the column, and reads it through `openseal_login_password_hash`.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn password_hash(&mut self, user: UserId) -> Result<Option<Personal<String>>> {
        let acct = self.tx.acct();
        let row = sqlx::query_scalar!("SELECT openseal_login_password_hash($2, $1)", acct, user.0)
            .fetch_one(self.tx.conn())
            .await
            .map_err(db)?;
        Ok(row.map(Personal))
    }

    /// Set a member's Argon2id PHC string (computed by the caller; never a password).
    /// Only a member of this account, and of no other, can be changed (SEC-ID-01); a
    /// user of several accounts sets their own through [`Users::update_own`] or an
    /// invitation ([`Users::accept_invitation_with_password`]).
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when not a member; `CS-DB-0009` ([`StoreError::is_shared_user`])
    /// when also a member of another account.
    pub async fn set_password_hash(&mut self, user: UserId, phc: &Personal<String>) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE users SET password_hash = $3 WHERE id = $2 AND EXISTS (\
             SELECT 1 FROM account_memberships m WHERE m.account_id = $1 AND m.user_id = $2) \
             AND NOT openseal_user_in_other_account($2)",
            acct,
            user.0,
            phc.get()
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        self.sole_member_written(user, done.rows_affected()).await
    }

    /// After an update of a user row guarded by sole membership: done, refused for a
    /// user of another account too, or not a member here.
    async fn sole_member_written(&mut self, user: UserId, rows: u64) -> Result<()> {
        if rows > 0 {
            return Ok(());
        }
        let shared = sqlx::query_scalar!(
            r#"SELECT openseal_user_in_other_account($1) AS "shared!""#,
            user.0
        )
        .fetch_one(self.tx.conn())
        .await
        .map_err(db)?;
        if shared {
            Err(StoreError::Refused {
                sqlstate: SHARED_USER_SQLSTATE.to_owned(),
            })
        } else {
            affected(rows, "user")
        }
    }

    /// The user of `session`, a live session of this account, changes their own name
    /// and/or password (an Argon2id PHC string); `None` leaves either as it is. A new
    /// password ends their sessions in every account they belong to (SEC-ID-01).
    /// Returns the user, or `None` when the session is not live here or its member is
    /// disabled.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` for a name the schema refuses.
    pub async fn update_own(
        &mut self,
        session: StaffSessionId,
        name: Option<&Personal<String>>,
        phc: Option<&Personal<String>>,
        now: OffsetDateTime,
    ) -> Result<Option<UserId>> {
        let user = sqlx::query_scalar!(
            "SELECT openseal_update_own_user($1, $2, $3, $4)",
            session.0,
            name.map(|n| n.get().as_str()),
            phc.map(|p| p.get().as_str()),
            now
        )
        .fetch_one(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(user.map(UserId))
    }
}

/// The SQLSTATE a [`StoreError::Refused`] carries when the user to change is also a
/// member of another account (SEC-ID-01, docs/20 `CS-DB-0009`).
pub const SHARED_USER_SQLSTATE: &str = "OS003";

impl StoreError {
    /// Whether this refuses a change to a user who is also a member of another account
    /// (SEC-ID-01): only the user themselves may change their password or name.
    #[must_use]
    pub fn is_shared_user(&self) -> bool {
        matches!(self, Self::Refused { sqlstate } if sqlstate == SHARED_USER_SQLSTATE)
    }
}

/// A user invitation (WEB-06): ids and times only; the token is stored as SHA-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitation {
    /// Its id.
    pub id: UserInvitationId,
    /// The member invited.
    pub user_id: UserId,
    /// When the worker sent the current link.
    pub sent_at: Option<OffsetDateTime>,
    /// When the current link expires.
    pub expires_at: Option<OffsetDateTime>,
    /// When it was accepted.
    pub accepted_at: Option<OffsetDateTime>,
    /// When it was revoked.
    pub revoked_at: Option<OffsetDateTime>,
}

impl Users<'_> {
    /// Change a member's permission profile in this account.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when not a member; `CS-DB-0008` for a profile of another account.
    pub async fn set_profile(&mut self, user: UserId, profile: PermissionProfileId) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE account_memberships SET permission_profile_id = $3 \
             WHERE account_id = $1 AND user_id = $2",
            acct,
            user.0,
            profile.0
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        affected(done.rows_affected(), "user")
    }

    /// Disable (`Some(at)`) or enable (`None`) a member in this account only; their
    /// other accounts are untouched.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when not a member.
    pub async fn set_disabled(&mut self, user: UserId, at: Option<OffsetDateTime>) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE account_memberships SET disabled_at = $3 \
             WHERE account_id = $1 AND user_id = $2",
            acct,
            user.0,
            at
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        affected(done.rows_affected(), "user")
    }

    /// Record an invitation for a member; the worker sends it.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` when the user is not a member.
    pub async fn create_invitation(
        &mut self,
        id: UserInvitationId,
        user: UserId,
        invited_by: UserId,
        now: OffsetDateTime,
    ) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "INSERT INTO user_invitations (id, account_id, user_id, invited_by, created_at) \
             VALUES ($1, $2, $3, $4, $5)",
            id.0,
            acct,
            user.0,
            invited_by.0,
            now
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// An invitation of this account.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn invitation(&mut self, id: UserInvitationId) -> Result<Option<Invitation>> {
        let acct = self.tx.acct();
        let row = sqlx::query!(
            "SELECT id, user_id, sent_at, expires_at, accepted_at, revoked_at \
             FROM user_invitations WHERE account_id = $1 AND id = $2",
            acct,
            id.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(row.map(|r| Invitation {
            id: UserInvitationId(r.id),
            user_id: UserId(r.user_id),
            sent_at: r.sent_at,
            expires_at: r.expires_at,
            accepted_at: r.accepted_at,
            revoked_at: r.revoked_at,
        }))
    }

    /// A member's invitations, newest first.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn invitations(&mut self, user: UserId) -> Result<Vec<Invitation>> {
        let acct = self.tx.acct();
        let rows = sqlx::query!(
            "SELECT id, user_id, sent_at, expires_at, accepted_at, revoked_at \
             FROM user_invitations WHERE account_id = $1 AND user_id = $2 \
             ORDER BY created_at DESC, id DESC",
            acct,
            user.0
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(rows
            .into_iter()
            .map(|r| Invitation {
                id: UserInvitationId(r.id),
                user_id: UserId(r.user_id),
                sent_at: r.sent_at,
                expires_at: r.expires_at,
                accepted_at: r.accepted_at,
                revoked_at: r.revoked_at,
            })
            .collect())
    }

    /// Give an open invitation its link: the token's SHA-256, its expiry and the time
    /// sent, replacing any earlier link. False when it is accepted or revoked.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn set_invitation_token(
        &mut self,
        id: UserInvitationId,
        token_sha256: &[u8; 32],
        expires_at: OffsetDateTime,
        sent_at: OffsetDateTime,
    ) -> Result<bool> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE user_invitations SET token_sha256 = $3, expires_at = $4, sent_at = $5 \
             WHERE account_id = $1 AND id = $2 AND accepted_at IS NULL AND revoked_at IS NULL",
            acct,
            id.0,
            token_sha256.as_slice(),
            expires_at,
            sent_at
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(done.rows_affected() == 1)
    }

    /// Spend an open, sent, unexpired invitation of this account and set its member's
    /// password (an Argon2id PHC string). The link reached the member's own address, so
    /// this is the member setting their own password, even when they belong to other
    /// accounts too. Their other open invitations here are revoked and their sessions
    /// end in every account (SEC-ID-01). Returns the member, or `None` when the
    /// invitation was not open (a second use of the link).
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn accept_invitation_with_password(
        &mut self,
        id: UserInvitationId,
        phc: &Personal<String>,
        now: OffsetDateTime,
    ) -> Result<Option<UserId>> {
        let user = sqlx::query_scalar!(
            "SELECT openseal_accept_user_invitation($1, $2, $3)",
            id.0,
            phc.get(),
            now
        )
        .fetch_one(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(user.map(UserId))
    }

    /// Revoke a member's open invitations (sent again, disabled, or set up otherwise).
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn revoke_invitations(&mut self, user: UserId, now: OffsetDateTime) -> Result<u64> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE user_invitations SET revoked_at = $3 \
             WHERE account_id = $1 AND user_id = $2 AND accepted_at IS NULL \
             AND revoked_at IS NULL",
            acct,
            user.0,
            now
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(done.rows_affected())
    }
}
