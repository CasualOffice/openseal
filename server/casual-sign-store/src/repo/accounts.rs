//! The account's own row, staff users through memberships, and permission profiles
//! (docs/22 §8).

use casual_sign_audit::Personal;
use time::OffsetDateTime;

use super::{affected, text_enum};
use crate::error::{Result, StoreError, db};
use crate::ids::{AccountId, PermissionProfileId, UserId};
use crate::store::TenantTx;

/// The current account's row.
#[derive(Debug, Clone, PartialEq)]
pub struct Account {
    /// Its id.
    pub id: AccountId,
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
            "SELECT id, name, settings, data_region, created_at FROM accounts WHERE id = $1",
            acct
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?
        .ok_or(StoreError::NotFound { entity: "account" })?;
        Ok(Account {
            id: AccountId(r.id),
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
            "SELECT u.id, u.email, u.name, u.login_kind, u.disabled_at, m.permission_profile_id \
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
            "SELECT u.id, u.email, u.name, u.login_kind, u.disabled_at, m.permission_profile_id \
             FROM account_memberships m JOIN users u ON u.id = m.user_id \
             WHERE m.account_id = $1 ORDER BY u.name, u.id",
            acct
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        rows.into_iter().map(|r| member!(r)).collect()
    }

    /// Change a member's name. Only a member of this account can be changed.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when not a member.
    pub async fn rename(&mut self, user: UserId, name: &Personal<String>) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE users SET name = $3 WHERE id = $2 AND EXISTS (\
             SELECT 1 FROM account_memberships m WHERE m.account_id = $1 AND m.user_id = $2)",
            acct,
            user.0,
            name.get()
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        affected(done.rows_affected(), "user")
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
