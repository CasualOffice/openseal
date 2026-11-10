//! The account's own row, staff users through memberships, and permission profiles
//! (docs/22 §8).

use casual_sign_audit::Personal;
use sqlx::postgres::PgRow;
use time::OffsetDateTime;

use super::{col, text_enum};
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
        let row = sqlx::query(
            "SELECT id, name, settings, data_region, created_at FROM accounts WHERE id = $1",
        )
        .bind(acct)
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?
        .ok_or(StoreError::NotFound { entity: "account" })?;
        Ok(Account {
            id: AccountId(col(&row, "id")?),
            name: col(&row, "name")?,
            settings: col(&row, "settings")?,
            data_region: col(&row, "data_region")?,
            created_at: col(&row, "created_at")?,
        })
    }

    /// Replace this account's settings.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when the account does not exist; `CS-DB-0008` when not an object.
    pub async fn set_settings(&mut self, settings: &serde_json::Value) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query("UPDATE accounts SET settings = $2 WHERE id = $1")
            .bind(acct)
            .bind(settings)
            .execute(self.tx.conn())
            .await
            .map_err(db)?;
        if done.rows_affected() == 0 {
            return Err(StoreError::NotFound { entity: "account" });
        }
        Ok(())
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

fn member(row: &PgRow) -> Result<Member> {
    let kind: String = col(row, "login_kind")?;
    Ok(Member {
        user_id: UserId(col(row, "id")?),
        email: Personal(col(row, "email")?),
        name: Personal(col(row, "name")?),
        login_kind: LoginKind::parse(&kind, "login_kind")?,
        permission_profile_id: PermissionProfileId(col(row, "permission_profile_id")?),
        disabled_at: col(row, "disabled_at")?,
    })
}

const MEMBER_SELECT: &str = "SELECT u.id, u.email, u.name, u.login_kind, u.disabled_at, \
     m.permission_profile_id FROM account_memberships m JOIN users u ON u.id = m.user_id \
     WHERE m.account_id = $1";

impl Users<'_> {
    /// Create a permission profile.
    ///
    /// # Errors
    ///
    /// `CS-DB-0006` for a duplicate id or name.
    pub async fn create_profile(&mut self, profile: &PermissionProfile) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query(
            "INSERT INTO permission_profiles (id, account_id, name, kind, permissions) \
             VALUES ($2, $1, $3, $4, $5)",
        )
        .bind(acct)
        .bind(profile.id.0)
        .bind(&profile.name)
        .bind(profile.kind.as_str())
        .bind(&profile.permissions)
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
        let row = sqlx::query(
            "SELECT id, name, kind, permissions FROM permission_profiles \
             WHERE account_id = $1 AND id = $2",
        )
        .bind(acct)
        .bind(id.0)
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        row.map(|r| {
            let kind: String = col(&r, "kind")?;
            Ok(PermissionProfile {
                id: PermissionProfileId(col(&r, "id")?),
                name: col(&r, "name")?,
                kind: ProfileKind::parse(&kind, "kind")?,
                permissions: col(&r, "permissions")?,
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
        sqlx::query(
            "INSERT INTO users (id, email, email_normalized, name, login_kind, idp_issuer, idp_subject) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(user.id.0)
        .bind(user.email.get())
        .bind(user.email_normalized.get())
        .bind(user.name.get())
        .bind(user.login_kind.as_str())
        .bind(issuer)
        .bind(subject)
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        self.add_member(user.id, profile).await
    }

    /// Make an existing user (found through login resolution) a member of this account.
    ///
    /// # Errors
    ///
    /// `CS-DB-0006` when already a member; `CS-DB-0008` for an unknown user or a profile
    /// of another account.
    pub async fn add_member(&mut self, user: UserId, profile: PermissionProfileId) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query(
            "INSERT INTO account_memberships (account_id, user_id, permission_profile_id) \
             VALUES ($1, $2, $3)",
        )
        .bind(acct)
        .bind(user.0)
        .bind(profile.0)
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// A member of this account.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn get(&mut self, user: UserId) -> Result<Option<Member>> {
        let acct = self.tx.acct();
        let sql = format!("{MEMBER_SELECT} AND m.user_id = $2");
        let row = sqlx::query(&sql)
            .bind(acct)
            .bind(user.0)
            .fetch_optional(self.tx.conn())
            .await
            .map_err(db)?;
        row.as_ref().map(member).transpose()
    }

    /// Every member of this account, by name.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn list(&mut self) -> Result<Vec<Member>> {
        let acct = self.tx.acct();
        let sql = format!("{MEMBER_SELECT} ORDER BY u.name, u.id");
        let rows = sqlx::query(&sql)
            .bind(acct)
            .fetch_all(self.tx.conn())
            .await
            .map_err(db)?;
        rows.iter().map(member).collect()
    }

    /// Change a member's name. Only a member of this account can be changed.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when not a member.
    pub async fn rename(&mut self, user: UserId, name: &Personal<String>) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query(
            "UPDATE users SET name = $3 WHERE id = $2 AND EXISTS (\
             SELECT 1 FROM account_memberships m WHERE m.account_id = $1 AND m.user_id = $2)",
        )
        .bind(acct)
        .bind(user.0)
        .bind(name.get())
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        if done.rows_affected() == 0 {
            return Err(StoreError::NotFound { entity: "user" });
        }
        Ok(())
    }

    /// Remove a member from this account (the user remains for their other accounts).
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when not a member; `CS-DB-0008` when rows still reference them.
    pub async fn remove_member(&mut self, user: UserId) -> Result<()> {
        let acct = self.tx.acct();
        let done =
            sqlx::query("DELETE FROM account_memberships WHERE account_id = $1 AND user_id = $2")
                .bind(acct)
                .bind(user.0)
                .execute(self.tx.conn())
                .await
                .map_err(db)?;
        if done.rows_affected() == 0 {
            return Err(StoreError::NotFound { entity: "user" });
        }
        Ok(())
    }
}
