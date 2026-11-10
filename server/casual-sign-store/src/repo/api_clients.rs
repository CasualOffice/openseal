//! API clients and keys (docs/40 §2, SEC-A10). The secret is stored as its SHA-256 only
//! and never read back.

use time::OffsetDateTime;

use super::{affected, text_enum};
use crate::error::{Result, db};
use crate::ids::{ApiClientId, UserId};
use crate::store::TenantTx;

text_enum!(
    /// The kind of API client.
    ApiClientKind {
        /// An OAuth 2.1 application.
        OauthApp = "oauth_app",
        /// A personal API key.
        ApiKey = "api_key",
        /// An RFC 7523 JWT bearer integration.
        JwtIntegration = "jwt_integration",
    }
);

/// A new API client.
#[derive(Debug, Clone)]
pub struct NewApiClient {
    /// Host-minted id.
    pub id: ApiClientId,
    /// Kind.
    pub kind: ApiClientKind,
    /// Display name.
    pub name: String,
    /// Owning member.
    pub owner_user_id: Option<UserId>,
    /// Public prefix for secret scanning.
    pub key_prefix: Option<String>,
    /// SHA-256 of the secret, when it has one.
    pub secret_sha256: Option<[u8; 32]>,
    /// Scopes.
    pub scopes: Vec<String>,
    /// Expiry.
    pub expires_at: Option<OffsetDateTime>,
}

/// An API client as stored, without its secret's hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiClient {
    /// Id.
    pub id: ApiClientId,
    /// Kind.
    pub kind: ApiClientKind,
    /// Name.
    pub name: String,
    /// Owner.
    pub owner_user_id: Option<UserId>,
    /// Prefix.
    pub key_prefix: Option<String>,
    /// Scopes.
    pub scopes: Vec<String>,
    /// Expiry.
    pub expires_at: Option<OffsetDateTime>,
    /// Revoked, when set.
    pub revoked_at: Option<OffsetDateTime>,
}

/// API clients of this account. Reached through `TenantTx::api_clients`.
#[derive(Debug)]
pub struct ApiClients<'t> {
    pub(crate) tx: &'t mut TenantTx,
}

impl ApiClients<'_> {
    /// Register a client.
    ///
    /// # Errors
    ///
    /// `CS-DB-0006` duplicate; `CS-DB-0008` an owner who is not a member.
    pub async fn create(&mut self, c: &NewApiClient) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "INSERT INTO api_clients (id, account_id, kind, name, owner_user_id, key_prefix, \
             secret_sha256, scopes, expires_at) VALUES ($2, $1, $3, $4, $5, $6, $7, $8, $9)",
            acct,
            c.id.0,
            c.kind.as_str(),
            c.name,
            c.owner_user_id.map(|u| u.0),
            c.key_prefix.as_deref(),
            c.secret_sha256.as_ref().map(|h| h.as_slice()),
            &c.scopes,
            c.expires_at
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// A client of this account.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn get(&mut self, id: ApiClientId) -> Result<Option<ApiClient>> {
        let acct = self.tx.acct();
        let row = sqlx::query!(
            "SELECT id, kind, name, owner_user_id, key_prefix, scopes, expires_at, revoked_at \
             FROM api_clients WHERE account_id = $1 AND id = $2",
            acct,
            id.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        row.map(|r| {
            Ok(ApiClient {
                id: ApiClientId(r.id),
                kind: ApiClientKind::parse(&r.kind, "kind")?,
                name: r.name,
                owner_user_id: r.owner_user_id.map(UserId),
                key_prefix: r.key_prefix,
                scopes: r.scopes,
                expires_at: r.expires_at,
                revoked_at: r.revoked_at,
            })
        })
        .transpose()
    }

    /// Revoke a client at `at`.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when this account has no such client.
    pub async fn revoke(&mut self, id: ApiClientId, at: OffsetDateTime) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE api_clients SET revoked_at = COALESCE(revoked_at, $3) \
             WHERE account_id = $1 AND id = $2",
            acct,
            id.0,
            at
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        affected(done.rows_affected(), "api client")
    }
}
