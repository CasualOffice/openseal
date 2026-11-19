//! OAuth 2.1 grants acting for a member (slice 8, docs/40 §2, migration 0048): a
//! member's consent that an API client acts as them, authorization codes bound to a
//! PKCE challenge, and rotating refresh tokens. Codes and refresh tokens are stored as
//! their SHA-256 only and never read back.

use time::OffsetDateTime;
use uuid::Uuid;

use super::{affected, hash32};
use crate::error::{Result, db};
use crate::ids::{ApiClientId, OAuthConsentId, UserId};
use crate::store::TenantTx;

/// A member's consent that a client acts as them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consent {
    /// Id; access tokens name it, so revoking it ends them.
    pub id: OAuthConsentId,
    /// The client.
    pub client_id: ApiClientId,
    /// The member.
    pub user_id: UserId,
    /// The scopes consented to.
    pub scopes: Vec<String>,
    /// When given.
    pub granted_at: OffsetDateTime,
    /// When revoked.
    pub revoked_at: Option<OffsetDateTime>,
}

/// A new authorization code.
#[derive(Debug, Clone)]
pub struct NewCode {
    /// Host-minted id.
    pub id: Uuid,
    /// The consent it was issued under.
    pub consent_id: OAuthConsentId,
    /// SHA-256 of the code.
    pub code_sha256: [u8; 32],
    /// The redirect URI it was issued to; the exchange must name the same.
    pub redirect_uri: String,
    /// The PKCE S256 challenge.
    pub code_challenge: String,
    /// Scopes granted by this code.
    pub scopes: Vec<String>,
    /// Expiry.
    pub expires_at: OffsetDateTime,
}

/// A code spent by [`OAuth::spend_code`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpentCode {
    /// The consent.
    pub consent_id: OAuthConsentId,
    /// The redirect URI it was issued to.
    pub redirect_uri: String,
    /// The PKCE challenge.
    pub code_challenge: String,
    /// The scopes.
    pub scopes: Vec<String>,
    /// Its expiry (the caller compares with its own clock).
    pub expires_at: OffsetDateTime,
}

/// A new refresh token.
#[derive(Debug, Clone)]
pub struct NewRefresh {
    /// Host-minted id.
    pub id: Uuid,
    /// The consent.
    pub consent_id: OAuthConsentId,
    /// The rotation family: every token rotated from one code.
    pub family_id: Uuid,
    /// SHA-256 of the token.
    pub token_sha256: [u8; 32],
    /// Scopes.
    pub scopes: Vec<String>,
    /// Issued.
    pub created_at: OffsetDateTime,
    /// Expiry.
    pub expires_at: OffsetDateTime,
}

/// What spending a refresh token found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refresh {
    /// Live and now spent: rotate it.
    Live {
        /// The consent.
        consent_id: OAuthConsentId,
        /// Its family.
        family_id: Uuid,
        /// Its scopes.
        scopes: Vec<String>,
    },
    /// Spent before, or revoked: its whole family is now revoked (the replay rule).
    Replayed,
    /// Unknown or expired.
    Unknown,
}

/// OAuth grants of this account. Reached through `TenantTx::oauth`.
#[derive(Debug)]
pub struct OAuth<'t> {
    pub(crate) tx: &'t mut TenantTx,
}

impl OAuth<'_> {
    /// Record `user`'s consent that `client` acts as them with `scopes`: the live
    /// consent widened to hold them too, or a new one with the host-minted `new_id`.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` for a client or member of another account.
    pub async fn consent_to(
        &mut self,
        new_id: OAuthConsentId,
        client: ApiClientId,
        user: UserId,
        scopes: &[String],
        at: OffsetDateTime,
    ) -> Result<Consent> {
        let acct = self.tx.acct();
        if let Some(c) = self.live_consent(client, user).await? {
            let mut all = c.scopes.clone();
            for s in scopes {
                if !all.contains(s) {
                    all.push(s.clone());
                }
            }
            sqlx::query!(
                "UPDATE oauth_consents SET scopes = $3 WHERE account_id = $1 AND id = $2",
                acct,
                c.id.0,
                &all
            )
            .execute(self.tx.conn())
            .await
            .map_err(db)?;
            return Ok(Consent { scopes: all, ..c });
        }
        let id = new_id;
        sqlx::query!(
            "INSERT INTO oauth_consents (id, account_id, client_id, user_id, scopes, granted_at) \
             VALUES ($2, $1, $3, $4, $5, $6)",
            acct,
            id.0,
            client.0,
            user.0,
            scopes,
            at
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(Consent {
            id,
            client_id: client,
            user_id: user,
            scopes: scopes.to_vec(),
            granted_at: at,
            revoked_at: None,
        })
    }

    /// The live consent `user` gave `client`.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn live_consent(
        &mut self,
        client: ApiClientId,
        user: UserId,
    ) -> Result<Option<Consent>> {
        let acct = self.tx.acct();
        let r = sqlx::query!(
            "SELECT id, client_id, user_id, scopes, granted_at, revoked_at FROM oauth_consents \
             WHERE account_id = $1 AND client_id = $2 AND user_id = $3 AND revoked_at IS NULL",
            acct,
            client.0,
            user.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(r.map(|r| Consent {
            id: OAuthConsentId(r.id),
            client_id: ApiClientId(r.client_id),
            user_id: UserId(r.user_id),
            scopes: r.scopes,
            granted_at: r.granted_at,
            revoked_at: r.revoked_at,
        }))
    }

    /// A consent of this account, live or revoked.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn consent(&mut self, id: OAuthConsentId) -> Result<Option<Consent>> {
        let acct = self.tx.acct();
        let r = sqlx::query!(
            "SELECT id, client_id, user_id, scopes, granted_at, revoked_at FROM oauth_consents \
             WHERE account_id = $1 AND id = $2",
            acct,
            id.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(r.map(|r| Consent {
            id: OAuthConsentId(r.id),
            client_id: ApiClientId(r.client_id),
            user_id: UserId(r.user_id),
            scopes: r.scopes,
            granted_at: r.granted_at,
            revoked_at: r.revoked_at,
        }))
    }

    /// `user`'s live consents, newest first.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn consents_of(&mut self, user: UserId) -> Result<Vec<Consent>> {
        let acct = self.tx.acct();
        let rows = sqlx::query!(
            "SELECT id, client_id, user_id, scopes, granted_at, revoked_at FROM oauth_consents \
             WHERE account_id = $1 AND user_id = $2 AND revoked_at IS NULL \
             ORDER BY granted_at DESC, id DESC",
            acct,
            user.0
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(rows
            .into_iter()
            .map(|r| Consent {
                id: OAuthConsentId(r.id),
                client_id: ApiClientId(r.client_id),
                user_id: UserId(r.user_id),
                scopes: r.scopes,
                granted_at: r.granted_at,
                revoked_at: r.revoked_at,
            })
            .collect())
    }

    /// Revoke `user`'s consent `id` and every refresh token issued under it.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when `user` has no such live consent.
    pub async fn revoke_consent(
        &mut self,
        id: OAuthConsentId,
        user: UserId,
        at: OffsetDateTime,
    ) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE oauth_consents SET revoked_at = $4 \
             WHERE account_id = $1 AND id = $2 AND user_id = $3 AND revoked_at IS NULL",
            acct,
            id.0,
            user.0,
            at
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        affected(done.rows_affected(), "consent")?;
        sqlx::query!(
            "UPDATE oauth_refresh_tokens SET revoked_at = $3 \
             WHERE account_id = $1 AND consent_id = $2 AND revoked_at IS NULL",
            acct,
            id.0,
            at
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// Store an authorization code.
    ///
    /// # Errors
    ///
    /// `CS-DB-0006` for a duplicate code.
    pub async fn create_code(&mut self, c: &NewCode) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "INSERT INTO oauth_codes (id, account_id, consent_id, code_sha256, redirect_uri, \
             code_challenge, scopes, expires_at) VALUES ($2, $1, $3, $4, $5, $6, $7, $8)",
            acct,
            c.id,
            c.consent_id.0,
            c.code_sha256.as_slice(),
            c.redirect_uri,
            c.code_challenge,
            &c.scopes,
            c.expires_at
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// Spend the code whose hash is `sha` at `at`, once: a second spend finds nothing.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn spend_code(
        &mut self,
        sha: &[u8; 32],
        at: OffsetDateTime,
    ) -> Result<Option<SpentCode>> {
        let acct = self.tx.acct();
        let r = sqlx::query!(
            "UPDATE oauth_codes SET used_at = $3 \
             WHERE account_id = $1 AND code_sha256 = $2 AND used_at IS NULL \
             RETURNING consent_id, redirect_uri, code_challenge, scopes, expires_at",
            acct,
            sha.as_slice(),
            at
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(r.map(|r| SpentCode {
            consent_id: OAuthConsentId(r.consent_id),
            redirect_uri: r.redirect_uri,
            code_challenge: r.code_challenge,
            scopes: r.scopes,
            expires_at: r.expires_at,
        }))
    }

    /// Store a refresh token.
    ///
    /// # Errors
    ///
    /// `CS-DB-0006` for a duplicate token.
    pub async fn create_refresh(&mut self, t: &NewRefresh) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "INSERT INTO oauth_refresh_tokens (id, account_id, consent_id, family_id, \
             token_sha256, scopes, created_at, expires_at) \
             VALUES ($2, $1, $3, $4, $5, $6, $7, $8)",
            acct,
            t.id,
            t.consent_id.0,
            t.family_id,
            t.token_sha256.as_slice(),
            &t.scopes,
            t.created_at,
            t.expires_at
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// Spend the refresh token whose hash is `sha` at `at`. A token spent before or
    /// revoked revokes its whole family: a stolen token used after its owner rotated
    /// it ends both (OAuth 2.1 §4.3.1).
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0010` for an unreadable row.
    pub async fn spend_refresh(&mut self, sha: &[u8; 32], at: OffsetDateTime) -> Result<Refresh> {
        let acct = self.tx.acct();
        let live = sqlx::query!(
            "UPDATE oauth_refresh_tokens SET used_at = $3 \
             WHERE account_id = $1 AND token_sha256 = $2 AND used_at IS NULL \
               AND revoked_at IS NULL AND expires_at > $3 \
             RETURNING consent_id, family_id, scopes",
            acct,
            sha.as_slice(),
            at
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        if let Some(r) = live {
            return Ok(Refresh::Live {
                consent_id: OAuthConsentId(r.consent_id),
                family_id: r.family_id,
                scopes: r.scopes,
            });
        }
        let seen = sqlx::query!(
            "SELECT family_id, token_sha256, expires_at, used_at, revoked_at \
             FROM oauth_refresh_tokens WHERE account_id = $1 AND token_sha256 = $2",
            acct,
            sha.as_slice()
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        let Some(r) = seen else {
            return Ok(Refresh::Unknown);
        };
        hash32(r.token_sha256, "token_sha256")?;
        if r.used_at.is_none() && r.revoked_at.is_none() {
            // Merely expired.
            return Ok(Refresh::Unknown);
        }
        sqlx::query!(
            "UPDATE oauth_refresh_tokens SET revoked_at = COALESCE(revoked_at, $3) \
             WHERE account_id = $1 AND family_id = $2",
            acct,
            r.family_id,
            at
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(Refresh::Replayed)
    }
}
