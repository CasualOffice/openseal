//! Idempotency records (docs/40 §1, migration 0008): the first response to a `POST`
//! carrying `Idempotency-Key`, per principal, so a replay within 24 hours answers the
//! same. Written in the same transaction as the change the request made.

use time::OffsetDateTime;

use super::hash32;
use crate::error::{Result, db};
use crate::store::TenantTx;

/// A stored first response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The principal that sent the request (`user:<id>`, `client:<id>`).
    pub principal: String,
    /// The client's key.
    pub key: String,
    /// SHA-256 of the method, path and body of the first request.
    pub request_sha256: [u8; 32],
    /// The HTTP status answered.
    pub status: i32,
    /// The body answered; `None` when it revealed a secret, which is never stored.
    pub body: Option<Vec<u8>>,
    /// When.
    pub created_at: OffsetDateTime,
}

/// Idempotency records of this account. Reached through `TenantTx::idempotency`.
#[derive(Debug)]
pub struct Idempotency<'t> {
    pub(crate) tx: &'t mut TenantTx,
}

impl Idempotency<'_> {
    /// The record of `principal`'s `key` in this account, made at or after `since`.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn get(
        &mut self,
        principal: &str,
        key: &str,
        since: OffsetDateTime,
    ) -> Result<Option<Record>> {
        let acct = self.tx.acct();
        let row = sqlx::query!(
            "SELECT principal, key, request_sha256, status, body, created_at FROM idempotency_keys \
             WHERE account_id = $1 AND principal = $2 AND key = $3 AND created_at >= $4",
            acct,
            principal,
            key,
            since
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        row.map(|r| {
            Ok(Record {
                principal: r.principal,
                key: r.key,
                request_sha256: hash32(r.request_sha256, "request_sha256")?,
                status: r.status,
                body: r.body,
                created_at: r.created_at,
            })
        })
        .transpose()
    }

    /// Store a first response, replacing an expired record of the same key; returns
    /// whether it was stored (false when a live record exists: a concurrent first
    /// request won).
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` for a value out of bounds.
    pub async fn put(&mut self, r: &Record, expired_before: OffsetDateTime) -> Result<bool> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "INSERT INTO idempotency_keys (account_id, principal, key, request_sha256, status, \
             body, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (account_id, principal, key) DO UPDATE SET \
               request_sha256 = EXCLUDED.request_sha256, status = EXCLUDED.status, \
               body = EXCLUDED.body, created_at = EXCLUDED.created_at \
             WHERE idempotency_keys.created_at < $8",
            acct,
            r.principal,
            r.key,
            r.request_sha256.as_slice(),
            r.status,
            r.body.as_deref(),
            r.created_at,
            expired_before
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(done.rows_affected() == 1)
    }
}
