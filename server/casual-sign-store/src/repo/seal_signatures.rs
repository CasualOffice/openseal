//! The signatures keyd made for a seal (migration 0035, `CON-09`, docs/23 §5.4): one row
//! per signature, the digest keyd signed and the alias, written by the worker with the
//! sealed bytes so the console can match keyd's operation log against them. Ids and
//! hashes only; operational, not evidence. Insert-only.

use time::OffsetDateTime;

use crate::error::{Result, db};
use crate::ids::EnvelopeId;
use crate::store::TenantTx;

/// The `seal_signatures` repository.
#[derive(Debug)]
pub struct SealSignatures<'t> {
    pub(crate) tx: &'t mut TenantTx,
}

impl SealSignatures<'_> {
    /// Record that keyd signed `digest` with `alias` for `envelope`; a row already there
    /// is kept. Returns whether this call added it.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` for an envelope of another account, a digest that is not 32, 48 or
    /// 64 bytes, or an alias outside `[A-Za-z0-9._-]{1,64}`.
    pub async fn record(
        &mut self,
        envelope: EnvelopeId,
        digest: &[u8],
        alias: &str,
        at: OffsetDateTime,
    ) -> Result<bool> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "INSERT INTO seal_signatures (account_id, envelope_id, digest, alias, at) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
            acct,
            envelope.0,
            digest,
            alias,
            at
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(done.rows_affected() == 1)
    }

    /// The digests recorded for `envelope`, in byte order.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn digests(&mut self, envelope: EnvelopeId) -> Result<Vec<Vec<u8>>> {
        let acct = self.tx.acct();
        let rows = sqlx::query_scalar!(
            "SELECT digest FROM seal_signatures WHERE account_id = $1 AND envelope_id = $2 \
             ORDER BY digest",
            acct,
            envelope.0
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(rows)
    }
}
