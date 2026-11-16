//! Key monitoring (docs/23 §5.4): alerts raised by the certificate expiry scan
//! (`CON-08`) and reconciliation runs of keyd's signatures against the seals recorded
//! (`CON-09`, migration 0037). The console reads seal digests only through
//! `platform.seal_digests` and `platform.seal_digests_of`, definer functions returning
//! envelope ids, digests and times; it writes `platform.alerts` and
//! `platform.reconciliation_runs`, both append-only.

use serde_json::Value;
use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{PlatformError, Result, db};
use crate::store::{MAX_PAGE, PlatformStore, PlatformTx};

/// Most envelope ids one `platform.seal_digests_of` call takes.
pub const MAX_ENVELOPES_PER_CALL: usize = 1000;

/// A seal record: the envelope, the digest keyd signed for it, and when it was stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealDigest {
    /// The envelope.
    pub envelope: Uuid,
    /// The digest keyd signed.
    pub digest: Vec<u8>,
    /// When the worker stored the seal (`None` from [`PlatformStore::seal_digests_of`]).
    pub at: Option<OffsetDateTime>,
}

/// One reconciliation run, as recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationRun {
    /// Its id.
    pub id: Uuid,
    /// When it ran.
    pub at: OffsetDateTime,
    /// The first keyd sequence read.
    pub from_seq: u64,
    /// The last keyd sequence judged (`from_seq - 1` when none).
    pub upto_seq: u64,
    /// Where the next run starts reading.
    pub next_seq: u64,
    /// Signatures and seal records before this time were judged.
    pub cutoff: OffsetDateTime,
    /// keyd signatures judged.
    pub signatures: u32,
    /// Of which matched a seal record.
    pub matched: u32,
    /// Mismatches alerted, in either direction.
    pub unmatched: u32,
    /// Orphaned retries: `[{"seq": n, "envelope_id": "..."}]`.
    pub orphaned: Value,
}

fn u64_of(v: i64, what: &'static str) -> Result<u64> {
    u64::try_from(v).map_err(|_| PlatformError::Corrupt { what })
}

fn u32_of(v: i32, what: &'static str) -> Result<u32> {
    u32::try_from(v).map_err(|_| PlatformError::Corrupt { what })
}

fn i64_of(v: u64, what: &'static str) -> Result<i64> {
    i64::try_from(v).map_err(|_| PlatformError::Corrupt { what })
}

fn i32_of(v: u32, what: &'static str) -> Result<i32> {
    i32::try_from(v).map_err(|_| PlatformError::Corrupt { what })
}

impl PlatformStore {
    /// The seal records stored in `[from, to)`, oldest first (at most 100,000).
    ///
    /// # Errors
    /// A database error.
    pub async fn seal_digests(
        &self,
        from: OffsetDateTime,
        to: OffsetDateTime,
    ) -> Result<Vec<SealDigest>> {
        let rows = sqlx::query("SELECT envelope_id, digest, at FROM platform.seal_digests($1, $2)")
            .bind(from)
            .bind(to)
            .fetch_all(self.pool())
            .await
            .map_err(db)?;
        rows.iter()
            .map(|r| {
                Ok(SealDigest {
                    envelope: r.try_get("envelope_id").map_err(db)?,
                    digest: r.try_get("digest").map_err(db)?,
                    at: Some(r.try_get("at").map_err(db)?),
                })
            })
            .collect()
    }

    /// Every seal record of the envelopes named, in calls of at most
    /// [`MAX_ENVELOPES_PER_CALL`] ids.
    ///
    /// # Errors
    /// A database error.
    pub async fn seal_digests_of(&self, envelopes: &[Uuid]) -> Result<Vec<SealDigest>> {
        let mut out = Vec::new();
        for chunk in envelopes.chunks(MAX_ENVELOPES_PER_CALL) {
            let rows = sqlx::query("SELECT envelope_id, digest FROM platform.seal_digests_of($1)")
                .bind(chunk)
                .fetch_all(self.pool())
                .await
                .map_err(db)?;
            for r in &rows {
                out.push(SealDigest {
                    envelope: r.try_get("envelope_id").map_err(db)?,
                    digest: r.try_get("digest").map_err(db)?,
                    at: None,
                });
            }
        }
        Ok(out)
    }

    /// The newest reconciliation runs, newest first.
    ///
    /// # Errors
    /// A database error; `CS-DB-0001` for a stored value out of range.
    pub async fn reconciliation_runs(&self, limit: u32) -> Result<Vec<ReconciliationRun>> {
        let rows = sqlx::query(
            "SELECT id, at, from_seq, upto_seq, next_seq, cutoff, signatures, matched, unmatched, \
                    orphaned \
               FROM platform.reconciliation_runs ORDER BY at DESC, id DESC LIMIT $1",
        )
        .bind(i64::from(limit.clamp(1, MAX_PAGE)))
        .fetch_all(self.pool())
        .await
        .map_err(db)?;
        rows.iter()
            .map(|r| {
                Ok(ReconciliationRun {
                    id: r.try_get("id").map_err(db)?,
                    at: r.try_get("at").map_err(db)?,
                    from_seq: u64_of(r.try_get("from_seq").map_err(db)?, "from_seq")?,
                    upto_seq: u64_of(r.try_get("upto_seq").map_err(db)?, "upto_seq")?,
                    next_seq: u64_of(r.try_get("next_seq").map_err(db)?, "next_seq")?,
                    cutoff: r.try_get("cutoff").map_err(db)?,
                    signatures: u32_of(r.try_get("signatures").map_err(db)?, "signatures")?,
                    matched: u32_of(r.try_get("matched").map_err(db)?, "matched")?,
                    unmatched: u32_of(r.try_get("unmatched").map_err(db)?, "unmatched")?,
                    orphaned: r.try_get("orphaned").map_err(db)?,
                })
            })
            .collect()
    }

    /// Whether an alert with this source, code and subject was ever raised.
    ///
    /// # Errors
    /// A database error.
    pub async fn alert_raised(&self, source: &str, code: &str, subject: &Value) -> Result<bool> {
        sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM platform.alerts \
                             WHERE source = $1 AND code = $2 AND subject = $3)",
        )
        .bind(source)
        .bind(code)
        .bind(subject)
        .fetch_one(self.pool())
        .await
        .map_err(db)
    }
}

impl PlatformTx {
    /// Raise alert `id`: `source` (`[a-z][a-z0-9_-]{0,63}`), a `CS-*` code, and a subject
    /// of ids and labels.
    ///
    /// # Errors
    /// `CS-DB-0008` for a source, code or subject of the wrong shape; a database error.
    pub async fn raise_alert(
        &mut self,
        id: Uuid,
        at: OffsetDateTime,
        source: &str,
        code: &str,
        subject: &Value,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO platform.alerts (id, at, source, code, subject) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(id)
        .bind(at)
        .bind(source)
        .bind(code)
        .bind(subject)
        .execute(&mut *self.tx)
        .await
        .map_err(db)?;
        Ok(())
    }

    /// Record a reconciliation run (`run.id` is used as given).
    ///
    /// # Errors
    /// `CS-DB-0008` for a value the table's checks refuse; a database error.
    pub async fn record_reconciliation(&mut self, run: &ReconciliationRun) -> Result<()> {
        sqlx::query(
            "INSERT INTO platform.reconciliation_runs \
               (id, at, from_seq, upto_seq, next_seq, cutoff, signatures, matched, unmatched, orphaned) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(run.id)
        .bind(run.at)
        .bind(i64_of(run.from_seq, "from_seq")?)
        .bind(i64_of(run.upto_seq, "upto_seq")?)
        .bind(i64_of(run.next_seq, "next_seq")?)
        .bind(run.cutoff)
        .bind(i32_of(run.signatures, "signatures")?)
        .bind(i32_of(run.matched, "matched")?)
        .bind(i32_of(run.unmatched, "unmatched")?)
        .bind(&run.orphaned)
        .execute(&mut *self.tx)
        .await
        .map_err(db)?;
        Ok(())
    }
}
