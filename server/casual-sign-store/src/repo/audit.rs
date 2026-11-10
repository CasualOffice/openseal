//! The audit chain (docs/32): append and read, nothing else. There is no update or
//! delete method; the application role lacks the privileges and a trigger refuses both
//! (migration 0005).
//!
//! An event is stored as its RFC 8785 canonical bytes, exactly what its hash covers, so
//! reading back never re-encodes. The database recomputes the hash on insert and checks
//! that `seq` and `prev` extend the chain; [`Audit::chain`] re-verifies on the way out.

use casual_sign_audit::{AuditEvent, Chain, Hash256, json};
use casual_sign_model::Id;
use time::OffsetDateTime;

use super::{hash32, opt_hash32};
use crate::error::{Result, StoreError};
use crate::ids::EnvelopeId;
use crate::store::TenantTx;

/// Most nesting levels read back from a stored event (as `AuditLimits::default`).
const MAX_DEPTH: usize = 32;

/// An event as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEvent {
    /// Position in the chain.
    pub seq: u64,
    /// The previous event's hash.
    pub prev: Option<[u8; 32]>,
    /// This event's hash.
    pub hash: [u8; 32],
    /// The event type (`envelope.sent`, ...).
    pub event_type: String,
    /// The event's own time.
    pub at: OffsetDateTime,
    /// The canonical bytes hashed (may hold personal data: never log).
    pub canonical: Vec<u8>,
}

/// The audit chain of this account's envelopes. Reached through `TenantTx::audit`.
#[derive(Debug)]
pub struct Audit<'t> {
    pub(crate) tx: &'t mut TenantTx,
}

fn chain_broken(seq: u64) -> impl Fn(sqlx::Error) -> StoreError {
    move |e| StoreError::from_sqlx(&e, Some(seq))
}

impl Audit<'_> {
    /// Append `event` to its envelope's chain; returns its hash. Call in the same
    /// transaction as the state change it records (docs/32 §1).
    ///
    /// # Errors
    ///
    /// `CS-DB-0005` when the event is for another envelope, cannot be written, or does
    /// not extend the chain; `CS-DB-0008` when the envelope is not this account's.
    pub async fn append(&mut self, envelope: EnvelopeId, event: &AuditEvent) -> Result<Hash256> {
        let seq = event.seq;
        let broken = StoreError::ChainBroken { seq };
        if event.envelope_id.as_str() != envelope.to_string() {
            return Err(broken);
        }
        let value = event.to_value().map_err(|_| broken.clone())?;
        let event_type = value
            .get("type")
            .and_then(json::Value::as_str)
            .ok_or(broken.clone())?
            .to_owned();
        let canonical = event.canonical().map_err(|_| broken.clone())?;
        let hash = Hash256::digest(&canonical);
        let at = OffsetDateTime::from_unix_timestamp_nanos(
            i128::from(event.at.unix_millis()).saturating_mul(1_000_000),
        )
        .map_err(|_| broken.clone())?;
        let seq_db = i64::try_from(seq).map_err(|_| broken)?;
        let acct = self.tx.acct();
        sqlx::query!(
            "INSERT INTO audit_events (account_id, envelope_id, seq, prev_hash, hash, event_type, \
             at, canonical) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            acct,
            envelope.0,
            seq_db,
            event.prev.as_ref().map(|h| h.as_bytes().as_slice()),
            hash.as_bytes().as_slice(),
            event_type,
            at,
            canonical
        )
        .execute(self.tx.conn())
        .await
        .map_err(chain_broken(seq))?;
        Ok(hash)
    }

    /// The stored events of an envelope of this account, in order.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn events(&mut self, envelope: EnvelopeId) -> Result<Vec<StoredEvent>> {
        let acct = self.tx.acct();
        let rows = sqlx::query!(
            "SELECT seq, prev_hash, hash, event_type, at, canonical FROM audit_events \
             WHERE account_id = $1 AND envelope_id = $2 ORDER BY seq",
            acct,
            envelope.0
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(crate::error::db)?;
        rows.into_iter()
            .map(|r| {
                Ok(StoredEvent {
                    seq: u64::try_from(r.seq).map_err(|_| StoreError::Corrupt { column: "seq" })?,
                    prev: opt_hash32(r.prev_hash, "prev_hash")?,
                    hash: hash32(r.hash, "hash")?,
                    event_type: r.event_type,
                    at: r.at,
                    canonical: r.canonical,
                })
            })
            .collect()
    }

    /// The chain head (`seq`, hash) of an envelope of this account, if it has events.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn head(&mut self, envelope: EnvelopeId) -> Result<Option<(u64, Hash256)>> {
        let acct = self.tx.acct();
        let row = sqlx::query!(
            "SELECT seq, hash FROM audit_events WHERE account_id = $1 AND envelope_id = $2 \
             ORDER BY seq DESC LIMIT 1",
            acct,
            envelope.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(crate::error::db)?;
        row.map(|r| {
            Ok((
                u64::try_from(r.seq).map_err(|_| StoreError::Corrupt { column: "seq" })?,
                Hash256(hash32(r.hash, "hash")?),
            ))
        })
        .transpose()
    }

    /// The envelope's chain, rebuilt from the stored bytes through
    /// [`Chain::append`], which re-checks every link; each stored hash must equal the
    /// recomputed one.
    ///
    /// # Errors
    ///
    /// `CS-DB-0005` naming the first event that does not verify; `CS-DB-0010` for an
    /// unreadable row.
    pub async fn chain(&mut self, envelope: EnvelopeId) -> Result<Chain> {
        let id = Id::new(envelope.to_string()).map_err(|_| StoreError::Corrupt {
            column: "envelope_id",
        })?;
        let mut chain = Chain::new(id);
        for stored in self.events(envelope).await? {
            let broken = StoreError::ChainBroken { seq: stored.seq };
            let tree = json::parse(&stored.canonical, MAX_DEPTH).map_err(|_| broken.clone())?;
            let event = AuditEvent::from_value(&tree).map_err(|_| broken.clone())?;
            if event.seq != stored.seq {
                return Err(broken);
            }
            let hash = chain.append(event).map_err(|_| broken.clone())?;
            if hash.as_bytes() != &stored.hash || Hash256::digest(&stored.canonical) != hash {
                return Err(broken);
            }
        }
        Ok(chain)
    }
}
