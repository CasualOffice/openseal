//! Anchors of chain heads (migration 0041, docs/32 §5, `FG-158`): per account and UTC day,
//! the Merkle tree over the heads that changed, its RFC 3161 token, and each envelope's
//! leaf and audit path. Evidence: insert-only, refused UPDATE and DELETE by triggers.
//! Ids, hashes and the token only.

use time::{Date, OffsetDateTime};
use uuid::Uuid;

use crate::error::{Result, StoreError, db};
use crate::ids::EnvelopeId;
use crate::repo::hash32;
use crate::store::TenantTx;

/// Rows per leaf insert statement.
const CHUNK: usize = 5_000;

/// The `chain_anchors` and `chain_anchor_leaves` repository.
#[derive(Debug)]
pub struct Anchors<'t> {
    pub(crate) tx: &'t mut TenantTx,
}

/// An envelope's head to anchor: the last event recorded before the period's end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadToAnchor {
    /// The envelope.
    pub envelope: EnvelopeId,
    /// The event's sequence number.
    pub seq: u64,
    /// The event's hash.
    pub head: [u8; 32],
}

/// An anchor, as stored.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredAnchor {
    /// Its id.
    pub id: Uuid,
    /// The UTC day it covers.
    pub period: Date,
    /// Leaves in its tree.
    pub tree_size: u64,
    /// The tree's root.
    pub root: [u8; 32],
    /// The DER `TimeStampToken` over the statement.
    pub timestamp_token: Vec<u8>,
    /// The token's `genTime`.
    pub tsa_time: OffsetDateTime,
    /// When the worker stored it.
    pub created_at: OffsetDateTime,
}

impl core::fmt::Debug for StoredAnchor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoredAnchor")
            .field("id", &self.id)
            .field("period", &self.period)
            .field("tree_size", &self.tree_size)
            .field("token_len", &self.timestamp_token.len())
            .finish_non_exhaustive()
    }
}

/// A leaf to store with its anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewLeaf {
    /// Its index in the tree.
    pub leaf_index: u64,
    /// The head anchored.
    pub head: HeadToAnchor,
    /// The audit path from the leaf up.
    pub path: Vec<[u8; 32]>,
}

/// An envelope's leaf, with its anchor: what its proof file is made from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredLeaf {
    /// The anchor.
    pub anchor: StoredAnchor,
    /// The leaf's index.
    pub leaf_index: u64,
    /// The head's event's sequence number.
    pub seq: u64,
    /// The head.
    pub head: [u8; 32],
    /// The audit path.
    pub path: Vec<[u8; 32]>,
}

fn u64_of(v: i64, column: &'static str) -> Result<u64> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt { column })
}

fn i64_of(v: u64) -> Result<i64> {
    i64::try_from(v).map_err(|_| StoreError::Constraint {
        constraint: None,
        sqlstate: "22003".into(),
    })
}

fn path_of(bytes: &[u8]) -> Result<Vec<[u8; 32]>> {
    if !bytes.len().is_multiple_of(32) {
        return Err(StoreError::Corrupt { column: "path" });
    }
    bytes
        .chunks(32)
        .map(|c| hash32(c.to_vec(), "path"))
        .collect()
}

impl Anchors<'_> {
    /// The head, as of `end`, of every envelope with an event in `[start, end)` whose head
    /// is not anchored yet, in envelope id order; at most `limit`.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0010` for a stored value out of shape.
    pub async fn heads_for_period(
        &mut self,
        start: OffsetDateTime,
        end: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<HeadToAnchor>> {
        let acct = self.tx.acct();
        let rows = sqlx::query!(
            r#"SELECT h.envelope_id AS "envelope_id!", h.seq AS "seq!", h.hash AS "hash!"
                 FROM (SELECT DISTINCT ON (a.envelope_id) a.envelope_id, a.seq, a.hash
                         FROM audit_events AS a
                        WHERE a.account_id = $1 AND a.at < $3
                          AND a.envelope_id IN (SELECT e.envelope_id FROM audit_events AS e
                                                 WHERE e.account_id = $1
                                                   AND e.at >= $2 AND e.at < $3)
                        ORDER BY a.envelope_id, a.seq DESC) AS h
                WHERE NOT EXISTS (SELECT 1 FROM chain_anchor_leaves AS l
                                   WHERE l.account_id = $1 AND l.envelope_id = h.envelope_id
                                     AND l.head = h.hash)
                ORDER BY h.envelope_id
                LIMIT $4"#,
            acct,
            start,
            end,
            i64::from(limit)
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        rows.into_iter()
            .map(|r| {
                Ok(HeadToAnchor {
                    envelope: EnvelopeId(r.envelope_id),
                    seq: u64_of(r.seq, "seq")?,
                    head: hash32(r.hash, "hash")?,
                })
            })
            .collect()
    }

    /// The anchor of `period`, if one is stored.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0010`.
    pub async fn by_period(&mut self, period: Date) -> Result<Option<StoredAnchor>> {
        let acct = self.tx.acct();
        let row = sqlx::query!(
            "SELECT id, period, tree_size, root, timestamp_token, tsa_time, created_at \
               FROM chain_anchors WHERE account_id = $1 AND period = $2",
            acct,
            period
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        row.map(|r| {
            Ok(StoredAnchor {
                id: r.id,
                period: r.period,
                tree_size: u64_of(r.tree_size, "tree_size")?,
                root: hash32(r.root, "root")?,
                timestamp_token: r.timestamp_token,
                tsa_time: r.tsa_time,
                created_at: r.created_at,
            })
        })
        .transpose()
    }

    /// Store `anchor` and its `leaves`. Returns false, storing nothing, when the period
    /// already has an anchor (another run stored it first).
    ///
    /// # Errors
    ///
    /// `CS-DB-0006` for a head already anchored; `CS-DB-0008` for a value out of its
    /// checks; `CS-DB-0001`.
    pub async fn insert(&mut self, anchor: &StoredAnchor, leaves: &[NewLeaf]) -> Result<bool> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "INSERT INTO chain_anchors \
               (account_id, id, period, tree_size, root, timestamp_token, tsa_time, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (account_id, period) DO NOTHING",
            acct,
            anchor.id,
            anchor.period,
            i64_of(anchor.tree_size)?,
            &anchor.root[..],
            &anchor.timestamp_token,
            anchor.tsa_time,
            anchor.created_at
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        if done.rows_affected() == 0 {
            return Ok(false);
        }
        for chunk in leaves.chunks(CHUNK) {
            let mut index = Vec::with_capacity(chunk.len());
            let mut envelope = Vec::with_capacity(chunk.len());
            let mut seq = Vec::with_capacity(chunk.len());
            let mut head = Vec::with_capacity(chunk.len());
            let mut path = Vec::with_capacity(chunk.len());
            for l in chunk {
                index.push(i64_of(l.leaf_index)?);
                envelope.push(l.head.envelope.0);
                seq.push(i64_of(l.head.seq)?);
                head.push(l.head.head.to_vec());
                path.push(l.path.concat());
            }
            sqlx::query!(
                "INSERT INTO chain_anchor_leaves \
                   (account_id, anchor_id, leaf_index, envelope_id, seq, head, path) \
                 SELECT $1, $2, i, e, s, h, p \
                   FROM UNNEST($3::bigint[], $4::uuid[], $5::bigint[], $6::bytea[], $7::bytea[]) \
                     AS t (i, e, s, h, p)",
                acct,
                anchor.id,
                &index,
                &envelope,
                &seq,
                &head,
                &path
            )
            .execute(self.tx.conn())
            .await
            .map_err(db)?;
        }
        Ok(true)
    }

    /// Every leaf of `envelope`, with its anchor, oldest period first.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0010`.
    pub async fn leaves_of(&mut self, envelope: EnvelopeId) -> Result<Vec<StoredLeaf>> {
        let acct = self.tx.acct();
        let rows = sqlx::query!(
            "SELECT a.id, a.period, a.tree_size, a.root, a.timestamp_token, a.tsa_time, \
                    a.created_at, l.leaf_index, l.seq, l.head, l.path \
               FROM chain_anchor_leaves AS l \
               JOIN chain_anchors AS a ON a.account_id = l.account_id AND a.id = l.anchor_id \
              WHERE l.account_id = $1 AND l.envelope_id = $2 \
              ORDER BY a.period, l.seq",
            acct,
            envelope.0
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        rows.into_iter()
            .map(|r| {
                Ok(StoredLeaf {
                    anchor: StoredAnchor {
                        id: r.id,
                        period: r.period,
                        tree_size: u64_of(r.tree_size, "tree_size")?,
                        root: hash32(r.root, "root")?,
                        timestamp_token: r.timestamp_token,
                        tsa_time: r.tsa_time,
                        created_at: r.created_at,
                    },
                    leaf_index: u64_of(r.leaf_index, "leaf_index")?,
                    seq: u64_of(r.seq, "seq")?,
                    head: hash32(r.head, "head")?,
                    path: path_of(&r.path)?,
                })
            })
            .collect()
    }
}
