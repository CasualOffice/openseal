//! Anchors and proof files from the store's rows (docs/32 §5, `FG-158`): what the worker
//! publishes and what the API serves (`GET /api/v1/envelopes/{id}/anchor-proof`), made
//! here once so both write the same bytes. Moved from `casual_sign_worker::anchor`, which
//! re-exports them.

use casual_sign_audit::{AuditError, Hash256, ShapeFault, Timestamp};
use casual_sign_model::Id;
use casual_sign_sdk::anchor::{Anchor, AnchorProof, InclusionProof};
use casual_sign_store::EnvelopeId;
use casual_sign_store::repo::anchors::{StoredAnchor, StoredLeaf};
use time::Date;

fn out_of_shape() -> AuditError {
    AuditError::Shape {
        fault: ShapeFault::Member("anchor"),
        index: None,
    }
}

/// The `YYYY-MM-DD` of `day`.
#[must_use]
pub fn period_text(day: Date) -> String {
    format!(
        "{:04}-{:02}-{:02}",
        day.year(),
        u8::from(day.month()),
        day.day()
    )
}

/// The engine's [`Anchor`] of a stored anchor.
///
/// # Errors
///
/// `CS-AUD-0003` when a stored value is out of the anchor's shape.
pub fn anchor_of(a: &StoredAnchor) -> Result<Anchor, AuditError> {
    let millis =
        i64::try_from(a.tsa_time.unix_timestamp_nanos() / 1_000_000).map_err(|_| out_of_shape())?;
    Ok(Anchor {
        id: Id::new(a.id.to_string()).map_err(|_| out_of_shape())?,
        period: period_text(a.period),
        tree_size: a.tree_size,
        root: Hash256(a.root),
        tsa_time: Timestamp::from_unix_millis(millis).ok_or_else(out_of_shape)?,
        timestamp_token: a.timestamp_token.clone(),
    })
}

/// The published line of a stored anchor (canonical JSON, `openseal.anchor`).
///
/// # Errors
///
/// As [`anchor_of`] and [`Anchor::to_json`].
pub fn published(a: &StoredAnchor) -> Result<Vec<u8>, AuditError> {
    anchor_of(a)?.to_json()
}

/// One leaf's proof file (`openseal.anchor-proof`, canonical JSON).
///
/// # Errors
///
/// As [`anchor_of`]; `CS-AUD-0009` for a stored path longer than a proof's.
pub fn proof_file(envelope: EnvelopeId, leaf: &StoredLeaf) -> Result<Vec<u8>, AuditError> {
    AnchorProof {
        envelope_id: Id::new(envelope.0.to_string()).map_err(|_| out_of_shape())?,
        seq: leaf.seq,
        head: Hash256(leaf.head),
        proof: InclusionProof {
            leaf_index: leaf.leaf_index,
            tree_size: leaf.anchor.tree_size,
            path: leaf.path.iter().map(|p| Hash256(*p)).collect(),
        },
        anchor: anchor_of(&leaf.anchor)?,
    }
    .to_json()
}

/// An envelope's proof files (`openseal.anchor-proof`), one per anchor covering one of
/// its heads, in the order of `leaves`.
///
/// # Errors
///
/// As [`proof_file`].
pub fn proof_files(
    envelope: EnvelopeId,
    leaves: &[StoredLeaf],
) -> Result<Vec<Vec<u8>>, AuditError> {
    leaves.iter().map(|l| proof_file(envelope, l)).collect()
}
