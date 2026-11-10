//! The purge tombstone (docs/32 §7): when an envelope's documents and personal data are
//! purged, what remains is the fact that the agreement existed and was purged: envelope
//! id, chain head, event count, sealed hashes, purge time and policy.
//!
//! The chain's last event must be `envelope.purged`, so the head the tombstone keeps
//! commits to the purge itself. Every party's sealed copy still carries its own chain up
//! to the certificate's head; the tombstone's chain extends it.

use casual_sign_model::Id;

use crate::chain::Chain;
use crate::error::AuditError;
use crate::event::EventData;
use crate::hash::Hash256;
use crate::jcs;
use crate::json::Value;
use crate::time::Timestamp;
use crate::verify::ChainReport;

/// What remains of a purged envelope. No personal data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tombstone {
    /// The envelope.
    pub envelope_id: Id,
    /// The head of the chain, ending with `envelope.purged`.
    pub chain_head: Hash256,
    /// Events in the chain.
    pub event_count: u64,
    /// SHA-256 of each sealed document, as `document.sealed` recorded them.
    pub sealed_hashes: Vec<Hash256>,
    /// When the purge ran (the `envelope.purged` event's time).
    pub purged_at: Timestamp,
    /// The policy or request that purged it.
    pub policy: String,
}

impl Tombstone {
    /// The tombstone of `chain`, whose last event must be `envelope.purged`.
    ///
    /// # Errors
    ///
    /// `CS-AUD-0010` when the chain is empty or does not end with `envelope.purged`.
    pub fn from_chain(chain: &Chain) -> Result<Self, AuditError> {
        let last = chain.events().last().ok_or(AuditError::Tombstone)?;
        let EventData::EnvelopePurged { policy } = &last.event.data else {
            return Err(AuditError::Tombstone);
        };
        let sealed_hashes = chain
            .events()
            .iter()
            .filter_map(|e| match &e.event.data {
                EventData::DocumentSealed { sealed_hash, .. } => Some(*sealed_hash),
                _ => None,
            })
            .collect();
        Ok(Self {
            envelope_id: chain.envelope_id().clone(),
            chain_head: last.hash,
            event_count: u64::try_from(chain.len()).map_err(|_| AuditError::Tombstone)?,
            sealed_hashes,
            purged_at: last.event.at,
            policy: policy.clone(),
        })
    }

    /// Whether `report` (of a chain verified elsewhere, such as a party's copy extended
    /// by the operator's) ends at this tombstone's head with its count.
    #[must_use]
    pub fn matches(&self, report: &ChainReport) -> bool {
        report.is_valid()
            && report.head == Some(self.chain_head)
            && u64::try_from(report.events).ok() == Some(self.event_count)
            && report.envelope_id.as_ref() == Some(&self.envelope_id)
    }

    /// The canonical JSON (RFC 8785) of the tombstone, as stored.
    ///
    /// # Errors
    ///
    /// `CS-AUD-0010` when the count passes 2^53 − 1.
    pub fn to_json(&self) -> Result<Vec<u8>, AuditError> {
        if self.event_count > crate::json::MAX_SAFE_INTEGER {
            return Err(AuditError::Tombstone);
        }
        // At most 2^53 − 1, checked above: exact.
        let count = self.event_count as f64;
        let v = Value::Object(vec![
            ("kind".into(), Value::String("openseal.tombstone".into())),
            ("v".into(), Value::Number(1.0)),
            (
                "envelope_id".into(),
                Value::String(self.envelope_id.as_str().into()),
            ),
            (
                "chain_head".into(),
                Value::String(self.chain_head.to_string()),
            ),
            ("event_count".into(), Value::Number(count)),
            (
                "sealed_hashes".into(),
                Value::Array(
                    self.sealed_hashes
                        .iter()
                        .map(|h| Value::String(h.to_string()))
                        .collect(),
                ),
            ),
            (
                "purged_at".into(),
                Value::String(self.purged_at.to_string()),
            ),
            ("policy".into(), Value::String(self.policy.clone())),
        ]);
        jcs::to_vec(&v).map_err(|_| AuditError::Tombstone)
    }
}

// Tests may unwrap, index and panic (CLAUDE.md).
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Actor, Context};
    use crate::verify::{VerifyOptions, verify_trail};

    fn chain_with(last: EventData) -> Chain {
        let mut c = Chain::new(Id::new("env").unwrap());
        let t = |ms| Timestamp::from_unix_millis(ms).unwrap();
        let sealed = Hash256::digest(b"sealed");
        for (i, d) in [
            EventData::EnvelopeExpired {},
            EventData::DocumentSealed {
                document_id: Id::new("d").unwrap(),
                sealed_hash: sealed,
                profile: "pades-b-lta".into(),
                certificate_fingerprint: sealed,
                tsa_time: None,
            },
            last,
        ]
        .into_iter()
        .enumerate()
        {
            let e = c.next(
                t(i64::try_from(i).unwrap()),
                Actor::system(),
                Context::default(),
                d,
            );
            c.append(e).unwrap();
        }
        c
    }

    #[test]
    fn a_tombstone_keeps_head_count_and_sealed_hashes() {
        let c = chain_with(EventData::EnvelopePurged {
            policy: "retention-7y".into(),
        });
        let ts = Tombstone::from_chain(&c).unwrap();
        assert_eq!(ts.chain_head, c.head().unwrap());
        assert_eq!(ts.event_count, 3);
        assert_eq!(ts.sealed_hashes, [Hash256::digest(b"sealed")]);
        let report = verify_trail(&c.to_trail_json().unwrap(), &VerifyOptions::default());
        assert!(ts.matches(&report));
        let json = String::from_utf8(ts.to_json().unwrap()).unwrap();
        assert!(json.starts_with(r#"{"chain_head":"sha256:"#), "{json}");
    }

    #[test]
    fn only_a_purged_chain_has_a_tombstone() {
        let c = chain_with(EventData::EnvelopeExpired {});
        assert_eq!(Tombstone::from_chain(&c).unwrap_err().code(), "CS-AUD-0010");
        assert!(Tombstone::from_chain(&Chain::new(Id::new("e").unwrap())).is_err());
    }
}
