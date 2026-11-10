//! The per-envelope hash chain (docs/32 §2 and §4, ADR-010) and its wire form, the
//! audit trail file embedded in every sealed document as `audit-trail.json`.
//!
//! [`Chain::append`] is the only way in: it refuses an event for another envelope, a
//! `seq` that is not the next, a `prev` that is not the head, and a time earlier than the
//! previous event's by more than the tolerance. Nothing removes or changes an event.

use casual_sign_model::Id;

use crate::error::{AuditError, ShapeFault};
use crate::event::{Actor, AuditEvent, Context, EVENT_VERSION, EventData};
use crate::hash::Hash256;
use crate::jcs;
use crate::json::Value;
use crate::time::Timestamp;
use crate::verify::{ChainReport, VerifyOptions, verify_trail};
use crate::{AuditLimits, DEFAULT_TIME_TOLERANCE_MS};

/// The value of the trail's `format` member.
pub const TRAIL_FORMAT: &str = "openseal.audit-trail";
/// The trail file's version.
pub const TRAIL_VERSION: u64 = 1;
/// The name the trail is embedded under (docs/30 §8).
pub const TRAIL_FILE_NAME: &str = "audit-trail.json";

/// An event in a chain, with its hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainedEvent {
    /// The event.
    pub event: AuditEvent,
    /// `SHA-256(JCS(event))`.
    pub hash: Hash256,
}

/// One envelope's chain of events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    envelope_id: Id,
    events: Vec<ChainedEvent>,
    tolerance_ms: u64,
    max_events: usize,
}

impl Chain {
    /// An empty chain for `envelope_id`, with the default time tolerance
    /// ([`DEFAULT_TIME_TOLERANCE_MS`]) and limits.
    #[must_use]
    pub fn new(envelope_id: Id) -> Self {
        Self {
            envelope_id,
            events: Vec::new(),
            tolerance_ms: DEFAULT_TIME_TOLERANCE_MS,
            max_events: AuditLimits::default().max_events,
        }
    }

    /// The same chain, accepting an event up to `ms` earlier than the one before it
    /// (servers' clocks differ slightly; docs/32 §2).
    #[must_use]
    pub fn with_time_tolerance(mut self, ms: u64) -> Self {
        self.tolerance_ms = ms;
        self
    }

    /// The envelope.
    #[must_use]
    pub fn envelope_id(&self) -> &Id {
        &self.envelope_id
    }

    /// The events, in order.
    #[must_use]
    pub fn events(&self) -> &[ChainedEvent] {
        &self.events
    }

    /// Number of events.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// True before the first event.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// The hash of the last event: what the certificate prints and the seal protects.
    #[must_use]
    pub fn head(&self) -> Option<Hash256> {
        self.events.last().map(|e| e.hash)
    }

    /// The `seq` the next event must carry.
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        u64::try_from(self.events.len()).unwrap_or(u64::MAX)
    }

    /// The next event, with `v`, `envelope_id`, `seq` and `prev` filled in from the chain.
    #[must_use]
    pub fn next(
        &self,
        at: Timestamp,
        actor: Actor,
        context: Context,
        data: EventData,
    ) -> AuditEvent {
        AuditEvent {
            v: EVENT_VERSION,
            envelope_id: self.envelope_id.clone(),
            seq: self.next_seq(),
            prev: self.head(),
            at,
            actor,
            context,
            data,
        }
    }

    /// Append `event`, returning its hash.
    ///
    /// # Errors
    ///
    /// `CS-AUD-0004` another envelope, `CS-AUD-0005` not the next `seq`, `CS-AUD-0006`
    /// `prev` not the head, `CS-AUD-0007` time backwards beyond the tolerance,
    /// `CS-AUD-0002` the chain is full, `CS-AUD-0003` an event that cannot be written.
    pub fn append(&mut self, event: AuditEvent) -> Result<Hash256, AuditError> {
        if self.events.len() >= self.max_events {
            return Err(AuditError::Limit {
                limit: "events per chain",
                max: u64::try_from(self.max_events).unwrap_or(u64::MAX),
            });
        }
        if event.envelope_id != self.envelope_id {
            return Err(AuditError::WrongEnvelope { seq: event.seq });
        }
        let expected = self.next_seq();
        if event.seq != expected {
            return Err(AuditError::SeqNotNext {
                expected,
                found: event.seq,
            });
        }
        if event.prev != self.head() {
            return Err(AuditError::PrevNotHead { seq: event.seq });
        }
        if let Some(last) = self.events.last() {
            let back = last
                .event
                .at
                .unix_millis()
                .saturating_sub(event.at.unix_millis());
            if back > 0 && back.unsigned_abs() > self.tolerance_ms {
                return Err(AuditError::TimeBackwards {
                    seq: event.seq,
                    by_ms: back.unsigned_abs(),
                });
            }
        }
        let hash = event.hash()?;
        self.events.push(ChainedEvent { event, hash });
        Ok(hash)
    }

    /// The trail as a JSON tree: `{ format, v, envelope_id, head, events }`, each event
    /// carrying its `hash`.
    ///
    /// # Errors
    ///
    /// `CS-AUD-0003` for an event that cannot be written (not reachable through
    /// [`Chain::append`]).
    pub fn to_value(&self) -> Result<Value, AuditError> {
        let mut events = Vec::with_capacity(self.events.len());
        for e in &self.events {
            let mut v = e.event.to_value()?;
            if let Value::Object(members) = &mut v {
                members.push(("hash".into(), Value::String(e.hash.to_string())));
            }
            events.push(v);
        }
        // A small constant.
        let version = TRAIL_VERSION as f64;
        Ok(Value::Object(vec![
            ("format".into(), Value::String(TRAIL_FORMAT.into())),
            ("v".into(), Value::Number(version)),
            (
                "envelope_id".into(),
                Value::String(self.envelope_id.as_str().into()),
            ),
            (
                "head".into(),
                self.head()
                    .map_or(Value::Null, |h| Value::String(h.to_string())),
            ),
            ("events".into(), Value::Array(events)),
        ]))
    }

    /// The trail file: the canonical JSON (RFC 8785) of [`Chain::to_value`]. Same chain,
    /// same bytes.
    ///
    /// # Errors
    ///
    /// As [`Chain::to_value`].
    pub fn to_trail_json(&self) -> Result<Vec<u8>, AuditError> {
        jcs::to_vec(&self.to_value()?)
    }

    /// Read a trail file back into a chain, after verifying it.
    ///
    /// # Errors
    ///
    /// `CS-AUD-0008` with the report when verification fails; `CS-AUD-0003` when an
    /// event verifies but is of a type this build does not know.
    pub fn from_trail_json(
        bytes: &[u8],
        options: &VerifyOptions,
    ) -> Result<(Self, ChainReport), AuditError> {
        let report = verify_trail(bytes, options);
        if !report.is_valid() {
            return Err(AuditError::ChainInvalid {
                problems: report.problems.len(),
            });
        }
        let tree = crate::json::parse(bytes, options.limits.max_depth)?;
        let envelope_id = report
            .envelope_id
            .clone()
            .ok_or(AuditError::shape(ShapeFault::Id))?;
        let mut chain = Self::new(envelope_id).with_time_tolerance(options.time_tolerance_ms);
        chain.max_events = options.limits.max_events;
        let events = tree
            .get("events")
            .and_then(Value::as_array)
            .ok_or(AuditError::shape(ShapeFault::Member("events")))?;
        for (index, v) in events.iter().enumerate() {
            let e = AuditEvent::from_value(v).map_err(|e| match e {
                AuditError::Shape { fault, .. } => AuditError::Shape {
                    fault,
                    index: Some(index),
                },
                other => other,
            })?;
            chain.append(e)?;
        }
        if chain.head() != report.head {
            return Err(AuditError::ChainInvalid { problems: 1 });
        }
        Ok((chain, report))
    }
}

// Tests may unwrap, index and panic (CLAUDE.md).
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]
#[cfg(test)]
mod tests {
    use super::*;

    fn t(ms: i64) -> Timestamp {
        Timestamp::from_unix_millis(1_794_302_043_512 + ms).unwrap()
    }

    fn chain(n: usize) -> Chain {
        let mut c = Chain::new(Id::new("env-1").unwrap());
        for i in 0..n {
            let e = c.next(
                t(i64::try_from(i).unwrap() * 1000),
                Actor::system(),
                Context::default(),
                EventData::EnvelopeViewedBySender {},
            );
            c.append(e).unwrap();
        }
        c
    }

    #[test]
    fn append_links_and_the_head_moves() {
        let c = chain(3);
        assert_eq!(c.len(), 3);
        assert_eq!(c.events()[1].event.prev, Some(c.events()[0].hash));
        assert_eq!(c.head(), Some(c.events()[2].hash));
        assert_eq!(c.events()[0].hash, c.events()[0].event.hash().unwrap());
    }

    #[test]
    fn append_refuses_another_envelope() {
        let mut c = chain(2);
        let mut e = c.next(
            t(5000),
            Actor::system(),
            Context::default(),
            EventData::EnvelopeExpired {},
        );
        e.envelope_id = Id::new("env-2").unwrap();
        assert_eq!(c.append(e).unwrap_err().code(), "CS-AUD-0004");
    }

    #[test]
    fn append_refuses_a_seq_that_is_not_next() {
        let mut c = chain(2);
        for seq in [0, 1, 3, 100] {
            let mut e = c.next(
                t(5000),
                Actor::system(),
                Context::default(),
                EventData::EnvelopeExpired {},
            );
            e.seq = seq;
            assert_eq!(c.append(e).unwrap_err().code(), "CS-AUD-0005", "{seq}");
        }
    }

    #[test]
    fn append_refuses_a_prev_that_is_not_the_head() {
        let mut c = chain(2);
        let mut e = c.next(
            t(5000),
            Actor::system(),
            Context::default(),
            EventData::EnvelopeExpired {},
        );
        e.prev = Some(c.events()[0].hash);
        assert_eq!(c.append(e).unwrap_err().code(), "CS-AUD-0006");
    }

    #[test]
    fn append_refuses_time_going_backwards_beyond_tolerance() {
        let mut c = chain(2).with_time_tolerance(500);
        // Previous event at t(1000): 500 ms back is allowed, 501 is not.
        let e = c.next(
            t(499),
            Actor::system(),
            Context::default(),
            EventData::EnvelopeExpired {},
        );
        assert_eq!(c.append(e).unwrap_err().code(), "CS-AUD-0007");
        let e = c.next(
            t(500),
            Actor::system(),
            Context::default(),
            EventData::EnvelopeExpired {},
        );
        assert!(c.append(e).is_ok());
    }

    #[test]
    fn trail_round_trips_byte_for_byte() {
        let c = chain(5);
        let json = c.to_trail_json().unwrap();
        let (back, report) = Chain::from_trail_json(&json, &VerifyOptions::default()).unwrap();
        assert!(report.is_valid(), "{report:?}");
        assert_eq!(back, c);
        assert_eq!(back.to_trail_json().unwrap(), json);
        let text = String::from_utf8(json).unwrap();
        assert!(
            text.starts_with(r#"{"envelope_id":"env-1","events":[{"actor":{"kind":"system"}"#),
            "{text}"
        );
    }
}
