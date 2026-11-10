//! Chain verification (docs/32 §4): anyone with the audit JSON recomputes every hash and
//! checks the `prev` links, `seq` density, the envelope and the order of times.
//!
//! Hashes are recomputed over the events **as received** (canonicalized, without their
//! `hash` member), never over a typed re-encoding, so a member this build does not know
//! still counts. Each event's `prev` is checked against the *recomputed* hash of the
//! event before it, so editing an event and its stored hash together is still caught by
//! the next link.
//!
//! What the chain alone cannot show: that events were cut from its end, or that the whole
//! chain was rewritten. Both are caught against a head known from elsewhere: the head the
//! certificate prints and the seal protects ([`VerifyOptions::expected_head`]).
//!
//! Verification never stops at the first problem: the report lists every problem found,
//! up to [`MAX_PROBLEMS`], with the event's index.

use casual_sign_model::Id;

use crate::chain::{TRAIL_FORMAT, TRAIL_VERSION};
use crate::error::{AuditError, ShapeFault};
use crate::event::{AuditEvent, EVENT_VERSION, EventData};
use crate::hash::Hash256;
use crate::jcs;
use crate::json::{self, Value};
use crate::time::Timestamp;
use crate::{AuditLimits, DEFAULT_TIME_TOLERANCE_MS};

/// Most problems a report lists; further ones are counted in
/// [`ChainReport::problems_dropped`].
pub const MAX_PROBLEMS: usize = 1_000;

/// What verification checks against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyOptions {
    /// The envelope the chain must belong to; when `None`, the first event's.
    pub envelope_id: Option<Id>,
    /// The head known from elsewhere (the certificate, the seal, an anchor): catches a
    /// chain cut short or rewritten whole.
    pub expected_head: Option<Hash256>,
    /// The number of events known from elsewhere.
    pub expected_count: Option<u64>,
    /// How far an event's time may be before the previous event's, in milliseconds.
    pub time_tolerance_ms: u64,
    /// Input bounds.
    pub limits: AuditLimits,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            envelope_id: None,
            expected_head: None,
            expected_count: None,
            time_tolerance_ms: DEFAULT_TIME_TOLERANCE_MS,
            limits: AuditLimits::default(),
        }
    }
}

/// Where a head to compare with came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HeadSource {
    /// The trail file's own `head` member.
    Declared,
    /// [`VerifyOptions::expected_head`].
    Expected,
}

/// One thing wrong with a chain.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProblemKind {
    /// The input is not a trail at all (unparseable JSON, a limit crossed, no `events`):
    /// the code says which.
    Unreadable(&'static str),
    /// The trail's `format`, `v` or `envelope_id` member is wrong or missing.
    TrailShape(ShapeFault),
    /// The trail holds no events.
    Empty,
    /// An event lacks a member the chain needs, or has one malformed.
    Malformed(ShapeFault),
    /// The event's stored `hash` is not the hash of its content: the event was edited.
    HashMismatch,
    /// `prev` is not the hash of the event before: an event was removed, inserted or
    /// moved, or the one before was edited.
    PrevMismatch,
    /// The first event is not `seq` 0 with `prev` `null`: events were cut from the start
    /// or one was inserted before it.
    NotGenesis,
    /// `seq` skips numbers: events were removed or moved.
    SeqGap {
        /// The number expected.
        expected: u64,
        /// The number found.
        found: u64,
    },
    /// `seq` repeats the previous event's.
    SeqDuplicate {
        /// The repeated number.
        seq: u64,
    },
    /// `seq` is lower than the previous event's: events were reordered.
    SeqBackwards {
        /// The number expected.
        expected: u64,
        /// The number found.
        found: u64,
    },
    /// The event names another envelope.
    WrongEnvelope,
    /// The event's time is earlier than the previous event's by more than the tolerance.
    TimeBackwards {
        /// How far back, in milliseconds.
        by_ms: u64,
    },
    /// The event's schema version is not one this build reads.
    UnsupportedVersion,
    /// The last event's hash is not the head given.
    HeadMismatch(HeadSource),
    /// The number of events is not the one given.
    CountMismatch {
        /// The number given.
        expected: u64,
        /// The number found.
        found: u64,
    },
}

/// A problem, and the index of the event it concerns (`None` for the trail as a whole).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Problem {
    /// The event's position in the trail, from 0.
    pub index: Option<usize>,
    /// What is wrong.
    pub kind: ProblemKind,
}

/// The outcome of verifying a chain. Positions, hashes and counts only: no event
/// content, so the report can be logged.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ChainReport {
    /// Events read.
    pub events: usize,
    /// The envelope, from the options or the first event.
    pub envelope_id: Option<Id>,
    /// The recomputed hash of the last event.
    pub head: Option<Hash256>,
    /// Every problem found, in order.
    pub problems: Vec<Problem>,
    /// Problems beyond [`MAX_PROBLEMS`], counted only.
    pub problems_dropped: u64,
    /// Indexes of events whose `type` this build does not know. Their hashes and links
    /// were checked as for any event; only their data could not be read.
    pub unrecognised: Vec<usize>,
}

impl ChainReport {
    /// True when the chain verified: at least one event and no problem.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.events > 0 && self.problems.is_empty() && self.problems_dropped == 0
    }

    /// True when some problem is of a kind `pred` accepts.
    pub fn has(&self, pred: impl Fn(&ProblemKind) -> bool) -> bool {
        self.problems.iter().any(|p| pred(&p.kind))
    }

    /// `Ok(())` when valid, else `CS-AUD-0008`.
    ///
    /// # Errors
    ///
    /// `CS-AUD-0008` with the number of problems.
    pub fn into_result(self) -> Result<Self, AuditError> {
        if self.is_valid() {
            Ok(self)
        } else {
            let n = self
                .problems
                .len()
                .saturating_add(usize::try_from(self.problems_dropped).unwrap_or(usize::MAX));
            Err(AuditError::ChainInvalid { problems: n.max(1) })
        }
    }

    fn push(&mut self, index: Option<usize>, kind: ProblemKind) {
        if self.problems.len() >= MAX_PROBLEMS {
            self.problems_dropped = self.problems_dropped.saturating_add(1);
        } else {
            self.problems.push(Problem { index, kind });
        }
    }
}

/// Verify a trail file (`audit-trail.json`): `{ format, v, envelope_id, head, events }`.
#[must_use]
pub fn verify_trail(bytes: &[u8], options: &VerifyOptions) -> ChainReport {
    let mut report = ChainReport::default();
    if bytes.len() > options.limits.max_trail_bytes {
        report.push(None, ProblemKind::Unreadable("CS-AUD-0002"));
        return report;
    }
    let tree = match json::parse(bytes, options.limits.max_depth) {
        Ok(t) => t,
        Err(e) => {
            report.push(None, ProblemKind::Unreadable(e.code()));
            return report;
        }
    };
    let Some(events) = tree.get("events").and_then(Value::as_array) else {
        report.push(None, ProblemKind::Unreadable("CS-AUD-0003"));
        return report;
    };
    if tree.get("format").and_then(Value::as_str) != Some(TRAIL_FORMAT) {
        report.push(None, ProblemKind::TrailShape(ShapeFault::Format));
    }
    if tree.get("v").and_then(Value::as_safe_u64) != Some(TRAIL_VERSION) {
        report.push(None, ProblemKind::TrailShape(ShapeFault::Version));
    }
    let trail_envelope = tree
        .get("envelope_id")
        .and_then(Value::as_str)
        .and_then(|s| Id::new(s).ok());
    if trail_envelope.is_none() {
        report.push(None, ProblemKind::TrailShape(ShapeFault::Id));
    }
    let declared_head = match tree.get("head") {
        Some(Value::Null) => None,
        Some(Value::String(s)) => match Hash256::parse(s) {
            Ok(h) => Some(h),
            Err(_) => {
                report.push(None, ProblemKind::TrailShape(ShapeFault::Hash));
                None
            }
        },
        _ => {
            report.push(None, ProblemKind::TrailShape(ShapeFault::Member("head")));
            None
        }
    };
    // The trail's own envelope id is what its events must name, unless the caller says.
    let mut opts = options.clone();
    if opts.envelope_id.is_none() {
        opts.envelope_id.clone_from(&trail_envelope);
    } else if trail_envelope.is_some() && trail_envelope != opts.envelope_id {
        report.push(None, ProblemKind::WrongEnvelope);
    }
    check_events(events, &opts, &mut report);
    if report.head != declared_head {
        report.push(None, ProblemKind::HeadMismatch(HeadSource::Declared));
    }
    report
}

/// Verify a chain given as its events' JSON trees, each carrying its `hash`.
#[must_use]
pub fn verify_chain(events: &[Value], options: &VerifyOptions) -> ChainReport {
    let mut report = ChainReport::default();
    check_events(events, options, &mut report);
    report
}

/// What the previous event left for the next to be checked against.
struct Previous {
    hash: Hash256,
    seq: Option<u64>,
    at: Option<Timestamp>,
}

fn check_events(events: &[Value], options: &VerifyOptions, report: &mut ChainReport) {
    if events.len() > options.limits.max_events {
        report.push(None, ProblemKind::Unreadable("CS-AUD-0002"));
        return;
    }
    report.events = events.len();
    report.envelope_id.clone_from(&options.envelope_id);
    if events.is_empty() {
        report.push(None, ProblemKind::Empty);
    }
    let mut previous: Option<Previous> = None;
    for (index, event) in events.iter().enumerate() {
        let at_index = Some(index);
        let Value::Object(_) = event else {
            report.push(
                at_index,
                ProblemKind::Malformed(ShapeFault::Member("event")),
            );
            // The chain cannot be followed past an event with no hash.
            previous = None;
            continue;
        };

        // Content: the stored hash against the recomputed one.
        let recomputed = match jcs::to_vec(&event.without("hash")) {
            Ok(bytes) => Hash256::digest(&bytes),
            Err(e) => {
                report.push(at_index, ProblemKind::Unreadable(e.code()));
                previous = None;
                continue;
            }
        };
        match event
            .get("hash")
            .and_then(Value::as_str)
            .map(Hash256::parse)
        {
            Some(Ok(stored)) if stored == recomputed => {}
            Some(Ok(_)) => report.push(at_index, ProblemKind::HashMismatch),
            _ => report.push(at_index, ProblemKind::Malformed(ShapeFault::Hash)),
        }

        // Version.
        if event.get("v").and_then(Value::as_safe_u64) != Some(EVENT_VERSION) {
            report.push(at_index, ProblemKind::UnsupportedVersion);
        }

        // Envelope.
        match event
            .get("envelope_id")
            .and_then(Value::as_str)
            .and_then(|s| Id::new(s).ok())
        {
            Some(id) => match &report.envelope_id {
                Some(want) if *want != id => report.push(at_index, ProblemKind::WrongEnvelope),
                Some(_) => {}
                None => report.envelope_id = Some(id),
            },
            None => report.push(at_index, ProblemKind::Malformed(ShapeFault::Id)),
        }

        // Sequence.
        let seq = event.get("seq").and_then(Value::as_safe_u64);
        if seq.is_none() {
            report.push(at_index, ProblemKind::Malformed(ShapeFault::Seq));
        }

        // Link.
        let prev = match event.get("prev") {
            Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Hash256::parse(s).map(Some),
            _ => Err(AuditError::shape(ShapeFault::Prev)),
        };
        let prev = match prev {
            Ok(p) => Some(p),
            Err(_) => {
                report.push(at_index, ProblemKind::Malformed(ShapeFault::Prev));
                None
            }
        };

        // Time.
        let at = match event
            .get("at")
            .and_then(Value::as_str)
            .map(Timestamp::parse)
        {
            Some(Ok(t)) => Some(t),
            _ => {
                report.push(at_index, ProblemKind::Malformed(ShapeFault::Timestamp));
                None
            }
        };

        if index == 0 {
            if seq != Some(0) || prev != Some(None) {
                report.push(at_index, ProblemKind::NotGenesis);
            }
        } else {
            match (&previous, prev) {
                (Some(p), Some(Some(link))) if link == p.hash => {}
                (_, Some(_)) => report.push(at_index, ProblemKind::PrevMismatch),
                (_, None) => {}
            }
            if let (
                Some(Previous {
                    seq: Some(last), ..
                }),
                Some(s),
            ) = (&previous, seq)
            {
                let expected = last.saturating_add(1);
                if s == *last {
                    report.push(at_index, ProblemKind::SeqDuplicate { seq: s });
                } else if s < *last {
                    report.push(at_index, ProblemKind::SeqBackwards { expected, found: s });
                } else if s != expected {
                    report.push(at_index, ProblemKind::SeqGap { expected, found: s });
                }
            }
            if let (Some(Previous { at: Some(last), .. }), Some(now)) = (&previous, at) {
                let back = last.unix_millis().saturating_sub(now.unix_millis());
                if back > 0 && back.unsigned_abs() > options.time_tolerance_ms {
                    report.push(
                        at_index,
                        ProblemKind::TimeBackwards {
                            by_ms: back.unsigned_abs(),
                        },
                    );
                }
            }
        }

        // Data: a known type must decode; an unknown one is noted, not failed.
        let known = event
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|t| EventData::TYPES.contains(&t));
        if !known {
            report.unrecognised.push(index);
        } else if let Err(AuditError::Shape { fault, .. }) = AuditEvent::from_value(event) {
            // Members already reported above are not reported twice.
            if matches!(
                fault,
                ShapeFault::Data | ShapeFault::Member("actor" | "context" | "type" | "data")
            ) {
                report.push(at_index, ProblemKind::Malformed(fault));
            }
        }

        previous = Some(Previous {
            hash: recomputed,
            seq,
            at,
        });
    }
    report.head = previous.map(|p| p.hash);
    if let Some(want) = options.expected_head
        && report.head != Some(want)
    {
        report.push(None, ProblemKind::HeadMismatch(HeadSource::Expected));
    }
    if let Some(want) = options.expected_count {
        let found = u64::try_from(events.len()).unwrap_or(u64::MAX);
        if found != want {
            report.push(
                None,
                ProblemKind::CountMismatch {
                    expected: want,
                    found,
                },
            );
        }
    }
}
