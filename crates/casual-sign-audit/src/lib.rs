//! OpenSeal audit events: canonical form, hash chain and chain verification (docs/32,
//! ADR-010, stage 1I `T-1I`).
//!
//! - [`AuditEvent`]: `{ v, envelope_id, seq, prev, at, type, actor, context, data }`
//!   with every event type of docs/32 §3 as a variant of [`EventData`]. Personal data is
//!   wrapped in [`Personal`] and listed in [`PERSONAL_MEMBERS`].
//! - [`jcs`]: RFC 8785 canonical JSON over this crate's own strict, bounded [`json`]
//!   parser. An event's hash is `SHA-256(JCS(event without hash))`.
//! - [`Chain`]: append-only; [`Chain::append`] enforces envelope, dense `seq`, `prev` =
//!   head and time order. [`Chain::to_trail_json`] writes `audit-trail.json`.
//! - [`verify_trail`] and [`verify_chain`]: recompute every hash and report every
//!   deletion, insertion, reordering, edit, duplicate, foreign event and backwards time
//!   as a [`Problem`] in a [`ChainReport`].
//! - [`merkle`]: RFC 6962 tree hashing over chain heads for anchoring (docs/32 §5), with
//!   inclusion proofs and their verifier.
//! - [`Tombstone`]: what a purge keeps (docs/32 §7).
//! - [`Location`]: where a signer was when they acted, from the device or approximated
//!   from the IP address, in `context.location` (GEO-01, personal data).
//!
//! The crate performs no I/O, reads no clock and draws no randomness (times are
//! supplied), and builds for `wasm32-unknown-unknown`. Every error is an [`AuditError`]
//! whose [`AuditError::code`] is a `CS-AUD-*` code; messages and reports carry indexes,
//! counts and hashes, never event content.

mod chain;
mod error;
mod event;
mod hash;
pub mod jcs;
pub mod json;
mod location;
pub mod merkle;
mod time;
mod tombstone;
mod verify;

pub use chain::{Chain, ChainedEvent, TRAIL_FILE_NAME, TRAIL_FORMAT, TRAIL_VERSION};
pub use error::{AuditError, JsonFault, LocationFault, ShapeFault};
pub use event::{
    Actor, ActorKind, AdoptionMethod, AuditEvent, AuthMethod, Channel, Context, DocumentHash,
    EVENT_VERSION, EventData, MarkKind, PERSONAL_MEMBERS, Personal, SignInIdentity,
};
pub use hash::Hash256;
pub use location::{
    Coordinates, FallbackReason, Location, LocationSource, MAX_ACCURACY_M, MAX_DATABASE_BYTES,
    MAX_PLACE_BYTES,
};
pub use time::{Civil, Timestamp};
pub use tombstone::Tombstone;
pub use verify::{
    ChainReport, HeadSource, MAX_PROBLEMS, Problem, ProblemKind, VerifyOptions, verify_chain,
    verify_trail,
};

/// How far an event's time may be before the previous event's by default, in
/// milliseconds: servers' clocks are NTP-disciplined but not identical (docs/32 §2). A
/// decision of `T-1I`.
pub const DEFAULT_TIME_TOLERANCE_MS: u64 = 1_000;

/// Bounds on audit JSON read from outside (`CS-AUD-0002`). Decisions of `T-1I`; docs/21
/// records them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditLimits {
    /// Most bytes in a trail file.
    pub max_trail_bytes: usize,
    /// Most events in one chain.
    pub max_events: usize,
    /// Most nesting levels of arrays and objects.
    pub max_depth: usize,
}

impl Default for AuditLimits {
    fn default() -> Self {
        Self {
            max_trail_bytes: 64 * 1024 * 1024,
            max_events: 100_000,
            max_depth: 32,
        }
    }
}
