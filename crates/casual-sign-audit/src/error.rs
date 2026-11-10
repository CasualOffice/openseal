//! Typed errors with stable codes (docs/20 `CS-AUD-*`). Messages carry positions, counts
//! and sequence numbers only: never an event's content, a name or an address (SEC-D01).

use core::fmt;

/// Why JSON text was refused (`CS-AUD-0001`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum JsonFault {
    /// Not UTF-8, or a byte where none is allowed.
    Syntax,
    /// An object names the same member twice (RFC 8785 §3.1 requires unique names).
    DuplicateKey,
    /// A `\u` escape is a lone surrogate (I-JSON, RFC 7493 §2.1).
    LoneSurrogate,
    /// A number is too large for an IEEE 754 double (I-JSON, RFC 7493 §2.2).
    NumberOutOfRange,
    /// A value is not a finite number and cannot be written (RFC 8785 §3.2.2.3).
    NonFinite,
    /// Bytes follow the value.
    TrailingData,
}

/// What an event or trail lacked or got wrong (`CS-AUD-0003`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ShapeFault {
    /// A required member is absent or of the wrong JSON type; the member is named.
    Member(&'static str),
    /// `v` is not a version this build reads.
    Version,
    /// `at` is not `YYYY-MM-DDTHH:MM:SS.mmmZ` naming a real instant.
    Timestamp,
    /// A hash is not `sha256:` followed by 64 lower-case hex digits.
    Hash,
    /// An id is not 1 to 64 bytes of `[A-Za-z0-9_-]`.
    Id,
    /// `seq` is not an integer from 0 to 2^53 − 1.
    Seq,
    /// `prev` is `null` on an event after the first, or set on the first.
    Prev,
    /// `type` and `data` do not form an event type of docs/32 §3.
    Data,
    /// The trail's `format` is not `openseal.audit-trail`.
    Format,
}

/// What was wrong with a location (`CS-AUD-0011`, GEO-01). Names the member only, never
/// its value: a location is personal data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LocationFault {
    /// `source` is unknown, a member has the wrong JSON type, or the members do not match
    /// the source (a device location with a reason or no accuracy, an IP location with an
    /// accuracy or no reason).
    Source,
    /// Latitude not finite or outside −90 to 90.
    Latitude,
    /// Longitude not finite or outside −180 to 180.
    Longitude,
    /// Only one coordinate, or a device location without coordinates.
    Coordinates,
    /// A device coordinate with more than 4 decimal places.
    Precision,
    /// Device accuracy negative, not finite or over its bound.
    Accuracy,
    /// The GeoIP database name is empty, too long or has a control character, or an IP
    /// location gives coordinates or a place without naming its database.
    Database,
    /// The country is not two upper-case ASCII letters.
    Country,
    /// The region is empty, too long or has a control character.
    Region,
    /// The city is empty, too long or has a control character.
    City,
}

/// Every audit error. [`AuditError::code`] gives the docs/20 code.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditError {
    /// JSON text was malformed at `offset` (`CS-AUD-0001`).
    Json {
        /// What was wrong.
        fault: JsonFault,
        /// Byte offset in the input.
        offset: usize,
    },
    /// A bound of [`crate::AuditLimits`] was crossed (`CS-AUD-0002`).
    Limit {
        /// Which bound.
        limit: &'static str,
        /// Its value.
        max: u64,
    },
    /// An event or trail has the wrong shape (`CS-AUD-0003`).
    Shape {
        /// What was wrong.
        fault: ShapeFault,
        /// The event's index in its trail, when there is one.
        index: Option<usize>,
    },
    /// Append refused: the event names another envelope (`CS-AUD-0004`).
    WrongEnvelope {
        /// The event's sequence number.
        seq: u64,
    },
    /// Append refused: `seq` is not the next number (`CS-AUD-0005`).
    SeqNotNext {
        /// The number the chain expects.
        expected: u64,
        /// The number given.
        found: u64,
    },
    /// Append refused: `prev` is not the chain head (`CS-AUD-0006`).
    PrevNotHead {
        /// The event's sequence number.
        seq: u64,
    },
    /// Append refused: `at` is earlier than the previous event by more than the
    /// tolerance (`CS-AUD-0007`).
    TimeBackwards {
        /// The event's sequence number.
        seq: u64,
        /// How far back, in milliseconds.
        by_ms: u64,
    },
    /// A chain failed verification; the report lists why (`CS-AUD-0008`).
    ChainInvalid {
        /// Problems found.
        problems: usize,
    },
    /// A Merkle inclusion proof does not lead to the root, or names a leaf outside the
    /// tree (`CS-AUD-0009`).
    ProofInvalid,
    /// A tombstone cannot be made, or does not match the chain it names (`CS-AUD-0010`).
    Tombstone,
    /// A signer's location is invalid or over its bounds (`CS-AUD-0011`, GEO-01).
    Location {
        /// What was wrong.
        fault: LocationFault,
    },
}

impl AuditError {
    /// The stable code (docs/20).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Json { .. } => "CS-AUD-0001",
            Self::Limit { .. } => "CS-AUD-0002",
            Self::Shape { .. } => "CS-AUD-0003",
            Self::WrongEnvelope { .. } => "CS-AUD-0004",
            Self::SeqNotNext { .. } => "CS-AUD-0005",
            Self::PrevNotHead { .. } => "CS-AUD-0006",
            Self::TimeBackwards { .. } => "CS-AUD-0007",
            Self::ChainInvalid { .. } => "CS-AUD-0008",
            Self::ProofInvalid => "CS-AUD-0009",
            Self::Tombstone => "CS-AUD-0010",
            Self::Location { .. } => "CS-AUD-0011",
        }
    }

    pub(crate) fn shape(fault: ShapeFault) -> Self {
        Self::Shape { fault, index: None }
    }

    pub(crate) fn location(fault: LocationFault) -> Self {
        Self::Location { fault }
    }
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            Self::Json { fault, offset } => {
                write!(f, "{code}: malformed JSON ({fault:?}) at byte {offset}")
            }
            Self::Limit { limit, max } => write!(f, "{code}: {limit} over its limit of {max}"),
            Self::Shape { fault, index } => match index {
                Some(i) => write!(f, "{code}: event {i} has the wrong shape ({fault:?})"),
                None => write!(f, "{code}: wrong shape ({fault:?})"),
            },
            Self::WrongEnvelope { seq } => {
                write!(f, "{code}: event {seq} names another envelope")
            }
            Self::SeqNotNext { expected, found } => {
                write!(f, "{code}: seq {found} given where {expected} is next")
            }
            Self::PrevNotHead { seq } => write!(f, "{code}: event {seq} does not link to the head"),
            Self::TimeBackwards { seq, by_ms } => {
                write!(
                    f,
                    "{code}: event {seq} is {by_ms} ms before the previous one"
                )
            }
            Self::ChainInvalid { problems } => {
                write!(
                    f,
                    "{code}: chain failed verification with {problems} problems"
                )
            }
            Self::ProofInvalid => write!(f, "{code}: inclusion proof does not verify"),
            Self::Tombstone => write!(f, "{code}: tombstone does not match its chain"),
            Self::Location { fault } => write!(f, "{code}: invalid location ({fault:?})"),
        }
    }
}

impl std::error::Error for AuditError {}
