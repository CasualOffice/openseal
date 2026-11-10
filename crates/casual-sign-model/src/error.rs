//! The one error type of this crate.

use core::fmt;

/// Why a value could not be built. Each variant maps to one stable code in docs/20.
///
/// Messages carry counts and limits only, never the offending value (`SEC-D01`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ModelError {
    /// A text value, option or message is longer than its limit (`CS-FLD-0002`).
    TextTooLong {
        /// Bytes supplied.
        bytes: usize,
        /// Bytes allowed.
        limit: usize,
    },
    /// Too many options on a dropdown or radio group (`CS-FLD-0002`).
    TooManyOptions {
        /// Options supplied.
        count: usize,
        /// Options allowed.
        limit: usize,
    },
    /// Two options carry the same value (`CS-FLD-0002`).
    DuplicateOption {
        /// Zero-based position of the second occurrence.
        index: usize,
    },
    /// A data label is empty, too long or holds a control character (`CS-FLD-0002`).
    InvalidLabel {
        /// Bytes supplied.
        bytes: usize,
    },
    /// An id is empty, too long or holds a character outside `[A-Za-z0-9_-]` (`CS-FLD-0005`).
    InvalidId {
        /// Bytes supplied.
        bytes: usize,
    },
    /// A formula expression is longer than its limit (`CS-FLD-0021`).
    FormulaTooLong {
        /// Characters supplied, counted up to one past the limit.
        chars: usize,
        /// Characters allowed.
        limit: usize,
    },
    /// A precision or decimal count is over 15 (`CS-FLD-0021`).
    PrecisionOutOfRange {
        /// Precision supplied.
        precision: u8,
    },
    /// A field's page or rectangle is outside what a page can hold (`CS-FLD-0004`).
    PlacementOutOfRange,
    /// A rule's lower bound is above its upper bound (`CS-FLD-0002` for validation rules).
    RuleBoundsInverted,
    /// A group rule's bounds are inverted or zero where one is needed (`CS-FLD-0003`).
    InvalidGroupRule,
    /// A currency code is not three upper-case ASCII letters (`CS-FLD-0002`).
    InvalidCurrency,
    /// A colour is not `#rrggbb` (`CS-FLD-0002`).
    InvalidColor,
    /// A routing order is 0 or over 999 (`CS-WF-0004`).
    RoutingOrderOutOfRange {
        /// The order supplied.
        order: u32,
    },
    /// A reminder step is over 999 days (`CS-WF-0004`).
    ReminderOutOfRange,
}

impl ModelError {
    /// The stable code from docs/20.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::TextTooLong { .. }
            | Self::TooManyOptions { .. }
            | Self::DuplicateOption { .. }
            | Self::InvalidLabel { .. }
            | Self::RuleBoundsInverted
            | Self::InvalidCurrency
            | Self::InvalidColor => "CS-FLD-0002",
            Self::InvalidGroupRule => "CS-FLD-0003",
            Self::PlacementOutOfRange => "CS-FLD-0004",
            Self::InvalidId { .. } => "CS-FLD-0005",
            Self::FormulaTooLong { .. } | Self::PrecisionOutOfRange { .. } => "CS-FLD-0021",
            Self::RoutingOrderOutOfRange { .. } | Self::ReminderOutOfRange => "CS-WF-0004",
        }
    }
}

impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            Self::TextTooLong { bytes, limit } => {
                write!(f, "{code}: text of {bytes} bytes over limit {limit}")
            }
            Self::TooManyOptions { count, limit } => {
                write!(f, "{code}: {count} options over limit {limit}")
            }
            Self::DuplicateOption { index } => {
                write!(f, "{code}: option {index} repeats an earlier option")
            }
            Self::InvalidLabel { bytes } => {
                write!(f, "{code}: data label of {bytes} bytes is not valid")
            }
            Self::InvalidId { bytes } => write!(f, "{code}: id of {bytes} bytes is not valid"),
            Self::FormulaTooLong { chars, limit } => {
                write!(
                    f,
                    "{code}: formula of at least {chars} characters over limit {limit}"
                )
            }
            Self::PrecisionOutOfRange { precision } => {
                write!(f, "{code}: precision {precision} over 15")
            }
            Self::PlacementOutOfRange => {
                write!(f, "{code}: field placement outside the page bounds")
            }
            Self::RuleBoundsInverted => write!(f, "{code}: rule minimum above its maximum"),
            Self::InvalidGroupRule => write!(f, "{code}: group rule bounds are not valid"),
            Self::InvalidCurrency => write!(f, "{code}: currency is not an ISO 4217 code"),
            Self::InvalidColor => write!(f, "{code}: colour is not #rrggbb"),
            Self::RoutingOrderOutOfRange { order } => {
                write!(f, "{code}: routing order {order} outside 1 to 999")
            }
            Self::ReminderOutOfRange => write!(f, "{code}: reminder step over 999 days"),
        }
    }
}

impl std::error::Error for ModelError {}
