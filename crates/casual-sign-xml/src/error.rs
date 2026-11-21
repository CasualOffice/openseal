//! Errors, each with a stable docs/20 code. Messages carry codes, byte offsets and
//! counts, never document content.

use core::fmt;

/// Why a document could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum XmlError {
    /// The input is larger than [`crate::Limits::max_bytes`] (`CS-XML-0001`).
    TooLarge {
        /// Its size in bytes.
        bytes: usize,
        /// The limit.
        limit: usize,
    },
    /// Elements nest deeper than [`crate::Limits::max_depth`] (`CS-XML-0002`).
    TooDeep {
        /// Byte offset of the element that crossed the limit.
        offset: usize,
    },
    /// More nodes or elements than the limits, or more attributes on one element
    /// (`CS-XML-0003`).
    TooManyNodes {
        /// Byte offset where the limit was crossed.
        offset: usize,
    },
    /// Not well formed: syntax, unbalanced tags, a duplicate attribute, an undefined
    /// entity or prefix, an invalid character or character reference, or (strict) a
    /// processing instruction (`CS-XML-0004`).
    Malformed {
        /// Byte offset of the problem.
        offset: usize,
    },
    /// A document type or entity declaration: refused, so no external entity is ever
    /// resolved and no entity expands (`CS-XML-0005`).
    Dtd {
        /// Byte offset of the declaration.
        offset: usize,
    },
    /// Strict mode: the input is not UTF-8, or declares another encoding
    /// (`CS-XML-0006`).
    Encoding,
    /// The host's cancellation predicate returned true (`CS-XML-0007`).
    Cancelled,
}

impl XmlError {
    /// The stable docs/20 code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::TooLarge { .. } => "CS-XML-0001",
            Self::TooDeep { .. } => "CS-XML-0002",
            Self::TooManyNodes { .. } => "CS-XML-0003",
            Self::Malformed { .. } => "CS-XML-0004",
            Self::Dtd { .. } => "CS-XML-0005",
            Self::Encoding => "CS-XML-0006",
            Self::Cancelled => "CS-XML-0007",
        }
    }
}

impl fmt::Display for XmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            Self::TooLarge { bytes, limit } => {
                write!(f, "{code}: XML of {bytes} bytes exceeds {limit}")
            }
            Self::TooDeep { offset } => write!(f, "{code}: XML nesting too deep at byte {offset}"),
            Self::TooManyNodes { offset } => {
                write!(
                    f,
                    "{code}: too many XML nodes or attributes at byte {offset}"
                )
            }
            Self::Malformed { offset } => write!(f, "{code}: malformed XML at byte {offset}"),
            Self::Dtd { offset } => {
                write!(
                    f,
                    "{code}: document type or entity declaration at byte {offset}"
                )
            }
            Self::Encoding => write!(f, "{code}: not UTF-8"),
            Self::Cancelled => write!(f, "{code}: cancelled"),
        }
    }
}

impl std::error::Error for XmlError {}
