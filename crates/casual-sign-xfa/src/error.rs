//! Errors, each with a stable docs/20 code. Messages carry codes, byte offsets and
//! counts, never document content.

use std::fmt;

/// Why an XFA form could not be laid out.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum XfaError {
    /// The XFA packets together are larger than [`crate::XfaLimits::max_xml_bytes`]
    /// (`CS-XFA-0001`).
    TooLarge {
        /// Their size in bytes.
        bytes: u64,
        /// The limit.
        limit: u64,
    },
    /// XML elements nest deeper than [`crate::XfaLimits::max_depth`] (`CS-XFA-0002`).
    TooDeep {
        /// Byte offset of the element that crossed the limit.
        offset: usize,
    },
    /// More XML nodes than [`crate::XfaLimits::max_nodes`], or more attributes on one
    /// element than [`crate::XfaLimits::max_attributes`] (`CS-XFA-0003`).
    TooManyNodes {
        /// Byte offset where the limit was crossed.
        offset: usize,
    },
    /// The XML is not well formed: syntax, unbalanced tags, a duplicate attribute, an
    /// undefined entity or an invalid character reference (`CS-XFA-0004`).
    Malformed {
        /// Byte offset of the problem.
        offset: usize,
    },
    /// A document type declaration or entity declaration: refused, so no external
    /// entity is ever resolved and no entity expands (`CS-XFA-0005`).
    Dtd {
        /// Byte offset of the declaration.
        offset: usize,
    },
    /// No `template` packet with a root subform (`CS-XFA-0006`).
    NoTemplate,
    /// Merging and laying out made more form nodes or layout items than
    /// [`crate::XfaLimits::max_form_nodes`] (`CS-XFA-0007`).
    TooManyItems {
        /// The limit.
        limit: usize,
    },
    /// Layout made more pages than [`crate::XfaLimits::max_pages`] (`CS-XFA-0008`).
    TooManyPages {
        /// The limit.
        limit: usize,
    },
    /// The host's cancellation predicate returned true (`CS-XFA-0009`).
    Cancelled,
    /// No usable face was supplied to draw text with (`CS-XFA-0010`).
    NoFont,
}

impl XfaError {
    /// The stable docs/20 code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::TooLarge { .. } => "CS-XFA-0001",
            Self::TooDeep { .. } => "CS-XFA-0002",
            Self::TooManyNodes { .. } => "CS-XFA-0003",
            Self::Malformed { .. } => "CS-XFA-0004",
            Self::Dtd { .. } => "CS-XFA-0005",
            Self::NoTemplate => "CS-XFA-0006",
            Self::TooManyItems { .. } => "CS-XFA-0007",
            Self::TooManyPages { .. } => "CS-XFA-0008",
            Self::Cancelled => "CS-XFA-0009",
            Self::NoFont => "CS-XFA-0010",
        }
    }
}

impl fmt::Display for XfaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            Self::TooLarge { bytes, limit } => {
                write!(f, "{code}: XFA packets of {bytes} bytes exceed {limit}")
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
            Self::NoTemplate => write!(f, "{code}: no XFA template with a root subform"),
            Self::TooManyItems { limit } => {
                write!(f, "{code}: more than {limit} form nodes or layout items")
            }
            Self::TooManyPages { limit } => write!(f, "{code}: more than {limit} pages"),
            Self::Cancelled => write!(f, "{code}: cancelled"),
            Self::NoFont => write!(f, "{code}: no usable face supplied"),
        }
    }
}

impl std::error::Error for XfaError {}
