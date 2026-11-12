//! Typed errors with the stable codes of docs/20.

use core::fmt;

/// Why a text was refused. `code()` gives the docs/20 code.
///
/// Errors carry sizes and limits only, never any of the text scanned (`SEC-D01`): the
/// text is a document's content and may itself be the personal data being looked for.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PiiError {
    /// The text is larger than [`crate::Options::max_text_bytes`] (`CS-PII-0001`).
    TextTooLarge {
        /// Bytes supplied.
        bytes: usize,
        /// The limit in force.
        limit: usize,
    },
}

impl PiiError {
    /// The stable docs/20 code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::TextTooLarge { .. } => "CS-PII-0001",
        }
    }
}

impl fmt::Display for PiiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TextTooLarge { bytes, limit } => write!(
                f,
                "{}: text of {bytes} bytes is over the {limit}-byte limit for personal-data detection",
                self.code()
            ),
        }
    }
}

impl std::error::Error for PiiError {}
