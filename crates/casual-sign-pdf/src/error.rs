//! Typed errors with stable codes from docs/20.
//!
//! Every variant carries offsets, object numbers, counts and limits only: never
//! document text (docs/20, `SEC-D01`).

use core::fmt;

/// Why a PDF was refused. [`PdfError::code`] gives the stable `CS-PDF-*` code.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PdfError {
    /// The input is larger than `Limits::max_input_bytes` (`CS-PDF-0001`).
    TooLarge {
        /// Input size in bytes.
        size: u64,
        /// The limit in force.
        limit: u64,
    },
    /// More distinct objects, or more entries in one xref section, than
    /// `Limits::max_objects` (`CS-PDF-0002`).
    TooManyObjects {
        /// The limit in force.
        limit: u32,
    },
    /// One object holds more values than `Limits::max_object_values`
    /// (`CS-PDF-0002`).
    TooManyValues {
        /// Byte offset of the value that crossed the limit.
        offset: u64,
    },
    /// A `/Size` above 8,388,607 was declared; under strict reading this is refused
    /// (`CS-PDF-0002`).
    XrefSizeAbsurd {
        /// Byte offset of the xref section declaring it.
        offset: u64,
    },
    /// One stream decoded past `Limits::max_stream_bytes` (`CS-PDF-0003`).
    StreamTooLarge {
        /// The stream's object number.
        object: u32,
        /// The cap in force.
        limit: u64,
    },
    /// One stream decoded past its ratio allowance (`CS-PDF-0003`).
    DecodeRatio {
        /// The stream's object number.
        object: u32,
        /// Encoded length of the stream in bytes.
        encoded: u64,
    },
    /// The document's total decode budget is spent (`CS-PDF-0003`).
    DecodeBudget {
        /// The stream being decoded when the budget ran out.
        object: u32,
        /// The budget in force.
        limit: u64,
    },
    /// Arrays and dictionaries nested deeper than `Limits::max_depth` (`CS-PDF-0004`).
    TooDeep {
        /// Byte offset of the opening bracket that crossed the limit.
        offset: u64,
    },
    /// A chain of references longer than `Limits::max_ref_depth` (`CS-PDF-0004`).
    ReferenceTooDeep {
        /// The object whose value started the chain.
        object: u32,
    },
    /// An object needed itself to be read, such as an object stream inside itself or
    /// a `/Length` pointing at its own stream (`CS-PDF-0004`).
    ReferenceCycle {
        /// The object found on its own resolution path.
        object: u32,
    },
    /// Not a PDF, or damaged beyond what the chosen mode repairs (`CS-PDF-0005`).
    NotPdf {
        /// Byte offset where reading failed, when known.
        offset: Option<u64>,
    },
    /// An object could not be parsed, under strict reading (`CS-PDF-0005`).
    Malformed {
        /// Object number, when the failure belongs to one.
        object: Option<u32>,
        /// Byte offset where parsing failed.
        offset: u64,
    },
    /// More revisions than `Limits::max_revisions` (`CS-PDF-0006`).
    TooManyRevisions {
        /// The limit in force.
        limit: u16,
    },
    /// A `/Prev` chain returns to a section already read (`CS-PDF-0006`).
    PrevLoop {
        /// Byte offset the chain returned to.
        offset: u64,
    },
    /// More pages than `Limits::max_pages` (`CS-PDF-0007`).
    TooManyPages {
        /// The limit in force.
        limit: u32,
    },
    /// The page tree visits a node twice (`CS-PDF-0007`).
    PageTreeCycle {
        /// The node reached a second time.
        object: u32,
    },
    /// A string longer than `Limits::max_string_bytes` (`CS-PDF-0008`).
    StringTooLong {
        /// Byte offset of the string.
        offset: u64,
    },
    /// A name longer than `Limits::max_name_bytes` (`CS-PDF-0008`).
    NameTooLong {
        /// Byte offset of the name.
        offset: u64,
    },
    /// The document is encrypted and neither the empty user password nor any password
    /// in the host's `Credentials` opens it (`CS-PDF-0009`).
    Encrypted,
    /// Public-key security handler: not supported (`CS-PDF-0010`).
    PublicKeySecurity,
    /// A security handler other than the standard one, or a version, revision or crypt
    /// filter method it does not define (`CS-PDF-0010`).
    UnsupportedSecurity,
    /// A filter this reader does not decode, where decoding was required
    /// (`CS-PDF-0011`).
    UnsupportedFilter {
        /// The stream's object number.
        object: u32,
    },
    /// A filter chain longer than `Limits::max_filter_chain` (`CS-PDF-0011`).
    FilterChainTooLong {
        /// The stream's object number.
        object: u32,
    },
    /// A dynamic-only XFA form: nothing static to sign (`CS-PDF-0012`).
    DynamicXfa,
    /// The host's cancellation predicate returned true (`CS-PDF-0013`).
    Cancelled,
    /// A page's content streams hold more operators than `Limits::max_content_ops`
    /// (`CS-PDF-0013`, as docs/21 assigns it).
    TooManyContentOps {
        /// Zero-based page index.
        page: u32,
    },
    /// A signed document needed repair, which would break its signatures
    /// (`CS-PDF-0014`).
    DamagedSigned,
    /// The allocator refused memory the reader asked for within its limits
    /// (`CS-PDF-0003`: only decoding asks for large blocks).
    OutOfMemory,
}

impl PdfError {
    /// The stable code from docs/20.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::TooLarge { .. } => "CS-PDF-0001",
            Self::TooManyObjects { .. }
            | Self::TooManyValues { .. }
            | Self::XrefSizeAbsurd { .. } => "CS-PDF-0002",
            Self::StreamTooLarge { .. }
            | Self::DecodeRatio { .. }
            | Self::DecodeBudget { .. }
            | Self::OutOfMemory => "CS-PDF-0003",
            Self::TooDeep { .. } | Self::ReferenceTooDeep { .. } | Self::ReferenceCycle { .. } => {
                "CS-PDF-0004"
            }
            Self::NotPdf { .. } | Self::Malformed { .. } => "CS-PDF-0005",
            Self::TooManyRevisions { .. } | Self::PrevLoop { .. } => "CS-PDF-0006",
            Self::TooManyPages { .. } | Self::PageTreeCycle { .. } => "CS-PDF-0007",
            Self::StringTooLong { .. } | Self::NameTooLong { .. } => "CS-PDF-0008",
            Self::Encrypted => "CS-PDF-0009",
            Self::PublicKeySecurity | Self::UnsupportedSecurity => "CS-PDF-0010",
            Self::UnsupportedFilter { .. } | Self::FilterChainTooLong { .. } => "CS-PDF-0011",
            Self::DynamicXfa => "CS-PDF-0012",
            Self::Cancelled | Self::TooManyContentOps { .. } => "CS-PDF-0013",
            Self::DamagedSigned => "CS-PDF-0014",
        }
    }

    /// True when the error ends the whole read in every mode: a limit on the
    /// document as a whole, as opposed to damage local to one object.
    pub(crate) fn is_document_wide(&self) -> bool {
        matches!(
            self,
            Self::TooLarge { .. }
                | Self::TooManyObjects { .. }
                | Self::DecodeBudget { .. }
                | Self::TooDeep { .. }
                | Self::TooManyRevisions { .. }
                | Self::TooManyPages { .. }
                | Self::PageTreeCycle { .. }
                | Self::Encrypted
                | Self::PublicKeySecurity
                | Self::UnsupportedSecurity
                | Self::DynamicXfa
                | Self::Cancelled
                | Self::DamagedSigned
                | Self::OutOfMemory
        )
    }
}

impl fmt::Display for PdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            Self::TooLarge { size, limit } => {
                write!(f, "{code}: input of {size} bytes exceeds {limit}")
            }
            Self::TooManyObjects { limit } => write!(f, "{code}: more than {limit} objects"),
            Self::TooManyValues { offset } => write!(
                f,
                "{code}: too many values in one object at offset {offset}"
            ),
            Self::XrefSizeAbsurd { offset } => {
                write!(f, "{code}: /Size above 8388607 in xref at {offset}")
            }
            Self::StreamTooLarge { object, limit } => {
                write!(f, "{code}: stream {object} decodes past {limit} bytes")
            }
            Self::DecodeRatio { object, encoded } => {
                write!(
                    f,
                    "{code}: stream {object} ({encoded} bytes encoded) exceeds the decode ratio"
                )
            }
            Self::DecodeBudget { object, limit } => {
                write!(
                    f,
                    "{code}: document decode budget of {limit} bytes spent at stream {object}"
                )
            }
            Self::TooDeep { offset } => write!(f, "{code}: nesting too deep at offset {offset}"),
            Self::ReferenceTooDeep { object } => {
                write!(f, "{code}: reference chain too long from object {object}")
            }
            Self::ReferenceCycle { object } => {
                write!(f, "{code}: object {object} needs itself to be read")
            }
            Self::NotPdf { offset: Some(o) } => {
                write!(f, "{code}: not a readable PDF (offset {o})")
            }
            Self::NotPdf { offset: None } => write!(f, "{code}: not a readable PDF"),
            Self::Malformed {
                object: Some(n),
                offset,
            } => write!(f, "{code}: object {n} malformed at offset {offset}"),
            Self::Malformed {
                object: None,
                offset,
            } => write!(f, "{code}: malformed at offset {offset}"),
            Self::TooManyRevisions { limit } => write!(f, "{code}: more than {limit} revisions"),
            Self::PrevLoop { offset } => {
                write!(f, "{code}: /Prev chain loops back to offset {offset}")
            }
            Self::TooManyPages { limit } => write!(f, "{code}: more than {limit} pages"),
            Self::PageTreeCycle { object } => {
                write!(f, "{code}: page tree reaches object {object} twice")
            }
            Self::StringTooLong { offset } => {
                write!(f, "{code}: string too long at offset {offset}")
            }
            Self::NameTooLong { offset } => write!(f, "{code}: name too long at offset {offset}"),
            Self::Encrypted => write!(f, "{code}: encrypted, and no password supplied opens it"),
            Self::UnsupportedSecurity => {
                write!(f, "{code}: security handler or revision not supported")
            }
            Self::PublicKeySecurity => {
                write!(f, "{code}: public-key security handler not supported")
            }
            Self::UnsupportedFilter { object } => {
                write!(f, "{code}: stream {object} uses an unsupported filter")
            }
            Self::FilterChainTooLong { object } => {
                write!(f, "{code}: stream {object} has too many filters")
            }
            Self::DynamicXfa => write!(f, "{code}: dynamic-only XFA form"),
            Self::Cancelled => write!(f, "{code}: stopped by the host"),
            Self::TooManyContentOps { page } => {
                write!(f, "{code}: page {page} has too many content operators")
            }
            Self::DamagedSigned => write!(f, "{code}: signed document needs repair"),
            Self::OutOfMemory => write!(f, "{code}: allocation refused"),
        }
    }
}

impl std::error::Error for PdfError {}

/// Crate-internal result.
pub(crate) type Result<T> = core::result::Result<T, PdfError>;

/// Byte offset as `u64` for error payloads.
pub(crate) fn off(pos: usize) -> u64 {
    u64::try_from(pos).unwrap_or(u64::MAX)
}
