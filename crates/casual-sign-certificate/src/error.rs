//! Typed errors with stable codes. Messages carry counts and object numbers, never a
//! name, an address or document text (SEC-D01).

use core::fmt;

use casual_sign_audit::AuditError;
use casual_sign_flatten::FlattenError;
use casual_sign_pdf::{PdfError, WriteError};

/// Why a certificate was not made. [`CertificateError::code`] gives the docs/20 code.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum CertificateError {
    /// The input is incomplete or over a bound: the member is named (`CS-AUD-0020`).
    Input {
        /// What was wrong.
        what: &'static str,
    },
    /// The certificate would need more pages than allowed (`CS-AUD-0021`).
    TooManyPages {
        /// Pages it would need.
        pages: usize,
        /// The limit.
        limit: usize,
    },
    /// The document already carries an associated file or embedded files: the pipeline
    /// normalizes uploads, which removes them, so this is not a document it delivered
    /// (`CS-AUD-0022`).
    AlreadyAttached,
    /// The document's catalog or page tree cannot be appended to (`CS-AUD-0023`).
    PageTree {
        /// The object concerned, when there is one.
        object: Option<u32>,
    },
    /// Lines of text did not fit their boxes even at the smallest size: a supplied face
    /// is far wider than the measure used to break lines (`CS-AUD-0024`). Refused rather
    /// than printed clipped.
    TextOverflow {
        /// Lines that did not fit.
        lines: usize,
    },
    /// The audit chain is empty, cannot be written, or names another envelope (the
    /// audit crate's code).
    Audit(AuditError),
    /// Drawing the pages failed (the flattener's code: `CS-FLT-0001` for a character no
    /// supplied face has, `CS-FLT-0002`/`0003` for a signature image).
    Flatten(FlattenError),
    /// Writing the update failed (`CS-WRT-*`).
    Write(WriteError),
    /// Reading a document failed (`CS-PDF-*`).
    Read(PdfError),
}

impl CertificateError {
    /// The stable code (docs/20).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Input { .. } => "CS-AUD-0020",
            Self::TooManyPages { .. } => "CS-AUD-0021",
            Self::AlreadyAttached => "CS-AUD-0022",
            Self::PageTree { .. } => "CS-AUD-0023",
            Self::TextOverflow { .. } => "CS-AUD-0024",
            Self::Audit(e) => e.code(),
            Self::Flatten(e) => e.code(),
            Self::Write(e) => e.code(),
            Self::Read(e) => e.code(),
        }
    }
}

impl fmt::Display for CertificateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            Self::Input { what } => write!(f, "{code}: certificate input: {what}"),
            Self::TooManyPages { pages, limit } => {
                write!(f, "{code}: certificate needs {pages} pages, limit {limit}")
            }
            Self::AlreadyAttached => {
                write!(
                    f,
                    "{code}: document already carries embedded or associated files"
                )
            }
            Self::PageTree { object: Some(n) } => {
                write!(f, "{code}: page tree unusable at object {n}")
            }
            Self::PageTree { object: None } => write!(f, "{code}: no usable catalog or page tree"),
            Self::TextOverflow { lines } => {
                write!(f, "{code}: {lines} lines of text did not fit their boxes")
            }
            Self::Audit(e) => write!(f, "{e}"),
            Self::Flatten(e) => write!(f, "{e}"),
            Self::Write(e) => write!(f, "{e}"),
            Self::Read(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CertificateError {}

impl From<AuditError> for CertificateError {
    fn from(e: AuditError) -> Self {
        Self::Audit(e)
    }
}

impl From<FlattenError> for CertificateError {
    fn from(e: FlattenError) -> Self {
        Self::Flatten(e)
    }
}

impl From<WriteError> for CertificateError {
    fn from(e: WriteError) -> Self {
        Self::Write(e)
    }
}

impl From<PdfError> for CertificateError {
    fn from(e: PdfError) -> Self {
        Self::Read(e)
    }
}
