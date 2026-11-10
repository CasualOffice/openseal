//! Why a flattening or a fill was not written. Messages carry field ids, object
//! numbers and counts, never a value, a name or document text (`SEC-D01`).

use core::fmt;

use casual_sign_model::Id;
use casual_sign_pdf::{PdfError, WriteError};

/// Why [`crate::flatten`] did not produce a document. [`FlattenError::code`] is the
/// stable code from docs/20.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FlattenError {
    /// A character of the field's value is in none of the supplied faces
    /// (`CS-FLT-0001`). Nothing is drawn in its place.
    MissingGlyph {
        /// The field.
        field: Id,
    },
    /// An image is over the upload size, or its width or height is over the cap
    /// (`CS-FLT-0002`, docs/21 §Images).
    ImageTooLarge {
        /// The field.
        field: Id,
    },
    /// An image is not a PNG or a baseline/progressive 8-bit JPEG, or does not decode
    /// (`CS-FLT-0003`).
    ImageUndecodable {
        /// The field.
        field: Id,
    },
    /// A drawn signature has more points than docs/21 allows, or a point that is not
    /// finite (`CS-FLD-0002`).
    TooManyPoints {
        /// The field.
        field: Id,
        /// Points supplied.
        points: usize,
    },
    /// A string to draw is over 4,000 bytes (`CS-FLD-0002`).
    TextTooLong {
        /// The field.
        field: Id,
        /// Bytes supplied.
        bytes: usize,
    },
    /// The value's kind does not suit the field type, for example a checkbox state on a
    /// text field (`CS-FLD-0002`).
    ValueMismatch {
        /// The field.
        field: Id,
    },
    /// A signature, initials, stamp or drawing value names a capture the input does not
    /// hold (`CS-FLD-0005`).
    UnknownCapture {
        /// The field.
        field: Id,
    },
    /// The field's page is not in the document, or its rectangle is not on the page
    /// (`CS-FLD-0004`).
    OffPage {
        /// The field.
        field: Id,
    },
    /// More fields on one page than [`crate::limits::MAX_FIELDS_PER_PAGE`]
    /// (`CS-FLT-0004`, proposed).
    TooManyFields {
        /// 1-based page number.
        page: u32,
        /// Fields supplied for it.
        fields: usize,
    },
    /// A supplied face is not a TrueType font this crate can read and subset
    /// (`CS-FLT-0005`, proposed).
    FontUnreadable {
        /// Index of the face in the [`crate::FontSet`].
        face: usize,
    },
    /// The document could not be read (its `CS-PDF-*` code).
    Read(PdfError),
    /// The update could not be written (its `CS-WRT-*` code).
    Write(WriteError),
}

impl FlattenError {
    /// The stable code (docs/20).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingGlyph { .. } => "CS-FLT-0001",
            Self::ImageTooLarge { .. } => "CS-FLT-0002",
            Self::ImageUndecodable { .. } => "CS-FLT-0003",
            Self::TooManyPoints { .. } | Self::TextTooLong { .. } | Self::ValueMismatch { .. } => {
                "CS-FLD-0002"
            }
            Self::UnknownCapture { .. } => "CS-FLD-0005",
            Self::OffPage { .. } => "CS-FLD-0004",
            Self::TooManyFields { .. } => "CS-FLT-0004",
            Self::FontUnreadable { .. } => "CS-FLT-0005",
            Self::Read(e) => e.code(),
            Self::Write(e) => e.code(),
        }
    }
}

impl fmt::Display for FlattenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            Self::MissingGlyph { field } => write!(
                f,
                "{code}: field {} has a character no bundled font draws",
                field.as_str()
            ),
            Self::ImageTooLarge { field } => {
                write!(
                    f,
                    "{code}: image of field {} is over its cap",
                    field.as_str()
                )
            }
            Self::ImageUndecodable { field } => {
                write!(
                    f,
                    "{code}: image of field {} does not decode",
                    field.as_str()
                )
            }
            Self::TooManyPoints { field, points } => write!(
                f,
                "{code}: drawn signature of field {} has {points} points or a bad point",
                field.as_str()
            ),
            Self::TextTooLong { field, bytes } => write!(
                f,
                "{code}: text of field {} is {bytes} bytes",
                field.as_str()
            ),
            Self::ValueMismatch { field } => write!(
                f,
                "{code}: value of field {} does not suit its type",
                field.as_str()
            ),
            Self::UnknownCapture { field } => write!(
                f,
                "{code}: field {} names a capture that was not supplied",
                field.as_str()
            ),
            Self::OffPage { field } => {
                write!(
                    f,
                    "{code}: field {} is not on a page of the document",
                    field.as_str()
                )
            }
            Self::TooManyFields { page, fields } => {
                write!(f, "{code}: page {page} has {fields} fields")
            }
            Self::FontUnreadable { face } => write!(f, "{code}: face {face} is not readable"),
            Self::Read(e) => write!(f, "{e}"),
            Self::Write(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for FlattenError {}

impl From<PdfError> for FlattenError {
    fn from(e: PdfError) -> Self {
        Self::Read(e)
    }
}

impl From<WriteError> for FlattenError {
    fn from(e: WriteError) -> Self {
        Self::Write(e)
    }
}
