//! Draws field values, signatures, initials and checkmarks into a PDF's pages as one
//! incremental update, with fonts embedded and subset (docs/30 §7, `T-1E`), and
//! optionally fills the PDF's own form fields in place, keeping them fillable
//! (`FILL-01`).
//!
//! [`flatten`] takes an admitted, normalized document (the bytes delivered to signers,
//! docs/30 §1) and returns those bytes followed by one update, so the delivered bytes
//! stay a prefix of every later revision. For each field with a value it writes a Form
//! XObject in the field's own coordinates (points, origin at the bottom-left of the
//! field as displayed) and invokes it from a content stream appended to the page's
//! `/Contents`, wrapped in `q … Q` with a `cm` derived from the page's crop box,
//! `/Rotate` and `/UserUnit` through [`casual_sign_fields::PageGeometry`]: the function
//! the editor positions its overlays with.
//!
//! - **Text** is set without shaping in the field's family (Liberation Sans, Serif or
//!   Mono for Helvetica, Times and Courier), size, colour and alignment, shrunk to fit
//!   when allowed, wrapped at whitespace with long words broken; a masked field draws
//!   bullets. Faces are embedded as TrueType subsets (`/FontFile2`) with `/W` and a
//!   `ToUnicode` map, so text stays extractable and searchable. A character in no
//!   supplied face is `CS-FLT-0001`.
//! - **Signatures, initials, stamps and drawings**: pad strokes as smoothed paths, PNG
//!   and JPEG images re-encoded after a bounded decode, typed text in a script face;
//!   optionally a "Signed by" caption with the envelope id and a signing reason.
//! - **Checkboxes and radio buttons** converted from the document's form as their own
//!   on-state appearance (a vector checkmark or dot when they have none, `FLT-04`);
//!   other checkboxes as a checkmark; dropdowns and every other value as text;
//!   `date_signed` in the field's date format.
//! - The document's AcroForm is removed in the same update (fields and widgets gone,
//!   `/AcroForm` dropped from the catalog): widgets of converted fields keep their
//!   border and background, other widgets keep their appearance, drawn into the page.
//!   With [`FormMode::FillInPlace`] the form stays: converted fields get `/V` and new
//!   appearance streams instead (`FILL-01`).
//! - **What the signer sees is what is sealed** (`FLT-03`, SEC-S03): optional content
//!   is flattened to the default configuration's visibility and `/OCProperties`
//!   removed; non-widget annotations with an appearance are drawn into the page and
//!   removed, those hidden from the screen (`/F` Hidden or NoView, or hidden optional
//!   content) are removed, links and annotations without an appearance stay.
//!
//! Output is deterministic: no clock, no randomness, fixed object order. The crate
//! performs no I/O and builds for `wasm32-unknown-unknown`; faces are supplied as bytes
//! ([`FontSet`]).

mod canvas;
mod draw;
mod error;
mod fill;
mod flatten;
mod fonts;
mod image;
mod ink;
mod optional;
mod read;
mod subset;
mod text;
mod write;

use std::collections::BTreeMap;

use casual_sign_fields::Conversion;
use casual_sign_model::{Field, FieldValue, Id, Rgb};

pub use error::FlattenError;
pub use flatten::flatten;
pub use fonts::{FontSet, Role};

/// Bounds on what flattening draws (docs/21 unless marked as a decision).
pub mod limits {
    /// Most bytes in an uploaded signature or stamp image (docs/21 §Images,
    /// `CS-FLT-0002`).
    pub const MAX_IMAGE_BYTES: usize = 5 * 1024 * 1024;
    /// Most pixels in either dimension of an image (docs/21 §Images, `CS-FLT-0002`).
    pub const MAX_IMAGE_SIDE: u32 = 4_096;
    /// Most points in one drawn signature, over all its strokes (docs/21,
    /// `CS-FLD-0002`).
    pub const MAX_INK_POINTS: usize = 20_000;
    /// Most bytes in any string drawn: a value, a typed signature, a name, a reason
    /// (docs/21 "Text field value", `CS-FLD-0002`).
    pub const MAX_TEXT_BYTES: usize = 4_000;
    /// Most fields on one page. A decision of `T-1E`, equal to docs/21's fields per
    /// envelope (`CS-FLT-0004`, proposed).
    pub const MAX_FIELDS_PER_PAGE: usize = 3_000;
    /// Deepest nesting of an optional content visibility expression (`/VE`). A
    /// decision of `FLT-03` (docs/21, `CS-FLT-0006`).
    pub const MAX_VE_DEPTH: usize = 32;
    /// Most terms read in one visibility expression, so an expression whose arrays are
    /// shared by reference cannot multiply its work (docs/21, `CS-FLT-0006`).
    pub const MAX_VE_TERMS: usize = 4_096;
}

/// A point of a drawn signature, in the pad's coordinates: origin top-left, y down.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct InkPoint {
    /// Horizontal position.
    pub x: f64,
    /// Vertical position, downwards.
    pub y: f64,
}

/// A signature drawn on a pad: its strokes, each a run of points.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Ink {
    /// The strokes, in the order drawn.
    pub strokes: Vec<Vec<InkPoint>>,
    /// Ink colour; black when absent.
    pub color: Option<Rgb>,
}

/// What a signature, initials, stamp or drawing looks like.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Art {
    /// Strokes from a signing pad, drawn as smoothed paths.
    Drawn(Ink),
    /// An uploaded PNG or JPEG.
    Image(Vec<u8>),
    /// Typed text in a script face: `style` picks among the set's script faces.
    Typed {
        /// The text.
        text: String,
        /// Which script face, wrapping.
        style: usize,
    },
}

/// A captured signature, initials, stamp or drawing, named by a
/// [`FieldValue::Signature`] value.
#[derive(Debug, Clone, PartialEq)]
pub struct Capture {
    /// The marks.
    pub art: Art,
    /// The signer's name for the "Signed by" caption.
    pub signed_by: Option<String>,
    /// The signing meaning (21 CFR Part 11 §11.50: review, approval, responsibility,
    /// authorship), drawn under the signature when present.
    pub reason: Option<String>,
}

/// What happens to the document's own form fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum FormMode {
    /// Draw every value into the pages and remove the AcroForm (docs/30 §7).
    #[default]
    Flatten,
    /// Write converted fields' values into the AcroForm (`/V`, appearance streams,
    /// checkbox and radio states) and keep it fillable; fields that did not come from
    /// the AcroForm, and signature fields, are drawn into the pages (`FILL-01`).
    FillInPlace,
}

/// Choices that shape the output.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FlattenOptions {
    /// What happens to the AcroForm.
    pub mode: FormMode,
    /// Draw a "Signed by" caption under each signature and initials, with the envelope
    /// id (DocuSign's "DocuSigned by") and the signing reason when present.
    pub signed_by_line: bool,
    /// Let a field with a fixed font size shrink to fit (an automatic size always may).
    pub shrink_fixed_sizes: bool,
    /// When the AcroForm is removed, keep the border and background of converted
    /// fields' widgets (from `/MK`).
    pub widget_frames: bool,
    /// When the AcroForm is removed, draw the appearance of widgets that were not
    /// converted (push buttons, unmapped fields) into the page.
    pub keep_unconverted_appearances: bool,
}

impl Default for FlattenOptions {
    fn default() -> Self {
        Self {
            mode: FormMode::Flatten,
            signed_by_line: true,
            shrink_fixed_sizes: true,
            widget_frames: true,
            keep_unconverted_appearances: true,
        }
    }
}

/// What to draw.
#[derive(Debug, Clone, Copy)]
pub struct FlattenInput<'a> {
    /// The document's fields.
    pub fields: &'a [Field],
    /// The value of every visible field that has one (`Outcome::values` from
    /// `casual_sign_fields::evaluate_envelope`): a field without an entry is not drawn.
    pub values: &'a BTreeMap<Id, FieldValue>,
    /// The captures that signature, initials, stamp and drawing values name.
    pub captures: &'a BTreeMap<Id, Capture>,
    /// The envelope id, for `envelope_id` fields without a value and for captions.
    pub envelope_id: Option<&'a str>,
    /// The conversion that made fields from this document's AcroForm, when it did.
    pub acroform: Option<&'a Conversion>,
}

/// Why a field was not drawn or filled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum NotDrawn {
    /// No value (or an empty one, or an unchecked box with nothing to show).
    NoValue,
    /// The type has no mark on the page: attachment, approve and decline.
    NoVisual,
}

/// A face embedded by the update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedFont {
    /// `/BaseFont`, with its subset tag.
    pub base_font: String,
    /// Glyphs kept in the subset (`.notdef` not counted).
    pub glyphs: usize,
}

/// What [`flatten`] did. Ids and counts only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct FlattenReport {
    /// Fields drawn into the pages, in input order.
    pub drawn: Vec<Id>,
    /// Fields written into the AcroForm in place (`FILL-01`).
    pub filled: Vec<Id>,
    /// Fields neither drawn nor filled, and why.
    pub not_drawn: Vec<(Id, NotDrawn)>,
    /// Fields whose text was set smaller than asked to fit.
    pub shrunk: Vec<Id>,
    /// Fields whose text did not fit at the smallest size and is clipped by the field.
    pub overflow: Vec<Id>,
    /// Whether the AcroForm was removed.
    pub acroform_removed: bool,
    /// Widget annotations removed from pages.
    pub widgets_removed: usize,
    /// Widgets of unconverted fields whose appearance was drawn into the page.
    pub appearances_kept: usize,
    /// Non-widget annotations drawn into the page from their appearance and removed
    /// (`FLT-03`).
    pub annotations_flattened: usize,
    /// Annotations removed because the signer could not see them: hidden by `/F`
    /// (Hidden, NoView) or by optional content, and the pop-ups of flattened ones.
    pub annotations_removed: usize,
    /// Non-widget annotations left as they are: links, and annotations without an
    /// appearance to draw.
    pub annotations_kept: usize,
    /// Whether the document had optional content, now flattened to its default
    /// visibility with `/OCProperties` removed (`FLT-03`).
    pub optional_content_flattened: bool,
    /// Hidden marked-content sequences removed from content streams.
    pub hidden_sections: usize,
    /// Content operators dropped or neutralized as hidden (painting in hidden
    /// sections, and invocations of hidden XObjects).
    pub hidden_operators: usize,
    /// A certified document filled in place: its optional content and annotations
    /// were left as certified, since its DocMDP permits no new page content.
    pub layers_kept_as_certified: bool,
    /// Faces embedded.
    pub fonts: Vec<EmbeddedFont>,
    /// Images embedded.
    pub images: usize,
}

/// The flattened document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flattened {
    /// The input bytes followed by the update.
    pub bytes: Vec<u8>,
    /// What was done.
    pub report: FlattenReport,
}
