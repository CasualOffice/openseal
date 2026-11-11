//! Dynamic XFA forms laid out into static PDF pages (`XFA-01`, docs/30 §3 "XFA").
//!
//! A dynamic XFA form (ISO 32000-1 §12.7.8, XFA 3.3) carries no page content: its
//! pages exist only as an XML template plus data that a viewer lays out. OpenSeal
//! signs what a signer saw, so it lays the form out itself, once, into ordinary PDF
//! pages with AcroForm widgets for the fields, and from then on the document is filled,
//! flattened and sealed like any other.
//!
//! [`lay_out`] takes the XFA packets (the concatenated `/XFA` streams, an XDP
//! document) and returns a new PDF: one page per laid-out page, the drawn content in
//! its content stream with faces embedded as TrueType subsets, and one widget per
//! field. The input is hostile: the XML reader is bounded and refuses DTDs and
//! entities ([`XfaLimits`], docs/21 §XFA), merging and layout are bounded in nodes
//! and pages, and **no script runs**: FormCalc and JavaScript (`<script>`,
//! `<calculate>`, `<validate>`, events) are counted in the report and ignored.
//!
//! What scripts would have done is therefore absent from the output: calculated
//! values, presence changes made at initialisation, page numbers written by script,
//! and instances added by script. The report lists what was ignored.
//!
//! Like every engine crate it performs no I/O, reads no clock and builds for
//! `wasm32-unknown-unknown`; faces are supplied as bytes ([`Faces`]).

mod error;
mod fonts;
mod form;
mod image;
mod layout;
mod pdf;
mod props;
mod subset;
mod text;
mod xml;

pub use error::XfaError;
pub use fonts::{FaceRole, Faces};

/// Bounds on what an XFA form may make the engine do (docs/21 §XFA).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XfaLimits {
    /// Largest XDP accepted, in bytes (`CS-XFA-0001`).
    pub max_xml_bytes: u64,
    /// Deepest element nesting (`CS-XFA-0002`).
    pub max_depth: usize,
    /// Most XML nodes, elements and text (`CS-XFA-0003`).
    pub max_nodes: usize,
    /// Most attributes on one element (`CS-XFA-0003`).
    pub max_attributes: usize,
    /// Deepest nesting of containers (subforms, areas, exclusion groups, fields, draws)
    /// that merging and layout follow (`CS-XFA-0002`). They recurse once per level, so
    /// this bounds their stack: 32 levels fit a 1 MiB stack in a debug build.
    pub max_nesting: usize,
    /// Most merged form nodes, counting every instance (`CS-XFA-0007`).
    pub max_form_nodes: usize,
    /// Most pages laid out (`CS-XFA-0008`).
    pub max_pages: usize,
    /// Largest embedded image, decoded from base64, in bytes; a larger one is not
    /// drawn and is reported.
    pub max_image_bytes: usize,
    /// Largest image side in pixels; a larger one is not drawn and is reported.
    pub max_image_side: u32,
}

impl Default for XfaLimits {
    fn default() -> Self {
        Self {
            max_xml_bytes: 64 * 1024 * 1024,
            max_depth: 64,
            max_nodes: 4_000_000,
            max_attributes: 256,
            max_nesting: 32,
            max_form_nodes: 200_000,
            max_pages: 2_000,
            max_image_bytes: 16 * 1024 * 1024,
            max_image_side: 16_384,
        }
    }
}

/// What was laid out and what was not. Counts only, never content.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct XfaReport {
    /// Pages written.
    pub pages: usize,
    /// Widgets written, one per visible field (and per exclusion-group member).
    pub widgets: usize,
    /// Fields by user interface: text, numeric, date-time, check button, choice list,
    /// signature, password.
    pub fields: FieldCounts,
    /// Draw objects drawn.
    pub draws: usize,
    /// Images drawn.
    pub images: usize,
    /// Images not drawn: an external reference (never fetched), a format other than
    /// JPEG and 8-bit PNG without alpha, or over the image limits.
    pub images_skipped: usize,
    /// Scripts present and not run (`script`, `calculate` and `validate` scripts, and
    /// events).
    pub scripts_ignored: usize,
    /// Push buttons, barcodes and image fields: drawn as their border and caption,
    /// without a widget.
    pub inert_fields: usize,
    /// Characters no supplied face has, not drawn.
    pub missing_glyphs: usize,
    /// Characters in a symbol typeface (Pi, Dingbats, Wingdings), drawn as the
    /// characters they encode rather than the symbol.
    pub symbol_chars: usize,
    /// Objects whose content did not fit their content area even alone, placed
    /// overflowing it.
    pub overflowed: usize,
    /// Objects excluded from print (`relevant="-print"`), not drawn: the output is the
    /// printed form.
    pub screen_only: usize,
    /// Template elements of kinds layout does not handle, by count.
    pub unsupported: usize,
}

/// Fields by user interface.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct FieldCounts {
    /// `textEdit` and `passwordEdit`.
    pub text: usize,
    /// `numericEdit`.
    pub numeric: usize,
    /// `dateTimeEdit`.
    pub date: usize,
    /// `checkButton`, alone or in an exclusion group.
    pub check: usize,
    /// `choiceList`.
    pub choice: usize,
    /// `signature`.
    pub signature: usize,
}

/// A laid-out form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Laid {
    /// A complete PDF: pages, embedded faces, AcroForm widgets, no XFA.
    pub pdf: Vec<u8>,
    /// What was done.
    pub report: XfaReport,
}

/// Lay out the XFA form in `xdp` (the `/XFA` packets concatenated in order) into a
/// new static PDF.
///
/// # Errors
///
/// An [`XfaError`] whose code is in docs/20: a limit crossed, malformed XML, a DTD, no
/// template, cancellation, or no usable face.
pub fn lay_out(
    xdp: &[u8],
    faces: &Faces,
    limits: &XfaLimits,
    cancel: &dyn Fn() -> bool,
) -> Result<Laid, XfaError> {
    let len = u64::try_from(xdp.len()).unwrap_or(u64::MAX);
    if len > limits.max_xml_bytes {
        return Err(XfaError::TooLarge {
            bytes: len,
            limit: limits.max_xml_bytes,
        });
    }
    let dom = xml::parse(
        xdp,
        xml::XmlLimits {
            max_depth: limits.max_depth,
            max_nodes: limits.max_nodes,
            max_attributes: limits.max_attributes,
        },
        cancel,
    )?;
    let mut fonts = fonts::Fonts::new(faces)?;
    let doc = layout::run(&dom, &mut fonts, limits, cancel)?;
    let pdf = pdf::write(&doc, &fonts);
    Ok(Laid {
        pdf,
        report: doc.report,
    })
}
