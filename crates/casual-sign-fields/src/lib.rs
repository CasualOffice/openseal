//! Field rules for OpenSeal: validation, conditional visibility, group rules, linked
//! fields and formulas, identical natively and in WASM (docs/30 §6, ADR-022).
//!
//! The browser runs this crate compiled to WebAssembly while a recipient fills fields;
//! the server runs the same code at completion (docs/24 §5) and believes only its own
//! answer. Everything here is pure and deterministic: no clock, no locale, no I/O, no
//! `#[cfg]` fork between targets, and no float in values or formulas. Geometry and text
//! positions are `f64`, whose basic operations IEEE 754 makes identical on every target. Values and formulas come from senders and
//! signers, so every bound of docs/21 is enforced and nothing panics on them.
//!
//! Entry points:
//! - [`validate`]: one value against one field.
//! - [`check_for_send`]: an envelope's fields before sending (formulas parse, labels
//!   exist, groups agree, no cycles).
//! - [`evaluate_envelope`]: everything at completion; returns an [`Outcome`].
//! - [`check_client`]: where a client's computed formula values differ (`CS-FLD-0022`).
//! - [`parse_formula`], [`Expression::evaluate`], [`format_result`]: the formula language.
//!
//! Placement (stage 1C, docs/30 §4–5):
//! - [`geometry`]: displayed page space to PDF user space and back (ADR-019).
//! - [`extract_text`], [`extract_page`]: text with positions, from a bounded
//!   interpreter of the text operators ([`text`]).
//! - [`place_anchor`]: anchor text to placed fields; [`scan_tags`]: text tags to fields.
//! - [`convert_acroform`]: existing AcroForm fields to OpenSeal fields;
//!   [`radio_choices`]: a radio group's options and the states they write, shared with
//!   flattening; [`annotation_pages`]: the page of a widget without `/P`.

mod acroform;
mod anchor;
mod cmap;
mod content;
mod envelope;
mod error;
mod font;
mod formula;
pub mod geometry;
mod parse;
mod tables;
mod tags;
pub mod text;
mod validate;

pub use acroform::{
    Conversion, Converted, MAX_ANNOTS_INDEXED, RadioChoice, RadioWidget, Skipped, Unmapped,
    annotation_pages, convert_acroform, name_text, radio_choices,
};
pub use anchor::{
    AnchorMatch, AnchorPlacement, AnchorSpec, AnchorUnits, MAX_ANCHOR_CHARS, MAX_ANCHOR_MATCHES,
    place_anchor,
};
pub use envelope::{Computed, Outcome, Values, check_client, check_for_send, evaluate_envelope};
pub use error::{FieldError, FormulaError, Invalid, Issue, PlaceError, TagProblem};
pub use formula::{Env, ErrorValue, Expression, format_result, parse_formula, round_result};
pub use geometry::{DisplayRect, PageGeometry, Point};
pub use tags::{MAX_TAG_CHARS, MAX_TAGS, TYPES, TagScan, TextTag, scan_tags};
pub use text::{PageText, TextRun, extract_page, extract_text};
pub use validate::{REGEX_DFA_LIMIT, REGEX_NEST_LIMIT, REGEX_SIZE_LIMIT, validate};

use unicode_normalization::UnicodeNormalization;

/// The key a data label is compared by: its NFC normalization, so one label typed with
/// a composed or a decomposed accent is the same label.
#[must_use]
pub fn label_key(label: &str) -> String {
    label.nfc().collect()
}
