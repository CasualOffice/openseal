//! OpenSeal's domain types as plain Rust values (docs/22).
//!
//! Every type here checks its invariants when it is built, including when it is
//! deserialized: a value that exists is within the limits of docs/21. Field values and
//! formulas come from senders and signers, so nothing here panics on them; a violation
//! is a [`ModelError`] carrying a stable code from docs/20.
//!
//! The serde names are snake_case and stable: they become the public API (docs/40). This
//! crate performs no I/O, reads no clock and draws no randomness; ids are minted by the
//! host and supplied.
//!
//! **Stage 1D** (`T-1D`): only the field-related types exist so far.

mod error;
mod field;
mod text;

pub use error::ModelError;
pub use field::{
    Align, Condition, Conditional, CurrencyCode, DateFormat, Field, FieldOptions, FieldType,
    FieldValue, FontFamily, Format, Formula, Group, GroupRule, LengthRule, NumberRule, Placement,
    Points, Rgb, Validation, ValidationRule,
};
pub use text::{DataLabel, FormulaText, Id, Text};

/// Limits on field data, from docs/21 §Fields and envelopes unless marked as a decision.
pub mod limits {
    /// Most bytes in a text value, option, message, tooltip or placeholder (`CS-FLD-0002`).
    pub const MAX_VALUE_BYTES: usize = 4_000;
    /// Most options on a dropdown or radio group (`CS-FLD-0002`).
    pub const MAX_OPTIONS: usize = 500;
    /// Most characters in a formula expression (`CS-FLD-0021`).
    pub const MAX_FORMULA_CHARS: usize = 1_024;
    /// Most nesting levels in a formula (`CS-FLD-0021`); enforced by the parser.
    pub const MAX_FORMULA_DEPTH: usize = 32;
    /// Most label references in one formula (`CS-FLD-0021`); enforced by the parser.
    pub const MAX_FORMULA_REFERENCES: usize = 100;
    /// Most decimal places a formula or number rule may keep (docs/30 §6).
    pub const MAX_PRECISION: u8 = 15;
    /// Most bytes in a data label. A decision of `T-1D`: docs/21 records this limit (255 bytes).
    pub const MAX_LABEL_BYTES: usize = 255;
    /// Most bytes in an opaque id. A decision of `T-1D`: a UUID is 36.
    pub const MAX_ID_BYTES: usize = 64;
    /// Most bytes in a sender's validation regex. A decision of `T-1D`: docs/21 names none.
    pub const MAX_REGEX_BYTES: usize = 1_024;
    /// Largest coordinate or size in points: PDF's 200-inch page limit (ISO 32000-2 Annex C).
    pub const MAX_POINTS: u32 = 14_400;
    /// Highest page number a field may name. A decision of `T-1D`, equal to docs/21's page cap.
    pub const MAX_PAGE: u32 = 5_000;
}
