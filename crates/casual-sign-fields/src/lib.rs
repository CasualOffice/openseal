//! Field rules for OpenSeal: validation, conditional visibility, group rules, linked
//! fields and formulas, identical natively and in WASM (docs/30 §6, ADR-022).
//!
//! The browser runs this crate compiled to WebAssembly while a recipient fills fields;
//! the server runs the same code at completion (docs/24 §5) and believes only its own
//! answer. Everything here is pure and deterministic: no clock, no locale, no float, no
//! I/O, no `#[cfg]` fork between targets. Values and formulas come from senders and
//! signers, so every bound of docs/21 is enforced and nothing panics on them.
//!
//! Entry points:
//! - [`validate`]: one value against one field.
//! - [`check_for_send`]: an envelope's fields before sending (formulas parse, labels
//!   exist, groups agree, no cycles).
//! - [`evaluate_envelope`]: everything at completion; returns an [`Outcome`].
//! - [`check_client`]: where a client's computed formula values differ (`CS-FLD-0022`).
//! - [`parse_formula`], [`Expression::evaluate`], [`format_result`]: the formula language.

mod envelope;
mod error;
mod formula;
mod parse;
mod validate;

pub use envelope::{Computed, Outcome, Values, check_client, check_for_send, evaluate_envelope};
pub use error::{FieldError, FormulaError, Invalid, Issue};
pub use formula::{Env, ErrorValue, Expression, format_result, parse_formula, round_result};
pub use validate::{REGEX_DFA_LIMIT, REGEX_NEST_LIMIT, REGEX_SIZE_LIMIT, validate};

use unicode_normalization::UnicodeNormalization;

/// The key a data label is compared by: its NFC normalization, so one label typed with
/// a composed or a decomposed accent is the same label.
#[must_use]
pub fn label_key(label: &str) -> String {
    label.nfc().collect()
}
