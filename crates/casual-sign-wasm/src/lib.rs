//! OpenSeal for the browser: field rules and the verifier compiled to WebAssembly
//! (docs/19, `WASM-01`).
//!
//! The browser runs the same field rules the server believes at completion, and anyone
//! can verify a signed PDF offline in a page, with the code the server and the CLI run.
//! Every function takes bytes and JSON and returns one canonical JSON object (keys sorted,
//! no whitespace): `{"ok": …}` or `{"error": {"code", "message"}}` with a docs/20 code.
//! Canonical output lets the WASM build be compared with the native one byte for byte
//! (Phase 1 exit item 6; `tools/wasm-parity.mjs`).
//!
//! The logic is in [`api`], plain Rust that runs natively too; the `#[wasm_bindgen]`
//! functions below only move bytes and strings across the boundary. Nothing here reads
//! a clock, draws randomness or fetches: the validation time and trust are supplied.
//!
//! Exports (JavaScript names):
//! - `verify(pdf: Uint8Array, trust: string) -> string` ([`api::verify`])
//! - `admit(pdf: Uint8Array) -> string` ([`api::admit`])
//! - `extract_text(pdf: Uint8Array) -> string` ([`api::extract_text`])
//! - `place_anchor(pdf: Uint8Array, anchors: string) -> string` ([`api::place_anchor`])
//! - `evaluate_envelope(fields: string, values: string) -> string` ([`api::evaluate`])
//! - `parity_cases() -> string`, with the `parity` feature only ([`parity_cases`])

use wasm_bindgen::prelude::wasm_bindgen;

pub mod api;
mod base64;
mod json;

/// Verify every signature in `pdf` against the trust in `trust_json` ([`api::verify`]).
#[wasm_bindgen]
#[must_use]
pub fn verify(pdf: &[u8], trust_json: &str) -> String {
    api::verify(pdf, trust_json)
}

/// Admit `pdf` and report what it holds ([`api::admit`]).
#[wasm_bindgen]
#[must_use]
pub fn admit(pdf: &[u8]) -> String {
    api::admit(pdf)
}

/// Every page's text with glyph positions ([`api::extract_text`]).
#[wasm_bindgen]
#[must_use]
pub fn extract_text(pdf: &[u8]) -> String {
    api::extract_text(pdf)
}

/// Place fields at anchor text ([`api::place_anchor`]).
#[wasm_bindgen]
#[must_use]
pub fn place_anchor(pdf: &[u8], anchors_json: &str) -> String {
    api::place_anchor(pdf, anchors_json)
}

/// Evaluate an envelope's field rules at completion ([`api::evaluate`]).
#[wasm_bindgen]
#[must_use]
pub fn evaluate_envelope(fields_json: &str, values_json: &str) -> String {
    api::evaluate(fields_json, values_json)
}

#[cfg(feature = "parity")]
#[path = "../../casual-sign-fields/tests/parity/cases.rs"]
mod cases;

/// The field-rule case table of `casual-sign-fields` (`tests/parity/cases.rs`), one line
/// per case, which must equal `tests/parity/expected.txt` natively and in WASM (ADR-022).
#[cfg(feature = "parity")]
#[wasm_bindgen]
#[must_use]
pub fn parity_cases() -> String {
    cases::run()
}
