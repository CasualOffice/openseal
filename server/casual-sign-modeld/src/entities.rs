//! Agreement entities (piece K; the pretrained part of `ML-07`): parties, dates, amounts,
//! durations and addresses through GLiNER ([`crate::gliner`]). A stub answering
//! `CS-ML-0010` until piece K fills it.

use crate::error::ModeldError;
use crate::manifest::Bundle;
use crate::wire::{Span, SpanRequest};

/// Find entity spans in `request`.
///
/// # Errors
/// `CS-ML-0010` until the entity model is built into modeld.
pub(crate) fn run(bundle: &Bundle, request: &SpanRequest) -> Result<Vec<Span>, ModeldError> {
    let _ = (bundle, request);
    Err(ModeldError::NotInstalled)
}
