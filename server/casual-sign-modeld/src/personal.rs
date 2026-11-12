//! Personal-data spans, the model layer of `ML-08` (piece K): names and addresses through
//! GLiNER-PII ([`crate::gliner`]); the deterministic recognisers run in the worker. A stub
//! answering `CS-ML-0010` until piece K fills it.

use crate::error::ModeldError;
use crate::manifest::Bundle;
use crate::wire::{Span, SpanRequest};

/// Find personal-data spans in `request`.
///
/// # Errors
/// `CS-ML-0010` until the personal-data model is built into modeld.
pub(crate) fn run(bundle: &Bundle, request: &SpanRequest) -> Result<Vec<Span>, ModeldError> {
    let _ = (bundle, request);
    Err(ModeldError::NotInstalled)
}
