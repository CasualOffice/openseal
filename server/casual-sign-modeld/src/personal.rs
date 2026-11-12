//! Personal-data spans, the model layer of `ML-08` (piece K, docs/33 §5.4): names and
//! addresses through GLiNER-PII base v1.0 ([`crate::gliner`]). Identifiers with a
//! checksum or a defined structure (cards, IBANs, national ids, phones, emails) are found
//! by the deterministic recognisers of `casual-sign-pii` in the worker, never by a model
//! (owner instruction 33); this layer is optional and off by default. GLiNER-PII is
//! English only (its encoder's vocabulary).

use std::time::Instant;

use crate::error::ModeldError;
use crate::gliner::SpanModels;
use crate::wire::{Span, SpanRequest};

/// Find personal-data spans in `request`.
///
/// # Errors
/// `CS-ML-0010` when the personal-data model is not installed; otherwise as
/// [`crate::gliner::Gliner::spans`].
pub(crate) fn run(
    models: &SpanModels,
    request: &SpanRequest,
    deadline: Instant,
) -> Result<Vec<Span>, ModeldError> {
    models
        .personal
        .as_ref()
        .ok_or(ModeldError::NotInstalled)?
        .spans(request, deadline)
}
