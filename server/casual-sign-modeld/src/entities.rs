//! Agreement entities (piece K; the pretrained part of `ML-07`, docs/33 §5.3): parties,
//! dates, amounts, durations and addresses through GLiNER multi v2.1, or GLiNER small
//! v2.1 in the English profile ([`crate::gliner`]). The labels come with each request
//! (`party organization`, `person`, `effective date`, `date`, `monetary amount`,
//! `duration`, `address`). Pretrained NER cannot tell a party from any organization named,
//! so every span is a suggestion a person accepts.

use std::time::Instant;

use crate::error::ModeldError;
use crate::gliner::SpanModels;
use crate::wire::{Span, SpanRequest};

/// Find entity spans in `request`.
///
/// # Errors
/// `CS-ML-0010` when no entity model is installed; otherwise as
/// [`crate::gliner::Gliner::spans`].
pub(crate) fn run(
    models: &SpanModels,
    request: &SpanRequest,
    deadline: Instant,
) -> Result<Vec<Span>, ModeldError> {
    models
        .entities
        .as_ref()
        .ok_or(ModeldError::NotInstalled)?
        .spans(request, deadline)
}
