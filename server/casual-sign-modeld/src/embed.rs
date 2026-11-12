//! Sentence embeddings (piece I; `ML-05`, and `ML-07` search): multilingual-e5-small (or
//! the MiniLM English profile) through `tokenizers` (`default-features = false`) and ONNX
//! Runtime, mean-pooled and L2-normalised. A stub answering `CS-ML-0010` until piece I
//! fills it.

use crate::error::ModeldError;
use crate::manifest::Bundle;
use crate::wire::Request;

/// Embed the texts of `request` (an EMBED request).
///
/// # Errors
/// `CS-ML-0010` until the embedding model is built into modeld.
pub(crate) fn run(bundle: &Bundle, request: &Request) -> Result<Vec<Vec<f32>>, ModeldError> {
    let _ = (bundle, request);
    Err(ModeldError::NotInstalled)
}
