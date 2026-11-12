//! Page hashes (piece I; `ML-05`): dHash and pHash of each page's raster (`image_hasher`),
//! the first stage of template matching. A stub answering `CS-ML-0010` until piece I fills
//! it.

use crate::error::ModeldError;
use crate::manifest::Bundle;
use crate::wire::{PageHash, Request};

/// Hash the pages of `request` (a HASH request).
///
/// # Errors
/// `CS-ML-0010` until page hashing is built into modeld.
pub(crate) fn run(bundle: &Bundle, request: &Request) -> Result<Vec<PageHash>, ModeldError> {
    let _ = (bundle, request);
    Err(ModeldError::NotInstalled)
}
