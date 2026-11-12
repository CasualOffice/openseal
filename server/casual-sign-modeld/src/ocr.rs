//! OCR (piece D; `ML-02`): rasterise ([`crate::raster`]), detect and recognise words with
//! the PaddleOCR pipeline (`oar-ocr` with `default-features = false`, local files only),
//! add rules and boxes ([`crate::rules`]), and answer words, quads and confidences per
//! page. A stub answering `CS-ML-0010` until piece D fills it.

use crate::error::ModeldError;
use crate::manifest::Bundle;
use crate::wire::{OcrPage, Request};

/// Read the pages of `request` (an OCR request).
///
/// # Errors
/// `CS-ML-0010` until the OCR models are built into modeld.
pub(crate) fn run(bundle: &Bundle, request: &Request) -> Result<Vec<OcrPage>, ModeldError> {
    let _ = (bundle, request);
    Err(ModeldError::NotInstalled)
}
