//! Page rasteriser (piece C of ADR-029's build plan; `ML-02`, `PDF-REN-01`): `hayro`
//! renders a page of the stored PDF to a grey raster, with the pixel cap checked from the
//! page box before allocation, a decoded-image budget, and a per-page time cap enforced by
//! a child that can be killed alone (review defect 11). Empty until piece C fills it; until
//! then OCR and HASH answer `CS-ML-0010`.
