//! GLiNER span decoding (piece K; `ML-07`, `ML-08`): tokenisation, windows with a fixed
//! stride, the span-scoring graph through ONNX Runtime, and greedy non-overlapping
//! decoding: our own code on the one `ort` version (ADR-029, D3). Offsets are UTF-8 byte
//! offsets into the exact NFC text the worker sent (review defect 19). Empty until piece K
//! fills it.
