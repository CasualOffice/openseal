//! OpenSeal's domain types: envelopes, documents, recipients, fields and templates
//! (docs/22). Plain values with invariants checked by constructors; no I/O, clock or
//! randomness, so the same types serve the server, the browser (WASM) and the CLI.
//!
//! **Skeleton.** Field types arrive with stage 1D (`T-1D`); envelopes and recipients
//! with Phase 2 stage 2A (`T-2A`).
