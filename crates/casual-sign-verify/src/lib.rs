//! Verifies any signed PDF, OpenSeal's or not (docs/31 §7): ByteRange coverage, digests,
//! CMS signatures, certificate chains to a supplied trust store at the signing time,
//! revocation, timestamps, and a classification of every revision after each signature.
//! The same code runs in the server, the browser (WASM) and the CLI.
//!
//! **Skeleton.** Built in stage 1H (`T-1H`).
