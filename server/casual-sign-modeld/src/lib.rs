//! OpenSeal's model daemon (ADR-029, docs/33; rows `ML-01`, `ML-09`): pretrained models
//! (no training) run here, in their own process, never in `crates/` and never in the
//! worker. modeld holds no secret and has no network egress; a hostile raster or a bug in
//! the inference runtime meets nothing worth stealing.
//!
//! Built like keyd (`casual-sign-keyd`, whose wire framing, mTLS and op log are copied
//! here with provenance in each module):
//!
//! - [`wire`]: the bounded binary protocol (INFO, OCR, HASH, EMBED, ENTITIES, PERSONAL).
//!   Spans come back as offsets, never text.
//! - [`ModelClient`]: the caller's side. **A caller depends on this crate with
//!   `default-features = false`** and gets only the client and the wire code: no
//!   inference runtime, rasteriser or tokenizer enters the worker (review defect 4).
//! - With the default `server` feature: [`Modeld`] (the mTLS daemon, slots, an op log of
//!   counts and ids only), [`Manifest`] and [`Bundle`] (weights pinned by SHA-256 in a
//!   manifest compiled into the binary; modeld does not start on a one-byte change), and
//!   the op modules the later pieces fill: `raster`, `rules` (piece C), `ocr` (D),
//!   `hash`, `embed` (I), `gliner`, `entities`, `personal` (K). Until filled, each op
//!   answers `CS-ML-0010` (not installed).
//!
//! Every output is a suggestion a person accepts; none enters a sealed document, the
//! audit chain or the evidence (docs/33 invariant 2). Errors are [`ModeldError`] with
//! `CS-ML-*` codes; no message, log line or `Debug` carries document content.

mod client;
mod error;
pub mod wire;

#[cfg(feature = "server")]
mod embed;
#[cfg(feature = "server")]
mod entities;
#[cfg(feature = "server")]
mod gliner;
#[cfg(feature = "server")]
mod hash;
#[cfg(feature = "server")]
mod manifest;
#[cfg(feature = "server")]
mod ocr;
#[cfg(feature = "server")]
pub mod oplog;
#[cfg(feature = "server")]
mod personal;
#[cfg(feature = "server")]
mod raster;
#[cfg(feature = "server")]
mod rules;
#[cfg(feature = "server")]
mod runtime;
#[cfg(feature = "server")]
mod server;

pub use client::{Call, DEADLINE_GRACE, Endpoint, ModelClient, client_tls};
pub use error::{BundleProblem, ModelRefusal, ModeldError};

#[cfg(feature = "server")]
pub use manifest::{ALLOWED_LICENCES, Bundle, Entry, MAX_BUNDLE, MAX_FILE, Manifest};
#[cfg(feature = "server")]
pub use oplog::{OpLog, OpRecord};
#[cfg(feature = "server")]
pub use server::{
    AllowList, DEFAULT_MEMORY_LIMIT, ModelService, Modeld, ModeldLimits, NO_RUNTIME, PER_SLOT_PEAK,
    SlotSettings, configured_slots, default_slots, fingerprint, resident_bytes, server_tls,
};
