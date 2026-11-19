//! OpenSeal's conversion daemon (ADR-042, docs/30 §3, docs/07 `SEC-P13`; rows `VS-06C`):
//! a Word document (`.docx`) uploaded to an envelope or a template is converted to PDF
//! here, never in the API server's process, and the PDF then goes through admission like
//! any upload. The original `.docx` is kept as the document's `original` version.
//!
//! - **The converter** is `docxide-pdf` (Apache-2.0, pure Rust; owner instruction 76),
//!   with every crate it pulls in passing `deny.toml`. Fonts come from the container
//!   (Apache-2.0 Croscore faces); the converter never fetches anything.
//! - **Contained.** convertd runs in its own container with no network at all
//!   (`network_mode: none`), a read-only root, no secrets, all capabilities dropped, and
//!   memory, CPU and process caps. Each job runs in a fresh child process with its own
//!   `setrlimit` caps (address space, CPU, no file writes, no core), killed at the job's
//!   wall-clock limit ([`child`], [`daemon`]).
//! - **Screened first.** Inside the child, before the converter reads it, the archive is
//!   checked for size, entry count, zip bombs, encryption, macros and its page estimate
//!   ([`screen()`]); external references are counted, never fetched.
//! - **One protocol** ([`wire`]): one request and one answer per connection over a Unix
//!   socket on a volume shared with the API server, the same frames between the daemon
//!   and its child.
//!
//! **A caller depends on this crate with `default-features = false`** and gets only
//! [`Client`], [`wire`] and the errors: no DOCX parser, image decoder or font code enters
//! the API server. Errors are [`ConvertError`] with `CS-CNV-*` codes; no message, log line
//! or `Debug` carries document content.

mod client;
mod error;
pub mod wire;

#[cfg(feature = "server")]
pub mod child;
#[cfg(feature = "server")]
pub mod daemon;
#[cfg(feature = "screen")]
mod screen;

pub use client::{Client, DEFAULT_TIMEOUT};
pub use error::{ConvertError, Reason};
pub use wire::Converted;

#[cfg(feature = "screen")]
pub use screen::{
    MAX_ENTRIES, MAX_EXPANDED, MAX_PAGES, MAX_PART, MAX_RATIO, RATIO_FLOOR, Screened, screen,
};

/// The converter and its version, as recorded in a converted document's admission
/// report (`converted.converter`).
pub const CONVERTER: &str = "docxide-pdf 0.21.4";
