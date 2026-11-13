//! The caller's side of OpenSeal's key daemon (docs/23 §5.2, docs/31 §5): keyd's wire
//! format, its errors, the mTLS client transport and the admin client, without `cryptoki`,
//! the development file key or the server, so that the console (and, with `CON-15`, the
//! worker) carry only what a caller needs.
//!
//! - [`wire`]: length-prefixed binary frames, every field bounded; the signing operations
//!   and the read-only admin operations `list-keys`, `oplog-head`, `oplog-range` and
//!   `health` (`CON-06`).
//! - [`KeydError`]: `CS-KEY-*` codes, and `CS-CON-0008` for an admin call refused.
//! - [`client_tls`], [`Endpoint`], [`call`]: one request, one response, on a fresh
//!   mutually authenticated TLS 1.3 connection.
//! - [`AdminClient`]: the console's read-only view of keyd. No private key, and no
//!   operation that signs, is reachable through it.

mod admin;
mod error;
mod tls;
pub mod wire;

pub use admin::{AdminClient, hex};
pub use error::{ADMIN_REFUSED, KeyConfigProblem, KeydError};
pub use tls::{Endpoint, call, client_tls, tls_certificates};
pub use wire::{Health, KeyHealth, KeyInfo, LogEntry};
