//! What the API server and the worker share (docs/19, docs/24 §1): the one path that
//! decides a command and records the decision, and the contract of the jobs it
//! enqueues.
//!
//! - [`mod@apply`]: load the envelope's engine state (locked), call
//!   [`casual_sign_workflow::decide`], then in the caller's one transaction write the
//!   state at the revision read, append the events to the hash chain
//!   (`PendingEvent::into_audit`, ADR-010), bring the relational rows the API lists into
//!   line (envelope columns, recipients, documents), revoke the tokens a decision
//!   revokes, and enqueue every other effect as a job. Nothing is visible until the
//!   caller commits.
//! - [`jobs`]: one job per effect: its kind, idempotency key, payload and due time.
//!
//! It exists so that the server need not depend on the worker, nor the worker on the
//! server: both depend on this.
//!
//! **Privacy.** Errors carry codes and the kind of thing named, never personal data.

pub mod apply;
pub mod capture;
pub mod crash;
mod error;
pub mod ids;
pub mod jobs;

pub use apply::{Applied, Loaded, apply, apply_in, apply_loaded, load_for_update};
pub use error::{HostError, Result};
