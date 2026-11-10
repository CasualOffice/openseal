//! OpenSeal's workflow engine: envelope and recipient state machines, routing, commands,
//! audit events and effects as one pure function (docs/24, ADR-011, stage 2A `T-2A`).
//!
//! [`decide`]`(state, command, context) -> Result<`[`Decision`]`, `[`WorkflowError`]`>`:
//!
//! - **Pure.** No clock, I/O or randomness: the time, the command id, the actor and the
//!   account's policy are in the [`Context`]; ids of new objects are in the command.
//!   The same inputs give the same decision, on every target including
//!   `wasm32-unknown-unknown`.
//! - **State, events, effects.** The server writes [`Decision::state`], appends
//!   [`Decision::events`] (the audit event types of docs/32 §3, numbered and hashed by
//!   `casual-sign-audit`'s chain, ADR-010) and enqueues [`Decision::effects`] as jobs
//!   keyed by [`EffectId`], in one transaction.
//! - **Invariants** (tested over random command sequences in `tests/properties.rs`): no
//!   status leaves a terminal status; `completed` only from a seal result that proves an
//!   independently verified seal of every document as delivered; every observable state
//!   change comes with at least one event; nobody is invited before every required
//!   recipient with a lower routing order has completed; voiding, declining and expiry
//!   cancel every pending timer and job; re-applying a command id gives a replayed
//!   decision with no events or effects.
//!
//! Every refusal is a [`WorkflowError`] with a stable `CS-WF-*`, `CS-AUTH-*` or
//! `CS-FLD-*` code (docs/20) and ids, never names, addresses or values.

mod changes;
mod command;
mod date;
mod effect;
mod engine;
mod error;
mod state;
mod validate;

pub use command::{
    Access, Change, Command, Context, Decision, Ersd, FieldEntry, PendingEvent, Policy, Principal,
    ReassignTo, SealedDocument, limits,
};
pub use effect::{
    Alert, Effect, EffectId, EffectKind, InvitationKind, Notice, Timer, WebhookTopic,
};
pub use engine::{canonical_hash, decide};
pub use error::{ObjectKind, Problem, SealFault, Violation, WorkflowError};
pub use state::{
    Bookkeeping, ConsentRecord, DocumentSpec, DocumentState, EnvelopeState, Fields, RecipientSpec,
    RecipientState, ScheduledTimer,
};
