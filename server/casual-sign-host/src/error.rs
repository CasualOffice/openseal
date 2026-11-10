//! Typed errors with stable codes (docs/20). The decide-and-record path issues the
//! codes the worker registered for it (`CS-WRK-0001` to `0004`); the engine's and the
//! store's errors pass through whole, so each host maps them as it answers.

use core::fmt;

use casual_sign_store::StoreError;
use casual_sign_workflow::WorkflowError;

/// Every error of the decide-and-record path.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostError {
    /// `CS-WRK-0001`: a time outside the engine's or the database's range (never from a
    /// sane clock).
    Clock,
    /// `CS-WRK-0002`: a stored engine state does not read back as an `EnvelopeState`.
    StateUnreadable,
    /// `CS-WRK-0003`: an engine id the database keys by UUID is not one.
    NotUuid {
        /// What it names (`envelope`, `recipient`, ...).
        what: &'static str,
    },
    /// `CS-WRK-0004`: a job's payload is malformed, or its kind is unknown.
    BadJob {
        /// The job's kind as stored (at most 64 characters).
        kind: String,
    },
    /// The engine refused the command (`CS-WF-*`, `CS-FLD-*`, `CS-AUTH-*`, ...).
    Workflow(WorkflowError),
    /// The store's error (`CS-DB-*`, `CS-BLOB-*`).
    Store(StoreError),
    /// Appending a decided event to the chain read back failed (`CS-AUD-*`).
    Chain {
        /// Its code.
        code: &'static str,
    },
}

impl HostError {
    /// The stable docs/20 code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Clock => "CS-WRK-0001",
            Self::StateUnreadable => "CS-WRK-0002",
            Self::NotUuid { .. } => "CS-WRK-0003",
            Self::BadJob { .. } => "CS-WRK-0004",
            Self::Workflow(e) => e.code(),
            Self::Store(e) => e.code(),
            Self::Chain { code } => code,
        }
    }
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            Self::Clock => write!(f, "{code}: time out of range"),
            Self::StateUnreadable => write!(f, "{code}: stored envelope state is unreadable"),
            Self::NotUuid { what } => write!(f, "{code}: {what} id is not a UUID"),
            Self::BadJob { kind } => write!(f, "{code}: job of kind {kind:?} is malformed"),
            Self::Workflow(e) => write!(f, "{e}"),
            Self::Store(e) => write!(f, "{e}"),
            Self::Chain { .. } => write!(f, "{code}: appending to the audit chain failed"),
        }
    }
}

impl std::error::Error for HostError {}

impl From<StoreError> for HostError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<WorkflowError> for HostError {
    fn from(e: WorkflowError) -> Self {
        Self::Workflow(e)
    }
}

/// Shorthand.
pub type Result<T, E = HostError> = core::result::Result<T, E>;
