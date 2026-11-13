//! Typed errors with stable codes (docs/20 `CS-CON-*`, `CS-PLAN-0006`, `CS-DB-*`).
//!
//! Messages carry codes, SQLSTATEs and sequence numbers, never a database error's text:
//! PostgreSQL's details quote the offending values (an e-mail in a unique violation, for
//! one), and those may be personal data (`SEC-D01`).

use core::fmt;

/// Every error the platform store returns.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PlatformError {
    /// `CS-CON-0001`: no live operator session (missing, expired, idle, revoked, or the
    /// operator is disabled). SQLSTATE `OS006`.
    NotAuthenticated,
    /// `CS-CON-0002`: the session has no second factor yet. SQLSTATE `OS007`.
    SecondFactor,
    /// `CS-CON-0003`: the operator's roles lack the action. SQLSTATE `OS008`.
    Forbidden,
    /// `CS-CON-0004`: the action needs a second operator's approval. SQLSTATE `OS009`.
    ApprovalRequired,
    /// `CS-PLAN-0006`: a plan, quota, assignment or override the database refused.
    /// SQLSTATE `OS010`.
    PlanInvalid,
    /// `CS-CON-0007`: the operator log does not verify at `seq`.
    LogBroken {
        /// The first event that does not verify.
        seq: u64,
    },
    /// `CS-DB-0014`: an appended operator event did not extend the chain. SQLSTATE `OS005`.
    ChainBroken,
    /// `CS-DB-0004`: an update, delete or truncate of an append-only table. SQLSTATE `OS001`.
    AppendOnly,
    /// `CS-DB-0008`: a value broke a check, a reference or a parameter rule (SQLSTATE
    /// class 22 or 23).
    Invalid {
        /// The SQLSTATE.
        sqlstate: String,
    },
    /// `CS-DB-0009`: the database refused the operation (a missing privilege).
    Refused,
    /// `CS-DB-0001`: the database could not be reached.
    Unavailable,
    /// `CS-DB-0010`: a stored value could not be read back.
    Corrupt {
        /// What could not be read.
        what: &'static str,
    },
    /// `CS-DB-0012`: any other database error.
    Database {
        /// The SQLSTATE, when there is one.
        sqlstate: Option<String>,
    },
}

impl PlatformError {
    /// The stable code (docs/20).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotAuthenticated => "CS-CON-0001",
            Self::SecondFactor => "CS-CON-0002",
            Self::Forbidden => "CS-CON-0003",
            Self::ApprovalRequired => "CS-CON-0004",
            Self::PlanInvalid => "CS-PLAN-0006",
            Self::LogBroken { .. } => "CS-CON-0007",
            Self::ChainBroken => "CS-DB-0014",
            Self::AppendOnly => "CS-DB-0004",
            Self::Invalid { .. } => "CS-DB-0008",
            Self::Refused => "CS-DB-0009",
            Self::Unavailable => "CS-DB-0001",
            Self::Corrupt { .. } => "CS-DB-0010",
            Self::Database { .. } => "CS-DB-0012",
        }
    }

    pub(crate) fn from_sqlx(err: &sqlx::Error) -> Self {
        match err {
            sqlx::Error::Database(d) => {
                let state = d.code().map(|c| c.into_owned());
                match state.as_deref() {
                    Some("OS006") => Self::NotAuthenticated,
                    Some("OS007") => Self::SecondFactor,
                    Some("OS008") => Self::Forbidden,
                    Some("OS009") => Self::ApprovalRequired,
                    Some("OS010") => Self::PlanInvalid,
                    Some("OS005") => Self::ChainBroken,
                    Some("OS001") => Self::AppendOnly,
                    Some("42501") => Self::Refused,
                    Some(s) if s.starts_with("22") || s.starts_with("23") => Self::Invalid {
                        sqlstate: s.to_owned(),
                    },
                    _ => Self::Database { sqlstate: state },
                }
            }
            sqlx::Error::Io(_)
            | sqlx::Error::Tls(_)
            | sqlx::Error::PoolTimedOut
            | sqlx::Error::PoolClosed
            | sqlx::Error::WorkerCrashed => Self::Unavailable,
            sqlx::Error::ColumnDecode { .. } | sqlx::Error::Decode(_) => {
                Self::Corrupt { what: "column" }
            }
            _ => Self::Database { sqlstate: None },
        }
    }
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LogBroken { seq } => {
                write!(f, "{}: operator log breaks at seq {seq}", self.code())
            }
            Self::Invalid { sqlstate } => write!(f, "{}: SQLSTATE {sqlstate}", self.code()),
            Self::Database { sqlstate: Some(s) } => write!(f, "{}: SQLSTATE {s}", self.code()),
            Self::Corrupt { what } => write!(f, "{}: {what}", self.code()),
            _ => f.write_str(self.code()),
        }
    }
}

impl std::error::Error for PlatformError {}

/// Map a driver error.
pub(crate) fn db(err: sqlx::Error) -> PlatformError {
    PlatformError::from_sqlx(&err)
}

/// The platform store's result.
pub type Result<T, E = PlatformError> = core::result::Result<T, E>;
