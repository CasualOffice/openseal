//! Typed errors with stable codes (docs/20 `CS-DB-*`, `CS-BLOB-*`).
//!
//! Messages carry codes, SQLSTATEs, constraint names, ids and counts, never a database
//! error's text: PostgreSQL's details quote the offending values (an email in a unique
//! violation, for one), and those are personal data or document content (SEC-D01).

use core::fmt;

/// Every error the store returns.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StoreError {
    /// `CS-DB-0001`: the database could not be reached, or the connection failed.
    Unavailable,
    /// `CS-DB-0002`: a migration failed, or an applied migration's checksum differs from
    /// this build's (an applied migration was edited; migrations are forward-only).
    Migration {
        /// The migration's number.
        version: i64,
    },
    /// `CS-DB-0003`: no such object in this account. Another account's object is
    /// indistinguishable from a missing one (docs/20 `CS-API-0002`).
    NotFound {
        /// What was looked for (`"envelope"`, `"recipient"`, ...).
        entity: &'static str,
    },
    /// `CS-DB-0004`: an update, delete or truncate of the audit chain or a tombstone was
    /// refused (docs/32 §1 principle 2).
    AppendOnly,
    /// `CS-DB-0005`: an audit event does not extend its envelope's chain: wrong hash,
    /// `seq` not the next, or `prev` not the head.
    ChainBroken {
        /// The `seq` offered.
        seq: u64,
    },
    /// `CS-DB-0006`: the object already exists (a unique constraint).
    Conflict {
        /// The constraint's name.
        constraint: String,
    },
    /// `CS-DB-0007`: stale version: the object changed since it was read (docs/24 §1,
    /// surfaced to API clients as `CS-WF-0002`).
    StaleVersion {
        /// What was updated.
        entity: &'static str,
    },
    /// `CS-DB-0008`: a value broke a check or reference constraint (including a reference
    /// to another account's object).
    Constraint {
        /// The constraint's name, when PostgreSQL gives one.
        constraint: Option<String>,
        /// The SQLSTATE.
        sqlstate: String,
    },
    /// `CS-DB-0009`: the database refused the operation: a missing privilege, or a row
    /// that row-level security does not let this account write.
    Refused {
        /// The SQLSTATE.
        sqlstate: String,
    },
    /// `CS-DB-0010`: a stored value could not be read back as its type.
    Corrupt {
        /// The column.
        column: &'static str,
    },
    /// `CS-DB-0011`: the database has a migration this build does not know: it is newer
    /// than the code.
    SchemaAhead {
        /// The newest version applied.
        version: i64,
    },
    /// `CS-DB-0012`: any other database error, by SQLSTATE.
    Database {
        /// The SQLSTATE, when there is one.
        sqlstate: Option<String>,
    },
    /// `CS-DB-0013`: a change to an immutable column was refused: a workspace's
    /// organization (SQLSTATE `OS004`, docs/23 §2.1).
    Immutable,
    /// `CS-BLOB-0001`: the blob store failed (I/O, network, or an unexpected answer).
    BlobUnavailable {
        /// The HTTP status or OS error number, when there is one.
        status: Option<i64>,
    },
    /// `CS-BLOB-0002`: no blob with this key.
    BlobNotFound,
    /// `CS-BLOB-0003`: the bytes stored under a key do not hash to it.
    BlobCorrupt,
    /// `CS-BLOB-0004`: the blob is larger than the store's limit.
    BlobTooLarge {
        /// The limit in bytes.
        max: u64,
    },
    /// `CS-BLOB-0005`: a key that is not 64 lower-case hexadecimal digits.
    BlobKey,
}

impl StoreError {
    /// The stable code (docs/20).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unavailable => "CS-DB-0001",
            Self::Migration { .. } => "CS-DB-0002",
            Self::NotFound { .. } => "CS-DB-0003",
            Self::AppendOnly => "CS-DB-0004",
            Self::ChainBroken { .. } => "CS-DB-0005",
            Self::Conflict { .. } => "CS-DB-0006",
            Self::StaleVersion { .. } => "CS-DB-0007",
            Self::Constraint { .. } => "CS-DB-0008",
            Self::Refused { .. } => "CS-DB-0009",
            Self::Corrupt { .. } => "CS-DB-0010",
            Self::SchemaAhead { .. } => "CS-DB-0011",
            Self::Database { .. } => "CS-DB-0012",
            Self::Immutable => "CS-DB-0013",
            Self::BlobUnavailable { .. } => "CS-BLOB-0001",
            Self::BlobNotFound => "CS-BLOB-0002",
            Self::BlobCorrupt => "CS-BLOB-0003",
            Self::BlobTooLarge { .. } => "CS-BLOB-0004",
            Self::BlobKey => "CS-BLOB-0005",
        }
    }

    /// Classify a database error by SQLSTATE, keeping only the constraint name.
    pub(crate) fn from_sqlx(err: &sqlx::Error, seq: Option<u64>) -> Self {
        match err {
            sqlx::Error::Database(db) => {
                let state = db.code().map(|c| c.into_owned());
                let constraint = db.constraint().map(str::to_owned);
                match state.as_deref() {
                    Some("OS001") => Self::AppendOnly,
                    Some("OS002") => Self::ChainBroken {
                        seq: seq.unwrap_or(0),
                    },
                    Some("OS004") => Self::Immutable,
                    Some("23505") => Self::Conflict {
                        constraint: constraint.unwrap_or_default(),
                    },
                    // Check, foreign key, not-null and exclusion violations; invalid text.
                    Some(s @ ("23502" | "23503" | "23514" | "23P01" | "22P02" | "22001")) => {
                        Self::Constraint {
                            constraint,
                            sqlstate: s.to_owned(),
                        }
                    }
                    // Insufficient privilege; row-level security refused a new row.
                    Some(s @ "42501") => Self::Refused {
                        sqlstate: s.to_owned(),
                    },
                    _ => Self::Database { sqlstate: state },
                }
            }
            sqlx::Error::Io(_)
            | sqlx::Error::Tls(_)
            | sqlx::Error::PoolTimedOut
            | sqlx::Error::PoolClosed
            | sqlx::Error::WorkerCrashed
            | sqlx::Error::Configuration(_) => Self::Unavailable,
            sqlx::Error::ColumnDecode { .. } | sqlx::Error::Decode(_) => {
                Self::Corrupt { column: "?" }
            }
            _ => Self::Database { sqlstate: None },
        }
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            Self::Unavailable => write!(f, "{code}: database unavailable"),
            Self::Migration { version } => {
                write!(f, "{code}: migration {version} failed or was edited")
            }
            Self::NotFound { entity } => write!(f, "{code}: {entity} not found"),
            Self::AppendOnly => write!(f, "{code}: audit events are append-only"),
            Self::ChainBroken { seq } => {
                write!(f, "{code}: audit event {seq} does not extend the chain")
            }
            Self::Conflict { constraint } => write!(f, "{code}: already exists ({constraint})"),
            Self::StaleVersion { entity } => {
                write!(f, "{code}: {entity} changed since it was read")
            }
            Self::Constraint {
                constraint,
                sqlstate,
            } => write!(
                f,
                "{code}: constraint {} violated (SQLSTATE {sqlstate})",
                constraint.as_deref().unwrap_or("?")
            ),
            Self::Refused { sqlstate } => {
                write!(f, "{code}: refused by the database (SQLSTATE {sqlstate})")
            }
            Self::Corrupt { column } => write!(f, "{code}: stored value in {column} unreadable"),
            Self::SchemaAhead { version } => {
                write!(
                    f,
                    "{code}: database has migration {version}, newer than this build"
                )
            }
            Self::Database { sqlstate } => write!(
                f,
                "{code}: database error (SQLSTATE {})",
                sqlstate.as_deref().unwrap_or("?")
            ),
            Self::Immutable => write!(f, "{code}: change to an immutable column refused"),
            Self::BlobUnavailable { status } => match status {
                Some(s) => write!(f, "{code}: blob store failed ({s})"),
                None => write!(f, "{code}: blob store failed"),
            },
            Self::BlobNotFound => write!(f, "{code}: blob not found"),
            Self::BlobCorrupt => write!(f, "{code}: blob does not match its key"),
            Self::BlobTooLarge { max } => write!(f, "{code}: blob over {max} bytes"),
            Self::BlobKey => write!(f, "{code}: blob key is not a SHA-256 in hex"),
        }
    }
}

impl std::error::Error for StoreError {}

/// The store's result type.
pub type Result<T, E = StoreError> = core::result::Result<T, E>;

/// Map a sqlx error (closure-friendly).
pub(crate) fn db(err: sqlx::Error) -> StoreError {
    StoreError::from_sqlx(&err, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    /// A database error carrying only a SQLSTATE, as PostgreSQL's would.
    #[derive(Debug)]
    struct Pg(&'static str);

    impl fmt::Display for Pg {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }

    impl std::error::Error for Pg {}

    impl sqlx::error::DatabaseError for Pg {
        fn message(&self) -> &str {
            self.0
        }
        fn code(&self) -> Option<Cow<'_, str>> {
            Some(Cow::Borrowed(self.0))
        }
        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }
        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }
    }

    fn code_of(state: &'static str) -> &'static str {
        StoreError::from_sqlx(&sqlx::Error::Database(Box::new(Pg(state))), None).code()
    }

    #[test]
    fn sqlstates_map_to_their_store_codes() {
        // ORG-02: a workspace's organization is immutable (catalog test 5, SEC-O10).
        assert_eq!(code_of("OS004"), "CS-DB-0013");
        assert_eq!(code_of("42501"), "CS-DB-0009");
        assert_eq!(code_of("OS001"), "CS-DB-0004");
    }
}
