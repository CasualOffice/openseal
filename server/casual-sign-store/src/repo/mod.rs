//! The tenancy-scoped repositories. Each borrows a [`TenantTx`] and binds its account as
//! `$1` of every statement; none takes an account id from its caller, and none has an
//! unscoped variant.

use crate::error::{Result, StoreError};
use crate::store::TenantTx;

pub mod accounts;
pub mod api_clients;
pub mod audit;
pub mod bulk_sends;
pub mod documents;
pub mod envelopes;
pub mod fields;
pub mod folders;
pub mod groups;
pub mod idempotency;
pub mod jobs;
pub mod ml;
pub mod recipients;
pub mod sessions;
pub mod templates;
pub mod webhooks;
pub mod workflow;

/// `CS-DB-0003` for `entity` when a statement touched no row.
pub(crate) fn affected(rows: u64, entity: &'static str) -> Result<()> {
    if rows == 0 {
        Err(StoreError::NotFound { entity })
    } else {
        Ok(())
    }
}

/// A 32-byte hash read back, or `CS-DB-0010` naming its column.
pub(crate) fn hash32(v: Vec<u8>, column: &'static str) -> Result<[u8; 32]> {
    <[u8; 32]>::try_from(v.as_slice()).map_err(|_| StoreError::Corrupt { column })
}

/// An optional 32-byte hash read back.
pub(crate) fn opt_hash32(v: Option<Vec<u8>>, column: &'static str) -> Result<Option<[u8; 32]>> {
    v.map(|v| hash32(v, column)).transpose()
}

/// A text column restricted by a CHECK constraint, as a Rust enum.
macro_rules! text_enum {
    ($(#[$doc:meta])* $name:ident { $($(#[$vdoc:meta])* $var:ident = $s:literal),* $(,)? }) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum $name { $($(#[$vdoc])* $var),* }

        impl $name {
            /// The stored text.
            #[must_use]
            pub fn as_str(self) -> &'static str {
                match self { $(Self::$var => $s),* }
            }

            // Not every enum is read back by a repository yet.
            #[allow(dead_code)]
            pub(crate) fn parse(s: &str, column: &'static str) -> crate::error::Result<Self> {
                match s {
                    $($s => Ok(Self::$var),)*
                    _ => Err(crate::error::StoreError::Corrupt { column }),
                }
            }
        }
    };
}
pub(crate) use text_enum;

impl TenantTx {
    /// This account's own row.
    pub fn account(&mut self) -> accounts::Accounts<'_> {
        accounts::Accounts { tx: self }
    }

    /// Staff users through this account's memberships, and permission profiles.
    pub fn users(&mut self) -> accounts::Users<'_> {
        accounts::Users { tx: self }
    }

    /// Groups of members (UXW-07).
    pub fn groups(&mut self) -> groups::Groups<'_> {
        groups::Groups { tx: self }
    }

    /// API clients and keys.
    pub fn api_clients(&mut self) -> api_clients::ApiClients<'_> {
        api_clients::ApiClients { tx: self }
    }

    /// Envelopes.
    pub fn envelopes(&mut self) -> envelopes::Envelopes<'_> {
        envelopes::Envelopes { tx: self }
    }

    /// Documents and their versions.
    pub fn documents(&mut self) -> documents::Documents<'_> {
        documents::Documents { tx: self }
    }

    /// Recipients and their invitation tokens.
    pub fn recipients(&mut self) -> recipients::Recipients<'_> {
        recipients::Recipients { tx: self }
    }

    /// Fields and their values.
    pub fn fields(&mut self) -> fields::Fields<'_> {
        fields::Fields { tx: self }
    }

    /// The audit chain: append and read only.
    pub fn audit(&mut self) -> audit::Audit<'_> {
        audit::Audit { tx: self }
    }

    /// The job queue, this account's side.
    pub fn jobs(&mut self) -> jobs::Jobs<'_> {
        jobs::Jobs { tx: self }
    }

    /// Templates, their roles, documents and fields.
    pub fn templates(&mut self) -> templates::Templates<'_> {
        templates::Templates { tx: self }
    }

    /// Webhook subscriptions and deliveries.
    pub fn webhooks(&mut self) -> webhooks::Webhooks<'_> {
        webhooks::Webhooks { tx: self }
    }

    /// Bulk sends from a template and their rows (UXW-04).
    pub fn bulk_sends(&mut self) -> bulk_sends::BulkSends<'_> {
        bulk_sends::BulkSends { tx: self }
    }

    /// Members' own envelope folders and their filings (UXW-02).
    pub fn folders(&mut self) -> folders::Folders<'_> {
        folders::Folders { tx: self }
    }

    /// The workflow engine's envelope states.
    pub fn workflow_states(&mut self) -> workflow::WorkflowStates<'_> {
        workflow::WorkflowStates { tx: self }
    }

    /// The worker's per-job step ledger.
    pub fn job_steps(&mut self) -> workflow::JobSteps<'_> {
        workflow::JobSteps { tx: self }
    }

    /// Staff sessions.
    pub fn sessions(&mut self) -> sessions::Sessions<'_> {
        sessions::Sessions { tx: self }
    }

    /// Document analysis: settings, entitlements, runs, suggestions (docs/33, WEB-19).
    pub fn ml(&mut self) -> ml::Ml<'_> {
        ml::Ml { tx: self }
    }

    /// Idempotency records of API requests.
    pub fn idempotency(&mut self) -> idempotency::Idempotency<'_> {
        idempotency::Idempotency { tx: self }
    }
}
