//! The tenancy-scoped repositories. Each borrows a [`TenantTx`] and binds its account as
//! `$1` of every statement; none takes an account id from its caller, and none has an
//! unscoped variant.

use sqlx::postgres::PgRow;
use sqlx::{Decode, Postgres, Row, Type};

use crate::error::{Result, StoreError};
use crate::store::TenantTx;

pub mod accounts;
pub mod api_clients;
pub mod audit;
pub mod documents;
pub mod envelopes;
pub mod fields;
pub mod jobs;
pub mod recipients;
pub mod templates;
pub mod webhooks;

/// Read a column, or `CS-DB-0010` naming it.
pub(crate) fn col<'r, T>(row: &'r PgRow, column: &'static str) -> Result<T>
where
    T: Decode<'r, Postgres> + Type<Postgres>,
{
    row.try_get(column)
        .map_err(|_| StoreError::Corrupt { column })
}

/// Read a 32-byte hash column.
pub(crate) fn hash_col(row: &PgRow, column: &'static str) -> Result<[u8; 32]> {
    let v: Vec<u8> = col(row, column)?;
    <[u8; 32]>::try_from(v.as_slice()).map_err(|_| StoreError::Corrupt { column })
}

/// Read an optional 32-byte hash column.
pub(crate) fn opt_hash_col(row: &PgRow, column: &'static str) -> Result<Option<[u8; 32]>> {
    let v: Option<Vec<u8>> = col(row, column)?;
    v.map(|v| <[u8; 32]>::try_from(v.as_slice()).map_err(|_| StoreError::Corrupt { column }))
        .transpose()
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
}
