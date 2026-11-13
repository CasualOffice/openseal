//! keyd's admin client (docs/23 §5.4, `CON-06`): the read-only operations the console
//! calls with its admin identity, which keyd answers only to its admin allow-list. An
//! admin identity cannot sign and a signing identity cannot call these (`CS-CON-0008`).

use crate::error::KeydError;
use crate::tls::{Endpoint, call};
use crate::wire::{Health, KeyInfo, LogEntry, MAX_RANGE, Request, Response};

/// A client of keyd's admin interface.
#[derive(Debug, Clone)]
pub struct AdminClient {
    endpoint: Endpoint,
}

fn unexpected() -> KeydError {
    KeydError::Malformed("unexpected answer")
}

impl AdminClient {
    /// A client over `endpoint`, whose client certificate is on keyd's admin allow-list.
    #[must_use]
    pub const fn new(endpoint: Endpoint) -> Self {
        Self { endpoint }
    }

    fn ask(&self, req: &Request) -> Result<Response, KeydError> {
        match call(&self.endpoint, req)? {
            Response::Error(n) => Err(KeydError::from_number(n)),
            r => Ok(r),
        }
    }

    /// Every key keyd serves, with its chain and validity.
    ///
    /// # Errors
    /// The code keyd answered (`CS-CON-0008` for a caller not on the admin allow-list,
    /// `CS-KEY-0001` for one on neither list), or `CS-KEY-0011` when unreachable.
    pub fn list_keys(&self) -> Result<Vec<KeyInfo>, KeydError> {
        match self.ask(&Request::ListKeys)? {
            Response::Keys(k) => Ok(k),
            _ => Err(unexpected()),
        }
    }

    /// The operation log's last sequence number and its hash (hex).
    ///
    /// # Errors
    /// As [`Self::list_keys`].
    pub fn oplog_head(&self) -> Result<(u64, String), KeydError> {
        match self.ask(&Request::OplogHead)? {
            Response::Head { seq, hash } => Ok((seq, hex(&hash))),
            _ => Err(unexpected()),
        }
    }

    /// Up to `n` (at most [`MAX_RANGE`]) operation-log records from sequence `from`.
    ///
    /// # Errors
    /// As [`Self::list_keys`]; `CS-KEY-0007` for `n` of zero or over the bound.
    pub fn oplog_range(&self, from: u64, n: u16) -> Result<Vec<LogEntry>, KeydError> {
        if n == 0 || n > MAX_RANGE {
            return Err(KeydError::Malformed("range length"));
        }
        match self.ask(&Request::OplogRange { from, n })? {
            Response::Range(r) => Ok(r),
            _ => Err(unexpected()),
        }
    }

    /// keyd's health: each key's backend state, the log's sequence, the uptime.
    ///
    /// # Errors
    /// As [`Self::list_keys`].
    pub fn health(&self) -> Result<Health, KeydError> {
        match self.ask(&Request::Health)? {
            Response::Health(h) => Ok(h),
            _ => Err(unexpected()),
        }
    }
}

/// Lowercase hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}
