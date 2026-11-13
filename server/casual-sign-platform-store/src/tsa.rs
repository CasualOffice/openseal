//! Time-stamping authorities (CON-07, docs/23 §5.4, migration 0034): reads of
//! `platform.tsa_endpoints`, and two-person changes by key custodians through
//! `platform.request_key_change`, `platform.grant_key_change` and
//! `platform.apply_key_change`. The console has SELECT only on the table.

use serde_json::Value;
use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{Result, db};
use crate::store::{PlatformStore, PlatformTx};

/// A configured TSA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsaEndpoint {
    /// Its id.
    pub id: Uuid,
    /// `http://` or `https://` URL.
    pub url: String,
    /// The policy OID expected, if any.
    pub policy_oid: Option<String>,
    /// Tried in ascending order.
    pub priority: i32,
    /// Whether the worker uses it.
    pub enabled: bool,
    /// SHA-256 of the TSA's signing certificate expected, if any.
    pub cert_sha256: Option<Vec<u8>>,
    /// When this version was applied.
    pub changed_at: OffsetDateTime,
    /// The approval that made it.
    pub approval: Uuid,
}

/// A key change's action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAction {
    /// Add or replace a TSA endpoint.
    TsaSet,
    /// Remove a TSA endpoint.
    TsaRemove,
}

impl KeyAction {
    /// The action's name in the approval tables.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TsaSet => "tsa.set",
            Self::TsaRemove => "tsa.remove",
        }
    }
}

impl PlatformStore {
    /// Every configured TSA, in the order the worker tries the enabled ones.
    ///
    /// # Errors
    /// A database error.
    pub async fn tsa_endpoints(&self) -> Result<Vec<TsaEndpoint>> {
        let rows = sqlx::query(
            "SELECT id, url, policy_oid, priority, enabled, cert_sha256, changed_at, approval \
             FROM platform.tsa_endpoints ORDER BY priority, id LIMIT 64",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter()
            .map(|r| {
                Ok(TsaEndpoint {
                    id: r.try_get("id").map_err(db)?,
                    url: r.try_get("url").map_err(db)?,
                    policy_oid: r.try_get("policy_oid").map_err(db)?,
                    priority: r.try_get("priority").map_err(db)?,
                    enabled: r.try_get("enabled").map_err(db)?,
                    cert_sha256: r.try_get("cert_sha256").map_err(db)?,
                    changed_at: r.try_get("changed_at").map_err(db)?,
                    approval: r.try_get("approval").map_err(db)?,
                })
            })
            .collect()
    }

    /// The payload a key-change request carries, for the approver to read.
    ///
    /// # Errors
    /// A database error.
    pub async fn approval_payload(&self, request: Uuid) -> Result<Option<Value>> {
        sqlx::query_scalar("SELECT payload FROM platform.approval_payloads WHERE request_id = $1")
            .bind(request)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)
    }
}

impl PlatformTx {
    /// Propose a key change (step 1): the whole payload is stored for the approver.
    ///
    /// # Errors
    /// `CS-CON-0003` for an operator who is not a key custodian, `CS-CON-0002` without a
    /// second factor in the last 5 minutes, `CS-CON-0006` for a payload that fails the
    /// database's checks.
    pub async fn request_key_change(
        &mut self,
        session: &[u8; 32],
        id: Uuid,
        action: KeyAction,
        target: Uuid,
        payload: &Value,
        now: OffsetDateTime,
    ) -> Result<Uuid> {
        sqlx::query_scalar("SELECT platform.request_key_change($1, $2, $3, $4, $5, $6)")
            .bind(session.as_slice())
            .bind(id)
            .bind(action.as_str())
            .bind(target)
            .bind(payload)
            .bind(now)
            .fetch_one(&mut *self.tx)
            .await
            .map_err(db)
    }

    /// Approve another key custodian's change (step 2); `false` when there is no live,
    /// unused key-change request with that id.
    ///
    /// # Errors
    /// `CS-CON-0004` for one's own request; the session check's codes.
    pub async fn grant_key_change(
        &mut self,
        session: &[u8; 32],
        request: Uuid,
        now: OffsetDateTime,
    ) -> Result<bool> {
        sqlx::query_scalar("SELECT platform.grant_key_change($1, $2, $3)")
            .bind(session.as_slice())
            .bind(request)
            .bind(now)
            .fetch_one(&mut *self.tx)
            .await
            .map_err(db)
    }

    /// Apply an approved key change (step 3); the action applied.
    ///
    /// # Errors
    /// `CS-CON-0004` without an unused approval by another key custodian for exactly the
    /// stored payload; `CS-CON-0002` without a fresh second factor.
    pub async fn apply_key_change(
        &mut self,
        session: &[u8; 32],
        request: Uuid,
        now: OffsetDateTime,
    ) -> Result<String> {
        sqlx::query_scalar("SELECT platform.apply_key_change($1, $2, $3)")
            .bind(session.as_slice())
            .bind(request)
            .bind(now)
            .fetch_one(&mut *self.tx)
            .await
            .map_err(db)
    }
}
