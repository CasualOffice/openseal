//! What every guarded `/api/v1` handler starts from: the state, the authenticated
//! principal, the client address, the idempotency seed and the headers.

use axum::extract::FromRequestParts;
use axum::http::HeaderMap;
use axum::http::request::Parts;
use casual_sign_store::TenantTx;

use crate::apply::{Commands, policy};
use crate::auth::Principal;
use crate::error::ApiError;
use crate::http::CommandSeed;
use crate::net::ClientIp;
use crate::state::AppState;

/// A guarded call.
#[derive(Debug, Clone)]
pub(crate) struct Call {
    pub st: AppState,
    pub p: Principal,
    pub ip: ClientIp,
    pub seed: Option<String>,
    pub headers: HeaderMap,
}

impl FromRequestParts<AppState> for Call {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, ApiError> {
        let p = parts
            .extensions
            .get::<Principal>()
            .cloned()
            .ok_or_else(ApiError::unauthenticated)?;
        Ok(Self {
            st: st.clone(),
            p,
            ip: parts
                .extensions
                .get::<ClientIp>()
                .copied()
                .unwrap_or_default(),
            seed: parts.extensions.get::<CommandSeed>().map(|s| s.0.clone()),
            headers: parts.headers.clone(),
        })
    }
}

impl Call {
    /// A transaction in the principal's account.
    pub(crate) async fn tx(&self) -> Result<TenantTx, ApiError> {
        Ok(self.st.store().for_account(self.p.account).begin().await?)
    }

    /// Command contexts for this request, with the account's policy.
    pub(crate) async fn commands(&self, tx: &mut TenantTx) -> Result<Commands, ApiError> {
        Ok(Commands::new(
            self.seed.clone(),
            self.st.now(),
            crate::api::staff_context(&self.headers, self.ip, &self.p),
            policy(tx).await?,
        ))
    }
}
