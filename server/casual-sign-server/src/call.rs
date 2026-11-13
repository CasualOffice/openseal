//! What every guarded `/api/v1` handler starts from: the state, the authenticated
//! principal, the client address, the idempotency seed and the headers.

use axum::extract::FromRequestParts;
use axum::http::HeaderMap;
use axum::http::request::Parts;
use casual_sign_audit::Personal;
use casual_sign_store::{ActorKind, AdminActor, TenantTx};

use crate::auth::Credential;

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
    /// Every admin event it appends (ORG-05) records this principal, the request id and
    /// the client address.
    pub(crate) async fn tx(&self) -> Result<TenantTx, ApiError> {
        let mut tx = self.st.store().for_account(self.p.account).begin().await?;
        tx.act_as(self.actor());
        Ok(tx)
    }

    /// The admin-log actor of this call (docs/23 §2.5): the user behind a session, or
    /// the API client behind a key or token.
    pub(crate) fn actor(&self) -> AdminActor {
        AdminActor {
            kind: match self.p.credential {
                Credential::Session(_) => ActorKind::User(self.p.user),
                Credential::ApiKey(c) | Credential::AccessToken(c) => ActorKind::ApiClient(c),
            },
            at: self.st.now(),
            request_id: crate::error::request_id(),
            ip: self.ip.0.map(|i| Personal(i.to_string())),
        }
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
