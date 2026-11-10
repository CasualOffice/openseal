//! Who is calling `/api/v1` (docs/40 §2): a staff session cookie with its CSRF token,
//! a personal API key, or an OAuth 2.1 client-credentials access token. Every request
//! is authenticated afresh, deny by default: a revoked key, a revoked client, an
//! expired token, a removed member or a disabled user is refused on its next request.
//!
//! A credential acts as a member of the account (a session's user, or the API client's
//! owner), and holds at most the scopes that member's permission profile grants
//! (SEC-A05): an API key's or a token's own scopes narrow them further, never widen.

use std::collections::BTreeSet;

use axum::http::{HeaderMap, Method, header};
use casual_sign_store::repo::accounts::ProfileKind;
use casual_sign_store::repo::api_clients::ApiClientKind;
use casual_sign_store::{AccountId, ApiClientId, StaffSessionId, TenantTx, UserId};
use uuid::Uuid;

use crate::crypto::{same, sha256};
use crate::error::ApiError;
use crate::state::AppState;

/// Every scope of docs/40 §2.
pub const SCOPES: [&str; 10] = [
    "envelopes:read",
    "envelopes:write",
    "envelopes:send",
    "templates:read",
    "templates:write",
    "bulk:send",
    "webhooks:manage",
    "admin:users",
    "admin:account",
    "audit:read",
];

/// The cookie that carries a staff session.
pub(crate) const SESSION_COOKIE: &str = "os_session";
/// The header that carries a staff session's CSRF token.
pub(crate) const CSRF_HEADER: &str = "x-csrf-token";
/// API keys start with this, for secret scanning (SEC-A10).
pub(crate) const API_KEY_PREFIX: &str = "osk_";

/// How the caller proved who they are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Credential {
    /// A staff session.
    Session(StaffSessionId),
    /// A personal API key.
    ApiKey(ApiClientId),
    /// An access token issued to an OAuth client.
    AccessToken(ApiClientId),
}

/// An authenticated caller of `/api/v1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// The account every object it reaches must belong to.
    pub account: AccountId,
    /// The member it acts as.
    pub user: UserId,
    /// How it authenticated.
    pub credential: Credential,
    /// What it may do.
    pub scopes: BTreeSet<&'static str>,
    /// An administrator of the account (acts on any envelope as `Admin`).
    pub admin: bool,
    /// May see every envelope of the account, not only their own.
    pub view_all: bool,
}

impl Principal {
    /// What events record of this credential: the method, and a hash naming the
    /// session or client (never the secret). The audit vocabulary has no API-key or
    /// OAuth-client method yet, so every staff credential records `account_login`
    /// (row proposed in the T-2C report).
    #[must_use]
    pub fn evidence(
        &self,
    ) -> (
        Vec<casual_sign_audit::AuthMethod>,
        casual_sign_audit::Hash256,
    ) {
        let name = match self.credential {
            Credential::Session(s) => format!("session:{s}"),
            Credential::ApiKey(c) => format!("api_key:{c}"),
            Credential::AccessToken(c) => format!("oauth_client:{c}"),
        };
        (
            vec![casual_sign_audit::AuthMethod::AccountLogin],
            casual_sign_audit::Hash256::digest(name.as_bytes()),
        )
    }
}

impl Principal {
    /// The API client, when the credential is one.
    #[must_use]
    pub fn client(&self) -> Option<ApiClientId> {
        match self.credential {
            Credential::ApiKey(c) | Credential::AccessToken(c) => Some(c),
            Credential::Session(_) => None,
        }
    }

    /// A stable name for idempotency records and rate limits.
    #[must_use]
    pub fn key(&self) -> String {
        match self.client() {
            Some(c) => format!("client:{c}"),
            None => format!("user:{}", self.user),
        }
    }

    /// Refuse unless the scope is held (`CS-AUTH-0006`). The empty scope is any
    /// authenticated caller.
    ///
    /// # Errors
    ///
    /// `CS-AUTH-0006`.
    pub fn require(&self, scope: &'static str) -> Result<(), ApiError> {
        if scope.is_empty() || self.scopes.contains(scope) {
            Ok(())
        } else {
            Err(ApiError::forbidden(scope))
        }
    }
}

/// The scopes a permission profile grants (docs/22 §8), whether it is an
/// administrator's, and whether it sees every envelope.
pub(crate) fn profile_scopes(
    kind: ProfileKind,
    permissions: &[String],
) -> (BTreeSet<&'static str>, bool, bool) {
    let pick = |names: &[&str]| -> BTreeSet<&'static str> {
        SCOPES
            .iter()
            .copied()
            .filter(|s| names.contains(s))
            .collect()
    };
    match kind {
        ProfileKind::Admin => (SCOPES.iter().copied().collect(), true, true),
        ProfileKind::Sender => (
            pick(&[
                "envelopes:read",
                "envelopes:write",
                "envelopes:send",
                "templates:read",
                "templates:write",
                "bulk:send",
                "audit:read",
            ]),
            false,
            false,
        ),
        ProfileKind::Viewer => (
            pick(&["envelopes:read", "templates:read", "audit:read"]),
            false,
            false,
        ),
        _ => {
            let names: Vec<&str> = permissions.iter().map(String::as_str).collect();
            (pick(&names), false, names.contains(&"view_all_envelopes"))
        }
    }
}

/// The value of cookie `name`.
pub(crate) fn cookie<'h>(headers: &'h HeaderMap, name: &str) -> Option<&'h str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = v.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then_some(token.trim())
}

fn is_safe(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// The member a credential acts as, with the profile's scopes narrowed by `limit`.
async fn as_member(
    tx: &mut TenantTx,
    account: AccountId,
    user: UserId,
    credential: Credential,
    limit: Option<&[String]>,
) -> Result<Principal, ApiError> {
    let member = tx.users().get(user).await?.ok_or_else(ApiError::expired)?;
    if member.disabled_at.is_some() {
        return Err(ApiError::expired());
    }
    let profile = tx
        .users()
        .profile(member.permission_profile_id)
        .await?
        .ok_or_else(ApiError::expired)?;
    let (mut scopes, admin, view_all) = profile_scopes(profile.kind, &profile.permissions);
    if let Some(limit) = limit {
        scopes.retain(|s| limit.iter().any(|l| l == s));
    }
    Ok(Principal {
        account,
        user,
        credential,
        scopes,
        admin,
        view_all,
    })
}

/// Authenticate a request to `/api/v1`.
///
/// # Errors
///
/// `CS-AUTH-0001` with no usable credential; `CS-AUTH-0002` for an expired token, a
/// revoked client or a removed member; `CS-AUTH-0008` for a session request that
/// changes something without its CSRF token.
pub(crate) async fn authenticate(
    state: &AppState,
    method: &Method,
    headers: &HeaderMap,
) -> Result<Principal, ApiError> {
    let now = state.now();
    if let Some(token) = bearer(headers) {
        if token.starts_with(API_KEY_PREFIX) {
            let (account, client) = state
                .store()
                .entry_points()
                .resolve_api_key(&sha256(token.as_bytes()), now)
                .await?
                .ok_or_else(ApiError::unauthenticated)?;
            let mut tx = state.store().for_account(account).begin().await?;
            let c = tx
                .api_clients()
                .get(client)
                .await?
                .ok_or_else(ApiError::unauthenticated)?;
            if c.kind != ApiClientKind::ApiKey {
                return Err(ApiError::unauthenticated());
            }
            let owner = c.owner_user_id.ok_or_else(ApiError::expired)?;
            return as_member(
                &mut tx,
                account,
                owner,
                Credential::ApiKey(client),
                Some(&c.scopes),
            )
            .await;
        }
        let claims = state
            .0
            .jwt
            .verify(token, &state.config().public_url)
            .ok_or_else(ApiError::unauthenticated)?;
        if claims.exp <= now.unix_timestamp() {
            return Err(ApiError::expired());
        }
        let account =
            AccountId(Uuid::parse_str(&claims.acct).map_err(|_| ApiError::unauthenticated())?);
        let client =
            ApiClientId(Uuid::parse_str(&claims.sub).map_err(|_| ApiError::unauthenticated())?);
        let mut tx = state.store().for_account(account).begin().await?;
        let c = tx
            .api_clients()
            .get(client)
            .await?
            .ok_or_else(ApiError::expired)?;
        let lapsed = c.expires_at.is_some_and(|e| e <= now);
        if c.revoked_at.is_some() || lapsed || c.kind != ApiClientKind::OauthApp {
            return Err(ApiError::expired());
        }
        let owner = c.owner_user_id.ok_or_else(ApiError::expired)?;
        let granted: Vec<String> = claims
            .scope
            .split(' ')
            .filter(|s| c.scopes.iter().any(|g| g == s))
            .map(str::to_owned)
            .collect();
        return as_member(
            &mut tx,
            account,
            owner,
            Credential::AccessToken(client),
            Some(&granted),
        )
        .await;
    }
    if let Some(secret) = cookie(headers, SESSION_COOKIE) {
        let s = state
            .store()
            .entry_points()
            .resolve_staff_session(&sha256(secret.as_bytes()), now)
            .await?
            .ok_or_else(ApiError::unauthenticated)?;
        if !is_safe(method) {
            let sent = headers
                .get(CSRF_HEADER)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(ApiError::csrf)?;
            if !same(&sha256(sent.as_bytes()), &s.csrf_sha256) {
                return Err(ApiError::csrf());
            }
        }
        let mut tx = state.store().for_account(s.account_id).begin().await?;
        return as_member(
            &mut tx,
            s.account_id,
            s.user_id,
            Credential::Session(s.session_id),
            None,
        )
        .await;
    }
    Err(ApiError::unauthenticated())
}

#[cfg(test)]
// Tests may unwrap, index and panic (CLAUDE.md).
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn profiles_grant_what_docs_22_says_and_custom_takes_only_known_scopes() {
        let (all, admin, view) = profile_scopes(ProfileKind::Admin, &[]);
        assert_eq!(all.len(), SCOPES.len());
        assert!(admin && view);
        let (v, admin, view) = profile_scopes(ProfileKind::Viewer, &[]);
        assert!(!admin && !view);
        assert!(v.contains("envelopes:read") && !v.contains("envelopes:write"));
        let (c, _, view) = profile_scopes(
            ProfileKind::Custom,
            &[
                "envelopes:read".into(),
                "root".into(),
                "view_all_envelopes".into(),
            ],
        );
        assert_eq!(c.into_iter().collect::<Vec<_>>(), vec!["envelopes:read"]);
        assert!(view);
    }

    #[test]
    fn cookies_and_bearer_are_read_exactly() {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_static("a=1; os_session=abc; os_sessionx=no"),
        );
        assert_eq!(cookie(&h, SESSION_COOKIE), Some("abc"));
        assert_eq!(cookie(&h, "b"), None);
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("bearer xyz"),
        );
        assert_eq!(bearer(&h), Some("xyz"));
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic xyz"));
        assert_eq!(bearer(&h), None);
    }
}
