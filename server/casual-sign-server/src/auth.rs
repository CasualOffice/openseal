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
use casual_sign_store::{
    AccountId, ApiClientId, GroupId, MfaPolicy, OrganizationAdmin, PermissionProfileId,
    StaffSessionId, TenantTx, UserId,
};
use uuid::Uuid;

use crate::authz::{self, Action, Actor, Grant, Membership};
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

/// The cookie that carries a staff session: `__Host-os_session` whenever cookies are
/// `Secure`, so the browser keeps it host-only, on path `/` and over HTTPS, and a
/// sibling subdomain cannot plant one (ASVS-05); plain `os_session` only for
/// plain-HTTP development, where a `__Host-` cookie would be refused.
pub(crate) fn session_cookie(secure: bool) -> &'static str {
    if secure {
        "__Host-os_session"
    } else {
        "os_session"
    }
}
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

/// Where a staff session stands with its second factor (ASVS-01, docs/40 §2). API keys
/// and access tokens are [`SecondFactor::NotOwed`]: they are credentials of their own,
/// made by a member who signed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecondFactor {
    /// Neither the user nor the account's policy asks for one.
    NotOwed,
    /// The session passed it.
    Passed,
    /// The user has a factor and the session has not passed it yet.
    Verify,
    /// The account's policy asks for a factor the user has not enrolled.
    Enrol,
}

impl SecondFactor {
    /// What a session owes, from its row: passed, the user enrolled, the account's
    /// policy, and whether the member is an administrator.
    #[must_use]
    pub fn of(passed: bool, enrolled: bool, policy: MfaPolicy, admin: bool) -> Self {
        if passed {
            return Self::Passed;
        }
        if enrolled {
            return Self::Verify;
        }
        let required = match policy {
            MfaPolicy::Optional => false,
            MfaPolicy::Administrators => admin,
            MfaPolicy::Everyone => true,
        };
        if required { Self::Enrol } else { Self::NotOwed }
    }

    /// What is owed before the session reaches anything but signing in: `verify`,
    /// `enrol`, or nothing.
    #[must_use]
    pub fn owed(self) -> Option<&'static str> {
        match self {
            Self::Verify => Some("verify"),
            Self::Enrol => Some("enrol"),
            Self::NotOwed | Self::Passed => None,
        }
    }

    /// The name the API answers for it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotOwed => "none",
            Self::Passed => "passed",
            Self::Verify => "verify",
            Self::Enrol => "enrol",
        }
    }
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
    /// The scopes whose every action it holds (docs/40 §2): what it may give an API key.
    pub scopes: BTreeSet<&'static str>,
    /// What it may do (ORG-07, docs/23 §2.2): its profile's workspace actions, narrowed
    /// by a key's or token's scopes.
    pub actions: BTreeSet<Action>,
    /// The permission profile it holds in the account.
    pub profile: PermissionProfileId,
    /// That profile's group scope (a delegated workspace admin's, ORG-07): the members it
    /// administers are those of these groups. `None` is the whole workspace.
    pub admin_scope: Option<BTreeSet<GroupId>>,
    /// An administrator of the account (acts on any envelope as `Admin`).
    pub admin: bool,
    /// May see every envelope of the account, not only their own.
    pub view_all: bool,
    /// A session's second factor; only [`crate::routes::Access::SigningIn`] routes
    /// serve a session that owes one.
    pub second_factor: SecondFactor,
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

impl Principal {
    /// Refuse unless the workspace action is held (`CS-AUTH-0006`; ORG-07).
    ///
    /// # Errors
    ///
    /// `CS-AUTH-0006`.
    pub fn require_action(&self, action: Action) -> Result<(), ApiError> {
        if self.actions.contains(&action) {
            Ok(())
        } else {
            Err(ApiError::forbidden(action.as_str()))
        }
    }

    /// What this caller holds for granting in its workspace ([`authz::held`]), with its
    /// organization role when it has one.
    #[must_use]
    pub fn actor(&self, org: Option<&OrganizationAdmin>) -> Actor {
        let member = Membership {
            actions: self.actions.clone(),
            admin: self.admin,
            scope: self.admin_scope.clone(),
        };
        Actor {
            user: self.user,
            profile: Some(self.profile),
            held: authz::held(Some(&member), org, self.account),
        }
    }

    /// Refuse (`403 CS-ORG-0005`) a grant beyond what this caller holds, or to itself
    /// ([`authz::grantable`], docs/23 §2.2): the one check of every grant path.
    ///
    /// # Errors
    ///
    /// `CS-ORG-0005`.
    pub fn may_grant(
        &self,
        org: Option<&OrganizationAdmin>,
        grant: &Grant,
    ) -> Result<(), ApiError> {
        authz::grantable(&self.actor(org), grant).map_err(|r| ApiError::grant_refused(r.what()))
    }
}

/// The grant a profile is: its actions, whether it is the administrator's, its scope.
#[must_use]
pub fn profile_grant(
    kind: ProfileKind,
    permissions: &[String],
    scope: Option<&[GroupId]>,
) -> Grant {
    Grant {
        actions: authz::profile_actions(kind, permissions),
        admin_profile: kind == ProfileKind::Admin,
        scope: scope.map(|s| s.iter().copied().collect()),
        to_user: None,
        profile: None,
    }
}

/// The custom-profile permission that shows every envelope of the account; with
/// [`SCOPES`] and the action names of [`authz::Action`], every name a profile may carry
/// (0034 `permission_profiles_known_permissions`).
pub const VIEW_ALL: &str = authz::VIEW_ALL;

/// The scopes a permission profile grants (docs/22 §8): those whose every action it
/// holds; whether it is an administrator's; and whether it sees every envelope.
pub(crate) fn profile_scopes(
    kind: ProfileKind,
    permissions: &[String],
) -> (BTreeSet<&'static str>, bool, bool) {
    let actions = authz::profile_actions(kind, permissions);
    (
        authz::scopes_held(&SCOPES, &actions),
        kind == ProfileKind::Admin,
        actions.contains(&Action::EnvelopesReadAll),
    )
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
    let mut actions = authz::profile_actions(profile.kind, &profile.permissions);
    if let Some(limit) = limit {
        // A key's scopes narrow the actions they cover; `envelopes.read_all` and
        // `envelopes.transfer`, which no scope covers, stay the profile's.
        actions.retain(|a| a.scope().is_none_or(|s| limit.iter().any(|l| l == s)));
    }
    let admin_scope = tx
        .users()
        .profile_scope(profile.id)
        .await?
        .map(|ids| ids.into_iter().collect());
    Ok(Principal {
        account,
        user,
        credential,
        scopes: authz::scopes_held(&SCOPES, &actions),
        view_all: actions.contains(&Action::EnvelopesReadAll),
        admin: profile.kind == ProfileKind::Admin,
        actions,
        profile: profile.id,
        admin_scope,
        second_factor: SecondFactor::NotOwed,
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
    if let Some(secret) = cookie(headers, session_cookie(state.config().secure_cookies)) {
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
        let mut p = as_member(
            &mut tx,
            s.account_id,
            s.user_id,
            Credential::Session(s.session_id),
            None,
        )
        .await?;
        p.second_factor = SecondFactor::of(s.mfa_verified, s.mfa_enrolled, s.mfa_policy, p.admin);
        return Ok(p);
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
    fn a_session_owes_its_factor_by_enrolment_and_policy() {
        use MfaPolicy::{Administrators, Everyone, Optional};
        use SecondFactor::{Enrol, NotOwed, Passed, Verify};
        // (passed, enrolled, policy, admin) -> owed
        for (passed, enrolled, policy, admin, want) in [
            (true, true, Everyone, true, Passed),
            (false, true, Optional, false, Verify),
            (false, false, Optional, true, NotOwed),
            (false, false, Administrators, true, Enrol),
            (false, false, Administrators, false, NotOwed),
            (false, false, Everyone, false, Enrol),
        ] {
            assert_eq!(SecondFactor::of(passed, enrolled, policy, admin), want);
        }
        assert_eq!(Verify.owed(), Some("verify"));
        assert_eq!(Passed.owed(), None);
    }

    #[test]
    fn cookies_and_bearer_are_read_exactly() {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_static("a=1; os_session=abc; os_sessionx=no"),
        );
        assert_eq!(cookie(&h, "os_session"), Some("abc"));
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
