//! Workspace switching (docs/23 §2.3, ORG-04): `GET /auth/workspaces` lists the workspaces
//! the signed-in person belongs to, by organization, and `POST /auth/switch` moves their
//! session to one of them.
//!
//! A session is bound to one workspace. The workspace always comes from the credential
//! (`SEC-O05`): switching never widens the current session, it ends it and issues a new
//! one in the target workspace, carrying the same sign-in (method, time and expiry), so
//! a switch can never extend a session. Membership is read per request through the
//! session's own hash (`openseal_user_workspaces`), never from an id the caller names.

use axum::body::Bytes;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use casual_sign_store::repo::sessions::NewSession;
use casual_sign_store::{AccountId, StaffSessionId, UserWorkspace};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::admin::cookie;
use super::envelopes::rfc3339;
use super::json;
use crate::auth::{Credential, session_cookie};
use crate::call::Call;
use crate::crypto::{random_secret, sha256};
use crate::dto::parse;
use crate::error::ApiError;
use crate::http::SecretBearing;

/// The session this call came with, and the SHA-256 of its cookie's secret. Only a
/// staff session switches: API keys and OAuth clients belong to one workspace.
fn session(c: &Call) -> Result<(StaffSessionId, [u8; 32]), ApiError> {
    let Credential::Session(s) = c.p.credential else {
        return Err(ApiError::invalid("/credential"));
    };
    let name = session_cookie(c.st.config().secure_cookies);
    let secret = crate::auth::cookie(&c.headers, name).ok_or_else(ApiError::unauthenticated)?;
    Ok((s, sha256(secret.as_bytes())))
}

async fn memberships(c: &Call, token: &[u8; 32]) -> Result<Vec<UserWorkspace>, ApiError> {
    Ok(c.st
        .store()
        .entry_points()
        .user_workspaces(token, c.st.now())
        .await?)
}

/// The listing, grouped by organization in the order the store answers (organization
/// name, then workspace name).
fn listing(current: AccountId, ws: &[UserWorkspace]) -> Value {
    let mut orgs: Vec<Value> = Vec::new();
    let mut last = None;
    for w in ws {
        let item = json!({
            "id": w.account_id.to_string(), "name": w.account_name,
            "status": w.account_status.as_str(), "current": w.account_id == current,
        });
        if last == Some(w.organization_id) {
            if let Some(list) = orgs
                .last_mut()
                .and_then(|o| o.get_mut("workspaces"))
                .and_then(Value::as_array_mut)
            {
                list.push(item);
            }
        } else {
            orgs.push(json!({
                "id": w.organization_id.to_string(), "name": w.organization_name,
                "workspaces": [item],
            }));
            last = Some(w.organization_id);
        }
    }
    json!({ "current": current.to_string(), "organizations": orgs })
}

/// `GET /auth/workspaces`: the caller's workspaces, grouped by organization, with the
/// current one marked. Metadata only: names, ids and status.
pub(crate) async fn workspaces(c: Call) -> Result<Response, ApiError> {
    let (_, token) = session(&c)?;
    let ws = memberships(&c, &token).await?;
    Ok(json(StatusCode::OK, &listing(c.p.account, &ws)))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SwitchIn {
    account_id: String,
}

/// `POST /auth/switch {account_id}`: end this session and start one in that workspace,
/// where the caller must hold an enabled membership (`403 CS-ORG-0001` otherwise, the
/// same for an id that does not exist). The new session keeps the sign-in's method,
/// time and expiry. Answers as login does: the new cookie and CSRF token.
pub(crate) async fn switch(c: Call, body: Bytes) -> Result<Response, ApiError> {
    let (old, token) = session(&c)?;
    let req: SwitchIn = parse(&body)?;
    let target = AccountId(
        Uuid::parse_str(req.account_id.trim()).map_err(|_| ApiError::invalid("/account_id"))?,
    );
    let ws = memberships(&c, &token).await?;
    if !ws.iter().any(|w| w.account_id == target) {
        return Err(ApiError::not_a_workspace_member());
    }
    // The target organization's sign-in policy (SSO, MFA, session age; CS-ORG-0007)
    // is checked here once organization policy exists (ORG-08, ORG-12; row ORG-31).
    let now = c.st.now();
    let mut from = c.tx().await?;
    let taken = from
        .sessions()
        .take(old, now)
        .await?
        .ok_or_else(ApiError::expired)?;
    if taken.user_id != c.p.user {
        return Err(ApiError::expired());
    }
    let secret = random_secret()?;
    let csrf = random_secret()?;
    let mut to = c.st.store().for_account(target).begin().await?;
    let id = StaffSessionId(Uuid::now_v7());
    to.sessions()
        .create(&NewSession {
            id,
            user_id: c.p.user,
            token_sha256: sha256(secret.as_bytes()),
            csrf_sha256: sha256(csrf.as_bytes()),
            method: taken.method,
            created_at: taken.created_at,
            expires_at: taken.expires_at,
        })
        .await?;
    // The sign-in's second factor holds in the new workspace too (ASVS-01).
    if let Some(at) = taken.mfa_at {
        to.sessions().set_mfa_at(id, at).await?;
    }
    // The new session first: if it fails, the old one is still in force.
    to.commit().await?;
    from.commit().await?;
    let left = u64::try_from(
        taken
            .expires_at
            .unix_timestamp()
            .saturating_sub(now.unix_timestamp()),
    )
    .unwrap_or(0);
    let mut r = json(
        StatusCode::OK,
        &json!({
            "account_id": target.to_string(), "user_id": c.p.user.to_string(),
            "csrf_token": csrf, "expires_at": rfc3339(taken.expires_at),
        }),
    );
    let secure = c.st.config().secure_cookies;
    if let Some(v) = cookie(session_cookie(secure), &secret, left, secure) {
        r.headers_mut().insert(header::SET_COOKIE, v);
    }
    r.extensions_mut().insert(SecretBearing);
    Ok(r.into_response())
}

#[cfg(test)]
// Tests may unwrap, index and panic (CLAUDE.md).
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use casual_sign_store::{OrganizationId, WorkspaceStatus};

    fn w(org: u128, org_name: &str, acct: u128, name: &str) -> UserWorkspace {
        UserWorkspace {
            account_id: AccountId(Uuid::from_u128(acct)),
            account_name: name.into(),
            account_status: WorkspaceStatus::Active,
            organization_id: OrganizationId(Uuid::from_u128(org)),
            organization_name: org_name.into(),
        }
    }

    #[test]
    fn the_listing_groups_by_organization_and_marks_the_current_workspace() {
        let ws = [
            w(1, "Alpha", 10, "Legal"),
            w(1, "Alpha", 11, "Sales"),
            w(2, "Bravo", 20, "Main"),
        ];
        let v = listing(AccountId(Uuid::from_u128(11)), &ws);
        let orgs = v["organizations"].as_array().unwrap();
        assert_eq!(orgs.len(), 2);
        assert_eq!(orgs[0]["name"], "Alpha");
        assert_eq!(orgs[0]["workspaces"].as_array().unwrap().len(), 2);
        assert_eq!(orgs[0]["workspaces"][0]["current"], false);
        assert_eq!(orgs[0]["workspaces"][1]["current"], true);
        assert_eq!(orgs[1]["workspaces"][0]["name"], "Main");
        assert_eq!(v["current"], Uuid::from_u128(11).to_string());
    }
}
