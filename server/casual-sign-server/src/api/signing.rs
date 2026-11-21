//! Signing providers (`RSP-01`, ADR-046 §3.11, §3.14): what the operator's catalogue
//! offers this account, which of them the account enabled, and its options.
//!
//! - `GET /signing-providers` (`envelopes:write`): the providers the catalogue offers
//!   this account, each with whether the account enabled it; a sender may name an
//!   enabled one as a signer's `signature.provider_id`.
//! - `GET /signing-providers/{id}` and `PUT /signing-providers/{id}` (`admin:account`):
//!   one provider's options: `enabled`, `required_qualifiers` (the `signatureQualifier`
//!   values one of which a credential must state, as the provider states them),
//!   `refuse_name_mismatch`, `session_minutes` (5 to 60), and `client_secret` when the
//!   account brought its own contract. The secret is write-only: stored sealed with
//!   AES-256-GCM under `OPENSEAL_PROVIDER_SECRETS_KEY`, bound to this account and
//!   provider, never returned (`own_client_secret` says whether one is set); `null`
//!   removes it. Each change is a `workspace.signing_provider_changed` admin event.
//!
//! A provider the catalogue does not list, or does not offer this account, answers as a
//! missing object: `404 CS-API-0002`.

use axum::body::Bytes;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::Response;
use casual_sign_store::TenantTx;
use casual_sign_store::repo::signing::AccountProvider;
use serde::Deserialize;
use serde_json::{Value, json};

use super::json;
use crate::call::Call;
use crate::dto::parse;
use crate::error::ApiError;
use crate::state::AppState;

/// Most `required_qualifiers` (docs/21).
const MAX_QUALIFIERS: usize = 8;

fn qualifier_ok(q: &str) -> bool {
    (1..=64).contains(&q.len())
        && q.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

fn default_row(id: &str) -> AccountProvider {
    AccountProvider {
        provider_id: id.to_owned(),
        enabled: false,
        required_qualifiers: Vec::new(),
        refuse_name_mismatch: false,
        session_minutes: 15,
        client_secret_sealed: None,
    }
}

fn detail(p: &casual_sign_csc::Provider, row: &AccountProvider) -> Value {
    json!({
        "id": p.id,
        "name": p.name,
        "kind": p.kind.as_str(),
        "enabled": row.enabled,
        "required_qualifiers": row.required_qualifiers,
        "refuse_name_mismatch": row.refuse_name_mismatch,
        "session_minutes": row.session_minutes,
        "own_client_secret": row.client_secret_sealed.is_some(),
    })
}

/// Whether `provider` is in the catalogue, offered to the account and enabled by it: a
/// signer may then be given it (ADR-046 §3.1).
pub(crate) async fn usable(
    st: &AppState,
    tx: &mut TenantTx,
    account: &str,
    provider: &str,
) -> Result<bool, ApiError> {
    let Some(s) = st.signing() else {
        return Ok(false);
    };
    if !s
        .catalogue
        .get(provider)
        .is_some_and(|p| p.offered_to(account))
    {
        return Ok(false);
    }
    Ok(tx
        .signing()
        .provider(provider)
        .await?
        .is_some_and(|r| r.enabled))
}

/// `GET /signing-providers`.
pub(crate) async fn list(c: Call) -> Result<Response, ApiError> {
    let account = c.p.account.0.to_string();
    let Some(s) = c.st.signing() else {
        return Ok(json(StatusCode::OK, &json!({"items": []})));
    };
    let mut tx = c.tx().await?;
    let rows = tx.signing().providers().await?;
    tx.commit().await?;
    let items: Vec<Value> = s
        .catalogue
        .providers()
        .iter()
        .filter(|p| p.offered_to(&account))
        .map(|p| {
            let enabled = rows.iter().any(|r| r.provider_id == p.id && r.enabled);
            json!({"id": p.id, "name": p.name, "kind": p.kind.as_str(), "enabled": enabled})
        })
        .collect();
    Ok(json(StatusCode::OK, &json!({ "items": items })))
}

/// The catalogue's provider `id` offered to the caller's account, or `404`.
fn offered<'a>(
    s: &'a crate::state::SigningProviders,
    account: &str,
    id: &str,
) -> Result<&'a casual_sign_csc::Provider, ApiError> {
    s.catalogue
        .get(id)
        .filter(|p| p.offered_to(account))
        .ok_or_else(ApiError::not_found)
}

/// `GET /signing-providers/{id}`.
pub(crate) async fn get(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let account = c.p.account.0.to_string();
    let s = c.st.signing().ok_or_else(ApiError::not_found)?;
    let p = offered(&s, &account, &id)?;
    let mut tx = c.tx().await?;
    let row = tx
        .signing()
        .provider(&p.id)
        .await?
        .unwrap_or_else(|| default_row(&p.id));
    tx.commit().await?;
    Ok(json(StatusCode::OK, &detail(p, &row)))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderIn {
    enabled: bool,
    #[serde(default)]
    required_qualifiers: Option<Vec<String>>,
    #[serde(default)]
    refuse_name_mismatch: Option<bool>,
    #[serde(default)]
    session_minutes: Option<i32>,
    /// Absent: keep; `null`: remove; a string: replace.
    #[serde(default, deserialize_with = "present")]
    client_secret: Option<Option<String>>,
}

/// A member that may be `null`: absent is `None`, `null` is `Some(None)`.
fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(d).map(Some)
}

/// `PUT /signing-providers/{id}`.
pub(crate) async fn put(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let account = c.p.account.0.to_string();
    let s = c.st.signing().ok_or_else(ApiError::not_found)?;
    let p = offered(&s, &account, &id)?;
    let req: ProviderIn = parse(&body)?;
    let mut tx = c.tx().await?;
    let mut row = tx
        .signing()
        .provider(&p.id)
        .await?
        .unwrap_or_else(|| default_row(&p.id));
    row.enabled = req.enabled;
    if let Some(q) = req.required_qualifiers {
        if q.len() > MAX_QUALIFIERS {
            return Err(ApiError::invalid("/required_qualifiers"));
        }
        for (i, v) in q.iter().enumerate() {
            if !qualifier_ok(v) {
                return Err(ApiError::invalid(&format!("/required_qualifiers/{i}")));
            }
        }
        row.required_qualifiers = q;
    }
    if let Some(r) = req.refuse_name_mismatch {
        row.refuse_name_mismatch = r;
    }
    if let Some(m) = req.session_minutes {
        if !(5..=60).contains(&m) {
            return Err(ApiError::invalid("/session_minutes"));
        }
        row.session_minutes = m;
    }
    let sealed = match &req.client_secret {
        None => None,
        Some(None) => Some(None),
        Some(Some(secret)) => {
            if secret.is_empty()
                || secret.len() > casual_sign_csc::sealing::MAX_PLAINTEXT
                || secret.chars().any(char::is_control)
            {
                return Err(ApiError::invalid("/client_secret"));
            }
            let binding =
                casual_sign_csc::sealing::client_secret_binding(c.p.account.0.as_bytes(), &p.id);
            Some(Some(
                s.key
                    .seal(secret.as_bytes(), &binding)
                    .map_err(|_| ApiError::internal("provider secret"))?,
            ))
        }
    };
    let now = c.st.now();
    tx.signing()
        .put_provider(&row, sealed.as_ref().map(|o| o.as_deref()), now)
        .await?;
    if let Some(v) = sealed {
        row.client_secret_sealed = v;
    }
    tx.commit().await?;
    Ok(json(StatusCode::OK, &detail(p, &row)))
}
