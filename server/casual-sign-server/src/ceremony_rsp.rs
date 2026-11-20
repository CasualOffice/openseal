//! The signer's side of a remote signing session (`RSP-01`, ADR-046 §3.4): start,
//! the provider's return, the state the page polls, authorizing the prepared hashes,
//! the prepared bytes, and cancel. The worker does the provider work (`remote_signing`
//! jobs); here the session's `state` is bound, checked and spent, and the code handed on
//! sealed.
//!
//! The provider sends the browser back to one address (`{OPENSEAL_PUBLIC_URL}/s/rsp`),
//! which cannot carry the signing link; the page keeps the link in the tab's session
//! storage, as RAUTH-01's sign-in does, and posts `state` and `code` here.
//!
//! - `POST /s/{token}/remote-signing {values, location?}`: `BeginRemoteSigning` (values
//!   checked and frozen), a session opened with a new `state` (kept as SHA-256) and PKCE
//!   verifier (sealed), answered with `remote_authorization_url` (scope `service`). A
//!   session left open past its time is failed `expired` first.
//! - `POST …/remote-signing/callback {state, code?, error?}`: the open session whose
//!   `state` this is, in the step it was sent for, within its time, spent once; the code
//!   and verifier sealed for the worker, which is queued. Anything else is
//!   `409 CS-RSP-0003` and nothing is kept. An `error` (the signer refused at the
//!   provider) fails the session `cancelled`.
//! - `GET …/remote-signing`: the view with `remote_signing {status, failure,
//!   provider}`.
//! - `POST …/remote-signing/authorize`: once prepared, a new `state` and verifier and
//!   `remote_authorization_url` with scope `credential` binding the prepared hashes.
//! - `GET …/remote-signing/documents/{id}`: the exact prepared bytes of a document.
//! - `POST …/remote-signing/cancel`: the signer stops; the session fails `cancelled`.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use casual_sign_audit::{Personal, RemoteFailure, RemoteProvider};
use casual_sign_csc::client::{Scope, authorization_url, pkce_challenge, pkce_verifier};
use casual_sign_model::{FieldValue, Id};
use casual_sign_store::repo::signing::{RemoteSession, SessionStatus};
use casual_sign_store::{EnvelopeId, RecipientId};
use casual_sign_workflow::{Command, FieldEntry};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Open, open};
use crate::apply::uid;
use crate::crypto::{random_secret, sha256};
use crate::dto::parse;
use crate::error::ApiError;
use crate::geo::DeviceLocation;
use crate::net::ClientIp;
use crate::state::AppState;

fn no_session() -> ApiError {
    ApiError::remote(StatusCode::CONFLICT, "CS-RSP-0003", None)
}

fn unavailable() -> ApiError {
    ApiError::remote(StatusCode::CONFLICT, "CS-RSP-0001", None)
}

fn session_id(s: &RemoteSession) -> Result<Id, ApiError> {
    Id::new(s.id.to_string()).map_err(|_| ApiError::internal("session"))
}

impl Open {
    /// The recipient's latest session.
    async fn latest_session(&mut self) -> Result<Option<RemoteSession>, ApiError> {
        let rid = RecipientId(uid(&self.recipient)?);
        Ok(self.tx.signing().latest_for(rid).await?)
    }

    /// Fail the recipient's open session with `reason` (engine and row).
    async fn fail_session(
        &mut self,
        s: &RemoteSession,
        reason: RemoteFailure,
        provider_code: Option<&str>,
    ) -> Result<(), ApiError> {
        let r = self.recipient.clone();
        let sid = session_id(s)?;
        if self
            .l
            .state
            .recipient(&r)
            .and_then(|x| x.remote.as_ref())
            .is_some_and(|x| x.session == sid)
        {
            self.run(Command::FailRemoteSigning {
                recipient: r,
                session: sid,
                reason,
                provider_code: provider_code.map(str::to_owned),
            })
            .await?;
        }
        let text = serde_json::to_value(reason)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_else(|| "cancelled".into());
        let now = self.cmds.now;
        self.tx
            .signing()
            .close(s.id, Some(&text), provider_code, now)
            .await?;
        Ok(())
    }

    /// A session left open past its time fails `expired` (ADR-046 §3.12).
    async fn expire_stale(&mut self) -> Result<Option<RemoteSession>, ApiError> {
        let Some(s) = self.latest_session().await? else {
            return Ok(None);
        };
        if s.closed_at.is_none() && s.expires_at <= self.cmds.now {
            self.fail_session(&s, RemoteFailure::Expired, None).await?;
            return self.latest_session().await;
        }
        Ok(Some(s))
    }

    /// The provider of this recipient's signature type, offered and enabled.
    async fn provider(
        &mut self,
        st: &AppState,
    ) -> Result<(std::sync::Arc<crate::state::SigningProviders>, String, i32), ApiError> {
        let me = self
            .l
            .state
            .recipient(&self.recipient)
            .ok_or_else(ApiError::expired)?;
        let pid = me
            .spec
            .signature
            .provider()
            .ok_or_else(|| ApiError::remote(StatusCode::CONFLICT, "CS-RSP-0007", None))?
            .as_str()
            .to_owned();
        let s = st.signing().ok_or_else(unavailable)?;
        let account = self.l.state.account_id.as_str().to_owned();
        if !s
            .catalogue
            .get(&pid)
            .is_some_and(|p| p.offered_to(&account))
        {
            return Err(unavailable());
        }
        let row = self
            .tx
            .signing()
            .provider(&pid)
            .await?
            .filter(|r| r.enabled)
            .ok_or_else(unavailable)?;
        Ok((s, pid, row.session_minutes))
    }

    fn remote_state(&self, s: Option<&RemoteSession>, name: Option<&str>) -> Value {
        match s {
            None => Value::Null,
            Some(s) => json!({
                "session": s.id.to_string(),
                "status": s.status.as_str(),
                "failure": s.failure,
                "provider": name,
                "documents": s.prepared.as_ref()
                    .and_then(|p| p.get("documents"))
                    .and_then(Value::as_array)
                    .map(|d| d.iter().filter_map(|x| x.get("document_id").cloned()).collect::<Vec<_>>())
                    .unwrap_or_default(),
            }),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValueIn {
    field: String,
    value: FieldValue,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartIn {
    #[serde(default)]
    values: Vec<ValueIn>,
    #[serde(default)]
    location: Option<DeviceLocation>,
}

/// `POST /s/{token}/remote-signing`.
pub(crate) async fn start(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path(token): Path<String>,
    body: Bytes,
) -> Response {
    let link = casual_sign_audit::Hash256(sha256(token.as_bytes())).hex();
    if let Err(r) = crate::http::limit(&st, "rsp", &format!("rsp-link:{link}"), 5) {
        return r;
    }
    ceremony!(st, token, headers, ip, method, false, |o| {
        let req: StartIn = parse(&body)?;
        o.locate(req.location.as_ref());
        let (signing, pid, minutes) = o.provider(&st).await?;
        o.expire_stale().await?;
        o.check_marks(req.values.iter().enumerate().map(|(i, v)| {
            (
                &v.value,
                Some(v.field.as_str()),
                format!("/values/{i}/value"),
            )
        }))
        .await?;
        let mut values = Vec::with_capacity(req.values.len());
        for (i, v) in req.values.into_iter().enumerate() {
            let f =
                Id::new(v.field).map_err(|_| ApiError::invalid(&format!("/values/{i}/field")))?;
            values.push(FieldEntry {
                field: f,
                value: Personal(v.value),
            });
        }
        let p = signing.catalogue.get(&pid).ok_or_else(unavailable)?;
        let sid = uuid::Uuid::now_v7();
        let r = o.recipient.clone();
        o.run(Command::BeginRemoteSigning {
            recipient: r.clone(),
            session: Id::new(sid.to_string()).map_err(|_| ApiError::internal("session"))?,
            provider: RemoteProvider {
                id: Id::new(p.id.clone()).map_err(|_| ApiError::internal("provider"))?,
                kind: p.kind.as_str().to_owned(),
                name: p.name.clone(),
            },
            values,
        })
        .await?;
        let state = random_secret()?;
        let verifier = pkce_verifier().map_err(|_| ApiError::internal("pkce"))?;
        let acct = o.l.state.account_id.as_str().to_owned();
        let acct = uuid::Uuid::parse_str(&acct).map_err(|_| ApiError::internal("account"))?;
        let sealed = signing
            .key
            .seal(
                verifier.as_bytes(),
                &casual_sign_csc::sealing::session_binding(acct.as_bytes(), sid.as_bytes(), "pkce"),
            )
            .map_err(|_| ApiError::internal("seal"))?;
        let now = o.cmds.now;
        let envelope = EnvelopeId(uid(&o.l.state.id)?);
        o.tx.signing()
            .open_session(
                sid,
                envelope,
                RecipientId(uid(&r)?),
                &pid,
                &sha256(state.as_bytes()),
                &sealed,
                now,
                now.saturating_add(time::Duration::minutes(i64::from(minutes))),
            )
            .await?;
        o.remote_url = Some(authorization_url(
            p,
            &Scope::Service,
            &state,
            &pkce_challenge(&verifier),
        ));
        let s = o.latest_session().await?;
        o.remote = Some(o.remote_state(s.as_ref(), Some(&p.name)));
        Ok(StatusCode::OK)
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CallbackIn {
    state: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// `POST /s/{token}/remote-signing/callback`.
pub(crate) async fn callback(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path(token): Path<String>,
    body: Bytes,
) -> Response {
    ceremony!(st, token, headers, ip, method, false, |o| {
        let req: CallbackIn = parse(&body)?;
        if req.state.is_empty() || req.state.len() > 256 {
            return Err(ApiError::invalid("/state"));
        }
        let signing = st.signing().ok_or_else(unavailable)?;
        let s = o.expire_stale().await?.ok_or_else(no_session)?;
        let hash = sha256(req.state.as_bytes());
        // The open session, sent for this step, with this `state`; else nothing is kept.
        let (expected, next, phase) = match s.status {
            SessionStatus::AuthorizingService => (s.status, SessionStatus::Preparing, "prepare"),
            SessionStatus::AuthorizingCredential => (s.status, SessionStatus::Signing, "sign"),
            _ => return Err(no_session()),
        };
        if s.closed_at.is_some() || s.state_sha256 != Some(hash) {
            return Err(no_session());
        }
        if let Some(err) = &req.error {
            let code: String = err
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || "_.-".contains(*c))
                .take(64)
                .collect();
            let reason = if code == "access_denied" {
                RemoteFailure::Cancelled
            } else {
                RemoteFailure::ProviderRefused
            };
            o.fail_session(&s, reason, Some(&code)).await?;
            let s = o.latest_session().await?;
            o.remote = Some(o.remote_state(s.as_ref(), None));
            return Ok(StatusCode::OK);
        }
        let code = req
            .code
            .filter(|c| !c.is_empty() && c.len() <= 2048)
            .ok_or_else(|| ApiError::invalid("/code"))?;
        let acct = uuid::Uuid::parse_str(o.l.state.account_id.as_str())
            .map_err(|_| ApiError::internal("account"))?;
        let pkce = s.pkce_sealed.clone().ok_or_else(no_session)?;
        let verifier = signing
            .key
            .open(
                &pkce,
                &casual_sign_csc::sealing::session_binding(
                    acct.as_bytes(),
                    s.id.as_bytes(),
                    "pkce",
                ),
            )
            .map_err(|_| no_session())?;
        let verifier = String::from_utf8(verifier).map_err(|_| no_session())?;
        let both = serde_json::to_vec(&json!({"code": code, "verifier": verifier}))
            .map_err(|_| ApiError::internal("code"))?;
        let sealed = signing
            .key
            .seal(
                &both,
                &casual_sign_csc::sealing::session_binding(
                    acct.as_bytes(),
                    s.id.as_bytes(),
                    "code",
                ),
            )
            .map_err(|_| ApiError::internal("seal"))?;
        let now = o.cmds.now;
        let rid = RecipientId(uid(&o.recipient)?);
        let taken =
            o.tx.signing()
                .take_state(rid, &hash, expected, &sealed, next, now)
                .await?;
        if taken.is_none() {
            return Err(no_session());
        }
        let envelope = EnvelopeId(uid(&o.l.state.id)?);
        o.tx.jobs()
            .enqueue(&casual_sign_host::jobs::remote_signing_job(
                casual_sign_store::JobId(uuid::Uuid::now_v7()),
                envelope,
                s.id,
                phase,
                now,
            ))
            .await?;
        let s = o.latest_session().await?;
        o.remote = Some(o.remote_state(s.as_ref(), None));
        Ok(StatusCode::OK)
    })
}

/// `GET /s/{token}/remote-signing`.
pub(crate) async fn status(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    ceremony!(st, token, headers, ip, method, false, |o| {
        let s = o.expire_stale().await?;
        let name = st.signing().and_then(|g| {
            s.as_ref()
                .and_then(|x| g.catalogue.get(&x.provider_id).map(|p| p.name.clone()))
        });
        o.remote = Some(o.remote_state(s.as_ref(), name.as_deref()));
        Ok(StatusCode::OK)
    })
}

/// `POST /s/{token}/remote-signing/authorize`.
pub(crate) async fn authorize(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    ceremony!(st, token, headers, ip, method, false, |o| {
        let signing = st.signing().ok_or_else(unavailable)?;
        let s = o.expire_stale().await?.ok_or_else(no_session)?;
        if s.closed_at.is_some() || s.status != SessionStatus::Prepared {
            return Err(no_session());
        }
        let p = signing
            .catalogue
            .get(&s.provider_id)
            .ok_or_else(unavailable)?;
        let prepared = s.prepared.clone().ok_or_else(no_session)?;
        let credential = prepared
            .get("credential_id")
            .and_then(Value::as_str)
            .ok_or_else(no_session)?
            .to_owned();
        let hashes: Vec<Vec<u8>> = prepared
            .get("documents")
            .and_then(Value::as_array)
            .ok_or_else(no_session)?
            .iter()
            .filter_map(|d| d.get("to_be_signed").and_then(Value::as_str))
            .filter_map(|b| {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.decode(b).ok()
            })
            .collect();
        if hashes.is_empty() {
            return Err(no_session());
        }
        let state = random_secret()?;
        let verifier = pkce_verifier().map_err(|_| ApiError::internal("pkce"))?;
        let acct = uuid::Uuid::parse_str(o.l.state.account_id.as_str())
            .map_err(|_| ApiError::internal("account"))?;
        let sealed = signing
            .key
            .seal(
                verifier.as_bytes(),
                &casual_sign_csc::sealing::session_binding(
                    acct.as_bytes(),
                    s.id.as_bytes(),
                    "pkce",
                ),
            )
            .map_err(|_| ApiError::internal("seal"))?;
        o.tx.signing()
            .advance(
                s.id,
                SessionStatus::AuthorizingCredential,
                Some(&sha256(state.as_bytes())),
                Some(&sealed),
                None,
                None,
                None,
            )
            .await?;
        o.remote_url = Some(authorization_url(
            p,
            &Scope::Credential {
                credential_id: &credential,
                hashes: &hashes,
                hash_algorithm_oid: casual_sign_csc::client::SHA256_OID,
            },
            &state,
            &pkce_challenge(&verifier),
        ));
        let s = o.latest_session().await?;
        o.remote = Some(o.remote_state(s.as_ref(), Some(&p.name)));
        Ok(StatusCode::OK)
    })
}

/// `POST /s/{token}/remote-signing/cancel`.
pub(crate) async fn cancel(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    ceremony!(st, token, headers, ip, method, false, |o| {
        let s = o.expire_stale().await?.ok_or_else(no_session)?;
        if s.closed_at.is_some() {
            return Err(no_session());
        }
        o.fail_session(&s, RemoteFailure::Cancelled, None).await?;
        let s = o.latest_session().await?;
        o.remote = Some(o.remote_state(s.as_ref(), None));
        Ok(StatusCode::OK)
    })
}

/// `GET /s/{token}/remote-signing/documents/{id}`: the exact prepared bytes.
pub(crate) async fn document(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path((token, doc)): Path<(String, String)>,
) -> Response {
    let mut o = match super::open(&st, &token, &headers, ip, &method, false).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    let found = async {
        let s = o.latest_session().await?.ok_or_else(no_session)?;
        if s.closed_at.is_some() {
            return Err(no_session());
        }
        let key = s
            .prepared
            .as_ref()
            .and_then(|p| p.get("documents"))
            .and_then(Value::as_array)
            .and_then(|d| {
                d.iter()
                    .find(|x| x.get("document_id").and_then(Value::as_str) == Some(doc.as_str()))
            })
            .and_then(|x| x.get("prepared"))
            .and_then(Value::as_str)
            .ok_or_else(ApiError::not_found)?
            .to_owned();
        let key =
            casual_sign_store::blob::BlobKey::parse(&key).map_err(|_| ApiError::not_found())?;
        let bytes =
            st.0.blobs
                .get(&key)
                .await
                .map_err(|_| ApiError::not_found())?;
        Ok::<_, ApiError>(bytes)
    }
    .await;
    match found {
        Ok(bytes) => {
            let _ = o.tx.rollback().await;
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/pdf"),
                    (
                        header::CONTENT_DISPOSITION,
                        "inline; filename=\"prepared.pdf\"",
                    ),
                ],
                bytes,
            )
                .into_response()
        }
        Err(e) => e.into_response(),
    }
}
