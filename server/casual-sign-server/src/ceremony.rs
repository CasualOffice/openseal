//! The recipient ceremony (docs/40 §6), under `/s/{token}`: not public API.
//!
//! The token is the invitation's (or an embedded view's) 256-bit secret; only its
//! SHA-256 is stored (SEC-A01). Its first use (`POST /s/{token}/session`) binds it to
//! this browser with a second secret in an `HttpOnly`, `SameSite=Strict` cookie; every
//! later call must carry that cookie (`CS-AUTH-0009` otherwise), so a forwarded or
//! leaked link opens nothing in another browser. Every call is rate-limited per token
//! and per client address, and every state change is a workflow command recorded in
//! the envelope's chain with the client's address, user agent, the link as the
//! authentication method, and a hash naming the token (never the token).
//!
//! State-changing calls must be `application/json`: a cross-site form cannot send that
//! without a CORS preflight, which this server never grants.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use casual_sign_audit::{AdoptionMethod, AuthMethod, Hash256, MarkKind};
use casual_sign_model::{FieldValue, Id};
use casual_sign_store::repo::documents::VersionKind;
use casual_sign_store::{DocumentId, RecipientId, TenantTx};
use casual_sign_workflow::{Command, FieldEntry, Principal as WfPrincipal, ReassignTo};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::{json as json_resp, request_context, same_id};
use crate::apply::{Commands, Loaded, load, policy, run, uid};
use crate::auth::cookie;
use crate::crypto::{random_secret, same, sha256, verify_password};
use crate::dto::{self, parse};
use crate::error::ApiError;
use crate::geo::DeviceLocation;
use crate::http::limit;
use crate::net::ClientIp;
use crate::state::AppState;

/// The cookie binding a ceremony link to a browser.
pub(crate) const CEREMONY_COOKIE: &str = "os_ceremony";

/// An opened ceremony: the recipient, their envelope (locked), and the transaction.
pub(crate) struct Open {
    tx: TenantTx,
    l: Loaded,
    recipient: Id,
    cmds: Commands,
    cookie: Option<String>,
}

fn json_body(method: &Method, headers: &HeaderMap) -> Result<(), ApiError> {
    if *method == Method::GET {
        return Ok(());
    }
    let ok = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|t| t.starts_with("application/json"));
    if ok {
        Ok(())
    } else {
        Err(ApiError::unsupported_media())
    }
}

async fn open(
    st: &AppState,
    token: &str,
    headers: &HeaderMap,
    ip: ClientIp,
    method: &Method,
    bind: bool,
) -> Result<Open, Response> {
    let hash = sha256(token.as_bytes());
    let hex = Hash256(hash).hex();
    let per = st.config().rate.ceremony_per_minute;
    limit(st, "ceremony", &format!("token:{hex}"), per)?;
    let ipkey = ip.0.map_or_else(
        || "none".to_owned(),
        |i| Hash256(sha256(i.to_string().as_bytes())).hex(),
    );
    limit(
        st,
        "ceremony",
        &format!("ceremony-ip:{ipkey}"),
        per.saturating_mul(4),
    )?;
    let inner = async {
        json_body(method, headers)?;
        if token.len() > 128 {
            return Err(ApiError::expired());
        }
        let now = st.now();
        let target = st
            .store()
            .entry_points()
            .resolve_recipient_token(&hash, now)
            .await?
            .ok_or_else(ApiError::expired)?;
        let mut tx = st.store().for_account(target.account_id).begin().await?;
        let record = tx
            .recipients()
            .token(&hash)
            .await?
            .ok_or_else(ApiError::expired)?;
        let presented = cookie(headers, CEREMONY_COOKIE).map(|c| sha256(c.as_bytes()));
        let mut set_cookie = None;
        match (record.session_sha256, presented) {
            (Some(bound), Some(p)) if same(&bound, &p) => {}
            (Some(_), _) => return Err(ApiError::other_browser()),
            (None, _) if bind => {
                let secret = random_secret()?;
                if !tx
                    .recipients()
                    .bind_token(record.id, &sha256(secret.as_bytes()), now)
                    .await?
                {
                    return Err(ApiError::other_browser());
                }
                set_cookie = Some(secret);
            }
            (None, _) => return Err(ApiError::other_browser()),
        }
        let l = load(&mut tx, target.envelope_id)
            .await?
            .ok_or_else(ApiError::expired)?;
        let recipient = l
            .state
            .recipients
            .iter()
            .find(|r| uid(r.id()).is_ok_and(|u| u == target.recipient_id.0))
            .map(|r| r.id().clone())
            .ok_or_else(ApiError::expired)?;
        let r = l
            .state
            .recipient(&recipient)
            .ok_or_else(ApiError::expired)?;
        let mut auth = vec![AuthMethod::EmailLink];
        auth.extend(
            r.auth_passed
                .iter()
                .copied()
                .filter(|m| *m != AuthMethod::EmailLink),
        );
        let ctx = request_context(
            headers,
            ip,
            auth,
            Some(Hash256::digest(
                format!("recipient_token:{}", record.id).as_bytes(),
            )),
        );
        let cmds = Commands::new(None, now, ctx, policy(&mut tx).await?);
        let _ = RecipientId(target.recipient_id.0);
        Ok(Open {
            tx,
            l,
            recipient,
            cmds,
            cookie: set_cookie,
        })
    };
    inner.await.map_err(IntoResponse::into_response)
}

impl Open {
    async fn run(&mut self, cmd: Command) -> Result<(), ApiError> {
        let ctx = self.cmds.ctx(
            WfPrincipal::Recipient {
                recipient_id: self.recipient.clone(),
            },
            None,
        )?;
        run(&mut self.tx, &mut self.l, &cmd, &ctx, self.cmds.now).await?;
        Ok(())
    }

    fn view(&self) -> Value {
        let s = &self.l.state;
        let me = s.recipient(&self.recipient);
        json!({
            "envelope": {
                "id": s.id, "status": s.status, "subject": s.subject.0, "message": s.message.0,
                "signing_options": s.options,
                "documents": s.documents.iter().map(dto::document).collect::<Vec<_>>(),
            },
            "recipient": me.map(dto::recipient),
            "fields": s.fields.0.iter()
                .filter(|f| f.recipient_id.as_ref() == Some(&self.recipient))
                .map(dto::field).collect::<Vec<_>>(),
            "consent_required": self.cmds.policy.ersd.as_ref().map(|e| json!({"version": e.version, "sha256": e.hash})),
            "auth_required": me.map(|r| r.spec.auth.iter().filter(|m| !r.auth_passed.contains(m)).copied().collect::<Vec<_>>()),
        })
    }

    async fn finish(self, status: StatusCode) -> Result<Response, ApiError> {
        let body = self.view();
        let cookie = self.cookie.clone();
        self.tx.commit().await?;
        let mut r = json_resp(status, &body);
        if let Some(secret) = cookie
            && let Ok(v) = HeaderValue::from_str(&format!(
                "{CEREMONY_COOKIE}={secret}; Path=/s/; HttpOnly; SameSite=Strict; Secure"
            ))
        {
            r.headers_mut().insert(header::SET_COOKIE, v);
        }
        Ok(r)
    }
}

/// Run `f` on an opened ceremony and answer its view.
macro_rules! ceremony {
    ($st:expr, $token:expr, $headers:expr, $ip:expr, $method:expr, $bind:expr, |$o:ident| $body:block) => {{
        let mut $o = match open(&$st, &$token, &$headers, $ip, &$method, $bind).await {
            Ok(o) => o,
            Err(r) => return r,
        };
        let result: Result<StatusCode, ApiError> = async { $body }.await;
        match result {
            Ok(status) => $o
                .finish(status)
                .await
                .unwrap_or_else(IntoResponse::into_response),
            Err(e) => e.into_response(),
        }
    }};
}

type Ex = (
    State<AppState>,
    axum::Extension<ClientIp>,
    Method,
    HeaderMap,
);

/// `POST /s/{token}/session`: first use binds the link to this browser and records the
/// opening (`recipient.delivered`); later calls from the bound browser just answer.
pub(crate) async fn session(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    ceremony!(st, token, headers, ip, method, true, |o| {
        let opened =
            o.l.state
                .recipient(&o.recipient)
                .is_some_and(|r| r.status != casual_sign_model::RecipientStatus::Sent);
        if !opened {
            let r = o.recipient.clone();
            o.run(Command::OpenLink { recipient: r }).await?;
        }
        Ok(StatusCode::OK)
    })
}

/// `GET /s/{token}`: the recipient's view.
pub(crate) async fn view(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    ceremony!(st, token, headers, ip, method, false, |o| {
        let _ = &mut o;
        Ok(StatusCode::OK)
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsentIn {
    ersd_version: String,
    #[serde(default)]
    location: Option<DeviceLocation>,
}

/// `POST /s/{token}/consent {ersd_version}`: accept the account's current disclosure.
pub(crate) async fn consent(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path(token): Path<String>,
    body: Bytes,
) -> Response {
    ceremony!(st, token, headers, ip, method, false, |o| {
        let req: ConsentIn = parse(&body)?;
        let _ = req.location;
        let ersd = o
            .cmds
            .policy
            .ersd
            .clone()
            .ok_or_else(|| ApiError::not_available("no disclosure configured"))?;
        if ersd.version.as_str() != req.ersd_version {
            return Err(ApiError::invalid("/ersd_version"));
        }
        let r = o.recipient.clone();
        o.run(Command::Consent {
            recipient: r,
            ersd_version: ersd.version,
            ersd_hash: ersd.hash,
        })
        .await?;
        Ok(StatusCode::OK)
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthIn {
    method: AuthMethod,
    code: String,
}

/// `POST /s/{token}/authenticate {method, code}`: an access code (Argon2id, SEC-A03).
/// The engine counts failures and locks after the account's limit. One-time codes by
/// email or SMS need the worker's delivery (slice 5): `CS-API-0014` until then.
pub(crate) async fn authenticate(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path(token): Path<String>,
    body: Bytes,
) -> Response {
    ceremony!(st, token, headers, ip, method, false, |o| {
        let req: AuthIn = parse(&body)?;
        if req.method != AuthMethod::AccessCode {
            return Err(ApiError::method_unavailable());
        }
        let r = o.recipient.clone();
        let phc = o.tx.recipients().access_code(RecipientId(uid(&r)?)).await?;
        o.run(Command::ChallengeAuth {
            recipient: r.clone(),
            method: req.method,
        })
        .await?;
        let code = req.code;
        let passed = match phc {
            Some(phc) => tokio::task::spawn_blocking(move || verify_password(&code, phc.get()))
                .await
                .unwrap_or(false),
            None => false,
        };
        o.run(Command::AuthResult {
            recipient: r,
            method: req.method,
            passed,
        })
        .await?;
        Ok(if passed {
            StatusCode::OK
        } else {
            StatusCode::FORBIDDEN
        })
    })
}

/// `GET /s/{token}/documents/{doc}/content`: the document as delivered (normalized).
pub(crate) async fn document(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path((token, doc)): Path<(String, String)>,
) -> Response {
    let mut o = match open(&st, &token, &headers, ip, &method, false).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    let result = async {
        let d =
            o.l.state
                .documents
                .iter()
                .find(|d| same_id(d.id(), &doc))
                .ok_or_else(ApiError::not_found)?;
        let versions = o.tx.documents().versions(DocumentId(uid(d.id())?)).await?;
        let v = versions
            .iter()
            .rev()
            .find(|v| {
                v.version.kind == VersionKind::Normalized
                    && v.version.sha256 == d.spec.delivered_hash.0
            })
            .ok_or_else(ApiError::not_found)?;
        st.0.blobs
            .get(&casual_sign_store::blob::BlobKey(v.version.sha256))
            .await
    }
    .await;
    match result {
        Ok(bytes) => {
            let mut r = (StatusCode::OK, bytes).into_response();
            r.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/pdf"),
            );
            r
        }
        Err(e) => e.into_response(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewedIn {
    pages_seen: Vec<u32>,
    #[serde(default)]
    location: Option<DeviceLocation>,
}

/// `POST /s/{token}/documents/{doc}/viewed {pages_seen}`.
pub(crate) async fn viewed(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path((token, doc)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    ceremony!(st, token, headers, ip, method, false, |o| {
        let req: ViewedIn = parse(&body)?;
        let _ = req.location;
        if req.pages_seen.len() > 5_000 {
            return Err(ApiError::invalid("/pages_seen"));
        }
        let d =
            o.l.state
                .documents
                .iter()
                .find(|d| same_id(d.id(), &doc))
                .ok_or_else(ApiError::not_found)?;
        let (document, hash) = (d.id().clone(), d.spec.delivered_hash);
        let r = o.recipient.clone();
        o.run(Command::ViewDocument {
            recipient: r,
            document,
            hash,
            pages_seen: req.pages_seen,
        })
        .await?;
        Ok(StatusCode::OK)
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdoptIn {
    mark: MarkKind,
    method: AdoptionMethod,
    /// PNG or JPEG.
    image_base64: String,
    #[serde(default)]
    location: Option<DeviceLocation>,
}

/// `POST /s/{token}/adopt {mark, method, image_base64}`: the image is stored (content
/// addressed) and its hash recorded. Answers `adoption_id`, the value a signature or
/// initials field takes (`{"signature": "<adoption_id>"}`).
pub(crate) async fn adopt(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path(token): Path<String>,
    body: Bytes,
) -> Response {
    let max = st.config().max_image_bytes;
    ceremony!(st, token, headers, ip, method, false, |o| {
        let req: AdoptIn = parse(&body)?;
        let _ = req.location;
        if req.image_base64.len().div_ceil(4) > max.div_ceil(3).saturating_add(1) {
            return Err(ApiError::too_large());
        }
        let image = STANDARD
            .decode(&req.image_base64)
            .map_err(|_| ApiError::invalid("/image_base64"))?;
        let png = image.starts_with(b"\x89PNG\r\n\x1a\n");
        let jpeg = image.starts_with(&[0xFF, 0xD8, 0xFF]);
        if image.len() > max || !(png || jpeg) {
            return Err(ApiError::invalid("/image_base64"));
        }
        let key = st.0.blobs.put(&image).await?;
        let r = o.recipient.clone();
        o.run(Command::AdoptSignature {
            recipient: r,
            mark: req.mark,
            method: req.method,
            image_hash: Hash256(key.0),
        })
        .await?;
        Ok(StatusCode::OK)
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FieldIn {
    value: FieldValue,
}

/// `PUT /s/{token}/fields/{field} {value}`.
pub(crate) async fn fill(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path((token, field)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    ceremony!(st, token, headers, ip, method, false, |o| {
        let f =
            o.l.state
                .fields
                .0
                .iter()
                .find(|f| same_id(&f.id, &field) && f.recipient_id.as_ref() == Some(&o.recipient))
                .map(|f| f.id.clone())
                .ok_or_else(ApiError::not_found)?;
        let req: FieldIn = parse(&body)?;
        let r = o.recipient.clone();
        o.run(Command::CompleteField {
            recipient: r,
            entry: FieldEntry {
                field: f,
                value: casual_sign_audit::Personal(req.value),
            },
        })
        .await?;
        Ok(StatusCode::OK)
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValueIn {
    field: String,
    value: FieldValue,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinishIn {
    #[serde(default)]
    values: Vec<ValueIn>,
    #[serde(default)]
    location: Option<DeviceLocation>,
}

/// `POST /s/{token}/finish {values?}`: sign (or complete, for a viewer or agent).
pub(crate) async fn finish(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path(token): Path<String>,
    body: Bytes,
) -> Response {
    ceremony!(st, token, headers, ip, method, false, |o| {
        let req: FinishIn = parse(&body)?;
        let _ = req.location;
        let mut values = Vec::with_capacity(req.values.len());
        for (i, v) in req.values.into_iter().enumerate() {
            let f =
                Id::new(v.field).map_err(|_| ApiError::invalid(&format!("/values/{i}/field")))?;
            values.push(FieldEntry {
                field: f,
                value: casual_sign_audit::Personal(v.value),
            });
        }
        let r = o.recipient.clone();
        o.run(Command::Finish {
            recipient: r,
            values,
        })
        .await?;
        Ok(StatusCode::OK)
    })
}

/// `POST /s/{token}/approve`.
pub(crate) async fn approve(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    ceremony!(st, token, headers, ip, method, false, |o| {
        let r = o.recipient.clone();
        o.run(Command::Approve { recipient: r }).await?;
        Ok(StatusCode::OK)
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclineIn {
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    location: Option<DeviceLocation>,
}

/// `POST /s/{token}/decline {reason?}`.
pub(crate) async fn decline(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path(token): Path<String>,
    body: Bytes,
) -> Response {
    ceremony!(st, token, headers, ip, method, false, |o| {
        let req: DeclineIn = parse(&body)?;
        let _ = req.location;
        let reason = req.reason.as_deref().map(dto::message).transpose()?;
        let r = o.recipient.clone();
        o.run(Command::Decline {
            recipient: r,
            reason,
        })
        .await?;
        Ok(StatusCode::OK)
    })
}

/// `POST /s/{token}/finish-later`.
pub(crate) async fn finish_later(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    ceremony!(st, token, headers, ip, method, false, |o| {
        let r = o.recipient.clone();
        o.run(Command::FinishLater { recipient: r }).await?;
        Ok(StatusCode::OK)
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReassignIn {
    name: String,
    email: String,
    #[serde(default)]
    reason: Option<String>,
}

/// `POST /s/{token}/reassign {name, email, reason?}`.
pub(crate) async fn reassign(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path(token): Path<String>,
    body: Bytes,
) -> Response {
    ceremony!(st, token, headers, ip, method, false, |o| {
        let req: ReassignIn = parse(&body)?;
        let name = req.name.trim();
        if name.is_empty() || name.chars().count() > 255 {
            return Err(ApiError::invalid("/name"));
        }
        if req.email.len() < 3 || req.email.len() > 320 || !req.email.contains('@') {
            return Err(ApiError::invalid("/email"));
        }
        let to = ReassignTo {
            id: crate::apply::eid(uuid::Uuid::now_v7())?,
            name: dto::subject(name)?,
            email: dto::subject(&req.email)?,
            phone: None,
            delivery: None,
        };
        let reason = req.reason.as_deref().map(dto::message).transpose()?;
        let r = o.recipient.clone();
        o.run(Command::Reassign {
            recipient: r,
            to,
            reason,
        })
        .await?;
        Ok(StatusCode::OK)
    })
}

#[allow(dead_code)]
fn _ex(_: Ex) {}
