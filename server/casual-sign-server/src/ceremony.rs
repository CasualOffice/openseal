//! The recipient ceremony (docs/40 §6), under `/s/{token}`: not public API.
//!
//! The token is the invitation's (or an embedded view's, or an in-person host's) 256-bit
//! secret; only its SHA-256 is stored (SEC-A01). Its first use (`POST /s/{token}/session`) binds it to
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
use casual_sign_audit::{AdoptionMethod, AuthMethod, EventData, Hash256, MarkKind};
use casual_sign_model::{FieldValue, Id};
use casual_sign_store::repo::documents::VersionKind;
use casual_sign_store::repo::recipients::TokenPurpose;
use casual_sign_store::{DocumentId, RecipientId, TenantTx};
use casual_sign_workflow::{Command, FieldEntry, Principal as WfPrincipal, ReassignTo};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::{json as json_resp, request_context, same_id};
use crate::apply::{Commands, Loaded, load, policy_of, run, uid};
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
    /// The member hosting an in-person signing, when the link is theirs (UXW-36):
    /// every command then runs as `InPersonHost`, never as the signer alone.
    host: Option<Id>,
    cmds: Commands,
    cookie: Option<String>,
    ip: ClientIp,
    geoip: Option<std::sync::Arc<crate::geo::GeoIp>>,
    /// The capture this request adopted, answered as `adoption_id`.
    adoption: Option<String>,
    /// Whether the cookie says `Secure` (the server's `secure_cookies`, as the staff
    /// session's: off only for plain-HTTP development on localhost).
    secure: bool,
    /// Who sent the envelope, as the view answers it (UXW-34).
    sender: Value,
    /// `/s/{token}`, the path the view's `consent_required.url` extends. The token is
    /// the caller's own, already resolved (URL-safe base64), so nothing new is revealed.
    link: String,
    /// The account's published disclosure text for the policy's ERSD, when there is
    /// one, with whether its text still hashes to the hash consent records (UXW-34).
    disclosure: Option<(casual_sign_store::repo::accounts::Disclosure, bool)>,
}

/// Who sent the envelope, for the recipient to judge whether the request is genuine
/// (docs/40 §6): the sending user's name and email as the account holds them now
/// (`null` once they are no longer a member), and the account's brand name, else its
/// name.
async fn sender_of(
    tx: &mut TenantTx,
    s: &casual_sign_workflow::EnvelopeState,
    acct: &casual_sign_store::repo::accounts::Account,
) -> Result<Value, ApiError> {
    let member = tx
        .users()
        .get(casual_sign_store::UserId(uid(&s.sender_user_id)?))
        .await?;
    let organisation = acct
        .settings
        .pointer("/branding/name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .unwrap_or(acct.name.as_str());
    Ok(json!({
        "name": member.as_ref().map(|m| m.name.get().clone()),
        "email": member.as_ref().map(|m| m.email.get().clone()),
        "organisation": organisation,
    }))
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
        // An in-person link acts as its host, who must still be an enabled member; it
        // records the host's sign-in, not an emailed link.
        let host = match (record.purpose, record.host_user_id) {
            (TokenPurpose::InPerson, Some(h)) => {
                let member = tx.users().get(h).await?.ok_or_else(ApiError::expired)?;
                if member.disabled_at.is_some() {
                    return Err(ApiError::expired());
                }
                Some(crate::apply::eid(h.0)?)
            }
            (TokenPurpose::InPerson, None) => return Err(ApiError::expired()),
            _ => None,
        };
        // An Inbox link (UXW-01) acts as the recipient, obtained by a signed-in member
        // who must still be an enabled member with the recipient's email; it records
        // that sign-in, not an emailed link.
        let signed_in = match (record.purpose, record.host_user_id) {
            (TokenPurpose::Account, Some(u)) => {
                let member = tx.users().get(u).await?.ok_or_else(ApiError::expired)?;
                if member.disabled_at.is_some()
                    || member.email.get().to_lowercase()
                        != r.spec.email.get().as_str().to_lowercase()
                {
                    return Err(ApiError::expired());
                }
                true
            }
            (TokenPurpose::Account, None) => return Err(ApiError::expired()),
            _ => false,
        };
        let first = if host.is_some() || signed_in {
            AuthMethod::AccountLogin
        } else {
            AuthMethod::EmailLink
        };
        let mut auth = vec![first];
        auth.extend(r.auth_passed.iter().copied().filter(|m| *m != first));
        let ctx = request_context(
            headers,
            ip,
            auth,
            Some(Hash256::digest(
                format!("recipient_token:{}", record.id).as_bytes(),
            )),
        );
        let acct = tx.account().get().await?;
        let policy = policy_of(&acct.settings);
        let sender = sender_of(&mut tx, &l.state, &acct).await?;
        let disclosure = match &policy.ersd {
            Some(e) => tx.account().disclosure(&e.hash.0).await?.map(|d| {
                let intact = same(&sha256(d.body.as_bytes()), &e.hash.0);
                (d, intact)
            }),
            None => None,
        };
        let cmds = Commands::new(None, now, ctx, policy);
        let _ = RecipientId(target.recipient_id.0);
        Ok(Open {
            tx,
            l,
            recipient,
            host,
            cmds,
            cookie: set_cookie,
            ip,
            geoip: st.0.geoip.get().cloned(),
            adoption: None,
            secure: st.config().secure_cookies,
            sender,
            link: format!("/s/{token}"),
            disclosure,
        })
    };
    inner.await.map_err(IntoResponse::into_response)
}

impl Open {
    /// The engine's `gate_ready` rule, checked before a write that would store or parse
    /// what the request carries (SEC-CER-01): a link alone never has an image, a file or
    /// a value stored, nor a PDF parsed, and never learns which field or document ids
    /// exist; the engine checks again when the command runs.
    fn ready(&self) -> Result<(), ApiError> {
        let r = self
            .l
            .state
            .recipient(&self.recipient)
            .ok_or_else(ApiError::expired)?;
        ready(r, &self.cmds.policy)
    }

    async fn run(&mut self, cmd: Command) -> Result<(), ApiError> {
        let principal = match &self.host {
            Some(user_id) => WfPrincipal::InPersonHost {
                user_id: user_id.clone(),
            },
            None => WfPrincipal::Recipient {
                recipient_id: self.recipient.clone(),
            },
        };
        let ctx = self.cmds.ctx(principal, None)?;
        run(&mut self.tx, &mut self.l, &cmd, &ctx).await?;
        Ok(())
    }

    /// Record where the signer was on this request's commands (GEO-01, docs/32 §2):
    /// when the envelope captures location (the setting before the command), the
    /// device's fix, else the IP approximation with the reason, else the reason alone;
    /// when it does not, nothing, whatever the request says.
    fn locate(&mut self, device: Option<&DeviceLocation>) {
        let capture = self.l.state.options.capture_location;
        self.cmds.request.location =
            crate::geo::evidence(device, capture, self.ip.0, self.geoip.as_deref())
                .map(casual_sign_audit::Personal);
    }

    /// Refuse a signature or initials value that does not name a capture this
    /// recipient adopted in this envelope (the seal job draws what the value names; a
    /// value naming anyone else's capture must never reach it).
    async fn check_marks<'v>(
        &mut self,
        values: impl Iterator<Item = (&'v FieldValue, String)>,
    ) -> Result<(), ApiError> {
        let mut mine: Option<Vec<String>> = None;
        for (v, at) in values {
            // An attachment value must name a file this recipient uploaded through
            // `PUT …/fields/{field}/attachment` (WEB-06): one of their fields holds it.
            if let FieldValue::Attachment(_) = v {
                let theirs = self.l.state.fields.0.iter().any(|f| {
                    f.recipient_id.as_ref() == Some(&self.recipient) && f.value.as_ref() == Some(v)
                });
                if !theirs {
                    return Err(ApiError::invalid(&at));
                }
                continue;
            }
            let FieldValue::Signature(id) = v else {
                continue;
            };
            if mine.is_none() {
                let chain = self.tx.audit().chain(self.l.id).await?;
                mine = Some(
                    chain
                        .events()
                        .iter()
                        .filter_map(|c| match &c.event.data {
                            EventData::RecipientSignatureAdopted {
                                recipient_id,
                                image_hash,
                                ..
                            } if *recipient_id == self.recipient => Some(image_hash.hex()),
                            _ => None,
                        })
                        .collect(),
                );
            }
            if !mine
                .as_ref()
                .is_some_and(|m| m.iter().any(|h| h == id.as_str()))
            {
                return Err(ApiError::invalid(&at));
            }
        }
        Ok(())
    }

    fn view(&self) -> Value {
        let s = &self.l.state;
        let me = s.recipient(&self.recipient);
        let mut v = self.view_of(s, me);
        if let (Some(a), Some(o)) = (&self.adoption, v.as_object_mut()) {
            o.insert("adoption_id".into(), Value::String(a.clone()));
        }
        v
    }

    fn view_of(
        &self,
        s: &casual_sign_workflow::EnvelopeState,
        me: Option<&casual_sign_workflow::RecipientState>,
    ) -> Value {
        // SEC-CER-01: until the recipient has passed every authentication they need, the
        // view names no document and no field (only what the invitation already said,
        // and what the page needs to ask for the code).
        let shown = me.is_some_and(|r| !r.auth_locked && r.auth_satisfied());
        let documents: Vec<Value> = if shown {
            s.documents.iter().map(dto::document).collect()
        } else {
            Vec::new()
        };
        let fields: Vec<Value> = if shown {
            s.fields
                .0
                .iter()
                .filter(|f| f.recipient_id.as_ref() == Some(&self.recipient))
                .map(dto::field)
                .collect()
        } else {
            Vec::new()
        };
        let mut v = json!({
            "envelope": {
                "id": s.id, "status": s.status, "subject": s.subject.0, "message": s.message.0,
                "signing_options": s.options,
                "documents": documents,
                // When it expires, so the page can say "sign by" (UXW-34).
                "expires_at": s.expires_at,
            },
            "recipient": me.map(dto::recipient),
            "fields": fields,
            // Whether the page asks the device for its location (GEO-01); when false it
            // never asks.
            "capture_location": s.options.capture_location,
            "consent_required": self.cmds.policy.ersd.as_ref().map(|e| {
                let mut c = json!({"version": e.version, "sha256": e.hash});
                // Only when the text is published and intact (UXW-34): the page never
                // links to a disclosure it cannot read.
                if let (Some((_, true)), Some(o)) = (&self.disclosure, c.as_object_mut()) {
                    o.insert("url".into(), Value::String(format!("{}/disclosure", self.link)));
                }
                c
            }),
            "sender": self.sender,
            "auth_required": me.map(|r| r.spec.auth.iter().filter(|m| !r.auth_passed.contains(m)).copied().collect::<Vec<_>>()),
        });
        // VS-02: an agent, intermediary or editor names later recipients, so their view
        // lists the ones they may still change (later in the order, not yet reached),
        // once authenticated; nobody else's view has the member.
        if let (true, Some(r), Some(o)) = (
            shown && me.is_some_and(|r| r.spec.rtype.edits_recipients()),
            me,
            v.as_object_mut(),
        ) {
            let later: Vec<Value> = s
                .recipients
                .iter()
                .filter(|q| {
                    q.spec.routing_order > r.spec.routing_order
                        && q.status == casual_sign_model::RecipientStatus::Created
                })
                .map(|q| {
                    json!({
                        "id": q.spec.id, "type": q.spec.rtype,
                        "routing_order": q.spec.routing_order,
                        "name": q.spec.name.0, "email": q.spec.email.0,
                    })
                })
                .collect();
            o.insert("later_recipients".into(), Value::Array(later));
        }
        v
    }

    async fn finish(self, status: StatusCode) -> Result<Response, ApiError> {
        let body = self.view();
        let cookie = self.cookie.clone();
        self.tx.commit().await?;
        let mut r = json_resp(status, &body);
        if let Some(secret) = cookie
            && let Ok(v) = HeaderValue::from_str(&format!(
                "{CEREMONY_COOKIE}={secret}; Path=/s/; HttpOnly; SameSite=Strict{}",
                if self.secure { "; Secure" } else { "" }
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

/// A request body that may be empty and may carry the device's location.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocationIn {
    #[serde(default)]
    location: Option<DeviceLocation>,
}

fn location_in(body: &Bytes) -> Result<LocationIn, ApiError> {
    if body.iter().all(u8::is_ascii_whitespace) {
        Ok(LocationIn::default())
    } else {
        parse(body)
    }
}

/// `POST /s/{token}/session`: first use binds the link to this browser and records the
/// opening (`recipient.delivered`); later calls from the bound browser just answer. The
/// page cannot have asked the device yet (it learns the setting from this answer), so
/// with location capture on the opening records the IP approximation as `unavailable`
/// unless the body carries a location.
pub(crate) async fn session(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path(token): Path<String>,
    body: Bytes,
) -> Response {
    ceremony!(st, token, headers, ip, method, true, |o| {
        let req = location_in(&body)?;
        o.locate(req.location.as_ref());
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

/// `GET /s/{token}`: for a browser navigating to a signing link (`Accept: text/html`)
/// the web app's signing page, which then asks for the view below as JSON (row
/// WEB-04); otherwise the recipient's view. The page carries nothing of the envelope,
/// so serving it checks no token and records nothing.
pub(crate) async fn view_or_page(
    st: State<AppState>,
    ip: axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    token: Path<String>,
) -> Response {
    if crate::web::wants_page(&headers)
        && let Some(app) = st.webapp()
    {
        return crate::web::sign_page(app);
    }
    view(st, ip, method, headers, token).await
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
        o.locate(req.location.as_ref());
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

/// How long an email one-time code works (SEC-A02).
const OTP_TTL: time::Duration = time::Duration::minutes(10);
/// The shortest wait between two codes for one recipient.
const OTP_RESEND_AFTER: time::Duration = time::Duration::seconds(30);
/// Codes one recipient may be sent in an hour.
const OTP_PER_HOUR: i64 = 5;
/// Code requests per link, and per email address, in a minute.
const OTP_PER_MINUTE: u32 = 3;
/// Wrong tries that spend one code, whatever the account's lockout limit.
const OTP_TRIES: i32 = 5;

/// `POST /s/{token}/otp`: email the recipient a one-time code (SEC-A02), `202` with
/// the view. Records `recipient.auth_challenged` (`email_otp`) and queues the worker's
/// `send_email_otp` job, which draws the code, stores only its Argon2id hash and emails
/// it; any earlier code stops working. Limited per link and per address (3 a minute),
/// and per recipient (30 seconds apart, 5 an hour): `CS-API-0003` with `Retry-After`.
pub(crate) async fn otp_send(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path(token): Path<String>,
    body: Bytes,
) -> Response {
    let link = Hash256(sha256(token.as_bytes())).hex();
    if let Err(r) = limit(&st, "otp", &format!("otp-link:{link}"), OTP_PER_MINUTE) {
        return r;
    }
    let limiter = st.clone();
    ceremony!(st, token, headers, ip, method, false, |o| {
        let _ = location_in(&body)?;
        let r = o.recipient.clone();
        let me = o.l.state.recipient(&r).ok_or_else(ApiError::expired)?;
        if !me.spec.auth.contains(&AuthMethod::EmailOtp) {
            return Err(ApiError::method_unavailable());
        }
        if me.auth_passed.contains(&AuthMethod::EmailOtp) {
            return Err(ApiError::not_available("already authenticated"));
        }
        let email = me.spec.email.0.as_str().trim().to_lowercase();
        if email.is_empty() {
            return Err(ApiError::method_unavailable());
        }
        let addr = Hash256(sha256(email.as_bytes())).hex();
        let now = o.cmds.now;
        let d = limiter
            .0
            .limiter
            .hit(&format!("otp-addr:{addr}"), OTP_PER_MINUTE, now);
        if !d.allowed {
            return Err(ApiError::rate_limited(d.reset_secs));
        }
        let rid = RecipientId(uid(&r)?);
        let (recent, latest) =
            o.tx.recipients()
                .otp_history(rid, now.saturating_sub(time::Duration::HOUR))
                .await?;
        if let Some(l) = latest {
            let next = l.saturating_add(OTP_RESEND_AFTER);
            if now < next {
                let wait = next
                    .unix_timestamp()
                    .saturating_sub(now.unix_timestamp())
                    .max(1);
                return Err(ApiError::rate_limited(u64::try_from(wait).unwrap_or(30)));
            }
        }
        if recent >= OTP_PER_HOUR {
            return Err(ApiError::rate_limited(600));
        }
        o.run(Command::ChallengeAuth {
            recipient: r,
            method: AuthMethod::EmailOtp,
        })
        .await?;
        let code = uuid::Uuid::now_v7();
        o.tx.recipients()
            .open_otp(rid, code, now, now.saturating_add(OTP_TTL))
            .await?;
        let job = casual_sign_host::jobs::email_otp_job(
            casual_sign_store::JobId(uuid::Uuid::now_v7()),
            o.l.id,
            code,
            now,
        );
        o.tx.jobs().enqueue(&job).await?;
        Ok(StatusCode::ACCEPTED)
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OtpIn {
    code: String,
}

/// `POST /s/{token}/otp/verify {code}`: check the recipient's open email one-time code
/// (Argon2id, whose comparison is constant-time). A pass spends the code (a replay
/// fails) and records `recipient.auth_passed`; anything else (wrong, expired, spent,
/// none sent) records `recipient.auth_failed`, which the engine counts to the account's
/// lockout (`max_auth_attempts`), when it locks the recipient and revokes the link, as
/// for an access code. Five wrong tries spend a code whatever that limit.
pub(crate) async fn otp_verify(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path(token): Path<String>,
    body: Bytes,
) -> Response {
    ceremony!(st, token, headers, ip, method, false, |o| {
        let req: OtpIn = parse(&body)?;
        let r = o.recipient.clone();
        let rid = RecipientId(uid(&r)?);
        let now = o.cmds.now;
        let open = o.tx.recipients().open_otp_code(Some(rid), None).await?;
        let code = req.code.trim().to_owned();
        let well_formed = code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit());
        let mut passed = false;
        if let Some(c) = &open
            && let Some(phc) = c.code_hash.clone()
            && c.expires_at > now
            && well_formed
        {
            passed = tokio::task::spawn_blocking(move || verify_password(&code, &phc))
                .await
                .unwrap_or(false);
        }
        if let Some(c) = &open
            && c.code_hash.is_some()
        {
            if passed {
                o.tx.recipients()
                    .close_otp(
                        rid,
                        casual_sign_store::repo::recipients::OtpClosed::Used,
                        now,
                    )
                    .await?;
            } else if o.tx.recipients().otp_failed(c.id).await? >= OTP_TRIES {
                o.tx.recipients()
                    .close_otp(
                        rid,
                        casual_sign_store::repo::recipients::OtpClosed::Exhausted,
                        now,
                    )
                    .await?;
            }
        }
        o.run(Command::AuthResult {
            recipient: r.clone(),
            method: AuthMethod::EmailOtp,
            passed,
        })
        .await?;
        if o.l.state.recipient(&r).is_some_and(|x| x.auth_locked) {
            o.tx.recipients()
                .close_otp(
                    rid,
                    casual_sign_store::repo::recipients::OtpClosed::Revoked,
                    now,
                )
                .await?;
        }
        Ok(if passed {
            StatusCode::OK
        } else {
            StatusCode::FORBIDDEN
        })
    })
}

/// `GET /s/{token}/documents/{doc}/content`: the document as delivered (normalized).
/// Only in the browser the link is bound to, once the recipient has passed every
/// authentication they need and, when the account has a disclosure, consented to it
/// (`403` before, SEC-CER-01): the link alone never yields the document.
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
        // SEC-CER-01: the link alone never yields the document.
        ready(
            o.l.state
                .recipient(&o.recipient)
                .ok_or_else(ApiError::expired)?,
            &o.cmds.policy,
        )?;
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
pub(crate) struct DownloadQuery {
    #[serde(default)]
    doc: Option<String>,
}

/// `GET /s/{token}/document?doc=` (WEB-06): a recipient who has finished downloads
/// the document as it stands: the sealed version once the envelope completes, else the
/// preview of the values completed so far (`preview`), while the link is valid and in
/// the browser it is bound to. `doc` may be left out when the envelope has one
/// document. Recorded as `document.downloaded` by the recipient.
pub(crate) async fn download(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path(token): Path<String>,
    axum::extract::Query(q): axum::extract::Query<DownloadQuery>,
) -> Response {
    let mut o = match open(&st, &token, &headers, ip, &method, false).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    let result = async {
        let me =
            o.l.state
                .recipient(&o.recipient)
                .ok_or_else(ApiError::expired)?;
        authenticated(me)?;
        let finished = me.status == casual_sign_model::RecipientStatus::Completed;
        if !finished {
            return Err(ApiError::not_available(
                "the document can be downloaded once you have finished",
            ));
        }
        let docs = &o.l.state.documents;
        let d = match (&q.doc, docs.as_slice()) {
            (Some(doc), _) => docs.iter().find(|d| same_id(d.id(), doc)),
            (None, [only]) => Some(only),
            (None, _) => return Err(ApiError::invalid("/query/doc")),
        }
        .ok_or_else(ApiError::not_found)?
        .id()
        .clone();
        let state = o.l.state.clone();
        let (bytes, sealed) = crate::preview::current(&st, &mut o.tx, &state, &d).await?;
        o.run(Command::RecordAccess {
            access: casual_sign_workflow::Access::DocumentDownloaded {
                document: d,
                hash: Hash256::digest(&bytes),
            },
        })
        .await?;
        o.tx.commit().await?;
        Ok((bytes, sealed))
    }
    .await;
    match result {
        Ok((bytes, sealed)) => {
            let mut r = (StatusCode::OK, bytes).into_response();
            let h = r.headers_mut();
            h.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/pdf"),
            );
            h.insert(
                header::CONTENT_DISPOSITION,
                HeaderValue::from_static("attachment"),
            );
            h.insert(
                "x-openseal-document",
                HeaderValue::from_static(if sealed { "sealed" } else { "preview" }),
            );
            r
        }
        Err(e) => e.into_response(),
    }
}

/// `GET /s/{token}/certificate` (VS-01): a recipient who has finished downloads the
/// certificate of completion once the envelope is `completed`, the same sealed PDF the
/// sender downloads (`GET /envelopes/{id}/certificate`), so every party holds it, not only
/// the sender. While the link is valid and in the browser it is bound to; `409
/// CS-API-0009` before the recipient has finished or before the seal job has made it.
/// Recorded as `certificate.downloaded` by the recipient.
pub(crate) async fn certificate(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    let mut o = match open(&st, &token, &headers, ip, &method, false).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    let result = async {
        let me =
            o.l.state
                .recipient(&o.recipient)
                .ok_or_else(ApiError::expired)?;
        authenticated(me)?;
        if me.status != casual_sign_model::RecipientStatus::Completed {
            return Err(ApiError::not_available(
                "the certificate can be downloaded once you have finished",
            ));
        }
        if o.l.state.status != casual_sign_model::EnvelopeStatus::Completed {
            return Err(ApiError::not_available(
                "the certificate is made by the seal job when the envelope completes",
            ));
        }
        let sha = o.tx.envelopes().certificate(o.l.id).await?.ok_or_else(|| {
            ApiError::not_available(
                "the certificate is made by the seal job when the envelope completes",
            )
        })?;
        let bytes =
            st.0.blobs
                .get(&casual_sign_store::blob::BlobKey(sha))
                .await?;
        let hash = Hash256::digest(&bytes);
        if hash != Hash256(sha) {
            return Err(ApiError::internal("certificate"));
        }
        o.run(Command::RecordAccess {
            access: casual_sign_workflow::Access::CertificateDownloaded { hash },
        })
        .await?;
        o.tx.commit().await?;
        Ok(bytes)
    }
    .await;
    match result {
        Ok(bytes) => {
            let mut r = (StatusCode::OK, bytes).into_response();
            let h = r.headers_mut();
            h.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/pdf"),
            );
            h.insert(
                header::CONTENT_DISPOSITION,
                HeaderValue::from_static("attachment"),
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
        o.ready()?;
        let req: ViewedIn = parse(&body)?;
        o.locate(req.location.as_ref());
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
/// addressed), then the capture document naming it (`{"kind":"image","image":"<hex>"}`,
/// the seal job's contract, `casual_sign_worker::capture`), whose hash is recorded.
/// Answers `adoption_id`, that hash in hex: the value a signature or initials field
/// takes (`{"signature": "<adoption_id>"}`).
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
        o.ready()?;
        let req: AdoptIn = parse(&body)?;
        o.locate(req.location.as_ref());
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
        let capture = serde_json::to_vec(&json!({"kind": "image", "image": Hash256(key.0).hex()}))
            .map_err(|_| ApiError::internal("capture"))?;
        let capture = Hash256(st.0.blobs.put(&capture).await?.0);
        let r = o.recipient.clone();
        o.run(Command::AdoptSignature {
            recipient: r,
            mark: req.mark,
            method: req.method,
            image_hash: capture,
        })
        .await?;
        o.adoption = Some(capture.hex());
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
        o.ready()?;
        let f =
            o.l.state
                .fields
                .0
                .iter()
                .find(|f| same_id(&f.id, &field) && f.recipient_id.as_ref() == Some(&o.recipient))
                .map(|f| f.id.clone())
                .ok_or_else(ApiError::not_found)?;
        let req: FieldIn = parse(&body)?;
        o.check_marks(std::iter::once((&req.value, "/value".to_owned())))
            .await?;
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
struct AttachmentIn {
    content_base64: String,
}

/// Largest signer attachment, in bytes (docs/21, WEB-06).
pub(crate) const MAX_ATTACHMENT_BYTES: usize = 10 * 1024 * 1024;

/// `PUT /s/{token}/fields/{field}/attachment {content_base64}` (WEB-06): the signer
/// attaches a file to their attachment field. Admitted as a PDF (the bounded reader of
/// docs/30 §2, nothing in it run or followed) or a PNG or JPEG by its signature; stored
/// write-once by SHA-256, which is the field's value, so the chain's
/// `recipient.field_completed` binds the file. Listed by hash in the certificate of
/// completion; never drawn into or appended to the sealed document (evidence-safe:
/// the sealed document stays exactly what was delivered plus the values drawn).
pub(crate) async fn attach(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path((token, field)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    ceremony!(st, token, headers, ip, method, false, |o| {
        o.ready()?;
        let f =
            o.l.state
                .fields
                .0
                .iter()
                .find(|f| {
                    same_id(&f.id, &field)
                        && f.recipient_id.as_ref() == Some(&o.recipient)
                        && f.field_type == casual_sign_model::FieldType::Attachment
                })
                .map(|f| f.id.clone())
                .ok_or_else(ApiError::not_found)?;
        let req: AttachmentIn = parse(&body)?;
        if req.content_base64.len()
            > MAX_ATTACHMENT_BYTES
                .div_ceil(3)
                .saturating_mul(4)
                .saturating_add(4)
        {
            return Err(ApiError::too_large());
        }
        let bytes = STANDARD
            .decode(&req.content_base64)
            .map_err(|_| ApiError::invalid("/content_base64"))?;
        if bytes.is_empty() || bytes.len() > MAX_ATTACHMENT_BYTES {
            return Err(ApiError::invalid("/content_base64"));
        }
        match casual_sign_host::capture::media_type(&bytes) {
            "application/pdf" => {
                let engine = st.0.engine.clone();
                let b = bytes.clone();
                tokio::task::spawn_blocking(move || {
                    engine.admit(&b, &casual_sign_sdk::Credentials::default())
                })
                .await
                .map_err(|_| ApiError::internal("admission"))?
                .map_err(|_| ApiError::invalid("/content_base64"))?;
            }
            "image/png" | "image/jpeg" => {}
            _ => return Err(ApiError::invalid("/content_base64")),
        }
        let key = st.0.blobs.put(&bytes).await?;
        let id = Id::new(Hash256(key.0).hex()).map_err(|_| ApiError::internal("attachment"))?;
        let r = o.recipient.clone();
        o.run(Command::CompleteField {
            recipient: r,
            entry: FieldEntry {
                field: f,
                value: casual_sign_audit::Personal(FieldValue::Attachment(id)),
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
        o.locate(req.location.as_ref());
        o.check_marks(
            req.values
                .iter()
                .enumerate()
                .map(|(i, v)| (&v.value, format!("/values/{i}/value"))),
        )
        .await?;
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NamedIn {
    id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    email: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipientsIn {
    recipients: Vec<NamedIn>,
    #[serde(default)]
    location: Option<DeviceLocation>,
}

/// `POST /s/{token}/recipients {recipients: [{id, name?, email?}], location?}` (VS-02):
/// an agent (and an intermediary or editor) names later recipients before finishing,
/// the engine's `RecipientEdit` (docs/24 §3). Only recipients later in the order and
/// not yet reached may be changed, and an agent changes only names and addresses (the
/// engine refuses anything else); the chain records `envelope.corrected` with the
/// recipient as actor. Answers the view, whose `later_recipients` shows the result.
pub(crate) async fn recipients(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path(token): Path<String>,
    body: Bytes,
) -> Response {
    ceremony!(st, token, headers, ip, method, false, |o| {
        // SEC-CER-01: a link alone never learns which recipient ids exist.
        o.ready()?;
        let me = o.recipient.clone();
        if !o
            .l
            .state
            .recipient(&me)
            .is_some_and(|r| r.spec.rtype.edits_recipients())
        {
            // The engine's own refusal, before any id is looked up.
            o.run(Command::RecipientEdit {
                recipient: me,
                changes: Vec::new(),
            })
            .await?;
            return Err(ApiError::not_found());
        }
        let req: RecipientsIn = parse(&body)?;
        o.locate(req.location.as_ref());
        if req.recipients.is_empty() || req.recipients.len() > MAX_NAMED {
            return Err(ApiError::invalid("/recipients"));
        }
        let mut changes = Vec::with_capacity(req.recipients.len());
        for (i, n) in req.recipients.iter().enumerate() {
            let at = format!("/recipients/{i}");
            let mut spec =
                o.l.state
                    .recipients
                    .iter()
                    .find(|r| same_id(r.id(), &n.id))
                    .map(|r| r.spec.clone())
                    .ok_or_else(ApiError::not_found)?;
            if let Some(name) = &n.name {
                let name = name.trim();
                if name.is_empty() || name.chars().count() > 255 {
                    return Err(ApiError::invalid(&format!("{at}/name")));
                }
                spec.name = casual_sign_audit::Personal(
                    casual_sign_model::Text::new(name)
                        .map_err(|_| ApiError::invalid(&format!("{at}/name")))?,
                );
            }
            if let Some(e) = &n.email {
                let e = e.trim();
                if e.len() < 3 || e.len() > 320 || !e.contains('@') {
                    return Err(ApiError::invalid(&format!("{at}/email")));
                }
                spec.email = casual_sign_audit::Personal(
                    casual_sign_model::Text::new(e)
                        .map_err(|_| ApiError::invalid(&format!("{at}/email")))?,
                );
            }
            changes.push(casual_sign_workflow::Change::UpdateRecipient { recipient: spec });
        }
        let r = o.recipient.clone();
        o.run(Command::RecipientEdit {
            recipient: r,
            changes,
        })
        .await?;
        Ok(StatusCode::OK)
    })
}

/// Most recipients one `POST /s/{token}/recipients` names (docs/21).
pub(crate) const MAX_NAMED: usize = 100;

/// `POST /s/{token}/approve`.
pub(crate) async fn approve(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path(token): Path<String>,
    body: Bytes,
) -> Response {
    ceremony!(st, token, headers, ip, method, false, |o| {
        let req = location_in(&body)?;
        o.locate(req.location.as_ref());
        let r = o.recipient.clone();
        o.run(Command::Approve { recipient: r }).await?;
        Ok(StatusCode::OK)
    })
}

/// `POST /s/{token}/withdraw-consent`: withdraw consent to electronic records; for a
/// recipient with a required action this declines (docs/24 §3).
pub(crate) async fn withdraw_consent(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path(token): Path<String>,
    body: Bytes,
) -> Response {
    ceremony!(st, token, headers, ip, method, false, |o| {
        let req = location_in(&body)?;
        o.locate(req.location.as_ref());
        let r = o.recipient.clone();
        o.run(Command::WithdrawConsent { recipient: r }).await?;
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
        o.locate(req.location.as_ref());
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
    #[serde(default)]
    location: Option<DeviceLocation>,
}

/// `POST /s/{token}/reassign {name, email, reason?, location?}` (WEB-07): the engine's
/// `Reassign` (docs/24): only when the envelope's `signing_options.allow_reassign`
/// is on and this recipient has a required action they have not finished. The new
/// recipient takes the same routing order and fields (values cleared) and is invited
/// when their turn has come; this link is revoked in the same transaction; the chain
/// records `recipient.reassigned` with the reason and, when the envelope captures
/// location, where.
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
        o.locate(req.location.as_ref());
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

/// The events every recipient may see in their history: the envelope's milestones.
const MILESTONES: &[&str] = &[
    "envelope.sent",
    "envelope.corrected",
    "envelope.voided",
    "envelope.declined",
    "envelope.expired",
    "envelope.completing",
    "envelope.completed",
];

/// Who acted, as a recipient's history says it: never another person's identity.
fn by(actor: &Value, me: &str) -> &'static str {
    match actor.get("kind").and_then(Value::as_str) {
        Some("recipient") if actor.get("id").and_then(Value::as_str) == Some(me) => "you",
        Some("recipient") => "recipient",
        Some("sender") => "sender",
        Some("user") => "user",
        Some("host") => "host",
        _ => "system",
    }
}

/// `GET /s/{token}/history` (WEB-07): the envelope's history as this recipient may see
/// it: the events they acted in or that concern them (`data.recipient_id`), and the
/// envelope's milestones (sent, corrected, voided, declined, expired, completing,
/// completed) from the first `envelope.sent` on, so a draft's own edits never read
/// as a correction (WEB-14), oldest first, as `{seq, type, at, by}`: `by` is `you`, `sender`,
/// `recipient` (another, unnamed), `user`, `host` or `system`. Nothing else of any
/// event is answered: no names, addresses, IPs, user agents, locations or values.
/// Only in the browser the link is bound to, once the recipient has passed every
/// authentication they need and, when the account has a disclosure, consented to it
/// (`403` before); still available after they finished or declined, while the link
/// is valid. The chain is verified as it is read. Reading it records nothing
/// (docs/32 §3 lists no access event for it) and changes nothing.
pub(crate) async fn history(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    let mut o = match open(&st, &token, &headers, ip, &method, false).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    let result = async {
        let r =
            o.l.state
                .recipient(&o.recipient)
                .ok_or_else(ApiError::expired)?;
        ready(r, &o.cmds.policy)?;
        // `chain` re-verifies every link; a broken chain is an error, never served.
        let _ = o.tx.audit().chain(o.l.id).await?;
        let events = o.tx.audit().events(o.l.id).await?;
        let me = o.recipient.as_str();
        // Before the first `envelope.sent` the envelope was a draft: the engine records a
        // draft's own edits as `envelope.corrected` (docs/24 As built), which is no
        // correction of anything a recipient received, so no milestone shows until it
        // was sent (WEB-14).
        let mut sent = false;
        let items: Vec<Value> = events
            .iter()
            .filter_map(|e| {
                sent |= e.event_type == "envelope.sent";
                let v: Value = serde_json::from_slice(&e.canonical).ok()?;
                let actor = v.get("actor").cloned().unwrap_or(Value::Null);
                let by = by(&actor, me);
                let concerns = v
                    .get("data")
                    .and_then(|d| d.get("recipient_id"))
                    .and_then(Value::as_str)
                    == Some(me);
                let milestone = sent && MILESTONES.contains(&e.event_type.as_str());
                let shown = by == "you" || concerns || milestone;
                shown.then(|| {
                    json!({
                        "seq": e.seq,
                        "type": e.event_type,
                        "at": crate::api::envelopes::rfc3339(e.at),
                        "by": by,
                    })
                })
            })
            .collect();
        Ok::<_, ApiError>(json!({ "events": items }))
    }
    .await;
    match result {
        Ok(v) => json_resp(StatusCode::OK, &v),
        Err(e) => e.into_response(),
    }
}

/// Refuse a recipient who is locked out or has not passed every authentication they
/// need (`CS-AUTH-0004`, `CS-AUTH-0003`): the engine's `gate_in` rule for consent,
/// applied to the reads that serve nothing but this recipient's ceremony.
fn authenticated(r: &casual_sign_workflow::RecipientState) -> Result<(), ApiError> {
    if r.auth_locked {
        return Err(casual_sign_workflow::WorkflowError::AuthLocked {
            recipient: r.id().clone(),
        }
        .into());
    }
    if !r.auth_satisfied() {
        return Err(casual_sign_workflow::WorkflowError::AuthRequired {
            recipient: r.id().clone(),
        }
        .into());
    }
    Ok(())
}

/// Refuse a recipient who is not [`authenticated`] or, when the account requires a
/// disclosure, has not consented to its current version (`CS-AUTH-0005`): the engine's
/// `gate_ready` rule, applied to the reads that serve the envelope's records (history,
/// the document), which ESIGN-style consent must precede.
fn ready(
    r: &casual_sign_workflow::RecipientState,
    policy: &casual_sign_workflow::Policy,
) -> Result<(), ApiError> {
    authenticated(r)?;
    if let Some(ersd) = &policy.ersd {
        let consented = r
            .consent
            .as_ref()
            .is_some_and(|c| c.ersd_version == ersd.version && c.ersd_hash == ersd.hash);
        if !consented {
            return Err(casual_sign_workflow::WorkflowError::ConsentRequired {
                recipient: r.id().clone(),
            }
            .into());
        }
    }
    Ok(())
}

/// `GET /s/{token}/disclosure` (UXW-34): the full disclosure (ERSD) the view's
/// `consent_required` names, `{version, sha256, text}`: `version` the label
/// `POST …/consent` takes, `sha256` over the text's UTF-8 (the hash consent records),
/// re-checked as it is read. The account's own published text, found by that hash;
/// `404 CS-API-0002` when the account requires no disclosure or has published no text
/// for it, `500 CS-API-0010` when the stored text no longer hashes to it (never served).
/// Under the rules consent has: only in the browser the link is bound to, and once the
/// recipient has passed every authentication they need (`403` before); still readable
/// after they finished or declined, while the link is valid. Records nothing (docs/32
/// §3 has no access event for reading the disclosure; accepting it is
/// `recipient.consented`) and changes nothing.
pub(crate) async fn disclosure(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    let o = match open(&st, &token, &headers, ip, &method, false).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    let result = (|| {
        let r =
            o.l.state
                .recipient(&o.recipient)
                .ok_or_else(ApiError::expired)?;
        authenticated(r)?;
        let ersd = o
            .cmds
            .policy
            .ersd
            .as_ref()
            .ok_or_else(ApiError::not_found)?;
        let (d, intact) = o.disclosure.as_ref().ok_or_else(ApiError::not_found)?;
        if !intact {
            return Err(ApiError::internal("disclosure hash"));
        }
        Ok::<_, ApiError>(json!({
            "version": ersd.version,
            "sha256": ersd.hash,
            "text": d.body,
        }))
    })();
    match result {
        Ok(v) => json_resp(StatusCode::OK, &v),
        Err(e) => e.into_response(),
    }
}

#[allow(dead_code)]
fn _ex(_: Ex) {}
