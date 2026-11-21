//! India eSign on the server (`RSP-02`, ADR-047 §3.1, §3.4, §3.6), OpenSeal the ASP.
//!
//! - **Consent.** The signing view of an eSign signer carries `remote_esign`: the
//!   versioned consent text (the points the v2.1 specification §3.3.1.1 lists, with the
//!   ESP's name), its version and the authentication modes offered. `POST
//!   /s/{token}/remote-signing` must carry `esign {consent, accepted: true, auth_mode}`;
//!   without the tick nothing is requested (`sc="Y"` is never sent on the platform's
//!   word), and the text's SHA-256 goes into `recipient.remote_signing_started`.
//! - **Hand-off.** Once prepared, `POST …/remote-signing/authorize` arms the next
//!   document's single-use answer and `GET …/remote-signing/esign` answers a small page
//!   whose form posts the signed request to the ESP in a top-level navigation (its own
//!   CSP allows the form to reach that ESP only).
//! - **The answer.** `POST /rsp/esign/{provider}/response` is public. It is rate-limited
//!   per provider and address, refuses a body over the limit before reading it, reads
//!   the answer within the eSign limits and verifies its XML Signature under the ESP's
//!   configured certificate, finds the open session its `txn` names, and spends that
//!   document's single-use state: a forged, wrapped, late, replayed or duplicate answer
//!   finds nothing and changes nothing. Every case answers the same way (a redirect to
//!   the signing page), for a known `txn` or not. The answer's bytes are kept with the
//!   evidence; once every document answered, the worker is queued.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use casual_sign_seclog::{Kind, Outcome, SecurityEvent, Value as SecValue};
use casual_sign_store::repo::signing::SessionStatus;
use casual_sign_store::{EnvelopeId, RecipientId};
use serde_json::{Value, json};

use crate::crypto::sha256;
use crate::error::ApiError;
use crate::net::ClientIp;
use crate::state::AppState;

/// The consent text's version (ADR-047 §3.1; counsel reviews it, `LEG-02`).
pub(crate) const CONSENT_VERSION: &str = "esign-consent-v1-en";

/// Largest answer body taken: a 512 KiB XML answer, form-encoded.
pub(crate) const MAX_ANSWER_BODY: usize = 1024 * 1024;

/// The consent the signer ticks before any request is made, with the ESP's name: the
/// points v2.1 §3.3.1.1 lists (identity and address from e-KYC, the certificate
/// application, a key made for one signature and then deleted), and that OpenSeal never
/// receives the Aadhaar number, VID, OTP or biometrics.
#[must_use]
pub(crate) fn consent_text(esp: &str) -> String {
    format!(
        "I consent to {esp} authenticating me through my e-KYC (Aadhaar or another e-KYC \
provider) and receiving my identity and address details for this purpose; applying on my behalf \
for a digital signature certificate in my name; generating a key pair to sign this document \
once; and deleting that key after signing. I will give my Aadhaar number or VID and my one-time \
password or biometrics to {esp} only, on its own page: OpenSeal never receives them."
    )
}

/// What the signing view says about an eSign signer's provider.
pub(crate) fn view_of(p: &casual_sign_csc::Provider) -> Option<Value> {
    let e = p.esign.as_ref()?;
    Some(json!({
        "consent_version": CONSENT_VERSION,
        "consent_text": consent_text(&p.name),
        "auth_modes": e.auth_modes,
    }))
}

/// The state hash spent by document `n`'s answer: the worker's rule
/// (`casual_sign_worker::worker::esign::response_state`), restated here because the
/// server does not depend on the worker.
#[must_use]
pub(crate) fn response_state(session: &str, n: usize) -> [u8; 32] {
    sha256(format!("openseal-esign-response-v1\n{session}\n{n}").as_bytes())
}

/// The session and document a `txn` names (`{session}.{n}`).
fn parse_txn(txn: &str) -> Option<(uuid::Uuid, usize)> {
    let (s, n) = txn.rsplit_once('.')?;
    let n: usize = n.parse().ok().filter(|n| (1..=64).contains(n))?;
    Some((uuid::Uuid::parse_str(s).ok()?, n))
}

/// The first document of a prepared record without an answer: `(n, total)`, 1-based.
pub(crate) fn next_document(prepared: &Value) -> Option<(usize, usize)> {
    let docs = prepared.get("documents")?.as_array()?;
    let n = docs.iter().position(|d| d.get("response").is_none())?;
    Some((n.saturating_add(1), docs.len()))
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// `scheme://host[:port]` of an allowed URL, for the hand-off page's `form-action`.
fn origin(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    (!host.is_empty() && !host.contains(['\'', ';', ' ', '"']))
        .then(|| format!("{scheme}://{host}"))
}

/// The hand-off page: a form posting the signed request to the ESP, submitted by
/// `/esign-handoff.js` or by its button.
fn handoff_page(
    esp: &str,
    action: &str,
    field: &str,
    request: &str,
    n: usize,
    of: usize,
) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<title>Continue to {esp}</title><link rel=\"stylesheet\" href=\"/esign-handoff.css\"></head>\
<body><main><h1>Continue to {esp}</h1><p>Document {n} of {of}. You sign at {esp}; OpenSeal never \
receives your Aadhaar number, VID, one-time password or biometrics.</p>\
<form id=\"esign\" method=\"post\" action=\"{action}\" data-testid=\"esign-handoff\">\
<input type=\"hidden\" name=\"{field}\" value=\"{request}\">\
<button type=\"submit\">Continue to {esp}</button></form></main>\
<script src=\"/esign-handoff.js\"></script></body></html>",
        esp = escape(esp),
        action = escape(action),
        field = escape(field),
        request = escape(request),
    )
}

/// `GET /s/{token}/remote-signing/esign`: the hand-off page for the armed document.
pub(crate) async fn handoff(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    method: Method,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    let mut o = match super::open(&st, &token, &headers, ip, &method, false).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    let found = async {
        let no = || ApiError::remote(StatusCode::CONFLICT, "CS-RSP-0003", None);
        let rid = RecipientId(crate::apply::uid(&o.recipient)?);
        let s = o.tx.signing().latest_for(rid).await?.ok_or_else(no)?;
        if s.closed_at.is_some() || s.status != SessionStatus::AuthorizingCredential {
            return Err(no());
        }
        let signing = st.signing().ok_or_else(no)?;
        let p = signing.catalogue.get(&s.provider_id).ok_or_else(no)?;
        let e = p.esign.as_ref().ok_or_else(no)?;
        let prepared = s.prepared.clone().ok_or_else(no)?;
        let (n, of) = next_document(&prepared).ok_or_else(no)?;
        let key = prepared
            .get("documents")
            .and_then(Value::as_array)
            .and_then(|d| d.get(n.saturating_sub(1)))
            .and_then(|d| d.get("request"))
            .and_then(Value::as_str)
            .ok_or_else(no)?;
        let key = casual_sign_store::blob::BlobKey::parse(key).map_err(|_| no())?;
        let xml = st.0.blobs.get(&key).await?;
        let xml = String::from_utf8(xml).map_err(|_| no())?;
        let action = e.esign_url.clone();
        let csp = format!(
            "default-src 'none'; script-src 'self'; style-src 'self'; base-uri 'none'; \
             frame-ancestors 'none'; form-action {}",
            origin(&action).ok_or_else(no)?
        );
        Ok::<_, ApiError>((
            handoff_page(&p.name, &action, &e.request_field, &xml, n, of),
            csp,
        ))
    }
    .await;
    let _ = o.tx.rollback().await;
    match found {
        Ok((page, csp)) => {
            let mut r = (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                page,
            )
                .into_response();
            if let Ok(v) = HeaderValue::from_str(&csp) {
                r.headers_mut().insert(header::CONTENT_SECURITY_POLICY, v);
            }
            r.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            r.headers_mut().insert(
                header::REFERRER_POLICY,
                HeaderValue::from_static("no-referrer"),
            );
            r
        }
        Err(e) => e.into_response(),
    }
}

/// Where every answer is sent back to: the signing page, which keeps the link in the
/// tab (`/s/rsp`, as RSP-01's return).
fn back(st: &AppState) -> Response {
    let to = format!(
        "{}/s/rsp?state=esign",
        st.config().public_url.trim_end_matches('/')
    );
    let mut r = StatusCode::SEE_OTHER.into_response();
    if let Ok(v) = HeaderValue::from_str(&to) {
        r.headers_mut().insert(header::LOCATION, v);
    }
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

fn refused(st: &AppState, provider: &str, code: &'static str, why: &'static str) {
    let mut ev = SecurityEvent::new(Kind::Denied, Outcome::Failure)
        .code(code)
        .with("reason", SecValue::Word(why));
    if let Some(l) = casual_sign_seclog::Label::new(provider) {
        ev = ev.with("provider", SecValue::Label(l));
    }
    crate::security::emit(st, ev);
}

/// The answer's XML from the body: the form field the catalogue names, or the body
/// itself when it is XML.
fn answer_xml(headers: &HeaderMap, body: &[u8], field: &str) -> Option<Vec<u8>> {
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    if ct.starts_with("application/xml") || ct.starts_with("text/xml") {
        return Some(body.to_vec());
    }
    let text = core::str::from_utf8(body).ok()?;
    for pair in text.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if crate::api::admin::form_decode(k).as_deref() == Some(field) {
            return crate::api::admin::form_decode(v).map(String::into_bytes);
        }
    }
    None
}

/// `POST /rsp/esign/{provider}/response`.
#[allow(clippy::too_many_lines)]
// The checks of ADR-047 §3.4 and §3.6, in order; each refusal answers as a success.
pub(crate) async fn response(
    State(st): State<AppState>,
    axum::Extension(ip): axum::Extension<ClientIp>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let who = ip.0.map_or_else(|| "unknown".to_owned(), |a| a.to_string());
    let key = format!("esign-answer:{provider}:{who}");
    if let Err(r) = crate::http::limit(&st, "rsp", &key, 30) {
        return r;
    }
    if body.len() > MAX_ANSWER_BODY {
        refused(&st, &provider, "CS-RSP-0004", "oversize");
        return back(&st);
    }
    let Some(signing) = st.signing() else {
        return back(&st);
    };
    let Some(p) = signing.catalogue.get(&provider) else {
        return back(&st);
    };
    let Some(e) = p.esign.as_ref() else {
        return back(&st);
    };
    let Some(xml) = answer_xml(&headers, &body, &e.response_field) else {
        refused(&st, &provider, "CS-RSP-0004", "no_answer");
        return back(&st);
    };
    let Ok(esp) = casual_sign_esign::VerifyingKey::from_certificate(&e.response_certificate) else {
        return back(&st);
    };
    let answer = match casual_sign_esign::response::read(&xml, &esp) {
        Ok(a) => a,
        Err(err) => {
            // Unsigned, wrongly signed, wrapped, DTD or entity, oversize: logged, ignored.
            refused(&st, &provider, err.code(), "answer_invalid");
            return back(&st);
        }
    };
    let Some((session, n)) = parse_txn(&answer.txn) else {
        refused(&st, &provider, "CS-RSP-0003", "txn");
        return back(&st);
    };
    let account = match st.store().esign_session_account(session, &provider).await {
        Ok(Some(a)) => a,
        _ => {
            refused(&st, &provider, "CS-RSP-0003", "no_open_session");
            return back(&st);
        }
    };
    let done = async {
        let mut tx = st.store().for_account(account).begin().await?;
        let Some(s) = tx.signing().session(session).await? else {
            return Ok::<_, ApiError>(false);
        };
        let Some(prepared) = s.prepared.clone() else {
            return Ok(false);
        };
        let total = prepared
            .get("documents")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        let last = n >= total || answer.status != casual_sign_esign::Status::Signed;
        let next = if last {
            SessionStatus::Signing
        } else {
            SessionStatus::Prepared
        };
        let acct = account.0;
        let marker = signing
            .key
            .seal(
                b"esign-answer",
                &casual_sign_csc::sealing::session_binding(
                    acct.as_bytes(),
                    session.as_bytes(),
                    "code",
                ),
            )
            .map_err(|_| ApiError::internal("seal"))?;
        let now = st.now();
        let state = response_state(&session.to_string(), n);
        // Spent once: a second, late or replayed answer finds nothing.
        let taken = tx
            .signing()
            .take_state(
                s.recipient_id,
                &state,
                SessionStatus::AuthorizingCredential,
                &marker,
                next,
                now,
            )
            .await?;
        if taken.is_none() {
            return Ok(false);
        }
        let blob = st.0.blobs.put(&xml).await?;
        let mut record = prepared;
        if let Some(d) = record
            .get_mut("documents")
            .and_then(Value::as_array_mut)
            .and_then(|d| d.get_mut(n.saturating_sub(1)))
            .and_then(Value::as_object_mut)
        {
            d.insert("response".into(), Value::String(blob.hex()));
        }
        tx.signing()
            .advance(s.id, next, None, None, None, None, Some(&record))
            .await?;
        if last {
            tx.jobs()
                .enqueue(&casual_sign_host::jobs::remote_signing_job(
                    casual_sign_store::JobId(uuid::Uuid::now_v7()),
                    EnvelopeId(s.envelope_id.0),
                    s.id,
                    "sign",
                    now,
                ))
                .await?;
        }
        tx.commit().await?;
        Ok(true)
    }
    .await;
    match done {
        Ok(true) => {}
        Ok(false) => refused(&st, &provider, "CS-RSP-0003", "late_or_duplicate"),
        Err(_) => refused(&st, &provider, "CS-RSP-0002", "store"),
    }
    back(&st)
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report (CLAUDE.md).
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn the_hand_off_page_escapes_the_request_and_allows_only_the_esps_origin() {
        let page = handoff_page(
            "ESP <x>",
            "https://esp.example.test/esign?a=1&b=2",
            "eSignRequest",
            "<Esign txn=\"1\"/>",
            1,
            2,
        );
        assert!(page.contains("value=\"&lt;Esign txn=&quot;1&quot;/&gt;\""));
        assert!(page.contains("ESP &lt;x&gt;"));
        assert!(!page.contains("<Esign"));
        assert_eq!(
            origin("https://esp.example.test:8443/x/y").as_deref(),
            Some("https://esp.example.test:8443")
        );
        assert_eq!(origin("https://a'; script-src *"), None);
    }

    #[test]
    fn the_server_and_worker_spend_the_same_state() {
        // The worker's rule, restated (casual-sign-worker esign.rs).
        let s = "0193a000-0000-7000-8000-0000000000e1";
        assert_eq!(
            response_state(s, 2),
            sha256(format!("openseal-esign-response-v1\n{s}\n2").as_bytes())
        );
        assert_eq!(parse_txn(&format!("{s}.2")).map(|x| x.1), Some(2));
        assert_eq!(parse_txn(s), None);
    }

    #[test]
    fn the_next_document_is_the_first_unanswered() {
        let v = json!({"documents": [{"response": "k"}, {}, {}]});
        assert_eq!(next_document(&v), Some((2, 3)));
        assert_eq!(
            next_document(&json!({"documents": [{"response": "k"}]})),
            None
        );
    }

    #[test]
    fn the_consent_names_the_esp_and_what_openseal_never_receives() {
        let t = consent_text("Example ESP");
        assert!(t.contains("Example ESP authenticating me"));
        assert!(t.contains("OpenSeal never receives them"));
    }
}
