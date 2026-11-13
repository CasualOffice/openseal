//! Wire shapes of `/api/v1` (docs/40 §3). Explicit, so an internal field of the engine's
//! state never reaches the API by accident (docs/22 §10): outputs are built field by
//! field, and inputs deny unknown fields.

use casual_sign_audit::{AuthMethod, Personal};
use casual_sign_model::{
    DateFormat, Delivery, Field, Id, RecipientType, ReminderPolicy, RoutingOrder, SealProfile,
    SigningOptions, Text,
};
use casual_sign_workflow::{DocumentState, EnvelopeState, RecipientSpec, RecipientState};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::error::{ApiError, FieldProblem};

/// Parse a JSON body, naming the failing location as a pointer (never the value).
pub(crate) fn parse<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    if body.is_empty() {
        return serde_json::from_slice(b"{}").map_err(|_| ApiError::malformed("empty body"));
    }
    serde_json::from_slice(body).map_err(|e| {
        if e.is_syntax() || e.is_eof() {
            ApiError::malformed("not JSON")
        } else {
            ApiError::invalid(&format!("/@{}:{}", e.line(), e.column()))
        }
    })
}

fn text(s: &str, pointer: &str) -> Result<Personal<Text>, ApiError> {
    Text::new(s)
        .map(Personal)
        .map_err(|_| ApiError::invalid(pointer))
}

/// A subject: at most 255 characters (docs/21).
pub(crate) fn subject(s: &str) -> Result<Personal<Text>, ApiError> {
    if s.chars().count() > 255 {
        return Err(ApiError::invalid("/subject"));
    }
    text(s, "/subject")
}

/// A message: at most 10,000 characters (docs/21) and the engine's 4,000 bytes.
pub(crate) fn message(s: &str) -> Result<Personal<Text>, ApiError> {
    if s.chars().count() > 10_000 {
        return Err(ApiError::invalid("/message"));
    }
    text(s, "/message")
}

/// A recipient as the API takes it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecipientIn {
    /// A name fields in the same request use to refer to this recipient.
    #[serde(default, rename = "ref")]
    pub reference: Option<String>,
    #[serde(rename = "type")]
    pub rtype: RecipientType,
    pub name: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default = "one")]
    pub routing_order: u32,
    #[serde(default)]
    pub delivery: Option<Delivery>,
    #[serde(default)]
    pub auth: Vec<AuthMethod>,
    /// The access code, when `auth` has `access_code`; stored only as Argon2id.
    #[serde(default)]
    pub access_code: Option<String>,
    #[serde(default)]
    pub embedded_client_user_id: Option<String>,
    #[serde(default)]
    pub time_zone_offset_minutes: i16,
    #[serde(default)]
    pub date_format: Option<DateFormat>,
}

fn one() -> u32 {
    1
}

/// Whether `p` is a phone number a code can be sent to: E.164, a `+` and 8 to 15 digits
/// (spaces, dots, dashes and brackets allowed between them), so an SMS or voice
/// provider is never handed a local number it would guess the country of.
pub(crate) fn phone_number(p: &str) -> bool {
    let p = p.trim();
    let Some(rest) = p.strip_prefix('+') else {
        return false;
    };
    let digits = rest.bytes().filter(u8::is_ascii_digit).count();
    rest.bytes()
        .all(|b| b.is_ascii_digit() || matches!(b, b' ' | b'.' | b'-' | b'(' | b')'))
        && (8..=15).contains(&digits)
        && !rest.starts_with('0')
}

impl RecipientIn {
    /// The engine's recipient with id `id`.
    pub(crate) fn spec(&self, id: Id, at: &str) -> Result<RecipientSpec, ApiError> {
        let name = self.name.trim();
        if name.is_empty() || name.chars().count() > 255 {
            return Err(ApiError::invalid(&format!("{at}/name")));
        }
        let email = self.email.as_deref().unwrap_or("");
        if !email.is_empty() && (email.len() < 3 || email.len() > 320 || !email.contains('@')) {
            return Err(ApiError::invalid(&format!("{at}/email")));
        }
        if let Some(p) = &self.phone
            && (p.len() < 3 || p.len() > 32)
        {
            return Err(ApiError::invalid(&format!("{at}/phone")));
        }
        if self.auth.contains(&AuthMethod::AccessCode)
            != self.access_code.as_ref().is_some_and(|c| !c.is_empty())
        {
            return Err(ApiError::invalid(&format!("{at}/access_code")));
        }
        // An email one-time code needs an address to send it to (SEC-A02).
        // A sign-in through an identity provider is bound to the recipient by email
        // (RAUTH-01), as an emailed code is.
        if (self.auth.contains(&AuthMethod::EmailOtp) || self.auth.contains(&AuthMethod::Sso))
            && email.is_empty()
        {
            return Err(ApiError::invalid(&format!("{at}/auth")));
        }
        // A code by SMS or voice call needs a number to send it to (slice 5).
        if (self.auth.contains(&AuthMethod::SmsOtp) || self.auth.contains(&AuthMethod::VoiceOtp))
            && !self.phone.as_deref().is_some_and(phone_number)
        {
            return Err(ApiError::invalid(&format!("{at}/phone")));
        }
        let embedded = self
            .embedded_client_user_id
            .as_deref()
            .map(|e| {
                Id::new(e).map_err(|_| ApiError::invalid(&format!("{at}/embedded_client_user_id")))
            })
            .transpose()?;
        Ok(RecipientSpec {
            id,
            rtype: self.rtype,
            routing_order: RoutingOrder::new(self.routing_order)
                .map_err(|_| ApiError::invalid(&format!("{at}/routing_order")))?,
            name: text(name, &format!("{at}/name"))?,
            email: text(email, &format!("{at}/email"))?,
            phone: self
                .phone
                .as_deref()
                .map(|p| text(p, &format!("{at}/phone")))
                .transpose()?,
            delivery: self.delivery.unwrap_or(if embedded.is_some() {
                Delivery::None
            } else {
                Delivery::Email
            }),
            auth: self.auth.clone(),
            embedded_client_user_id: embedded,
            time_zone_offset_minutes: self.time_zone_offset_minutes,
            date_format: self.date_format,
            witness_for: None,
        })
    }
}

/// A document uploaded inline.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DocumentIn {
    pub name: String,
    pub content_base64: String,
}

/// A field as the API takes it: the model's field without its ids, its recipient and
/// document named by id, by a recipient's `ref`, or by a document's index in the same
/// request; the rectangle flat (`page`, `x`, `y`, `width`, `height`) or as `placement`.
pub(crate) fn field_from(
    raw: &Value,
    id: Id,
    recipient: impl Fn(&str) -> Option<Id>,
    document: impl Fn(&Value) -> Option<Id>,
    at: &str,
) -> Result<Field, ApiError> {
    let Value::Object(map) = raw else {
        return Err(ApiError::invalid(at));
    };
    let mut out: Map<String, Value> = Map::new();
    let mut placement: Map<String, Value> = Map::new();
    for (k, v) in map {
        match k.as_str() {
            "recipient" | "recipient_id" => {
                let r = v
                    .as_str()
                    .and_then(&recipient)
                    .ok_or_else(|| ApiError::invalid(&format!("{at}/{k}")))?;
                out.insert("recipient_id".into(), Value::String(r.to_string()));
            }
            "document" | "document_id" => {
                let d = document(v).ok_or_else(|| ApiError::invalid(&format!("{at}/{k}")))?;
                out.insert("document_id".into(), Value::String(d.to_string()));
            }
            "page" | "x" | "y" | "width" | "height" => {
                placement.insert(k.clone(), v.clone());
            }
            "id" => return Err(ApiError::invalid(&format!("{at}/id"))),
            _ => {
                out.insert(k.clone(), v.clone());
            }
        }
    }
    if !placement.is_empty() {
        out.insert("placement".into(), Value::Object(placement));
    }
    out.insert("id".into(), Value::String(id.to_string()));
    serde_json::from_value(Value::Object(out)).map_err(|_| {
        ApiError::invalid(at).fields(vec![FieldProblem {
            pointer: at.to_owned(),
            code: "CS-FLD-0002",
        }])
    })
}

/// The one-call create of docs/40 §3.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnvelopeCreate {
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub message: String,
    /// `draft` (default) or `sent`.
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub documents: Vec<DocumentIn>,
    #[serde(default)]
    pub recipients: Vec<RecipientIn>,
    #[serde(default)]
    pub fields: Vec<Value>,
    #[serde(default)]
    pub reminders: Option<ReminderPolicy>,
    #[serde(default)]
    pub expires_in_days: Option<u32>,
    #[serde(default)]
    pub signing_options: Option<SigningOptions>,
    #[serde(default)]
    pub seal_profile: Option<SealProfile>,
}

/// Envelope settings a `PATCH` may change while it is a draft.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnvelopePatch {
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub reminders: Option<ReminderPolicy>,
    #[serde(default)]
    pub expires_in_days: Option<Option<u32>>,
    #[serde(default)]
    pub signing_options: Option<SigningOptions>,
    #[serde(default)]
    pub seal_profile: Option<SealProfile>,
}

fn document_out(d: &DocumentState) -> Value {
    json!({
        "id": d.spec.id,
        "name": d.spec.name.0,
        "pages": d.spec.pages,
        "bytes": d.spec.bytes,
        "upload_sha256": d.spec.upload_hash,
        "delivered_sha256": d.spec.delivered_hash,
        "admission_findings": d.spec.admission.map_or(0, |(_, n)| n),
        "fixed": d.fixed,
    })
}

/// A document as the API shows it.
pub(crate) fn document(d: &DocumentState) -> Value {
    document_out(d)
}

/// A recipient as the API shows it.
pub(crate) fn recipient(r: &RecipientState) -> Value {
    let s = &r.spec;
    json!({
        "id": s.id,
        "type": s.rtype,
        "routing_order": s.routing_order,
        "name": s.name.0,
        "email": s.email.0,
        "phone": s.phone.as_ref().map(|p| &p.0),
        "delivery": s.delivery,
        "auth": s.auth,
        "embedded_client_user_id": s.embedded_client_user_id,
        "time_zone_offset_minutes": s.time_zone_offset_minutes,
        "status": r.status,
        "completed_at": r.completed_at,
        "declined_reason": r.declined_reason.as_ref().map(|d| &d.0),
        "reassigned_to": r.reassigned_to,
        "reassigned_from": r.reassigned_from,
        "consented": r.consent.is_some(),
        "authenticated": r.auth_satisfied(),
    })
}

/// A field as the API shows it: the model's wire form.
pub(crate) fn field(f: &Field) -> Value {
    serde_json::to_value(f).unwrap_or(Value::Null)
}

/// An envelope as the API shows it.
pub(crate) fn envelope(s: &EnvelopeState) -> Value {
    json!({
        "id": s.id,
        "status": s.status,
        "version": s.version,
        "sender_user_id": s.sender_user_id,
        "subject": s.subject.0,
        "message": s.message.0,
        "created_at": s.created_at,
        "sent_at": s.sent_at,
        "ended_at": s.ended_at,
        "expires_at": s.expires_at,
        "void_reason": s.void_reason.as_ref().map(|r| &r.0),
        "reminders": s.reminders,
        "signing_options": s.options,
        "seal_profile": s.seal_profile,
        "documents": s.documents.iter().map(document_out).collect::<Vec<_>>(),
        "recipients": s.recipients.iter().map(recipient).collect::<Vec<_>>(),
        "fields": s.fields.0.iter().map(field).collect::<Vec<_>>(),
        "sealed": s.sealed,
    })
}

/// The `ETag` of an envelope at its version.
pub(crate) fn etag(s: &EnvelopeState) -> String {
    format!("\"v{}\"", s.version)
}

/// The version an `If-Match` names (`"v<n>"`, weak or strong).
pub(crate) fn if_match(headers: &axum::http::HeaderMap) -> Option<Result<u64, ApiError>> {
    let raw = headers.get(axum::http::header::IF_MATCH)?;
    Some(
        (|| {
            let s = raw.to_str().ok()?.trim();
            let s = s.strip_prefix("W/").unwrap_or(s);
            s.strip_prefix("\"v")?.strip_suffix('"')?.parse().ok()
        })()
        .ok_or_else(ApiError::precondition_failed),
    )
}
