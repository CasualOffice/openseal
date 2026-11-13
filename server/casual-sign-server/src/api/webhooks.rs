//! Webhook subscriptions (docs/40 §4, ADR-016). Delivery and signing are the worker's
//! (stage 2D); here a subscription is registered, read, listed, edited, paused and
//! disabled, a test event or a redelivery is queued for the worker (UXW-31..33), and its
//! URL is refused unless it is HTTPS to a public address (SEC-W01, at registration;
//! the worker checks again after resolving the name, against DNS rebinding).

use std::net::IpAddr;

use axum::body::Bytes;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use casual_sign_store::repo::webhooks::{Delivery, Subscription};
use casual_sign_store::{EnvelopeId, WebhookDeliveryId, WebhookSubscriptionId};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{json, path_id};
use crate::call::Call;
use crate::dto::parse;
use crate::error::ApiError;

/// The event types a subscription may name (docs/40 §4).
pub const EVENT_TYPES: [&str; 20] = [
    "envelope.sent",
    "envelope.delivered",
    "envelope.completed",
    "envelope.declined",
    "envelope.voided",
    "envelope.expired",
    "envelope.corrected",
    "envelope.purged",
    "recipient.sent",
    "recipient.delivered",
    "recipient.auth_failed",
    "recipient.completed",
    "recipient.declined",
    "recipient.reassigned",
    "recipient.finish_later",
    "recipient.bounced",
    "template.created",
    "template.updated",
    "template.deleted",
    "bulk_send.completed",
];

/// Whether an address is one a webhook may never reach: private, loopback,
/// link-local, unspecified, multicast, documentation, carrier-grade NAT, or the cloud
/// metadata range (SEC-W01).
#[must_use]
pub fn forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_unspecified()
                || v.is_broadcast()
                || v.is_multicast()
                || v.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (64..128).contains(&o[1]))
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                || o[0] >= 240
        }
        IpAddr::V6(v) => {
            if let Some(v4) = v.to_ipv4_mapped() {
                return forbidden_ip(IpAddr::V4(v4));
            }
            let s = v.segments();
            v.is_loopback()
                || v.is_unspecified()
                || v.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || s[0] == 0x2001 && s[1] == 0x0db8
                || s[0] == 0x0064 && s[1] == 0xff9b
        }
    }
}

/// Check a webhook URL at registration: `https://`, a host, no credentials, and not a
/// literal forbidden address or a local name.
pub(crate) fn check_url(url: &str) -> Result<(), ApiError> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(ApiError::webhook_url)?;
    if url.len() > 2048 || url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(ApiError::webhook_url());
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return Err(ApiError::webhook_url());
    }
    let host = if let Some(h) = authority.strip_prefix('[') {
        h.split(']').next().unwrap_or("")
    } else {
        authority.rsplit_once(':').map_or(authority, |(h, _)| h)
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if let Ok(ip) = host.parse::<IpAddr>() {
        return if forbidden_ip(ip) {
            Err(ApiError::webhook_url())
        } else {
            Ok(())
        };
    }
    let local = host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
        || !host.contains('.')
        || host == "metadata.google.internal";
    if local
        || host
            .split('.')
            .all(|l| l.chars().all(|c| c.is_ascii_digit()))
    {
        // A dotted all-number name is an address in another notation.
        return Err(ApiError::webhook_url());
    }
    Ok(())
}

fn sub_json(s: &Subscription) -> Value {
    json!({
        "id": s.id.to_string(),
        "envelope_id": s.envelope_id.map(|e| e.to_string()),
        "url": s.url,
        "event_types": s.event_types,
        "secret_refs": s.secret_refs,
        "active": s.active,
    })
}

/// `GET /webhooks`.
pub(crate) async fn list(c: Call) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let items: Vec<Value> = tx.webhooks().list().await?.iter().map(sub_json).collect();
    Ok(json(StatusCode::OK, &json!({ "items": items })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubIn {
    url: String,
    event_types: Vec<String>,
    /// Names of signing secrets the operator provisioned in the secrets store (1 to 4,
    /// for rotation). The secrets themselves never pass through the API.
    secret_refs: Vec<String>,
    #[serde(default)]
    envelope_id: Option<String>,
}

/// `POST /webhooks`.
pub(crate) async fn create(c: Call, body: Bytes) -> Result<Response, ApiError> {
    let req: SubIn = parse(&body)?;
    check_url(&req.url)?;
    check_events(&req.event_types)?;
    let ok_ref = |r: &String| {
        (1..=64).contains(&r.len())
            && r.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    };
    if req.secret_refs.is_empty()
        || req.secret_refs.len() > 4
        || !req.secret_refs.iter().all(ok_ref)
    {
        return Err(ApiError::invalid("/secret_refs"));
    }
    let mut tx = c.tx().await?;
    let envelope_id = match &req.envelope_id {
        Some(e) => {
            // An envelope the caller may see, or the same answer as none.
            let l = super::envelope(&mut tx, &c.p, e)
                .await
                .map_err(|_| ApiError::invalid("/envelope_id"))?;
            Some(l.id)
        }
        None => None,
    };
    let s = Subscription {
        id: WebhookSubscriptionId(Uuid::now_v7()),
        envelope_id,
        url: req.url,
        event_types: req.event_types,
        secret_refs: req.secret_refs,
        active: true,
    };
    tx.webhooks().subscribe(&s).await?;
    tx.commit().await?;
    Ok(json(StatusCode::CREATED, &sub_json(&s)))
}

/// `GET /webhooks/{id}`.
pub(crate) async fn get(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let id = WebhookSubscriptionId(path_id(&id)?);
    let mut tx = c.tx().await?;
    let s = tx
        .webhooks()
        .get(id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    Ok(json(StatusCode::OK, &sub_json(&s)))
}

/// `DELETE /webhooks/{id}`: disable (deliveries stay visible).
pub(crate) async fn delete(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let id = WebhookSubscriptionId(path_id(&id)?);
    let mut tx = c.tx().await?;
    tx.webhooks()
        .get(id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    tx.webhooks().disable(id).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `GET /webhooks/{id}/deliveries`.
pub(crate) async fn deliveries(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let id = WebhookSubscriptionId(path_id(&id)?);
    let mut tx = c.tx().await?;
    tx.webhooks()
        .get(id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let items: Vec<Value> = tx
        .webhooks()
        .deliveries(id, 100)
        .await?
        .iter()
        .map(delivery_json)
        .collect();
    Ok(json(StatusCode::OK, &json!({ "items": items })))
}

fn delivery_json(d: &Delivery) -> Value {
    json!({
        "id": d.id.to_string(), "event_id": d.event_id.to_string(), "event_type": d.event_type,
        "status": d.status, "attempts": d.attempts, "last_status_code": d.last_status_code,
    })
}

/// The event types of a request, checked as at registration.
fn check_events(types: &[String]) -> Result<(), ApiError> {
    if types.is_empty()
        || types.len() > EVENT_TYPES.len()
        || types.iter().any(|e| !EVENT_TYPES.contains(&e.as_str()))
    {
        return Err(ApiError::invalid("/event_types"));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubPatch {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    event_types: Option<Vec<String>>,
    #[serde(default)]
    active: Option<bool>,
}

/// `PATCH /webhooks/{id} {url?, event_types?, active?}` (UXW-31): edit, pause
/// (`active: false`) or resume (`true`) a subscription. A new URL passes the
/// registration check (SEC-W01); the worker checks it again at every delivery.
pub(crate) async fn patch(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let id = WebhookSubscriptionId(path_id(&id)?);
    let mut tx = c.tx().await?;
    tx.webhooks()
        .get(id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let req: SubPatch = parse(&body)?;
    if let Some(u) = &req.url {
        check_url(u)?;
    }
    if let Some(t) = &req.event_types {
        check_events(t)?;
    }
    tx.webhooks()
        .update(
            id,
            req.url.as_deref(),
            req.event_types.as_deref(),
            req.active,
        )
        .await?;
    let s = tx
        .webhooks()
        .get(id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    tx.commit().await?;
    Ok(json(StatusCode::OK, &sub_json(&s)))
}

/// Queue the job that sends `delivery` (UXW-32, UXW-33).
async fn queue_delivery(
    c: &Call,
    tx: &mut casual_sign_store::TenantTx,
    delivery: WebhookDeliveryId,
) -> Result<(), ApiError> {
    let job = casual_sign_host::jobs::webhook_delivery_job(
        casual_sign_store::JobId(Uuid::now_v7()),
        delivery.0,
        c.st.now(),
    );
    tx.jobs().enqueue(&job).await?;
    Ok(())
}

/// `POST /webhooks/{id}/test` (UXW-32, docs/40 §4): record a `webhook.test` delivery
/// (ids only: the subscription and the account) and queue it for the worker, which
/// signs and sends it as any other (SEC-W01 at connect time) and records the answer in
/// the delivery log. `202` with the delivery as recorded (`pending`); a paused or
/// disabled subscription is `409 CS-API-0009`.
pub(crate) async fn test(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let id = WebhookSubscriptionId(path_id(&id)?);
    let mut tx = c.tx().await?;
    let s = tx
        .webhooks()
        .get(id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    if !s.active {
        return Err(ApiError::not_available("subscription not active"));
    }
    check_url(&s.url)?;
    let event_id = Uuid::now_v7();
    let d = Delivery {
        id: WebhookDeliveryId(Uuid::now_v7()),
        subscription_id: id,
        event_id,
        event_type: "webhook.test".into(),
        payload: json!({
            "id": event_id.to_string(),
            "type": "webhook.test",
            "created_at": super::envelopes::rfc3339(c.st.now()),
            "account_id": c.p.account.to_string(),
            "data": { "subscription_id": id.to_string() },
        }),
        status: "pending".into(),
        attempts: 0,
        last_status_code: None,
    };
    tx.webhooks().record_delivery(&d).await?;
    queue_delivery(&c, &mut tx, d.id).await?;
    tx.commit().await?;
    Ok(json(StatusCode::ACCEPTED, &delivery_json(&d)))
}

/// `POST /webhooks/{id}/deliveries/{d}/redeliver` (UXW-33, docs/40 §4): send one
/// delivery's event again, the same event id and payload, through the worker (SEC-W01
/// checked again: the URL as registered here, every resolved address at connect time).
/// `202` with the delivery, back to `pending`; a paused or disabled subscription is
/// `409 CS-API-0009`.
pub(crate) async fn redeliver(
    c: Call,
    Path((id, delivery)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let id = WebhookSubscriptionId(path_id(&id)?);
    let delivery = WebhookDeliveryId(path_id(&delivery)?);
    let mut tx = c.tx().await?;
    let s = tx
        .webhooks()
        .get(id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let d = tx
        .webhooks()
        .delivery(delivery)
        .await?
        .filter(|d| d.subscription_id == id)
        .ok_or_else(ApiError::not_found)?;
    if !s.active {
        return Err(ApiError::not_available("subscription not active"));
    }
    check_url(&s.url)?;
    tx.webhooks().requeue(d.id).await?;
    queue_delivery(&c, &mut tx, d.id).await?;
    let d = tx
        .webhooks()
        .delivery(delivery)
        .await?
        .ok_or_else(ApiError::not_found)?;
    tx.commit().await?;
    Ok(json(StatusCode::ACCEPTED, &delivery_json(&d)))
}

#[allow(dead_code)]
fn _ids(_: EnvelopeId) {}

#[cfg(test)]
// Tests may unwrap, index and panic (CLAUDE.md).
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn only_public_https_urls_register() {
        for ok in [
            "https://hooks.example.com/x",
            "https://93.184.216.34/h",
            "https://example.com:8443",
        ] {
            assert!(check_url(ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://hooks.example.com",
            "https://localhost/x",
            "https://127.0.0.1/",
            "https://10.1.2.3/",
            "https://169.254.169.254/latest",
            "https://[::1]/",
            "https://[fe80::1]/",
            "https://[::ffff:10.0.0.1]/",
            "https://user:pw@example.com/",
            "https://intranet/",
            "https://2130706433/",
            "https://metadata.google.internal/",
            "https://100.64.0.1/",
        ] {
            assert_eq!(check_url(bad).unwrap_err().code(), "CS-API-0013", "{bad}");
        }
    }
}
