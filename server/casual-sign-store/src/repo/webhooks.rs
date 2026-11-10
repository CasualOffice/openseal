//! Webhook subscriptions and deliveries (docs/40 §4, ADR-016). Secrets are references
//! into the secrets store, never the secrets.

use time::OffsetDateTime;
use uuid::Uuid;

use super::affected;
use crate::error::{Result, db};
use crate::ids::{EnvelopeId, WebhookDeliveryId, WebhookSubscriptionId};
use crate::store::TenantTx;

/// A subscription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    /// Host-minted id.
    pub id: WebhookSubscriptionId,
    /// Per-envelope subscription, when set.
    pub envelope_id: Option<EnvelopeId>,
    /// HTTPS URL (validated against SSRF by the server, SEC-W01).
    pub url: String,
    /// Event types.
    pub event_types: Vec<String>,
    /// Secret references, 1 to 4.
    pub secret_refs: Vec<String>,
    /// `active` or `disabled`.
    pub active: bool,
}

/// A delivery.
#[derive(Debug, Clone, PartialEq)]
pub struct Delivery {
    /// Host-minted id.
    pub id: WebhookDeliveryId,
    /// Subscription.
    pub subscription_id: WebhookSubscriptionId,
    /// The event's id (the `webhook-id` header).
    pub event_id: Uuid,
    /// Event type.
    pub event_type: String,
    /// Payload: ids and summaries, never documents.
    pub payload: serde_json::Value,
    /// `pending`, `delivered` or `failed`.
    pub status: String,
    /// Attempts so far.
    pub attempts: i32,
    /// Last HTTP status.
    pub last_status_code: Option<i32>,
}

/// Webhooks of this account. Reached through `TenantTx::webhooks`.
#[derive(Debug)]
pub struct Webhooks<'t> {
    pub(crate) tx: &'t mut TenantTx,
}

/// A subscription row as selected.
struct SubscriptionRow {
    id: Uuid,
    envelope_id: Option<Uuid>,
    url: String,
    event_types: Vec<String>,
    secret_refs: Vec<String>,
    status: String,
}

impl From<SubscriptionRow> for Subscription {
    fn from(r: SubscriptionRow) -> Self {
        Self {
            id: WebhookSubscriptionId(r.id),
            envelope_id: r.envelope_id.map(EnvelopeId),
            url: r.url,
            event_types: r.event_types,
            secret_refs: r.secret_refs,
            active: r.status == "active",
        }
    }
}

impl Webhooks<'_> {
    /// Subscribe.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` a non-HTTPS URL, no event types, or an envelope of another account.
    pub async fn subscribe(&mut self, s: &Subscription) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "INSERT INTO webhook_subscriptions (id, account_id, envelope_id, url, event_types, \
             secret_refs, status) VALUES ($2, $1, $3, $4, $5, $6, $7)",
            acct,
            s.id.0,
            s.envelope_id.map(|e| e.0),
            s.url,
            &s.event_types,
            &s.secret_refs,
            if s.active { "active" } else { "disabled" }
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// A subscription of this account.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn get(&mut self, id: WebhookSubscriptionId) -> Result<Option<Subscription>> {
        let acct = self.tx.acct();
        let row = sqlx::query_as!(
            SubscriptionRow,
            "SELECT id, envelope_id, url, event_types, secret_refs, status \
             FROM webhook_subscriptions WHERE account_id = $1 AND id = $2",
            acct,
            id.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(row.map(Subscription::from))
    }

    /// This account's subscriptions.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn list(&mut self) -> Result<Vec<Subscription>> {
        let acct = self.tx.acct();
        let rows = sqlx::query_as!(
            SubscriptionRow,
            "SELECT id, envelope_id, url, event_types, secret_refs, status \
             FROM webhook_subscriptions WHERE account_id = $1 ORDER BY created_at, id",
            acct
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(rows.into_iter().map(Subscription::from).collect())
    }

    /// Disable a subscription.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when this account has no such subscription.
    pub async fn disable(&mut self, id: WebhookSubscriptionId) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE webhook_subscriptions SET status = 'disabled' WHERE account_id = $1 AND id = $2",
            acct,
            id.0
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        affected(done.rows_affected(), "webhook subscription")
    }

    /// Record a pending delivery.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` when the subscription is not this account's; `CS-DB-0006` when the
    /// event was already recorded for it.
    pub async fn record_delivery(&mut self, d: &Delivery) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "INSERT INTO webhook_deliveries (id, account_id, subscription_id, event_id, event_type, \
             payload) VALUES ($2, $1, $3, $4, $5, $6)",
            acct,
            d.id.0,
            d.subscription_id.0,
            d.event_id,
            d.event_type,
            &d.payload
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// Record an attempt's outcome.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when this account has no such delivery.
    pub async fn record_attempt(
        &mut self,
        id: WebhookDeliveryId,
        status_code: Option<i32>,
        delivered: bool,
        next_attempt_at: Option<OffsetDateTime>,
        now: OffsetDateTime,
    ) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE webhook_deliveries SET attempts = attempts + 1, last_status_code = $3, \
               status = CASE WHEN $4 THEN 'delivered' WHEN $5::timestamptz IS NULL THEN 'failed' \
                             ELSE 'pending' END, \
               next_attempt_at = $5, delivered_at = CASE WHEN $4 THEN $6 ELSE delivered_at END \
             WHERE account_id = $1 AND id = $2",
            acct,
            id.0,
            status_code,
            delivered,
            next_attempt_at,
            now
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        affected(done.rows_affected(), "webhook delivery")
    }

    /// A subscription's deliveries, newest first, at most `limit` (capped at 1,000).
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn deliveries(
        &mut self,
        subscription: WebhookSubscriptionId,
        limit: u32,
    ) -> Result<Vec<Delivery>> {
        let acct = self.tx.acct();
        let rows = sqlx::query!(
            "SELECT id, subscription_id, event_id, event_type, payload, status, attempts, \
             last_status_code FROM webhook_deliveries WHERE account_id = $1 AND subscription_id = $2 \
             ORDER BY created_at DESC, id DESC LIMIT $3",
            acct,
            subscription.0,
            i64::from(limit.min(1000))
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(rows
            .into_iter()
            .map(|r| Delivery {
                id: WebhookDeliveryId(r.id),
                subscription_id: WebhookSubscriptionId(r.subscription_id),
                event_id: r.event_id,
                event_type: r.event_type,
                payload: r.payload,
                status: r.status,
                attempts: r.attempts,
                last_status_code: r.last_status_code,
            })
            .collect())
    }
}
