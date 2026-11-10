//! Webhook subscriptions and deliveries (docs/40 §4, ADR-016). Secrets are references
//! into the secrets store, never the secrets.

use sqlx::postgres::PgRow;
use time::OffsetDateTime;
use uuid::Uuid;

use super::col;
use crate::error::{Result, StoreError, db};
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

fn subscription(r: &PgRow) -> Result<Subscription> {
    let status: String = col(r, "status")?;
    Ok(Subscription {
        id: WebhookSubscriptionId(col(r, "id")?),
        envelope_id: col::<Option<Uuid>>(r, "envelope_id")?.map(EnvelopeId),
        url: col(r, "url")?,
        event_types: col(r, "event_types")?,
        secret_refs: col(r, "secret_refs")?,
        active: status == "active",
    })
}

fn delivery(r: &PgRow) -> Result<Delivery> {
    Ok(Delivery {
        id: WebhookDeliveryId(col(r, "id")?),
        subscription_id: WebhookSubscriptionId(col(r, "subscription_id")?),
        event_id: col(r, "event_id")?,
        event_type: col(r, "event_type")?,
        payload: col(r, "payload")?,
        status: col(r, "status")?,
        attempts: col(r, "attempts")?,
        last_status_code: col(r, "last_status_code")?,
    })
}

const SUB_SELECT: &str = "SELECT id, envelope_id, url, event_types, secret_refs, status \
     FROM webhook_subscriptions WHERE account_id = $1";
const DEL_SELECT: &str = "SELECT id, subscription_id, event_id, event_type, payload, status, \
     attempts, last_status_code FROM webhook_deliveries WHERE account_id = $1";

impl Webhooks<'_> {
    /// Subscribe.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` a non-HTTPS URL, no event types, or an envelope of another account.
    pub async fn subscribe(&mut self, s: &Subscription) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query(
            "INSERT INTO webhook_subscriptions (id, account_id, envelope_id, url, event_types, \
             secret_refs, status) VALUES ($2, $1, $3, $4, $5, $6, $7)",
        )
        .bind(acct)
        .bind(s.id.0)
        .bind(s.envelope_id.map(|e| e.0))
        .bind(&s.url)
        .bind(&s.event_types)
        .bind(&s.secret_refs)
        .bind(if s.active { "active" } else { "disabled" })
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// A subscription of this account.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn get(&mut self, id: WebhookSubscriptionId) -> Result<Option<Subscription>> {
        let acct = self.tx.acct();
        let sql = format!("{SUB_SELECT} AND id = $2");
        let row = sqlx::query(&sql)
            .bind(acct)
            .bind(id.0)
            .fetch_optional(self.tx.conn())
            .await
            .map_err(db)?;
        row.as_ref().map(subscription).transpose()
    }

    /// This account's subscriptions.
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn list(&mut self) -> Result<Vec<Subscription>> {
        let acct = self.tx.acct();
        let sql = format!("{SUB_SELECT} ORDER BY created_at, id");
        let rows = sqlx::query(&sql)
            .bind(acct)
            .fetch_all(self.tx.conn())
            .await
            .map_err(db)?;
        rows.iter().map(subscription).collect()
    }

    /// Disable a subscription.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when this account has no such subscription.
    pub async fn disable(&mut self, id: WebhookSubscriptionId) -> Result<()> {
        let acct = self.tx.acct();
        let done = sqlx::query(
            "UPDATE webhook_subscriptions SET status = 'disabled' WHERE account_id = $1 AND id = $2",
        )
        .bind(acct)
        .bind(id.0)
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        if done.rows_affected() == 0 {
            return Err(StoreError::NotFound {
                entity: "webhook subscription",
            });
        }
        Ok(())
    }

    /// Record a pending delivery.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` when the subscription is not this account's; `CS-DB-0006` when the
    /// event was already recorded for it.
    pub async fn record_delivery(&mut self, d: &Delivery) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query(
            "INSERT INTO webhook_deliveries (id, account_id, subscription_id, event_id, event_type, \
             payload) VALUES ($2, $1, $3, $4, $5, $6)",
        )
        .bind(acct)
        .bind(d.id.0)
        .bind(d.subscription_id.0)
        .bind(d.event_id)
        .bind(&d.event_type)
        .bind(&d.payload)
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
        let done = sqlx::query(
            "UPDATE webhook_deliveries SET attempts = attempts + 1, last_status_code = $3, \
               status = CASE WHEN $4 THEN 'delivered' WHEN $5::timestamptz IS NULL THEN 'failed' \
                             ELSE 'pending' END, \
               next_attempt_at = $5, delivered_at = CASE WHEN $4 THEN $6 ELSE delivered_at END \
             WHERE account_id = $1 AND id = $2",
        )
        .bind(acct)
        .bind(id.0)
        .bind(status_code)
        .bind(delivered)
        .bind(next_attempt_at)
        .bind(now)
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        if done.rows_affected() == 0 {
            return Err(StoreError::NotFound {
                entity: "webhook delivery",
            });
        }
        Ok(())
    }

    /// A subscription's deliveries, newest first, at most `limit` (capped at 1,000).
    ///
    /// # Errors
    ///
    /// `CS-DB-0010` for an unreadable row.
    pub async fn deliveries(
        &mut self,
        subscription: WebhookSubscriptionId,
        limit: u32,
    ) -> Result<Vec<Delivery>> {
        let acct = self.tx.acct();
        let sql = format!(
            "{DEL_SELECT} AND subscription_id = $2 ORDER BY created_at DESC, id DESC LIMIT $3"
        );
        let rows = sqlx::query(&sql)
            .bind(acct)
            .bind(subscription.0)
            .bind(i64::from(limit.min(1000)))
            .fetch_all(self.tx.conn())
            .await
            .map_err(db)?;
        rows.iter().map(delivery).collect()
    }
}
