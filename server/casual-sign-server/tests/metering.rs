//! PLAN-03 (docs/23 §7.2): `envelopes_sent` is counted in the deciding transaction when
//! `envelope.sent` is recorded, once per envelope, in the workspace and its organization;
//! a draft is not counted, and sending again is not counted twice.

#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::indexing_slicing
)]

mod common;

use axum::http::StatusCode;
use common::Rls;
use common::flow::{b64, ok, sent};
use common::harness::{Api, Tenant, pdf};
use serde_json::json;
use sqlx::Row;

/// `envelopes_sent` for the tenant's workspace and organization, summed over periods.
async fn counted(api: &Api, t: &Tenant) -> (i64, i64) {
    let row = sqlx::query(
        "SELECT \
           (SELECT COALESCE(sum(value), 0)::bigint FROM usage_counters \
             WHERE account_id = $1 AND meter = 'envelopes_sent'), \
           (SELECT COALESCE(sum(value), 0)::bigint FROM org_usage_counters \
             WHERE organization_id = $2 AND meter = 'envelopes_sent')",
    )
    .bind(t.boot.account.0)
    .bind(t.boot.organization.0)
    .fetch_one(&api.db.admin)
    .await
    .unwrap();
    (row.get(0), row.get(1))
}

#[tokio::test]
async fn a_sent_envelope_is_counted_once_in_its_workspace_and_organization() {
    let Some(api) = Api::new("metering_envelopes_sent", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    assert_eq!(counted(&api, &a).await, (0, 0));

    // A draft is not counted.
    let draft = ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            &a.auth,
            Some(json!({
                "subject": "PLAN-03",
                "documents": [{"name": "d.pdf", "content_base64": b64(&pdf(1))}],
                "recipients": [{"ref": "s1", "type": "signer", "name": "S1",
                    "email": "s1@example.test", "routing_order": 1}],
                "fields": [{"recipient": "s1", "document": 0, "type": "signature", "page": 1,
                    "x": 72, "y": 100, "width": 180, "height": 40, "required": true}],
            })),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "create draft",
    );
    assert_eq!(counted(&api, &a).await, (0, 0));

    // Sent on creation: one.
    sent(&api, &a, 1, &[]).await;
    assert_eq!(counted(&api, &a).await, (1, 1));

    // The draft sent: two; sending it again is refused and counts nothing.
    let base = format!("/api/v1/envelopes/{}", draft["id"].as_str().unwrap());
    ok(
        api.call("POST", &format!("{base}/send"), &a.auth, None, &[])
            .await,
        StatusCode::OK,
        "send draft",
    );
    assert_eq!(counted(&api, &a).await, (2, 2));
    let again = api
        .call("POST", &format!("{base}/send"), &a.auth, None, &[])
        .await;
    assert_ne!(again.status, StatusCode::OK, "a second send");
    assert_eq!(counted(&api, &a).await, (2, 2));

    // Another tenant's counters are its own.
    let b = api.tenant("bravo").await;
    assert_eq!(counted(&api, &b).await, (0, 0));
}
