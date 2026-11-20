//! Insights (`FG-141`, DocuSign's Insights): `GET /insights` answers the dashboard's
//! figures over the envelopes created in a window: counts by how they stand, the median
//! and 90th percentile of the time from sent to completed, what was sent and completed
//! each day in the caller's day, and the top senders. A holder of `reports.read` sees the
//! workspace; anyone else their own envelopes, and naming another sender is `403`.
//! Another account's envelopes are never counted.

#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

mod common;

use axum::http::StatusCode;
use common::Rls;
use common::flow::{b64, ok};
use common::harness::{Api, Auth, PASSWORD, Tenant, pdf, session_of};
use serde_json::{Value, json};

async fn create(api: &Api, t: &Tenant, status: &str) -> String {
    let e = ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            &t.auth,
            Some(json!({
                "subject": "Insight", "status": status,
                "documents": [{"name": "d.pdf", "content_base64": b64(&pdf(1))}],
                "recipients": [{"ref": "s", "type": "signer", "name": "Sig",
                    "email": "sig@example.test", "routing_order": 1}],
                "fields": [{"recipient": "s", "document": 0, "type": "signature", "page": 1,
                    "x": 72, "y": 100, "width": 180, "height": 40, "required": true}],
            })),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "create",
    );
    e["id"].as_str().unwrap().to_owned()
}

/// Set an envelope's list row as if it had been sent and ended at these times (the
/// figures read the row; the engine's clock is not what is under test here).
async fn ended(api: &Api, id: &str, status: &str, sent: &str, completed: Option<&str>) {
    sqlx::query(
        "UPDATE envelopes SET status = $2, sent_at = $3::timestamptz, \
                completed_at = $4::timestamptz, \
                voided_at = CASE WHEN $2 = 'voided' THEN $3::timestamptz END \
          WHERE id = $1::uuid",
    )
    .bind(id)
    .bind(status)
    .bind(sent)
    .bind(completed)
    .execute(&api.db.admin)
    .await
    .unwrap();
}

async fn insights(api: &Api, who: &Auth, query: &str) -> (StatusCode, Value) {
    let r = api
        .call("GET", &format!("/api/v1/insights{query}"), who, None, &[])
        .await;
    (r.status, r.json())
}

#[tokio::test]
async fn insights_count_time_to_complete_days_and_senders_for_the_scope_the_caller_holds() {
    let Some(api) = Api::new("insights", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let b = api.tenant("beta").await;
    // Alpha: three completed in 1, 3 and 11 hours, one declined, one voided, one draft.
    let at = "2026-11-01T10:00:00Z";
    for (hours, status) in [
        (Some(1), "completed"),
        (Some(3), "completed"),
        (Some(11), "completed"),
        (None, "declined"),
        (None, "voided"),
    ] {
        let id = create(&api, &a, "sent").await;
        let done = hours.map(|h| format!("2026-11-01T{:02}:00:00Z", 10 + h));
        ended(&api, &id, status, at, done.as_deref()).await;
    }
    create(&api, &a, "draft").await;
    // Beta's envelope is never in alpha's figures.
    create(&api, &b, "sent").await;

    let (s, v) = insights(&api, &a.auth, "").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["scope"], "workspace");
    assert_eq!(
        v["totals"],
        json!({"created": 6, "sent": 5, "completed": 3, "declined": 1, "voided": 1,
            "expired": 0, "in_progress": 0})
    );
    // Median of 1, 3 and 11 hours is 3 hours; the 90th percentile, continuous, is
    // 3 h + 0.8 × (11 h − 3 h) = 9.4 hours.
    assert_eq!(v["time_to_complete"]["median_seconds"], json!(10_800.0));
    assert_eq!(v["time_to_complete"]["p90_seconds"], json!(33_840.0));
    assert_eq!(
        v["days"],
        json!([{"day": "2026-11-01", "sent": 5, "completed": 3}])
    );
    let me = a.boot.admin.0.to_string();
    assert_eq!(
        v["top_senders"],
        json!([{"sender_user_id": me, "sent": 5, "completed": 3}])
    );

    // In UTC+03:00 the one completed at 21:00 UTC is completed the next day.
    let (_, v) = insights(&api, &a.auth, "?utc_offset_minutes=180").await;
    assert_eq!(
        v["days"],
        json!([{"day": "2026-11-01", "sent": 5, "completed": 2},
               {"day": "2026-11-02", "sent": 0, "completed": 1}])
    );
    // A window that leaves them out (by creation) counts nothing.
    let (_, v) = insights(&api, &a.auth, "?to=2000-01-01T00:00:00Z").await;
    assert_eq!(v["totals"]["created"], 0);
    assert!(v["time_to_complete"]["median_seconds"].is_null());
    // Refused: an offset beyond 14 hours, an empty window, a sender that is not an id.
    for q in [
        "?utc_offset_minutes=900",
        "?from=2026-01-02T00:00:00Z&to=2026-01-01T00:00:00Z",
        "?sender=x",
    ] {
        let (s, v) = insights(&api, &a.auth, q).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{q}: {v}");
    }

    // A sender without reports.read: their own envelopes only.
    ok(
        api.call(
            "POST",
            "/api/v1/users",
            &a.auth,
            Some(json!({"email": "sam@alpha.example.test", "name": "Sam",
                "profile": "sender", "password": PASSWORD})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "user",
    );
    let login = api
        .call(
            "POST",
            "/api/v1/auth/login",
            &Auth::None,
            Some(json!({"email": "sam@alpha.example.test", "password": PASSWORD})),
            &[],
        )
        .await;
    let sam = session_of(&login);
    let (s, v) = insights(&api, &sam, "").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["scope"], "own");
    assert_eq!(v["totals"]["created"], 0, "{v}");
    assert_eq!(v["top_senders"], json!([]));
    let (s, v) = insights(&api, &sam, "?sender=me").await;
    assert_eq!((s, &v["totals"]["created"]), (StatusCode::OK, &json!(0)));
    let (s, v) = insights(&api, &sam, &format!("?sender={me}")).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
}
