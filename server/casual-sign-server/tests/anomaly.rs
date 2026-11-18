//! ASVS-13: abnormal activity is detected and alerted (ASVS 8.1.4, 11.1.7, 11.1.8;
//! docs/65 §Logs). A burst of failed sign-ins from one client address, through the
//! router, raises one `alert.abnormal_activity` security event and one operator alert,
//! not one per request; the alert names the address only by its pseudonym; the burst
//! going on past the cooldown alerts once more and counts what was held back. A burst
//! of envelope sends or of bulk sends alerts once too (`ASVS-13A`).

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::StatusCode;
use casual_sign_server::{AbnormalActivity, AlertSink};
use common::Rls;
use common::bulk::{CSV, lease_template};
use common::flow::{b64, ok, sent};
use common::harness::{Api, Auth, Resp, pdf};
use serde_json::{Value, json};

const PEER: &str = "198.51.100.23";

#[derive(Debug, Default)]
struct Alerts(Mutex<Vec<AbnormalActivity>>);

impl AlertSink for Alerts {
    fn alert(&self, a: &AbnormalActivity) {
        self.0.lock().unwrap().push(a.clone());
    }
}

async fn login(api: &Api, email: &str) -> Resp {
    api.call(
        "POST",
        "/api/v1/auth/login",
        &Auth::None,
        Some(json!({"email": email, "password": "not the password at all"})),
        &[],
    )
    .await
}

fn alert_events(api: &Api) -> Vec<Value> {
    api.security
        .json()
        .into_iter()
        .filter(|l| l["event"] == "security" && l["kind"] == "alert.abnormal_activity")
        .collect()
}

#[tokio::test]
async fn a_burst_of_failed_sign_ins_from_one_address_raises_one_alert() {
    let Some(api) = Api::with("anomaly_burst", Rls::On, |c| {
        c.anomaly.auth_failures = 5;
        c.rate.login_per_minute = 1000;
    })
    .await
    else {
        return;
    };
    let alerts = Arc::new(Alerts::default());
    api.st.set_alert_sink(alerts.clone());
    api.set_peer(&format!("{PEER}:50000"));

    // Twenty failures, each for a different address so only the client trips.
    for i in 0..20 {
        let r = login(&api, &format!("guess{i}@anomaly.example.test")).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    let events = alert_events(&api);
    assert_eq!(events.len(), 1, "{events:?}");
    let e = &events[0];
    assert_eq!(e["rule"], "auth_failures");
    assert_eq!(e["code"], "CS-LOG-0002");
    assert_eq!(e["count"], 5);
    assert!(e["client"].as_str().unwrap().starts_with("p1:"), "{e}");
    assert!(e.get("principal").is_none(), "{e}");
    assert!(!e.to_string().contains(PEER), "{e}");
    assert!(!e.to_string().contains("anomaly.example.test"), "{e}");
    {
        let got = alerts.0.lock().unwrap();
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].rule, "auth_failures");
        assert_eq!(got[0].client.as_deref(), e["client"].as_str());
    }

    // Another address is counted apart and stays quiet below the threshold.
    api.set_peer("203.0.113.40:50000");
    for i in 0..4 {
        let _ = login(&api, &format!("other{i}@anomaly.example.test")).await;
    }
    let events = alert_events(&api);
    assert_eq!(events.len(), 1, "{events:?}");

    // Past the cooldown, the same address still failing alerts once more and counts
    // the trips held back.
    api.set_peer(&format!("{PEER}:50001"));
    api.clock.advance(Duration::from_secs(901));
    for i in 0..10 {
        let _ = login(&api, &format!("late{i}@anomaly.example.test")).await;
    }
    let events = alert_events(&api);
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(events[1]["suppressed"], 15, "{}", events[1]);
    assert_eq!(alerts.0.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn the_default_alert_is_an_abnormal_activity_line_beside_the_security_event() {
    let Some(api) = Api::with("anomaly_line", Rls::On, |c| {
        c.anomaly.rate_limited = 3;
        c.rate.login_per_minute = 2;
    })
    .await
    else {
        return;
    };
    api.set_peer(&format!("{PEER}:50000"));
    for _ in 0..12 {
        let _ = login(&api, "nobody@anomaly.example.test").await;
    }
    let lines = api.security.json();
    let alerts: Vec<&Value> = lines
        .iter()
        .filter(|l| l["event"] == "abnormal_activity")
        .collect();
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert_eq!(alerts[0]["level"], "WARN");
    assert_eq!(alerts[0]["rule"], "rate_limited");
    assert_eq!(alerts[0]["code"], "CS-LOG-0002");
    assert_eq!(alert_events(&api).len(), 1);
}

/// The rules of the operator alerts raised so far.
fn rules(alerts: &Alerts) -> Vec<&'static str> {
    alerts.0.lock().unwrap().iter().map(|a| a.rule).collect()
}

#[tokio::test]
async fn a_burst_of_envelope_sends_raises_one_alert() {
    // ASVS-13A: a hijacked account mailing on the operator's name. Sends one at a time
    // count by both routes; the third trips once, and more stay quiet in the cooldown.
    let Some(api) = Api::with("anomaly_sends", Rls::On, |c| {
        c.anomaly.sends = 3;
    })
    .await
    else {
        return;
    };
    let alerts = Arc::new(Alerts::default());
    api.st.set_alert_sink(alerts.clone());
    api.set_peer(&format!("{PEER}:50000"));
    let t = api.tenant("sender").await;
    sent(&api, &t, 1, &[]).await;
    sent(&api, &t, 1, &[]).await;
    assert!(rules(&alerts).is_empty(), "{:?}", alerts.0.lock().unwrap());
    // A draft, then `POST /envelopes/{id}/send`.
    let draft = ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            &t.auth,
            Some(json!({
                "subject": "ASVS-13A",
                "documents": [{"name": "d.pdf", "content_base64": b64(&pdf(1))}],
                "recipients": [{"type": "signer", "name": "D", "email": "d@example.test"}],
            })),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "draft",
    );
    // A draft is not a send.
    assert!(rules(&alerts).is_empty(), "{:?}", alerts.0.lock().unwrap());
    let id = draft["id"].as_str().unwrap();
    ok(
        api.call(
            "POST",
            &format!("/api/v1/envelopes/{id}/send"),
            &t.auth,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "send the draft",
    );
    assert_eq!(rules(&alerts), vec!["sends"]);
    let got = alerts.0.lock().unwrap()[0].clone();
    assert_eq!(got.count, 3);
    assert_eq!(got.code, "CS-LOG-0002");
    assert!(got.principal.is_some() || got.client.is_some(), "{got:?}");
    sent(&api, &t, 1, &[]).await;
    assert_eq!(rules(&alerts), vec!["sends"]);
    let events = alert_events(&api);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["rule"], "sends");
}

#[tokio::test]
async fn a_burst_of_bulk_sends_raises_one_alert_and_a_check_of_the_list_does_not_count() {
    let Some(api) = Api::with("anomaly_bulk", Rls::On, |c| {
        c.anomaly.bulk_sends = 2;
    })
    .await
    else {
        return;
    };
    let alerts = Arc::new(Alerts::default());
    api.st.set_alert_sink(alerts.clone());
    api.set_peer(&format!("{PEER}:50000"));
    let t = api.tenant("bulk").await;
    let tid = lease_template(&api, &t.auth).await;
    let bulk = |validate_only: bool| {
        let body = json!({"template_id": tid, "csv": CSV, "validate_only": validate_only});
        api.call("POST", "/api/v1/bulk-sends", &t.auth, Some(body), &[])
    };
    for _ in 0..3 {
        assert_eq!(bulk(true).await.status, StatusCode::OK);
    }
    assert_eq!(bulk(false).await.status, StatusCode::CREATED);
    assert!(rules(&alerts).is_empty(), "{:?}", alerts.0.lock().unwrap());
    assert_eq!(bulk(false).await.status, StatusCode::CREATED);
    assert_eq!(rules(&alerts), vec!["bulk_sends"]);
    assert_eq!(alerts.0.lock().unwrap()[0].count, 2);
}
