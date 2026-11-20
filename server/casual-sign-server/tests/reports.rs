//! Workspace reports (`VS-06`, `UXW-25`): the envelope, recipient and usage reports over
//! a window, as JSON and as formula-safe CSV; a member without `reports.read` is
//! refused; another account's envelopes are never in them.

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

async fn sent(api: &Api, t: &Tenant, subject: &str, signer: &str) -> Value {
    ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            &t.auth,
            Some(json!({
                "subject": subject, "status": "sent",
                "documents": [{"name": "d.pdf", "content_base64": b64(&pdf(1))}],
                "recipients": [{"ref": "s", "type": "signer", "name": signer,
                    "email": "sig@example.test", "routing_order": 1}],
                "fields": [{"recipient": "s", "document": 0, "type": "signature", "page": 1,
                    "x": 72, "y": 100, "width": 180, "height": 40, "required": true}],
            })),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "create",
    )
}

#[tokio::test]
async fn the_three_reports_answer_json_and_formula_safe_csv_to_reports_read_only() {
    let Some(api) = Api::new("reports", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let one = sent(&api, &a, "Lease 1", "=HYPERLINK(\"http://x\")").await;
    let two = sent(&api, &a, "Lease 2", "Bea").await;
    ok(
        api.call(
            "POST",
            &format!("/api/v1/envelopes/{}/void", two["id"].as_str().unwrap()),
            &a.auth,
            Some(json!({"reason": "Superseded"})),
            &[],
        )
        .await,
        StatusCode::OK,
        "void",
    );
    let b = api.tenant("beta").await;
    sent(&api, &b, "Other account", "Zed").await;

    let env = ok(
        api.call("GET", "/api/v1/reports/envelopes", &a.auth, None, &[])
            .await,
        StatusCode::OK,
        "envelope report",
    );
    let mut subjects: Vec<&str> = env["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["subject"].as_str().unwrap())
        .collect();
    subjects.sort_unstable();
    assert_eq!(subjects, ["Lease 1", "Lease 2"], "this account's only");
    assert_eq!(env["truncated"], false);
    assert_eq!(env["items"][0]["recipients"], 1);

    let rec = ok(
        api.call("GET", "/api/v1/reports/recipients", &a.auth, None, &[])
            .await,
        StatusCode::OK,
        "recipient report",
    );
    assert_eq!(rec["items"].as_array().unwrap().len(), 2);

    let usage = ok(
        api.call("GET", "/api/v1/reports/usage", &a.auth, None, &[])
            .await,
        StatusCode::OK,
        "usage report",
    );
    assert_eq!(usage["items"][0]["created"], 2);
    assert_eq!(usage["items"][0]["sent"], 2);
    assert_eq!(usage["items"][0]["voided"], 1);

    // A window that ends before anything was created is empty; one that is backwards is refused.
    let empty = ok(
        api.call(
            "GET",
            "/api/v1/reports/envelopes?to=2000-01-01T00:00:00Z",
            &a.auth,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "early",
    );
    assert_eq!(empty["items"], json!([]));
    let r = api
        .call(
            "GET",
            "/api/v1/reports/envelopes?from=2030-01-01T00:00:00Z&to=2000-01-01T00:00:00Z",
            &a.auth,
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    // `limit` reached is said.
    let capped = ok(
        api.call(
            "GET",
            "/api/v1/reports/envelopes?limit=1",
            &a.auth,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "capped",
    );
    assert_eq!(capped["truncated"], true);

    // CSV: a header, CRLF, a name a spreadsheet would run written as text.
    let csv = api
        .call(
            "GET",
            "/api/v1/reports/recipients?format=csv",
            &a.auth,
            None,
            &[],
        )
        .await;
    assert_eq!(csv.status, StatusCode::OK);
    let text = String::from_utf8(csv.body.to_vec()).unwrap();
    assert!(
        text.starts_with(
            "envelope_id,subject,envelope_status,routing_order,name,email,type,status\r\n"
        ),
        "{text}"
    );
    assert!(text.contains("\"'=HYPERLINK(\"\"http://x\"\")\""), "{text}");
    assert!(!text.contains(",=HYPERLINK"), "{text}");
    let _ = one;

    // An unknown report is 404; a sender (no reports.read) is refused.
    let r = api
        .call("GET", "/api/v1/reports/secrets", &a.auth, None, &[])
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
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
    let r = api
        .call("GET", "/api/v1/reports/envelopes", &sam, None, &[])
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{:?}", r.json());
}
