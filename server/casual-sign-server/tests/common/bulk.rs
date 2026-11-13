//! Bulk send from a template end to end (UXW-04), shared by `tests/bulk_send.rs` and
//! the contract scenario (which must call every operation).

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::flow::{b64, ok};
use super::harness::{Api, Auth, pdf};

/// A template with one two-page document, two signer roles in order (`Tenant`, then
/// `Landlord`) and a signature field for each; answers its id.
pub async fn lease_template(api: &Api, auth: &Auth) -> String {
    let t = ok(
        api.call(
            "POST",
            "/api/v1/templates",
            auth,
            Some(
                json!({"name": "Lease", "email_subject": "Please sign the lease",
                "roles": [{"name": "Tenant", "type": "signer", "routing_order": 1},
                          {"name": "Landlord", "type": "signer", "routing_order": 2}]}),
            ),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "template",
    );
    let id = t["id"].as_str().unwrap().to_owned();
    let base = format!("/api/v1/templates/{id}");
    let with_doc = ok(
        api.call(
            "POST",
            &format!("{base}/documents"),
            auth,
            Some(json!({"name": "lease.pdf", "content_base64": b64(&pdf(2))})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "template document",
    );
    let doc = with_doc["documents"][0]["id"].as_str().unwrap().to_owned();
    let role = |name: &str| {
        t["roles"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == name)
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let at = |role: String, y: &str| {
        json!({"role_id": role, "document_id": doc, "type": "signature", "required": true,
               "placement": {"page": 2, "x": "72", "y": y, "width": "160", "height": "36"}})
    };
    ok(
        api.call(
            "POST",
            &format!("{base}/fields"),
            auth,
            Some(json!({"items": [at(role("Tenant"), "100"), at(role("Landlord"), "200")]})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "template fields",
    );
    id
}

/// The list the tests send: two good rows, one with a bad email, one missing a name.
pub const CSV: &str = "Tenant::name,Tenant::email,Landlord::name,Landlord::email\r\n\
Ann Lee,ann@example.test,Lou Park,lou@example.test\r\n\
\"Bo, Jr.\",bo@example.test,Lou Park,lou@example.test\r\n\
Cy Moe,not-an-email,Lou Park,lou@example.test\r\n\
,dee@example.test,Lou Park,lou@example.test\r\n";

/// Every bulk-send operation: check the list, make the batch, send it to the end,
/// read it and list it, and cancel a second one. Answers the finished batch.
pub async fn bulk_send(api: &Api, auth: &Auth) -> Value {
    let tid = lease_template(api, auth).await;
    let checked = ok(
        api.call(
            "POST",
            "/api/v1/bulk-sends",
            auth,
            Some(json!({"template_id": tid, "csv": CSV, "validate_only": true})),
            &[],
        )
        .await,
        StatusCode::OK,
        "check the list",
    );
    assert_eq!(checked["row_count"], 4);
    assert_eq!(checked["valid"], 2);
    let made = ok(
        api.call(
            "POST",
            "/api/v1/bulk-sends",
            auth,
            Some(json!({"template_id": tid, "name": "Spring leases", "csv": CSV})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "make the batch",
    );
    let id = made["id"].as_str().unwrap().to_owned();
    let mut last = made;
    // Each call sends at most a step of rows; the caller repeats until none is pending.
    for _ in 0..10 {
        if last["counts"]["pending"] == 0 {
            break;
        }
        last = ok(
            api.call(
                "POST",
                &format!("/api/v1/bulk-sends/{id}/send"),
                auth,
                None,
                &[],
            )
            .await,
            StatusCode::OK,
            "send rows",
        );
    }
    let got = ok(
        api.call("GET", &format!("/api/v1/bulk-sends/{id}"), auth, None, &[])
            .await,
        StatusCode::OK,
        "read the batch",
    );
    assert_eq!(got, last);
    let listed = ok(
        api.call("GET", "/api/v1/bulk-sends", auth, None, &[]).await,
        StatusCode::OK,
        "list batches",
    );
    assert!(
        listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["id"] == id.as_str())
    );
    // A second batch, cancelled before it is sent: nothing of it is sent.
    let other = ok(
        api.call(
            "POST",
            "/api/v1/bulk-sends",
            auth,
            Some(json!({"template_id": tid, "csv": CSV})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "second batch",
    );
    let cancelled = ok(
        api.call(
            "POST",
            &format!(
                "/api/v1/bulk-sends/{}/cancel",
                other["id"].as_str().unwrap()
            ),
            auth,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "cancel",
    );
    assert_eq!(cancelled["status"], "cancelled");
    assert_eq!(cancelled["counts"]["cancelled"], 2);
    assert_eq!(cancelled["counts"]["sent"], 0);
    last
}
