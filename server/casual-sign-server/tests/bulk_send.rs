//! Bulk send from a template (UXW-04): a CSV list becomes one sent envelope per valid
//! row, made from the template's document, roles and fields; a row with a problem is
//! reported with its column and code and never sent; progress is read between steps;
//! another account cannot see or send the batch.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines
)]

mod common;

use axum::http::StatusCode;
use common::Rls;
use common::bulk::{CSV, bulk_send, lease_template};
use common::harness::Api;
use serde_json::json;

#[tokio::test]
async fn a_csv_list_sends_one_envelope_per_valid_row_and_reports_the_others() {
    let Some(api) = Api::new("bulk_send", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let b = api.tenant("beta").await;
    let done = bulk_send(&api, &a.auth).await;
    assert_eq!(done["status"], "completed", "{done}");
    assert!(done["finished_at"].is_string());
    assert_eq!(
        done["counts"],
        json!({"pending": 0, "sent": 2, "failed": 2, "cancelled": 0})
    );
    let rows = done["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 4);
    // Per-row problems: the column and the code, never sent.
    assert_eq!(rows[2]["status"], "failed");
    assert_eq!(
        rows[2]["problems"],
        json!([{"column": "Tenant::email", "code": "CS-BLK-0002"}])
    );
    assert!(rows[2]["envelope_id"].is_null());
    assert_eq!(rows[3]["status"], "failed");
    assert_eq!(rows[3]["error_code"], "CS-BLK-0001");
    // Each sent row is a sent envelope from the template, to the row's people, in the
    // template's routing order, with the template's fields.
    for (row, (tenant, email)) in [
        (0, ("Ann Lee", "ann@example.test")),
        (1, ("Bo, Jr.", "bo@example.test")),
    ] {
        assert_eq!(rows[row]["status"], "sent");
        let env = rows[row]["envelope_id"].as_str().unwrap();
        let e = api
            .call(
                "GET",
                &format!("/api/v1/envelopes/{env}"),
                &a.auth,
                None,
                &[],
            )
            .await
            .json();
        assert_eq!(e["status"], "sent", "{e}");
        assert_eq!(e["subject"], "Please sign the lease");
        let rs = e["recipients"].as_array().unwrap();
        assert_eq!(rs.len(), 2);
        assert_eq!(
            (rs[0]["name"].as_str(), rs[0]["email"].as_str()),
            (Some(tenant), Some(email))
        );
        assert_eq!(rs[0]["routing_order"], 1);
        assert_eq!(rs[1]["name"], "Lou Park");
        assert_eq!(rs[1]["routing_order"], 2);
        assert_eq!(e["documents"].as_array().unwrap().len(), 1);
        assert_eq!(e["fields"].as_array().unwrap().len(), 2);
        // The envelope knows its batch in the database (envelopes.bulk_send_id).
        let batch: Option<uuid::Uuid> =
            sqlx::query_scalar("SELECT bulk_send_id FROM envelopes WHERE id = $1::uuid")
                .bind(env)
                .fetch_one(&api.db.admin)
                .await
                .unwrap();
        assert_eq!(batch.map(|u| u.to_string()).as_deref(), done["id"].as_str());
    }

    // Another account: not found, and nothing it sends is listed or sent.
    let id = done["id"].as_str().unwrap();
    for (m, p) in [
        ("GET", format!("/api/v1/bulk-sends/{id}")),
        ("POST", format!("/api/v1/bulk-sends/{id}/send")),
        ("POST", format!("/api/v1/bulk-sends/{id}/cancel")),
    ] {
        let r = api.call(m, &p, &b.auth, None, &[]).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{m} {p}");
    }
    let theirs = api
        .call("GET", "/api/v1/bulk-sends", &b.auth, None, &[])
        .await;
    assert_eq!(theirs.json()["items"], json!([]));
    // Another account's template is not one to send from.
    let tid = done["template_id"].as_str().unwrap();
    let r = api
        .call(
            "POST",
            "/api/v1/bulk-sends",
            &b.auth,
            Some(json!({"template_id": tid, "csv": CSV})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn a_list_whose_columns_do_not_fit_the_template_is_refused_whole() {
    let Some(api) = Api::new("bulk_send_columns", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let tid = lease_template(&api, &a.auth).await;
    let send = |csv: String| {
        let api = &api;
        let auth = &a.auth;
        let tid = tid.clone();
        async move {
            api.call(
                "POST",
                "/api/v1/bulk-sends",
                auth,
                Some(json!({"template_id": tid, "csv": csv})),
                &[],
            )
            .await
        }
    };
    // A missing role column and an unknown one.
    let r = send("Tenant::name,Tenant::email,Owner::email\nA,a@x.test,b@x.test\n".into()).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    let codes: Vec<String> = r.json()["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            format!(
                "{} {}",
                e["pointer"].as_str().unwrap(),
                e["code"].as_str().unwrap()
            )
        })
        .collect();
    assert_eq!(codes, ["/columns/2 CS-BLK-0005", "/columns CS-BLK-0004"]);
    // A header and no rows; an unclosed quote; more than 1000 rows.
    let header = "tenant::NAME , Tenant::email,Landlord::name,Landlord::email";
    let mut big = format!("{header}\n");
    for i in 0..1001 {
        big.push_str(&format!("N{i},n{i}@x.test,L,l@x.test\n"));
    }
    for csv in [
        format!("{header}\n"),
        format!("{header}\n\"A,a@x.test,L,l@x.test\n"),
        big,
    ] {
        let r = send(csv).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(r.json()["errors"][0]["code"], "CS-BLK-0007");
    }
    // Nothing was stored.
    let listed = api
        .call("GET", "/api/v1/bulk-sends", &a.auth, None, &[])
        .await;
    assert_eq!(listed.json()["items"], json!([]));
}
