//! Envelope id stamping (`FG-009`, ADR-045): `signing_options.stamp_envelope_id` per
//! envelope, defaulting to the account's `stamp_envelope_id` setting when a request does
//! not say; the signing page is told through the envelope's options, and the document as
//! it stands (`content?version=current`) carries "Envelope ID: <id>" on every page, as
//! the seal will (the sealed document is checked by the worker's end-to-end test).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

mod common;

use axum::http::StatusCode;
use common::Rls;
use common::flow::{b64, ok, sent};
use common::harness::{Api, Tenant, pdf};
use serde_json::{Value, json};

/// Every page's text.
fn pages_of(pdf: &[u8]) -> Vec<String> {
    let never = || false;
    let mut a = casual_sign_pdf::admit(pdf, &casual_sign_pdf::Limits::default(), &never).unwrap();
    let pages = a.report.pages.clone();
    casual_sign_fields::extract_text(&mut a.document, &pages, &never)
        .unwrap()
        .iter()
        .map(|p| {
            p.runs
                .iter()
                .map(|r| r.text.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect()
}

async fn draft(api: &Api, t: &Tenant, options: Option<Value>) -> Value {
    let mut body = json!({
        "subject": "FG-009",
        "documents": [{"name": "w.pdf", "content_base64": b64(&pdf(1))}],
    });
    if let Some(o) = options {
        body["signing_options"] = o;
    }
    ok(
        api.call("POST", "/api/v1/envelopes", &t.auth, Some(body), &[])
            .await,
        StatusCode::CREATED,
        "create draft",
    )
}

fn stamped(e: &Value) -> bool {
    e["signing_options"]
        .get("stamp_envelope_id")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// The document as it stands now, with the values completed so far.
async fn current(api: &Api, t: &Tenant, e: &Value) -> Vec<u8> {
    let (id, doc) = (
        e["id"].as_str().unwrap(),
        e["documents"][0]["id"].as_str().unwrap(),
    );
    let r = api
        .call(
            "GET",
            &format!("/api/v1/envelopes/{id}/documents/{doc}/content?version=current"),
            &t.auth,
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    r.body.to_vec()
}

#[tokio::test]
async fn the_envelope_id_is_stamped_on_every_page_when_the_envelope_or_account_says() {
    let Some(api) = Api::new("envelope_id_stamp", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;

    // Off by default, and absent from the options when off.
    let e = draft(&api, &a, None).await;
    assert!(e["signing_options"].get("stamp_envelope_id").is_none());
    assert!(stamped(
        &draft(&api, &a, Some(json!({"stamp_envelope_id": true}))).await
    ));

    // The account's default: a boolean only.
    let bad = api
        .call(
            "PATCH",
            "/api/v1/accounts/me",
            &a.auth,
            Some(json!({"settings": {"stamp_envelope_id": "yes"}})),
            &[],
        )
        .await;
    assert_eq!(
        bad.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{:?}",
        bad.json()
    );
    ok(
        api.call(
            "PATCH",
            "/api/v1/accounts/me",
            &a.auth,
            Some(json!({"settings": {"stamp_envelope_id": true}})),
            &[],
        )
        .await,
        StatusCode::OK,
        "account default on",
    );
    // A request that does not say takes it; one that says keeps what it says.
    assert!(stamped(&draft(&api, &a, None).await));
    assert!(stamped(
        &draft(&api, &a, Some(json!({"capture_location": false}))).await
    ));
    assert!(!stamped(
        &draft(&api, &a, Some(json!({"stamp_envelope_id": false}))).await
    ));

    // Sent with the account's default: two pages, each stamped with this envelope's id.
    let e = sent(&api, &a, 1, &[]).await;
    assert!(stamped(&e), "{}", e["signing_options"]);
    let line = format!("Envelope ID: {}", e["id"].as_str().unwrap());
    let pages = pages_of(&current(&api, &a, &e).await);
    assert_eq!(pages.len(), 2);
    for p in &pages {
        assert_eq!(p.matches(&line).count(), 1, "{p}");
    }

    // Off again: a new envelope is not stamped.
    ok(
        api.call(
            "PATCH",
            "/api/v1/accounts/me",
            &a.auth,
            Some(json!({"settings": {"stamp_envelope_id": null}})),
            &[],
        )
        .await,
        StatusCode::OK,
        "account default removed",
    );
    let e = sent(&api, &a, 1, &[]).await;
    assert!(!stamped(&e));
    let pages = pages_of(&current(&api, &a, &e).await);
    assert!(
        pages.iter().all(|p| !p.contains("Envelope ID")),
        "{pages:?}"
    );
}
