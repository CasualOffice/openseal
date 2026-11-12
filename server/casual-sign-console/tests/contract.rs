//! The console's route table, its OpenAPI document (`api/console-openapi.yaml`) and its
//! router agree, operation by operation with each operation's `x-roles`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use casual_sign_console::crypto::MfaKey;
use casual_sign_console::{AppState, Config, ROUTES, SystemClock};
use casual_sign_platform_store::PlatformStore;
use casual_sign_platform_store::sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

fn document() -> serde_norway::Value {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../api/console-openapi.yaml");
    serde_norway::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn the_route_table_and_the_openapi_document_are_equal() {
    let doc = document();
    let paths = doc["paths"].as_mapping().unwrap();
    let mut in_doc = BTreeSet::new();
    for (path, item) in paths {
        for (method, op) in item.as_mapping().unwrap() {
            let method = method.as_str().unwrap().to_uppercase();
            let roles = op["x-roles"]
                .as_str()
                .unwrap_or_else(|| panic!("{method} {path:?} has no x-roles"));
            in_doc.insert((method, path.as_str().unwrap().to_owned(), roles.to_owned()));
        }
    }
    let in_code: BTreeSet<_> = ROUTES
        .iter()
        .map(|(m, p, r)| ((*m).to_owned(), (*p).to_owned(), (*r).to_owned()))
        .collect();
    let only_doc: Vec<_> = in_doc.difference(&in_code).collect();
    let only_code: Vec<_> = in_code.difference(&in_doc).collect();
    assert!(
        only_doc.is_empty(),
        "in console-openapi.yaml, not in ROUTES: {only_doc:?}"
    );
    assert!(
        only_code.is_empty(),
        "in ROUTES, not in console-openapi.yaml: {only_code:?}"
    );
    for (_, _, r) in ROUTES {
        assert!(
            ["public", "pending", "any", "operators", "owners"].contains(r),
            "unknown roles {r}"
        );
    }
}

/// Every route in the table is served (the router answers something other than the
/// fallback's 404 or 405), and an unknown path answers a problem body.
#[tokio::test]
async fn every_listed_route_is_served() {
    // A pool that never connects: requests that reach the database fail with 503, which
    // still proves the route exists.
    let pool = PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(50))
        .connect_lazy("postgres://nobody:none@127.0.0.1:9/none")
        .unwrap();
    let state = AppState::new(
        PlatformStore::new(pool),
        MfaKey::new(&[1u8; 32]).unwrap(),
        Arc::new(SystemClock),
        Config::default(),
    )
    .unwrap();
    let app = casual_sign_console::app(state);
    for (method, path, _) in ROUTES {
        let p = path.replace("{id}", "0190c8e2-0000-7000-8000-000000000000");
        let req = Request::builder()
            .method(*method)
            .uri(&p)
            .header("content-type", "application/json")
            .header("cookie", "__Host-os_op=x")
            .header("x-csrf-token", "x")
            .body(Body::from("{}"))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let s = resp.status();
        assert!(
            s != StatusCode::NOT_FOUND && s != StatusCode::METHOD_NOT_ALLOWED,
            "{method} {p} is not served ({s})"
        );
        let h = resp.headers();
        assert_eq!(h["cache-control"], "no-store", "{method} {p}");
        assert!(
            h["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("frame-ancestors 'none'")
        );
    }
    let resp = app
        .clone()
        .oneshot(Request::builder().uri("/nope").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(resp.headers()["content-type"], "application/problem+json");
}
