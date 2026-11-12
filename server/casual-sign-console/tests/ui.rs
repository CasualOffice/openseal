//! The console serves its own UI (CON-17): the page and its files from the binary, with
//! the page's Content Security Policy and cache headers, nothing else; the API keeps
//! its `no-store` and its policy that loads nothing.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use casual_sign_console::crypto::MfaKey;
use casual_sign_console::{AppState, Config, SystemClock};
use casual_sign_platform_store::PlatformStore;
use casual_sign_platform_store::sqlx::postgres::PgPoolOptions;
use http_body_util::BodyExt;
use tower::ServiceExt;

fn app() -> Router {
    // A pool that never connects: the UI needs no database.
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
    casual_sign_console::app(state)
}

async fn send(method: Method, path: &str) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let resp = app()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, headers, body)
}

#[tokio::test]
async fn the_page_is_served_with_its_content_security_policy() {
    let (status, h, body) = send(Method::GET, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h["content-type"], "text/html; charset=utf-8");
    let csp = h["content-security-policy"].to_str().unwrap();
    assert!(csp.starts_with("default-src 'self'"), "{csp}");
    for part in [
        "script-src 'self'",
        "style-src 'self'",
        "frame-ancestors 'none'",
        "object-src 'none'",
    ] {
        assert!(csp.contains(part), "{part} missing from {csp}");
    }
    assert!(!csp.contains("unsafe"), "{csp}");
    assert_eq!(h["cache-control"], "no-cache");
    assert_eq!(h["x-frame-options"], "DENY");
    assert_eq!(h["x-content-type-options"], "nosniff");
    let html = String::from_utf8(body).unwrap();
    assert!(html.contains(r#"<script type="module" src="/app.js"></script>"#));
    assert!(!html.contains("<script>"), "no inline script");
    assert!(!html.contains("style="), "no inline style");
}

#[tokio::test]
async fn every_file_has_its_type_and_fonts_are_cached_for_a_year() {
    for (path, ct, cache) in [
        ("/app.js", "text/javascript; charset=utf-8", "no-cache"),
        ("/api.js", "text/javascript; charset=utf-8", "no-cache"),
        ("/model.js", "text/javascript; charset=utf-8", "no-cache"),
        ("/dom.js", "text/javascript; charset=utf-8", "no-cache"),
        ("/art.js", "text/javascript; charset=utf-8", "no-cache"),
        ("/console.css", "text/css; charset=utf-8", "no-cache"),
        (
            "/fonts/geist-1.3.1-variable.woff2",
            "font/woff2",
            "public, max-age=31536000, immutable",
        ),
        (
            "/fonts/geist-mono-1.3.1-variable.woff2",
            "font/woff2",
            "public, max-age=31536000, immutable",
        ),
        (
            "/fonts/OFL-1.1-Geist.txt",
            "text/plain; charset=utf-8",
            "no-cache",
        ),
    ] {
        let (status, h, body) = send(Method::GET, path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(h["content-type"], ct, "{path}");
        assert_eq!(h["cache-control"], cache, "{path}");
        assert!(!body.is_empty(), "{path}");
    }
    let (status, h, body) = send(Method::HEAD, "/app.js").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h["content-type"], "text/javascript; charset=utf-8");
    assert!(body.is_empty());
}

/// Every file the page and its modules name is one the binary serves.
#[tokio::test]
async fn everything_the_ui_references_is_served() {
    let mut refs = Vec::new();
    let (_, _, page) = send(Method::GET, "/").await;
    let page = String::from_utf8(page).unwrap();
    for attr in ["src=\"", "href=\""] {
        for part in page.split(attr).skip(1) {
            let r = part.split('"').next().unwrap();
            if r.starts_with('/') {
                refs.push(r.to_owned());
            }
        }
    }
    for module in ["/app.js", "/api.js", "/model.js", "/dom.js", "/art.js"] {
        let (_, _, js) = send(Method::GET, module).await;
        for part in String::from_utf8(js).unwrap().split("from \"./").skip(1) {
            refs.push(format!("/{}", part.split('"').next().unwrap()));
        }
    }
    let (_, _, css) = send(Method::GET, "/console.css").await;
    for part in String::from_utf8(css).unwrap().split("url(\"").skip(1) {
        refs.push(part.split('"').next().unwrap().to_owned());
    }
    assert!(refs.len() > 8, "{refs:?}");
    for r in refs {
        let (status, _, _) = send(Method::GET, &r).await;
        assert_eq!(status, StatusCode::OK, "{r} is referenced but not served");
    }
}

#[tokio::test]
async fn an_unknown_file_is_a_404_problem_and_no_path_reaches_the_disk() {
    for path in [
        "/nope.js",
        "/fonts/missing.woff2",
        "/../Cargo.toml",
        "/%2e%2e/Cargo.toml",
        "/console-ui/app.js",
        "/package.json",
        "/tests/model.test.mjs",
    ] {
        let (status, h, _) = send(Method::GET, path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(h["content-type"], "application/problem+json", "{path}");
        assert_eq!(h["cache-control"], "no-store", "{path}");
    }
    // Only reads: a write to a UI path is the API's 404.
    let (status, _, _) = send(Method::POST, "/").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_api_keeps_its_own_headers() {
    let (status, h, _) = send(Method::GET, "/livez").await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(h["cache-control"], "no-store");
    assert!(
        h["content-security-policy"]
            .to_str()
            .unwrap()
            .starts_with("default-src 'none'")
    );
}
