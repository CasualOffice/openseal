//! ASVS 2.4.5, `ASVS-29`: staff password hashes are keyed with a pepper held outside the
//! database. A hash made before the pepper was configured still verifies, and the sign-in
//! that verifies it stores a new hash under the pepper; from then on a server on the same
//! database without the pepper (a copy of the database alone) cannot verify the password.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use casual_sign_server::{AppState, Blobs, Config, JwtKeys, ManualClock, PasswordPepper, app};
use casual_sign_store::blob::FsBlobStore;
use common::Rls;
use common::harness::{Api, Auth, PASSWORD, start};
use serde_json::json;
use tower::ServiceExt;

/// What `users.password_hash` holds for `user`, read as the schema owner.
async fn stored(api: &Api, user: uuid::Uuid) -> String {
    sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
        .bind(user)
        .fetch_one(&api.db.admin)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_pepper_rehashes_an_old_hash_at_sign_in_and_a_database_copy_alone_cannot_verify() {
    let Some(api) = Api::new("password_pepper", Rls::On).await else {
        return;
    };
    // The administrator's hash is made before any pepper.
    let (boot, email) = api.bare_tenant("pepper").await;
    let before = stored(&api, boot.admin.0).await;
    assert!(!before.contains("keyid="), "{before}");

    // The operator configures a pepper; the old hash still verifies, and is re-made.
    let pepper = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
    api.st
        .set_password_pepper(PasswordPepper::new(&pepper, None).unwrap());
    let login = |password: &str| json!({"email": email, "password": password});
    let r = api
        .call(
            "POST",
            "/api/v1/auth/login",
            &Auth::None,
            Some(login(PASSWORD)),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let after = stored(&api, boot.admin.0).await;
    assert_ne!(after, before);
    assert!(after.contains("keyid="), "{after}");

    // Under the pepper: the right password passes, a wrong one does not.
    let r = api
        .call(
            "POST",
            "/api/v1/auth/login",
            &Auth::None,
            Some(login(PASSWORD)),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    assert_eq!(stored(&api, boot.admin.0).await, after, "re-made only once");
    let r = api
        .call(
            "POST",
            "/api/v1/auth/login",
            &Auth::None,
            Some(login("not the password at all")),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    // A server on the same database without the pepper: the right password is refused.
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("blobs-{}", uuid::Uuid::now_v7()));
    let copy = AppState::new(
        api.db.store.clone(),
        Blobs::Fs(Arc::new(FsBlobStore::new(dir).unwrap())),
        JwtKeys::generate().unwrap(),
        Arc::new(ManualClock::at(start())),
        Config {
            public_url: "https://sign.example.test".into(),
            ..Config::default()
        },
    )
    .unwrap();
    let mut req = Request::post("/api/v1/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(login(PASSWORD).to_string()))
        .unwrap();
    req.extensions_mut().insert(ConnectInfo(
        "198.51.100.8:50000"
            .parse::<std::net::SocketAddr>()
            .unwrap(),
    ));
    let r = app(copy).oneshot(req).await.unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    api.db.drop().await;
}
