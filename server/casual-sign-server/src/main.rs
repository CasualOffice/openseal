//! `casual-sign-server`: serve the API, or `bootstrap` a first account.
//!
//! Configuration is the environment (secrets through `casual-sign-secrets`, so each
//! may come from a `*_FILE`):
//!
//! | Variable | Meaning |
//! | --- | --- |
//! | `OPENSEAL_DATABASE_URL` (secret) | PostgreSQL URL of the application role |
//! | `OPENSEAL_JWT_SIGNING_KEY` (secret) | P-256 PKCS#8 private key, base64 DER or PEM |
//! | `OPENSEAL_BLOB_DIR` | Directory of the file blob store |
//! | `OPENSEAL_PUBLIC_URL` | Public base URL (links, token issuer) |
//! | `OPENSEAL_LISTEN` | Address to listen on (default `127.0.0.1:8080`) |
//! | `OPENSEAL_TRUSTED_PROXIES` | Comma-separated CIDRs whose forwarding headers count |
//! | `OPENSEAL_DEV_INSECURE_KEY=1` | Development only: a throwaway token key, plain-HTTP cookies |
//! | `OPENSEAL_ADMIN_PASSWORD` (secret) | `bootstrap` only: the first administrator's password |
//!
//! `casual-sign-server bootstrap <account name> <admin email> <admin name>` creates an
//! account, its built-in profiles and its first administrator, and prints their ids.

use std::process::ExitCode;
use std::sync::Arc;

use base64::Engine as _;
use casual_sign_secrets::env_secret;
use casual_sign_server::net::{Cidr, ClientIp};
use casual_sign_server::{AppState, Blobs, Config, JwtKeys, SystemClock, app, bootstrap};
use casual_sign_store::Store;
use casual_sign_store::blob::FsBlobStore;

fn fail(what: &str) -> ExitCode {
    eprintln!("casual-sign-server: {what}");
    ExitCode::FAILURE
}

fn secret(name: &str) -> Result<Option<String>, String> {
    env_secret(name)
        .map(|s| s.map(|s| s.expose().to_owned()))
        .map_err(|e| format!("{name}: {}", e.code()))
}

fn jwt_key() -> Result<JwtKeys, String> {
    match secret("OPENSEAL_JWT_SIGNING_KEY")? {
        Some(k) => {
            let b64: String = k
                .lines()
                .filter(|l| !l.starts_with("-----"))
                .collect::<Vec<_>>()
                .join("");
            let der = base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .map_err(|_| "OPENSEAL_JWT_SIGNING_KEY: not base64 or PEM".to_owned())?;
            JwtKeys::from_pkcs8(&der).map_err(|e| format!("OPENSEAL_JWT_SIGNING_KEY: {}", e.code()))
        }
        None if std::env::var("OPENSEAL_DEV_INSECURE_KEY").as_deref() == Ok("1") => {
            eprintln!("casual-sign-server: development token key; never in production");
            JwtKeys::generate().map_err(|e| e.code().to_owned())
        }
        None => Err("OPENSEAL_JWT_SIGNING_KEY is not set".into()),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_ansi(false)
        .init();
    let url = match secret("OPENSEAL_DATABASE_URL") {
        Ok(Some(u)) => u,
        Ok(None) => return fail("OPENSEAL_DATABASE_URL is not set"),
        Err(e) => return fail(&e),
    };
    let store = match Store::connect(&url, 16).await {
        Ok(s) => s,
        Err(e) => return fail(e.code()),
    };
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("bootstrap") {
        let (Some(name), Some(email), Some(admin)) = (args.get(2), args.get(3), args.get(4)) else {
            return fail("usage: bootstrap <account name> <admin email> <admin name>");
        };
        let pw = match secret("OPENSEAL_ADMIN_PASSWORD") {
            Ok(Some(p)) => p,
            Ok(None) => return fail("OPENSEAL_ADMIN_PASSWORD is not set"),
            Err(e) => return fail(&e),
        };
        return match bootstrap(&store, name, email, admin, &pw).await {
            Ok(b) => {
                println!("account {}\nadmin {}", b.account, b.admin);
                ExitCode::SUCCESS
            }
            Err(e) => fail(e.code()),
        };
    }
    let jwt = match jwt_key() {
        Ok(k) => k,
        Err(e) => return fail(&e),
    };
    let Ok(dir) = std::env::var("OPENSEAL_BLOB_DIR") else {
        return fail("OPENSEAL_BLOB_DIR is not set");
    };
    let blobs = match FsBlobStore::new(&dir) {
        Ok(b) => Blobs::Fs(Arc::new(b)),
        Err(e) => return fail(e.code()),
    };
    let mut config = Config::default();
    if let Ok(u) = std::env::var("OPENSEAL_PUBLIC_URL") {
        config.public_url = u.trim_end_matches('/').to_owned();
    }
    if let Ok(list) = std::env::var("OPENSEAL_TRUSTED_PROXIES") {
        for c in list.split(',').filter(|c| !c.trim().is_empty()) {
            match Cidr::parse(c) {
                Some(c) => config.trusted_proxies.push(c),
                None => return fail("OPENSEAL_TRUSTED_PROXIES: not a CIDR list"),
            }
        }
    }
    config.secure_cookies = std::env::var("OPENSEAL_DEV_INSECURE_KEY").as_deref() != Ok("1");
    let state = match AppState::new(store, blobs, jwt, Arc::new(SystemClock), config) {
        Ok(s) => s,
        Err(e) => return fail(e.code()),
    };
    let listen = std::env::var("OPENSEAL_LISTEN").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let listener = match tokio::net::TcpListener::bind(&listen).await {
        Ok(l) => l,
        Err(_) => return fail("cannot listen"),
    };
    let _ = ClientIp::default;
    let service = app(state).into_make_service_with_connect_info::<std::net::SocketAddr>();
    if axum::serve(listener, service)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .is_err()
    {
        return fail("server stopped");
    }
    ExitCode::SUCCESS
}
