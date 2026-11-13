//! `casual-sign-server`: serve the API, or `bootstrap` a first account.
//!
//! Configuration is the environment (secrets through `casual-sign-secrets`, so each
//! may come from a `*_FILE`):
//!
//! | Variable | Meaning |
//! | --- | --- |
//! | `OPENSEAL_DATABASE_URL` (secret) | PostgreSQL URL of the application role |
//! | `OPENSEAL_JWT_SIGNING_KEY` (secret) | P-256 PKCS#8 private key, base64 DER or PEM |
//! | `OPENSEAL_JWT_PREVIOUS_KEY` (secret) | Optional, during a rotation: the key the signing key replaced; tokens it signed verify until they expire and it stays in JWKS (docs/65 §Rotation) |
//! | `OPENSEAL_BLOB_DIR` | Directory of the file blob store, or: |
//! | `OPENSEAL_S3_ENDPOINT`, `OPENSEAL_S3_BUCKET` | An S3-compatible bucket instead (created at start when missing) |
//! | `OPENSEAL_S3_REGION` | Its region (default `us-east-1`) |
//! | `OPENSEAL_S3_ACCESS_KEY`, `OPENSEAL_S3_SECRET_KEY` (secret) | Its credentials |
//! | `OPENSEAL_S3_VIRTUAL_HOST=1` | Virtual-host URLs (AWS) rather than path style (MinIO, SeaweedFS) |
//! | `OPENSEAL_S3_CA` | PEM file of the CA the object store's TLS certificate chains to, besides the platform's roots (a private CA, the production profile) |
//! | `OPENSEAL_SECRET_RELOAD_SECONDS` | How often the database URL file is read again for a rotated credential (default 30; `0` never; docs/65 §Rotation) |
//! | `OPENSEAL_WEBAPP_DIR` | The web app's folder (`webapp/`), served at `/` (row WEB-04); none: API only |
//! | `OPENSEAL_PUBLIC_URL` | Public base URL (links, token issuer) |
//! | `OPENSEAL_LISTEN` | Address to listen on (default `127.0.0.1:8080`) |
//! | `OPENSEAL_TRUSTED_PROXIES` | Comma-separated CIDRs whose forwarding headers count |
//! | `OPENSEAL_GEOIP_DB` | Optional GeoIP `.mmdb` the operator supplies (row GEO-01) |
//! | `OPENSEAL_ML_BUNDLE_ID` | The model bundle deployed with `casual-sign-modeld` (docs/33 §7); none: document analysis is not installed |
//! | `OPENSEAL_LOG_PSEUDONYM_KEY` (secret) | 32 bytes as base64: keys the pseudonyms security events give a presented e-mail or client address (ASVS-08); share it with the console so they match; none: a key per process; malformed: the server does not start (`CS-LOG-0001`) |
//! | `OPENSEAL_MFA_KEY` (secret) | 32 bytes as base64: seals staff TOTP seeds (ASVS-01); none: staff cannot enrol a second factor and no account may require one |
//! | `OPENSEAL_DEV_INSECURE_KEY=1` | Development only: a throwaway token key and second-factor key, plain-HTTP cookies |
//! | `OPENSEAL_CLAMD_ADDR` | `host:port` of ClamAV's clamd (ASVS-11): every upload is scanned before it is read or stored; none: nothing is scanned (a warning at start) |
//! | `OPENSEAL_CLAMD_TIMEOUT_SECS` | Most seconds one scan may take, 1 to 600 (default 60) |
//! | `OPENSEAL_CLAMD_MAX_BYTES` | Largest file sent to clamd (default 104857600, clamd's `StreamMaxLength`); at least the largest upload |
//! | `OPENSEAL_CLAMD_CONCURRENCY` | Scans at once, 1 to 64 (default 4) |
//! | `OPENSEAL_CLAMD_FAIL_OPEN=1` | Admit an upload clamd could not judge, recorded as `upload.unscanned_admitted`; default: refuse it (`503 CS-SCAN-0002`) |
//! | `OPENSEAL_ADMIN_PASSWORD` (secret) | `bootstrap` only: the first administrator's password |
//!
//! `casual-sign-server bootstrap <account name> <admin email> <admin name>` creates the
//! install's first organization and its first workspace (account), the built-in profiles
//! and the first administrator, who owns the organization, and prints their ids. It is
//! refused once any organization exists (docs/23 §2.1).
//!
//! `casual-sign-server migrate` applies every missing migration as the schema owner
//! named by `OPENSEAL_MIGRATE_DATABASE_URL` (secret), never the application role (T-2F).
//!
//! Backups and restores (ASVS-14, docs/65 §Backups; `tools/backup/openseal_backup.py`
//! runs them):
//!
//! - `casual-sign-server blobs-export <dir>` writes every blob of the configured store
//!   (`OPENSEAL_BLOB_DIR` or `OPENSEAL_S3_*`) to `<dir>/<sha256>`, checking each against
//!   its key; files already there are checked and kept.
//! - `casual-sign-server blobs-import <dir>` puts every file of `<dir>` into the store,
//!   refusing a name that is not a key or bytes that are not the name's.
//! - `casual-sign-server verify-evidence` connects as the schema owner
//!   (`OPENSEAL_MIGRATE_DATABASE_URL`, secret), rebuilds and verifies every envelope's
//!   audit chain, each workspace's and organization's admin log, and the operator log,
//!   then reads back every blob the evidence names from the store, each verified against
//!   its key: documents, certificates of completion, signature captures and the images
//!   they name, logos and attachments. It exits 0 only when all of it verifies,
//!   printing the counts.
//!
//! `casual-sign-server healthcheck` asks the server on `OPENSEAL_LISTEN` (its port, on
//! the loopback address) for `/.well-known/jwks.json` and exits 0 on `200`: a
//! container's health check with no shell or HTTP client in the image (T-2F).

use std::process::ExitCode;
use std::sync::Arc;

use base64::Engine as _;
use casual_sign_seclog::Level;
use casual_sign_secrets::env_secret;
use casual_sign_server::net::{Cidr, ClientIp};
use casual_sign_server::{
    AppState, Blobs, Config, JwtKeys, Scanner, ScannerConfig, SystemClock, app, bootstrap,
};
use casual_sign_store::Store;
use casual_sign_store::blob::{FsBlobStore, S3BlobStore, S3Config};

/// The `start_failed` line (one JSON line, ASVS-08) and a failing exit.
/// A docs/20 code in `what` is also its `code` field (`casual_sign_seclog::start_failed`).
fn fail(what: &str) -> ExitCode {
    casual_sign_seclog::start_failed(casual_sign_seclog::Service::Server, what);
    ExitCode::FAILURE
}

/// One JSON log line of the server's own (`casual-sign-seclog`, ASVS 1.7.1).
fn note(level: Level, event: &str, fields: &[(&str, &str)]) {
    casual_sign_seclog::write_strs(casual_sign_seclog::Service::Server, level, event, fields);
}

fn secret(name: &str) -> Result<Option<String>, String> {
    env_secret(name)
        .map(|s| s.map(|s| s.expose().to_owned()))
        .map_err(|e| format!("{name}: {}", e.code()))
}

/// The DER of a PKCS#8 key given as base64 or PEM.
fn pkcs8_der(name: &str, text: &str) -> Result<Vec<u8>, String> {
    let b64: String = text
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|_| format!("{name}: not base64 or PEM"))
}

fn jwt_key() -> Result<JwtKeys, String> {
    match secret("OPENSEAL_JWT_SIGNING_KEY")? {
        Some(k) => {
            let der = pkcs8_der("OPENSEAL_JWT_SIGNING_KEY", &k)?;
            let keys = JwtKeys::from_pkcs8(&der)
                .map_err(|e| format!("OPENSEAL_JWT_SIGNING_KEY: {}", e.code()))?;
            // A rotation's overlap (docs/65 §Rotation): the replaced key still verifies
            // the tokens it signed until they expire, and stays in JWKS.
            match secret("OPENSEAL_JWT_PREVIOUS_KEY")? {
                Some(p) => {
                    let der = pkcs8_der("OPENSEAL_JWT_PREVIOUS_KEY", &p)?;
                    keys.with_previous(&der)
                        .map_err(|e| format!("OPENSEAL_JWT_PREVIOUS_KEY: {}", e.code()))
                }
                None => Ok(keys),
            }
        }
        None if std::env::var("OPENSEAL_DEV_INSECURE_KEY").as_deref() == Ok("1") => {
            note(
                Level::Warn,
                "development_token_key",
                &[("note", "never in production")],
            );
            JwtKeys::generate().map_err(|e| e.code().to_owned())
        }
        None => Err("OPENSEAL_JWT_SIGNING_KEY is not set".into()),
    }
}

/// How often to read the database URL's file again (`OPENSEAL_SECRET_RELOAD_SECONDS`,
/// default 30, `0` never); only a `_FILE` can change under a running process.
fn reload_every() -> Result<Option<std::time::Duration>, String> {
    if std::env::var("OPENSEAL_DATABASE_URL_FILE").is_err() {
        return Ok(None);
    }
    let seconds: u64 = match std::env::var("OPENSEAL_SECRET_RELOAD_SECONDS") {
        Ok(s) => s
            .parse()
            .map_err(|_| "OPENSEAL_SECRET_RELOAD_SECONDS: not a number of seconds".to_owned())?,
        Err(_) => 30,
    };
    Ok((seconds > 0).then(|| std::time::Duration::from_secs(seconds)))
}

/// The key that seals staff TOTP seeds (ASVS-01): `OPENSEAL_MFA_KEY`, 32 bytes as
/// base64. Unset, staff cannot enrol a second factor, except in development, where a
/// random key is drawn (seeds then do not survive a restart).
fn mfa_key() -> Result<Option<casual_sign_server::MfaKey>, String> {
    match secret("OPENSEAL_MFA_KEY")? {
        Some(b64) => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .map_err(|_| "OPENSEAL_MFA_KEY: not base64".to_owned())?;
            casual_sign_server::MfaKey::new(&bytes)
                .map(Some)
                .map_err(|_| "OPENSEAL_MFA_KEY: not 32 bytes".to_owned())
        }
        None if std::env::var("OPENSEAL_DEV_INSECURE_KEY").as_deref() == Ok("1") => {
            note(
                Level::Warn,
                "development_mfa_key",
                &[("note", "never in production")],
            );
            casual_sign_server::MfaKey::generate()
                .map(Some)
                .map_err(|e| e.code().to_owned())
        }
        None => Ok(None),
    }
}

/// The S3 bucket named by `OPENSEAL_S3_*`, when `OPENSEAL_S3_ENDPOINT` is set.
fn s3_config() -> Result<Option<S3Config>, String> {
    let Some(endpoint) = std::env::var("OPENSEAL_S3_ENDPOINT")
        .ok()
        .filter(|v| !v.is_empty())
    else {
        return Ok(None);
    };
    let need = |name: &str| {
        std::env::var(name)
            .ok()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| format!("{name} is not set"))
    };
    Ok(Some(S3Config {
        endpoint,
        bucket: need("OPENSEAL_S3_BUCKET")?,
        region: std::env::var("OPENSEAL_S3_REGION").unwrap_or_else(|_| "us-east-1".into()),
        access_key: need("OPENSEAL_S3_ACCESS_KEY")?,
        secret_key: secret("OPENSEAL_S3_SECRET_KEY")?
            .ok_or_else(|| "OPENSEAL_S3_SECRET_KEY is not set".to_owned())?,
        path_style: std::env::var("OPENSEAL_S3_VIRTUAL_HOST").as_deref() != Ok("1"),
        ca_pem: match std::env::var("OPENSEAL_S3_CA")
            .ok()
            .filter(|v| !v.is_empty())
        {
            Some(path) => {
                Some(std::fs::read(path).map_err(|_| "OPENSEAL_S3_CA: unreadable".to_owned())?)
            }
            None => None,
        },
    }))
}

async fn blob_store() -> Result<Blobs, String> {
    if let Some(config) = s3_config()? {
        let s3 =
            S3BlobStore::new(&config).map_err(|e| format!("OPENSEAL_S3_ENDPOINT: {}", e.code()))?;
        s3.create_bucket()
            .await
            .map_err(|e| format!("OPENSEAL_S3_BUCKET: {}", e.code()))?;
        return Ok(Blobs::S3(Arc::new(s3)));
    }
    let dir = std::env::var("OPENSEAL_BLOB_DIR")
        .map_err(|_| "OPENSEAL_BLOB_DIR or OPENSEAL_S3_ENDPOINT is not set".to_owned())?;
    FsBlobStore::new(&dir)
        .map(|b| Blobs::Fs(Arc::new(b)))
        .map_err(|e| format!("OPENSEAL_BLOB_DIR: {}", e.code()))
}

/// `healthcheck`: one plain HTTP request to this host's own listener.
fn healthcheck() -> ExitCode {
    use std::io::{Read as _, Write as _};
    let listen = std::env::var("OPENSEAL_LISTEN").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let Some(port) = listen
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
    else {
        return fail("OPENSEAL_LISTEN: no port");
    };
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let timeout = std::time::Duration::from_secs(3);
    let Ok(mut conn) = std::net::TcpStream::connect_timeout(&addr, timeout) else {
        return fail("healthcheck: no answer");
    };
    let _ = conn.set_read_timeout(Some(timeout));
    let _ = conn.set_write_timeout(Some(timeout));
    if conn
        .write_all(
            b"GET /.well-known/jwks.json HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .is_err()
    {
        return fail("healthcheck: no answer");
    }
    let mut head = [0u8; 12];
    match conn.read_exact(&mut head) {
        Ok(()) if head.starts_with(b"HTTP/1.1 200") => ExitCode::SUCCESS,
        _ => fail("healthcheck: not 200"),
    }
}

/// `migrate`: every missing migration, as the schema owner.
async fn migrate() -> ExitCode {
    let url = match secret("OPENSEAL_MIGRATE_DATABASE_URL") {
        Ok(Some(u)) => u,
        Ok(None) => return fail("OPENSEAL_MIGRATE_DATABASE_URL is not set"),
        Err(e) => return fail(&e),
    };
    let store = match Store::connect(&url, 2).await {
        Ok(s) => s,
        Err(e) => return fail(e.code()),
    };
    match store.migrate().await {
        Ok(r) => {
            println!(
                "migrations: {} applied, {} already applied",
                r.applied.len(),
                r.already.len()
            );
            ExitCode::SUCCESS
        }
        Err(e) => fail(e.code()),
    }
}

/// The store as the backup commands use it: the server's own configuration.
async fn blobs_or_fail() -> Result<Blobs, ExitCode> {
    blob_store().await.map_err(|e| fail(&e))
}

/// `blobs-export <dir>` and `blobs-import <dir>` (ASVS-14).
async fn blobs_copy(export: bool, dir: Option<&String>) -> ExitCode {
    use casual_sign_store::blob::{export_to_dir, import_from_dir};
    let Some(dir) = dir.map(std::path::Path::new) else {
        return fail("usage: blobs-export <dir> | blobs-import <dir>");
    };
    let blobs = match blobs_or_fail().await {
        Ok(b) => b,
        Err(code) => return code,
    };
    if export {
        let report = match &blobs {
            Blobs::Fs(s) => export_to_dir(s.as_ref(), dir).await,
            Blobs::S3(s) => export_to_dir(s.as_ref(), dir).await,
        };
        match report {
            Ok(r) => {
                println!(
                    "blobs exported={} present={} ignored={}",
                    r.exported, r.present, r.ignored
                );
                ExitCode::SUCCESS
            }
            Err(e) => fail(&e.to_string()),
        }
    } else {
        let report = match &blobs {
            Blobs::Fs(s) => import_from_dir(s.as_ref(), dir).await,
            Blobs::S3(s) => import_from_dir(s.as_ref(), dir).await,
        };
        match report {
            Ok(r) => {
                println!("blobs imported={}", r.imported);
                ExitCode::SUCCESS
            }
            Err(e) => fail(&e.to_string()),
        }
    }
}

/// `verify-evidence` (ASVS-14): every chain, the operator log, then every blob the
/// evidence names (documents, certificates of completion, signature captures and the
/// images they name, logos, attachments), each read back against its key.
async fn verify_evidence() -> ExitCode {
    use casual_sign_store::blob::BlobStore as _;
    let url = match secret("OPENSEAL_MIGRATE_DATABASE_URL") {
        Ok(Some(u)) => u,
        Ok(None) => return fail("OPENSEAL_MIGRATE_DATABASE_URL is not set"),
        Err(e) => return fail(&e),
    };
    let store = match Store::connect(&url, 2).await {
        Ok(s) => s,
        Err(e) => return fail(e.code()),
    };
    let report = match store.verify_evidence().await {
        Ok(r) => r,
        Err(e) => return fail(&e.to_string()),
    };
    // The operator log lives in the same database (`platform` schema, docs/23 §5.1); the
    // owner role reads it as the console's role would.
    let pool = match casual_sign_platform_store::sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
    {
        Ok(p) => p,
        Err(_) => return fail("CS-DB-0001: database unavailable (operator log)"),
    };
    let operator = match casual_sign_platform_store::PlatformStore::new(pool)
        .verify_log()
        .await
    {
        Ok(r) => r,
        Err(e) => return fail(&format!("{e} (operator log)")),
    };
    let keys = match store.evidence_blob_keys().await {
        Ok(k) => k,
        Err(e) => return fail(&e.to_string()),
    };
    let blobs = match blobs_or_fail().await {
        Ok(b) => b,
        Err(code) => return code,
    };
    let captures: std::collections::BTreeSet<_> = keys.captures.iter().collect();
    let mut checked: std::collections::BTreeSet<casual_sign_store::blob::BlobKey> =
        std::collections::BTreeSet::new();
    let mut images = Vec::new();
    for key in &keys.named {
        let read = match &blobs {
            Blobs::Fs(s) => s.get(key).await,
            Blobs::S3(s) => s.get(key).await,
        };
        let bytes = match read {
            Ok(b) => b,
            Err(e) => return fail(&format!("{e} (blob {key})")),
        };
        // A capture is drawn, typed, or names the image the signer uploaded: that image
        // is evidence too. A capture the seal job could not read fails here as well.
        if captures.contains(key) {
            use casual_sign_host::capture::{Parsed, parse};
            match parse(&bytes) {
                Ok(Parsed::Image(hex)) => match casual_sign_store::blob::BlobKey::parse(&hex) {
                    Ok(image) => images.push(image),
                    Err(e) => return fail(&format!("{e} (capture {key})")),
                },
                Ok(Parsed::Art(_)) => {}
                Err(e) => return fail(&format!("{e} (capture {key})")),
            }
        }
        checked.insert(*key);
    }
    for image in images {
        if !checked.insert(image) {
            continue;
        }
        let read = match &blobs {
            Blobs::Fs(s) => s.get(&image).await,
            Blobs::S3(s) => s.get(&image).await,
        };
        if let Err(e) = read {
            return fail(&format!("{e} (signature image {image})"));
        }
    }
    println!(
        "evidence verified: envelopes={} audit_events={} workspaces={} admin_events={} \
         organizations={} org_admin_events={} operator_events={} blobs={}",
        report.envelopes,
        report.audit_events,
        report.workspaces,
        report.admin_events,
        report.organizations,
        report.org_admin_events,
        operator.events,
        checked.len()
    );
    ExitCode::SUCCESS
}

#[tokio::main]
async fn main() -> ExitCode {
    {
        use tracing_subscriber::Layer as _;
        use tracing_subscriber::layer::SubscriberExt as _;
        // One JSON line per event on standard error (ASVS-08, docs/65 §Logs).
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        let _ = tracing::subscriber::set_global_default(
            tracing_subscriber::registry().with(
                casual_sign_seclog::JsonLayer::stderr(casual_sign_seclog::Service::Server)
                    .with_filter(filter),
            ),
        );
    }
    casual_sign_server::quiet_panics();
    casual_sign_host::crash::startup();
    match std::env::args().nth(1).as_deref() {
        Some("healthcheck") => return healthcheck(),
        Some("migrate") => return migrate().await,
        Some("verify-evidence") => return verify_evidence().await,
        Some(cmd @ ("blobs-export" | "blobs-import")) => {
            let dir = std::env::args().nth(2);
            return blobs_copy(cmd == "blobs-export", dir.as_ref()).await;
        }
        _ => {}
    }
    // Outside development the public URL is HTTPS (or HTTP to a loopback address): links
    // in invitations and the token issuer must not travel in clear (ASVS-19, HRD-06).
    if std::env::var("OPENSEAL_DEV_INSECURE_KEY").as_deref() != Ok("1")
        && let Ok(u) = std::env::var("OPENSEAL_PUBLIC_URL")
        && !casual_sign_server::idp::endpoint(&u)
    {
        return fail("OPENSEAL_PUBLIC_URL must be https outside development");
    }
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
                println!(
                    "organization {}\naccount {}\nadmin {}",
                    b.organization, b.account, b.admin
                );
                ExitCode::SUCCESS
            }
            Err(e) => fail(e.code()),
        };
    }
    // A rotated database credential is picked up from its file without a restart
    // (HRD-06, docs/65 §Rotation).
    match reload_every() {
        Ok(Some(every)) => {
            let _watch = store.watch_database_url(
                every,
                url.clone(),
                || {
                    env_secret("OPENSEAL_DATABASE_URL")
                        .ok()
                        .flatten()
                        .map(|s| s.expose().to_owned())
                },
                |what| tracing::warn!(target: "openseal::secrets", what, "database credential"),
            );
        }
        Ok(None) => {}
        Err(e) => return fail(&e),
    }
    let jwt = match jwt_key() {
        Ok(k) => k,
        Err(e) => return fail(&e),
    };
    let blobs = match blob_store().await {
        Ok(b) => b,
        Err(e) => return fail(&e),
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
    if let Ok(b) = std::env::var("OPENSEAL_ML_BUNDLE_ID") {
        let ok = (1..=64).contains(&b.len())
            && b.bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'));
        if !ok {
            return fail("OPENSEAL_ML_BUNDLE_ID: not an id ([A-Za-z0-9._-]{1,64})");
        }
        config.ml_bundle = Some(b);
    }
    // Abnormal-activity thresholds (ASVS-13, docs/65 §Logs).
    match casual_sign_server::AnomalyConfig::from_vars(|n| std::env::var(n).ok()) {
        Ok(a) => config.anomaly = a,
        Err(e) => return fail(&e),
    }
    let public_url = config.public_url.clone();
    // Malware scanning of uploads through clamd (ASVS-11, docs/65 §Malware scanning).
    let scanner =
        match ScannerConfig::from_vars(|n| std::env::var(n).ok(), config.max_document_bytes) {
            Ok(c) => c,
            Err(e) => return fail(&e),
        };
    let state = match AppState::new(store, blobs, jwt, Arc::new(SystemClock), config) {
        Ok(s) => s,
        Err(e) => return fail(e.code()),
    };
    match scanner {
        Some(c) => {
            let fail_open = c.fail_open;
            let scanner = Scanner::new(c);
            // A start-up check only: clamd may still be loading its signatures, and
            // every scan decides for itself (fail closed unless fail-open is set).
            if scanner.ping().await {
                tracing::info!(fail_open, "uploads are scanned for malware by clamd");
            } else {
                tracing::warn!(
                    fail_open,
                    "clamd does not answer yet; uploads are refused until it does unless fail-open is set"
                );
            }
            state.set_scanner(scanner);
        }
        None => {
            tracing::warn!("OPENSEAL_CLAMD_ADDR is not set: uploads are not scanned for malware")
        }
    }
    // Security events, their pseudonyms keyed by OPENSEAL_LOG_PSEUDONYM_KEY (ASVS-08).
    match casual_sign_seclog::Pseudonymizer::from_env() {
        Ok(p) => state.set_security_log(casual_sign_seclog::SecurityLog::new(
            casual_sign_seclog::Service::Server,
            Arc::new(casual_sign_seclog::Stderr),
            p,
        )),
        Err(e) => {
            note(
                Level::Error,
                "start_failed",
                &[("code", e.code()), ("error", &e.to_string())],
            );
            return ExitCode::FAILURE;
        }
    }
    match mfa_key() {
        Ok(Some(k)) => state.set_mfa_key(k),
        Ok(None) => {}
        Err(e) => return fail(&e),
    }
    if let Ok(path) = std::env::var("OPENSEAL_GEOIP_DB") {
        match casual_sign_server::geo::GeoIp::open(std::path::Path::new(&path)) {
            Ok(g) => state.set_geoip(g),
            Err(e) => return fail(&format!("OPENSEAL_GEOIP_DB: {e}")),
        }
    }
    // Recipient sign-in through OpenID Connect providers (`sso`, RAUTH-01): the
    // operator's JSON file of providers, client secrets included, so mounted as a secret.
    if let Ok(path) = std::env::var("OPENSEAL_RECIPIENT_IDPS_FILE") {
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => return fail("OPENSEAL_RECIPIENT_IDPS_FILE: cannot read the file"),
        };
        match casual_sign_server::idp::RecipientIdps::from_json(&bytes, &public_url) {
            Ok(i) => state.set_recipient_idps(i),
            Err(e) => return fail(&format!("OPENSEAL_RECIPIENT_IDPS_FILE: {e}")),
        }
    }
    if let Ok(dir) = std::env::var("OPENSEAL_WEBAPP_DIR") {
        match casual_sign_server::web::WebApp::load(std::path::Path::new(&dir)) {
            Ok(w) => state.set_webapp(w),
            Err(e) => return fail(&format!("OPENSEAL_WEBAPP_DIR: {e}")),
        }
    }
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
