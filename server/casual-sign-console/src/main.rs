//! `casual-sign-console`: serve the platform console's API, or administer it from the
//! host.
//!
//! Configuration is the environment (secrets through `casual-sign-secrets`, so each may
//! come from a `*_FILE`):
//!
//! | Variable | Meaning |
//! | --- | --- |
//! | `OPENSEAL_CONSOLE_DATABASE_URL` (secret) | PostgreSQL URL of a LOGIN role that is a member of `openseal_console` (never the application's) |
//! | `OPENSEAL_CONSOLE_MFA_KEY` (secret) | 32 bytes, base64: seals operators' TOTP seeds at rest |
//! | `OPENSEAL_CONSOLE_LISTEN` | Address to listen on (default `127.0.0.1:8090`) |
//! | `OPENSEAL_CONSOLE_PUBLIC=1` | Allow a non-loopback bind (needs `OPENSEAL_TRUSTED_PROXIES`; TLS terminates at the proxy) |
//! | `OPENSEAL_TRUSTED_PROXIES` | Comma-separated CIDRs whose forwarding headers count |
//! | `OPENSEAL_CONSOLE_ORIGIN`, `OPENSEAL_PUBLIC_URL` | When both are set they must differ: the console never shares the application's origin |
//! | `OPENSEAL_CONSOLE_KEYD_ADDR` | keyd's `host:port`; when set, the Keys page and health read keyd's admin interface (`CON-06`) |
//! | `OPENSEAL_CONSOLE_KEYD_SERVER_NAME` | The name keyd's server certificate is checked against (default `localhost`) |
//! | `OPENSEAL_CONSOLE_KEYD_CA` | PEM path: the CA keyd's server certificate chains to |
//! | `OPENSEAL_CONSOLE_KEYD_CLIENT_CERT` | PEM path: the console's admin client certificate, whose fingerprint is on keyd's `OPENSEAL_KEYD_ADMIN_ALLOW_LIST` (never its signing list) |
//! | `OPENSEAL_CONSOLE_KEYD_CLIENT_KEY` (secret) | Its private key (PEM) |
//! | `OPENSEAL_MIGRATE_DATABASE_URL` (secret) | `set-service-target` and `remove-service-target` only: the schema owner |
//!
//! Commands:
//!
//! - (none) or `serve`: verify the operator log (refusing to start when it does not
//!   verify, `CS-CON-0007`), check the listener (`CS-CON-0005`), and serve.
//! - `bootstrap-operator <email>`: the first platform owner; prints their id and a
//!   one-time enrolment token (24 hours) with which they set their password and TOTP. Refused once any
//!   operator exists.
//! - `verify-log`: verify the operator log; exit 0 when it does.
//! - `set-service-target <name> <role> <http|tcp> <target>`, `remove-service-target
//!   <name>`: what the Services page probes (deployment configuration, `SEC-X06`).

use std::process::ExitCode;
use std::sync::Arc;

use base64::Engine as _;
use casual_sign_console::crypto::{MfaKey, random_secret, sha256};
use casual_sign_console::net::Cidr;
use casual_sign_console::{AppState, Config, SystemClock, app, check_listener};
use casual_sign_platform_store::sqlx::postgres::PgPoolOptions;
use casual_sign_platform_store::{Detail, EventDraft, NewOperator, PlatformStore, ServiceTarget};
use casual_sign_secrets::env_secret;

fn fail(what: &str) -> ExitCode {
    eprintln!("casual-sign-console: {what}");
    ExitCode::FAILURE
}

fn secret(name: &str) -> Result<String, String> {
    match env_secret(name) {
        Ok(Some(s)) => Ok(s.expose().to_owned()),
        Ok(None) => Err(format!("{name} is not set (CS-CON-0017)")),
        Err(e) => Err(format!("{name}: {}", e.code())),
    }
}

async fn pool(var: &str, max: u32) -> Result<casual_sign_platform_store::sqlx::PgPool, String> {
    let url = secret(var)?;
    PgPoolOptions::new()
        .max_connections(max)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(&url)
        .await
        .map_err(|_| format!("{var}: the database cannot be reached (CS-CON-0015)"))
}

fn mfa_key() -> Result<MfaKey, String> {
    let b64 = secret("OPENSEAL_CONSOLE_MFA_KEY")?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|_| "OPENSEAL_CONSOLE_MFA_KEY: not base64 (CS-CON-0017)".to_owned())?;
    MfaKey::new(&bytes)
        .map_err(|_| "OPENSEAL_CONSOLE_MFA_KEY: not 32 bytes (CS-CON-0017)".to_owned())
}

fn config() -> Result<(Config, bool), String> {
    let mut c = Config::default();
    if let Ok(l) = std::env::var("OPENSEAL_CONSOLE_LISTEN") {
        c.listen = l
            .parse()
            .map_err(|_| "OPENSEAL_CONSOLE_LISTEN: not host:port (CS-CON-0017)".to_owned())?;
    }
    if let Ok(p) = std::env::var("OPENSEAL_TRUSTED_PROXIES") {
        for part in p.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            c.trusted_proxies.push(
                Cidr::parse(part).ok_or_else(|| {
                    "OPENSEAL_TRUSTED_PROXIES: not a CIDR (CS-CON-0017)".to_owned()
                })?,
            );
        }
    }
    let public = std::env::var("OPENSEAL_CONSOLE_PUBLIC").as_deref() == Ok("1");
    c.keyd = keyd_client()?;
    Ok((c, public))
}

/// keyd's admin client, when `OPENSEAL_CONSOLE_KEYD_ADDR` is set (`CON-06`).
fn keyd_client() -> Result<Option<casual_sign_keyd_client::AdminClient>, String> {
    let Some(addr) = std::env::var("OPENSEAL_CONSOLE_KEYD_ADDR")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        return Ok(None);
    };
    let file = |name: &str| -> Result<Vec<u8>, String> {
        let path = std::env::var(name).map_err(|_| format!("{name} is not set (CS-CON-0017)"))?;
        std::fs::read(path).map_err(|_| format!("{name}: unreadable (CS-CON-0017)"))
    };
    let ca = file("OPENSEAL_CONSOLE_KEYD_CA")?;
    let cert = file("OPENSEAL_CONSOLE_KEYD_CLIENT_CERT")?;
    let key = secret("OPENSEAL_CONSOLE_KEYD_CLIENT_KEY")?;
    let tls = casual_sign_keyd_client::client_tls(&ca, Some((&cert, key.as_bytes())))
        .map_err(|e| format!("OPENSEAL_CONSOLE_KEYD_*: {}", e.code()))?;
    Ok(Some(casual_sign_keyd_client::AdminClient::new(
        casual_sign_keyd_client::Endpoint {
            addr,
            server_name: std::env::var("OPENSEAL_CONSOLE_KEYD_SERVER_NAME")
                .unwrap_or_else(|_| "localhost".into()),
            tls,
            timeout: std::time::Duration::from_secs(5),
        },
    )))
}

async fn serve() -> ExitCode {
    let (config, public) = match config() {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };
    let origin = std::env::var("OPENSEAL_CONSOLE_ORIGIN").ok();
    let app_origin = std::env::var("OPENSEAL_PUBLIC_URL").ok();
    if let Err(e) = check_listener(
        config.listen,
        public,
        &config.trusted_proxies,
        origin.as_deref(),
        app_origin.as_deref(),
    ) {
        return fail(&e.to_string());
    }
    let mfa = match mfa_key() {
        Ok(k) => k,
        Err(e) => return fail(&e),
    };
    let store = match pool("OPENSEAL_CONSOLE_DATABASE_URL", 8).await {
        Ok(p) => PlatformStore::new(p),
        Err(e) => return fail(&e),
    };
    match store.verify_log().await {
        Ok(r) => tracing::info!(events = r.events, "operator log verifies"),
        Err(e) => return fail(&format!("operator log: {e}")),
    }
    let listen = config.listen;
    let state = match AppState::new(store, mfa, Arc::new(SystemClock), config) {
        Ok(s) => s,
        Err(e) => return fail(&e.to_string()),
    };
    let listener = match tokio::net::TcpListener::bind(listen).await {
        Ok(l) => l,
        Err(_) => return fail("cannot bind OPENSEAL_CONSOLE_LISTEN"),
    };
    tracing::info!(%listen, "console listening");
    let service = app(state).into_make_service_with_connect_info::<std::net::SocketAddr>();
    if axum::serve(listener, service)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .is_err()
    {
        return fail("console stopped");
    }
    ExitCode::SUCCESS
}

async fn bootstrap_operator(email: &str) -> ExitCode {
    let email = email.trim().to_lowercase();
    if !email.contains('@') || email.len() > 254 {
        return fail("bootstrap-operator: not an e-mail address (CS-CON-0010)");
    }
    let store = match pool("OPENSEAL_CONSOLE_DATABASE_URL", 1).await {
        Ok(p) => PlatformStore::new(p),
        Err(e) => return fail(&e),
    };
    let Ok(token) = random_secret() else {
        return fail("random (CS-CON-0014)");
    };
    let now = time::OffsetDateTime::now_utc();
    let Some(expires) = now.checked_add(casual_sign_console::api::ENROLMENT_TTL) else {
        return fail("time (CS-CON-0014)");
    };
    let id = uuid::Uuid::now_v7();
    let new = NewOperator {
        id,
        email: &email,
        enrolment_sha256: sha256(token.as_bytes()),
        enrolment_expires: expires,
    };
    let run = async {
        let mut tx = store.begin().await?;
        if !tx.bootstrap_operator(&new, now).await? {
            return Ok(false);
        }
        tx.append(
            &EventDraft::new("operator.bootstrapped", None, now)
                .with("operator_id", Detail::Id(id)),
        )
        .await?;
        tx.commit().await?;
        Ok::<_, casual_sign_platform_store::PlatformError>(true)
    };
    match run.await {
        Ok(true) => {
            println!("operator {id}");
            println!("enrolment token (once; expires {expires}): {token}");
            ExitCode::SUCCESS
        }
        Ok(false) => fail("bootstrap-operator: an operator already exists"),
        Err(e) => fail(&format!("bootstrap-operator: {e}")),
    }
}

async fn verify_log() -> ExitCode {
    let store = match pool("OPENSEAL_CONSOLE_DATABASE_URL", 1).await {
        Ok(p) => PlatformStore::new(p),
        Err(e) => return fail(&e),
    };
    match store.verify_log().await {
        Ok(r) => {
            println!(
                "operator log verifies: {} events, head {}",
                r.events,
                r.head.map_or_else(|| "none".to_owned(), |h| h.hex())
            );
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e.to_string()),
    }
}

async fn service_target(args: &[String]) -> ExitCode {
    let owner = match pool("OPENSEAL_MIGRATE_DATABASE_URL", 1).await {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let r = match args {
        [cmd, name, role, probe, target] if cmd == "set-service-target" => {
            let t = ServiceTarget {
                name: name.clone(),
                role: role.clone(),
                probe: probe.clone(),
                target: target.clone(),
            };
            casual_sign_platform_store::set_service_target(&owner, &t)
                .await
                .map(|()| true)
        }
        [cmd, name] if cmd == "remove-service-target" => {
            casual_sign_platform_store::remove_service_target(&owner, name).await
        }
        _ => {
            return fail(
                "usage: set-service-target <name> <role> <http|tcp> <target> | remove-service-target <name>",
            );
        }
    };
    match r {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => fail("no such service target"),
        Err(e) => fail(&e.to_string()),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("serve") => serve().await,
        Some("bootstrap-operator") => match args.get(1) {
            Some(email) if args.len() == 2 => bootstrap_operator(email).await,
            _ => fail("usage: bootstrap-operator <email>"),
        },
        Some("verify-log") => verify_log().await,
        Some("set-service-target" | "remove-service-target") => service_target(&args).await,
        Some(_) => fail(
            "usage: [serve] | bootstrap-operator <email> | verify-log | set-service-target … | remove-service-target …",
        ),
    }
}
