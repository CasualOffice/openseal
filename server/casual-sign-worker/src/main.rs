//! `casual-sign-worker`: the job runner (docs/24 §1). Configured by environment:
//!
//! | Variable | Meaning |
//! | --- | --- |
//! | `OPENSEAL_DATABASE_URL` (or `_FILE`) | PostgreSQL URL as the application role |
//! | `OPENSEAL_BLOB_DIR` | The filesystem blob store's root, or: |
//! | `OPENSEAL_S3_ENDPOINT`, `OPENSEAL_S3_BUCKET`, `OPENSEAL_S3_REGION` (default `us-east-1`) | An S3-compatible bucket instead, as the API server's |
//! | `OPENSEAL_S3_ACCESS_KEY`, `OPENSEAL_S3_SECRET_KEY` (or `_FILE`) | Its credentials |
//! | `OPENSEAL_S3_VIRTUAL_HOST=1` | Virtual-host URLs (AWS) rather than path style |
//! | `OPENSEAL_WORKER_NAME` | Recorded on claimed jobs (default `worker`) |
//! | `OPENSEAL_BASE_URL` | Signing links are `{base}/s/{token}` |
//! | `OPENSEAL_MAIL_FROM`, `OPENSEAL_MAIL_FROM_NAME`, `OPENSEAL_MAIL_DOMAIN` | The `From` address and name; the `Message-ID` domain |
//! | `OPENSEAL_ABUSE` | Where recipients report abuse (every email names it) |
//! | `OPENSEAL_SMTP_HOST`, `OPENSEAL_SMTP_PORT` | The SMTP relay (default port 587) |
//! | `OPENSEAL_SMTP_SECURITY` | `starttls` (default), `implicit`, or `plain` (a local relay only) |
//! | `OPENSEAL_SMTP_USER`, `OPENSEAL_SMTP_PASSWORD` (or `_FILE`) | Relay credentials, when needed |
//! | `OPENSEAL_TSA_URLS` | RFC 3161 time-stamping authorities, comma-separated, tried in order, while the console has configured none (`platform.tsa_endpoints`, read at most once a minute, `CON-07`) |
//! | `OPENSEAL_TRUST_ANCHORS` | PEM file of the anchors the sealed output must chain to |
//! | `OPENSEAL_KEYD_ADDR`, `OPENSEAL_KEYD_SERVER_NAME`, `OPENSEAL_KEYD_CA` | keyd's address, its certificate's name, and the CA it chains to (PEM path) |
//! | `OPENSEAL_KEYD_CLIENT_CERT`, `OPENSEAL_KEYD_CLIENT_KEY` | This worker's client certificate chain and key (PEM paths) |
//! | `OPENSEAL_KEYD_ALIAS` | The platform key's alias (default `platform`) |
//! | `OPENSEAL_MODELD_ADDR`, `OPENSEAL_MODELD_SERVER_NAME`, `OPENSEAL_MODELD_CA` | Optional: the model service's address, its certificate's name and CA (PEM path); unset, document-analysis jobs end as `unavailable` (docs/33 §1) |
//! | `OPENSEAL_MODELD_CLIENT_CERT`, `OPENSEAL_MODELD_CLIENT_KEY` | This worker's client certificate chain and key for the model service (PEM paths) |
//! | `OPENSEAL_WORKER_DEV_KEY`, `OPENSEAL_WORKER_DEV_CHAIN` | Instead of keyd: a PEM key and its chain, development only, needs `OPENSEAL_DEV_INSECURE_KEY=1` |
//! | `OPENSEAL_WEBHOOK_ALLOW` | Non-public ranges webhooks may reach anyway, comma-separated CIDRs (default none) |
//! | `OPENSEAL_WEBHOOK_EXTRA_ROOTS` | PEM file of CAs webhook receivers may chain to besides the platform's roots (a private CA) |
//! | `OPENSEAL_SEAL_NAME`, `OPENSEAL_SEAL_REASON` | The seal's `/Name` and `/Reason` |
//! | `OPENSEAL_SMS_GATEWAY_URL`, `OPENSEAL_SMS_GATEWAY_SECRET` (or `_FILE`) | Optional: the HTTPS gateway that sends SMS and voice one-time codes, and its bearer secret (`messenger::HttpGateway`); unset, such codes fail `CS-WRK-0013` |
//!
//! Webhook signing secrets are read by the reference a subscription stores, as an
//! environment variable `NAME` or `NAME_FILE`. The worker stops when killed; every job
//! is crash-safe, so no graceful shutdown is needed for correctness.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use casual_sign_keyd::{DevKeyConsent, Endpoint, FileKey, RemoteKey, certificates, client_tls};
use casual_sign_sdk::{CertificateOptions, Engine, FontSet, Limits, TrustStore};
use casual_sign_secrets::env_secret;
use casual_sign_store::Store;
use casual_sign_store::blob::{BlobStore, FsBlobStore, S3BlobStore, S3Config};
use casual_sign_worker::email::{Mailer, SmtpConfig, SmtpSecurity};
use casual_sign_worker::seal::{SealKey, SealServices, Shared};
use casual_sign_worker::webhook::{IpRange, Sender, SsrfPolicy};
use casual_sign_worker::{
    EnvSecrets, LogAlerts, NoPayments, SystemClock, Worker, WorkerConfig, WorkerError, tsa,
};

fn var(name: &'static str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn need(name: &'static str) -> Result<String, WorkerError> {
    var(name).ok_or(WorkerError::Config { setting: name })
}

fn read(name: &'static str) -> Result<Vec<u8>, WorkerError> {
    std::fs::read(need(name)?).map_err(|_| WorkerError::Config { setting: name })
}

fn secret(name: &'static str) -> Result<Option<casual_sign_secrets::Secret>, WorkerError> {
    env_secret(name).map_err(|_| WorkerError::Config { setting: name })
}

fn seal_key() -> Result<SealKey, WorkerError> {
    if let Some(path) = var("OPENSEAL_WORKER_DEV_KEY") {
        let consent =
            DevKeyConsent::from_env().map_err(|e| WorkerError::Pipeline { code: e.code() })?;
        let pem = std::fs::read(path).map_err(|_| WorkerError::Config {
            setting: "OPENSEAL_WORKER_DEV_KEY",
        })?;
        let chain = certificates(&read("OPENSEAL_WORKER_DEV_CHAIN")?)
            .map_err(|e| WorkerError::Pipeline { code: e.code() })?;
        let key = Arc::new(
            FileKey::load(consent, &pem, chain, None)
                .map_err(|e| WorkerError::Pipeline { code: e.code() })?,
        );
        return Ok(SealKey::Local {
            provider: Arc::new(move || Box::new(Shared(Arc::clone(&key) as Arc<_>))),
            development: true,
        });
    }
    let ca = read("OPENSEAL_KEYD_CA")?;
    let cert = read("OPENSEAL_KEYD_CLIENT_CERT")?;
    let key = read("OPENSEAL_KEYD_CLIENT_KEY")?;
    let tls = client_tls(&ca, Some((&cert, &key)))
        .map_err(|e| WorkerError::Pipeline { code: e.code() })?;
    let endpoint = Endpoint {
        addr: need("OPENSEAL_KEYD_ADDR")?,
        server_name: need("OPENSEAL_KEYD_SERVER_NAME")?,
        tls,
        timeout: Duration::from_secs(30),
    };
    let alias = var("OPENSEAL_KEYD_ALIAS").unwrap_or_else(|| "platform".into());
    let remote = RemoteKey::connect(endpoint, &alias)
        .map_err(|e| WorkerError::Pipeline { code: e.code() })?;
    Ok(SealKey::Remote(remote))
}

/// The model service's client, when `OPENSEAL_MODELD_ADDR` is set (docs/33 §1): the
/// client and wire format only, no inference runtime in this process (`SEC-I14`).
fn inference() -> Result<Option<Arc<dyn casual_sign_worker::ml::Inference>>, WorkerError> {
    let Some(addr) = var("OPENSEAL_MODELD_ADDR") else {
        return Ok(None);
    };
    let ca = read("OPENSEAL_MODELD_CA")?;
    let cert = read("OPENSEAL_MODELD_CLIENT_CERT")?;
    let key = read("OPENSEAL_MODELD_CLIENT_KEY")?;
    let tls = casual_sign_modeld::client_tls(&ca, Some((&cert, &key)))
        .map_err(|e| WorkerError::Model { code: e.code() })?;
    let endpoint = casual_sign_modeld::Endpoint {
        addr,
        server_name: need("OPENSEAL_MODELD_SERVER_NAME")?,
        tls,
        connect_timeout: Duration::from_secs(10),
    };
    Ok(Some(Arc::new(casual_sign_worker::ml::Modeld::new(
        casual_sign_modeld::ModelClient::new(endpoint),
    ))))
}

fn configure() -> Result<(WorkerConfig, SmtpConfig, SealServices, SsrfPolicy, String), WorkerError>
{
    let mut config = WorkerConfig {
        name: var("OPENSEAL_WORKER_NAME").unwrap_or_else(|| "worker".into()),
        base_url: need("OPENSEAL_BASE_URL")?,
        mail_from: need("OPENSEAL_MAIL_FROM")?,
        mail_domain: need("OPENSEAL_MAIL_DOMAIN")?,
        abuse: need("OPENSEAL_ABUSE")?,
        ..WorkerConfig::default()
    };
    if let Some(n) = var("OPENSEAL_MAIL_FROM_NAME") {
        config.mail_from_name = n;
    }
    let security = match var("OPENSEAL_SMTP_SECURITY").as_deref() {
        None | Some("starttls") => SmtpSecurity::StartTls,
        Some("implicit") => SmtpSecurity::Implicit,
        Some("plain") => SmtpSecurity::Plain,
        Some(_) => {
            return Err(WorkerError::Config {
                setting: "OPENSEAL_SMTP_SECURITY",
            });
        }
    };
    let credentials = match (var("OPENSEAL_SMTP_USER"), secret("OPENSEAL_SMTP_PASSWORD")?) {
        (Some(u), Some(p)) => Some((u, p)),
        (None, None) => None,
        _ => {
            return Err(WorkerError::Config {
                setting: "OPENSEAL_SMTP_USER",
            });
        }
    };
    let smtp = SmtpConfig {
        host: need("OPENSEAL_SMTP_HOST")?,
        port: var("OPENSEAL_SMTP_PORT")
            .map(|p| p.parse::<u16>())
            .transpose()
            .map_err(|_| WorkerError::Config {
                setting: "OPENSEAL_SMTP_PORT",
            })?
            .unwrap_or(587),
        security,
        credentials,
        hello_name: config.mail_domain.clone(),
        timeout: Duration::from_secs(30),
    };
    let mut trust = TrustStore::new();
    let anchors = certificates(&read("OPENSEAL_TRUST_ANCHORS")?)
        .map_err(|e| WorkerError::Pipeline { code: e.code() })?;
    for a in anchors {
        let der = der::Encode::to_der(&a).map_err(|_| WorkerError::Config {
            setting: "OPENSEAL_TRUST_ANCHORS",
        })?;
        trust.add_anchor(&der).map_err(|_| WorkerError::Config {
            setting: "OPENSEAL_TRUST_ANCHORS",
        })?;
    }
    let tsa_urls: Vec<String> = need("OPENSEAL_TSA_URLS")?
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();
    let fonts = FontSet::bundled();
    let mut policy = SsrfPolicy::default();
    if let Some(list) = var("OPENSEAL_WEBHOOK_ALLOW") {
        for r in list.split(',').filter(|s| !s.trim().is_empty()) {
            policy.allow.push(IpRange::parse(r)?);
        }
    }
    // The database's TSAs (CON-07), read at most once a minute; these URLs while it has
    // none. Database URLs pass the webhook address policy at every use.
    let tsa_directory = tsa::TsaDirectory::new(tsa_urls, policy.clone(), Duration::from_secs(60));
    let seal = SealServices {
        engine: Engine::new(Limits::default(), fonts.clone()),
        fonts,
        key: seal_key()?,
        timestamps: tsa_directory.factory(),
        tsa_directory: Some(tsa_directory),
        revocation: tsa::http_revocation(),
        trust,
        crls: Vec::new(),
        name: var("OPENSEAL_SEAL_NAME"),
        reason: var("OPENSEAL_SEAL_REASON"),
        location: None,
        certificate: CertificateOptions::default(),
        verify_url: None,
    };
    let db = secret("OPENSEAL_DATABASE_URL")?.ok_or(WorkerError::Config {
        setting: "OPENSEAL_DATABASE_URL",
    })?;
    Ok((config, smtp, seal, policy, db.expose().to_owned()))
}

/// The S3 bucket named by `OPENSEAL_S3_*`, when `OPENSEAL_S3_ENDPOINT` is set.
fn s3_config() -> Result<Option<S3Config>, WorkerError> {
    let Some(endpoint) = var("OPENSEAL_S3_ENDPOINT") else {
        return Ok(None);
    };
    let secret_key = secret("OPENSEAL_S3_SECRET_KEY")?.ok_or(WorkerError::Config {
        setting: "OPENSEAL_S3_SECRET_KEY",
    })?;
    Ok(Some(S3Config {
        endpoint,
        bucket: need("OPENSEAL_S3_BUCKET")?,
        region: var("OPENSEAL_S3_REGION").unwrap_or_else(|| "us-east-1".into()),
        access_key: need("OPENSEAL_S3_ACCESS_KEY")?,
        secret_key: secret_key.expose().to_owned(),
        path_style: var("OPENSEAL_S3_VIRTUAL_HOST").as_deref() != Some("1"),
    }))
}

async fn run() -> Result<(), WorkerError> {
    let (config, smtp, seal, policy, db) = configure()?;
    let store = Store::connect(&db, 8).await?;
    match s3_config()? {
        Some(s3) => {
            let blobs = S3BlobStore::new(&s3)?;
            serve(store, Arc::new(blobs), config, smtp, seal, policy).await
        }
        None => {
            let blobs = FsBlobStore::new(need("OPENSEAL_BLOB_DIR")?)?;
            serve(store, Arc::new(blobs), config, smtp, seal, policy).await
        }
    }
}

async fn serve<B: BlobStore + 'static>(
    store: Store,
    blobs: Arc<B>,
    config: WorkerConfig,
    smtp: SmtpConfig,
    seal: SealServices,
    policy: SsrfPolicy,
) -> Result<(), WorkerError> {
    let mut roots = Vec::new();
    if var("OPENSEAL_WEBHOOK_EXTRA_ROOTS").is_some() {
        for c in certificates(&read("OPENSEAL_WEBHOOK_EXTRA_ROOTS")?)
            .map_err(|e| WorkerError::Pipeline { code: e.code() })?
        {
            roots.push(der::Encode::to_der(&c).map_err(|_| WorkerError::Config {
                setting: "OPENSEAL_WEBHOOK_EXTRA_ROOTS",
            })?);
        }
    }
    let worker = Worker::new(
        store,
        blobs,
        config,
        Some(Mailer::new(&smtp)?),
        Sender::new(policy, &roots),
        Arc::new(EnvSecrets),
        seal,
        Arc::new(NoPayments),
        Arc::new(LogAlerts),
        Arc::new(SystemClock),
    );
    let worker = match inference()? {
        Some(i) => worker.with_inference(i),
        None => worker,
    };
    // SMS and voice one-time codes (slice 5), when a gateway is configured.
    let worker = match var("OPENSEAL_SMS_GATEWAY_URL") {
        Some(url) => {
            let secret = secret("OPENSEAL_SMS_GATEWAY_SECRET")?.ok_or(WorkerError::Config {
                setting: "OPENSEAL_SMS_GATEWAY_SECRET",
            })?;
            worker.with_messenger(Arc::new(casual_sign_worker::messenger::HttpGateway::new(
                &url, secret,
            )?))
        }
        None => worker,
    };
    #[cfg(feature = "crash-points")]
    let worker = worker.with_fault_hook(Arc::new(|at, kind| {
        // P2-CRASH: `OPENSEAL_CRASH_AT=worker:<Boundary>:<job kind>` kills the process.
        casual_sign_host::crash::point("worker", &format!("{at:?}:{kind}"));
        false
    }));
    let (_stop, rx) = tokio::sync::watch::channel(false);
    casual_sign_worker::log("INFO", "started", &[]);
    worker.run(rx).await;
    Ok(())
}

fn main() -> ExitCode {
    casual_sign_host::crash::startup();
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => {
            eprintln!("casual-sign-worker: CS-WRK-0001: the runtime does not start");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(run()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("casual-sign-worker: {e}");
            ExitCode::FAILURE
        }
    }
}
