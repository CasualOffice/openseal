//! The worker's test harness: a fresh PostgreSQL database per test (the store's
//! harness, `OPENSEAL_TEST_DATABASE_URL`), an in-process SMTP sink, an HTTPS webhook
//! receiver on loopback, a movable clock, the seal tests' throwaway PKI and TSA, and
//! worker "incarnations": each runs on a runtime of its own with its own connection
//! pool, so a crash test can stop one dead at a boundary and drop its runtime, as a
//! killed process leaves things, then start the next.

// Not every test binary uses every helper.
#![allow(dead_code)]
// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    missing_docs
)]

#[path = "../../../casual-sign-store/tests/common/mod.rs"]
pub mod db;
#[path = "../../../../crates/casual-sign-seal/tests/common/mod.rs"]
pub mod pki;

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use casual_sign_audit::{AdoptionMethod, Hash256, MarkKind, Personal, Timestamp};
use casual_sign_model::{
    Delivery, Field, FieldType, FieldValue, Id, Placement, Points, RecipientType, RoutingOrder,
    Text,
};
use casual_sign_sdk::{
    CertificateOptions, Credentials, Engine, FontSet, KeyProvider, Limits, NoRevocation,
};
use casual_sign_store::blob::{BlobStore, FsBlobStore};
use casual_sign_store::repo::accounts::{LoginKind, NewUser, PermissionProfile, ProfileKind};
use casual_sign_store::repo::webhooks::Subscription;
use casual_sign_store::{
    AccountId, EnvelopeId, PermissionProfileId, Store, UserId, WebhookSubscriptionId,
};
use casual_sign_worker::seal::{SealKey, SealServices};
use casual_sign_worker::webhook::{IpRange, Sender, SsrfPolicy};
use casual_sign_worker::{
    AlertSink, Applied, Boundary, Clock, FaultHook, JobOutcome, NoPayments, OperatorAlert,
    SecretSource, Worker, WorkerConfig, apply,
};
use casual_sign_workflow::{
    Change, Command, Context, DocumentSpec, EnvelopeState, FieldEntry, Policy, Principal,
    RecipientSpec,
};
use rust_decimal::Decimal;
use sqlx::postgres::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

pub use db::{Rls, TestDb, fresh};

// ------------------------------------------------------------------------ clock

/// A clock the test moves.
#[derive(Debug)]
pub struct TestClock(AtomicI64);

impl TestClock {
    pub fn at(ms: i64) -> Arc<Self> {
        Arc::new(Self(AtomicI64::new(ms)))
    }
    pub fn ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
    pub fn advance(&self, d: Duration) {
        self.0
            .fetch_add(i64::try_from(d.as_millis()).unwrap(), Ordering::SeqCst);
    }
    pub fn ts(&self) -> Timestamp {
        Timestamp::from_unix_millis(self.ms()).unwrap()
    }
}

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp_nanos(i128::from(self.ms()) * 1_000_000).unwrap()
    }
}

// ------------------------------------------------------------------------ SMTP sink

/// One message the sink accepted.
#[derive(Debug, Clone)]
pub struct Mail {
    pub to: Vec<String>,
    pub data: String,
}

impl Mail {
    pub fn header(&self, name: &str) -> Option<String> {
        let head = self.data.split("\r\n\r\n").next()?;
        let prefix = format!("{name}: ");
        let mut out: Option<String> = None;
        for line in head.split("\r\n") {
            if let Some(v) = line.strip_prefix(&prefix) {
                out = Some(v.to_owned());
            } else if line.starts_with(' ') {
                if let Some(o) = out.as_mut() {
                    o.push_str(line);
                }
            } else if out.is_some() {
                break;
            }
        }
        out
    }
    pub fn message_id(&self) -> String {
        self.header("Message-ID").unwrap()
    }
    pub fn body(&self) -> String {
        let (_, b) = self.data.split_once("\r\n\r\n").unwrap();
        let joined: String = b.split("\r\n").collect();
        String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(joined.trim())
                .unwrap(),
        )
        .unwrap()
    }
    /// The signing link's token, if the body has one.
    pub fn token(&self) -> Option<String> {
        let body = self.body();
        let at = body.find("/s/")?;
        Some(
            body[at + 3..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .collect(),
        )
    }
}

/// A blocking, in-process SMTP server: enough of RFC 5321 for lettre; refuses the
/// recipients in `reject` with 550, and those in `tempfail` with 451 (try again later).
#[derive(Debug, Clone)]
pub struct Smtp {
    pub port: u16,
    pub mails: Arc<Mutex<Vec<Mail>>>,
    pub reject: Arc<Mutex<Vec<String>>>,
    pub tempfail: Arc<Mutex<Vec<String>>>,
}

impl Smtp {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let s = Self {
            port,
            mails: Arc::new(Mutex::new(Vec::new())),
            reject: Arc::new(Mutex::new(Vec::new())),
            tempfail: Arc::new(Mutex::new(Vec::new())),
        };
        let me = s.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(conn) = conn else { continue };
                let me = me.clone();
                std::thread::spawn(move || me.session(conn));
            }
        });
        s
    }

    fn session(&self, conn: std::net::TcpStream) {
        let mut w = conn.try_clone().unwrap();
        let mut r = BufReader::new(conn);
        let say = |w: &mut std::net::TcpStream, s: &str| {
            let _ = w.write_all(s.as_bytes());
        };
        say(&mut w, "220 sink.test ESMTP\r\n");
        let mut to = Vec::new();
        loop {
            let mut line = String::new();
            if r.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            let upper = line.to_ascii_uppercase();
            if upper.starts_with("EHLO") || upper.starts_with("HELO") {
                say(&mut w, "250 sink.test\r\n");
            } else if upper.starts_with("MAIL FROM") {
                to.clear();
                say(&mut w, "250 OK\r\n");
            } else if upper.starts_with("RCPT TO") {
                let addr = line
                    .split_once('<')
                    .and_then(|(_, a)| a.split_once('>'))
                    .map(|(a, _)| a.to_owned())
                    .unwrap_or_default();
                if self.reject.lock().unwrap().contains(&addr) {
                    say(&mut w, "550 5.1.1 no such user\r\n");
                } else if self.tempfail.lock().unwrap().contains(&addr) {
                    say(&mut w, "451 4.3.0 try again later\r\n");
                } else {
                    to.push(addr);
                    say(&mut w, "250 OK\r\n");
                }
            } else if upper.starts_with("DATA") {
                say(&mut w, "354 go on\r\n");
                let mut data = String::new();
                loop {
                    let mut l = String::new();
                    if r.read_line(&mut l).unwrap_or(0) == 0 {
                        return;
                    }
                    if l == ".\r\n" {
                        break;
                    }
                    let l = l.strip_prefix('.').map_or(l.clone(), str::to_owned);
                    data.push_str(&l);
                }
                self.mails.lock().unwrap().push(Mail {
                    to: to.clone(),
                    data,
                });
                say(&mut w, "250 OK queued\r\n");
            } else if upper.starts_with("QUIT") {
                say(&mut w, "221 bye\r\n");
                return;
            } else {
                say(&mut w, "250 OK\r\n");
            }
        }
    }

    pub fn mails(&self) -> Vec<Mail> {
        self.mails.lock().unwrap().clone()
    }

    pub fn to(&self, addr: &str) -> Vec<Mail> {
        self.mails()
            .into_iter()
            .filter(|m| m.to.iter().any(|t| t == addr))
            .collect()
    }
}

// ------------------------------------------------------------------------ HTTPS receiver

/// One webhook request received.
#[derive(Debug, Clone)]
pub struct Req {
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

/// An HTTPS webhook receiver on 127.0.0.1 with its own throwaway CA.
#[derive(Debug, Clone)]
pub struct Hook {
    pub url: String,
    pub ca_der: Vec<u8>,
    pub got: Arc<Mutex<Vec<Req>>>,
    pub status: Arc<AtomicU16>,
}

impl Hook {
    pub fn start() -> Self {
        use rcgen::{
            BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair,
            PKCS_ECDSA_P256_SHA256,
        };
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = CertifiedIssuer::self_signed(ca, ca_key).unwrap();
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let leaf = CertificateParams::new(vec!["127.0.0.1".to_owned()])
            .unwrap()
            .signed_by(&key, &ca)
            .unwrap();
        let chain = vec![rustls_pki_types::CertificateDer::from(leaf.der().to_vec())];
        let pk = rustls_pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, pk)
        .unwrap();
        let config = Arc::new(config);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = Self {
            url: format!("https://127.0.0.1:{port}/hook"),
            ca_der: ca.der().to_vec(),
            got: Arc::new(Mutex::new(Vec::new())),
            status: Arc::new(AtomicU16::new(200)),
        };
        let me = h.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(conn) = conn else { continue };
                let me = me.clone();
                let config = Arc::clone(&config);
                std::thread::spawn(move || me.serve(conn, config));
            }
        });
        h
    }

    fn serve(&self, sock: std::net::TcpStream, config: Arc<rustls::ServerConfig>) {
        let conn = rustls::ServerConnection::new(config).unwrap();
        let mut s = rustls::StreamOwned::new(conn, sock);
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let head_end = loop {
            let n = match s.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            buf.extend_from_slice(&chunk[..n]);
            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break p;
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
        let mut headers = BTreeMap::new();
        for line in head.split("\r\n").skip(1) {
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
            }
        }
        let len: usize = headers
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let mut body = buf[head_end + 4..].to_vec();
        while body.len() < len {
            let n = match s.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            body.extend_from_slice(&chunk[..n]);
        }
        self.got.lock().unwrap().push(Req { headers, body });
        let status = self.status.load(Ordering::SeqCst);
        let _ = s.write_all(
            format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        );
        let _ = s.flush();
        s.conn.send_close_notify();
        let _ = s.conn.complete_io(&mut s.sock);
    }

    pub fn requests(&self) -> Vec<Req> {
        self.got.lock().unwrap().clone()
    }
}

// ------------------------------------------------------------------------ services

/// Webhook secrets by reference.
#[derive(Debug, Default)]
pub struct MapSecrets(pub BTreeMap<String, String>);

impl SecretSource for MapSecrets {
    fn secret(&self, reference: &str) -> Option<casual_sign_secrets::Secret> {
        self.0
            .get(reference)
            .map(|s| casual_sign_secrets::Secret::new(s.clone()))
    }
}

/// Alerts collected for assertions.
#[derive(Debug, Default)]
pub struct Alerts(pub Mutex<Vec<OperatorAlert>>);

impl AlertSink for Alerts {
    fn alert(&self, a: &OperatorAlert) {
        self.0.lock().unwrap().push(a.clone());
    }
}

/// The seal tests' P-256 key, counting signatures (every one is a keyd call in
/// production).
pub struct CountingKey {
    inner: pki::TestProvider,
    count: Arc<AtomicUsize>,
}

impl KeyProvider for CountingKey {
    fn algorithm(&self) -> casual_sign_sdk::SignatureAlgorithm {
        self.inner.algorithm()
    }
    fn certificate_chain(&self) -> &[casual_sign_sdk::Certificate] {
        self.inner.certificate_chain()
    }
    fn sign(
        &self,
        signed_attrs_der: &[u8],
    ) -> Result<casual_sign_sdk::Signature, casual_sign_sdk::KeyError> {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.inner.sign(signed_attrs_der)
    }
}

pub const SECRET: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";

/// 2026-11-01T12:00:00Z, the seal tests' signing time.
pub fn start_ms() -> i64 {
    i64::try_from(pki::SIGNING_TIME.as_millis()).unwrap()
}

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// `fixtures/hostile/valid.pdf`, generated when absent (it is not committed).
pub fn valid_pdf() -> Vec<u8> {
    // Tests run in parallel; generating the fixtures once per process keeps one test from
    // reading `valid.pdf` while another is still writing it.
    static GENERATED: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = GENERATED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let path = repo_root().join("fixtures/hostile/valid.pdf");
    if !path.exists() {
        let out = std::process::Command::new("python3")
            .args(["-I", "fixtures/tools/generate.py"])
            .current_dir(repo_root())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    std::fs::read(path).unwrap()
}

pub fn id(u: Uuid) -> Id {
    Id::new(u.hyphenated().to_string()).unwrap()
}

pub fn text(s: &str) -> Personal<Text> {
    Personal(Text::new(s).unwrap())
}

/// The ids of a two-signer envelope.
#[derive(Debug, Clone, Copy)]
pub struct Ids {
    pub env: Uuid,
    pub doc: Uuid,
    pub r1: Uuid,
    pub r2: Uuid,
    pub f1: Uuid,
    pub f2: Uuid,
}

/// One test's world.
pub struct Env {
    pub db: TestDb,
    pub account: AccountId,
    pub sender: UserId,
    pub blobs: PathBuf,
    pub smtp: Smtp,
    pub hook: Hook,
    pub clock: Arc<TestClock>,
    pub signatures: Arc<AtomicUsize>,
    pub alerts: Arc<Alerts>,
    pub engine: Engine,
    pub delivered: Vec<u8>,
    pub original: Vec<u8>,
    pub pages: u32,
    /// Captures stored, by recipient: their blob key (64 hex).
    pub captures: Mutex<BTreeMap<Uuid, String>>,
    /// Whether the seal's verification is tampered with (the trust store is emptied),
    /// to show the envelope stays `completing` without a verified seal.
    pub untrusted: AtomicBool,
    /// A key to seal with instead of the seal tests' in-process one (keyd's).
    pub key: Mutex<Option<SealKey>>,
    /// More trust anchors (DER) for sealing and verification.
    pub anchors: Mutex<Vec<Vec<u8>>>,
    /// Whether the webhook SSRF policy allow-lists loopback (where the receiver is).
    pub allow_loopback: AtomicBool,
    /// The model service the worker is given (document analysis; none by default).
    pub inference: Mutex<Option<Arc<dyn casual_sign_worker::ml::Inference>>>,
    /// The SMS and voice provider the worker is given (none by default).
    pub messenger: Mutex<Option<Arc<dyn casual_sign_worker::messenger::Messenger>>>,
    next: AtomicU64,
}

/// A worker incarnation stopped dead at a boundary.
#[derive(Debug)]
pub struct Crashed;

impl Env {
    pub async fn new(test: &str) -> Option<Self> {
        Self::with_ids(test, AccountId(Uuid::now_v7()), UserId(Uuid::now_v7())).await
    }

    /// A world whose account and sender have these ids, so that two worlds given the
    /// same commands seal the same bytes (`ML-32`).
    pub async fn with_ids(test: &str, account: AccountId, sender: UserId) -> Option<Self> {
        let db = fresh(test, Rls::On).await?;
        // A workspace of an organization of its own, made by the owner role as the
        // console will; a test's further workspaces use `bootstrap_workspace`.
        let org = db.organization("Acme Test").await;
        let mut tx = db.store.for_organization(org).begin().await.unwrap();
        tx.create_workspace(account, "Acme Test", &db::builtin_profiles())
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let mut tx = db.store.for_account(account).begin().await.unwrap();
        let profile = PermissionProfileId(Uuid::now_v7());
        tx.users()
            .create_profile(&PermissionProfile {
                id: profile,
                name: "Senders".into(),
                kind: ProfileKind::Sender,
                permissions: vec!["envelopes:send".into()],
            })
            .await
            .unwrap();
        tx.users()
            .create_member(
                &NewUser {
                    id: sender,
                    email: Personal(format!("sam+{}@example.test", sender.0.simple())),
                    email_normalized: Personal(format!("sam+{}@example.test", sender.0.simple())),
                    name: Personal("Sam Sender".into()),
                    login_kind: LoginKind::Local,
                    idp: None,
                },
                profile,
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let blobs = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("worker-blobs-{}", Uuid::now_v7().simple()));
        std::fs::create_dir_all(&blobs).unwrap();
        let engine = Engine::new(Limits::default(), FontSet::bundled());
        let original = valid_pdf();
        let d = engine.prepare(&original, &Credentials::default()).unwrap();
        let pages = u32::try_from(d.admission.pages.len()).unwrap();
        let env = Self {
            db,
            account,
            sender,
            blobs,
            smtp: Smtp::start(),
            hook: Hook::start(),
            clock: TestClock::at(start_ms()),
            signatures: Arc::new(AtomicUsize::new(0)),
            alerts: Arc::new(Alerts::default()),
            engine,
            delivered: d.bytes,
            original,
            pages,
            captures: Mutex::new(BTreeMap::new()),
            untrusted: AtomicBool::new(false),
            key: Mutex::new(None),
            anchors: Mutex::new(Vec::new()),
            allow_loopback: AtomicBool::new(true),
            inference: Mutex::new(None),
            messenger: Mutex::new(None),
            next: AtomicU64::new(0),
        };
        env.blob_store().put(&env.delivered).await.unwrap();
        Some(env)
    }

    pub fn blob_store(&self) -> FsBlobStore {
        FsBlobStore::new(&self.blobs).unwrap()
    }

    /// The store as the application role on a pool of its own (one per runtime).
    fn app_pool(db: &TestDb) -> PgPool {
        PgPool::connect_lazy_with((*db.app.connect_options()).clone())
    }

    fn seal_services(&self) -> SealServices {
        let count = Arc::clone(&self.signatures);
        let clock = Arc::clone(&self.clock);
        let key = self
            .key
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| SealKey::Local {
                provider: Arc::new(move || {
                    Box::new(CountingKey {
                        inner: pki::p256(),
                        count: Arc::clone(&count),
                    })
                }),
                development: false,
            });
        let mut trust = pki::trust();
        for a in self.anchors.lock().unwrap().iter() {
            trust.add_anchor(a).unwrap();
        }
        SealServices {
            engine: self.engine.clone(),
            fonts: FontSet::bundled(),
            key,
            timestamps: Arc::new(move || {
                Box::new(pki::TestTsa::new(Duration::from_millis(
                    u64::try_from(clock.ms()).unwrap() + 1000,
                )))
            }),
            revocation: Arc::new(|| Box::new(NoRevocation)),
            trust,
            crls: Vec::new(),
            name: Some("OpenSeal test operator".into()),
            reason: Some("Sealed on completion".into()),
            location: None,
            certificate: CertificateOptions::default(),
            verify_url: None,
        }
    }

    fn worker(&self, faults: Option<FaultHook>) -> Worker<FsBlobStore> {
        let config = WorkerConfig {
            name: "test-worker".into(),
            batch: 8,
            base_url: "https://sign.example.test".into(),
            mail_from: "no-reply@example.test".into(),
            mail_domain: "example.test".into(),
            ..WorkerConfig::default()
        };
        let mailer =
            casual_sign_worker::email::Mailer::new(&casual_sign_worker::email::SmtpConfig {
                host: "127.0.0.1".into(),
                port: self.smtp.port,
                security: casual_sign_worker::email::SmtpSecurity::Plain,
                credentials: None,
                hello_name: "worker.test".into(),
                timeout: Duration::from_secs(10),
            })
            .unwrap();
        let policy = SsrfPolicy {
            allow: if self.allow_loopback.load(Ordering::SeqCst) {
                vec![IpRange::parse("127.0.0.0/8").unwrap()]
            } else {
                Vec::new()
            },
        };
        let mut seal = self.seal_services();
        if self.untrusted.load(Ordering::SeqCst) {
            // No anchors: the seal's self-check requires integrity only, so sealing
            // succeeds, but the independent verification cannot build the chain.
            seal.trust = casual_sign_sdk::TrustStore::new();
        }
        let w = Worker::new(
            Store::from_pool(Self::app_pool(&self.db)),
            Arc::new(self.blob_store()),
            config,
            Some(mailer),
            Sender::new(policy, std::slice::from_ref(&self.hook.ca_der)),
            Arc::new(MapSecrets(BTreeMap::from([(
                "WH_SECRET".to_owned(),
                SECRET.to_owned(),
            )]))),
            seal,
            Arc::new(NoPayments),
            Arc::clone(&self.alerts) as Arc<dyn AlertSink>,
            Arc::clone(&self.clock) as Arc<dyn Clock>,
        );
        let w = match self.inference.lock().unwrap().clone() {
            Some(i) => w.with_inference(i),
            None => w,
        };
        let w = match self.messenger.lock().unwrap().clone() {
            Some(m) => w.with_messenger(m),
            None => w,
        };
        match faults {
            Some(f) => w.with_fault_hook(f),
            None => w,
        }
    }

    /// Run one worker incarnation until nothing is due, on a runtime of its own; with
    /// `crash`, stop it dead at the first time it reaches that boundary in a job of that
    /// kind, and drop its runtime.
    pub async fn incarnation(
        &self,
        crash: Option<(Boundary, &'static str)>,
    ) -> Result<Vec<(String, JobOutcome)>, Crashed> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let hook: Option<FaultHook> = crash.map(|(b, kind)| {
            let fired = Arc::new(AtomicBool::new(false));
            let f: FaultHook = Arc::new(move |at: Boundary, k: &str| {
                if at == b && k == kind && !fired.swap(true, Ordering::SeqCst) {
                    let _ = tx.send(());
                    true
                } else {
                    false
                }
            });
            f
        });
        let worker = self.worker(hook);
        let handle = rt.spawn(async move { worker.run_until_idle(64).await });
        let out = tokio::select! {
            r = handle => Ok(r.unwrap().unwrap()),
            Some(()) = rx.recv() => Err(Crashed),
        };
        rt.shutdown_background();
        out
    }

    /// Run incarnations until idle (no crash).
    pub async fn run(&self) -> Vec<(String, JobOutcome)> {
        self.incarnation(None).await.unwrap()
    }

    /// Move past every lease a dead incarnation left.
    pub fn after_crash(&self) {
        self.clock.advance(Duration::from_secs(301));
    }

    pub fn ctx(&self, principal: Principal) -> Context {
        let n = self.next.fetch_add(1, Ordering::SeqCst);
        Context {
            command_id: Id::new(format!("cmd-{n}")).unwrap(),
            now: self.clock.ts(),
            principal,
            request: casual_sign_audit::Context {
                ip: Some(Personal("203.0.113.9".into())),
                user_agent: Some(Personal("worker-test".into())),
                ..casual_sign_audit::Context::default()
            },
            expected_version: None,
            policy: Policy::default(),
        }
    }

    pub async fn apply(&self, env: Uuid, principal: Principal, cmd: Command) -> Applied {
        let ctx = self.ctx(principal);
        match apply(&self.db.store, self.account, EnvelopeId(env), &cmd, &ctx).await {
            Ok(a) => a,
            Err(e) => panic!("{} refused: {e}", cmd.name()),
        }
    }

    pub fn as_sender(&self) -> Principal {
        Principal::Sender {
            user_id: id(self.sender.0),
        }
    }

    pub async fn state(&self, env: Uuid) -> EnvelopeState {
        let mut tx = self
            .db
            .store
            .for_account(self.account)
            .begin()
            .await
            .unwrap();
        let s = casual_sign_worker::apply::load_state(&mut tx, EnvelopeId(env))
            .await
            .unwrap()
            .unwrap();
        tx.commit().await.unwrap();
        s
    }

    /// The stored chain's event types, re-verified on the way out.
    pub async fn events(&self, env: Uuid) -> Vec<String> {
        let mut tx = self
            .db
            .store
            .for_account(self.account)
            .begin()
            .await
            .unwrap();
        let chain = tx.audit().chain(EnvelopeId(env)).await.unwrap();
        let events = tx.audit().events(EnvelopeId(env)).await.unwrap();
        tx.commit().await.unwrap();
        assert_eq!(chain.len(), events.len());
        events.into_iter().map(|e| e.event_type).collect()
    }

    pub async fn count(&self, env: Uuid, ty: &str) -> usize {
        self.events(env).await.iter().filter(|t| *t == ty).count()
    }

    /// A typed signature capture stored as a blob; returns its key.
    pub async fn capture(&self, who: Uuid, name: &str) -> String {
        let doc = serde_json::json!({"kind": "typed", "text": name, "style": 0});
        let key = self
            .blob_store()
            .put(&serde_json::to_vec(&doc).unwrap())
            .await
            .unwrap();
        self.captures.lock().unwrap().insert(who, key.hex());
        key.hex()
    }

    pub async fn subscribe(&self, types: &[&str]) -> Uuid {
        let sid = Uuid::now_v7();
        let mut tx = self
            .db
            .store
            .for_account(self.account)
            .begin()
            .await
            .unwrap();
        tx.webhooks()
            .subscribe(&Subscription {
                id: WebhookSubscriptionId(sid),
                envelope_id: None,
                url: self.hook.url.clone(),
                event_types: types.iter().map(|t| (*t).to_owned()).collect(),
                secret_refs: vec!["WH_SECRET".into()],
                active: true,
            })
            .await
            .unwrap();
        tx.commit().await.unwrap();
        sid
    }

    fn recipient(&self, rid: Uuid, order: u32, name: &str) -> RecipientSpec {
        RecipientSpec {
            id: id(rid),
            rtype: RecipientType::Signer,
            routing_order: RoutingOrder::new(order).unwrap(),
            name: text(name),
            email: text(&format!("{}@example.test", rid.simple())),
            phone: None,
            delivery: Delivery::Email,
            auth: Vec::new(),
            embedded_client_user_id: None,
            time_zone_offset_minutes: 0,
            date_format: None,
            witness_for: None,
        }
    }

    fn signature_field(&self, fid: Uuid, doc: Uuid, rid: Uuid, y: i64) -> Field {
        let p = |v: i64| Points::new(Decimal::from(v)).unwrap();
        let mut f = Field::new(
            id(fid),
            id(doc),
            FieldType::Signature,
            Placement::new(1, p(36), p(y), p(200), p(40)).unwrap(),
        );
        f.recipient_id = Some(id(rid));
        f.required = true;
        f
    }

    pub fn email_of(&self, rid: Uuid) -> String {
        format!("{}@example.test", rid.simple())
    }

    /// A draft with one document and two sequential signers, each with a signature
    /// field; `changes` are added to the edit.
    pub async fn draft(&self, extra: Vec<Change>) -> Ids {
        let ids = Ids {
            env: Uuid::now_v7(),
            doc: Uuid::now_v7(),
            r1: Uuid::now_v7(),
            r2: Uuid::now_v7(),
            f1: Uuid::now_v7(),
            f2: Uuid::now_v7(),
        };
        self.draft_with(ids, extra).await
    }

    /// [`Env::draft`] with these ids.
    pub async fn draft_with(&self, ids: Ids, extra: Vec<Change>) -> Ids {
        self.apply(
            ids.env,
            self.as_sender(),
            Command::Create {
                envelope_id: id(ids.env),
                account_id: id(self.account.0),
                sender_user_id: id(self.sender.0),
                subject: text("Master services agreement"),
                message: text("Please sign at your convenience."),
            },
        )
        .await;
        let mut changes = vec![
            Change::AddDocument {
                document: DocumentSpec {
                    id: id(ids.doc),
                    name: text("msa.pdf"),
                    upload_hash: Hash256::digest(&self.original),
                    bytes: u64::try_from(self.original.len()).unwrap(),
                    delivered_hash: Hash256::digest(&self.delivered),
                    pages: self.pages,
                    admission: None,
                },
            },
            Change::AddRecipient {
                recipient: self.recipient(ids.r1, 1, "Ada Lovelace"),
            },
            Change::AddRecipient {
                recipient: self.recipient(ids.r2, 2, "Grace Hopper"),
            },
            Change::AddField {
                field: Personal(self.signature_field(ids.f1, ids.doc, ids.r1, 500)),
            },
            Change::AddField {
                field: Personal(self.signature_field(ids.f2, ids.doc, ids.r2, 600)),
            },
        ];
        changes.extend(extra);
        self.apply(ids.env, self.as_sender(), Command::Edit { changes })
            .await;
        ids
    }

    pub async fn send(&self, ids: Ids) -> Applied {
        self.apply(ids.env, self.as_sender(), Command::Send).await
    }

    /// Take a signer from their link to signed.
    pub async fn sign(&self, ids: Ids, rid: Uuid, fid: Uuid, name: &str) -> Applied {
        let me = Principal::Recipient {
            recipient_id: id(rid),
        };
        self.apply(
            ids.env,
            me.clone(),
            Command::OpenLink { recipient: id(rid) },
        )
        .await;
        self.apply(
            ids.env,
            me.clone(),
            Command::ViewDocument {
                recipient: id(rid),
                document: id(ids.doc),
                hash: Hash256::digest(&self.delivered),
                pages_seen: (1..=self.pages).collect(),
            },
        )
        .await;
        let cap = self.capture(rid, name).await;
        self.apply(
            ids.env,
            me.clone(),
            Command::AdoptSignature {
                recipient: id(rid),
                mark: MarkKind::Signature,
                method: AdoptionMethod::Type,
                image_hash: Hash256(hex32(&cap)),
            },
        )
        .await;
        self.apply(
            ids.env,
            me,
            Command::Finish {
                recipient: id(rid),
                values: vec![FieldEntry {
                    field: id(fid),
                    value: Personal(FieldValue::Signature(Id::new(cap).unwrap())),
                }],
            },
        )
        .await
    }

    /// The sealed bytes of the envelope's document, from the blob store.
    pub async fn sealed_bytes(&self, env: Uuid) -> Vec<Vec<u8>> {
        let s = self.state(env).await;
        let mut out = Vec::new();
        for d in &s.sealed {
            out.push(
                self.blob_store()
                    .get(&casual_sign_store::blob::BlobKey(*d.hash.as_bytes()))
                    .await
                    .unwrap(),
            );
        }
        out
    }

    /// Jobs by status, from the database (the owner role, for counting).
    pub async fn jobs(&self) -> Vec<(String, String, i32)> {
        sqlx::query_as::<_, (String, String, i32)>(
            "SELECT kind, status, attempts FROM jobs ORDER BY created_at, kind",
        )
        .fetch_all(&self.db.admin)
        .await
        .unwrap()
    }

    pub async fn job_count(&self, kind: &str, status: &str) -> usize {
        self.jobs()
            .await
            .iter()
            .filter(|(k, s, _)| k == kind && s == status)
            .count()
    }
}

pub fn hex32(hex: &str) -> [u8; 32] {
    casual_sign_store::blob::BlobKey::parse(hex).unwrap().0
}

/// Write `files` with a manifest (`level` B-T) and the seal root, then run pyHanko.
pub fn independent(dir: &std::path::Path, files: &[(String, Vec<u8>)]) {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();
    let mut manifest = String::from("file\texpect\twhy\tlevel\n");
    for (name, bytes) in files {
        std::fs::write(dir.join(name), bytes).unwrap();
        manifest.push_str(&format!("{name}\tintact\tT-2D worker seal\tB-T\n"));
    }
    std::fs::write(dir.join("manifest.tsv"), manifest).unwrap();
    std::fs::write(dir.join("trust-root.pem"), pki::root_pem()).unwrap();
    let Ok(python) = std::env::var("OPENSEAL_VERIFY_PYTHON") else {
        eprintln!(
            "NOTE: OPENSEAL_VERIFY_PYTHON is not set; pyHanko not run over {}",
            dir.display()
        );
        return;
    };
    let script = repo_root().join("tools/verify-sealed.py");
    let out = std::process::Command::new(python)
        .arg("-I")
        .arg(script)
        .arg(dir)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    eprintln!(
        "pyHanko (tools/verify-sealed.py {}):\n{text}",
        dir.display()
    );
    assert!(out.status.success(), "pyHanko disagreed:\n{text}");
}
