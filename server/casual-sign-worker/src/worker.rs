//! The job runner: claim due jobs (SKIP LOCKED, through the store's entry point), keep
//! their leases alive, run each effect, feed its result back through the engine and
//! finish the job in the same transaction, retry failures with back-off and jitter, and
//! dead-letter what cannot succeed.
//!
//! **Crash safety.** A job's external act (an email accepted, a webhook answered, a
//! document sealed and stored) is recorded as a job step the moment it happens, in its
//! own transaction; the result command and the job's completion commit together
//! afterwards. A worker killed anywhere leaves either nothing done (the job runs again
//! when its lease lapses), or the act done and recorded (the re-run skips it and only
//! feeds the result), or, in the window between the act and its record, the act done
//! once more on re-run: the documented at-least-once contract, which stable
//! `Message-ID`s and `webhook-id`s let receivers collapse. Result commands carry ids
//! derived from the job, so the engine answers a second application `replayed` and no
//! audit event is written twice.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use casual_sign_audit::{Channel, Hash256};
use casual_sign_model::{Id, Text};
use casual_sign_sdk::Art;
use casual_sign_store::blob::{BlobKey, BlobStore};
use casual_sign_store::repo::documents::{NewVersion, VersionKind};
use casual_sign_store::repo::recipients::{NewToken, TokenPurpose};
use casual_sign_store::repo::webhooks::Delivery;
use casual_sign_store::{
    AccountId, ClaimedJob, DocumentId, DocumentVersionId, EnvelopeId, JobId, RecipientId,
    RecipientTokenId, Store, TenantTx, UserId, WebhookDeliveryId,
};
use casual_sign_workflow::{
    Command, EffectId, EffectKind, EnvelopeState, InvitationKind, Notice, Policy, SealedDocument,
};
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::apply::{
    EffectJob, apply_in, id_of, job_command_id, load_state, odt, system_context, ts, uuid_of,
};
use crate::capture;
use crate::email::{self, Fill, Mailer, Message, Sent, Template};
use crate::error::{Result, WorkerError};
use crate::jobs;
use crate::seal::{self, SealInput, SealServices};
use crate::webhook;

/// The worker's clock (supplied, so tests can move time).
pub trait Clock: Send + Sync {
    /// Now.
    fn now(&self) -> OffsetDateTime;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// An operator alert: ids and codes only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorAlert {
    /// What (`seal_failed`, `job_dead`, ...).
    pub kind: String,
    /// The error code concerned.
    pub code: String,
    /// The account.
    pub account: Uuid,
    /// The envelope, when one is concerned.
    pub envelope: Option<Uuid>,
    /// The job.
    pub job: Uuid,
}

/// Where operator alerts go (a pager, a chat channel, a log).
pub trait AlertSink: Send + Sync {
    /// Raise one. Must not block for long and must not fail the job.
    fn alert(&self, alert: &OperatorAlert);
}

/// Alerts as log lines on standard error.
#[derive(Debug, Clone, Copy, Default)]
pub struct LogAlerts;

impl AlertSink for LogAlerts {
    fn alert(&self, a: &OperatorAlert) {
        crate::log(
            "ALERT",
            &a.kind,
            &[
                ("code", a.code.clone()),
                ("account", a.account.to_string()),
                (
                    "envelope",
                    a.envelope.map(|e| e.to_string()).unwrap_or_default(),
                ),
                ("job", a.job.to_string()),
            ],
        );
    }
}

/// Where webhook signing secrets are found, by the reference a subscription stores.
pub trait SecretSource: Send + Sync {
    /// The secret (`whsec_…`) a reference names.
    fn secret(&self, reference: &str) -> Option<casual_sign_secrets::Secret>;
}

/// Secrets from the environment: a reference `NAME` (`[A-Z0-9_]{1,64}`) reads `NAME`
/// or `NAME_FILE` through `casual-sign-secrets`.
#[derive(Debug, Clone, Copy, Default)]
pub struct EnvSecrets;

impl SecretSource for EnvSecrets {
    fn secret(&self, reference: &str) -> Option<casual_sign_secrets::Secret> {
        if reference.is_empty()
            || reference.len() > 64
            || !reference
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            return None;
        }
        casual_sign_secrets::env_secret(reference).ok().flatten()
    }
}

/// A payment charge request (slice 13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Charge {
    /// The account.
    pub account: Uuid,
    /// The envelope.
    pub envelope: Uuid,
    /// The payer.
    pub recipient: Id,
    /// The payment field.
    pub field: Id,
    /// The idempotency key the gateway must honour.
    pub idempotency_key: String,
}

/// A payment gateway (Stripe, Braintree, ...). Slice 13 builds real ones.
pub trait PaymentGateway: Send + Sync {
    /// Charge once per idempotency key.
    ///
    /// # Errors
    ///
    /// The gateway's failure, as a worker error.
    fn charge(&self, charge: &Charge) -> Result<()>;
}

/// No gateway: every charge fails with `CS-WRK-0014` (and the job is dead-lettered with
/// an alert). Payments are slice 13.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPayments;

impl PaymentGateway for NoPayments {
    fn charge(&self, _: &Charge) -> Result<()> {
        Err(WorkerError::NoPaymentGateway)
    }
}

/// A place in a job where a crash is meaningful. The crash tests stop the worker at
/// each; in production the hook is never set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Boundary {
    /// The job is claimed; nothing else has happened.
    Claimed,
    /// An email was accepted by the SMTP server; not yet recorded.
    EmailSent,
    /// A webhook receiver answered; not yet recorded.
    WebhookAnswered,
    /// The documents are sealed (keyd signed); nothing stored yet.
    Sealed,
    /// The external act is recorded as a job step; the result is not yet committed.
    Recorded,
    /// The result command is applied in the transaction; not yet committed.
    BeforeCommit,
}

/// Decides, at each boundary, whether the worker stops dead there (tests only).
pub type FaultHook = Arc<dyn Fn(Boundary, &str) -> bool + Send + Sync>;

/// The worker's settings.
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// This worker's name, recorded on the jobs it claims.
    pub name: String,
    /// Jobs claimed per round.
    pub batch: u32,
    /// The lease on a claimed job; a heartbeat renews it every third of it.
    pub lease: Duration,
    /// Sleep between rounds that found nothing.
    pub idle: Duration,
    /// Signing links are `{base_url}/s/{token}`.
    pub base_url: String,
    /// The envelope sender's `From` address (the platform's, not the sender's).
    pub mail_from: String,
    /// Its display name.
    pub mail_from_name: String,
    /// The domain of generated `Message-ID`s.
    pub mail_domain: String,
    /// The product name in footers.
    pub product: String,
    /// Where to report abuse (`SEC-M01`).
    pub abuse: String,
    /// Lifetime of a link token when the envelope has no expiry.
    pub token_ttl: Duration,
    /// The account policy commands are decided under (per-account settings are read by
    /// the API, `T-2C`; the worker uses the operator's defaults).
    pub policy: Policy,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            name: "worker".into(),
            batch: 16,
            lease: Duration::from_secs(300),
            idle: Duration::from_secs(2),
            base_url: "https://openseal.invalid".into(),
            mail_from: "no-reply@openseal.invalid".into(),
            mail_from_name: "OpenSeal".into(),
            mail_domain: "openseal.invalid".into(),
            product: "OpenSeal".into(),
            abuse: "abuse@openseal.invalid".into(),
            token_ttl: Duration::from_secs(30 * 86_400),
            policy: Policy::default(),
        }
    }
}

/// The worker.
pub struct Worker<B: BlobStore> {
    store: Store,
    blobs: Arc<B>,
    config: WorkerConfig,
    mailer: Option<Mailer>,
    webhooks: webhook::Sender,
    secrets: Arc<dyn SecretSource>,
    seal: SealServices,
    payments: Arc<dyn PaymentGateway>,
    alerts: Arc<dyn AlertSink>,
    clock: Arc<dyn Clock>,
    faults: Option<FaultHook>,
}

impl<B: BlobStore> core::fmt::Debug for Worker<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Worker")
            .field("name", &self.config.name)
            .finish_non_exhaustive()
    }
}

/// What one job came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobOutcome {
    /// Done; its result (if any) committed with it.
    Done,
    /// Failed; queued again.
    Retry(String),
    /// Failed; dead.
    Dead(String),
}

/// The parts every handler needs.
struct Ctx<'a> {
    job: &'a ClaimedJob,
    lease: Uuid,
    account: AccountId,
    envelope: EnvelopeId,
    payload: EffectJob,
}

fn store_err(e: casual_sign_store::StoreError) -> WorkerError {
    WorkerError::Store(e)
}

/// A uniformly drawn 6-digit code: 32 random bits, redrawn above the largest multiple
/// of 10^6 (no modulo bias).
fn one_time_code() -> Result<String> {
    const LIMIT: u32 = 4_294_000_000;
    loop {
        let mut raw = [0u8; 4];
        aws_lc_rs::rand::fill(&mut raw).map_err(|_| WorkerError::Config { setting: "rng" })?;
        let v = u32::from_le_bytes(raw);
        if v < LIMIT {
            return Ok(format!("{:06}", v % 1_000_000));
        }
    }
}

/// The code's Argon2id PHC string, with the API server's parameters (it verifies).
fn hash_code(code: &str) -> Result<String> {
    use argon2::password_hash::{PasswordHasher, SaltString};
    use argon2::{Algorithm, Argon2, Params, Version};
    let failed = || WorkerError::Config { setting: "argon2" };
    let mut salt = [0u8; 16];
    aws_lc_rs::rand::fill(&mut salt).map_err(|_| WorkerError::Config { setting: "rng" })?;
    let salt = SaltString::encode_b64(&salt).map_err(|_| failed())?;
    let params = Params::new(19 * 1024, 2, 1, None).map_err(|_| failed())?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password(code.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| failed())
}

impl<B: BlobStore + 'static> Worker<B> {
    /// A worker over `store` and `blobs`.
    #[allow(clippy::too_many_arguments)]
    // One argument per service the effects need; a builder would only rename them.
    #[must_use]
    pub fn new(
        store: Store,
        blobs: Arc<B>,
        config: WorkerConfig,
        mailer: Option<Mailer>,
        webhooks: webhook::Sender,
        secrets: Arc<dyn SecretSource>,
        seal: SealServices,
        payments: Arc<dyn PaymentGateway>,
        alerts: Arc<dyn AlertSink>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            store,
            blobs,
            config,
            mailer,
            webhooks,
            secrets,
            seal,
            payments,
            alerts,
            clock,
            faults: None,
        }
    }

    /// Stop dead at the boundaries `hook` names (crash tests).
    #[must_use]
    pub fn with_fault_hook(mut self, hook: FaultHook) -> Self {
        self.faults = Some(hook);
        self
    }

    async fn boundary(&self, b: Boundary, kind: &str) {
        if let Some(h) = &self.faults
            && h(b, kind)
        {
            // A crash: nothing after this point runs. The test drops the runtime.
            std::future::pending::<()>().await;
        }
    }

    fn now(&self) -> OffsetDateTime {
        self.clock.now()
    }

    /// Claim one batch and run it; returns how many jobs ran.
    ///
    /// # Errors
    ///
    /// The store's codes when the claim itself fails.
    pub async fn run_once(&self) -> Result<Vec<(String, JobOutcome)>> {
        let lease = jobs::random_uuid();
        let claimed = self
            .store
            .entry_points()
            .claim_jobs(
                &self.config.name,
                jobs::KINDS,
                self.config.batch,
                self.now(),
                self.config.lease,
                lease,
            )
            .await?;
        let mut out = Vec::with_capacity(claimed.len());
        for job in claimed {
            let o = self.process(&job, lease).await;
            out.push((job.kind.clone(), o));
        }
        Ok(out)
    }

    /// Run rounds until one finds nothing due, at most `rounds`; returns every outcome.
    ///
    /// # Errors
    ///
    /// As [`Worker::run_once`].
    pub async fn run_until_idle(&self, rounds: usize) -> Result<Vec<(String, JobOutcome)>> {
        let mut all = Vec::new();
        for _ in 0..rounds {
            let got = self.run_once().await?;
            if got.is_empty() {
                break;
            }
            all.extend(got);
        }
        Ok(all)
    }

    /// Run until `stop` turns true.
    pub async fn run(&self, mut stop: tokio::sync::watch::Receiver<bool>) {
        loop {
            if *stop.borrow() {
                return;
            }
            let idle = match self.run_once().await {
                Ok(v) => v.is_empty(),
                Err(e) => {
                    crate::log("WARN", "claim_failed", &[("code", e.code().to_owned())]);
                    true
                }
            };
            if idle {
                tokio::select! {
                    () = tokio::time::sleep(self.config.idle) => {}
                    _ = stop.changed() => {}
                }
            }
        }
    }

    async fn process(&self, job: &ClaimedJob, lease: Uuid) -> JobOutcome {
        self.boundary(Boundary::Claimed, &job.kind).await;
        let heartbeat = self.spawn_heartbeat(job, lease);
        let result = self.dispatch(job, lease).await;
        heartbeat.abort();
        match result {
            Ok(()) => JobOutcome::Done,
            Err(e) => self.failed(job, lease, &e).await,
        }
    }

    fn spawn_heartbeat(&self, job: &ClaimedJob, lease: Uuid) -> tokio::task::JoinHandle<()> {
        let store = self.store.clone();
        let clock = Arc::clone(&self.clock);
        let every = self
            .config
            .lease
            .checked_div(3)
            .unwrap_or(self.config.lease);
        let length = self.config.lease;
        let (account, id) = (job.account_id, job.id);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                let until = jobs::after(clock.now(), length);
                let ok = async {
                    let mut tx = store.for_account(account).begin().await?;
                    tx.jobs().heartbeat(id, lease, until).await?;
                    tx.commit().await
                }
                .await;
                if ok.is_err() {
                    return;
                }
            }
        })
    }

    async fn failed(&self, job: &ClaimedJob, lease: Uuid, e: &WorkerError) -> JobOutcome {
        let code = e.code();
        crate::log(
            "WARN",
            "job_failed",
            &[
                ("kind", job.kind.clone()),
                ("job", job.id.0.to_string()),
                ("attempt", job.attempts.to_string()),
                ("code", code.to_owned()),
            ],
        );
        let now = self.now();
        let written = async {
            let mut tx = self.store.for_account(job.account_id).begin().await?;
            if e.retryable() {
                let wait = jobs::backoff(job.attempts, jobs::random_unit());
                tx.jobs()
                    .fail(job.id, lease, jobs::after(now, wait), code)
                    .await?;
            } else {
                tx.jobs().bury(job.id, lease, now, code).await?;
            }
            let state = tx.jobs().get(job.id).await?;
            tx.commit().await?;
            Ok::<_, casual_sign_store::StoreError>(state)
        }
        .await;
        match written {
            Ok(Some(s)) if s.status == "dead" => {
                self.alerts.alert(&OperatorAlert {
                    kind: "job_dead".into(),
                    code: code.to_owned(),
                    account: job.account_id.0,
                    envelope: job.envelope_id.map(|e| e.0),
                    job: job.id.0,
                });
                JobOutcome::Dead(code.to_owned())
            }
            // The lease was lost meanwhile: whoever holds it now decides.
            _ => JobOutcome::Retry(code.to_owned()),
        }
    }

    async fn dispatch(&self, job: &ClaimedJob, lease: Uuid) -> Result<()> {
        if job.kind == casual_sign_host::jobs::SEND_USER_INVITATION {
            return self.user_invitation(job, lease).await;
        }
        if job.kind == casual_sign_host::jobs::SEND_EMAIL_OTP {
            return self.email_otp(job, lease).await;
        }
        if job.kind == casual_sign_host::jobs::SEND_WEBHOOK_DELIVERY {
            return self.webhook_delivery(job, lease).await;
        }
        if job.kind == casual_sign_host::jobs::SEND_PASSWORD_RESET {
            return self.password_reset(job, lease).await;
        }
        let payload = jobs::parse(&job.kind, &job.payload)?;
        let envelope = EnvelopeId(payload.envelope_id);
        if job.envelope_id != Some(envelope) {
            return Err(WorkerError::BadJob {
                kind: job.kind.clone(),
            });
        }
        let ctx = Ctx {
            job,
            lease,
            account: job.account_id,
            envelope,
            payload,
        };
        match ctx.payload.effect.kind.clone() {
            EffectKind::SendInvitation {
                recipient,
                channel,
                invitation,
            } => {
                let template = match invitation {
                    InvitationKind::Copy => Template::CopyInvitation,
                    _ => Template::Invitation,
                };
                let report = Command::InvitationDispatched {
                    recipient: recipient.clone(),
                    channel,
                };
                self.message_one(
                    &ctx,
                    &recipient,
                    channel,
                    template,
                    TokenPurpose::Invitation,
                    Some(report),
                )
                .await
            }
            EffectKind::SendReminder { recipient, channel } => {
                let report = Command::ReminderDispatched {
                    recipient: recipient.clone(),
                    channel,
                };
                self.message_one(
                    &ctx,
                    &recipient,
                    channel,
                    Template::Reminder,
                    TokenPurpose::Reminder,
                    Some(report),
                )
                .await
            }
            EffectKind::SendExpiryWarning { recipient, channel } => {
                self.message_one(
                    &ctx,
                    &recipient,
                    channel,
                    Template::ExpiryWarning,
                    TokenPurpose::Reminder,
                    None,
                )
                .await
            }
            EffectKind::NotifySender { notice, .. } => self.notify_sender(&ctx, notice).await,
            EffectKind::NotifyRecipients { recipients, notice } => {
                self.notify_recipients(&ctx, &recipients, template_of(notice), None)
                    .await
            }
            EffectKind::SendCompletionCopies { recipients } => {
                self.notify_recipients(
                    &ctx,
                    &recipients,
                    Template::Completed,
                    Some(TokenPurpose::CompletedCopy),
                )
                .await
            }
            EffectKind::Schedule { .. } => {
                let cmd = Command::TimerDue {
                    timer: ctx.payload.effect.id.clone(),
                };
                self.finish(&ctx, Some(cmd)).await
            }
            EffectKind::SealEnvelope { .. } => self.seal_job(&ctx).await,
            EffectKind::RevokeTokens { recipient } => {
                let rid = RecipientId(uuid_of(&recipient, "recipient")?);
                let now = self.now();
                let mut tx = self.tx(&ctx).await?;
                tx.recipients().revoke_tokens(rid, now).await?;
                self.complete_in(tx, &ctx).await
            }
            EffectKind::DeliverWebhook { topic, recipient } => {
                self.webhook_job(&ctx, topic, recipient.as_ref()).await
            }
            EffectKind::ChargePayment { recipient, field } => {
                self.payments.charge(&Charge {
                    account: ctx.account.0,
                    envelope: ctx.envelope.0,
                    recipient,
                    field,
                    idempotency_key: jobs::idempotency_key(ctx.envelope, &ctx.payload.effect),
                })?;
                self.finish(&ctx, None).await
            }
            EffectKind::AlertOperator { alert, code } => {
                let kind = match serde_json::to_value(alert) {
                    Ok(serde_json::Value::String(s)) => s,
                    _ => "alert".into(),
                };
                self.alerts.alert(&OperatorAlert {
                    kind,
                    code: code.as_str().to_owned(),
                    account: ctx.account.0,
                    envelope: Some(ctx.envelope.0),
                    job: job.id.0,
                });
                self.finish(&ctx, None).await
            }
            EffectKind::PurgeData { .. } | EffectKind::DeleteDraft => self.purge(&ctx).await,
            _ => Err(WorkerError::BadJob {
                kind: job.kind.clone(),
            }),
        }
    }

    async fn tx(&self, ctx: &Ctx<'_>) -> Result<TenantTx> {
        Ok(self.store.for_account(ctx.account).begin().await?)
    }

    /// Finish the job in `tx` and commit.
    async fn complete_in(&self, mut tx: TenantTx, ctx: &Ctx<'_>) -> Result<()> {
        self.boundary(Boundary::BeforeCommit, &ctx.job.kind).await;
        tx.jobs()
            .complete(ctx.job.id, ctx.lease, self.now())
            .await
            .map_err(|e| match e.code() {
                "CS-DB-0003" => WorkerError::LeaseLost,
                _ => store_err(e),
            })?;
        tx.commit().await?;
        Ok(())
    }

    /// Apply the job's result command (if any) and finish the job, in one transaction.
    /// A command the engine refuses because the envelope moved on (voided meanwhile, a
    /// late timer) is recorded as a step and the job finishes: the effect happened, its
    /// report no longer applies.
    async fn finish(&self, ctx: &Ctx<'_>, command: Option<Command>) -> Result<()> {
        let mut tx = self.tx(ctx).await?;
        if let Some(cmd) = command {
            let now = ts(self.now())?;
            let c = system_context(job_command_id(ctx.job.id)?, now, self.config.policy.clone());
            match apply_in(&mut tx, ctx.envelope, &cmd, &c).await {
                Ok(_) => {}
                Err(WorkerError::Workflow { code }) => {
                    drop(tx);
                    crate::log(
                        "INFO",
                        "result_refused",
                        &[
                            ("job", ctx.job.id.0.to_string()),
                            ("command", cmd.name().to_owned()),
                            ("code", code.to_owned()),
                        ],
                    );
                    tx = self.tx(ctx).await?;
                    tx.job_steps()
                        .record(
                            ctx.job.id,
                            "result.refused",
                            &serde_json::json!({ "code": code }),
                            self.now(),
                        )
                        .await?;
                }
                Err(e) => return Err(e),
            }
        }
        self.complete_in(tx, ctx).await
    }

    async fn record_step(
        &self,
        ctx: &Ctx<'_>,
        step: &str,
        detail: serde_json::Value,
    ) -> Result<()> {
        let mut tx = self.tx(ctx).await?;
        tx.job_steps()
            .record(ctx.job.id, step, &detail, self.now())
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn steps(
        &self,
        ctx: &Ctx<'_>,
    ) -> Result<Vec<casual_sign_store::repo::workflow::JobStep>> {
        let mut tx = self.tx(ctx).await?;
        let s = tx.job_steps().list(ctx.job.id).await?;
        tx.commit().await?;
        Ok(s)
    }

    async fn state(&self, ctx: &Ctx<'_>) -> Result<EnvelopeState> {
        let mut tx = self.tx(ctx).await?;
        let s = load_state(&mut tx, ctx.envelope).await?;
        tx.commit().await?;
        s.ok_or(WorkerError::Store(
            casual_sign_store::StoreError::NotFound {
                entity: "envelope state",
            },
        ))
    }

    /// A fresh link token for a recipient: 256 random bits, base64url; only its SHA-256
    /// (of the token's text as it appears in the link) is stored (`SEC-A01`).
    async fn mint_link(
        &self,
        ctx: &Ctx<'_>,
        state: &EnvelopeState,
        recipient: RecipientId,
        purpose: TokenPurpose,
    ) -> Result<String> {
        let mut raw = [0u8; 32];
        aws_lc_rs::rand::fill(&mut raw).map_err(|_| WorkerError::Config { setting: "rng" })?;
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        let now = self.now();
        let expires_at = match state.expires_at {
            Some(t) if purpose != TokenPurpose::CompletedCopy => odt(t)?,
            _ => jobs::after(now, self.config.token_ttl),
        };
        let mut tx = self.tx(ctx).await?;
        tx.recipients()
            .issue_token(&NewToken {
                id: RecipientTokenId(jobs::random_uuid()),
                envelope_id: ctx.envelope,
                recipient_id: recipient,
                token_sha256: *Hash256::digest(token.as_bytes()).as_bytes(),
                purpose,
                host_user_id: None,
                expires_at,
            })
            .await?;
        tx.commit().await?;
        Ok(format!(
            "{}/s/{token}",
            self.config.base_url.trim_end_matches('/')
        ))
    }

    /// `send_user_invitation` (WEB-06): mint the invitation's one-time link (256 random
    /// bits, base64url, only its SHA-256 stored, 7 days), replacing any earlier one, and
    /// email it to the member; once per job (a job step), nothing for an invitation
    /// accepted or revoked meanwhile. The link is `{base_url}/#/accept-invite?token=`,
    /// in the fragment, which browsers never send to a server.
    async fn user_invitation(&self, job: &ClaimedJob, lease: Uuid) -> Result<()> {
        use casual_sign_store::UserInvitationId;
        let bad = || WorkerError::BadJob {
            kind: job.kind.clone(),
        };
        let p: casual_sign_host::jobs::UserInvitationJob =
            serde_json::from_value(job.payload.clone()).map_err(|_| bad())?;
        if job.envelope_id.is_some() {
            return Err(bad());
        }
        let id = UserInvitationId(p.invitation_id);
        let account = job.account_id;
        let mut tx = self.store.for_account(account).begin().await?;
        let done = tx
            .job_steps()
            .list(job.id)
            .await?
            .iter()
            .any(|s| s.step == "email.invitation");
        let open = tx
            .users()
            .invitation(id)
            .await?
            .filter(|i| i.accepted_at.is_none() && i.revoked_at.is_none());
        let (Some(inv), false) = (open, done) else {
            return self.close_job(tx, job, lease).await;
        };
        let member = tx
            .users()
            .get(inv.user_id)
            .await?
            .ok_or(WorkerError::SealInput { what: "user" })?;
        let account_name = tx.account().get().await?.name;
        let mut raw = [0u8; 32];
        aws_lc_rs::rand::fill(&mut raw).map_err(|_| WorkerError::Config { setting: "rng" })?;
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        let now = self.now();
        let expires = jobs::after(now, Duration::from_secs(7 * 86_400));
        if !tx
            .users()
            .set_invitation_token(
                id,
                Hash256::digest(token.as_bytes()).as_bytes(),
                expires,
                now,
            )
            .await?
        {
            return self.close_job(tx, job, lease).await;
        }
        tx.commit().await?;
        let link = format!(
            "{}/#/accept-invite?token={token}",
            self.config.base_url.trim_end_matches('/')
        );
        let mailer = self.mailer.as_ref().ok_or(WorkerError::NoChannel)?;
        let (subject, body) = email::render(
            Template::UserInvitation,
            &Fill {
                name: member.name.get(),
                subject: &account_name,
                message: "",
                link: Some(&link),
                product: &self.config.product,
                abuse: &self.config.abuse,
            },
        );
        let msg = Message {
            from: self.config.mail_from.clone(),
            from_name: self.config.mail_from_name.clone(),
            to: member.email.get().clone(),
            to_name: member.name.get().clone(),
            subject,
            body,
            message_id: self.message_id(job.id, "invitation"),
            date: now,
        };
        let sent = mailer.send(&msg).await?;
        self.boundary(Boundary::EmailSent, &job.kind).await;
        let mut tx = self.store.for_account(account).begin().await?;
        tx.job_steps()
            .record(
                job.id,
                "email.invitation",
                &serde_json::json!({
                    "outcome": if matches!(sent, Sent::Accepted) { "accepted" } else { "bounced" },
                    "message_id": msg.message_id,
                }),
                now,
            )
            .await?;
        self.close_job(tx, job, lease).await
    }

    /// `send_password_reset` (UXW-38): mint the reset's one-time link (256 random bits,
    /// base64url, only its SHA-256 stored, 1 hour) and email it to the user; once (the
    /// row's `sent_at`, then a job step), nothing for a reset spent, revoked or sent
    /// meanwhile. The link is `{base_url}/#/reset-password?token=`, in the fragment.
    async fn password_reset(&self, job: &ClaimedJob, lease: Uuid) -> Result<()> {
        use casual_sign_store::PasswordResetId;
        let bad = || WorkerError::BadJob {
            kind: job.kind.clone(),
        };
        let p: casual_sign_host::jobs::PasswordResetJob =
            serde_json::from_value(job.payload.clone()).map_err(|_| bad())?;
        if job.envelope_id.is_some() {
            return Err(bad());
        }
        let id = PasswordResetId(p.reset_id);
        let account = job.account_id;
        let mut tx = self.store.for_account(account).begin().await?;
        let done = tx
            .job_steps()
            .list(job.id)
            .await?
            .iter()
            .any(|s| s.step == "email.password_reset");
        let open = tx.users().password_reset(id).await?.filter(|r| {
            r.sent_at.is_none() && r.used_at.is_none() && r.revoked_at.is_none()
        });
        let (Some(reset), false) = (open, done) else {
            return self.close_job(tx, job, lease).await;
        };
        let Some(user) = tx.users().get(reset.user_id).await? else {
            return self.close_job(tx, job, lease).await;
        };
        let mut raw = [0u8; 32];
        aws_lc_rs::rand::fill(&mut raw).map_err(|_| WorkerError::Config { setting: "rng" })?;
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        let now = self.now();
        let expires = jobs::after(now, Duration::from_secs(3600));
        if !tx
            .users()
            .set_password_reset_token(
                id,
                Hash256::digest(token.as_bytes()).as_bytes(),
                expires,
                now,
            )
            .await?
        {
            return self.close_job(tx, job, lease).await;
        }
        tx.commit().await?;
        let link = format!(
            "{}/#/reset-password?token={token}",
            self.config.base_url.trim_end_matches('/')
        );
        let mailer = self.mailer.as_ref().ok_or(WorkerError::NoChannel)?;
        let (subject, body) = email::render(
            Template::PasswordReset,
            &Fill {
                name: user.name.get(),
                subject: "",
                message: "",
                link: Some(&link),
                product: &self.config.product,
                abuse: &self.config.abuse,
            },
        );
        let msg = Message {
            from: self.config.mail_from.clone(),
            from_name: self.config.mail_from_name.clone(),
            to: user.email.get().clone(),
            to_name: user.name.get().clone(),
            subject,
            body,
            message_id: self.message_id(job.id, "reset"),
            date: now,
        };
        let sent = mailer.send(&msg).await?;
        self.boundary(Boundary::EmailSent, &job.kind).await;
        let mut tx = self.store.for_account(account).begin().await?;
        tx.job_steps()
            .record(
                job.id,
                "email.password_reset",
                &serde_json::json!({
                    "outcome": if matches!(sent, Sent::Accepted) { "accepted" } else { "bounced" },
                    "message_id": msg.message_id,
                }),
                now,
            )
            .await?;
        self.close_job(tx, job, lease).await
    }

    /// `send_webhook_delivery` (UXW-32, UXW-33): send one recorded delivery (a test
    /// event, or one asked to be delivered again) to its subscription, signed as every
    /// delivery (Standard Webhooks, the delivery's own event id), through the same SSRF
    /// policy (SEC-W01), and record the answer. A refused URL fails the delivery with no
    /// retry; another failure is retried with back-off within the job's few attempts. A
    /// subscription paused or disabled meanwhile sends nothing.
    async fn webhook_delivery(&self, job: &ClaimedJob, lease: Uuid) -> Result<()> {
        let bad = || WorkerError::BadJob {
            kind: job.kind.clone(),
        };
        let p: casual_sign_host::jobs::WebhookDeliveryJob =
            serde_json::from_value(job.payload.clone()).map_err(|_| bad())?;
        if job.envelope_id.is_some() {
            return Err(bad());
        }
        let account = job.account_id;
        let mut tx = self.store.for_account(account).begin().await?;
        let done = tx
            .job_steps()
            .list(job.id)
            .await?
            .iter()
            .any(|s| s.step == "webhook.sent");
        let Some(delivery) = tx
            .webhooks()
            .delivery(WebhookDeliveryId(p.delivery_id))
            .await?
        else {
            return self.close_job(tx, job, lease).await;
        };
        let sub = tx
            .webhooks()
            .get(delivery.subscription_id)
            .await?
            .filter(|s| s.active);
        let (Some(sub), false) = (sub, done) else {
            return self.close_job(tx, job, lease).await;
        };
        tx.commit().await?;
        let body = serde_json::to_vec(&delivery.payload).map_err(|_| bad())?;
        let mut keys = Vec::new();
        for r in &sub.secret_refs {
            if let Some(s) = self.secrets.secret(r) {
                keys.push(webhook::secret_key(s.expose())?);
            }
        }
        if keys.is_empty() {
            return Err(WorkerError::SecretMissing);
        }
        let ts = self.now().unix_timestamp();
        let headers = webhook::headers(&keys, &delivery.event_id.to_string(), ts, &body);
        let sender = self.webhooks.clone();
        let url = sub.url.clone();
        let answer = tokio::task::spawn_blocking(move || sender.post(&url, &headers, &body))
            .await
            .map_err(|_| WorkerError::WebhookFailed { status: None })?;
        self.boundary(Boundary::WebhookAnswered, &job.kind).await;
        let (status, delivered) = match &answer {
            Ok(a) => (Some(i32::from(a.status)), a.delivered()),
            Err(_) => (None, false),
        };
        let refused = matches!(answer, Err(WorkerError::WebhookRefused));
        let last = job.attempts >= jobs::max_attempts(&job.kind);
        let now = self.now();
        let next = if delivered || last || refused {
            None
        } else {
            Some(jobs::after(now, jobs::backoff(job.attempts, 0.5)))
        };
        let mut tx = self.store.for_account(account).begin().await?;
        tx.webhooks()
            .record_attempt(delivery.id, status, delivered, next, now)
            .await?;
        if delivered || refused {
            tx.job_steps()
                .record(
                    job.id,
                    "webhook.sent",
                    &serde_json::json!({ "status": status, "refused": refused }),
                    now,
                )
                .await?;
            return self.close_job(tx, job, lease).await;
        }
        tx.commit().await?;
        Err(WorkerError::WebhookFailed { status: None })
    }

    /// `send_email_otp` (SEC-A02): draw the recipient's 6-digit code (uniform, from the
    /// system's random source), store only its Argon2id PHC string on the open code's
    /// row, and email it; nothing for a code closed, sent or expired meanwhile. The code
    /// lives only in this function and the message: never in the job, a step, a log or
    /// the audit chain. A message lost after the row is marked sent is not resent (the
    /// recipient asks for another code).
    async fn email_otp(&self, job: &ClaimedJob, lease: Uuid) -> Result<()> {
        let bad = || WorkerError::BadJob {
            kind: job.kind.clone(),
        };
        let p: casual_sign_host::jobs::EmailOtpJob =
            serde_json::from_value(job.payload.clone()).map_err(|_| bad())?;
        let envelope = job.envelope_id.ok_or_else(bad)?;
        let mut tx = self.store.for_account(job.account_id).begin().await?;
        let now = self.now();
        let open = tx
            .recipients()
            .open_otp_code(None, Some(p.code_id))
            .await?
            .filter(|c| c.code_hash.is_none() && c.expires_at > now);
        let Some(code_row) = open else {
            return self.close_job(tx, job, lease).await;
        };
        let person = tx
            .recipients()
            .get(code_row.recipient_id)
            .await?
            .ok_or(WorkerError::SealInput { what: "recipient" })?;
        let to = person
            .recipient
            .email
            .clone()
            .ok_or(WorkerError::NoChannel)?;
        let subject = tx
            .envelopes()
            .get(envelope)
            .await?
            .ok_or(WorkerError::SealInput { what: "envelope" })?
            .subject;
        let code = one_time_code()?;
        let phc = {
            let code = code.clone();
            tokio::task::spawn_blocking(move || hash_code(&code))
                .await
                .map_err(|_| WorkerError::Config { setting: "argon2" })??
        };
        if !tx
            .recipients()
            .otp_sent(code_row.id, &casual_sign_audit::Personal(phc), now)
            .await?
        {
            return self.close_job(tx, job, lease).await;
        }
        tx.commit().await?;
        let mailer = self.mailer.as_ref().ok_or(WorkerError::NoChannel)?;
        let (subject, body) = email::render(
            Template::EmailOtp,
            &Fill {
                name: person.recipient.name.get(),
                subject: subject.get(),
                message: "",
                link: Some(&code),
                product: &self.config.product,
                abuse: &self.config.abuse,
            },
        );
        let msg = Message {
            from: self.config.mail_from.clone(),
            from_name: self.config.mail_from_name.clone(),
            to: to.get().clone(),
            to_name: person.recipient.name.get().clone(),
            subject,
            body,
            message_id: self.message_id(job.id, "otp"),
            date: now,
        };
        let sent = mailer.send(&msg).await?;
        self.boundary(Boundary::EmailSent, &job.kind).await;
        let mut tx = self.store.for_account(job.account_id).begin().await?;
        tx.job_steps()
            .record(
                job.id,
                "email.otp",
                &serde_json::json!({
                    "outcome": if matches!(sent, Sent::Accepted) { "accepted" } else { "bounced" },
                    "message_id": msg.message_id,
                }),
                now,
            )
            .await?;
        self.close_job(tx, job, lease).await
    }

    /// Finish a job that has no envelope in `tx` and commit.
    async fn close_job(&self, mut tx: TenantTx, job: &ClaimedJob, lease: Uuid) -> Result<()> {
        self.boundary(Boundary::BeforeCommit, &job.kind).await;
        tx.jobs()
            .complete(job.id, lease, self.now())
            .await
            .map_err(|e| match e.code() {
                "CS-DB-0003" => WorkerError::LeaseLost,
                _ => store_err(e),
            })?;
        tx.commit().await?;
        Ok(())
    }

    fn message_id(&self, job: JobId, who: &str) -> String {
        let who: String = who.chars().filter(char::is_ascii_alphanumeric).collect();
        format!("<{}.{}@{}>", job.0.simple(), who, self.config.mail_domain)
    }

    /// Send one templated email to one person, unless this job already did; returns
    /// whether it bounced.
    #[allow(clippy::too_many_arguments)]
    // The parts of one message; grouping them would only move the list.
    async fn send_once(
        &self,
        ctx: &Ctx<'_>,
        step: &str,
        who: &str,
        to: &str,
        to_name: &str,
        template: Template,
        state: &EnvelopeState,
        link: Option<&str>,
    ) -> Result<Sent> {
        let mailer = self.mailer.as_ref().ok_or(WorkerError::NoChannel)?;
        let message = if matches!(template, Template::Invitation | Template::CopyInvitation) {
            state.message.get().as_str()
        } else {
            ""
        };
        let (subject, body) = email::render(
            template,
            &Fill {
                name: to_name,
                subject: state.subject.get().as_str(),
                message,
                link,
                product: &self.config.product,
                abuse: &self.config.abuse,
            },
        );
        let msg = Message {
            from: self.config.mail_from.clone(),
            from_name: self.config.mail_from_name.clone(),
            to: to.to_owned(),
            to_name: to_name.to_owned(),
            subject,
            body,
            message_id: self.message_id(ctx.job.id, who),
            date: self.now(),
        };
        let sent = mailer.send(&msg).await?;
        self.boundary(Boundary::EmailSent, &ctx.job.kind).await;
        let outcome = match sent {
            Sent::Accepted => "accepted",
            Sent::Bounced => "bounced",
        };
        self.record_step(
            ctx,
            step,
            serde_json::json!({ "outcome": outcome, "message_id": msg.message_id }),
        )
        .await?;
        self.boundary(Boundary::Recorded, &ctx.job.kind).await;
        Ok(sent)
    }

    async fn message_one(
        &self,
        ctx: &Ctx<'_>,
        recipient: &Id,
        channel: Channel,
        template: Template,
        purpose: TokenPurpose,
        report: Option<Command>,
    ) -> Result<()> {
        let state = self.state(ctx).await?;
        if state.is_finished() {
            return self.finish(ctx, None).await;
        }
        let r = state
            .recipient(recipient)
            .ok_or(WorkerError::SealInput { what: "recipient" })?;
        match channel {
            Channel::Email => {}
            Channel::Link => return self.finish(ctx, report).await,
            _ => return Err(WorkerError::NoChannel),
        }
        let step = format!("email.{}", recipient.as_str());
        let done = self.steps(ctx).await?;
        let sent = match done.iter().find(|s| s.step == step) {
            Some(s) => {
                if s.detail.get("outcome").and_then(|v| v.as_str()) == Some("bounced") {
                    Sent::Bounced
                } else {
                    Sent::Accepted
                }
            }
            None => {
                let rid = RecipientId(uuid_of(recipient, "recipient")?);
                let link = self.mint_link(ctx, &state, rid, purpose).await?;
                self.send_once(
                    ctx,
                    &step,
                    recipient.as_str(),
                    r.spec.email.get().as_str(),
                    r.spec.name.get().as_str(),
                    template,
                    &state,
                    Some(&link),
                )
                .await?
            }
        };
        let report = match (sent, report) {
            (Sent::Bounced, Some(Command::InvitationDispatched { recipient, channel })) => {
                Some(Command::InvitationBounced { recipient, channel })
            }
            (_, r) => r,
        };
        self.finish(ctx, report).await
    }

    async fn notify_sender(&self, ctx: &Ctx<'_>, notice: Notice) -> Result<()> {
        let state = self.state(ctx).await?;
        let step = "email.sender".to_owned();
        if !self.steps(ctx).await?.iter().any(|s| s.step == step) {
            let user = UserId(uuid_of(&state.sender_user_id, "user")?);
            let mut tx = self.tx(ctx).await?;
            let member = tx.users().get(user).await?;
            tx.commit().await?;
            let member = member.ok_or(WorkerError::SealInput { what: "sender" })?;
            self.send_once(
                ctx,
                &step,
                "sender",
                member.email.get(),
                member.name.get(),
                template_of(notice),
                &state,
                None,
            )
            .await?;
        }
        self.finish(ctx, None).await
    }

    async fn notify_recipients(
        &self,
        ctx: &Ctx<'_>,
        recipients: &[Id],
        template: Template,
        link: Option<TokenPurpose>,
    ) -> Result<()> {
        let state = self.state(ctx).await?;
        let done = self.steps(ctx).await?;
        for rid in recipients {
            let step = format!("email.{}", rid.as_str());
            if done.iter().any(|s| s.step == step) {
                continue;
            }
            let Some(r) = state.recipient(rid) else {
                continue;
            };
            let email = r.spec.email.get().as_str();
            if email.is_empty() {
                continue;
            }
            let url = match link {
                Some(p) => Some(
                    self.mint_link(ctx, &state, RecipientId(uuid_of(rid, "recipient")?), p)
                        .await?,
                ),
                None => None,
            };
            self.send_once(
                ctx,
                &step,
                rid.as_str(),
                email,
                r.spec.name.get().as_str(),
                template,
                &state,
                url.as_deref(),
            )
            .await?;
        }
        self.finish(ctx, None).await
    }

    async fn purge(&self, ctx: &Ctx<'_>) -> Result<()> {
        let now = self.now();
        let mut tx = self.tx(ctx).await?;
        for r in tx.recipients().list(ctx.envelope).await? {
            tx.recipients().revoke_tokens(r.recipient.id, now).await?;
        }
        // Blobs are write-once with no delete (docs/22 §9); their removal is the
        // retention job's (slice 15, WRK-PURGE row).
        self.complete_in(tx, ctx).await
    }

    // ------------------------------------------------------------------ webhooks

    async fn webhook_job(
        &self,
        ctx: &Ctx<'_>,
        topic: casual_sign_workflow::WebhookTopic,
        recipient: Option<&Id>,
    ) -> Result<()> {
        let event_type = webhook::event_type(topic);
        let mut tx = self.tx(ctx).await?;
        let subs: Vec<_> = tx
            .webhooks()
            .list()
            .await?
            .into_iter()
            .filter(|s| {
                s.active
                    && s.envelope_id.is_none_or(|e| e == ctx.envelope)
                    && s.event_types.iter().any(|t| t == &event_type || t == "*")
            })
            .collect();
        tx.commit().await?;
        if subs.is_empty() {
            return self.finish(ctx, None).await;
        }
        let event_id = ctx.job.id.0;
        let body = webhook_body(ctx, &event_type, recipient)?;
        let done = self.steps(ctx).await?;
        let last_attempt = ctx.job.attempts >= jobs::max_attempts(&ctx.job.kind);
        let mut failures = 0usize;
        let mut refused = false;
        for sub in subs {
            let step = format!("webhook.{}", sub.id.0.simple());
            if done.iter().any(|s| s.step == step) {
                continue;
            }
            let delivery = WebhookDeliveryId(jobs::derived_uuid(&[
                ctx.job.id.0.as_bytes(),
                sub.id.0.as_bytes(),
            ]));
            // The delivery log row, once (a re-run finds it).
            {
                let mut tx = self.tx(ctx).await?;
                let existing = tx.webhooks().deliveries(sub.id, 1000).await?;
                if !existing.iter().any(|d| d.id == delivery) {
                    tx.webhooks()
                        .record_delivery(&Delivery {
                            id: delivery,
                            subscription_id: sub.id,
                            event_id,
                            event_type: event_type.clone(),
                            payload: serde_json::from_slice(&body)
                                .unwrap_or_else(|_| serde_json::json!({})),
                            status: "pending".into(),
                            attempts: 0,
                            last_status_code: None,
                        })
                        .await?;
                }
                tx.commit().await?;
            }
            let mut keys = Vec::new();
            for r in &sub.secret_refs {
                if let Some(s) = self.secrets.secret(r) {
                    keys.push(webhook::secret_key(s.expose())?);
                }
            }
            if keys.is_empty() {
                return Err(WorkerError::SecretMissing);
            }
            let ts = self.now().unix_timestamp();
            let headers = webhook::headers(&keys, &event_id.to_string(), ts, &body);
            let sender = self.webhooks.clone();
            let url = sub.url.clone();
            let b = body.clone();
            let answer = tokio::task::spawn_blocking(move || sender.post(&url, &headers, &b))
                .await
                .map_err(|_| WorkerError::WebhookFailed { status: None })?;
            self.boundary(Boundary::WebhookAnswered, &ctx.job.kind)
                .await;
            let (status, delivered) = match &answer {
                Ok(a) => (Some(i32::from(a.status)), a.delivered()),
                Err(_) => (None, false),
            };
            if matches!(answer, Err(WorkerError::WebhookRefused)) {
                refused = true;
            }
            let now = self.now();
            let next = if delivered || last_attempt || refused {
                None
            } else {
                Some(jobs::after(now, jobs::backoff(ctx.job.attempts, 0.5)))
            };
            let mut tx = self.tx(ctx).await?;
            tx.webhooks()
                .record_attempt(delivery, status, delivered, next, now)
                .await?;
            if delivered {
                tx.job_steps()
                    .record(
                        ctx.job.id,
                        &step,
                        &serde_json::json!({ "status": status }),
                        now,
                    )
                    .await?;
            } else {
                failures = failures.saturating_add(1);
            }
            tx.commit().await?;
            if delivered {
                self.boundary(Boundary::Recorded, &ctx.job.kind).await;
            }
        }
        if refused {
            return Err(WorkerError::WebhookRefused);
        }
        if failures > 0 {
            return Err(WorkerError::WebhookFailed { status: None });
        }
        self.finish(ctx, None).await
    }

    // ------------------------------------------------------------------ sealing

    async fn seal_job(&self, ctx: &Ctx<'_>) -> Result<()> {
        let job_effect = ctx.payload.effect.id.clone();
        let state = self.state(ctx).await?;
        // The engine decides whether this job is still the pending one; never seal for
        // one it would refuse (a cancelled or superseded job).
        if state.status != casual_sign_model::EnvelopeStatus::Completing
            || state.book.seal_job.as_ref() != Some(&job_effect)
        {
            return self.finish(ctx, None).await;
        }
        let stored = self
            .steps(ctx)
            .await?
            .into_iter()
            .find(|s| s.step == "seal.stored");
        let documents: Vec<SealedDocument> = match stored {
            Some(s) => {
                serde_json::from_value(s.detail.get("documents").cloned().unwrap_or_default())
                    .map_err(|_| WorkerError::StateUnreadable)?
            }
            None => match self.seal_and_store(ctx, state).await {
                Ok(d) => d,
                // Infrastructure: the job retries.
                Err(e @ WorkerError::Store(_)) => return Err(e),
                // The seal itself failed: the engine records it, alerts, and schedules a
                // new seal job; the envelope stays `completing`.
                Err(e) => {
                    crate::log(
                        "WARN",
                        "seal_failed",
                        &[
                            ("envelope", ctx.envelope.0.to_string()),
                            ("code", e.code().to_owned()),
                        ],
                    );
                    let code = Text::new(e.code()).map_err(|_| WorkerError::StateUnreadable)?;
                    return self
                        .finish(
                            ctx,
                            Some(Command::SealFailed {
                                job: job_effect,
                                code,
                            }),
                        )
                        .await;
                }
            },
        };
        self.finish(
            ctx,
            Some(Command::SealSucceeded {
                job: job_effect,
                documents,
            }),
        )
        .await
    }

    async fn seal_and_store(
        &self,
        ctx: &Ctx<'_>,
        state: EnvelopeState,
    ) -> Result<Vec<SealedDocument>> {
        // Gather.
        let mut tx = self.tx(ctx).await?;
        let chain = tx.audit().chain(ctx.envelope).await?;
        let account = tx.account().get().await?;
        let sender = tx
            .users()
            .get(UserId(uuid_of(&state.sender_user_id, "user")?))
            .await?
            .ok_or(WorkerError::SealInput { what: "sender" })?;
        tx.commit().await?;
        let mut delivered = Vec::with_capacity(state.documents.len());
        for d in &state.documents {
            let bytes = self
                .blobs
                .get(&BlobKey(*d.spec.delivered_hash.as_bytes()))
                .await
                .map_err(|e| match e.code() {
                    "CS-BLOB-0002" | "CS-BLOB-0003" => WorkerError::SealInput { what: "document" },
                    _ => store_err(e),
                })?;
            delivered.push(bytes);
        }
        let mut captures: BTreeMap<String, Art> = BTreeMap::new();
        for id in seal::capture_ids(&state, &chain) {
            let key = BlobKey::parse(&id).map_err(|_| WorkerError::BadCapture)?;
            let bytes = self.blob_or(&key, "capture").await?;
            let art = match capture::parse(&bytes)? {
                capture::Parsed::Art(a) => a,
                capture::Parsed::Image(k) => {
                    let key = BlobKey::parse(&k).map_err(|_| WorkerError::BadCapture)?;
                    capture::image_art(self.blob_or(&key, "capture").await?)?
                }
            };
            captures.insert(id, art);
        }
        // Signer attachments (WEB-06): each value names its file by SHA-256; the file
        // is read to give its size and kind, and its hash checked.
        let mut attachments = Vec::new();
        for f in &state.fields.0 {
            let Some(casual_sign_model::FieldValue::Attachment(id)) = &f.value else {
                continue;
            };
            let key = BlobKey::parse(id.as_str())
                .map_err(|_| WorkerError::SealInput { what: "attachment" })?;
            let bytes = self.blob_or(&key, "attachment").await?;
            if Hash256::digest(&bytes).hex() != id.as_str() {
                return Err(WorkerError::SealInput { what: "attachment" });
            }
            let recipient = f
                .recipient_id
                .as_ref()
                .and_then(|r| state.recipient(r))
                .map(|r| r.spec.name.get().as_str().to_owned())
                .unwrap_or_default();
            attachments.push(casual_sign_certificate::AttachmentRow {
                recipient,
                field: f
                    .label
                    .as_ref()
                    .map_or_else(|| f.id.as_str().to_owned(), |l| l.as_str().to_owned()),
                media_type: casual_sign_host::capture::media_type(&bytes).to_owned(),
                bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                sha256: Hash256::digest(&bytes),
            });
        }
        let now = ts(self.now())?;
        let input = SealInput {
            attachments,
            state,
            chain,
            account_name: account.name,
            sender: casual_sign_sdk::evidence::Party {
                name: sender.name.get().clone(),
                email: sender.email.get().clone(),
            },
            delivered,
            captures,
            now,
        };
        // Seal (blocking: keyd and the TSA are synchronous).
        let services = self.seal.clone();
        let (outs, input) = tokio::task::spawn_blocking(move || {
            let r = seal::seal_all(&services, &input);
            (r, input)
        })
        .await
        .map_err(|_| WorkerError::Pipeline {
            code: "CS-SEAL-0001",
        })?;
        let sealed = outs?;
        self.boundary(Boundary::Sealed, &ctx.job.kind).await;

        // Store, read back, verify independently: the documents and the certificate.
        let certificate = self.blobs.put(&sealed.certificate).await?;
        let back = self.blobs.get(&certificate).await?;
        seal::verify_stored(&self.seal, &back, input.state.seal_profile, now)?;
        let outs = sealed.documents;
        let mut records = Vec::with_capacity(outs.len());
        let mut versions = Vec::with_capacity(outs.len());
        for out in outs {
            let key = self.blobs.put(&out.bytes).await?;
            let back = self.blobs.get(&key).await?;
            seal::verify_stored(&self.seal, &back, input.state.seal_profile, now)?;
            let mut record = out.record;
            record.verified = true;
            versions.push((record.document_id.clone(), key, back.len(), out.pages));
            records.push(record);
        }
        let mut tx = self.tx(ctx).await?;
        for (doc, key, len, pages) in versions {
            tx.documents()
                .add_version(&NewVersion {
                    id: DocumentVersionId(jobs::derived_uuid(&[
                        ctx.job.id.0.as_bytes(),
                        doc.as_str().as_bytes(),
                        b"sealed",
                    ])),
                    document_id: DocumentId(uuid_of(&doc, "document")?),
                    kind: VersionKind::Sealed,
                    sha256: key.0,
                    byte_len: i64::try_from(len).unwrap_or(i64::MAX),
                    page_count: i32::try_from(pages).unwrap_or(i32::MAX),
                    admission_report: None,
                    pages: serde_json::json!([]),
                })
                .await?;
        }
        tx.envelopes()
            .set_certificate(ctx.envelope, &certificate.0)
            .await?;
        tx.job_steps()
            .record(
                ctx.job.id,
                "seal.stored",
                &serde_json::json!({ "documents": records }),
                self.now(),
            )
            .await?;
        tx.commit().await?;
        self.boundary(Boundary::Recorded, &ctx.job.kind).await;
        Ok(records)
    }

    async fn blob_or(&self, key: &BlobKey, what: &'static str) -> Result<Vec<u8>> {
        self.blobs.get(key).await.map_err(|e| match e.code() {
            "CS-BLOB-0002" | "CS-BLOB-0003" | "CS-BLOB-0004" => WorkerError::SealInput { what },
            _ => store_err(e),
        })
    }
}

fn template_of(n: Notice) -> Template {
    match n {
        Notice::Voided => Template::Voided,
        Notice::Declined => Template::Declined,
        Notice::Expired => Template::Expired,
        Notice::Completed => Template::Completed,
        Notice::AuthLocked => Template::AuthLocked,
        Notice::Bounced => Template::Bounced,
        _ => Template::Corrected,
    }
}

/// The webhook body (docs/40 §4): ids, the event type and time, the envelope's status
/// and version; never a document, a name, an address or a value.
#[derive(Serialize)]
struct WebhookBody<'a> {
    id: String,
    #[serde(rename = "type")]
    event_type: &'a str,
    created_at: String,
    account_id: String,
    data: WebhookData,
}

#[derive(Serialize)]
struct WebhookData {
    envelope_id: String,
    status: casual_sign_model::EnvelopeStatus,
    version: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    recipient_id: Option<String>,
}

fn webhook_body(ctx: &Ctx<'_>, event_type: &str, recipient: Option<&Id>) -> Result<Vec<u8>> {
    let at = OffsetDateTime::from_unix_timestamp_nanos(
        i128::from(ctx.payload.decided_at).saturating_mul(1_000_000),
    )
    .map_err(|_| WorkerError::BadJob {
        kind: ctx.job.kind.clone(),
    })?;
    let body = WebhookBody {
        id: ctx.job.id.0.to_string(),
        event_type,
        created_at: at
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
        account_id: ctx.account.0.to_string(),
        data: WebhookData {
            envelope_id: id_of(ctx.envelope.0, "envelope")?.as_str().to_owned(),
            status: ctx.payload.status,
            version: ctx.payload.version,
            recipient_id: recipient.map(|r| r.as_str().to_owned()),
        },
    };
    serde_json::to_vec(&body).map_err(|_| WorkerError::BadJob {
        kind: ctx.job.kind.clone(),
    })
}

/// The effect id a seal job carries (for tests and tools).
#[must_use]
pub fn seal_job_of(state: &EnvelopeState) -> Option<EffectId> {
    state.book.seal_job.clone()
}
