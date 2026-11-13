//! The console's door to the database: reads of `platform` tables and of tenant metadata
//! through definer functions, and writes through definer functions in a [`PlatformTx`]
//! that also appends the operator event, so a change and its event commit together.

use casual_sign_audit::Hash256;
use sqlx::postgres::{PgPool, PgRow};
use sqlx::{Postgres, Row, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{PlatformError, Result, db};
use crate::event::{ChainReport, ChainVerifier, EventDraft, OrgScope, StoredEvent};

/// `pg_advisory_xact_lock` key serializing operator-log appends: "OSEALOPL" as an integer.
const LOG_LOCK: i64 = 0x4F53_4541_4C4F_504C;

/// Largest page of any listing.
pub const MAX_PAGE: u32 = 200;

/// An operator role (docs/23 §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Operators and their roles.
    PlatformOwner,
    /// Organizations, workspaces, plans.
    Operator,
    /// Seal profiles, TSA, trust anchors.
    KeyCustodian,
    /// Health and usage, read-only.
    Observer,
}

impl Role {
    /// Every role.
    pub const ALL: [Role; 4] = [
        Self::PlatformOwner,
        Self::Operator,
        Self::KeyCustodian,
        Self::Observer,
    ];

    /// The stored name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PlatformOwner => "platform_owner",
            Self::Operator => "operator",
            Self::KeyCustodian => "key_custodian",
            Self::Observer => "observer",
        }
    }

    /// The role named `s`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == s)
    }
}

fn roles(names: &[String]) -> Result<Vec<Role>> {
    names
        .iter()
        .map(|n| Role::parse(n).ok_or(PlatformError::Corrupt { what: "roles" }))
        .collect()
}

/// What a sign-in needs about an operator.
#[derive(Clone, PartialEq, Eq)]
pub struct OperatorLogin {
    /// The operator.
    pub id: Uuid,
    /// The Argon2id PHC string; `None` until the operator enrols.
    pub password_hash: Option<String>,
    /// Disabled operators cannot sign in.
    pub disabled: bool,
}

impl core::fmt::Debug for OperatorLogin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OperatorLogin")
            .field("id", &self.id)
            .field("disabled", &self.disabled)
            .finish_non_exhaustive()
    }
}

/// An operator as listed to platform owners.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorSummary {
    /// The operator.
    pub id: Uuid,
    /// Their sign-in address (operator data, shown to platform owners only).
    pub email: String,
    /// Their roles.
    pub roles: Vec<Role>,
    /// When created.
    pub created_at: OffsetDateTime,
    /// When disabled.
    pub disabled_at: Option<OffsetDateTime>,
}

/// A resolved session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// The operator.
    pub operator: Uuid,
    /// Their roles.
    pub roles: Vec<Role>,
    /// When the second factor was last entered; `None` before it.
    pub mfa_at: Option<OffsetDateTime>,
    /// SHA-256 of the session's CSRF token.
    pub csrf_sha256: [u8; 32],
    /// When the session ends.
    pub expires_at: OffsetDateTime,
}

/// A new operator, created without a password or second factor: they set both through
/// the one-time enrolment link whose token hash is `enrolment_sha256`.
#[derive(Debug, Clone)]
pub struct NewOperator<'a> {
    /// The new id.
    pub id: Uuid,
    /// Normalized e-mail.
    pub email: &'a str,
    /// SHA-256 of the enrolment token.
    pub enrolment_sha256: [u8; 32],
    /// When the enrolment link lapses (at most 7 days).
    pub enrolment_expires: OffsetDateTime,
}

/// An organization with its counts. No e-mail, person or content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrganizationRow {
    /// Id.
    pub id: Uuid,
    /// Name (tenant metadata, docs/07).
    pub name: String,
    /// `active`, `suspended` or `closed`.
    pub status: String,
    /// Data-region labels.
    pub data_regions: Vec<String>,
    /// Created.
    pub created_at: OffsetDateTime,
    /// Workspaces.
    pub workspaces: i64,
    /// Distinct enabled members across its workspaces.
    pub members: i64,
    /// Envelopes across its workspaces.
    pub envelopes: i64,
    /// Owners (detail only).
    pub owners: Option<i64>,
}

/// A workspace with its counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRow {
    /// Id.
    pub id: Uuid,
    /// Name (tenant metadata).
    pub name: String,
    /// `active` or `archived`.
    pub status: String,
    /// Data-region label.
    pub data_region: Option<String>,
    /// Created.
    pub created_at: OffsetDateTime,
    /// Enabled members.
    pub members: i64,
    /// Templates.
    pub templates: i64,
    /// Envelopes.
    pub envelopes: i64,
    /// Drafts.
    pub envelopes_draft: i64,
    /// Sent and not finished.
    pub envelopes_in_progress: i64,
    /// Completed.
    pub envelopes_completed: i64,
}

/// Queue depth for one job kind and status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobStat {
    /// Kind.
    pub kind: String,
    /// `queued`, `running` or `dead`.
    pub status: String,
    /// Count.
    pub jobs: i64,
    /// Age of the oldest queued job, seconds.
    pub oldest_seconds: Option<i64>,
}

/// A dead letter, without its payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadJob {
    /// Job id.
    pub id: Uuid,
    /// Kind.
    pub kind: String,
    /// Workspace.
    pub workspace_id: Uuid,
    /// Envelope, when the job has one.
    pub envelope_id: Option<Uuid>,
    /// Its last error code.
    pub error_code: Option<String>,
    /// Attempts made.
    pub attempts: i32,
    /// When it died.
    pub finished_at: Option<OffsetDateTime>,
}

/// A service the console probes, from deployment configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceTarget {
    /// Name.
    pub name: String,
    /// What it is (`server`, `worker`, `keyd`, `tsa`, `blob`, `email`, `console`, `other`).
    pub role: String,
    /// `http` or `tcp`.
    pub probe: String,
    /// URL or `host:port`.
    pub target: String,
}

/// A two-person action awaiting or past its approval (docs/23 §5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRow {
    /// The request.
    pub id: Uuid,
    /// Who asked.
    pub requester: Uuid,
    /// `organization.suspend` or `organization.resume`.
    pub action: String,
    /// The object it is for.
    pub target: Uuid,
    /// When asked.
    pub created_at: OffsetDateTime,
    /// When it lapses.
    pub expires_at: OffsetDateTime,
    /// Approvers so far.
    pub approvers: Vec<Uuid>,
    /// Whether it was spent.
    pub used: bool,
}

/// A two-person organization action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrgAction {
    /// Suspend: new work refused, sent envelopes continue (docs/23 §5.3).
    Suspend,
    /// Resume a suspended organization.
    Resume,
}

impl OrgAction {
    /// The stored name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Suspend => "organization.suspend",
            Self::Resume => "organization.resume",
        }
    }

    /// The action named `s`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        [Self::Suspend, Self::Resume]
            .into_iter()
            .find(|a| a.as_str() == s)
    }
}

/// An alert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertRow {
    /// Id.
    pub id: Uuid,
    /// When.
    pub at: OffsetDateTime,
    /// Raised by.
    pub source: String,
    /// Code.
    pub code: String,
    /// The alert it resolves.
    pub resolves: Option<Uuid>,
}

fn i64_to_u64(n: i64, what: &'static str) -> Result<u64> {
    u64::try_from(n).map_err(|_| PlatformError::Corrupt { what })
}

fn hash_col(row: &PgRow, col: &str) -> Result<Option<Hash256>> {
    let v: Option<Vec<u8>> = row.try_get(col).map_err(db)?;
    v.map(|b| {
        <[u8; 32]>::try_from(b.as_slice())
            .map(Hash256)
            .map_err(|_| PlatformError::Corrupt { what: "hash" })
    })
    .transpose()
}

fn event_row(row: &PgRow) -> Result<StoredEvent> {
    Ok(StoredEvent {
        seq: i64_to_u64(row.try_get("seq").map_err(db)?, "seq")?,
        prev: hash_col(row, "prev_hash")?,
        hash: hash_col(row, "hash")?.ok_or(PlatformError::Corrupt { what: "hash" })?,
        action: row.try_get("action").map_err(db)?,
        operator: row.try_get("operator_id").map_err(db)?,
        at: row.try_get("at").map_err(db)?,
        canonical: row.try_get("canonical").map_err(db)?,
    })
}

fn org_row(r: &PgRow, detail: bool) -> Result<OrganizationRow> {
    Ok(OrganizationRow {
        id: r.try_get("id").map_err(db)?,
        name: r.try_get("name").map_err(db)?,
        status: r.try_get("status").map_err(db)?,
        data_regions: r.try_get("data_regions").map_err(db)?,
        created_at: r.try_get("created_at").map_err(db)?,
        workspaces: r.try_get("workspaces").map_err(db)?,
        members: r.try_get("members").map_err(db)?,
        envelopes: r.try_get("envelopes").map_err(db)?,
        owners: if detail {
            Some(r.try_get("owners").map_err(db)?)
        } else {
            None
        },
    })
}

/// The platform store, over a pool connected as `openseal_console`.
#[derive(Debug, Clone)]
pub struct PlatformStore {
    pool: PgPool,
}

impl PlatformStore {
    /// Over `pool`, which must connect as a member of `openseal_console`.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// The pool (for shutdown).
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Whether the database answers.
    ///
    /// # Errors
    /// `CS-DB-0001` when it does not.
    pub async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(())
    }

    /// Begin a write transaction.
    ///
    /// # Errors
    /// `CS-DB-0001` when the database cannot be reached.
    pub async fn begin(&self) -> Result<PlatformTx> {
        Ok(PlatformTx {
            tx: self.pool.begin().await.map_err(db)?,
        })
    }

    // Operators and sessions ----------------------------------------------------------

    /// The operator signing in with `email` (normalized), if any.
    ///
    /// # Errors
    /// A database error.
    pub async fn operator_login(&self, email: &str) -> Result<Option<OperatorLogin>> {
        let row = sqlx::query(
            "SELECT id, password_hash, disabled_at IS NOT NULL AS disabled \
             FROM platform.operators WHERE email = $1",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        row.map(|r| {
            Ok(OperatorLogin {
                id: r.try_get("id").map_err(db)?,
                password_hash: r.try_get("password_hash").map_err(db)?,
                disabled: r.try_get("disabled").map_err(db)?,
            })
        })
        .transpose()
    }

    /// The sealed TOTP seed of `operator`.
    ///
    /// # Errors
    /// A database error.
    pub async fn operator_seed(&self, operator: Uuid) -> Result<Option<Vec<u8>>> {
        sqlx::query_scalar("SELECT seed_sealed FROM platform.operator_mfa WHERE operator_id = $1")
            .bind(operator)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)
    }

    /// The operator and pending sealed seed of an unspent, unexpired enrolment link.
    ///
    /// # Errors
    /// A database error.
    pub async fn pending_enrolment(
        &self,
        token_sha256: &[u8; 32],
        now: OffsetDateTime,
    ) -> Result<Option<(Uuid, Option<Vec<u8>>)>> {
        let row = sqlx::query(
            "SELECT operator_id, pending_seed FROM platform.operator_enrolments \
             WHERE token_sha256 = $1 AND used_at IS NULL AND $2 < expires_at",
        )
        .bind(token_sha256.as_slice())
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        row.map(|r| {
            Ok((
                r.try_get("operator_id").map_err(db)?,
                r.try_get("pending_seed").map_err(db)?,
            ))
        })
        .transpose()
    }

    /// Every operator, oldest first (at most 1,000).
    ///
    /// # Errors
    /// A database error.
    pub async fn operators(&self) -> Result<Vec<OperatorSummary>> {
        let rows = sqlx::query(
            "SELECT id, email, roles, created_at, disabled_at FROM platform.operators \
             ORDER BY created_at, id LIMIT 1000",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter()
            .map(|r| {
                Ok(OperatorSummary {
                    id: r.try_get("id").map_err(db)?,
                    email: r.try_get("email").map_err(db)?,
                    roles: roles(&r.try_get::<Vec<String>, _>("roles").map_err(db)?)?,
                    created_at: r.try_get("created_at").map_err(db)?,
                    disabled_at: r.try_get("disabled_at").map_err(db)?,
                })
            })
            .collect()
    }

    /// The live session for `token_sha256` at `now`, marked seen; `None` when it is not
    /// live.
    ///
    /// # Errors
    /// A database error.
    pub async fn resolve_session(
        &self,
        token_sha256: &[u8; 32],
        now: OffsetDateTime,
    ) -> Result<Option<Session>> {
        let row = sqlx::query(
            "SELECT operator_id, roles, mfa_at, csrf_sha256, expires_at \
             FROM platform.resolve_session($1, $2)",
        )
        .bind(token_sha256.as_slice())
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        row.map(|r| {
            let csrf: Vec<u8> = r.try_get("csrf_sha256").map_err(db)?;
            Ok(Session {
                operator: r.try_get("operator_id").map_err(db)?,
                roles: roles(&r.try_get::<Vec<String>, _>("roles").map_err(db)?)?,
                mfa_at: r.try_get("mfa_at").map_err(db)?,
                csrf_sha256: <[u8; 32]>::try_from(csrf.as_slice())
                    .map_err(|_| PlatformError::Corrupt { what: "csrf" })?,
                expires_at: r.try_get("expires_at").map_err(db)?,
            })
        })
        .transpose()
    }

    // The operator log ----------------------------------------------------------------

    /// Events after `after` (exclusive; `None` from the start), oldest first.
    ///
    /// # Errors
    /// A database error.
    pub async fn events(&self, after: Option<u64>, limit: u32) -> Result<Vec<StoredEvent>> {
        let after = after
            .map(|a| i64::try_from(a).map_err(|_| PlatformError::Corrupt { what: "seq" }))
            .transpose()?
            .unwrap_or(-1);
        let rows = sqlx::query(
            "SELECT seq, prev_hash, hash, action, operator_id, at, canonical \
             FROM platform.operator_events WHERE seq > $1 ORDER BY seq LIMIT $2",
        )
        .bind(after)
        .bind(i64::from(limit.clamp(1, MAX_PAGE)))
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter().map(event_row).collect()
    }

    /// Verify the whole operator log against its stored head, in pages.
    ///
    /// # Errors
    /// `CS-CON-0007` naming the first event that does not verify.
    pub async fn verify_log(&self) -> Result<ChainReport> {
        let mut v = ChainVerifier::default();
        let mut after = None;
        loop {
            let page = self.events(after, MAX_PAGE).await?;
            let Some(last) = page.last() else { break };
            after = Some(last.seq);
            for e in &page {
                v.push(e)?;
            }
        }
        let head = sqlx::query("SELECT head FROM platform.operator_chain WHERE singleton")
            .fetch_one(&self.pool)
            .await
            .map_err(db)?;
        v.finish(hash_col(&head, "head")?)
    }

    // Tenant metadata -----------------------------------------------------------------

    /// One page of organizations after `after`.
    ///
    /// # Errors
    /// A database error.
    pub async fn organizations(
        &self,
        after: Option<Uuid>,
        limit: u32,
    ) -> Result<Vec<OrganizationRow>> {
        let rows = sqlx::query("SELECT * FROM platform.organizations_page($1, $2)")
            .bind(after)
            .bind(i32::try_from(limit.clamp(1, MAX_PAGE)).unwrap_or(1))
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
        rows.iter().map(|r| org_row(r, false)).collect()
    }

    /// One organization.
    ///
    /// # Errors
    /// A database error.
    pub async fn organization(&self, id: Uuid) -> Result<Option<OrganizationRow>> {
        let row = sqlx::query("SELECT * FROM platform.organization($1)")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        row.map(|r| org_row(&r, true)).transpose()
    }

    /// The workspaces of an organization.
    ///
    /// # Errors
    /// A database error.
    pub async fn workspaces(&self, organization: Uuid) -> Result<Vec<WorkspaceRow>> {
        let rows = sqlx::query("SELECT * FROM platform.organization_workspaces($1)")
            .bind(organization)
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
        rows.iter()
            .map(|r| {
                Ok(WorkspaceRow {
                    id: r.try_get("id").map_err(db)?,
                    name: r.try_get("name").map_err(db)?,
                    status: r.try_get("status").map_err(db)?,
                    data_region: r.try_get("data_region").map_err(db)?,
                    created_at: r.try_get("created_at").map_err(db)?,
                    members: r.try_get("members").map_err(db)?,
                    templates: r.try_get("templates").map_err(db)?,
                    envelopes: r.try_get("envelopes").map_err(db)?,
                    envelopes_draft: r.try_get("envelopes_draft").map_err(db)?,
                    envelopes_in_progress: r.try_get("envelopes_in_progress").map_err(db)?,
                    envelopes_completed: r.try_get("envelopes_completed").map_err(db)?,
                })
            })
            .collect()
    }

    /// Queue depth by kind and status at `now`.
    ///
    /// # Errors
    /// A database error.
    pub async fn job_stats(&self, now: OffsetDateTime) -> Result<Vec<JobStat>> {
        let rows = sqlx::query("SELECT * FROM platform.job_stats($1)")
            .bind(now)
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
        rows.iter()
            .map(|r| {
                Ok(JobStat {
                    kind: r.try_get("kind").map_err(db)?,
                    status: r.try_get("status").map_err(db)?,
                    jobs: r.try_get("jobs").map_err(db)?,
                    oldest_seconds: r.try_get("oldest_seconds").map_err(db)?,
                })
            })
            .collect()
    }

    /// Dead letters, newest first.
    ///
    /// # Errors
    /// A database error.
    pub async fn dead_jobs(&self, limit: u32) -> Result<Vec<DeadJob>> {
        let rows = sqlx::query("SELECT * FROM platform.dead_jobs($1)")
            .bind(i32::try_from(limit.clamp(1, MAX_PAGE)).unwrap_or(1))
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
        rows.iter()
            .map(|r| {
                Ok(DeadJob {
                    id: r.try_get("id").map_err(db)?,
                    kind: r.try_get("kind").map_err(db)?,
                    workspace_id: r.try_get("workspace_id").map_err(db)?,
                    envelope_id: r.try_get("envelope_id").map_err(db)?,
                    error_code: r.try_get("error_code").map_err(db)?,
                    attempts: r.try_get("attempts").map_err(db)?,
                    finished_at: r.try_get("finished_at").map_err(db)?,
                })
            })
            .collect()
    }

    /// Database connections by state.
    ///
    /// # Errors
    /// A database error.
    pub async fn pool_stats(&self) -> Result<Vec<(String, i64)>> {
        let rows = sqlx::query("SELECT state, connections FROM platform.pool_stats()")
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
        rows.iter()
            .map(|r| Ok((r.try_get(0).map_err(db)?, r.try_get(1).map_err(db)?)))
            .collect()
    }

    /// The configured service targets.
    ///
    /// # Errors
    /// A database error.
    pub async fn service_targets(&self) -> Result<Vec<ServiceTarget>> {
        let rows = sqlx::query(
            "SELECT name, role, probe, target FROM platform.service_targets ORDER BY name LIMIT 64",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter()
            .map(|r| {
                Ok(ServiceTarget {
                    name: r.try_get("name").map_err(db)?,
                    role: r.try_get("role").map_err(db)?,
                    probe: r.try_get("probe").map_err(db)?,
                    target: r.try_get("target").map_err(db)?,
                })
            })
            .collect()
    }

    /// Approval requests made in the last 24 hours or still live, newest first (at most
    /// 200).
    ///
    /// # Errors
    /// A database error.
    pub async fn approvals(&self, now: OffsetDateTime) -> Result<Vec<ApprovalRow>> {
        let rows = sqlx::query(
            "SELECT r.id, r.requester, r.action, r.target, r.created_at, r.expires_at, \
                    COALESCE((SELECT array_agg(g.approver ORDER BY g.granted_at) FROM platform.approval_grants g \
                               WHERE g.request_id = r.id), '{}') AS approvers, \
                    EXISTS (SELECT 1 FROM platform.approval_uses u WHERE u.request_id = r.id) AS used \
             FROM platform.approval_requests r \
             WHERE r.expires_at > $1 - interval '24 hours' \
             ORDER BY r.created_at DESC, r.id LIMIT 200",
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter()
            .map(|r| {
                Ok(ApprovalRow {
                    id: r.try_get("id").map_err(db)?,
                    requester: r.try_get("requester").map_err(db)?,
                    action: r.try_get("action").map_err(db)?,
                    target: r.try_get("target").map_err(db)?,
                    created_at: r.try_get("created_at").map_err(db)?,
                    expires_at: r.try_get("expires_at").map_err(db)?,
                    approvers: r.try_get("approvers").map_err(db)?,
                    used: r.try_get("used").map_err(db)?,
                })
            })
            .collect()
    }

    /// The newest alerts.
    ///
    /// # Errors
    /// A database error.
    pub async fn alerts(&self, limit: u32) -> Result<Vec<AlertRow>> {
        let rows = sqlx::query(
            "SELECT id, at, source, code, resolves FROM platform.alerts ORDER BY at DESC, id LIMIT $1",
        )
        .bind(i64::from(limit.clamp(1, MAX_PAGE)))
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter()
            .map(|r| {
                Ok(AlertRow {
                    id: r.try_get("id").map_err(db)?,
                    at: r.try_get("at").map_err(db)?,
                    source: r.try_get("source").map_err(db)?,
                    code: r.try_get("code").map_err(db)?,
                    resolves: r.try_get("resolves").map_err(db)?,
                })
            })
            .collect()
    }
}

/// A write transaction: definer-function writes and the operator events that record them,
/// committed together.
#[derive(Debug)]
pub struct PlatformTx {
    tx: Transaction<'static, Postgres>,
}

impl PlatformTx {
    /// Commit.
    ///
    /// # Errors
    /// A database error.
    pub async fn commit(self) -> Result<()> {
        self.tx.commit().await.map_err(db)
    }

    /// Append `draft` to the operator log at the chain's head; its seq and hash.
    ///
    /// # Errors
    /// `CS-DB-0008` for a malformed draft, `CS-DB-0014` when the database refuses the link.
    pub async fn append(&mut self, draft: &EventDraft) -> Result<(u64, Hash256)> {
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(LOG_LOCK)
            .execute(&mut *self.tx)
            .await
            .map_err(db)?;
        let head = sqlx::query("SELECT seq, head FROM platform.operator_chain WHERE singleton")
            .fetch_one(&mut *self.tx)
            .await
            .map_err(db)?;
        let last: Option<i64> = head.try_get("seq").map_err(db)?;
        let prev = hash_col(&head, "head")?;
        let seq = match last {
            None => 0,
            Some(s) => i64_to_u64(s, "seq")?
                .checked_add(1)
                .ok_or(PlatformError::Corrupt { what: "seq" })?,
        };
        let canonical = draft.canonical(seq, prev.as_ref())?;
        let hash = Hash256::digest(&canonical);
        sqlx::query(
            "INSERT INTO platform.operator_events (seq, prev_hash, hash, action, operator_id, at, canonical) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(i64::try_from(seq).map_err(|_| PlatformError::Corrupt { what: "seq" })?)
        .bind(prev.map(|h| h.0.to_vec()))
        .bind(hash.0.as_slice())
        .bind(&draft.action)
        .bind(draft.operator)
        .bind(draft.at)
        .bind(&canonical)
        .execute(&mut *self.tx)
        .await
        .map_err(db)?;
        Ok((seq, hash))
    }

    /// Append `draft` to the operator log, as [`Self::append`], and copy it into the
    /// admin log of the organization `on` names (`org_admin_events`, docs/23 §2.5, §5.1),
    /// in this transaction: what every console write on an organization or a workspace
    /// does, so tenants see what the platform did to them. The database refuses to commit
    /// such a write without its copy (`admin_change_has_event`, migration 0026). Returns
    /// the copy's organization and `seq`, or `None` when there is no such organization or
    /// workspace (nothing is appended then).
    ///
    /// # Errors
    /// `CS-DB-0008` for a malformed draft or one without an operator; `CS-DB-0014` when
    /// either log refuses the link or the copy names another operator than `session`'s;
    /// the session check's codes (`CS-CON-0001` to `CS-CON-0003`).
    pub async fn append_on(
        &mut self,
        session: &[u8; 32],
        on: OrgScope,
        draft: &EventDraft,
    ) -> Result<Option<(Uuid, u64)>> {
        let (org, ws) = match on {
            OrgScope::Organization(o) => (Some(o), None),
            OrgScope::Workspace(w) => (None, Some(w)),
        };
        let Some(tip) = sqlx::query(
            "SELECT organization_id, next_seq, head FROM platform.org_log_tip($1, $2, $3, $4)",
        )
        .bind(session.as_slice())
        .bind(org)
        .bind(ws)
        .bind(draft.at)
        .fetch_optional(&mut *self.tx)
        .await
        .map_err(db)?
        else {
            return Ok(None);
        };
        let org: Uuid = tip.try_get("organization_id").map_err(db)?;
        let seq = i64_to_u64(tip.try_get("next_seq").map_err(db)?, "seq")?;
        let prev = hash_col(&tip, "head")?;
        let (op_seq, op_hash) = self.append(draft).await?;
        let canonical = draft.org_copy(org, seq, prev.as_ref(), (op_seq, &op_hash))?;
        let hash = Hash256::digest(&canonical);
        sqlx::query("SELECT platform.copy_to_org_log($1, $2, $3, $4, $5, $6, $7, $8, $9)")
            .bind(session.as_slice())
            .bind(org)
            .bind(i64::try_from(seq).map_err(|_| PlatformError::Corrupt { what: "seq" })?)
            .bind(prev.map(|h| h.0.to_vec()))
            .bind(hash.0.as_slice())
            .bind(&draft.action)
            .bind(draft.org_copy_at()?)
            .bind(&canonical)
            .bind(draft.at)
            .execute(&mut *self.tx)
            .await
            .map_err(db)?;
        Ok(Some((org, seq)))
    }

    /// The first platform owner, with an enrolment link; `false` once any operator
    /// exists.
    ///
    /// # Errors
    /// A database error, `CS-DB-0008` for a malformed value.
    pub async fn bootstrap_operator(
        &mut self,
        op: &NewOperator<'_>,
        now: OffsetDateTime,
    ) -> Result<bool> {
        sqlx::query_scalar("SELECT platform.bootstrap_operator($1, $2, $3, $4, $5)")
            .bind(op.id)
            .bind(op.email)
            .bind(op.enrolment_sha256.as_slice())
            .bind(now)
            .bind(op.enrolment_expires)
            .fetch_one(&mut *self.tx)
            .await
            .map_err(db)
    }

    /// A new operator with `roles` and an enrolment link, by the platform owner of
    /// `session`; `false` when the e-mail is taken.
    ///
    /// # Errors
    /// `CS-CON-0001` to `CS-CON-0004` from the session check, or a database error.
    pub async fn create_operator(
        &mut self,
        session: &[u8; 32],
        op: &NewOperator<'_>,
        roles: &[Role],
        now: OffsetDateTime,
    ) -> Result<bool> {
        let names: Vec<&str> = roles.iter().map(|r| r.as_str()).collect();
        sqlx::query_scalar("SELECT platform.create_operator($1, $2, $3, $4, $5, $6, $7)")
            .bind(session.as_slice())
            .bind(op.id)
            .bind(op.email)
            .bind(names)
            .bind(op.enrolment_sha256.as_slice())
            .bind(now)
            .bind(op.enrolment_expires)
            .fetch_one(&mut *self.tx)
            .await
            .map_err(db)
    }

    /// Enrolment step 1: store the sealed seed shown to the operator; their id, or `None`
    /// when the link is not live.
    ///
    /// # Errors
    /// A database error.
    pub async fn begin_enrolment(
        &mut self,
        token_sha256: &[u8; 32],
        seed_sealed: &[u8],
        now: OffsetDateTime,
    ) -> Result<Option<Uuid>> {
        sqlx::query_scalar("SELECT platform.begin_enrolment($1, $2, $3)")
            .bind(token_sha256.as_slice())
            .bind(seed_sealed)
            .bind(now)
            .fetch_one(&mut *self.tx)
            .await
            .map_err(db)
    }

    /// Enrolment step 2, after the console checked a code of the pending seed for `step`:
    /// set the password and the second factor, spend the link. The operator id, or `None`.
    ///
    /// # Errors
    /// A database error.
    pub async fn finish_enrolment(
        &mut self,
        token_sha256: &[u8; 32],
        password_hash: &str,
        step: u64,
        now: OffsetDateTime,
    ) -> Result<Option<Uuid>> {
        sqlx::query_scalar("SELECT platform.finish_enrolment($1, $2, $3, $4)")
            .bind(token_sha256.as_slice())
            .bind(password_hash)
            .bind(i64::try_from(step).map_err(|_| PlatformError::Invalid {
                sqlstate: "22003".into(),
            })?)
            .bind(now)
            .fetch_one(&mut *self.tx)
            .await
            .map_err(db)
    }

    /// Disable `operator` and end their sessions.
    ///
    /// # Errors
    /// As [`Self::create_operator`].
    pub async fn disable_operator(
        &mut self,
        session: &[u8; 32],
        operator: Uuid,
        now: OffsetDateTime,
    ) -> Result<bool> {
        self.call_bool(
            "SELECT platform.disable_operator($1, $2, $3)",
            session,
            |q| q.bind(operator),
            now,
        )
        .await
    }

    /// Open a session (second factor still to come); `false` when the operator cannot
    /// sign in.
    ///
    /// # Errors
    /// A database error.
    pub async fn open_session(
        &mut self,
        operator: Uuid,
        token_sha256: &[u8; 32],
        csrf_sha256: &[u8; 32],
        ip: Option<&str>,
        now: OffsetDateTime,
        expires: OffsetDateTime,
    ) -> Result<bool> {
        sqlx::query_scalar("SELECT platform.open_session($1, $2, $3, $4, $5, $6)")
            .bind(operator)
            .bind(token_sha256.as_slice())
            .bind(csrf_sha256.as_slice())
            .bind(ip)
            .bind(now)
            .bind(expires)
            .fetch_one(&mut *self.tx)
            .await
            .map_err(db)
    }

    /// Record a checked TOTP code for time step `step`; `false` when the step was
    /// already used or the session is not live.
    ///
    /// # Errors
    /// A database error.
    pub async fn confirm_mfa(
        &mut self,
        token_sha256: &[u8; 32],
        step: u64,
        now: OffsetDateTime,
    ) -> Result<bool> {
        sqlx::query_scalar("SELECT platform.confirm_mfa($1, $2, $3)")
            .bind(token_sha256.as_slice())
            .bind(i64::try_from(step).map_err(|_| PlatformError::Invalid {
                sqlstate: "22003".into(),
            })?)
            .bind(now)
            .fetch_one(&mut *self.tx)
            .await
            .map_err(db)
    }

    /// End a session.
    ///
    /// # Errors
    /// A database error.
    pub async fn revoke_session(
        &mut self,
        token_sha256: &[u8; 32],
        now: OffsetDateTime,
    ) -> Result<bool> {
        let r: Option<bool> = sqlx::query_scalar("SELECT platform.revoke_session($1, $2)")
            .bind(token_sha256.as_slice())
            .bind(now)
            .fetch_one(&mut *self.tx)
            .await
            .map_err(db)?;
        Ok(r.unwrap_or(false))
    }

    /// Rename an organization; `false` when there is none.
    ///
    /// # Errors
    /// As [`Self::create_operator`].
    pub async fn rename_organization(
        &mut self,
        session: &[u8; 32],
        org: Uuid,
        name: &str,
        now: OffsetDateTime,
    ) -> Result<bool> {
        self.call_bool(
            "SELECT platform.rename_organization($1, $2, $3, $4)",
            session,
            |q| q.bind(org).bind(name.to_owned()),
            now,
        )
        .await
    }

    /// Set an organization's data-region labels.
    ///
    /// # Errors
    /// As [`Self::create_operator`]; `CS-DB-0008` for invalid labels.
    pub async fn set_organization_regions(
        &mut self,
        session: &[u8; 32],
        org: Uuid,
        regions: &[String],
        now: OffsetDateTime,
    ) -> Result<bool> {
        let regions = regions.to_vec();
        self.call_bool(
            "SELECT platform.set_organization_regions($1, $2, $3, $4)",
            session,
            |q| q.bind(org).bind(regions),
            now,
        )
        .await
    }

    /// Set a workspace's data-region label (one of its organization's, or none).
    ///
    /// # Errors
    /// As [`Self::set_organization_regions`].
    pub async fn set_workspace_region(
        &mut self,
        session: &[u8; 32],
        workspace: Uuid,
        region: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<bool> {
        let region = region.map(str::to_owned);
        self.call_bool(
            "SELECT platform.set_workspace_region($1, $2, $3, $4)",
            session,
            |q| q.bind(workspace).bind(region),
            now,
        )
        .await
    }

    /// Archive (`archived`) or restore (`active`) a workspace.
    ///
    /// # Errors
    /// As [`Self::create_operator`].
    pub async fn set_workspace_status(
        &mut self,
        session: &[u8; 32],
        workspace: Uuid,
        status: &str,
        now: OffsetDateTime,
    ) -> Result<bool> {
        let status = status.to_owned();
        self.call_bool(
            "SELECT platform.set_workspace_status($1, $2, $3, $4)",
            session,
            |q| q.bind(workspace).bind(status),
            now,
        )
        .await
    }

    /// Ask for a two-person organization action (step 1); needs a second factor entered
    /// within 5 minutes.
    ///
    /// # Errors
    /// `CS-CON-0001` to `CS-CON-0003` from the session check, or a database error.
    pub async fn request_approval(
        &mut self,
        session: &[u8; 32],
        id: Uuid,
        action: OrgAction,
        organization: Uuid,
        now: OffsetDateTime,
    ) -> Result<Uuid> {
        sqlx::query_scalar("SELECT platform.request_approval($1, $2, $3, $4, $5)")
            .bind(session.as_slice())
            .bind(id)
            .bind(action.as_str())
            .bind(organization)
            .bind(now)
            .fetch_one(&mut *self.tx)
            .await
            .map_err(db)
    }

    /// Approve another operator's request (step 2); `false` when there is no live,
    /// unused request with that id.
    ///
    /// # Errors
    /// `CS-CON-0004` for one's own request; the session check's codes.
    pub async fn grant_approval(
        &mut self,
        session: &[u8; 32],
        request: Uuid,
        now: OffsetDateTime,
    ) -> Result<bool> {
        sqlx::query_scalar("SELECT platform.grant_approval($1, $2, $3)")
            .bind(session.as_slice())
            .bind(request)
            .bind(now)
            .fetch_one(&mut *self.tx)
            .await
            .map_err(db)
    }

    /// Apply an approved organization action (step 3); `false` when the organization
    /// is not in the state the action changes.
    ///
    /// # Errors
    /// `CS-CON-0004` without an unused approval by another operator for this action and
    /// organization; `CS-CON-0002` without a second factor in the last 5 minutes.
    pub async fn apply_org_action(
        &mut self,
        session: &[u8; 32],
        request: Uuid,
        action: OrgAction,
        organization: Uuid,
        now: OffsetDateTime,
    ) -> Result<bool> {
        let sql = match action {
            OrgAction::Suspend => "SELECT platform.apply_suspend_organization($1, $2, $3, $4)",
            OrgAction::Resume => "SELECT platform.apply_resume_organization($1, $2, $3, $4)",
        };
        sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .bind(session.as_slice())
            .bind(request)
            .bind(organization)
            .bind(now)
            .fetch_one(&mut *self.tx)
            .await
            .map_err(db)
    }

    /// Call a session-checked definer function `sql` whose parameters are the session,
    /// those `bind` adds, then `now`.
    async fn call_bool<'q, F>(
        &mut self,
        sql: &'q str,
        session: &[u8; 32],
        bind: F,
        now: OffsetDateTime,
    ) -> Result<bool>
    where
        F: FnOnce(
            sqlx::query::QueryScalar<'q, Postgres, bool, sqlx::postgres::PgArguments>,
        )
            -> sqlx::query::QueryScalar<'q, Postgres, bool, sqlx::postgres::PgArguments>,
    {
        let q = sqlx::query_scalar::<_, bool>(sqlx::AssertSqlSafe(sql)).bind(session.to_vec());
        bind(q).bind(now).fetch_one(&mut *self.tx).await.map_err(db)
    }
}

/// Set (insert or replace) a service target. Deployment configuration, not an operator
/// action: `owner` must connect as the schema owner (the migrator), since the console
/// role cannot write `platform.service_targets` (`SEC-X06`).
///
/// # Errors
/// `CS-DB-0008` for a malformed name, role, probe or target; a database error.
pub async fn set_service_target(owner: &PgPool, t: &ServiceTarget) -> Result<()> {
    sqlx::query(
        "INSERT INTO platform.service_targets (name, role, probe, target) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (name) DO UPDATE SET role = EXCLUDED.role, probe = EXCLUDED.probe, \
         target = EXCLUDED.target",
    )
    .bind(&t.name)
    .bind(&t.role)
    .bind(&t.probe)
    .bind(&t.target)
    .execute(owner)
    .await
    .map_err(db)?;
    Ok(())
}

/// Remove a service target (as [`set_service_target`]); whether one was removed.
///
/// # Errors
/// A database error.
pub async fn remove_service_target(owner: &PgPool, name: &str) -> Result<bool> {
    let r = sqlx::query("DELETE FROM platform.service_targets WHERE name = $1")
        .bind(name)
        .execute(owner)
        .await
        .map_err(db)?;
    Ok(r.rows_affected() > 0)
}
