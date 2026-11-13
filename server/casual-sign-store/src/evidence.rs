//! Re-verify every chain in the database at once (ASVS-14, docs/65 §Backups): each
//! envelope's audit chain, each workspace's and each organization's admin log, and the
//! document blobs they rely on. What a restore drill runs after restoring a backup into a
//! fresh stack, and what an operator runs after any restore, before reopening.
//!
//! It reads every account's rows, so it needs a role that row-level security does not
//! filter: the schema owner (the role `migrate` uses) or a superuser. Run as the
//! application role it would see nothing and "verify" an empty database, so it first
//! checks the role and refuses (`CS-DB-0015`). It only reads.

use core::fmt;

use uuid::Uuid;

use crate::blob::BlobKey;
use crate::error::{Result, StoreError, db};
use crate::ids::{AccountId, EnvelopeId, OrganizationId};
use crate::repo::opt_hash32;
use crate::store::Store;

/// Rows read per page while walking a table.
const PAGE: i64 = 1000;

/// What [`Store::verify_evidence`] checked.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EvidenceReport {
    /// Envelopes whose audit chain was rebuilt and verified.
    pub envelopes: u64,
    /// Audit events in those chains.
    pub audit_events: u64,
    /// Workspaces (accounts) whose admin log was verified.
    pub workspaces: u64,
    /// Events in those logs.
    pub admin_events: u64,
    /// Organizations whose admin log was verified.
    pub organizations: u64,
    /// Events in those logs.
    pub org_admin_events: u64,
}

/// The chain that failed to verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceSubject {
    /// An envelope's audit chain.
    Envelope {
        /// Its account.
        account: AccountId,
        /// The envelope.
        envelope: EnvelopeId,
    },
    /// A workspace's admin log.
    Workspace(AccountId),
    /// An organization's admin log.
    Organization(OrganizationId),
}

/// A failed verification: the store's error and, when one chain failed, which.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceError {
    /// The chain, when the failure is one chain's (none for a role or database failure).
    pub subject: Option<EvidenceSubject>,
    /// What went wrong (`CS-DB-0005`, `CS-DB-0014`, `CS-DB-0015`, ...).
    pub error: StoreError,
}

impl EvidenceError {
    /// The stable code (docs/20).
    #[must_use]
    pub fn code(&self) -> &'static str {
        self.error.code()
    }
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.subject {
            None => write!(f, "{}", self.error),
            Some(EvidenceSubject::Envelope { account, envelope }) => write!(
                f,
                "{} (account {}, envelope {})",
                self.error, account.0, envelope.0
            ),
            Some(EvidenceSubject::Workspace(a)) => write!(f, "{} (workspace {})", self.error, a.0),
            Some(EvidenceSubject::Organization(o)) => {
                write!(f, "{} (organization {})", self.error, o.0)
            }
        }
    }
}

impl std::error::Error for EvidenceError {}

impl From<StoreError> for EvidenceError {
    fn from(error: StoreError) -> Self {
        Self {
            subject: None,
            error,
        }
    }
}

fn count(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

impl Store {
    /// Rebuild and verify every audit chain and admin log in the database, and check
    /// each envelope's stored chain head against its rebuilt chain. Call with an
    /// owner-role store.
    ///
    /// # Errors
    ///
    /// `CS-DB-0015` when the role is filtered by row-level security; `CS-DB-0005` naming
    /// the envelope whose chain does not verify or whose stored head is not its last
    /// event; `CS-DB-0014` naming the workspace or organization whose admin log does not
    /// verify; `CS-DB-0001`, `CS-DB-0010` for the database.
    pub async fn verify_evidence(&self) -> Result<EvidenceReport, EvidenceError> {
        self.require_unfiltered_role().await?;
        let mut report = EvidenceReport::default();
        self.verify_envelopes(&mut report).await?;
        self.verify_workspaces(&mut report).await?;
        self.verify_organizations(&mut report).await?;
        Ok(report)
    }

    /// Refuse a role that row-level security filters: it would see no other account.
    async fn require_unfiltered_role(&self) -> Result<()> {
        let sees_all = sqlx::query_scalar!(
            r#"SELECT (r.rolsuper OR r.rolbypassrls
                       OR (pg_has_role(current_user, c.relowner, 'USAGE')
                           AND NOT c.relforcerowsecurity)) AS "sees_all!"
               FROM pg_roles r, pg_class c
               WHERE r.rolname = current_user AND c.oid = 'public.audit_events'::regclass"#
        )
        .fetch_optional(self.pool())
        .await
        .map_err(db)?;
        if sees_all == Some(true) {
            Ok(())
        } else {
            Err(StoreError::FilteredRole)
        }
    }

    async fn verify_envelopes(&self, report: &mut EvidenceReport) -> Result<(), EvidenceError> {
        let (mut after_account, mut after_id) = (Uuid::nil(), Uuid::nil());
        loop {
            let rows = sqlx::query!(
                "SELECT account_id, id, chain_head FROM envelopes \
                 WHERE (account_id, id) > ($1, $2) ORDER BY account_id, id LIMIT $3",
                after_account,
                after_id,
                PAGE
            )
            .fetch_all(self.pool())
            .await
            .map_err(db)?;
            let Some(last) = rows.last() else {
                return Ok(());
            };
            (after_account, after_id) = (last.account_id, last.id);
            for row in rows {
                let (account, envelope) = (AccountId(row.account_id), EnvelopeId(row.id));
                let subject = EvidenceSubject::Envelope { account, envelope };
                let at = |error: StoreError| EvidenceError {
                    subject: Some(subject),
                    error,
                };
                let stored_head = opt_hash32(row.chain_head, "chain_head").map_err(at)?;
                let mut tx = self.for_account(account).begin().await.map_err(at)?;
                let chain = tx.audit().chain(envelope).await.map_err(at)?;
                tx.rollback().await.map_err(at)?;
                let head = chain.head().map(|h| *h.as_bytes());
                if head != stored_head {
                    let seq = count(chain.len()).saturating_sub(1);
                    return Err(at(StoreError::ChainBroken { seq }));
                }
                report.envelopes = report.envelopes.saturating_add(1);
                report.audit_events = report.audit_events.saturating_add(count(chain.len()));
            }
        }
    }

    async fn verify_workspaces(&self, report: &mut EvidenceReport) -> Result<(), EvidenceError> {
        let mut after = Uuid::nil();
        loop {
            let ids = sqlx::query_scalar!(
                "SELECT id FROM accounts WHERE id > $1 ORDER BY id LIMIT $2",
                after,
                PAGE
            )
            .fetch_all(self.pool())
            .await
            .map_err(db)?;
            let Some(last) = ids.last() else {
                return Ok(());
            };
            after = *last;
            for id in ids {
                let account = AccountId(id);
                let at = |error: StoreError| EvidenceError {
                    subject: Some(EvidenceSubject::Workspace(account)),
                    error,
                };
                let mut tx = self.for_account(account).begin().await.map_err(at)?;
                let log = tx.verified_admin_log().await.map_err(at)?;
                tx.rollback().await.map_err(at)?;
                report.workspaces = report.workspaces.saturating_add(1);
                report.admin_events = report.admin_events.saturating_add(count(log.len()));
            }
        }
    }

    async fn verify_organizations(&self, report: &mut EvidenceReport) -> Result<(), EvidenceError> {
        let mut after = Uuid::nil();
        loop {
            let ids = sqlx::query_scalar!(
                "SELECT id FROM organizations WHERE id > $1 ORDER BY id LIMIT $2",
                after,
                PAGE
            )
            .fetch_all(self.pool())
            .await
            .map_err(db)?;
            let Some(last) = ids.last() else {
                return Ok(());
            };
            after = *last;
            for id in ids {
                let org = OrganizationId(id);
                let at = |error: StoreError| EvidenceError {
                    subject: Some(EvidenceSubject::Organization(org)),
                    error,
                };
                let mut tx = self.for_organization(org).begin().await.map_err(at)?;
                let log = tx.verified_admin_log().await.map_err(at)?;
                tx.rollback().await.map_err(at)?;
                report.organizations = report.organizations.saturating_add(1);
                report.org_admin_events = report.org_admin_events.saturating_add(count(log.len()));
            }
        }
    }

    /// Every blob key the evidence names, each once, ascending, with the subset that
    /// are signature captures: what a restored blob store must hold. An uploaded
    /// signature's image is named only inside its capture (`casual-sign-host`'s
    /// `capture::parse`), so the caller reads each capture for it. Call with an
    /// owner-role store.
    ///
    /// # Errors
    ///
    /// `CS-DB-0015` when the role is filtered by row-level security; `CS-DB-0010` for a
    /// stored key that is not 64 hexadecimal digits; `CS-DB-0001`.
    pub async fn evidence_blob_keys(&self) -> Result<EvidenceBlobKeys> {
        self.require_unfiltered_role().await?;
        let named = sqlx::query_scalar::<_, String>(EVIDENCE_BLOB_KEYS_SQL)
            .fetch_all(self.pool())
            .await
            .map_err(db)?;
        let captures = sqlx::query_scalar::<_, String>(CAPTURE_BLOB_KEYS_SQL)
            .fetch_all(self.pool())
            .await
            .map_err(db)?;
        Ok(EvidenceBlobKeys {
            named: parse_keys(named)?,
            captures: parse_keys(captures)?,
        })
    }
}

fn parse_keys(hex: Vec<String>) -> Result<Vec<BlobKey>> {
    hex.iter()
        .map(|h| BlobKey::parse(h).map_err(|_| StoreError::Corrupt { column: "blob key" }))
        .collect()
}

/// The blob keys the evidence names (ASVS-14), as lower-case hexadecimal, each once,
/// ascending: the documents' versions (uploaded, delivered, flattened, sealed), the
/// template documents, each envelope's certificate of completion, each adopted
/// signature's capture, each brand's logo, and each attachment a signer uploaded (named
/// only in the envelope's workflow state, `fields[*].value.attachment`). The backup tool
/// runs this same text in its dump's snapshot (tools/backup/openseal_backup.py, whose
/// tests check the two are identical).
pub const EVIDENCE_BLOB_KEYS_SQL: &str = r#"SELECT DISTINCT encode(k, 'hex') FROM (
    SELECT sha256 AS k FROM document_versions
    UNION ALL SELECT sha256 FROM template_documents
    UNION ALL SELECT certificate_sha256 FROM envelopes WHERE certificate_sha256 IS NOT NULL
    UNION ALL SELECT image_sha256 FROM signature_adoptions
    UNION ALL SELECT logo_sha256 FROM brands WHERE logo_sha256 IS NOT NULL
    UNION ALL SELECT decode(a #>> '{}', 'hex') FROM envelope_states,
        jsonb_path_query(state, '$.fields[*].value.attachment') AS a
        WHERE jsonb_typeof(a) = 'string' AND (a #>> '{}') ~ '^[0-9a-f]{64}$'
) AS keys ORDER BY 1"#;

/// The signature captures among [`EVIDENCE_BLOB_KEYS_SQL`]'s keys: drawn, typed, or
/// naming the image the signer uploaded.
pub const CAPTURE_BLOB_KEYS_SQL: &str =
    "SELECT DISTINCT encode(image_sha256, 'hex') FROM signature_adoptions ORDER BY 1";

/// What [`Store::evidence_blob_keys`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvidenceBlobKeys {
    /// Every key the database names, ascending.
    pub named: Vec<BlobKey>,
    /// The signature captures among them, ascending.
    pub captures: Vec<BlobKey>,
}
