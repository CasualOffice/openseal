//! Document analysis, this account's side (WEB-19, ML-01; docs/33 §2, §6, §7, §13,
//! migration 0021): the workspace's switches and entitlements, analysis runs, their
//! suggestions, OCR words and template page hashes.
//!
//! Everything here is advisory and outside the evidence: nothing in this module touches
//! an envelope's state, its audit chain or a document version (docs/33 invariant 2).

use time::OffsetDateTime;
use uuid::Uuid;

use super::{affected, hash32, text_enum};
use crate::error::{Result, StoreError, db};
use crate::ids::{AnalysisRunId, EnvelopeId, SuggestionId, TemplateDocumentId, TemplateId, UserId};
use crate::store::TenantTx;

/// The most template page hashes one account's search reads (docs/33 §4: 50,000 page
/// vectors in process).
pub const MAX_FINGERPRINTS: i64 = 50_000;

/// A workspace's switches (docs/33 §6 settings), as stored. Every feature is off unless
/// its administrator turned it on.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MlSettings {
    /// OCR of scanned and image-only pages.
    pub ocr: bool,
    /// Matching uploads against the account's templates.
    pub template_matching: bool,
    /// Agreement details (parties, dates, amounts).
    pub extraction: bool,
    /// Personal data found for redaction and retention.
    pub personal_data: bool,
    /// The personal-data model profile asked for, or the default.
    pub personal_data_model: Option<String>,
    /// OCR script packs besides the default recogniser.
    pub ocr_scripts: Vec<String>,
    /// Read again pages whose only text is a scanner's invisible OCR layer.
    pub reread_scanner_text: bool,
}

text_enum!(
    /// What a run is.
    RunKind {
        /// A draft envelope's document.
        AnalyzeDocument = "analyze_document",
        /// A template's document.
        FingerprintTemplate = "fingerprint_template",
    }
);

text_enum!(
    /// Where a run is.
    RunStatus {
        /// Enqueued.
        Queued = "queued",
        /// A worker holds it.
        Running = "running",
        /// Finished; its suggestions are written.
        Done = "done",
        /// Failed for good; no suggestions.
        Failed = "failed",
        /// No model service was configured to run it.
        Unavailable = "unavailable",
    }
);

text_enum!(
    /// What a suggestion is.
    SuggestionKind {
        /// The upload looks like one of the account's templates.
        Template = "template",
        /// An agreement detail (party, date, amount, ...).
        Entity = "entity",
        /// Personal data.
        PersonalData = "personal_data",
    }
);

text_enum!(
    /// What a person decided about a suggestion.
    SuggestionState {
        /// Not decided.
        Open = "open",
        /// Accepted: its ordinary action was taken.
        Accepted = "accepted",
        /// Dismissed.
        Dismissed = "dismissed",
    }
);

/// A run to record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRun {
    /// Host-minted id.
    pub id: AnalysisRunId,
    /// The document analysed (`documents.id` or `template_documents.id`).
    pub document_id: Uuid,
    /// Its draft envelope, for `AnalyzeDocument`.
    pub envelope_id: Option<EnvelopeId>,
    /// Its template, for `FingerprintTemplate`.
    pub template_id: Option<TemplateId>,
    /// Which.
    pub kind: RunKind,
    /// `ocr`, `template`, `entities`, `personal_data`, in that order.
    pub uses: Vec<String>,
    /// The stored, normalized PDF's SHA-256 (its blob key).
    pub document_sha256: [u8; 32],
    /// The job's idempotency key (`SEC-I06`: names the account and the document).
    pub job_key: String,
    /// When.
    pub created_at: OffsetDateTime,
}

/// A run as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    /// Its id.
    pub id: AnalysisRunId,
    /// The document analysed.
    pub document_id: Uuid,
    /// Its envelope, if any.
    pub envelope_id: Option<EnvelopeId>,
    /// Its template, if any.
    pub template_id: Option<TemplateId>,
    /// Which.
    pub kind: RunKind,
    /// What it reads for.
    pub uses: Vec<String>,
    /// The document's SHA-256.
    pub document_sha256: [u8; 32],
    /// The job's idempotency key.
    pub job_key: String,
    /// Where it is.
    pub status: RunStatus,
    /// The model bundle that ran it.
    pub bundle_id: Option<String>,
    /// The inference runtime's version.
    pub ort_version: Option<String>,
    /// 1-based pages read by OCR.
    pub ocr_pages: Vec<i32>,
    /// Whether a bound cut it short.
    pub truncated: bool,
    /// Why it failed.
    pub code: Option<String>,
    /// When it was asked for.
    pub created_at: OffsetDateTime,
    /// When it ended.
    pub finished_at: Option<OffsetDateTime>,
}

/// How a run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunEnd {
    /// `Done`, `Failed` or `Unavailable`.
    pub status: RunStatus,
    /// The bundle that ran it.
    pub bundle_id: Option<String>,
    /// The runtime's version.
    pub ort_version: Option<String>,
    /// 1-based pages read by OCR.
    pub ocr_pages: Vec<i32>,
    /// Whether a bound cut it short.
    pub truncated: bool,
    /// Why it failed.
    pub code: Option<String>,
    /// When.
    pub at: OffsetDateTime,
}

/// A suggestion to record.
#[derive(Debug, Clone, PartialEq)]
pub struct NewSuggestion {
    /// Host-minted id.
    pub id: SuggestionId,
    /// What.
    pub kind: SuggestionKind,
    /// 1-based page, when it has one.
    pub page: Option<i32>,
    /// `{x, y, width, height}` in displayed points, when known.
    pub rect: Option<serde_json::Value>,
    /// What it is ("Start date", "Email address", the template's name, ...).
    pub label: String,
    /// UTF-8 byte offsets into the page's analysed text.
    pub span: Option<(i32, i32)>,
    /// A normalized value (an ISO date, an amount), when the rules made one.
    pub normalized: Option<String>,
    /// The template a `Template` suggestion names, with pages matched and its pages.
    pub template: Option<(TemplateId, i32, i32)>,
    /// From 0 to 1.
    pub score: f32,
    /// The model that made it (manifest id).
    pub model_id: String,
    /// Its weights' SHA-256.
    pub weights_sha256: [u8; 32],
}

/// A suggestion as stored, with its run's document.
#[derive(Debug, Clone, PartialEq)]
pub struct Suggestion {
    /// Its id.
    pub id: SuggestionId,
    /// Its run.
    pub run_id: AnalysisRunId,
    /// The document.
    pub document_id: Uuid,
    /// What.
    pub kind: SuggestionKind,
    /// 1-based page.
    pub page: Option<i32>,
    /// Where on it.
    pub rect: Option<serde_json::Value>,
    /// What it is.
    pub label: String,
    /// UTF-8 byte offsets into the page's analysed text.
    pub span: Option<(i32, i32)>,
    /// A normalized value.
    pub normalized: Option<String>,
    /// The template, pages matched and its pages, for a `Template` suggestion.
    pub template: Option<(TemplateId, Option<i32>, Option<i32>)>,
    /// From 0 to 1.
    pub score: f32,
    /// The model.
    pub model_id: String,
    /// Its weights' SHA-256.
    pub weights_sha256: [u8; 32],
    /// What was decided.
    pub state: SuggestionState,
    /// Who decided.
    pub decided_by: Option<UserId>,
    /// When.
    pub decided_at: Option<OffsetDateTime>,
}

/// A template page's hashes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    /// The template.
    pub template_id: TemplateId,
    /// Its document.
    pub document_id: TemplateDocumentId,
    /// 1-based page.
    pub page: i32,
    /// Difference hash.
    pub dhash: i64,
    /// DCT perceptual hash.
    pub phash: i64,
    /// The hashing method's id.
    pub model_id: String,
    /// Its SHA-256.
    pub weights_sha256: [u8; 32],
}

/// Filters of [`Ml::envelope_suggestions`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SuggestionFilter {
    /// Only this kind.
    pub kind: Option<SuggestionKind>,
    /// Only this state.
    pub state: Option<SuggestionState>,
    /// After this id (the cursor).
    pub after: Option<SuggestionId>,
}

/// Document analysis for this account. Reached through `TenantTx::ml`.
#[derive(Debug)]
pub struct Ml<'t> {
    pub(crate) tx: &'t mut TenantTx,
}

fn status(s: &str) -> Result<RunStatus> {
    RunStatus::parse(s, "analysis_runs.status")
}

impl Ml<'_> {
    /// The workspace's switches; every feature off when none were ever set.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn settings(&mut self) -> Result<MlSettings> {
        let acct = self.tx.acct();
        let row = sqlx::query!(
            "SELECT ocr, template_matching, extraction, personal_data, personal_data_model, \
             ocr_scripts, reread_scanner_text FROM ml_settings WHERE account_id = $1",
            acct
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(row.map_or_else(MlSettings::default, |r| MlSettings {
            ocr: r.ocr,
            template_matching: r.template_matching,
            extraction: r.extraction,
            personal_data: r.personal_data,
            personal_data_model: r.personal_data_model,
            ocr_scripts: r.ocr_scripts,
            reread_scanner_text: r.reread_scanner_text,
        }))
    }

    /// Store the workspace's switches, as `by` set them.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` for an unknown script or a malformed model id.
    pub async fn set_settings(
        &mut self,
        s: &MlSettings,
        by: UserId,
        now: OffsetDateTime,
    ) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "INSERT INTO ml_settings (account_id, ocr, template_matching, extraction, personal_data, \
               personal_data_model, ocr_scripts, reread_scanner_text, updated_at, updated_by) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (account_id) DO UPDATE SET ocr = EXCLUDED.ocr, \
               template_matching = EXCLUDED.template_matching, extraction = EXCLUDED.extraction, \
               personal_data = EXCLUDED.personal_data, \
               personal_data_model = EXCLUDED.personal_data_model, \
               ocr_scripts = EXCLUDED.ocr_scripts, \
               reread_scanner_text = EXCLUDED.reread_scanner_text, \
               updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by",
            acct,
            s.ocr,
            s.template_matching,
            s.extraction,
            s.personal_data,
            s.personal_data_model.as_deref(),
            &s.ocr_scripts,
            s.reread_scanner_text,
            now,
            by.0
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// The `ml.*` entitlements the workspace's plan grants; none without a row.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn entitlements(&mut self) -> Result<Vec<String>> {
        let acct = self.tx.acct();
        let row = sqlx::query_scalar!(
            "SELECT features FROM ml_entitlements WHERE account_id = $1",
            acct
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(row.unwrap_or_default())
    }

    /// Record a run unless one with its job key exists; returns whether this call did.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` an envelope or template of another account, or a malformed row.
    pub async fn insert_run(&mut self, r: &NewRun) -> Result<bool> {
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "INSERT INTO analysis_runs (id, account_id, document_id, envelope_id, template_id, kind, \
               uses, document_sha256, job_key, created_at) \
             VALUES ($2, $1, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (account_id, job_key) DO NOTHING",
            acct,
            r.id.0,
            r.document_id,
            r.envelope_id.map(|e| e.0),
            r.template_id.map(|t| t.0),
            r.kind.as_str(),
            &r.uses,
            r.document_sha256.as_slice(),
            r.job_key,
            r.created_at
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(done.rows_affected() == 1)
    }

    /// The run with this job key.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0010` a stored value that does not read back.
    pub async fn run_by_key(&mut self, key: &str) -> Result<Option<Run>> {
        let acct = self.tx.acct();
        let id = sqlx::query_scalar!(
            "SELECT id FROM analysis_runs WHERE account_id = $1 AND job_key = $2",
            acct,
            key
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        match id {
            Some(id) => self.run(AnalysisRunId(id)).await,
            None => Ok(None),
        }
    }

    /// The newest run of `document` (`documents.id` or `template_documents.id`).
    ///
    /// # Errors
    ///
    /// As [`Ml::run`].
    pub async fn latest_run(&mut self, document: Uuid) -> Result<Option<Run>> {
        let acct = self.tx.acct();
        let id = sqlx::query_scalar!(
            "SELECT id FROM analysis_runs WHERE account_id = $1 AND document_id = $2 \
             ORDER BY created_at DESC, id DESC LIMIT 1",
            acct,
            document
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?;
        match id {
            Some(id) => self.run(AnalysisRunId(id)).await,
            None => Ok(None),
        }
    }

    /// A run of this account.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0010` a stored value that does not read back.
    pub async fn run(&mut self, id: AnalysisRunId) -> Result<Option<Run>> {
        let acct = self.tx.acct();
        let Some(r) = sqlx::query!(
            "SELECT id, document_id, envelope_id, template_id, kind, uses, document_sha256, job_key, \
               status, bundle_id, ort_version, ocr_pages, truncated, code, created_at, finished_at \
             FROM analysis_runs WHERE account_id = $1 AND id = $2",
            acct,
            id.0
        )
        .fetch_optional(self.tx.conn())
        .await
        .map_err(db)?
        else {
            return Ok(None);
        };
        Ok(Some(Run {
            id: AnalysisRunId(r.id),
            document_id: r.document_id,
            envelope_id: r.envelope_id.map(EnvelopeId),
            template_id: r.template_id.map(TemplateId),
            kind: RunKind::parse(&r.kind, "analysis_runs.kind")?,
            uses: r.uses,
            document_sha256: hash32(r.document_sha256, "analysis_runs.document_sha256")?,
            job_key: r.job_key,
            status: status(&r.status)?,
            bundle_id: r.bundle_id,
            ort_version: r.ort_version,
            ocr_pages: r.ocr_pages,
            truncated: r.truncated,
            code: r.code,
            created_at: r.created_at,
            finished_at: r.finished_at,
        }))
    }

    /// Mark a queued run as running (a worker holds it). A run already ended is left.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn start_run(&mut self, id: AnalysisRunId) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "UPDATE analysis_runs SET status = 'running' \
             WHERE account_id = $1 AND id = $2 AND status IN ('queued', 'running')",
            acct,
            id.0
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// End a run that has not ended.
    ///
    /// # Errors
    ///
    /// `CS-DB-0003` when this account has no such open run; `CS-DB-0008` a malformed value.
    pub async fn finish_run(&mut self, id: AnalysisRunId, end: &RunEnd) -> Result<()> {
        if matches!(end.status, RunStatus::Queued | RunStatus::Running) {
            return Err(StoreError::Constraint {
                constraint: None,
                sqlstate: "23514".into(),
            });
        }
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE analysis_runs SET status = $3, bundle_id = $4, ort_version = $5, ocr_pages = $6, \
               truncated = $7, code = $8, finished_at = $9 \
             WHERE account_id = $1 AND id = $2 AND status IN ('queued', 'running')",
            acct,
            id.0,
            end.status.as_str(),
            end.bundle_id.as_deref(),
            end.ort_version.as_deref(),
            &end.ocr_pages,
            end.truncated,
            end.code.as_deref(),
            end.at
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        affected(done.rows_affected(), "analysis run")
    }

    /// Record a run's suggestions.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` a run or template of another account, or a malformed row.
    pub async fn add_suggestions(
        &mut self,
        run: AnalysisRunId,
        document: Uuid,
        list: &[NewSuggestion],
    ) -> Result<()> {
        let acct = self.tx.acct();
        for s in list {
            sqlx::query!(
                "INSERT INTO suggestions (id, account_id, run_id, document_id, kind, page, rect, label, \
                   span_start, span_end, normalized, template_id, pages_matched, pages_total, score, \
                   model_id, weights_sha256) \
                 VALUES ($2, $1, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)",
                acct,
                s.id.0,
                run.0,
                document,
                s.kind.as_str(),
                s.page,
                s.rect.as_ref(),
                s.label,
                s.span.map(|x| x.0),
                s.span.map(|x| x.1),
                s.normalized.as_deref(),
                s.template.map(|t| t.0.0),
                s.template.map(|t| t.1),
                s.template.map(|t| t.2),
                s.score,
                s.model_id,
                s.weights_sha256.as_slice()
            )
            .execute(self.tx.conn())
            .await
            .map_err(db)?;
        }
        Ok(())
    }

    /// Suggestions of the runs of `envelope`, by id, at most `limit` (1 to 200).
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0010` a stored value that does not read back.
    pub async fn envelope_suggestions(
        &mut self,
        envelope: EnvelopeId,
        filter: SuggestionFilter,
        limit: i64,
    ) -> Result<Vec<Suggestion>> {
        self.select(envelope, filter, None, limit).await
    }

    /// One suggestion of `envelope`'s runs.
    ///
    /// # Errors
    ///
    /// As [`Ml::envelope_suggestions`].
    pub async fn envelope_suggestion(
        &mut self,
        envelope: EnvelopeId,
        id: SuggestionId,
    ) -> Result<Option<Suggestion>> {
        Ok(self
            .select(envelope, SuggestionFilter::default(), Some(id), 1)
            .await?
            .into_iter()
            .next())
    }

    async fn select(
        &mut self,
        envelope: EnvelopeId,
        filter: SuggestionFilter,
        only: Option<SuggestionId>,
        limit: i64,
    ) -> Result<Vec<Suggestion>> {
        let acct = self.tx.acct();
        let rows = sqlx::query!(
            "SELECT s.id, s.run_id, s.document_id, s.kind, s.page, s.rect, s.label, s.span_start, \
               s.span_end, s.normalized, s.template_id, s.pages_matched, s.pages_total, s.score, \
               s.model_id, s.weights_sha256, s.state, s.decided_by, s.decided_at \
             FROM suggestions s JOIN analysis_runs r ON r.account_id = s.account_id AND r.id = s.run_id \
             WHERE s.account_id = $1 AND r.envelope_id = $2 \
               AND ($3::text IS NULL OR s.kind = $3) AND ($4::text IS NULL OR s.state = $4) \
               AND ($5::uuid IS NULL OR s.id > $5) AND ($6::uuid IS NULL OR s.id = $6) \
             ORDER BY s.id LIMIT $7",
            acct,
            envelope.0,
            filter.kind.map(SuggestionKind::as_str),
            filter.state.map(SuggestionState::as_str),
            filter.after.map(|a| a.0),
            only.map(|o| o.0),
            limit.clamp(1, 200)
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        rows.into_iter()
            .map(|r| {
                Ok(Suggestion {
                    id: SuggestionId(r.id),
                    run_id: AnalysisRunId(r.run_id),
                    document_id: r.document_id,
                    kind: SuggestionKind::parse(&r.kind, "suggestions.kind")?,
                    page: r.page,
                    rect: r.rect,
                    label: r.label,
                    span: r.span_start.zip(r.span_end),
                    normalized: r.normalized,
                    template: r
                        .template_id
                        .map(|t| (TemplateId(t), r.pages_matched, r.pages_total)),
                    score: r.score,
                    model_id: r.model_id,
                    weights_sha256: hash32(r.weights_sha256, "suggestions.weights_sha256")?,
                    state: SuggestionState::parse(&r.state, "suggestions.state")?,
                    decided_by: r.decided_by.map(UserId),
                    decided_at: r.decided_at,
                })
            })
            .collect()
    }

    /// Decide an open suggestion; returns whether it was open (and is now decided).
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` when `state` is `Open` or `by` is not a user.
    pub async fn decide(
        &mut self,
        id: SuggestionId,
        state: SuggestionState,
        by: UserId,
        now: OffsetDateTime,
    ) -> Result<bool> {
        if state == SuggestionState::Open {
            return Err(StoreError::Constraint {
                constraint: None,
                sqlstate: "23514".into(),
            });
        }
        let acct = self.tx.acct();
        let done = sqlx::query!(
            "UPDATE suggestions SET state = $3, decided_by = $4, decided_at = $5 \
             WHERE account_id = $1 AND id = $2 AND state = 'open'",
            acct,
            id.0,
            state.as_str(),
            by.0,
            now
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(done.rows_affected() == 1)
    }

    /// Store the OCR words of one page a run read.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` a run of another account; `CS-DB-0006` the page stored twice.
    pub async fn put_ocr_page(
        &mut self,
        run: AnalysisRunId,
        page: i32,
        words: &serde_json::Value,
    ) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "INSERT INTO ocr_pages (account_id, run_id, page, words) VALUES ($1, $2, $3, $4)",
            acct,
            run.0,
            page,
            words
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// The OCR words a run stored, by 1-based page.
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn ocr_pages(&mut self, run: AnalysisRunId) -> Result<Vec<(i32, serde_json::Value)>> {
        let acct = self.tx.acct();
        let rows = sqlx::query!(
            "SELECT page, words FROM ocr_pages WHERE account_id = $1 AND run_id = $2 ORDER BY page",
            acct,
            run.0
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(rows.into_iter().map(|r| (r.page, r.words)).collect())
    }

    /// Replace the page hashes of one template document.
    ///
    /// # Errors
    ///
    /// `CS-DB-0008` a template of another account or a malformed row.
    pub async fn put_fingerprints(
        &mut self,
        template: TemplateId,
        document: TemplateDocumentId,
        pages: &[Fingerprint],
    ) -> Result<()> {
        self.forget_template_document(template, document).await?;
        let acct = self.tx.acct();
        for f in pages {
            sqlx::query!(
                "INSERT INTO template_fingerprints (account_id, template_id, document_id, page, \
                   dhash, phash, model_id, weights_sha256) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                acct,
                template.0,
                document.0,
                f.page,
                f.dhash,
                f.phash,
                f.model_id,
                f.weights_sha256.as_slice()
            )
            .execute(self.tx.conn())
            .await
            .map_err(db)?;
        }
        Ok(())
    }

    /// Drop the page hashes of a template document (it was removed or replaced).
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`.
    pub async fn forget_template_document(
        &mut self,
        template: TemplateId,
        document: TemplateDocumentId,
    ) -> Result<()> {
        let acct = self.tx.acct();
        sqlx::query!(
            "DELETE FROM template_fingerprints WHERE account_id = $1 AND template_id = $2 \
             AND document_id = $3",
            acct,
            template.0,
            document.0
        )
        .execute(self.tx.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// Every template page hash of this account, at most [`MAX_FINGERPRINTS`].
    ///
    /// # Errors
    ///
    /// `CS-DB-0001`; `CS-DB-0010` a stored value that does not read back.
    pub async fn fingerprints(&mut self) -> Result<Vec<Fingerprint>> {
        let acct = self.tx.acct();
        let rows = sqlx::query!(
            "SELECT template_id, document_id, page, dhash, phash, model_id, weights_sha256 \
             FROM template_fingerprints WHERE account_id = $1 \
             ORDER BY template_id, document_id, page LIMIT $2",
            acct,
            MAX_FINGERPRINTS
        )
        .fetch_all(self.tx.conn())
        .await
        .map_err(db)?;
        rows.into_iter()
            .map(|r| {
                Ok(Fingerprint {
                    template_id: TemplateId(r.template_id),
                    document_id: TemplateDocumentId(r.document_id),
                    page: r.page,
                    dhash: r.dhash,
                    phash: r.phash,
                    model_id: r.model_id,
                    weights_sha256: hash32(
                        r.weights_sha256,
                        "template_fingerprints.weights_sha256",
                    )?,
                })
            })
            .collect()
    }
}
