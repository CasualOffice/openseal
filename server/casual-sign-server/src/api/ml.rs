//! Document analysis (WEB-19, ML-01; docs/33 §6, §7): the workspace's ML settings,
//! asking for and reading an analysis, and its suggestions, which a person accepts or
//! dismisses.
//!
//! - **Off by default at every level.** A feature is in effect only when the operator
//!   deployed the model service (`Config::ml_bundle`), the plan entitles the workspace
//!   (`ml_entitlements`) and its administrator turned it on (`ml_settings`). With none in
//!   effect, an upload enqueues nothing and every call here but the settings answers
//!   `403 CS-ML-0011`, which the web app reads as "hide every ML surface".
//! - **Access.** Every object is found through the principal's account, and an envelope
//!   the principal may not see is `404` before anything else (`api::envelope`). Asking
//!   for an analysis and deciding a suggestion are its sender's or an administrator's.
//! - **Suggestions only.** Nothing here changes an envelope, its audit chain or a
//!   document. Accepting records who decided and when; the ordinary action the person
//!   takes (applying the matched template, adding a field) goes through the ordinary
//!   endpoints and is recorded there (docs/33 invariant 2).
//! - **No span text is stored.** A suggestion's `value` is read from the stored
//!   document (or the stored OCR words of its page) when it is listed.

use std::collections::BTreeMap;

use axum::body::Bytes;
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::response::Response;
use casual_sign_host::ml::{self as hml, AnalysisJob, Feature};
use casual_sign_model::EnvelopeStatus as MStatus;
use casual_sign_store::blob::BlobKey;
use casual_sign_store::repo::documents::VersionKind;
use casual_sign_store::repo::ml::{
    MlSettings, NewRun, Run, RunKind, Suggestion, SuggestionFilter, SuggestionKind, SuggestionState,
};
use casual_sign_store::repo::templates::TemplateAccess;
use casual_sign_store::{
    AccountId, AnalysisRunId, DocumentId, EnvelopeId, JobId, SuggestionId, TemplateDocumentId,
    TemplateId, TenantTx,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{envelope as find, json, path_id};
use crate::api::envelopes::{doc_in, rfc3339};
use crate::apply::{Loaded, uid};
use crate::auth::Principal;
use crate::call::Call;
use crate::dto::parse;
use crate::error::ApiError;
use crate::state::AppState;

/// OCR script packs a workspace may ask for (docs/33 §5.1).
pub(crate) const OCR_SCRIPTS: [&str; 6] =
    ["latin", "cyrillic", "greek", "cjk", "arabic", "devanagari"];

/// The features in effect for the transaction's account.
pub(crate) async fn in_effect(st: &AppState, tx: &mut TenantTx) -> Result<Vec<Feature>, ApiError> {
    let installed = st.config().ml_bundle.is_some();
    if !installed {
        return Ok(Vec::new());
    }
    let settings = tx.ml().settings().await?;
    let entitlements = tx.ml().entitlements().await?;
    Ok(hml::effective(&settings, &entitlements, installed))
}

fn bundle(st: &AppState) -> Result<&str, ApiError> {
    st.config()
        .ml_bundle
        .as_deref()
        .ok_or_else(ApiError::ml_off)
}

// Settings ------------------------------------------------------------------------------

fn settings_json(s: &MlSettings, entitlements: &[String], installed: bool) -> Value {
    let not_in_plan: Vec<&str> = Feature::ALL
        .into_iter()
        .filter(|f| !hml::entitled(*f, entitlements))
        .map(Feature::name)
        .collect();
    json!({
        "ocr": s.ocr,
        "template_matching": s.template_matching,
        "extraction": s.extraction,
        "personal_data": s.personal_data,
        "personal_data_model": s.personal_data_model,
        "ocr_scripts": s.ocr_scripts,
        "reread_scanner_text": s.reread_scanner_text,
        "not_in_plan": not_in_plan,
        "installed": installed,
    })
}

/// `GET /account/settings/ml`: the workspace's switches, which features its plan lacks,
/// and whether the model service is installed. Workspace administrators only.
pub(crate) async fn settings(c: Call) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let s = tx.ml().settings().await?;
    let e = tx.ml().entitlements().await?;
    tx.commit().await?;
    Ok(json(
        StatusCode::OK,
        &settings_json(&s, &e, c.st.config().ml_bundle.is_some()),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsPatch {
    ocr: Option<bool>,
    template_matching: Option<bool>,
    extraction: Option<bool>,
    personal_data: Option<bool>,
    #[serde(default, deserialize_with = "present")]
    personal_data_model: Option<Option<String>>,
    ocr_scripts: Option<Vec<String>>,
    reread_scanner_text: Option<bool>,
}

/// A member that may be `null` (reset) as well as absent.
fn present<'de, D>(d: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Some(Option::deserialize(d)?))
}

fn model_id(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

/// `PATCH /account/settings/ml`: turn features on or off. Turning on a feature the plan
/// lacks, or any feature while the model service is not installed, is `403 CS-ML-0011`;
/// turning one off is always allowed. Answers the settings.
pub(crate) async fn patch_settings(c: Call, body: Bytes) -> Result<Response, ApiError> {
    let req: SettingsPatch = parse(&body)?;
    let mut tx = c.tx().await?;
    let mut s = tx.ml().settings().await?;
    let e = tx.ml().entitlements().await?;
    let installed = c.st.config().ml_bundle.is_some();
    for (f, v) in [
        (Feature::Ocr, req.ocr),
        (Feature::TemplateMatching, req.template_matching),
        (Feature::Extraction, req.extraction),
        (Feature::PersonalData, req.personal_data),
    ] {
        let Some(on) = v else { continue };
        if on && !installed {
            return Err(ApiError::ml_off().detail("not installed on this server"));
        }
        if on && !hml::entitled(f, &e) {
            return Err(ApiError::ml_off().detail(format!("{} is not in the plan", f.name())));
        }
        match f {
            Feature::Ocr => s.ocr = on,
            Feature::TemplateMatching => s.template_matching = on,
            Feature::Extraction => s.extraction = on,
            Feature::PersonalData => s.personal_data = on,
        }
    }
    if let Some(m) = req.personal_data_model {
        if m.as_deref().is_some_and(|m| !model_id(m)) {
            return Err(ApiError::invalid("/personal_data_model"));
        }
        s.personal_data_model = m;
    }
    if let Some(list) = req.ocr_scripts {
        let mut out: Vec<String> = Vec::new();
        for (i, x) in list.iter().enumerate() {
            if !OCR_SCRIPTS.contains(&x.as_str()) {
                return Err(ApiError::invalid(&format!("/ocr_scripts/{i}")));
            }
            if !out.contains(x) {
                out.push(x.clone());
            }
        }
        s.ocr_scripts = out;
    }
    if let Some(r) = req.reread_scanner_text {
        s.reread_scanner_text = r;
    }
    tx.ml().set_settings(&s, c.p.user, c.st.now()).await?;
    tx.commit().await?;
    Ok(json(StatusCode::OK, &settings_json(&s, &e, installed)))
}

// Analysis ------------------------------------------------------------------------------

fn run_json(r: &Run) -> Value {
    let mut v = json!({
        "id": r.id.0.to_string(),
        "document_id": r.document_id.to_string(),
        "status": r.status.as_str(),
        "uses": r.uses,
        "ocr_pages": r.ocr_pages,
        "truncated": r.truncated,
        "bundle_id": r.bundle_id,
        "created_at": rfc3339(r.created_at),
    });
    if let Some(o) = v.as_object_mut() {
        if let Some(t) = r.finished_at {
            o.insert("finished_at".into(), json!(rfc3339(t)));
        }
        if let Some(code) = &r.code {
            o.insert("code".into(), json!(code));
        }
    }
    v
}

/// Who may ask for an analysis or decide a suggestion: the envelope's sender or an
/// administrator (others who may see it read only).
fn may_change(p: &Principal, l: &Loaded) -> Result<(), ApiError> {
    if p.admin || l.state.sender_user_id.as_str() == p.user.to_string() {
        Ok(())
    } else {
        Err(ApiError::forbidden(
            "the envelope's sender or an administrator",
        ))
    }
}

/// The stored, normalized PDF's SHA-256 of an envelope document.
async fn normalized_sha(tx: &mut TenantTx, doc: Uuid) -> Result<[u8; 32], ApiError> {
    tx.documents()
        .versions(DocumentId(doc))
        .await?
        .iter()
        .rev()
        .find(|v| v.version.kind == VersionKind::Normalized)
        .map(|v| v.version.sha256)
        .ok_or_else(ApiError::not_found)
}

/// Record a run and enqueue its job, unless one with the same key exists; the run.
#[allow(clippy::too_many_arguments)] // One argument per part of the key and payload.
async fn enqueue(
    st: &AppState,
    tx: &mut TenantTx,
    account: AccountId,
    kind: &'static str,
    document: Uuid,
    owner: (Option<EnvelopeId>, Option<TemplateId>),
    sha: [u8; 32],
    uses: Vec<String>,
) -> Result<Run, ApiError> {
    let bundle = bundle(st)?;
    let key = match owner.1 {
        Some(t) => hml::fingerprint_key(account, t.0, document, &sha, bundle),
        None => hml::analyze_key(account, document, &sha, &uses, bundle),
    };
    if let Some(r) = tx.ml().run_by_key(&key).await? {
        return Ok(r);
    }
    let run = AnalysisRunId(Uuid::now_v7());
    let now = st.now();
    tx.ml()
        .insert_run(&NewRun {
            id: run,
            document_id: document,
            envelope_id: owner.0,
            template_id: owner.1,
            kind: if owner.1.is_some() {
                RunKind::FingerprintTemplate
            } else {
                RunKind::AnalyzeDocument
            },
            uses: uses.clone(),
            document_sha256: sha,
            job_key: key.clone(),
            created_at: now,
        })
        .await?;
    let payload = AnalysisJob {
        run_id: run.0,
        account_id: account.0,
        document_id: document,
        envelope_id: owner.0.map(|e| e.0),
        template_id: owner.1.map(|t| t.0),
        uses,
        document_sha256: hml::hex(&sha),
    };
    tx.jobs()
        .enqueue(&hml::analysis_job(
            JobId(Uuid::now_v7()),
            kind,
            &payload,
            key.clone(),
            now,
        ))
        .await?;
    tx.ml()
        .run_by_key(&key)
        .await?
        .ok_or_else(|| ApiError::internal("analysis run"))
}

/// In the transaction that admits an upload to a draft envelope: enqueue its analysis
/// when the workspace has any feature in effect. With none, nothing at all is written
/// (`ML-01`: no job, responses unchanged).
pub(crate) async fn on_envelope_upload(
    st: &AppState,
    tx: &mut TenantTx,
    account: AccountId,
    envelope: EnvelopeId,
    document: Uuid,
    sha: [u8; 32],
) -> Result<(), ApiError> {
    let features = in_effect(st, tx).await?;
    if features.is_empty() {
        return Ok(());
    }
    enqueue(
        st,
        tx,
        account,
        hml::ANALYZE_DOCUMENT,
        document,
        (Some(envelope), None),
        sha,
        hml::uses_of(&features),
    )
    .await?;
    Ok(())
}

/// In the transaction that adds a template document: enqueue its page hashes when
/// template matching is in effect; otherwise nothing is written.
pub(crate) async fn on_template_upload(
    st: &AppState,
    tx: &mut TenantTx,
    account: AccountId,
    template: TemplateId,
    document: TemplateDocumentId,
    sha: [u8; 32],
) -> Result<(), ApiError> {
    let features = in_effect(st, tx).await?;
    if !features.contains(&Feature::TemplateMatching) {
        return Ok(());
    }
    enqueue(
        st,
        tx,
        account,
        hml::FINGERPRINT_TEMPLATE,
        document.0,
        (None, Some(template)),
        sha,
        hml::uses_of(&[Feature::TemplateMatching]),
    )
    .await?;
    Ok(())
}

/// `POST /envelopes/{id}/documents/{doc}/analysis`: ask for the document to be analysed
/// with the features in effect (idempotent on the job key). `202 {status, uses, …}`.
pub(crate) async fn request_envelope(
    c: Call,
    Path((id, doc)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let l = find(&mut tx, &c.p, &id).await?;
    let d = uid(doc_in(&l.state, &doc)?.id())?;
    let features = in_effect(&c.st, &mut tx).await?;
    if features.is_empty() {
        return Err(ApiError::ml_off());
    }
    may_change(&c.p, &l)?;
    if l.state.status != MStatus::Draft {
        return Err(ApiError::wrong_state("a draft envelope only"));
    }
    let sha = normalized_sha(&mut tx, d).await?;
    let run = enqueue(
        &c.st,
        &mut tx,
        c.p.account,
        hml::ANALYZE_DOCUMENT,
        d,
        (Some(l.id), None),
        sha,
        hml::uses_of(&features),
    )
    .await?;
    tx.commit().await?;
    Ok(json(StatusCode::ACCEPTED, &run_json(&run)))
}

/// `GET /envelopes/{id}/documents/{doc}/analysis`: the newest analysis of the document.
pub(crate) async fn envelope_analysis(
    c: Call,
    Path((id, doc)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let l = find(&mut tx, &c.p, &id).await?;
    let d = uid(doc_in(&l.state, &doc)?.id())?;
    if in_effect(&c.st, &mut tx).await?.is_empty() {
        return Err(ApiError::ml_off());
    }
    let run = tx
        .ml()
        .latest_run(d)
        .await?
        .ok_or_else(ApiError::not_found)?;
    tx.commit().await?;
    Ok(json(StatusCode::OK, &run_json(&run)))
}

/// A template of this account the caller may act on with `need` (UXW-06), and one of
/// its documents: `(template, document, sha256)`.
async fn template_doc(
    tx: &mut TenantTx,
    c: &Call,
    need: TemplateAccess,
    id: &str,
    doc: &str,
) -> Result<(TemplateId, TemplateDocumentId, [u8; 32]), ApiError> {
    let t = TemplateId(path_id(id)?);
    crate::api::templates::found(tx, c, t, need).await?;
    let d = TemplateDocumentId(path_id(doc)?);
    let found = tx
        .templates()
        .documents(t)
        .await?
        .into_iter()
        .find(|x| x.id == d)
        .ok_or_else(ApiError::not_found)?;
    Ok((t, d, found.sha256))
}

/// `POST /templates/{id}/documents/{doc}/analysis`: the template document's page hashes,
/// for matching uploads against it (`fingerprint_template`). Needs template matching in
/// effect.
pub(crate) async fn request_template(
    c: Call,
    Path((id, doc)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let (t, d, sha) = template_doc(&mut tx, &c, TemplateAccess::Edit, &id, &doc).await?;
    if !in_effect(&c.st, &mut tx)
        .await?
        .contains(&Feature::TemplateMatching)
    {
        return Err(ApiError::ml_off());
    }
    let run = enqueue(
        &c.st,
        &mut tx,
        c.p.account,
        hml::FINGERPRINT_TEMPLATE,
        d.0,
        (None, Some(t)),
        sha,
        hml::uses_of(&[Feature::TemplateMatching]),
    )
    .await?;
    tx.commit().await?;
    Ok(json(StatusCode::ACCEPTED, &run_json(&run)))
}

/// `GET /templates/{id}/documents/{doc}/analysis`.
pub(crate) async fn template_analysis(
    c: Call,
    Path((id, doc)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let (_, d, _) = template_doc(&mut tx, &c, TemplateAccess::Use, &id, &doc).await?;
    if in_effect(&c.st, &mut tx).await?.is_empty() {
        return Err(ApiError::ml_off());
    }
    let run = tx
        .ml()
        .latest_run(d.0)
        .await?
        .ok_or_else(ApiError::not_found)?;
    tx.commit().await?;
    Ok(json(StatusCode::OK, &run_json(&run)))
}

// Suggestions ---------------------------------------------------------------------------

fn feature_of(k: SuggestionKind) -> Feature {
    match k {
        SuggestionKind::Template => Feature::TemplateMatching,
        SuggestionKind::Entity => Feature::Extraction,
        _ => Feature::PersonalData,
    }
}

fn parse_kind(s: &str) -> Option<SuggestionKind> {
    Some(match s {
        "template" => SuggestionKind::Template,
        "entity" => SuggestionKind::Entity,
        "personal_data" => SuggestionKind::PersonalData,
        _ => return None,
    })
}

fn parse_state(s: &str) -> Option<SuggestionState> {
    Some(match s {
        "open" => SuggestionState::Open,
        "accepted" => SuggestionState::Accepted,
        "dismissed" => SuggestionState::Dismissed,
        _ => return None,
    })
}

fn suggestion_json(s: &Suggestion, value: Option<&str>) -> Value {
    let mut v = json!({
        "id": s.id.0.to_string(),
        "kind": s.kind.as_str(),
        "document_id": s.document_id.to_string(),
        "page": s.page,
        "rect": s.rect,
        "label": s.label,
        "value": value,
        "normalized": s.normalized,
        "score": s.score,
        "model": {"id": s.model_id, "sha256": hml::hex(&s.weights_sha256)},
        "state": s.state.as_str(),
    });
    if let Some(o) = v.as_object_mut() {
        if let Some((t, matched, total)) = s.template {
            o.insert("template_id".into(), json!(t.0.to_string()));
            o.insert("pages_matched".into(), json!(matched));
            o.insert("pages_total".into(), json!(total));
        }
        if let Some(u) = s.decided_by {
            o.insert("decided_by".into(), json!(u.0.to_string()));
        }
        if let Some(t) = s.decided_at {
            o.insert("decided_at".into(), json!(rfc3339(t)));
        }
    }
    v
}

/// The analysed text of every page of a run's document: the text layer, or the OCR
/// words of pages read by OCR (as the worker sent them, `casual_sign_host::ml::page_text`).
async fn run_texts(
    st: &AppState,
    tx: &mut TenantTx,
    run: AnalysisRunId,
) -> Result<Vec<String>, ApiError> {
    let Some(r) = tx.ml().run(run).await? else {
        return Ok(Vec::new());
    };
    let ocr: BTreeMap<i32, Value> = tx.ml().ocr_pages(run).await?.into_iter().collect();
    let bytes = st.0.blobs.get(&BlobKey(r.document_sha256)).await?;
    let engine = st.0.engine.clone();
    let layers = tokio::task::spawn_blocking(move || engine.page_texts(&bytes))
        .await
        .map_err(|_| ApiError::internal("page text"))??;
    Ok(layers
        .iter()
        .enumerate()
        .map(|(i, l)| {
            let page = i32::try_from(i).unwrap_or(i32::MAX).saturating_add(1);
            hml::page_text(l, ocr.get(&page))
        })
        .collect())
}

/// The value of each suggestion that names a span, read from its run's stored text.
async fn values(
    st: &AppState,
    tx: &mut TenantTx,
    list: &[Suggestion],
) -> Result<Vec<Option<String>>, ApiError> {
    let mut texts: BTreeMap<AnalysisRunId, Vec<String>> = BTreeMap::new();
    let mut out = Vec::with_capacity(list.len());
    for s in list {
        let (Some((a, b)), Some(page)) = (s.span, s.page) else {
            out.push(None);
            continue;
        };
        if let std::collections::btree_map::Entry::Vacant(e) = texts.entry(s.run_id) {
            e.insert(run_texts(st, tx, s.run_id).await?);
        }
        let v = usize::try_from(page.saturating_sub(1))
            .ok()
            .and_then(|i| texts.get(&s.run_id)?.get(i))
            .and_then(|t| hml::span_text(t, a, b))
            .map(str::to_owned);
        out.push(v);
    }
    Ok(out)
}

/// Whether `s`'s document is still one of the envelope's.
fn current(l: &Loaded, s: &Suggestion) -> bool {
    l.state
        .documents
        .iter()
        .any(|d| uid(d.id()).is_ok_and(|u| u == s.document_id))
}

/// `GET /envelopes/{id}/suggestions?kind=&state=&cursor=&limit=`: the suggestions of the
/// envelope's analyses whose feature is in effect, by id, cursor-paginated (`limit` 1 to
/// 200, default 50). Each `value` is read from the stored document now.
pub(crate) async fn suggestions(
    c: Call,
    Path(id): Path<String>,
    Query(q): Query<BTreeMap<String, String>>,
) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let l = find(&mut tx, &c.p, &id).await?;
    let features = in_effect(&c.st, &mut tx).await?;
    if features.is_empty() {
        return Err(ApiError::ml_off());
    }
    let kind = match q.get("kind").map(String::as_str) {
        None | Some("") => None,
        Some(k) => Some(parse_kind(k).ok_or_else(|| ApiError::invalid("/query/kind"))?),
    };
    let state = match q.get("state").map(String::as_str) {
        None | Some("") => None,
        Some(s) => Some(parse_state(s).ok_or_else(|| ApiError::invalid("/query/state"))?),
    };
    let after = match q.get("cursor").map(String::as_str) {
        None | Some("") => None,
        Some(s) => Some(SuggestionId(
            Uuid::parse_str(s).map_err(|_| ApiError::invalid("/query/cursor"))?,
        )),
    };
    let limit = match q.get("limit").map(String::as_str) {
        None | Some("") => 50,
        Some(s) => s
            .parse::<i64>()
            .ok()
            .filter(|n| (1..=200).contains(n))
            .ok_or_else(|| ApiError::invalid("/query/limit"))?,
    };
    let mut got = tx
        .ml()
        .envelope_suggestions(
            l.id,
            SuggestionFilter { kind, state, after },
            limit.saturating_add(1),
        )
        .await?;
    let more = got.len() > usize::try_from(limit).unwrap_or(usize::MAX);
    got.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
    let next = if more {
        got.last().map(|s| s.id.0.to_string())
    } else {
        None
    };
    let shown: Vec<Suggestion> = got
        .into_iter()
        .filter(|s| features.contains(&feature_of(s.kind)) && current(&l, s))
        .collect();
    let vals = values(&c.st, &mut tx, &shown).await?;
    tx.commit().await?;
    let items: Vec<Value> = shown
        .iter()
        .zip(&vals)
        .map(|(s, v)| suggestion_json(s, v.as_deref()))
        .collect();
    Ok(json(
        StatusCode::OK,
        &json!({ "items": items, "next_cursor": next }),
    ))
}

async fn decide(
    c: Call,
    id: &str,
    sug: &str,
    state: SuggestionState,
) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let l = find(&mut tx, &c.p, id).await?;
    let features = in_effect(&c.st, &mut tx).await?;
    if features.is_empty() {
        return Err(ApiError::ml_off());
    }
    let sid = SuggestionId(path_id(sug)?);
    let s = tx
        .ml()
        .envelope_suggestion(l.id, sid)
        .await?
        .filter(|s| features.contains(&feature_of(s.kind)))
        .ok_or_else(ApiError::not_found)?;
    may_change(&c.p, &l)?;
    if s.state != SuggestionState::Open || !current(&l, &s) {
        return Err(ApiError::ml_stale());
    }
    if !tx.ml().decide(sid, state, c.p.user, c.st.now()).await? {
        return Err(ApiError::ml_stale());
    }
    let s = tx
        .ml()
        .envelope_suggestion(l.id, sid)
        .await?
        .ok_or_else(|| ApiError::internal("suggestion"))?;
    let v = values(&c.st, &mut tx, std::slice::from_ref(&s)).await?;
    tx.commit().await?;
    Ok(json(
        StatusCode::OK,
        &suggestion_json(&s, v.first().and_then(Option::as_deref)),
    ))
}

/// `POST /envelopes/{id}/suggestions/{s}/accept`: record that a person accepted it
/// (`decided_by`, `decided_at`); the action it suggests is the person's own, through the
/// ordinary endpoints. `409 CS-ML-0012` when already decided or its document left.
pub(crate) async fn accept(
    c: Call,
    Path((id, s)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    decide(c, &id, &s, SuggestionState::Accepted).await
}

/// `POST /envelopes/{id}/suggestions/{s}/dismiss`.
pub(crate) async fn dismiss(
    c: Call,
    Path((id, s)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    decide(c, &id, &s, SuggestionState::Dismissed).await
}
