//! Envelopes and everything inside one (docs/40 §3): documents, recipients, fields,
//! send, correct, void, resend, status, audit events, downloads and the embedded
//! signing view. Every change is a workflow command (docs/24 §1) run by
//! the command pipeline (`apply`).

use std::collections::BTreeMap;

use axum::body::Bytes;
use axum::extract::{Path, Query};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use casual_sign_audit::{Hash256, Personal};
use casual_sign_model::{EnvelopeStatus as MStatus, Id};
use casual_sign_sdk::{AdmissionReport, Credentials, NormalizationReport};
use casual_sign_store::repo::documents::{Document, NewVersion, VersionKind};
use casual_sign_store::repo::envelopes::{
    After, AfterKey, DateField, EnvelopeStatus, FolderFilter, ListFilter, Listed, Sort, SortKey,
    never_expires, status_rank,
};
use casual_sign_store::repo::recipients::{NewToken, TokenPurpose};
use casual_sign_store::{
    DocumentId, DocumentVersionId, EnvelopeId, FolderId, Meter, RecipientId, RecipientTokenId,
    TenantTx, UserId,
};
use casual_sign_workflow::{
    Access, Change, Command, DocumentSpec, EnvelopeState, Principal as WfPrincipal,
};
use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{envelope as find, json, json_tagged, path_id, same_id, staff};
use crate::apply::{Commands, Loaded, create as create_env, eid, run, uid};
use crate::call::Call;
use crate::crypto::{hash_password, random_secret, sha256};
use crate::dto::{self, DocumentIn, EnvelopeCreate, EnvelopePatch, RecipientIn, parse};
use crate::error::ApiError;
use crate::http::SecretBearing;
use crate::state::AppState;

// Helpers -------------------------------------------------------------------------------

/// The expected version from `If-Match`; `required` answers `428` when absent.
fn expected(c: &Call, required: bool) -> Result<Option<u64>, ApiError> {
    match dto::if_match(&c.headers) {
        Some(v) => v.map(Some),
        None if required => Err(ApiError::precondition_required()),
        None => Ok(None),
    }
}

/// Run one staff command on a loaded envelope.
async fn command(
    c: &Call,
    tx: &mut TenantTx,
    cmds: &mut Commands,
    l: &mut Loaded,
    cmd: Command,
    expected: Option<u64>,
) -> Result<(), ApiError> {
    let ctx = cmds.ctx(staff(&c.p, &l.state)?, expected)?;
    run(tx, l, &cmd, &ctx).await?;
    Ok(())
}

/// Edit a draft, or correct a sent envelope, with `changes`.
async fn change(
    c: &Call,
    tx: &mut TenantTx,
    l: &mut Loaded,
    changes: Vec<Change>,
    expected: Option<u64>,
) -> Result<(), ApiError> {
    let mut cmds = c.commands(tx).await?;
    let cmd = if l.state.status == MStatus::Draft {
        Command::Edit { changes }
    } else {
        Command::Correct { changes }
    };
    command(c, tx, &mut cmds, l, cmd, expected).await
}

fn envelope_response(status: StatusCode, s: &EnvelopeState) -> Response {
    json_tagged(status, &dto::envelope(s), &dto::etag(s))
}

fn new_id() -> Result<Id, ApiError> {
    eid(Uuid::now_v7())
}

/// Bytes from base64, at most `max` decoded.
pub(crate) fn base64(s: &str, max: usize, at: &str) -> Result<Vec<u8>, ApiError> {
    if s.len().div_ceil(4) > max.div_ceil(3).saturating_add(1) {
        return Err(ApiError::too_large());
    }
    let b = STANDARD.decode(s).map_err(|_| ApiError::invalid(at))?;
    if b.len() > max {
        return Err(ApiError::too_large());
    }
    Ok(b)
}

fn admission_json(a: &AdmissionReport, n: Option<&NormalizationReport>) -> (Value, u32) {
    let removed: Vec<&str> = n
        .map(|n| n.removed.iter().map(|r| r.code).collect())
        .unwrap_or_default();
    let findings = u32::try_from(removed.len()).unwrap_or(u32::MAX);
    (
        json!({
            "page_count": a.page_count,
            "repaired": a.repaired,
            "signed": a.is_signed(),
            "docmdp": a.docmdp,
            "actions": a.actions.len(),
            "embedded_files": a.embedded_files.len(),
            "rich_media": a.rich_media.len(),
            "external_streams": a.external_streams.len(),
            "xfa": a.has_xfa,
            "optional_content": a.has_optional_content,
            "encrypted": a.encryption.is_some(),
            "form_fields": a.fields.len(),
            "removed": removed,
            "normalized": n.is_some(),
        }),
        findings,
    )
}

pub(crate) fn pages_json(a: &AdmissionReport) -> Value {
    Value::Array(
        a.pages
            .iter()
            .map(|p| {
                json!({
                    "width": p.crop_box.urx - p.crop_box.llx,
                    "height": p.crop_box.ury - p.crop_box.lly,
                    "rotate": p.rotate,
                })
            })
            .collect(),
    )
}

/// Admit and normalize an upload (docs/30 §2, §3), store the original and the
/// delivered bytes, and record the document's rows. Signed input is kept as it is.
async fn add_document(
    st: &AppState,
    tx: &mut TenantTx,
    env: EnvelopeId,
    name: &str,
    bytes: Vec<u8>,
) -> Result<DocumentSpec, ApiError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 255 {
        return Err(ApiError::invalid("/name"));
    }
    if bytes.len() > st.config().max_document_bytes {
        return Err(ApiError::too_large());
    }
    let engine = st.0.engine.clone();
    let (original, delivered) = tokio::task::spawn_blocking(move || {
        let delivered = match engine.prepare(&bytes, &Credentials::default()) {
            Err(e) if e.code() == "CS-PDF-0014" => engine.keep_signed(&bytes),
            other => other,
        };
        (bytes, delivered)
    })
    .await
    .map_err(|_| ApiError::internal("admission"))?;
    let delivered = delivered?;
    let pages = delivered.admission.page_count;
    if pages == 0 || pages > casual_sign_workflow::limits::MAX_PAGES {
        return Err(ApiError::invalid("/content"));
    }
    let original_key = st.0.blobs.put(&original).await?;
    let delivered_key = st.0.blobs.put(&delivered.bytes).await?;
    let (report, findings) = admission_json(&delivered.admission, delivered.normalization.as_ref());
    let report_hash = Hash256::digest(&serde_json::to_vec(&report).unwrap_or_default());
    let doc = DocumentId(Uuid::now_v7());
    // Storage is checked against the plan under its counter rows' lock (PLAN-04,
    // `CS-PLAN-0004`; a suspended organization takes no new document, `CS-PLAN-0005`).
    let storage = tx.gauge_lock(Meter::StorageBytes).await?;
    let ord = tx
        .documents()
        .list(env)
        .await?
        .iter()
        .map(|d| d.ord)
        .max()
        .map_or(0, |m| m.saturating_add(1));
    tx.documents()
        .insert(&Document {
            id: doc,
            envelope_id: env,
            ord,
            name: name.to_owned(),
        })
        .await?;
    let geometry = pages_json(&delivered.admission);
    let page_count = i32::try_from(pages).unwrap_or(i32::MAX);
    for (kind, key, len, admission) in [
        (VersionKind::Original, original_key, original.len(), None),
        (
            VersionKind::Normalized,
            delivered_key,
            delivered.bytes.len(),
            Some(report.clone()),
        ),
    ] {
        tx.documents()
            .add_version(&NewVersion {
                id: DocumentVersionId(Uuid::now_v7()),
                document_id: doc,
                kind,
                sha256: key.0,
                byte_len: i64::try_from(len).unwrap_or(i64::MAX),
                page_count,
                admission_report: admission,
                pages: geometry.clone(),
            })
            .await?;
    }
    tx.gauge_check(storage, st.now(), "document", doc.0).await?;
    Ok(DocumentSpec {
        id: eid(doc.0)?,
        name: Personal(casual_sign_model::Text::new(name).map_err(|_| ApiError::invalid("/name"))?),
        upload_hash: Hash256(original_key.0),
        bytes: u64::try_from(original.len()).unwrap_or(u64::MAX),
        delivered_hash: delivered.hash,
        pages,
        admission: Some((report_hash, findings)),
    })
}

/// Recipients of a request, as changes, with their access codes stored.
async fn recipients_in(
    tx: &mut TenantTx,
    list: &[RecipientIn],
    at: &str,
) -> Result<
    (
        Vec<Change>,
        BTreeMap<String, Id>,
        Vec<(RecipientId, String)>,
    ),
    ApiError,
> {
    let mut changes = Vec::new();
    let mut refs = BTreeMap::new();
    let mut codes = Vec::new();
    let _ = tx;
    for (i, r) in list.iter().enumerate() {
        let id = new_id()?;
        let spec = r.spec(id.clone(), &format!("{at}/{i}"))?;
        if let Some(reference) = &r.reference {
            refs.insert(reference.clone(), id.clone());
        }
        if let Some(code) = r.access_code.as_ref().filter(|c| !c.is_empty()) {
            codes.push((RecipientId(uid(&id)?), code.clone()));
        }
        changes.push(Change::AddRecipient { recipient: spec });
    }
    Ok((changes, refs, codes))
}

async fn store_codes(tx: &mut TenantTx, codes: Vec<(RecipientId, String)>) -> Result<(), ApiError> {
    for (r, code) in codes {
        let phc = tokio::task::spawn_blocking(move || hash_password(&code))
            .await
            .map_err(|_| ApiError::internal("argon2"))??;
        tx.recipients()
            .set_access_code(r, Uuid::now_v7(), &Personal(phc))
            .await?;
    }
    Ok(())
}

fn days_from(now: OffsetDateTime, days: u32) -> Result<casual_sign_audit::Timestamp, ApiError> {
    crate::apply::ts(crate::state::plus(
        now,
        time::Duration::days(i64::from(days)),
    )?)
}

// Envelopes -----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(crate) struct ListQuery {
    cursor: Option<String>,
    limit: Option<u32>,
    /// One status, or several separated by commas (WEB-08).
    status: Option<String>,
    /// Text the subject or a recipient's name or email contains (row WEB-04).
    q: Option<String>,
    /// `created_at` (default), `updated_at`, `expires_at`, `subject` or `status`.
    sort: Option<String>,
    /// `asc` or `desc`; by default times newest first, subjects and statuses ascending.
    order: Option<String>,
    /// A sender's user id, or `me`.
    sender: Option<String>,
    /// `date_field` at or after (RFC 3339).
    from: Option<String>,
    /// `date_field` before (RFC 3339).
    to: Option<String>,
    /// Text a recipient's name or email contains (UXW-03).
    recipient: Option<String>,
    /// Which date `from` and `to` bound: `updated_at` (default), `created_at`,
    /// `sent_at`, `completed_at` (UXW-03).
    date_field: Option<String>,
    /// One of the caller's folders, or `none` (UXW-02).
    folder: Option<String>,
    /// `true`: the Deleted view (UXW-02).
    deleted: Option<String>,
    /// `me`: the Inbox (UXW-01).
    waiting_for: Option<String>,
}

fn parse_date_field(s: &str) -> Option<DateField> {
    [
        DateField::Updated,
        DateField::Created,
        DateField::Sent,
        DateField::Completed,
    ]
    .into_iter()
    .find(|d| d.as_str() == s)
}

/// A free-text list parameter: trimmed, empty as absent, at most [`MAX_QUERY`]
/// characters and no control characters.
fn text_param<'a>(v: Option<&'a str>, at: &str) -> Result<Option<&'a str>, ApiError> {
    let t = v.map(str::trim).filter(|t| !t.is_empty());
    if t.is_some_and(|t| t.chars().count() > MAX_QUERY || t.chars().any(char::is_control)) {
        return Err(ApiError::invalid(at));
    }
    Ok(t)
}

/// The longest `q` searched for, in characters.
const MAX_QUERY: usize = 200;

fn parse_status(s: &str) -> Option<EnvelopeStatus> {
    Some(match s {
        "draft" => EnvelopeStatus::Draft,
        "sent" => EnvelopeStatus::Sent,
        "delivered" => EnvelopeStatus::Delivered,
        "completing" => EnvelopeStatus::Completing,
        "completed" => EnvelopeStatus::Completed,
        "declined" => EnvelopeStatus::Declined,
        "voided" => EnvelopeStatus::Voided,
        "expired" => EnvelopeStatus::Expired,
        _ => return None,
    })
}

fn sort_name(k: SortKey) -> &'static str {
    match k {
        SortKey::Created => "created_at",
        SortKey::Updated => "updated_at",
        SortKey::Expires => "expires_at",
        SortKey::Subject => "subject",
        SortKey::Status => "status",
    }
}

fn parse_sort(s: &str) -> Option<SortKey> {
    [
        SortKey::Created,
        SortKey::Updated,
        SortKey::Expires,
        SortKey::Subject,
        SortKey::Status,
    ]
    .into_iter()
    .find(|k| sort_name(*k) == s)
}

/// A cursor names its sort, so a cursor of another sort is refused rather than
/// misread: `v2|<sort>|<a or d>|<key>|<id>`, base64url; a time key in nanoseconds, a
/// subject key in base64url. The earlier `<nanoseconds>.<id>` (newest first by
/// creation) is still read.
fn encode_cursor(sort: Sort, a: &After) -> String {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let key = match &a.key {
        AfterKey::Time(t) => t.unix_timestamp_nanos().to_string(),
        AfterKey::Text(t) => b64.encode(t),
        AfterKey::Rank(r) => r.to_string(),
    };
    let raw = format!(
        "v2|{}|{}|{key}|{}",
        sort_name(sort.key),
        if sort.descending { "d" } else { "a" },
        a.id
    );
    b64.encode(raw)
}

fn decode_cursor(s: &str, sort: Sort) -> Option<After> {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let raw = String::from_utf8(b64.decode(s).ok()?).ok()?;
    let time = |t: &str| OffsetDateTime::from_unix_timestamp_nanos(t.parse().ok()?).ok();
    let Some(rest) = raw.strip_prefix("v2|") else {
        // The earlier form: creation time, newest first.
        let (t, id) = raw.split_once('.')?;
        return (sort.key == SortKey::Created && sort.descending).then_some(After {
            key: AfterKey::Time(time(t)?),
            id: EnvelopeId(Uuid::parse_str(id).ok()?),
        });
    };
    let mut parts = rest.split('|');
    let (name, dir, key, id) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some()
        || name != sort_name(sort.key)
        || dir != if sort.descending { "d" } else { "a" }
    {
        return None;
    }
    let key = match sort.key {
        SortKey::Created | SortKey::Updated | SortKey::Expires => AfterKey::Time(time(key)?),
        SortKey::Subject => AfterKey::Text(String::from_utf8(b64.decode(key).ok()?).ok()?),
        SortKey::Status => AfterKey::Rank(key.parse().ok()?),
    };
    Some(After {
        key,
        id: EnvelopeId(Uuid::parse_str(id).ok()?),
    })
}

/// The cursor after `l` in `sort`.
fn after_of(sort: Sort, l: &Listed) -> After {
    let e = &l.envelope;
    let key = match sort.key {
        SortKey::Created => AfterKey::Time(e.created_at),
        SortKey::Updated => AfterKey::Time(e.updated_at),
        SortKey::Expires => AfterKey::Time(e.expires_at.unwrap_or_else(never_expires)),
        SortKey::Subject => AfterKey::Text(l.subject_key.get().clone()),
        SortKey::Status => AfterKey::Rank(status_rank(e.status)),
    };
    After { key, id: e.id }
}

fn instant(s: Option<&str>, at: &str) -> Result<Option<OffsetDateTime>, ApiError> {
    s.map(|t| {
        OffsetDateTime::parse(t, &time::format_description::well_known::Rfc3339)
            .map_err(|_| ApiError::invalid(at))
    })
    .transpose()
}

/// `GET /envelopes`: a page of the envelopes the principal may see that are not
/// removed from the lists, filtered and sorted as asked (WEB-08), newest first by
/// default.
pub(crate) async fn list(c: Call, Query(q): Query<ListQuery>) -> Result<Response, ApiError> {
    let limit = q.limit.unwrap_or(50);
    if !(1..=200).contains(&limit) {
        return Err(ApiError::invalid("/query/limit"));
    }
    let key = match q.sort.as_deref() {
        None => SortKey::Created,
        Some(s) => parse_sort(s).ok_or_else(|| ApiError::invalid("/query/sort"))?,
    };
    let descending = match q.order.as_deref() {
        None => matches!(key, SortKey::Created | SortKey::Updated | SortKey::Expires),
        Some("desc") => true,
        Some("asc") => false,
        Some(_) => return Err(ApiError::invalid("/query/order")),
    };
    let sort = Sort { key, descending };
    let after = q
        .cursor
        .as_deref()
        .map(|s| decode_cursor(s, sort).ok_or_else(|| ApiError::invalid("/query/cursor")))
        .transpose()?;
    let mut statuses = Vec::new();
    for s in q.status.as_deref().unwrap_or("").split(',') {
        let s = s.trim();
        if s.is_empty() {
            continue;
        }
        let st = parse_status(s).ok_or_else(|| ApiError::invalid("/query/status"))?;
        if !statuses.contains(&st) {
            statuses.push(st);
        }
    }
    let search = text_param(q.q.as_deref(), "/query/q")?;
    let recipient = text_param(q.recipient.as_deref(), "/query/recipient")?;
    let asked = match q.sender.as_deref() {
        None => None,
        Some("me") => Some(c.p.user),
        Some(s) => Some(UserId(
            Uuid::parse_str(s).map_err(|_| ApiError::invalid("/query/sender"))?,
        )),
    };
    let changed_from = instant(q.from.as_deref(), "/query/from")?;
    let changed_to = instant(q.to.as_deref(), "/query/to")?;
    let date_field = match q.date_field.as_deref() {
        None => DateField::Updated,
        Some(s) => parse_date_field(s).ok_or_else(|| ApiError::invalid("/query/date_field"))?,
    };
    let folder = match q.folder.as_deref() {
        None => FolderFilter::Any,
        Some("none") => FolderFilter::None,
        Some(s) => FolderFilter::In(FolderId(
            Uuid::parse_str(s).map_err(|_| ApiError::invalid("/query/folder"))?,
        )),
    };
    let deleted = match q.deleted.as_deref() {
        None | Some("false") => false,
        Some("true") => true,
        Some(_) => return Err(ApiError::invalid("/query/deleted")),
    };
    let waiting = match q.waiting_for.as_deref() {
        None => false,
        Some("me") => true,
        Some(_) => return Err(ApiError::invalid("/query/waiting_for")),
    };
    // Without `view_all`, the caller's own only: another sender asked for is an empty
    // page, never someone else's envelopes. The Inbox is its own access: envelopes
    // waiting for the caller as a recipient, whoever sent them.
    let own = (!(c.p.admin || c.p.view_all || waiting)).then_some(c.p.user);
    let sender = match (own, asked) {
        (Some(me), Some(other)) if me != other => return Ok(page_json(Vec::new(), None)),
        (Some(me), _) => Some(me),
        (None, a) => a,
    };
    let filter = ListFilter {
        statuses: &statuses,
        sender,
        search,
        changed_from,
        changed_to,
        recipient,
        date_field,
        member: Some(c.p.user),
        folder,
        deleted,
        waiting,
    };
    let mut tx = c.tx().await?;
    let page = tx
        .envelopes()
        .search(&filter, sort, after.as_ref(), limit)
        .await?;
    let next = (page.len() == usize::try_from(limit).unwrap_or(usize::MAX))
        .then(|| page.last())
        .flatten()
        .map(|l| encode_cursor(sort, &after_of(sort, l)));
    let items: Vec<Value> = page
        .iter()
        .map(|l| {
            let e = &l.envelope;
            let mut item = json!({
                "id": e.id.to_string(),
                "status": e.status.as_str(),
                "subject": e.subject.get(),
                "sender_user_id": e.sender_user_id.to_string(),
                "created_at": rfc3339(e.created_at),
                "updated_at": rfc3339(e.updated_at),
                "sent_at": e.sent_at.map(rfc3339),
                "completed_at": e.completed_at.map(rfc3339),
                "expires_at": e.expires_at.map(rfc3339),
                "folder_id": l.folder.map(|f| f.to_string()),
            });
            if waiting && let Some(map) = item.as_object_mut() {
                map.insert(
                    "my_recipient_id".into(),
                    json!(l.my_recipient.map(|r| r.to_string())),
                );
            }
            item
        })
        .collect();
    Ok(page_json(items, next))
}

fn page_json(items: Vec<Value>, next: Option<String>) -> Response {
    json(
        StatusCode::OK,
        &json!({ "items": items, "next_cursor": next }),
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContactsQuery {
    q: Option<String>,
    limit: Option<u32>,
}

/// `GET /contacts?q=&limit=`: past recipients for autocomplete (WEB-06), one per email
/// address, most recently used first, from the envelopes the principal may see.
pub(crate) async fn contacts(
    c: Call,
    Query(q): Query<ContactsQuery>,
) -> Result<Response, ApiError> {
    let limit = q.limit.unwrap_or(10);
    if !(1..=50).contains(&limit) {
        return Err(ApiError::invalid("/query/limit"));
    }
    let search = q.q.as_deref().map(str::trim).filter(|t| !t.is_empty());
    if search.is_some_and(|t| t.chars().count() > MAX_QUERY || t.chars().any(char::is_control)) {
        return Err(ApiError::invalid("/query/q"));
    }
    let sender = (!(c.p.admin || c.p.view_all)).then_some(c.p.user);
    let mut tx = c.tx().await?;
    let found = tx.recipients().contacts(search, sender, limit).await?;
    let items: Vec<Value> = found
        .iter()
        .map(|x| {
            json!({
                "name": x.name.get(),
                "email": x.email.get(),
                "last_used_at": rfc3339(x.last_used),
            })
        })
        .collect();
    Ok(json(StatusCode::OK, &json!({ "items": items })))
}

pub(crate) fn rfc3339(t: OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// `POST /envelopes`: create a draft, or create and send in one call (docs/40 §3).
pub(crate) async fn create(c: Call, body: Bytes) -> Result<Response, ApiError> {
    c.p.require("envelopes:write")?;
    let req: EnvelopeCreate = parse(&body)?;
    let send = match req.status.as_deref() {
        None | Some("draft") => false,
        Some("sent") => {
            c.p.require("envelopes:send")?;
            true
        }
        Some(_) => return Err(ApiError::invalid("/status")),
    };
    let subject = dto::subject(&req.subject)?;
    let message = dto::message(&req.message)?;
    let mut decoded = Vec::with_capacity(req.documents.len());
    let mut total = 0usize;
    for (i, d) in req.documents.iter().enumerate() {
        let b = base64(
            &d.content_base64,
            c.st.config().max_document_bytes,
            &format!("/documents/{i}/content_base64"),
        )?;
        total = total.saturating_add(b.len());
        decoded.push((d.name.clone(), b));
    }
    if total > c.st.config().max_envelope_bytes {
        return Err(ApiError::too_large());
    }
    let mut tx = c.tx().await?;
    let mut cmds = c.commands(&mut tx).await?;
    let env = EnvelopeId(Uuid::now_v7());
    let me = eid(c.p.user.0)?;
    let principal = WfPrincipal::Sender {
        user_id: me.clone(),
    };
    let create = Command::Create {
        envelope_id: eid(env.0)?,
        account_id: eid(c.p.account.0)?,
        sender_user_id: me,
        subject,
        message,
    };
    let ctx = cmds.ctx(principal, None)?;
    let mut l = create_env(&mut tx, c.p.account, env, &create, &ctx, c.p.client()).await?;
    let mut changes = Vec::new();
    let mut doc_ids = Vec::new();
    let mut uploads = Vec::new();
    for (name, bytes) in decoded {
        let spec = add_document(&c.st, &mut tx, env, &name, bytes).await?;
        doc_ids.push(spec.id.clone());
        uploads.push((uid(&spec.id)?, spec.delivered_hash.0));
        changes.push(Change::AddDocument { document: spec });
    }
    let (rchanges, refs, codes) = recipients_in(&mut tx, &req.recipients, "/recipients").await?;
    changes.extend(rchanges);
    for (i, f) in req.fields.iter().enumerate() {
        let field = dto::field_from(
            f,
            new_id()?,
            |r| refs.get(r).cloned().or_else(|| Id::new(r).ok()),
            |d| match d {
                Value::Number(n) => n
                    .as_u64()
                    .and_then(|i| doc_ids.get(usize::try_from(i).ok()?).cloned()),
                Value::String(s) => Id::new(s.as_str()).ok(),
                _ => None,
            },
            &format!("/fields/{i}"),
        )?;
        changes.push(Change::AddField {
            field: Personal(field),
        });
    }
    if let Some(r) = req.reminders {
        changes.push(Change::SetReminders { reminders: r });
    }
    if let Some(d) = req.expires_in_days {
        changes.push(Change::SetExpiry {
            expires_at: Some(days_from(cmds.now, d)?),
        });
    }
    if let Some(o) = req.signing_options {
        changes.push(Change::SetSigningOptions { options: o });
    }
    if let Some(s) = req.seal_profile {
        changes.push(Change::SetSealProfile { profile: s });
    }
    if !changes.is_empty() {
        command(
            &c,
            &mut tx,
            &mut cmds,
            &mut l,
            Command::Edit { changes },
            None,
        )
        .await?;
    }
    store_codes(&mut tx, codes).await?;
    if send {
        command(&c, &mut tx, &mut cmds, &mut l, Command::Send, None).await?;
    } else {
        // Document analysis of the draft's uploads (docs/33 §2), only with a feature in
        // effect; otherwise nothing is written (ML-01).
        for (doc, sha) in uploads {
            crate::api::ml::on_envelope_upload(&c.st, &mut tx, c.p.account, env, doc, sha).await?;
        }
    }
    tx.commit().await?;
    let mut r = envelope_response(StatusCode::CREATED, &l.state);
    if let Ok(v) = HeaderValue::from_str(&format!("/api/v1/envelopes/{env}")) {
        r.headers_mut().insert(header::LOCATION, v);
    }
    Ok(r)
}

/// `GET /envelopes/{id}`.
pub(crate) async fn get(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let l = find(&mut tx, &c.p, &id).await?;
    Ok(envelope_response(StatusCode::OK, &l.state))
}

/// `GET /envelopes/{id}/status`: the envelope's and each recipient's status.
pub(crate) async fn status(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let l = find(&mut tx, &c.p, &id).await?;
    let s = &l.state;
    Ok(json_tagged(
        StatusCode::OK,
        &json!({
            "id": s.id, "status": s.status, "version": s.version,
            "recipients": s.recipients.iter().map(|r| json!({"id": r.id(), "status": r.status})).collect::<Vec<_>>(),
        }),
        &dto::etag(s),
    ))
}

/// `PATCH /envelopes/{id}`: subject, message, reminders, expiry, options, profile.
pub(crate) async fn patch(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    c.p.require("envelopes:write")?;
    let mut tx = c.tx().await?;
    let mut l = find(&mut tx, &c.p, &id).await?;
    let v = expected(&c, true)?;
    let req: EnvelopePatch = parse(&body)?;
    let mut changes = Vec::new();
    if let Some(s) = &req.subject {
        changes.push(Change::SetSubject {
            subject: dto::subject(s)?,
        });
    }
    if let Some(m) = &req.message {
        changes.push(Change::SetMessage {
            message: dto::message(m)?,
        });
    }
    if let Some(r) = req.reminders {
        changes.push(Change::SetReminders { reminders: r });
    }
    if let Some(d) = req.expires_in_days {
        let at = d.map(|d| days_from(c.st.now(), d)).transpose()?;
        changes.push(Change::SetExpiry { expires_at: at });
    }
    if let Some(o) = req.signing_options {
        changes.push(Change::SetSigningOptions { options: o });
    }
    if let Some(p) = req.seal_profile {
        changes.push(Change::SetSealProfile { profile: p });
    }
    if changes.is_empty() {
        return Err(ApiError::invalid(""));
    }
    change(&c, &mut tx, &mut l, changes, v).await?;
    tx.commit().await?;
    Ok(envelope_response(StatusCode::OK, &l.state))
}

/// `DELETE /envelopes/{id}`: delete a draft (recorded, docs/24 As built), or remove an
/// envelope that ended without completing (declined, voided, expired) from the lists
/// (WEB-08): a soft delete recorded as `envelope.deleted`; its documents, state and
/// audit chain stay, and it is still reachable by id. A completed envelope, or one in
/// flight, is `409`.
pub(crate) async fn delete(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    c.p.require("envelopes:write")?;
    let mut tx = c.tx().await?;
    let mut l = find(&mut tx, &c.p, &id).await?;
    let v = expected(&c, true)?;
    let mut cmds = c.commands(&mut tx).await?;
    let cmd = if l.state.status == MStatus::Draft {
        Command::DeleteDraft
    } else {
        Command::DeleteEnded
    };
    command(&c, &mut tx, &mut cmds, &mut l, cmd, v).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /envelopes/{id}/send`.
pub(crate) async fn send(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let mut l = find(&mut tx, &c.p, &id).await?;
    let v = expected(&c, false)?;
    let mut cmds = c.commands(&mut tx).await?;
    command(&c, &mut tx, &mut cmds, &mut l, Command::Send, v).await?;
    tx.commit().await?;
    Ok(envelope_response(StatusCode::OK, &l.state))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VoidIn {
    reason: String,
}

/// `POST /envelopes/{id}/void {reason}`.
pub(crate) async fn void(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let mut l = find(&mut tx, &c.p, &id).await?;
    let v = expected(&c, false)?;
    let req: VoidIn = parse(&body)?;
    if req.reason.trim().is_empty() {
        return Err(ApiError::invalid("/reason"));
    }
    let reason = dto::message(&req.reason)?;
    let mut cmds = c.commands(&mut tx).await?;
    command(&c, &mut tx, &mut cmds, &mut l, Command::Void { reason }, v).await?;
    tx.commit().await?;
    Ok(envelope_response(StatusCode::OK, &l.state))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorrectIn {
    changes: Vec<Change>,
}

/// `POST /envelopes/{id}/correct {changes}`: one correction, all or none (docs/24 §6
/// as built). The changes are the engine's change list.
pub(crate) async fn correct(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let mut l = find(&mut tx, &c.p, &id).await?;
    let v = expected(&c, true)?;
    let req: CorrectIn = parse(&body)?;
    if req.changes.iter().any(|ch| {
        matches!(
            ch,
            Change::AddDocument { .. } | Change::ReplaceDocument { .. }
        )
    }) {
        // Documents arrive through the documents endpoint, which admits them.
        return Err(ApiError::invalid("/changes"));
    }
    let mut cmds = c.commands(&mut tx).await?;
    command(
        &c,
        &mut tx,
        &mut cmds,
        &mut l,
        Command::Correct {
            changes: req.changes,
        },
        v,
    )
    .await?;
    tx.commit().await?;
    Ok(envelope_response(StatusCode::OK, &l.state))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResendIn {
    #[serde(default)]
    recipient_ids: Vec<String>,
}

/// `POST /envelopes/{id}/resend {recipient_ids?}`.
pub(crate) async fn resend(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let mut l = find(&mut tx, &c.p, &id).await?;
    let req: ResendIn = parse(&body)?;
    let recipients = req
        .recipient_ids
        .iter()
        .map(|r| Id::new(r.as_str()).map_err(|_| ApiError::invalid("/recipient_ids")))
        .collect::<Result<Vec<_>, _>>()?;
    let mut cmds = c.commands(&mut tx).await?;
    command(
        &c,
        &mut tx,
        &mut cmds,
        &mut l,
        Command::Resend { recipients },
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(envelope_response(StatusCode::OK, &l.state))
}

/// `GET /envelopes/{id}/audit`: the hash-chained events, re-verified on read.
pub(crate) async fn audit(
    c: Call,
    Path(id): Path<String>,
    Query(q): Query<BTreeMap<String, String>>,
) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let l = find(&mut tx, &c.p, &id).await?;
    if q.get("format").is_some_and(|f| f != "json") {
        return Err(ApiError::not_available(
            "the PDF audit report is built with the certificate (stage 2D)",
        ));
    }
    // `chain` re-verifies every link; a broken chain is an error, never served.
    let _ = tx.audit().chain(l.id).await?;
    let events = tx.audit().events(l.id).await?;
    let items: Vec<Value> = events
        .iter()
        .map(|e| {
            json!({
                "seq": e.seq,
                "type": e.event_type,
                "at": rfc3339(e.at),
                "hash": Hash256(e.hash),
                "prev": e.prev.map(Hash256),
                "event": serde_json::from_slice::<Value>(&e.canonical).unwrap_or(Value::Null),
            })
        })
        .collect();
    Ok(json(
        StatusCode::OK,
        &json!({ "items": items, "chain_head": items.last().map(|e| e["hash"].clone()) }),
    ))
}

// Documents -----------------------------------------------------------------------------

/// `GET /envelopes/{id}/documents`.
pub(crate) async fn documents(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let l = find(&mut tx, &c.p, &id).await?;
    let items: Vec<Value> = l.state.documents.iter().map(dto::document).collect();
    Ok(json_tagged(
        StatusCode::OK,
        &json!({ "items": items }),
        &dto::etag(&l.state),
    ))
}

/// `POST /envelopes/{id}/documents`: JSON `{name, content_base64}`, or the PDF itself
/// as `application/pdf` with `?name=`.
pub(crate) async fn add_document_route(
    c: Call,
    Path(id): Path<String>,
    Query(q): Query<BTreeMap<String, String>>,
    body: Bytes,
) -> Result<Response, ApiError> {
    c.p.require("envelopes:write")?;
    let mut tx = c.tx().await?;
    let mut l = find(&mut tx, &c.p, &id).await?;
    let v = expected(&c, false)?;
    let pdf = c
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|t| t.starts_with("application/pdf"));
    let (name, bytes) = if pdf {
        let name = q
            .get("name")
            .cloned()
            .ok_or_else(|| ApiError::invalid("/query/name"))?;
        (name, body.to_vec())
    } else {
        let d: DocumentIn = parse(&body)?;
        let b = base64(
            &d.content_base64,
            c.st.config().max_document_bytes,
            "/content_base64",
        )?;
        (d.name, b)
    };
    // The envelope's total stays within the limit however its documents arrive
    // (FG-006, docs/21), not only in a one-call create.
    let held = l
        .state
        .documents
        .iter()
        .fold(0u64, |n, d| n.saturating_add(d.spec.bytes));
    let limit = u64::try_from(c.st.config().max_envelope_bytes).unwrap_or(u64::MAX);
    let adding = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if held.saturating_add(adding) > limit {
        return Err(ApiError::too_large());
    }
    let spec = add_document(&c.st, &mut tx, l.id, &name, bytes).await?;
    let doc_id = spec.id.clone();
    let upload = (uid(&spec.id)?, spec.delivered_hash.0);
    change(
        &c,
        &mut tx,
        &mut l,
        vec![Change::AddDocument { document: spec }],
        v,
    )
    .await?;
    if l.state.status == MStatus::Draft {
        crate::api::ml::on_envelope_upload(&c.st, &mut tx, c.p.account, l.id, upload.0, upload.1)
            .await?;
    }
    tx.commit().await?;
    let d = l
        .state
        .document(&doc_id)
        .ok_or_else(|| ApiError::internal("document"))?;
    Ok(json_tagged(
        StatusCode::CREATED,
        &dto::document(d),
        &dto::etag(&l.state),
    ))
}

pub(crate) fn doc_in<'a>(
    s: &'a EnvelopeState,
    doc: &str,
) -> Result<&'a casual_sign_workflow::DocumentState, ApiError> {
    s.documents
        .iter()
        .find(|d| same_id(d.id(), doc))
        .ok_or_else(ApiError::not_found)
}

/// `GET /envelopes/{id}/documents/{doc}`.
pub(crate) async fn document(
    c: Call,
    Path((id, doc)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let l = find(&mut tx, &c.p, &id).await?;
    let d = doc_in(&l.state, &doc)?;
    Ok(json_tagged(
        StatusCode::OK,
        &dto::document(d),
        &dto::etag(&l.state),
    ))
}

/// `DELETE /envelopes/{id}/documents/{doc}`.
pub(crate) async fn delete_document(
    c: Call,
    Path((id, doc)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    c.p.require("envelopes:write")?;
    let mut tx = c.tx().await?;
    let mut l = find(&mut tx, &c.p, &id).await?;
    let d = doc_in(&l.state, &doc)?.id().clone();
    let v = expected(&c, true)?;
    change(
        &c,
        &mut tx,
        &mut l,
        vec![Change::RemoveDocument { id: d }],
        v,
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `GET /envelopes/{id}/documents/{doc}/content?version=original|normalized|sealed`.
/// A download from a sent envelope is recorded in its chain (docs/32 §3 Access).
pub(crate) async fn content(
    c: Call,
    Path((id, doc)): Path<(String, String)>,
    Query(q): Query<BTreeMap<String, String>>,
) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let mut l = find(&mut tx, &c.p, &id).await?;
    let d = doc_in(&l.state, &doc)?.id().clone();
    let kind = match q.get("version").map(String::as_str) {
        None | Some("normalized") => VersionKind::Normalized,
        Some("original") => VersionKind::Original,
        Some("sealed") => VersionKind::Sealed,
        Some("current") => return current(&c, tx, &mut l, &d).await,
        Some(_) => return Err(ApiError::invalid("/query/version")),
    };
    let versions = tx.documents().versions(DocumentId(uid(&d)?)).await?;
    let Some(v) = versions.iter().rev().find(|v| v.version.kind == kind) else {
        return Err(if kind == VersionKind::Sealed {
            ApiError::not_available("sealed when the envelope completes")
        } else {
            ApiError::not_found()
        });
    };
    let sha = v.version.sha256;
    let access = (l.state.status != MStatus::Draft && kind != VersionKind::Original).then_some(
        Access::DocumentDownloaded {
            document: d,
            hash: Hash256(sha),
        },
    );
    serve_pdf(&c, tx, &mut l, sha, access).await
}

/// `POST /envelopes/{id}/documents/{doc}/detect-fields`: suggested fields for the
/// delivered document (WEB-06), from underscore lines, painted rules and boxes and the
/// labels near them ("Signature", "Sign here", "Date", "Name", "Initials", "Title",
/// "Company"), plus its AcroForm fields. Each suggestion is in the field geometry the
/// field endpoints take (page, x, y, width, height: displayed points, origin top-left,
/// ADR-019), so a client adds one by naming a recipient. Nothing is changed or recorded.
pub(crate) async fn detect_fields(
    c: Call,
    Path((id, doc)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    c.p.require("envelopes:write")?;
    let mut tx = c.tx().await?;
    let l = find(&mut tx, &c.p, &id).await?;
    let d = doc_in(&l.state, &doc)?.id().clone();
    let versions = tx.documents().versions(DocumentId(uid(&d)?)).await?;
    tx.commit().await?;
    let v = versions
        .iter()
        .rev()
        .find(|v| v.version.kind == VersionKind::Normalized)
        .ok_or_else(ApiError::not_found)?;
    let bytes =
        c.st.0
            .blobs
            .get(&casual_sign_store::blob::BlobKey(v.version.sha256))
            .await?;
    let engine = c.st.0.engine.clone();
    let doc_id = d.clone();
    let found = tokio::task::spawn_blocking(move || {
        let mut n: u32 = 0;
        let mut next = || {
            n = n.saturating_add(1);
            Id::new(format!("acroform-{n}")).unwrap_or_else(|_| doc_id.clone())
        };
        engine.detect_fields(&bytes, &doc_id, &mut next)
    })
    .await
    .map_err(|_| ApiError::internal("detection"))??;
    let items: Vec<Value> = found
        .fields
        .iter()
        .map(|f| {
            let mut v = serde_json::to_value(f.placement).unwrap_or(Value::Null);
            if let Some(o) = v.as_object_mut() {
                o.insert("document_id".into(), json!(d));
                o.insert("type".into(), json!(f.field_type));
                o.insert("source".into(), json!(f.source.as_str()));
                o.insert("confidence".into(), json!(f.confidence));
                if let Some(label) = &f.label {
                    o.insert("cue".into(), json!(label));
                }
            }
            v
        })
        .collect();
    Ok(json(
        StatusCode::OK,
        &json!({ "items": items, "truncated": found.truncated }),
    ))
}

/// `content?version=current` (WEB-06): the sealed version once sealed, else a preview
/// of the values completed so far with a "not signed" banner on every page, made on
/// request and never stored (`preview`). Recorded as `document.downloaded` with the
/// hash of the bytes served once the envelope is sent.
async fn current(c: &Call, mut tx: TenantTx, l: &mut Loaded, d: &Id) -> Result<Response, ApiError> {
    let (bytes, sealed) = crate::preview::current(&c.st, &mut tx, &l.state, d).await?;
    let access = (l.state.status != MStatus::Draft).then(|| Access::DocumentDownloaded {
        document: d.clone(),
        hash: Hash256::digest(&bytes),
    });
    let mut r = serve_bytes(c, tx, l, bytes, access).await?;
    r.headers_mut().insert(
        "x-openseal-document",
        HeaderValue::from_static(if sealed { "sealed" } else { "preview" }),
    );
    Ok(r)
}

/// Read a stored PDF, record its download in the chain when `access` says so, commit,
/// and answer it as an attachment.
async fn serve_pdf(
    c: &Call,
    tx: TenantTx,
    l: &mut Loaded,
    sha256: [u8; 32],
    access: Option<Access>,
) -> Result<Response, ApiError> {
    let bytes =
        c.st.0
            .blobs
            .get(&casual_sign_store::blob::BlobKey(sha256))
            .await?;
    serve_bytes(c, tx, l, bytes, access).await
}

/// Record a download in the chain when `access` says so, commit, and answer `bytes`
/// as a PDF attachment.
async fn serve_bytes(
    c: &Call,
    mut tx: TenantTx,
    l: &mut Loaded,
    bytes: Vec<u8>,
    access: Option<Access>,
) -> Result<Response, ApiError> {
    if let Some(access) = access {
        let mut cmds = c.commands(&mut tx).await?;
        command(
            c,
            &mut tx,
            &mut cmds,
            l,
            Command::RecordAccess { access },
            None,
        )
        .await?;
    }
    tx.commit().await?;
    let mut r = (StatusCode::OK, bytes).into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/pdf"),
    );
    r.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment"),
    );
    Ok(r)
}

/// `GET /envelopes/{id}/certificate`: the certificate of completion on its own, with
/// the audit trail embedded, sealed by the seal job (stage 2D) when the envelope
/// completes; for a declined, voided or expired envelope, its envelope certificate
/// (UXW-30), which says how it ended and never claims completion, made and sealed by
/// the worker when it ended. `409 CS-API-0009` before either exists (an ended envelope
/// without one asks the worker for it then). The download is recorded in the chain.
pub(crate) async fn certificate(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let mut l = find(&mut tx, &c.p, &id).await?;
    let Some(sha) = tx.envelopes().certificate(l.id).await? else {
        if matches!(
            l.state.status,
            MStatus::Declined | MStatus::Voided | MStatus::Expired
        ) {
            // An envelope that ended before the worker made envelope certificates
            // (UXW-30): ask for it now; the queue keeps one job per envelope.
            let job = casual_sign_host::jobs::ended_certificate_job(
                casual_sign_store::JobId(Uuid::now_v7()),
                l.id,
                c.st.now(),
            );
            tx.jobs().enqueue(&job).await?;
            tx.commit().await?;
            return Err(ApiError::not_available(
                "the envelope certificate is being made; ask again shortly",
            ));
        }
        return Err(ApiError::not_available(
            "the certificate is made by the seal job when the envelope completes",
        ));
    };
    let access = Some(Access::CertificateDownloaded { hash: Hash256(sha) });
    serve_pdf(&c, tx, &mut l, sha, access).await
}

/// `GET /envelopes/{id}/attachments/{sha256}` (WEB-08): a signer's attachment, the file
/// an attachment field's value names, for staff who may see the envelope. The bytes are
/// checked against the hash before they are served, answered as an attachment of the
/// type their leading bytes show (PDF, PNG or JPEG, as admitted), and recorded as
/// `attachment.downloaded` with the field and the hash. Any other hash, and a purged
/// envelope's, is `404`.
pub(crate) async fn attachment(
    c: Call,
    Path((id, sha)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let mut l = find(&mut tx, &c.p, &id).await?;
    let hash = Hash256::parse(&format!("sha256:{sha}")).map_err(|_| ApiError::not_found())?;
    let field = l
        .state
        .fields
        .0
        .iter()
        .find(|f| {
            matches!(&f.value, Some(casual_sign_model::FieldValue::Attachment(a))
                if a.as_str() == hash.hex())
        })
        .map(|f| f.id.clone())
        .ok_or_else(ApiError::not_found)?;
    let bytes =
        c.st.0
            .blobs
            .get(&casual_sign_store::blob::BlobKey(hash.0))
            .await?;
    if Hash256::digest(&bytes) != hash {
        return Err(ApiError::internal("attachment"));
    }
    let media = casual_sign_host::capture::media_type(&bytes);
    let mut cmds = c.commands(&mut tx).await?;
    command(
        &c,
        &mut tx,
        &mut cmds,
        &mut l,
        Command::RecordAccess {
            access: Access::AttachmentDownloaded { field, hash },
        },
        None,
    )
    .await?;
    tx.commit().await?;
    let mut r = (StatusCode::OK, bytes).into_response();
    r.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(media));
    r.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment"),
    );
    Ok(r)
}

/// `GET /envelopes/{id}/documents/combined`: the sealed documents with the certificate
/// as one PDF. For an envelope of one document that is its sealed version (the
/// certificate is appended to it before sealing); several documents need a PDF merge
/// the engine does not have yet, and answer `409 CS-API-0009`, as does an envelope not
/// yet sealed.
pub(crate) async fn combined(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let mut l = find(&mut tx, &c.p, &id).await?;
    let [doc] = l.state.documents.as_slice() else {
        return Err(ApiError::not_available(
            "combining several documents into one PDF is not available yet",
        ));
    };
    let d = doc.id().clone();
    let versions = tx.documents().versions(DocumentId(uid(&d)?)).await?;
    let Some(v) = versions
        .iter()
        .rev()
        .find(|v| v.version.kind == VersionKind::Sealed)
    else {
        return Err(ApiError::not_available(
            "sealed when the envelope completes",
        ));
    };
    let sha = v.version.sha256;
    let access = Some(Access::DocumentDownloaded {
        document: d,
        hash: Hash256(sha),
    });
    serve_pdf(&c, tx, &mut l, sha, access).await
}

// Recipients ----------------------------------------------------------------------------

fn rec_in<'a>(
    s: &'a EnvelopeState,
    r: &str,
) -> Result<&'a casual_sign_workflow::RecipientState, ApiError> {
    s.recipients
        .iter()
        .find(|x| same_id(x.id(), r))
        .ok_or_else(ApiError::not_found)
}

/// `GET /envelopes/{id}/recipients`.
pub(crate) async fn recipients(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let l = find(&mut tx, &c.p, &id).await?;
    let items: Vec<Value> = l.state.recipients.iter().map(dto::recipient).collect();
    Ok(json_tagged(
        StatusCode::OK,
        &json!({ "items": items }),
        &dto::etag(&l.state),
    ))
}

/// `POST /envelopes/{id}/recipients`: one recipient, or `{"items": [...]}`.
pub(crate) async fn add_recipients(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    c.p.require("envelopes:write")?;
    let mut tx = c.tx().await?;
    let mut l = find(&mut tx, &c.p, &id).await?;
    let v = expected(&c, false)?;
    let raw: Value = parse(&body)?;
    let list: Vec<RecipientIn> = match raw.get("items") {
        Some(items) => {
            serde_json::from_value(items.clone()).map_err(|_| ApiError::invalid("/items"))?
        }
        None => vec![serde_json::from_value(raw).map_err(|_| ApiError::invalid(""))?],
    };
    let (changes, _, codes) = recipients_in(&mut tx, &list, "/items").await?;
    let ids: Vec<Id> = changes
        .iter()
        .filter_map(|ch| match ch {
            Change::AddRecipient { recipient } => Some(recipient.id.clone()),
            _ => None,
        })
        .collect();
    change(&c, &mut tx, &mut l, changes, v).await?;
    store_codes(&mut tx, codes).await?;
    tx.commit().await?;
    let items: Vec<Value> = ids
        .iter()
        .filter_map(|i| l.state.recipient(i))
        .map(dto::recipient)
        .collect();
    Ok(json_tagged(
        StatusCode::CREATED,
        &json!({ "items": items }),
        &dto::etag(&l.state),
    ))
}

/// `GET /envelopes/{id}/recipients/{r}`.
pub(crate) async fn recipient(
    c: Call,
    Path((id, r)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let l = find(&mut tx, &c.p, &id).await?;
    let x = rec_in(&l.state, &r)?;
    Ok(json_tagged(
        StatusCode::OK,
        &dto::recipient(x),
        &dto::etag(&l.state),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipientPatch {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    routing_order: Option<u32>,
    /// A new type (row UX-12): a draft only; a correction keeps the type, which the
    /// engine enforces.
    #[serde(default, rename = "type")]
    rtype: Option<casual_sign_model::RecipientType>,
    #[serde(default)]
    auth: Option<Vec<casual_sign_audit::AuthMethod>>,
    /// A new access code (row WEB-04); stored only as Argon2id, never returned.
    #[serde(default)]
    access_code: Option<String>,
}

/// `PATCH /envelopes/{id}/recipients/{r}`: name, email, routing order, type (a draft
/// only), authentication and the access code, while the envelope is a draft or being corrected (the engine
/// refuses the change otherwise, and then no code is stored).
///
/// The access code follows the authentication methods it ends up with: `access_code`
/// among them needs a code, given here or set before; a code given without the method
/// is refused; dropping the method deletes the stored code.
pub(crate) async fn patch_recipient(
    c: Call,
    Path((id, r)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    c.p.require("envelopes:write")?;
    let mut tx = c.tx().await?;
    let mut l = find(&mut tx, &c.p, &id).await?;
    let mut spec = rec_in(&l.state, &r)?.spec.clone();
    let v = expected(&c, true)?;
    let req: RecipientPatch = parse(&body)?;
    if let Some(n) = &req.name {
        if n.trim().is_empty() || n.chars().count() > 255 {
            return Err(ApiError::invalid("/name"));
        }
        spec.name = Personal(
            casual_sign_model::Text::new(n.trim()).map_err(|_| ApiError::invalid("/name"))?,
        );
    }
    if let Some(e) = &req.email {
        if e.len() < 3 || e.len() > 320 || !e.contains('@') {
            return Err(ApiError::invalid("/email"));
        }
        spec.email = Personal(
            casual_sign_model::Text::new(e.as_str()).map_err(|_| ApiError::invalid("/email"))?,
        );
    }
    if let Some(o) = req.routing_order {
        spec.routing_order = casual_sign_model::RoutingOrder::new(o)
            .map_err(|_| ApiError::invalid("/routing_order"))?;
    }
    if let Some(t) = req.rtype {
        spec.rtype = t;
    }
    let had_code = spec
        .auth
        .contains(&casual_sign_audit::AuthMethod::AccessCode);
    if let Some(a) = req.auth {
        spec.auth = a;
    }
    let wants_code = spec
        .auth
        .contains(&casual_sign_audit::AuthMethod::AccessCode);
    let code = req.access_code.filter(|c| !c.is_empty());
    let refused = match &code {
        Some(c) => !wants_code || c.chars().count() > 255,
        None => wants_code && !had_code,
    };
    if refused {
        return Err(ApiError::invalid("/access_code"));
    }
    let rid = spec.id.clone();
    change(
        &c,
        &mut tx,
        &mut l,
        vec![Change::UpdateRecipient { recipient: spec }],
        v,
    )
    .await?;
    let stored = RecipientId(uid(&rid)?);
    if let Some(code) = code {
        store_codes(&mut tx, vec![(stored, code)]).await?;
    } else if had_code && !wants_code {
        tx.recipients().clear_access_code(stored).await?;
    }
    tx.commit().await?;
    let x = l.state.recipient(&rid).ok_or_else(ApiError::not_found)?;
    Ok(json_tagged(
        StatusCode::OK,
        &dto::recipient(x),
        &dto::etag(&l.state),
    ))
}

/// `DELETE /envelopes/{id}/recipients/{r}`.
pub(crate) async fn delete_recipient(
    c: Call,
    Path((id, r)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    c.p.require("envelopes:write")?;
    let mut tx = c.tx().await?;
    let mut l = find(&mut tx, &c.p, &id).await?;
    let rid = rec_in(&l.state, &r)?.id().clone();
    let v = expected(&c, true)?;
    change(
        &c,
        &mut tx,
        &mut l,
        vec![Change::RemoveRecipient { id: rid }],
        v,
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// Fields --------------------------------------------------------------------------------

fn field_in<'a>(s: &'a EnvelopeState, f: &str) -> Result<&'a casual_sign_model::Field, ApiError> {
    s.fields
        .0
        .iter()
        .find(|x| same_id(&x.id, f))
        .ok_or_else(ApiError::not_found)
}

/// `GET /envelopes/{id}/fields?recipient_id=&document_id=`.
pub(crate) async fn fields(
    c: Call,
    Path(id): Path<String>,
    Query(q): Query<BTreeMap<String, String>>,
) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let l = find(&mut tx, &c.p, &id).await?;
    let items: Vec<Value> = l
        .state
        .fields
        .0
        .iter()
        .filter(|f| {
            q.get("recipient_id")
                .is_none_or(|r| f.recipient_id.as_ref().is_some_and(|x| x.as_str() == r))
        })
        .filter(|f| {
            q.get("document_id")
                .is_none_or(|d| f.document_id.as_str() == d)
        })
        .map(dto::field)
        .collect();
    Ok(json_tagged(
        StatusCode::OK,
        &json!({ "items": items }),
        &dto::etag(&l.state),
    ))
}

/// `POST /envelopes/{id}/fields`: one field, or `{"items": [...]}` (a batch).
pub(crate) async fn add_fields(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    c.p.require("envelopes:write")?;
    let mut tx = c.tx().await?;
    let mut l = find(&mut tx, &c.p, &id).await?;
    let v = expected(&c, false)?;
    let raw: Value = parse(&body)?;
    let list: Vec<Value> = match raw.get("items") {
        Some(Value::Array(items)) => items.clone(),
        Some(_) => return Err(ApiError::invalid("/items")),
        None => vec![raw],
    };
    let mut changes = Vec::new();
    let mut ids = Vec::new();
    for (i, f) in list.iter().enumerate() {
        let fid = new_id()?;
        let field = dto::field_from(
            f,
            fid.clone(),
            |r| Id::new(r).ok(),
            |d| d.as_str().and_then(|s| Id::new(s).ok()),
            &format!("/items/{i}"),
        )?;
        ids.push(fid);
        changes.push(Change::AddField {
            field: Personal(field),
        });
    }
    change(&c, &mut tx, &mut l, changes, v).await?;
    tx.commit().await?;
    let items: Vec<Value> = l
        .state
        .fields
        .0
        .iter()
        .filter(|f| ids.contains(&f.id))
        .map(dto::field)
        .collect();
    Ok(json_tagged(
        StatusCode::CREATED,
        &json!({ "items": items }),
        &dto::etag(&l.state),
    ))
}

/// `GET /envelopes/{id}/fields/{f}`.
pub(crate) async fn field(
    c: Call,
    Path((id, f)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let l = find(&mut tx, &c.p, &id).await?;
    let x = field_in(&l.state, &f)?;
    Ok(json_tagged(
        StatusCode::OK,
        &dto::field(x),
        &dto::etag(&l.state),
    ))
}

/// `PATCH /envelopes/{id}/fields/{f}`: a JSON merge of the field's wire form (its
/// id, document and recipient stay unless named).
pub(crate) async fn patch_field(
    c: Call,
    Path((id, f)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    c.p.require("envelopes:write")?;
    let mut tx = c.tx().await?;
    let mut l = find(&mut tx, &c.p, &id).await?;
    let current = field_in(&l.state, &f)?.clone();
    let v = expected(&c, true)?;
    let patch: Value = parse(&body)?;
    let Value::Object(patch) = patch else {
        return Err(ApiError::invalid(""));
    };
    let mut merged = dto::field(&current);
    if let Value::Object(m) = &mut merged {
        m.remove("id");
        for (k, val) in patch {
            if k == "id" {
                return Err(ApiError::invalid("/id"));
            }
            if val.is_null() {
                m.remove(&k);
            } else {
                m.insert(k, val);
            }
        }
    }
    let field = dto::field_from(
        &merged,
        current.id.clone(),
        |r| Id::new(r).ok(),
        |d| d.as_str().and_then(|s| Id::new(s).ok()),
        "",
    )?;
    change(
        &c,
        &mut tx,
        &mut l,
        vec![Change::UpdateField {
            field: Personal(field),
        }],
        v,
    )
    .await?;
    tx.commit().await?;
    let x = field_in(&l.state, &f)?;
    Ok(json_tagged(
        StatusCode::OK,
        &dto::field(x),
        &dto::etag(&l.state),
    ))
}

/// `DELETE /envelopes/{id}/fields/{f}`.
pub(crate) async fn delete_field(
    c: Call,
    Path((id, f)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    c.p.require("envelopes:write")?;
    let mut tx = c.tx().await?;
    let mut l = find(&mut tx, &c.p, &id).await?;
    let fid = field_in(&l.state, &f)?.id.clone();
    let v = expected(&c, true)?;
    change(
        &c,
        &mut tx,
        &mut l,
        vec![Change::RemoveField { id: fid }],
        v,
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `GET /envelopes/{id}/form-data`: every labelled field's value by its data label.
pub(crate) async fn form_data(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let l = find(&mut tx, &c.p, &id).await?;
    let mut out = serde_json::Map::new();
    for f in &l.state.fields.0 {
        if let (Some(label), Some(value)) = (&f.label, &f.value) {
            out.insert(
                label.as_str().to_owned(),
                serde_json::to_value(value).unwrap_or(Value::Null),
            );
        }
    }
    Ok(json(StatusCode::OK, &Value::Object(out)))
}

// Embedded signing ----------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewIn {
    recipient_id: String,
    #[serde(default)]
    auth_asserted: Option<String>,
}

/// `POST /envelopes/{id}/views/signing`: a single-use, five-minute ceremony link for
/// an embedded recipient (docs/40 §5). Only the API client that created the envelope
/// may ask (row WF-05, `CS-AUTH-0010`); its assertion of how it authenticated the
/// signer is recorded as `auth.asserted_by_host`.
pub(crate) async fn view_signing(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let mut l = find(&mut tx, &c.p, &id).await?;
    let req: ViewIn = parse(&body)?;
    let client = c.p.client().ok_or_else(ApiError::not_embedding_owner)?;
    if l.host_client != Some(client) {
        return Err(ApiError::not_embedding_owner());
    }
    let r = rec_in(&l.state, &req.recipient_id).map_err(|_| ApiError::invalid("/recipient_id"))?;
    if r.spec.embedded_client_user_id.is_none() {
        return Err(ApiError::invalid("/recipient_id"));
    }
    let rid = r.id().clone();
    if let Some(claim) = &req.auth_asserted {
        let mut cmds = c.commands(&mut tx).await?;
        let ctx = cmds.ctx(
            WfPrincipal::Host {
                client_id: eid(client.0)?,
            },
            None,
        )?;
        let claim = dto::message(claim)?;
        // The assertion needs the recipient to have opened: the host opening its view
        // for them is that opening (recorded with the host as actor).
        if l.state
            .recipient(&rid)
            .is_some_and(|r| r.status == casual_sign_model::RecipientStatus::Sent)
        {
            run(
                &mut tx,
                &mut l,
                &Command::OpenLink {
                    recipient: rid.clone(),
                },
                &ctx,
            )
            .await?;
        }
        let ctx = cmds.ctx(
            WfPrincipal::Host {
                client_id: eid(client.0)?,
            },
            None,
        )?;
        run(
            &mut tx,
            &mut l,
            &Command::HostAssertAuth {
                recipient: rid.clone(),
                claim,
            },
            &ctx,
        )
        .await?;
    }
    let token = random_secret()?;
    let expires = crate::state::plus_std(c.st.now(), c.st.config().view_ttl)?;
    tx.recipients()
        .issue_token(&NewToken {
            id: RecipientTokenId(Uuid::now_v7()),
            envelope_id: l.id,
            recipient_id: RecipientId(uid(&rid)?),
            token_sha256: sha256(token.as_bytes()),
            purpose: TokenPurpose::Embedded,
            host_user_id: None,
            expires_at: expires,
        })
        .await?;
    tx.commit().await?;
    let url = format!("{}/s/{token}", c.st.config().public_url);
    let mut r = json(
        StatusCode::CREATED,
        &json!({ "url": url, "expires_at": rfc3339(expires) }),
    );
    r.extensions_mut().insert(SecretBearing);
    Ok(r)
}

/// How long a hosted in-person link lives (UXW-36): one sitting at the host's desk.
/// Every call checks it, so the signing must finish within it; hosting again mints a
/// new one.
const IN_PERSON_TTL: std::time::Duration = std::time::Duration::from_secs(3600);

/// `POST /envelopes/{id}/recipients/{r}/host` (UXW-36, docs/24 §2): a member who may
/// send and may see the envelope hosts an in-person signer. The engine records
/// `recipient.in_person_hosted` with the member as host and actor (their sign-in as
/// the authentication), every earlier link of that recipient is revoked, and a
/// one-time ceremony link acting as this member hosting the signer is returned to the
/// caller only (`SecretBearing`). Another account's envelope is `404`; a recipient who
/// is not an in-person signer, or whose turn has not come or has passed, is the
/// engine's refusal.
pub(crate) async fn host_in_person(
    c: Call,
    Path((id, r)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    c.p.require("envelopes:send")?;
    if !body.iter().all(u8::is_ascii_whitespace) {
        let _: HostIn = parse(&body)?;
    }
    let mut tx = c.tx().await?;
    let mut l = find(&mut tx, &c.p, &id).await?;
    let rid = rec_in(&l.state, &r)?.id().clone();
    let mut cmds = c.commands(&mut tx).await?;
    let ctx = cmds.ctx(
        WfPrincipal::InPersonHost {
            user_id: eid(c.p.user.0)?,
        },
        None,
    )?;
    run(
        &mut tx,
        &mut l,
        &Command::HostInPerson {
            recipient: rid.clone(),
        },
        &ctx,
    )
    .await?;
    let now = c.st.now();
    let recipient = RecipientId(uid(&rid)?);
    tx.recipients().revoke_tokens(recipient, now).await?;
    let token = random_secret()?;
    let expires = crate::state::plus_std(now, IN_PERSON_TTL)?;
    tx.recipients()
        .issue_token(&NewToken {
            id: RecipientTokenId(Uuid::now_v7()),
            envelope_id: l.id,
            recipient_id: recipient,
            token_sha256: sha256(token.as_bytes()),
            purpose: TokenPurpose::InPerson,
            host_user_id: Some(c.p.user),
            expires_at: expires,
        })
        .await?;
    tx.commit().await?;
    let url = format!("{}/s/{token}", c.st.config().public_url);
    let mut resp = json(
        StatusCode::CREATED,
        &json!({ "url": url, "expires_at": rfc3339(expires) }),
    );
    resp.extensions_mut().insert(SecretBearing);
    Ok(resp)
}

/// The body of `…/host` and `…/sign-link`: empty, or an empty object.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostIn {}

/// Whether the signed-in member with `email` is recipient `r` for the Inbox: the same
/// address ignoring case, and a recipient who acts through a link (not a copy, an
/// in-person signer whose link only a host obtains, or an embedded recipient whose
/// links only the embedding host obtains). The store's Inbox query applies the same
/// rule.
fn is_me(r: &casual_sign_workflow::RecipientState, email: &str) -> bool {
    use casual_sign_model::RecipientType as T;
    !matches!(r.spec.rtype, T::Cc | T::InPersonSigner)
        && r.spec.embedded_client_user_id.is_none()
        && r.spec.email.get().as_str().to_lowercase() == email
}

/// How long an Inbox signing link lives (UXW-01): it is used at once, in the browser
/// that asked, and binds to that browser on first use.
const SIGN_LINK_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// `POST /envelopes/{id}/sign-link` (UXW-01): a signed-in member signs, approves or
/// views an envelope of this account that waits for them as a recipient, from inside
/// the app. The caller must be, by their account email, a recipient whose turn it is
/// and who acts through a link; the answer is a one-time ceremony link (`{url,
/// expires_at}`, five minutes, `SecretBearing`) of purpose `account` naming the member.
/// The ceremony then records the member's sign-in (`account_login`) as how the link was
/// obtained, instead of an emailed link, and applies every authentication the sender
/// required, as for an emailed link. An envelope the caller neither may see nor is a
/// recipient of is `404`; one where they are a recipient whose turn has not come, or
/// has passed, is `409 CS-WF-0007`. Issuing a link changes nothing in the envelope.
pub(crate) async fn sign_link(
    c: Call,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let l = crate::apply::load(&mut tx, EnvelopeId(path_id(&id)?))
        .await?
        .ok_or_else(ApiError::not_found)?;
    let member = tx
        .users()
        .get(c.p.user)
        .await?
        .filter(|m| m.disabled_at.is_none())
        .ok_or_else(ApiError::not_found)?;
    let email = member.email.get().to_lowercase();
    let mine: Vec<&casual_sign_workflow::RecipientState> = l
        .state
        .recipients
        .iter()
        .filter(|r| is_me(r, &email))
        .collect();
    if mine.is_empty() && !super::visible(&c.p, &l.state) {
        return Err(ApiError::not_found());
    }
    // The person signs in themselves: an API key or OAuth client, which may act for a
    // member without them, never obtains a link that records their sign-in.
    if c.p.client().is_some() {
        return Err(ApiError::forbidden("a signed-in session"));
    }
    if !body.iter().all(u8::is_ascii_whitespace) {
        let _: HostIn = parse(&body)?;
    }
    let live = matches!(l.state.status, MStatus::Sent | MStatus::Delivered);
    let mut turn: Vec<&&casual_sign_workflow::RecipientState> = mine
        .iter()
        .filter(|r| live && r.status.is_active())
        .collect();
    turn.sort_by_key(|r| r.spec.routing_order);
    let r = turn.first().ok_or_else(ApiError::not_reached)?;
    let token = random_secret()?;
    let expires = crate::state::plus_std(c.st.now(), SIGN_LINK_TTL)?;
    tx.recipients()
        .issue_token(&NewToken {
            id: RecipientTokenId(Uuid::now_v7()),
            envelope_id: l.id,
            recipient_id: RecipientId(uid(r.id())?),
            token_sha256: sha256(token.as_bytes()),
            purpose: TokenPurpose::Account,
            host_user_id: Some(c.p.user),
            expires_at: expires,
        })
        .await?;
    tx.commit().await?;
    let url = format!("{}/s/{token}", c.st.config().public_url);
    let mut resp = json(
        StatusCode::CREATED,
        &json!({ "url": url, "expires_at": rfc3339(expires) }),
    );
    resp.extensions_mut().insert(SecretBearing);
    Ok(resp)
}

/// For tests and the worker's own use: issue an invitation token for a recipient of
/// an envelope (the worker mints the invitation's token when it sends the email,
/// stage 2D). Returns the token.
///
/// # Errors
///
/// Store errors.
pub async fn issue_invitation_token(
    st: &AppState,
    account: casual_sign_store::AccountId,
    envelope: EnvelopeId,
    recipient: RecipientId,
    ttl: std::time::Duration,
) -> Result<String, ApiError> {
    let token = random_secret()?;
    let mut tx = st.store().for_account(account).begin().await?;
    tx.recipients()
        .issue_token(&NewToken {
            id: RecipientTokenId(Uuid::now_v7()),
            envelope_id: envelope,
            recipient_id: recipient,
            token_sha256: sha256(token.as_bytes()),
            purpose: TokenPurpose::Invitation,
            host_user_id: None,
            expires_at: crate::state::plus_std(st.now(), ttl)?,
        })
        .await?;
    tx.commit().await?;
    Ok(token)
}

#[allow(dead_code)]
fn _unused(_: UserId, _: &str) {
    let _ = path_id;
}
