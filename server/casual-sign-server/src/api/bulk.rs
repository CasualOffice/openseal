//! Bulk send from a template (UXW-04, docs/40 §3): a list of recipient sets, given as
//! a CSV file's text or as JSON rows, becomes one envelope per row, each made and sent
//! exactly as `POST /envelopes` makes and sends one (`envelopes::create_in`).
//!
//! - `POST /bulk-sends` checks every row against the template's columns and makes the
//!   batch: a row with a problem is stored as `failed` with its problems and never sent.
//!   With `validate_only` nothing is stored and the check is answered.
//! - `POST /bulk-sends/{id}/send` sends the next rows, at most [`SEND_STEP`] per call,
//!   each in its own transaction, and answers the batch: the caller repeats it until no
//!   row is pending, which is the progress the web app shows. A row the engine refuses
//!   is `failed` with the refusal's code; the other rows go on.
//! - `POST /bulk-sends/{id}/cancel` stops a batch: its pending rows are not sent.
//!
//! The columns are two per template role, in the template's role order:
//! `<role>::name` and `<role>::email`, matched ignoring case and surrounding spaces.
//! Row values are personal data: never logged, and problems name a column and a code.

use std::collections::BTreeMap;

use axum::body::Bytes;
use axum::extract::{Path, Query};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use casual_sign_audit::Personal;
use casual_sign_store::repo::bulk_sends::{BulkRow, BulkSend, NewRow, RowStatus};
use casual_sign_store::repo::templates::{Template, TemplateDocument, TemplateField, TemplateRole};
use casual_sign_store::{BulkSendId, BulkSendRowId, StoreError, TemplateId, TenantTx};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::envelopes::{create_in, rfc3339};
use super::{json, path_id};
use crate::call::Call;
use crate::dto::{EnvelopeCreate, parse};
use crate::error::{ApiError, FieldProblem};

/// The most rows one bulk send takes (docs/21).
pub(crate) const MAX_ROWS: usize = 1000;
/// The most rows one `POST …/send` sends.
pub(crate) const SEND_STEP: usize = 10;
/// The most bulk sends one list answers.
const MAX_LIST: i64 = 100;

/// A required value is empty.
const MISSING: &str = "CS-BLK-0001";
/// An email address that cannot be one.
const BAD_EMAIL: &str = "CS-BLK-0002";
/// A name over 255 characters or with control characters.
const BAD_NAME: &str = "CS-BLK-0003";
/// A column the template needs is not in the list.
const MISSING_COLUMN: &str = "CS-BLK-0004";
/// A column the template does not have, or one given twice.
const UNKNOWN_COLUMN: &str = "CS-BLK-0005";
/// A CSV row with more values than the header has columns.
const ROW_SHAPE: &str = "CS-BLK-0006";
/// No row, more than [`MAX_ROWS`], or CSV that cannot be read.
const BAD_LIST: &str = "CS-BLK-0007";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BulkCreate {
    template_id: String,
    #[serde(default)]
    name: Option<String>,
    /// The list as CSV text: a header row, then one row per envelope.
    #[serde(default)]
    csv: Option<String>,
    /// The list as JSON: each row an object from column to value.
    #[serde(default)]
    rows: Option<Vec<BTreeMap<String, String>>>,
    /// Check only: nothing is stored or sent.
    #[serde(default)]
    validate_only: bool,
}

// CSV -----------------------------------------------------------------------------------

/// RFC 4180 records: commas, double-quoted values with `""` for a quote, CRLF or LF line
/// ends, a leading byte-order mark ignored, lines with no value in any cell skipped. At most `max_records`
/// records are read; `None` when there are more, or a quote is never closed.
pub(crate) fn csv_records(text: &str, max_records: usize) -> Option<Vec<Vec<String>>> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut out: Vec<Vec<String>> = Vec::new();
    let mut record: Vec<String> = Vec::new();
    let mut cell = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    let finish = |record: &mut Vec<String>, out: &mut Vec<Vec<String>>| -> bool {
        // A line of empty cells (",,," as a spreadsheet writes its unused rows) is blank.
        let blank = record.iter().all(|c| c.trim().is_empty());
        if !blank {
            if out.len() >= max_records {
                return false;
            }
            out.push(std::mem::take(record));
        }
        record.clear();
        true
    };
    while let Some(ch) = chars.next() {
        if quoted {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    cell.push('"');
                } else {
                    quoted = false;
                }
            } else {
                cell.push(ch);
            }
            continue;
        }
        match ch {
            '"' if cell.is_empty() => quoted = true,
            ',' => record.push(std::mem::take(&mut cell)),
            '\r' if chars.peek() == Some(&'\n') => {}
            '\n' | '\r' => {
                record.push(std::mem::take(&mut cell));
                if !finish(&mut record, &mut out) {
                    return None;
                }
            }
            _ => cell.push(ch),
        }
    }
    if quoted {
        return None;
    }
    if !cell.is_empty() || !record.is_empty() {
        record.push(cell);
        if !finish(&mut record, &mut out) {
            return None;
        }
    }
    Some(out)
}

// Checking rows ------------------------------------------------------------------------

/// The columns of a template's list: two per role, in role order.
pub(crate) fn columns(roles: &[TemplateRole]) -> Vec<String> {
    roles
        .iter()
        .flat_map(|r| [format!("{}::name", r.name), format!("{}::email", r.name)])
        .collect()
}

fn column_key(s: &str) -> String {
    s.trim().to_lowercase()
}

/// One row's problem: a column of [`columns`] (or none, for the whole row) and a code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Problem {
    column: Option<String>,
    code: &'static str,
}

fn problem_json(p: &Problem) -> Value {
    json!({"column": p.column, "code": p.code})
}

/// A checked row: the recipients for each role and its problems (none: it can be sent).
#[derive(Debug, Clone)]
pub(crate) struct Checked {
    recipients: Vec<(String, String)>,
    problems: Vec<Problem>,
}

fn bad_email(e: &str) -> bool {
    let mut parts = e.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return true;
    };
    e.len() > 320
        || local.is_empty()
        || domain.is_empty()
        || e.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn bad_name(n: &str) -> bool {
    n.chars().count() > 255 || n.chars().any(char::is_control)
}

/// Check one row's values (by [`columns`] position) for the template's roles.
pub(crate) fn check_row(roles: &[TemplateRole], values: &[String], shape: bool) -> Checked {
    let cols = columns(roles);
    let mut recipients = Vec::with_capacity(roles.len());
    let mut problems = Vec::new();
    if !shape {
        problems.push(Problem {
            column: None,
            code: ROW_SHAPE,
        });
    }
    for (i, _) in roles.iter().enumerate() {
        let at = |k: usize| values.get(k).map_or("", |v| v.trim()).to_owned();
        let (ni, ei) = (i.saturating_mul(2), i.saturating_mul(2).saturating_add(1));
        let (name, email) = (at(ni), at(ei));
        let name_problem = if name.is_empty() {
            Some(MISSING)
        } else if bad_name(&name) {
            Some(BAD_NAME)
        } else {
            None
        };
        let email_problem = if email.is_empty() {
            Some(MISSING)
        } else if bad_email(&email) {
            Some(BAD_EMAIL)
        } else {
            None
        };
        for (k, p) in [(ni, name_problem), (ei, email_problem)] {
            if let Some(code) = p {
                problems.push(Problem {
                    column: cols.get(k).cloned(),
                    code,
                });
            }
        }
        recipients.push((name, email));
    }
    Checked {
        recipients,
        problems,
    }
}

/// The rows of a request as values in [`columns`] order, each with whether its shape
/// was right; or the problems that refuse the whole list.
fn rows_of(req: &BulkCreate, roles: &[TemplateRole]) -> Result<Vec<(Vec<String>, bool)>, ApiError> {
    let cols = columns(roles);
    let want: BTreeMap<String, usize> = cols
        .iter()
        .enumerate()
        .map(|(i, c)| (column_key(c), i))
        .collect();
    let refuse = |pointer: &str, code: &'static str| {
        ApiError::invalid(pointer).fields(vec![FieldProblem {
            pointer: pointer.to_owned(),
            code,
        }])
    };
    // Where each given column goes, or the problems with the header.
    let place = |header: &[String], at: &str| -> Result<Vec<Option<usize>>, ApiError> {
        let mut seen = vec![false; cols.len()];
        let mut map = Vec::with_capacity(header.len());
        let mut problems = Vec::new();
        for (i, h) in header.iter().enumerate() {
            match want.get(&column_key(h)) {
                Some(&k) if !seen.get(k).copied().unwrap_or(true) => {
                    if let Some(s) = seen.get_mut(k) {
                        *s = true;
                    }
                    map.push(Some(k));
                }
                _ => {
                    problems.push(FieldProblem {
                        pointer: format!("{at}/{i}"),
                        code: UNKNOWN_COLUMN,
                    });
                    map.push(None);
                }
            }
        }
        let missing = seen.iter().filter(|s| !**s).count();
        if missing > 0 {
            problems.push(FieldProblem {
                pointer: "/columns".into(),
                code: MISSING_COLUMN,
            });
        }
        if problems.is_empty() {
            Ok(map)
        } else {
            Err(ApiError::invalid("/columns")
                .fields(problems)
                .detail(format!("{missing} missing")))
        }
    };
    let spread = |map: &[Option<usize>], cells: &[String]| -> Vec<String> {
        let mut out = vec![String::new(); cols.len()];
        for (j, cell) in cells.iter().enumerate() {
            if let Some(Some(k)) = map.get(j)
                && let Some(slot) = out.get_mut(*k)
            {
                slot.clone_from(cell);
            }
        }
        out
    };
    let rows = match (&req.csv, &req.rows) {
        (Some(text), None) => {
            let recs = csv_records(text, MAX_ROWS.saturating_add(1))
                .ok_or_else(|| refuse("/csv", BAD_LIST))?;
            let mut it = recs.into_iter();
            let header = it.next().ok_or_else(|| refuse("/csv", BAD_LIST))?;
            let map = place(&header, "/columns")?;
            it.map(|cells| {
                let shape = cells.len() <= header.len();
                (spread(&map, &cells), shape)
            })
            .collect::<Vec<_>>()
        }
        (None, Some(list)) => {
            if list.len() > MAX_ROWS {
                return Err(refuse("/rows", BAD_LIST));
            }
            let mut out = Vec::with_capacity(list.len());
            for (i, row) in list.iter().enumerate() {
                let header: Vec<String> = row.keys().cloned().collect();
                let cells: Vec<String> = row.values().cloned().collect();
                let map = place(&header, &format!("/rows/{i}"))?;
                out.push((spread(&map, &cells), true));
            }
            out
        }
        _ => return Err(ApiError::invalid("/csv")),
    };
    if rows.is_empty() || rows.len() > MAX_ROWS {
        return Err(refuse(
            if req.csv.is_some() { "/csv" } else { "/rows" },
            BAD_LIST,
        ));
    }
    Ok(rows)
}

// Building envelopes -------------------------------------------------------------------

/// The one-call create request for one row: the template's subject, message, roles as
/// recipients with the row's names and emails, and every role-bound field.
fn envelope_request(
    t: &Template,
    roles: &[TemplateRole],
    docs: &[TemplateDocument],
    fields: &[TemplateField],
    recipients: &[(String, String)],
) -> Result<EnvelopeCreate, ApiError> {
    let reference = |i: usize| format!("role{i}");
    let rs: Vec<Value> = roles
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let (name, email) = recipients.get(i).cloned().unwrap_or_default();
            json!({
                "ref": reference(i), "type": r.kind.as_str(), "name": name, "email": email,
                "routing_order": r.routing_order,
            })
        })
        .collect();
    let mut fs = Vec::with_capacity(fields.len());
    for f in fields {
        let (Some(ri), Some(di)) = (
            roles.iter().position(|r| r.id == f.role_id),
            docs.iter().position(|d| d.id == f.template_document_id),
        ) else {
            continue;
        };
        let mut v = f.spec.get().clone();
        if let Some(o) = v.as_object_mut() {
            o.remove("id");
            o.insert("recipient_id".into(), json!(reference(ri)));
            o.insert("document_id".into(), json!(di));
        }
        fs.push(v);
    }
    let subject = t
        .email_subject
        .as_ref()
        .map(|s| s.get().clone())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| t.name.clone());
    let message = t
        .email_message
        .as_ref()
        .map(|s| s.get().clone())
        .unwrap_or_default();
    serde_json::from_value(json!({
        "subject": subject.chars().take(255).collect::<String>(), "message": message,
        "status": "sent", "recipients": rs, "fields": fs,
    }))
    .map_err(|_| ApiError::internal("bulk request"))
}

/// The recipients a stored row holds, by role position.
fn stored_recipients(row: &BulkRow) -> Vec<(String, String)> {
    row.input
        .get()
        .get("recipients")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|r| {
                    let s = |k: &str| r.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
                    (s("name"), s("email"))
                })
                .collect()
        })
        .unwrap_or_default()
}

// Answers ------------------------------------------------------------------------------

fn send_json(b: &BulkSend) -> Value {
    json!({
        "id": b.id.to_string(), "name": b.name.get(), "template_id": b.template_id.to_string(),
        "sender_user_id": b.sender_user_id.to_string(), "status": b.status.as_str(),
        "row_count": b.row_count,
        "counts": {"pending": b.pending, "sent": b.sent, "failed": b.failed, "cancelled": b.cancelled},
        "created_at": rfc3339(b.created_at), "finished_at": b.finished_at.map(rfc3339),
    })
}

fn row_json(r: &BulkRow) -> Value {
    let input = r.input.get();
    json!({
        "row": r.row_index, "status": r.status.as_str(),
        "envelope_id": r.envelope_id.map(|e| e.to_string()), "error_code": r.error_code,
        "recipients": input.get("recipients").cloned().unwrap_or_else(|| json!([])),
        "problems": input.get("problems").cloned().unwrap_or_else(|| json!([])),
    })
}

async fn with_rows(tx: &mut TenantTx, b: &BulkSend) -> Result<Value, ApiError> {
    let rows = tx.bulk_sends().rows(b.id).await?;
    let mut v = send_json(b);
    if let Some(o) = v.as_object_mut() {
        o.insert(
            "rows".into(),
            Value::Array(rows.iter().map(row_json).collect()),
        );
    }
    Ok(v)
}

/// Only the caller's own, unless they may see every envelope.
fn sender_filter(c: &Call) -> Option<casual_sign_store::UserId> {
    (!(c.p.admin || c.p.view_all)).then_some(c.p.user)
}

async fn visible(tx: &mut TenantTx, c: &Call, id: &str) -> Result<BulkSend, ApiError> {
    let id = BulkSendId(path_id(id)?);
    tx.bulk_sends()
        .get(id, sender_filter(c))
        .await?
        .ok_or_else(ApiError::not_found)
}

struct Loaded {
    template: Template,
    roles: Vec<TemplateRole>,
    docs: Vec<TemplateDocument>,
    fields: Vec<TemplateField>,
}

async fn load_template(tx: &mut TenantTx, id: TemplateId) -> Result<Option<Loaded>, ApiError> {
    let Some(template) = tx.templates().get(id).await? else {
        return Ok(None);
    };
    let roles = tx.templates().roles(id).await?;
    let docs = tx.templates().documents(id).await?;
    let fields = tx.templates().fields(id).await?;
    Ok(Some(Loaded {
        template,
        roles,
        docs,
        fields,
    }))
}

// Handlers -----------------------------------------------------------------------------

/// `POST /bulk-sends {template_id, name?, csv | rows, validate_only?}`.
pub(crate) async fn create(c: Call, body: Bytes) -> Result<Response, ApiError> {
    // Each row becomes a sent envelope: what `POST /envelopes` with `status: sent` needs.
    c.p.require("envelopes:write")?;
    c.p.require("envelopes:send")?;
    let req: BulkCreate = parse(&body)?;
    let tid = TemplateId(
        Uuid::parse_str(&req.template_id).map_err(|_| ApiError::invalid("/template_id"))?,
    );
    let mut tx = c.tx().await?;
    // A template the caller may not use (UXW-06) is as one that does not exist.
    if tx
        .templates()
        .access(tid, c.p.user, c.p.admin)
        .await?
        .is_none()
    {
        return Err(ApiError::invalid("/template_id"));
    }
    let t = load_template(&mut tx, tid)
        .await?
        .ok_or_else(|| ApiError::invalid("/template_id"))?;
    // A template with nothing to sign or no one to send it to makes no envelope.
    if t.docs.is_empty() || t.roles.is_empty() {
        return Err(ApiError::invalid("/template_id").detail(format!(
            "{} documents, {} roles",
            t.docs.len(),
            t.roles.len()
        )));
    }
    let name = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map_or_else(|| t.template.name.clone(), str::to_owned);
    if name.chars().count() > 255 || name.chars().any(char::is_control) {
        return Err(ApiError::invalid("/name"));
    }
    let cols = columns(&t.roles);
    let rows = rows_of(&req, &t.roles)?;
    let checked: Vec<Checked> = rows
        .iter()
        .map(|(values, shape)| check_row(&t.roles, values, *shape))
        .collect();
    let recipients_json = |ch: &Checked| -> Value {
        Value::Array(
            t.roles
                .iter()
                .zip(&ch.recipients)
                .map(|(r, (n, e))| json!({"role": r.name, "name": n, "email": e}))
                .collect(),
        )
    };
    if req.validate_only {
        tx.commit().await?;
        let valid = checked.iter().filter(|ch| ch.problems.is_empty()).count();
        let items: Vec<Value> = checked
            .iter()
            .enumerate()
            .map(|(i, ch)| {
                json!({
                    "row": i,
                    "status": if ch.problems.is_empty() { "pending" } else { "failed" },
                    "recipients": recipients_json(ch),
                    "problems": ch.problems.iter().map(problem_json).collect::<Vec<_>>(),
                })
            })
            .collect();
        return Ok(json(
            StatusCode::OK,
            &json!({"columns": cols, "row_count": checked.len(), "valid": valid, "rows": items}),
        ));
    }
    let id = BulkSendId(Uuid::now_v7());
    let mut new_rows = Vec::with_capacity(checked.len());
    for (i, ch) in checked.iter().enumerate() {
        let ok = ch.problems.is_empty();
        new_rows.push(NewRow {
            id: BulkSendRowId(Uuid::now_v7()),
            row_index: i32::try_from(i).map_err(|_| ApiError::invalid("/rows"))?,
            input: Personal(json!({
                "recipients": recipients_json(ch),
                "problems": ch.problems.iter().map(problem_json).collect::<Vec<_>>(),
            })),
            status: if ok {
                RowStatus::Pending
            } else {
                RowStatus::Failed
            },
            error_code: ch.problems.first().map(|p| p.code.to_owned()),
        });
    }
    tx.bulk_sends()
        .create(id, c.p.user, tid, &name, &new_rows)
        .await?;
    tx.bulk_sends().settle(id, c.st.now()).await?;
    let b = tx
        .bulk_sends()
        .get(id, None)
        .await?
        .ok_or_else(|| ApiError::internal("bulk send"))?;
    let v = with_rows(&mut tx, &b).await?;
    tx.commit().await?;
    let mut r = json(StatusCode::CREATED, &v);
    if let Ok(h) = HeaderValue::from_str(&format!("/api/v1/bulk-sends/{id}")) {
        r.headers_mut().insert(header::LOCATION, h);
    }
    Ok(r)
}

/// The query of `GET /bulk-sends`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListQuery {
    limit: Option<i64>,
}

/// `GET /bulk-sends`: the caller's bulk sends (every one for an administrator or a
/// member who sees every envelope), newest first, without their rows.
pub(crate) async fn list(c: Call, Query(q): Query<ListQuery>) -> Result<Response, ApiError> {
    let limit = q.limit.unwrap_or(50);
    if !(1..=MAX_LIST).contains(&limit) {
        return Err(ApiError::invalid("/query/limit"));
    }
    let mut tx = c.tx().await?;
    let items = tx.bulk_sends().list(sender_filter(&c), None, limit).await?;
    tx.commit().await?;
    Ok(json(
        StatusCode::OK,
        &json!({"items": items.iter().map(send_json).collect::<Vec<_>>()}),
    ))
}

/// `GET /bulk-sends/{id}`: the batch, its counts and every row.
pub(crate) async fn get(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    let mut tx = c.tx().await?;
    let b = visible(&mut tx, &c, &id).await?;
    let v = with_rows(&mut tx, &b).await?;
    tx.commit().await?;
    Ok(json(StatusCode::OK, &v))
}

/// `POST /bulk-sends/{id}/send`: send the next pending rows, at most [`SEND_STEP`], each
/// in its own transaction; answers the batch with its rows. Only its sender sends it:
/// each envelope is theirs.
pub(crate) async fn send(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    c.p.require("envelopes:write")?;
    c.p.require("envelopes:send")?;
    let mut tx = c.tx().await?;
    let b = visible(&mut tx, &c, &id).await?;
    if b.sender_user_id != c.p.user {
        return Err(ApiError::forbidden("bulk:send"));
    }
    let t = load_template(&mut tx, b.template_id).await?;
    // The documents are read once for every row this call sends.
    let mut docs = Vec::new();
    if let Some(t) = &t {
        for d in &t.docs {
            let bytes =
                c.st.0
                    .blobs
                    .get(&casual_sign_store::blob::BlobKey(d.sha256))
                    .await?;
            docs.push((d.name.clone(), bytes.to_vec()));
        }
    }
    tx.commit().await?;
    for _ in 0..SEND_STEP {
        let mut tx = c.tx().await?;
        let Some(row) = tx.bulk_sends().claim(b.id).await? else {
            tx.commit().await?;
            break;
        };
        let outcome = match &t {
            None => Err(ApiError::not_found()),
            Some(t) => match envelope_request(
                &t.template,
                &t.roles,
                &t.docs,
                &t.fields,
                &stored_recipients(&row),
            ) {
                Err(e) => Err(e),
                Ok(req) => create_in(&c, &mut tx, &req, docs.clone(), true)
                    .await
                    .map(|(env, _)| env),
            },
        };
        match outcome {
            Ok(env) => {
                tx.bulk_sends().sent(b.id, row.id, env).await?;
                tx.commit().await?;
            }
            Err(e) => {
                tx.rollback().await?;
                let mut tx = c.tx().await?;
                match tx.bulk_sends().failed(row.id, e.code()).await {
                    // Another caller settled it meanwhile.
                    Ok(()) | Err(StoreError::NotFound { .. }) => {}
                    Err(other) => return Err(other.into()),
                }
                tx.commit().await?;
            }
        }
    }
    let mut tx = c.tx().await?;
    tx.bulk_sends().settle(b.id, c.st.now()).await?;
    let b = visible(&mut tx, &c, &id).await?;
    let v = with_rows(&mut tx, &b).await?;
    tx.commit().await?;
    Ok(json(StatusCode::OK, &v))
}

/// `POST /bulk-sends/{id}/cancel`: the pending rows are not sent; the sent envelopes
/// stay as they are (void them one by one). `409` once it completed or was cancelled.
pub(crate) async fn cancel(c: Call, Path(id): Path<String>) -> Result<Response, ApiError> {
    c.p.require("envelopes:send")?;
    let mut tx = c.tx().await?;
    let b = visible(&mut tx, &c, &id).await?;
    if b.sender_user_id != c.p.user && !c.p.admin {
        return Err(ApiError::forbidden("bulk:send"));
    }
    if !tx.bulk_sends().cancel(b.id, c.st.now()).await? {
        return Err(ApiError::wrong_state("bulk send finished"));
    }
    let b = visible(&mut tx, &c, &id).await?;
    let v = with_rows(&mut tx, &b).await?;
    tx.commit().await?;
    Ok(json(StatusCode::OK, &v))
}

#[cfg(test)]
// Tests may unwrap, index and panic (CLAUDE.md).
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn csv_reads_quotes_crlf_bom_and_skips_blank_lines() {
        let r = csv_records("\u{feff}a,\"b, \"\"c\"\"\"\r\n\r\nx,y\n", 10).unwrap();
        assert_eq!(r, vec![vec!["a", "b, \"c\""], vec!["x", "y"]]);
    }

    #[test]
    fn csv_refuses_an_open_quote_and_too_many_records() {
        assert!(csv_records("a,\"b\n", 10).is_none());
        assert!(csv_records("a\nb\nc\n", 2).is_none());
        assert_eq!(csv_records("a\nb\n", 2).unwrap().len(), 2);
    }

    #[test]
    fn csv_skips_a_line_of_empty_cells_as_a_spreadsheet_writes_it() {
        let r = csv_records("a,b\nx,y\n,\n , \n", 10).unwrap();
        assert_eq!(r, vec![vec!["a", "b"], vec!["x", "y"]]);
    }

    #[test]
    fn email_check() {
        assert!(!bad_email("ann@example.com"));
        for e in ["ann", "@x", "a@", "a@b@c", "a b@c", "a@b\u{7}"] {
            assert!(bad_email(e), "{e}");
        }
    }
}
