//! Workspace reports (`VS-06`, `UXW-25`, docs/96 FG-140; DocuSign's envelope, recipient
//! and usage reports): `GET /reports/{envelopes|recipients|usage}` over the envelopes
//! created in a window, of one sender when asked, as JSON or as CSV. Read-only; held by
//! `reports.read` (administrators by default). A CSV cell that a spreadsheet would read
//! as a formula is written as text (a leading `'`), so a subject or a name typed by
//! anyone cannot run in the reader's spreadsheet.

use axum::extract::{Path, Query};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use casual_sign_store::repo::reports::{MAX_OFFSET_MINUTES, MAX_ROWS, Window};
use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use super::envelopes::rfc3339;
use super::json;
use crate::authz::Action;
use crate::call::Call;
use crate::error::ApiError;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReportQuery {
    /// Created at or after (RFC 3339); by default, any time.
    from: Option<String>,
    /// Created before (RFC 3339); by default, any time.
    to: Option<String>,
    /// A sender's user id, or `me`.
    sender: Option<String>,
    /// `json` (the default) or `csv`.
    format: Option<String>,
    /// At most this many rows (1 to 10,000; the default).
    limit: Option<u32>,
}

fn instant(s: Option<&str>, at: &str) -> Result<Option<OffsetDateTime>, ApiError> {
    s.map(|t| {
        OffsetDateTime::parse(t, &time::format_description::well_known::Rfc3339)
            .map_err(|_| ApiError::invalid(at))
    })
    .transpose()
}

/// One CSV cell (RFC 4180): quoted when it holds a comma, quote or line break; text a
/// spreadsheet would take for a formula (`=`, `+`, `-`, `@`, tab, carriage return
/// first) gets a leading `'` (OWASP CSV injection).
pub(crate) fn cell(s: &str) -> String {
    let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{s}")
    } else {
        s.to_owned()
    };
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

fn csv_response(head: &str, rows: &[Vec<String>], truncated: bool) -> Response {
    let mut out = String::from(head);
    out.push_str("\r\n");
    for r in rows {
        let line: Vec<String> = r.iter().map(|c| cell(c)).collect();
        out.push_str(&line.join(","));
        out.push_str("\r\n");
    }
    let mut r = (StatusCode::OK, out).into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    if truncated {
        r.headers_mut()
            .insert("x-truncated", HeaderValue::from_static("true"));
    }
    r
}

/// `GET /reports/{kind}?from&to&sender&format&limit`: the envelope report (one row per
/// envelope), the recipient report (one row per recipient) or the usage report (one
/// row per sender, with how their envelopes stand). `truncated` (or `x-truncated` on
/// CSV) says the limit was reached.
pub(crate) async fn report(
    c: Call,
    Path(kind): Path<String>,
    Query(q): Query<ReportQuery>,
) -> Result<Response, ApiError> {
    let from = instant(q.from.as_deref(), "/query/from")?.unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let to = instant(q.to.as_deref(), "/query/to")?
        .unwrap_or_else(casual_sign_store::repo::envelopes::never_expires);
    if to <= from {
        return Err(ApiError::invalid("/query/to"));
    }
    let sender = match q.sender.as_deref() {
        None => None,
        Some("me") => Some(c.p.user.0),
        Some(s) => Some(Uuid::parse_str(s).map_err(|_| ApiError::invalid("/query/sender"))?),
    };
    let csv = match q.format.as_deref() {
        None | Some("json") => false,
        Some("csv") => true,
        Some(_) => return Err(ApiError::invalid("/query/format")),
    };
    let limit = q.limit.unwrap_or(MAX_ROWS);
    if !(1..=MAX_ROWS).contains(&limit) {
        return Err(ApiError::invalid("/query/limit"));
    }
    let w = Window { from, to, sender };
    let at = |t: Option<OffsetDateTime>| t.map(rfc3339).unwrap_or_default();
    let mut tx = c.tx().await?;
    match kind.as_str() {
        "envelopes" => {
            let rows = tx.reports().envelopes(w, limit).await?;
            let truncated = rows.len() == usize::try_from(limit).unwrap_or(usize::MAX);
            if csv {
                let lines: Vec<Vec<String>> = rows
                    .iter()
                    .map(|r| {
                        vec![
                            r.id.to_string(),
                            r.subject.clone(),
                            r.status.clone(),
                            r.sender_user_id.to_string(),
                            rfc3339(r.created_at),
                            at(r.sent_at),
                            at(r.completed_at),
                            at(r.voided_at),
                            at(r.expires_at),
                            r.recipients.to_string(),
                        ]
                    })
                    .collect();
                return Ok(csv_response(
                    "envelope_id,subject,status,sender_user_id,created_at,sent_at,completed_at,voided_at,expires_at,recipients",
                    &lines,
                    truncated,
                ));
            }
            let items: Vec<Value> = rows
                .iter()
                .map(|r| {
                    json!({
                        "envelope_id": r.id.to_string(), "subject": r.subject, "status": r.status,
                        "sender_user_id": r.sender_user_id.to_string(),
                        "created_at": rfc3339(r.created_at), "sent_at": r.sent_at.map(rfc3339),
                        "completed_at": r.completed_at.map(rfc3339), "voided_at": r.voided_at.map(rfc3339),
                        "expires_at": r.expires_at.map(rfc3339), "recipients": r.recipients,
                    })
                })
                .collect();
            Ok(json(
                StatusCode::OK,
                &json!({ "items": items, "truncated": truncated }),
            ))
        }
        "recipients" => {
            let rows = tx.reports().recipients(w, limit).await?;
            let truncated = rows.len() == usize::try_from(limit).unwrap_or(usize::MAX);
            if csv {
                let lines: Vec<Vec<String>> = rows
                    .iter()
                    .map(|r| {
                        vec![
                            r.envelope_id.to_string(),
                            r.subject.clone(),
                            r.envelope_status.clone(),
                            r.routing_order.to_string(),
                            r.name.clone(),
                            r.email.clone().unwrap_or_default(),
                            r.rtype.clone(),
                            r.status.clone(),
                        ]
                    })
                    .collect();
                return Ok(csv_response(
                    "envelope_id,subject,envelope_status,routing_order,name,email,type,status",
                    &lines,
                    truncated,
                ));
            }
            let items: Vec<Value> = rows
                .iter()
                .map(|r| {
                    json!({
                        "envelope_id": r.envelope_id.to_string(), "subject": r.subject,
                        "envelope_status": r.envelope_status, "routing_order": r.routing_order,
                        "name": r.name, "email": r.email, "type": r.rtype, "status": r.status,
                    })
                })
                .collect();
            Ok(json(
                StatusCode::OK,
                &json!({ "items": items, "truncated": truncated }),
            ))
        }
        "usage" => {
            let rows = tx.reports().usage(w).await?;
            if csv {
                let lines: Vec<Vec<String>> = rows
                    .iter()
                    .map(|r| {
                        vec![
                            r.sender_user_id.to_string(),
                            r.created.to_string(),
                            r.sent.to_string(),
                            r.completed.to_string(),
                            r.declined.to_string(),
                            r.voided.to_string(),
                            r.expired.to_string(),
                        ]
                    })
                    .collect();
                return Ok(csv_response(
                    "sender_user_id,created,sent,completed,declined,voided,expired",
                    &lines,
                    false,
                ));
            }
            let items: Vec<Value> = rows
                .iter()
                .map(|r| {
                    json!({
                        "sender_user_id": r.sender_user_id.to_string(), "created": r.created,
                        "sent": r.sent, "completed": r.completed, "declined": r.declined,
                        "voided": r.voided, "expired": r.expired,
                    })
                })
                .collect();
            Ok(json(
                StatusCode::OK,
                &json!({ "items": items, "truncated": false }),
            ))
        }
        _ => Err(ApiError::not_found()),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InsightsQuery {
    /// Created at or after (RFC 3339); by default, any time.
    from: Option<String>,
    /// Created before (RFC 3339); by default, any time.
    to: Option<String>,
    /// A sender's user id, or `me`.
    sender: Option<String>,
    /// The caller's offset from UTC in minutes, for the days of the series (default 0).
    utc_offset_minutes: Option<i32>,
}

/// `GET /insights?from&to&sender&utc_offset_minutes` (`FG-141`, DocuSign's Insights):
/// the dashboard's figures over the envelopes created in the window. A holder of
/// `reports.read` sees the workspace, of `sender` when given; anyone else their own
/// envelopes only, and naming another sender is `403`. Aggregates only: no subject, name
/// or address is in the answer.
pub(crate) async fn insights(
    c: Call,
    Query(q): Query<InsightsQuery>,
) -> Result<Response, ApiError> {
    let from = instant(q.from.as_deref(), "/query/from")?.unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let to = instant(q.to.as_deref(), "/query/to")?
        .unwrap_or_else(casual_sign_store::repo::envelopes::never_expires);
    if to <= from {
        return Err(ApiError::invalid("/query/to"));
    }
    let offset = q.utc_offset_minutes.unwrap_or(0);
    if !(-MAX_OFFSET_MINUTES..=MAX_OFFSET_MINUTES).contains(&offset) {
        return Err(ApiError::invalid("/query/utc_offset_minutes"));
    }
    let named = match q.sender.as_deref() {
        None => None,
        Some("me") => Some(c.p.user.0),
        Some(s) => Some(Uuid::parse_str(s).map_err(|_| ApiError::invalid("/query/sender"))?),
    };
    // Without `reports.read`, one's own envelopes only.
    let workspace = c.p.actions.contains(&Action::ReportsRead);
    let sender = if workspace {
        named
    } else {
        match named {
            Some(s) if s != c.p.user.0 => return Err(ApiError::forbidden("reports.read")),
            _ => Some(c.p.user.0),
        }
    };
    let mut tx = c.tx().await?;
    let i = tx
        .reports()
        .insights(Window { from, to, sender }, offset)
        .await?;
    Ok(json(
        StatusCode::OK,
        &json!({
            "scope": if workspace { "workspace" } else { "own" },
            "from": q.from.as_ref().map(|_| rfc3339(from)),
            "to": q.to.as_ref().map(|_| rfc3339(to)),
            "sender": sender.map(|s| s.to_string()),
            "utc_offset_minutes": offset,
            "totals": {
                "created": i.created, "sent": i.sent, "completed": i.completed,
                "declined": i.declined, "voided": i.voided, "expired": i.expired,
                "in_progress": i.in_progress,
            },
            "time_to_complete": {
                "completed": i.completed,
                "median_seconds": i.median_seconds.map(f64::round),
                "p90_seconds": i.p90_seconds.map(f64::round),
            },
            "days": i.days.iter().map(|d| json!({"day": d.day, "sent": d.sent, "completed": d.completed})).collect::<Vec<_>>(),
            "top_senders": i.top_senders.iter().map(|t| json!({
                "sender_user_id": t.sender_user_id.to_string(), "sent": t.sent, "completed": t.completed,
            })).collect::<Vec<_>>(),
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::cell;

    #[test]
    fn a_cell_a_spreadsheet_would_run_is_written_as_text() {
        assert_eq!(cell("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(cell("+1"), "'+1");
        assert_eq!(cell("-2"), "'-2");
        assert_eq!(cell("@SUM(A1)"), "'@SUM(A1)");
        assert_eq!(cell("a, b"), "\"a, b\"");
        assert_eq!(cell("Lease 4"), "Lease 4");
    }
}
