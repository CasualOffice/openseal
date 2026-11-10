//! The JSON-in, JSON-out core: plain Rust, the same natively and in WebAssembly. The
//! `#[wasm_bindgen]` exports in `lib.rs` only move bytes and strings across the boundary.
//!
//! Every function returns one canonical JSON object (`json.rs`): `{"ok": …}` on success,
//! `{"error": {"code": …, "message": …}}` when the request or the document cannot be
//! used. Codes are docs/20's; a request that is not the JSON described is `CS-API-0001`.
//! Messages carry object numbers, indexes and counts, never document content.

use core::time::Duration;
use std::collections::BTreeMap;
use std::str::FromStr;

use casual_sign_fields::text::Quad;
use casual_sign_fields::{
    AnchorMatch, AnchorSpec, AnchorUnits, Computed, PageText, Point, Values, evaluate_envelope,
};
use casual_sign_model::{Field, Points};
use casual_sign_pdf::{AdmissionReport, Limits, PdfError, Rect};
use casual_sign_verify::{
    Check, Disallowed, Indication, ModificationClass, RevisionChanges, SignatureKind,
    SignatureReport, TimePolicy, TimeSource, TrustStore, VerificationReport, VerifyOptions,
};
use rust_decimal::Decimal;
use serde_json::{Map, Value, json};

use crate::json::{float, to_canonical};

/// The docs/20 code for a request that is not the JSON a function takes.
const MALFORMED: &str = "CS-API-0001";

fn ok(v: Value) -> String {
    to_canonical(&json!({ "ok": v }))
}

fn error(code: &str, message: impl Into<String>) -> String {
    to_canonical(&json!({ "error": { "code": code, "message": message.into() } }))
}

fn pdf_error(e: &PdfError) -> String {
    error(e.code(), e.to_string())
}

/// No host cancellation inside one call: the host bounds work by [`Limits`] (docs/21).
fn never() -> bool {
    false
}

// ------------------------------------------------------------------ verify

/// `verify(pdf, trust)`: every signature and document timestamp (docs/31 §7).
///
/// `trust_json` is an object: `validation_time` (Unix seconds, required: the verifier
/// reads no clock), `anchors` and `intermediates` (base64 DER certificates),
/// `ocsp_responses` and `crls` (base64 DER), `time_policy` (`"proof_of_existence"`,
/// the default, or `"validation_time"`). Unknown keys are refused.
#[must_use]
pub fn verify(pdf: &[u8], trust_json: &str) -> String {
    let (trust, options) = match trust_from_json(trust_json) {
        Ok(t) => t,
        Err(e) => return e,
    };
    ok(report_json(&casual_sign_verify::verify(
        pdf, &trust, &options,
    )))
}

fn trust_from_json(s: &str) -> Result<(TrustStore, VerifyOptions), String> {
    let v: Value = serde_json::from_str(s).map_err(|e| error(MALFORMED, format!("trust: {e}")))?;
    let Value::Object(map) = v else {
        return Err(error(MALFORMED, "trust: not an object"));
    };
    for k in map.keys() {
        if !matches!(
            k.as_str(),
            "validation_time"
                | "anchors"
                | "intermediates"
                | "ocsp_responses"
                | "crls"
                | "time_policy"
        ) {
            return Err(error(MALFORMED, format!("trust: unknown key {k:?}")));
        }
    }
    let secs = map
        .get("validation_time")
        .and_then(Value::as_u64)
        .ok_or_else(|| error(MALFORMED, "trust: validation_time must be Unix seconds"))?;
    let mut options = VerifyOptions::at(Duration::from_secs(secs));
    options.time_policy = match map.get("time_policy").and_then(Value::as_str) {
        None if !map.contains_key("time_policy") => TimePolicy::ProofOfExistence,
        Some("proof_of_existence") => TimePolicy::ProofOfExistence,
        Some("validation_time") => TimePolicy::ValidationTime,
        _ => return Err(error(MALFORMED, "trust: unknown time_policy")),
    };
    options.ocsp_responses = blobs(&map, "ocsp_responses")?;
    options.crls = blobs(&map, "crls")?;
    let mut trust = TrustStore::new();
    for (i, der) in blobs(&map, "anchors")?.iter().enumerate() {
        trust
            .add_anchor(der)
            .map_err(|e| error(e.code(), format!("trust: anchor {i} is not a certificate")))?;
    }
    for (i, der) in blobs(&map, "intermediates")?.iter().enumerate() {
        trust.add_intermediate(der).map_err(|e| {
            error(
                e.code(),
                format!("trust: intermediate {i} is not a certificate"),
            )
        })?;
    }
    Ok((trust, options))
}

fn blobs(map: &Map<String, Value>, key: &str) -> Result<Vec<Vec<u8>>, String> {
    let Some(v) = map.get(key) else {
        return Ok(Vec::new());
    };
    let Some(items) = v.as_array() else {
        return Err(error(MALFORMED, format!("trust: {key} must be an array")));
    };
    items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            item.as_str()
                .and_then(crate::base64::decode)
                .ok_or_else(|| error(MALFORMED, format!("trust: {key}[{i}] is not base64")))
        })
        .collect()
}

fn duration(d: Duration) -> Value {
    json!({ "secs": d.as_secs(), "nanos": d.subsec_nanos() })
}

fn reason_json(r: Option<casual_sign_verify::Reason>) -> (Value, Value) {
    match r {
        Some(r) => (json!(r.sub.name()), json!(r.code)),
        None => (Value::Null, Value::Null),
    }
}

fn indication_json(i: &Indication) -> Value {
    let (sub, code) = reason_json(i.reason());
    json!({ "indication": i.name(), "sub_indication": sub, "code": code })
}

fn check_json(c: &Check) -> Value {
    let status = match c {
        Check::NotRun => "not_run",
        Check::Passed => "passed",
        Check::Failed(_) => "failed",
    };
    let reason = match c {
        Check::Failed(r) => Some(*r),
        Check::NotRun | Check::Passed => None,
    };
    let (sub, code) = reason_json(reason);
    json!({ "status": status, "sub_indication": sub, "code": code })
}

fn disallowed_json(d: Disallowed) -> Value {
    let (why, n) = match d {
        Disallowed::ObjectChanged(n) => ("object_changed", Some(n)),
        Disallowed::ObjectRemoved(n) => ("object_removed", Some(n)),
        Disallowed::PageChanged(n) => ("page_changed", Some(n)),
        Disallowed::AnnotationRemoved(n) => ("annotation_removed", Some(n)),
        Disallowed::CatalogChanged => ("catalog_changed", None),
        Disallowed::TrailerChanged => ("trailer_changed", None),
        Disallowed::FieldChanged(n) => ("field_changed", Some(n)),
        Disallowed::LockedField(n) => ("locked_field", Some(n)),
        Disallowed::NotPermitted(p) => ("not_permitted", Some(u32::from(p))),
        Disallowed::SignatureChanged(n) => ("signature_changed", Some(n)),
        Disallowed::Unreadable => ("unreadable", None),
    };
    json!({ "disallowed": why, "number": n })
}

fn class_json(c: ModificationClass) -> Value {
    match c {
        ModificationClass::DssUpdate => json!("dss_update"),
        ModificationClass::DocumentTimestamp => json!("document_timestamp"),
        ModificationClass::Metadata => json!("metadata"),
        ModificationClass::Signature => json!("signature"),
        ModificationClass::FormFill => json!("form_fill"),
        ModificationClass::Annotation => json!("annotation"),
        ModificationClass::Disallowed(d) => disallowed_json(d),
    }
}

fn revision_json(r: &RevisionChanges) -> Value {
    json!({
        "revision": r.revision,
        "allowed": r.allowed(),
        "classes": r.classes.iter().map(|c| class_json(*c)).collect::<Vec<_>>(),
    })
}

fn signature_json(s: &SignatureReport) -> Value {
    let kind = match s.kind {
        SignatureKind::Approval => json!({ "type": "approval" }),
        SignatureKind::Certification { permissions } => {
            json!({ "type": "certification", "permissions": permissions })
        }
        SignatureKind::DocumentTimestamp => json!({ "type": "document_timestamp" }),
    };
    let time_source = match s.time_source {
        TimeSource::SignatureTimestamp => "signature_timestamp",
        TimeSource::DocumentTimestamp => "document_timestamp",
        TimeSource::ValidationTime => "validation_time",
    };
    let c = &s.checks;
    json!({
        "field": s.field,
        "value": s.value,
        "sub_filter": s.sub_filter,
        "kind": kind,
        "byte_range": s.byte_range,
        "signed_revision": s.signed_revision,
        "covers_whole_document": s.covers_whole_document,
        "indication": indication_json(&s.indication),
        "checks": {
            "byte_range": check_json(&c.byte_range),
            "digest": check_json(&c.digest),
            "signature": check_json(&c.signature),
            "timestamp": check_json(&c.timestamp),
            "chain": check_json(&c.chain),
            "revocation": check_json(&c.revocation),
            "modifications": check_json(&c.modifications),
        },
        "validation_time": duration(s.validation_time),
        "time_source": time_source,
        "timestamp": s.timestamp.map(|t| duration(t.gen_time)),
        "modifications_after": s.modifications_after.iter().map(revision_json).collect::<Vec<_>>(),
    })
}

/// The whole verification report as JSON (the shape `verify` returns under `ok`).
#[must_use]
pub fn report_json(r: &VerificationReport) -> Value {
    json!({
        "error": r.error.map(|e| json!({ "code": e.code })),
        "revisions": r.revisions,
        "signatures": r.signatures.iter().map(signature_json).collect::<Vec<_>>(),
        "revision_changes": r.revision_changes.iter().map(revision_json).collect::<Vec<_>>(),
        "covered_by_last_signature": r.covered_by_last_signature,
        "all_passed": r.all_passed(),
    })
}

// ------------------------------------------------------------------ admit

/// `admit(pdf)`: admission with the default, recovering reader and docs/21 limits
/// (docs/30 §2). Enum values are the Rust variant names (`"XrefRebuilt"`,
/// `"Action(JavaScript)"`).
#[must_use]
pub fn admit(pdf: &[u8]) -> String {
    match casual_sign_pdf::admit(pdf, &Limits::default(), &never) {
        Ok(a) => ok(admission_json(&a.report)),
        Err(e) => pdf_error(&e),
    }
}

fn name(v: &impl core::fmt::Debug) -> Value {
    json!(format!("{v:?}"))
}

fn rect_json(r: &Rect) -> Value {
    json!([float(r.llx), float(r.lly), float(r.urx), float(r.ury)])
}

fn admission_json(r: &AdmissionReport) -> Value {
    json!({
        "version": r.version.map(|v| format!("{}.{}", v.major, v.minor)),
        "page_count": r.page_count,
        "pages": r.pages.iter().map(|p| json!({
            "object": p.object,
            "media_box": rect_json(&p.media_box),
            "crop_box": rect_json(&p.crop_box),
            "rotate": p.rotate,
            "user_unit": float(p.user_unit),
            "media_box_defaulted": p.media_box_defaulted,
        })).collect::<Vec<_>>(),
        "revisions": r.revisions.iter().map(|v| json!({
            "xref_offset": v.xref_offset,
            "end_offset": v.end_offset,
            "kind": name(&v.kind),
        })).collect::<Vec<_>>(),
        "object_count": r.object_count,
        "repaired": r.repaired,
        "stream_lengths_corrected": r.stream_lengths_corrected,
        "fields": r.fields.iter().map(|f| json!({
            "object": f.object,
            "name": f.name,
            "field_type": name(&f.field_type),
            "widgets": f.widgets.iter().map(|w| json!({
                "object": w.object,
                "rect": rect_json(&w.rect),
                "page": w.page,
                "appearance_states": w.appearance_states,
            })).collect::<Vec<_>>(),
            "flags": f.flags,
            "max_len": f.max_len,
            "options": f.options.iter().map(|o| json!([o.export, o.display])).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "signatures": r.signatures.iter().map(|s| json!({
            "field": s.field,
            "value": s.value,
            "sub_filter": s.sub_filter,
            "kind": name(&s.kind),
        })).collect::<Vec<_>>(),
        "is_signed": r.is_signed(),
        "has_perms": r.has_perms,
        "docmdp": r.docmdp,
        "actions": r.actions.iter().map(|a| json!({
            "object": a.object,
            "kind": name(&a.kind),
            "automatic": a.automatic,
        })).collect::<Vec<_>>(),
        "embedded_files": r.embedded_files,
        "rich_media": r.rich_media,
        "external_streams": r.external_streams,
        "has_xfa": r.has_xfa,
        "has_optional_content": r.has_optional_content,
        "encryption": r.encryption.map(|e| json!({
            "version": e.version,
            "revision": e.revision,
            "key_bits": e.key_bits,
            "strings": name(&e.strings),
            "streams": name(&e.streams),
            "opened_with": name(&e.opened_with),
            "empty_password": e.empty_password,
        })),
        "decoded_bytes": r.decoded_bytes,
        "findings": r.findings.iter().map(|f| json!({
            "code": f.code,
            "kind": name(&f.kind),
            "object": f.object,
            "page": f.page,
        })).collect::<Vec<_>>(),
        "findings_dropped": r.findings_dropped,
    })
}

// ------------------------------------------------------------------ text

fn point(p: Point) -> Value {
    json!([float(p.x), float(p.y)])
}

fn quad(q: &Quad) -> Value {
    json!([point(q.ll), point(q.lr), point(q.ur), point(q.ul)])
}

fn page_json(p: &PageText) -> Value {
    let (w, h) = p.geometry.displayed_size();
    json!({
        "page": p.page,
        "displayed_size": [float(w), float(h)],
        "rotate": p.geometry.rotate(),
        "text": p.text(),
        "operators": p.operators,
        "findings": p.findings.iter().map(|f| json!({
            "code": f.code,
            "issue": name(&f.issue),
            "object": f.object,
        })).collect::<Vec<_>>(),
        "runs": p.runs.iter().map(|r| json!({
            "text": r.text,
            "size": float(r.size),
            "quad": quad(&r.quad),
            "glyphs": r.glyphs.len(),
        })).collect::<Vec<_>>(),
    })
}

fn pages(pdf: &[u8]) -> Result<Vec<PageText>, String> {
    let mut a =
        casual_sign_pdf::admit(pdf, &Limits::default(), &never).map_err(|e| pdf_error(&e))?;
    let infos = a.report.pages.clone();
    casual_sign_fields::extract_text(&mut a.document, &infos, &never).map_err(|e| pdf_error(&e))
}

/// `extract_text(pdf)`: every page's text, and each show operator's run with its
/// quadrilateral in displayed page space, size and glyph count (docs/30 §5).
///
/// Runs, not glyphs: per-glyph geometry made the answer for a 900-page document 680 MB,
/// more than a JavaScript string holds; glyph positions are used inside the module by
/// [`place_anchor`]. The answer is written one page at a time, so peak memory is the
/// answer plus one page's JSON, not a JSON tree of the whole document (which ran a
/// 32-bit module out of memory).
#[must_use]
pub fn extract_text(pdf: &[u8]) -> String {
    let p = match pages(pdf) {
        Ok(p) => p,
        Err(e) => return e,
    };
    // `{"ok":{"pages":[…]}}` is canonical: each object around the pages has one key.
    let mut out = String::from(r#"{"ok":{"pages":["#);
    for (i, page) in p.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&to_canonical(&page_json(page)));
    }
    out.push_str("]}}");
    out
}

// ------------------------------------------------------------------ anchors

/// `place_anchor(pdf, anchors)`: anchor text to placed fields (docs/30 §5).
///
/// `anchors_json` is an array of objects: `text` (required), `offset_x`, `offset_y`,
/// `width`, `height` (decimal strings, points unless `units`; width and height default
/// to 100 and 20), `units` (`points`, `inches`, `millimetres`, `centimetres`, `pixels`),
/// `ignore_if_absent`, `case_sensitive`, `whole_word` (booleans), `matching` (`first` or
/// `all`). The answer holds one result per anchor, in order.
#[must_use]
pub fn place_anchor(pdf: &[u8], anchors_json: &str) -> String {
    let specs = match anchors_from_json(anchors_json) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let text = match pages(pdf) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let results: Vec<Value> = specs
        .iter()
        .enumerate()
        .map(
            |(i, spec)| match casual_sign_fields::place_anchor(&text, spec, i) {
                Ok(placed) => json!({ "ok": placed.iter().map(|p| json!({
                    "placement": serde_json::to_value(p.placement).unwrap_or(Value::Null),
                    "text_rect": [
                        float(p.text_rect.x),
                        float(p.text_rect.y),
                        float(p.text_rect.width),
                        float(p.text_rect.height),
                    ],
                })).collect::<Vec<_>>() }),
                Err(e) => json!({ "error": { "code": e.code(), "message": e.to_string() } }),
            },
        )
        .collect();
    ok(json!({ "anchors": results }))
}

fn anchors_from_json(s: &str) -> Result<Vec<AnchorSpec>, String> {
    let v: Value =
        serde_json::from_str(s).map_err(|e| error(MALFORMED, format!("anchors: {e}")))?;
    let Value::Array(items) = v else {
        return Err(error(MALFORMED, "anchors: not an array"));
    };
    items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            anchor_from_json(item).map_err(|m| error(MALFORMED, format!("anchors[{i}]: {m}")))
        })
        .collect()
}

fn anchor_from_json(v: &Value) -> Result<AnchorSpec, String> {
    let Value::Object(map) = v else {
        return Err("not an object".into());
    };
    let mut spec = AnchorSpec {
        text: String::new(),
        offset_x: Decimal::ZERO,
        offset_y: Decimal::ZERO,
        units: AnchorUnits::Points,
        ignore_if_absent: false,
        case_sensitive: false,
        whole_word: false,
        matching: AnchorMatch::All,
        width: Points::new(Decimal::from(100)).map_err(|_| "width")?,
        height: Points::new(Decimal::from(20)).map_err(|_| "height")?,
    };
    let decimal = |k: &str, x: &Value| -> Result<Decimal, String> {
        x.as_str()
            .and_then(|s| Decimal::from_str(s).ok())
            .ok_or_else(|| format!("{k} must be a decimal string"))
    };
    let boolean = |k: &str, x: &Value| -> Result<bool, String> {
        x.as_bool().ok_or_else(|| format!("{k} must be a boolean"))
    };
    for (k, x) in map {
        match k.as_str() {
            "text" => {
                x.as_str()
                    .ok_or("text must be a string")?
                    .clone_into(&mut spec.text);
            }
            "offset_x" => spec.offset_x = decimal(k, x)?,
            "offset_y" => spec.offset_y = decimal(k, x)?,
            "width" => {
                spec.width = Points::new(decimal(k, x)?).map_err(|e| format!("width: {e}"))?;
            }
            "height" => {
                spec.height = Points::new(decimal(k, x)?).map_err(|e| format!("height: {e}"))?;
            }
            "units" => {
                spec.units = match x.as_str() {
                    Some("points") => AnchorUnits::Points,
                    Some("inches") => AnchorUnits::Inches,
                    Some("millimetres") => AnchorUnits::Millimetres,
                    Some("centimetres") => AnchorUnits::Centimetres,
                    Some("pixels") => AnchorUnits::Pixels,
                    _ => return Err("unknown units".into()),
                };
            }
            "ignore_if_absent" => spec.ignore_if_absent = boolean(k, x)?,
            "case_sensitive" => spec.case_sensitive = boolean(k, x)?,
            "whole_word" => spec.whole_word = boolean(k, x)?,
            "matching" => {
                spec.matching = match x.as_str() {
                    Some("first") => AnchorMatch::First,
                    Some("all") => AnchorMatch::All,
                    _ => return Err("matching must be first or all".into()),
                };
            }
            other => return Err(format!("unknown key {other:?}")),
        }
    }
    Ok(spec)
}

// ------------------------------------------------------------------ envelope

/// `evaluate_envelope(fields, values)`: every field rule at completion (docs/24 §5,
/// docs/30 §6). `fields_json` is an array of fields and `values_json` an object from
/// field id to value, both in the model's serde form (docs/22, docs/40).
#[must_use]
pub fn evaluate(fields_json: &str, values_json: &str) -> String {
    let fields: Vec<Field> = match serde_json::from_str(fields_json) {
        Ok(f) => f,
        Err(e) => return error(MALFORMED, format!("fields: {e}")),
    };
    let values: Values = match serde_json::from_str(values_json) {
        Ok(v) => v,
        Err(e) => return error(MALFORMED, format!("values: {e}")),
    };
    let o = evaluate_envelope(&fields, &values);
    let computed: BTreeMap<String, Value> = o
        .computed
        .iter()
        .map(|(id, c): (_, &Computed)| {
            let v = match c {
                Ok(text) => json!({ "ok": text }),
                Err(e) => json!({ "error": e.name() }),
            };
            (id.to_string(), v)
        })
        .collect();
    ok(json!({
        "complete": o.is_complete(),
        "issues": o.issues.iter().map(|i| json!({
            "field_id": i.field_id,
            "code": i.code(),
            "message": i.error.to_string(),
        })).collect::<Vec<_>>(),
        "values": serde_json::to_value(&o.values).unwrap_or(Value::Null),
        "computed": computed,
        "dropped": o.dropped,
        "hidden": o.hidden,
    }))
}

// Tests may unwrap (CLAUDE.md).
#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    const PDF: &[u8] = include_bytes!("../../../fixtures/signed/b-lt.pdf");

    /// Each answer equals its own canonical form: what the page-by-page writer of
    /// `extract_text` builds by hand must be what `to_canonical` would write.
    #[test]
    fn every_answer_is_canonical() {
        let trust = r#"{"validation_time":1796083200}"#;
        let anchors = r#"[{"text":"Agreement","units":"millimetres","offset_x":"2.5"}]"#;
        for out in [
            extract_text(PDF),
            admit(PDF),
            verify(PDF, trust),
            place_anchor(PDF, anchors),
        ] {
            let v: Value = serde_json::from_str(&out).unwrap();
            assert!(v.get("ok").is_some(), "{out}");
            assert_eq!(to_canonical(&v), out);
        }
    }

    #[test]
    fn malformed_requests_are_refused_with_a_code() {
        for out in [
            verify(PDF, "{}"),
            verify(PDF, r#"{"validation_time":1,"anchors":["Zg="]}"#),
            verify(PDF, r#"{"validation_time":1,"extra":1}"#),
            place_anchor(PDF, r#"[{"text":"a","units":"furlongs"}]"#),
            place_anchor(PDF, "{}"),
        ] {
            assert!(
                out.starts_with(r#"{"error":{"code":"CS-API-0001""#),
                "{out}"
            );
        }
        let not_cert = verify(PDF, r#"{"validation_time":1,"anchors":["Zm9v"]}"#);
        assert!(
            not_cert.starts_with(r#"{"error":{"code":"CS-VER-0003""#),
            "{not_cert}"
        );
        assert!(admit(b"not a pdf").starts_with(r#"{"error":{"code":"CS-PDF-"#));
    }
}
