//! Fields placed from a document's own text (`VS-04E`, docs/30 §5, docs/40 §3): an
//! `anchor` on a field (DocuSign's anchor tabs) becomes one placed field per match, and
//! `"text_tags": true` on create turns each `{{type:recipient…}}` tag (SignNow's text
//! tags) into a field. Both read the delivered document with the engine's bounded text
//! interpreter (`casual_sign_sdk::Engine::place_anchors`, `text_tags`) and change
//! nothing in it; the field endpoints then take the placed fields as any other.

use std::str::FromStr;

use casual_sign_fields::{AnchorMatch, AnchorSpec, AnchorUnits};
use casual_sign_model::{Id, Points};
use casual_sign_store::blob::BlobKey;
use rust_decimal::Decimal;
use serde_json::{Map, Value, json};

use crate::error::ApiError;
use crate::state::AppState;

/// A document an anchor or a tag may be read from: its id and its delivered bytes' key.
pub(crate) type Source = (Id, BlobKey);

/// The size a placed field takes when the request gives none, by kind (the editor's
/// defaults, `webapp/geometry.js`).
fn default_size(kind: &str) -> (i64, i64) {
    match kind {
        "signature" => (160, 44),
        "initials" => (64, 44),
        "checkbox" => (16, 16),
        "stamp" => (120, 60),
        "drawing" => (180, 90),
        "radio_group" => (120, 60),
        _ => (160, 22),
    }
}

/// The engine's anchor spec from a field's `anchor` member and the field's own size.
fn spec_of(anchor: &Value, field: &Map<String, Value>, at: &str) -> Result<AnchorSpec, ApiError> {
    let Value::Object(map) = anchor else {
        return Err(ApiError::invalid(at));
    };
    let kind = field.get("type").and_then(Value::as_str).unwrap_or("text");
    let (w, h) = default_size(kind);
    let parent = at.trim_end_matches("/anchor");
    let size = |k: &str, d: i64| -> Result<Points, ApiError> {
        let bad = || ApiError::invalid(&format!("{parent}/{k}"));
        let v = match field.get(k) {
            None => Decimal::from(d),
            Some(x) => decimal(x).ok_or_else(bad)?,
        };
        Points::new(v).map_err(|_| bad())
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
        width: size("width", w)?,
        height: size("height", h)?,
    };
    for (k, x) in map {
        let bad = || ApiError::invalid(&format!("{at}/{k}"));
        match k.as_str() {
            "text" => x.as_str().ok_or_else(bad)?.clone_into(&mut spec.text),
            "offset_x" => spec.offset_x = decimal(x).ok_or_else(bad)?,
            "offset_y" => spec.offset_y = decimal(x).ok_or_else(bad)?,
            "units" => {
                spec.units = match x.as_str() {
                    Some("points") => AnchorUnits::Points,
                    Some("inches") => AnchorUnits::Inches,
                    Some("millimetres") => AnchorUnits::Millimetres,
                    Some("centimetres") => AnchorUnits::Centimetres,
                    Some("pixels") => AnchorUnits::Pixels,
                    _ => return Err(bad()),
                };
            }
            "ignore_if_absent" => spec.ignore_if_absent = x.as_bool().ok_or_else(bad)?,
            "case_sensitive" => spec.case_sensitive = x.as_bool().ok_or_else(bad)?,
            "whole_word" => spec.whole_word = x.as_bool().ok_or_else(bad)?,
            "matching" => {
                spec.matching = match x.as_str() {
                    Some("first") => AnchorMatch::First,
                    Some("all") => AnchorMatch::All,
                    _ => return Err(bad()),
                };
            }
            _ => return Err(bad()),
        }
    }
    if spec.text.is_empty() {
        return Err(ApiError::invalid(&format!("{at}/text")));
    }
    Ok(spec)
}

/// A decimal given as a JSON number or a decimal string.
fn decimal(v: &Value) -> Option<Decimal> {
    match v {
        Value::String(s) => Decimal::from_str(s).ok(),
        Value::Number(n) => Decimal::from_str(&n.to_string()).ok(),
        _ => None,
    }
}

/// The delivered bytes of document `doc` among `sources`.
async fn bytes_of(st: &AppState, sources: &[Source], doc: &Id) -> Result<Vec<u8>, ApiError> {
    let (_, key) = sources
        .iter()
        .find(|(id, _)| id == doc)
        .ok_or_else(ApiError::not_found)?;
    Ok(st.0.blobs.get(key).await?)
}

/// Every field of `raws` with its `anchor` placed: a field without one is kept as it
/// is; one with an `anchor` becomes a field at each match (`matching: all`, the
/// default) or the first, with the anchor removed and the rectangle set, or none when
/// the text is absent and `ignore_if_absent` is set. `document(raw)` names the field's
/// document; `at` the request's pointer to the list. Each placed field keeps the
/// pointer of the field it came from.
pub(crate) async fn place_anchors(
    st: &AppState,
    raws: &[Value],
    sources: &[Source],
    document: impl Fn(&Value) -> Option<Id>,
    at: &str,
) -> Result<Vec<(Value, String)>, ApiError> {
    let mut out = Vec::with_capacity(raws.len());
    for (i, raw) in raws.iter().enumerate() {
        let ptr = format!("{at}/{i}");
        let Some(anchor) = raw.get("anchor") else {
            out.push((raw.clone(), ptr));
            continue;
        };
        let Value::Object(map) = raw else {
            return Err(ApiError::invalid(&ptr));
        };
        let spec = spec_of(anchor, map, &format!("{ptr}/anchor"))?;
        let doc = map
            .get("document")
            .or_else(|| map.get("document_id"))
            .and_then(&document)
            .ok_or_else(|| ApiError::invalid(&format!("{ptr}/document")))?;
        let bytes = bytes_of(st, sources, &doc).await?;
        let engine = st.0.engine.clone();
        let placed = tokio::task::spawn_blocking(move || {
            engine.place_anchors(&bytes, std::slice::from_ref(&spec))
        })
        .await
        .map_err(|_| ApiError::internal("anchors"))??;
        let placements = match placed.into_iter().next() {
            Some(Ok(p)) => p,
            Some(Err(e)) => return Err(ApiError::placing(&format!("{ptr}/anchor"), e.code())),
            None => Vec::new(),
        };
        for p in placements {
            let mut f = map.clone();
            f.remove("anchor");
            for k in ["page", "x", "y", "width", "height", "placement"] {
                f.remove(k);
            }
            if let Value::Object(pl) = serde_json::to_value(p.placement).unwrap_or(Value::Null) {
                f.extend(pl);
            }
            out.push((Value::Object(f), ptr.clone()));
        }
    }
    Ok(out)
}

/// The fields the text tags of `sources` place (`"text_tags": true`): each tag's kind,
/// recipient (its reference as written, which the request's recipients name by `ref`),
/// `required`, data label and rectangle, on its document. A malformed tag refuses the
/// request (`CS-FLD-0011` at `/text_tags`), never a guess.
pub(crate) async fn tag_fields(st: &AppState, sources: &[Source]) -> Result<Vec<Value>, ApiError> {
    let mut out = Vec::new();
    for (doc, key) in sources {
        let bytes = st.0.blobs.get(key).await?;
        let engine = st.0.engine.clone();
        let scan = tokio::task::spawn_blocking(move || engine.text_tags(&bytes))
            .await
            .map_err(|_| ApiError::internal("text tags"))??;
        if let Some(e) = scan.errors.first() {
            return Err(ApiError::placing("/text_tags", e.code()));
        }
        for tag in scan.tags {
            let mut f = json!({
                "recipient": tag.recipient.to_string(),
                "document": doc.to_string(),
                "type": tag.field_type,
            });
            if let (Value::Object(m), Value::Object(pl)) = (
                &mut f,
                serde_json::to_value(tag.placement).unwrap_or(Value::Null),
            ) {
                m.extend(pl);
                if tag.required {
                    m.insert("required".into(), Value::Bool(true));
                }
                if let Some(l) = &tag.label {
                    m.insert("label".into(), json!(l));
                }
            }
            out.push(f);
        }
    }
    Ok(out)
}
