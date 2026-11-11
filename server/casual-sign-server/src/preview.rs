//! The in-progress preview download (WEB-06): the delivered document with the values
//! completed so far flattened into a copy, and a banner on every page saying it is a
//! preview and not signed.
//!
//! **Evidence.** The preview is made on request and never stored, hashed into the
//! envelope or sealed: the delivered document and its hash are untouched, and the
//! sealed document is made only by the seal job. What a preview shows is chosen so it
//! never claims more than happened: values of recipients who have completed, and values
//! the sender fixed (`locked`); a recipient's values in progress are not shown. The
//! download is recorded in the chain as `document.downloaded` with the SHA-256 of the
//! bytes served, like every other download.

use std::collections::BTreeMap;

use casual_sign_host::capture;
use casual_sign_model::{
    Align, Field, FieldType, FieldValue, Format, Id, Placement, Points, RecipientStatus, Rgb, Text,
};
use casual_sign_sdk::{Capture, FlattenOptions};
use casual_sign_store::blob::BlobKey;
use casual_sign_store::repo::documents::VersionKind;
use casual_sign_workflow::EnvelopeState;
use rust_decimal::Decimal;
use serde_json::Value;

use crate::error::ApiError;
use crate::state::AppState;

/// The banner's text, on every page of a preview.
pub(crate) const BANNER: &str = "PREVIEW - NOT SIGNED. Values completed so far; not the agreement.";
/// Banner box, points.
const BANNER_W: i64 = 340;
const BANNER_H: i64 = 12;
const BANNER_TOP: i64 = 4;

/// The fields of `document` as a preview draws them: values of completed recipients
/// and the sender's locked values kept, everything else emptied; plus one banner per
/// page. `pages` is the stored version's page geometry (`[{width, height, rotate}]`).
pub(crate) fn preview_fields(
    state: &EnvelopeState,
    document: &Id,
    pages: &Value,
) -> Result<Vec<Field>, ApiError> {
    let mut out: Vec<Field> = Vec::new();
    for f in state.fields.0.iter().filter(|f| &f.document_id == document) {
        let finished = f
            .recipient_id
            .as_ref()
            .and_then(|r| state.recipient(r))
            .is_some_and(|r| r.status == RecipientStatus::Completed);
        let mut f = f.clone();
        if !(finished || f.locked) {
            f.value = None;
            f.default = None;
        }
        // A preview never refuses an incomplete form: what is missing stays empty.
        f.required = false;
        out.push(f);
    }
    let list = pages.as_array().map(Vec::as_slice).unwrap_or_default();
    for (i, p) in list.iter().enumerate() {
        let (w, _) = displayed(p);
        let page = u32::try_from(i)
            .map_err(|_| ApiError::internal("page"))?
            .saturating_add(1);
        let width = BANNER_W.min(w.saturating_sub(8));
        if width <= 0 {
            continue;
        }
        let x = w.saturating_sub(width) / 2;
        let pt = |n: i64| Points::new(Decimal::from(n)).map_err(|_| ApiError::internal("banner"));
        let placement = Placement::new(page, pt(x)?, pt(BANNER_TOP)?, pt(width)?, pt(BANNER_H)?)
            .map_err(|_| ApiError::internal("banner"))?;
        let id = Id::new(format!("openseal-preview-banner-{page}"))
            .map_err(|_| ApiError::internal("banner"))?;
        let mut b = Field::new(id, document.clone(), FieldType::Text, placement);
        b.read_only = true;
        b.locked = true;
        b.value = Some(FieldValue::Text(
            Text::new(BANNER).map_err(|_| ApiError::internal("banner"))?,
        ));
        b.format = Some(Format {
            color: Some(Rgb([0xb0, 0x00, 0x20])),
            align: Some(Align::Center),
            font_size: Some(pt(8)?),
            ..Format::default()
        });
        out.push(b);
    }
    Ok(out)
}

/// A page's displayed width and height in whole points (rotation applied).
fn displayed(p: &Value) -> (i64, i64) {
    let n = |k: &str| {
        p.get(k)
            .and_then(Value::as_f64)
            .filter(|v| v.is_finite() && *v > 0.0 && *v < 14_400.0)
            .map_or(0, |v| v.floor() as i64)
    };
    let (w, h) = (n("width"), n("height"));
    match p.get("rotate").and_then(Value::as_i64) {
        Some(90 | 270) => (h, w),
        _ => (w, h),
    }
}

/// The art each signature value of `fields` names, read from the blob store with the
/// seal job's bounds.
async fn captures(st: &AppState, fields: &[Field]) -> Result<BTreeMap<Id, Capture>, ApiError> {
    let mut out = BTreeMap::new();
    for f in fields {
        let Some(FieldValue::Signature(id)) = &f.value else {
            continue;
        };
        if out.contains_key(id) {
            continue;
        }
        let bad = |_| ApiError::internal("capture");
        let key = BlobKey::parse(id.as_str()).map_err(|_| ApiError::internal("capture"))?;
        let bytes = st.0.blobs.get(&key).await?;
        let art = match capture::parse(&bytes).map_err(bad)? {
            capture::Parsed::Art(a) => a,
            capture::Parsed::Image(k) => {
                let key = BlobKey::parse(&k).map_err(|_| ApiError::internal("capture"))?;
                capture::image_art(st.0.blobs.get(&key).await?).map_err(bad)?
            }
        };
        out.insert(
            id.clone(),
            Capture {
                art,
                signed_by: None,
                reason: None,
            },
        );
    }
    Ok(out)
}

/// The document as it stands (`version=current`): its sealed version once sealed,
/// else the preview of the values completed so far. Answers the bytes and whether they
/// are the sealed version.
pub(crate) async fn current(
    st: &AppState,
    tx: &mut casual_sign_store::TenantTx,
    state: &EnvelopeState,
    document: &Id,
) -> Result<(Vec<u8>, bool), ApiError> {
    let stored = casual_sign_store::DocumentId(crate::apply::uid(document)?);
    let versions = tx.documents().versions(stored).await?;
    if let Some(v) = versions
        .iter()
        .rev()
        .find(|v| v.version.kind == VersionKind::Sealed)
    {
        return Ok((st.0.blobs.get(&BlobKey(v.version.sha256)).await?, true));
    }
    let d = state.document(document).ok_or_else(ApiError::not_found)?;
    let pages = versions
        .iter()
        .rev()
        .find(|v| {
            v.version.kind == VersionKind::Normalized && v.version.sha256 == d.spec.delivered_hash.0
        })
        .map(|v| v.version.pages.clone())
        .ok_or_else(ApiError::not_found)?;
    Ok((render(st, state, document, &pages).await?, false))
}

/// The preview of one document (blocking work off the async runtime).
pub(crate) async fn render(
    st: &AppState,
    state: &EnvelopeState,
    document: &Id,
    pages: &Value,
) -> Result<Vec<u8>, ApiError> {
    let d = state.document(document).ok_or_else(ApiError::not_found)?;
    let delivered = st.0.blobs.get(&BlobKey(d.spec.delivered_hash.0)).await?;
    let fields = preview_fields(state, document, pages)?;
    let caps = captures(st, &fields).await?;
    let engine = st.0.engine.clone();
    let envelope = state.id.as_str().to_owned();
    let filled = tokio::task::spawn_blocking(move || {
        let values = BTreeMap::new();
        let fill = casual_sign_sdk::Fill {
            fields: &fields,
            values: &values,
            captures: &caps,
            envelope_id: Some(envelope.as_str()),
            acroform: None,
            require_complete: false,
        };
        engine.fill_and_flatten(&delivered, &fill, &FlattenOptions::default())
    })
    .await
    .map_err(|_| ApiError::internal("preview"))??;
    Ok(filled.bytes)
}
