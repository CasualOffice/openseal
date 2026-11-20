//! `POST /conversions` (ADR-042, `VS-06C`): a Word document converted and admitted
//! exactly as an upload of it would be, answered as the PDF, and nothing stored. The web
//! editor shows this preview while a sender places fields; the upload itself (the
//! `.docx`, kept as the document's original) is converted again on save, by the same
//! converter with the same fonts, so the pages the fields were placed on are the pages
//! delivered.

use axum::body::Bytes;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use casual_sign_convertd::{ConvertError, Reason};
use casual_sign_sdk::Credentials;
use casual_sign_store::UploadKind;

use super::envelopes::screen_and_convert;
use crate::call::Call;
use crate::error::ApiError;

/// `POST /conversions`, the `.docx` as the body: the admitted PDF.
pub(crate) async fn convert(c: Call, body: Bytes) -> Result<Response, ApiError> {
    c.p.require("envelopes:write")?;
    if body.len() > c.st.config().max_document_bytes {
        return Err(ApiError::too_large());
    }
    if !crate::convert::is_word(&body) {
        return Err(ApiError::conversion(ConvertError::Unsupported(
            Reason::NotZip,
        )));
    }
    let screened = screen_and_convert(&c, UploadKind::Document, Vec::new(), &body).await?;
    let pdf = screened
        .converted
        .map(|c| c.pdf)
        .ok_or_else(|| ApiError::internal("conversion"))?;
    let engine = c.st.0.engine.clone();
    let delivered =
        tokio::task::spawn_blocking(
            move || match engine.prepare(&pdf, &Credentials::default()) {
                Err(e) if e.code() == "CS-PDF-0014" => engine.keep_signed(&pdf),
                other => other,
            },
        )
        .await
        .map_err(|_| ApiError::internal("admission"))??;
    let pages = delivered.admission.page_count;
    if pages == 0 || pages > casual_sign_workflow::limits::MAX_PAGES {
        return Err(ApiError::invalid("/content"));
    }
    let mut r = (StatusCode::OK, delivered.bytes).into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/pdf"),
    );
    r.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment"),
    );
    // Document content is not kept in the idempotency record: a preview stores nothing.
    r.extensions_mut().insert(crate::http::SecretBearing);
    Ok(r)
}
