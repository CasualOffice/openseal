//! Word uploads converted to PDF (ADR-042, owner instruction 76; docs/07 `SEC-P13`; row
//! `VS-06C`): a `.docx` uploaded to an envelope (one-call create as JSON, a draft's
//! upload as JSON and as the raw body) or to a template is converted by convertd and the
//! PDF admitted; the `.docx` is the document's `original` version (its SHA-256 the
//! document's `upload_sha256`) and the admission report says it was converted, by what,
//! into which PDF, with how many external references. A refusal from the converter
//! answers its `CS-CNV-*` code and stores nothing; without a converter a Word upload is
//! refused `415 CS-CNV-0002 conversion_off`; an unreachable one `503 CS-CNV-0005` with
//! `Retry-After`. `POST /conversions` answers the admitted PDF and stores nothing.
//!
//! The converter here is a fake speaking convertd's protocol (`common::convertd`); the
//! real one is tested in `casual-sign-convertd`'s `tests/convert.rs` and on the Compose
//! stack (`webapp/e2e/manage-correct.spec.mjs`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::panic
)]

mod common;

use axum::body::Body;
use axum::http::StatusCode;
use casual_sign_convertd::Client;
use common::Rls;
use common::convertd::{converted_pdf, docm, docx, fake_converter};
use common::flow::{b64, ok};
use common::harness::{Api, Resp, Tenant, pdf};
use serde_json::{Value, json};

const DOCX: &str = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

fn sha256_hex(b: &[u8]) -> String {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b)
        .as_ref()
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

/// Every file under the blob directory.
fn blobs(api: &Api) -> usize {
    fn walk(p: &std::path::Path) -> usize {
        std::fs::read_dir(p).map_or(0, |d| {
            d.flatten()
                .map(|e| {
                    let p = e.path();
                    if p.is_dir() { walk(&p) } else { 1 }
                })
                .sum()
        })
    }
    walk(&api.blob_dir)
}

async fn reports(api: &Api) -> Vec<Value> {
    sqlx::query_scalar::<_, Value>(
        "SELECT admission_report FROM document_versions WHERE kind = 'normalized' ORDER BY created_at, id",
    )
    .fetch_all(&api.db.admin)
    .await
    .unwrap()
}

async fn create(api: &Api, t: &Tenant, name: &str, content: &[u8]) -> Resp {
    api.call(
        "POST",
        "/api/v1/envelopes",
        &t.auth,
        Some(json!({"subject": "VS-06C", "documents": [{"name": name, "content_base64": b64(content)}]})),
        &[],
    )
    .await
}

async fn raw_upload(api: &Api, t: &Tenant, env: &str, media: &str, body: Vec<u8>) -> Resp {
    api.send(
        "POST",
        &format!("/api/v1/envelopes/{env}/documents?name=terms.docx"),
        &t.auth,
        Body::from(body),
        &[("content-type", media)],
    )
    .await
}

fn refused(r: &Resp, status: StatusCode, code: &str, detail: &str, what: &str) {
    assert_eq!(
        r.status,
        status,
        "{what}: {}",
        String::from_utf8_lossy(&r.body)
    );
    assert_eq!(r.code(), code, "{what}");
    assert_eq!(r.json()["detail"], detail, "{what}");
}

#[tokio::test]
async fn a_word_upload_is_converted_admitted_and_kept_as_the_original() {
    let Some(api) = Api::new("word_upload_converted", Rls::On).await else {
        return;
    };
    let a = api.tenant("acme").await;
    api.st.set_converter(fake_converter().await);

    // The one-call create, as JSON.
    let env = ok(
        create(&api, &a, "contract.docx", &docx()).await,
        StatusCode::CREATED,
        "create with a Word document",
    );
    let id = env["id"].as_str().unwrap().to_owned();
    let d = &env["documents"][0];
    assert_eq!(d["pages"], 2, "the converted PDF's pages");
    assert_eq!(d["name"], "contract.docx");
    assert_eq!(
        d["upload_sha256"],
        format!("sha256:{}", sha256_hex(&docx())),
        "the upload hash is the Word document's"
    );
    let doc = d["id"].as_str().unwrap().to_owned();

    // The original is the .docx itself, served as one.
    let content = format!("/api/v1/envelopes/{id}/documents/{doc}/content");
    let original = api
        .call(
            "GET",
            &format!("{content}?version=original"),
            &a.auth,
            None,
            &[],
        )
        .await;
    assert_eq!(original.status, StatusCode::OK);
    assert_eq!(original.body.as_ref(), docx().as_slice());
    assert_eq!(original.headers["content-type"], DOCX);
    // The delivered document is the admitted PDF.
    let delivered = api.call("GET", &content, &a.auth, None, &[]).await;
    assert_eq!(delivered.status, StatusCode::OK);
    assert!(delivered.body.starts_with(b"%PDF-"));
    assert_eq!(delivered.headers["content-type"], "application/pdf");

    // The admission report records the conversion.
    let report = reports(&api).await.last().unwrap().clone();
    assert_eq!(report["converted"]["from"], "docx");
    assert_eq!(
        report["converted"]["converter"],
        casual_sign_convertd::CONVERTER
    );
    assert_eq!(
        report["converted"]["pdf_sha256"],
        sha256_hex(&converted_pdf())
    );
    assert_eq!(report["converted"]["external_references"], 1);
    assert_eq!(report["page_count"], 2);

    // A draft's upload as the raw body with the Word media type, and as JSON.
    ok(
        raw_upload(&api, &a, &id, DOCX, docx()).await,
        StatusCode::CREATED,
        "raw Word upload",
    );
    ok(
        api.call(
            "POST",
            &format!("/api/v1/envelopes/{id}/documents"),
            &a.auth,
            Some(json!({"name": "annex.docx", "content_base64": b64(&docx())})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "JSON Word upload",
    );
    // A PDF is admitted as before: no `converted` in its report.
    ok(
        raw_upload(&api, &a, &id, "application/pdf", pdf(1)).await,
        StatusCode::CREATED,
        "raw PDF upload",
    );
    assert!(
        reports(&api)
            .await
            .last()
            .unwrap()
            .get("converted")
            .is_none()
    );

    // A template's document.
    let t = ok(
        api.call(
            "POST",
            "/api/v1/templates",
            &a.auth,
            Some(json!({"name": "Order", "roles": [{"name": "Buyer", "type": "signer"}]})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "template",
    );
    ok(
        api.call(
            "POST",
            &format!("/api/v1/templates/{}/documents", t["id"].as_str().unwrap()),
            &a.auth,
            Some(json!({"name": "order.docx", "content_base64": b64(&docx())})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "template Word document",
    );

    // The editor's preview: the admitted PDF, nothing stored.
    let before = blobs(&api);
    let preview = api
        .send(
            "POST",
            "/api/v1/conversions",
            &a.auth,
            Body::from(docx()),
            &[("content-type", DOCX), ("idempotency-key", "vs06c-preview")],
        )
        .await;
    assert_eq!(
        preview.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&preview.body)
    );
    assert!(preview.body.starts_with(b"%PDF-"));
    assert_eq!(preview.headers["content-type"], "application/pdf");
    assert_eq!(blobs(&api), before, "a preview stores nothing");
    // Nor does its idempotency record keep the document.
    let kept: Vec<Option<Vec<u8>>> =
        sqlx::query_scalar("SELECT body FROM idempotency_keys WHERE key = 'vs06c-preview'")
            .fetch_all(&api.db.admin)
            .await
            .unwrap();
    assert_eq!(kept, vec![None], "the preview's idempotency record");
    api.db.drop().await;
}

#[tokio::test]
async fn a_refused_or_unconvertible_word_upload_stores_nothing() {
    let Some(api) = Api::new("word_upload_refused", Rls::On).await else {
        return;
    };
    let a = api.tenant("acme").await;

    // No converter configured: refused, a PDF still admitted.
    refused(
        &create(&api, &a, "contract.docx", &docx()).await,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "CS-CNV-0002",
        "conversion_off",
        "no converter",
    );
    let env = ok(
        create(&api, &a, "a.pdf", &pdf(1)).await,
        StatusCode::CREATED,
        "a PDF without a converter",
    );
    let id = env["id"].as_str().unwrap().to_owned();

    api.st.set_converter(fake_converter().await);
    let stored = blobs(&api);
    // Macros: refused, nothing of it stored, the envelope unchanged.
    refused(
        &create(&api, &a, "macro.docm", &docm()).await,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "CS-CNV-0004",
        "macros",
        "macro create",
    );
    refused(
        &raw_upload(&api, &a, &id, DOCX, docm()).await,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "CS-CNV-0004",
        "macros",
        "macro upload",
    );
    let e = api
        .call(
            "GET",
            &format!("/api/v1/envelopes/{id}"),
            &a.auth,
            None,
            &[],
        )
        .await
        .json();
    assert_eq!(e["documents"].as_array().unwrap().len(), 1);
    // The preview refuses a PDF (nothing to convert) and a macro-enabled document.
    for (body, code) in [(pdf(1), "CS-CNV-0002"), (docm(), "CS-CNV-0004")] {
        let r = api
            .send(
                "POST",
                "/api/v1/conversions",
                &a.auth,
                Body::from(body),
                &[("content-type", DOCX)],
            )
            .await;
        assert_eq!(r.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(r.code(), code);
    }
    assert_eq!(blobs(&api), stored, "nothing of a refused upload is stored");
    api.db.drop().await;
}

#[tokio::test]
async fn an_unreachable_converter_answers_503_with_retry_after() {
    let Some(api) = Api::new("word_upload_unreachable", Rls::On).await else {
        return;
    };
    let a = api.tenant("acme").await;
    api.st.set_converter(Client::new(
        std::env::temp_dir().join("no-convertd-here.sock"),
    ));
    let r = create(&api, &a, "contract.docx", &docx()).await;
    refused(
        &r,
        StatusCode::SERVICE_UNAVAILABLE,
        "CS-CNV-0005",
        "connect",
        "unreachable",
    );
    assert_eq!(r.headers["retry-after"], "30");
    api.db.drop().await;
}
