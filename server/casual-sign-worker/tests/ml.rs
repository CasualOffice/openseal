//! Document analysis in the worker (WEB-19, ML-01; docs/33 §2) against a fake model
//! service through the `Inference` seam:
//!
//! - `analyze_document`: OCR only of the page with no text layer, entity and
//!   personal-data spans (the deterministic recognisers and the model) stored as page and
//!   byte offsets that name the right text, the run `done` with its bundle, and the
//!   envelope's state and audit chain untouched.
//! - `fingerprint_template` stores a template document's page prints, and a later upload
//!   that matches them gets a `template` suggestion.
//! - A final model error ends the run `failed` with its code (the job completes); with no
//!   model service the run ends `unavailable`.
//!
//! Needs `OPENSEAL_TEST_DATABASE_URL`; without it the tests pass vacuously.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::too_many_lines
)]

mod common;

use std::sync::{Arc, Mutex};

use casual_sign_host::ml::{self as hml, AnalysisJob};
use casual_sign_modeld::wire::{Info, OcrPage, PageHash, Span, SpanRequest, Word};
use casual_sign_modeld::{Call, ModeldError};
use casual_sign_sdk::Credentials;
use casual_sign_store::blob::{BlobKey, BlobStore};
use casual_sign_store::repo::ml::{NewRun, RunKind, RunStatus};
use casual_sign_store::repo::templates::{Template, TemplateDocument};
use casual_sign_store::{AnalysisRunId, EnvelopeId, JobId, TemplateDocumentId, TemplateId};
use casual_sign_worker::JobOutcome;
use casual_sign_worker::ml::Inference;
use casual_sign_workflow::Command;
use common::Env;
use uuid::Uuid;

/// What the fake model service was asked, as `op:account:detail`.
#[derive(Debug, Default)]
struct Fake {
    calls: Mutex<Vec<String>>,
    fail: Option<fn() -> ModeldError>,
}

impl Fake {
    fn log(&self, call: &Call, what: String) {
        self.calls
            .lock()
            .unwrap()
            .push(format!("{what}:{}", call.account));
    }
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

/// Spans of `needle` in `text`, as modeld answers them (byte offsets into what was sent).
fn find(text: &str, needle: &str, label: u8) -> Vec<Span> {
    text.find(needle)
        .map(|i| Span {
            start: u32::try_from(i).unwrap(),
            end: u32::try_from(i + needle.len()).unwrap(),
            label,
            score: 9_100,
        })
        .into_iter()
        .collect()
}

impl Inference for Fake {
    fn info(&self, call: &Call) -> Result<Info, ModeldError> {
        self.log(call, "info".into());
        if let Some(f) = self.fail {
            return Err(f());
        }
        Ok(Info {
            bundle_id: "bundle-fake".into(),
            runtime: "1.28.0".into(),
            models: vec![
                ("gliner-multi-v2.1".into(), [1; 32]),
                ("gliner-multi-pii".into(), [2; 32]),
                ("e5-small".into(), [3; 32]),
            ],
        })
    }

    fn ocr(
        &self,
        call: &Call,
        _pdf: &[u8],
        pages: &[u16],
        dpi: u16,
        _scripts: &[String],
    ) -> Result<Vec<OcrPage>, ModeldError> {
        self.log(call, format!("ocr{pages:?}@{dpi}"));
        Ok(pages
            .iter()
            .map(|p| OcrPage {
                page: *p,
                status: 0,
                width: 1275,
                height: 1650,
                dpi,
                rotate: 0,
                crop: [0.0, 0.0, 612.0, 792.0],
                words: ["Witness:", "Ada", "Lovelace"]
                    .iter()
                    .enumerate()
                    .map(|(i, w)| {
                        let x = 150.0 + 200.0 * i as f32;
                        Word {
                            text: (*w).into(),
                            quad: [
                                (x, 300.0),
                                (x + 150.0, 300.0),
                                (x + 150.0, 330.0),
                                (x, 330.0),
                            ],
                            conf: 9_500,
                        }
                    })
                    .collect(),
                lines: vec![],
                rules: vec![],
                boxes: vec![],
            })
            .collect())
    }

    fn hash(
        &self,
        call: &Call,
        _pdf: &[u8],
        pages: Vec<u16>,
    ) -> Result<Vec<PageHash>, ModeldError> {
        self.log(call, format!("hash{pages:?}"));
        Ok(pages
            .into_iter()
            .map(|p| PageHash {
                page: p,
                dhash: 0xF0F0_0000_1111_0000 ^ u64::from(p),
                phash: 0x0F0F_FFFF_0000_1111,
            })
            .collect())
    }

    fn embed(&self, call: &Call, texts: Vec<String>) -> Result<Vec<Vec<f32>>, ModeldError> {
        self.log(call, format!("embed{}", texts.len()));
        Ok(texts.iter().map(|_| vec![0.6, 0.8]).collect())
    }

    fn entities(&self, call: &Call, req: SpanRequest) -> Result<Vec<Span>, ModeldError> {
        self.log(call, "entities".into());
        assert_eq!(req.labels[1], "date");
        Ok(find(&req.text, "December 1, 2026", 1))
    }

    fn personal(&self, call: &Call, req: SpanRequest) -> Result<Vec<Span>, ModeldError> {
        self.log(call, "personal".into());
        let mut out = find(&req.text, "Ada Lovelace", 0);
        // A span on the address the recognisers already found is dropped as a repeat.
        out.extend(find(&req.text, "ada@example.com", 4));
        Ok(out)
    }
}

/// A two-page PDF: page 1 has a text layer, page 2 none (a scan).
fn two_pages() -> Vec<u8> {
    let content =
        "BT /F1 11 Tf 72 640 Td (Start date: December 1, 2026. Contact ada@example.com) Tj ET";
    let objs = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
        "<< /Type /Pages /Kids [3 0 R 6 0 R] /Count 2 >>".to_owned(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R \
         /Resources << /Font << /F1 5 0 R >> >> >>"
            .to_owned(),
        format!(
            "<< /Length {} >>\nstream\n{content}\nendstream",
            content.len()
        ),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>".to_owned(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 7 0 R /Resources << >> >>"
            .to_owned(),
        "<< /Length 0 >>\nstream\n\nendstream".to_owned(),
    ];
    let mut out = b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n".to_vec();
    let mut offsets = Vec::new();
    for (i, o) in objs.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{o}\nendobj\n", i + 1).as_bytes());
    }
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes());
    for o in offsets {
        out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objs.len() + 1
        )
        .as_bytes(),
    );
    out
}

/// Store `bytes` as a normalized PDF; its SHA-256.
async fn stored(env: &Env, bytes: &[u8]) -> ([u8; 32], Vec<u8>) {
    let d = env.engine.prepare(bytes, &Credentials::default()).unwrap();
    let key = env.blob_store().put(&d.bytes).await.unwrap();
    (key.0, d.bytes)
}

/// What the server does on an upload with features in effect: a run and its job.
async fn enqueue(
    env: &Env,
    kind: &'static str,
    document: Uuid,
    owner: (Option<Uuid>, Option<Uuid>),
    sha: [u8; 32],
    uses: &[&str],
) -> AnalysisRunId {
    let uses: Vec<String> = uses.iter().map(|u| (*u).to_owned()).collect();
    let run = AnalysisRunId(Uuid::now_v7());
    let key = match owner.1 {
        Some(t) => hml::fingerprint_key(env.account, t, document, &sha, "bundle-fake"),
        None => hml::analyze_key(env.account, document, &sha, &uses, "bundle-fake"),
    };
    let mut tx = env.db.store.for_account(env.account).begin().await.unwrap();
    tx.ml()
        .insert_run(&NewRun {
            id: run,
            document_id: document,
            envelope_id: owner.0.map(EnvelopeId),
            template_id: owner.1.map(TemplateId),
            kind: if owner.1.is_some() {
                RunKind::FingerprintTemplate
            } else {
                RunKind::AnalyzeDocument
            },
            uses: uses.clone(),
            document_sha256: sha,
            job_key: key.clone(),
            created_at: time::OffsetDateTime::now_utc(),
        })
        .await
        .unwrap();
    let payload = AnalysisJob {
        run_id: run.0,
        account_id: env.account.0,
        document_id: document,
        envelope_id: owner.0,
        template_id: owner.1,
        uses,
        document_sha256: hml::hex(&sha),
    };
    let job = hml::analysis_job(
        JobId(Uuid::now_v7()),
        kind,
        &payload,
        key,
        casual_sign_worker::Clock::now(env.clock.as_ref()),
    );
    tx.jobs().enqueue(&job).await.unwrap();
    tx.commit().await.unwrap();
    run
}

async fn run_row(env: &Env, run: AnalysisRunId) -> casual_sign_store::repo::ml::Run {
    let mut tx = env.db.store.for_account(env.account).begin().await.unwrap();
    let r = tx.ml().run(run).await.unwrap().unwrap();
    tx.commit().await.unwrap();
    r
}

const ALL_USES: [&str; 4] = ["ocr", "template", "entities", "personal_data"];

#[tokio::test]
async fn an_upload_is_read_and_its_suggestions_name_the_right_text() {
    let Some(env) = Env::new("ml_analyze").await else {
        return;
    };
    let fake = Arc::new(Fake::default());
    *env.inference.lock().unwrap() = Some(fake.clone());
    let ids = env.draft(vec![]).await;
    let before = env.state(ids.env).await;
    let events = env.events(ids.env).await;
    let (sha, pdf) = stored(&env, &two_pages()).await;
    let run = enqueue(
        &env,
        hml::ANALYZE_DOCUMENT,
        ids.doc,
        (Some(ids.env), None),
        sha,
        &ALL_USES,
    )
    .await;

    let out = env.run().await;
    assert!(
        out.contains(&(hml::ANALYZE_DOCUMENT.to_owned(), JobOutcome::Done)),
        "{out:?}"
    );
    let r = run_row(&env, run).await;
    assert_eq!(r.status, RunStatus::Done);
    assert_eq!(r.bundle_id.as_deref(), Some("bundle-fake"));
    assert_eq!(
        r.ocr_pages,
        vec![2],
        "only the page without a text layer is read"
    );
    let calls = fake.calls();
    let acct = env.account.0.simple().to_string();
    assert!(calls.contains(&format!("ocr[1]@150:{acct}")), "{calls:?}");
    assert!(
        calls.iter().all(|c| c.ends_with(&acct)),
        "every call names the account"
    );
    // No fingerprints in the account: no page hashes asked for an upload.
    assert!(!calls.iter().any(|c| c.starts_with("hash")), "{calls:?}");

    // Each span names its text in the page's analysed text (the layer, or OCR words).
    let layers = env.engine.page_texts(&pdf).unwrap();
    let mut tx = env.db.store.for_account(env.account).begin().await.unwrap();
    let words = tx.ml().ocr_pages(run).await.unwrap();
    let list = tx
        .ml()
        .envelope_suggestions(EnvelopeId(ids.env), Default::default(), 200)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(words.len(), 1);
    let w = &words[0].1[1];
    assert_eq!(w["text"], "Ada");
    // 350 px at 150 DPI is 168 pt.
    assert!((w["x"].as_f64().unwrap() - 168.0).abs() < 0.01, "{w}");
    let text_of = |page: i32| {
        let i = usize::try_from(page - 1).unwrap();
        let ocr = words.iter().find(|(p, _)| *p == page).map(|(_, v)| v);
        hml::page_text(&layers[i], ocr)
    };
    let shown: Vec<(String, String, String, i32)> = list
        .iter()
        .map(|s| {
            let (a, b) = s.span.unwrap();
            let t = text_of(s.page.unwrap());
            (
                s.kind.as_str().to_owned(),
                s.label.clone(),
                hml::span_text(&t, a, b).unwrap().to_owned(),
                s.page.unwrap(),
            )
        })
        .collect();
    let want = |k: &str, l: &str, v: &str, p: i32| (k.to_owned(), l.to_owned(), v.to_owned(), p);
    assert!(
        shown.contains(&want("entity", "Date", "December 1, 2026", 1)),
        "{shown:?}"
    );
    assert!(
        shown.contains(&want(
            "personal_data",
            "Email address",
            "ada@example.com",
            1
        )),
        "{shown:?}"
    );
    assert!(
        shown.contains(&want("personal_data", "Person name", "Ada Lovelace", 2)),
        "{shown:?}"
    );
    assert_eq!(
        shown.iter().filter(|s| s.2 == "ada@example.com").count(),
        1,
        "the model's repeat of a recognised span is dropped"
    );
    let email = list.iter().find(|s| s.label == "Email address").unwrap();
    assert_eq!(email.model_id, "casual-sign-pii");
    let date = list.iter().find(|s| s.label == "Date").unwrap();
    assert_eq!(
        (date.model_id.as_str(), date.weights_sha256),
        ("gliner-multi-v2.1", [1; 32])
    );

    // Advisory: the envelope and its evidence are exactly as they were.
    let after = env.state(ids.env).await;
    assert_eq!(after.version, before.version);
    assert_eq!(after.status, before.status);
    assert_eq!(env.events(ids.env).await, events);
}

#[tokio::test]
async fn a_template_is_fingerprinted_and_a_matching_upload_suggests_it() {
    let Some(env) = Env::new("ml_template").await else {
        return;
    };
    let fake = Arc::new(Fake::default());
    *env.inference.lock().unwrap() = Some(fake.clone());
    let (sha, pdf) = stored(&env, &two_pages()).await;
    let t = TemplateId(Uuid::now_v7());
    let d = TemplateDocumentId(Uuid::now_v7());
    let mut tx = env.db.store.for_account(env.account).begin().await.unwrap();
    tx.templates()
        .insert(&Template {
            id: t,
            owner_user_id: env.sender,
            name: "Mutual NDA".into(),
            email_subject: None,
            email_message: None,
            settings: serde_json::json!({}),
            matching_rules: serde_json::json!([]),
            version: 1,
        })
        .await
        .unwrap();
    tx.templates()
        .add_document(&TemplateDocument {
            id: d,
            template_id: t,
            ord: 0,
            name: "nda.pdf".into(),
            sha256: sha,
            byte_len: i64::try_from(pdf.len()).unwrap(),
            page_count: 2,
            pages: serde_json::json!([{}, {}]),
        })
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let fp = enqueue(
        &env,
        hml::FINGERPRINT_TEMPLATE,
        d.0,
        (None, Some(t.0)),
        sha,
        &["template"],
    )
    .await;
    let out = env.run().await;
    assert!(
        out.contains(&(hml::FINGERPRINT_TEMPLATE.to_owned(), JobOutcome::Done)),
        "{out:?}"
    );
    assert_eq!(run_row(&env, fp).await.status, RunStatus::Done);
    let mut tx = env.db.store.for_account(env.account).begin().await.unwrap();
    let prints = tx.ml().fingerprints().await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(prints.len(), 2);
    assert!(
        prints[0].embedding.is_some(),
        "page 1 has text, so an embedding"
    );
    assert!(prints[1].embedding.is_none(), "page 2 has none");

    // An upload of the same pages matches.
    let ids = env.draft(vec![]).await;
    let run = enqueue(
        &env,
        hml::ANALYZE_DOCUMENT,
        ids.doc,
        (Some(ids.env), None),
        sha,
        &["template"],
    )
    .await;
    env.run().await;
    assert_eq!(run_row(&env, run).await.status, RunStatus::Done);
    let mut tx = env.db.store.for_account(env.account).begin().await.unwrap();
    let list = tx
        .ml()
        .envelope_suggestions(EnvelopeId(ids.env), Default::default(), 10)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(list.len(), 1, "{list:?}");
    assert_eq!(list[0].label, "Mutual NDA");
    assert_eq!(list[0].template, Some((t, Some(2), Some(2))));
    assert!(list[0].score > 0.9, "{}", list[0].score);
}

#[tokio::test]
async fn a_final_model_error_fails_the_run_and_no_service_leaves_it_unavailable() {
    let Some(env) = Env::new("ml_failures").await else {
        return;
    };
    let ids = env.draft(vec![]).await;
    let (sha, _) = stored(&env, &two_pages()).await;
    // No model service configured.
    let none = enqueue(
        &env,
        hml::ANALYZE_DOCUMENT,
        ids.doc,
        (Some(ids.env), None),
        sha,
        &["ocr"],
    )
    .await;
    env.run().await;
    assert_eq!(run_row(&env, none).await.status, RunStatus::Unavailable);
    // A final error (inference failed inside the runtime): failed with its code, and
    // the job is done, not dead (a dead analysis would alert an operator for nothing).
    let fake = Arc::new(Fake {
        fail: Some(|| ModeldError::Inference),
        ..Fake::default()
    });
    *env.inference.lock().unwrap() = Some(fake);
    let failed = enqueue(
        &env,
        hml::ANALYZE_DOCUMENT,
        ids.doc,
        (Some(ids.env), None),
        sha,
        &["entities"],
    )
    .await;
    let out = env.run().await;
    assert!(
        out.contains(&(hml::ANALYZE_DOCUMENT.to_owned(), JobOutcome::Done)),
        "{out:?}"
    );
    let r = run_row(&env, failed).await;
    assert_eq!(
        (r.status, r.code.as_deref()),
        (RunStatus::Failed, Some("CS-ML-0013"))
    );
    assert!(env.alerts.0.lock().unwrap().is_empty());
}

/// Analysis rows of an envelope or a template, by table (the owner role, for counting):
/// runs, their suggestions, their OCR pages, and the template's page prints.
async fn derived(env: &Env, envelope: Option<Uuid>, template: Option<Uuid>) -> [i64; 4] {
    const QUERIES: [&str; 4] = [
        "SELECT count(*) FROM analysis_runs WHERE account_id = $1 \
         AND (envelope_id = $2 OR template_id = $3)",
        "SELECT count(*) FROM suggestions WHERE account_id = $1 AND (template_id = $3 \
         OR run_id IN (SELECT id FROM analysis_runs WHERE account_id = $1 \
         AND (envelope_id = $2 OR template_id = $3)))",
        "SELECT count(*) FROM ocr_pages WHERE account_id = $1 \
         AND run_id IN (SELECT id FROM analysis_runs WHERE account_id = $1 \
         AND (envelope_id = $2 OR template_id = $3))",
        "SELECT count(*) FROM template_fingerprints WHERE account_id = $1 \
         AND template_id = $3 AND ($2::uuid IS NULL OR true)",
    ];
    let mut out = [0; 4];
    for (i, q) in QUERIES.into_iter().enumerate() {
        out[i] = sqlx::query_scalar::<_, i64>(q)
            .bind(env.account.0)
            .bind(envelope)
            .bind(template)
            .fetch_one(&env.db.admin)
            .await
            .unwrap();
    }
    out
}

/// `ML-31`, `SEC-I07`: analysis is derived document content. Purging an envelope (a
/// deleted draft) removes its runs, their suggestions and OCR pages; deleting a template
/// removes its run, its page prints and every suggestion naming it. Another envelope's
/// analysis stays.
#[tokio::test]
async fn purging_an_envelope_or_a_template_purges_its_analysis() {
    let Some(env) = Env::new("ml_purge").await else {
        return;
    };
    let fake = Arc::new(Fake::default());
    *env.inference.lock().unwrap() = Some(fake);
    let (sha, pdf) = stored(&env, &two_pages()).await;
    let t = TemplateId(Uuid::now_v7());
    let d = TemplateDocumentId(Uuid::now_v7());
    let mut tx = env.db.store.for_account(env.account).begin().await.unwrap();
    tx.templates()
        .insert(&Template {
            id: t,
            owner_user_id: env.sender,
            name: "Mutual NDA".into(),
            email_subject: None,
            email_message: None,
            settings: serde_json::json!({}),
            matching_rules: serde_json::json!([]),
            version: 1,
        })
        .await
        .unwrap();
    tx.templates()
        .add_document(&TemplateDocument {
            id: d,
            template_id: t,
            ord: 0,
            name: "nda.pdf".into(),
            sha256: sha,
            byte_len: i64::try_from(pdf.len()).unwrap(),
            page_count: 2,
            pages: serde_json::json!([{}, {}]),
        })
        .await
        .unwrap();
    tx.commit().await.unwrap();
    enqueue(
        &env,
        hml::FINGERPRINT_TEMPLATE,
        d.0,
        (None, Some(t.0)),
        sha,
        &["template"],
    )
    .await;
    env.run().await;

    let gone = env.draft(vec![]).await;
    let kept = env.draft(vec![]).await;
    for ids in [gone, kept] {
        enqueue(
            &env,
            hml::ANALYZE_DOCUMENT,
            ids.doc,
            (Some(ids.env), None),
            sha,
            &ALL_USES,
        )
        .await;
    }
    env.run().await;
    let before = derived(&env, Some(gone.env), None).await;
    assert!(
        before[0] == 1 && before[1] > 1 && before[2] == 1,
        "the envelope has a run, suggestions (a template one too) and an OCR page: {before:?}"
    );
    let other = derived(&env, Some(kept.env), None).await;

    env.apply(gone.env, env.as_sender(), Command::DeleteDraft)
        .await;
    let out = env.run().await;
    assert!(
        out.iter()
            .any(|(k, o)| k == "delete_draft" && *o == JobOutcome::Done),
        "{out:?}"
    );
    assert_eq!(
        derived(&env, Some(gone.env), None).await,
        [0; 4],
        "a purged envelope keeps no run, suggestion or OCR page"
    );
    assert_eq!(derived(&env, Some(kept.env), None).await, other);
    // An analysis asked for as the draft was deleted, queued after the purge ran, finds
    // the envelope purged and leaves nothing behind.
    enqueue(
        &env,
        hml::ANALYZE_DOCUMENT,
        gone.doc,
        (Some(gone.env), None),
        sha,
        &["ocr", "entities"],
    )
    .await;
    env.run().await;
    assert_eq!(
        derived(&env, Some(gone.env), None).await,
        [0; 4],
        "an analysis queued after the purge writes nothing back"
    );

    // A template deleted for good takes its run, its page prints and the suggestions
    // that name it, in every envelope.
    let prints = derived(&env, None, Some(t.0)).await;
    assert!(
        prints[0] == 1 && prints[1] == 1 && prints[3] == 2,
        "its run, the kept envelope's suggestion of it, two page prints: {prints:?}"
    );
    let mut tx = env.db.store.for_account(env.account).begin().await.unwrap();
    tx.templates().delete(t).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(derived(&env, None, Some(t.0)).await, [0; 4]);
    let left = derived(&env, Some(kept.env), None).await;
    assert_eq!((left[0], left[2]), (other[0], other[2]));
    assert_eq!(left[1], other[1] - 1, "only its template suggestion went");
}

/// One envelope taken from draft to sealed in a world of fixed ids; with `ml`, its
/// document is analysed with every feature on before it is sent and its suggestions are
/// decided. The sealed bytes, the chain's event types, and the stored original and
/// delivered documents afterwards.
async fn sealed_world(
    name: &str,
    ml: bool,
) -> Option<(Vec<Vec<u8>>, Vec<String>, Vec<u8>, Vec<u8>)> {
    let fixed = |n: u128| Uuid::from_u128(0x0193_0000_0000_7000_8000_0000_0000_0000 | n);
    let mut env = Env::with_ids(
        name,
        casual_sign_store::AccountId(fixed(1)),
        casual_sign_store::UserId(fixed(2)),
    )
    .await?;
    // A document with text to find and a scanned page to read.
    env.original = two_pages();
    let (_, delivered) = stored(&env, &env.original).await;
    env.delivered = delivered;
    env.pages = 2;
    let ids = common::Ids {
        env: fixed(3),
        doc: fixed(4),
        r1: fixed(5),
        r2: fixed(6),
        f1: fixed(7),
        f2: fixed(8),
    };
    env.blob_store().put(&env.original).await.unwrap();
    env.draft_with(ids, vec![]).await;
    if ml {
        *env.inference.lock().unwrap() = Some(Arc::new(Fake::default()));
        let sha = *casual_sign_sdk::Hash256::digest(&env.delivered).as_bytes();
        let run = enqueue(
            &env,
            hml::ANALYZE_DOCUMENT,
            ids.doc,
            (Some(ids.env), None),
            sha,
            &ALL_USES,
        )
        .await;
        env.run().await;
        assert_eq!(run_row(&env, run).await.status, RunStatus::Done);
        let mut tx = env.db.store.for_account(env.account).begin().await.unwrap();
        let list = tx
            .ml()
            .envelope_suggestions(EnvelopeId(ids.env), Default::default(), 200)
            .await
            .unwrap();
        for (i, s) in list.iter().enumerate() {
            let state = if i % 2 == 0 {
                casual_sign_store::repo::ml::SuggestionState::Accepted
            } else {
                casual_sign_store::repo::ml::SuggestionState::Dismissed
            };
            tx.ml()
                .decide(s.id, state, env.sender, time::OffsetDateTime::now_utc())
                .await
                .unwrap();
        }
        tx.commit().await.unwrap();
        assert!(!list.is_empty(), "the analysis suggested something");
    }
    env.send(ids).await;
    env.run().await;
    env.sign(ids, ids.r1, ids.f1, "Ada Lovelace").await;
    env.run().await;
    env.sign(ids, ids.r2, ids.f2, "Grace Hopper").await;
    let out = env.run().await;
    assert!(out.iter().all(|(_, o)| *o == JobOutcome::Done), "{out:?}");
    let state = env.state(ids.env).await;
    assert_eq!(
        state.status,
        casual_sign_model::EnvelopeStatus::Completed,
        "sealed and verified"
    );
    let blobs = env.blob_store();
    let key = |b: &[u8]| BlobKey(*casual_sign_sdk::Hash256::digest(b).as_bytes());
    let original = blobs.get(&key(&env.original)).await.unwrap();
    let delivered = blobs.get(&key(&env.delivered)).await.unwrap();
    assert_eq!(original, env.original);
    assert_eq!(delivered, env.delivered);
    Some((
        env.sealed_bytes(ids.env).await,
        env.events(ids.env).await,
        original,
        delivered,
    ))
}

/// `ML-32`, `SEC-I13`: analysis is advisory. An envelope whose document was analysed
/// with every feature on (OCR, template matching, entities, personal data) and its
/// suggestions accepted or dismissed seals to the same bytes, with the same audit chain,
/// as the same envelope with ML off; the original and delivered documents are untouched.
#[tokio::test]
async fn analysis_never_changes_the_sealed_or_original_document_bytes() {
    let Some(off) = sealed_world("ml_seal_off", false).await else {
        return;
    };
    let on = sealed_world("ml_seal_on", true).await.unwrap();
    assert_eq!(off.0.len(), 1);
    assert_eq!(off.1, on.1, "the same audit chain");
    assert_eq!(
        (&off.2, &off.3),
        (&on.2, &on.3),
        "the same stored documents"
    );
    // Every byte a signature covers is the same; only each signature's `/Contents` (the
    // CMS, whose ECDSA values and timestamp tokens differ from one seal to the next even
    // with ML off) may differ, at the same offsets.
    let (a, b) = (&off.0[0], &on.0[0]);
    assert_eq!(a.len(), b.len(), "sealed lengths");
    let gaps = unsigned_gaps(a);
    assert!(!gaps.is_empty(), "the sealed PDF has a signature");
    assert_eq!(gaps, unsigned_gaps(b), "the same byte ranges are signed");
    let mut at = 0;
    for (start, end) in gaps.iter().copied().chain([(a.len(), a.len())]) {
        assert!(
            a[at..start] == b[at..start],
            "signed bytes {at}..{start} differ with ML on"
        );
        at = end;
    }
    // The worker verified its seal before `completed`; pyHanko checks the ML-on one.
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("worker-ml-sealed");
    common::independent(&dir, &[("ml-on-bt.pdf".into(), b.clone())]);
}

/// The byte ranges no signature covers (each `/ByteRange [a b c d]`'s gap `a+b..c`),
/// sorted.
fn unsigned_gaps(pdf: &[u8]) -> Vec<(usize, usize)> {
    let needle = b"/ByteRange [";
    let mut out = Vec::new();
    for i in 0..pdf.len().saturating_sub(needle.len()) {
        if &pdf[i..i + needle.len()] != needle {
            continue;
        }
        let rest = &pdf[i + needle.len()..];
        let close = rest.iter().position(|c| *c == b']').unwrap();
        let n: Vec<usize> = std::str::from_utf8(&rest[..close])
            .unwrap()
            .split_whitespace()
            .map(|v| v.parse().unwrap())
            .collect();
        assert_eq!(n.len(), 4);
        out.push((n[0] + n[1], n[2]));
    }
    out.sort_unstable();
    out
}
