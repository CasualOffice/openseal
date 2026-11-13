//! Document analysis through the API (WEB-19, ML-01; docs/33 §2, §6, §7):
//!
//! - With every feature off (the default), no analysis job or run is ever written and
//!   detect-fields answers the same bytes as with every feature on (`ML-01` exit).
//! - Settings: off at every level, `not_in_plan` and `installed` reported, turning on a
//!   feature outside the plan or without a model service refused with `CS-ML-0011`,
//!   administrators only.
//! - An upload enqueues `analyze_document` keyed by account and document (`SEC-I06`:
//!   two accounts uploading identical bytes get two runs); asking again is idempotent.
//! - Suggestions list with their value read from the stored text, filter and paginate,
//!   are accepted or dismissed once (`CS-ML-0012`), and another account's envelope,
//!   document or suggestion is `404`.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use axum::http::StatusCode;
use casual_sign_store::repo::ml::{NewSuggestion, RunEnd, RunStatus, SuggestionKind};
use casual_sign_store::{AccountId, AnalysisRunId, SuggestionId};
use common::Rls;
use common::flow::{b64, ok};
use common::harness::{Api, Auth, Tenant, pdf, text_pdf};
use serde_json::{Value, json};
use sqlx::Row;

const BUNDLE: &str = "bundle-test-1";
const ALL: &str = "{ml.ocr,ml.template_matching,ml.extraction,ml.personal_data}";
const TEXT: &str = "BT /F1 11 Tf 72 640 Td (Start date: December 1, 2026) Tj ET \
                    BT /F1 11 Tf 72 600 Td (Signature: ____________________) Tj ET";

async fn with_bundle(test: &str) -> Option<Api> {
    Api::with(test, Rls::On, |c| c.ml_bundle = Some(BUNDLE.into())).await
}

/// What the operator does (as the migrator role): entitle the workspace.
async fn entitle(api: &Api, t: &Tenant, features: &str) {
    sqlx::query(
        "INSERT INTO ml_entitlements (account_id, features) VALUES ($1, $2::text[]) \
         ON CONFLICT (account_id) DO UPDATE SET features = EXCLUDED.features",
    )
    .bind(t.boot.account.0)
    .bind(features)
    .execute(&api.db.admin)
    .await
    .unwrap();
}

async fn all_on(api: &Api, t: &Tenant) {
    entitle(api, t, ALL).await;
    ok(
        api.call(
            "PATCH",
            "/api/v1/account/settings/ml",
            &t.auth,
            Some(json!({"ocr": true, "template_matching": true, "extraction": true, "personal_data": true})),
            &[],
        )
        .await,
        StatusCode::OK,
        "all on",
    );
}

async fn ml_rows(api: &Api) -> (i64, i64) {
    let jobs: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM jobs WHERE kind IN ('analyze_document', 'fingerprint_template')",
    )
    .fetch_one(&api.db.admin)
    .await
    .unwrap();
    let runs: i64 = sqlx::query_scalar("SELECT count(*) FROM analysis_runs")
        .fetch_one(&api.db.admin)
        .await
        .unwrap();
    (jobs, runs)
}

async fn draft(api: &Api, t: &Tenant, bytes: &[u8]) -> (String, String) {
    let e = ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            &t.auth,
            Some(json!({"subject": "d", "documents": [{"name": "d.pdf", "content_base64": b64(bytes)}]})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "draft",
    );
    (
        e["id"].as_str().unwrap().to_owned(),
        e["documents"][0]["id"].as_str().unwrap().to_owned(),
    )
}

/// `ML-01`'s exit: with every feature off no job and no run is written on any upload
/// path, and detect-fields is byte-identical to its answer with every feature on.
#[tokio::test]
async fn with_every_feature_off_nothing_is_enqueued_and_detect_fields_is_unchanged() {
    let Some(api) = with_bundle("ml_off_enqueues_nothing").await else {
        return;
    };
    let a = api.tenant("alpha").await;
    // Entitled but not turned on, then turned on but not entitled: both are "off".
    entitle(&api, &a, ALL).await;
    let (id, doc) = draft(&api, &a, &text_pdf(TEXT)).await;
    ok(
        api.call(
            "POST",
            &format!("/api/v1/envelopes/{id}/documents"),
            &a.auth,
            Some(json!({"name": "e.pdf", "content_base64": b64(&pdf(1))})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "second document",
    );
    let t = ok(
        api.call(
            "POST",
            "/api/v1/templates",
            &a.auth,
            Some(json!({"name": "T", "roles": [{"name": "R", "type": "signer"}]})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "template",
    );
    let tid = t["id"].as_str().unwrap();
    ok(
        api.call(
            "POST",
            &format!("/api/v1/templates/{tid}/documents"),
            &a.auth,
            Some(json!({"name": "t.pdf", "content_base64": b64(&pdf(1))})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "template document",
    );
    assert_eq!(ml_rows(&api).await, (0, 0), "an ML job or run with ML off");
    let detect = format!("/api/v1/envelopes/{id}/documents/{doc}/detect-fields");
    let off = api.call("POST", &detect, &a.auth, None, &[]).await;
    assert_eq!(off.status, StatusCode::OK);
    // Every ML call answers CS-ML-0011, which the web app reads as "hide".
    for (m, p) in [
        ("GET", format!("/api/v1/envelopes/{id}/suggestions")),
        (
            "GET",
            format!("/api/v1/envelopes/{id}/documents/{doc}/analysis"),
        ),
        (
            "POST",
            format!("/api/v1/envelopes/{id}/documents/{doc}/analysis"),
        ),
    ] {
        let r = api.call(m, &p, &a.auth, None, &[]).await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (StatusCode::FORBIDDEN, "CS-ML-0011"),
            "{m} {p}"
        );
    }
    assert_eq!(ml_rows(&api).await, (0, 0));
    // On: detect-fields still answers the same bytes (OCR suggestions merge later, ML-02).
    all_on(&api, &a).await;
    let on = api.call("POST", &detect, &a.auth, None, &[]).await;
    assert_eq!(on.body, off.body, "detect-fields changed with ML on");

    // Without a model service, nothing is in effect whatever the settings say.
    let Some(bare) = Api::new("ml_not_installed", Rls::On).await else {
        return;
    };
    let b = bare.tenant("bravo").await;
    entitle(&bare, &b, ALL).await;
    sqlx::query(
        "INSERT INTO ml_settings (account_id, ocr, extraction, updated_at) VALUES ($1, true, true, now())",
    )
    .bind(b.boot.account.0)
    .execute(&bare.db.admin)
    .await
    .unwrap();
    draft(&bare, &b, &pdf(1)).await;
    assert_eq!(
        ml_rows(&bare).await,
        (0, 0),
        "an ML job without a model service"
    );
    let s = ok(
        bare.call("GET", "/api/v1/account/settings/ml", &b.auth, None, &[])
            .await,
        StatusCode::OK,
        "settings",
    );
    assert_eq!(s["installed"], false);
    let r = bare
        .call(
            "PATCH",
            "/api/v1/account/settings/ml",
            &b.auth,
            Some(json!({"template_matching": true})),
            &[],
        )
        .await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::FORBIDDEN, "CS-ML-0011")
    );
}

#[tokio::test]
async fn settings_are_off_by_default_and_gated_by_plan_and_admin() {
    let Some(api) = with_bundle("ml_settings").await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let s = ok(
        api.call("GET", "/api/v1/account/settings/ml", &a.auth, None, &[])
            .await,
        StatusCode::OK,
        "defaults",
    );
    assert_eq!(
        s,
        json!({"ocr": false, "template_matching": false, "extraction": false, "personal_data": false,
            "personal_data_model": null, "ocr_scripts": [], "reread_scanner_text": false,
            "not_in_plan": ["ocr", "template_matching", "extraction", "personal_data"], "installed": true})
    );
    let patch = |body: Value| {
        api.call(
            "PATCH",
            "/api/v1/account/settings/ml",
            &a.auth,
            Some(body),
            &[],
        )
    };
    let r = patch(json!({"ocr": true})).await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::FORBIDDEN, "CS-ML-0011")
    );
    // Turning off is always allowed.
    ok(patch(json!({"ocr": false})).await, StatusCode::OK, "off");
    entitle(&api, &a, "{ml.ocr,ml.extraction}").await;
    let s = ok(
        patch(json!({"ocr": true, "ocr_scripts": ["latin", "arabic", "latin"], "personal_data_model": "gliner-pii-base"})).await,
        StatusCode::OK,
        "on",
    );
    assert_eq!(s["ocr"], true);
    assert_eq!(s["ocr_scripts"], json!(["latin", "arabic"]));
    assert_eq!(s["personal_data_model"], "gliner-pii-base");
    assert_eq!(
        s["not_in_plan"],
        json!(["template_matching", "personal_data"])
    );
    let r = patch(json!({"personal_data": true})).await;
    assert_eq!(r.code(), "CS-ML-0011");
    let r = patch(json!({"ocr_scripts": ["klingon"]})).await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, "CS-API-0001")
    );
    let r = patch(json!({"surprise": true})).await;
    assert_eq!(r.code(), "CS-API-0001");
    ok(
        patch(json!({"personal_data_model": null})).await,
        StatusCode::OK,
        "reset model",
    );
    // A credential without admin:account is refused.
    let key = ok(
        api.call(
            "POST",
            "/api/v1/api-clients",
            &a.auth,
            Some(json!({"name": "k", "kind": "api_key", "scopes": ["envelopes:read", "envelopes:write"]})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "key",
    );
    let narrow = Auth::Bearer(key["key"].as_str().unwrap().to_owned());
    let r = api
        .call("GET", "/api/v1/account/settings/ml", &narrow, None, &[])
        .await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::FORBIDDEN, "CS-AUTH-0006")
    );
    // The workspace cannot grant itself an entitlement.
    let mut tx = api
        .db
        .store
        .for_account(a.boot.account)
        .begin()
        .await
        .unwrap();
    assert!(tx.ml().entitlements().await.unwrap().len() == 2);
    tx.commit().await.unwrap();
    let denied = sqlx::query("UPDATE ml_entitlements SET features = '{ml.personal_data}'")
        .execute(&api.db.app)
        .await;
    assert!(denied.is_err(), "the application role wrote an entitlement");
}

/// `SEC-I06`: two accounts uploading identical bytes get two runs, each keyed by its own
/// account and document.
#[tokio::test]
async fn identical_bytes_in_two_accounts_are_two_runs() {
    let Some(api) = with_bundle("ml_two_accounts").await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let b = api.tenant("bravo").await;
    all_on(&api, &a).await;
    all_on(&api, &b).await;
    let bytes = text_pdf(TEXT);
    let (_, da) = draft(&api, &a, &bytes).await;
    let (_, db) = draft(&api, &b, &bytes).await;
    let rows = sqlx::query(
        "SELECT account_id, idempotency_key, payload FROM jobs WHERE kind = 'analyze_document' ORDER BY created_at",
    )
    .fetch_all(&api.db.admin)
    .await
    .unwrap();
    assert_eq!(rows.len(), 2);
    for (row, (t, d)) in rows.iter().zip([(&a, &da), (&b, &db)]) {
        let acct: uuid::Uuid = row.get(0);
        let key: String = row.get(1);
        let payload: Value = row.get(2);
        assert_eq!(acct, t.boot.account.0);
        assert!(
            key.starts_with(&format!("analyze:{}:{d}:", t.boot.account.0)),
            "{key}"
        );
        assert!(key.ends_with(&format!(":ocr,template,entities,personal_data:{BUNDLE}")));
        assert_eq!(payload["document_id"], d.as_str());
        assert_eq!(
            payload["uses"],
            json!(["ocr", "template", "entities", "personal_data"])
        );
    }
    let keys: Vec<String> = rows.iter().map(|r| r.get(1)).collect();
    assert_ne!(keys[0], keys[1]);
}

/// Record what a worker would: a finished run with two spans and a template match.
async fn finish_with_suggestions(
    api: &Api,
    account: AccountId,
    run: AnalysisRunId,
    document: uuid::Uuid,
    template: Option<casual_sign_store::TemplateId>,
) -> Vec<SuggestionId> {
    let mut tx = api.db.store.for_account(account).begin().await.unwrap();
    // "Start date: December 1, 2026": "December 1, 2026" is bytes 12..28.
    let s = |kind, label: &str, span, score| NewSuggestion {
        id: SuggestionId(uuid::Uuid::now_v7()),
        kind,
        page: Some(1),
        rect: None,
        label: label.into(),
        span,
        normalized: None,
        template: None,
        score,
        model_id: "gliner-multi".into(),
        weights_sha256: [9; 32],
    };
    let mut list = vec![
        s(SuggestionKind::Entity, "Start date", Some((12, 28)), 0.97),
        s(SuggestionKind::PersonalData, "Date", Some((12, 28)), 0.6),
    ];
    if let Some(t) = template {
        let mut m = s(SuggestionKind::Template, "T", None, 0.96);
        m.template = Some((t, 1, 1));
        list.push(m);
    }
    tx.ml().add_suggestions(run, document, &list).await.unwrap();
    tx.ml()
        .finish_run(
            run,
            &RunEnd {
                status: RunStatus::Done,
                bundle_id: Some(BUNDLE.into()),
                ort_version: Some("1.28.0".into()),
                ocr_pages: vec![],
                truncated: false,
                code: None,
                at: common::harness::start(),
            },
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    list.iter().map(|x| x.id).collect()
}

#[tokio::test]
async fn analysis_and_suggestions_end_to_end_and_other_accounts_are_refused() {
    let Some(api) = with_bundle("ml_suggestions").await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let b = api.tenant("bravo").await;
    all_on(&api, &a).await;
    all_on(&api, &b).await;
    let t = ok(
        api.call(
            "POST",
            "/api/v1/templates",
            &a.auth,
            Some(json!({"name": "T", "roles": [{"name": "R", "type": "signer"}]})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "template",
    );
    let tid = t["id"].as_str().unwrap().to_owned();
    let with = ok(
        api.call(
            "POST",
            &format!("/api/v1/templates/{tid}/documents"),
            &a.auth,
            Some(json!({"name": "t.pdf", "content_base64": b64(&pdf(1))})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "template document",
    );
    let tdoc = with["documents"][0]["id"].as_str().unwrap().to_owned();
    let fp: i64 =
        sqlx::query_scalar("SELECT count(*) FROM jobs WHERE kind = 'fingerprint_template'")
            .fetch_one(&api.db.admin)
            .await
            .unwrap();
    assert_eq!(fp, 1, "a template document's page hashes are enqueued");
    let tpath = format!("/api/v1/templates/{tid}/documents/{tdoc}/analysis");
    let tr = ok(
        api.call("POST", &tpath, &a.auth, None, &[]).await,
        StatusCode::ACCEPTED,
        "template analysis",
    );
    assert_eq!(tr["uses"], json!(["template"]));
    let tg = ok(
        api.call("GET", &tpath, &a.auth, None, &[]).await,
        StatusCode::OK,
        "template analysis get",
    );
    assert_eq!(tg["id"], tr["id"], "the upload's run, found again");
    assert_eq!(
        api.call("GET", &tpath, &b.auth, None, &[]).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        api.call("POST", &tpath, &b.auth, None, &[]).await.status,
        StatusCode::NOT_FOUND
    );

    let (id, doc) = draft(&api, &a, &text_pdf(TEXT)).await;
    let path = format!("/api/v1/envelopes/{id}/documents/{doc}/analysis");
    let first = ok(
        api.call("GET", &path, &a.auth, None, &[]).await,
        StatusCode::OK,
        "analysis",
    );
    assert_eq!(first["status"], "queued");
    assert_eq!(
        first["uses"],
        json!(["ocr", "template", "entities", "personal_data"])
    );
    let again = ok(
        api.call("POST", &path, &a.auth, None, &[]).await,
        StatusCode::ACCEPTED,
        "again",
    );
    assert_eq!(again["id"], first["id"], "asking again finds the same run");
    let jobs: i64 = sqlx::query_scalar("SELECT count(*) FROM jobs WHERE kind = 'analyze_document'")
        .fetch_one(&api.db.admin)
        .await
        .unwrap();
    assert_eq!(jobs, 1);

    let run = AnalysisRunId(first["id"].as_str().unwrap().parse().unwrap());
    let ids = finish_with_suggestions(
        &api,
        a.boot.account,
        run,
        doc.parse().unwrap(),
        Some(casual_sign_store::TemplateId(tid.parse().unwrap())),
    )
    .await;
    let done = ok(
        api.call("GET", &path, &a.auth, None, &[]).await,
        StatusCode::OK,
        "done",
    );
    assert_eq!(done["status"], "done");
    assert_eq!(done["bundle_id"], BUNDLE);

    let list = format!("/api/v1/envelopes/{id}/suggestions");
    let all = ok(
        api.call("GET", &list, &a.auth, None, &[]).await,
        StatusCode::OK,
        "list",
    );
    let items = all["items"].as_array().unwrap();
    assert_eq!(items.len(), 3, "{all}");
    assert_eq!(items[0]["kind"], "entity");
    assert_eq!(
        items[0]["value"], "December 1, 2026",
        "the value is read from the stored text"
    );
    assert_eq!(items[0]["model"]["sha256"], "09".repeat(32));
    assert_eq!(items[0]["state"], "open");
    assert_eq!(items[2]["kind"], "template");
    assert_eq!(items[2]["template_id"], tid.as_str());
    assert_eq!(items[2]["pages_matched"], 1);
    assert!(items[2]["value"].is_null());
    let page = ok(
        api.call("GET", &format!("{list}?limit=1"), &a.auth, None, &[])
            .await,
        StatusCode::OK,
        "page",
    );
    assert_eq!(page["items"].as_array().unwrap().len(), 1);
    let next = page["next_cursor"].as_str().unwrap();
    let rest = ok(
        api.call(
            "GET",
            &format!("{list}?limit=5&cursor={next}"),
            &a.auth,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "rest",
    );
    assert_eq!(rest["items"].as_array().unwrap().len(), 2);
    assert!(rest["next_cursor"].is_null());
    let pii = ok(
        api.call(
            "GET",
            &format!("{list}?kind=personal_data"),
            &a.auth,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "kind",
    );
    assert_eq!(pii["items"].as_array().unwrap().len(), 1);
    assert_eq!(
        api.call("GET", &format!("{list}?kind=nope"), &a.auth, None, &[])
            .await
            .code(),
        "CS-API-0001"
    );

    // Another account: the envelope, the document and the suggestions are not found.
    for (m, p) in [
        ("GET", list.clone()),
        ("GET", path.clone()),
        ("POST", path.clone()),
        ("POST", format!("{list}/{}/accept", ids[0])),
        ("POST", format!("{list}/{}/dismiss", ids[0])),
    ] {
        let r = api.call(m, &p, &b.auth, None, &[]).await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (StatusCode::NOT_FOUND, "CS-API-0002"),
            "{m} {p}"
        );
    }
    // ... nor through B's own envelope.
    let (bid, _) = draft(&api, &b, &pdf(1)).await;
    let r = api
        .call(
            "POST",
            &format!("/api/v1/envelopes/{bid}/suggestions/{}/accept", ids[0]),
            &b.auth,
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    let accepted = ok(
        api.call(
            "POST",
            &format!("{list}/{}/accept", ids[0]),
            &a.auth,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "accept",
    );
    assert_eq!(accepted["state"], "accepted");
    assert_eq!(accepted["decided_by"], a.boot.admin.0.to_string());
    assert!(accepted["decided_at"].is_string());
    let r = api
        .call(
            "POST",
            &format!("{list}/{}/accept", ids[0]),
            &a.auth,
            None,
            &[],
        )
        .await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::CONFLICT, "CS-ML-0012")
    );
    let r = api
        .call(
            "POST",
            &format!("{list}/{}/dismiss", ids[0]),
            &a.auth,
            None,
            &[],
        )
        .await;
    assert_eq!(r.code(), "CS-ML-0012");
    let dismissed = ok(
        api.call(
            "POST",
            &format!("{list}/{}/dismiss", ids[1]),
            &a.auth,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "dismiss",
    );
    assert_eq!(dismissed["state"], "dismissed");
    let open = ok(
        api.call("GET", &format!("{list}?state=open"), &a.auth, None, &[])
            .await,
        StatusCode::OK,
        "open",
    );
    assert_eq!(open["items"].as_array().unwrap().len(), 1);

    // A kind whose feature is turned off is no longer shown or decided.
    ok(
        api.call(
            "PATCH",
            "/api/v1/account/settings/ml",
            &a.auth,
            Some(json!({"template_matching": false})),
            &[],
        )
        .await,
        StatusCode::OK,
        "template matching off",
    );
    let shown = ok(
        api.call("GET", &list, &a.auth, None, &[]).await,
        StatusCode::OK,
        "shown",
    );
    assert_eq!(shown["items"].as_array().unwrap().len(), 2);
    let r = api
        .call(
            "POST",
            &format!("{list}/{}/accept", ids[2]),
            &a.auth,
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    // Once sent, an envelope's documents are not analysed any more.
    let sent = ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            &a.auth,
            Some(json!({"subject": "s", "status": "sent",
                "documents": [{"name": "s.pdf", "content_base64": b64(&text_pdf(TEXT))}],
                "recipients": [{"ref": "r0", "type": "signer", "name": "S", "email": "s@example.test"}],
                "fields": [{"recipient": "r0", "document": 0, "type": "signature", "page": 1,
                    "x": 72, "y": 100, "width": 150, "height": 30}]})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "sent",
    );
    let sid = sent["id"].as_str().unwrap();
    let sdoc = sent["documents"][0]["id"].as_str().unwrap();
    let r = api
        .call(
            "POST",
            &format!("/api/v1/envelopes/{sid}/documents/{sdoc}/analysis"),
            &a.auth,
            None,
            &[],
        )
        .await;
    assert_eq!(
        (r.status, r.code().as_str()),
        (StatusCode::CONFLICT, "CS-WF-0001")
    );
    let jobs: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM jobs WHERE kind = 'analyze_document' AND envelope_id = $1",
    )
    .bind(uuid::Uuid::parse_str(sid).unwrap())
    .fetch_one(&api.db.admin)
    .await
    .unwrap();
    assert_eq!(jobs, 0, "an envelope created as sent is not analysed");
    // The analysis left no trace in the evidence: no audit event names it.
    let events: Vec<String> =
        sqlx::query_scalar("SELECT event_type FROM audit_events WHERE envelope_id = $1")
            .bind(uuid::Uuid::parse_str(&id).unwrap())
            .fetch_all(&api.db.admin)
            .await
            .unwrap();
    assert!(
        events
            .iter()
            .all(|t| !t.contains("analysis") && !t.contains("suggestion")),
        "{events:?}"
    );
}
