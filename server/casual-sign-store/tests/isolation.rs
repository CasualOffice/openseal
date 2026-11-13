//! Cross-tenant isolation (SEC-A04, ADR-013): every repository method, given another
//! account's ids, finds nothing or refuses, and leaves the other account's rows as they
//! were. Run twice: with row-level security on, and with it disabled on every table, which
//! proves the repository alone isolates. A third test proves RLS alone isolates, through
//! raw SQL that bypasses the repository. Document-analysis rows (migration 0021) are
//! seeded in both accounts with identical template page hashes, so a search that
//! crossed accounts would match.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use casual_sign_audit::Personal;
use casual_sign_store::repo::api_clients::{ApiClientKind, NewApiClient};
use casual_sign_store::repo::documents::Document;
use casual_sign_store::repo::envelopes::{EnvelopeStatus, Transition};
use casual_sign_store::repo::fields::FieldValue;
use casual_sign_store::repo::ml::{
    Fingerprint, NewRun, NewSuggestion, RunEnd, RunKind, RunStatus, SuggestionFilter,
    SuggestionKind, SuggestionState,
};
use casual_sign_store::repo::recipients::{NewToken, RecipientStatus, TokenPurpose};
use casual_sign_store::repo::templates::{Template, TemplateDocument, TemplateField, TemplateRole};
use casual_sign_store::repo::webhooks::{Delivery, Subscription};
use casual_sign_store::*;
use common::world::{
    self, MlWorld, World, events, id, new_envelope, new_field, new_job, new_recipient, new_version,
    now, rect,
};
use common::{Rls, fresh};
use sqlx::Row;

/// The error codes a refused cross-tenant write may carry: not found, or a reference
/// constraint (the composite foreign key), or RLS refusing the new row.
fn refused<T: core::fmt::Debug>(what: &str, r: Result<T, StoreError>) {
    match r {
        Ok(v) => panic!("{what}: cross-tenant call succeeded: {v:?}"),
        Err(e) => assert!(
            matches!(
                e.code(),
                "CS-DB-0003" | "CS-DB-0008" | "CS-DB-0009" | "CS-DB-0005"
            ),
            "{what}: unexpected {e}"
        ),
    }
}

async fn every_repository_method_refuses_another_accounts_ids(rls: Rls) {
    let name = format!("every_repository_method_refuses_another_accounts_ids_{rls:?}");
    let Some(db) = fresh(&name, rls).await else {
        return;
    };
    let a = world::seed(&db, "alpha").await;
    let b = world::seed(&db, "bravo").await;
    let am = world::seed_ml(&db, &a).await;
    let bm = world::seed_ml(&db, &b).await;
    // A's switches and plan differ from B's, so reading A's would show.
    sqlx::query("UPDATE ml_settings SET ocr_scripts = '{latin,greek}' WHERE account_id = $1")
        .bind(a.account.0)
        .execute(&db.admin)
        .await
        .unwrap();
    sqlx::query("UPDATE ml_entitlements SET features = '{ml.ocr}' WHERE account_id = $1")
        .bind(a.account.0)
        .execute(&db.admin)
        .await
        .unwrap();
    let t = db.store.for_account(b.account);
    // Each refused write runs in a transaction of its own (an error aborts a PostgreSQL
    // transaction), which B then commits: a refused call must leave nothing behind.
    macro_rules! w {
        ($what:expr, |$tx:ident| $call:expr $(,)?) => {{
            let mut $tx = t.begin().await.unwrap();
            refused($what, $call);
            let _ = $tx.commit().await;
        }};
    }
    let mut tx = t.begin().await.unwrap();

    // Account.
    assert_eq!(tx.account().get().await.unwrap().id, b.account);

    // Users and profiles.
    assert!(tx.users().get(a.user).await.unwrap().is_none());
    assert!(
        tx.users()
            .list()
            .await
            .unwrap()
            .iter()
            .all(|m| m.user_id != a.user)
    );
    assert!(tx.users().profile(a.profile).await.unwrap().is_none());
    w!("users.rename", |tx| tx
        .users()
        .rename(a.user, &Personal("x".into()))
        .await);
    w!("users.remove_member", |tx| tx
        .users()
        .remove_member(a.user)
        .await);
    w!("users.add_existing_member (A's user by id alone)", |tx| tx
        .users()
        .add_existing_member(a.user, &Personal("guess@example.test".into()), b.profile)
        .await);
    w!("users.add_existing_member (A's profile)", |tx| tx
        .users()
        .add_existing_member(a.user, &Personal("alpha@example.test".into()), a.profile)
        .await);

    // API clients.
    assert!(tx.api_clients().get(a.api_client).await.unwrap().is_none());
    w!("api_clients.revoke", |tx| tx
        .api_clients()
        .revoke(a.api_client, now())
        .await);
    w!("api_clients.create (A's owner)", |tx| tx
        .api_clients()
        .create(&NewApiClient {
            id: ApiClientId(id()),
            kind: ApiClientKind::ApiKey,
            name: "x".into(),
            owner_user_id: Some(a.user),
            key_prefix: None,
            secret_sha256: None,
            scopes: vec![],
            expires_at: None,
        })
        .await,);

    // Envelopes.
    assert!(tx.envelopes().get(a.envelope).await.unwrap().is_none());
    assert!(!tx.envelopes().exists(a.envelope).await.unwrap());
    assert!(
        tx.envelopes()
            .list(None, 100)
            .await
            .unwrap()
            .iter()
            .all(|e| e.id != a.envelope)
    );
    w!("envelopes.update_draft", |tx| tx
        .envelopes()
        .update_draft(a.envelope, 1, &Personal("x".into()), &Personal("y".into()))
        .await,);
    w!("envelopes.transition", |tx| tx
        .envelopes()
        .transition(
            a.envelope,
            1,
            &Transition {
                status: EnvelopeStatus::Voided,
                at: now(),
                void_reason: None,
            },
        )
        .await,);
    w!("envelopes.insert (A's sender)", |tx| tx
        .envelopes()
        .insert(&new_envelope(EnvelopeId(id()), a.user))
        .await,);

    // Documents and versions.
    assert!(tx.documents().get(a.document).await.unwrap().is_none());
    assert!(tx.documents().list(a.envelope).await.unwrap().is_empty());
    assert!(tx.documents().version(a.version).await.unwrap().is_none());
    assert!(
        tx.documents()
            .versions(a.document)
            .await
            .unwrap()
            .is_empty()
    );
    w!("documents.delete_from_draft", |tx| tx
        .documents()
        .delete_from_draft(a.document)
        .await);
    w!("documents.insert (A's envelope)", |tx| tx
        .documents()
        .insert(&Document {
            id: DocumentId(id()),
            envelope_id: a.envelope,
            ord: 0,
            name: "x.pdf".into(),
        })
        .await,);
    w!("documents.add_version (A's document)", |tx| tx
        .documents()
        .add_version(&new_version(DocumentVersionId(id()), a.document))
        .await,);

    // Recipients and tokens.
    assert!(tx.recipients().get(a.recipient).await.unwrap().is_none());
    assert!(tx.recipients().list(a.envelope).await.unwrap().is_empty());
    w!("recipients.set_status", |tx| tx
        .recipients()
        .set_status(a.recipient, RecipientStatus::Completed, None)
        .await,);
    assert_eq!(
        tx.recipients()
            .revoke_tokens(a.recipient, now())
            .await
            .unwrap(),
        0
    );
    w!("recipients.insert (A's envelope)", |tx| tx
        .recipients()
        .insert(&new_recipient(RecipientId(id()), a.envelope))
        .await,);
    w!("recipients.issue_token (A's recipient)", |tx| tx
        .recipients()
        .issue_token(&NewToken {
            id: RecipientTokenId(id()),
            envelope_id: a.envelope,
            recipient_id: a.recipient,
            token_sha256: world::hash("forged"),
            purpose: TokenPurpose::Invitation,
            host_user_id: None,
            expires_at: now(),
        })
        .await,);

    // Fields and values.
    assert!(tx.fields().get(a.field).await.unwrap().is_none());
    assert!(tx.fields().list(a.envelope).await.unwrap().is_empty());
    assert!(tx.fields().value(a.field).await.unwrap().is_none());
    assert!(tx.fields().values(a.envelope).await.unwrap().is_empty());
    w!("fields.delete_from_draft", |tx| tx
        .fields()
        .delete_from_draft(a.field)
        .await);
    w!("fields.set_value", |tx| tx
        .fields()
        .set_value(&FieldValue {
            field_id: a.field,
            envelope_id: a.envelope,
            recipient_id: a.recipient,
            value: Personal(serde_json::json!("forged")),
            value_sha256: world::hash("forged"),
            set_at: now(),
        })
        .await,);
    w!("fields.insert (A's envelope)", |tx| tx
        .fields()
        .insert(&new_field(
            FieldId(id()),
            a.envelope,
            a.document,
            a.recipient
        ))
        .await,);

    // Audit.
    assert!(tx.audit().events(a.envelope).await.unwrap().is_empty());
    assert!(tx.audit().head(a.envelope).await.unwrap().is_none());
    assert!(tx.audit().chain(a.envelope).await.unwrap().is_empty());
    for e in events(a.envelope, 3) {
        w!("audit.append (A's envelope)", |tx| tx
            .audit()
            .append(a.envelope, &e)
            .await);
    }

    // Jobs.
    assert!(tx.jobs().get(a.job).await.unwrap().is_none());
    w!("jobs.complete", |tx| tx
        .jobs()
        .complete(a.job, id(), now())
        .await);
    w!("jobs.fail", |tx| tx
        .jobs()
        .fail(a.job, id(), now(), "CS-X")
        .await);
    w!("jobs.enqueue (A's envelope)", |tx| tx
        .jobs()
        .enqueue(&new_job(JobId(id()), Some(a.envelope), "x"))
        .await,);

    // Templates.
    assert!(tx.templates().get(a.template).await.unwrap().is_none());
    assert!(
        tx.templates()
            .list()
            .await
            .unwrap()
            .iter()
            .all(|t| t.id != a.template)
    );
    assert!(tx.templates().roles(a.template).await.unwrap().is_empty());
    assert!(
        tx.templates()
            .documents(a.template)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(tx.templates().fields(a.template).await.unwrap().is_empty());
    w!("templates.rename", |tx| tx
        .templates()
        .rename(a.template, 1, "x")
        .await);
    w!("templates.insert (A's owner)", |tx| tx
        .templates()
        .insert(&Template {
            id: TemplateId(id()),
            owner_user_id: a.user,
            name: "x".into(),
            email_subject: None,
            email_message: None,
            settings: serde_json::json!({}),
            matching_rules: serde_json::json!([]),
            version: 1,
        })
        .await,);
    w!("templates.add_role (A's template)", |tx| tx
        .templates()
        .add_role(&TemplateRole {
            id: TemplateRoleId(id()),
            template_id: a.template,
            name: "Signer".into(),
            routing_order: 1,
            kind: casual_sign_store::repo::recipients::RecipientType::Signer,
            default_auth: serde_json::json!([]),
        })
        .await,);
    w!("templates.add_document (A's template)", |tx| tx
        .templates()
        .add_document(&TemplateDocument {
            id: TemplateDocumentId(id()),
            template_id: a.template,
            ord: 0,
            name: "x.pdf".into(),
            sha256: world::hash("x"),
            byte_len: 1,
            page_count: 1,
            pages: serde_json::json!([]),
        })
        .await,);
    w!("templates.add_field (A's template, document, role)", |tx| {
        tx.templates()
            .add_field(&TemplateField {
                id: TemplateFieldId(id()),
                template_id: a.template,
                template_document_id: a.template_document,
                role_id: a.role,
                kind: casual_sign_model::FieldType::Text,
                rect: rect(),
                required: false,
                label: None,
                spec: Personal(serde_json::json!({})),
            })
            .await
    },);

    // Webhooks.
    assert!(tx.webhooks().get(a.subscription).await.unwrap().is_none());
    assert!(
        tx.webhooks()
            .list()
            .await
            .unwrap()
            .iter()
            .all(|s| s.id != a.subscription)
    );
    assert!(
        tx.webhooks()
            .deliveries(a.subscription, 100)
            .await
            .unwrap()
            .is_empty()
    );
    w!("webhooks.disable", |tx| tx
        .webhooks()
        .disable(a.subscription)
        .await);
    w!("webhooks.record_attempt", |tx| tx
        .webhooks()
        .record_attempt(a.delivery, Some(200), true, None, now())
        .await,);
    w!("webhooks.subscribe (A's envelope)", |tx| tx
        .webhooks()
        .subscribe(&Subscription {
            id: WebhookSubscriptionId(id()),
            envelope_id: Some(a.envelope),
            url: "https://evil.example.test/".into(),
            event_types: vec!["envelope.completed".into()],
            secret_refs: vec!["s".into()],
            active: true,
        })
        .await,);
    w!("webhooks.record_delivery (A's subscription)", |tx| tx
        .webhooks()
        .record_delivery(&Delivery {
            id: WebhookDeliveryId(id()),
            subscription_id: a.subscription,
            event_id: id(),
            event_type: "envelope.completed".into(),
            payload: serde_json::json!({}),
            status: "pending".into(),
            attempts: 0,
            last_status_code: None,
        })
        .await,);

    // Document analysis (migration 0021).
    assert_eq!(
        tx.ml().settings().await.unwrap().ocr_scripts,
        vec!["latin".to_owned()]
    );
    assert_eq!(tx.ml().entitlements().await.unwrap().len(), 4);
    assert!(tx.ml().run(am.run).await.unwrap().is_none());
    assert!(
        tx.ml()
            .run_by_key(&format!("analyze:{}:{}", a.account.0, a.document.0))
            .await
            .unwrap()
            .is_none()
    );
    assert!(tx.ml().latest_run(a.document.0).await.unwrap().is_none());
    assert!(
        tx.ml()
            .envelope_suggestions(a.envelope, SuggestionFilter::default(), 100)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        tx.ml()
            .envelope_suggestion(a.envelope, am.suggestion)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        tx.ml()
            .envelope_suggestion(b.envelope, am.suggestion)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !tx.ml()
            .decide(am.suggestion, SuggestionState::Accepted, b.user, now())
            .await
            .unwrap(),
        "B decided A's suggestion"
    );
    assert!(tx.ml().ocr_pages(am.run).await.unwrap().is_empty());
    // B's upload is compared against B's templates only, though A's pages hash the same.
    let fps = tx.ml().fingerprints().await.unwrap();
    assert_eq!(
        fps.iter().map(|f| f.template_id).collect::<Vec<_>>(),
        vec![b.template],
        "B's template search reached another account's pages"
    );
    tx.ml().start_run(am.run).await.unwrap();
    tx.ml()
        .forget_template_document(a.template, a.template_document)
        .await
        .unwrap();
    w!("ml.finish_run", |tx| tx
        .ml()
        .finish_run(
            am.run,
            &RunEnd {
                status: RunStatus::Done,
                bundle_id: None,
                ort_version: None,
                ocr_pages: vec![],
                truncated: false,
                code: None,
                at: now(),
            },
        )
        .await,);
    w!("ml.insert_run (A's envelope)", |tx| tx
        .ml()
        .insert_run(&NewRun {
            id: AnalysisRunId(id()),
            document_id: a.document.0,
            envelope_id: Some(a.envelope),
            template_id: None,
            kind: RunKind::AnalyzeDocument,
            uses: vec!["ocr".into()],
            document_sha256: world::hash("doc"),
            job_key: "analyze:forged".into(),
            created_at: now(),
        })
        .await,);
    w!("ml.insert_run (A's template)", |tx| tx
        .ml()
        .insert_run(&NewRun {
            id: AnalysisRunId(id()),
            document_id: a.template_document.0,
            envelope_id: None,
            template_id: Some(a.template),
            kind: RunKind::FingerprintTemplate,
            uses: vec!["template".into()],
            document_sha256: world::hash("doc"),
            job_key: "fingerprint:forged".into(),
            created_at: now(),
        })
        .await,);
    w!("ml.add_suggestions (A's run)", |tx| tx
        .ml()
        .add_suggestions(
            am.run,
            a.document.0,
            &[NewSuggestion {
                id: SuggestionId(id()),
                kind: SuggestionKind::Entity,
                page: Some(1),
                rect: None,
                label: "x".into(),
                span: None,
                normalized: None,
                template: None,
                score: 0.5,
                model_id: "m".into(),
                weights_sha256: world::hash("w"),
            }],
        )
        .await,);
    w!("ml.add_suggestions (A's template)", |tx| tx
        .ml()
        .add_suggestions(
            bm.run,
            b.document.0,
            &[NewSuggestion {
                id: SuggestionId(id()),
                kind: SuggestionKind::Template,
                page: Some(1),
                rect: None,
                label: "x".into(),
                span: None,
                normalized: None,
                template: Some((a.template, 1, 1)),
                score: 0.5,
                model_id: "m".into(),
                weights_sha256: world::hash("w"),
            }],
        )
        .await,);
    w!("ml.put_ocr_page (A's run)", |tx| tx
        .ml()
        .put_ocr_page(am.run, 2, &serde_json::json!([]))
        .await,);
    w!("ml.put_fingerprints (A's template)", |tx| tx
        .ml()
        .put_fingerprints(
            a.template,
            a.template_document,
            &[Fingerprint {
                template_id: a.template,
                document_id: a.template_document,
                page: 2,
                dhash: 1,
                phash: 1,
                embedding: None,
                model_id: "m".into(),
                weights_sha256: world::hash("w"),
            }],
        )
        .await,);

    // A's rows are exactly as seeded, and A still reaches every one of them (so the
    // checks above were made against ids that exist).
    assert_untouched(&db.store, &a).await;
    assert_untouched(&db.store, &b).await;
    assert_ml_untouched(&db.store, &a, &am, 1).await;
    assert_ml_untouched(&db.store, &b, &bm, 4).await;
    db.drop().await;
}

/// The seeded rows of `w` are exactly as seeded, reached through its own account.
async fn assert_untouched(store: &Store, w: &World) {
    let mut tx = store.for_account(w.account).begin().await.unwrap();
    let e = tx.envelopes().get(w.envelope).await.unwrap().unwrap();
    assert_eq!((e.status, e.version), (EnvelopeStatus::Draft, 1));
    assert!(e.chain_head.is_some());
    assert!(tx.users().get(w.user).await.unwrap().is_some());
    assert!(tx.users().profile(w.profile).await.unwrap().is_some());
    assert!(
        tx.api_clients()
            .get(w.api_client)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_none()
    );
    assert_eq!(tx.documents().list(w.envelope).await.unwrap().len(), 1);
    assert!(tx.documents().version(w.version).await.unwrap().is_some());
    let r = tx.recipients().get(w.recipient).await.unwrap().unwrap();
    assert_eq!(r.status, RecipientStatus::Created);
    assert_eq!(tx.fields().list(w.envelope).await.unwrap().len(), 1);
    assert_eq!(
        tx.fields().value(w.field).await.unwrap().unwrap().value,
        Personal(serde_json::json!("Ada"))
    );
    assert_eq!(tx.audit().chain(w.envelope).await.unwrap().len(), 2);
    assert_eq!(
        tx.jobs().get(w.job).await.unwrap().unwrap().status,
        "queued"
    );
    let t = tx.templates().get(w.template).await.unwrap().unwrap();
    assert_eq!((t.name.as_str(), t.version), ("NDA", 1));
    assert_eq!(tx.templates().roles(w.template).await.unwrap().len(), 1);
    assert_eq!(tx.templates().documents(w.template).await.unwrap().len(), 1);
    assert_eq!(tx.templates().fields(w.template).await.unwrap().len(), 1);
    assert!(
        tx.webhooks()
            .get(w.subscription)
            .await
            .unwrap()
            .unwrap()
            .active
    );
    let d = tx.webhooks().deliveries(w.subscription, 10).await.unwrap();
    assert_eq!((d.len(), d[0].attempts), (1, 0));
}

/// The seeded analysis rows of `w` are exactly as seeded: the run queued, its suggestion
/// open, its OCR page and template hashes there, every switch on and `features` entitled.
async fn assert_ml_untouched(store: &Store, w: &World, m: &MlWorld, features: usize) {
    let mut tx = store.for_account(w.account).begin().await.unwrap();
    let s = tx.ml().settings().await.unwrap();
    assert!(s.ocr && s.template_matching && s.extraction && s.personal_data);
    assert_eq!(tx.ml().entitlements().await.unwrap().len(), features);
    let r = tx.ml().run(m.run).await.unwrap().unwrap();
    assert_eq!((r.status, r.finished_at), (RunStatus::Queued, None));
    let list = tx
        .ml()
        .envelope_suggestions(w.envelope, SuggestionFilter::default(), 100)
        .await
        .unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(
        (list[0].id, list[0].state, list[0].decided_by),
        (m.suggestion, SuggestionState::Open, None)
    );
    assert_eq!(tx.ml().ocr_pages(m.run).await.unwrap().len(), 1);
    let fps = tx.ml().fingerprints().await.unwrap();
    assert_eq!(fps.len(), 1);
    assert_eq!(
        (fps[0].template_id, fps[0].dhash, fps[0].phash),
        (w.template, world::FINGERPRINT.0, world::FINGERPRINT.1)
    );
}

#[tokio::test]
async fn every_repository_method_refuses_another_accounts_ids_with_rls() {
    every_repository_method_refuses_another_accounts_ids(Rls::On).await;
}

#[tokio::test]
async fn every_repository_method_refuses_another_accounts_ids_without_rls() {
    every_repository_method_refuses_another_accounts_ids(Rls::Off).await;
}

/// The second line on its own: raw SQL through the application role, bypassing the
/// repository, sees and changes only the account set for the transaction, sees nothing
/// when none is set, and cannot write a row for another account.
#[tokio::test]
async fn row_level_security_alone_isolates_every_tenant_table() {
    let Some(db) = fresh("row_level_security_alone_isolates", Rls::On).await else {
        return;
    };
    let a = world::seed(&db, "alpha").await;
    let b = world::seed(&db, "bravo").await;
    world::seed_ml(&db, &a).await;
    world::seed_ml(&db, &b).await;
    let tables = common::rls_tables(&db.admin).await;
    // Every analysis table is checked with rows on both sides, not two empty tables.
    for t in [
        "ml_settings",
        "ml_entitlements",
        "analysis_runs",
        "suggestions",
        "ocr_pages",
        "template_fingerprints",
    ] {
        assert!(tables.iter().any(|x| x == t), "{t} is not under RLS");
    }
    for t in &tables {
        let truth_sql = match t.as_str() {
            "accounts" => "SELECT count(*) FROM accounts WHERE id = $1".to_owned(),
            "users" => {
                "SELECT count(*) FROM users u WHERE EXISTS (SELECT 1 FROM account_memberships m \
                        WHERE m.user_id = u.id AND m.account_id = $1)"
                    .to_owned()
            }
            // A workspace reads its own organization's row; organization tables are
            // invisible in account scope (ORG-02).
            "organizations" => "SELECT count(*) FROM organizations o JOIN accounts a \
                                ON a.organization_id = o.id WHERE a.id = $1"
                .to_owned(),
            "organization_admins"
            | "org_permission_sets"
            | "org_admin_events"
            | "org_usage_counters" => "SELECT 0::bigint WHERE $1::uuid IS NOT NULL".to_owned(),
            _ => format!("SELECT count(*) FROM {t} WHERE account_id = $1"),
        };
        let truth: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(truth_sql))
            .bind(b.account.0)
            .fetch_one(&db.admin)
            .await
            .unwrap();
        if t.starts_with("ml_")
            || matches!(
                t.as_str(),
                "analysis_runs" | "suggestions" | "ocr_pages" | "template_fingerprints"
            )
        {
            assert!(truth > 0, "{t}: no rows seeded for account B");
        }
        let mut conn = db.app.begin().await.unwrap();
        let unset: i64 =
            sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {t}")))
                .fetch_one(&mut *conn)
                .await
                .unwrap();
        assert_eq!(unset, 0, "{t}: rows visible with no account set");
        sqlx::query("SELECT set_config('openseal.account_id', $1, true)")
            .bind(b.account.0.to_string())
            .execute(&mut *conn)
            .await
            .unwrap();
        let seen: i64 =
            sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {t}")))
                .fetch_one(&mut *conn)
                .await
                .unwrap();
        assert_eq!(
            seen, truth,
            "{t}: RLS shows {seen} rows, account B has {truth}"
        );
        conn.rollback().await.unwrap();
    }

    // Unfiltered writes reach only B's rows.
    let mut conn = db.app.begin().await.unwrap();
    sqlx::query("SELECT set_config('openseal.account_id', $1, true)")
        .bind(b.account.0.to_string())
        .execute(&mut *conn)
        .await
        .unwrap();
    let hit = sqlx::query("UPDATE envelopes SET subject = 'rewritten'")
        .execute(&mut *conn)
        .await
        .unwrap();
    assert_eq!(hit.rows_affected(), 1);
    let hit = sqlx::query("DELETE FROM field_values")
        .execute(&mut *conn)
        .await
        .unwrap();
    assert_eq!(hit.rows_affected(), 1);
    // A row claiming account A is refused by the policy's WITH CHECK.
    let err = sqlx::query("INSERT INTO jobs (id, account_id, kind, idempotency_key, run_at) VALUES ($1, $2, 'x', 'k', now())")
        .bind(id())
        .bind(a.account.0)
        .execute(&mut *conn)
        .await
        .unwrap_err();
    assert_eq!(
        err.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("42501"),
        "{err}"
    );
    conn.rollback().await.unwrap();
    let subject: String = sqlx::query("SELECT subject FROM envelopes WHERE id = $1")
        .bind(a.envelope.0)
        .fetch_one(&db.admin)
        .await
        .unwrap()
        .get(0);
    assert_eq!(subject, "Please sign");
    db.drop().await;
}
