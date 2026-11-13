//! `Store::verify_evidence` (ASVS-14): after a restore, every audit chain and admin log
//! is rebuilt and checked, and any tampering, by a superuser with the triggers off, as a
//! restore from a bad backup would be, is named by the chain it broke.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use casual_sign_store::blob::BlobKey;
use casual_sign_store::{EvidenceSubject, Store};
use common::world::{self, hash};
use common::{Rls, TestDb, fresh};
use sqlx::Executor;

async fn admin_sql(db: &TestDb, sql: &str) {
    db.admin
        .execute(sqlx::raw_sql(sqlx::AssertSqlSafe(sql.to_owned())))
        .await
        .unwrap();
}

#[tokio::test]
async fn every_chain_verifies_and_is_counted() {
    let Some(db) = fresh("evidence_every_chain_verifies", Rls::On).await else {
        return;
    };
    let a = world::seed(&db, "alpha").await;
    let b = world::seed(&db, "beta").await;
    let owner = Store::from_pool(db.admin.clone());
    let report = owner.verify_evidence().await.unwrap();
    assert_eq!(report.envelopes, 2);
    assert_eq!(report.audit_events, a.events + b.events);
    assert_eq!(report.workspaces, 2);
    assert_eq!(report.organizations, 2);
    let admin: i64 = sqlx::query_scalar("SELECT count(*) FROM admin_events")
        .fetch_one(&db.admin)
        .await
        .unwrap();
    let org_admin: i64 = sqlx::query_scalar("SELECT count(*) FROM org_admin_events")
        .fetch_one(&db.admin)
        .await
        .unwrap();
    assert!(admin > 0 && org_admin > 0);
    assert_eq!(report.admin_events, u64::try_from(admin).unwrap());
    assert_eq!(report.org_admin_events, u64::try_from(org_admin).unwrap());
    // The documents' blobs, each once, ascending: both seeds use the same bytes.
    let keys = owner.evidence_blob_keys().await.unwrap().named;
    let mut want = vec![BlobKey(hash("pdf")), BlobKey(hash("nda"))];
    want.sort();
    assert_eq!(keys, want);
    db.drop().await;
}

/// Every blob the evidence relies on, not only the documents (`ASVS-14` review finding
/// 2): the certificate of completion, each adopted signature's capture, a brand's logo,
/// and a signer's attachment (named only in the envelope's workflow state).
#[tokio::test]
async fn the_blob_keys_cover_certificates_captures_logos_and_attachments() {
    let Some(db) = fresh("evidence_blob_keys_cover_everything", Rls::On).await else {
        return;
    };
    let w = world::seed(&db, "alpha").await;
    let (cert, capture, logo, attachment) = (
        hash("cert"),
        hash("capture"),
        hash("logo"),
        hash("attachment"),
    );
    let hex = |h: &[u8; 32]| h.iter().map(|b| format!("{b:02x}")).collect::<String>();
    admin_sql(
        &db,
        &format!(
            "UPDATE envelopes SET certificate_sha256 = '\\x{cert}' WHERE id = '{env}'; \
             INSERT INTO signature_adoptions (id, account_id, recipient_id, mark, method, image_sha256, adopted_at) \
               VALUES (gen_random_uuid(), '{acct}', '{rcpt}', 'signature', 'draw', '\\x{capture}', now()); \
             INSERT INTO brands (id, account_id, name, logo_sha256) \
               VALUES (gen_random_uuid(), '{acct}', 'Brand', '\\x{logo}'); \
             INSERT INTO envelope_states (account_id, envelope_id, state, revision, updated_at) \
               VALUES ('{acct}', '{env}', '{{\"fields\": [{{\"value\": {{\"attachment\": \"{attachment}\"}}}}, \
                 {{\"value\": {{\"text\": \"{capture}\"}}}}, {{\"value\": {{\"attachment\": \"not-a-key\"}}}}]}}', 1, now())",
            cert = hex(&cert),
            capture = hex(&capture),
            logo = hex(&logo),
            attachment = hex(&attachment),
            env = w.envelope,
            acct = w.account,
            rcpt = w.recipient,
        ),
    )
    .await;
    let owner = Store::from_pool(db.admin.clone());
    let keys = owner.evidence_blob_keys().await.unwrap();
    assert_eq!(keys.captures, vec![BlobKey(capture)]);
    let keys = keys.named;
    let mut want: Vec<BlobKey> = [hash("pdf"), hash("nda"), cert, capture, logo, attachment]
        .into_iter()
        .map(BlobKey)
        .collect();
    want.sort();
    assert_eq!(keys, want);
    db.drop().await;
}

#[tokio::test]
async fn a_role_that_row_level_security_filters_is_refused() {
    let Some(db) = fresh("evidence_filtered_role", Rls::On).await else {
        return;
    };
    world::seed(&db, "alpha").await;
    // The application role sees no account without a scope: it must not report an
    // empty, "verified" database.
    let err = db.store.verify_evidence().await.unwrap_err();
    assert_eq!(err.code(), "CS-DB-0015", "{err}");
    assert_eq!(err.subject, None);
    let err = db.store.evidence_blob_keys().await.unwrap_err();
    assert_eq!(err.code(), "CS-DB-0015");
    db.drop().await;
}

#[tokio::test]
async fn an_altered_audit_event_names_its_envelope() {
    let Some(db) = fresh("evidence_altered_audit_event", Rls::On).await else {
        return;
    };
    let w = world::seed(&db, "alpha").await;
    world::seed(&db, "beta").await;
    // A superuser can switch the append-only triggers off (docs/07 SEC-S07): the
    // rebuilt chain is what catches it. One byte of the first event's bytes changes.
    admin_sql(
        &db,
        &format!(
            "ALTER TABLE audit_events DISABLE TRIGGER USER; \
             UPDATE audit_events SET canonical = overlay(canonical placing '\\x20' from 2 for 1) \
             WHERE envelope_id = '{}' AND seq = 0; \
             ALTER TABLE audit_events ENABLE TRIGGER USER",
            w.envelope
        ),
    )
    .await;
    let err = Store::from_pool(db.admin.clone())
        .verify_evidence()
        .await
        .unwrap_err();
    assert_eq!(err.code(), "CS-DB-0005", "{err}");
    assert_eq!(
        err.subject,
        Some(EvidenceSubject::Envelope {
            account: w.account,
            envelope: w.envelope
        })
    );
    assert!(err.to_string().contains(&w.envelope.0.to_string()), "{err}");
    db.drop().await;
}

#[tokio::test]
async fn a_stored_head_that_is_not_the_last_event_is_refused() {
    let Some(db) = fresh("evidence_stored_head", Rls::On).await else {
        return;
    };
    let w = world::seed(&db, "alpha").await;
    // A restore that lost the last event (or kept a stale envelope row) leaves the
    // envelope's head pointing past the chain: every event verifies, the head does not.
    admin_sql(
        &db,
        &format!(
            "ALTER TABLE envelopes DISABLE TRIGGER USER; \
             UPDATE envelopes SET chain_head = '\\x{}' WHERE id = '{}'; \
             ALTER TABLE envelopes ENABLE TRIGGER USER",
            "ab".repeat(32),
            w.envelope
        ),
    )
    .await;
    let err = Store::from_pool(db.admin.clone())
        .verify_evidence()
        .await
        .unwrap_err();
    assert_eq!(err.code(), "CS-DB-0005", "{err}");
    assert_eq!(
        err.subject,
        Some(EvidenceSubject::Envelope {
            account: w.account,
            envelope: w.envelope
        })
    );
    db.drop().await;
}

#[tokio::test]
async fn an_altered_admin_event_names_its_workspace_or_organization() {
    let Some(db) = fresh("evidence_altered_admin_event", Rls::On).await else {
        return;
    };
    let w = world::seed(&db, "alpha").await;
    admin_sql(
        &db,
        &format!(
            "ALTER TABLE admin_events DISABLE TRIGGER USER; \
             UPDATE admin_events SET canonical = overlay(canonical placing '\\x20' from 2 for 1) \
             WHERE account_id = '{}' AND seq = 0; \
             ALTER TABLE admin_events ENABLE TRIGGER USER",
            w.account
        ),
    )
    .await;
    let owner = Store::from_pool(db.admin.clone());
    let err = owner.verify_evidence().await.unwrap_err();
    assert_eq!(err.code(), "CS-DB-0014", "{err}");
    assert_eq!(err.subject, Some(EvidenceSubject::Workspace(w.account)));

    let Some(db2) = fresh("evidence_altered_org_admin_event", Rls::On).await else {
        return;
    };
    let w2 = world::seed(&db2, "beta").await;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "ALTER TABLE org_admin_events DISABLE TRIGGER USER; \
         UPDATE org_admin_events SET canonical = overlay(canonical placing '\\x20' from 2 for 1) \
         WHERE organization_id = '{}' AND seq = 0; \
         ALTER TABLE org_admin_events ENABLE TRIGGER USER",
        w2.organization
    )))
    .execute(&db2.admin)
    .await
    .unwrap();
    let err = Store::from_pool(db2.admin.clone())
        .verify_evidence()
        .await
        .unwrap_err();
    assert_eq!(err.code(), "CS-DB-0014", "{err}");
    assert_eq!(
        err.subject,
        Some(EvidenceSubject::Organization(w2.organization))
    );
    db.drop().await;
    db2.drop().await;
}
