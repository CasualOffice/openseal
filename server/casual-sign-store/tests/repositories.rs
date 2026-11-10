//! Repository behaviour within one account: round trips, optimistic concurrency, draft
//! guards, and errors that carry codes but never the values involved.

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
use casual_sign_store::repo::accounts::{LoginKind, NewUser};
use casual_sign_store::repo::envelopes::{EnvelopeStatus, Transition};
use casual_sign_store::repo::fields::FieldValue;
use casual_sign_store::*;
use common::world::{self, id, new_envelope, now};
use common::{Rls, fresh};

#[tokio::test]
async fn round_trips_concurrency_and_draft_guards() {
    let Some(db) = fresh("round_trips_concurrency_and_draft_guards", Rls::On).await else {
        return;
    };
    let w = world::seed(&db.store, "alpha").await;
    let t = db.store.for_account(w.account);

    let mut tx = t.begin().await.unwrap();
    let e = tx.envelopes().get(w.envelope).await.unwrap().unwrap();
    assert_eq!(e.subject, Personal("Please sign".to_owned()));
    let v2 = tx
        .envelopes()
        .update_draft(
            w.envelope,
            e.version,
            &Personal("New".into()),
            &Personal("Body".into()),
        )
        .await
        .unwrap();
    assert_eq!(v2, 2);
    // A writer holding the old version is told it is stale.
    let stale = tx
        .envelopes()
        .update_draft(
            w.envelope,
            1,
            &Personal("Lost".into()),
            &Personal(String::new()),
        )
        .await
        .unwrap_err();
    assert_eq!(stale.code(), "CS-DB-0007");
    let v3 = tx
        .envelopes()
        .transition(
            w.envelope,
            v2,
            &Transition {
                status: EnvelopeStatus::Sent,
                at: now(),
                void_reason: None,
            },
        )
        .await
        .unwrap();
    let sent = tx.envelopes().get(w.envelope).await.unwrap().unwrap();
    assert_eq!(
        (sent.status, sent.version, sent.sent_at),
        (EnvelopeStatus::Sent, v3, Some(now()))
    );
    // Drafts only: no subject edits, document or field removal once sent.
    assert_eq!(
        tx.envelopes()
            .update_draft(w.envelope, v3, &Personal("x".into()), &Personal("y".into()))
            .await
            .unwrap_err()
            .code(),
        "CS-DB-0007"
    );
    assert_eq!(
        tx.documents()
            .delete_from_draft(w.document)
            .await
            .unwrap_err()
            .code(),
        "CS-DB-0003"
    );
    assert_eq!(
        tx.fields()
            .delete_from_draft(w.field)
            .await
            .unwrap_err()
            .code(),
        "CS-DB-0003"
    );
    // A value is replaced, not duplicated.
    tx.fields()
        .set_value(&FieldValue {
            field_id: w.field,
            envelope_id: w.envelope,
            recipient_id: w.recipient,
            value: Personal(serde_json::json!("Ada Lovelace")),
            value_sha256: world::hash("Ada Lovelace"),
            set_at: now(),
        })
        .await
        .unwrap();
    let values = tx.fields().values(w.envelope).await.unwrap();
    assert_eq!(values.len(), 1);
    assert_eq!(values[0].value, Personal(serde_json::json!("Ada Lovelace")));
    // A value for a field under the wrong recipient is refused.
    let wrong = tx
        .fields()
        .set_value(&FieldValue {
            field_id: w.field,
            envelope_id: w.envelope,
            recipient_id: RecipientId(id()),
            value: Personal(serde_json::json!("x")),
            value_sha256: world::hash("x"),
            set_at: now(),
        })
        .await
        .unwrap_err();
    assert_eq!(wrong.code(), "CS-DB-0003");
    let f = tx.fields().get(w.field).await.unwrap().unwrap();
    assert_eq!(f.rect, world::rect());
    tx.commit().await.unwrap();

    // Voiding needs a time; the reason is kept.
    let mut tx = t.begin().await.unwrap();
    tx.envelopes()
        .transition(
            w.envelope,
            v3,
            &Transition {
                status: EnvelopeStatus::Voided,
                at: now(),
                void_reason: Some(Personal("duplicate".into())),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        tx.envelopes()
            .list(Some(EnvelopeStatus::Voided), 10)
            .await
            .unwrap()
            .len(),
        1
    );
    tx.commit().await.unwrap();
    db.drop().await;
}

#[tokio::test]
async fn errors_carry_codes_and_constraint_names_never_values() {
    let Some(db) = fresh("errors_carry_codes_never_values", Rls::On).await else {
        return;
    };
    let w = world::seed(&db.store, "alpha").await;
    let t = db.store.for_account(w.account);
    // A duplicate email: PostgreSQL's detail quotes the value; the store's error must not.
    let mut tx = t.begin().await.unwrap();
    let err = tx
        .users()
        .create_member(
            &NewUser {
                id: UserId(id()),
                email: Personal("alpha@example.test".into()),
                email_normalized: Personal("alpha@example.test".into()),
                name: Personal("Twin".into()),
                login_kind: LoginKind::Local,
                idp: None,
            },
            w.profile,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), "CS-DB-0006");
    let text = format!("{err} {err:?}");
    assert!(!text.contains("alpha@example.test"), "{text}");
    assert!(text.contains("users_email_normalized_key"), "{text}");
    drop(tx);
    // An over-long subject: a check constraint, by name only.
    let mut tx = t.begin().await.unwrap();
    let mut e = new_envelope(EnvelopeId(id()), w.user);
    e.subject = Personal("s".repeat(256));
    let err = tx.envelopes().insert(&e).await.unwrap_err();
    assert_eq!(err.code(), "CS-DB-0008");
    assert!(!format!("{err} {err:?}").contains("sss"), "{err:?}");
    // Personal data never reaches Debug.
    let debug = format!("{e:?}");
    assert!(
        !debug.contains("sss") && debug.contains("<personal>"),
        "{debug}"
    );
    db.drop().await;
}
