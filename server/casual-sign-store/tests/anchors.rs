//! Anchors of chain heads (migration 0041, docs/32 §5, `FG-158`): the day's heads are
//! found, an anchor stores once per day, its leaves read back as the envelope's proof,
//! and the tables are append-only for every role.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use casual_sign_store::repo::anchors::{NewLeaf, StoredAnchor};
use common::world;
use common::{Rls, fresh};
use time::{Duration, OffsetDateTime, Time};

fn day_of(t: OffsetDateTime) -> (time::Date, OffsetDateTime, OffsetDateTime) {
    let start = t.replace_time(Time::MIDNIGHT);
    (t.date(), start, start + Duration::days(1))
}

#[tokio::test]
async fn a_day_is_anchored_once_and_its_leaves_are_append_only() {
    let Some(db) = fresh("a_day_is_anchored_once", Rls::On).await else {
        return;
    };
    let w = world::seed(&db, "alpha").await;
    let (period, start, end) = day_of(world::now());
    let mut tx = db.store.for_account(w.account).begin().await.unwrap();
    let heads = tx
        .anchors()
        .heads_for_period(start, end, 100)
        .await
        .unwrap();
    // The seed appended two events: the head is the second.
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0].envelope, w.envelope);
    assert_eq!(heads[0].seq, 1);
    // Nothing the day before.
    let before = tx
        .anchors()
        .heads_for_period(start - Duration::days(1), start, 100)
        .await
        .unwrap();
    assert!(before.is_empty());
    let anchor = StoredAnchor {
        id: world::id(),
        period,
        tree_size: 1,
        root: heads[0].head,
        timestamp_token: vec![0x30, 0x00],
        tsa_time: end,
        created_at: end,
    };
    let leaves = [NewLeaf {
        leaf_index: 0,
        head: heads[0],
        path: Vec::new(),
    }];
    assert!(tx.anchors().insert(&anchor, &leaves).await.unwrap());
    // A second anchor of the same day stores nothing.
    let again = StoredAnchor {
        id: world::id(),
        ..anchor.clone()
    };
    assert!(!tx.anchors().insert(&again, &leaves).await.unwrap());
    assert_eq!(
        tx.anchors().by_period(period).await.unwrap(),
        Some(anchor.clone())
    );
    let mine = tx.anchors().leaves_of(w.envelope).await.unwrap();
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].anchor, anchor);
    assert_eq!(mine[0].head, heads[0].head);
    // An anchored head is not offered again.
    assert!(
        tx.anchors()
            .heads_for_period(start, end, 100)
            .await
            .unwrap()
            .is_empty()
    );
    tx.commit().await.unwrap();

    // Append-only for the owner too (the trigger), and for the application role (no
    // privilege).
    for sql in [
        "UPDATE chain_anchors SET tree_size = 2",
        "DELETE FROM chain_anchors",
        "UPDATE chain_anchor_leaves SET seq = 0",
        "DELETE FROM chain_anchor_leaves",
        "TRUNCATE chain_anchor_leaves",
    ] {
        let err = sqlx::raw_sql(sqlx::AssertSqlSafe(sql.to_owned()))
            .execute(&db.admin)
            .await
            .unwrap_err();
        let code = err
            .as_database_error()
            .and_then(|e| e.code())
            .map(|c| c.into_owned());
        assert_eq!(code.as_deref(), Some("OS001"), "{sql}");
    }
    db.drop().await;
}

#[tokio::test]
async fn the_enqueue_queues_one_job_per_account_and_day() {
    let Some(db) = fresh("the_enqueue_queues_one_job", Rls::On).await else {
        return;
    };
    let _w = world::seed(&db, "alpha").await;
    let (period, start, end) = day_of(world::now());
    let ep = db.store.entry_points();
    assert_eq!(
        ep.enqueue_anchor_jobs(period, start, end, end)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        ep.enqueue_anchor_jobs(period, start, end, end)
            .await
            .unwrap(),
        0
    );
    // A day with no events queues nothing; a period over a day is refused.
    let (p2, s2, e2) = day_of(world::now() - Duration::days(3));
    assert_eq!(ep.enqueue_anchor_jobs(p2, s2, e2, end).await.unwrap(), 0);
    let err = ep
        .enqueue_anchor_jobs(period, start, end + Duration::days(1), end)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "CS-DB-0008");
    db.drop().await;
}
