//! The database credential rotation drill (`HRD-06`, docs/65 §Rotation): while signer
//! traffic runs, a new login is created, the store is pointed at it, and the old login
//! loses `LOGIN` at once. Not one request may fail, and within a connection lifetime
//! every session is the new login's, so the old one can be dropped.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use casual_sign_store::Store;
use common::{Rls, fresh};
use sqlx::Executor;
use time::OffsetDateTime;

async fn sql(db: &common::TestDb, text: String) {
    db.admin
        .execute(sqlx::raw_sql(sqlx::AssertSqlSafe(text)))
        .await
        .unwrap();
}

async fn sessions_of(db: &common::TestDb, login: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE usename = $1 AND datname = $2")
        .bind(login)
        .bind(db.name())
        .fetch_one(&db.admin)
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotating_the_database_login_drops_no_signer_request() {
    let Some(db) = fresh("rotating_the_database_login", Rls::On).await else {
        return;
    };
    let (_, account) = db.account("rotation").await;
    // Logins are cluster-wide: unique names, dropped at the end.
    let tag = uuid::Uuid::new_v4().simple().to_string();
    let (blue, green) = (
        format!("rot_blue_{}", &tag[..12]),
        format!("rot_green_{}", &tag[..12]),
    );
    sql(
        &db,
        format!("CREATE ROLE {blue} LOGIN PASSWORD 'blue-pw' IN ROLE openseal_app"),
    )
    .await;

    // The URL lives in a secret file, as `OPENSEAL_DATABASE_URL_FILE` names it; the store
    // reads it again every 50 ms (production: `OPENSEAL_SECRET_RELOAD_SECONDS`, 30 s).
    let secret = std::env::temp_dir().join(format!("openseal-rotation-{tag}"));
    std::fs::write(&secret, format!("{}\n", db.url_as(&blue, "blue-pw"))).unwrap();
    let store =
        Store::connect_with_lifetime(&db.url_as(&blue, "blue-pw"), 4, Duration::from_millis(300))
            .await
            .unwrap();
    static RELOADS: AtomicU64 = AtomicU64::new(0);
    let path = secret.clone();
    let _watch = store.watch_database_url(
        Duration::from_millis(50),
        db.url_as(&blue, "blue-pw"),
        move || {
            let text = std::fs::read_to_string(&path).ok()?;
            Some(text.trim_end().to_owned())
        },
        |what| {
            assert_eq!(what, "reloaded");
            RELOADS.fetch_add(1, Ordering::Relaxed);
        },
    );

    // Signer traffic: the first lookup of every signer request (a token's hash), a
    // tenant transaction, and a bare round trip, from eight tasks over four connections.
    let stop = Arc::new(AtomicBool::new(false));
    let (ok, failed) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    let mut tasks = Vec::new();
    for i in 0..8u8 {
        let (store, stop, ok, failed) = (store.clone(), stop.clone(), ok.clone(), failed.clone());
        tasks.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let token = [i; 32];
                let r = async {
                    store
                        .entry_points()
                        .resolve_recipient_token(&token, OffsetDateTime::now_utc())
                        .await?;
                    store.for_account(account).begin().await?.commit().await?;
                    store.ping().await
                }
                .await;
                match r {
                    Ok(()) => ok.fetch_add(1, Ordering::Relaxed),
                    Err(e) => {
                        eprintln!("request failed: {}", e.code());
                        failed.fetch_add(1, Ordering::Relaxed)
                    }
                };
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }));
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(sessions_of(&db, &blue).await > 0);

    // The rotation, as the runbook orders it: a new login, the secret file rewritten in
    // place, one reload interval, then the old login retired.
    sql(
        &db,
        format!("CREATE ROLE {green} LOGIN PASSWORD 'green-pw' IN ROLE openseal_app"),
    )
    .await;
    std::fs::write(&secret, format!("{}\n", db.url_as(&green, "green-pw"))).unwrap();
    for _ in 0..40 {
        if RELOADS.load(Ordering::Relaxed) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(
        RELOADS.load(Ordering::Relaxed),
        1,
        "the new secret was not reloaded"
    );
    sql(&db, format!("ALTER ROLE {blue} NOLOGIN")).await;

    // Several connection lifetimes of traffic after the switch.
    tokio::time::sleep(Duration::from_millis(2_000)).await;
    stop.store(true, Ordering::Relaxed);
    for t in tasks {
        t.await.unwrap();
    }
    let (ok, failed) = (ok.load(Ordering::Relaxed), failed.load(Ordering::Relaxed));
    assert!(ok > 100, "too little traffic to mean anything: {ok}");
    assert_eq!(
        failed,
        0,
        "{failed} of {} signer requests failed",
        ok + failed
    );

    // Every session is the new login's, so the old one can go.
    let mut blue_left = sessions_of(&db, &blue).await;
    for _ in 0..20 {
        if blue_left == 0 {
            break;
        }
        store.ping().await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        blue_left = sessions_of(&db, &blue).await;
    }
    assert_eq!(blue_left, 0, "the old login still holds sessions");
    assert!(sessions_of(&db, &green).await > 0);

    // A malformed URL is refused and the pool keeps the working one.
    assert_eq!(
        store.set_database_url("not a url").unwrap_err().code(),
        "CS-DB-0001"
    );
    store.ping().await.unwrap();
    // The same file read again changes nothing.
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(RELOADS.load(Ordering::Relaxed), 1);

    std::fs::remove_file(&secret).unwrap();
    drop(store);
    db.drop().await;
    let server = common::server_url("cleanup").unwrap();
    let maint = sqlx::PgPool::connect(&server).await.unwrap();
    for role in [&blue, &green] {
        maint
            .execute(sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                "DROP ROLE IF EXISTS {role}"
            ))))
            .await
            .unwrap();
    }
}
