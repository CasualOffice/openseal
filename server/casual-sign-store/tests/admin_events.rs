//! ORG-05 (ADR-028, docs/23 §2.5): the admin audit logs.
//!
//! - UPDATE, DELETE and TRUNCATE of `admin_events` and `org_admin_events` are refused for
//!   the owner (`OS001`, `CS-DB-0004`) and the application role (by privilege, `42501`).
//! - An event that does not extend its chain (hash, `seq`, `prev`, or columns that differ
//!   from its bytes) is refused: `OS005`, `CS-DB-0014`.
//! - A settings, member, profile, workspace or organization change committed by the
//!   application role without its event is refused at commit (`admin_change_has_event`).
//! - The repositories append the events themselves: settings, members, profiles,
//!   workspace creation and archiving, the bootstrap; each reads back as a verified chain.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use casual_sign_audit::{Hash256, Personal};
use casual_sign_store::repo::accounts::{LoginKind, NewUser};
use casual_sign_store::*;
use common::world::{id, now};
use common::{Rls, TestDb, builtin_profiles, fresh};
use sqlx::{Executor, PgPool};

fn sqlstate(err: &sqlx::Error) -> Option<String> {
    err.as_database_error()
        .and_then(|e| e.code())
        .map(|c| c.into_owned())
}

fn constraint(err: &sqlx::Error) -> Option<String> {
    err.as_database_error()
        .and_then(|e| e.constraint())
        .map(str::to_owned)
}

/// Run `sql` as the application role in a transaction scoped by `setting` = `value`.
async fn as_app(
    app: &PgPool,
    setting: &str,
    value: uuid::Uuid,
    sql: &str,
) -> Result<u64, sqlx::Error> {
    let mut tx = app.begin().await?;
    sqlx::query("SELECT set_config($1, $2, true)")
        .bind(setting)
        .bind(value.to_string())
        .execute(&mut *tx)
        .await?;
    let n = tx
        .execute(sqlx::raw_sql(sqlx::AssertSqlSafe(sql.to_owned())))
        .await?
        .rows_affected();
    tx.commit().await?;
    Ok(n)
}

fn user(email: &str) -> NewUser {
    NewUser {
        id: UserId(id()),
        email: Personal(email.to_owned()),
        email_normalized: Personal(email.to_owned()),
        name: Personal("Ada".to_owned()),
        login_kind: LoginKind::Local,
        idp: None,
    }
}

fn actor(u: UserId) -> AdminActor {
    AdminActor {
        kind: ActorKind::User(u),
        at: now(),
        request_id: Some("req-1".to_owned()),
        ip: Some(Personal("192.0.2.7".to_owned())),
    }
}

/// A workspace (made through the app's organization scope) with one administrator.
async fn workspace_with_admin(
    db: &TestDb,
    name: &str,
) -> (OrganizationId, AccountId, UserId, BuiltinProfiles) {
    let org = db.organization(name).await;
    let account = AccountId(id());
    let profiles = builtin_profiles();
    let mut tx = db.store.for_organization(org).begin().await.unwrap();
    let proof = tx.create_workspace(account, name, &profiles).await.unwrap();
    let mut tx = tx.into_workspace(&proof).await.unwrap();
    let admin = user(&format!("admin@{name}.example"));
    tx.users()
        .create_member(&admin, profiles.admin)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    (org, account, admin.id, profiles)
}

fn event(e: &StoredAdminEvent) -> serde_json::Value {
    serde_json::from_slice(&e.canonical).unwrap()
}

/// The row's exit test, part 1: UPDATE and DELETE (and TRUNCATE) refused for both roles.
#[tokio::test]
async fn update_delete_and_truncate_of_admin_logs_are_refused_for_owner_and_app_role() {
    for rls in [Rls::On, Rls::Off] {
        let Some(db) = fresh("admin_logs_append_only", rls).await else {
            return;
        };
        let (org, account, _, _) = workspace_with_admin(&db, "alpha").await;
        for (table, setting, scope) in [
            ("admin_events", "openseal.account_id", account.0),
            ("org_admin_events", "openseal.organization_id", org.0),
        ] {
            let n: i64 =
                sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
                    .fetch_one(&db.admin)
                    .await
                    .unwrap();
            assert!(n > 0, "{table} holds an event to refuse changing");
            for sql in [
                format!("UPDATE {table} SET action = 'x'"),
                format!("DELETE FROM {table}"),
                format!("TRUNCATE {table}"),
            ] {
                let owner = db
                    .admin
                    .execute(sqlx::raw_sql(sqlx::AssertSqlSafe(sql.clone())))
                    .await
                    .unwrap_err();
                assert_eq!(
                    sqlstate(&owner).as_deref(),
                    Some("OS001"),
                    "owner: {sql}: {owner}"
                );
                assert!(owner.to_string().contains("CS-DB-0004"), "{owner}");
                let app = as_app(&db.app, setting, scope, &sql).await.unwrap_err();
                assert_eq!(
                    sqlstate(&app).as_deref(),
                    Some("42501"),
                    "app: {sql}: {app}"
                );
            }
        }
        db.drop().await;
    }
}

/// The row's exit test, part 2: an event that does not extend its chain is `OS005`,
/// which the store reports as `CS-DB-0014`; the stored log still verifies.
#[tokio::test]
async fn an_admin_event_that_does_not_extend_its_chain_is_refused() {
    let Some(db) = fresh("admin_chain_broken", Rls::On).await else {
        return;
    };
    let (_, account, _, _) = workspace_with_admin(&db, "alpha").await;
    let mut tx = db.store.for_account(account).begin().await.unwrap();
    let log = tx.verified_admin_log().await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(log.len(), 1, "member.added");
    let head = log[0].hash;
    let canonical = |seq: u64, prev: Option<[u8; 32]>| {
        let prev = prev.map_or("null".to_owned(), |p| format!("\"{}\"", Hash256(p).hex()));
        format!(
            "{{\"account\":\"{account}\",\"action\":\"member.removed\",\"actor\":{{\"kind\":\"system\"}},\
             \"at\":1,\"changes\":[],\"prev\":{prev},\"seq\":{seq},\"target\":{{}},\"v\":1}}"
        )
        .into_bytes()
    };
    let insert = |seq: i64, prev: Option<[u8; 32]>, hash: [u8; 32], bytes: Vec<u8>| {
        format!(
            "INSERT INTO admin_events (account_id, seq, prev_hash, hash, action, at, canonical) \
             VALUES ('{account}', {seq}, {}, '\\x{}', 'member.removed', now(), '\\x{}')",
            prev.map_or("NULL".to_owned(), |p| format!("'\\x{}'", Hash256(p).hex())),
            Hash256(hash).hex(),
            hex(&bytes),
        )
    };
    let good = canonical(1, Some(head));
    let good_hash = *Hash256::digest(&good).as_bytes();
    let wrong_prev = canonical(1, Some([7; 32]));
    let cases = [
        // Hash is not SHA-256 of the bytes.
        insert(1, Some(head), [9; 32], good.clone()),
        // `seq` skips one (bytes agree with the columns).
        insert(
            2,
            Some(head),
            *Hash256::digest(&canonical(2, Some(head))).as_bytes(),
            canonical(2, Some(head)),
        ),
        // `prev` is not the head.
        insert(
            1,
            Some([7; 32]),
            *Hash256::digest(&wrong_prev).as_bytes(),
            wrong_prev.clone(),
        ),
        // Columns differ from the bytes: seq column 1, bytes say seq 0.
        insert(
            1,
            Some(head),
            *Hash256::digest(&canonical(0, Some(head))).as_bytes(),
            canonical(0, Some(head)),
        ),
    ];
    for sql in cases {
        let err = as_app(&db.app, "openseal.account_id", account.0, &sql)
            .await
            .unwrap_err();
        assert_eq!(sqlstate(&err).as_deref(), Some("OS005"), "{sql}: {err}");
    }
    // The store classifies it as CS-DB-0014.
    let e = StoreError::AdminChainBroken { seq: 1 };
    assert_eq!(e.code(), "CS-DB-0014");
    // The well-formed next event is accepted.
    as_app(
        &db.app,
        "openseal.account_id",
        account.0,
        &insert(1, Some(head), good_hash, good),
    )
    .await
    .unwrap();
    let mut tx = db.store.for_account(account).begin().await.unwrap();
    assert_eq!(tx.verified_admin_log().await.unwrap().len(), 2);
    tx.commit().await.unwrap();
    db.drop().await;
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The row's exit test, part 3: a settings change committed without its event fails,
/// and so does a member, profile or organization change.
#[tokio::test]
async fn an_admin_change_without_its_event_is_refused_at_commit() {
    let Some(db) = fresh("admin_change_without_event", Rls::On).await else {
        return;
    };
    let (org, account, admin, profiles) = workspace_with_admin(&db, "alpha").await;
    let a = account.0;
    for sql in [
        "UPDATE accounts SET settings = '{\"brand\":\"x\"}'::jsonb".to_owned(),
        "UPDATE accounts SET name = 'renamed'".to_owned(),
        format!(
            "UPDATE account_memberships SET permission_profile_id = '{}' WHERE user_id = '{}'",
            profiles.sender.0, admin.0
        ),
        format!(
            "DELETE FROM account_memberships WHERE user_id = '{}'",
            admin.0
        ),
        format!(
            "INSERT INTO permission_profiles (id, account_id, name, kind) VALUES ('{}', '{a}', 'Extra', 'custom')",
            id()
        ),
    ] {
        let err = as_app(&db.app, "openseal.account_id", a, &sql)
            .await
            .unwrap_err();
        assert_eq!(sqlstate(&err).as_deref(), Some("23514"), "{sql}: {err}");
        assert_eq!(
            constraint(&err).as_deref(),
            Some(ADMIN_EVENT_CONSTRAINT),
            "{sql}"
        );
    }
    let err = as_app(
        &db.app,
        "openseal.organization_id",
        org.0,
        "UPDATE organizations SET name = 'x'",
    )
    .await
    .unwrap_err();
    assert_eq!(
        constraint(&err).as_deref(),
        Some(ADMIN_EVENT_CONSTRAINT),
        "{err}"
    );
    // Nothing changed.
    let name: String = sqlx::query_scalar("SELECT name FROM accounts WHERE id = $1")
        .bind(a)
        .fetch_one(&db.admin)
        .await
        .unwrap();
    assert_eq!(name, "alpha");
    // The same change through the repository carries its event and commits.
    let mut tx = db.store.for_account(account).begin().await.unwrap();
    tx.act_as(actor(admin));
    tx.account()
        .set_settings(&serde_json::json!({"brand": "x", "webhook_secret": "s3"}))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    db.drop().await;
}

/// The row's exit test, part 4: workspace creation writes its event (organization log),
/// in the same transaction; archiving does too.
#[tokio::test]
async fn workspace_creation_and_archiving_write_their_events() {
    let Some(db) = fresh("workspace_creation_event", Rls::On).await else {
        return;
    };
    let org = db.organization("acme").await;
    let account = AccountId(id());
    let mut tx = db.store.for_organization(org).begin().await.unwrap();
    let who = UserId(id());
    tx.act_as(actor(who));
    let proof = tx
        .create_workspace(account, "Sales", &builtin_profiles())
        .await
        .unwrap();
    tx.archive_workspace(&proof).await.unwrap();
    // Archived again: no second event.
    tx.archive_workspace(&proof).await.unwrap();
    tx.commit().await.unwrap();
    let mut tx = db.store.for_organization(org).begin().await.unwrap();
    let log = tx.verified_admin_log().await.unwrap();
    tx.commit().await.unwrap();
    let actions: Vec<&str> = log.iter().map(|e| e.action.as_str()).collect();
    assert_eq!(actions, ["workspace.created", "workspace.archived"]);
    let created = event(&log[0]);
    assert_eq!(created["organization"], org.0.to_string());
    assert_eq!(created["target"]["workspace"], account.0.to_string());
    assert_eq!(created["actor"]["kind"], "user");
    assert_eq!(created["actor"]["id"], who.0.to_string());
    assert_eq!(created["request_id"], "req-1");
    assert_eq!(created["seq"], 0);
    assert_eq!(event(&log[1])["prev"], Hash256(log[0].hash).hex());
    // A creation whose transaction rolls back leaves neither workspace nor event.
    let mut tx = db.store.for_organization(org).begin().await.unwrap();
    tx.create_workspace(AccountId(id()), "Gone", &builtin_profiles())
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    let mut tx = db.store.for_organization(org).begin().await.unwrap();
    assert_eq!(tx.verified_admin_log().await.unwrap().len(), 2);
    assert_eq!(tx.workspaces().await.unwrap().len(), 1);
    tx.commit().await.unwrap();
    db.drop().await;
}

/// Settings, member and profile changes through the repositories append events with
/// the changed keys; secrets are recorded as rotated; names and emails never.
#[tokio::test]
async fn repository_changes_append_verified_events() {
    let Some(db) = fresh("repository_admin_events", Rls::On).await else {
        return;
    };
    let (_, account, admin, profiles) = workspace_with_admin(&db, "alpha").await;
    let mut tx = db.store.for_account(account).begin().await.unwrap();
    tx.act_as(actor(admin));
    let before = tx.account().get().await.unwrap().settings;
    let mut after = before.clone();
    after["brand"] = serde_json::json!({"color": "#c00"});
    after["smtp_password"] = serde_json::json!("hunter2");
    tx.account().set_settings(&after).await.unwrap();
    let member = user("bob@alpha.example");
    tx.users()
        .create_member(&member, profiles.sender)
        .await
        .unwrap();
    tx.users()
        .set_profile(member.id, profiles.viewer)
        .await
        .unwrap();
    tx.users()
        .set_disabled(member.id, Some(now()))
        .await
        .unwrap();
    tx.users().remove_member(member.id).await.unwrap();
    tx.commit().await.unwrap();

    let mut tx = db.store.for_account(account).begin().await.unwrap();
    let log = tx.verified_admin_log().await.unwrap();
    let page = tx.admin_events(Some(1), 2).await.unwrap();
    tx.commit().await.unwrap();
    let actions: Vec<&str> = log.iter().map(|e| e.action.as_str()).collect();
    assert_eq!(
        actions,
        [
            "member.added",
            "workspace.settings_changed",
            "member.added",
            "member.profile_changed",
            "member.disabled",
            "member.removed"
        ]
    );
    assert_eq!(page.iter().map(|e| e.seq).collect::<Vec<_>>(), [2, 3]);
    let settings = event(&log[1]);
    assert_eq!(settings["actor"]["id"], admin.0.to_string());
    assert_eq!(settings["ip"], "192.0.2.7");
    let changes = settings["changes"].as_array().unwrap();
    assert_eq!(changes.len(), 2, "{changes:?}");
    assert_eq!(changes[0]["key"], "brand");
    assert_eq!(changes[0]["new"]["color"], "#c00");
    assert_eq!(changes[1]["key"], "smtp_password");
    assert_eq!(changes[1]["new"], "rotated");
    let profile = event(&log[3]);
    assert_eq!(profile["changes"][0]["old"], profiles.sender.0.to_string());
    assert_eq!(profile["changes"][0]["new"], profiles.viewer.0.to_string());
    for e in &log {
        let text = String::from_utf8(e.canonical.clone()).unwrap();
        assert!(
            !text.contains("hunter2") && !text.contains("bob@") && !text.contains("Ada"),
            "{text}"
        );
    }
    db.drop().await;
}

/// The bootstrap writes the organization's first events in its own transaction.
#[tokio::test]
async fn the_bootstrap_writes_organization_events() {
    let Some(db) = fresh("bootstrap_admin_events", Rls::On).await else {
        return;
    };
    let org = OrganizationId(id());
    let account = AccountId(id());
    let profiles = builtin_profiles();
    let mut tx = db
        .store
        .bootstrap_organization(org, account, "First", &profiles)
        .await
        .unwrap();
    let admin = user("root@first.example");
    tx.users()
        .create_member(&admin, profiles.admin)
        .await
        .unwrap();
    tx.account()
        .make_first_owner(admin.id, now())
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let mut tx = db.store.for_organization(org).begin().await.unwrap();
    let actions: Vec<String> = tx
        .verified_admin_log()
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.action)
        .collect();
    tx.commit().await.unwrap();
    assert_eq!(
        actions,
        ["organization.created", "organization.admin_added"]
    );
    db.drop().await;
}

async fn head(db: &TestDb, table: &str, id: uuid::Uuid) -> Option<Vec<u8>> {
    sqlx::query_scalar::<_, Option<Vec<u8>>>(sqlx::AssertSqlSafe(format!(
        "SELECT admin_chain_head FROM {table} WHERE id = $1"
    )))
    .bind(id)
    .fetch_one(&db.admin)
    .await
    .unwrap()
}

/// An insert into another workspace's or organization's log is refused before anything
/// about that chain is read (`42501`, never an `OS005` naming its next `seq`), and its
/// head does not move.
#[tokio::test]
async fn an_event_for_another_scope_is_refused_without_reading_its_chain_rls_on() {
    another_scope_is_refused("admin_event_other_scope_on", Rls::On).await;
}

/// The same with row security off: the chain trigger alone refuses it.
#[tokio::test]
async fn an_event_for_another_scope_is_refused_without_reading_its_chain_rls_off() {
    another_scope_is_refused("admin_event_other_scope_off", Rls::Off).await;
}

async fn another_scope_is_refused(name: &str, rls: Rls) {
    let Some(db) = fresh(name, rls).await else {
        return;
    };
    let (org_a, a, _, _) = workspace_with_admin(&db, "alpha").await;
    let (org_b, b, _, _) = workspace_with_admin(&db, "bravo").await;
    let before = (
        head(&db, "accounts", a.0).await,
        head(&db, "organizations", org_a.0).await,
    );
    let (h1, h2) = ("11".repeat(32), "22".repeat(32));
    for (setting, scope, sql) in [
        (
            "openseal.account_id",
            b.0,
            format!(
                "INSERT INTO admin_events (account_id, seq, prev_hash, hash, action, at, canonical) \
                 VALUES ('{a}', 5, '\\x{h1}', '\\x{h2}', 'x', now(), '\\x7b7d')"
            ),
        ),
        (
            "openseal.organization_id",
            org_b.0,
            format!(
                "INSERT INTO org_admin_events (organization_id, seq, prev_hash, hash, action, at, \
                 canonical) VALUES ('{org_a}', 5, '\\x{h1}', '\\x{h2}', 'x', now(), '\\x7b7d')"
            ),
        ),
    ] {
        let err = as_app(&db.app, setting, scope, &sql).await.unwrap_err();
        assert_eq!(sqlstate(&err).as_deref(), Some("42501"), "{sql}: {err}");
        assert!(!err.to_string().contains("next"), "{err}");
    }
    let after = (
        head(&db, "accounts", a.0).await,
        head(&db, "organizations", org_a.0).await,
    );
    assert_eq!(before, after);
    db.drop().await;
}

/// Wait (bounded, no sleep) until some backend on the test database waits on a lock.
async fn until_a_backend_waits_on_a_lock(db: &TestDb) {
    for _ in 0..10_000 {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
             WHERE datname = current_database() AND wait_event_type = 'Lock'",
        )
        .fetch_one(&db.admin)
        .await
        .unwrap();
        if waiting > 0 {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("the second transaction never waited on the chain head");
}

/// Two admin changes to one workspace at the same time both commit: the second waits on
/// the head lock, then reads the `seq` the first one wrote (never a stale one, which the
/// chain trigger would refuse as a broken chain, `CS-DB-0014`).
#[tokio::test]
async fn concurrent_admin_changes_to_one_workspace_both_commit() {
    let Some(db) = fresh("admin_events_concurrent_ws", Rls::On).await else {
        return;
    };
    let (_, account, admin, profiles) = workspace_with_admin(&db, "alpha").await;
    let (m1, m2) = (user("b1@alpha.example"), user("b2@alpha.example"));
    let mut tx = db.store.for_account(account).begin().await.unwrap();
    tx.act_as(actor(admin));
    for m in [&m1, &m2] {
        tx.users().create_member(m, profiles.sender).await.unwrap();
    }
    tx.commit().await.unwrap();
    // Profile changes touch only membership rows, so the head lock is the only thing
    // the second transaction waits on.
    let mut first = db.store.for_account(account).begin().await.unwrap();
    first.act_as(actor(admin));
    first
        .users()
        .set_profile(m1.id, profiles.viewer)
        .await
        .unwrap();
    let store = db.store.clone();
    let m2 = m2.id;
    let second = tokio::spawn(async move {
        let mut tx = store.for_account(account).begin().await?;
        tx.act_as(actor(admin));
        tx.users().set_profile(m2, profiles.viewer).await?;
        tx.commit().await
    });
    until_a_backend_waits_on_a_lock(&db).await;
    first.commit().await.unwrap();
    second.await.unwrap().unwrap();
    let mut tx = db.store.for_account(account).begin().await.unwrap();
    let seqs: Vec<_> = tx
        .verified_admin_log()
        .await
        .unwrap()
        .iter()
        .map(|e| e.seq)
        .collect();
    tx.commit().await.unwrap();
    assert_eq!(seqs, [0, 1, 2, 3, 4]);
    db.drop().await;
}

/// The same for one organization: two workspaces created in it at the same time.
#[tokio::test]
async fn concurrent_admin_changes_to_one_organization_both_commit() {
    let Some(db) = fresh("admin_events_concurrent_org", Rls::On).await else {
        return;
    };
    let org = db.organization("alpha").await;
    let mut first = db.store.for_organization(org).begin().await.unwrap();
    first
        .create_workspace(AccountId(id()), "one", &builtin_profiles())
        .await
        .unwrap();
    let store = db.store.clone();
    let p2 = builtin_profiles();
    let second = tokio::spawn(async move {
        let mut tx = store.for_organization(org).begin().await?;
        tx.create_workspace(AccountId(id()), "two", &p2).await?;
        tx.commit().await
    });
    until_a_backend_waits_on_a_lock(&db).await;
    first.commit().await.unwrap();
    second.await.unwrap().unwrap();
    let mut tx = db.store.for_organization(org).begin().await.unwrap();
    let actions: Vec<String> = tx
        .verified_admin_log()
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.action)
        .collect();
    tx.commit().await.unwrap();
    assert_eq!(
        actions.iter().filter(|a| *a == "workspace.created").count(),
        2,
        "{actions:?}"
    );
    db.drop().await;
}
