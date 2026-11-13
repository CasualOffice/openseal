//! The console's database role, checked against the catalog (`SEC-X01`, `SEC-X02`,
//! `SEC-X04`; docs/23 §5.1): no grant on any `public` table or function, exactly the
//! platform grants the design names, and an operator log nobody can rewrite.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

mod common;

use casual_sign_platform_store::sqlx::{self, Row};

/// Every `public` table, each refused to the console for SELECT, INSERT, UPDATE and
/// DELETE; and every SECURITY DEFINER function in `public` refused for EXECUTE.
#[tokio::test]
async fn the_console_role_reaches_no_public_table_or_function() {
    let Some(db) = common::fresh("the_console_role_reaches_no_public_table_or_function").await
    else {
        return;
    };
    let tables: Vec<String> = sqlx::query(
        "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm') ORDER BY 1",
    )
    .fetch_all(&db.owner)
    .await
    .unwrap()
    .iter()
    .map(|r| r.get(0))
    .collect();
    assert!(
        tables.len() > 30,
        "expected every tenant table, found {}",
        tables.len()
    );
    let mut granted = Vec::new();
    for t in &tables {
        for p in [
            "SELECT",
            "INSERT",
            "UPDATE",
            "DELETE",
            "TRUNCATE",
            "REFERENCES",
            "TRIGGER",
        ] {
            let has: bool = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT has_table_privilege('openseal_console', 'public.{t}', '{p}')"
            )))
            .fetch_one(&db.owner)
            .await
            .unwrap();
            if has {
                granted.push(format!("{p} {t}"));
            }
        }
        // And as the console's own login: the read itself is refused.
        let err = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT 1 FROM public.{t} LIMIT 1"
        )))
        .execute(&db.console)
        .await
        .expect_err(t);
        let code = err
            .as_database_error()
            .and_then(|d| d.code())
            .unwrap_or_default();
        assert_eq!(code, "42501", "SELECT on {t} as the console");
    }
    assert!(
        granted.is_empty(),
        "console grants on public tables: {granted:?}"
    );

    let definer: Vec<String> = sqlx::query(
        "SELECT p.oid::regprocedure::text FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace \
         WHERE n.nspname = 'public' AND p.prosecdef \
           AND has_function_privilege('openseal_console', p.oid, 'EXECUTE')",
    )
    .fetch_all(&db.owner)
    .await
    .unwrap()
    .iter()
    .map(|r| r.get(0))
    .collect();
    assert!(
        definer.is_empty(),
        "public definer functions the console can run: {definer:?}"
    );
    db.drop().await;
}

/// `SEC-X02`: no path to impersonation. The tables a session, key, token or invitation
/// for a tenant identity lives in refuse the console's writes.
#[tokio::test]
async fn the_console_cannot_mint_a_tenant_session_key_or_invitation() {
    let Some(db) =
        common::fresh("the_console_cannot_mint_a_tenant_session_key_or_invitation").await
    else {
        return;
    };
    for t in [
        "staff_sessions",
        "api_clients",
        "user_invitations",
        "users",
        "account_memberships",
        "organization_admins",
    ] {
        // The grant itself, since row-level security would also answer 42501 to a role
        // that had one.
        for p in ["INSERT", "UPDATE"] {
            let has: bool = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT has_table_privilege('openseal_console', 'public.{t}', '{p}')"
            )))
            .fetch_one(&db.owner)
            .await
            .unwrap();
            assert!(!has, "the console holds {p} on {t}");
        }
        let err = sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO public.{t} DEFAULT VALUES"
        )))
        .execute(&db.console)
        .await
        .expect_err(t);
        let code = err
            .as_database_error()
            .and_then(|d| d.code())
            .unwrap_or_default();
        assert_eq!(code, "42501", "INSERT into {t} as the console");
    }
    db.drop().await;
}

/// The console's direct privileges in `platform` are exactly: SELECT on every table,
/// INSERT on the two append-only ones; EXECUTE on the named definer functions only.
#[tokio::test]
async fn platform_grants_are_exactly_the_designed_ones() {
    let Some(db) = common::fresh("platform_grants_are_exactly_the_designed_ones").await else {
        return;
    };
    let rows = sqlx::query(
        "SELECT c.relname, p.priv, has_table_privilege('openseal_console', c.oid, p.priv) \
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
         CROSS JOIN unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE']) AS p(priv) \
         WHERE n.nspname = 'platform' AND c.relkind = 'r' ORDER BY 1, 2",
    )
    .fetch_all(&db.owner)
    .await
    .unwrap();
    let mut wrong = Vec::new();
    for r in &rows {
        let (t, p, has): (String, String, bool) = (r.get(0), r.get(1), r.get(2));
        let expected =
            p == "SELECT" || (p == "INSERT" && (t == "operator_events" || t == "alerts"));
        if has != expected {
            wrong.push(format!("{p} {t}: {has}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "platform table grants differ from the design: {wrong:?}"
    );

    let mut callable: Vec<String> = sqlx::query(
        "SELECT p.proname::text FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace \
         WHERE n.nspname = 'platform' AND has_function_privilege('openseal_console', p.oid, 'EXECUTE')",
    )
    .fetch_all(&db.owner)
    .await
    .unwrap()
    .iter()
    .map(|r| r.get(0))
    .collect();
    callable.sort();
    let mut expected = vec![
        "begin_enrolment",
        "bootstrap_operator",
        "confirm_mfa",
        "create_operator",
        "dead_jobs",
        "disable_operator",
        "finish_enrolment",
        "job_stats",
        "open_session",
        "organization",
        "organization_workspaces",
        "organizations_page",
        "pool_stats",
        "rename_organization",
        "resolve_session",
        "revoke_session",
        "set_organization_regions",
        "set_workspace_region",
        "set_workspace_status",
        "request_approval",
        "grant_approval",
        "apply_suspend_organization",
        "apply_resume_organization",
        // CON-16, migration 0026: the copy of each organization write into its admin log.
        "org_log_tip",
        "copy_to_org_log",
        "xact_copied_to_org_log",
    ];
    expected.sort_unstable();
    assert_eq!(callable, expected);

    // Every SECURITY DEFINER function in `platform` pins its search_path.
    let unpinned: Vec<String> = sqlx::query(
        "SELECT p.proname::text FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace \
         WHERE n.nspname = 'platform' AND p.prosecdef \
           AND NOT EXISTS (SELECT 1 FROM unnest(p.proconfig) c WHERE c LIKE 'search_path=%')",
    )
    .fetch_all(&db.owner)
    .await
    .unwrap()
    .iter()
    .map(|r| r.get(0))
    .collect();
    assert!(
        unpinned.is_empty(),
        "definer functions without search_path: {unpinned:?}"
    );
    db.drop().await;
}

/// `SEC-X04`: the operator log refuses UPDATE, DELETE and TRUNCATE for the console and
/// for the owner, and refuses an event that does not extend the chain.
#[tokio::test]
async fn the_operator_log_is_append_only_and_chained_in_the_database() {
    let Some(db) =
        common::fresh("the_operator_log_is_append_only_and_chained_in_the_database").await
    else {
        return;
    };
    let store = casual_sign_platform_store::PlatformStore::new(db.console.clone());
    let at = time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
    let mut tx = store.begin().await.unwrap();
    tx.append(&casual_sign_platform_store::EventDraft::new(
        "operator.test",
        None,
        at,
    ))
    .await
    .unwrap();
    tx.append(&casual_sign_platform_store::EventDraft::new(
        "operator.test",
        None,
        at,
    ))
    .await
    .unwrap();
    tx.commit().await.unwrap();

    for (pool, who) in [(&db.console, "console"), (&db.owner, "owner")] {
        for sql in [
            "UPDATE platform.operator_events SET action = 'operator.x' WHERE seq = 0",
            "DELETE FROM platform.operator_events WHERE seq = 1",
            "TRUNCATE platform.operator_events",
        ] {
            let err = sqlx::query(sql).execute(pool).await.expect_err(sql);
            let code = err
                .as_database_error()
                .and_then(|d| d.code())
                .unwrap_or_default();
            assert!(
                code == "OS001" || code == "42501",
                "{who}: {sql} gave {code}"
            );
        }
    }
    // An event that does not extend the chain: a wrong seq, a wrong prev, a wrong hash.
    let head: Vec<u8> = sqlx::query_scalar("SELECT head FROM platform.operator_chain")
        .fetch_one(&db.owner)
        .await
        .unwrap();
    let body = |seq: i64, prev: &str| {
        format!(
            "{{\"action\":\"operator.test\",\"operator\":null,\"prev\":{prev},\"seq\":{seq},\"v\":1}}"
        )
    };
    let hex: String = head.iter().map(|b| format!("{b:02x}")).collect();
    for (seq, prev, canonical, hash_ok) in [
        (
            5_i64,
            Some(head.clone()),
            body(5, &format!("\"{hex}\"")),
            true,
        ),
        (2, None, body(2, "null"), true),
        (2, Some(head.clone()), body(2, &format!("\"{hex}\"")), false),
        (2, Some(head.clone()), body(3, &format!("\"{hex}\"")), true),
        // The right seq after a prev that is not the head.
        (
            2,
            Some(vec![7u8; 32]),
            body(2, &format!("\"{}\"", "07".repeat(32))),
            true,
        ),
    ] {
        let hash: Vec<u8> = if hash_ok {
            casual_sign_console::crypto::sha256(canonical.as_bytes()).to_vec()
        } else {
            vec![0u8; 32]
        };
        let err = sqlx::query(
            "INSERT INTO platform.operator_events (seq, prev_hash, hash, action, operator_id, at, canonical) \
             VALUES ($1, $2, $3, 'operator.test', NULL, now(), $4)",
        )
        .bind(seq)
        .bind(prev)
        .bind(hash)
        .bind(canonical.as_bytes())
        .execute(&db.console)
        .await
        .expect_err("a broken link must be refused");
        let code = err
            .as_database_error()
            .and_then(|d| d.code())
            .unwrap_or_default();
        assert!(code == "OS005" || code == "23514", "seq {seq}: {code}");
    }
    assert_eq!(store.verify_log().await.unwrap().events, 2);
    db.drop().await;
}
