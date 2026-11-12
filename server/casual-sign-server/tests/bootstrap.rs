//! ORG-02 review: `bootstrap_workspace` makes the workspace and its first administrator
//! in one transaction, so a failing administrator (here an email already taken) leaves
//! no workspace behind in the organization.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use casual_sign_server::bootstrap_workspace;
use common::Rls;
use common::harness::{Api, PASSWORD};

#[tokio::test]
async fn a_failed_first_administrator_leaves_no_workspace() {
    let Some(api) = Api::new("bootstrap_workspace_atomic", Rls::On).await else {
        return;
    };
    // The install's first organization, with administrator admin@alpha.example.test.
    let _alpha = api.tenant("alpha").await;
    let org = casual_sign_store::OrganizationId(uuid::Uuid::now_v7());
    sqlx::query("INSERT INTO organizations (id, name) VALUES ($1, 'bravo')")
        .bind(org.0)
        .execute(&api.db.admin)
        .await
        .unwrap();
    let err = bootstrap_workspace(
        &api.db.store,
        org,
        "bravo",
        "admin@alpha.example.test",
        "Admin",
        PASSWORD,
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), "CS-DB-0006", "{err:?}");
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM accounts WHERE organization_id = $1")
        .bind(org.0)
        .fetch_one(&api.db.admin)
        .await
        .unwrap();
    assert_eq!(
        left, 0,
        "a workspace without an administrator was left behind"
    );
    // With a fresh email the same call succeeds.
    bootstrap_workspace(
        &api.db.store,
        org,
        "bravo",
        "admin@bravo.example.test",
        "Admin",
        PASSWORD,
    )
    .await
    .unwrap();
}
