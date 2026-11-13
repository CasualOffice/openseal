//! Every console write on an organization is copied into that organization's admin log
//! (`CON-16`, docs/23 §2.5, §5.1; docs/07 `SEC-O13`, `SEC-X04`): in the write's
//! transaction, as `operator.*`, naming the acting operator and the operator event it
//! copies; a write without its copy does not commit, and a copy that fails takes its
//! write with it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    missing_docs
)]

mod common;

use axum::http::StatusCode;
use casual_sign_platform_store::sqlx::{self, Row};
use casual_sign_platform_store::{Detail, EventDraft};
use common::{Console, Session};
use serde_json::{Value, json};
use uuid::Uuid;

const PASSWORD: &str = "correct horse battery staple";

/// The owner and a second operator, both signed in with fresh second factors.
async fn two_operators(c: &Console) -> (Session, Session) {
    let owner_seed = c.bootstrap("owner@ops.example", PASSWORD).await;
    let owner = c.sign_in("owner@ops.example", PASSWORD, &owner_seed).await;
    let r = c
        .call(
            &owner,
            "POST",
            "/console/v1/operators",
            Some(json!({"email": "second@ops.example", "roles": ["operator"]})),
        )
        .await;
    let token = r.json()["enrolment_token"].as_str().unwrap().to_owned();
    let second_seed = c.enrol(&token, "second operator pw").await;
    let second = c
        .sign_in("second@ops.example", "second operator pw", &second_seed)
        .await;
    let owner = c.sign_in("owner@ops.example", PASSWORD, &owner_seed).await;
    (owner, second)
}

/// The organization's admin log, as the owner reads it: (seq, action, canonical JSON).
async fn org_log(db: &common::TestDb, org: Uuid) -> Vec<(i64, String, Value)> {
    sqlx::query(
        "SELECT seq, action, canonical FROM org_admin_events WHERE organization_id = $1 ORDER BY seq",
    )
    .bind(org)
    .fetch_all(&db.owner)
    .await
    .unwrap()
    .iter()
    .map(|r| {
        let bytes: Vec<u8> = r.get("canonical");
        (
            r.get("seq"),
            r.get("action"),
            serde_json::from_slice(&bytes).unwrap(),
        )
    })
    .collect()
}

/// The chain holds: each hash is SHA-256 of its bytes, each `prev` the hash before it,
/// and the organization's stored head is the last hash.
async fn assert_org_chain(db: &common::TestDb, org: Uuid) {
    let broken: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM org_admin_events e \
          WHERE e.organization_id = $1 \
            AND (e.hash <> sha256(e.canonical) \
                 OR e.prev_hash IS DISTINCT FROM (SELECT p.hash FROM org_admin_events p \
                     WHERE p.organization_id = e.organization_id AND p.seq = e.seq - 1))",
    )
    .bind(org)
    .fetch_one(&db.owner)
    .await
    .unwrap();
    assert_eq!(broken, 0, "organization log links");
    let head_ok: bool = sqlx::query_scalar(
        "SELECT o.admin_chain_head IS NOT DISTINCT FROM (SELECT e.hash FROM org_admin_events e \
             WHERE e.organization_id = o.id ORDER BY e.seq DESC LIMIT 1) \
           FROM organizations o WHERE o.id = $1",
    )
    .bind(org)
    .fetch_one(&db.owner)
    .await
    .unwrap();
    assert!(head_ok, "organization log head");
}

async fn operator_id(db: &common::TestDb, email: &str) -> Uuid {
    sqlx::query_scalar("SELECT id FROM platform.operators WHERE email = $1")
        .bind(email)
        .fetch_one(&db.owner)
        .await
        .unwrap()
}

async fn approve(
    c: &Console,
    owner: &Session,
    second: &Session,
    action: &str,
    org: Uuid,
) -> String {
    let r = c
        .call(
            owner,
            "POST",
            "/console/v1/approvals",
            Some(json!({"action": action, "organization": org})),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text);
    let id = r.json()["id"].as_str().unwrap().to_owned();
    let g = c
        .call(
            second,
            "POST",
            &format!("/console/v1/approvals/{id}/grant"),
            None,
        )
        .await;
    assert_eq!(g.status, StatusCode::NO_CONTENT, "{}", g.text);
    id
}

/// The acceptance test: rename, data-region labels, a workspace's label, archive and
/// restore, suspend and resume each append one `operator.*` copy to the organization's
/// log, naming the operator, its targets and the operator event it copies.
#[tokio::test]
async fn every_console_write_on_an_organization_is_copied_into_its_admin_log() {
    let Some(db) =
        common::fresh("every_console_write_on_an_organization_is_copied_into_its_admin_log").await
    else {
        return;
    };
    let seed = db.seed().await;
    let c = common::console(&db);
    let (owner, second) = two_operators(&c).await;
    let owner_id = operator_id(&db, "owner@ops.example").await;
    let (org, ws) = (seed.org, seed.workspace);
    let before = org_log(&db, org).await.len();

    let calls = [
        (
            format!("/console/v1/organizations/{org}"),
            json!({"name": "Renamed By Operator"}),
        ),
        (
            format!("/console/v1/organizations/{org}"),
            json!({"data_regions": ["eu-1", "us-1"]}),
        ),
        (
            format!("/console/v1/workspaces/{ws}"),
            json!({"data_region": "eu-1"}),
        ),
        (
            format!("/console/v1/workspaces/{ws}"),
            json!({"status": "archived"}),
        ),
        (
            format!("/console/v1/workspaces/{ws}"),
            json!({"status": "active"}),
        ),
    ];
    for (path, body) in calls {
        let r = c.call(&owner, "PATCH", &path, Some(body.clone())).await;
        assert_eq!(
            r.status,
            StatusCode::NO_CONTENT,
            "{path} {body}: {}",
            r.text
        );
    }
    let id = approve(&c, &owner, &second, "organization.suspend", org).await;
    let r = c
        .call(
            &owner,
            "POST",
            &format!("/console/v1/organizations/{org}/suspend"),
            Some(json!({"approval": id})),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.text);
    let id = approve(&c, &owner, &second, "organization.resume", org).await;
    let r = c
        .call(
            &owner,
            "POST",
            &format!("/console/v1/organizations/{org}/resume"),
            Some(json!({"approval": id})),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.text);

    let log = org_log(&db, org).await;
    let copies: Vec<_> = log[before..].to_vec();
    let actions: Vec<&str> = copies.iter().map(|(_, a, _)| a.as_str()).collect();
    assert_eq!(
        actions,
        [
            "operator.organization.renamed",
            "operator.organization.regions_set",
            "operator.workspace.region_set",
            "operator.workspace.archived",
            "operator.workspace.restored",
            "operator.organization.suspended",
            "operator.organization.resumed",
        ]
    );
    let org_s = org.to_string();
    let ws_s = ws.to_string();
    for (seq, action, body) in &copies {
        assert_eq!(body["organization"], json!(org_s), "{action}");
        assert_eq!(body["seq"], json!(seq), "{action}");
        assert_eq!(
            body["actor"],
            json!({"kind": "operator", "id": owner_id.to_string()}),
            "{action}"
        );
        // The copy names the operator event it copies, which says the same.
        let op_seq = body["operator_event"]["seq"].as_i64().unwrap();
        let row = sqlx::query("SELECT action, hash FROM platform.operator_events WHERE seq = $1")
            .bind(op_seq)
            .fetch_one(&db.owner)
            .await
            .unwrap();
        assert_eq!(row.get::<String, _>("action"), *action);
        let hash: Vec<u8> = row.get("hash");
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(body["operator_event"]["hash"], json!(hex), "{action}");
        // Tenants see who acted, never from where.
        assert!(body.get("ip").is_none(), "{action}");
        let target = if action.starts_with("operator.workspace.") {
            json!({"workspace": ws_s})
        } else if action.ends_with("suspended") || action.ends_with("resumed") {
            json!({"organization": org_s, "approval": body["target"]["approval"]})
        } else {
            json!({"organization": org_s})
        };
        assert_eq!(body["target"], target, "{action}");
    }
    assert_eq!(
        copies[1].2["details"],
        json!({"data_regions": ["eu-1", "us-1"]})
    );
    assert_eq!(copies[2].2["details"], json!({"data_region": "eu-1"}));
    assert_org_chain(&db, org).await;
    db.drop().await;
}

/// A console write whose transaction appends only the operator event, not the copy,
/// does not commit (`admin_change_has_event`), and nothing changes.
#[tokio::test]
async fn a_console_write_without_its_copy_does_not_commit() {
    let Some(db) = common::fresh("a_console_write_without_its_copy_does_not_commit").await else {
        return;
    };
    let seed = db.seed().await;
    let c = common::console(&db);
    let (owner, _) = two_operators(&c).await;
    let owner_id = operator_id(&db, "owner@ops.example").await;
    let token = casual_sign_console::crypto::sha256(owner.cookie.as_ref().unwrap().as_bytes());
    let now = c.clock.get();
    let before = org_log(&db, seed.org).await.len();

    // Archive a workspace with the operator event only.
    let mut tx = c.store.begin().await.unwrap();
    assert!(
        tx.set_workspace_status(&token, seed.workspace, "archived", now)
            .await
            .unwrap()
    );
    tx.append(
        &EventDraft::new("operator.workspace.archived", Some(owner_id), now)
            .with("workspace", Detail::Id(seed.workspace)),
    )
    .await
    .unwrap();
    let err = tx.commit().await.unwrap_err();
    assert_eq!(err.code(), "CS-DB-0008", "{err:?}");
    let status: String = sqlx::query_scalar("SELECT status FROM accounts WHERE id = $1")
        .bind(seed.workspace)
        .fetch_one(&db.owner)
        .await
        .unwrap();
    assert_eq!(status, "active");

    // Rename an organization with no event at all.
    let mut tx = c.store.begin().await.unwrap();
    assert!(
        tx.rename_organization(&token, seed.org, "Silent", now)
            .await
            .unwrap()
    );
    assert_eq!(tx.commit().await.unwrap_err().code(), "CS-DB-0008");
    let name: String = sqlx::query_scalar("SELECT name FROM organizations WHERE id = $1")
        .bind(seed.org)
        .fetch_one(&db.owner)
        .await
        .unwrap();
    assert_ne!(name, "Silent");
    assert_eq!(org_log(&db, seed.org).await.len(), before);
    db.drop().await;
}

/// The copy must name the session's own operator and link an operator event of its own:
/// bytes naming another operator (or another kind of actor), or linking no operator
/// event or one that does not exist, are refused, and the write in that transaction goes
/// with it.
#[tokio::test]
async fn a_forged_copy_is_refused_and_its_write_rolls_back() {
    let Some(db) = common::fresh("a_forged_copy_is_refused_and_its_write_rolls_back").await else {
        return;
    };
    let seed = db.seed().await;
    let c = common::console(&db);
    let (owner, _) = two_operators(&c).await;
    let token = casual_sign_console::crypto::sha256(owner.cookie.as_ref().unwrap().as_bytes());
    let now = c.clock.get();
    let before = org_log(&db, seed.org).await.len();
    let other = operator_id(&db, "second@ops.example").await;

    let own = operator_id(&db, "owner@ops.example").await;
    let nowhere = json!({"seq": 999_999, "hash": "00".repeat(32)});
    for (actor, operator_event) in [
        (
            json!({"kind": "operator", "id": other.to_string()}),
            Value::Null,
        ),
        (
            json!({"kind": "user", "id": other.to_string()}),
            Value::Null,
        ),
        // Its own operator, but no operator event behind it.
        (
            json!({"kind": "operator", "id": own.to_string()}),
            Value::Null,
        ),
        (
            json!({"kind": "operator", "id": own.to_string()}),
            nowhere.clone(),
        ),
    ] {
        let mut conn = db.console.begin().await.unwrap();
        let tip = sqlx::query("SELECT next_seq, head FROM platform.org_log_tip($1, $2, NULL, $3)")
            .bind(token.as_slice())
            .bind(seed.org)
            .bind(now)
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        let seq: i64 = tip.get("next_seq");
        let head: Option<Vec<u8>> = tip.get("head");
        sqlx::query("SELECT platform.rename_organization($1, $2, 'Forged', $3)")
            .bind(token.as_slice())
            .bind(seed.org)
            .bind(now)
            .execute(&mut *conn)
            .await
            .unwrap();
        let ms = now.unix_timestamp_nanos() / 1_000_000;
        let at = time::OffsetDateTime::from_unix_timestamp_nanos(ms * 1_000_000).unwrap();
        let prev = head
            .as_ref()
            .map(|h| Value::String(h.iter().map(|b| format!("{b:02x}")).collect()))
            .unwrap_or(Value::Null);
        // Canonical enough for the database's checks (it re-derives nothing else).
        let doc = json!({
            "action": "operator.organization.renamed", "actor": actor, "at": ms as u64,
            "operator_event": operator_event, "organization": seed.org.to_string(),
            "prev": prev, "seq": seq, "target": {}, "v": 1,
        });
        let bytes = serde_json::to_vec(&doc).unwrap();
        let hash = casual_sign_console::crypto::sha256(&bytes);
        let err = sqlx::query(
            "SELECT platform.copy_to_org_log($1, $2, $3, $4, $5, 'operator.organization.renamed', $6, $7, $8)",
        )
        .bind(token.as_slice())
        .bind(seed.org)
        .bind(seq)
        .bind(head)
        .bind(hash.as_slice())
        .bind(at)
        .bind(&bytes)
        .bind(now)
        .execute(&mut *conn)
        .await
        .unwrap_err();
        let code = err
            .as_database_error()
            .and_then(|d| d.code())
            .unwrap_or_default()
            .into_owned();
        assert_eq!(code, "OS005", "{actor} {operator_event}");
        drop(conn);
    }
    let name: String = sqlx::query_scalar("SELECT name FROM organizations WHERE id = $1")
        .bind(seed.org)
        .fetch_one(&db.owner)
        .await
        .unwrap();
    assert_ne!(name, "Forged");
    assert_eq!(org_log(&db, seed.org).await.len(), before);
    db.drop().await;
}
