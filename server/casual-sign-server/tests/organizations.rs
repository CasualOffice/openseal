//! ORG-03: the organization routes (`/organizations/me`, its workspaces, admins and admin
//! log; docs/23 §2.2, §6). An organization owner creates, joins and archives a
//! workspace; a member with no organization role gets `403`; every organization route
//! answers `404` for another organization's ids (generated from the route table); the
//! last owner cannot leave (`CS-ORG-0008`); a removed admin's next request is refused
//! (`SEC-O06`); a join is the only way to content and is logged in both chains, and a
//! delegated admin cannot join (`SEC-O07`).

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::too_many_lines
)]

mod common;

use axum::http::StatusCode;
use casual_sign_server::table;
use common::Rls;
use common::harness::{Api, Auth, PASSWORD, Resp, session_of};
use serde_json::{Value, json};

async fn login(api: &Api, email: &str) -> Auth {
    let r = api
        .call(
            "POST",
            "/api/v1/auth/login",
            &Auth::None,
            Some(json!({"email": email, "password": PASSWORD})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    session_of(&r)
}

fn is(r: &Resp, status: StatusCode, code: Option<&str>, what: &str) -> Value {
    assert_eq!(r.status, status, "{what}: {:?}", r.json());
    if let Some(c) = code {
        assert_eq!(r.code(), c, "{what}");
    }
    r.json()
}

async fn actions(api: &Api, s: &Auth, path: &str) -> Vec<String> {
    let r = api.call("GET", path, s, None, &[]).await;
    is(&r, StatusCode::OK, None, path)["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap().to_owned())
        .collect()
}

async fn organization_routes(rls: Rls) {
    let Some(api) = Api::new(&format!("organization_routes_{rls:?}"), rls).await else {
        return;
    };
    // alpha: the install's organization, its bootstrap admin its owner.
    let alpha = api.tenant("alpha").await;
    let owner = login(&api, &alpha.email).await;
    // bravo: another organization; its workspace admin made its owner.
    let bravo = api.tenant("bravo").await;
    sqlx::query(
        "INSERT INTO organization_admins (organization_id, user_id, role, created_at) \
         VALUES ($1, $2, 'owner', now())",
    )
    .bind(bravo.boot.organization.0)
    .bind(bravo.boot.admin.0)
    .execute(&api.db.admin)
    .await
    .unwrap();
    let other = login(&api, &bravo.email).await;

    // A member of alpha's workspace with no organization role.
    let m_email = "member@alpha.example.test";
    let r = api
        .call(
            "POST",
            "/api/v1/users",
            &alpha.auth,
            Some(
                json!({"email": m_email, "name": "Member", "profile": "sender",
                "password": PASSWORD}),
            ),
            &[],
        )
        .await;
    let member_id = is(&r, StatusCode::CREATED, None, "member")["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let member = login(&api, m_email).await;

    // The organization, as its owner; not to a member without a role, nor to an API key.
    let r = api
        .call("GET", "/api/v1/organizations/me", &owner, None, &[])
        .await;
    let o = is(&r, StatusCode::OK, None, "organization");
    assert_eq!(o["role"], "owner");
    assert_eq!(o["id"], alpha.boot.organization.to_string());
    for (who, auth) in [("member", &member), ("api key", &alpha.auth)] {
        let r = api
            .call("GET", "/api/v1/organizations/me", auth, None, &[])
            .await;
        is(&r, StatusCode::FORBIDDEN, Some("CS-AUTH-0006"), who);
        let r = api
            .call(
                "POST",
                "/api/v1/organizations/me/workspaces",
                auth,
                Some(json!({"name": "Nope"})),
                &[],
            )
            .await;
        is(&r, StatusCode::FORBIDDEN, Some("CS-AUTH-0006"), who);
    }

    // Rename, logged.
    let r = api
        .call(
            "PATCH",
            "/api/v1/organizations/me",
            &owner,
            Some(json!({"name": "Alpha Group"})),
            &[],
        )
        .await;
    assert_eq!(
        is(&r, StatusCode::OK, None, "rename")["name"],
        "Alpha Group"
    );

    // The owner creates a workspace.
    let r = api
        .call(
            "POST",
            "/api/v1/organizations/me/workspaces",
            &owner,
            Some(json!({"name": "Legal"})),
            &[],
        )
        .await;
    let w = is(&r, StatusCode::CREATED, None, "create");
    assert_eq!(w["status"], "active");
    let wid = w["id"].as_str().unwrap().to_owned();
    let r = api
        .call(
            "GET",
            "/api/v1/organizations/me/workspaces",
            &owner,
            None,
            &[],
        )
        .await;
    let names: Vec<String> = is(&r, StatusCode::OK, None, "list")["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["name"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(names, ["Legal", "alpha"]);
    let r = api
        .call(
            "GET",
            &format!("/api/v1/organizations/me/workspaces/{wid}"),
            &owner,
            None,
            &[],
        )
        .await;
    assert_eq!(is(&r, StatusCode::OK, None, "get")["name"], "Legal");

    // Every organization route with an id answers 404 to another organization's owner
    // for alpha's ids, and leaves them as they were (generated from the route table).
    let mut probed = 0;
    for route in table() {
        if !route.path.starts_with("/api/v1/organizations/me/") || !route.path.contains('{') {
            continue;
        }
        let path = route
            .path
            .replace("{id}", &wid)
            .replace("{user}", &alpha.boot.admin.to_string());
        let body = match (route.method, route.path) {
            ("PATCH", _) => Some(json!({"role": "admin"})),
            (_, p) if p.ends_with("/join") => Some(json!({"profile": "admin"})),
            _ => None,
        };
        let r = api.call(route.method, &path, &other, body, &[]).await;
        is(
            &r,
            StatusCode::NOT_FOUND,
            Some("CS-API-0002"),
            &format!("{} {}", route.method, route.path),
        );
        probed += 1;
    }
    assert_eq!(probed, 5, "organization routes with an id");
    let r = api
        .call(
            "GET",
            "/api/v1/organizations/me/workspaces",
            &other,
            None,
            &[],
        )
        .await;
    let theirs = is(&r, StatusCode::OK, None, "bravo's list");
    assert_eq!(theirs["items"].as_array().unwrap().len(), 1);
    assert_eq!(theirs["items"][0]["id"], bravo.boot.account.to_string());

    // SEC-O07: a delegated admin, even one whose set names every action, cannot join.
    let set = uuid::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO org_permission_sets (id, organization_id, name, permissions) \
         VALUES ($1, $2, 'all', ARRAY['org.workspaces.join','org.workspaces.create'])",
    )
    .bind(set)
    .bind(alpha.boot.organization.0)
    .execute(&api.db.admin)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO organization_admins (organization_id, user_id, role, permission_set_id, \
         created_at) VALUES ($1, $2, 'delegated', $3, now())",
    )
    .bind(alpha.boot.organization.0)
    .bind(uuid::Uuid::parse_str(&member_id).unwrap())
    .bind(set)
    .execute(&api.db.admin)
    .await
    .unwrap();
    let r = api
        .call(
            "POST",
            &format!("/api/v1/organizations/me/workspaces/{wid}/join"),
            &member,
            Some(json!({"profile": "admin"})),
            &[],
        )
        .await;
    is(
        &r,
        StatusCode::FORBIDDEN,
        Some("CS-AUTH-0006"),
        "delegated join",
    );
    // An owner promotes a delegated admin to admin: the permission set and scope go.
    let r = api
        .call(
            "PATCH",
            &format!("/api/v1/organizations/me/admins/{member_id}"),
            &owner,
            Some(json!({"role": "admin"})),
            &[],
        )
        .await;
    let promoted = is(&r, StatusCode::OK, None, "promote delegated");
    assert_eq!(promoted["role"], "admin");
    assert!(promoted["permission_set_id"].is_null(), "{promoted}");
    let r = api
        .call(
            "DELETE",
            &format!("/api/v1/organizations/me/admins/{member_id}"),
            &owner,
            None,
            &[],
        )
        .await;
    is(&r, StatusCode::OK, None, "remove promoted");

    // The owner joins, visibly: the workspace's log and the organization's.
    let r = api
        .call(
            "POST",
            &format!("/api/v1/organizations/me/workspaces/{wid}/join"),
            &owner,
            Some(json!({"profile": "sender"})),
            &[],
        )
        .await;
    let j = is(&r, StatusCode::CREATED, None, "join");
    assert_eq!(j["user_id"], alpha.boot.admin.to_string());
    let in_w: Vec<(String, String)> = sqlx::query_as(
        "SELECT action, convert_from(canonical, 'UTF8') FROM admin_events \
         WHERE account_id = $1 ORDER BY seq",
    )
    .bind(uuid::Uuid::parse_str(&wid).unwrap())
    .fetch_all(&api.db.admin)
    .await
    .unwrap();
    let joined = in_w
        .iter()
        .find(|(a, _)| a == "member.added")
        .expect("member.added in the workspace's log");
    assert!(joined.1.contains("organization"), "{}", joined.1);

    // Archive; idempotent; no join into an archived workspace.
    for _ in 0..2 {
        let r = api
            .call(
                "POST",
                &format!("/api/v1/organizations/me/workspaces/{wid}/archive"),
                &owner,
                None,
                &[],
            )
            .await;
        assert_eq!(
            is(&r, StatusCode::OK, None, "archive")["status"],
            "archived"
        );
    }
    let r = api
        .call(
            "POST",
            &format!("/api/v1/organizations/me/workspaces/{wid}/join"),
            &owner,
            Some(json!({"profile": "admin"})),
            &[],
        )
        .await;
    is(
        &r,
        StatusCode::CONFLICT,
        Some("CS-ORG-0010"),
        "archived join",
    );

    // Admins: only a member of one of its workspaces, never oneself.
    let r = api
        .call(
            "POST",
            "/api/v1/organizations/me/admins",
            &owner,
            Some(json!({"user_id": bravo.boot.admin.to_string(), "role": "admin"})),
            &[],
        )
        .await;
    is(
        &r,
        StatusCode::UNPROCESSABLE_ENTITY,
        Some("CS-ORG-0018"),
        "outsider",
    );
    let r = api
        .call(
            "POST",
            "/api/v1/organizations/me/admins",
            &owner,
            Some(json!({"user_id": alpha.boot.admin.to_string(), "role": "admin"})),
            &[],
        )
        .await;
    is(&r, StatusCode::FORBIDDEN, Some("CS-ORG-0005"), "self");
    let r = api
        .call(
            "POST",
            "/api/v1/organizations/me/admins",
            &owner,
            Some(json!({"user_id": member_id, "role": "admin"})),
            &[],
        )
        .await;
    assert_eq!(
        is(&r, StatusCode::CREATED, None, "add admin")["role"],
        "admin"
    );
    let r = api
        .call("GET", "/api/v1/organizations/me", &member, None, &[])
        .await;
    assert_eq!(is(&r, StatusCode::OK, None, "admin reads")["role"], "admin");
    // An admin does not manage admins.
    let r = api
        .call(
            "PATCH",
            &format!("/api/v1/organizations/me/admins/{member_id}"),
            &member,
            Some(json!({"role": "owner"})),
            &[],
        )
        .await;
    is(
        &r,
        StatusCode::FORBIDDEN,
        Some("CS-AUTH-0006"),
        "admin self-promotes",
    );
    let r = api
        .call(
            "PATCH",
            &format!("/api/v1/organizations/me/admins/{member_id}"),
            &owner,
            Some(json!({"role": "owner"})),
            &[],
        )
        .await;
    assert_eq!(is(&r, StatusCode::OK, None, "promote")["role"], "owner");
    let r = api
        .call("GET", "/api/v1/organizations/me/admins", &owner, None, &[])
        .await;
    assert_eq!(
        is(&r, StatusCode::OK, None, "admins")["items"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    // SEC-O06: removed, the next request is refused.
    let r = api
        .call(
            "DELETE",
            &format!("/api/v1/organizations/me/admins/{member_id}"),
            &owner,
            None,
            &[],
        )
        .await;
    is(&r, StatusCode::OK, None, "remove");
    let r = api
        .call("GET", "/api/v1/organizations/me", &member, None, &[])
        .await;
    is(
        &r,
        StatusCode::FORBIDDEN,
        Some("CS-AUTH-0006"),
        "removed admin",
    );

    // The last owner cannot leave.
    let r = api
        .call(
            "DELETE",
            &format!("/api/v1/organizations/me/admins/{}", alpha.boot.admin),
            &owner,
            None,
            &[],
        )
        .await;
    is(&r, StatusCode::CONFLICT, Some("CS-ORG-0008"), "last owner");
    let r = api
        .call("GET", "/api/v1/organizations/me", &owner, None, &[])
        .await;
    assert_eq!(is(&r, StatusCode::OK, None, "still owner")["role"], "owner");

    // The organization's log, verified whole, holds each change in order.
    let got = actions(&api, &owner, "/api/v1/organizations/me/audit?verify=full").await;
    let want = [
        "organization.renamed",
        "workspace.created",
        "org.workspace_joined",
        "workspace.archived",
        "organization.admin_added",
        "organization.admin_role_changed",
        "organization.admin_removed",
    ];
    let mut at = 0;
    for w in want {
        let i = got[at..]
            .iter()
            .position(|a| a == w)
            .unwrap_or_else(|| panic!("{w} missing after {at}: {got:?}"));
        at += i + 1;
    }
    let r = api
        .call(
            "GET",
            "/api/v1/organizations/me/audit?format=csv&limit=2",
            &owner,
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.headers.contains_key("x-next-cursor"));
    let r = api
        .call("GET", "/api/v1/organizations/me/audit", &member, None, &[])
        .await;
    is(
        &r,
        StatusCode::FORBIDDEN,
        Some("CS-AUTH-0006"),
        "member reads log",
    );
    // Another organization's log does not hold alpha's events.
    let theirs = actions(&api, &other, "/api/v1/organizations/me/audit").await;
    assert!(
        !theirs.iter().any(|a| a == "workspace.archived"),
        "{theirs:?}"
    );
    api.db.drop().await;
}

#[tokio::test]
async fn organization_routes_with_rls() {
    organization_routes(Rls::On).await;
}

#[tokio::test]
async fn organization_routes_without_rls() {
    organization_routes(Rls::Off).await;
}
