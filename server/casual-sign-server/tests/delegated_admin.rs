//! Delegated workspace administration and the rule against escalation (ORG-07; ADR-028
//! (d), docs/23 §2.2, docs/07 `SEC-O02`).
//!
//! The grant routes are generated from the route table: every non-`GET` route whose
//! action creates, changes or assigns a profile, or mints a credential. For each, a
//! delegated workspace admin (a custom profile naming some admin actions, limited to
//! one group) asking for one action beyond its own, one group beyond its scope, or
//! anything for itself is refused `403 CS-ORG-0005`, while the same grant within its
//! rights succeeds. The group scope also limits what it sees: members and groups
//! outside it answer `404`, as another tenant's do.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines
)]

mod common;

use std::collections::BTreeSet;

use axum::http::StatusCode;
use casual_sign_server::authz::Action;
use casual_sign_server::{Access, table};
use common::Rls;
use common::flow::ok;
use common::harness::{Api, Auth, PASSWORD, Tenant, session_of};
use serde_json::{Value, json};

/// A member of `a` with `profile`, signed in: their session and user id.
async fn member(api: &Api, a: &Tenant, email: &str, profile: &str) -> (Auth, String) {
    let u = ok(
        api.call(
            "POST",
            "/api/v1/users",
            &a.auth,
            Some(json!({"email": email, "name": email, "profile": profile, "password": PASSWORD})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "user",
    );
    let login = api
        .call(
            "POST",
            "/api/v1/auth/login",
            &Auth::None,
            Some(json!({"email": email, "password": PASSWORD})),
            &[],
        )
        .await;
    (session_of(&login), u["id"].as_str().unwrap().to_owned())
}

async fn make(api: &Api, auth: &Auth, path: &str, body: Value) -> String {
    ok(
        api.call("POST", path, auth, Some(body), &[]).await,
        StatusCode::CREATED,
        path,
    )["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// The grant routes, from the route table (`SEC-O02`: "for each grant route").
fn grant_routes() -> BTreeSet<(&'static str, &'static str)> {
    table()
        .into_iter()
        .filter(|r| r.method != "GET")
        .filter(|r| {
            matches!(
                r.access,
                Access::Action(
                    Action::ProfilesManage
                        | Action::UsersInvite
                        | Action::UsersUpdate
                        | Action::ApiClientsManage
                )
            )
        })
        // Re-sending an invitation and revoking a key grant nothing.
        .filter(|r| {
            !matches!(
                (r.method, r.path),
                ("POST", "/api/v1/users/{id}/invite") | ("DELETE", "/api/v1/api-clients/{id}")
            )
        })
        .map(|r| (r.method, r.path))
        .collect()
}

async fn delegated(rls: Rls) {
    let Some(api) = Api::new(&format!("delegated_admin_{rls:?}"), rls).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let g1 = make(&api, &a.auth, "/api/v1/groups", json!({"name": "Sales"})).await;
    let g2 = make(&api, &a.auth, "/api/v1/groups", json!({"name": "Legal"})).await;
    // The delegated workspace admin: user administration within Sales only.
    let mine = [
        "users.read",
        "users.invite",
        "users.update",
        "profiles.manage",
        "groups.manage",
        "envelopes.read",
    ];
    let delegate = make(
        &api,
        &a.auth,
        "/api/v1/permission-profiles",
        json!({"name": "Sales admin", "permissions": mine, "admin_scope_group_ids": [g1]}),
    )
    .await;
    // Profiles an administrator made that go beyond the delegate in one way each.
    let remover = make(
        &api,
        &a.auth,
        "/api/v1/permission-profiles",
        json!({"name": "Remover", "permissions": ["users.read", "users.remove"],
               "admin_scope_group_ids": [g1]}),
    )
    .await;
    let legal = make(
        &api,
        &a.auth,
        "/api/v1/permission-profiles",
        json!({"name": "Legal reader", "permissions": ["users.read"],
               "admin_scope_group_ids": [g2]}),
    )
    .await;
    let (dana, dana_id) = member(&api, &a, "dana@alpha.example.test", &delegate).await;
    let (_sam, sam_id) = member(&api, &a, "sam@alpha.example.test", "sender").await;
    let (_olga, olga_id) = member(&api, &a, "olga@alpha.example.test", "sender").await;
    let (kai, _) = {
        let keys = make(
            &api,
            &a.auth,
            "/api/v1/permission-profiles",
            json!({"name": "Key keeper", "permissions": ["api_clients.manage", "envelopes.read"]}),
        )
        .await;
        member(&api, &a, "kai@alpha.example.test", &keys).await
    };
    for (g, users) in [(&g1, vec![&dana_id, &sam_id]), (&g2, vec![&olga_id])] {
        ok(
            api.call(
                "PUT",
                &format!("/api/v1/groups/{g}/members"),
                &a.auth,
                Some(json!({"user_ids": users})),
                &[],
            )
            .await,
            StatusCode::OK,
            "members",
        );
    }

    // One within its rights succeeds: the controls of the refusals below.
    let narrow = ok(
        api.call(
            "POST",
            "/api/v1/permission-profiles",
            &dana,
            Some(
                json!({"name": "Sales reader", "permissions": ["users.read"],
                        "admin_scope_group_ids": [g1]}),
            ),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "a grant within its rights",
    );
    let narrow = narrow["id"].as_str().unwrap().to_owned();
    assert_eq!(narrow_actions(&api, &a, &narrow).await, ["users.read"]);
    ok(
        api.call(
            "PATCH",
            &format!("/api/v1/users/{sam_id}"),
            &dana,
            Some(json!({"profile": narrow})),
            &[],
        )
        .await,
        StatusCode::OK,
        "assigning within its rights",
    );

    // (route, case, request) → 403 CS-ORG-0005, each.
    let pp = "/api/v1/permission-profiles";
    let cases: Vec<(&str, &str, &str, String, Value, &Auth)> = vec![
        (
            "POST",
            pp,
            "one action beyond",
            pp.to_owned(),
            json!({"name": "x1", "permissions": ["users.read", "users.remove"], "admin_scope_group_ids": [g1]}),
            &dana,
        ),
        (
            "POST",
            pp,
            "one group beyond",
            pp.to_owned(),
            json!({"name": "x2", "permissions": ["users.read"], "admin_scope_group_ids": [g1, g2]}),
            &dana,
        ),
        (
            "POST",
            pp,
            "the whole workspace",
            pp.to_owned(),
            json!({"name": "x3", "permissions": ["users.read"]}),
            &dana,
        ),
        (
            "POST",
            pp,
            "the administrator's view of every envelope",
            pp.to_owned(),
            json!({"name": "x4", "permissions": ["envelopes.read_all"]}),
            &dana,
        ),
        (
            "PATCH",
            "/api/v1/permission-profiles/{id}",
            "one action beyond",
            format!("{pp}/{narrow}"),
            json!({"permissions": ["users.read", "users.remove"]}),
            &dana,
        ),
        (
            "PATCH",
            "/api/v1/permission-profiles/{id}",
            "one group beyond",
            format!("{pp}/{narrow}"),
            json!({"admin_scope_group_ids": [g2]}),
            &dana,
        ),
        (
            "PATCH",
            "/api/v1/permission-profiles/{id}",
            "for itself",
            format!("{pp}/{delegate}"),
            json!({"name": "Sales admin (mine)"}),
            &dana,
        ),
        (
            "DELETE",
            "/api/v1/permission-profiles/{id}",
            "for itself",
            format!("{pp}/{delegate}"),
            Value::Null,
            &dana,
        ),
        (
            "PATCH",
            "/api/v1/users/{id}",
            "one action beyond",
            format!("/api/v1/users/{sam_id}"),
            json!({"profile": remover}),
            &dana,
        ),
        (
            "PATCH",
            "/api/v1/users/{id}",
            "one group beyond",
            format!("/api/v1/users/{sam_id}"),
            json!({"profile": legal}),
            &dana,
        ),
        (
            "PATCH",
            "/api/v1/users/{id}",
            "the administrator profile",
            format!("/api/v1/users/{sam_id}"),
            json!({"profile": "admin"}),
            &dana,
        ),
        (
            "PATCH",
            "/api/v1/users/{id}",
            "for itself",
            format!("/api/v1/users/{dana_id}"),
            json!({"profile": narrow}),
            &dana,
        ),
        (
            "POST",
            "/api/v1/users",
            "a member outside its groups",
            "/api/v1/users".to_owned(),
            json!({"email": "new@alpha.example.test", "name": "New", "profile": "viewer", "password": PASSWORD}),
            &dana,
        ),
        (
            "POST",
            "/api/v1/api-clients",
            "one action beyond",
            "/api/v1/api-clients".to_owned(),
            json!({"name": "wide", "kind": "api_key", "scopes": ["envelopes:read", "envelopes:write"]}),
            &kai,
        ),
    ];
    let mut covered = BTreeSet::new();
    for (method, route, case, path, body, who) in &cases {
        let body = (!body.is_null()).then(|| body.clone());
        let r = api.call(method, path, who, body, &[]).await;
        assert_eq!(
            (r.status, r.code()),
            (StatusCode::FORBIDDEN, "CS-ORG-0005".to_owned()),
            "{method} {route}: {case}: {}",
            String::from_utf8_lossy(&r.body)
        );
        covered.insert((*method, *route));
    }
    let routes = grant_routes();
    let missing: Vec<_> = routes.difference(&covered).collect();
    assert!(
        missing.is_empty(),
        "grant routes without a case: {missing:?}"
    );
    // Nothing was changed by a refusal: Sam still holds the narrow profile.
    let sam = ok(
        api.call("GET", &format!("/api/v1/users/{sam_id}"), &dana, None, &[])
            .await,
        StatusCode::OK,
        "sam",
    );
    assert_eq!(sam["permission_profile_id"], narrow.as_str());

    // The scope limits what it sees: Sales' members only; Legal's and its group 404.
    let listed = ok(
        api.call("GET", "/api/v1/users", &dana, None, &[]).await,
        StatusCode::OK,
        "users",
    );
    let ids: BTreeSet<&str> = listed["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, BTreeSet::from([dana_id.as_str(), sam_id.as_str()]));
    for path in [
        format!("/api/v1/users/{olga_id}"),
        format!("/api/v1/groups/{g2}"),
    ] {
        let r = api.call("GET", &path, &dana, None, &[]).await;
        assert_eq!(
            (r.status, r.code()),
            (StatusCode::NOT_FOUND, "CS-API-0002".to_owned()),
            "{path}"
        );
    }
    // Pulling Olga into its group is refused at her id.
    let r = api
        .call(
            "PUT",
            &format!("/api/v1/groups/{g1}/members"),
            &dana,
            Some(json!({"user_ids": [dana_id, sam_id, olga_id]})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    // It sees only profiles whose actions it holds: not the administrator's or Remover.
    let profiles = ok(
        api.call("GET", "/api/v1/permission-profiles", &dana, None, &[])
            .await,
        StatusCode::OK,
        "profiles",
    );
    let names: BTreeSet<&str> = profiles["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains("Sales reader") && !names.contains("Remover"),
        "{names:?}"
    );
    assert!(
        !names
            .iter()
            .any(|n| n.contains("Admin") && *n != "Sales admin"),
        "{names:?}"
    );
    // A sensitive action never carries a group scope, whoever asks (database too).
    let r = api
        .call(
            "POST",
            pp,
            &a.auth,
            Some(
                json!({"name": "Scoped hooks", "permissions": ["webhooks.manage"],
                        "admin_scope_group_ids": [g1]}),
            ),
            &[],
        )
        .await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::FORBIDDEN, "CS-ORG-0005".to_owned())
    );
    api.db.drop().await;
}

async fn narrow_actions(api: &Api, a: &Tenant, id: &str) -> Vec<String> {
    let p = ok(
        api.call(
            "GET",
            &format!("/api/v1/permission-profiles/{id}"),
            &a.auth,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "profile",
    );
    serde_json::from_value(p["actions"].clone()).unwrap()
}

#[tokio::test]
async fn a_delegated_admin_cannot_grant_beyond_itself_with_rls() {
    delegated(Rls::On).await;
}

#[tokio::test]
async fn a_delegated_admin_cannot_grant_beyond_itself_without_rls() {
    delegated(Rls::Off).await;
}
