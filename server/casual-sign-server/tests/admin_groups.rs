//! Admin groups and custom permission profiles (UXW-07), as `webapp/admin.js` calls
//! them: `POST /groups`, `GET`/`PATCH`/`DELETE /groups/{id}`, `PUT /groups/{id}/members`,
//! `GET`/`POST /permission-profiles`, `GET`/`PATCH`/`DELETE /permission-profiles/{id}`.
//! Permissions are decided on the server on every request: a custom profile's members
//! hold exactly its permissions, and a change applies from their next request; nobody
//! gives a profile, or changes a member, beyond their own rights; built-in profiles are
//! fixed and a held profile is not deleted. Removing a member who is in a group works
//! (0033 cascades), and deleting a group takes its template shares with it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines
)]

mod common;

use axum::http::StatusCode;
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

async fn status(
    api: &Api,
    m: &str,
    p: &str,
    auth: &Auth,
    body: Option<Value>,
) -> (StatusCode, String) {
    let r = api.call(m, p, auth, body, &[]).await;
    (r.status, r.code())
}

fn forbidden() -> (StatusCode, String) {
    (StatusCode::FORBIDDEN, "CS-AUTH-0006".to_owned())
}

async fn groups_and_profiles(rls: Rls) {
    let Some(api) = Api::new(&format!("admin_groups_{rls:?}"), rls).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let b = api.tenant("beta").await;
    let (_mia, mia_id) = member(&api, &a, "mia@alpha.example.test", "sender").await;

    // The built-in profiles, listed first with what they grant; fixed.
    let list = ok(
        api.call("GET", "/api/v1/permission-profiles", &a.auth, None, &[])
            .await,
        StatusCode::OK,
        "profiles",
    );
    let kinds: Vec<&str> = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds.len(), 3, "{list}");
    assert!(
        list["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p["builtin"] == true)
    );
    let viewer = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["kind"] == "viewer")
        .unwrap();
    assert_eq!(
        viewer["permissions"],
        json!(["envelopes:read", "templates:read", "audit:read"])
    );
    let viewer_id = viewer["id"].as_str().unwrap().to_owned();
    assert_eq!(
        status(
            &api,
            "PATCH",
            &format!("/api/v1/permission-profiles/{viewer_id}"),
            &a.auth,
            Some(json!({"permissions": ["envelopes:send"]})),
        )
        .await,
        (StatusCode::CONFLICT, "CS-WF-0001".to_owned()),
        "a built-in profile is fixed"
    );

    // A custom profile: known permissions only, a name used once.
    let r = api
        .call(
            "POST",
            "/api/v1/permission-profiles",
            &a.auth,
            Some(json!({"name": "Author", "permissions": ["templates:read", "root"]})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(r.json()["errors"][0]["pointer"], "/permissions/1");
    let author = ok(
        api.call(
            "POST",
            "/api/v1/permission-profiles",
            &a.auth,
            Some(json!({"name": "Author", "permissions": ["admin:users", "templates:write", "templates:read"]})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "custom profile",
    );
    assert_eq!(author["builtin"], false);
    assert_eq!(
        author["permissions"],
        json!(["templates:read", "templates:write", "admin:users"])
    );
    let author_id = author["id"].as_str().unwrap().to_owned();
    let author_path = format!("/api/v1/permission-profiles/{author_id}");
    let r = api
        .call(
            "POST",
            "/api/v1/permission-profiles",
            &a.auth,
            Some(json!({"name": "Author", "permissions": []})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(r.json()["errors"][0]["code"], "exists");

    // Kim holds it: templates, not envelopes, on every request.
    let (kim, kim_id) = member(&api, &a, "kim@alpha.example.test", &author_id).await;
    let tpl = |n: &str| json!({"name": n, "roles": [{"name": "Client", "type": "signer"}]});
    let r = api
        .call("POST", "/api/v1/templates", &kim, Some(tpl("Kim NDA")), &[])
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "kim may write templates");
    assert_eq!(
        status(&api, "GET", "/api/v1/envelopes", &kim, None).await,
        forbidden(),
        "kim may not read envelopes"
    );

    // The administrator takes template writing away: Kim's next request is refused.
    let changed = ok(
        api.call(
            "PATCH",
            &author_path,
            &a.auth,
            Some(json!({"permissions": ["templates:read", "admin:users"]})),
            &[],
        )
        .await,
        StatusCode::OK,
        "profile changed",
    );
    assert_eq!(changed["members"], 1);
    assert_eq!(
        status(&api, "POST", "/api/v1/templates", &kim, Some(tpl("Kim 2"))).await,
        forbidden(),
        "the change applies from kim's next request"
    );

    // Kim manages users, but gives nothing beyond her own rights and changes nobody
    // above her.
    assert_eq!(
        status(
            &api,
            "POST",
            "/api/v1/permission-profiles",
            &kim,
            Some(json!({"name": "Sender+", "permissions": ["envelopes:send"]})),
        )
        .await,
        forbidden(),
        "a profile beyond kim's rights"
    );
    assert_eq!(
        status(
            &api,
            "PATCH",
            &author_path,
            &kim,
            Some(json!({"permissions": ["templates:read", "admin:users", "admin:account"]})),
        )
        .await,
        forbidden(),
        "kim raising her own profile"
    );
    for profile in ["admin", "sender"] {
        assert_eq!(
            status(
                &api,
                "POST",
                "/api/v1/users",
                &kim,
                Some(json!({"email": format!("{profile}@alpha.example.test"), "name": "X", "profile": profile, "password": PASSWORD})),
            )
            .await,
            forbidden(),
            "kim adding a member with the {profile} profile"
        );
    }
    for (m, body) in [
        ("PATCH", Some(json!({"profile": "viewer"}))),
        ("PATCH", Some(json!({"disabled": true}))),
        ("DELETE", None),
    ] {
        assert_eq!(
            status(&api, m, &format!("/api/v1/users/{mia_id}"), &kim, body).await,
            forbidden(),
            "kim changing mia, a sender, with {m}"
        );
    }
    // Nor re-send mia's invitation (PRF-01).
    assert_eq!(
        status(
            &api,
            "POST",
            &format!("/api/v1/users/{mia_id}/invite"),
            &kim,
            None
        )
        .await,
        forbidden(),
        "kim re-inviting mia, a sender"
    );
    let reader = ok(
        api.call(
            "POST",
            "/api/v1/permission-profiles",
            &kim,
            Some(json!({"name": "Reader", "permissions": ["templates:read"]})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "a profile within kim's rights",
    );
    let reader_path = format!(
        "/api/v1/permission-profiles/{}",
        reader["id"].as_str().unwrap()
    );

    // A held profile is not deleted; an unused one is.
    assert_eq!(
        status(&api, "DELETE", &author_path, &a.auth, None).await,
        (StatusCode::CONFLICT, "CS-WF-0001".to_owned())
    );
    assert_eq!(
        status(
            &api,
            "DELETE",
            &format!("/api/v1/permission-profiles/{viewer_id}"),
            &a.auth,
            None
        )
        .await,
        (StatusCode::CONFLICT, "CS-WF-0001".to_owned())
    );
    let r = api.call("DELETE", &reader_path, &a.auth, None, &[]).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(
        status(&api, "GET", &reader_path, &a.auth, None).await.0,
        StatusCode::NOT_FOUND
    );

    // Groups: made, named once, members set to members of the account only.
    let legal = ok(
        api.call(
            "POST",
            "/api/v1/groups",
            &a.auth,
            Some(json!({"name": "Legal"})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "group",
    );
    assert_eq!(legal["members"], 0);
    let gid = legal["id"].as_str().unwrap().to_owned();
    let gpath = format!("/api/v1/groups/{gid}");
    let r = api
        .call(
            "POST",
            "/api/v1/groups",
            &a.auth,
            Some(json!({"name": "Legal"})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(r.json()["errors"][0]["code"], "exists");
    let (_, beta_user) = member(&api, &b, "bo@beta.example.test", "sender").await;
    let r = api
        .call(
            "PUT",
            &format!("{gpath}/members"),
            &a.auth,
            Some(json!({"user_ids": [mia_id, beta_user]})),
            &[],
        )
        .await;
    assert_eq!(
        r.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "another account's user"
    );
    assert_eq!(r.json()["errors"][0]["pointer"], "/user_ids/1");
    let set = ok(
        api.call(
            "PUT",
            &format!("{gpath}/members"),
            &a.auth,
            Some(json!({"user_ids": [mia_id, kim_id, mia_id]})),
            &[],
        )
        .await,
        StatusCode::OK,
        "members",
    );
    assert_eq!(set["members"], 2);
    let renamed = ok(
        api.call(
            "PATCH",
            &gpath,
            &a.auth,
            Some(json!({"name": "Legal team"})),
            &[],
        )
        .await,
        StatusCode::OK,
        "rename",
    );
    assert_eq!(renamed["name"], "Legal team");
    let one = ok(
        api.call("GET", &gpath, &a.auth, None, &[]).await,
        StatusCode::OK,
        "group",
    );
    assert_eq!(one["user_ids"].as_array().unwrap().len(), 2);
    for (ids, n) in [(json!([kim_id]), 1), (json!([kim_id, mia_id]), 2)] {
        let set = ok(
            api.call(
                "PUT",
                &format!("{gpath}/members"),
                &a.auth,
                Some(json!({"user_ids": ids})),
                &[],
            )
            .await,
            StatusCode::OK,
            "members",
        );
        assert_eq!(set["members"], n);
    }

    // Another account's group and profile are not found, for every operation.
    for (m, p, body) in [
        ("GET", gpath.clone(), None),
        ("PATCH", gpath.clone(), Some(json!({"name": "x"}))),
        (
            "PUT",
            format!("{gpath}/members"),
            Some(json!({"user_ids": []})),
        ),
        ("DELETE", gpath.clone(), None),
        ("GET", author_path.clone(), None),
        ("PATCH", author_path.clone(), Some(json!({"name": "x"}))),
        ("DELETE", author_path.clone(), None),
    ] {
        assert_eq!(
            status(&api, m, &p, &b.auth, body).await,
            (StatusCode::NOT_FOUND, "CS-API-0002".to_owned()),
            "{m} {p} from beta"
        );
    }

    // A member in a group can be removed from the account; the group loses them.
    let r = api
        .call(
            "DELETE",
            &format!("/api/v1/users/{mia_id}"),
            &a.auth,
            None,
            &[],
        )
        .await;
    assert_eq!(
        r.status,
        StatusCode::NO_CONTENT,
        "remove a grouped member: {}",
        String::from_utf8_lossy(&r.body)
    );
    let one = ok(
        api.call("GET", &gpath, &a.auth, None, &[]).await,
        StatusCode::OK,
        "group",
    );
    assert_eq!(one["user_ids"], json!([kim_id]));

    // Deleting a group takes the template shares naming it with it.
    let t = ok(
        api.call(
            "POST",
            "/api/v1/templates",
            &a.auth,
            Some(tpl("Shared")),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "template",
    );
    let shares = format!("/api/v1/templates/{}/shares", t["id"].as_str().unwrap());
    ok(
        api.call(
            "PUT",
            &shares,
            &a.auth,
            Some(json!({"items": [{"group_id": gid}]})),
            &[],
        )
        .await,
        StatusCode::OK,
        "share with the group",
    );
    let r = api.call("DELETE", &gpath, &a.auth, None, &[]).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let left = ok(
        api.call("GET", &shares, &a.auth, None, &[]).await,
        StatusCode::OK,
        "shares",
    );
    assert_eq!(left["items"], json!([]), "{left}");
    assert_eq!(
        status(&api, "GET", &gpath, &a.auth, None).await.0,
        StatusCode::NOT_FOUND
    );

    // Every change is in the workspace's admin log.
    let log = ok(
        api.call("GET", "/api/v1/admin-events?limit=500", &a.auth, None, &[])
            .await,
        StatusCode::OK,
        "admin log",
    );
    let actions: Vec<&str> = log["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    for want in [
        "profile.created",
        "profile.changed",
        "profile.deleted",
        "group.created",
        "group.renamed",
        "group.member_added",
        "group.member_removed",
        "group.deleted",
    ] {
        assert!(actions.contains(&want), "{want} in {actions:?}");
    }
}

#[tokio::test]
async fn groups_and_custom_profiles_are_managed_and_enforced_per_request_with_rls() {
    groups_and_profiles(Rls::On).await;
}

#[tokio::test]
async fn groups_and_custom_profiles_are_managed_and_enforced_per_request_without_rls() {
    groups_and_profiles(Rls::Off).await;
}
