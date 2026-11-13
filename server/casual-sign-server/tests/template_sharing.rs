//! Template sharing, Shared with me and Favourites (UXW-06), as `webapp/api.js` calls
//! them: `PUT`/`GET /templates/{id}/shares`, `GET /templates?view=owned|shared|
//! favourites`, `PUT`/`DELETE /templates/{id}/favourite`, `GET /groups`. Access is
//! decided on the server per request and per template, deny by default: a template is
//! its owner's (and the administrators') until shared; a share lets a member, a group's
//! members or the whole account use it, and edit it with `can_edit`; deleting and
//! sharing stay with the owner.

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

/// A sender of `a`, signed in: their session and user id.
async fn member(api: &Api, a: &Tenant, email: &str) -> (Auth, String) {
    let u = ok(
        api.call(
            "POST",
            "/api/v1/users",
            &a.auth,
            Some(json!({"email": email, "name": email, "profile": "sender", "password": PASSWORD})),
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

/// The names in `GET /templates{query}` as `auth` sees it.
async fn names(api: &Api, auth: &Auth, query: &str) -> Vec<String> {
    let page = ok(
        api.call("GET", &format!("/api/v1/templates{query}"), auth, None, &[])
            .await,
        StatusCode::OK,
        query,
    );
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_owned())
        .collect()
}

async fn status(
    api: &Api,
    m: &str,
    p: &str,
    auth: &Auth,
    body: Option<Value>,
) -> (StatusCode, String) {
    let r = api.call(m, p, auth, body, &[("if-match", "\"v1\"")]).await;
    (r.status, r.code())
}

async fn sharing(rls: Rls) {
    let Some(api) = Api::new(&format!("template_sharing_{rls:?}"), rls).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let b = api.tenant("beta").await;
    let (sam, _) = member(&api, &a, "sam@alpha.example.test").await;
    let (lee, _) = member(&api, &a, "lee@alpha.example.test").await;
    let (pat, pat_id) = member(&api, &a, "pat@alpha.example.test").await;

    let made = ok(
        api.call(
            "POST",
            "/api/v1/templates",
            &sam,
            Some(json!({"name": "Sam NDA", "roles": [{"name": "Client", "type": "signer"}]})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "template",
    );
    let tid = made["id"].as_str().unwrap().to_owned();
    let base = format!("/api/v1/templates/{tid}");
    let shares = format!("{base}/shares");
    let star = format!("{base}/favourite");

    // Unshared: the owner's and the administrators' alone; every other member is
    // answered 404 for every read and change, as for another account.
    assert_eq!(names(&api, &sam, "").await, ["Sam NDA"]);
    assert_eq!(names(&api, &a.auth, "").await, ["Sam NDA"]);
    assert!(names(&api, &lee, "").await.is_empty());
    for (m, p) in [
        ("GET", base.clone()),
        ("PATCH", base.clone()),
        ("DELETE", base.clone()),
        ("POST", format!("{base}/duplicate")),
        ("GET", format!("{base}/fields")),
        ("GET", shares.clone()),
        ("PUT", shares.clone()),
        ("PUT", star.clone()),
    ] {
        let body = match m {
            "PUT" => Some(json!({"items": []})),
            "PATCH" => Some(json!({"name": "x"})),
            _ => None,
        };
        assert_eq!(
            status(&api, m, &p, &lee, body).await,
            (StatusCode::NOT_FOUND, "CS-API-0002".to_owned()),
            "{m} {p} as an unshared member"
        );
    }

    // Shared with Lee by email, to use: Lee lists it under Shared with me, reads it and
    // copies it, but may not change, delete or share it (403).
    let put = ok(
        api.call(
            "PUT",
            &shares,
            &sam,
            Some(json!({"items": [{"email": "LEE@alpha.example.test"}]})),
            &[],
        )
        .await,
        StatusCode::OK,
        "share with Lee",
    );
    assert_eq!(
        put["items"][0]["user"]["email"], "lee@alpha.example.test",
        "{put}"
    );
    assert_eq!(put["items"][0]["can_edit"], false);
    assert_eq!(names(&api, &lee, "").await, ["Sam NDA"]);
    assert_eq!(names(&api, &lee, "?view=shared").await, ["Sam NDA"]);
    assert!(names(&api, &lee, "?view=owned").await.is_empty());
    assert!(names(&api, &sam, "?view=shared").await.is_empty());
    assert_eq!(names(&api, &sam, "?view=owned").await, ["Sam NDA"]);
    let got = ok(
        api.call("GET", &base, &lee, None, &[]).await,
        StatusCode::OK,
        "read",
    );
    assert_eq!(
        (got["access"].as_str(), got["favourite"].as_bool()),
        (Some("use"), Some(false))
    );
    for (m, p, body) in [
        ("PATCH", base.clone(), Some(json!({"name": "x"}))),
        (
            "POST",
            format!("{base}/roles"),
            Some(json!({"name": "X", "type": "signer"})),
        ),
        ("DELETE", base.clone(), None),
        ("GET", shares.clone(), None),
        ("PUT", shares.clone(), Some(json!({"items": []}))),
    ] {
        assert_eq!(
            status(&api, m, &p, &lee, body).await,
            (StatusCode::FORBIDDEN, "CS-AUTH-0006".to_owned()),
            "{m} {p} with a use share"
        );
    }
    let copy = ok(
        api.call("POST", &format!("{base}/duplicate"), &lee, None, &[])
            .await,
        StatusCode::CREATED,
        "copy",
    );
    assert_eq!(copy["access"], "owner");
    assert_eq!(names(&api, &lee, "?view=owned").await, ["Copy of Sam NDA"]);

    // Favourites are each member's own.
    let r = api.call("PUT", &star, &lee, None, &[]).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let r = api.call("PUT", &star, &lee, None, &[]).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "idempotent");
    assert_eq!(names(&api, &lee, "?view=favourites").await, ["Sam NDA"]);
    assert!(names(&api, &sam, "?view=favourites").await.is_empty());
    let r = api.call("DELETE", &star, &lee, None, &[]).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert!(names(&api, &lee, "?view=favourites").await.is_empty());

    // A group, to edit: Pat (a member) may change it; Lee, no longer shared, is 404.
    let group = uuid::Uuid::now_v7();
    sqlx::query("INSERT INTO groups (id, account_id, name) VALUES ($1, $2, 'Legal')")
        .bind(group)
        .bind(a.boot.account.0)
        .execute(&api.db.admin)
        .await
        .unwrap();
    sqlx::query("INSERT INTO group_members (account_id, group_id, user_id) VALUES ($1, $2, $3)")
        .bind(a.boot.account.0)
        .bind(group)
        .bind(uuid::Uuid::parse_str(&pat_id).unwrap())
        .execute(&api.db.admin)
        .await
        .unwrap();
    let groups = ok(
        api.call("GET", "/api/v1/groups", &sam, None, &[]).await,
        StatusCode::OK,
        "groups",
    );
    assert_eq!(
        groups["items"],
        json!([{"id": group.to_string(), "name": "Legal", "members": 1}])
    );
    let put = ok(
        api.call(
            "PUT",
            &shares,
            &sam,
            Some(json!({"items": [{"group_id": group.to_string(), "can_edit": true}]})),
            &[],
        )
        .await,
        StatusCode::OK,
        "share with Legal",
    );
    assert_eq!(put["items"][0]["group"]["name"], "Legal", "{put}");
    let read = api.call("GET", &base, &pat, None, &[]).await;
    assert_eq!(read.json()["access"], "edit");
    let renamed = api
        .call(
            "PATCH",
            &base,
            &pat,
            Some(json!({"name": "Legal NDA"})),
            &[("if-match", &read.etag())],
        )
        .await;
    assert_eq!(renamed.status, StatusCode::OK, "{:?}", renamed.json());
    assert_eq!(names(&api, &pat, "?view=shared").await, ["Legal NDA"]);
    assert_eq!(
        status(&api, "GET", &base, &lee, None).await.0,
        StatusCode::NOT_FOUND,
        "the shares were replaced"
    );
    // An editor still may not delete it.
    assert_eq!(
        status(&api, "DELETE", &base, &pat, None).await.0,
        StatusCode::FORBIDDEN
    );

    // The whole account: every member may use it.
    ok(
        api.call(
            "PUT",
            &shares,
            &sam,
            Some(json!({"items": [{"account": true}]})),
            &[],
        )
        .await,
        StatusCode::OK,
        "share with everyone",
    );
    assert_eq!(names(&api, &lee, "?view=shared").await, ["Legal NDA"]);

    // Refused shares: the owner; the same target twice; not a member (another account's
    // admin too); an unknown group; two targets in one; none. Nothing changes.
    for items in [
        json!([{"email": "sam@alpha.example.test"}]),
        json!([{"account": true}, {"account": true}]),
        json!([{"email": "nobody@alpha.example.test"}]),
        json!([{"email": b.email}]),
        json!([{"group_id": uuid::Uuid::now_v7().to_string()}]),
        json!([{"account": true, "email": "lee@alpha.example.test"}]),
        json!([{"can_edit": true}]),
    ] {
        let r = api
            .call("PUT", &shares, &sam, Some(json!({ "items": items })), &[])
            .await;
        assert_eq!(
            r.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{items}: {:?}",
            r.json()
        );
    }
    let now = ok(
        api.call("GET", &shares, &sam, None, &[]).await,
        StatusCode::OK,
        "shares",
    );
    assert_eq!(now["items"].as_array().unwrap().len(), 1, "{now}");
    assert_eq!(now["items"][0]["account"], true);

    // Another account reaches none of it.
    for (m, p) in [
        ("GET", shares.clone()),
        ("PUT", shares.clone()),
        ("PUT", star.clone()),
        ("DELETE", star.clone()),
    ] {
        let body = (m == "PUT").then(|| json!({"items": []}));
        assert_eq!(
            status(&api, m, &p, &b.auth, body).await.0,
            StatusCode::NOT_FOUND,
            "{m} {p} as another account"
        );
    }
    let theirs = ok(
        api.call("GET", "/api/v1/groups", &b.auth, None, &[]).await,
        StatusCode::OK,
        "beta groups",
    );
    assert_eq!(theirs["items"], json!([]));

    // The Deleted view is the owner's: Sam deletes it; Lee's Deleted view does not show
    // it and Lee cannot restore it; the administrator's does.
    let etag = api.call("GET", &base, &sam, None, &[]).await.etag();
    let r = api
        .call("DELETE", &base, &sam, None, &[("if-match", &etag)])
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert!(names(&api, &lee, "?deleted=true").await.is_empty());
    assert_eq!(names(&api, &sam, "?deleted=true").await, ["Legal NDA"]);
    assert_eq!(names(&api, &a.auth, "?deleted=true").await, ["Legal NDA"]);
    assert_eq!(
        status(&api, "POST", &format!("{base}/restore"), &lee, None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let bad = api
        .call("GET", "/api/v1/templates?view=everyone", &sam, None, &[])
        .await;
    assert_eq!(bad.status, StatusCode::UNPROCESSABLE_ENTITY);
    api.db.drop().await;
}

#[tokio::test]
async fn templates_are_shared_with_members_groups_and_the_account_and_starred_with_rls() {
    sharing(Rls::On).await;
}

#[tokio::test]
async fn templates_are_shared_with_members_groups_and_the_account_and_starred_without_rls() {
    sharing(Rls::Off).await;
}
