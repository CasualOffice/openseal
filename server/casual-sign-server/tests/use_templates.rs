//! Slice 3 (templates, `VS-03`), as `webapp/api.js` calls it:
//!
//! - `POST /envelopes/from-templates`: one envelope from one template, or from several
//!   (composite templates, `FG-097`), made on the server from the stored documents;
//!   roles matched by name across templates.
//! - Template folders (`TSH-03`): `POST /folders {kind: templates}`, `GET
//!   /folders?kind=templates`, `POST /folders/{id|none}/templates`, `GET
//!   /templates?folder=`; each member's own, deny by default.

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
use common::slice3::template;
use serde_json::{Value, json};

/// A sender of `a`, signed in.
async fn member(api: &Api, a: &Tenant, email: &str) -> Auth {
    ok(
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
    session_of(&login)
}

async fn refused(api: &Api, auth: &Auth, body: Value) -> (StatusCode, String) {
    let r = api
        .call(
            "POST",
            "/api/v1/envelopes/from-templates",
            auth,
            Some(body),
            &[],
        )
        .await;
    let pointer = r.json()["errors"][0]["pointer"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    (r.status, pointer)
}

async fn composite(rls: Rls) {
    let Some(api) = Api::new(&format!("use_templates_composite_{rls:?}"), rls).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let b = api.tenant("beta").await;
    let k = &a.auth;
    let nda = template(&api, k, "NDA", 1, &[("Buyer", "signer", 1)]).await;
    let order = template(
        &api,
        k,
        "Order",
        2,
        &[
            ("buyer", "signer", 3),
            ("Seller", "signer", 2),
            ("Agent", "cc", 4),
        ],
    )
    .await;

    // One envelope from both: NDA's document, then Order's; Buyer (named in both, any
    // case) is one recipient with NDA's routing order and both templates' fields.
    let env = ok(
        api.call(
            "POST",
            "/api/v1/envelopes/from-templates",
            k,
            Some(json!({
                "template_ids": [nda["id"], order["id"]],
                "recipients": [
                    {"role": "BUYER", "name": "Bea Buyer", "email": "bea@example.test"},
                    {"role": "Seller", "name": "Sol Seller", "email": "sol@example.test"},
                    {"role": "Agent", "name": "Ali Agent", "email": "ali@example.test"},
                    {"name": "Cam Copy", "email": "cam@example.test"}
                ],
                "status": "sent"
            })),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "envelope from two templates",
    );
    assert_eq!(env["status"], "sent");
    assert_eq!(
        env["subject"], "Please sign: NDA",
        "the first template's subject"
    );
    let docs: Vec<(&str, i64)> = env["documents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            (
                d["name"].as_str().unwrap(),
                d["pages"].as_i64().unwrap_or(-1),
            )
        })
        .collect();
    assert_eq!(
        docs.iter().map(|d| d.0).collect::<Vec<_>>(),
        ["NDA.pdf", "Order.pdf"]
    );
    let people: Vec<(String, String, i64)> = env["recipients"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["email"].as_str().unwrap().to_owned(),
                r["type"].as_str().unwrap().to_owned(),
                r["routing_order"].as_i64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        people,
        [
            ("bea@example.test".into(), "signer".into(), 1),
            ("sol@example.test".into(), "signer".into(), 2),
            ("ali@example.test".into(), "cc".into(), 4),
            ("cam@example.test".into(), "cc".into(), 5),
        ]
    );
    let rid = |email: &str| {
        env["recipients"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["email"] == email)
            .unwrap()["id"]
            .clone()
    };
    let did = |i: usize| env["documents"][i]["id"].clone();
    let fields: Vec<(Value, Value, Value)> = env["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["label"].clone(),
                f["recipient_id"].clone(),
                f["document_id"].clone(),
            )
        })
        .collect();
    assert_eq!(fields.len(), 3, "{fields:?}");
    assert!(fields.contains(&(json!("NDA Buyer"), rid("bea@example.test"), did(0))));
    assert!(fields.contains(&(json!("Order buyer"), rid("bea@example.test"), did(1))));
    assert!(fields.contains(&(json!("Order Seller"), rid("sol@example.test"), did(1))));

    // One template alone, kept as a draft to edit: what the web app's Use does.
    let draft = ok(
        api.call(
            "POST",
            "/api/v1/envelopes/from-templates",
            k,
            Some(json!({
                "template_ids": [nda["id"]],
                "recipients": [{"role": "Buyer", "name": "Bea", "email": "bea@example.test"}],
                "subject": "Our NDA", "message": "Thanks"
            })),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "draft from one template",
    );
    assert_eq!(
        (&draft["status"], &draft["subject"], &draft["message"]),
        (&json!("draft"), &json!("Our NDA"), &json!("Thanks"))
    );

    // Refusals: each at the member that is wrong, and nothing made.
    let before = api
        .call("GET", "/api/v1/envelopes", k, None, &[])
        .await
        .json()["items"]
        .as_array()
        .unwrap()
        .len();
    let both = json!([nda["id"], order["id"]]);
    let bea = json!({"role": "Buyer", "name": "Bea", "email": "bea@example.test"});
    let sol = json!({"role": "Seller", "name": "Sol", "email": "sol@example.test"});
    let ali = json!({"role": "Agent", "name": "Ali", "email": "ali@example.test"});
    for (body, want) in [
        // A role nobody fills.
        (
            json!({"template_ids": both, "recipients": [bea, sol]}),
            "/recipients",
        ),
        // A role no template has.
        (
            json!({"template_ids": both, "recipients": [bea, sol, ali,
                   {"role": "Notary", "name": "N", "email": "n@example.test"}]}),
            "/recipients/3/role",
        ),
        // A role filled twice.
        (
            json!({"template_ids": both, "recipients": [bea, sol, ali, bea]}),
            "/recipients/3/role",
        ),
        // The same template twice; none; another account's; not an id.
        (
            json!({"template_ids": [nda["id"], nda["id"]], "recipients": [bea]}),
            "/template_ids/1",
        ),
        (
            json!({"template_ids": [], "recipients": []}),
            "/template_ids",
        ),
        (
            json!({"template_ids": ["x"], "recipients": []}),
            "/template_ids/0",
        ),
        (
            json!({"template_ids": both, "recipients": [bea, sol, ali], "status": "done"}),
            "/status",
        ),
    ] {
        assert_eq!(
            refused(&api, k, body.clone()).await,
            (StatusCode::UNPROCESSABLE_ENTITY, want.to_owned()),
            "{body}"
        );
    }
    // A role whose type differs in a later template.
    let cc_buyer = template(&api, k, "Copy", 1, &[("Buyer", "cc", 1)]).await;
    assert_eq!(
        refused(
            &api,
            k,
            json!({"template_ids": [nda["id"], cc_buyer["id"]], "recipients": [bea]})
        )
        .await,
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            "/template_ids/1".to_owned()
        )
    );
    // Another account's template is as none: refused at its position.
    assert_eq!(
        refused(
            &api,
            &b.auth,
            json!({"template_ids": [nda["id"]], "recipients": [bea]})
        )
        .await,
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            "/template_ids/0".to_owned()
        )
    );
    let after = api
        .call("GET", "/api/v1/envelopes", k, None, &[])
        .await
        .json()["items"]
        .as_array()
        .unwrap()
        .len();
    assert_eq!(after, before, "a refused request made an envelope");
    api.db.drop().await;
}

#[tokio::test]
async fn an_envelope_is_made_from_several_templates_with_roles_matched_by_name_with_rls() {
    composite(Rls::On).await;
}

#[tokio::test]
async fn an_envelope_is_made_from_several_templates_with_roles_matched_by_name_without_rls() {
    composite(Rls::Off).await;
}

/// A template shared for use can be used; one not shared cannot (deny by default).
#[tokio::test]
async fn a_member_uses_only_the_templates_they_may() {
    let Some(api) = Api::new("use_templates_access", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let sam = member(&api, &a, "sam@alpha.example.test").await;
    let lee = member(&api, &a, "lee@alpha.example.test").await;
    let t = template(&api, &sam, "Sam NDA", 1, &[("Client", "signer", 1)]).await;
    let body = json!({"template_ids": [t["id"]],
        "recipients": [{"role": "Client", "name": "C", "email": "c@example.test"}]});
    assert_eq!(
        refused(&api, &lee, body.clone()).await,
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            "/template_ids/0".to_owned()
        )
    );
    ok(
        api.call(
            "PUT",
            &format!("/api/v1/templates/{}/shares", t["id"].as_str().unwrap()),
            &sam,
            Some(json!({"items": [{"email": "lee@alpha.example.test"}]})),
            &[],
        )
        .await,
        StatusCode::OK,
        "share",
    );
    ok(
        api.call(
            "POST",
            "/api/v1/envelopes/from-templates",
            &lee,
            Some(body),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "use a shared template",
    );
    api.db.drop().await;
}

async fn folders(rls: Rls) {
    let Some(api) = Api::new(&format!("template_folders_{rls:?}"), rls).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let b = api.tenant("beta").await;
    let sam = member(&api, &a, "sam@alpha.example.test").await;
    let lee = member(&api, &a, "lee@alpha.example.test").await;
    let nda = template(&api, &sam, "NDA", 1, &[("Client", "signer", 1)]).await;
    let order = template(&api, &sam, "Order", 1, &[("Client", "signer", 1)]).await;
    let nda_id = nda["id"].as_str().unwrap();
    let names = |v: Value| -> Vec<String> {
        v["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_owned())
            .collect()
    };

    // A template folder: listed with templates' folders, not with envelopes'.
    let f = ok(
        api.call(
            "POST",
            "/api/v1/folders",
            &sam,
            Some(json!({"name": "Sales", "kind": "templates"})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "template folder",
    );
    assert_eq!((&f["kind"], &f["count"]), (&json!("templates"), &json!(0)));
    let fid = f["id"].as_str().unwrap().to_owned();
    let envelope_folders = ok(
        api.call("GET", "/api/v1/folders", &sam, None, &[]).await,
        StatusCode::OK,
        "envelope folders",
    );
    assert!(envelope_folders["items"].as_array().unwrap().is_empty());
    // The same name may be an envelope folder too; twice of one kind is refused.
    ok(
        api.call(
            "POST",
            "/api/v1/folders",
            &sam,
            Some(json!({"name": "Sales"})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "envelope folder of the same name",
    );
    let again = api
        .call(
            "POST",
            "/api/v1/folders",
            &sam,
            Some(json!({"name": "sales", "kind": "templates"})),
            &[],
        )
        .await;
    assert_eq!(again.status, StatusCode::UNPROCESSABLE_ENTITY);
    let bad_kind = api
        .call(
            "POST",
            "/api/v1/folders",
            &sam,
            Some(json!({"name": "X", "kind": "boxes"})),
            &[],
        )
        .await;
    assert_eq!(bad_kind.status, StatusCode::UNPROCESSABLE_ENTITY);

    // Filed: the list carries the folder, and `?folder=` narrows to it or to none.
    let moved = ok(
        api.call(
            "POST",
            &format!("/api/v1/folders/{fid}/templates"),
            &sam,
            Some(json!({"template_ids": [nda_id]})),
            &[],
        )
        .await,
        StatusCode::OK,
        "file",
    );
    assert_eq!(moved["moved"], 1);
    let all = ok(
        api.call("GET", "/api/v1/templates", &sam, None, &[]).await,
        StatusCode::OK,
        "list",
    );
    let filed: Vec<(&str, &Value)> = all["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| (t["name"].as_str().unwrap(), &t["folder_id"]))
        .collect();
    assert_eq!(filed, [("NDA", &json!(fid)), ("Order", &Value::Null)]);
    let in_folder = api
        .call(
            "GET",
            &format!("/api/v1/templates?folder={fid}"),
            &sam,
            None,
            &[],
        )
        .await
        .json();
    assert_eq!(names(in_folder), ["NDA"]);
    let in_none = api
        .call("GET", "/api/v1/templates?folder=none", &sam, None, &[])
        .await
        .json();
    assert_eq!(names(in_none), ["Order"]);
    let listed = api
        .call("GET", "/api/v1/folders?kind=templates", &sam, None, &[])
        .await
        .json();
    assert_eq!(
        (&listed["items"][0]["name"], &listed["items"][0]["count"]),
        (&json!("Sales"), &json!(1))
    );
    let bad = api
        .call("GET", "/api/v1/folders?kind=boxes", &sam, None, &[])
        .await;
    assert_eq!(bad.status, StatusCode::UNPROCESSABLE_ENTITY);

    // A folder is its owner's: another member, or another account, finds none, and
    // a member's filing is theirs alone.
    for who in [&lee, &b.auth] {
        let r = api
            .call(
                "POST",
                &format!("/api/v1/folders/{fid}/templates"),
                who,
                Some(json!({"template_ids": [nda_id]})),
                &[],
            )
            .await;
        assert_eq!(r.status, StatusCode::NOT_FOUND);
        let r = api
            .call(
                "PATCH",
                &format!("/api/v1/folders/{fid}"),
                who,
                Some(json!({"name": "Y"})),
                &[],
            )
            .await;
        assert_eq!(r.status, StatusCode::NOT_FOUND);
    }
    // A template Lee may not use cannot be filed by Lee, even in Lee's own folder.
    let lf = ok(
        api.call(
            "POST",
            "/api/v1/folders",
            &lee,
            Some(json!({"name": "Mine", "kind": "templates"})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "lee's folder",
    );
    let lfid = lf["id"].as_str().unwrap();
    let r = api
        .call(
            "POST",
            &format!("/api/v1/folders/{lfid}/templates"),
            &lee,
            Some(json!({"template_ids": [nda_id]})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // An envelope folder takes no template, and a template folder no envelope.
    let ef = api
        .call("GET", "/api/v1/folders", &sam, None, &[])
        .await
        .json();
    let efid = ef["items"][0]["id"].as_str().unwrap();
    let r = api
        .call(
            "POST",
            &format!("/api/v1/folders/{efid}/templates"),
            &sam,
            Some(json!({"template_ids": [nda_id]})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    // Renamed, then removed: the template stays, in no folder.
    ok(
        api.call(
            "PATCH",
            &format!("/api/v1/folders/{fid}"),
            &sam,
            Some(json!({"name": "Sales 2026"})),
            &[],
        )
        .await,
        StatusCode::OK,
        "rename",
    );
    let gone = api
        .call("DELETE", &format!("/api/v1/folders/{fid}"), &sam, None, &[])
        .await;
    assert_eq!(gone.status, StatusCode::NO_CONTENT);
    let all = api
        .call("GET", "/api/v1/templates", &sam, None, &[])
        .await
        .json();
    assert_eq!(names(all.clone()), ["NDA", "Order"]);
    assert!(
        all["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|t| t["folder_id"].is_null())
    );
    let _ = order;
    api.db.drop().await;
}

#[tokio::test]
async fn template_folders_are_each_members_own_with_rls() {
    folders(Rls::On).await;
}

#[tokio::test]
async fn template_folders_are_each_members_own_without_rls() {
    folders(Rls::Off).await;
}
