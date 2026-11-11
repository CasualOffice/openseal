//! Recipient autocomplete (WEB-06): `GET /api/v1/contacts?q=` answers past recipients
//! of the account, one per email address (any case), the name last used with it, most
//! recent first; never another account's (row-level security on and off), and a member
//! without `view_all` sees only the people they sent to.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

mod common;

use axum::http::StatusCode;
use common::Rls;
use common::flow::{b64, ok};
use common::harness::{Api, Auth, PASSWORD, Tenant, pdf, session_of};
use serde_json::{Value, json};

async fn draft(api: &Api, auth: &Auth, people: &[(&str, &str)]) {
    let recipients: Vec<Value> = people
        .iter()
        .enumerate()
        .map(|(i, (n, e))| json!({"type": "signer", "name": n, "email": e, "routing_order": i + 1}))
        .collect();
    ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            auth,
            Some(json!({"subject": "c", "documents": [{"name": "c.pdf", "content_base64": b64(&pdf(1))}],
                "recipients": recipients})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "draft",
    );
}

async fn contacts(api: &Api, auth: &Auth, q: &str) -> Vec<(String, String)> {
    let r = ok(
        api.call("GET", &format!("/api/v1/contacts{q}"), auth, None, &[])
            .await,
        StatusCode::OK,
        "contacts",
    );
    r["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["name"].as_str().unwrap().to_owned(),
                c["email"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

fn pairs(l: &[(&str, &str)]) -> Vec<(String, String)> {
    l.iter()
        .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
        .collect()
}

async fn scenario(rls: Rls) {
    let Some(api) = Api::new("contacts", rls).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let b = api.tenant("beta").await;
    draft(
        &api,
        &a.auth,
        &[("Ann Old", "ann@example.test"), ("Bob", "bob@example.test")],
    )
    .await;
    api.clock.advance(std::time::Duration::from_secs(60));
    // Later, Ann again under another name and case: one entry, the newer name.
    draft(
        &api,
        &a.auth,
        &[
            ("Ann Newer", "ANN@example.test"),
            ("100%_x", "pct@example.test"),
        ],
    )
    .await;
    draft(&api, &b.auth, &[("Beta Person", "ann.beta@example.test")]).await;

    let all = contacts(&api, &a.auth, "").await;
    assert_eq!(all.len(), 3, "{all:?}");
    assert_eq!(all[0].0, "Ann Newer", "{all:?}");
    assert!(all.iter().all(|(_, e)| e != "ann.beta@example.test"));
    assert_eq!(
        contacts(&api, &a.auth, "?q=ann").await,
        pairs(&[("Ann Newer", "ANN@example.test")])
    );
    // Wildcards are literal.
    assert_eq!(
        contacts(&api, &a.auth, "?q=%25_").await,
        pairs(&[("100%_x", "pct@example.test")])
    );
    assert_eq!(contacts(&api, &a.auth, "?q=_").await.len(), 1);
    assert_eq!(contacts(&api, &a.auth, "?limit=1").await.len(), 1);
    // Beta sees only its own, whatever it searches for.
    assert_eq!(
        contacts(&api, &b.auth, "?q=example").await,
        pairs(&[("Beta Person", "ann.beta@example.test")])
    );
    let bad = api
        .call("GET", "/api/v1/contacts?limit=51", &a.auth, None, &[])
        .await;
    assert_eq!(bad.status, StatusCode::UNPROCESSABLE_ENTITY);

    // A sender without view_all sees only the people they sent to.
    sender_sees_own(&api, &a).await;
}

async fn sender_sees_own(api: &Api, a: &Tenant) {
    ok(
        api.call(
            "POST",
            "/api/v1/users",
            &a.auth,
            Some(json!({"email": "sam@alpha.example.test", "name": "Sam", "profile": "sender", "password": PASSWORD})),
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
            Some(json!({"email": "sam@alpha.example.test", "password": PASSWORD})),
            &[],
        )
        .await;
    let sam = session_of(&login);
    assert!(contacts(api, &sam, "").await.is_empty());
    draft(api, &sam, &[("Sam's Client", "client@example.test")]).await;
    assert_eq!(
        contacts(api, &sam, "").await,
        pairs(&[("Sam's Client", "client@example.test")])
    );
}

#[tokio::test]
async fn contacts_are_deduplicated_recent_first_and_account_scoped() {
    scenario(Rls::On).await;
}

#[tokio::test]
async fn contacts_stay_in_the_account_with_row_level_security_disabled() {
    scenario(Rls::Off).await;
}
