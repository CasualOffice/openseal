//! Editable templates (WEB-06): documents, roles and role-bound fields added, changed
//! and removed under `If-Match`; duplicate; delete; another account's template is
//! `404` for every editing operation.

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
use common::harness::Api;
use common::templates::edit_template;
use serde_json::json;

#[tokio::test]
async fn a_template_is_edited_duplicated_and_deleted() {
    let Some(api) = Api::new("templates_edit", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let b = api.tenant("beta").await;
    let copy = edit_template(&api, &a.auth).await;
    // Beta cannot read, change, copy or delete alpha's template.
    let base = format!("/api/v1/templates/{copy}");
    for (m, p, body) in [
        ("GET", base.clone(), None),
        ("POST", format!("{base}/duplicate"), None),
        (
            "POST",
            format!("{base}/roles"),
            Some(json!({"name": "X", "type": "signer"})),
        ),
        ("DELETE", base.clone(), None),
    ] {
        let r = api
            .call(m, &p, &b.auth, body, &[("if-match", "\"v1\"")])
            .await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{m} {p}: {:?}", r.json());
    }
    let still = api.call("GET", &base, &a.auth, None, &[]).await;
    assert_eq!(still.status, StatusCode::OK);
}
