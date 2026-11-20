//! Slice 6 (`VS-06`) quick views and search on the server: `GET /envelopes?auth_failed=true`
//! (DocuSign's Authentication Failed), `?expires_before=` (Expiring soon), and envelope
//! custom fields (`GET`/`PUT /envelopes/{id}/custom-fields`) searched with
//! `?custom_field=&custom_value=` (FG-132, FG-139). Access is per account: another
//! account's envelope is `404` and never listed.

#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::indexing_slicing
)]

mod common;

use axum::http::StatusCode;
use common::Rls;
use common::flow::{b64, invite, ok, open};
use common::harness::{Api, Auth, Tenant, pdf};
use serde_json::{Value, json};

/// A sent envelope with one signer, `subject`, an access code when `code`, expiring in
/// `days` when given. Answers the envelope.
async fn sent(api: &Api, t: &Tenant, subject: &str, code: bool, days: Option<u32>) -> Value {
    let mut signer = json!({"ref": "s1", "type": "signer", "name": "Sig One",
        "email": "one@example.test", "routing_order": 1});
    if code {
        signer["auth"] = json!(["access_code"]);
        signer["access_code"] = json!("right-4711");
    }
    let mut body = json!({
        "subject": subject, "status": "sent",
        "documents": [{"name": "d.pdf", "content_base64": b64(&pdf(1))}],
        "recipients": [signer],
        "fields": [{"recipient": "s1", "document": 0, "type": "signature", "page": 1,
            "x": 72, "y": 100, "width": 180, "height": 40, "required": true}],
    });
    if let Some(d) = days {
        body["expires_in_days"] = json!(d);
    }
    ok(
        api.call("POST", "/api/v1/envelopes", &t.auth, Some(body), &[])
            .await,
        StatusCode::CREATED,
        "create",
    )
}

async fn subjects(api: &Api, auth: &Auth, query: &str) -> Vec<String> {
    let page = ok(
        api.call(
            "GET",
            &format!("/api/v1/envelopes?{query}"),
            auth,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        query,
    );
    let mut s: Vec<String> = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["subject"].as_str().unwrap().to_owned())
        .collect();
    s.sort();
    s
}

/// A wrong access code at `token`'s link.
async fn fail_auth(api: &Api, token: &str) {
    let (_, h) = open(api, token).await;
    let h: Vec<(&str, &str)> = h.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let r = api
        .call(
            "POST",
            &format!("/s/{token}/authenticate"),
            &Auth::None,
            Some(json!({"method": "access_code", "code": "wrong"})),
            &h,
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "wrong code");
}

#[tokio::test]
async fn the_authentication_failed_view_lists_envelopes_whose_recipient_failed_until_resent() {
    let Some(api) = Api::new("manage_views_auth_failed", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let failed = sent(&api, &a, "Failed", true, None).await;
    let _calm = sent(&api, &a, "Calm", true, None).await;
    let _plain = sent(&api, &a, "Plain", false, None).await;
    let env = failed["id"].as_str().unwrap();
    let rec = failed["recipients"][0]["id"].as_str().unwrap();
    assert!(subjects(&api, &a.auth, "auth_failed=true").await.is_empty());

    let token = invite(&api, &a, env, rec).await;
    fail_auth(&api, &token).await;
    assert_eq!(
        subjects(&api, &a.auth, "auth_failed=true").await,
        ["Failed"],
        "only the envelope whose signer failed"
    );
    // Every envelope is still in the plain list.
    assert_eq!(
        subjects(&api, &a.auth, "").await,
        ["Calm", "Failed", "Plain"]
    );
    // Resending clears the failures (docs/24 §3): the envelope leaves the view.
    ok(
        api.call(
            "POST",
            &format!("/api/v1/envelopes/{env}/resend"),
            &a.auth,
            Some(json!({})),
            &[],
        )
        .await,
        StatusCode::OK,
        "resend",
    );
    assert!(subjects(&api, &a.auth, "auth_failed=true").await.is_empty());
    // Another account sees nothing of it.
    let b = api.tenant("beta").await;
    assert!(subjects(&api, &b.auth, "auth_failed=true").await.is_empty());
    // A value other than true or false is refused.
    let r = api
        .call(
            "GET",
            "/api/v1/envelopes?auth_failed=yes",
            &a.auth,
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn expiring_soon_and_custom_fields_are_searched_on_the_server() {
    let Some(api) = Api::new("manage_views_custom", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let soon = sent(&api, &a, "Soon", false, Some(3)).await;
    let _later = sent(&api, &a, "Later", false, Some(60)).await;
    let _never = sent(&api, &a, "Never", false, None).await;
    let week = (time::OffsetDateTime::now_utc() + time::Duration::days(7))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let week = week.replace('+', "%2B");
    assert_eq!(
        subjects(&api, &a.auth, &format!("expires_before={week}")).await,
        ["Soon"]
    );

    // Custom fields: replaced whole, read back by name, searched by name and value.
    let env = soon["id"].as_str().unwrap();
    let path = format!("/api/v1/envelopes/{env}/custom-fields");
    let put = ok(
        api.call(
            "PUT",
            &path,
            &a.auth,
            Some(json!({"items": [
                {"name": "Region", "value": "North-West"},
                {"name": "Deal", "value": "D-1042"},
            ]})),
            &[],
        )
        .await,
        StatusCode::OK,
        "put",
    );
    assert_eq!(put["items"][0]["name"], "Region");
    let got = ok(
        api.call("GET", &path, &a.auth, None, &[]).await,
        StatusCode::OK,
        "get",
    );
    assert_eq!(
        got["items"],
        json!([{"name": "Deal", "value": "D-1042"}, {"name": "Region", "value": "North-West"}])
    );
    assert_eq!(
        subjects(&api, &a.auth, "custom_field=Region&custom_value=north").await,
        ["Soon"]
    );
    assert_eq!(subjects(&api, &a.auth, "custom_field=Deal").await, ["Soon"]);
    assert!(
        subjects(&api, &a.auth, "custom_field=Region&custom_value=south")
            .await
            .is_empty()
    );
    // `%` in the value is matched as itself, not as a wildcard.
    assert!(
        subjects(&api, &a.auth, "custom_field=Region&custom_value=%25")
            .await
            .is_empty()
    );
    // A value without a name, a repeated name, an empty name are refused.
    let r = api
        .call(
            "GET",
            "/api/v1/envelopes?custom_value=x",
            &a.auth,
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    for bad in [
        json!({"items": [{"name": "A", "value": "1"}, {"name": "A", "value": "2"}]}),
        json!({"items": [{"name": " ", "value": "1"}]}),
        json!({"items": [{"name": "A", "value": "x".repeat(1001)}]}),
    ] {
        let r = api.call("PUT", &path, &a.auth, Some(bad), &[]).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    }
    // Clearing them takes the envelope out of the search.
    ok(
        api.call("PUT", &path, &a.auth, Some(json!({"items": []})), &[])
            .await,
        StatusCode::OK,
        "clear",
    );
    assert!(
        subjects(&api, &a.auth, "custom_field=Deal")
            .await
            .is_empty()
    );
    // Another account: 404 on both, and nothing listed.
    let b = api.tenant("beta").await;
    let r = api.call("GET", &path, &b.auth, None, &[]).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = api
        .call("PUT", &path, &b.auth, Some(json!({"items": []})), &[])
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}
