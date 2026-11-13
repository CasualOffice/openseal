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

/// UX-11: every field setting the editor offers (tooltip, placeholder, value, read-only,
/// options, custom options, validation, format) is kept by a template field and read
/// back as sent; a `PATCH` changes them, and `null` removes one (a JSON merge, as an
/// envelope field's `PATCH`), which is how the editor clears a setting.
#[tokio::test]
async fn a_template_field_keeps_every_setting_and_a_patch_clears_one_with_null() {
    let Some(api) = Api::new("templates_settings", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let t = api
        .call(
            "POST",
            "/api/v1/templates",
            &a.auth,
            Some(json!({"name": "Order", "roles": [{"name": "Buyer", "type": "signer"}]})),
            &[],
        )
        .await
        .json();
    let base = format!("/api/v1/templates/{}", t["id"].as_str().unwrap());
    let role = t["roles"][0]["id"].as_str().unwrap().to_owned();
    let with_doc = api
        .call(
            "POST",
            &format!("{base}/documents"),
            &a.auth,
            Some(json!({"name": "order.pdf", "content_base64": common::flow::b64(&common::harness::pdf(1))})),
            &[],
        )
        .await
        .json();
    let doc = with_doc["documents"][0]["id"].as_str().unwrap().to_owned();
    let at = |y: &str| json!({"page": 1, "x": "72", "y": y, "width": "160", "height": "24"});
    let text = json!({
        "role_id": role, "document_id": doc, "type": "text", "placement": at("100"),
        "required": true, "label": "po", "tooltip": "Your purchase order", "placeholder": "PO-0000",
        "read_only": true, "value": {"text": "PO-1234"},
        "validation": {"kind": "length", "max": 12},
        "format": {"font_family": "courier", "font_size": "11", "align": "right", "mask": true},
    });
    let pick = json!({
        "role_id": role, "document_id": doc, "type": "dropdown", "placement": at("200"),
        "options": ["Red", "Green"], "allow_custom": true, "tooltip": "Colour",
    });
    let tick = json!({
        "role_id": role, "document_id": doc, "type": "checkbox", "placement": at("300"),
        "read_only": true, "value": {"checked": true},
    });
    let made = api
        .call(
            "POST",
            &format!("{base}/fields"),
            &a.auth,
            Some(json!({"items": [text, pick, tick]})),
            &[],
        )
        .await;
    assert_eq!(made.status, StatusCode::CREATED, "{:?}", made.json());
    let ids: Vec<String> = made.json()["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap().to_owned())
        .collect();
    let read = api.call("GET", &base, &a.auth, None, &[]).await.json();
    let got = |id: &str| {
        read["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["id"] == id)
            .cloned()
            .unwrap()
    };
    let f0 = got(&ids[0]);
    for k in [
        "required",
        "label",
        "tooltip",
        "placeholder",
        "read_only",
        "value",
        "validation",
    ] {
        assert_eq!(f0[k], text[k], "{k} read back");
    }
    assert_eq!(f0["format"]["font_family"], "courier");
    assert_eq!(f0["format"]["align"], "right");
    assert_eq!(f0["format"]["mask"], true);
    assert_eq!(
        f0["format"]["font_size"].as_str().map(str::parse::<f64>),
        Some(Ok(11.0))
    );
    let f1 = got(&ids[1]);
    for k in ["options", "allow_custom", "tooltip"] {
        assert_eq!(f1[k], pick[k], "{k} read back");
    }
    let f2 = got(&ids[2]);
    for k in ["read_only", "value"] {
        assert_eq!(f2[k], tick[k], "{k} read back");
    }

    // A change, and every cleared setting named with null, as the editor sends it.
    let etag = api.call("GET", &base, &a.auth, None, &[]).await.etag();
    let patched = api
        .call(
            "PATCH",
            &format!("{base}/fields/{}", ids[0]),
            &a.auth,
            Some(json!({
                "role_id": role, "placement": at("100"), "required": true, "label": "po",
                "tooltip": "Changed", "read_only": null, "value": null, "placeholder": null,
                "validation": {"kind": "email"}, "format": null, "options": null, "allow_custom": null,
            })),
            &[("if-match", etag.as_str())],
        )
        .await;
    assert_eq!(patched.status, StatusCode::OK, "{:?}", patched.json());
    let f0 = got_after(&api, &a.auth, &base, &ids[0]).await;
    assert_eq!(f0["tooltip"], "Changed");
    assert_eq!(f0["validation"], json!({"kind": "email"}));
    assert_eq!(f0["label"], "po", "a member not named stays");
    assert_eq!(f0["required"], true, "a member not named stays");
    for k in ["read_only", "value", "placeholder", "format"] {
        assert!(f0.get(k).is_none(), "{k} cleared: {f0}");
    }
}

async fn got_after(
    api: &Api,
    auth: &common::harness::Auth,
    base: &str,
    id: &str,
) -> serde_json::Value {
    let read = api.call("GET", base, auth, None, &[]).await.json();
    read["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == id)
        .cloned()
        .unwrap()
}
