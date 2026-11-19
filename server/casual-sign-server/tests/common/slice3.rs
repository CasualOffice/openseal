//! Slice 3 (templates, `VS-03`): composite use and template folders, shared by
//! `tests/use_templates.rs` and the contract scenario (which must call every operation).

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::flow::{b64, ok};
use super::harness::{Api, Auth, pdf};

/// A template named `name` with one document of `pages` pages, the `roles` given
/// (`(name, type, routing order)`), and one signature field (or, for a role that is not
/// a signer, none) per signer role on the last page; answers the whole template.
pub async fn template(
    api: &Api,
    auth: &Auth,
    name: &str,
    pages: u16,
    roles: &[(&str, &str, u32)],
) -> Value {
    let rs: Vec<Value> = roles
        .iter()
        .map(|(n, t, o)| json!({"name": n, "type": t, "routing_order": o}))
        .collect();
    let t = ok(
        api.call(
            "POST",
            "/api/v1/templates",
            auth,
            Some(
                json!({"name": name, "email_subject": format!("Please sign: {name}"), "roles": rs}),
            ),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "template",
    );
    let id = t["id"].as_str().unwrap().to_owned();
    let base = format!("/api/v1/templates/{id}");
    let with_doc = ok(
        api.call(
            "POST",
            &format!("{base}/documents"),
            auth,
            Some(json!({"name": format!("{name}.pdf"), "content_base64": b64(&pdf(usize::from(pages)))})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "template document",
    );
    let doc = with_doc["documents"][0]["id"].as_str().unwrap().to_owned();
    let items: Vec<Value> = t["roles"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["type"] == "signer")
        .enumerate()
        .map(|(i, r)| {
            json!({"role_id": r["id"], "document_id": doc, "type": "signature", "required": true,
                   "label": format!("{name} {}", r["name"].as_str().unwrap()),
                   "placement": {"page": pages, "x": "72", "y": (100 + 60 * i).to_string(),
                                 "width": "160", "height": "36"}})
        })
        .collect();
    if !items.is_empty() {
        ok(
            api.call(
                "POST",
                &format!("{base}/fields"),
                auth,
                Some(json!({"items": items})),
                &[],
            )
            .await,
            StatusCode::CREATED,
            "template fields",
        );
    }
    ok(
        api.call("GET", &base, auth, None, &[]).await,
        StatusCode::OK,
        "read template",
    )
}

/// Every slice-3 operation once: an envelope from two templates (one role in both),
/// and a template folder with a template filed in it and out again. Answers the
/// envelope.
pub async fn every_operation(api: &Api, auth: &Auth) -> Value {
    let nda = template(api, auth, "NDA", 1, &[("Buyer", "signer", 1)]).await;
    let order = template(
        api,
        auth,
        "Order",
        2,
        &[("buyer", "signer", 1), ("Seller", "signer", 2)],
    )
    .await;
    let env = ok(
        api.call(
            "POST",
            "/api/v1/envelopes/from-templates",
            auth,
            Some(json!({
                "template_ids": [nda["id"], order["id"]],
                "recipients": [
                    {"role": "Buyer", "name": "Bea Buyer", "email": "bea@example.test"},
                    {"role": "Seller", "name": "Sol Seller", "email": "sol@example.test"}
                ],
                "status": "sent"
            })),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "envelope from two templates",
    );
    let folder = ok(
        api.call(
            "POST",
            "/api/v1/folders",
            auth,
            Some(json!({"name": "Sales", "kind": "templates"})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "template folder",
    );
    let fid = folder["id"].as_str().unwrap();
    let moved = ok(
        api.call(
            "POST",
            &format!("/api/v1/folders/{fid}/templates"),
            auth,
            Some(json!({"template_ids": [nda["id"]]})),
            &[],
        )
        .await,
        StatusCode::OK,
        "file a template",
    );
    assert_eq!(moved["moved"], 1);
    ok(
        api.call(
            "POST",
            "/api/v1/folders/none/templates",
            auth,
            Some(json!({"template_ids": [nda["id"]]})),
            &[],
        )
        .await,
        StatusCode::OK,
        "unfile a template",
    );
    env
}
