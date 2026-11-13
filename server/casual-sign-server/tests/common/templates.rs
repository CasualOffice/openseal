//! Template editing end to end (WEB-06), shared by `tests/templates.rs` and the
//! contract scenario (which must call every operation).

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::flow::{b64, ok};
use super::harness::{Api, Auth, pdf};

async fn etag(api: &Api, auth: &Auth, t: &str) -> String {
    api.call("GET", &format!("/api/v1/templates/{t}"), auth, None, &[])
        .await
        .etag()
}

/// Build a template, edit every part of it, duplicate it, delete it; answers the id
/// of the duplicate (still there).
pub async fn edit_template(api: &Api, auth: &Auth) -> String {
    let t = ok(
        api.call(
            "POST",
            "/api/v1/templates",
            auth,
            Some(
                json!({"name": "Lease", "email_subject": "Please sign the lease",
                "roles": [{"name": "Tenant", "type": "signer"}]}),
            ),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "create template",
    );
    let id = t["id"].as_str().unwrap().to_owned();
    let base = format!("/api/v1/templates/{id}");
    let tenant = t["roles"][0]["id"].as_str().unwrap().to_owned();

    // Documents.
    let with_doc = ok(
        api.call(
            "POST",
            &format!("{base}/documents"),
            auth,
            Some(json!({"name": "lease.pdf", "content_base64": b64(&pdf(2))})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "add template document",
    );
    let doc = with_doc["documents"][0]["id"].as_str().unwrap().to_owned();
    assert_eq!(with_doc["documents"][0]["pages"], 2);
    let content = api
        .call(
            "GET",
            &format!("{base}/documents/{doc}/content"),
            auth,
            None,
            &[],
        )
        .await;
    assert_eq!(content.status, StatusCode::OK);
    assert!(content.body.starts_with(b"%PDF-"));
    let spare = ok(
        api.call(
            "POST",
            &format!("{base}/documents"),
            auth,
            Some(json!({"name": "spare.pdf", "content_base64": b64(&pdf(1))})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "second document",
    )["documents"][1]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Roles.
    let landlord = ok(
        api.call(
            "POST",
            &format!("{base}/roles"),
            auth,
            Some(json!({"name": "Landlord", "type": "signer", "routing_order": 2})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "add role",
    )["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "Landlord")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let e = etag(api, auth, &id).await;
    let renamed = ok(
        api.call(
            "PATCH",
            &format!("{base}/roles/{landlord}"),
            auth,
            Some(json!({"name": "Owner", "routing_order": 3})),
            &[("if-match", &e)],
        )
        .await,
        StatusCode::OK,
        "patch role",
    );
    assert!(
        renamed["roles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["name"] == "Owner" && r["routing_order"] == 3)
    );

    // Fields, bound to roles; a page beyond the document and an unknown role refused.
    let added = ok(
        api.call(
            "POST",
            &format!("{base}/fields"),
            auth,
            Some(json!({"items": [
                {"role_id": tenant, "document_id": doc, "type": "signature", "page": 2, "x": 72, "y": 600, "width": 180, "height": 40, "required": true},
                {"role_id": landlord, "document_id": doc, "type": "text", "page": 1, "x": 72, "y": 100, "width": 180, "height": 20, "label": "rent"},
                {"role_id": tenant, "document_id": spare, "type": "date_signed", "page": 1, "x": 72, "y": 100, "width": 100, "height": 18},
            ]})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "add template fields",
    );
    let sig = added["items"][0]["id"].as_str().unwrap().to_owned();
    let rent = added["items"][1]["id"].as_str().unwrap().to_owned();
    assert_eq!(added["items"][0]["role_id"], tenant.as_str());
    for bad in [
        json!({"role_id": tenant, "document_id": doc, "type": "text", "page": 3, "x": 1, "y": 1, "width": 10, "height": 10}),
        json!({"role_id": doc, "document_id": doc, "type": "text", "page": 1, "x": 1, "y": 1, "width": 10, "height": 10}),
    ] {
        let r = api
            .call("POST", &format!("{base}/fields"), auth, Some(bad), &[])
            .await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{:?}", r.json());
    }
    let e = etag(api, auth, &id).await;
    let moved = ok(
        api.call(
            "PATCH",
            &format!("{base}/fields/{rent}"),
            auth,
            Some(json!({"x": 300, "required": true, "role_id": tenant})),
            &[("if-match", &e)],
        )
        .await,
        StatusCode::OK,
        "patch template field",
    );
    assert_eq!(moved["placement"]["x"], "300", "{moved}");
    assert_eq!(moved["role_id"], tenant.as_str());
    assert_eq!(moved["label"], "rent");
    // A stale version is refused.
    let stale = api
        .call(
            "PATCH",
            &format!("{base}/fields/{rent}"),
            auth,
            Some(json!({"x": 10})),
            &[("if-match", &e)],
        )
        .await;
    assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);
    let e = etag(api, auth, &id).await;
    let gone = api
        .call(
            "DELETE",
            &format!("{base}/fields/{sig}"),
            auth,
            None,
            &[("if-match", &e)],
        )
        .await;
    assert_eq!(gone.status, StatusCode::NO_CONTENT);
    // Removing a role removes its fields; removing a document removes its fields.
    let e = etag(api, auth, &id).await;
    let r = api
        .call(
            "DELETE",
            &format!("{base}/roles/{landlord}"),
            auth,
            None,
            &[("if-match", &e)],
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let e = etag(api, auth, &id).await;
    let r = api
        .call(
            "DELETE",
            &format!("{base}/documents/{spare}"),
            auth,
            None,
            &[("if-match", &e)],
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let left = ok(
        api.call("GET", &format!("{base}/fields"), auth, None, &[])
            .await,
        StatusCode::OK,
        "template fields",
    );
    let left: Vec<&Value> = left["items"].as_array().unwrap().iter().collect();
    assert_eq!(left.len(), 1, "{left:?}");
    assert_eq!(left[0]["id"], rent.as_str());

    // Template settings, duplicate, delete.
    let e = etag(api, auth, &id).await;
    let patched = ok(
        api.call(
            "PATCH",
            &base,
            auth,
            Some(json!({"email_message": "Thanks", "email_subject": null})),
            &[("if-match", &e)],
        )
        .await,
        StatusCode::OK,
        "patch template",
    );
    assert_eq!(patched["email_message"], "Thanks");
    assert_eq!(patched["email_subject"], Value::Null);
    let copy = ok(
        api.call("POST", &format!("{base}/duplicate"), auth, None, &[])
            .await,
        StatusCode::CREATED,
        "duplicate",
    );
    assert_eq!(copy["name"], "Copy of Lease");
    assert_eq!(copy["documents"].as_array().unwrap().len(), 1);
    assert_eq!(copy["fields"].as_array().unwrap().len(), 1);
    assert_ne!(copy["fields"][0]["id"], rent.as_str());
    assert_eq!(copy["fields"][0]["role_id"], copy["roles"][0]["id"]);
    assert_eq!(copy["fields"][0]["document_id"], copy["documents"][0]["id"]);
    assert_eq!(
        copy["documents"][0]["sha256"],
        patched["documents"][0]["sha256"]
    );
    let e = etag(api, auth, &id).await;
    let no_match = api.call("DELETE", &base, auth, None, &[]).await;
    assert_eq!(no_match.status, StatusCode::PRECONDITION_REQUIRED);
    let del = api
        .call("DELETE", &base, auth, None, &[("if-match", &e)])
        .await;
    assert_eq!(del.status, StatusCode::NO_CONTENT);
    let after = api.call("GET", &base, auth, None, &[]).await;
    assert_eq!(after.status, StatusCode::NOT_FOUND);
    // UXW-02: kept in the Deleted view, and restored whole.
    let back = api
        .call("POST", &format!("{base}/restore"), auth, None, &[])
        .await;
    assert_eq!(back.status, StatusCode::OK);
    assert_eq!(back.json()["id"].as_str(), Some(id.as_str()));
    copy["id"].as_str().unwrap().to_owned()
}
