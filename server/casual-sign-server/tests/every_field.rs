//! Slice 4, every field (`VS-04A`, `VS-04C`), through the API and the ceremony.
//!
//! The first test fills every engine field kind the earlier slices left (date, email
//! address, phone, SSN, ZIP, multi-select, a regex rule, stamp, drawing) beside the ones
//! the server fills (envelope id, formula) and the display and button kinds (hyperlink,
//! approve, decline); each kind's bad value is refused with its field's code; a stamp
//! and a drawing are adopted as what they are; the values are drawn in the document.
//!
//! The second test is the signing view's `rules`: the server's own evaluation of the
//! recipient's fields (hidden by a condition, computed by a formula, mirrored by a
//! linked label), changing as the signer fills the fields they depend on, and a
//! checkbox group's rule refusing finish until it holds.

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
use common::flow::{b64, invite, ok, open, sent};
use common::harness::{Api, Auth, png};
use serde_json::{Value, json};

fn at(y: u32, ty: &str) -> Value {
    json!({"recipient": "s1", "document": 0, "type": ty, "page": 2, "x": 72, "y": y, "width": 220, "height": 20})
}

fn with(mut v: Value, extra: Value) -> Value {
    for (k, x) in extra.as_object().unwrap() {
        v[k] = x.clone();
    }
    v
}

/// The id of the field `key` names in an envelope or view (`label`, else `type`).
fn id_of(fields: &Value, key: &str) -> String {
    let all = fields.as_array().unwrap();
    all.iter()
        .find(|f| f["label"] == key)
        .or_else(|| all.iter().find(|f| f["type"] == key))
        .unwrap_or_else(|| panic!("no field {key}"))["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

struct Signer<'a> {
    api: &'a Api,
    token: String,
    headers: Vec<(&'static str, String)>,
}

impl Signer<'_> {
    async fn call(&self, method: &str, path: &str, body: Option<Value>) -> common::harness::Resp {
        let h: Vec<(&str, &str)> = self.headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        self.api
            .call(
                method,
                &format!("/s/{}{path}", self.token),
                &Auth::None,
                body,
                &h,
            )
            .await
    }
    async fn put(&self, field: &str, value: Value) -> common::harness::Resp {
        self.call(
            "PUT",
            &format!("/fields/{field}"),
            Some(json!({ "value": value })),
        )
        .await
    }
    async fn adopt(&self, mark: &str, method: &str) -> common::harness::Resp {
        self.call(
            "POST",
            "/adopt",
            Some(json!({"mark": mark, "method": method, "image_base64": b64(&png())})),
        )
        .await
    }
}

async fn signer<'a>(api: &'a Api, a: &common::harness::Tenant, e: &Value) -> Signer<'a> {
    let id = e["id"].as_str().unwrap();
    let r1 = e["recipients"][0]["id"].as_str().unwrap();
    let token = invite(api, a, id, r1).await;
    let (_, headers) = open(api, &token).await;
    Signer {
        api,
        token,
        headers,
    }
}

/// The text drawn in the document's current version.
async fn drawn(api: &Api, a: &common::harness::Tenant, e: &Value) -> String {
    let id = e["id"].as_str().unwrap();
    let doc = e["documents"][0]["id"].as_str().unwrap();
    let preview = api
        .call(
            "GET",
            &format!("/api/v1/envelopes/{id}/documents/{doc}/content?version=current"),
            &a.auth,
            None,
            &[],
        )
        .await;
    assert_eq!(preview.status, StatusCode::OK, "{:?}", preview.json());
    let never = || false;
    let mut adm =
        casual_sign_pdf::admit(&preview.body, &casual_sign_pdf::Limits::default(), &never).unwrap();
    let pages = adm.report.pages.clone();
    casual_sign_fields::extract_text(&mut adm.document, &pages, &never)
        .unwrap()
        .iter()
        .flat_map(|p| p.runs.iter().map(|r| r.text.clone()))
        .collect::<Vec<_>>()
        .join(" ")
}

#[tokio::test]
async fn every_field_kind_is_filled_checked_adopted_and_drawn() {
    let Some(api) = Api::new("every_field_kinds", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let fields = [
        with(
            at(40, "date"),
            json!({"label": "start", "format": {"date_format": "dd_mm_yyyy"}}),
        ),
        with(at(70, "email_address"), json!({"label": "mail"})),
        with(at(100, "phone"), json!({"label": "tel"})),
        with(at(130, "ssn"), json!({"label": "ssn"})),
        with(at(160, "zip"), json!({"label": "zip"})),
        with(
            at(190, "multi_select"),
            json!({"label": "extras", "options": ["Insurance", "Delivery", "Warranty"]}),
        ),
        with(
            at(220, "text"),
            json!({"label": "policy", "validation": {"kind": "regex", "pattern": "^POL-[0-9]{4}$", "message": "POL- and four digits"}}),
        ),
        with(at(250, "stamp"), json!({"label": "stamp"})),
        with(at(280, "drawing"), json!({"label": "sketch"})),
        with(at(310, "envelope_id"), json!({"label": "envid"})),
        with(at(340, "number"), json!({"label": "qty"})),
        with(
            at(370, "formula"),
            json!({"label": "total", "formula": {"expression": "qty * 12.5", "precision": 2}}),
        ),
        with(
            at(400, "hyperlink"),
            json!({"label": "terms", "value": {"text": "https://example.test/terms"}, "read_only": true}),
        ),
        with(at(430, "approve"), json!({"label": "ok"})),
        with(at(460, "decline"), json!({"label": "no"})),
    ];
    let e = sent(&api, &a, 1, &fields).await;
    let s = signer(&api, &a, &e).await;
    let f = |k: &str| id_of(&e["fields"], k);

    // Each kind's bad value is refused.
    for (k, v) in [
        ("start", json!({"text": "2026-13-45"})),
        ("start", json!({"text": "next week"})),
        ("mail", json!({"text": "not an address"})),
        ("tel", json!({"text": "call me"})),
        ("ssn", json!({"text": "123-45-678"})),
        ("zip", json!({"text": "ABCDE"})),
        ("extras", json!({"choices": ["Insurance", "Spaceship"]})),
        ("extras", json!({"choice": "Insurance"})),
        ("policy", json!({"text": "POL-12"})),
        ("qty", json!({"text": "many"})),
    ] {
        let r = s.put(&f(k), v.clone()).await;
        assert_eq!(
            r.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{v} into {k}: {:?}",
            r.json()
        );
    }
    // Server-filled, computed, display and button kinds take no value from a signer.
    for k in ["envid", "total", "terms", "ok", "no"] {
        let r = s.put(&f(k), json!({"text": "mine"})).await;
        assert!(
            r.status.is_client_error(),
            "{k} took a value: {:?}",
            r.json()
        );
    }

    // A stamp and a drawing are adopted as what they are, and fill their fields; a
    // stamp's capture does not fill a signature field (it is not a signature).
    let stamp = ok(s.adopt("stamp", "upload").await, StatusCode::OK, "stamp");
    let stamp = stamp["adoption_id"].as_str().unwrap().to_owned();
    let sketch = ok(s.adopt("drawing", "draw").await, StatusCode::OK, "drawing");
    let sketch = sketch["adoption_id"].as_str().unwrap().to_owned();
    // With a signature adopted too, the stamp's capture is still not a signature.
    let sig = ok(s.adopt("signature", "draw").await, StatusCode::OK, "adopt");
    let r = s
        .put(&f("signature"), json!({"signature": stamp.clone()}))
        .await;
    assert_eq!(
        r.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a stamp signed: {:?}",
        r.json()
    );

    for (k, v) in [
        ("start", json!({"text": "02/03/2026"})),
        ("mail", json!({"text": "buyer@example.test"})),
        ("tel", json!({"text": "+44 20 7946 0958"})),
        ("ssn", json!({"text": "123-45-6789"})),
        ("zip", json!({"text": "94105-1234"})),
        ("extras", json!({"choices": ["Warranty", "Insurance"]})),
        ("policy", json!({"text": "POL-2026"})),
        ("qty", json!({"text": "3"})),
        ("stamp", json!({"signature": stamp})),
        ("sketch", json!({"signature": sketch})),
    ] {
        let r = s.put(&f(k), v.clone()).await;
        assert_eq!(r.status, StatusCode::OK, "{v} into {k}: {:?}", r.json());
    }
    let doc = e["documents"][0]["id"].as_str().unwrap();
    ok(
        s.call(
            "POST",
            &format!("/documents/{doc}/viewed"),
            Some(json!({"pages_seen": [1, 2]})),
        )
        .await,
        StatusCode::OK,
        "viewed",
    );
    let done = ok(
        s.call(
            "POST",
            "/finish",
            Some(json!({"values": [
                {"field": f("signature"), "value": {"signature": sig["adoption_id"]}},
            ]})),
        )
        .await,
        StatusCode::OK,
        "finish",
    );
    assert_eq!(done["recipient"]["status"], "completed");

    // The chain names each adoption by what it is.
    let id = e["id"].as_str().unwrap();
    let audit = ok(
        api.call(
            "GET",
            &format!("/api/v1/envelopes/{id}/audit"),
            &a.auth,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "audit",
    );
    let marks: Vec<String> = audit["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["type"] == "recipient.signature_adopted")
        .map(|e| {
            e["event"]["data"]["mark"]
                .as_str()
                .unwrap_or_default()
                .to_owned()
        })
        .collect();
    for m in ["stamp", "drawing", "signature"] {
        assert!(marks.iter().any(|x| x == m), "{m} not adopted: {marks:?}");
    }

    let text = drawn(&api, &a, &e).await;
    for want in [
        "02/03/2026",
        "buyer@example.test",
        "+44 20 7946 0958",
        "123-45-6789",
        "94105-1234",
        "Insurance",
        "Warranty",
        "POL-2026",
        "37.50",
        "https://example.test/terms",
        id,
    ] {
        assert!(text.contains(want), "{want} not drawn: {text}");
    }
}

#[tokio::test]
async fn the_signing_view_carries_the_servers_rules_as_the_signer_fills() {
    let Some(api) = Api::new("every_field_rules", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let fields = [
        with(at(40, "checkbox"), json!({"label": "agree"})),
        with(
            at(70, "text"),
            json!({"label": "detail", "required": true,
                "conditional": {"parent_label": "agree", "when": "checked"}}),
        ),
        with(at(100, "number"), json!({"label": "qty"})),
        with(at(130, "number"), json!({"label": "price"})),
        with(
            at(160, "formula"),
            json!({"label": "total", "formula": {"expression": "qty * price", "precision": 2}}),
        ),
        with(at(190, "text"), json!({"label": "ref"})),
        with(
            at(400, "text"),
            json!({"label": "ref", "width": 120, "x": 300}),
        ),
        with(
            at(220, "checkbox"),
            json!({"label": "opt_a", "group": {"id": "opts", "rule": {"rule": "select_at_least", "min": 1}}}),
        ),
        with(
            at(250, "checkbox"),
            json!({"label": "opt_b", "group": {"id": "opts", "rule": {"rule": "select_at_least", "min": 1}}}),
        ),
    ];
    let e = sent(&api, &a, 1, &fields).await;
    let s = signer(&api, &a, &e).await;
    let f = |k: &str| id_of(&e["fields"], k);
    let refs: Vec<String> = e["fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| x["label"] == "ref")
        .map(|x| x["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(refs.len(), 2);

    // Before anything is filled: the detail is hidden (its parent is not ticked), the
    // total is computed from empty lines, nothing is linked yet.
    let view = ok(s.call("GET", "", None).await, StatusCode::OK, "view");
    let rules = &view["rules"];
    assert!(
        rules["hidden"]
            .as_array()
            .unwrap()
            .contains(&json!(f("detail"))),
        "{rules}"
    );
    assert_eq!(
        rules["computed"][f("total")],
        json!({"ok": "0.00"}),
        "{rules}"
    );

    // Ticking the parent shows the detail; the lines compute the total; one linked
    // field's value is the other's.
    let v = ok(
        s.put(&f("agree"), json!({"checked": true})).await,
        StatusCode::OK,
        "agree",
    );
    assert!(
        !v["rules"]["hidden"]
            .as_array()
            .unwrap()
            .contains(&json!(f("detail"))),
        "{}",
        v["rules"]
    );
    ok(
        s.put(&f("qty"), json!({"text": "4"})).await,
        StatusCode::OK,
        "qty",
    );
    let v = ok(
        s.put(&f("price"), json!({"text": "2.25"})).await,
        StatusCode::OK,
        "price",
    );
    assert_eq!(v["rules"]["computed"][f("total")], json!({"ok": "9.00"}));
    let v = ok(
        s.put(&refs[0], json!({"text": "R-77"})).await,
        StatusCode::OK,
        "ref",
    );
    assert_eq!(v["rules"]["values"][&refs[1]], json!({"text": "R-77"}));

    // The detail is now shown and required, and the group needs one option: finish is
    // refused naming both, then passes once they hold.
    let doc = e["documents"][0]["id"].as_str().unwrap();
    ok(
        s.call(
            "POST",
            &format!("/documents/{doc}/viewed"),
            Some(json!({"pages_seen": [1, 2]})),
        )
        .await,
        StatusCode::OK,
        "viewed",
    );
    let sig = ok(s.adopt("signature", "draw").await, StatusCode::OK, "adopt");
    let sig = json!({"field": f("signature"), "value": {"signature": sig["adoption_id"]}});
    let refused = s
        .call("POST", "/finish", Some(json!({"values": [sig.clone()]})))
        .await;
    assert_eq!(
        refused.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{:?}",
        refused.json()
    );
    let said = refused.json()["errors"].to_string();
    assert!(said.contains(&format!("/fields/{}", f("detail"))), "{said}");
    assert!(said.contains(&format!("/fields/{}", f("opt_a"))), "{said}");
    ok(
        s.put(&f("detail"), json!({"text": "Details given"})).await,
        StatusCode::OK,
        "detail",
    );
    ok(
        s.put(&f("opt_b"), json!({"checked": true})).await,
        StatusCode::OK,
        "opt_b",
    );
    let done = ok(
        s.call("POST", "/finish", Some(json!({"values": [sig]})))
            .await,
        StatusCode::OK,
        "finish",
    );
    assert_eq!(done["recipient"]["status"], "completed");
    let text = drawn(&api, &a, &e).await;
    for want in ["Details given", "9.00", "R-77"] {
        assert!(text.contains(want), "{want} not drawn: {text}");
    }
    assert_eq!(
        text.matches("R-77").count(),
        2,
        "both linked fields drawn: {text}"
    );
}
