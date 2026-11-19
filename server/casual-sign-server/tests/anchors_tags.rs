//! Slice 4, anchors and text tags through the API (`VS-04E`, docs/40 §3): a field with
//! an `anchor` is placed at each match of its text in the delivered document (on create
//! and on `POST /fields`), offsets in the anchor's units; an absent anchor refuses the
//! request (`CS-FLD-0010`) unless `ignore_if_absent`; `"text_tags": true` places a field
//! at each `{{type:recipient…}}` tag, its recipient a request `ref`; a malformed tag
//! refuses the request (`CS-FLD-0011`).

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
use common::harness::{Api, text_pdf};
use serde_json::{Value, json};

const CONTENT: &str = "BT /F1 11 Tf 72 640 Td (Buyer signs here: /sig1/) Tj ET \
                       BT /F1 11 Tf 72 600 Td (Dated: /date1/ and again /date1/) Tj ET \
                       BT /F1 11 Tf 72 500 Td ({{text:client:req:company_name}}) Tj ET \
                       BT /F1 11 Tf 300 500 Td ({{s:client}}) Tj ET";

fn num(v: &Value) -> f64 {
    v.as_str()
        .map_or_else(|| v.as_f64().unwrap(), |s| s.parse().unwrap())
}

#[tokio::test]
async fn anchored_and_tagged_fields_are_placed_at_their_text() {
    let Some(api) = Api::new("anchors_tags", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let create = |fields: Value, tags: bool| {
        json!({
            "subject": "VS-04E",
            "documents": [{"name": "a.pdf", "content_base64": b64(&text_pdf(CONTENT))}],
            "recipients": [{"ref": "client", "type": "signer", "name": "C", "email": "c@example.test"}],
            "fields": fields,
            "text_tags": tags,
        })
    };
    let e = ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            &a.auth,
            Some(create(
                json!([
                    {"recipient": "client", "document": 0, "type": "signature", "anchor": {"text": "/sig1/", "offset_y": "-4"}},
                    {"recipient": "client", "document": 0, "type": "date_signed", "width": 90, "height": 18, "anchor": {"text": "/date1/"}},
                    {"recipient": "client", "document": 0, "type": "initials", "anchor": {"text": "/nowhere/", "ignore_if_absent": true}},
                ]),
                true,
            )),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "create",
    );
    let fields = e["fields"].as_array().unwrap();
    let of = |t: &str| fields.iter().filter(|f| f["type"] == t).collect::<Vec<_>>();
    // The signature at "/sig1/" (top-left at the match, 4 points up), default size.
    let sig = of("signature");
    assert_eq!(
        sig.len(),
        2,
        "the anchor's and the {{s:client}} tag's: {fields:?}"
    );
    let anchored = sig
        .iter()
        .find(|f| num(&f["placement"]["x"]) > 100.0 && num(&f["placement"]["y"]) < 160.0)
        .expect("a signature at /sig1/");
    assert_eq!(anchored["placement"]["page"], 1);
    let y = num(&anchored["placement"]["y"]);
    // Displayed space: the text's baseline is 792 − 640 = 152 from the top.
    assert!(y > 130.0 && y < 152.0, "{anchored}");
    assert_eq!(num(&anchored["placement"]["width"]), 160.0);
    // Every match of "/date1/": two fields, each 90 × 18.
    let dates = of("date_signed");
    assert_eq!(dates.len(), 2, "{fields:?}");
    for d in &dates {
        assert_eq!(num(&d["placement"]["width"]), 90.0);
    }
    // Absent but ignored: no initials.
    assert!(of("initials").is_empty());
    // The tags: a required text field labelled company_name, and a signature.
    let text = of("text");
    assert_eq!(text.len(), 1, "{fields:?}");
    assert_eq!(text[0]["label"], "company_name");
    assert_eq!(text[0]["required"], true);
    assert!(
        (num(&text[0]["placement"]["x"]) - 72.0).abs() < 2.0,
        "{}",
        text[0]
    );

    // POST /fields takes an anchor too, on the stored document.
    let id = e["id"].as_str().unwrap();
    let doc = e["documents"][0]["id"].as_str().unwrap();
    // The editor's Detect fields suggests the text tags (source `tag`).
    let found = ok(
        api.call(
            "POST",
            &format!("/api/v1/envelopes/{id}/documents/{doc}/detect-fields"),
            &a.auth,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "detect",
    );
    let tagged: Vec<(&str, &str)> = found["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| x["source"] == "tag")
        .map(|x| (x["type"].as_str().unwrap(), x["cue"].as_str().unwrap()))
        .collect();
    assert_eq!(
        tagged,
        [("text", "company_name"), ("signature", "client")],
        "{found}"
    );
    let rid = e["recipients"][0]["id"].as_str().unwrap();
    let added = ok(
        api.call(
            "POST",
            &format!("/api/v1/envelopes/{id}/fields"),
            &a.auth,
            Some(json!({"items": [{"recipient_id": rid, "document_id": doc, "type": "checkbox",
                "anchor": {"text": "/sig1/", "matching": "first", "offset_x": "1", "units": "inches"}}]})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "add",
    );
    let cb = &added["items"][0];
    assert_eq!(cb["type"], "checkbox");
    assert!(
        num(&cb["placement"]["x"]) > num(&anchored["placement"]["x"]) + 70.0,
        "{cb}"
    );

    // An absent anchor refuses the request, naming it; nothing is made.
    let r = api
        .call(
            "POST",
            "/api/v1/envelopes",
            &a.auth,
            Some(create(
                json!([{"recipient": "client", "document": 0, "type": "signature", "anchor": {"text": "/missing/"}}]),
                false,
            )),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{:?}", r.json());
    assert_eq!(r.json()["code"], "CS-FLD-0010");
    assert_eq!(r.json()["errors"][0]["pointer"], "/fields/0/anchor");

    // A malformed tag refuses the request.
    let bad = "BT /F1 11 Tf 72 640 Td ({{nonsense}}) Tj ET";
    let r = api
        .call(
            "POST",
            "/api/v1/envelopes",
            &a.auth,
            Some(json!({
                "subject": "bad tag",
                "documents": [{"name": "b.pdf", "content_base64": b64(&text_pdf(bad))}],
                "recipients": [{"ref": "client", "type": "signer", "name": "C", "email": "c@example.test"}],
                "text_tags": true,
            })),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{:?}", r.json());
    assert_eq!(r.json()["code"], "CS-FLD-0011");
}
