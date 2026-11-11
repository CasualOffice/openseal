//! Field types end to end through the API and the ceremony (WEB-06): company, title,
//! number with bounds and decimals, radio group, dropdown, attachment, note, a value
//! pre-filled and locked by the sender, and text validation presets (email, phone, ZIP,
//! maximum length). Invalid values are refused with their field's code; read-only and
//! locked fields cannot be changed; an attachment value must be a file the signer
//! uploaded; the values completed are drawn in the preview.

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
    json!({"recipient": "s1", "document": 0, "type": ty, "page": 2, "x": 72, "y": y, "width": 200, "height": 20})
}

fn with(mut v: Value, extra: Value) -> Value {
    for (k, x) in extra.as_object().unwrap() {
        v[k] = x.clone();
    }
    v
}

#[tokio::test]
async fn every_new_field_type_is_validated_filled_and_drawn() {
    let Some(api) = Api::new("field_types", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let fields = [
        with(at(40, "company"), json!({"label": "company"})),
        with(at(70, "title"), json!({"label": "title"})),
        with(
            at(100, "number"),
            json!({"label": "qty", "validation": {"kind": "number", "min": "1", "max": "100", "decimals": 0}}),
        ),
        with(
            at(130, "radio_group"),
            json!({"label": "plan", "options": ["Basic", "Pro"]}),
        ),
        with(
            at(160, "dropdown"),
            json!({"label": "term", "options": ["12 months", "24 months"]}),
        ),
        with(at(190, "attachment"), json!({"label": "id_proof"})),
        with(
            at(220, "note"),
            json!({"value": {"text": "Sender note: read clause 4"}, "read_only": true, "locked": true}),
        ),
        with(
            at(250, "text"),
            json!({"label": "ref", "value": {"text": "PO-7781"}, "locked": true}),
        ),
        with(
            at(280, "text"),
            json!({"label": "mail", "validation": {"kind": "email"}}),
        ),
        with(
            at(310, "text"),
            json!({"label": "tel", "validation": {"kind": "phone"}}),
        ),
        with(
            at(340, "text"),
            json!({"label": "zip", "validation": {"kind": "zip"}}),
        ),
        with(
            at(370, "text"),
            json!({"label": "code", "validation": {"kind": "length", "max": 5}}),
        ),
    ];
    let e = sent(&api, &a, 1, &fields).await;
    let id = e["id"].as_str().unwrap().to_owned();
    let doc = e["documents"][0]["id"].as_str().unwrap().to_owned();
    let r1 = e["recipients"][0]["id"].as_str().unwrap().to_owned();
    let by_label = |l: &str| {
        e["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["label"] == l)
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let by_type = |t: &str| {
        e["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["type"] == t)
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let t = invite(&api, &a, &id, &r1).await;
    let (_, h) = open(&api, &t).await;
    let h: Vec<(&str, &str)> = h.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let put = |f: String, v: Value| {
        let (api, t, h) = (&api, &t, &h);
        async move {
            api.call(
                "PUT",
                &format!("/s/{t}/fields/{f}"),
                &Auth::None,
                Some(json!({ "value": v })),
                h,
            )
            .await
        }
    };
    // Refused values: each with its field's problem.
    for (f, v) in [
        (by_label("qty"), json!({"text": "500"})),
        (by_label("qty"), json!({"text": "2.5"})),
        (by_label("plan"), json!({"choice": "Enterprise"})),
        (by_label("term"), json!({"choice": "6 months"})),
        (by_label("mail"), json!({"text": "not an address"})),
        (by_label("tel"), json!({"text": "call me"})),
        (by_label("zip"), json!({"text": "ABCDE"})),
        (by_label("code"), json!({"text": "TOOLONG"})),
        (by_label("plan"), json!({"text": "Basic"})),
    ] {
        let r = put(f.clone(), v.clone()).await;
        assert_eq!(
            r.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{v} into {f}: {:?}",
            r.json()
        );
    }
    // Read-only and sender-locked fields cannot be changed.
    for f in [by_type("note"), by_label("ref")] {
        let r = put(f.clone(), json!({"text": "changed"})).await;
        assert!(r.status.is_client_error(), "{f} changed: {:?}", r.json());
    }
    // An attachment value naming a file this signer did not upload is refused.
    let forged = put(by_label("id_proof"), json!({"attachment": "ab".repeat(32)})).await;
    assert_eq!(
        forged.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{:?}",
        forged.json()
    );
    // Upload: a text file is refused; a PNG is the field's value.
    let attach = |content: Vec<u8>| {
        let (api, t, h) = (&api, &t, &h);
        let f = by_label("id_proof");
        async move {
            api.call(
                "PUT",
                &format!("/s/{t}/fields/{f}/attachment"),
                &Auth::None,
                Some(json!({ "content_base64": b64(&content) })),
                h,
            )
            .await
        }
    };
    assert_eq!(
        attach(b"just text".to_vec()).await.status,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let up = attach(png()).await;
    assert_eq!(up.status, StatusCode::OK, "{:?}", up.json());
    let sha = casual_sign_audit::Hash256::digest(&png()).hex();
    let mine = up.json()["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["label"] == "id_proof")
        .unwrap()["value"]
        .clone();
    assert_eq!(mine, json!({"attachment": sha}));
    // Valid values for the rest, then sign.
    for (f, v) in [
        (by_label("company"), json!({"text": "Acme Holdings"})),
        (by_label("title"), json!({"text": "Director"})),
        (by_label("qty"), json!({"text": "42"})),
        (by_label("plan"), json!({"choice": "Pro"})),
        (by_label("term"), json!({"choice": "24 months"})),
        (by_label("mail"), json!({"text": "a@example.test"})),
        (by_label("tel"), json!({"text": "+1 555 123 4567"})),
        (by_label("zip"), json!({"text": "94105"})),
        (by_label("code"), json!({"text": "AB12"})),
    ] {
        let r = put(f.clone(), v.clone()).await;
        assert_eq!(r.status, StatusCode::OK, "{v} into {f}: {:?}", r.json());
    }
    let s = format!("/s/{t}");
    ok(
        api.call(
            "POST",
            &format!("{s}/documents/{doc}/viewed"),
            &Auth::None,
            Some(json!({"pages_seen": [1, 2]})),
            &h,
        )
        .await,
        StatusCode::OK,
        "viewed",
    );
    let adopted = ok(
        api.call(
            "POST",
            &format!("{s}/adopt"),
            &Auth::None,
            Some(json!({"mark": "signature", "method": "draw", "image_base64": b64(&png())})),
            &h,
        )
        .await,
        StatusCode::OK,
        "adopt",
    );
    let sig = by_type("signature");
    let done = ok(
        api.call(
            "POST",
            &format!("{s}/finish"),
            &Auth::None,
            Some(json!({"values": [
                {"field": sig, "value": {"signature": adopted["adoption_id"]}},
                {"field": by_label("id_proof"), "value": {"attachment": sha}},
            ]})),
            &h,
        )
        .await,
        StatusCode::OK,
        "finish",
    );
    assert_eq!(done["recipient"]["status"], "completed");

    // The chain binds the attachment's hash; the preview draws the values.
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
    let completed = audit["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["type"] == "recipient.field_completed")
        .count();
    assert!(completed >= 10, "{completed}");
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
    let text: String = casual_sign_fields::extract_text(&mut adm.document, &pages, &never)
        .unwrap()
        .iter()
        .flat_map(|p| p.runs.iter().map(|r| r.text.clone()))
        .collect::<Vec<_>>()
        .join(" ");
    for want in [
        "Acme Holdings",
        "Director",
        "42",
        "24 months",
        "a@example.test",
        "94105",
        "AB12",
        "Sender note: read clause 4",
        "PO-7781",
    ] {
        assert!(text.contains(want), "{want} not drawn: {text}");
    }
}
