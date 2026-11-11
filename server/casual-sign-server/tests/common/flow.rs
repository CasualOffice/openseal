//! Steps the WEB-06 tests share: create a sent envelope, mint a link, open it, sign.

use axum::http::StatusCode;
use base64::Engine as _;
use serde_json::{Value, json};
use sqlx::Row;

use super::harness::{Api, Auth, Resp, Tenant, ceremony_cookie, pdf, png};

/// Base64 of `bytes`.
pub fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The JSON of `r`, after checking its status.
pub fn ok(r: Resp, want: StatusCode, what: &str) -> Value {
    assert_eq!(
        r.status,
        want,
        "{what}: {}",
        String::from_utf8_lossy(&r.body)
    );
    r.json()
}

/// Mint the invitation token the worker would put in the email.
pub async fn invite(api: &Api, t: &Tenant, env: &str, rec: &str) -> String {
    casual_sign_server::issue_invitation_token(
        &api.st,
        t.boot.account,
        casual_sign_store::EnvelopeId(env.parse().unwrap()),
        casual_sign_store::RecipientId(rec.parse().unwrap()),
        std::time::Duration::from_secs(86_400),
    )
    .await
    .unwrap()
}

/// Bind the link to "this browser"; answer the view and the cookie header.
pub async fn open(api: &Api, token: &str) -> (Value, Vec<(&'static str, String)>) {
    let r = api
        .call(
            "POST",
            &format!("/s/{token}/session"),
            &Auth::None,
            Some(json!({})),
            &[],
        )
        .await;
    assert_eq!(
        r.status,
        StatusCode::OK,
        "session: {}",
        String::from_utf8_lossy(&r.body)
    );
    let cookie = ceremony_cookie(&r);
    (r.json(), vec![("cookie", cookie)])
}

/// Job kinds enqueued for an envelope, oldest first.
pub async fn jobs(api: &Api, env: &str) -> Vec<String> {
    sqlx::query("SELECT kind FROM jobs WHERE envelope_id = $1::uuid ORDER BY created_at, kind")
        .bind(env)
        .fetch_all(&api.db.admin)
        .await
        .unwrap()
        .iter()
        .map(|r| r.get::<String, _>(0))
        .collect()
}

/// A sent envelope of one two-page document, `signers` signers in sequence (named
/// `S<n>`, `s<n>@example.test`), each with one required signature field, plus `extra`
/// fields (`recipient` is the 0-based signer index as a string ref `s<n>`).
pub async fn sent(api: &Api, t: &Tenant, signers: usize, extra: &[Value]) -> Value {
    let recipients: Vec<Value> = (1..=signers)
        .map(|n| {
            json!({"ref": format!("s{n}"), "type": "signer", "name": format!("S{n}"),
                "email": format!("s{n}@example.test"), "routing_order": n})
        })
        .collect();
    let mut fields: Vec<Value> = (1..=signers)
        .map(|n| {
            json!({"recipient": format!("s{n}"), "document": 0, "type": "signature", "page": 1,
                "x": 72, "y": 100 * n, "width": 180, "height": 40, "required": true})
        })
        .collect();
    fields.extend(extra.iter().cloned());
    ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            &t.auth,
            Some(json!({
                "subject": "WEB-06", "status": "sent",
                "documents": [{"name": "w.pdf", "content_base64": b64(&pdf(2))}],
                "recipients": recipients, "fields": fields,
            })),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "create sent envelope",
    )
}

/// Sign as the recipient behind `token`: open, view every document, adopt, give
/// `values` (`(field id, value)`), sign every own signature field, finish. Answers the
/// view after finishing and the cookie the link is now bound to.
pub async fn sign(
    api: &Api,
    token: &str,
    values: &[(String, Value)],
) -> (Value, Vec<(&'static str, String)>) {
    let s = format!("/s/{token}");
    let (view, bound) = open(api, token).await;
    let h = bound.clone();
    let h: Vec<(&str, &str)> = h.iter().map(|(k, v)| (*k, v.as_str())).collect();
    for d in view["envelope"]["documents"].as_array().unwrap() {
        let doc = d["id"].as_str().unwrap();
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
    }
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
    let adoption = adopted["adoption_id"].as_str().unwrap().to_owned();
    let mut all: Vec<Value> = values
        .iter()
        .map(|(f, v)| json!({"field": f, "value": v}))
        .collect();
    for f in view["fields"].as_array().unwrap() {
        if f["type"] == "signature" {
            all.push(json!({"field": f["id"], "value": {"signature": adoption}}));
        }
    }
    let done = ok(
        api.call(
            "POST",
            &format!("{s}/finish"),
            &Auth::None,
            Some(json!({ "values": all })),
            &h,
        )
        .await,
        StatusCode::OK,
        "finish",
    );
    (done, bound)
}
