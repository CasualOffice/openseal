//! Evidence capture (docs/32 §1.5): every command's audit event carries the client's
//! address, its user agent, how the actor authenticated and a hash naming the session.
//! A forwarding header from an untrusted peer is ignored; from a configured proxy, the
//! right-most untrusted hop counts. Neither the address nor the user agent reaches the
//! logs. (The log capture needs the binary to itself: `tracing`'s per-callsite
//! interest is process-wide, so the proxy case lives in `evidence_proxy.rs`.)

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::too_many_lines
)]

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use base64::Engine as _;
use common::Rls;
use common::harness::{Api, Auth, ceremony_cookie, pdf};
use serde_json::{Value, json};

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

const UA: &str = "EvidenceBrowser/7.1 (test)";

async fn events(api: &Api, auth: &Auth, env: &str) -> Vec<Value> {
    let a = api
        .call(
            "GET",
            &format!("/api/v1/envelopes/{env}/audit"),
            auth,
            None,
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::OK);
    a.json()["items"].as_array().unwrap().clone()
}

fn context<'a>(events: &'a [Value], kind: &str) -> &'a Value {
    let e = events
        .iter()
        .rev()
        .find(|e| e["type"] == kind)
        .unwrap_or_else(|| panic!("no {kind}"));
    &e["event"]["context"]
}

async fn sent_envelope(api: &Api, auth: &Auth, headers: &[(&str, &str)]) -> (String, String) {
    let e = api
        .call("POST", "/api/v1/envelopes", auth, Some(json!({
            "subject": "Evidence", "status": "sent",
            "documents": [{"name": "e.pdf", "content_base64": base64::engine::general_purpose::STANDARD.encode(pdf(1))}],
            "recipients": [{"ref": "s", "type": "signer", "name": "Ev", "email": "ev@example.test"}],
            "fields": [{"recipient": "s", "document": 0, "type": "signature", "page": 1, "x": 10, "y": 10, "width": 100, "height": 30, "required": true}],
        })), headers)
        .await;
    assert_eq!(e.status, StatusCode::CREATED, "{:?}", e.json());
    let e = e.json();
    (
        e["id"].as_str().unwrap().to_owned(),
        e["recipients"][0]["id"].as_str().unwrap().to_owned(),
    )
}

#[tokio::test]
async fn events_record_the_peer_and_user_agent_and_ignore_spoofed_forwarding() {
    let Some(api) = Api::new("evidence_untrusted", Rls::On).await else {
        return;
    };
    let logs = Captured::default();
    let sink = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || sink.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let a = api.tenant("alpha").await;
    api.set_peer("198.51.100.23:40000");
    let spoof = [
        ("user-agent", UA),
        ("x-forwarded-for", "203.0.113.66"),
        ("forwarded", "for=203.0.113.67"),
    ];
    let (env, rec) = sent_envelope(&api, &a.auth, &spoof).await;
    let ev = events(&api, &a.auth, &env).await;
    for kind in ["envelope.created", "envelope.sent"] {
        let c = context(&ev, kind);
        assert_eq!(c["ip"], "198.51.100.23", "{kind}: {c}");
        assert_eq!(c["user_agent"], UA, "{kind}");
        assert_eq!(c["auth"], json!(["account_login"]), "{kind}");
        assert!(
            c["session"].as_str().unwrap().starts_with("sha256:"),
            "{kind}"
        );
    }

    // The ceremony: another device, another address; the link is the method.
    api.set_peer("[2001:db8::42]:443");
    let token = casual_sign_server::issue_invitation_token(
        &api.st,
        a.boot.account,
        casual_sign_store::EnvelopeId(env.parse().unwrap()),
        casual_sign_store::RecipientId(rec.parse().unwrap()),
        std::time::Duration::from_secs(3600),
    )
    .await
    .unwrap();
    let phone = "PhoneBrowser/1.0";
    let r = api
        .call(
            "POST",
            &format!("/s/{token}/session"),
            &Auth::None,
            Some(json!({})),
            &[("user-agent", phone), ("x-forwarded-for", "203.0.113.66")],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let cookie = ceremony_cookie(&r);
    let r = api
        .call(
            "POST",
            &format!("/s/{token}/decline"),
            &Auth::None,
            Some(json!({"reason": "No"})),
            &[("user-agent", phone), ("cookie", &cookie)],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let ev = events(&api, &a.auth, &env).await;
    for kind in ["recipient.delivered", "recipient.declined"] {
        let c = context(&ev, kind);
        assert_eq!(c["ip"], "2001:db8::42", "{kind}: {c}");
        assert_eq!(c["user_agent"], phone, "{kind}");
        assert_eq!(c["auth"], json!(["email_link"]), "{kind}");
        assert!(c["session"].as_str().is_some(), "{kind}");
    }

    // A download by the sender is an access event with the same evidence.
    api.set_peer("198.51.100.24:40001");
    let doc = api
        .call(
            "GET",
            &format!("/api/v1/envelopes/{env}"),
            &a.auth,
            None,
            &[],
        )
        .await
        .json()["documents"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let r = api
        .call(
            "GET",
            &format!("/api/v1/envelopes/{env}/documents/{doc}/content"),
            &a.auth,
            None,
            &[("user-agent", UA)],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let ev = events(&api, &a.auth, &env).await;
    let c = context(&ev, "document.downloaded");
    assert_eq!(c["ip"], "198.51.100.24");

    // Nothing personal in the logs: no address, no user agent, no token.
    let text = String::from_utf8_lossy(&logs.0.lock().unwrap()).into_owned();
    assert!(text.contains("request"), "logs were captured: {text}");
    for secret in [
        "198.51.100.23",
        "198.51.100.24",
        "2001:db8::42",
        "203.0.113.66",
        UA,
        phone,
        token.as_str(),
        "ev@example.test",
    ] {
        assert!(!text.contains(secret), "log carries {secret}");
    }
    api.db.drop().await;
}
