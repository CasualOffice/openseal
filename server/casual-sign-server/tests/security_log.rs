//! ASVS-08: the server's security event log (docs/07 §Security event log). Every kind
//! the server emits (`casual_sign_seclog::Kind::emitted_by(Server)`) is written by a
//! real request through the router, each line names the request and a principal by id
//! or keyed pseudonym, and no line carries an e-mail address, a client address in
//! clear, a password, a token or document text.

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

use std::collections::BTreeSet;
use std::time::Duration;

use axum::http::StatusCode;
use casual_sign_seclog::{Kind, Service};
use casual_sign_server::{Clock as _, MfaKey, totp};
use common::Rls;
use common::flow::{b64, invite, ok, open, sent};
use common::harness::{Api, Auth, PASSWORD, Resp, session_of, text_pdf};
use serde_json::{Value, json};

/// Text only the uploaded document holds.
const MARKER: &str = "ZEPHYRMARKER7781";
const WRONG: &str = "not the password at all";
const PEER: &str = "198.51.100.7";

fn unbase32(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => panic!("not base32"),
        };
        buf = (buf << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buf >> bits) & 0xff).unwrap());
        }
    }
    out
}

async fn login(api: &Api, email: &str, password: &str) -> Resp {
    api.call(
        "POST",
        "/api/v1/auth/login",
        &Auth::None,
        Some(json!({"email": email, "password": password})),
        &[],
    )
    .await
}

/// The security lines of `kind`.
fn of(lines: &[Value], kind: Kind) -> Vec<Value> {
    lines
        .iter()
        .filter(|l| l["event"] == "security" && l["kind"] == kind.as_str())
        .cloned()
        .collect()
}

/// Whether `s` holds something shaped like a dotted IPv4 address.
fn has_ipv4(s: &str) -> bool {
    s.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .any(|w| {
            let parts: Vec<&str> = w.split('.').collect();
            parts.len() == 4
                && parts
                    .iter()
                    .all(|p| !p.is_empty() && p.parse::<u8>().is_ok())
        })
}

#[tokio::test]
async fn every_server_security_event_is_emitted_without_personal_data() {
    let Some(api) = Api::with("security_log", Rls::On, |c| {
        c.rate.login_per_minute = 6;
    })
    .await
    else {
        return;
    };
    api.set_peer(&format!("{PEER}:50000"));
    api.st.set_mfa_key(MfaKey::new(&[7u8; 32]).unwrap());
    let t = api.tenant("seclog").await;
    let mut secrets: Vec<String> = vec![PASSWORD.into(), WRONG.into(), t.key.clone()];

    // Sign-in refused (unknown address, then a wrong password), then passed.
    assert_eq!(
        login(&api, "nobody@seclog.example.test", WRONG)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        login(&api, &t.email, WRONG).await.status,
        StatusCode::UNAUTHORIZED
    );
    let s1 = session_of(&login(&api, &t.email, PASSWORD).await);
    if let Auth::Session { cookie, csrf } = &s1 {
        secrets.push(cookie.clone());
        secrets.push(csrf.clone());
    }

    // No credential (401); a session's change without its CSRF token (403).
    let r = api
        .call("GET", "/api/v1/envelopes", &Auth::None, None, &[])
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let no_csrf = match &s1 {
        Auth::Session { cookie, .. } => Auth::Session {
            cookie: cookie.clone(),
            csrf: "wrong".into(),
        },
        a => a.clone(),
    };
    let r = api
        .call(
            "POST",
            "/api/v1/folders",
            &no_csrf,
            Some(json!({"name": "x"})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{:?}", r.json());
    let denied_request = r.headers["x-request-id"].to_str().unwrap().to_owned();

    // An administrative change (a user created), a document uploaded and read.
    let r = api
        .call(
            "POST",
            "/api/v1/users",
            &t.auth,
            Some(
                json!({"email": "member@seclog.example.test", "name": "Mem Ber",
                "profile": "sender"}),
            ),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.json());
    let e = ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            &t.auth,
            Some(json!({"subject": "Seclog", "documents": [{"name": "m.pdf",
                "content_base64": b64(&text_pdf(MARKER))}],
                "recipients": [{"ref": "s1", "type": "signer", "name": "S1",
                    "email": "s1@example.test", "routing_order": 1}],
                "fields": [{"recipient": "s1", "document": 0, "type": "text", "page": 1,
                    "x": 72, "y": 100, "width": 180, "height": 20}]})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "envelope",
    );
    let env = e["id"].as_str().unwrap().to_owned();
    let doc = e["documents"][0]["id"].as_str().unwrap().to_owned();
    let r = api
        .call(
            "GET",
            &format!("/api/v1/envelopes/{env}/documents/{doc}/content"),
            &t.auth,
            None,
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&r.body).contains(MARKER));

    // An upload refused by admission: not a PDF.
    let r = api
        .call(
            "POST",
            "/api/v1/envelopes",
            &t.auth,
            Some(json!({"subject": "Bad", "documents": [{"name": "b.pdf",
                "content_base64": b64(format!("not a pdf {MARKER}").as_bytes())}]})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{:?}", r.json());

    // The second factor: enrol and confirm, then a later session's replayed code
    // (refused, `reused`) and a fresh one.
    let r = api
        .call("POST", "/api/v1/auth/mfa/totp/enrol", &s1, None, &[])
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let seed = unbase32(r.json()["secret"].as_str().unwrap());
    let good = totp::code(&seed, totp::step_at(api.clock.now().unix_timestamp()));
    let r = api
        .call(
            "POST",
            "/api/v1/auth/mfa/totp/confirm",
            &s1,
            Some(json!({"code": good})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let s2 = session_of(&login(&api, &t.email, PASSWORD).await);
    let r = api
        .call(
            "POST",
            "/api/v1/auth/mfa/verify",
            &s2,
            Some(json!({"code": good})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    api.clock.advance(Duration::from_secs(30));
    let next = totp::code(&seed, totp::step_at(api.clock.now().unix_timestamp()));
    let r = api
        .call(
            "POST",
            "/api/v1/auth/mfa/verify",
            &s2,
            Some(json!({"code": next})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());

    // Password change refused (wrong current password) and done; sign out.
    let r = api
        .call(
            "PATCH",
            "/api/v1/users/me",
            &s2,
            Some(json!({"password": "a brand new passphrase 42", "current_password": WRONG})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{:?}", r.json());
    let r = api
        .call(
            "PATCH",
            "/api/v1/users/me",
            &s2,
            Some(json!({"password": "a brand new passphrase 42", "current_password": PASSWORD})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    secrets.push("a brand new passphrase 42".into());
    let r = api
        .call("POST", "/api/v1/auth/logout", &s2, None, &[])
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);

    // Reset asked for; a reset link and an invitation link that are not real; an OAuth
    // client that is not one.
    let r = api
        .call(
            "POST",
            "/api/v1/auth/password-reset",
            &Auth::None,
            Some(json!({"email": t.email})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    for path in [
        "/api/v1/auth/password-reset/confirm",
        "/api/v1/auth/accept-invite",
    ] {
        let r = api
            .call(
                "POST",
                path,
                &Auth::None,
                Some(json!({"token": "forged-token-value", "password": "another passphrase 77"})),
                &[],
            )
            .await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{path}");
    }
    let r = api
        .send(
            "POST",
            "/api/v1/oauth/token",
            &Auth::None,
            axum::body::Body::from(format!(
                "grant_type=client_credentials&client_id={}&client_secret=osk_forged",
                uuid::Uuid::now_v7()
            )),
            &[("content-type", "application/x-www-form-urlencoded")],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    // A recipient locked out by wrong access codes (the account allows three).
    let e = sent(&api, &t, 1, &[]).await;
    let env2 = e["id"].as_str().unwrap().to_owned();
    let rec = e["recipients"][0]["id"].as_str().unwrap().to_owned();
    let base = format!("/api/v1/envelopes/{env2}");
    let etag = api.call("GET", &base, &t.auth, None, &[]).await.etag();
    let r = api
        .call(
            "PATCH",
            &format!("{base}/recipients/{rec}"),
            &t.auth,
            Some(json!({"auth": ["access_code"], "access_code": "right-4711"})),
            &[("if-match", &etag)],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let token = invite(&api, &t, &env2, &rec).await;
    secrets.push(token.clone());
    let (_, h) = open(&api, &token).await;
    let h: Vec<(&str, &str)> = h.iter().map(|(k, v)| (*k, v.as_str())).collect();
    for _ in 0..3 {
        let r = api
            .call(
                "POST",
                &format!("/s/{token}/authenticate"),
                &Auth::None,
                Some(json!({"method": "access_code", "code": "wrong-0000"})),
                &h,
            )
            .await;
        assert_eq!(r.status, StatusCode::FORBIDDEN);
    }

    // Over the sign-in rate (6 a minute per address).
    let mut limited = false;
    for _ in 0..8 {
        if login(&api, "nobody@seclog.example.test", WRONG)
            .await
            .status
            == StatusCode::TOO_MANY_REQUESTS
        {
            limited = true;
        }
    }
    assert!(limited);

    // Every kind the server emits was emitted.
    let lines = api.security.json();
    let seen: BTreeSet<&str> = lines
        .iter()
        .filter(|l| l["event"] == "security")
        .filter_map(|l| l["kind"].as_str())
        .collect();
    let want: BTreeSet<&str> = Kind::emitted_by(Service::Server)
        .into_iter()
        .map(Kind::as_str)
        .collect();
    let missing: Vec<&&str> = want.difference(&seen).collect();
    assert!(missing.is_empty(), "not emitted: {missing:?}");

    // What the lines say.
    for l in &lines {
        assert_eq!(l["service"], "server", "{l}");
        assert!(l["ts"].is_string() && l["level"].is_string(), "{l}");
        if l["route"].is_string() {
            assert!(
                l["request_id"].is_string(),
                "a request's event names it: {l}"
            );
            assert_eq!(l["client"].as_str().unwrap().len(), 35, "{l}");
        }
    }
    let sign_in = of(&lines, Kind::SignIn);
    let failed: Vec<&Value> = sign_in
        .iter()
        .filter(|l| l["outcome"] == "failure")
        .collect();
    assert!(failed.len() >= 2);
    for f in &failed {
        assert!(
            f["principal"].as_str().unwrap().starts_with("subject:p1:"),
            "a refused sign-in names a pseudonym: {f}"
        );
    }
    // The same presented address gives the same pseudonym (attempts correlate).
    let unknown: BTreeSet<&str> = failed
        .iter()
        .filter(|f| f["code"] == "CS-AUTH-0007")
        .map(|f| f["principal"].as_str().unwrap())
        .collect();
    assert_eq!(
        unknown.len(),
        2,
        "two addresses, two pseudonyms: {unknown:?}"
    );
    let passed = sign_in.iter().find(|l| l["outcome"] == "success").unwrap();
    assert_eq!(
        passed["principal"],
        format!("user:{}", t.boot.admin),
        "{passed}"
    );
    assert_eq!(passed["account_id"], t.boot.account.to_string());
    let denied = of(&lines, Kind::Denied);
    let d = denied
        .iter()
        .find(|l| l["request_id"] == denied_request.as_str())
        .unwrap();
    assert_eq!(d["code"], "CS-AUTH-0008");
    assert_eq!(d["principal"], format!("user:{}", t.boot.admin), "{d}");
    let mfa = of(&lines, Kind::Mfa);
    assert!(
        mfa.iter()
            .any(|l| l["outcome"] == "failure" && l["reason"] == "reused"),
        "ASVS 2.8.5: {mfa:?}"
    );
    assert!(mfa.iter().any(|l| l["outcome"] == "success"));
    let read = of(&lines, Kind::DocumentRead);
    assert!(
        read.iter().any(|l| l["objects"] == json!([env, doc])),
        "{read:?}"
    );
    let lock = of(&lines, Kind::Lockout);
    assert_eq!(lock[0]["principal"], format!("recipient:{rec}"));

    // Nothing personal, secret or from the document.
    for raw in api.security.lines() {
        assert!(!raw.contains('@'), "an e-mail address: {raw}");
        assert!(!raw.contains(PEER) && !has_ipv4(&raw), "an address: {raw}");
        assert!(!raw.contains(MARKER), "document text: {raw}");
        assert!(!raw.contains("Mem Ber") && !raw.contains("Seclog"), "{raw}");
        for s in &secrets {
            assert!(!raw.contains(s.as_str()), "a secret: {raw}");
        }
    }
}

/// ASVS 8.3.5: a staff read of what analysis found in a document (the run, the
/// suggestions with their decrypted values) and of the envelope's fields (their filled
/// values) is a `data.document_read` event like a read of the document itself.
#[tokio::test]
async fn reads_of_analysis_suggestions_and_fields_are_document_reads() {
    let Some(api) = Api::with("security_log_ml_reads", Rls::On, |c| {
        c.ml_bundle = Some("bundle-test-1".into());
    })
    .await
    else {
        return;
    };
    let t = api.tenant("seclogml").await;
    sqlx::query(
        "INSERT INTO ml_entitlements (account_id, features) VALUES ($1, $2::text[]) \
         ON CONFLICT (account_id) DO UPDATE SET features = EXCLUDED.features",
    )
    .bind(t.boot.account.0)
    .bind("{ml.ocr,ml.template_matching,ml.extraction,ml.personal_data}")
    .execute(&api.db.admin)
    .await
    .unwrap();
    ok(
        api.call(
            "PATCH",
            "/api/v1/account/settings/ml",
            &t.auth,
            Some(
                json!({"ocr": true, "template_matching": true, "extraction": true,
                "personal_data": true}),
            ),
            &[],
        )
        .await,
        StatusCode::OK,
        "analysis on",
    );
    let e = ok(
        api.call(
            "POST",
            "/api/v1/envelopes",
            &t.auth,
            Some(json!({"subject": "Seclog", "documents": [{"name": "m.pdf",
                "content_base64": b64(&text_pdf(MARKER))}],
                "recipients": [{"ref": "s1", "type": "signer", "name": "S1",
                    "email": "s1@example.test", "routing_order": 1}],
                "fields": [{"recipient": "s1", "document": 0, "type": "text", "page": 1,
                    "x": 72, "y": 100, "width": 180, "height": 20}]})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "envelope",
    );
    let env = e["id"].as_str().unwrap().to_owned();
    let doc = e["documents"][0]["id"].as_str().unwrap().to_owned();
    let field = e["fields"][0]["id"].as_str().unwrap().to_owned();
    // A template's document, its analysis requested so there is one to read.
    let tpl = ok(
        api.call(
            "POST",
            "/api/v1/templates",
            &t.auth,
            Some(json!({"name": "T", "roles": [{"name": "R", "type": "signer"}]})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "template",
    );
    let tid = tpl["id"].as_str().unwrap().to_owned();
    let with = ok(
        api.call(
            "POST",
            &format!("/api/v1/templates/{tid}/documents"),
            &t.auth,
            Some(json!({"name": "t.pdf", "content_base64": b64(&text_pdf(MARKER))})),
            &[],
        )
        .await,
        StatusCode::CREATED,
        "template document",
    );
    let tdoc = with["documents"][0]["id"].as_str().unwrap().to_owned();
    let tpath = format!("/api/v1/templates/{tid}/documents/{tdoc}/analysis");
    ok(
        api.call("POST", &tpath, &t.auth, None, &[]).await,
        StatusCode::ACCEPTED,
        "template analysis",
    );
    for path in [
        format!("/api/v1/envelopes/{env}/documents/{doc}/analysis"),
        format!("/api/v1/envelopes/{env}/suggestions"),
        format!("/api/v1/envelopes/{env}/fields"),
        format!("/api/v1/envelopes/{env}/fields/{field}"),
        // The envelope itself carries every field with its value.
        format!("/api/v1/envelopes/{env}"),
        tpath.clone(),
    ] {
        let r = api.call("GET", &path, &t.auth, None, &[]).await;
        assert_eq!(r.status, StatusCode::OK, "{path}: {:?}", r.json());
    }
    let lines = api.security.json();
    let reads = of(&lines, Kind::DocumentRead);
    for (route, object) in [
        ("/api/v1/envelopes/{id}/documents/{doc}/analysis", &env),
        ("/api/v1/envelopes/{id}/suggestions", &env),
        ("/api/v1/envelopes/{id}/fields", &env),
        ("/api/v1/envelopes/{id}/fields/{f}", &env),
        ("/api/v1/envelopes/{id}", &env),
        ("/api/v1/templates/{id}/documents/{doc}/analysis", &tid),
    ] {
        assert!(
            reads
                .iter()
                .any(|l| l["route"] == route && l["objects"][0] == object.as_str()),
            "{route} not logged as a read: {reads:?}"
        );
    }
}

/// A lockout is logged only once it is recorded: when the transaction that records
/// the failed authentication does not commit, no `auth.lockout` line claims it.
#[tokio::test]
async fn a_lockout_that_does_not_commit_is_not_logged() {
    let Some(api) = Api::with("security_log_lockout_commit", Rls::On, |_| {}).await else {
        return;
    };
    let t = api.tenant("seclocklog").await;
    let e = sent(&api, &t, 1, &[]).await;
    let env = e["id"].as_str().unwrap().to_owned();
    let rec = e["recipients"][0]["id"].as_str().unwrap().to_owned();
    let base = format!("/api/v1/envelopes/{env}");
    let etag = api.call("GET", &base, &t.auth, None, &[]).await.etag();
    let r = api
        .call(
            "PATCH",
            &format!("{base}/recipients/{rec}"),
            &t.auth,
            Some(json!({"auth": ["access_code"], "access_code": "right-4711"})),
            &[("if-match", &etag)],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let token = invite(&api, &t, &env, &rec).await;
    let (_, h) = open(&api, &token).await;
    let h: Vec<(&str, &str)> = h.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let path = format!("/s/{token}/authenticate");
    let wrong = || {
        api.call(
            "POST",
            &path,
            &Auth::None,
            Some(json!({"method": "access_code", "code": "wrong-0000"})),
            &h,
        )
    };
    for _ in 0..2 {
        assert_eq!(wrong().await.status, StatusCode::FORBIDDEN);
    }
    // The third failure locks the recipient out, but its transaction cannot commit: a
    // deferred constraint trigger refuses every audit event at commit.
    for sql in [
        "CREATE FUNCTION seclog_refuse() RETURNS trigger LANGUAGE plpgsql AS \
         $$ BEGIN RAISE EXCEPTION 'refused at commit'; END $$",
        "CREATE CONSTRAINT TRIGGER seclog_refuse AFTER INSERT ON audit_events \
         DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION seclog_refuse()",
    ] {
        sqlx::query(sql).execute(&api.db.admin).await.unwrap();
    }
    let r = wrong().await;
    assert!(r.status.is_server_error(), "{}: {:?}", r.status, r.json());
    let lines = api.security.json();
    assert!(
        of(&lines, Kind::Lockout).is_empty(),
        "a lockout that never committed was logged: {lines:?}"
    );

    // Once commits pass again, the lockout is recorded and logged.
    sqlx::query("DROP TRIGGER seclog_refuse ON audit_events")
        .execute(&api.db.admin)
        .await
        .unwrap();
    assert_eq!(wrong().await.status, StatusCode::FORBIDDEN);
    let lines = api.security.json();
    let lock = of(&lines, Kind::Lockout);
    assert_eq!(lock[0]["principal"], format!("recipient:{rec}"), "{lock:?}");
}

/// `reason: reused` (the replay alert, ASVS 2.8.5) means only that: a matching code
/// whose check fails in the database is a failure without that reason.
#[tokio::test]
async fn a_database_failure_on_a_second_factor_is_not_logged_as_reused() {
    let Some(api) = Api::with("security_log_mfa_db", Rls::On, |_| {}).await else {
        return;
    };
    api.st.set_mfa_key(MfaKey::new(&[7u8; 32]).unwrap());
    let t = api.tenant("seclogmfa").await;
    let s1 = session_of(&login(&api, &t.email, PASSWORD).await);
    let r = api
        .call("POST", "/api/v1/auth/mfa/totp/enrol", &s1, None, &[])
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let seed = unbase32(r.json()["secret"].as_str().unwrap());
    let good = totp::code(&seed, totp::step_at(api.clock.now().unix_timestamp()));
    let r = api
        .call(
            "POST",
            "/api/v1/auth/mfa/totp/confirm",
            &s1,
            Some(json!({"code": good})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let s2 = session_of(&login(&api, &t.email, PASSWORD).await);
    api.clock.advance(Duration::from_secs(30));
    // The check that records the step fails in the database.
    sqlx::query(
        "CREATE OR REPLACE FUNCTION openseal_verify_own_totp(p_session_id uuid, \
         p_step bigint, p_now timestamptz) RETURNS uuid LANGUAGE plpgsql AS \
         $$ BEGIN RAISE EXCEPTION 'unavailable'; END $$",
    )
    .execute(&api.db.admin)
    .await
    .unwrap();
    let next = totp::code(&seed, totp::step_at(api.clock.now().unix_timestamp()));
    let r = api
        .call(
            "POST",
            "/api/v1/auth/mfa/verify",
            &s2,
            Some(json!({"code": next})),
            &[],
        )
        .await;
    assert!(r.status.is_server_error(), "{}: {:?}", r.status, r.json());
    let mfa = of(&api.security.json(), Kind::Mfa);
    let last = mfa.last().unwrap();
    assert_eq!(last["outcome"], "failure", "{last}");
    assert!(last["reason"].is_null(), "not a reused code: {last}");
}
