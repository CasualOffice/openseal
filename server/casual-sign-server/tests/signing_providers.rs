//! `RSP-01` (ADR-046 §3.1, §3.11, §3.14): the operator's catalogue offers signing
//! providers; an account enables one and may store its own client secret, sealed with
//! AES-256-GCM and never returned; a signer may be given a remote signature type only
//! with a provider the account enabled (`422 CS-RSP-0001`), and two remote signers never
//! share a routing order (`422 CS-RSP-0007`, naming both).

#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::indexing_slicing
)]

mod common;

use axum::http::StatusCode;
use casual_sign_csc::{Catalogue, CscError, ProviderSecretsKey};
use common::Rls;
use common::flow::{b64, ok};
use common::harness::{Api, Tenant, pdf};
use serde_json::{Value, json};

const PEM: &[u8] = b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n";

fn catalogue(only_for: Option<&str>) -> Catalogue {
    let accounts = only_for.map_or(json!(["*"]), |a| json!([a]));
    let file = json!({"providers": [{
        "id": "csc-ci", "kind": "csc", "name": "CI provider",
        "base_uri": "https://csc.example.test/csc/v2",
        "authorization_endpoint": "https://csc.example.test/oauth2/authorize",
        "token_endpoint": "https://csc.example.test/oauth2/token",
        "client_id": "openseal", "client_secret_ref": "CSC_SECRET",
        "trust_anchors_file": "/anchors.pem", "accounts": accounts}]});
    Catalogue::parse(
        file.to_string().as_bytes(),
        "https://sign.example.test",
        &|_| -> Result<_, CscError> {
            Ok(Some(casual_sign_secrets::Secret::new(
                "operator".to_owned(),
            )))
        },
        &|_| Some(PEM.to_vec()),
    )
    .unwrap()
}

fn remote(r: &str, order: u32) -> Value {
    json!({"ref": r, "type": "signer", "name": format!("Signer {r}"),
        "email": format!("{r}@example.test"), "routing_order": order,
        "signature": {"type": "remote", "provider_id": "csc-ci"}})
}

fn simple(r: &str, order: u32) -> Value {
    json!({"ref": r, "type": "signer", "name": format!("Signer {r}"),
        "email": format!("{r}@example.test"), "routing_order": order})
}

async fn create(
    api: &Api,
    t: &Tenant,
    recipients: Vec<Value>,
    send: bool,
) -> common::harness::Resp {
    let fields: Vec<Value> = recipients
        .iter()
        .map(|r| {
            json!({"recipient": r["ref"], "document": 0, "type": "signature", "page": 1,
                "x": 72, "y": 100, "width": 180, "height": 40, "required": true})
        })
        .collect();
    api.call(
        "POST",
        "/api/v1/envelopes",
        &t.auth,
        Some(json!({
            "subject": "RSP-01", "status": if send { "sent" } else { "draft" },
            "documents": [{"name": "d.pdf", "content_base64": b64(&pdf(1))}],
            "recipients": recipients, "fields": fields,
        })),
        &[],
    )
    .await
}

#[tokio::test]
async fn an_account_enables_a_provider_and_its_own_secret_is_sealed() {
    let Some(api) = Api::new("signing_providers", Rls::On).await else {
        return;
    };
    api.st
        .set_signing_providers(catalogue(None), ProviderSecretsKey::new(&[9; 32]).unwrap());
    let a = api.tenant("alpha").await;

    // Offered, not yet enabled.
    let list = ok(
        api.call("GET", "/api/v1/signing-providers", &a.auth, None, &[])
            .await,
        StatusCode::OK,
        "list",
    );
    assert_eq!(
        list,
        json!({"items": [{"id": "csc-ci", "name": "CI provider", "kind": "csc", "enabled": false}]})
    );
    // A remote signer with a provider the account did not enable: 422 CS-RSP-0001.
    let r = create(&api, &a, vec![remote("s1", 1)], true).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{:?}", r.json());
    assert_eq!(r.code(), "CS-RSP-0001");
    let p = r.json()["errors"][0]["pointer"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(p.ends_with("/signature/provider_id"), "{p}");

    // Enable it, with the account's own client secret.
    let put = ok(
        api.call(
            "PUT",
            "/api/v1/signing-providers/csc-ci",
            &a.auth,
            Some(
                json!({"enabled": true, "required_qualifiers": ["eu_eidas_qes"],
                "client_secret": "account-own-secret"}),
            ),
            &[],
        )
        .await,
        StatusCode::OK,
        "put",
    );
    assert_eq!(put["own_client_secret"], true);
    assert!(!put.to_string().contains("account-own-secret"), "{put}");
    let got = ok(
        api.call(
            "GET",
            "/api/v1/signing-providers/csc-ci",
            &a.auth,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "get",
    );
    assert_eq!(got, put);
    assert_eq!(got["required_qualifiers"], json!(["eu_eidas_qes"]));
    // Another account reading the same catalogue entry sees its own settings, never
    // this account's (the id names a shared catalogue entry, not an account's object).
    let b = api.tenant("beta").await;
    let theirs = ok(
        api.call(
            "GET",
            "/api/v1/signing-providers/csc-ci",
            &b.auth,
            None,
            &[],
        )
        .await,
        StatusCode::OK,
        "another account's get",
    );
    assert_eq!(theirs["enabled"], false, "{theirs}");
    assert_eq!(theirs["own_client_secret"], false, "{theirs}");
    assert_ne!(
        theirs["required_qualifiers"],
        json!(["eu_eidas_qes"]),
        "{theirs}"
    );
    let b_list = ok(
        api.call("GET", "/api/v1/signing-providers", &b.auth, None, &[])
            .await,
        StatusCode::OK,
        "another account's list",
    );
    assert_eq!(b_list["items"][0]["enabled"], false, "{b_list}");

    // Stored sealed: never in clear, opens only bound to this account and provider.
    let sealed: Vec<u8> = sqlx::query_scalar(
        "SELECT client_secret_sealed FROM account_signing_providers WHERE provider_id = 'csc-ci'",
    )
    .fetch_one(&api.db.admin)
    .await
    .unwrap();
    assert!(!sealed.windows(18).any(|w| w == b"account-own-secret"));
    let key = ProviderSecretsKey::new(&[9; 32]).unwrap();
    let acct = a.boot.account.0;
    let opened = key
        .open(
            &sealed,
            &casual_sign_csc::sealing::client_secret_binding(acct.as_bytes(), "csc-ci"),
        )
        .unwrap();
    assert_eq!(opened, b"account-own-secret");
    let other = uuid::Uuid::now_v7();
    assert!(
        key.open(
            &sealed,
            &casual_sign_csc::sealing::client_secret_binding(other.as_bytes(), "csc-ci"),
        )
        .is_err(),
        "moved to another account's row, it does not open"
    );
    // The admin log records the change, the secret only as rotated.
    let log = ok(
        api.call("GET", "/api/v1/admin-events", &a.auth, None, &[])
            .await,
        StatusCode::OK,
        "admin log",
    );
    let text = log.to_string();
    assert!(
        text.contains("workspace.signing_provider_changed"),
        "{text}"
    );
    assert!(text.contains("rotated") && !text.contains("account-own-secret"));

    // Now a remote signer sends, and the recipient carries the type.
    let e = ok(
        create(&api, &a, vec![simple("s1", 1), remote("s2", 2)], true).await,
        StatusCode::CREATED,
        "send",
    );
    let r2 = e["recipients"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "Signer s2")
        .unwrap()
        .clone();
    assert_eq!(
        r2["signature"],
        json!({"type": "remote", "provider_id": "csc-ci"})
    );
    let r1 = e["recipients"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "Signer s1")
        .unwrap()
        .clone();
    assert_eq!(r1["signature"], Value::Null);

    // Two remote signers at one routing order: 422 CS-RSP-0007 naming both.
    let r = create(&api, &a, vec![remote("s1", 1), remote("s2", 1)], true).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{:?}", r.json());
    assert_eq!(r.code(), "CS-RSP-0007");
    let pointers: Vec<String> = r.json()["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["pointer"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(pointers.len(), 2, "{pointers:?}");
    assert!(pointers.iter().all(|p| p.starts_with("/recipients/")));
    assert_ne!(pointers[0], pointers[1]);

    // Disabled again: a new remote signer is refused, the secret can be removed.
    ok(
        api.call(
            "PUT",
            "/api/v1/signing-providers/csc-ci",
            &a.auth,
            Some(json!({"enabled": false, "client_secret": null})),
            &[],
        )
        .await,
        StatusCode::OK,
        "disable",
    );
    let r = create(&api, &a, vec![remote("s1", 1)], false).await;
    assert_eq!(r.code(), "CS-RSP-0001");
}

#[tokio::test]
async fn a_provider_not_offered_to_the_account_is_missing_and_bad_options_are_refused() {
    let Some(api) = Api::new("signing_providers_offered", Rls::On).await else {
        return;
    };
    let a = api.tenant("alpha").await;
    let b = api.tenant("bravo").await;
    api.st.set_signing_providers(
        catalogue(Some(&a.boot.account.0.to_string())),
        ProviderSecretsKey::new(&[9; 32]).unwrap(),
    );
    let list = ok(
        api.call("GET", "/api/v1/signing-providers", &b.auth, None, &[])
            .await,
        StatusCode::OK,
        "list",
    );
    assert_eq!(list, json!({"items": []}));
    for method in ["GET", "PUT"] {
        let r = api
            .call(
                method,
                "/api/v1/signing-providers/csc-ci",
                &b.auth,
                (method == "PUT").then(|| json!({"enabled": true})),
                &[],
            )
            .await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{method}");
    }
    for (body, pointer) in [
        (
            json!({"enabled": true, "session_minutes": 2}),
            "/session_minutes",
        ),
        (
            json!({"enabled": true, "required_qualifiers": ["EU QES"]}),
            "/required_qualifiers/0",
        ),
        (
            json!({"enabled": true, "client_secret": ""}),
            "/client_secret",
        ),
    ] {
        let r = api
            .call(
                "PUT",
                "/api/v1/signing-providers/csc-ci",
                &a.auth,
                Some(body),
                &[],
            )
            .await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{pointer}");
        assert_eq!(r.json()["errors"][0]["pointer"], pointer);
    }
    let r = api
        .call(
            "PUT",
            "/api/v1/signing-providers/csc-ci",
            &a.auth,
            Some(json!({"enabled": true, "pin": "1234"})),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
}
