//! The seal job through keyd (docs/31 §5): the worker seals with keyd's `RemoteKey`
//! over mTLS; keyd serves a development file key, says so, and every seal then carries
//! the development `/Reason`. keyd's operation log records the signature against the
//! envelope id.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;
#[path = "../../casual-sign-keyd/tests/common/mod.rs"]
mod keyd_common;

use std::sync::Arc;
use std::time::Duration;

use casual_sign_keyd::{DEV_REASON, DevKeyConsent, DigestSigner, FileKey, KeydLimits, RemoteKey};
use casual_sign_model::EnvelopeStatus;
use casual_sign_worker::seal::{KeydKey, SealKey};
use common::Env;
use keyd_common::{Pki, endpoint, scratch, start_keyd};
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_seal_goes_through_keyd_with_the_development_reason() {
    let Some(env) = Env::new("seal_through_keyd").await else {
        return;
    };
    let pki = Pki::new();
    let dir = scratch("worker-keyd");
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = pki.signer("T-2D worker dev key", &key);
    let file_key = FileKey::load(
        DevKeyConsent::from_env_value(Some("1")).unwrap(),
        key.serialize_pem().as_bytes(),
        vec![cert, pki.seal_root()],
        None,
    )
    .unwrap();
    let worker_id = pki.client_identity("worker");
    let keyd = start_keyd(
        &pki,
        vec![("platform", Arc::new(file_key) as Arc<dyn DigestSigner>)],
        &[&worker_id.2],
        KeydLimits::default(),
        &dir,
    );
    let remote = RemoteKey::connect(endpoint(&pki, &keyd, Some(&worker_id)), "platform").unwrap();
    assert!(DigestSigner::is_development(&remote));
    *env.key.lock().unwrap() = Some(SealKey::Remote(remote));
    env.anchors
        .lock()
        .unwrap()
        .push(keyd_common::der(&pki.seal_root()));

    let ids = env.draft(vec![]).await;
    env.send(ids).await;
    env.run().await;
    env.sign(ids, ids.r1, ids.f1, "Ada Lovelace").await;
    env.run().await;
    env.sign(ids, ids.r2, ids.f2, "Grace Hopper").await;
    env.run().await;
    assert_eq!(env.state(ids.env).await.status, EnvelopeStatus::Completed);

    let sealed = env.sealed_bytes(ids.env).await;
    // /Reason is not ASCII (an em dash): written as UTF-16BE hex.
    let mut reason = String::from("<FEFF");
    for unit in DEV_REASON.encode_utf16() {
        reason.push_str(&format!("{unit:04X}"));
    }
    reason.push('>');
    assert!(
        sealed[0]
            .windows(reason.len())
            .any(|w| w == reason.as_bytes()),
        "the development reason is written"
    );
    // Verified against keyd's seal root (and the test TSA's).
    let mut trust = common::pki::trust();
    trust
        .add_anchor(&keyd_common::der(&pki.seal_root()))
        .unwrap();
    let report = env.engine.verify(
        &sealed[0],
        &trust,
        &env.engine.verify_options(Duration::from_millis(
            u64::try_from(env.clock.ms()).unwrap(),
        )),
    );
    casual_sign_worker::seal::check_verified(&report, casual_sign_sdk::Profile::BaselineT).unwrap();
    // keyd logged two signatures (the document and the standalone certificate), both
    // against the envelope.
    let log = std::fs::read_to_string(&keyd.oplog).unwrap();
    let signs: Vec<&str> = log.lines().filter(|l| l.contains("\tsign\t")).collect();
    assert_eq!(signs.len(), 2, "{log}");
    for s in &signs {
        assert!(s.contains(&ids.env.hyphenated().to_string()));
    }

    // CON-09: the worker recorded each signature's digest, as keyd logged it, in
    // `seal_signatures` with the sealed bytes, so the console can reconcile keyd's log.
    let records = casual_sign_keyd::oplog::read_range(&keyd.oplog, 1, 64, u64::MAX).unwrap();
    let mut logged: Vec<String> = records
        .iter()
        .filter(|r| r.op == "sign" && r.outcome == "ok")
        .map(|r| r.digest.clone())
        .collect();
    logged.sort();
    let mut tx = env.db.store.for_account(env.account).begin().await.unwrap();
    let recorded: Vec<String> = tx
        .seal_signatures()
        .digests(casual_sign_store::EnvelopeId(ids.env))
        .await
        .unwrap()
        .iter()
        .map(|d| d.iter().map(|b| format!("{b:02x}")).collect())
        .collect();
    tx.commit().await.unwrap();
    assert_eq!(recorded.len(), 2);
    assert_eq!(
        recorded, logged,
        "seal_signatures holds exactly keyd's digests"
    );
}

/// A development file key under the seal root, named `cn`.
fn dev_key(pki: &Pki, cn: &str) -> Arc<dyn DigestSigner> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = pki.signer(cn, &key);
    Arc::new(
        FileKey::load(
            DevKeyConsent::from_env_value(Some("1")).unwrap(),
            key.serialize_pem().as_bytes(),
            vec![cert, pki.seal_root()],
            None,
        )
        .unwrap(),
    )
}

/// keyd's `sign` records for `env`: the alias each used.
fn aliases_signed_for(oplog: &std::path::Path, env: uuid::Uuid) -> Vec<String> {
    std::fs::read_to_string(oplog)
        .unwrap()
        .lines()
        .map(|l| l.split('\t').collect::<Vec<_>>())
        .filter(|f| {
            f.get(3) == Some(&"sign") && f.get(7) == Some(&env.hyphenated().to_string().as_str())
        })
        .map(|f| f[4].to_owned())
        .collect()
}

/// `seal_signatures` holds exactly keyd's logged digests for `envelope`, under `alias`.
async fn assert_recorded(env: &Env, oplog: &std::path::Path, envelope: uuid::Uuid, alias: &str) {
    let mut logged: Vec<String> = std::fs::read_to_string(oplog)
        .unwrap()
        .lines()
        .map(|l| l.split('\t').map(str::to_owned).collect::<Vec<_>>())
        .filter(|f| {
            f.get(3).map(String::as_str) == Some("sign")
                && f.get(7) == Some(&envelope.hyphenated().to_string())
                && f.get(8).map(String::as_str) == Some("ok")
        })
        .map(|f| f[6].clone())
        .collect();
    logged.sort();
    assert!(!logged.is_empty());
    let recorded: Vec<(String, String)> = sqlx::query_as::<_, (Vec<u8>, String)>(
        "SELECT digest, alias FROM seal_signatures WHERE envelope_id = $1 ORDER BY digest",
    )
    .bind(envelope)
    .fetch_all(&env.db.admin)
    .await
    .unwrap()
    .into_iter()
    .map(|(d, a)| (d.iter().map(|b| format!("{b:02x}")).collect(), a))
    .collect();
    let expected: Vec<(String, String)> =
        logged.into_iter().map(|d| (d, alias.to_owned())).collect();
    assert_eq!(recorded, expected, "seal_signatures holds keyd's digests");
}

/// Sign `ids` through and let the worker seal (or try to).
async fn complete(env: &Env) -> common::Ids {
    let ids = env.draft(vec![]).await;
    env.send(ids).await;
    env.run().await;
    env.sign(ids, ids.r1, ids.f1, "Ada Lovelace").await;
    env.run().await;
    env.sign(ids, ids.r2, ids.f2, "Grace Hopper").await;
    env.run().await;
    ids
}

/// **Seal key rotation (`CON-10`, `HRD-06`):** the worker seals with the alias the key
/// custodians put in force (`openseal_seal_alias`, migration 0035) from its start, with
/// no restart; it refuses a version whose change is not fully approved and an alias keyd
/// does not serve, and the envelope then stays `completing` (nothing sealed with an older
/// key). Whether a version is approved is the database's verdict, tested with the
/// console (`casual-sign-console` `tests/keys.rs`); here it is stubbed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_seal_key_follows_the_approved_alias_from_its_start() {
    alias_rotation("seal_key_follows_alias", |e| {
        SealKey::Remote(RemoteKey::connect(e, "platform").unwrap())
    })
    .await;
}

/// The same rotation with the worker binary's key, connected to keyd on first use
/// (`SealKey::Keyd`, HRD-01): another alias is fetched from the same keyd per seal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_lazily_connected_keyd_key_follows_the_approved_alias_too() {
    alias_rotation("seal_keyd_follows_alias", |e| {
        SealKey::Keyd(KeydKey::new(e, "platform"))
    })
    .await;
}

async fn alias_rotation(name: &str, key: impl FnOnce(casual_sign_keyd::Endpoint) -> SealKey) {
    let Some(env) = Env::new(name).await else {
        return;
    };
    let pki = Pki::new();
    let dir = scratch(&format!("{name}-keyd"));
    let worker_id = pki.client_identity("worker");
    let keyd = start_keyd(
        &pki,
        vec![
            ("platform", dev_key(&pki, "seal 2026")),
            ("platform-2027", dev_key(&pki, "seal 2027")),
        ],
        &[&worker_id.2],
        KeydLimits::default(),
        &dir,
    );
    *env.key.lock().unwrap() = Some(key(endpoint(&pki, &keyd, Some(&worker_id))));
    env.anchors
        .lock()
        .unwrap()
        .push(keyd_common::der(&pki.seal_root()));
    // The database's verdict, stubbed from a table the test writes.
    for sql in [
        "CREATE TABLE seal_alias_stub (alias text, active_from timestamptz, approved boolean)",
        "CREATE OR REPLACE FUNCTION openseal_seal_alias(p_at timestamptz) \
         RETURNS TABLE (alias text, approval uuid, active_from timestamptz, approved boolean) \
         LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$ \
           SELECT s.alias, gen_random_uuid(), s.active_from, s.approved FROM seal_alias_stub s \
            WHERE s.active_from <= p_at ORDER BY s.active_from DESC LIMIT 1 $$",
    ] {
        sqlx::query(sql).execute(&env.db.admin).await.unwrap();
    }
    let stub = |alias: &'static str, approved: bool| {
        let at = env.clock.ms();
        let admin = env.db.admin.clone();
        async move {
            sqlx::query(
                "INSERT INTO seal_alias_stub VALUES ($1, to_timestamp($2::double precision / 1000), $3)",
            )
            .bind(alias)
            .bind(at)
            .bind(approved)
            .execute(&admin)
            .await
            .unwrap();
        }
    };

    // None set: the configured alias.
    let first = complete(&env).await;
    assert_eq!(env.state(first.env).await.status, EnvelopeStatus::Completed);
    assert_eq!(
        aliases_signed_for(&keyd.oplog, first.env),
        ["platform", "platform"]
    );

    // From its start, the new alias, with no restart.
    env.clock.advance(Duration::from_secs(60));
    stub("platform-2027", true).await;
    let second = complete(&env).await;
    assert_eq!(
        env.state(second.env).await.status,
        EnvelopeStatus::Completed
    );
    assert_eq!(
        aliases_signed_for(&keyd.oplog, second.env),
        ["platform-2027", "platform-2027"]
    );
    // CON-09: whichever key the worker holds, configured or rotated to, it recorded
    // keyd's digests for the seal under the alias that signed, for the console.
    assert_recorded(&env, &keyd.oplog, first.env, "platform").await;
    assert_recorded(&env, &keyd.oplog, second.env, "platform-2027").await;
    // The seal under the new key verifies independently (docs/04 rule 26): pyHanko over
    // it, when `OPENSEAL_VERIFY_PYTHON` names a Python with pyHanko.
    let out = scratch(&format!("{name}-pyhanko"));
    std::fs::write(
        out.join("rotated.pdf"),
        &env.sealed_bytes(second.env).await[0],
    )
    .unwrap();
    std::fs::write(
        out.join("manifest.tsv"),
        "file\texpect\twhy\nrotated.pdf\tintact\tCON-10 seal under the rotated alias\n",
    )
    .unwrap();
    std::fs::write(out.join("trust-root.pem"), pki.seal_root_pem()).unwrap();
    keyd_common::pyhanko(&out);

    // A version whose change is not fully approved: refused, nothing sealed.
    env.clock.advance(Duration::from_secs(60));
    stub("platform", false).await;
    let third = complete(&env).await;
    assert_eq!(
        env.state(third.env).await.status,
        EnvelopeStatus::Completing
    );
    assert!(aliases_signed_for(&keyd.oplog, third.env).is_empty());
    // An alias keyd does not serve: refused too.
    env.clock.advance(Duration::from_secs(60));
    stub("retired", true).await;
    let fourth = complete(&env).await;
    assert_eq!(
        env.state(fourth.env).await.status,
        EnvelopeStatus::Completing
    );
    let alerts = env.alerts.0.lock().unwrap().clone();
    for code in ["CS-CON-0006", "CS-KEY-0002"] {
        assert!(
            alerts
                .iter()
                .any(|a| a.kind == "seal_failed" && a.code == code),
            "{code}: {alerts:?}"
        );
    }
}

/// Install `key` as the database's seal token key, as the schema owner (`KEYD-02`).
async fn install_token_key(env: &Env, key: &[u8; 32]) {
    sqlx::query("SELECT openseal_keyd.set_seal_token_key($1)")
        .bind(key.as_slice())
        .execute(&env.db.admin)
        .await
        .unwrap();
}

/// keyd's `sign` outcomes for `envelope`, in order.
fn sign_outcomes(oplog: &std::path::Path, envelope: uuid::Uuid) -> Vec<String> {
    std::fs::read_to_string(oplog)
        .unwrap()
        .lines()
        .map(|l| l.split('\t').map(str::to_owned).collect::<Vec<_>>())
        .filter(|f| {
            f.get(3).map(String::as_str) == Some("sign")
                && f.get(7) == Some(&envelope.hyphenated().to_string())
        })
        .map(|f| f[8].clone())
        .collect()
}

/// **`KEYD-02` (`SEC-S05`, ADR-036): keyd, holding the seal token key, signs only for an
/// envelope the database says owes a seal.** The worker seals end to end with the token
/// the database mints for the `completing` envelope. The database mints none for an
/// envelope that is not completing (sent, or completed and sealed), and keyd refuses a
/// signature asked under that envelope's id without one (`CS-KEY-0015`, recorded), as it
/// refuses another envelope's token. The application role can neither read nor replace
/// the token key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keyd_signs_only_for_an_envelope_the_database_says_owes_a_seal() {
    let Some(env) = Env::new("keyd_seal_token").await else {
        return;
    };
    let pki = Pki::new();
    let dir = scratch("keyd-seal-token-worker");
    let worker_id = pki.client_identity("worker");
    let token_key = [0x42u8; 32];
    let keyd = keyd_common::start_keyd_full(
        &pki,
        vec![("platform", dev_key(&pki, "KEYD-02 seal"))],
        &[&worker_id.2],
        &[],
        KeydLimits::default(),
        &dir,
        None,
        Some(casual_sign_keyd::SealTokenKey::new(&token_key).unwrap()),
    );
    install_token_key(&env, &token_key).await;
    let ep = endpoint(&pki, &keyd, Some(&worker_id));
    *env.key.lock().unwrap() = Some(SealKey::Keyd(KeydKey::new(ep.clone(), "platform")));
    env.anchors
        .lock()
        .unwrap()
        .push(keyd_common::der(&pki.seal_root()));

    // The worker's normal seal, through keyd with the database's token.
    let done = complete(&env).await;
    assert_eq!(env.state(done.env).await.status, EnvelopeStatus::Completed);
    assert_eq!(sign_outcomes(&keyd.oplog, done.env), ["ok", "ok"]);
    assert_recorded(&env, &keyd.oplog, done.env, "platform").await;

    // A sent envelope and the completed one owe no seal: the database mints nothing.
    let sent = env.draft(vec![]).await;
    env.send(sent).await;
    env.run().await;
    for (id, what) in [(sent.env, "sent"), (done.env, "completed")] {
        let mut tx = env.db.store.for_account(env.account).begin().await.unwrap();
        let t = tx
            .seal_signatures()
            .seal_token(casual_sign_store::EnvelopeId(id))
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(t, None, "{what}");
    }
    // The worker's identity asking keyd directly for the sent envelope is refused, with
    // no token and with the completed envelope's, and keyd records both refusals.
    let direct = RemoteKey::connect(ep, "platform")
        .unwrap()
        .for_envelope(&sent.env.hyphenated().to_string())
        .unwrap();
    let digest = casual_sign_keyd::digest_for(DigestSigner::algorithm(&direct), b"not a seal");
    assert_eq!(
        direct.sign_digest(&digest).unwrap_err().code(),
        "CS-KEY-0015"
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let other = casual_sign_keyd::SealTokenKey::new(&token_key)
        .unwrap()
        .mint(&done.env.hyphenated().to_string(), now + 600);
    assert_eq!(
        direct
            .clone()
            .with_seal_token(other)
            .sign_digest(&digest)
            .unwrap_err()
            .code(),
        "CS-KEY-0015"
    );
    assert_eq!(
        sign_outcomes(&keyd.oplog, sent.env),
        ["CS-KEY-0015", "CS-KEY-0015"]
    );

    // The application role (the server's and the worker's) can neither read the key
    // nor replace it.
    for sql in [
        "SELECT key FROM openseal_keyd.seal_token_key",
        "SELECT openseal_keyd.set_seal_token_key('\\x00')",
    ] {
        let err = sqlx::query(sql).execute(&env.db.app).await.unwrap_err();
        let state = err.as_database_error().and_then(|e| e.code()).unwrap();
        assert_eq!(state, "42501", "{sql}");
    }
}

/// keyd holds the token key but the database does not yet: the worker seals without a
/// token, keyd refuses it (`CS-KEY-0015`), the seal fails safe (a `seal_failed` alert,
/// the envelope stays `completing`, nothing signed); once the key is installed the next
/// seal job completes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_database_without_the_token_key_seals_nothing_until_it_is_installed() {
    let Some(env) = Env::new("keyd_seal_token_missing").await else {
        return;
    };
    let pki = Pki::new();
    let dir = scratch("keyd-seal-token-missing");
    let worker_id = pki.client_identity("worker");
    let token_key = [0x24u8; 32];
    let keyd = keyd_common::start_keyd_full(
        &pki,
        vec![("platform", dev_key(&pki, "KEYD-02 missing"))],
        &[&worker_id.2],
        &[],
        KeydLimits::default(),
        &dir,
        None,
        Some(casual_sign_keyd::SealTokenKey::new(&token_key).unwrap()),
    );
    *env.key.lock().unwrap() = Some(SealKey::Remote(
        RemoteKey::connect(endpoint(&pki, &keyd, Some(&worker_id)), "platform").unwrap(),
    ));
    env.anchors
        .lock()
        .unwrap()
        .push(keyd_common::der(&pki.seal_root()));

    let ids = complete(&env).await;
    assert_eq!(env.state(ids.env).await.status, EnvelopeStatus::Completing);
    // The seal reports a key failure as `CS-SEAL-0001` (casual-sign-crypto's `KeyError`
    // carries no backend code); keyd's log and the worker's `transport.backend_failed`
    // line name `CS-KEY-0015`.
    let alerts = env.alerts.0.lock().unwrap().clone();
    assert!(
        alerts
            .iter()
            .any(|a| a.kind == "seal_failed" && a.code == "CS-SEAL-0001"),
        "{alerts:?}"
    );
    let refused = sign_outcomes(&keyd.oplog, ids.env);
    assert!(
        !refused.is_empty() && refused.iter().all(|o| o == "CS-KEY-0015"),
        "{refused:?}"
    );

    install_token_key(&env, &token_key).await;
    env.clock.advance(Duration::from_secs(61));
    env.run().await;
    assert_eq!(env.state(ids.env).await.status, EnvelopeStatus::Completed);
}
