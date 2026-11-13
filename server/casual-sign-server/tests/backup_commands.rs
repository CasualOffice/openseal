//! The backup and restore commands of the binary (ASVS-14, docs/65 §Backups):
//! `blobs-export` and `blobs-import` carry a store through a directory unchanged and
//! refuse altered bytes; `verify-evidence` passes on an intact database and store, and
//! names what it finds broken: a missing document blob, an altered audit event, or a role
//! that cannot see every account.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use axum::http::StatusCode;
use base64::Engine as _;
use casual_sign_store::blob::{BlobKey, BlobStore, FsBlobStore};
use common::Rls;
use common::harness::{Api, pdf};
use serde_json::json;
use sqlx::Executor;

fn scratch(test: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("backup-commands")
        .join(format!("{test}-{}", uuid::Uuid::now_v7().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run the server binary with only the variables given (no S3 or database settings
/// leak in from the environment running the tests).
fn run(args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_casual-sign-server"));
    cmd.env_clear().args(args);
    if let Ok(path) = std::env::var("PATH") {
        cmd.env("PATH", path);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

/// Run SQL as the superuser.
async fn admin(api: &Api, sql: &str) {
    api.db
        .admin
        .execute(sqlx::raw_sql(sqlx::AssertSqlSafe(sql.to_owned())))
        .await
        .unwrap();
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blobs_export_then_import_carries_every_blob_and_refuses_altered_bytes() {
    let src = scratch("src");
    let store = FsBlobStore::new(&src).unwrap();
    let mut keys = Vec::new();
    for i in 0..3 {
        keys.push(store.put(format!("%PDF-1.7 {i}").as_bytes()).await.unwrap());
    }
    let out = scratch("out").join("blobs");
    let out_s = out.to_str().unwrap();
    let o = run(
        &["blobs-export", out_s],
        &[("OPENSEAL_BLOB_DIR", src.to_str().unwrap())],
    );
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(stdout(&o).trim(), "blobs exported=3 present=0 ignored=0");

    let dst = scratch("dst");
    let o = run(
        &["blobs-import", out_s],
        &[("OPENSEAL_BLOB_DIR", dst.to_str().unwrap())],
    );
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(stdout(&o).trim(), "blobs imported=3");
    let restored = FsBlobStore::new(&dst).unwrap();
    for k in &keys {
        assert_eq!(restored.get(k).await.unwrap(), store.get(k).await.unwrap());
    }

    // One flipped byte in the copy: the import fails and says why.
    let file = out.join(keys[0].hex());
    let mut bytes = std::fs::read(&file).unwrap();
    bytes[3] ^= 0x20;
    std::fs::write(&file, &bytes).unwrap();
    let o = run(
        &["blobs-import", out_s],
        &[("OPENSEAL_BLOB_DIR", scratch("dst2").to_str().unwrap())],
    );
    assert!(!o.status.success());
    assert!(stderr(&o).contains("CS-BLOB-0003"), "{}", stderr(&o));

    let o = run(
        &["blobs-export"],
        &[("OPENSEAL_BLOB_DIR", src.to_str().unwrap())],
    );
    assert!(!o.status.success());
    assert!(stderr(&o).contains("usage"), "{}", stderr(&o));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verify_evidence_passes_on_an_intact_install_and_names_what_is_broken() {
    let Some(api) = Api::new("verify_evidence_command", Rls::On).await else {
        return;
    };
    let t = api.tenant("alpha").await;
    let doc = pdf(1);
    let e = api
        .call("POST", "/api/v1/envelopes", &t.auth, Some(json!({
            "subject": "Backed up", "status": "sent",
            "documents": [{"name": "b.pdf", "content_base64": base64::engine::general_purpose::STANDARD.encode(&doc)}],
            "recipients": [{"ref": "s", "type": "signer", "name": "Bea", "email": "bea@example.test"}],
            "fields": [{"recipient": "s", "document": 0, "type": "signature", "page": 1, "x": 10, "y": 10, "width": 100, "height": 30, "required": true}],
        })), &[])
        .await;
    assert_eq!(e.status, StatusCode::CREATED, "{:?}", e.json());
    let envelope = e.json()["id"].as_str().unwrap().to_owned();
    let owner = api.db.owner_url();
    let blob_dir = api.blob_dir.to_str().unwrap().to_owned();
    let env = [
        ("OPENSEAL_MIGRATE_DATABASE_URL", owner.as_str()),
        ("OPENSEAL_BLOB_DIR", blob_dir.as_str()),
    ];

    let o = run(&["verify-evidence"], &env);
    assert!(o.status.success(), "{}", stderr(&o));
    let line = stdout(&o);
    assert!(
        line.starts_with("evidence verified: envelopes=1 "),
        "{line}"
    );
    assert!(line.contains(" workspaces=1 "), "{line}");
    assert!(!line.contains(" blobs=0"), "{line}");
    assert!(line.contains(" operator_events=0"), "{line}");

    // As the application role it would see nothing: refused, not "verified".
    let app = api.db.app_url();
    let o = run(
        &["verify-evidence"],
        &[
            ("OPENSEAL_MIGRATE_DATABASE_URL", app.as_str()),
            ("OPENSEAL_BLOB_DIR", blob_dir.as_str()),
        ],
    );
    assert!(!o.status.success());
    assert!(stderr(&o).contains("CS-DB-0015"), "{}", stderr(&o));

    // A document blob the restore did not bring back.
    let keys: Vec<Vec<u8>> = sqlx::query_scalar("SELECT sha256 FROM document_versions")
        .fetch_all(&api.db.admin)
        .await
        .unwrap();
    let key = BlobKey(keys[0].clone().try_into().unwrap());
    let hex = key.hex();
    let path = api.blob_dir.join(&hex[..2]).join(&hex[2..4]).join(&hex);
    let moved = path.with_extension("moved");
    std::fs::rename(&path, &moved).unwrap();
    let o = run(&["verify-evidence"], &env);
    assert!(!o.status.success());
    assert!(
        stderr(&o).contains("CS-BLOB-0002") && stderr(&o).contains(&hex),
        "{}",
        stderr(&o)
    );
    std::fs::rename(&moved, &path).unwrap();

    // Every blob the evidence names, not only the documents (`ASVS-14` review finding
    // 2): an adopted signature's capture and the image it names, and the certificate of
    // completion. Each missing one fails, naming its key.
    let blobs = FsBlobStore::new(&api.blob_dir).unwrap();
    let image = BlobKey::of(b"\x89PNG drill signature image");
    let capture = blobs
        .put(format!(r#"{{"kind":"image","image":"{}"}}"#, image.hex()).as_bytes())
        .await
        .unwrap();
    let recipient: uuid::Uuid = sqlx::query_scalar("SELECT id FROM recipients LIMIT 1")
        .fetch_one(&api.db.admin)
        .await
        .unwrap();
    admin(
        &api,
        &format!(
            "INSERT INTO signature_adoptions (id, account_id, recipient_id, mark, method, image_sha256, adopted_at) \
             SELECT gen_random_uuid(), account_id, id, 'signature', 'draw', '\\x{}', now() \
             FROM recipients WHERE id = '{recipient}'",
            capture.hex()
        ),
    )
    .await;
    let o = run(&["verify-evidence"], &env);
    assert!(!o.status.success(), "{}", stdout(&o));
    assert!(
        stderr(&o).contains("CS-BLOB-0002") && stderr(&o).contains(&image.hex()),
        "{}",
        stderr(&o)
    );
    assert_eq!(
        blobs.put(b"\x89PNG drill signature image").await.unwrap(),
        image
    );
    let o = run(&["verify-evidence"], &env);
    assert!(o.status.success(), "{}", stderr(&o));
    let named = |line: &str, key: &str| -> u64 {
        let at = line.find(&format!(" {key}=")).unwrap() + key.len() + 2;
        line[at..]
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap()
    };
    assert_eq!(
        named(&stdout(&o), "blobs"),
        named(&line, "blobs") + 2,
        "{}",
        stdout(&o)
    );
    // A drawn capture names no image and verifies; a capture the seal job could not read
    // fails, naming it.
    let adopt = |capture: BlobKey| {
        format!(
            "INSERT INTO signature_adoptions (id, account_id, recipient_id, mark, method, image_sha256, adopted_at) \
             SELECT gen_random_uuid(), account_id, id, 'initials', 'draw', '\\x{}', now() \
             FROM recipients WHERE id = '{recipient}'",
            capture.hex()
        )
    };
    let drawn = blobs
        .put(br#"{"kind":"drawn","strokes":[[[0,1],[2,3]]]}"#)
        .await
        .unwrap();
    admin(&api, &adopt(drawn)).await;
    let o = run(&["verify-evidence"], &env);
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(
        named(&stdout(&o), "blobs"),
        named(&line, "blobs") + 3,
        "{}",
        stdout(&o)
    );
    let bad = blobs.put(br#"{"kind":"strokes"}"#).await.unwrap();
    admin(&api, &adopt(bad)).await;
    let o = run(&["verify-evidence"], &env);
    assert!(!o.status.success());
    assert!(
        stderr(&o).contains("CS-WRK-0016") && stderr(&o).contains(&bad.hex()),
        "{}",
        stderr(&o)
    );
    admin(
        &api,
        &format!(
            "ALTER TABLE signature_adoptions DISABLE TRIGGER USER; \
             DELETE FROM signature_adoptions WHERE image_sha256 = '\\x{}'; \
             ALTER TABLE signature_adoptions ENABLE TRIGGER USER",
            bad.hex()
        ),
    )
    .await;

    let certificate = BlobKey::of(b"a certificate the restore lost");
    admin(
        &api,
        &format!(
            "ALTER TABLE envelopes DISABLE TRIGGER USER; \
             UPDATE envelopes SET certificate_sha256 = '\\x{}' WHERE id = '{envelope}'; \
             ALTER TABLE envelopes ENABLE TRIGGER USER",
            certificate.hex()
        ),
    )
    .await;
    let o = run(&["verify-evidence"], &env);
    assert!(!o.status.success());
    assert!(
        stderr(&o).contains("CS-BLOB-0002") && stderr(&o).contains(&certificate.hex()),
        "{}",
        stderr(&o)
    );
    admin(
        &api,
        &format!(
            "ALTER TABLE envelopes DISABLE TRIGGER USER; \
             UPDATE envelopes SET certificate_sha256 = NULL WHERE id = '{envelope}'; \
             ALTER TABLE envelopes ENABLE TRIGGER USER"
        ),
    )
    .await;

    // The operator log (platform.operator_events) is verified too (review finding 6): a
    // stored head that no event produced fails it.
    admin(
        &api,
        &format!(
            "ALTER TABLE platform.operator_chain DISABLE TRIGGER USER; \
             UPDATE platform.operator_chain SET seq = 0, head = '\\x{}'; \
             ALTER TABLE platform.operator_chain ENABLE TRIGGER USER",
            "ab".repeat(32)
        ),
    )
    .await;
    let o = run(&["verify-evidence"], &env);
    assert!(!o.status.success());
    assert!(stderr(&o).contains("CS-CON-0007"), "{}", stderr(&o));
    admin(
        &api,
        "ALTER TABLE platform.operator_chain DISABLE TRIGGER USER; \
         UPDATE platform.operator_chain SET seq = NULL, head = NULL; \
         ALTER TABLE platform.operator_chain ENABLE TRIGGER USER",
    )
    .await;
    let o = run(&["verify-evidence"], &env);
    assert!(o.status.success(), "{}", stderr(&o));

    // An audit event altered behind the triggers' back.
    api.db
        .admin
        .execute(sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "ALTER TABLE audit_events DISABLE TRIGGER USER; \
             UPDATE audit_events SET canonical = overlay(canonical placing '\\x20' from 2 for 1) \
             WHERE envelope_id = '{envelope}' AND seq = 0; \
             ALTER TABLE audit_events ENABLE TRIGGER USER"
        ))))
        .await
        .unwrap();
    let o = run(&["verify-evidence"], &env);
    assert!(!o.status.success());
    assert!(
        stderr(&o).contains("CS-DB-0005") && stderr(&o).contains(&envelope),
        "{}",
        stderr(&o)
    );
}
