//! The S3 blob store against a real S3-compatible server named by
//! `OPENSEAL_TEST_S3_ENDPOINT` (with `OPENSEAL_TEST_S3_ACCESS_KEY` and
//! `OPENSEAL_TEST_S3_SECRET_KEY`); skipped with a note when unset.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use casual_sign_store::blob::{BlobKey, BlobStore, S3BlobStore, S3Config};

fn config(test: &str) -> Option<S3Config> {
    let Ok(endpoint) = std::env::var("OPENSEAL_TEST_S3_ENDPOINT") else {
        eprintln!(
            "SKIPPED {test}: set OPENSEAL_TEST_S3_ENDPOINT (and _ACCESS_KEY, _SECRET_KEY) to run it"
        );
        return None;
    };
    Some(S3Config {
        endpoint,
        bucket: format!("openseal-t-{}", uuid::Uuid::new_v4().simple()),
        region: "us-east-1".into(),
        access_key: std::env::var("OPENSEAL_TEST_S3_ACCESS_KEY").unwrap_or_default(),
        secret_key: std::env::var("OPENSEAL_TEST_S3_SECRET_KEY").unwrap_or_default(),
        path_style: true,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s3_put_get_exists_and_write_once() {
    let Some(cfg) = config("s3_put_get_exists_and_write_once") else {
        return;
    };
    assert!(!format!("{cfg:?}").contains(&cfg.secret_key) || cfg.secret_key.is_empty());
    let store = S3BlobStore::new(&cfg).unwrap();
    store.create_bucket().await.unwrap();
    let bytes = b"%PDF-1.7 s3 fixture".to_vec();
    let key = store.put(&bytes).await.unwrap();
    assert_eq!(key, BlobKey::of(&bytes));
    assert!(store.exists(&key).await.unwrap());
    assert_eq!(store.get(&key).await.unwrap(), bytes);
    // A second put of the same bytes succeeds with the same key.
    assert_eq!(store.put(&bytes).await.unwrap(), key);
    assert_eq!(store.get(&key).await.unwrap(), bytes);
    let missing = BlobKey::of(b"never stored");
    assert!(!store.exists(&missing).await.unwrap());
    assert_eq!(
        store.get(&missing).await.unwrap_err().code(),
        "CS-BLOB-0002"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s3_caps_and_verifies_what_it_reads() {
    let Some(cfg) = config("s3_caps_and_verifies_what_it_reads") else {
        return;
    };
    let small = S3BlobStore::with_max_bytes(&cfg, 8).unwrap();
    small.create_bucket().await.unwrap();
    assert_eq!(
        small.put(&[1u8; 9]).await.unwrap_err().code(),
        "CS-BLOB-0004"
    );
    // Store 32 bytes with a larger cap, then read them through the 8-byte one.
    let big = S3BlobStore::new(&cfg).unwrap();
    let key = big.put(&[2u8; 32]).await.unwrap();
    assert_eq!(small.get(&key).await.unwrap_err().code(), "CS-BLOB-0004");
}
