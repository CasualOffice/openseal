//! The filesystem blob store: content-addressed, write-once, verified on read, bounded.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use std::path::PathBuf;

use casual_sign_store::blob::{BlobKey, BlobStore, FsBlobStore};

/// A fresh directory under the crate's target directory (scratch stays in the worktree).
fn scratch(test: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("blob-fs")
        .join(format!("{test}-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn final_path(root: &std::path::Path, key: &BlobKey) -> PathBuf {
    let hex = key.hex();
    root.join(&hex[..2]).join(&hex[2..4]).join(&hex)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn put_returns_the_sha256_and_get_returns_the_bytes() {
    let root = scratch("roundtrip");
    let store = FsBlobStore::new(&root).unwrap();
    let bytes = b"%PDF-1.7 fixture".to_vec();
    let key = store.put(&bytes).await.unwrap();
    assert_eq!(key, BlobKey::of(&bytes));
    assert!(store.exists(&key).await.unwrap());
    assert_eq!(store.get(&key).await.unwrap(), bytes);
    // Putting the same bytes again is a no-op with the same key.
    assert_eq!(store.put(&bytes).await.unwrap(), key);
    // Nothing is left in the temporary directory.
    assert_eq!(std::fs::read_dir(root.join("tmp")).unwrap().count(), 0);
    // The stored file is read-only.
    assert!(
        std::fs::metadata(final_path(&root, &key))
            .unwrap()
            .permissions()
            .readonly()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missing_blob_is_not_found() {
    let store = FsBlobStore::new(scratch("missing")).unwrap();
    let key = BlobKey::of(b"never stored");
    assert!(!store.exists(&key).await.unwrap());
    assert_eq!(store.get(&key).await.unwrap_err().code(), "CS-BLOB-0002");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stored_blob_is_never_replaced_and_tampering_is_caught_on_read() {
    let root = scratch("write-once");
    let store = FsBlobStore::new(&root).unwrap();
    let bytes = b"the agreement".to_vec();
    let key = BlobKey::of(&bytes);
    // Something else already sits at the key's name (tampering, or a torn earlier write).
    let path = final_path(&root, &key);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"a forgery").unwrap();
    // put does not overwrite it...
    assert_eq!(store.put(&bytes).await.unwrap(), key);
    assert_eq!(std::fs::read(&path).unwrap(), b"a forgery");
    // ...and get refuses bytes that do not hash to their key.
    assert_eq!(store.get(&key).await.unwrap_err().code(), "CS-BLOB-0003");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blobs_over_the_cap_are_refused_both_ways() {
    let root = scratch("cap");
    let store = FsBlobStore::with_max_bytes(&root, 16).unwrap();
    assert_eq!(
        store.put(&[7u8; 17]).await.unwrap_err().code(),
        "CS-BLOB-0004"
    );
    let ok = store.put(&[7u8; 16]).await.unwrap();
    assert_eq!(store.get(&ok).await.unwrap().len(), 16);
    // A file larger than the cap placed under a key is refused on read before hashing.
    let big = vec![1u8; 32];
    let key = BlobKey::of(&big);
    let path = final_path(&root, &key);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, &big).unwrap();
    assert_eq!(store.get(&key).await.unwrap_err().code(), "CS-BLOB-0004");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_writers_of_the_same_bytes_all_succeed_with_one_file() {
    let root = scratch("race");
    let store = FsBlobStore::new(&root).unwrap();
    let bytes = vec![42u8; 64 * 1024];
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let s = store.clone();
        let b = bytes.clone();
        tasks.push(tokio::spawn(async move { s.put(&b).await }));
    }
    let key = BlobKey::of(&bytes);
    for t in tasks {
        assert_eq!(t.await.unwrap().unwrap(), key);
    }
    assert_eq!(store.get(&key).await.unwrap(), bytes);
    assert_eq!(std::fs::read_dir(root.join("tmp")).unwrap().count(), 0);
}

#[tokio::test]
async fn works_on_a_current_thread_runtime() {
    // Blocking work goes to spawn_blocking, which a current-thread runtime supports.
    let store = FsBlobStore::new(scratch("current-thread")).unwrap();
    let key = store.put(b"x").await.unwrap();
    assert_eq!(store.get(&key).await.unwrap(), b"x");
}

/// Every page of `store`'s listing, joined: (keys, ignored, pages).
async fn list_all(store: &impl BlobStore) -> (Vec<BlobKey>, u64, usize) {
    let (mut keys, mut ignored, mut pages, mut after) = (Vec::new(), 0, 0, None);
    loop {
        let page = store.list(after).await.unwrap();
        keys.extend(page.keys);
        ignored += page.ignored;
        pages += 1;
        match page.next {
            Some(n) => after = Some(n),
            None => return (keys, ignored, pages),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_walks_every_key_in_order_in_pages_and_skips_what_is_not_a_blob() {
    let root = scratch("list");
    let store = FsBlobStore::new(&root).unwrap();
    let empty = store.list(None).await.unwrap();
    assert!(empty.keys.is_empty() && empty.next.is_none() && empty.ignored == 0);
    // More than one page (1000 keys a page).
    let mut want = Vec::new();
    for i in 0u32..1002 {
        want.push(store.put(&i.to_le_bytes()).await.unwrap());
    }
    want.sort();
    // Not blobs: a stray file at the root, a key filed in the wrong directory, a file
    // with a key's name that is a directory, and a write in flight in `tmp`.
    std::fs::write(root.join("README"), b"not a blob").unwrap();
    let stray = BlobKey::of(b"stray");
    let wrong = root.join("00").join("00");
    std::fs::create_dir_all(&wrong).unwrap();
    std::fs::write(wrong.join(stray.hex()), b"stray").unwrap();
    let dir_key = BlobKey::of(b"a directory");
    std::fs::create_dir_all(final_path(&root, &dir_key)).unwrap();
    std::fs::write(root.join("tmp").join("partial.1.0"), b"partial").unwrap();
    let (keys, ignored, pages) = list_all(&store).await;
    assert_eq!(keys, want);
    assert_eq!(pages, 2);
    assert_eq!(ignored, 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_store_exported_to_a_directory_imports_into_a_fresh_one_unchanged() {
    use casual_sign_store::blob::{export_to_dir, import_from_dir};
    let source = FsBlobStore::new(scratch("export-source")).unwrap();
    let mut want = Vec::new();
    for i in 0u32..5 {
        want.push(
            source
                .put(format!("%PDF-1.7 blob {i}").as_bytes())
                .await
                .unwrap(),
        );
    }
    want.sort();
    let dir = scratch("export-dir").join("blobs");
    let first = export_to_dir(&source, &dir).await.unwrap();
    assert_eq!((first.exported, first.present, first.ignored), (5, 0, 0));
    // Again into the same directory: every file is checked and kept.
    let again = export_to_dir(&source, &dir).await.unwrap();
    assert_eq!((again.exported, again.present), (0, 5));

    let target = FsBlobStore::new(scratch("import-target")).unwrap();
    let imported = import_from_dir(&target, &dir).await.unwrap();
    assert_eq!(imported.imported, 5);
    let (keys, _, _) = list_all(&target).await;
    assert_eq!(keys, want);
    for k in &want {
        assert_eq!(target.get(k).await.unwrap(), source.get(k).await.unwrap());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_import_refuses_altered_or_foreign_files_and_an_export_an_altered_one() {
    use casual_sign_store::blob::{export_to_dir, import_from_dir};
    let source = FsBlobStore::new(scratch("refuse-source")).unwrap();
    let key = source.put(b"%PDF-1.7 the sealed bytes").await.unwrap();
    let dir = scratch("refuse-dir").join("blobs");
    export_to_dir(&source, &dir).await.unwrap();
    let file = dir.join(key.hex());

    // One byte changed: refused, and nothing is put.
    let mut bytes = std::fs::read(&file).unwrap();
    bytes[0] ^= 1;
    std::fs::write(&file, &bytes).unwrap();
    let target = FsBlobStore::new(scratch("refuse-target")).unwrap();
    let err = import_from_dir(&target, &dir).await.unwrap_err();
    assert_eq!(err.code(), "CS-BLOB-0003");
    assert!(list_all(&target).await.0.is_empty());
    // An export finding that altered file refuses it too, rather than keeping it.
    let err = export_to_dir(&source, &dir).await.unwrap_err();
    assert_eq!(err.code(), "CS-BLOB-0003");

    // A file that is not named by a key (an interrupted copy, anything else).
    std::fs::remove_file(&file).unwrap();
    export_to_dir(&source, &dir).await.unwrap();
    std::fs::write(dir.join(format!("{}.part", key.hex())), b"partial").unwrap();
    let err = import_from_dir(&target, &dir).await.unwrap_err();
    assert_eq!(err.code(), "CS-BLOB-0005");
    assert!(list_all(&target).await.0.is_empty());
}
