//! The conversion daemon end to end (ADR-042, docs/07 `SEC-P13`, docs/21 §DOCX
//! conversion; `VS-06C`): every hostile fixture of `fixtures/hostile/docx/` meets its
//! manifest's code through a real per-job child; a valid document converts to a PDF that
//! admission takes; external references are counted and never fetched; a job over its
//! time is killed; the daemon answers over its socket, refuses beyond its slots, and its
//! client reads the same codes.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use casual_sign_convertd::daemon::{Daemon, Limits};
use casual_sign_convertd::{Client, ConvertError, Reason};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The DOCX hostile fixtures, generated once if missing (`generate.py --docx`, under 1 s).
fn fixtures() -> PathBuf {
    let dir = repo().join("fixtures/hostile/docx");
    if !dir.join("docx_valid.docx").exists() {
        let ok = Command::new("python3")
            .args(["-I", "fixtures/tools/generate.py", "--docx"])
            .current_dir(repo())
            .status()
            .unwrap()
            .success();
        assert!(ok, "generate.py --docx failed");
    }
    dir
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(fixtures().join(name)).unwrap()
}

fn daemon(limits: Limits) -> Daemon {
    Daemon::new(
        PathBuf::from(env!("CARGO_BIN_EXE_casual-sign-convertd")),
        None,
        limits,
    )
}

fn pages(pdf: &[u8]) -> u32 {
    casual_sign_pdf::admit(pdf, &casual_sign_pdf::Limits::default(), &|| false)
        .unwrap()
        .report
        .page_count
}

#[test]
fn every_docx_fixture_meets_its_manifest_code() {
    let dir = fixtures();
    let manifest = std::fs::read_to_string(dir.join("manifest.tsv")).unwrap();
    let d = daemon(Limits::default());
    let mut checked = 0;
    for line in manifest.lines().skip(1).filter(|l| !l.trim().is_empty()) {
        let cols: Vec<&str> = line.split('\t').collect();
        let (file, code) = (cols[0], cols[2]);
        let got = d.convert(std::fs::read(dir.join(file)).unwrap());
        match (code, got) {
            ("-", Ok(c)) => assert!(c.pdf.starts_with(b"%PDF-"), "{file}"),
            ("-", Err(e)) => panic!("{file}: expected a PDF, got {e}"),
            (want, Ok(_)) => panic!("{file}: expected {want}, got a PDF"),
            (want, Err(e)) => assert_eq!(e.code(), want, "{file}: {e}"),
        }
        checked += 1;
    }
    assert_eq!(checked, 14);
}

#[test]
fn each_refusal_names_its_reason() {
    let d = daemon(Limits::default());
    for (file, want) in [
        ("docx_macro.docm", ConvertError::Macros),
        ("docx_vba_part.docx", ConvertError::Macros),
        (
            "docx_template.dotx",
            ConvertError::Unsupported(Reason::Template),
        ),
        (
            "docx_not_word.docx",
            ConvertError::Unsupported(Reason::NotWord),
        ),
        (
            "docx_encrypted.docx",
            ConvertError::Unsupported(Reason::Encrypted),
        ),
        ("docx_zip_bomb.docx", ConvertError::OverLimit(Reason::Ratio)),
        (
            "docx_part_70mib.docx",
            ConvertError::OverLimit(Reason::Part),
        ),
        (
            "docx_expanded_300mib.docx",
            ConvertError::OverLimit(Reason::Expanded),
        ),
        (
            "docx_lying_size.docx",
            ConvertError::Failed(Reason::Malformed),
        ),
        (
            "docx_entries_4097.docx",
            ConvertError::OverLimit(Reason::Entries),
        ),
        (
            "docx_pages_5001.docx",
            ConvertError::OverLimit(Reason::Pages),
        ),
        (
            "docx_malformed_xml.docx",
            ConvertError::Failed(Reason::Malformed),
        ),
    ] {
        assert_eq!(d.convert(fixture(file)).err(), Some(want), "{file}");
    }
    // Bytes that are not a ZIP at all, a PDF among them.
    assert_eq!(
        d.convert(b"%PDF-1.7\n".to_vec()).err(),
        Some(ConvertError::Unsupported(Reason::NotZip))
    );
}

#[test]
fn a_valid_document_converts_to_a_pdf_admission_takes() {
    let c = daemon(Limits::default())
        .convert(fixture("docx_valid.docx"))
        .unwrap();
    assert_eq!(c.external_refs, 0);
    assert_eq!(pages(&c.pdf), 2, "one explicit page break: two pages");
}

#[test]
fn external_references_are_counted_and_never_fetched() {
    // The fixture links a picture and a hyperlink to this address. If anything fetched
    // the picture, a connection would wait here.
    let listener = TcpListener::bind("127.0.0.1:47391").expect("port 47391 is free");
    listener.set_nonblocking(true).unwrap();
    let c = daemon(Limits::default())
        .convert(fixture("docx_external_picture.docx"))
        .unwrap();
    assert_eq!(c.external_refs, 2);
    assert!(pages(&c.pdf) >= 1);
    match listener.accept() {
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        other => panic!("something connected to the linked address: {other:?}"),
    }
}

#[test]
fn a_job_over_its_time_is_killed() {
    let d = daemon(Limits {
        job_time: Duration::from_millis(1),
        ..Limits::default()
    });
    assert_eq!(
        d.convert(fixture("docx_valid.docx")).err(),
        Some(ConvertError::OverLimit(Reason::Time))
    );
}

/// Only Linux enforces `RLIMIT_AS` (the shipped container is Linux; CI runs this).
#[cfg(target_os = "linux")]
#[test]
fn a_child_over_its_memory_ends_without_an_answer() {
    let d = daemon(Limits {
        address_space: 16 << 20,
        ..Limits::default()
    });
    assert_eq!(
        d.convert(fixture("docx_valid.docx")).err(),
        Some(ConvertError::OverLimit(Reason::Memory))
    );
}

static SOCKETS: AtomicU32 = AtomicU32::new(0);

/// A daemon serving on a fresh socket in the temporary directory.
fn serving(limits: Limits) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "convertd-{}-{}.sock",
        std::process::id(),
        SOCKETS.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    let d = daemon(limits);
    std::thread::spawn(move || d.serve(&listener));
    path
}

#[tokio::test]
async fn the_client_converts_and_reads_refusals_over_the_socket() {
    let socket = serving(Limits::default());
    let client = Client::new(&socket);
    assert!(client.ping().await);
    let c = client.convert(&fixture("docx_valid.docx")).await.unwrap();
    assert_eq!(pages(&c.pdf), 2);
    assert_eq!(
        client.convert(&fixture("docx_macro.docm")).await.err(),
        Some(ConvertError::Macros)
    );
    assert!(casual_sign_convertd::daemon::ping(
        &socket,
        Duration::from_secs(3)
    ));
    let _ = std::fs::remove_file(socket);
}

#[tokio::test]
async fn beyond_its_slots_the_daemon_answers_busy_at_once() {
    let socket = serving(Limits {
        slots: 0,
        ..Limits::default()
    });
    assert_eq!(
        Client::new(&socket)
            .convert(&fixture("docx_valid.docx"))
            .await
            .err(),
        Some(ConvertError::Unavailable(Reason::Busy))
    );
    let _ = std::fs::remove_file(socket);
}

#[tokio::test]
async fn a_missing_daemon_is_unavailable_and_a_slow_one_times_out() {
    let gone = std::env::temp_dir().join("convertd-no-such.sock");
    assert_eq!(
        Client::new(&gone).convert(b"PK\x03\x04").await.err(),
        Some(ConvertError::Unavailable(Reason::Connect))
    );
    assert!(!Client::new(&gone).ping().await);
    // A listener that accepts and never answers.
    let path = std::env::temp_dir().join(format!("convertd-silent-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let l = UnixListener::bind(&path).unwrap();
    let (keep, held) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        if let Ok((s, _)) = l.accept() {
            let _ = keep.send(s);
        }
    });
    assert_eq!(
        Client::new(&path)
            .with_timeout(Duration::from_millis(200))
            .convert(&fixture("docx_valid.docx"))
            .await
            .err(),
        Some(ConvertError::OverLimit(Reason::Time))
    );
    drop(held.recv());
    let _ = std::fs::remove_file(path);
}
