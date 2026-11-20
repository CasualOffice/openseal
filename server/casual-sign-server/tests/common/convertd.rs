//! A fake conversion daemon (ADR-042, `VS-06C`) speaking convertd's wire protocol on a
//! Unix socket in the temporary directory: it answers a two-page PDF (with one external
//! reference) for any `.docx`, and `CS-CNV-0004` for one carrying `vbaProject`. The real
//! converter is tested in `casual-sign-convertd`'s own tests; here the server's handling
//! of its answers is.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use casual_sign_convertd::wire::{Converted, MAX_INPUT, write_answer};
use casual_sign_convertd::{Client, ConvertError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

use super::harness::pdf;

static N: AtomicU32 = AtomicU32::new(0);

/// The PDF the fake answers for every convertible document.
pub fn converted_pdf() -> Vec<u8> {
    pdf(2)
}

/// Start a fake convertd; its socket path.
pub async fn fake_convertd() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "fake-convertd-{}-{}.sock",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&path);
    let l = UnixListener::bind(&path).unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut h = [0u8; 10];
                if s.read_exact(&mut h).await.is_err() {
                    return;
                }
                let len = u32::from_be_bytes([h[6], h[7], h[8], h[9]]) as usize;
                assert!(len <= MAX_INPUT);
                let mut body = vec![0u8; len];
                if s.read_exact(&mut body).await.is_err() {
                    return;
                }
                let answer = if body.windows(10).any(|w| w == b"vbaProject") {
                    Err(ConvertError::Macros)
                } else {
                    Ok(Converted {
                        pdf: converted_pdf(),
                        external_refs: 1,
                    })
                };
                let mut out = Vec::new();
                write_answer(&mut out, &answer).unwrap();
                let _ = s.write_all(&out).await;
            });
        }
    });
    path
}

/// A client of a fresh fake convertd.
pub async fn fake_converter() -> Client {
    Client::new(fake_convertd().await)
}

/// Bytes the server takes for a Word document (a ZIP's signature); the fake converts
/// anything.
pub fn docx() -> Vec<u8> {
    b"PK\x03\x04 a Word document, as far as the server can tell".to_vec()
}

/// A Word document the fake refuses as macro-enabled.
pub fn docm() -> Vec<u8> {
    b"PK\x03\x04 word/vbaProject.bin".to_vec()
}
