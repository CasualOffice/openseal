//! ASVS-26: the binary's panic hook logs where a panic happened, never its message
//! (which may carry a value from a request). A file of its own: the hook is global.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(clippy::unwrap_used, clippy::panic)]

use std::io::Write;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<u8>>>);

impl Write for Log {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_panic_is_logged_by_place_without_its_message() {
    let log = Log::default();
    let writer = log.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    casual_sign_console::quiet_panics();
    let caught = std::panic::catch_unwind(|| panic!("secret-in-panic"));
    let _ = std::panic::take_hook();
    assert!(caught.is_err());
    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    assert!(
        text.contains("panicked") && text.contains("panic_hook.rs"),
        "{text}"
    );
    assert!(!text.contains("secret-in-panic"), "{text}");
}
