//! The daemon: accepts one request per connection on a Unix socket and runs each
//! conversion in a fresh child process ([`crate::child`]), killed when it overruns
//! [`Limits::job_time`]. At most [`Limits::slots`] jobs run at once; a request beyond
//! them is answered `CS-CNV-0005 busy` at once, so a burst never queues unbounded work.
//!
//! The daemon itself never parses a document: it moves bytes between the socket and the
//! child, and reads the child's answer as hostile input (the same checks the client
//! makes).

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::child::CHILD_ARG;
use crate::error::{ConvertError, Reason};
use crate::wire::{
    Converted, MAX_OUTPUT, Request, read_answer, read_request, write_answer, write_convert,
    write_pong,
};

/// Default for [`Limits::job_time`].
pub const JOB_TIME: Duration = Duration::from_secs(60);
/// Default for [`Limits::address_space`]: 2 GiB.
pub const ADDRESS_SPACE: u64 = 2 << 30;
/// Default for [`Limits::cpu_seconds`].
pub const CPU_SECONDS: u64 = 60;
/// Default for [`Limits::slots`].
pub const SLOTS: usize = 2;
/// How long a caller may take to send its request.
pub const READ_TIME: Duration = Duration::from_secs(30);

/// Bounds each job runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Wall-clock time per job before its child is killed.
    pub job_time: Duration,
    /// The child's `RLIMIT_AS`, bytes (Linux).
    pub address_space: u64,
    /// The child's `RLIMIT_CPU`, seconds.
    pub cpu_seconds: u64,
    /// Jobs at once.
    pub slots: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            job_time: JOB_TIME,
            address_space: ADDRESS_SPACE,
            cpu_seconds: CPU_SECONDS,
            slots: SLOTS,
        }
    }
}

/// The conversion daemon.
#[derive(Debug, Clone)]
pub struct Daemon {
    exe: PathBuf,
    font_dir: Option<PathBuf>,
    limits: Limits,
    running: Arc<AtomicUsize>,
}

/// One job's outcome, for the log line: the code (or `ok`), the reason, the time taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    /// `ok`, or the refusal's code.
    pub code: &'static str,
    /// The refusal's reason, or empty.
    pub reason: &'static str,
    /// Milliseconds the job took.
    pub millis: u128,
}

impl Daemon {
    /// A daemon running children from `exe` (the convertd binary itself), with fonts
    /// from `font_dir` before the system's.
    #[must_use]
    pub fn new(exe: PathBuf, font_dir: Option<PathBuf>, limits: Limits) -> Self {
        Self {
            exe,
            font_dir,
            limits,
            running: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// The limits.
    #[must_use]
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Convert in a fresh child (see the module notes).
    ///
    /// # Errors
    /// The child's refusal; `CS-CNV-0003 time` when it overruns and is killed;
    /// `CS-CNV-0003 memory` when it ends without an answer (its memory limit, a signal);
    /// `CS-CNV-0005 protocol` for an answer outside the protocol.
    pub fn convert(&self, docx: Vec<u8>) -> Result<Converted, ConvertError> {
        let fonts = self
            .font_dir
            .as_ref()
            .map_or_else(|| "-".to_owned(), |d| d.to_string_lossy().into_owned());
        let mut child = Command::new(&self.exe)
            .arg(CHILD_ARG)
            .arg(self.limits.address_space.to_string())
            .arg(self.limits.cpu_seconds.to_string())
            .arg(fonts)
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ConvertError::Unavailable(Reason::Failed))?;
        let (Some(mut stdin), Some(mut stdout)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ConvertError::Unavailable(Reason::Failed));
        };
        let (tx, rx) = mpsc::channel();
        // The write and the read happen on a helper thread, so a child that stops reading
        // or never answers cannot block the daemon past the job time.
        std::thread::spawn(move || {
            let sent = write_convert(&mut stdin, &docx).is_ok();
            drop(stdin);
            let answer = if sent {
                Some(read_answer(&mut stdout))
            } else {
                None
            };
            let _ = tx.send(answer);
        });
        let got = rx.recv_timeout(self.limits.job_time);
        // Fresh per job: the child is ended whatever it answered.
        let _ = child.kill();
        let _ = child.wait();
        match got {
            Err(_) => Err(ConvertError::OverLimit(Reason::Time)),
            // The child ended without a complete answer: its memory limit, a signal, an
            // abort, or its CPU limit.
            Ok(None | Some(Err(ConvertError::Unavailable(Reason::Protocol)))) => {
                Err(ConvertError::OverLimit(Reason::Memory))
            }
            Ok(Some(Ok(Some(c)))) => Ok(c),
            Ok(Some(Ok(None))) => Err(ConvertError::Unavailable(Reason::Protocol)),
            Ok(Some(Err(e))) => Err(e),
        }
    }

    /// Answer one connection: a ping, or a conversion when a slot is free.
    pub fn handle(&self, mut s: UnixStream) -> Option<Outcome> {
        let _ = s.set_read_timeout(Some(READ_TIME));
        let _ = s.set_write_timeout(Some(READ_TIME));
        let started = Instant::now();
        let answer = match read_request(&mut s) {
            Ok(Request::Ping) => {
                let _ = write_pong(&mut s);
                return None;
            }
            Ok(Request::Convert(docx)) => match Slot::take(&self.running, self.limits.slots) {
                Some(_slot) => self.convert(docx),
                None => Err(ConvertError::Unavailable(Reason::Busy)),
            },
            Err(e) => Err(e),
        };
        let answer = match answer {
            Ok(c) if c.pdf.len() <= MAX_OUTPUT => {
                let _ = write_answer(&mut s, &Ok(c));
                Ok(())
            }
            Ok(_) => Err(ConvertError::OverLimit(Reason::Output)),
            Err(e) => Err(e),
        };
        if let Err(e) = answer {
            let _ = write_answer(&mut s, &Err(e));
        }
        let _ = s.flush();
        let millis = started.elapsed().as_millis();
        Some(match answer {
            Ok(()) => Outcome {
                code: "ok",
                reason: "",
                millis,
            },
            Err(e) => Outcome {
                code: e.code(),
                reason: e.reason().as_str(),
                millis,
            },
        })
    }

    /// Serve `listener` until it fails: a thread per connection, one log line per job
    /// on stderr (code, reason, milliseconds; never a name or content).
    ///
    /// # Errors
    /// The listener's error.
    pub fn serve(&self, listener: &UnixListener) -> std::io::Result<()> {
        loop {
            let (s, _) = listener.accept()?;
            let me = self.clone();
            std::thread::spawn(move || {
                if let Some(o) = me.handle(s) {
                    let mut err = std::io::stderr().lock();
                    let _ = writeln!(
                        err,
                        r#"{{"level":"info","target":"convertd","msg":"conversion","code":"{}","reason":"{}","ms":{}}}"#,
                        o.code, o.reason, o.millis
                    );
                }
            });
        }
    }
}

/// A taken job slot, given back when dropped.
struct Slot(Arc<AtomicUsize>);

impl Slot {
    fn take(running: &Arc<AtomicUsize>, slots: usize) -> Option<Self> {
        running
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < slots).then(|| n.saturating_add(1))
            })
            .ok()
            .map(|_| Self(Arc::clone(running)))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let _ = self
            .0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                Some(n.saturating_sub(1))
            });
    }
}

/// Whether a daemon answers a ping on `socket` within `timeout` (the health check).
#[must_use]
pub fn ping(socket: &std::path::Path, timeout: Duration) -> bool {
    let Ok(mut s) = UnixStream::connect(socket) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(timeout));
    let _ = s.set_write_timeout(Some(timeout));
    if s.write_all(&crate::wire::request_header(crate::wire::OP_PING, 0))
        .is_err()
    {
        return false;
    }
    let mut buf = Vec::new();
    let _ = s.take(64).read_to_end(&mut buf);
    matches!(read_answer(&mut buf.as_slice()), Ok(None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_are_taken_and_given_back() {
        let running = Arc::new(AtomicUsize::new(0));
        let a = Slot::take(&running, 2);
        let b = Slot::take(&running, 2);
        assert!(a.is_some() && b.is_some());
        assert!(Slot::take(&running, 2).is_none());
        drop(a);
        assert!(Slot::take(&running, 2).is_some());
        drop(b);
        assert_eq!(running.load(Ordering::Acquire), 0);
    }
}
