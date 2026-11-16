//! Malware scanning of uploads (ASVS-11, ASVS 12.4.2; docs/07 `SEC-P17`, docs/65
//! §Malware scanning).
//!
//! Every uploaded file (an envelope's or a template's document, a signer's attachment,
//! an adopted signature image, a staff user's saved mark) is streamed to ClamAV's
//! `clamd`, running in its own container, before anything else reads it and before
//! anything of it is stored.
//!
//! - **The protocol** is `clamd`'s `INSTREAM` over TCP: `zINSTREAM\0`, the bytes in
//!   chunks each prefixed by its length as a 4-byte big-endian number, a zero length to
//!   end, then one NUL-terminated answer: `stream: OK`, `stream: <signature> FOUND`, or
//!   `<message> ERROR` (`INSTREAM size limit exceeded. ERROR` past `StreamMaxLength`).
//!   It is small enough to write here; no maintained crate was worth a dependency.
//! - **Bounded.** At most [`ScannerConfig::max_bytes`] are sent (clamd's own
//!   `StreamMaxLength`, 100 MiB by default); the whole exchange, including waiting for
//!   one of [`ScannerConfig::concurrency`] slots, has [`ScannerConfig::timeout`]; the
//!   answer is read into at most [`MAX_REPLY`] bytes and a signature name kept to
//!   [`MAX_SIGNATURE`] printable characters.
//! - **Fail closed.** A scan that does not complete (no connection, timeout, a file
//!   larger than the scanner takes, a `clamd` error, an answer that is not one of the
//!   three) refuses the upload with `503 CS-SCAN-0002`, unless the operator set the
//!   fail-open switch, which admits it unscanned. Malware is always refused, `422
//!   CS-SCAN-0001`.
//! - **Recorded.** A refusal, and an upload admitted unscanned, append an admin event to
//!   the workspace's hash-chained admin log in a transaction of their own
//!   (`upload.malware_refused`, `upload.unscanned_refused`, `upload.unscanned_admitted`),
//!   with the upload's kind, the ids it was for, its SHA-256 and length; a clean
//!   document's admission report says `"malware_scan": "clean"`, and the envelope's
//!   chain binds the report's hash.
//! - **Nothing personal in logs**: a log line names the code, the kind, the signature or
//!   reason, and the request id.
//!
//! Without a configured scanner (`OPENSEAL_CLAMD_ADDR` unset), nothing is scanned and
//! the server says so once at start.

use std::time::Duration;

use casual_sign_store::{AccountId, AdminActor, ScreenedUpload, UploadKind, UploadScreening};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::error::ApiError;
use crate::state::AppState;

/// Longest answer read from `clamd`, in bytes.
pub const MAX_REPLY: usize = 1024;

/// Longest signature name kept, in characters.
pub const MAX_SIGNATURE: usize = 128;

/// Bytes per `INSTREAM` chunk.
const CHUNK: usize = 64 * 1024;

/// Default for [`ScannerConfig::max_bytes`]: `clamd`'s default `StreamMaxLength`.
pub const DEFAULT_MAX_BYTES: usize = 100 * 1024 * 1024;

/// Default for [`ScannerConfig::timeout`].
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// Default for [`ScannerConfig::concurrency`].
pub const DEFAULT_CONCURRENCY: usize = 4;

/// How to reach `clamd` and how far to trust it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerConfig {
    /// `clamd`'s TCP address, `host:port`.
    pub addr: String,
    /// The most time one scan may take, waiting for a slot included.
    pub timeout: Duration,
    /// The largest file sent; a larger one is not scanned (`too_large`). Keep it at
    /// most `clamd`'s `StreamMaxLength` and at least the largest upload the server
    /// takes.
    pub max_bytes: usize,
    /// Scans at once; further uploads wait for a slot within their timeout.
    pub concurrency: usize,
    /// Admit an upload the scanner could not judge (recorded as
    /// `upload.unscanned_admitted`) instead of refusing it. Off by default.
    pub fail_open: bool,
}

impl ScannerConfig {
    /// A configuration for `addr` with the defaults: 60 s, 100 MiB, 4 at once, fail
    /// closed.
    #[must_use]
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            timeout: DEFAULT_TIMEOUT,
            max_bytes: DEFAULT_MAX_BYTES,
            concurrency: DEFAULT_CONCURRENCY,
            fail_open: false,
        }
    }

    /// The configuration the `OPENSEAL_CLAMD_*` variables describe, read through `var`
    /// (an unset or empty variable is `None`): `None` when `OPENSEAL_CLAMD_ADDR` is not
    /// set. `max_upload` is the largest upload the server takes, which the scanner
    /// must accept.
    ///
    /// # Errors
    ///
    /// A message naming the variable that is not valid.
    pub fn from_vars(
        var: impl Fn(&str) -> Option<String>,
        max_upload: usize,
    ) -> Result<Option<Self>, String> {
        let get = |n: &str| var(n).filter(|v| !v.trim().is_empty());
        let Some(addr) = get("OPENSEAL_CLAMD_ADDR") else {
            return Ok(None);
        };
        let addr = addr.trim().to_owned();
        let port_ok = addr
            .rsplit_once(':')
            .is_some_and(|(h, p)| !h.is_empty() && p.parse::<u16>().is_ok_and(|p| p != 0));
        if !port_ok {
            return Err("OPENSEAL_CLAMD_ADDR: not host:port".into());
        }
        let mut c = Self::new(addr);
        let num = |n: &str, lo: u64, hi: u64| -> Result<Option<u64>, String> {
            get(n)
                .map(|v| {
                    v.trim()
                        .parse::<u64>()
                        .ok()
                        .filter(|x| (lo..=hi).contains(x))
                        .ok_or_else(|| format!("{n}: not a whole number from {lo} to {hi}"))
                })
                .transpose()
        };
        if let Some(s) = num("OPENSEAL_CLAMD_TIMEOUT_SECS", 1, 600)? {
            c.timeout = Duration::from_secs(s);
        }
        if let Some(b) = num("OPENSEAL_CLAMD_MAX_BYTES", 1, 4 * 1024 * 1024 * 1024)? {
            c.max_bytes = usize::try_from(b).map_err(|_| "OPENSEAL_CLAMD_MAX_BYTES: too large")?;
        }
        if c.max_bytes < max_upload {
            return Err(format!(
                "OPENSEAL_CLAMD_MAX_BYTES: {} is less than the largest upload, {max_upload}",
                c.max_bytes
            ));
        }
        if let Some(n) = num("OPENSEAL_CLAMD_CONCURRENCY", 1, 64)? {
            c.concurrency = usize::try_from(n).unwrap_or(DEFAULT_CONCURRENCY);
        }
        c.fail_open = match get("OPENSEAL_CLAMD_FAIL_OPEN").as_deref().map(str::trim) {
            None | Some("0") => false,
            Some("1") => true,
            Some(_) => return Err("OPENSEAL_CLAMD_FAIL_OPEN: not 0 or 1".into()),
        };
        Ok(Some(c))
    }
}

/// What the scanner said of a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Nothing found.
    Clean,
    /// Malware, by the scanner's signature name.
    Infected(String),
}

/// Why a scan did not complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unscanned {
    /// `clamd` could not be reached, or the connection broke.
    Connect,
    /// The scan, waiting for a slot included, took longer than the timeout.
    Timeout,
    /// The file is larger than the scanner takes.
    TooLarge,
    /// `clamd` answered an error.
    Error,
    /// `clamd` answered something that is not one of its answers.
    Protocol,
}

impl Unscanned {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Timeout => "timeout",
            Self::TooLarge => "too_large",
            Self::Error => "error",
            Self::Protocol => "protocol",
        }
    }
}

/// A `clamd` client.
#[derive(Debug)]
pub struct Scanner {
    config: ScannerConfig,
    slots: Semaphore,
}

impl Scanner {
    /// A client for `config`.
    #[must_use]
    pub fn new(config: ScannerConfig) -> Self {
        let slots = Semaphore::new(config.concurrency.max(1));
        Self { config, slots }
    }

    /// Its configuration.
    #[must_use]
    pub fn config(&self) -> &ScannerConfig {
        &self.config
    }

    /// Whether `clamd` answers `PING` with `PONG` within the timeout (the start-up
    /// check; a scan never depends on it).
    pub async fn ping(&self) -> bool {
        let exchange = async {
            let mut s = TcpStream::connect(&self.config.addr).await.ok()?;
            s.write_all(b"zPING\0").await.ok()?;
            let reply = read_reply(&mut s).await.ok()?;
            Some(reply == b"PONG")
        };
        matches!(
            tokio::time::timeout(self.config.timeout, exchange).await,
            Ok(Some(true))
        )
    }

    /// Scan `bytes`.
    pub(crate) async fn scan(&self, bytes: &[u8]) -> Result<Verdict, Unscanned> {
        if bytes.len() > self.config.max_bytes {
            return Err(Unscanned::TooLarge);
        }
        let run = async {
            let _slot = self.slots.acquire().await.map_err(|_| Unscanned::Error)?;
            let mut s = TcpStream::connect(&self.config.addr)
                .await
                .map_err(|_| Unscanned::Connect)?;
            instream(&mut s, bytes).await
        };
        tokio::time::timeout(self.config.timeout, run)
            .await
            .unwrap_or(Err(Unscanned::Timeout))
    }
}

/// One `INSTREAM` exchange on `s`. `clamd` may answer before reading everything (past
/// its `StreamMaxLength`) and close, so the answer is read even when sending failed;
/// but a clean answer counts only when every byte was sent.
async fn instream<S>(s: &mut S, bytes: &[u8]) -> Result<Verdict, Unscanned>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let sent = send(s, bytes).await;
    let reply = read_reply(s).await;
    match (sent, reply) {
        (Ok(()), Ok(r)) => parse_reply(&r),
        (Err(()), Ok(r)) => match parse_reply(&r) {
            Ok(Verdict::Clean) => Err(Unscanned::Protocol),
            other => other,
        },
        (_, Err(e)) => Err(e),
    }
}

async fn send<S>(s: &mut S, bytes: &[u8]) -> Result<(), ()>
where
    S: AsyncWrite + Unpin,
{
    s.write_all(b"zINSTREAM\0").await.map_err(drop)?;
    for chunk in bytes.chunks(CHUNK) {
        let n = u32::try_from(chunk.len()).map_err(drop)?;
        s.write_all(&n.to_be_bytes()).await.map_err(drop)?;
        s.write_all(chunk).await.map_err(drop)?;
    }
    s.write_all(&0u32.to_be_bytes()).await.map_err(drop)?;
    s.flush().await.map_err(drop)
}

/// The answer up to its NUL (or the end of the stream), at most [`MAX_REPLY`] bytes,
/// without trailing NUL or newline.
async fn read_reply<S>(s: &mut S) -> Result<Vec<u8>, Unscanned>
where
    S: AsyncRead + Unpin,
{
    let mut out = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        let n = s.read(&mut buf).await.map_err(|_| Unscanned::Connect)?;
        let got = buf.get(..n).ok_or(Unscanned::Protocol)?;
        if n == 0 {
            break;
        }
        if let Some(end) = got.iter().position(|b| *b == 0) {
            out.extend_from_slice(got.get(..end).ok_or(Unscanned::Protocol)?);
            break;
        }
        out.extend_from_slice(got);
        if out.len() > MAX_REPLY {
            return Err(Unscanned::Protocol);
        }
    }
    if out.len() > MAX_REPLY {
        return Err(Unscanned::Protocol);
    }
    while out.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        out.pop();
    }
    if out.is_empty() {
        return Err(Unscanned::Connect);
    }
    Ok(out)
}

/// Read one `clamd` answer.
pub(crate) fn parse_reply(reply: &[u8]) -> Result<Verdict, Unscanned> {
    let text = std::str::from_utf8(reply).map_err(|_| Unscanned::Protocol)?;
    if let Some(rest) = text.strip_prefix("stream: ") {
        if rest == "OK" {
            return Ok(Verdict::Clean);
        }
        if let Some(name) = rest.strip_suffix(" FOUND") {
            return Ok(Verdict::Infected(signature(name)));
        }
    }
    if text.ends_with(" ERROR") {
        return Err(if text.contains("size limit exceeded") {
            Unscanned::TooLarge
        } else {
            Unscanned::Error
        });
    }
    Err(Unscanned::Protocol)
}

/// A signature name fit for a log line and the admin log: printable ASCII, at most
/// [`MAX_SIGNATURE`] characters, `unknown` when nothing is left.
fn signature(name: &str) -> String {
    let s: String = name
        .trim()
        .chars()
        .filter(|c| c.is_ascii_graphic())
        .take(MAX_SIGNATURE)
        .collect();
    if s.is_empty() { "unknown".into() } else { s }
}

/// What a document's admission report records of its scan: `None` without a scanner.
pub(crate) type ScanNote = Option<&'static str>;

/// Who uploaded, for the admin event.
pub(crate) struct Uploader {
    /// The workspace.
    pub account: AccountId,
    /// The actor (a staff user, an API client, or the server for a recipient).
    pub actor: AdminActor,
}

/// Scan an upload before anything else reads it (ASVS-11). Answers what the admission
/// report records: `None` with no scanner configured, `clean`, or `unscanned` when the
/// fail-open switch admitted a file the scanner could not judge (recorded in the admin
/// log).
///
/// # Errors
///
/// `422 CS-SCAN-0001` for malware; `503 CS-SCAN-0002` when the scan did not complete
/// and the server fails closed. Both are recorded in the admin log first.
pub(crate) async fn screen(
    st: &AppState,
    who: Uploader,
    kind: UploadKind,
    target: Vec<(&'static str, String)>,
    bytes: &[u8],
) -> Result<ScanNote, ApiError> {
    let Some(scanner) = st.scanner() else {
        return Ok(None);
    };
    let (outcome, answer) = match scanner.scan(bytes).await {
        Ok(Verdict::Clean) => return Ok(Some("clean")),
        Ok(Verdict::Infected(signature)) => {
            tracing::warn!(
                code = "CS-SCAN-0001",
                kind = kind.as_str(),
                signature = %signature,
                request_id = %crate::error::request_id().unwrap_or_default(),
                "upload refused: malware found"
            );
            (
                UploadScreening::MalwareRefused { signature },
                Err(ApiError::malware()),
            )
        }
        Err(why) => {
            let reason = why.as_str();
            let fail_open = scanner.config().fail_open;
            tracing::warn!(
                code = "CS-SCAN-0002",
                kind = kind.as_str(),
                reason,
                admitted = fail_open,
                request_id = %crate::error::request_id().unwrap_or_default(),
                "upload not scanned"
            );
            if fail_open {
                (
                    UploadScreening::UnscannedAdmitted { reason },
                    Ok(Some("unscanned")),
                )
            } else {
                (
                    UploadScreening::UnscannedRefused { reason },
                    Err(ApiError::scanner_unavailable(reason)),
                )
            }
        }
    };
    let event = ScreenedUpload {
        kind,
        target,
        sha256: crate::crypto::sha256(bytes),
        bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        outcome,
    };
    let mut tx = st.store().for_account(who.account).begin().await?;
    tx.act_as(who.actor);
    tx.record_upload_screening(&event).await?;
    tx.commit().await?;
    answer
}

#[cfg(test)]
// Tests may unwrap, index and panic (CLAUDE.md).
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// The EICAR anti-malware test file: every scanner reports it, and it is harmless.
    const EICAR: &[u8] = br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    /// How the fake `clamd` behaves.
    #[derive(Clone, Copy)]
    enum Fake {
        /// Reads the stream and judges it: EICAR found, anything else clean.
        Honest,
        /// Accepts the connection and never answers.
        Hang,
        /// Answers the size-limit error after reading `n` bytes of data, and closes.
        Limit(usize),
        /// Answers this text.
        Says(&'static [u8]),
    }

    /// A fake `clamd` on a free loopback port, serving `mode` to every connection;
    /// answers its address and a channel of the payloads it received.
    async fn fake(mode: Fake) -> (String, tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                let tx = tx.clone();
                tokio::spawn(async move {
                    let mut cmd = Vec::new();
                    while cmd.last() != Some(&0) {
                        let Ok(b) = s.read_u8().await else { return };
                        cmd.push(b);
                    }
                    if cmd == b"zPING\0" {
                        let _ = s.write_all(b"PONG\0").await;
                        return;
                    }
                    assert_eq!(cmd, b"zINSTREAM\0");
                    if let Fake::Hang = mode {
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                        return;
                    }
                    let mut data = Vec::new();
                    loop {
                        let mut len = [0u8; 4];
                        if s.read_exact(&mut len).await.is_err() {
                            return;
                        }
                        let n = u32::from_be_bytes(len) as usize;
                        if n == 0 {
                            break;
                        }
                        assert!(n <= CHUNK, "chunk of {n}");
                        let mut chunk = vec![0u8; n];
                        s.read_exact(&mut chunk).await.unwrap();
                        data.extend_from_slice(&chunk);
                        if let Fake::Limit(max) = mode
                            && data.len() > max
                        {
                            let _ = s.write_all(b"INSTREAM size limit exceeded. ERROR\0").await;
                            // Drain until the client hangs up, so closing never resets
                            // the connection before the client read the answer.
                            let _ = tokio::io::copy(&mut s, &mut tokio::io::sink()).await;
                            return;
                        }
                    }
                    let found = data.windows(EICAR.len()).any(|w| w == EICAR);
                    let _ = tx.send(data);
                    let reply: &[u8] = match mode {
                        Fake::Says(t) => t,
                        _ if found => b"stream: Eicar-Test-Signature FOUND\0",
                        _ => b"stream: OK\0",
                    };
                    let _ = s.write_all(reply).await;
                });
            }
        });
        (addr, rx)
    }

    fn scanner(addr: String) -> Scanner {
        let mut c = ScannerConfig::new(addr);
        c.timeout = Duration::from_millis(500);
        Scanner::new(c)
    }

    #[tokio::test]
    async fn eicar_is_found_and_a_clean_file_passes_in_whole_chunks() {
        let (addr, mut got) = fake(Fake::Honest).await;
        let s = scanner(addr);
        assert_eq!(
            s.scan(EICAR).await,
            Ok(Verdict::Infected("Eicar-Test-Signature".into()))
        );
        assert_eq!(got.recv().await.unwrap(), EICAR);
        // Three chunks and a bit: the framing carries every byte, in order.
        let big: Vec<u8> = (0..CHUNK * 3 + 17).map(|i| (i % 251) as u8).collect();
        assert_eq!(s.scan(&big).await, Ok(Verdict::Clean));
        assert_eq!(got.recv().await.unwrap(), big);
        assert_eq!(s.scan(b"").await, Ok(Verdict::Clean));
        assert!(s.ping().await);
    }

    #[tokio::test]
    async fn a_scanner_that_is_down_hangs_or_babbles_is_unscanned_never_clean() {
        // Nothing listens on a port just closed.
        let addr = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().to_string()
        };
        // Windows retries a refused connect for about two seconds, past the 500 ms
        // budget, so a closed port there ends as Timeout; either way it is unscanned.
        assert!(matches!(
            scanner(addr.clone()).scan(b"x").await,
            Err(Unscanned::Connect | Unscanned::Timeout)
        ));
        assert!(!scanner(addr).ping().await);
        let (addr, _rx) = fake(Fake::Hang).await;
        assert_eq!(scanner(addr).scan(b"x").await, Err(Unscanned::Timeout));
        let (addr, _rx) = fake(Fake::Says(b"stream: maybe\0")).await;
        assert_eq!(scanner(addr).scan(b"x").await, Err(Unscanned::Protocol));
        let (addr, _rx) = fake(Fake::Says(b"Can't allocate memory ERROR\0")).await;
        assert_eq!(scanner(addr).scan(b"x").await, Err(Unscanned::Error));
        let (addr, _rx) = fake(Fake::Says(&[b'A'; 2000])).await;
        assert_eq!(scanner(addr).scan(b"x").await, Err(Unscanned::Protocol));
    }

    #[tokio::test]
    async fn past_the_scanners_limit_is_too_large_on_either_side() {
        let (addr, _rx) = fake(Fake::Limit(CHUNK)).await;
        let big = vec![7u8; CHUNK * 40];
        assert_eq!(
            scanner(addr.clone()).scan(&big).await,
            Err(Unscanned::TooLarge)
        );
        let mut c = ScannerConfig::new(addr);
        c.max_bytes = 10;
        assert_eq!(
            Scanner::new(c).scan(&[0u8; 11]).await,
            Err(Unscanned::TooLarge)
        );
    }

    #[test]
    fn answers_are_read_strictly_and_names_kept_printable_and_short() {
        assert_eq!(parse_reply(b"stream: OK"), Ok(Verdict::Clean));
        assert_eq!(
            parse_reply(b"stream: Win.Test.EICAR_HDB-1 FOUND"),
            Ok(Verdict::Infected("Win.Test.EICAR_HDB-1".into()))
        );
        let long = format!("stream: {} FOUND", "A\u{7}".repeat(300));
        assert_eq!(
            parse_reply(long.as_bytes()),
            Ok(Verdict::Infected("A".repeat(MAX_SIGNATURE)))
        );
        assert_eq!(
            parse_reply(b"stream:  FOUND"),
            Ok(Verdict::Infected("unknown".into()))
        );
        for bad in [
            &b"OK"[..],
            b"stream: ok",
            b"stream: OK FOUND?",
            b"\xff\xfe",
            b"PONG",
        ] {
            assert_eq!(parse_reply(bad), Err(Unscanned::Protocol), "{bad:?}");
        }
    }

    #[test]
    fn configuration_comes_from_the_variables_and_refuses_what_cannot_work() {
        let vars = |pairs: &'static [(&'static str, &'static str)]| {
            move |n: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == n)
                    .map(|(_, v)| (*v).to_owned())
            }
        };
        let max = 50 * 1024 * 1024;
        assert_eq!(ScannerConfig::from_vars(vars(&[]), max), Ok(None));
        assert_eq!(
            ScannerConfig::from_vars(vars(&[("OPENSEAL_CLAMD_ADDR", " ")]), max),
            Ok(None)
        );
        let c = ScannerConfig::from_vars(vars(&[("OPENSEAL_CLAMD_ADDR", "clamav:3310")]), max)
            .unwrap()
            .unwrap();
        assert_eq!(c, ScannerConfig::new("clamav:3310"));
        assert!(!c.fail_open);
        let c = ScannerConfig::from_vars(
            vars(&[
                ("OPENSEAL_CLAMD_ADDR", "10.0.0.5:3310"),
                ("OPENSEAL_CLAMD_TIMEOUT_SECS", "90"),
                ("OPENSEAL_CLAMD_MAX_BYTES", "62914560"),
                ("OPENSEAL_CLAMD_CONCURRENCY", "8"),
                ("OPENSEAL_CLAMD_FAIL_OPEN", "1"),
            ]),
            max,
        )
        .unwrap()
        .unwrap();
        assert_eq!(c.timeout, Duration::from_secs(90));
        assert_eq!(c.max_bytes, 62_914_560);
        assert_eq!(c.concurrency, 8);
        assert!(c.fail_open);
        for bad in [
            &[("OPENSEAL_CLAMD_ADDR", "clamav")][..],
            &[("OPENSEAL_CLAMD_ADDR", "clamav:0")],
            &[("OPENSEAL_CLAMD_ADDR", ":3310")],
            &[
                ("OPENSEAL_CLAMD_ADDR", "c:1"),
                ("OPENSEAL_CLAMD_TIMEOUT_SECS", "0"),
            ],
            &[
                ("OPENSEAL_CLAMD_ADDR", "c:1"),
                ("OPENSEAL_CLAMD_CONCURRENCY", "x"),
            ],
            &[
                ("OPENSEAL_CLAMD_ADDR", "c:1"),
                ("OPENSEAL_CLAMD_FAIL_OPEN", "yes"),
            ],
            // Smaller than the largest upload: every large document would be refused.
            &[
                ("OPENSEAL_CLAMD_ADDR", "c:1"),
                ("OPENSEAL_CLAMD_MAX_BYTES", "1048576"),
            ],
        ] {
            assert!(ScannerConfig::from_vars(vars(bad), max).is_err(), "{bad:?}");
        }
    }
}
