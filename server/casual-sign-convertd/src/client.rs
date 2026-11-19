//! The caller's side (the API server): one request over the daemon's Unix socket, the
//! whole exchange within a deadline. The answer is read as hostile input: lengths are
//! checked before anything is allocated and a PDF must start as one.

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::error::{ConvertError, Reason};
use crate::wire::{
    Converted, Head, MAX_INPUT, OP_CONVERT, OP_PING, looks_like_pdf, parse_head, request_header,
    rest_len,
};

/// Default for [`Client::timeout`]: the daemon's own job time (60 s) plus room to queue
/// and to move the bytes.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(90);

/// A conversion daemon reached over its Unix socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    socket: PathBuf,
    timeout: Duration,
}

const PROTOCOL: ConvertError = ConvertError::Unavailable(Reason::Protocol);
const CONNECT: ConvertError = ConvertError::Unavailable(Reason::Connect);

impl Client {
    /// A client for the daemon listening on `socket`, with [`DEFAULT_TIMEOUT`].
    #[must_use]
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// The same client with another deadline for the whole exchange.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The socket path.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// The deadline for one exchange.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Whether the daemon answers a ping within the deadline.
    pub async fn ping(&self) -> bool {
        let exchange = async {
            let mut s = UnixStream::connect(&self.socket).await.ok()?;
            s.write_all(&request_header(OP_PING, 0)).await.ok()?;
            let head = read_head(&mut s).await.ok()?;
            Some(head == Head::Pong)
        };
        matches!(
            tokio::time::timeout(self.timeout, exchange).await,
            Ok(Some(true))
        )
    }

    /// Convert a `.docx` to PDF.
    ///
    /// # Errors
    /// The daemon's refusal (`CS-CNV-0001` to `0004`); `CS-CNV-0005` when it cannot be
    /// reached (`connect`), overruns the deadline (`time`, as `CS-CNV-0003`), or answers
    /// outside the protocol (`protocol`); `CS-CNV-0003 input` for a body over
    /// [`MAX_INPUT`], refused before connecting.
    pub async fn convert(&self, docx: &[u8]) -> Result<Converted, ConvertError> {
        let len = u32::try_from(docx.len())
            .ok()
            .filter(|_| docx.len() <= MAX_INPUT)
            .ok_or(ConvertError::OverLimit(Reason::Input))?;
        let exchange = async {
            let mut s = UnixStream::connect(&self.socket)
                .await
                .map_err(|_| CONNECT)?;
            s.write_all(&request_header(OP_CONVERT, len))
                .await
                .map_err(|_| CONNECT)?;
            s.write_all(docx).await.map_err(|_| CONNECT)?;
            s.flush().await.map_err(|_| CONNECT)?;
            match read_head(&mut s).await? {
                Head::Pong => Err(PROTOCOL),
                Head::Refused(e) => Err(e),
                Head::Converted { external, len } => {
                    let mut pdf = vec![0u8; len];
                    s.read_exact(&mut pdf).await.map_err(|_| PROTOCOL)?;
                    if !looks_like_pdf(&pdf) {
                        return Err(PROTOCOL);
                    }
                    Ok(Converted {
                        pdf,
                        external_refs: external,
                    })
                }
            }
        };
        tokio::time::timeout(self.timeout, exchange)
            .await
            .unwrap_or(Err(ConvertError::OverLimit(Reason::Time)))
    }
}

async fn read_head(s: &mut UnixStream) -> Result<Head, ConvertError> {
    let mut prefix = [0u8; 6];
    s.read_exact(&mut prefix).await.map_err(|_| PROTOCOL)?;
    let mut rest = vec![0u8; rest_len(prefix)];
    s.read_exact(&mut rest).await.map_err(|_| PROTOCOL)?;
    parse_head(prefix, &rest)
}
