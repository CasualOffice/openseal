//! The caller's side (the worker's): one request per short mTLS connection to modeld.
//! Copied from keyd's `client.rs` (`server/casual-sign-keyd/src/client.rs`, stage 2E).
//!
//! This module and [`crate::wire`] are all a caller links: with
//! `default-features = false` this crate has no inference dependency (ADR-029 review
//! defect 4; `tests/feature_gate.rs`). Every answer is decoded against the request it
//! answers, so modeld cannot hand the worker a span outside its text, a page it did not
//! ask for or a vector it did not ask for.

use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};

use crate::error::ModeldError;
use crate::wire::{
    EmbedKind, Info, OcrPage, Op, PageHash, Request, Response, Span, SpanRequest, read_frame,
    write_frame,
};

/// The worker's socket timeout beyond the request's own deadline (docs/33 §3).
pub const DEADLINE_GRACE: Duration = Duration::from_secs(5);

/// TLS certificates from PEM, for rustls.
///
/// # Errors
/// `CS-ML-0001` when none parse.
pub(crate) fn tls_certificates(bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>, ModeldError> {
    let out = CertificateDer::pem_slice_iter(bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ModeldError::TlsConfig(format!("a certificate PEM block: {e}")))?;
    if out.is_empty() {
        return Err(ModeldError::TlsConfig("no CERTIFICATE block".into()));
    }
    Ok(out)
}

/// The client's TLS configuration: the CA modeld's server certificate chains to, and the
/// client certificate chain and key (PEM) modeld's allow list names. `None` for the client
/// credentials makes a client without a certificate (tests of refusal only).
///
/// # Errors
/// `CS-ML-0001` when any of them does not load.
pub fn client_tls(
    server_ca_pem: &[u8],
    client: Option<(&[u8], &[u8])>,
) -> Result<Arc<ClientConfig>, ModeldError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let tls = |e: rustls::Error| ModeldError::TlsConfig(e.to_string());
    let mut roots = RootCertStore::empty();
    for ca in tls_certificates(server_ca_pem)? {
        roots.add(ca).map_err(tls)?;
    }
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls)?
        .with_root_certificates(roots);
    let config = match client {
        Some((chain_pem, key_pem)) => {
            let key = PrivateKeyDer::from_pem_slice(key_pem)
                .map_err(|_| ModeldError::TlsConfig("the client key does not load".into()))?;
            builder
                .with_client_auth_cert(tls_certificates(chain_pem)?, key)
                .map_err(tls)?
        }
        None => builder.with_no_client_auth(),
    };
    Ok(Arc::new(config))
}

/// Where modeld is and how to reach it.
#[derive(Debug, Clone)]
pub struct Endpoint {
    /// `host:port`.
    pub addr: String,
    /// The name modeld's server certificate is checked against.
    pub server_name: String,
    /// The client TLS configuration ([`client_tls`]).
    pub tls: Arc<ClientConfig>,
    /// Connect timeout.
    pub connect_timeout: Duration,
}

/// Who a call is for and how long it may take: recorded in modeld's op log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    /// The account id (`[A-Za-z0-9._-]{1,64}`).
    pub account: String,
    /// The job id (`[A-Za-z0-9._-]{1,64}`).
    pub job: String,
    /// The deadline modeld is given; the socket waits [`DEADLINE_GRACE`] longer.
    pub deadline: Duration,
}

/// A connection-per-call client of modeld.
#[derive(Debug, Clone)]
pub struct ModelClient {
    endpoint: Endpoint,
}

fn transport(e: impl core::fmt::Display) -> ModeldError {
    ModeldError::Transport(e.to_string())
}

fn unexpected() -> ModeldError {
    ModeldError::Malformed("unexpected answer")
}

impl ModelClient {
    /// A client of the modeld at `endpoint`.
    #[must_use]
    pub fn new(endpoint: Endpoint) -> Self {
        Self { endpoint }
    }

    /// Send one request and read its answer, on a fresh mTLS connection.
    ///
    /// The request is checked against the same bounds modeld enforces before anything is
    /// sent. A `CS-ML-` error modeld answers is returned as that error.
    ///
    /// # Errors
    /// `CS-ML-0004` for a request over a bound or a malformed answer, `CS-ML-0008` when
    /// modeld cannot be reached or the handshake fails, or the code modeld answered.
    pub fn call(&self, req: &Request) -> Result<Response, ModeldError> {
        let mut session = self.session()?;
        let resp = session.exchange(req);
        session.close();
        resp
    }

    /// Open an mTLS connection that stays open across requests: a document opened on it
    /// (DOC_OPEN) can be read page by page and is closed with the connection (docs/33
    /// §3.1).
    ///
    /// # Errors
    /// `CS-ML-0008` when modeld cannot be reached or the handshake fails.
    pub fn session(&self) -> Result<Session, ModeldError> {
        let name = ServerName::try_from(self.endpoint.server_name.clone())
            .map_err(|_| ModeldError::TlsConfig("server name".into()))?;
        let addr = self
            .endpoint
            .addr
            .to_socket_addrs()
            .map_err(transport)?
            .next()
            .ok_or_else(|| transport("address does not resolve"))?;
        let sock =
            TcpStream::connect_timeout(&addr, self.endpoint.connect_timeout).map_err(transport)?;
        let conn = ClientConnection::new(self.endpoint.tls.clone(), name).map_err(transport)?;
        Ok(Session {
            stream: StreamOwned::new(conn, sock),
        })
    }

    fn request(call: &Call, op: Op) -> Request {
        Request {
            deadline_ms: u32::try_from(call.deadline.as_millis()).unwrap_or(u32::MAX),
            account: call.account.clone(),
            job: call.job.clone(),
            op,
        }
    }

    /// The installed bundle.
    ///
    /// # Errors
    /// As [`ModelClient::call`].
    pub fn info(&self, call: &Call) -> Result<Info, ModeldError> {
        match self.call(&Self::request(call, Op::Info))? {
            Response::Info(i) => Ok(i),
            _ => Err(unexpected()),
        }
    }

    /// Perceptual hashes of `pages` of `pdf`.
    ///
    /// # Errors
    /// As [`ModelClient::call`].
    pub fn hash(
        &self,
        call: &Call,
        pdf: Vec<u8>,
        pages: Vec<u16>,
    ) -> Result<Vec<PageHash>, ModeldError> {
        match self.call(&Self::request(call, Op::Hash { pdf, pages }))? {
            Response::Hash(h) => Ok(h),
            _ => Err(unexpected()),
        }
    }

    /// Embeddings of `texts`.
    ///
    /// # Errors
    /// As [`ModelClient::call`].
    pub fn embed(
        &self,
        call: &Call,
        kind: EmbedKind,
        texts: Vec<String>,
    ) -> Result<Vec<Vec<f32>>, ModeldError> {
        match self.call(&Self::request(call, Op::Embed { kind, texts }))? {
            Response::Embed(v) => Ok(v),
            _ => Err(unexpected()),
        }
    }

    /// Entity spans of `request.text`.
    ///
    /// # Errors
    /// As [`ModelClient::call`].
    pub fn entities(&self, call: &Call, request: SpanRequest) -> Result<Vec<Span>, ModeldError> {
        match self.call(&Self::request(call, Op::Entities(request)))? {
            Response::Spans(s) => Ok(s),
            _ => Err(unexpected()),
        }
    }

    /// Personal-data spans of `request.text`.
    ///
    /// # Errors
    /// As [`ModelClient::call`].
    pub fn personal(&self, call: &Call, request: SpanRequest) -> Result<Vec<Span>, ModeldError> {
        match self.call(&Self::request(call, Op::Personal(request)))? {
            Response::Spans(s) => Ok(s),
            _ => Err(unexpected()),
        }
    }
}

/// An open connection to modeld (from [`ModelClient::session`]). A document opened on it
/// lives until [`Session::close_document`] or the end of the session, never longer.
pub struct Session {
    stream: StreamOwned<ClientConnection, TcpStream>,
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session").finish_non_exhaustive()
    }
}

impl Session {
    /// Send one request on this connection and read its answer.
    ///
    /// # Errors
    /// As [`ModelClient::call`].
    pub fn exchange(&mut self, req: &Request) -> Result<Response, ModeldError> {
        let body = req.encode()?;
        Request::decode(&body)?;
        let wait = Duration::from_millis(u64::from(req.deadline_ms)).saturating_add(DEADLINE_GRACE);
        self.stream
            .sock
            .set_read_timeout(Some(wait))
            .map_err(transport)?;
        self.stream
            .sock
            .set_write_timeout(Some(wait))
            .map_err(transport)?;
        write_frame(&mut self.stream, &body)?;
        let answer = read_frame(&mut self.stream)?
            .ok_or_else(|| transport("modeld closed the connection"))?;
        match Response::decode(&answer, req)? {
            Response::Error(n) => Err(ModeldError::from_number(n)),
            ok => Ok(ok),
        }
    }

    /// Open `pdf` on this connection: its handle and page count.
    ///
    /// # Errors
    /// As [`ModelClient::call`]; `CS-ML-0006` when the PDF cannot be opened.
    pub fn open_document(&mut self, call: &Call, pdf: Vec<u8>) -> Result<(u32, u32), ModeldError> {
        match self.exchange(&ModelClient::request(call, Op::DocOpen { pdf }))? {
            Response::Opened { doc, pages } => Ok((doc, pages)),
            _ => Err(unexpected()),
        }
    }

    /// Close the document `doc`.
    ///
    /// # Errors
    /// As [`ModelClient::call`]; `CS-ML-0004` for a handle this connection does not hold.
    pub fn close_document(&mut self, call: &Call, doc: u32) -> Result<(), ModeldError> {
        match self.exchange(&ModelClient::request(call, Op::DocClose { doc }))? {
            Response::Closed => Ok(()),
            _ => Err(unexpected()),
        }
    }

    /// OCR page `page` (zero-based) of the open document `doc` at `dpi`, with the
    /// `scripts` packs besides the default recogniser. A page that cannot be read comes
    /// back with its `status` set, not as an error.
    ///
    /// # Errors
    /// As [`ModelClient::call`].
    pub fn ocr(
        &mut self,
        call: &Call,
        doc: u32,
        page: u16,
        dpi: u16,
        scripts: Vec<String>,
    ) -> Result<OcrPage, ModeldError> {
        let op = Op::Ocr {
            doc,
            page,
            dpi,
            scripts,
        };
        match self.exchange(&ModelClient::request(call, op))? {
            Response::Ocr(p) => Ok(p),
            _ => Err(unexpected()),
        }
    }

    /// End the session with a TLS close.
    pub fn close(mut self) {
        self.stream.conn.send_close_notify();
        let _ = self.stream.conn.complete_io(&mut self.stream.sock);
    }
}
