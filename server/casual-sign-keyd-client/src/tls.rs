//! The caller's transport: an mTLS client configuration and one request, one response, on
//! a fresh connection. Moved from `casual-sign-keyd`'s client (`CON-06`, `CON-15`).

use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};

use crate::error::KeydError;
use crate::wire::{Request, Response, read_frame, write_frame};

/// TLS certificates from PEM, for rustls.
///
/// # Errors
/// `CS-KEY-0010` when none parse.
pub fn tls_certificates(bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>, KeydError> {
    let out = CertificateDer::pem_slice_iter(bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| KeydError::TlsConfig(format!("a certificate PEM block: {e}")))?;
    if out.is_empty() {
        return Err(KeydError::TlsConfig("no CERTIFICATE block".into()));
    }
    Ok(out)
}

/// The client's TLS configuration: the CA keyd's server certificate chains to, and the
/// client certificate chain and key (PEM) keyd's allow-list names. `None` for the
/// client credentials makes a client without a certificate (tests of refusal only).
///
/// # Errors
/// `CS-KEY-0010` when any of them does not load.
pub fn client_tls(
    server_ca_pem: &[u8],
    client: Option<(&[u8], &[u8])>,
) -> Result<Arc<ClientConfig>, KeydError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let tls = |e: rustls::Error| KeydError::TlsConfig(e.to_string());
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
                .map_err(|_| KeydError::TlsConfig("the client key does not load".into()))?;
            builder
                .with_client_auth_cert(tls_certificates(chain_pem)?, key)
                .map_err(tls)?
        }
        None => builder.with_no_client_auth(),
    };
    Ok(Arc::new(config))
}

/// Where keyd is and how to reach it.
#[derive(Debug, Clone)]
pub struct Endpoint {
    /// `host:port`.
    pub addr: String,
    /// The name keyd's server certificate is checked against.
    pub server_name: String,
    /// The client TLS configuration ([`client_tls`]).
    pub tls: Arc<ClientConfig>,
    /// Connect, read and write timeout.
    pub timeout: Duration,
}

fn transport(e: impl core::fmt::Display) -> KeydError {
    KeydError::Transport(e.to_string())
}

/// One request, one response, on a fresh mTLS connection.
///
/// # Errors
/// `CS-KEY-0011` when keyd cannot be reached or the handshake fails; `CS-KEY-0007` for
/// an answer that does not follow the protocol.
pub fn call(endpoint: &Endpoint, req: &Request) -> Result<Response, KeydError> {
    let name = ServerName::try_from(endpoint.server_name.clone())
        .map_err(|_| KeydError::TlsConfig("server name".into()))?;
    let addr = endpoint
        .addr
        .to_socket_addrs()
        .map_err(transport)?
        .next()
        .ok_or_else(|| transport("address does not resolve"))?;
    let sock = TcpStream::connect_timeout(&addr, endpoint.timeout).map_err(transport)?;
    sock.set_read_timeout(Some(endpoint.timeout))
        .map_err(transport)?;
    sock.set_write_timeout(Some(endpoint.timeout))
        .map_err(transport)?;
    let conn = ClientConnection::new(endpoint.tls.clone(), name).map_err(transport)?;
    let mut s = StreamOwned::new(conn, sock);
    write_frame(&mut s, &req.encode()?)?;
    let body = read_frame(&mut s)?.ok_or_else(|| transport("keyd closed the connection"))?;
    let resp = Response::decode(&body, req)?;
    s.conn.send_close_notify();
    let _ = s.conn.complete_io(&mut s.sock);
    Ok(resp)
}
