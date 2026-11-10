//! The caller's side: a [`KeyProvider`] that signs through a remote keyd over mTLS, so
//! the worker seals without holding a key. The chain and algorithm are fetched once, at
//! [`RemoteKey::connect`]; each signature is one short TLS connection carrying one
//! digest (the hash of the CMS signed attributes) and the envelope id.

use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use casual_sign_crypto::{Certificate, KeyError, KeyProvider, Signature, SignatureAlgorithm};
use der::Decode;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{PrivateKeyDer, ServerName};

use crate::error::KeydError;
use crate::pem::tls_certificates;
use crate::signer::{DigestSigner, from_wire_id, sign_attributes, wire_id};
use crate::wire::{Request, Response, read_frame, valid_id, write_frame};

/// Largest signature accepted from keyd (RSA 8192 is 1,024 bytes).
const MAX_SIGNATURE: usize = 1024;

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

/// A key held by a remote keyd.
#[derive(Debug, Clone)]
pub struct RemoteKey {
    endpoint: Endpoint,
    alias: String,
    envelope: String,
    algorithm: SignatureAlgorithm,
    development: bool,
    chain: Vec<Certificate>,
}

fn transport(e: impl core::fmt::Display) -> KeydError {
    KeydError::Transport(e.to_string())
}

/// One request, one response, on a fresh mTLS connection.
fn call(endpoint: &Endpoint, req: &Request) -> Result<Response, KeydError> {
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

impl RemoteKey {
    /// Fetch the algorithm and chain of `alias` from keyd.
    ///
    /// # Errors
    /// `CS-KEY-0011` when keyd cannot be reached or the handshake fails (no or an
    /// untrusted client certificate); the code keyd answered otherwise (`CS-KEY-0001`
    /// for a caller not on its allow-list, `CS-KEY-0002` for an unknown alias).
    pub fn connect(endpoint: Endpoint, alias: &str) -> Result<Self, KeydError> {
        if !valid_id(alias, false) {
            return Err(KeydError::Malformed("alias outside [A-Za-z0-9._-]{1,64}"));
        }
        let resp = call(
            &endpoint,
            &Request::Chain {
                alias: alias.to_owned(),
            },
        )?;
        let (alg, development, certs) = match resp {
            Response::Chain {
                alg,
                development,
                certs,
            } => (alg, development, certs),
            Response::Error(n) => return Err(KeydError::from_number(n)),
            Response::Signature(_) => return Err(KeydError::Malformed("unexpected answer")),
        };
        let algorithm = from_wire_id(alg).ok_or(KeydError::Malformed("unknown algorithm"))?;
        let chain = certs
            .iter()
            .map(|d| Certificate::from_der(d).map_err(|_| KeydError::Malformed("certificate")))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            endpoint,
            alias: alias.to_owned(),
            envelope: String::new(),
            algorithm,
            development,
            chain,
        })
    }

    /// The same key, with signatures recorded in keyd's log against `envelope`.
    ///
    /// # Errors
    /// `CS-KEY-0007` for an id outside `[A-Za-z0-9._-]{0,64}`.
    pub fn for_envelope(&self, envelope: &str) -> Result<Self, KeydError> {
        if !valid_id(envelope, true) {
            return Err(KeydError::Malformed(
                "envelope id outside [A-Za-z0-9._-]{0,64}",
            ));
        }
        let mut out = self.clone();
        envelope.clone_into(&mut out.envelope);
        Ok(out)
    }
}

impl DigestSigner for RemoteKey {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn certificate_chain(&self) -> &[Certificate] {
        &self.chain
    }

    fn is_development(&self) -> bool {
        self.development
    }

    fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, KeydError> {
        crate::signer::check_digest(self.algorithm, digest)?;
        let alg = wire_id(self.algorithm).ok_or(KeydError::Malformed("algorithm"))?;
        let resp = call(
            &self.endpoint,
            &Request::Sign {
                alias: self.alias.clone(),
                alg,
                digest: digest.to_vec(),
                envelope: self.envelope.clone(),
            },
        )?;
        match resp {
            Response::Signature(sig) if !sig.is_empty() && sig.len() <= MAX_SIGNATURE => Ok(sig),
            Response::Error(n) => Err(KeydError::from_number(n)),
            _ => Err(KeydError::Malformed("unexpected answer")),
        }
    }
}

impl KeyProvider for RemoteKey {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn certificate_chain(&self) -> &[Certificate] {
        &self.chain
    }

    fn sign(&self, signed_attrs_der: &[u8]) -> Result<Signature, KeyError> {
        sign_attributes(self, signed_attrs_der)
    }
}
