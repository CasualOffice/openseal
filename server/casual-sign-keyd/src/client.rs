//! The caller's side: a [`KeyProvider`] that signs through a remote keyd over mTLS, so
//! the worker seals without holding a key. The chain and algorithm are fetched once, at
//! [`RemoteKey::connect`]; each signature is one short TLS connection carrying one
//! digest (the hash of the CMS signed attributes) and the envelope id.

use casual_sign_crypto::{Certificate, KeyError, KeyProvider, Signature, SignatureAlgorithm};
use casual_sign_keyd_client::{Endpoint, call};
use der::Decode;

use crate::error::KeydError;
use crate::signer::{DigestSigner, from_wire_id, sign_attributes, wire_id};
use crate::wire::{Request, Response, valid_id};

/// Largest signature accepted from keyd (RSA 8192 is 1,024 bytes).
const MAX_SIGNATURE: usize = 1024;

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

impl RemoteKey {
    /// Fetch the algorithm and chain of `alias` from keyd.
    ///
    /// # Errors
    /// `CS-KEY-0011` when keyd cannot be reached; `CS-KEY-0013` when the handshake is
    /// refused (keyd's certificate not trusted or not named as configured, or no or an
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
            _ => return Err(KeydError::Malformed("unexpected answer")),
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

    fn backend(&self) -> &'static str {
        "remote"
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
