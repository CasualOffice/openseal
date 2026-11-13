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

/// Told of each signature keyd did not give (unreachable, handshake refused, refused
/// by keyd): the caller's security log (`ASVS-08`, ASVS 9.2.5).
pub type FailureHook = std::sync::Arc<dyn Fn(&KeydError) + Send + Sync>;

/// A key held by a remote keyd.
#[derive(Clone)]
pub struct RemoteKey {
    endpoint: Endpoint,
    alias: String,
    envelope: String,
    algorithm: SignatureAlgorithm,
    development: bool,
    chain: Vec<Certificate>,
    on_failure: Option<FailureHook>,
}

impl core::fmt::Debug for RemoteKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RemoteKey")
            .field("endpoint", &self.endpoint)
            .field("alias", &self.alias)
            .field("envelope", &self.envelope)
            .field("algorithm", &self.algorithm)
            .field("development", &self.development)
            .field("chain", &self.chain.len())
            .finish_non_exhaustive()
    }
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
            on_failure: None,
        })
    }

    /// The same key, telling `hook` of every signature keyd does not give.
    #[must_use]
    pub fn on_failure(mut self, hook: FailureHook) -> Self {
        self.on_failure = Some(hook);
        self
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
        let answer = call(
            &self.endpoint,
            &Request::Sign {
                alias: self.alias.clone(),
                alg,
                digest: digest.to_vec(),
                envelope: self.envelope.clone(),
            },
        )
        .and_then(|resp| match resp {
            Response::Signature(sig) if !sig.is_empty() && sig.len() <= MAX_SIGNATURE => Ok(sig),
            Response::Error(n) => Err(KeydError::from_number(n)),
            _ => Err(KeydError::Malformed("unexpected answer")),
        });
        if let (Err(e), Some(hook)) = (&answer, &self.on_failure) {
            hook(e);
        }
        answer
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
