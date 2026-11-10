//! Keys in a PKCS#11 token (an HSM; SoftHSM in development and tests), through
//! `cryptoki`'s safe API.
//!
//! The private key is found by `CKA_LABEL` and/or `CKA_ID` and must be unique; its
//! certificate chain is supplied, or the signer certificate is read from the token (the
//! `CKO_CERTIFICATE` with the key's `CKA_ID`). Before a key is handed out, a probe
//! signature is verified against the certificate's public key ([`crate::cert_key::probe`]).
//!
//! Signing is over a digest: `CKM_ECDSA` (raw `r || s`, re-encoded as DER),
//! `CKM_RSA_PKCS` over a `DigestInfo`, or `CKM_RSA_PKCS_PSS` with the digest's hash, MGF1
//! with the same hash and a salt of the digest's length. One session per key, behind a
//! mutex; a failed operation reopens the session and logs in again once, so an HSM that
//! restarted is recovered without restarting keyd. The PIN is a
//! [`casual_sign_secrets::Secret`]: it is passed to `C_Login` and appears nowhere else.

use std::path::Path;
use std::sync::Mutex;

use casual_sign_crypto::{Certificate, KeyError, KeyProvider, Signature, SignatureAlgorithm};
use casual_sign_secrets::Secret;
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as P11Error, RvError};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::{AuthPin, Ulong};
use der::Decode;

use crate::cert_key::{CertKey, algorithm_for, cert_key, probe};
use crate::error::{KeyConfigProblem, KeydError};
use crate::signer::{
    DigestSigner, check_digest, digest_info, digest_len, ecdsa_raw_to_der, sign_attributes,
};

/// A loaded PKCS#11 module, initialized once per process. Every key from one module
/// shares it; `C_Finalize` runs when the last of them is dropped.
#[derive(Clone)]
pub struct Pkcs11Module {
    ctx: Pkcs11,
}

impl core::fmt::Debug for Pkcs11Module {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pkcs11Module").finish_non_exhaustive()
    }
}

impl Pkcs11Module {
    /// Load the module at `path` and initialize it for multi-threaded use.
    ///
    /// # Errors
    /// `CS-KEY-0003` when the library does not load or initialize.
    pub fn open(path: &Path) -> Result<Self, KeydError> {
        let ctx = Pkcs11::new(path).map_err(|e| KeydError::backend("loading the module", e))?;
        match ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
            Ok(()) | Err(P11Error::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
            Err(e) => return Err(KeydError::backend("C_Initialize", e)),
        }
        Ok(Self { ctx })
    }

    /// The cryptoki context, for provisioning tools and tests that create tokens and
    /// keys. keyd itself only finds and signs.
    #[must_use]
    pub fn context(&self) -> &Pkcs11 {
        &self.ctx
    }

    /// The slot whose token has `label`.
    ///
    /// # Errors
    /// `CS-KEY-0006` (`NoToken`) when none has; `CS-KEY-0003` when the module fails.
    pub fn slot(&self, label: &str) -> Result<Slot, KeydError> {
        let slots = self
            .ctx
            .get_slots_with_token()
            .map_err(|e| KeydError::backend("C_GetSlotList", e))?;
        for slot in slots {
            let info = self
                .ctx
                .get_token_info(slot)
                .map_err(|e| KeydError::backend("C_GetTokenInfo", e))?;
            if info.label().trim_end() == label {
                return Ok(slot);
            }
        }
        Err(KeydError::KeyConfig(KeyConfigProblem::NoToken))
    }

    /// Open the key `config` describes, and prove it is its certificate's.
    ///
    /// # Errors
    /// `CS-KEY-0006` for a missing, ambiguous or mismatched key or certificate;
    /// `CS-KEY-0003` when the token fails or refuses the PIN.
    pub fn key(&self, config: Pkcs11KeyConfig) -> Result<Pkcs11Key, KeydError> {
        if config.key_label.is_none() && config.key_id.is_none() {
            return Err(KeydError::KeyConfig(KeyConfigProblem::NoSelector));
        }
        let slot = self.slot(&config.token_label)?;
        let (session, key) = open_session(&self.ctx, slot, &config)?;
        let chain = match config.chain {
            ChainSource::Supplied(chain) => chain,
            ChainSource::Token { rest } => {
                let mut chain = vec![token_certificate(&session, key)?];
                chain.extend(rest);
                chain
            }
        };
        let leaf = chain
            .first()
            .ok_or(KeydError::KeyConfig(KeyConfigProblem::NoCertificate))?;
        let algorithm = algorithm_for(leaf, config.rsa_algorithm)?;
        check_key_type(&session, key, cert_key(leaf)?)?;
        let out = Pkcs11Key {
            ctx: self.ctx.clone(),
            slot,
            pin: config.pin,
            key_label: config.key_label,
            key_id: config.key_id,
            state: Mutex::new(Some((session, key))),
            algorithm,
            chain,
        };
        probe(&out)?;
        Ok(out)
    }
}

/// Where a PKCS#11 key's certificate chain comes from.
#[derive(Debug, Clone)]
pub enum ChainSource {
    /// The whole chain, signer first, from configuration.
    Supplied(Vec<Certificate>),
    /// The signer certificate from the token (the `CKO_CERTIFICATE` with the key's
    /// `CKA_ID`), then `rest` (intermediates) from configuration.
    Token {
        /// Intermediates after the signer certificate.
        rest: Vec<Certificate>,
    },
}

/// How to find and use one key in a token.
#[derive(Debug, Clone)]
pub struct Pkcs11KeyConfig {
    /// The token's label.
    pub token_label: String,
    /// The private key's `CKA_LABEL`.
    pub key_label: Option<String>,
    /// The private key's `CKA_ID`.
    pub key_id: Option<Vec<u8>>,
    /// The user PIN (from `casual-sign-secrets`; its `Debug` is redacted).
    pub pin: Secret,
    /// The certificate chain.
    pub chain: ChainSource,
    /// For an RSA key: the scheme and hash (PKCS#1 v1.5 SHA-256 when `None`).
    pub rsa_algorithm: Option<SignatureAlgorithm>,
}

/// A private key in a PKCS#11 token. Implements [`DigestSigner`] for keyd and
/// [`KeyProvider`] for sealing in process.
pub struct Pkcs11Key {
    ctx: Pkcs11,
    slot: Slot,
    pin: Secret,
    key_label: Option<String>,
    key_id: Option<Vec<u8>>,
    /// `None` after a failure until the next operation reopens it.
    state: Mutex<Option<(Session, ObjectHandle)>>,
    algorithm: SignatureAlgorithm,
    chain: Vec<Certificate>,
}

impl core::fmt::Debug for Pkcs11Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pkcs11Key")
            .field("key_label", &self.key_label)
            .field("algorithm", &self.algorithm)
            .field("chain", &self.chain.len())
            .finish_non_exhaustive()
    }
}

fn login(session: &Session, pin: &Secret) -> Result<(), KeydError> {
    let pin = AuthPin::from(pin.expose());
    match session.login(UserType::User, Some(&pin)) {
        Ok(()) | Err(P11Error::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(()),
        Err(e) => Err(KeydError::backend("C_Login", e)),
    }
}

fn find_key(
    session: &Session,
    label: Option<&str>,
    id: Option<&[u8]>,
) -> Result<ObjectHandle, KeydError> {
    let mut template = vec![Attribute::Class(ObjectClass::PRIVATE_KEY)];
    if let Some(l) = label {
        template.push(Attribute::Label(l.as_bytes().to_vec()));
    }
    if let Some(i) = id {
        template.push(Attribute::Id(i.to_vec()));
    }
    let found = session
        .find_objects(&template)
        .map_err(|e| KeydError::backend("C_FindObjects", e))?;
    match found.as_slice() {
        [one] => Ok(*one),
        [] => Err(KeydError::KeyConfig(KeyConfigProblem::KeyNotFound)),
        many => Err(KeydError::KeyConfig(KeyConfigProblem::KeyAmbiguous(
            many.len(),
        ))),
    }
}

fn open_session(
    ctx: &Pkcs11,
    slot: Slot,
    config: &Pkcs11KeyConfig,
) -> Result<(Session, ObjectHandle), KeydError> {
    reopen(
        ctx,
        slot,
        &config.pin,
        config.key_label.as_deref(),
        config.key_id.as_deref(),
    )
}

fn reopen(
    ctx: &Pkcs11,
    slot: Slot,
    pin: &Secret,
    label: Option<&str>,
    id: Option<&[u8]>,
) -> Result<(Session, ObjectHandle), KeydError> {
    let session = ctx
        .open_ro_session(slot)
        .map_err(|e| KeydError::backend("C_OpenSession", e))?;
    login(&session, pin)?;
    let key = find_key(&session, label, id)?;
    Ok((session, key))
}

/// The signer certificate stored beside `key` (same `CKA_ID`).
fn token_certificate(session: &Session, key: ObjectHandle) -> Result<Certificate, KeydError> {
    let id = session
        .get_attributes(key, &[AttributeType::Id])
        .map_err(|e| KeydError::backend("C_GetAttributeValue", e))?
        .into_iter()
        .find_map(|a| match a {
            Attribute::Id(v) => Some(v),
            _ => None,
        })
        .ok_or(KeydError::KeyConfig(KeyConfigProblem::NoCertificate))?;
    let certs = session
        .find_objects(&[
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::Id(id),
        ])
        .map_err(|e| KeydError::backend("C_FindObjects", e))?;
    let [cert] = certs.as_slice() else {
        return Err(KeydError::KeyConfig(if certs.is_empty() {
            KeyConfigProblem::NoCertificate
        } else {
            KeyConfigProblem::BadCertificate
        }));
    };
    let value = session
        .get_attributes(*cert, &[AttributeType::Value])
        .map_err(|e| KeydError::backend("C_GetAttributeValue", e))?
        .into_iter()
        .find_map(|a| match a {
            Attribute::Value(v) => Some(v),
            _ => None,
        })
        .ok_or(KeydError::KeyConfig(KeyConfigProblem::NoCertificate))?;
    Certificate::from_der(&value)
        .map_err(|_| KeydError::KeyConfig(KeyConfigProblem::BadCertificate))
}

/// The token's key type agrees with the certificate's (the probe then proves the key
/// itself is the certificate's).
fn check_key_type(session: &Session, key: ObjectHandle, want: CertKey) -> Result<(), KeydError> {
    let kind = session
        .get_attributes(key, &[AttributeType::KeyType])
        .map_err(|e| KeydError::backend("C_GetAttributeValue", e))?
        .into_iter()
        .find_map(|a| match a {
            Attribute::KeyType(k) => Some(k),
            _ => None,
        });
    let ok = match want {
        CertKey::P256 | CertKey::P384 => kind == Some(KeyType::EC),
        CertKey::Rsa(_) => kind == Some(KeyType::RSA),
    };
    if ok {
        Ok(())
    } else {
        Err(KeydError::KeyConfig(
            KeyConfigProblem::KeyCertificateMismatch,
        ))
    }
}

fn pss(alg: SignatureAlgorithm) -> Option<Mechanism<'static>> {
    let (hash_alg, mgf) = match alg {
        SignatureAlgorithm::RsaPssSha256 => (MechanismType::SHA256, PkcsMgfType::MGF1_SHA256),
        SignatureAlgorithm::RsaPssSha384 => (MechanismType::SHA384, PkcsMgfType::MGF1_SHA384),
        SignatureAlgorithm::RsaPssSha512 => (MechanismType::SHA512, PkcsMgfType::MGF1_SHA512),
        _ => return None,
    };
    let s_len = Ulong::try_from(digest_len(alg)).ok()?;
    Some(Mechanism::RsaPkcsPss(PkcsPssParams {
        hash_alg,
        mgf,
        s_len,
    }))
}

impl Pkcs11Key {
    fn sign_once(
        &self,
        session: &Session,
        key: ObjectHandle,
        digest: &[u8],
    ) -> Result<Vec<u8>, KeydError> {
        let alg = self.algorithm;
        let call = |m: &Mechanism<'_>, data: &[u8]| {
            session
                .sign(m, key, data)
                .map_err(|e| KeydError::backend("C_Sign", e))
        };
        if crate::signer::is_ecdsa(alg) {
            ecdsa_raw_to_der(&call(&Mechanism::Ecdsa, digest)?)
        } else if let Some(m) = pss(alg) {
            call(&m, digest)
        } else {
            call(
                &Mechanism::RsaPkcs,
                &digest_info(alg.digest_algorithm(), digest)?,
            )
        }
    }
}

impl DigestSigner for Pkcs11Key {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn certificate_chain(&self) -> &[Certificate] {
        &self.chain
    }

    fn is_development(&self) -> bool {
        false
    }

    fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, KeydError> {
        check_digest(self.algorithm, digest)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| KeydError::backend("session", "lock poisoned"))?;
        // A live session first; on failure, one fresh session and login (an HSM that
        // restarted), then give up with the backend's error.
        if let Some((session, key)) = state.as_ref() {
            match self.sign_once(session, *key, digest) {
                Ok(sig) => return Ok(sig),
                Err(_) => *state = None,
            }
        }
        let (session, key) = reopen(
            &self.ctx,
            self.slot,
            &self.pin,
            self.key_label.as_deref(),
            self.key_id.as_deref(),
        )?;
        let sig = self.sign_once(&session, key, digest)?;
        *state = Some((session, key));
        Ok(sig)
    }
}

impl KeyProvider for Pkcs11Key {
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
