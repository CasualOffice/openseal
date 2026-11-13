//! OpenSeal's key daemon (stage 2E, docs/31 §5, `SEC-S04`, `SEC-S05`): signing keys
//! live here, behind PKCS#11, and nowhere else.
//!
//! - [`Pkcs11Module`] / [`Pkcs11Key`]: a key in an HSM token (SoftHSM in development),
//!   found by label or id, PIN from [`casual_sign_secrets`], proven to be its
//!   certificate's before use. ECDSA P-256/P-384, RSA PKCS#1 v1.5 and PSS.
//! - [`FileKey`]: a PEM key file, **development only**: refused without
//!   [`DevKeyConsent`] (`OPENSEAL_DEV_INSECURE_KEY=1`, `CS-KEY-0004`); seals made with it
//!   must carry [`DEV_REASON`].
//! - [`Keyd`]: the daemon. mTLS (rustls, TLS 1.3, client certificate required and on an
//!   [`AllowList`]), get-certificate-chain and sign-digest, a per-caller rate limit, and
//!   an append-only hash-chained [`OpLog`] written before any signature is released.
//!   A second, admin allow-list ([`KeyService::with_admin`], `CON-06`) is answered the
//!   read-only `list-keys`, `oplog-head`, `oplog-range` and `health`, and nothing else; a
//!   signing caller cannot call them (`CS-CON-0008`).
//! - [`RemoteKey`]: the caller's [`casual_sign_crypto::KeyProvider`] over keyd, so the worker seals
//!   remotely.
//!
//! Every key implements [`casual_sign_crypto::KeyProvider`] and [`DigestSigner`]. keyd
//! signs digests: no document byte and no signed attribute reaches it. Errors are
//! [`KeydError`] with `CS-KEY-*` codes (docs/20); no PIN, key byte or document content
//! is ever in a message, a log line or a `Debug`.
//!
//! Cloud KMS backends (AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault Transit) are
//! further [`DigestSigner`] implementations, tracked separately.

mod cert_key;
mod client;
mod file_key;
pub mod oplog;
mod pem;
mod pkcs11;
mod server;
mod signer;

/// keyd's errors live in `casual-sign-keyd-client`, shared with its callers.
mod error {
    pub use casual_sign_keyd_client::{KeyConfigProblem, KeydError};
}
/// The wire format lives in `casual-sign-keyd-client`, shared with its callers.
mod wire {
    pub(crate) use casual_sign_keyd_client::wire::{
        Health, KeyHealth, KeyInfo, LogEntry, Request, Response, read_frame, valid_id, write_frame,
    };
}

pub use casual_sign_keyd_client::{AdminClient, Endpoint, client_tls};
pub use cert_key::{MIN_RSA_SIGN_BITS, algorithm_for, probe};
pub use client::RemoteKey;
pub use error::{KeyConfigProblem, KeydError};
pub use file_key::{DEV_KEY_VARIABLE, DEV_REASON, DevKeyConsent, FileKey};
pub use oplog::{OpLog, OpRecord};
pub use pem::{MAX_CHAIN, certificates};
pub use pkcs11::{ChainSource, Pkcs11Key, Pkcs11KeyConfig, Pkcs11Module};
pub use server::{AllowList, KeyService, Keyd, KeydLimits, fingerprint, server_tls};
pub use signer::{DigestSigner, digest_for, digest_len};

/// Re-exported so hosts name the same types.
pub use casual_sign_secrets::Secret;
