//! Cryptographic structures for OpenSeal (docs/31, ADR-006): CMS SignedData, X.509,
//! RFC 3161 timestamps, OCSP and CRLs, and the [`KeyProvider`] seam through which a host
//! signs. No primitive is implemented here; they come from the RustCrypto crates ADR-006
//! names, so this crate builds for `wasm32-unknown-unknown`. It holds no key, samples no
//! time or randomness, and performs no I/O: keys, nonces, times and network answers are
//! supplied (ADR-004).
//!
//! - [`digest`]: SHA-256/384/512 over byte ranges without copying.
//! - [`KeyProvider`]: signs the DER signed attributes (docs/31 §4 step 5, ADR-009).
//! - [`cms`]: build a detached PAdES CMS ([`cms::sign_detached`]) and parse and verify one
//!   ([`cms::ParsedCms`]), DER only, hashing signed attributes exactly as received.
//! - [`tsp`]: RFC 3161 request and response checks.
//! - [`revocation`]: OCSP and CRL status at a time.
//!
//! Every error is a [`CryptoError`] whose [`CryptoError::code`] is a docs/20 code;
//! messages carry no document bytes, key material or names.

pub mod cms;
mod der_walk;
pub mod digest;
mod error;
pub mod ess;
mod key;
pub mod oid;
pub mod revocation;
mod signature;
pub mod tsp;

pub use digest::{DigestAlgorithm, DigestValue, Hasher};
pub use error::{
    CryptoError, KeyError, RevocationFailure, SignedAttribute, Structure, TimestampFailure,
};
pub use key::{KeyProvider, Signature};
pub use signature::{MAX_RSA_BITS, MIN_RSA_VERIFY_BITS, SignatureAlgorithm};

/// Re-exported so hosts and tests name the same certificate type this crate uses.
pub use x509_cert::Certificate;
/// Re-exported for [`revocation`] callers.
pub use x509_cert::serial_number::SerialNumber;
