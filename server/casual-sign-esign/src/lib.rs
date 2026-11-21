//! OpenSeal as an Application Service Provider (ASP) to an India eSign Service Provider
//! (ESP) under the CCA eSign API (`RSP-02`, ADR-047).
//!
//! - [`request`]: the v2.1 `Esign` request, with no Aadhaar data, signed through a
//!   caller-supplied signer (keyd's ASP key, released only with a database-minted ASP
//!   token for an open session, ADR-047 §3.5).
//! - [`response`]: the `EsignResp` answer, its XML Signature verified under the ESP's
//!   configured certificate before any value is read.
//! - [`dsig`]: the one XML Signature profile both use; [`c14n`]: Canonical XML 1.0 and
//!   Exclusive Canonicalization 1.0 over trees read by `casual-sign-xml` (strict).
//! - [`error`]: codes, and the session result each ESP error code ends a session with
//!   (ADR-047 §3.9).
//!
//! Nothing here performs I/O or keeps time: the host passes bytes, keys and the clock.
//! No general XML library is used (ADR-047 §6); xmlsec1, an independent implementation,
//! checks this crate's canonicalization and signatures in tests and on the CI's stub ESP.

pub mod c14n;
pub mod dsig;
pub mod error;
pub mod request;
pub mod response;

pub use dsig::{Algorithm, VerifyingKey};
pub use error::{EsignError, Failure, failure_for, provider_code};
pub use request::{AuthMode, Request};
pub use response::{DocSignature, Response, Status};
