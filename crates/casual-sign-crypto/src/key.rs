//! The `KeyProvider` seam (docs/31 §4 step 5, §5; ADR-009). This crate never holds a
//! private key: a host implements this trait over `keyd`, an HSM, a cloud KMS or, in
//! development only, a file key.

use x509_cert::Certificate;

use crate::error::KeyError;
use crate::signature::SignatureAlgorithm;

/// A signature value as it goes into `SignerInfo.signature`: a DER `Ecdsa-Sig-Value` for
/// ECDSA, the modulus-length octet string for RSA.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(Vec<u8>);

impl Signature {
    /// Wrap bytes returned by a backend.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Signs DER-encoded CMS signed attributes with a key the engine never sees.
///
/// The provider receives **the encoded signed attributes** (content type, the document's
/// digest, the signer certificate's hash: a few hundred bytes, never the document) and
/// hashes and signs them in one call, which keeps FIPS-approved `sign` APIs usable
/// (`SPK-02`: `sign_digest` is not FIPS-approved in aws-lc-rs).
pub trait KeyProvider {
    /// The algorithm [`KeyProvider::sign`] uses. Its digest is also the CMS
    /// `digestAlgorithm`.
    fn algorithm(&self) -> SignatureAlgorithm;

    /// The signer certificate first, then any intermediates and, optionally, the root.
    fn certificate_chain(&self) -> &[Certificate];

    /// Hash `signed_attrs_der` with the algorithm's digest and sign it.
    ///
    /// # Errors
    /// [`KeyError`] when the backend fails or refuses; the engine reports `CS-SEAL-0001`.
    fn sign(&self, signed_attrs_der: &[u8]) -> Result<Signature, KeyError>;
}
