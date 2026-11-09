//! ESS `SigningCertificateV2` (RFC 5035), which RustCrypto lacks (docs/66 pitfall 2).
//! Taken from the SPK-02 spike (`spikes/spk-02-crypto/verify/src/lib.rs`, ours), with the
//! optional `policies` field added so signers that write it still decode.

use der::Sequence;
use der::asn1::{Any, OctetString};
use spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;
use x509_cert::ext::pkix::name::{GeneralName, GeneralNames};
use x509_cert::serial_number::SerialNumber;

use crate::digest::DigestAlgorithm;
use crate::error::CryptoError;
use crate::signature::to_der;

/// `IssuerSerial`.
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct IssuerSerial {
    /// The issuer, as `GeneralNames` holding a `directoryName`.
    pub issuer: GeneralNames,
    /// The serial number.
    pub serial_number: SerialNumber,
}

/// `ESSCertIDv2`. `hashAlgorithm` is `DEFAULT id-sha256`, so DER omits it for SHA-256.
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct EssCertIdV2 {
    /// Absent means SHA-256.
    #[asn1(optional = "true")]
    pub hash_algorithm: Option<AlgorithmIdentifierOwned>,
    /// Hash of the whole certificate DER.
    pub cert_hash: OctetString,
    /// Optional issuer and serial.
    #[asn1(optional = "true")]
    pub issuer_serial: Option<IssuerSerial>,
}

/// `SigningCertificateV2`.
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct SigningCertificateV2 {
    /// The first entry identifies the signer certificate.
    pub certs: Vec<EssCertIdV2>,
    /// `SEQUENCE OF PolicyInformation`; read and ignored, never written.
    #[asn1(optional = "true")]
    pub policies: Option<Vec<Any>>,
}

impl SigningCertificateV2 {
    /// The attribute value naming `cert`, hashed with SHA-256 and with `IssuerSerial`.
    pub(crate) fn for_certificate(cert: &Certificate) -> Result<Self, CryptoError> {
        let hash = DigestAlgorithm::Sha256.digest(&to_der(cert)?);
        let tbs = cert.tbs_certificate();
        Ok(Self {
            certs: vec![EssCertIdV2 {
                hash_algorithm: None,
                cert_hash: OctetString::new(hash.as_bytes()).map_err(|_| CryptoError::Encoding)?,
                issuer_serial: Some(IssuerSerial {
                    issuer: vec![GeneralName::DirectoryName(tbs.issuer().clone())],
                    serial_number: tbs.serial_number().clone(),
                }),
            }],
            policies: None,
        })
    }

    /// Whether the first entry identifies `cert` (hash, and issuer/serial when present).
    pub(crate) fn matches(&self, cert: &Certificate) -> Result<(), CryptoError> {
        let first = self
            .certs
            .first()
            .ok_or(CryptoError::SigningCertificateMismatch)?;
        let alg = match &first.hash_algorithm {
            None => DigestAlgorithm::Sha256,
            Some(a) => DigestAlgorithm::from_algorithm_identifier(a)?,
        };
        let cert_der =
            to_der(cert).map_err(|_| CryptoError::Malformed(crate::Structure::Certificate))?;
        if alg.digest(&cert_der).as_bytes() != first.cert_hash.as_bytes() {
            return Err(CryptoError::SigningCertificateMismatch);
        }
        if let Some(is) = &first.issuer_serial {
            let tbs = cert.tbs_certificate();
            let issuer_ok = is
                .issuer
                .iter()
                .any(|g| matches!(g, GeneralName::DirectoryName(n) if n == tbs.issuer()));
            if !issuer_ok || is.serial_number != *tbs.serial_number() {
                return Err(CryptoError::SigningCertificateMismatch);
            }
        }
        Ok(())
    }
}
