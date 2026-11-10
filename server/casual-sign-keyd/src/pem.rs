//! Certificates from PEM or DER, with rustls-pki-types' PEM reader (no hand-written
//! PEM parser).

use casual_sign_crypto::Certificate;
use der::Decode;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;

use crate::error::{KeyConfigProblem, KeydError};

/// Most certificates a chain may hold.
pub const MAX_CHAIN: usize = 8;

/// The certificates of a PEM file (or one DER certificate), in order. At least one, at
/// most [`MAX_CHAIN`].
///
/// # Errors
/// `CS-KEY-0006` when a block does not parse, or there are none or too many.
pub fn certificates(bytes: &[u8]) -> Result<Vec<Certificate>, KeydError> {
    let bad = || KeydError::KeyConfig(KeyConfigProblem::BadCertificate);
    let ders: Vec<Vec<u8>> = if bytes.first() == Some(&0x30) {
        vec![bytes.to_vec()]
    } else {
        CertificateDer::pem_slice_iter(bytes)
            .map(|c| c.map(|c| c.as_ref().to_vec()).map_err(|_| bad()))
            .collect::<Result<_, _>>()?
    };
    if ders.is_empty() {
        return Err(KeydError::KeyConfig(KeyConfigProblem::NoCertificate));
    }
    if ders.len() > MAX_CHAIN {
        return Err(bad());
    }
    ders.iter()
        .map(|d| Certificate::from_der(d).map_err(|_| bad()))
        .collect()
}

/// TLS certificates from PEM, for rustls.
///
/// # Errors
/// `CS-KEY-0010` when none parse.
pub(crate) fn tls_certificates(bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>, KeydError> {
    let out = CertificateDer::pem_slice_iter(bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| KeydError::TlsConfig(format!("a certificate PEM block: {e}")))?;
    if out.is_empty() {
        return Err(KeydError::TlsConfig("no CERTIFICATE block".into()));
    }
    Ok(out)
}
