//! The network a seal needs (docs/31 §6, §9): RFC 3161 time-stamping over HTTPS to the
//! configured TSAs with failover, OCSP to the responder a certificate names and CRLs
//! from its distribution points. The engine builds every request and checks every
//! answer; this only carries bytes.
//!
//! Adapted from `casual-sign-cli`'s `net.rs` (this repository; same licence): owned
//! (`'static`) sources so a factory can hand one to each seal, and log lines that name
//! no URL (a URL can carry a token or tenant name).

use std::sync::Arc;
use std::time::Duration;

use casual_sign_sdk::{
    Certificate, CrlQuery, OcspQuery, RevocationSource, SourceError, TimestampSource,
};
use x509_cert::ext::pkix::crl::dp::DistributionPoint;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::ext::pkix::{AuthorityInfoAccessSyntax, CrlDistributionPoints};

use crate::seal::{RevocationFactory, TsaFactory};

/// Largest answer read from a TSA or responder (docs/21: 1 MiB), and from a CRL (32 MiB).
const MAX_ANSWER: u64 = 1024 * 1024;
const MAX_CRL: u64 = 32 * 1024 * 1024;
/// An upper bound on a timestamp token's DER length (2 to 8 KiB in practice).
const TOKEN_BOUND: usize = 16 * 1024;
const OCSP: &str = "1.3.6.1.5.5.7.48.1";

fn agent() -> ureq::Agent {
    let native = rustls_native_certs::load_native_certs();
    let roots: Vec<ureq::tls::Certificate<'static>> = native
        .certs
        .iter()
        .map(|c| ureq::tls::Certificate::from_der(c.as_ref()).to_owned())
        .collect();
    let tls = ureq::tls::TlsConfig::builder()
        .provider(ureq::tls::TlsProvider::Rustls)
        .root_certs(ureq::tls::RootCerts::new_with_certs(&roots))
        .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .build();
    ureq::Agent::config_builder()
        .tls_config(tls)
        .timeout_global(Some(Duration::from_secs(30)))
        .max_redirects(0)
        .http_status_as_error(true)
        .user_agent("openseal-worker")
        .build()
        .into()
}

fn read(mut r: ureq::http::Response<ureq::Body>, limit: u64) -> Option<Vec<u8>> {
    r.body_mut().with_config().limit(limit).read_to_vec().ok()
}

/// TSAs tried in order until one answers.
struct HttpTsa {
    agent: ureq::Agent,
    urls: Arc<Vec<String>>,
}

impl TimestampSource for HttpTsa {
    fn token_len_bound(&self) -> usize {
        TOKEN_BOUND
    }

    fn nonce(&self) -> Vec<u8> {
        let mut n = [0u8; 16];
        if aws_lc_rs::rand::fill(&mut n).is_err() {
            return Vec::new();
        }
        // Never all zero, and positive as a DER INTEGER.
        if let Some(first) = n.first_mut() {
            *first = (*first & 0x7f) | 0x01;
        }
        n.to_vec()
    }

    fn timestamp(&self, request_der: &[u8]) -> Result<Vec<u8>, SourceError> {
        for (i, url) in self.urls.iter().enumerate() {
            let answer = self
                .agent
                .post(url)
                .header("Content-Type", "application/timestamp-query")
                .send(request_der)
                .ok()
                .and_then(|r| read(r, MAX_ANSWER));
            match answer {
                Some(a) => return Ok(a),
                None => crate::log("WARN", "tsa_failed", &[("tsa", i.to_string())]),
            }
        }
        Err(SourceError::Unavailable)
    }
}

/// A factory of HTTP time-stamp sources over `urls` (tried in order).
#[must_use]
pub fn http_tsa(urls: Vec<String>) -> TsaFactory {
    let urls = Arc::new(urls);
    let agent = agent();
    Arc::new(move || {
        Box::new(HttpTsa {
            agent: agent.clone(),
            urls: Arc::clone(&urls),
        })
    })
}

fn uri(name: &GeneralName) -> Option<String> {
    match name {
        GeneralName::UniformResourceIdentifier(u) => {
            let s = u.as_str();
            (s.starts_with("http://") || s.starts_with("https://")).then(|| s.to_owned())
        }
        _ => None,
    }
}

fn ocsp_url(cert: &Certificate) -> Option<String> {
    let (_, aia) = cert
        .tbs_certificate()
        .get_extension::<AuthorityInfoAccessSyntax>()
        .ok()??;
    aia.0
        .iter()
        .filter(|d| d.access_method.to_string() == OCSP)
        .find_map(|d| uri(&d.access_location))
}

fn crl_urls(cert: &Certificate) -> Vec<String> {
    let Ok(Some((_, dps))) = cert
        .tbs_certificate()
        .get_extension::<CrlDistributionPoints>()
    else {
        return Vec::new();
    };
    dps.0
        .iter()
        .filter_map(|dp: &DistributionPoint| match &dp.distribution_point {
            Some(DistributionPointName::FullName(names)) => names.iter().find_map(uri),
            _ => None,
        })
        .collect()
}

/// OCSP first, CRL as the fallback.
struct HttpRevocation {
    agent: ureq::Agent,
}

impl RevocationSource for HttpRevocation {
    fn ocsp(&self, query: &OcspQuery<'_>) -> Result<Option<Vec<u8>>, SourceError> {
        let Some(url) = ocsp_url(query.certificate) else {
            return Ok(None);
        };
        Ok(self
            .agent
            .post(&url)
            .header("Content-Type", "application/ocsp-request")
            .send(query.request_der)
            .ok()
            .and_then(|r| read(r, MAX_ANSWER)))
    }

    fn crl(&self, query: &CrlQuery<'_>) -> Result<Option<Vec<u8>>, SourceError> {
        for url in crl_urls(query.certificate) {
            if let Some(crl) = self
                .agent
                .get(&url)
                .call()
                .ok()
                .and_then(|r| read(r, MAX_CRL))
            {
                return Ok(Some(crl));
            }
        }
        Ok(None)
    }
}

/// A factory of HTTP revocation sources.
#[must_use]
pub fn http_revocation() -> RevocationFactory {
    let agent = agent();
    Arc::new(move || {
        Box::new(HttpRevocation {
            agent: agent.clone(),
        })
    })
}
