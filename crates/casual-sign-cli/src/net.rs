//! The network a seal needs (docs/31 §6, §9), reached by the host: RFC 3161 over HTTP to
//! one or more TSAs with failover, OCSP over HTTP POST (RFC 6960 appendix A) to the
//! responder a certificate's AIA names, and CRLs from its distribution points. The
//! engine builds every request and checks every answer; this only carries bytes.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use casual_sign_sdk::{
    Certificate, CrlQuery, OcspQuery, RevocationSource, SourceError, TimestampSource,
};
use x509_cert::ext::pkix::crl::dp::DistributionPoint;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::ext::pkix::{AuthorityInfoAccessSyntax, CrlDistributionPoints};

/// Largest answer read from a TSA or responder (docs/21 caps CMS, timestamp and OCSP
/// input at 1 MiB, CRLs at 32 MiB).
const MAX_ANSWER: u64 = 1024 * 1024;
const MAX_CRL: u64 = 32 * 1024 * 1024;

/// An upper bound on a timestamp token's DER length: tokens with the TSA's chain are
/// 2 to 8 KiB in practice. An underestimate costs the engine one retry, never a
/// truncation (docs/31 §4 step 2).
const TOKEN_BOUND: usize = 16 * 1024;

const OCSP: &str = "1.3.6.1.5.5.7.48.1";

/// A blocking HTTP client: rustls on aws-lc-rs, roots from the platform's store, a
/// 30-second budget per request, redirects not followed.
pub(crate) struct Http {
    agent: OnceLock<ureq::Agent>,
}

impl Http {
    pub(crate) fn new() -> Self {
        Self {
            agent: OnceLock::new(),
        }
    }

    fn agent(&self) -> &ureq::Agent {
        self.agent.get_or_init(|| {
            let native = rustls_native_certs::load_native_certs();
            let roots: Vec<ureq::tls::Certificate<'static>> = native
                .certs
                .iter()
                .map(|c| ureq::tls::Certificate::from_der(c.as_ref()).to_owned())
                .collect();
            let tls = ureq::tls::TlsConfig::builder()
                .provider(ureq::tls::TlsProvider::Rustls)
                .root_certs(ureq::tls::RootCerts::new_with_certs(&roots))
                .unversioned_rustls_crypto_provider(Arc::new(
                    rustls::crypto::aws_lc_rs::default_provider(),
                ))
                .build();
            ureq::Agent::config_builder()
                .tls_config(tls)
                .timeout_global(Some(Duration::from_secs(30)))
                .max_redirects(0)
                .http_status_as_error(true)
                .user_agent("openseal")
                .build()
                .into()
        })
    }

    fn read(mut response: ureq::http::Response<ureq::Body>, limit: u64) -> Result<Vec<u8>, String> {
        response
            .body_mut()
            .with_config()
            .limit(limit)
            .read_to_vec()
            .map_err(|e| e.to_string())
    }

    /// POST `body` as `content_type`; the answer's bytes.
    pub(crate) fn post(
        &self,
        url: &str,
        content_type: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, String> {
        let r = self
            .agent()
            .post(url)
            .header("Content-Type", content_type)
            .send(body)
            .map_err(|e| e.to_string())?;
        Self::read(r, MAX_ANSWER)
    }

    /// GET `url`, reading at most `limit` bytes.
    pub(crate) fn get(&self, url: &str, limit: u64) -> Result<Vec<u8>, String> {
        let r = self.agent().get(url).call().map_err(|e| e.to_string())?;
        Self::read(r, limit)
    }
}

/// TSAs tried in order until one answers (docs/31 §6).
pub(crate) struct HttpTsa<'a> {
    http: &'a Http,
    urls: Vec<String>,
}

impl<'a> HttpTsa<'a> {
    pub(crate) fn new(http: &'a Http, urls: Vec<String>) -> Self {
        Self { http, urls }
    }
}

impl TimestampSource for HttpTsa<'_> {
    fn token_len_bound(&self) -> usize {
        TOKEN_BOUND
    }

    fn nonce(&self) -> Vec<u8> {
        let mut n = [0u8; 16];
        if aws_lc_rs::rand::fill(&mut n).is_err() {
            return Vec::new();
        }
        // Never all zero (the engine refuses that), and positive as a DER INTEGER.
        if let Some(first) = n.first_mut() {
            *first = (*first & 0x7f) | 0x01;
        }
        n.to_vec()
    }

    fn timestamp(&self, request_der: &[u8]) -> Result<Vec<u8>, SourceError> {
        for url in &self.urls {
            match self
                .http
                .post(url, "application/timestamp-query", request_der)
            {
                Ok(answer) => return Ok(answer),
                Err(e) => eprintln!("openseal: TSA {url} failed: {e}"),
            }
        }
        Err(SourceError::Unavailable)
    }
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

/// The OCSP responder a certificate's Authority Information Access names.
pub(crate) fn ocsp_url(cert: &Certificate) -> Option<String> {
    let (_, aia) = cert
        .tbs_certificate()
        .get_extension::<AuthorityInfoAccessSyntax>()
        .ok()??;
    aia.0
        .iter()
        .filter(|d| d.access_method.to_string() == OCSP)
        .find_map(|d| uri(&d.access_location))
}

/// The HTTP CRL distribution points a certificate names.
pub(crate) fn crl_urls(cert: &Certificate) -> Vec<String> {
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

/// OCSP first, CRL as the fallback; a responder that fails gives no answer, so the
/// engine falls back, and a level that cannot be reached fails with `CS-SEAL-0004`.
pub(crate) struct HttpRevocation<'a> {
    http: &'a Http,
}

impl<'a> HttpRevocation<'a> {
    pub(crate) fn new(http: &'a Http) -> Self {
        Self { http }
    }
}

impl RevocationSource for HttpRevocation<'_> {
    fn ocsp(&self, query: &OcspQuery<'_>) -> Result<Option<Vec<u8>>, SourceError> {
        let Some(url) = ocsp_url(query.certificate) else {
            return Ok(None);
        };
        match self
            .http
            .post(&url, "application/ocsp-request", query.request_der)
        {
            Ok(answer) => Ok(Some(answer)),
            Err(e) => {
                eprintln!("openseal: OCSP {url} failed: {e}");
                Ok(None)
            }
        }
    }

    fn crl(&self, query: &CrlQuery<'_>) -> Result<Option<Vec<u8>>, SourceError> {
        for url in crl_urls(query.certificate) {
            match self.http.get(&url, MAX_CRL) {
                Ok(crl) => return Ok(Some(crl)),
                Err(e) => eprintln!("openseal: CRL {url} failed: {e}"),
            }
        }
        Ok(None)
    }
}
