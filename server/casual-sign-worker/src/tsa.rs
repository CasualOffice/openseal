//! The network a seal needs (docs/31 §6, §9): RFC 3161 time-stamping over HTTPS to the
//! configured TSAs with failover, OCSP to the responder a certificate names and CRLs
//! from its distribution points. The engine builds every request and checks every
//! answer; this only carries bytes.
//!
//! Adapted from `casual-sign-cli`'s `net.rs` (this repository; same licence): owned
//! (`'static`) sources so a factory can hand one to each seal, and log lines that name
//! no URL (a URL can carry a token or tenant name).

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use casual_sign_store::Store;

use casual_sign_sdk::{
    Certificate, CrlQuery, OcspQuery, RevocationSource, SourceError, TimestampSource,
};
use x509_cert::ext::pkix::crl::dp::DistributionPoint;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::ext::pkix::{AuthorityInfoAccessSyntax, CrlDistributionPoints};

use casual_sign_seclog::Value;

use crate::seal::{RevocationFactory, TsaFactory};

/// The code a time-stamping authority's failure is logged with (docs/20): not reached,
/// refused by the address policy, or answering no time-stamp; the next one is tried.
pub const TSA_FAILED: &str = "CS-WRK-0018";
use crate::webhook::SsrfPolicy;

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

/// TSAs tried in order until one answers. `policy`, for URLs from the database, is
/// checked against every address the host resolves to before each request (`SEC-W01`,
/// `SEC-X06`); the deployment's own `OPENSEAL_TSA_URLS` are not.
struct HttpTsa {
    agent: ureq::Agent,
    urls: Arc<Vec<String>>,
    policy: Option<SsrfPolicy>,
}

/// The host and port of an `http://` or `https://` URL with no user information.
fn tsa_authority(url: &str) -> Option<(String, u16)> {
    if url.len() > 2048 || !url.bytes().all(|b| b.is_ascii_graphic()) {
        return None;
    }
    let (rest, default) = match url.strip_prefix("https://") {
        Some(r) => (r, 443),
        None => (url.strip_prefix("http://")?, 80),
    };
    let auth = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if auth.is_empty() || auth.contains('@') {
        return None;
    }
    let (host, port) = if let Some(v6) = auth.strip_prefix('[') {
        let (h, after) = v6.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse::<u16>().ok()?,
            None if after.is_empty() => default,
            None => return None,
        };
        (h.to_owned(), port)
    } else {
        match auth.rsplit_once(':') {
            Some((h, p)) => (h.to_owned(), p.parse::<u16>().ok()?),
            None => (auth.to_owned(), default),
        }
    };
    (!host.is_empty() && port != 0).then_some((host, port))
}

/// Whether every address `url`'s host resolves to now is one `policy` permits.
fn address_permitted(url: &str, policy: &SsrfPolicy) -> bool {
    let Some((host, port)) = tsa_authority(url) else {
        return false;
    };
    let Ok(addrs) = (host.as_str(), port).to_socket_addrs() else {
        return false;
    };
    let addrs: Vec<SocketAddr> = addrs.take(16).collect();
    !addrs.is_empty() && addrs.iter().all(|a| policy.permits(a.ip()))
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
            // The TSA by its place in the list, never its URL (ASVS-08, 9.2.5).
            let failed = |reason: &'static str| {
                crate::backend_failed(
                    "tsa",
                    TSA_FAILED,
                    &[
                        ("index", Value::Count(u64::try_from(i).unwrap_or(u64::MAX))),
                        ("reason", Value::Word(reason)),
                    ],
                );
            };
            if let Some(policy) = &self.policy
                && !address_permitted(url, policy)
            {
                failed("address_refused");
                continue;
            }
            let answer = self
                .agent
                .post(url)
                .header("Content-Type", "application/timestamp-query")
                .send(request_der);
            let answer = match answer {
                Ok(r) => read(r, MAX_ANSWER).ok_or("answer"),
                Err(ureq::Error::StatusCode(_)) => Err("status"),
                Err(ureq::Error::Timeout(_)) => Err("timeout"),
                Err(ureq::Error::Tls(_) | ureq::Error::Rustls(_)) => Err("tls"),
                Err(_) => Err("connect"),
            };
            match answer {
                Ok(a) => return Ok(a),
                Err(reason) => failed(reason),
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
            policy: None,
        })
    })
}

/// The TSAs a seal uses (docs/23 §5.4, `CON-07`): the enabled rows of
/// `platform.tsa_endpoints`, set by two key custodians in the console, read at most once
/// per `ttl`; while there are none, the deployment's `OPENSEAL_TSA_URLS`. Database URLs
/// pass the `SEC-W01` address policy again at every use.
#[derive(Debug)]
pub struct TsaDirectory {
    fallback: Vec<String>,
    policy: SsrfPolicy,
    ttl: Duration,
    /// When the database was last read, and what it held.
    state: Mutex<(Option<Instant>, Vec<String>)>,
}

impl TsaDirectory {
    /// A directory over `fallback` (the environment's URLs) and `policy`.
    #[must_use]
    pub fn new(fallback: Vec<String>, policy: SsrfPolicy, ttl: Duration) -> Arc<Self> {
        Arc::new(Self {
            fallback,
            policy,
            ttl,
            state: Mutex::new((None, Vec::new())),
        })
    }

    /// The URLs to try now and whether they came from the database.
    #[must_use]
    pub fn current(&self) -> (Vec<String>, bool) {
        let db = self.state.lock().map(|s| s.1.clone()).unwrap_or_default();
        if db.is_empty() {
            (self.fallback.clone(), false)
        } else {
            (db, true)
        }
    }

    /// Read the database when the last read is older than the cache's lifetime. A failed
    /// read keeps what was there (logged, with no URL).
    pub async fn refresh(&self, store: &Store) {
        let stale = self
            .state
            .lock()
            .map(|s| s.0.is_none_or(|at| at.elapsed() >= self.ttl))
            .unwrap_or(true);
        if !stale {
            return;
        }
        match store.entry_points().tsa_urls().await {
            Ok(urls) => {
                if let Ok(mut s) = self.state.lock() {
                    *s = (Some(Instant::now()), urls);
                }
            }
            Err(e) => crate::log(
                "WARN",
                "tsa_directory_unread",
                &[("code", e.code().to_owned())],
            ),
        }
    }

    /// A factory of time-stamp sources over the directory's URLs at each seal.
    #[must_use]
    pub fn factory(self: &Arc<Self>) -> TsaFactory {
        let dir = Arc::clone(self);
        let agent = agent();
        Arc::new(move || {
            let (urls, from_db) = dir.current();
            Box::new(HttpTsa {
                agent: agent.clone(),
                urls: Arc::new(urls),
                policy: from_db.then(|| dir.policy.clone()),
            })
        })
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
