//! The operator's catalogue of signing providers (ADR-046 §3.11): a JSON file named by
//! `OPENSEAL_SIGNING_PROVIDERS_FILE`, read by the server and the worker at start, as the
//! recipient identity providers are (RAUTH-01, `OPENSEAL_RECIPIENT_IDPS_FILE`). For each
//! provider: an id and a display name, its kind (`csc`), the CSC API base URI and OAuth
//! 2.0 endpoints, the OAuth client registered there with its secret **by reference** (the
//! name of a secret read through `casual-sign-secrets`, `NAME` or `NAME_FILE`), the
//! trust anchors its signers' certificates chain to (a PEM file), and the accounts it is
//! offered to (`["*"]` for every account).
//!
//! **Network.** Endpoints come from the operator's file, never from a request. They must
//! be HTTPS, except `http` to a loopback address for a provider on the same host (a test
//! stack); the client checks every resolved address again before each request
//! (`SEC-W01`).

use std::path::Path;

use serde::Deserialize;

use crate::error::CscError;

/// Largest catalogue file read.
pub const MAX_FILE: u64 = 256 * 1024;
/// Most providers one catalogue lists.
pub const MAX_PROVIDERS: usize = 32;
/// Largest trust-anchor file read for one provider.
pub const MAX_ANCHORS_FILE: u64 = 256 * 1024;

/// What kind of provider (ADR-046 §3.11; `in_esign` is ADR-047's, not built).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Kind {
    /// A Cloud Signature Consortium API v2 service.
    Csc,
}

impl Kind {
    /// The wire name (`provider.kind` in the audit events).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Csc => "csc",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileIn {
    providers: Vec<ProviderIn>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderIn {
    id: String,
    kind: Kind,
    name: String,
    base_uri: String,
    authorization_endpoint: String,
    token_endpoint: String,
    client_id: String,
    client_secret_ref: String,
    trust_anchors_file: String,
    accounts: Vec<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
}

/// One provider of the catalogue.
pub struct Provider {
    /// The operator's id (`^[a-z0-9][a-z0-9-]{0,31}$`).
    pub id: String,
    /// What kind.
    pub kind: Kind,
    /// The name shown to senders and signers and printed on the certificate.
    pub name: String,
    /// The CSC API base URI (`…/csc/v2`), no trailing slash.
    pub base_uri: String,
    /// OAuth 2.0 authorization endpoint (the browser is sent here, top-level).
    pub authorization_endpoint: String,
    /// OAuth 2.0 token endpoint (the worker exchanges codes here).
    pub token_endpoint: String,
    /// The operator's OAuth client id.
    pub client_id: String,
    /// The operator's OAuth client secret, read at start.
    pub client_secret: casual_sign_secrets::Secret,
    /// The PEM of the anchors the provider's signer certificates chain to.
    pub trust_anchors_pem: Vec<u8>,
    /// Accounts it is offered to (UUID text); `None` for every account.
    pub accounts: Option<Vec<String>>,
    /// Where the provider sends the browser back (registered at the provider).
    pub redirect_uri: String,
}

impl core::fmt::Debug for Provider {
    /// The id and kind only: never the client secret.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Provider")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl Provider {
    /// Whether the catalogue offers this provider to `account` (UUID text).
    #[must_use]
    pub fn offered_to(&self, account: &str) -> bool {
        self.accounts
            .as_ref()
            .is_none_or(|list| list.iter().any(|a| a.eq_ignore_ascii_case(account)))
    }
}

/// The catalogue.
#[derive(Debug, Default)]
pub struct Catalogue {
    providers: Vec<Provider>,
}

/// Whether `url` is HTTPS, or HTTP to a loopback host, with a host and no credentials,
/// spaces or fragment.
#[must_use]
pub fn allowed_url(url: &str) -> bool {
    if url.len() > 2048 || url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return false;
    };
    if url.contains('#') {
        return false;
    }
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    let host = if let Some(h) = authority.strip_prefix('[') {
        h.split(']').next().unwrap_or("")
    } else {
        authority.rsplit_once(':').map_or(authority, |(h, _)| h)
    };
    if host.is_empty() {
        return false;
    }
    https || is_loopback_host(host)
}

/// `localhost`, `127.0.0.0/8` or `::1`.
#[must_use]
pub fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

fn valid_id(id: &str) -> bool {
    let b = id.as_bytes();
    (1..=32).contains(&b.len())
        && b.first()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

fn valid_account(a: &str) -> bool {
    a.len() == 36
        && a.bytes().enumerate().all(|(i, c)| {
            matches!(i, 8 | 13 | 18 | 23) == (c == b'-') && (c == b'-' || c.is_ascii_hexdigit())
        })
}

impl Catalogue {
    /// An empty catalogue: remote signing off.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Parse a catalogue, resolving each client secret through `secret` (its reference to
    /// its value) and each trust-anchor file through `read` (bounded to
    /// [`MAX_ANCHORS_FILE`]). `public_url` is the server's public address, for the
    /// default redirect URI `{public_url}/s/rsp`.
    ///
    /// # Errors
    /// `CS-RSP-0010` naming the provider and member at fault; `CS-KEY-0005` an
    /// unreadable secret.
    pub fn parse(
        text: &[u8],
        public_url: &str,
        secret: &dyn Fn(&str) -> Result<Option<casual_sign_secrets::Secret>, CscError>,
        read: &dyn Fn(&str) -> Option<Vec<u8>>,
    ) -> Result<Self, CscError> {
        let bad =
            |index: Option<usize>, member: &'static str| CscError::Catalogue { index, member };
        let file: FileIn = serde_json::from_slice(text).map_err(|_| bad(None, "json"))?;
        if file.providers.len() > MAX_PROVIDERS {
            return Err(bad(None, "providers"));
        }
        let mut providers: Vec<Provider> = Vec::with_capacity(file.providers.len());
        for (i, p) in file.providers.into_iter().enumerate() {
            let at = Some(i);
            if !valid_id(&p.id) || providers.iter().any(|q| q.id == p.id) {
                return Err(bad(at, "id"));
            }
            if p.name.trim().is_empty() || p.name.chars().count() > 100 {
                return Err(bad(at, "name"));
            }
            for (url, member) in [
                (&p.base_uri, "base_uri"),
                (&p.authorization_endpoint, "authorization_endpoint"),
                (&p.token_endpoint, "token_endpoint"),
            ] {
                if !allowed_url(url) || url.contains('?') && member == "base_uri" {
                    return Err(bad(at, member));
                }
            }
            if p.client_id.is_empty() || p.client_id.len() > 255 {
                return Err(bad(at, "client_id"));
            }
            let client_secret =
                secret(&p.client_secret_ref)?.ok_or_else(|| bad(at, "client_secret_ref"))?;
            let trust_anchors_pem = read(&p.trust_anchors_file)
                .filter(|b| !b.is_empty() && b.windows(11).any(|w| w == b"-----BEGIN "))
                .ok_or_else(|| bad(at, "trust_anchors_file"))?;
            let accounts = if p.accounts == ["*"] {
                None
            } else if p.accounts.is_empty() || !p.accounts.iter().all(|a| valid_account(a)) {
                return Err(bad(at, "accounts"));
            } else {
                Some(p.accounts)
            };
            let redirect_uri = match p.redirect_uri {
                Some(r) if allowed_url(&r) => r,
                Some(_) => return Err(bad(at, "redirect_uri")),
                None => format!("{}/s/rsp", public_url.trim_end_matches('/')),
            };
            providers.push(Provider {
                id: p.id,
                kind: p.kind,
                name: p.name.trim().to_owned(),
                base_uri: p.base_uri.trim_end_matches('/').to_owned(),
                authorization_endpoint: p.authorization_endpoint,
                token_endpoint: p.token_endpoint,
                client_id: p.client_id,
                client_secret,
                trust_anchors_pem,
                accounts,
                redirect_uri,
            });
        }
        Ok(Self { providers })
    }

    /// The catalogue `OPENSEAL_SIGNING_PROVIDERS_FILE` names (empty when unset), each
    /// secret read through `casual-sign-secrets`.
    ///
    /// # Errors
    /// As [`Catalogue::parse`]; `CS-RSP-0010` an unreadable or oversized file.
    pub fn from_env(public_url: &str) -> Result<Self, CscError> {
        let Some(path) = std::env::var_os("OPENSEAL_SIGNING_PROVIDERS_FILE") else {
            return Ok(Self::empty());
        };
        let text = read_bounded(Path::new(&path), MAX_FILE).ok_or(CscError::Catalogue {
            index: None,
            member: "file",
        })?;
        Self::parse(
            &text,
            public_url,
            &|name| casual_sign_secrets::env_secret(name).map_err(CscError::Secret),
            &|p| read_bounded(Path::new(p), MAX_ANCHORS_FILE),
        )
    }

    /// Every provider.
    #[must_use]
    pub fn providers(&self) -> &[Provider] {
        &self.providers
    }

    /// The provider `id`.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Provider> {
        self.providers.iter().find(|p| p.id == id)
    }

    /// Whether the catalogue lists any provider.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }
}

fn read_bounded(path: &Path, max: u64) -> Option<Vec<u8>> {
    use std::io::Read as _;
    let f = std::fs::File::open(path).ok()?;
    let mut out = Vec::new();
    f.take(max.saturating_add(1)).read_to_end(&mut out).ok()?;
    (u64::try_from(out.len()).ok()? <= max).then_some(out)
}

#[cfg(test)]
// Tests may unwrap and index (CLAUDE.md).
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    const PEM: &[u8] = b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n";

    fn parse(json: &str) -> Result<Catalogue, CscError> {
        Catalogue::parse(
            json.as_bytes(),
            "https://sign.example.test/",
            &|name| {
                Ok((name == "CSC_SECRET")
                    .then(|| casual_sign_secrets::Secret::new("s3cret".to_owned())))
            },
            &|p| (p == "/anchors.pem").then(|| PEM.to_vec()),
        )
    }

    fn one(extra: &str) -> String {
        format!(
            r#"{{"providers": [{{"id": "csc-ci", "kind": "csc", "name": "CI provider",
            "base_uri": "https://csc.example.test/csc/v2/",
            "authorization_endpoint": "https://csc.example.test/oauth2/authorize",
            "token_endpoint": "https://csc.example.test/oauth2/token",
            "client_id": "openseal", "client_secret_ref": "CSC_SECRET",
            "trust_anchors_file": "/anchors.pem", "accounts": ["*"]{extra}}}]}}"#
        )
    }

    #[test]
    fn a_provider_is_read_with_its_secret_by_reference() {
        let c = parse(&one("")).unwrap();
        let p = c.get("csc-ci").unwrap();
        assert_eq!(p.base_uri, "https://csc.example.test/csc/v2");
        assert_eq!(p.redirect_uri, "https://sign.example.test/s/rsp");
        assert_eq!(p.client_secret.expose(), "s3cret");
        assert!(p.offered_to("0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"));
        assert!(!format!("{p:?}").contains("s3cret"));
    }

    #[test]
    fn faults_name_the_member_and_never_a_value() {
        let cases = [
            (one("").replace("csc-ci", "CSC CI"), "id"),
            (
                one("").replace(
                    "https://csc.example.test/oauth2/token",
                    "http://csc.example.test/t",
                ),
                "token_endpoint",
            ),
            (
                one("").replace("CSC_SECRET", "MISSING"),
                "client_secret_ref",
            ),
            (
                one("").replace("/anchors.pem", "/nothing.pem"),
                "trust_anchors_file",
            ),
            (one("").replace(r#"["*"]"#, r#"["acct-1"]"#), "accounts"),
            (one(r#", "pin": "1234""#), "json"),
        ];
        for (json, member) in cases {
            match parse(&json) {
                Err(CscError::Catalogue { member: m, .. }) => assert_eq!(m, member, "{json}"),
                other => panic!("{member}: {other:?}"),
            }
        }
    }

    #[test]
    fn loopback_http_is_the_only_plain_http() {
        assert!(allowed_url("http://127.0.0.1:8091/csc/v2"));
        assert!(allowed_url("http://localhost:8091/authorize"));
        assert!(allowed_url("https://csc.example.test/x?y=1"));
        assert!(!allowed_url("http://csc:8091/csc/v2"));
        assert!(!allowed_url("https://user@csc.example.test/"));
        assert!(!allowed_url("ftp://csc.example.test/"));
        assert!(!allowed_url("https://csc.example.test/#frag"));
    }

    #[test]
    fn a_provider_offered_to_some_accounts_only() {
        let c = parse(&one("").replace(r#"["*"]"#, r#"["0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"]"#))
            .unwrap();
        let p = c.get("csc-ci").unwrap();
        assert!(p.offered_to("0193A1B2-C3D4-7E5F-8A9B-0C1D2E3F4A5B"));
        assert!(!p.offered_to("0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c"));
    }
}
