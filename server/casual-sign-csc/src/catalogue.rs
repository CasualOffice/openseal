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

/// What kind of provider (ADR-046 §3.11, ADR-047).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Kind {
    /// A Cloud Signature Consortium API v2 service.
    Csc,
    /// An India eSign Service Provider under the CCA eSign API, OpenSeal its ASP.
    InEsign,
}

impl Kind {
    /// The wire name (`provider.kind` in the audit events).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Csc => "csc",
            Self::InEsign => "in_esign",
        }
    }
}

/// Largest CMS placeholder an eSign row may plan (the engine's own bound is 1 MiB).
pub const MAX_ESIGN_PLACEHOLDER: usize = 512 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EsignIn {
    esign_url: String,
    #[serde(default = "default_api_version")]
    api_version: String,
    asp_id: String,
    asp_key_alias: String,
    response_certificate_file: String,
    cms_format: String,
    #[serde(default = "default_request_field")]
    request_field: String,
    #[serde(default = "default_response_field")]
    response_field: String,
    #[serde(default = "default_auth_modes")]
    auth_modes: Vec<String>,
    #[serde(default = "default_placeholder")]
    placeholder_bytes: usize,
    #[serde(default)]
    response_url: Option<String>,
    #[serde(default)]
    send_document_names: Option<bool>,
}

fn default_api_version() -> String {
    "2.1".to_owned()
}
fn default_request_field() -> String {
    "eSignRequest".to_owned()
}
fn default_response_field() -> String {
    "eSignResponse".to_owned()
}
fn default_auth_modes() -> Vec<String> {
    vec!["otp".to_owned(), "face".to_owned()]
}
const fn default_placeholder() -> usize {
    64 * 1024
}

/// An India eSign row's settings (ADR-047 §3.1 to §3.6).
#[derive(Debug, Clone)]
pub struct Esign {
    /// The ESP's page the browser posts the request to (v2.1).
    pub esign_url: String,
    /// The API version (`2.1`; `3.3` is `RSP-02A`).
    pub api_version: String,
    /// The ASP id the ESP registered for the operator.
    pub asp_id: String,
    /// keyd's alias of the ASP request-signing key (`asp-*`).
    pub asp_key_alias: String,
    /// The ESP's response-signing certificate, DER: the only key an answer is verified
    /// under (never one from the message).
    pub response_certificate: Vec<u8>,
    /// The ESP's CMS is CAdES-conformant (`cades`) or not (`pkcs7`): the `/SubFilter`
    /// written at preparation, which is inside the signed bytes.
    pub cades: bool,
    /// The form field the request goes in.
    pub request_field: String,
    /// The form field the answer comes back in.
    pub response_field: String,
    /// The authentication modes offered to signers (`otp`, `face`, `fingerprint`,
    /// `iris`).
    pub auth_modes: Vec<String>,
    /// The CMS placeholder planned, bytes.
    pub placeholder_bytes: usize,
    /// Where the ESP sends the answer: `{public_url}/rsp/esign/{id}/response`.
    pub response_url: String,
    /// Send the document's name as `docInfo` (owner instruction 82), or a generic label.
    pub send_document_names: bool,
}

fn pem_first_certificate(pem: &[u8]) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let text = core::str::from_utf8(pem).ok()?;
    let body = text
        .split("-----BEGIN CERTIFICATE-----")
        .nth(1)?
        .split("-----END CERTIFICATE-----")
        .next()?;
    let b64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(b64).ok()
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
    #[serde(default)]
    base_uri: String,
    #[serde(default)]
    authorization_endpoint: String,
    #[serde(default)]
    token_endpoint: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    client_secret_ref: String,
    trust_anchors_file: String,
    accounts: Vec<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
    #[serde(default)]
    esign: Option<EsignIn>,
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
    /// An India eSign row's settings (`kind` `in_esign`).
    pub esign: Option<Esign>,
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

/// An eSign row's settings, checked (ADR-047 §3.1 to §3.6).
fn esign_of(
    e: EsignIn,
    id: &str,
    public_url: &str,
    read: &dyn Fn(&str) -> Option<Vec<u8>>,
    at: Option<usize>,
) -> Result<Esign, CscError> {
    let bad = |member: &'static str| CscError::Catalogue { index: at, member };
    if !allowed_url(&e.esign_url) {
        return Err(bad("esign.esign_url"));
    }
    if e.api_version != "2.1" {
        // v3.3 is `RSP-02A`.
        return Err(bad("esign.api_version"));
    }
    let token = |s: &str, max: usize| {
        !s.is_empty()
            && s.len() <= max
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
    };
    if !token(&e.asp_id, 64) {
        return Err(bad("esign.asp_id"));
    }
    if !e.asp_key_alias.starts_with("asp-") || !token(&e.asp_key_alias, 64) {
        return Err(bad("esign.asp_key_alias"));
    }
    let response_certificate = read(&e.response_certificate_file)
        .and_then(|pem| pem_first_certificate(&pem))
        .ok_or_else(|| bad("esign.response_certificate_file"))?;
    let cades = match e.cms_format.as_str() {
        "cades" => true,
        "pkcs7" => false,
        _ => return Err(bad("esign.cms_format")),
    };
    for (f, member) in [
        (&e.request_field, "esign.request_field"),
        (&e.response_field, "esign.response_field"),
    ] {
        if !token(f, 64) {
            return Err(bad(member));
        }
    }
    if e.auth_modes.is_empty()
        || e.auth_modes.len() > 4
        || !e
            .auth_modes
            .iter()
            .all(|m| ["otp", "face", "fingerprint", "iris"].contains(&m.as_str()))
    {
        return Err(bad("esign.auth_modes"));
    }
    if !(8 * 1024..=MAX_ESIGN_PLACEHOLDER).contains(&e.placeholder_bytes) {
        return Err(bad("esign.placeholder_bytes"));
    }
    let response_url = match e.response_url {
        Some(r) if allowed_url(&r) || r.starts_with("https://") => r,
        Some(_) => return Err(bad("esign.response_url")),
        None => format!(
            "{}/rsp/esign/{id}/response",
            public_url.trim_end_matches('/')
        ),
    };
    Ok(Esign {
        esign_url: e.esign_url,
        api_version: e.api_version,
        asp_id: e.asp_id,
        asp_key_alias: e.asp_key_alias,
        response_certificate,
        cades,
        request_field: e.request_field,
        response_field: e.response_field,
        auth_modes: e.auth_modes,
        placeholder_bytes: e.placeholder_bytes,
        response_url,
        send_document_names: e.send_document_names.unwrap_or(true),
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
            let esign = match (p.kind, p.esign) {
                (Kind::InEsign, Some(e)) => Some(esign_of(e, &p.id, public_url, read, at)?),
                (Kind::InEsign, None) => return Err(bad(at, "esign")),
                (_, Some(_)) => return Err(bad(at, "esign")),
                (_, None) => None,
            };
            let client_secret = if esign.is_some() {
                casual_sign_secrets::Secret::new(String::new())
            } else {
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
                secret(&p.client_secret_ref)?.ok_or_else(|| bad(at, "client_secret_ref"))?
            };
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
                esign,
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

    fn esign_row(extra: &str) -> String {
        format!(
            r#"{{"providers": [{{"id": "esign-ci", "kind": "in_esign", "name": "CI ESP",
            "trust_anchors_file": "/anchors.pem", "accounts": ["*"],
            "esign": {{"esign_url": "https://esp.example.test/esign/2.1/signdoc",
            "asp_id": "ASP-OPENSEAL", "asp_key_alias": "asp-ci",
            "response_certificate_file": "/anchors.pem", "cms_format": "pkcs7"{extra}}}}}]}}"#
        )
    }

    #[test]
    fn an_esign_row_is_read_with_its_defaults() {
        let c = parse(&esign_row("")).unwrap();
        let p = c.get("esign-ci").unwrap();
        assert_eq!(p.kind, Kind::InEsign);
        let e = p.esign.as_ref().unwrap();
        assert_eq!(
            e.response_url,
            "https://sign.example.test/rsp/esign/esign-ci/response"
        );
        assert_eq!(e.auth_modes, ["otp", "face"]);
        assert!(!e.cades);
        assert_eq!(e.api_version, "2.1");
        assert_eq!(e.response_certificate, vec![0u8]);
        assert!(e.send_document_names);
    }

    #[test]
    fn an_esign_row_names_its_fault() {
        for (json, member) in [
            (
                esign_row("").replace("asp-ci", "platform"),
                "esign.asp_key_alias",
            ),
            (esign_row("").replace("pkcs7", "ber"), "esign.cms_format"),
            (esign_row(r#", "api_version": "3.3""#), "esign.api_version"),
            (
                esign_row(r#", "auth_modes": ["otp", "uid"]"#),
                "esign.auth_modes",
            ),
            (
                esign_row("").replace("https://esp.example.test", "http://esp.example.test"),
                "esign.esign_url",
            ),
            (esign_row("").replace(r#""esign": {"#, r#""x": {"#), "json"),
            (one(r#", "esign": {}"#), "json"),
        ] {
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
