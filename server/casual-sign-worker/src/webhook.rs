//! Webhooks (docs/40 §4, ADR-016): Standard Webhooks signatures, at-least-once delivery
//! with stable event ids, no documents in payloads, and SSRF-safe connections
//! (`SEC-W01`).
//!
//! **SSRF.** A webhook URL must be `https://`. Its host is resolved by the worker and
//! every address checked before the request, and again inside the HTTP client's
//! resolver at connect time (so a DNS answer that changes between the two, a rebinding
//! attack, is caught where it matters). Private, loopback, link-local (and so the cloud
//! metadata address), carrier-grade NAT, documentation, benchmarking, multicast and
//! reserved ranges are refused, IPv4-mapped and NAT64 IPv6 by their embedded IPv4,
//! unless an operator allow-lists a range. Redirects are not followed, the whole
//! exchange has a 10-second budget, and at most 64 KiB of the answer is read.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{DefaultConnector, NextTimeout};

use crate::error::{Result, WorkerError};

/// Whole-exchange budget for one delivery (docs/40 §4: 10 s).
pub const TIMEOUT: Duration = Duration::from_secs(10);
/// Most bytes of a receiver's answer read (and discarded).
pub const MAX_ANSWER: u64 = 64 * 1024;
/// Longest webhook URL (as the database's CHECK).
pub const MAX_URL: usize = 2048;

/// An IP range, `address/prefix`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpRange {
    /// The network address.
    pub addr: IpAddr,
    /// The prefix length.
    pub prefix: u8,
}

impl IpRange {
    /// Parse `a.b.c.d/n` or `x::y/n` (a bare address is a single host).
    ///
    /// # Errors
    ///
    /// `CS-WRK-0001` for anything else.
    pub fn parse(text: &str) -> Result<Self> {
        let bad = WorkerError::Config {
            setting: "webhook.allow",
        };
        let (a, p) = match text.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (text, None),
        };
        let addr: IpAddr = a.trim().parse().map_err(|_| bad.clone())?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            Some(p) => p.trim().parse::<u8>().map_err(|_| bad.clone())?,
            None => max,
        };
        if prefix > max {
            return Err(bad);
        }
        Ok(Self { addr, prefix })
    }

    /// Whether `ip` is in the range.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let shift = 32u32.saturating_sub(u32::from(self.prefix));
                let mask = u32::MAX.checked_shl(shift).unwrap_or(0);
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let shift = 128u32.saturating_sub(u32::from(self.prefix));
                let mask = u128::MAX.checked_shl(shift).unwrap_or(0);
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }
}

fn v4_public(a: Ipv4Addr) -> bool {
    let o = a.octets();
    let (o0, o1, o2) = (o[0], o[1], o[2]);
    !(o0 == 0
        || o0 == 10
        || o0 == 127
        || (o0 == 100 && (64..=127).contains(&o1))
        || (o0 == 169 && o1 == 254)
        || (o0 == 172 && (16..=31).contains(&o1))
        || (o0 == 192 && o1 == 0 && o2 == 0)
        || (o0 == 192 && o1 == 0 && o2 == 2)
        || (o0 == 192 && o1 == 168)
        || (o0 == 198 && (18..=19).contains(&o1))
        || (o0 == 198 && o1 == 51 && o2 == 100)
        || (o0 == 203 && o1 == 0 && o2 == 113)
        || o0 >= 224)
}

fn v6_public(a: Ipv6Addr) -> bool {
    let s = a.segments();
    if let Some(v4) = a.to_ipv4_mapped() {
        return v4_public(v4);
    }
    // NAT64 well-known prefix 64:ff9b::/96: judge the embedded IPv4.
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        let [_, _, _, _, _, _, hi, lo] = s;
        let v4 = Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo));
        return v4_public(v4);
    }
    !(a.is_unspecified()
        || a.is_loopback()
        || (s[0] & 0xfe00) == 0xfc00 // unique local fc00::/7 (AWS IMDS fd00:ec2::254 too)
        || (s[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        || (s[0] & 0xffc0) == 0xfec0 // site-local fec0::/10 (deprecated)
        || (s[0] & 0xff00) == 0xff00 // multicast
        || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
        || (s[0] == 0x0100 && s[1..4] == [0, 0, 0]) // discard 100::/64
        || (s[0] == 0 && s[1..6] == [0, 0, 0, 0, 0])) // IPv4-compatible ::/96
}

/// Whether `ip` is a public unicast address a webhook may reach.
#[must_use]
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => v4_public(a),
        IpAddr::V6(a) => v6_public(a),
    }
}

/// The SSRF policy: public addresses, plus the operator's allow-list.
#[derive(Debug, Clone, Default)]
pub struct SsrfPolicy {
    /// Ranges allowed although not public (an internal receiver; tests on loopback).
    pub allow: Vec<IpRange>,
}

impl SsrfPolicy {
    /// Whether `ip` may be connected to.
    #[must_use]
    pub fn permits(&self, ip: IpAddr) -> bool {
        is_public(ip) || self.allow.iter().any(|r| r.contains(ip))
    }

    /// Check a URL's shape and every address its host resolves to now. Blocking (DNS).
    ///
    /// # Errors
    ///
    /// `CS-WRK-0008` when the URL is not `https://host[:port]/...`, its host does not
    /// resolve, or any address is refused.
    pub fn check_url(&self, url: &str) -> Result<()> {
        let (host, port) = https_authority(url)?;
        let addrs: Vec<SocketAddr> = (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|_| WorkerError::WebhookRefused)?
            .collect();
        if addrs.is_empty() || !addrs.iter().all(|a| self.permits(a.ip())) {
            return Err(WorkerError::WebhookRefused);
        }
        Ok(())
    }
}

/// The host and port of an `https://` URL with no user information.
///
/// # Errors
///
/// `CS-WRK-0008` for anything else.
pub fn https_authority(url: &str) -> Result<(String, u16)> {
    let refused = WorkerError::WebhookRefused;
    if url.len() > MAX_URL || !url.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(refused);
    }
    let rest = url.strip_prefix("https://").ok_or(refused.clone())?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return Err(refused);
    }
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, after) = v6.split_once(']').ok_or(refused.clone())?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse::<u16>().map_err(|_| refused.clone())?,
            None if after.is_empty() => 443,
            None => return Err(refused),
        };
        (h.to_owned(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_owned(), p.parse::<u16>().map_err(|_| refused.clone())?),
            None => (authority.to_owned(), 443),
        }
    };
    if host.is_empty() || port == 0 {
        return Err(refused);
    }
    Ok((host, port))
}

/// The HTTP client's resolver: the default one, then every address checked against
/// the policy at connect time.
#[derive(Debug)]
struct CheckedResolver {
    inner: DefaultResolver,
    policy: SsrfPolicy,
}

impl Resolver for CheckedResolver {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        config: &ureq::config::Config,
        timeout: NextTimeout,
    ) -> core::result::Result<ResolvedSocketAddrs, ureq::Error> {
        let addrs = self.inner.resolve(uri, config, timeout)?;
        if addrs.is_empty() || !addrs.iter().all(|a| self.policy.permits(a.ip())) {
            return Err(ureq::Error::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "address refused by the webhook SSRF policy",
            )));
        }
        Ok(addrs)
    }
}

/// A webhook sender: an HTTPS client with the SSRF policy in its resolver.
#[derive(Clone)]
pub struct Sender {
    agent: ureq::Agent,
    policy: SsrfPolicy,
}

impl core::fmt::Debug for Sender {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sender")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

/// One delivery's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Answer {
    /// The HTTP status.
    pub status: u16,
}

impl Answer {
    /// 2xx.
    #[must_use]
    pub fn delivered(self) -> bool {
        (200..300).contains(&self.status)
    }
}

impl Sender {
    /// A sender trusting the platform's roots plus `extra_roots` (DER), under `policy`.
    #[must_use]
    pub fn new(policy: SsrfPolicy, extra_roots: &[Vec<u8>]) -> Self {
        let native = rustls_native_certs::load_native_certs();
        let mut roots: Vec<ureq::tls::Certificate<'static>> = native
            .certs
            .iter()
            .map(|c| ureq::tls::Certificate::from_der(c.as_ref()).to_owned())
            .collect();
        roots.extend(
            extra_roots
                .iter()
                .map(|d| ureq::tls::Certificate::from_der(d).to_owned()),
        );
        let tls = ureq::tls::TlsConfig::builder()
            .provider(ureq::tls::TlsProvider::Rustls)
            .root_certs(ureq::tls::RootCerts::new_with_certs(&roots))
            .unversioned_rustls_crypto_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .build();
        let config = ureq::Agent::config_builder()
            .tls_config(tls)
            .https_only(true)
            .timeout_global(Some(TIMEOUT))
            .max_redirects(0)
            .http_status_as_error(false)
            .user_agent("OpenSeal-Webhooks/1")
            .build();
        let agent = ureq::Agent::with_parts(
            config,
            DefaultConnector::new(),
            CheckedResolver {
                inner: DefaultResolver::default(),
                policy: policy.clone(),
            },
        );
        Self { agent, policy }
    }

    /// POST `body` to `url` with `headers`. Blocking: call from a blocking thread.
    ///
    /// # Errors
    ///
    /// `CS-WRK-0008` when the URL or an address is refused; `CS-WRK-0009` when the
    /// exchange fails (the receiver's status is returned as an [`Answer`], not an error).
    pub fn post(&self, url: &str, headers: &[(String, String)], body: &[u8]) -> Result<Answer> {
        self.policy.check_url(url)?;
        let mut req = self
            .agent
            .post(url)
            .header("Content-Type", "application/json");
        for (k, v) in headers {
            req = req.header(k.as_str(), v.as_str());
        }
        match req.send(body) {
            Ok(mut resp) => {
                let status = resp.status().as_u16();
                // Read (and drop) a bounded answer, so the connection can be reused.
                let _ = resp
                    .body_mut()
                    .with_config()
                    .limit(MAX_ANSWER)
                    .read_to_vec();
                Ok(Answer { status })
            }
            Err(ureq::Error::Io(e)) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                Err(WorkerError::WebhookRefused)
            }
            Err(ureq::Error::RequireHttpsOnly(_)) => Err(WorkerError::WebhookRefused),
            Err(_) => Err(WorkerError::WebhookFailed { status: None }),
        }
    }
}

/// A Standard Webhooks secret (`whsec_` followed by base64), decoded to its key bytes.
///
/// # Errors
///
/// `CS-WRK-0010` for a secret without the prefix or with bad base64, or under 16 bytes.
pub fn secret_key(secret: &str) -> Result<Vec<u8>> {
    let b64 = secret
        .strip_prefix("whsec_")
        .ok_or(WorkerError::SecretMissing)?;
    let key = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| WorkerError::SecretMissing)?;
    if key.len() < 16 {
        return Err(WorkerError::SecretMissing);
    }
    Ok(key)
}

/// The `webhook-signature` header: `v1,<base64 HMAC-SHA256(key, id.timestamp.body)>`
/// for each key, space-separated (several during rotation).
#[must_use]
pub fn signature(keys: &[Vec<u8>], id: &str, timestamp: i64, body: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD;
    keys.iter()
        .map(|k| {
            let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, k);
            let mut ctx = aws_lc_rs::hmac::Context::with_key(&key);
            ctx.update(id.as_bytes());
            ctx.update(b".");
            ctx.update(timestamp.to_string().as_bytes());
            ctx.update(b".");
            ctx.update(body);
            format!("v1,{}", b64.encode(ctx.sign().as_ref()))
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The headers of one attempt.
#[must_use]
pub fn headers(keys: &[Vec<u8>], id: &str, timestamp: i64, body: &[u8]) -> Vec<(String, String)> {
    vec![
        ("webhook-id".into(), id.to_owned()),
        ("webhook-timestamp".into(), timestamp.to_string()),
        (
            "webhook-signature".into(),
            signature(keys, id, timestamp, body),
        ),
    ]
}

/// The event type a topic is published as (docs/40 §4).
#[must_use]
pub fn event_type(topic: casual_sign_workflow::WebhookTopic) -> String {
    use casual_sign_workflow::WebhookTopic as T;
    match topic {
        T::RecipientAuthLocked => "recipient.auth_failed".into(),
        T::RecipientAutoResponded => "recipient.bounced".into(),
        other => {
            let w = match serde_json::to_value(other) {
                Ok(serde_json::Value::String(s)) => s,
                _ => String::new(),
            };
            match w.split_once('_') {
                Some((a, b)) => format!("{a}.{b}"),
                None => w,
            }
        }
    }
}

#[cfg(test)]
// Tests may unwrap and index (CLAUDE.md).
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn non_public_addresses_are_refused() {
        for a in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "192.0.2.1",
            "198.18.0.1",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd00:ec2::254",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::a9fe:a9fe",
            "2001:db8::1",
            "::127.0.0.1",
        ] {
            let ip: IpAddr = a.parse().unwrap();
            assert!(!is_public(ip), "{a} should be refused");
        }
        for a in [
            "8.8.8.8",
            "1.1.1.1",
            "172.32.0.1",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            assert!(is_public(a.parse().unwrap()), "{a} should pass");
        }
    }

    #[test]
    fn allow_list_ranges() {
        let p = SsrfPolicy {
            allow: vec![IpRange::parse("127.0.0.0/8").unwrap()],
        };
        assert!(p.permits("127.0.0.1".parse().unwrap()));
        assert!(!p.permits("10.0.0.1".parse().unwrap()));
        assert!(IpRange::parse("10.0.0.0/33").is_err());
        assert!(IpRange::parse("nope").is_err());
        let all6 = IpRange::parse("::/0").unwrap();
        assert!(all6.contains("::1".parse().unwrap()));
    }

    #[test]
    fn only_https_urls_without_userinfo() {
        assert_eq!(
            https_authority("https://example.com/hook").unwrap(),
            ("example.com".into(), 443)
        );
        assert_eq!(
            https_authority("https://[::1]:8443/x").unwrap(),
            ("::1".into(), 8443)
        );
        for u in [
            "http://example.com/",
            "https://user@example.com/",
            "https:///x",
            "https://example.com:0/",
            "https://exa mple.com/",
            "ftp://x",
        ] {
            assert_eq!(https_authority(u).unwrap_err().code(), "CS-WRK-0008", "{u}");
        }
        let p = SsrfPolicy::default();
        assert_eq!(
            p.check_url("https://127.0.0.1/hook").unwrap_err().code(),
            "CS-WRK-0008"
        );
        assert_eq!(
            p.check_url("https://localhost:9/hook").unwrap_err().code(),
            "CS-WRK-0008"
        );
    }

    /// The Standard Webhooks specification's published example.
    #[test]
    fn signature_matches_the_standard_webhooks_example() {
        let key = secret_key("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw").unwrap();
        let sig = signature(
            &[key],
            "msg_p5jXN8AQM9LWM0D4loKWxJek",
            1_614_265_330,
            br#"{"test": 2432232314}"#,
        );
        assert_eq!(sig, "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=");
        assert!(secret_key("MfKQ9r8").is_err());
        assert!(secret_key("whsec_!!").is_err());
    }

    /// Secret rotation (`HRD-06`, docs/65 §Rotation): while a subscription names the old
    /// and the new secret, every delivery carries one signature per secret, so a receiver
    /// holding either one accepts it, before and after it switches.
    #[test]
    fn during_rotation_a_receiver_holding_either_secret_accepts_the_delivery() {
        let old = secret_key("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw").unwrap();
        let new = secret_key("whsec_c2Vjb25kLXNlY3JldC1mb3Itcm90YXRpb24=").unwrap();
        let (id, ts, body) = ("msg_1", 1_700_000_000, br#"{"type":"envelope.completed"}"#);
        let header = signature(&[old.clone(), new.clone()], id, ts, body);
        let sent: Vec<&str> = header.split(' ').collect();
        assert_eq!(sent.len(), 2);
        for receiver in [&old, &new] {
            let expected = signature(std::slice::from_ref(receiver), id, ts, body);
            assert!(sent.contains(&expected.as_str()), "{header}");
        }
        // After the old secret is removed, only the new one signs.
        assert_eq!(signature(std::slice::from_ref(&new), id, ts, body), sent[1]);
    }

    #[test]
    fn topics_are_dotted_event_types() {
        use casual_sign_workflow::WebhookTopic as T;
        assert_eq!(event_type(T::EnvelopeCompleted), "envelope.completed");
        assert_eq!(event_type(T::RecipientSent), "recipient.sent");
        assert_eq!(event_type(T::RecipientAuthLocked), "recipient.auth_failed");
        assert_eq!(event_type(T::RecipientAutoResponded), "recipient.bounced");
    }
}
