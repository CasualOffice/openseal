//! The client's address, as evidence (docs/32 §1.5): the socket peer, unless the peer
//! is a configured trusted proxy, in which case the right-most hop of `Forwarded` (or
//! `X-Forwarded-For`) that is not itself a trusted proxy. A forwarding header from any
//! other peer is ignored: anyone can write one. The address is personal data: it goes
//! into audit events only, never into logs.

use std::net::{IpAddr, SocketAddr};

use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request};

/// The longest user agent recorded, in bytes (docs/21).
pub const MAX_USER_AGENT_BYTES: usize = 512;

/// A network: an address and a prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parse `10.0.0.0/8`, `::1/128` or a bare address.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = a.trim().parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            Some(p) => p.trim().parse().ok().filter(|p| *p <= max)?,
            None => max,
        };
        Some(Self { addr, prefix })
    }

    /// Whether `ip` is inside.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        match (canonical(self.addr), ip) {
            (IpAddr::V4(n), IpAddr::V4(i)) => {
                let shift = 32u32.saturating_sub(u32::from(self.prefix));
                let mask = u32::MAX.checked_shl(shift).unwrap_or(0);
                (u32::from(n) & mask) == (u32::from(i) & mask)
            }
            (IpAddr::V6(n), IpAddr::V6(i)) => {
                let shift = 128u32.saturating_sub(u32::from(self.prefix));
                let mask = u128::MAX.checked_shl(shift).unwrap_or(0);
                (u128::from(n) & mask) == (u128::from(i) & mask)
            }
            _ => false,
        }
    }
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// The client address of a request, as the request middleware determined it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClientIp(pub Option<IpAddr>);

fn hop(s: &str) -> Option<IpAddr> {
    let s = s.trim().trim_matches('"');
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Some(sa.ip());
    }
    // `[v6]` without a port, or `v4:port`.
    let s = s.trim_start_matches('[');
    let s = s.split(']').next().unwrap_or(s);
    s.parse().ok()
}

/// The forwarding chain, left (original client) to right (nearest proxy):
/// `Forwarded: for=` if present, else `X-Forwarded-For`.
fn chain(headers: &HeaderMap) -> Vec<Option<IpAddr>> {
    let forwarded: Vec<&str> = headers
        .get_all("forwarded")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    if !forwarded.is_empty() {
        return forwarded
            .iter()
            .flat_map(|v| v.split(','))
            .filter_map(|elem| {
                elem.split(';').find_map(|pair| {
                    let (k, v) = pair.split_once('=')?;
                    k.trim().eq_ignore_ascii_case("for").then(|| hop(v))
                })
            })
            .collect();
    }
    headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(hop)
        .collect()
}

/// The client address: the peer, or through trusted proxies the right-most untrusted
/// hop. An unparsable hop where the answer would be stops the walk at the last trusted
/// proxy's peer rather than guessing.
#[must_use]
pub fn client_ip(peer: Option<IpAddr>, headers: &HeaderMap, trusted: &[Cidr]) -> Option<IpAddr> {
    let peer = peer?;
    let is_trusted = |ip: IpAddr| trusted.iter().any(|c| c.contains(ip));
    if !is_trusted(peer) {
        return Some(peer);
    }
    let mut current = peer;
    for h in chain(headers).into_iter().rev() {
        match h {
            Some(ip) if is_trusted(ip) => current = ip,
            Some(ip) => return Some(ip),
            None => return Some(current),
        }
    }
    Some(current)
}

/// The peer address axum recorded for the connection, if any.
pub(crate) fn peer<B>(req: &Request<B>) -> Option<IpAddr> {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip())
}

/// The user agent, bounded to [`MAX_USER_AGENT_BYTES`] at a character boundary.
pub(crate) fn user_agent(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(axum::http::header::USER_AGENT)?.as_bytes();
    let ua =
        String::from_utf8_lossy(raw.get(..raw.len().min(MAX_USER_AGENT_BYTES.saturating_mul(2)))?);
    let ua = ua.as_ref();
    let mut end = ua.len().min(MAX_USER_AGENT_BYTES);
    while !ua.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    ua.get(..end).map(str::to_owned)
}

#[cfg(test)]
// Tests may unwrap, index and panic (CLAUDE.md).
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn cidrs_match_their_networks_only() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains(ip("10.9.8.7")));
        assert!(c.contains(ip("::ffff:10.1.1.1")));
        assert!(!c.contains(ip("11.0.0.1")));
        assert!(Cidr::parse("::1").unwrap().contains(ip("::1")));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(ip("8.8.8.8")));
        assert!(Cidr::parse("10.0.0.0/33").is_none());
        assert!(Cidr::parse("nonsense").is_none());
    }

    #[test]
    fn forwarding_headers_count_only_from_trusted_proxies() {
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_static("1.1.1.1, 203.0.113.9, 10.0.0.2"),
        );
        let trusted = [Cidr::parse("10.0.0.0/8").unwrap()];
        // From an untrusted peer the header is ignored.
        assert_eq!(
            client_ip(Some(ip("198.51.100.4")), &h, &trusted),
            Some(ip("198.51.100.4"))
        );
        // From a trusted proxy: the right-most untrusted hop, not the spoofable left-most.
        assert_eq!(
            client_ip(Some(ip("10.0.0.1")), &h, &trusted),
            Some(ip("203.0.113.9"))
        );
        // With nothing trusted, never the header.
        assert_eq!(
            client_ip(Some(ip("10.0.0.1")), &h, &[]),
            Some(ip("10.0.0.1"))
        );
        let mut f = HeaderMap::new();
        f.insert(
            "forwarded",
            HeaderValue::from_static("for=192.0.2.60;proto=https, for=\"[2001:db8::1]:4711\""),
        );
        assert_eq!(
            client_ip(Some(ip("10.0.0.1")), &f, &trusted),
            Some(ip("2001:db8::1"))
        );
        assert_eq!(client_ip(None, &h, &trusted), None);
    }

    #[test]
    fn user_agents_are_bounded_at_a_character_boundary() {
        let mut h = HeaderMap::new();
        let long = "é".repeat(400);
        h.insert(
            axum::http::header::USER_AGENT,
            HeaderValue::from_bytes(long.as_bytes()).unwrap(),
        );
        let ua = user_agent(&h).unwrap();
        assert!(ua.len() <= MAX_USER_AGENT_BYTES);
        assert!(ua.chars().all(|c| c == 'é'));
    }
}
