//! The `SEC-W01` address policy for URLs an operator proposes (TSA endpoints, `CON-07`,
//! `SEC-X06`): `http://` or `https://`, no user information, and every address the host
//! resolves to now is public unicast, unless it is in the deployment's allowed ranges
//! (`OPENSEAL_CONSOLE_TSA_ALLOW`). The worker checks the addresses again when it connects.
//!
//! The address classification is copied from `casual-sign-worker`'s `webhook.rs` (this
//! repository, same licence): the console cannot depend on the worker (docs/23 §5.2).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use crate::net::Cidr;

/// Longest URL accepted.
pub const MAX_URL: usize = 2048;

fn v4_public(a: Ipv4Addr) -> bool {
    let [o0, o1, o2, _] = a.octets();
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
    if let Some(v4) = a.to_ipv4_mapped() {
        return v4_public(v4);
    }
    let [s0, s1, s2, s3, s4, s5, hi, lo] = a.segments();
    // NAT64 well-known prefix 64:ff9b::/96: judge the embedded IPv4.
    if s0 == 0x0064 && s1 == 0xff9b && [s2, s3, s4, s5] == [0, 0, 0, 0] {
        let v4 = Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo));
        return v4_public(v4);
    }
    !(a.is_unspecified()
        || a.is_loopback()
        || (s0 & 0xfe00) == 0xfc00
        || (s0 & 0xffc0) == 0xfe80
        || (s0 & 0xffc0) == 0xfec0
        || (s0 & 0xff00) == 0xff00
        || (s0 == 0x2001 && s1 == 0x0db8)
        || (s0 == 0x0100 && [s1, s2, s3] == [0, 0, 0])
        || (s0 == 0 && [s1, s2, s3, s4, s5] == [0, 0, 0, 0, 0]))
}

/// Whether `ip` is a public unicast address.
#[must_use]
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => v4_public(a),
        IpAddr::V6(a) => v6_public(a),
    }
}

/// The host and port of an `http://` or `https://` URL with no user information, or
/// `None`.
#[must_use]
pub fn authority(url: &str) -> Option<(String, u16)> {
    if url.len() > MAX_URL || !url.bytes().all(|b| b.is_ascii_graphic()) {
        return None;
    }
    let (rest, default) = if let Some(r) = url.strip_prefix("https://") {
        (r, 443)
    } else {
        (url.strip_prefix("http://")?, 80)
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

/// Whether `url` passes the policy now: its shape, and every address its host resolves
/// to public or in `allow`. Blocking (DNS); run on a blocking thread.
#[must_use]
pub fn permits(url: &str, allow: &[Cidr]) -> bool {
    let Some((host, port)) = authority(url) else {
        return false;
    };
    let Ok(addrs) = (host.as_str(), port).to_socket_addrs() else {
        return false;
    };
    let addrs: Vec<SocketAddr> = addrs.take(16).collect();
    !addrs.is_empty()
        && addrs
            .iter()
            .all(|a| is_public(a.ip()) || allow.iter().any(|c| c.contains(a.ip())))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // tests may unwrap (CLAUDE.md)
mod tests {
    use super::*;

    #[test]
    fn private_loopback_link_local_and_metadata_addresses_are_refused() {
        for url in [
            "http://127.0.0.1/tsr",
            "https://10.1.2.3/",
            "http://169.254.169.254/latest/meta-data",
            "http://[::1]:8080/",
            "http://[fd00:ec2::254]/",
            "http://192.168.1.1",
            "http://[::ffff:10.0.0.1]/",
            "ftp://1.1.1.1/",
            "https://user@1.1.1.1/",
            "https://1.1.1.1:0/",
        ] {
            assert!(!permits(url, &[]), "{url}");
        }
        assert!(permits("https://1.1.1.1/tsr", &[]));
        assert!(permits("http://[2606:4700:4700::1111]:80/", &[]));
        let lo = [Cidr::parse("127.0.0.0/8").unwrap()];
        assert!(permits("http://127.0.0.1:9/tsr", &lo));
    }
}
