//! Service health (docs/23 §5.5): the database, the job queue and dead letters through
//! definer functions, and the services listed in `platform.service_targets` (set by
//! deployment configuration, never by an operator, `SEC-X06`), each probed with a short
//! timeout: `http` targets with a GET (healthy on 2xx), `tcp` targets by connecting.
//!
//! keyd's own `health` operation is read through its admin interface ([`crate::keys`],
//! `CON-06`) when the console is configured with keyd's address.

use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use casual_sign_platform_store::ServiceTarget;
use serde::Serialize;

/// Most targets probed at once.
pub const MAX_TARGETS: usize = 64;

/// One probe's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Probe {
    /// The target's name.
    pub name: String,
    /// What it is.
    pub role: String,
    /// `http` or `tcp`.
    pub probe: String,
    /// `up` or `down`.
    pub status: &'static str,
    /// Time to answer, milliseconds.
    pub latency_ms: u64,
    /// For an `http` probe that answered, the status code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
}

fn tcp(target: &str, timeout: Duration) -> bool {
    let Ok(addrs) = target.to_socket_addrs() else {
        return false;
    };
    addrs
        .take(4)
        .any(|a| TcpStream::connect_timeout(&a, timeout).is_ok())
}

fn http(url: &str, timeout: Duration) -> Option<u16> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .http_status_as_error(false)
        .max_redirects(0)
        .build()
        .into();
    agent.get(url).call().ok().map(|r| r.status().as_u16())
}

/// Probe one target (blocking; run on a blocking thread).
#[must_use]
pub fn probe(t: &ServiceTarget, timeout: Duration) -> Probe {
    let started = Instant::now();
    let (up, http_status) = match t.probe.as_str() {
        "http" => {
            let s = http(&t.target, timeout);
            (s.is_some_and(|c| (200..300).contains(&c)), s)
        }
        "tcp" => (tcp(&t.target, timeout), None),
        _ => (false, None),
    };
    Probe {
        name: t.name.clone(),
        role: t.role.clone(),
        probe: t.probe.clone(),
        status: if up { "up" } else { "down" },
        latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        http_status,
    }
}

/// Probe every target concurrently.
pub async fn probe_all(targets: Vec<ServiceTarget>, timeout: Duration) -> Vec<Probe> {
    let handles: Vec<_> = targets
        .into_iter()
        .take(MAX_TARGETS)
        .map(|t| {
            tokio::task::spawn_blocking(move || {
                let r = probe(&t, timeout);
                (t, r)
            })
        })
        .collect();
    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        if let Ok((_, r)) = h.await {
            out.push(r);
        }
    }
    out
}
