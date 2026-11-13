//! What every handler needs: the platform store, the clock, the MFA key, the
//! configuration and the rate limiter.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use casual_sign_platform_store::PlatformStore;
use time::OffsetDateTime;

use crate::crypto::MfaKey;
use crate::error::ConsoleError;
use crate::net::Cidr;

/// The source of "now". Time is supplied, so tests can move it.
pub trait Clock: Send + Sync + core::fmt::Debug {
    /// The current time.
    fn now(&self) -> OffsetDateTime;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// Requests per 60-second window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimits {
    /// Sign-in attempts per client address.
    pub login_per_ip: u32,
    /// Sign-in attempts per e-mail (hashed in memory).
    pub login_per_email: u32,
    /// TOTP attempts per operator.
    pub totp_per_operator: u32,
    /// Requests per operator session.
    pub api_per_session: u32,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            login_per_ip: 10,
            login_per_email: 5,
            totp_per_operator: 5,
            api_per_session: 600,
        }
    }
}

/// The console's configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Where to listen (`OPENSEAL_CONSOLE_LISTEN`, default `127.0.0.1:8090`).
    pub listen: SocketAddr,
    /// Session lifetime (8 hours, docs/23 §5.1; the database refuses longer).
    pub session_ttl: Duration,
    /// Rate limits.
    pub rate: RateLimits,
    /// Proxies whose forwarding headers count (`OPENSEAL_TRUSTED_PROXIES`).
    pub trusted_proxies: Vec<Cidr>,
    /// Timeout of one health probe.
    pub probe_timeout: Duration,
    /// Largest request body.
    pub max_body_bytes: usize,
    /// keyd's admin interface (`OPENSEAL_CONSOLE_KEYD_*`, `CON-06`), when configured.
    pub keyd: Option<casual_sign_keyd_client::AdminClient>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 8090)),
            session_ttl: Duration::from_secs(8 * 3600),
            rate: RateLimits::default(),
            trusted_proxies: Vec::new(),
            probe_timeout: Duration::from_secs(2),
            max_body_bytes: 64 * 1024,
            keyd: None,
        }
    }
}

/// Refuse a listener that would expose the console (docs/23 §5.2, `SEC-X03`): a
/// non-loopback address needs `public` (`OPENSEAL_CONSOLE_PUBLIC=1`) and trusted proxies
/// (the console speaks plain HTTP behind a TLS-terminating proxy); and the console's
/// origin may not be the public application's.
///
/// # Errors
/// `CS-CON-0005` naming the reason.
pub fn check_listener(
    listen: SocketAddr,
    public: bool,
    trusted_proxies: &[Cidr],
    console_origin: Option<&str>,
    app_origin: Option<&str>,
) -> Result<(), ConsoleError> {
    if !listen.ip().is_loopback() {
        if !public {
            return Err(ConsoleError::ListenerRefused(
                "non-loopback bind without OPENSEAL_CONSOLE_PUBLIC=1",
            ));
        }
        if trusted_proxies.is_empty() {
            return Err(ConsoleError::ListenerRefused(
                "public bind without OPENSEAL_TRUSTED_PROXIES (TLS terminates at the proxy)",
            ));
        }
    }
    if let (Some(c), Some(a)) = (console_origin, app_origin) {
        let norm = |s: &str| s.trim().trim_end_matches('/').to_ascii_lowercase();
        if norm(c) == norm(a) {
            return Err(ConsoleError::ListenerRefused(
                "console origin is the public application's origin",
            ));
        }
    }
    Ok(())
}

/// A fixed-window counter per key: at most `limit` hits per 60 s window (as the
/// server's). Bounded: past windows are swept when the map passes 100,000 keys.
#[derive(Debug, Default)]
pub(crate) struct RateLimiter {
    windows: Mutex<HashMap<String, (i64, u32)>>,
}

impl RateLimiter {
    /// Count a hit; `Err` with the seconds to the next window when over the limit.
    pub(crate) fn hit(
        &self,
        key: &str,
        limit: u32,
        now: OffsetDateTime,
    ) -> Result<(), ConsoleError> {
        let window = now.unix_timestamp().div_euclid(60);
        let reset =
            u64::try_from(60_i64.saturating_sub(now.unix_timestamp().rem_euclid(60))).unwrap_or(60);
        let Ok(mut map) = self.windows.lock() else {
            // A poisoned lock fails closed.
            return Err(ConsoleError::RateLimited(reset));
        };
        if map.len() > 100_000 {
            map.retain(|_, (w, _)| *w == window);
        }
        let slot = map.entry(key.to_owned()).or_insert((window, 0));
        if slot.0 != window {
            *slot = (window, 0);
        }
        slot.1 = slot.1.saturating_add(1);
        if slot.1 > limit {
            Err(ConsoleError::RateLimited(reset))
        } else {
            Ok(())
        }
    }
}

/// Everything a handler needs. Cheap to clone.
#[derive(Debug, Clone)]
pub struct AppState(pub(crate) Arc<Inner>);

#[derive(Debug)]
pub(crate) struct Inner {
    pub store: PlatformStore,
    pub mfa: MfaKey,
    pub clock: Arc<dyn Clock>,
    pub config: Config,
    pub limiter: RateLimiter,
    /// A PHC string no password matches, checked against when the e-mail is unknown, so
    /// a sign-in takes the same time either way.
    pub dummy_phc: String,
}

impl AppState {
    /// The state over `store`.
    ///
    /// # Errors
    /// `CS-CON-0014` when the start-up secret cannot be made.
    pub fn new(
        store: PlatformStore,
        mfa: MfaKey,
        clock: Arc<dyn Clock>,
        config: Config,
    ) -> Result<Self, ConsoleError> {
        Ok(Self(Arc::new(Inner {
            store,
            mfa,
            clock,
            config,
            limiter: RateLimiter::default(),
            dummy_phc: crate::crypto::hash_password(&crate::crypto::random_secret()?)?,
        })))
    }

    pub(crate) fn now(&self) -> OffsetDateTime {
        self.0.clock.now()
    }

    pub(crate) fn store(&self) -> &PlatformStore {
        &self.0.store
    }

    pub(crate) fn config(&self) -> &Config {
        &self.0.config
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // tests may unwrap (CLAUDE.md)
mod tests {
    use super::*;

    #[test]
    fn a_public_bind_needs_the_flag_and_proxies_and_a_separate_origin() {
        let lo: SocketAddr = "127.0.0.1:8090".parse().unwrap();
        let any: SocketAddr = "0.0.0.0:8090".parse().unwrap();
        let proxies = [Cidr::parse("10.0.0.0/8").unwrap()];
        assert!(check_listener(lo, false, &[], None, None).is_ok());
        assert!(check_listener("[::1]:8090".parse().unwrap(), false, &[], None, None).is_ok());
        for (public, p) in [(false, &[][..]), (true, &[][..]), (false, &proxies[..])] {
            assert_eq!(
                check_listener(any, public, p, None, None)
                    .unwrap_err()
                    .code(),
                "CS-CON-0005"
            );
        }
        assert!(check_listener(any, true, &proxies, None, None).is_ok());
        assert_eq!(
            check_listener(
                lo,
                false,
                &[],
                Some("https://sign.example.com/"),
                Some("https://SIGN.example.com")
            )
            .unwrap_err()
            .code(),
            "CS-CON-0005"
        );
        assert!(
            check_listener(
                lo,
                false,
                &[],
                Some("https://console.example.com"),
                Some("https://sign.example.com")
            )
            .is_ok()
        );
    }

    #[test]
    fn the_limiter_counts_per_key_per_window() {
        let l = RateLimiter::default();
        let t = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        assert!(l.hit("a", 2, t).is_ok());
        assert!(l.hit("a", 2, t).is_ok());
        assert_eq!(l.hit("a", 2, t).unwrap_err().code(), "CS-CON-0012");
        assert!(l.hit("b", 2, t).is_ok());
        assert!(l.hit("a", 2, t + time::Duration::seconds(60)).is_ok());
    }
}
