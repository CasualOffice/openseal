//! What every handler shares: the store, the blob store, the PDF engine, the token key,
//! the clock, the configuration and the rate limiter.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use casual_sign_sdk::{Engine, FontSet, Limits};
use casual_sign_store::Store;
use casual_sign_store::blob::{BlobKey, BlobStore, FsBlobStore, S3BlobStore};
use time::OffsetDateTime;

use crate::crypto::JwtKeys;
use crate::error::ApiError;

/// The server's time. Supplied, so tests can move it (CLAUDE.md: time is supplied).
pub trait Clock: Send + Sync + core::fmt::Debug {
    /// Now.
    fn now(&self) -> OffsetDateTime;
}

/// The operating system's clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// A clock a test sets.
#[derive(Debug, Default)]
pub struct ManualClock(AtomicI64);

impl ManualClock {
    /// At `t`, to the millisecond.
    #[must_use]
    pub fn at(t: OffsetDateTime) -> Self {
        let ms = i64::try_from(t.unix_timestamp_nanos() / 1_000_000).unwrap_or(0);
        Self(AtomicI64::new(ms))
    }

    /// Move forward by `d`.
    pub fn advance(&self, d: Duration) {
        let ms = i64::try_from(d.as_millis()).unwrap_or(i64::MAX);
        let _ = self
            .0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                Some(v.saturating_add(ms))
            });
    }
}

impl Clock for ManualClock {
    fn now(&self) -> OffsetDateTime {
        let ms = self.0.load(Ordering::SeqCst);
        OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms).saturating_mul(1_000_000))
            .unwrap_or(OffsetDateTime::UNIX_EPOCH)
    }
}

/// Where document blobs live.
#[derive(Debug, Clone)]
pub enum Blobs {
    /// A directory.
    Fs(Arc<FsBlobStore>),
    /// An S3-compatible bucket.
    S3(Arc<S3BlobStore>),
}

impl Blobs {
    pub(crate) async fn put(&self, bytes: &[u8]) -> Result<BlobKey, ApiError> {
        Ok(match self {
            Self::Fs(s) => s.put(bytes).await?,
            Self::S3(s) => s.put(bytes).await?,
        })
    }

    pub(crate) async fn get(&self, key: &BlobKey) -> Result<Vec<u8>, ApiError> {
        Ok(match self {
            Self::Fs(s) => s.get(key).await?,
            Self::S3(s) => s.get(key).await?,
        })
    }
}

/// Requests allowed per minute (docs/40 §1 rate limits, docs/21).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimits {
    /// Per authenticated principal on `/api/v1`.
    pub api_per_minute: u32,
    /// Per ceremony token, and separately per client address, on `/s/`.
    pub ceremony_per_minute: u32,
    /// Login and token attempts per client address and per login name.
    pub login_per_minute: u32,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            api_per_minute: 1200,
            ceremony_per_minute: 300,
            login_per_minute: 10,
        }
    }
}

/// Server settings.
#[derive(Debug, Clone)]
pub struct Config {
    /// This server's public base URL (no trailing slash), for links and the token
    /// issuer.
    pub public_url: String,
    /// Staff session lifetime.
    pub session_ttl: Duration,
    /// Access token lifetime (docs/40 §2: one hour).
    pub access_token_ttl: Duration,
    /// Embedded view link lifetime (docs/40 §5: five minutes).
    pub view_ttl: Duration,
    /// Rate limits.
    pub rate: RateLimits,
    /// Largest JSON body.
    pub max_json_bytes: usize,
    /// Largest uploaded document (docs/21: 50 MiB).
    pub max_document_bytes: usize,
    /// Largest total of an envelope's uploaded documents (docs/21: 200 MiB), whether
    /// they arrive in one create or one upload at a time (`FG-006`).
    pub max_envelope_bytes: usize,
    /// Largest adopted signature image.
    pub max_image_bytes: usize,
    /// Mark cookies `Secure` (off only for plain-HTTP development).
    pub secure_cookies: bool,
    /// Proxies whose `Forwarded` / `X-Forwarded-For` is believed (none by default).
    pub trusted_proxies: Vec<crate::net::Cidr>,
    /// The model bundle the operator deployed with the model service (docs/33 §7,
    /// WEB-19): its id (`[A-Za-z0-9._-]{1,64}`, from the bundle's `bundle.json`) goes
    /// into every analysis job's key. `None` (the default): no model service, so no
    /// feature is in effect and no analysis job is ever enqueued.
    pub ml_bundle: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            public_url: "http://localhost:8080".into(),
            session_ttl: Duration::from_secs(8 * 3600),
            access_token_ttl: Duration::from_secs(3600),
            view_ttl: Duration::from_secs(300),
            rate: RateLimits::default(),
            max_json_bytes: 1024 * 1024,
            max_document_bytes: 50 * 1024 * 1024,
            max_envelope_bytes: 200 * 1024 * 1024,
            max_image_bytes: 5 * 1024 * 1024,
            secure_cookies: true,
            trusted_proxies: Vec::new(),
            ml_bundle: None,
        }
    }
}

/// A fixed-window counter per key: at most `limit` hits per 60 s window. Bounded: the
/// map is swept of past windows when it grows past 100,000 keys.
#[derive(Debug, Default)]
pub(crate) struct RateLimiter {
    windows: Mutex<HashMap<String, (i64, u32)>>,
}

/// What the limiter answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RateDecision {
    pub allowed: bool,
    pub limit: u32,
    pub remaining: u32,
    pub reset_secs: u64,
}

impl RateLimiter {
    pub(crate) fn hit(&self, key: &str, limit: u32, now: OffsetDateTime) -> RateDecision {
        let window = now.unix_timestamp().div_euclid(60);
        let reset =
            u64::try_from(60_i64.saturating_sub(now.unix_timestamp().rem_euclid(60))).unwrap_or(60);
        let Ok(mut map) = self.windows.lock() else {
            // A poisoned lock fails closed.
            return RateDecision {
                allowed: false,
                limit,
                remaining: 0,
                reset_secs: reset,
            };
        };
        if map.len() > 100_000 {
            map.retain(|_, (w, _)| *w == window);
        }
        let slot = map.entry(key.to_owned()).or_insert((window, 0));
        if slot.0 != window {
            *slot = (window, 0);
        }
        slot.1 = slot.1.saturating_add(1);
        RateDecision {
            allowed: slot.1 <= limit,
            limit,
            remaining: limit.saturating_sub(slot.1),
            reset_secs: reset,
        }
    }
}

/// `t` plus `d`, refusing an overflow (`CS-API-0010`).
pub(crate) fn plus(t: OffsetDateTime, d: time::Duration) -> Result<OffsetDateTime, ApiError> {
    t.checked_add(d).ok_or_else(|| ApiError::internal("time"))
}

/// `t` plus a standard duration.
pub(crate) fn plus_std(t: OffsetDateTime, d: Duration) -> Result<OffsetDateTime, ApiError> {
    plus(
        t,
        time::Duration::try_from(d).map_err(|_| ApiError::internal("time"))?,
    )
}

/// Everything a handler needs. Cheap to clone.
#[derive(Debug, Clone)]
pub struct AppState(pub(crate) Arc<Inner>);

#[derive(Debug)]
pub(crate) struct Inner {
    pub store: Store,
    pub blobs: Blobs,
    pub engine: Engine,
    pub jwt: JwtKeys,
    pub clock: Arc<dyn Clock>,
    pub config: Config,
    pub limiter: RateLimiter,
    pub dummy_phc: String,
    pub geoip: std::sync::OnceLock<Arc<crate::geo::GeoIp>>,
    pub webapp: std::sync::OnceLock<Arc<crate::web::WebApp>>,
    pub idps: std::sync::OnceLock<Arc<crate::idp::RecipientIdps>>,
    pub mfa: std::sync::OnceLock<Arc<crate::mfa::MfaKey>>,
    pub scanner: std::sync::OnceLock<Arc<crate::scan::Scanner>>,
}

impl AppState {
    /// The state for `store` and `blobs`, signing access tokens with `jwt`.
    ///
    /// # Errors
    ///
    /// `CS-API-0010` when the startup secrets cannot be made.
    pub fn new(
        store: Store,
        blobs: Blobs,
        jwt: JwtKeys,
        clock: Arc<dyn Clock>,
        config: Config,
    ) -> Result<Self, ApiError> {
        Ok(Self(Arc::new(Inner {
            store,
            blobs,
            engine: Engine::new(Limits::default(), FontSet::bundled()),
            jwt,
            clock,
            config,
            limiter: RateLimiter::default(),
            dummy_phc: crate::crypto::dummy_phc()?,
            geoip: std::sync::OnceLock::new(),
            webapp: std::sync::OnceLock::new(),
            idps: std::sync::OnceLock::new(),
            mfa: std::sync::OnceLock::new(),
            scanner: std::sync::OnceLock::new(),
        })))
    }

    /// Approximate signer locations from `geoip` (row GEO-01). Set once; a second
    /// call is ignored.
    pub fn set_geoip(&self, geoip: crate::geo::GeoIp) {
        let _ = self.0.geoip.set(Arc::new(geoip));
    }

    /// Serve `webapp` at `/` and its signing page at `/s/{token}` for a browser (row
    /// WEB-04). Set once; a second call is ignored.
    pub fn set_webapp(&self, webapp: crate::web::WebApp) {
        let _ = self.0.webapp.set(Arc::new(webapp));
    }

    /// Let recipients sign in through `idps` (`sso`, RAUTH-01). Set once; a second call
    /// is ignored.
    pub fn set_recipient_idps(&self, idps: crate::idp::RecipientIdps) {
        let _ = self.0.idps.set(Arc::new(idps));
    }

    /// Let staff enrol a TOTP second factor, its seeds sealed under `key` (ASVS-01).
    /// Without it, enrolment answers `409 CS-API-0009` and no account may require a
    /// factor. Set once; a second call is ignored.
    pub fn set_mfa_key(&self, key: crate::mfa::MfaKey) {
        let _ = self.0.mfa.set(Arc::new(key));
    }

    /// Scan every upload with `scanner` before it is read or stored (ASVS-11). Without
    /// it, nothing is scanned. Set once; a second call is ignored.
    pub fn set_scanner(&self, scanner: crate::scan::Scanner) {
        let _ = self.0.scanner.set(Arc::new(scanner));
    }

    pub(crate) fn scanner(&self) -> Option<&Arc<crate::scan::Scanner>> {
        self.0.scanner.get()
    }

    pub(crate) fn mfa_key(&self) -> Option<&Arc<crate::mfa::MfaKey>> {
        self.0.mfa.get()
    }

    pub(crate) fn webapp(&self) -> Option<&Arc<crate::web::WebApp>> {
        self.0.webapp.get()
    }

    pub(crate) fn now(&self) -> OffsetDateTime {
        self.0.clock.now()
    }

    pub(crate) fn store(&self) -> &Store {
        &self.0.store
    }

    pub(crate) fn config(&self) -> &Config {
        &self.0.config
    }
}

#[cfg(test)]
// Tests may unwrap, index and panic (CLAUDE.md).
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_limiter_counts_per_key_per_window() {
        let l = RateLimiter::default();
        let t = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        assert!(l.hit("a", 2, t).allowed);
        assert!(l.hit("a", 2, t).allowed);
        let third = l.hit("a", 2, t);
        assert!(!third.allowed);
        assert_eq!(third.remaining, 0);
        assert!(l.hit("b", 2, t).allowed);
        assert!(l.hit("a", 2, t + time::Duration::seconds(60)).allowed);
    }
}
