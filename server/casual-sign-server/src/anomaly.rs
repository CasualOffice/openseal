//! Abnormal-activity detection (`ASVS-13`, ASVS 8.1.4, 11.1.7, 11.1.8; docs/65 §Logs,
//! docs/07 `SEC-D07`).
//!
//! The server counts, per principal and per client address, what an attack looks like
//! in its security events and requests: requests, `429`s, authentication failures,
//! refusals (`403`), staff document reads (mass download) and envelope voids. Each
//! count is a sliding window (two fixed buckets, the older weighted by how much of it
//! still overlaps the window). When a count reaches its threshold the server writes
//! one `alert.abnormal_activity` security event and raises one operator alert through
//! its [`AlertSink`] (by default a JSON line, `"event":"abnormal_activity"`, the same
//! channel as the worker's `job_dead` and `seal_failed`).
//!
//! **One alert per burst, not one per request.** After an alert the subject is quiet
//! for the cooldown; trips meanwhile are only counted, and the next alert says how many
//! (`suppressed`). Across all subjects at most `max_alerts_per_minute` alerts go out;
//! the rest are counted (`dropped`) in the next one.
//!
//! **Bounded memory.** Subjects are ids and keyed pseudonyms (never an address or an
//! e-mail in clear, `SEC-D01`), so every key has a fixed size, and the table holds at
//! most `max_tracked` of them. When it is full, idle entries are swept (at most once a
//! second); if it is still full, a new subject is not tracked, the table's own alert
//! (`rule: tracking_full`, `CS-LOG-0003`) says so, and the subjects already tracked keep
//! their counts: spraying many addresses cannot flush a tracked one.
//!
//! Counts are per server process. Behind a load balancer each instance sees a share of
//! the traffic; docs/65 §Logs gives the collector-side rules over every instance's lines.

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use std::time::Duration;

use casual_sign_seclog::{Level, Principal, Pseudonym, SecurityLog};
use serde_json::{Map, Value as Json};
use time::OffsetDateTime;

/// The code of an alert raised by a threshold (docs/20).
pub const CODE_THRESHOLD: &str = "CS-LOG-0002";
/// The code of the alert that the detector's table is full (docs/20).
pub const CODE_TABLE_FULL: &str = "CS-LOG-0003";

/// What is counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Rule {
    /// Every request.
    Requests,
    /// Requests answered `429`.
    RateLimited,
    /// Failed sign-ins, second factors, tokens, resets, password changes, invitation
    /// links, `401`s and recipient lockouts.
    AuthFailures,
    /// Requests refused `403`.
    Denied,
    /// Staff reads of a document, its data or its evidence.
    DocumentReads,
    /// Envelopes voided.
    Voids,
}

impl Rule {
    /// The name in the alert's `rule`.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Requests => "requests",
            Self::RateLimited => "rate_limited",
            Self::AuthFailures => "auth_failures",
            Self::Denied => "access_denied",
            Self::DocumentReads => "document_reads",
            Self::Voids => "voids",
        }
    }
}

/// The detection thresholds (docs/65 §Logs, `OPENSEAL_ALERT_*`). A threshold is the
/// count within one window that raises an alert; `0` turns that rule off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnomalyConfig {
    /// The sliding window every count covers (default 5 minutes).
    pub window: Duration,
    /// How long a subject stays quiet after an alert (default 15 minutes).
    pub cooldown: Duration,
    /// Requests per principal or address (default 6,000: 20 a second for 5 minutes).
    pub requests: u32,
    /// `429`s per principal or address (default 30).
    pub rate_limited: u32,
    /// Authentication failures per principal or address (default 20).
    pub auth_failures: u32,
    /// `403`s per principal or address (default 50).
    pub denied: u32,
    /// Staff document reads per principal (default 500).
    pub document_reads: u32,
    /// Envelopes voided per principal (default 25).
    pub voids: u32,
    /// Subjects tracked at once, per rule together (default 50,000).
    pub max_tracked: usize,
    /// Alerts raised per minute across every subject (default 20).
    pub max_alerts_per_minute: u32,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(300),
            cooldown: Duration::from_secs(900),
            requests: 6000,
            rate_limited: 30,
            auth_failures: 20,
            denied: 50,
            document_reads: 500,
            voids: 25,
            max_tracked: 50_000,
            max_alerts_per_minute: 20,
        }
    }
}

impl AnomalyConfig {
    /// The defaults, changed by whichever `OPENSEAL_ALERT_*` variables `var` gives.
    ///
    /// # Errors
    /// The variable's name and its allowed range when a value is not a whole number in
    /// that range (the server then does not start).
    pub fn from_vars(var: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let num = |n: &str, lo: u64, hi: u64| -> Result<Option<u64>, String> {
            var(n)
                .filter(|v| !v.trim().is_empty())
                .map(|v| {
                    v.trim()
                        .parse::<u64>()
                        .ok()
                        .filter(|x| (lo..=hi).contains(x))
                        .ok_or_else(|| format!("{n}: not a whole number from {lo} to {hi}"))
                })
                .transpose()
        };
        let mut c = Self::default();
        if let Some(s) = num("OPENSEAL_ALERT_WINDOW_SECS", 10, 86_400)? {
            c.window = Duration::from_secs(s);
        }
        if let Some(s) = num("OPENSEAL_ALERT_COOLDOWN_SECS", 0, 86_400)? {
            c.cooldown = Duration::from_secs(s);
        }
        let max = u64::from(u32::MAX);
        for (name, slot) in [
            ("OPENSEAL_ALERT_REQUESTS", &mut c.requests),
            ("OPENSEAL_ALERT_RATE_LIMITED", &mut c.rate_limited),
            ("OPENSEAL_ALERT_AUTH_FAILURES", &mut c.auth_failures),
            ("OPENSEAL_ALERT_DENIED", &mut c.denied),
            ("OPENSEAL_ALERT_DOCUMENT_READS", &mut c.document_reads),
            ("OPENSEAL_ALERT_VOIDS", &mut c.voids),
            (
                "OPENSEAL_ALERT_MAX_PER_MINUTE",
                &mut c.max_alerts_per_minute,
            ),
        ] {
            if let Some(v) = num(name, 0, max)? {
                *slot = u32::try_from(v).unwrap_or(u32::MAX);
            }
        }
        if let Some(n) = num("OPENSEAL_ALERT_MAX_TRACKED", 1_000, 10_000_000)? {
            c.max_tracked = usize::try_from(n).unwrap_or(c.max_tracked);
        }
        Ok(c)
    }

    const fn threshold(&self, rule: Rule) -> u32 {
        match rule {
            Rule::Requests => self.requests,
            Rule::RateLimited => self.rate_limited,
            Rule::AuthFailures => self.auth_failures,
            Rule::Denied => self.denied,
            Rule::DocumentReads => self.document_reads,
            Rule::Voids => self.voids,
        }
    }

    fn window_secs(&self) -> i64 {
        i64::try_from(self.window.as_secs())
            .unwrap_or(86_400)
            .max(1)
    }

    fn cooldown_secs(&self) -> i64 {
        i64::try_from(self.cooldown.as_secs()).unwrap_or(86_400)
    }
}

/// One operator alert: abnormal activity by a principal or from a client address.
/// Ids, fixed words, counts and pseudonyms only (`SEC-D01`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbnormalActivity {
    /// What was counted (`auth_failures`, `rate_limited`, `requests`, `access_denied`,
    /// `document_reads`, `voids`), or `tracking_full`.
    pub rule: &'static str,
    /// `CS-LOG-0002` (a threshold reached) or `CS-LOG-0003` (the table full).
    pub code: &'static str,
    /// The count in the window when it tripped (for `tracking_full`: subjects not
    /// tracked since the last such alert).
    pub count: u64,
    /// The threshold.
    pub threshold: u64,
    /// The window, in seconds.
    pub window_secs: u64,
    /// The principal over the threshold (`user:<id>`, `subject:p1:<hex>`, ...).
    pub principal: Option<String>,
    /// The client address over the threshold, as its pseudonym.
    pub client: Option<String>,
    /// Trips by these subjects held back by the cooldown since their last alert.
    pub suppressed: u64,
    /// Alerts held back by the per-minute cap since the last alert went out.
    pub dropped: u64,
}

/// Where the server's operator alerts go (a pager, a chat channel, a log). The same
/// seam as the worker's `AlertSink`.
pub trait AlertSink: Send + Sync + fmt::Debug {
    /// Raise one. Must not block for long and must not fail the request.
    fn alert(&self, alert: &AbnormalActivity);
}

/// Alerts as JSON lines through the security log's sink: `"event":"abnormal_activity"`,
/// `WARN`, beside the worker's `job_dead` and `seal_failed` (docs/65 §Logs).
#[derive(Debug, Clone)]
pub struct LogAlerts(pub SecurityLog);

impl AlertSink for LogAlerts {
    fn alert(&self, a: &AbnormalActivity) {
        let mut m = Map::new();
        m.insert("rule".into(), Json::from(a.rule));
        m.insert("code".into(), Json::from(a.code));
        m.insert("count".into(), Json::from(a.count));
        m.insert("threshold".into(), Json::from(a.threshold));
        m.insert("window_s".into(), Json::from(a.window_secs));
        if let Some(p) = &a.principal {
            m.insert("principal".into(), Json::from(p.as_str()));
        }
        if let Some(c) = &a.client {
            m.insert("client".into(), Json::from(c.as_str()));
        }
        m.insert("suppressed".into(), Json::from(a.suppressed));
        m.insert("dropped".into(), Json::from(a.dropped));
        self.0.info(Level::Warn, "abnormal_activity", m);
    }
}

/// Who a count is of.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Subject<'a> {
    /// A principal (an id, or a pseudonym of a presented identifier).
    Principal(&'a Principal),
    /// A client address, as its pseudonym.
    Address(&'a Pseudonym),
}

impl Subject<'_> {
    fn key(self, rule: Rule) -> String {
        match self {
            Self::Principal(p) => format!("{}|{}", rule.as_str(), p.text()),
            Self::Address(a) => format!("{}|address:{}", rule.as_str(), a.as_str()),
        }
    }
}

/// A count over its threshold that is due an alert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Trip {
    /// The rule, or `None` for the table full.
    pub rule: Option<Rule>,
    /// Which of the subjects observed are over the threshold (indexes).
    pub over: Vec<usize>,
    /// The largest count among them.
    pub count: u64,
    /// The threshold.
    pub threshold: u64,
    /// Trips held back by the cooldown since these subjects' last alert.
    pub suppressed: u64,
    /// Alerts held back by the per-minute cap.
    pub dropped: u64,
}

/// One subject's count.
#[derive(Debug, Clone, Copy)]
struct Slot {
    /// The window index of `cur`.
    bucket: i64,
    cur: u32,
    prev: u32,
    /// The last observation (seconds), for sweeping.
    last: i64,
    /// No alert for this subject before this time (seconds).
    quiet_until: i64,
    suppressed: u32,
}

impl Slot {
    const fn new(bucket: i64, now: i64) -> Self {
        Self {
            bucket,
            cur: 0,
            prev: 0,
            last: now,
            quiet_until: i64::MIN,
            suppressed: 0,
        }
    }

    /// Count one at `now` and give the sliding count.
    fn hit(&mut self, now: i64, window: i64) -> u64 {
        let idx = now.div_euclid(window);
        if idx <= self.bucket {
            // The same bucket (or a clock that went back): count here.
            self.cur = self.cur.saturating_add(1);
        } else if idx == self.bucket.saturating_add(1) {
            self.prev = self.cur;
            self.cur = 1;
            self.bucket = idx;
        } else {
            self.prev = 0;
            self.cur = 1;
            self.bucket = idx;
        }
        self.last = now;
        // The older bucket counts for the part of it still inside the window.
        let into = u64::try_from(now.rem_euclid(window)).unwrap_or(0);
        let w = u64::try_from(window).unwrap_or(1).max(1);
        let carried = u64::from(self.prev)
            .saturating_mul(w.saturating_sub(into))
            .checked_div(w)
            .unwrap_or(0);
        carried.saturating_add(u64::from(self.cur))
    }
}

#[derive(Debug, Default)]
struct Table {
    slots: HashMap<String, Slot>,
    last_sweep: i64,
    /// Subjects not tracked because the table was full, since the last such alert.
    untracked: u64,
    full_quiet_until: i64,
    /// The minute `sent` counts in, and alerts sent in it.
    minute: i64,
    sent: u32,
    /// Alerts held back by the cap since the last one went out.
    dropped: u64,
}

impl Table {
    /// Whether the per-minute cap lets one more alert out now; counts it if so.
    fn allow(&mut self, now: i64, cap: u32) -> bool {
        let minute = now.div_euclid(60);
        if minute != self.minute {
            self.minute = minute;
            self.sent = 0;
        }
        if self.sent >= cap {
            self.dropped = self.dropped.saturating_add(1);
            return false;
        }
        self.sent = self.sent.saturating_add(1);
        true
    }
}

/// The server's counters (one per process).
#[derive(Debug)]
pub(crate) struct Detector {
    config: AnomalyConfig,
    table: Mutex<Table>,
}

impl Detector {
    pub(crate) fn new(config: AnomalyConfig) -> Self {
        Self {
            config,
            table: Mutex::new(Table {
                last_sweep: i64::MIN,
                full_quiet_until: i64::MIN,
                ..Table::default()
            }),
        }
    }

    /// Subjects tracked now (tests).
    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.table.lock().map(|t| t.slots.len()).unwrap_or(0)
    }

    /// Count one `rule` event by each of `subjects` at `now`; the alerts now due.
    pub(crate) fn observe(
        &self,
        rule: Rule,
        subjects: &[Subject<'_>],
        now: OffsetDateTime,
    ) -> Vec<Trip> {
        let threshold = self.config.threshold(rule);
        if threshold == 0 || subjects.is_empty() {
            return Vec::new();
        }
        // A poisoned lock stops detection, never the request.
        let Ok(mut t) = self.table.lock() else {
            return Vec::new();
        };
        let now = now.unix_timestamp();
        let window = self.config.window_secs();
        let mut over = Vec::new();
        let mut due = false;
        let mut count = 0u64;
        let mut full = false;
        for (i, s) in subjects.iter().enumerate() {
            let key = s.key(rule);
            if !t.slots.contains_key(&key) && t.slots.len() >= self.config.max_tracked {
                if now > t.last_sweep {
                    t.last_sweep = now;
                    let idle = now.saturating_sub(window.saturating_mul(2));
                    t.slots.retain(|_, s| s.last >= idle || s.quiet_until > now);
                }
                if t.slots.len() >= self.config.max_tracked {
                    t.untracked = t.untracked.saturating_add(1);
                    full = true;
                    continue;
                }
            }
            let slot = t
                .slots
                .entry(key)
                .or_insert_with(|| Slot::new(now.div_euclid(window), now));
            let n = slot.hit(now, window);
            if n >= u64::from(threshold) {
                over.push(i);
                count = count.max(n);
                due |= now >= slot.quiet_until;
            }
        }
        let mut trips = Vec::new();
        if !over.is_empty() {
            let keys: Vec<String> = over
                .iter()
                .filter_map(|i| subjects.get(*i).map(|s| s.key(rule)))
                .collect();
            if due && t.allow(now, self.config.max_alerts_per_minute) {
                let quiet = now.saturating_add(self.config.cooldown_secs());
                let mut suppressed = 0u64;
                for k in &keys {
                    if let Some(s) = t.slots.get_mut(k) {
                        suppressed = suppressed.saturating_add(u64::from(s.suppressed));
                        s.suppressed = 0;
                        s.quiet_until = quiet;
                    }
                }
                trips.push(Trip {
                    rule: Some(rule),
                    over,
                    count,
                    threshold: u64::from(threshold),
                    suppressed,
                    dropped: std::mem::take(&mut t.dropped),
                });
            } else if !due {
                for k in &keys {
                    if let Some(s) = t.slots.get_mut(k) {
                        s.suppressed = s.suppressed.saturating_add(1);
                    }
                }
            }
        }
        if full && now >= t.full_quiet_until && t.allow(now, self.config.max_alerts_per_minute) {
            t.full_quiet_until = now.saturating_add(self.config.cooldown_secs());
            trips.push(Trip {
                rule: None,
                over: Vec::new(),
                count: std::mem::take(&mut t.untracked),
                threshold: u64::try_from(self.config.max_tracked).unwrap_or(u64::MAX),
                suppressed: 0,
                dropped: std::mem::take(&mut t.dropped),
            });
        }
        trips
    }

    /// The window, in seconds.
    pub(crate) fn window_secs(&self) -> u64 {
        self.config.window.as_secs()
    }
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report.
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;
    use casual_sign_seclog::{Domain, Pseudonymizer};

    fn at(s: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_794_391_200 + s).unwrap()
    }

    fn config() -> AnomalyConfig {
        AnomalyConfig {
            auth_failures: 5,
            ..AnomalyConfig::default()
        }
    }

    #[test]
    fn a_burst_from_one_address_trips_one_alert_not_one_per_event() {
        let d = Detector::new(config());
        let p = Pseudonymizer::new(&[1; 32]);
        let addr = p.of(Domain::Ip, b"198.51.100.7");
        let mut trips = Vec::new();
        for i in 0..50 {
            trips.extend(d.observe(Rule::AuthFailures, &[Subject::Address(&addr)], at(i)));
        }
        assert_eq!(trips.len(), 1, "{trips:?}");
        assert_eq!(trips[0].count, 5);
        assert_eq!(trips[0].over, vec![0]);
        // The burst going on past the cooldown (900 s after the alert at 4 s) alerts
        // again, once, and says how many trips were held back: 45 in the first burst,
        // and 894 s to 903 s (the count reaches 5 again at 894 s).
        let mut again = Vec::new();
        for i in 890..=905 {
            again.extend(d.observe(Rule::AuthFailures, &[Subject::Address(&addr)], at(i)));
        }
        assert_eq!(again.len(), 1, "{again:?}");
        assert_eq!(again[0].suppressed, 55);
    }

    #[test]
    fn a_count_below_the_threshold_or_spread_beyond_the_window_does_not_trip() {
        let d = Detector::new(config());
        let p = Pseudonymizer::new(&[1; 32]);
        let addr = p.of(Domain::Ip, b"198.51.100.7");
        for i in 0..4 {
            assert!(
                d.observe(Rule::AuthFailures, &[Subject::Address(&addr)], at(i))
                    .is_empty()
            );
        }
        // One failure every two windows never adds up.
        for i in 1..20 {
            assert!(
                d.observe(Rule::AuthFailures, &[Subject::Address(&addr)], at(i * 600))
                    .is_empty()
            );
        }
        // Rules count apart; 0 turns a rule off.
        let off = Detector::new(AnomalyConfig {
            auth_failures: 0,
            ..AnomalyConfig::default()
        });
        for i in 0..100 {
            assert!(
                off.observe(Rule::AuthFailures, &[Subject::Address(&addr)], at(i))
                    .is_empty()
            );
        }
    }

    #[test]
    fn the_sliding_window_carries_the_previous_bucket_in_part() {
        // Four in the last minute of one window and one at the start of the next: five
        // within five minutes.
        let d = Detector::new(config());
        let p = Pseudonymizer::new(&[1; 32]);
        let addr = p.of(Domain::Ip, b"198.51.100.7");
        // `at(0)` is on a window boundary (1_794_391_200 is a multiple of 300).
        let base = 300;
        for i in 0..4 {
            assert!(
                d.observe(
                    Rule::AuthFailures,
                    &[Subject::Address(&addr)],
                    at(base - 4 + i)
                )
                .is_empty()
            );
        }
        // At the boundary the previous bucket still counts in full.
        let t = d.observe(Rule::AuthFailures, &[Subject::Address(&addr)], at(base));
        assert_eq!(t.len(), 1, "{t:?}");
    }

    #[test]
    fn memory_stays_bounded_under_many_distinct_addresses_and_says_so_once() {
        let cap = 1_000;
        let d = Detector::new(AnomalyConfig {
            max_tracked: cap,
            auth_failures: 5,
            ..AnomalyConfig::default()
        });
        let p = Pseudonymizer::new(&[1; 32]);
        // A tracked address under attack before the spray.
        let victim = p.of(Domain::Ip, b"203.0.113.9");
        for i in 0..3 {
            assert!(
                d.observe(Rule::AuthFailures, &[Subject::Address(&victim)], at(i))
                    .is_empty()
            );
        }
        let mut full_alerts = 0;
        for i in 0..20_000u32 {
            let a = p.of(Domain::Ip, &i.to_be_bytes());
            for t in d.observe(Rule::AuthFailures, &[Subject::Address(&a)], at(10)) {
                assert_eq!(t.rule, None, "{t:?}");
                full_alerts += 1;
            }
            assert!(d.tracked() <= cap, "{}", d.tracked());
        }
        assert_eq!(full_alerts, 1);
        // The spray did not flush the tracked address: its count goes on.
        let mut t = Vec::new();
        for i in 0..2 {
            t.extend(d.observe(Rule::AuthFailures, &[Subject::Address(&victim)], at(20 + i)));
        }
        assert_eq!(t.len(), 1, "{t:?}");
        assert_eq!(t[0].rule, Some(Rule::AuthFailures));
        // Once the spray is idle for two windows, it is swept and new subjects counted.
        let late = p.of(Domain::Ip, b"192.0.2.1");
        let _ = d.observe(Rule::AuthFailures, &[Subject::Address(&late)], at(2_000));
        assert!(d.tracked() < 10, "{}", d.tracked());
    }

    #[test]
    fn the_per_minute_cap_holds_alerts_back_and_counts_them() {
        let d = Detector::new(AnomalyConfig {
            auth_failures: 1,
            max_alerts_per_minute: 3,
            ..AnomalyConfig::default()
        });
        let p = Pseudonymizer::new(&[1; 32]);
        let mut n = 0;
        for i in 0..10u32 {
            let a = p.of(Domain::Ip, &i.to_be_bytes());
            n += d
                .observe(Rule::AuthFailures, &[Subject::Address(&a)], at(0))
                .len();
        }
        assert_eq!(n, 3);
        let a = p.of(Domain::Ip, b"next minute");
        let t = d.observe(Rule::AuthFailures, &[Subject::Address(&a)], at(61));
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].dropped, 7);
    }

    #[test]
    fn thresholds_come_from_the_environment_and_bad_values_are_refused() {
        let c = AnomalyConfig::from_vars(|n| match n {
            "OPENSEAL_ALERT_AUTH_FAILURES" => Some("7".into()),
            "OPENSEAL_ALERT_VOIDS" => Some("0".into()),
            "OPENSEAL_ALERT_WINDOW_SECS" => Some(" 60 ".into()),
            _ => None,
        })
        .unwrap();
        assert_eq!(c.auth_failures, 7);
        assert_eq!(c.voids, 0);
        assert_eq!(c.window, Duration::from_secs(60));
        assert_eq!(c.requests, AnomalyConfig::default().requests);
        for (n, v) in [
            ("OPENSEAL_ALERT_WINDOW_SECS", "5"),
            ("OPENSEAL_ALERT_REQUESTS", "-1"),
            ("OPENSEAL_ALERT_MAX_TRACKED", "10"),
            ("OPENSEAL_ALERT_DENIED", "many"),
        ] {
            let e = AnomalyConfig::from_vars(|k| (k == n).then(|| v.to_owned())).unwrap_err();
            assert!(e.starts_with(n), "{e}");
        }
    }
}
