//! Public anchoring of audit chain heads (docs/32 §5, `FG-158`): the worker's side.
//!
//! Each UTC day `D`, from `D + 1` 00:00 plus [`ANCHOR_DELAY`], a worker with anchoring on
//! queues one `anchor_chain_heads` job per account that has an audit event in `D`
//! (`openseal_enqueue_anchor_jobs`, migration 0041; days up to [`LOOKBACK_DAYS`] back
//! are queued too, so a worker that was down catches up). The job takes, for every
//! envelope whose chain gained an event in `D`, its head as of the end of `D`; builds the
//! RFC 6962 tree over those heads in envelope id order; gets an RFC 3161 token over the
//! tree's statement (root and size) from the deployment's TSAs; stores the anchor and
//! every leaf's audit path in one transaction; then hands the published form (no
//! envelope, no account) to the [`AnchorSink`] and closes the job.
//!
//! Crash safety: nothing is stored before the token is checked; the anchor and its leaves
//! commit together and at most one per account and day (`UNIQUE (account_id, period)`);
//! a job that finds its day already anchored publishes it again and closes. Publication
//! is therefore at least once: a line can appear twice after a crash, with the same id.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use time::{Date, OffsetDateTime, Time};

// Made in `casual-sign-host` so the API serves the same proof bytes the worker stores
// and publishes (`GET /api/v1/envelopes/{id}/anchor-proof`).
pub use casual_sign_host::anchor::{anchor_of, period_text, proof_file, proof_files, published};

/// How long after a day ends its anchor is queued: events recorded with a time just
/// before midnight have committed by then.
pub const ANCHOR_DELAY: Duration = Duration::from_secs(10 * 60);
/// How many closed days back a worker queues anchors for (catching up after downtime).
pub const LOOKBACK_DAYS: u8 = 7;

/// Where published anchors go: one canonical JSON line per anchor (`openseal.anchor`).
pub trait AnchorSink: Send + Sync {
    /// Publish `line` (canonical JSON, no newline).
    ///
    /// # Errors
    ///
    /// When the sink did not take it; the job is retried and publishes again.
    fn publish(&self, line: &[u8]) -> Result<(), SinkFailed>;
}

/// A sink did not take a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SinkFailed;

/// Appends each line and a newline to a file and syncs it: the operator publishes the
/// file (a transparency page, a public repository, a mailing list).
#[derive(Debug)]
pub struct FileSink {
    path: PathBuf,
    lock: Mutex<()>,
}

impl FileSink {
    /// A sink appending to `path` (created when absent).
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            lock: Mutex::new(()),
        }
    }
}

impl AnchorSink for FileSink {
    fn publish(&self, line: &[u8]) -> Result<(), SinkFailed> {
        let _held = self.lock.lock().map_err(|_| SinkFailed)?;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| SinkFailed)?;
        let mut buf = Vec::with_capacity(line.len().saturating_add(1));
        buf.extend_from_slice(line);
        buf.push(b'\n');
        f.write_all(&buf).map_err(|_| SinkFailed)?;
        f.sync_data().map_err(|_| SinkFailed)
    }
}

/// `[start, end)` of UTC day `day`.
#[must_use]
pub fn day_bounds(day: Date) -> (OffsetDateTime, OffsetDateTime) {
    let start = day.with_time(Time::MIDNIGHT).assume_utc();
    let end = day
        .next_day()
        .map_or(OffsetDateTime::new_utc(Date::MAX, Time::MAX), |d| {
            d.with_time(Time::MIDNIGHT).assume_utc()
        });
    (start, end)
}

/// The latest UTC day whose anchor is due at `now`.
#[must_use]
pub fn latest_due(now: OffsetDateTime) -> Option<Date> {
    let delay = time::Duration::try_from(ANCHOR_DELAY).unwrap_or(time::Duration::ZERO);
    now.to_offset(time::UtcOffset::UTC)
        .checked_sub(delay)?
        .date()
        .previous_day()
}

/// The days to queue at `now`, oldest first: those after `done` (the latest already
/// queued by this process), at most [`LOOKBACK_DAYS`] back.
#[must_use]
pub fn days_to_queue(now: OffsetDateTime, done: Option<Date>) -> Vec<Date> {
    let Some(latest) = latest_due(now) else {
        return Vec::new();
    };
    let mut days = Vec::new();
    let mut d = latest;
    for _ in 0..LOOKBACK_DAYS {
        if done.is_some_and(|x| d <= x) {
            break;
        }
        days.push(d);
        match d.previous_day() {
            Some(p) => d = p,
            None => break,
        }
    }
    days.reverse();
    days
}

/// `YYYY-MM-DD` read back.
#[must_use]
pub fn parse_period(text: &str) -> Option<Date> {
    let mut parts = text.splitn(3, '-');
    let year: i32 = parts.next()?.parse().ok()?;
    let month: u8 = parts.next()?.parse().ok()?;
    let day: u8 = parts.next()?.parse().ok()?;
    let d = Date::from_calendar_date(year, time::Month::try_from(month).ok()?, day).ok()?;
    (period_text(d) == text).then_some(d)
}

#[cfg(test)]
// Tests may unwrap and index (CLAUDE.md).
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn day(m: u8, d: u8) -> Date {
        Date::from_calendar_date(2026, time::Month::try_from(m).unwrap(), d).unwrap()
    }

    fn at(d: Date, h: u8, m: u8, s: u8) -> OffsetDateTime {
        d.with_hms(h, m, s).unwrap().assume_utc()
    }

    #[test]
    fn the_day_is_due_ten_minutes_after_it_ends() {
        assert_eq!(latest_due(at(day(11, 17), 0, 9, 59)), Some(day(11, 15)));
        assert_eq!(latest_due(at(day(11, 17), 0, 10, 0)), Some(day(11, 16)));
        let days = days_to_queue(at(day(11, 17), 8, 0, 0), None);
        assert_eq!(days.len(), 7);
        assert_eq!(days[6], day(11, 16));
        let after = days_to_queue(at(day(11, 17), 8, 0, 0), Some(day(11, 14)));
        assert_eq!(after, vec![day(11, 15), day(11, 16)]);
        assert!(days_to_queue(at(day(11, 17), 8, 0, 0), Some(days[6])).is_empty());
        let (s, e) = day_bounds(days[6]);
        assert_eq!(s, at(day(11, 16), 0, 0, 0));
        assert_eq!(e, at(day(11, 17), 0, 0, 0));
        assert_eq!(parse_period("2026-11-16"), Some(days[6]));
        assert_eq!(parse_period("2026-11-6"), None);
        assert_eq!(parse_period("2026-02-30"), None);
        assert_eq!(parse_period("2026-11-16-1"), None);
    }
}
