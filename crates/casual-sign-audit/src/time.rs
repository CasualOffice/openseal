//! Event times: the server's clock, in UTC, to the millisecond (docs/32 §2).
//!
//! One written form only, `YYYY-MM-DDTHH:MM:SS.mmmZ`, so the canonical JSON of an event
//! has exactly one spelling of its time. The engine never reads a clock: hosts supply
//! times (CLAUDE.md "time is supplied").

use core::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{AuditError, ShapeFault};

/// An instant, as milliseconds since 1970-01-01T00:00:00Z, within years 0000 to 9999.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

/// A civil date and time of day.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Civil {
    /// Year, 0 to 9999.
    pub year: i64,
    /// Month, 1 to 12.
    pub month: u32,
    /// Day of the month, 1 to 31.
    pub day: u32,
    /// Hour, 0 to 23.
    pub hour: u32,
    /// Minute, 0 to 59.
    pub minute: u32,
    /// Second, 0 to 59.
    pub second: u32,
    /// Millisecond, 0 to 999.
    pub milli: u32,
}

const MS_PER_DAY: i64 = 86_400_000;
/// 0000-01-01T00:00:00.000Z.
const MIN_MS: i64 = -62_167_219_200_000;
/// 9999-12-31T23:59:59.999Z.
const MAX_MS: i64 = 253_402_300_799_999;

/// Days from 1970-01-01 to `y-m-d` (proleptic Gregorian; H. Hinnant's algorithm).
// Inputs are a parsed year 0 to 9999, month 1 to 12 and day 1 to 31: no step overflows.
#[allow(clippy::arithmetic_side_effects)]
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y.saturating_sub(1) } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(m);
    let mp = if m > 2 {
        m.saturating_sub(3)
    } else {
        m.saturating_add(9)
    };
    let doy = (153_i64.saturating_mul(mp).saturating_add(2)) / 5 + i64::from(d) - 1;
    let doe = yoe
        .saturating_mul(365)
        .saturating_add(yoe / 4)
        .saturating_sub(yoe / 100)
        .saturating_add(doy);
    era.saturating_mul(146_097)
        .saturating_add(doe)
        .saturating_sub(719_468)
}

/// The civil date of `days` since 1970-01-01.
// `days` comes from a timestamp within years 0 to 9999 (about ±3 million): no step
// overflows.
#[allow(clippy::arithmetic_side_effects)]
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days.saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe.saturating_add(era.saturating_mul(400));
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y.saturating_add(1) } else { y };
    (
        y,
        u32::try_from(m).unwrap_or(1),
        u32::try_from(d).unwrap_or(1),
    )
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        _ => 0,
    }
}

impl Timestamp {
    /// From milliseconds since the Unix epoch, if within years 0000 to 9999.
    #[must_use]
    pub fn from_unix_millis(ms: i64) -> Option<Self> {
        (MIN_MS..=MAX_MS).contains(&ms).then_some(Self(ms))
    }

    /// Milliseconds since the Unix epoch.
    #[must_use]
    pub fn unix_millis(self) -> i64 {
        self.0
    }

    /// The civil date and time at `offset_minutes` east of UTC (a supplied offset: the
    /// engine holds no time-zone database). `None` when the shifted time leaves years
    /// 0000 to 9999.
    #[must_use]
    pub fn civil(self, offset_minutes: i32) -> Option<Civil> {
        let ms = self
            .0
            .checked_add(i64::from(offset_minutes).checked_mul(60_000)?)?;
        if !(MIN_MS..=MAX_MS).contains(&ms) {
            return None;
        }
        let days = ms.div_euclid(MS_PER_DAY);
        let rest = ms.rem_euclid(MS_PER_DAY);
        let (year, month, day) = civil_from_days(days);
        let part = |v: i64| u32::try_from(v).unwrap_or(0);
        Some(Civil {
            year,
            month,
            day,
            hour: part(rest / 3_600_000),
            minute: part(rest / 60_000 % 60),
            second: part(rest / 1000 % 60),
            milli: part(rest % 1000),
        })
    }

    /// Parse the one written form, `YYYY-MM-DDTHH:MM:SS.mmmZ`.
    ///
    /// # Errors
    ///
    /// `CS-AUD-0003` ([`ShapeFault::Timestamp`]) for any other text or an impossible
    /// date.
    pub fn parse(text: &str) -> Result<Self, AuditError> {
        let bad = || AuditError::shape(ShapeFault::Timestamp);
        let b = text.as_bytes();
        if b.len() != 24 {
            return Err(bad());
        }
        for (i, want) in [
            (4, b'-'),
            (7, b'-'),
            (10, b'T'),
            (13, b':'),
            (16, b':'),
            (19, b'.'),
            (23, b'Z'),
        ] {
            if b.get(i) != Some(&want) {
                return Err(bad());
            }
        }
        let n = |r: core::ops::Range<usize>| -> Result<u32, AuditError> {
            let s = text.get(r).ok_or_else(bad)?;
            if !s.bytes().all(|c| c.is_ascii_digit()) {
                return Err(bad());
            }
            s.parse().map_err(|_| bad())
        };
        let (y, mo, d) = (n(0..4)?, n(5..7)?, n(8..10)?);
        let (h, mi, s, ms) = (n(11..13)?, n(14..16)?, n(17..19)?, n(20..23)?);
        let y = i64::from(y);
        if !(1..=12).contains(&mo) || d == 0 || d > days_in_month(y, mo) || h > 23 || mi > 59 {
            return Err(bad());
        }
        if s > 59 {
            return Err(bad());
        }
        // At most 23:59:59.999: far inside i64.
        let ms_of_day = i64::from(h)
            .saturating_mul(3_600_000)
            .saturating_add(i64::from(mi).saturating_mul(60_000))
            .saturating_add(i64::from(s).saturating_mul(1000))
            .saturating_add(i64::from(ms));
        let total = days_from_civil(y, mo, d)
            .checked_mul(MS_PER_DAY)
            .and_then(|v| v.checked_add(ms_of_day))
            .ok_or_else(bad)?;
        Self::from_unix_millis(total).ok_or_else(bad)
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.civil(0) {
            Some(c) => write!(
                f,
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
                c.year, c.month, c.day, c.hour, c.minute, c.second, c.milli
            ),
            None => write!(f, "invalid"),
        }
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

// Tests may unwrap, index and panic (CLAUDE.md).
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_instants() {
        let t = Timestamp::parse("2026-11-10T09:14:03.512Z").unwrap();
        assert_eq!(t.unix_millis(), 1_794_302_043_512);
        assert_eq!(t.to_string(), "2026-11-10T09:14:03.512Z");
        assert_eq!(Timestamp::parse("1970-01-01T00:00:00.000Z").unwrap().0, 0);
        assert_eq!(
            Timestamp::parse("0000-01-01T00:00:00.000Z").unwrap().0,
            MIN_MS
        );
        assert_eq!(
            Timestamp::parse("9999-12-31T23:59:59.999Z").unwrap().0,
            MAX_MS
        );
        assert!(Timestamp::parse("2024-02-29T00:00:00.000Z").is_ok());
    }

    #[test]
    fn every_millisecond_day_round_trips() {
        // Every day of 1900..2100 and a spread across the range.
        let mut day = Timestamp::parse("1900-01-01T00:00:00.000Z").unwrap().0;
        let end = Timestamp::parse("2100-12-31T23:59:59.999Z").unwrap().0;
        while day < end {
            let t = Timestamp(day + 45_296_789);
            assert_eq!(Timestamp::parse(&t.to_string()).unwrap(), t);
            day += MS_PER_DAY;
        }
        for ms in [MIN_MS, MIN_MS + 1, -1, 0, 1, MAX_MS - 1, MAX_MS] {
            let t = Timestamp(ms);
            assert_eq!(Timestamp::parse(&t.to_string()).unwrap(), t);
        }
    }

    #[test]
    fn only_one_written_form() {
        for bad in [
            "2026-11-10T09:14:03.512",
            "2026-11-10T09:14:03Z",
            "2026-11-10T09:14:03.512+00:00",
            "2026-11-10 09:14:03.512Z",
            "2026-11-10t09:14:03.512z",
            "2026-02-29T00:00:00.000Z",
            "2026-13-01T00:00:00.000Z",
            "2026-00-01T00:00:00.000Z",
            "2026-01-00T00:00:00.000Z",
            "2026-01-01T24:00:00.000Z",
            "2026-01-01T00:60:00.000Z",
            "2026-01-01T00:00:60.000Z",
            "+026-01-01T00:00:00.000Z",
            "2026-01-01T00:00:00.-00Z",
        ] {
            assert!(Timestamp::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn offsets_shift_the_civil_time() {
        let t = Timestamp::parse("2026-12-31T23:30:00.000Z").unwrap();
        let c = t.civil(60).unwrap();
        assert_eq!(
            (c.year, c.month, c.day, c.hour, c.minute),
            (2027, 1, 1, 0, 30)
        );
        let c = t.civil(-330).unwrap();
        assert_eq!((c.day, c.hour, c.minute), (31, 18, 0));
        assert!(Timestamp(MAX_MS).civil(1).is_none());
    }
}
