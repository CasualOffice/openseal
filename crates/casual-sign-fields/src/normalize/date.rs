//! Calendar dates: ISO, numeric in the US or UK order, written out ("March 15, 2026",
//! "the 15th day of March, 2026") and relative to a supplied base ("in thirty (30) days").

use core::fmt;

use super::duration::{self, DurationUnit};
use super::words;
use super::{Locale, NormalizedDate};

/// A date in the proleptic Gregorian calendar, years 1 to 9999.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Date {
    year: u16,
    month: u8,
    day: u8,
}

impl Date {
    /// The date, or `None` when it does not exist (`2026-02-29`) or the year is outside
    /// 1..=9999.
    #[must_use]
    pub fn new(year: u16, month: u8, day: u8) -> Option<Self> {
        let valid = (1..=9999).contains(&year)
            && (1..=12).contains(&month)
            && day >= 1
            && day <= days_in_month(year, month);
        valid.then_some(Self { year, month, day })
    }

    /// The year.
    #[must_use]
    pub fn year(&self) -> u16 {
        self.year
    }

    /// The month, 1 to 12.
    #[must_use]
    pub fn month(&self) -> u8 {
        self.month
    }

    /// The day of the month, from 1.
    #[must_use]
    pub fn day(&self) -> u8 {
        self.day
    }

    /// Days since 1970-01-01. Howard Hinnant's `days_from_civil`, as `parse::CivilDate`.
    fn day_number(self) -> Option<i64> {
        let month = i64::from(self.month);
        let y = i64::from(self.year).checked_sub(i64::from(month <= 2))?;
        let era = y.div_euclid(400);
        let yoe = y.checked_sub(era.checked_mul(400)?)?;
        let mp = if month > 2 {
            month.checked_sub(3)?
        } else {
            month.checked_add(9)?
        };
        let doy = mp
            .checked_mul(153)?
            .checked_add(2)?
            .checked_div(5)?
            .checked_add(i64::from(self.day))?
            .checked_sub(1)?;
        let doe = yoe
            .checked_mul(365)?
            .checked_add(yoe.checked_div(4)?)?
            .checked_sub(yoe.checked_div(100)?)?
            .checked_add(doy)?;
        era.checked_mul(146_097)?
            .checked_add(doe)?
            .checked_sub(719_468)
    }

    /// The date `days` after 1970-01-01. Hinnant's `civil_from_days`.
    fn from_day_number(days: i64) -> Option<Self> {
        let z = days.checked_add(719_468)?;
        let era = z.div_euclid(146_097);
        let doe = z.checked_sub(era.checked_mul(146_097)?)?;
        let yoe = doe
            .checked_sub(doe.checked_div(1460)?)?
            .checked_add(doe.checked_div(36_524)?)?
            .checked_sub(doe.checked_div(146_096)?)?
            .checked_div(365)?;
        let doy = doe.checked_sub(
            yoe.checked_mul(365)?
                .checked_add(yoe.checked_div(4)?)?
                .checked_sub(yoe.checked_div(100)?)?,
        )?;
        let mp = doy.checked_mul(5)?.checked_add(2)?.checked_div(153)?;
        let day = doy
            .checked_sub(mp.checked_mul(153)?.checked_add(2)?.checked_div(5)?)?
            .checked_add(1)?;
        let month = if mp < 10 {
            mp.checked_add(3)?
        } else {
            mp.checked_sub(9)?
        };
        let year = yoe
            .checked_add(era.checked_mul(400)?)?
            .checked_add(i64::from(month <= 2))?;
        Self::new(
            u16::try_from(year).ok()?,
            u8::try_from(month).ok()?,
            u8::try_from(day).ok()?,
        )
    }

    /// The day of the week, 0 for Monday to 6 for Sunday (1970-01-01 was a Thursday).
    fn weekday(self) -> Option<usize> {
        usize::try_from(self.day_number()?.checked_add(3)?.rem_euclid(7)).ok()
    }

    /// This date moved by `days` (negative goes back). `None` outside years 1..=9999.
    #[must_use]
    pub fn add_days(self, days: i64) -> Option<Self> {
        Self::from_day_number(self.day_number()?.checked_add(days)?)
    }

    /// This date moved by `months`, the day clamped to the end of a shorter month
    /// (January 31 plus one month is February 28 or 29), as `dateutil.relativedelta`.
    #[must_use]
    pub fn add_months(self, months: i64) -> Option<Self> {
        let index = i64::from(self.year)
            .checked_mul(12)?
            .checked_add(i64::from(self.month))?
            .checked_sub(1)?
            .checked_add(months)?;
        let year = u16::try_from(index.div_euclid(12)).ok()?;
        let month = u8::try_from(index.rem_euclid(12).checked_add(1)?).ok()?;
        if !(1..=9999).contains(&year) {
            return None;
        }
        let day = self.day.min(days_in_month(year, month));
        Self::new(year, month, day)
    }
}

impl fmt::Display for Date {
    /// ISO 8601 calendar date: `2026-03-15`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            let leap =
                year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
            if leap { 29 } else { 28 }
        }
        _ => 0,
    }
}

/// Month names and the abbreviations agreements use, with their number.
const MONTHS: [(&str, u8); 24] = [
    ("january", 1),
    ("jan", 1),
    ("february", 2),
    ("feb", 2),
    ("march", 3),
    ("mar", 3),
    ("april", 4),
    ("apr", 4),
    ("may", 5),
    ("june", 6),
    ("jun", 6),
    ("july", 7),
    ("jul", 7),
    ("august", 8),
    ("aug", 8),
    ("september", 9),
    ("sept", 9),
    ("sep", 9),
    ("october", 10),
    ("oct", 10),
    ("november", 11),
    ("nov", 11),
    ("december", 12),
    ("dec", 12),
];

const WEEKDAYS: [&str; 14] = [
    "monday",
    "mon",
    "tuesday",
    "tue",
    "wednesday",
    "wed",
    "thursday",
    "thu",
    "friday",
    "fri",
    "saturday",
    "sat",
    "sunday",
    "sun",
];

fn month(word: &str) -> Option<u8> {
    MONTHS.iter().find(|(w, _)| *w == word).map(|&(_, m)| m)
}

/// Reads a date span. See [`super::normalize_date`].
pub(super) fn parse(span: &str, base: Date, locale: Locale) -> Option<NormalizedDate> {
    let text = span
        .trim()
        .trim_end_matches(['.', ',', ';', ':'])
        .trim_end();
    if let Some(found) = numeric(text, base, locale) {
        return Some(found);
    }
    let lower = text.to_lowercase();
    if let Some(found) = relative(&lower, base) {
        return Some(found);
    }
    written(&lower).map(|date| NormalizedDate {
        date,
        relative: false,
        ambiguous: false,
    })
}

/// `2026-03-15`, `2026/03/15`, `03/15/2026` (US), `15/03/2026` (UK), `15.03.2026`,
/// `3/15/26`.
fn numeric(text: &str, base: Date, locale: Locale) -> Option<NormalizedDate> {
    let sep = ['-', '/', '.'].into_iter().find(|&c| text.contains(c))?;
    let mut parts = text.split(sep);
    let (a, b, c) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(a), Some(b), Some(c), None) => (a, b, c),
        _ => return None,
    };
    let settled = |date| NormalizedDate {
        date,
        relative: false,
        ambiguous: false,
    };
    if a.len() == 4 {
        // Year first is always year-month-day (`2026-3-15` too: dateparser reads
        // `2026-13-01` as the 13th of January, which we refuse). A dotted year-first
        // date is not a form anyone writes.
        if sep == '.' {
            return None;
        }
        let date = Date::new(
            u16::try_from(words::digits(a, 4)?).ok()?,
            u8::try_from(words::digits(b, 2)?).ok()?,
            u8::try_from(words::digits(c, 2)?).ok()?,
        )?;
        return Some(settled(date));
    }
    // A two-digit year is a guess about the century, so it is always for a person to
    // confirm.
    let (year, guessed_century) = match c.len() {
        4 => (u16::try_from(words::digits(c, 4)?).ok()?, false),
        2 => (
            two_digit_year(u16::try_from(words::digits(c, 2)?).ok()?, base)?,
            true,
        ),
        _ => return None,
    };
    let settled = |date| NormalizedDate {
        date,
        relative: false,
        ambiguous: guessed_century,
    };
    let first = u8::try_from(words::digits(a, 2)?).ok()?;
    let second = u8::try_from(words::digits(b, 2)?).ok()?;
    // Dots are day-first wherever they are used (15.03.2026); slashes and hyphens follow
    // the locale.
    let day_first = sep == '.' || locale == Locale::EnGb;
    let (preferred, other) = if day_first {
        (
            Date::new(year, second, first),
            Date::new(year, first, second),
        )
    } else {
        (
            Date::new(year, first, second),
            Date::new(year, second, first),
        )
    };
    match (preferred, other) {
        (Some(p), Some(o)) => Some(NormalizedDate {
            date: p,
            relative: false,
            ambiguous: p != o || guessed_century,
        }),
        (Some(p), None) => Some(settled(p)),
        // 15/03/2026 read in the US order cannot be a date; the other order is the only
        // reading.
        (None, Some(o)) => Some(settled(o)),
        (None, None) => None,
    }
}

/// A two-digit year read into the century that puts it within 50 years of the base
/// (the base's year minus 50 to plus 49), so the answer depends on the supplied base
/// and never on the clock.
fn two_digit_year(yy: u16, base: Date) -> Option<u16> {
    let low = base.year.saturating_sub(50).max(1);
    let century = low.checked_div(100)?.checked_mul(100)?;
    let candidate = century.checked_add(yy)?;
    let year = if candidate < low {
        candidate.checked_add(100)?
    } else {
        candidate
    };
    (1..=9999).contains(&year).then_some(year)
}

/// "today", "tomorrow", "yesterday", "in thirty (30) days", "30 days from today",
/// "two weeks ago", resolved against `base`. A date relative to anything but today
/// ("30 days after the Effective Date") is not resolved: the anchor is not known here.
fn relative(lower: &str, base: Date) -> Option<NormalizedDate> {
    let resolved = |date| NormalizedDate {
        date,
        relative: true,
        ambiguous: false,
    };
    match lower {
        "today" | "now" => return Some(resolved(base)),
        "tomorrow" => return base.add_days(1).map(resolved),
        "yesterday" => return base.add_days(-1).map(resolved),
        _ => {}
    }
    let (span, forward) = if let Some(rest) = lower.strip_prefix("in ") {
        (rest, true)
    } else if let Some(rest) = ["from today", "from now", "after today", "hence"]
        .iter()
        .find_map(|tail| lower.strip_suffix(tail))
    {
        (rest, true)
    } else if let Some(rest) = ["ago", "before today"]
        .iter()
        .find_map(|tail| lower.strip_suffix(tail))
    {
        (rest, false)
    } else {
        return None;
    };
    let duration = duration::parse(span)?;
    let count = i64::from(duration.count());
    let count = if forward { count } else { count.checked_neg()? };
    let date = match duration.unit() {
        DurationUnit::Day => base.add_days(count)?,
        DurationUnit::Week => base.add_days(count.checked_mul(7)?)?,
        DurationUnit::Month => base.add_months(count)?,
        DurationUnit::Year => base.add_months(count.checked_mul(12)?)?,
        // Business days need a holiday calendar; hours need a time of day.
        DurationUnit::BusinessDay | DurationUnit::Hour => return None,
    };
    Some(resolved(date))
}

/// "March 15, 2026", "Mar. 15th 2026", "15 March 2026", "15-Mar-2026",
/// "Monday, March 15, 2026", "the 15th day of March, 2026", "this first day of
/// March 2026", "March fifteenth, 2026".
fn written(lower: &str) -> Option<Date> {
    let cleaned: String = lower
        .chars()
        .map(|c| {
            if matches!(c, ',' | '.' | '-' | '/') {
                ' '
            } else {
                c
            }
        })
        .collect();
    let mut tokens: Vec<&str> = cleaned.split_whitespace().collect();
    // Leading words that carry no date: "on", "dated", "as of", a weekday, "the", "this".
    // A weekday is kept to check against the date: "Monday, March 15, 2026" is refused,
    // since March 15, 2026 is a Sunday and one of the two is wrong.
    let mut weekday = None;
    loop {
        match tokens.first() {
            Some(&("on" | "dated" | "the" | "this")) => {
                tokens.remove(0);
            }
            Some(&"as") if tokens.get(1) == Some(&"of") => {
                tokens.drain(..2);
            }
            Some(w) if WEEKDAYS.contains(w) => {
                weekday = WEEKDAYS
                    .iter()
                    .position(|d| d == w)
                    .and_then(|i| i.checked_div(2));
                tokens.remove(0);
            }
            _ => break,
        }
    }
    let date = day_month_year(&tokens)?;
    match weekday {
        Some(stated) if Some(stated) != date.weekday() => None,
        _ => Some(date),
    }
}

/// The date in `tokens`, leading words already removed.
fn day_month_year(tokens: &[&str]) -> Option<Date> {
    let (&year_text, rest) = tokens.split_last()?;
    let year = u16::try_from(words::digits(year_text, 4)?).ok()?;
    if year_text.len() != 4 {
        return None;
    }
    // Month first: "March 15", "March fifteenth", "March the 15th".
    if let Some((&first, day_words)) = rest.split_first()
        && let Some(m) = month(first)
    {
        let day_words = match day_words.split_first() {
            Some((&"the", tail)) => tail,
            _ => day_words,
        };
        return Date::new(year, m, day(day_words)?);
    }
    // Day first: "15 March", "15th of March", "15th day of March", "fifteenth day of March".
    let (&month_text, rest) = rest.split_last()?;
    let m = month(month_text)?;
    let rest = match rest {
        [head @ .., "day", "of"] | [head @ .., "of"] => head,
        _ => rest,
    };
    Date::new(year, m, day(rest)?)
}

/// A day of the month: `15`, `15th`, `fifteenth`, `twenty-first` (already split).
fn day(tokens: &[&str]) -> Option<u8> {
    let value = match tokens {
        [one] => {
            let digits_end = one.find(|c: char| !c.is_ascii_digit()).unwrap_or(one.len());
            let (number, suffix) = one.split_at(digits_end);
            if number.is_empty() {
                words::ordinal_day(&[(*one).to_owned()])?
            } else {
                if !matches!(suffix, "" | "st" | "nd" | "rd" | "th") {
                    return None;
                }
                u32::try_from(words::digits(number, 2)?).ok()?
            }
        }
        [_, _] => words::ordinal_day(&tokens.iter().map(|t| (*t).to_owned()).collect::<Vec<_>>())?,
        _ => return None,
    };
    u8::try_from(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A date the test knows exists (checked by `Date::new` in the round-trip test).
    fn d(year: u16, month: u8, day: u8) -> Date {
        Date { year, month, day }
    }

    #[test]
    fn day_numbers_round_trip_across_the_range() {
        for date in [
            d(1, 1, 1),
            d(1969, 12, 31),
            d(1970, 1, 1),
            d(2000, 2, 29),
            d(2026, 11, 12),
            d(9999, 12, 31),
        ] {
            assert_eq!(Date::new(date.year, date.month, date.day), Some(date));
            assert_eq!(
                date.day_number().and_then(Date::from_day_number),
                Some(date)
            );
        }
        assert_eq!(d(9999, 12, 31).add_days(1), None);
        assert_eq!(d(1, 1, 1).add_days(-1), None);
        assert_eq!(d(2026, 1, 1).add_days(i64::MAX), None);
    }

    #[test]
    fn months_clamp_to_the_end_of_a_shorter_month() {
        assert_eq!(d(2026, 1, 31).add_months(1), Some(d(2026, 2, 28)));
        assert_eq!(d(2028, 1, 31).add_months(1), Some(d(2028, 2, 29)));
        assert_eq!(d(2026, 3, 31).add_months(-1), Some(d(2026, 2, 28)));
        assert_eq!(d(2026, 11, 12).add_months(14), Some(d(2028, 1, 12)));
        assert_eq!(d(9999, 12, 1).add_months(1), None);
        assert_eq!(d(2026, 1, 1).add_months(i64::MIN), None);
    }

    #[test]
    fn two_digit_years_follow_the_base_not_the_clock() {
        assert_eq!(two_digit_year(26, d(2026, 1, 1)), Some(2026));
        assert_eq!(two_digit_year(75, d(2026, 1, 1)), Some(2075));
        assert_eq!(two_digit_year(76, d(2026, 1, 1)), Some(1976));
        assert_eq!(two_digit_year(99, d(1990, 1, 1)), Some(1999));
        assert_eq!(two_digit_year(5, d(30, 1, 1)), Some(5));
    }
}
