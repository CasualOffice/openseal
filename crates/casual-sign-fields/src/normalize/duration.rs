//! Durations: "thirty (30) days", "12-month", "ten (10) business days", "a year".

use core::fmt;

use super::words;

/// The unit a duration counts in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurationUnit {
    /// Hours.
    Hour,
    /// Calendar days ("days", "calendar days").
    Day,
    /// Business, working or banking days. ISO 8601 has no such unit, and which days
    /// count depends on a holiday calendar this module does not have.
    BusinessDay,
    /// Weeks.
    Week,
    /// Months. A quarter is three of them.
    Month,
    /// Years.
    Year,
}

/// A duration read from agreement text: a whole count of one unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Duration {
    count: u32,
    unit: DurationUnit,
}

/// The largest count accepted: anything longer than this many hours or years is not a
/// term an agreement states, and the bound keeps date arithmetic in range.
pub const MAX_DURATION_COUNT: u32 = 100_000;

impl Duration {
    /// A duration of `count` units, or `None` above [`MAX_DURATION_COUNT`].
    #[must_use]
    pub fn new(count: u32, unit: DurationUnit) -> Option<Self> {
        (count <= MAX_DURATION_COUNT).then_some(Self { count, unit })
    }

    /// How many units.
    #[must_use]
    pub fn count(&self) -> u32 {
        self.count
    }

    /// The unit.
    #[must_use]
    pub fn unit(&self) -> DurationUnit {
        self.unit
    }

    /// The ISO 8601 duration (`P30D`, `P2W`, `P6M`, `P1Y`, `PT48H`), or `None` for
    /// business days, which ISO 8601 cannot express.
    #[must_use]
    pub fn iso8601(&self) -> Option<String> {
        let n = self.count;
        Some(match self.unit {
            DurationUnit::Hour => format!("PT{n}H"),
            DurationUnit::Day => format!("P{n}D"),
            DurationUnit::Week => format!("P{n}W"),
            DurationUnit::Month => format!("P{n}M"),
            DurationUnit::Year => format!("P{n}Y"),
            DurationUnit::BusinessDay => return None,
        })
    }
}

impl fmt::Display for Duration {
    /// ISO 8601 where it can say it; `10 business days` otherwise.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.iso8601() {
            Some(iso) => f.write_str(&iso),
            None => write!(f, "{} business days", self.count),
        }
    }
}

/// Words a span may start with before the count ("within thirty (30) days").
const LEADING: [&[&str]; 6] = [
    &["within"],
    &["for"],
    &["a", "period", "of"],
    &["period", "of"],
    &["a", "term", "of"],
    &["term", "of"],
];

/// A unit word, singular or plural, and how many of the unit it is.
fn unit_word(word: &str) -> Option<(DurationUnit, u32)> {
    Some(match word {
        "hour" | "hours" => (DurationUnit::Hour, 1),
        "day" | "days" => (DurationUnit::Day, 1),
        "week" | "weeks" => (DurationUnit::Week, 1),
        "month" | "months" => (DurationUnit::Month, 1),
        "quarter" | "quarters" => (DurationUnit::Month, 3),
        "year" | "years" => (DurationUnit::Year, 1),
        _ => return None,
    })
}

/// Reads a duration span. See [`super::normalize_duration`].
pub(super) fn parse(span: &str) -> Option<Duration> {
    let lower = span.trim().to_lowercase();
    // A possessive ("thirty (30) days' notice" cut at the unit) and closing punctuation.
    let lower = lower.trim_end_matches(['\'', '’', '.', ',', ';', ':']);
    // A sign is not part of a duration; splitting on hyphens below would drop it.
    if lower.starts_with(['-', '−']) {
        return None;
    }
    // Words, with the parenthesised numeral kept as its own word.
    let mut words: Vec<&str> = lower
        .split(|c: char| c.is_whitespace() || c == '-')
        .filter(|w| !w.is_empty())
        .collect();
    // "for a period of", "within a term of": strip leading words until none is left.
    while let Some(lead) = LEADING.iter().find(|lead| words.starts_with(lead)) {
        words.drain(..lead.len());
    }
    let (unit_text, rest) = words.split_last()?;
    let (unit, factor) = unit_word(unit_text)?;
    let (unit, rest) = match (unit, rest.split_last()) {
        (DurationUnit::Day, Some((&"calendar", rest))) => (DurationUnit::Day, rest),
        (DurationUnit::Day, Some((&("business" | "working" | "banking"), rest))) => {
            (DurationUnit::BusinessDay, rest)
        }
        _ => (unit, rest),
    };
    let count = if rest == ["a"] || rest == ["an"] || rest == ["one"] {
        1
    } else {
        words::count(&rest.join(" "))?
    };
    let count = u32::try_from(count).ok()?.checked_mul(factor)?;
    Duration::new(count, unit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_forms() {
        let iso = |s: &str| parse(s).and_then(|d| d.iso8601());
        assert_eq!(iso("thirty (30) days").as_deref(), Some("P30D"));
        assert_eq!(iso("48 hours").as_deref(), Some("PT48H"));
        assert_eq!(iso("2 quarters").as_deref(), Some("P6M"));
        assert_eq!(iso("ten (10) business days"), None);
        assert_eq!(
            parse("ten (10) business days").map(|d| d.to_string()),
            Some("10 business days".into())
        );
    }

    #[test]
    fn counts_beyond_the_bound_are_refused() {
        assert!(parse("100000 days").is_some());
        assert_eq!(parse("100001 days"), None);
        assert_eq!(parse("40000 quarters"), None);
        assert_eq!(parse("one billion years"), None);
    }
}
