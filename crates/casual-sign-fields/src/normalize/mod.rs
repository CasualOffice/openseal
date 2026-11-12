//! Normalisation of dates, durations and amounts that extraction found in agreement
//! text (`ML-07`, docs/33 §5.3): a span such as "thirty (30) days", "March 15, 2026"
//! or "1.250,00 €" becomes `P30D`, `2026-03-15` or `1250.00 EUR`.
//!
//! These are rules, not a model, and they are pure: no clock, no locale of the machine,
//! no I/O. A relative date ("in thirty (30) days", "tomorrow") resolves against a base
//! date the caller supplies (the envelope's recorded time), so the same span and base
//! give the same answer natively, in WASM and years later. Every result is a
//! suggestion a person confirms; nothing here enters the sealed PDF or the audit chain.
//!
//! Each function returns `None` when it cannot read the span with confidence, rather
//! than guessing: a written count that disagrees with its numeral ("thirty (31)"), a
//! date that does not exist, a relative date anchored to anything but today ("30 days
//! after the Effective Date"), or a span longer than [`MAX_NORMALIZE_BYTES`]. Spans are
//! untrusted text and nothing here panics on them.
//!
//! Forms read:
//! - **Dates** ([`normalize_date`]): ISO `2026-03-15`; numeric `03/15/2026` in the US
//!   order or `15/03/2026` in the UK order per [`Locale`], dotted `15.03.2026` always
//!   day first, two-digit years windowed around the base; written "March 15, 2026",
//!   "15 March 2026", "15-Mar-2026", "the 15th day of March, 2026", "March fifteenth,
//!   2026"; relative "today", "tomorrow", "in two (2) weeks", "30 days from today",
//!   "one year ago".
//! - **Durations** ([`normalize_duration`]): "thirty (30) days", "30-day", "a year",
//!   "ten (10) business days", "two quarters", "48 hours", with an optional "within",
//!   "for" or "a period of".
//! - **Amounts** ([`normalize_amount`]): "USD 1,250.00", "$1,250", "1.250,00 €",
//!   "1 250,00 EUR", "CHF 1'250.00", "One Thousand Two Hundred Fifty Dollars
//!   ($1,250.00)", "five hundred dollars and fifty cents".

mod amount;
mod date;
mod duration;
mod words;

pub use amount::Amount;
pub use date::Date;
pub use duration::{Duration, DurationUnit, MAX_DURATION_COUNT};

/// The longest span read, in bytes. Extraction spans are a few words; anything longer
/// is not one value, and the bound keeps the work per span small.
pub const MAX_NORMALIZE_BYTES: usize = 256;

/// The order a numeric date with slashes or hyphens is read in. ISO dates and written
/// dates read the same in every locale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Locale {
    /// Month first: `03/15/2026` is March 15.
    #[default]
    EnUs,
    /// Day first: `15/03/2026` is March 15.
    EnGb,
}

/// A date read from a span.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NormalizedDate {
    date: Date,
    relative: bool,
    ambiguous: bool,
}

impl NormalizedDate {
    /// The calendar date.
    #[must_use]
    pub fn date(&self) -> Date {
        self.date
    }

    /// True when the span was relative ("in 30 days") and so depends on the base.
    #[must_use]
    pub fn relative(&self) -> bool {
        self.relative
    }

    /// True when a numeric date reads as a different valid date in the other order
    /// (`04/05/2026`), so the locale decided it, or has a two-digit year, so the window
    /// around the base chose the century. A person should confirm either.
    #[must_use]
    pub fn ambiguous(&self) -> bool {
        self.ambiguous
    }
}

/// Reads a date span. `base` resolves relative dates and two-digit years; `locale`
/// orders numeric dates with slashes or hyphens. `None` when the span is not one date
/// this module can read with confidence.
#[must_use]
pub fn normalize_date(span: &str, base: Date, locale: Locale) -> Option<NormalizedDate> {
    if span.len() > MAX_NORMALIZE_BYTES {
        return None;
    }
    date::parse(span, base, locale)
}

/// Reads a duration span ("thirty (30) days"). `None` when the span is not one
/// duration, or a written count disagrees with its numeral.
#[must_use]
pub fn normalize_duration(span: &str) -> Option<Duration> {
    if span.len() > MAX_NORMALIZE_BYTES {
        return None;
    }
    duration::parse(span)
}

/// Reads an amount span ("USD 1,250.00", "1.250,00 €"). `None` when the span is not one
/// amount, the words and numeral disagree, or it has more than 28 significant digits.
#[must_use]
pub fn normalize_amount(span: &str) -> Option<Amount> {
    if span.len() > MAX_NORMALIZE_BYTES {
        return None;
    }
    amount::parse(span)
}
