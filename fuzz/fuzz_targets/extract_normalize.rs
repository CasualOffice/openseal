//! Extracted spans into date, duration and amount normalisation (`ML-07`, `F-007`).
//! Any panic or hang is a finding. The first two bytes pick the base date's year and
//! the locale, so relative dates and two-digit years are exercised across the range;
//! a result must be a real date, a bounded count, or a value of at most 28 digits.
#![no_main]

use casual_sign_fields::normalize::{
    Date, Locale, MAX_DURATION_COUNT, normalize_amount, normalize_date, normalize_duration,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (head, rest) = data.split_at(data.len().min(2));
    let year = head.iter().fold(1u16, |y, b| y.wrapping_mul(31).wrapping_add(u16::from(*b)));
    let year = 1 + year % 9999;
    let Some(base) = Date::new(year, 6, 30) else {
        return;
    };
    let locale = if head.first().is_some_and(|b| b & 1 == 1) {
        Locale::EnGb
    } else {
        Locale::EnUs
    };
    let Ok(span) = core::str::from_utf8(rest) else {
        return;
    };
    if let Some(found) = normalize_date(span, base, locale) {
        let d = found.date();
        assert_eq!(Date::new(d.year(), d.month(), d.day()), Some(d));
    }
    if let Some(found) = normalize_duration(span) {
        assert!(found.count() <= MAX_DURATION_COUNT);
    }
    if let Some(found) = normalize_amount(span) {
        assert!(found.value().mantissa().unsigned_abs() < 10u128.pow(28));
    }
});
