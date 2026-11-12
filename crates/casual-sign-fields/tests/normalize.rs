//! Normalisation of extracted dates, durations and amounts (`ML-07`, docs/33 §5.3):
//! table tests over the forms agreements use, relative dates against a supplied base,
//! locale order, refusal of spans that cannot be read with confidence, and no panic on
//! any input. `tests/normalize/dates.tsv` is shared with
//! `tools/ml/crosscheck-normalize.py`, which compares the date rows with Python
//! `dateparser` offline.

// Tests may unwrap, index and panic (CLAUDE.md): a failure here is the test failing.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::panic
)]

use casual_sign_fields::normalize::{
    Date, DurationUnit, Locale, MAX_NORMALIZE_BYTES, normalize_amount, normalize_date,
    normalize_duration,
};
use proptest::prelude::*;

fn date(text: &str) -> Date {
    let mut parts = text.split('-').map(|p| p.parse::<u32>().unwrap());
    let (y, m, d) = (
        parts.next().unwrap(),
        parts.next().unwrap(),
        parts.next().unwrap(),
    );
    Date::new(
        u16::try_from(y).unwrap(),
        u8::try_from(m).unwrap(),
        u8::try_from(d).unwrap(),
    )
    .unwrap_or_else(|| panic!("bad date {text}"))
}

fn locale(name: &str) -> Locale {
    match name {
        "en-US" => Locale::EnUs,
        "en-GB" => Locale::EnGb,
        other => panic!("unknown locale {other}"),
    }
}

/// `span <TAB> locale <TAB> base <TAB> expected <TAB> flags <TAB> dateparser`, `-` for
/// none. Flags: `r` relative, `a` ambiguous. The last column is for the cross-check.
#[test]
fn date_table() {
    let table = include_str!("normalize/dates.tsv");
    let mut rows = 0;
    for (line_no, line) in table.lines().enumerate() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        assert_eq!(cols.len(), 6, "line {}: {line:?}", line_no + 1);
        let (span, loc, base, expected, flags) = (cols[0], cols[1], cols[2], cols[3], cols[4]);
        let got = normalize_date(span, date(base), locale(loc));
        if expected == "-" {
            assert_eq!(got, None, "line {}: {span:?}", line_no + 1);
        } else {
            let got = got.unwrap_or_else(|| panic!("line {}: {span:?} not read", line_no + 1));
            assert_eq!(
                got.date().to_string(),
                expected,
                "line {}: {span:?}",
                line_no + 1
            );
            assert_eq!(got.relative(), flags.contains('r'), "relative: {span:?}");
            assert_eq!(got.ambiguous(), flags.contains('a'), "ambiguous: {span:?}");
        }
        rows += 1;
    }
    assert!(rows >= 60, "only {rows} rows");
}

#[test]
fn relative_dates_follow_the_supplied_base() {
    let span = "in thirty (30) days";
    let a = normalize_date(span, date("2026-01-15"), Locale::EnUs).unwrap();
    let b = normalize_date(span, date("2030-12-15"), Locale::EnUs).unwrap();
    assert_eq!(a.date().to_string(), "2026-02-14");
    assert_eq!(b.date().to_string(), "2031-01-14");
    // The same span and base give the same answer every time.
    for _ in 0..3 {
        assert_eq!(
            normalize_date(span, date("2026-01-15"), Locale::EnUs),
            Some(a)
        );
    }
}

#[test]
fn duration_table() {
    use DurationUnit::{BusinessDay, Day, Hour, Month, Week, Year};
    type Row = (
        &'static str,
        Option<(u32, DurationUnit)>,
        Option<&'static str>,
    );
    let rows: &[Row] = &[
        ("thirty (30) days", Some((30, Day)), Some("P30D")),
        ("Thirty (30) Days", Some((30, Day)), Some("P30D")),
        ("30 days", Some((30, Day)), Some("P30D")),
        ("thirty days", Some((30, Day)), Some("P30D")),
        ("30 (thirty) days", Some((30, Day)), Some("P30D")),
        ("30-day", Some((30, Day)), Some("P30D")),
        ("sixty (60) calendar days", Some((60, Day)), Some("P60D")),
        ("ten (10) business days", Some((10, BusinessDay)), None),
        ("5 working days", Some((5, BusinessDay)), None),
        ("three (3) banking days", Some((3, BusinessDay)), None),
        ("one (1) year", Some((1, Year)), Some("P1Y")),
        ("a year", Some((1, Year)), Some("P1Y")),
        ("two years", Some((2, Year)), Some("P2Y")),
        ("12-month", Some((12, Month)), Some("P12M")),
        ("twelve (12) months", Some((12, Month)), Some("P12M")),
        ("six months", Some((6, Month)), Some("P6M")),
        ("a month", Some((1, Month)), Some("P1M")),
        ("one quarter", Some((3, Month)), Some("P3M")),
        ("2 weeks", Some((2, Week)), Some("P2W")),
        ("an hour", Some((1, Hour)), Some("PT1H")),
        ("forty-eight (48) hours", Some((48, Hour)), Some("PT48H")),
        ("within thirty (30) days", Some((30, Day)), Some("P30D")),
        (
            "for a period of five (5) years",
            Some((5, Year)),
            Some("P5Y"),
        ),
        ("a period of five (5) years", Some((5, Year)), Some("P5Y")),
        ("for two (2) years", Some((2, Year)), Some("P2Y")),
        ("a term of three (3) years", Some((3, Year)), Some("P3Y")),
        ("thirty (30) days'", Some((30, Day)), Some("P30D")),
        ("ninety (90) days’", Some((90, Day)), Some("P90D")),
        (
            "three hundred sixty-five (365) days",
            Some((365, Day)),
            Some("P365D"),
        ),
        ("1,000 days", Some((1000, Day)), Some("P1000D")),
        // Refused: disagreement, no unit, unknown unit, junk, nothing.
        ("thirty (31) days", None, None),
        ("thirty", None, None),
        ("30 fortnights", None, None),
        ("days", None, None),
        ("thirty (30) days after the Effective Date", None, None),
        ("", None, None),
        ("-30 days", None, None),
        ("30.5 days", None, None),
    ];
    for &(span, expected, iso) in rows {
        let got = normalize_duration(span);
        assert_eq!(got.map(|d| (d.count(), d.unit())), expected, "{span:?}");
        assert_eq!(got.and_then(|d| d.iso8601()).as_deref(), iso, "{span:?}");
    }
}

#[test]
fn amount_table() {
    // span, value, currency, ambiguous
    type Row = (
        &'static str,
        Option<(&'static str, Option<&'static str>, bool)>,
    );
    let rows: &[Row] = &[
        ("USD 1,250.00", Some(("1250.00", Some("USD"), false))),
        ("USD1,250.00", Some(("1250.00", Some("USD"), false))),
        ("$1,250.00", Some(("1250.00", Some("USD"), false))),
        ("US$1,250", Some(("1250", Some("USD"), true))),
        ("$ 1,250,000", Some(("1250000", Some("USD"), false))),
        ("1,250.00 USD", Some(("1250.00", Some("USD"), false))),
        ("£500", Some(("500", Some("GBP"), false))),
        ("£1,000.50", Some(("1000.50", Some("GBP"), false))),
        ("GBP 2,500", Some(("2500", Some("GBP"), true))),
        ("1.250,00 €", Some(("1250.00", Some("EUR"), false))),
        ("1.250,00€", Some(("1250.00", Some("EUR"), false))),
        ("€1.250,00", Some(("1250.00", Some("EUR"), false))),
        ("EUR 1.250,00", Some(("1250.00", Some("EUR"), false))),
        ("1 250,00 EUR", Some(("1250.00", Some("EUR"), false))),
        (
            "1\u{a0}250,00\u{a0}€",
            Some(("1250.00", Some("EUR"), false)),
        ),
        ("1\u{202f}250,00 €", Some(("1250.00", Some("EUR"), false))),
        ("1.250 €", Some(("1250", Some("EUR"), true))),
        ("1.250 EUR", Some(("1250", Some("EUR"), true))),
        ("1,250 USD", Some(("1250", Some("USD"), true))),
        ("1,250 dollars", Some(("1250", Some("USD"), true))),
        ("1,250 €", Some(("1.250", Some("EUR"), true))),
        ("1.250 USD", Some(("1.250", Some("USD"), true))),
        ("EUR 1.250", Some(("1.250", Some("EUR"), true))),
        ("CHF 1'250.00", Some(("1250.00", Some("CHF"), false))),
        ("¥100,000", Some(("100000", Some("JPY"), true))),
        ("¥1,000,000", Some(("1000000", Some("JPY"), false))),
        ("₹5,000", Some(("5000", Some("INR"), true))),
        ("-$3.50", Some(("-3.50", Some("USD"), false))),
        ("$-3.50", Some(("-3.50", Some("USD"), false))),
        ("1250", Some(("1250", None, false))),
        ("1,250.00", Some(("1250.00", None, false))),
        ("1,250.00 dollars", Some(("1250.00", Some("USD"), false))),
        ("500 euros", Some(("500", Some("EUR"), false))),
        (
            "One Thousand Two Hundred Fifty Dollars ($1,250.00)",
            Some(("1250.00", Some("USD"), false)),
        ),
        (
            "one thousand two hundred fifty (1,250) euros",
            None, // the currency word must come before the numeral or inside it
        ),
        (
            "One Thousand Two Hundred Fifty U.S. Dollars (US$1,250.00)",
            Some(("1250.00", Some("USD"), false)),
        ),
        (
            "One Thousand Two Hundred Fifty ($1,250.00)",
            Some(("1250.00", Some("USD"), false)),
        ),
        (
            "Five Hundred Euros (EUR 500.00)",
            Some(("500.00", Some("EUR"), false)),
        ),
        ("five hundred dollars", Some(("500", Some("USD"), false))),
        (
            "five hundred dollars and fifty cents",
            Some(("500.50", Some("USD"), false)),
        ),
        (
            "five hundred and 50/100 dollars",
            Some(("500.50", Some("USD"), false)),
        ),
        (
            "ten thousand pounds sterling",
            Some(("10000", Some("GBP"), false)),
        ),
        (
            "one million US dollars only",
            Some(("1000000", Some("USD"), false)),
        ),
        // Refused.
        ("One Thousand Dollars ($1,250.00)", None),
        ("Five Hundred Euros ($500.00)", None),
        ("($1,250.00)", None),
        ("thirty", None),
        ("NET 30", None),
        ("USDA 30", None),
        ("$", None),
        ("$1,25,000", None),
        ("$1.250.00", None),
        ("1e5 USD", None),
        ("$ 1 250'000", None),
        ("five hundred dollars and 150 cents", None),
        ("", None),
    ];
    for &(span, expected) in rows {
        let got = normalize_amount(span);
        let got = got.map(|a| {
            (
                a.value().to_string(),
                a.currency().map(|c| c.as_str().to_owned()),
                a.ambiguous(),
            )
        });
        let expected = expected.map(|(v, c, amb)| (v.to_owned(), c.map(str::to_owned), amb));
        assert_eq!(got, expected, "{span:?}");
    }
}

#[test]
fn amounts_display_value_then_code() {
    assert_eq!(
        normalize_amount("1.250,00 €").unwrap().to_string(),
        "1250.00 EUR"
    );
    assert_eq!(normalize_amount("1250").unwrap().to_string(), "1250");
}

#[test]
fn spans_over_the_bound_are_refused() {
    let pad = " ".repeat(MAX_NORMALIZE_BYTES);
    assert!(normalize_duration("30 days").is_some());
    assert_eq!(normalize_duration(&format!("{pad}30 days")), None);
    assert_eq!(normalize_amount(&format!("{pad}$5")), None);
    assert_eq!(
        normalize_date(
            &format!("{pad}2026-01-01"),
            date("2026-01-01"),
            Locale::EnUs
        ),
        None
    );
}

proptest! {
    #[test]
    fn no_span_panics(span in ".{0,300}", y in 1u16..=9999, m in 1u8..=12, d in 1u8..=28) {
        let base = Date::new(y, m, d).unwrap();
        let _ = normalize_date(&span, base, Locale::EnUs);
        let _ = normalize_date(&span, base, Locale::EnGb);
        let _ = normalize_duration(&span);
        let _ = normalize_amount(&span);
    }

    #[test]
    fn shaped_spans_do_not_panic(
        n in any::<u64>(),
        unit in prop::sample::select(vec!["days", "months", "years", "weeks", "business days"]),
        lead in prop::sample::select(vec!["in ", "", "within "]),
        tail in prop::sample::select(vec!["", " ago", " from today"]),
        y in 1u16..=9999,
    ) {
        let base = Date::new(y, 12, 31).unwrap();
        let _ = normalize_date(&format!("{lead}{n} {unit}{tail}"), base, Locale::EnUs);
        let _ = normalize_duration(&format!("{lead}{n} {unit}"));
        let _ = normalize_amount(&format!("${n}.{n}"));
    }
}
