//! Our own parsers for numbers and dates: no operating-system locale, no float, the same
//! answer in every browser and on every server.

use casual_sign_model::{DateFormat, NumberRule};
use rust_decimal::Decimal;

use crate::error::Invalid;

/// Most significant digits a decimal holds; a longer number is refused rather than rounded.
const MAX_DIGITS: usize = 28;

/// Currency symbols accepted before an amount when the rule names a currency.
const CURRENCY_SYMBOLS: [char; 5] = ['$', '€', '£', '¥', '₹'];

/// Parses a number the way a person in any locale types it for the API: an optional
/// sign, digits with optional `,` thousands grouping in threes, and an optional `.`
/// fraction. No exponent, no `NaN`, no `Infinity`, no locale's own separators.
///
/// With a currency in `rule`, one symbol or the ISO code may precede the amount
/// (`$12.50`, `USD 12.50`, `-$3`). Bounds and decimal places are checked too.
pub(crate) fn parse_number(text: &str, rule: Option<&NumberRule>) -> Result<Decimal, Invalid> {
    let mut rest = text.trim();
    let mut negative = false;
    let mut signed = false;
    if let Some(r) = rest.strip_prefix('-') {
        (rest, negative, signed) = (r, true, true);
    } else if let Some(r) = rest.strip_prefix('+') {
        (rest, signed) = (r, true);
    }
    if let Some(code) = rule.and_then(NumberRule::currency) {
        let stripped = rest
            .strip_prefix(code.as_str())
            .or_else(|| rest.strip_prefix(|c: char| CURRENCY_SYMBOLS.contains(&c)));
        if let Some(r) = stripped {
            rest = r.strip_prefix(' ').unwrap_or(r);
            if !signed {
                if let Some(r) = rest.strip_prefix('-') {
                    (rest, negative) = (r, true);
                } else if let Some(r) = rest.strip_prefix('+') {
                    rest = r;
                }
            }
        }
    }
    let (int_part, frac_part) = match rest.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (rest, None),
    };
    let int_digits = integer_digits(int_part).ok_or(Invalid::Number)?;
    let frac_digits = match frac_part {
        Some(f) if !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()) => f,
        Some(_) => return Err(Invalid::Number),
        None => "",
    };
    if int_digits.len().saturating_add(frac_digits.len()) > MAX_DIGITS {
        return Err(Invalid::Number);
    }
    let mut plain = String::with_capacity(MAX_DIGITS.saturating_add(2));
    if negative {
        plain.push('-');
    }
    plain.push_str(&int_digits);
    if !frac_digits.is_empty() {
        plain.push('.');
        plain.push_str(frac_digits);
    }
    let value = Decimal::from_str_exact(&plain).map_err(|_| Invalid::Number)?;
    let value = if value.is_zero() {
        Decimal::ZERO
    } else {
        value
    };
    if let Some(rule) = rule {
        if frac_digits.len() > usize::from(rule.max_decimals()) {
            return Err(Invalid::TooManyDecimals);
        }
        if rule.min().is_some_and(|min| value < min) {
            return Err(Invalid::BelowMinimum);
        }
        if rule.max().is_some_and(|max| value > max) {
            return Err(Invalid::AboveMaximum);
        }
    }
    Ok(value)
}

/// The digits of an integer part: plain (`12345`) or grouped by commas in threes
/// (`12,345`). `None` for anything else, including an empty part.
fn integer_digits(part: &str) -> Option<String> {
    if part.is_empty() {
        return None;
    }
    if !part.contains(',') {
        return part
            .bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| part.to_owned());
    }
    let mut groups = part.split(',');
    let head = groups.next()?;
    if head.is_empty() || head.len() > 3 || !head.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut digits = head.to_owned();
    for group in groups {
        if group.len() != 3 || !group.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        digits.push_str(group);
    }
    Some(digits)
}

/// A calendar date in the proleptic Gregorian calendar, years 1 to 9999.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CivilDate {
    year: i64,
    month: i64,
    day: i64,
}

impl CivilDate {
    /// Days since 1970-01-01 (negative before). Howard Hinnant's `days_from_civil`.
    pub(crate) fn day_number(self) -> Option<i64> {
        let y = if self.month <= 2 {
            self.year.checked_sub(1)?
        } else {
            self.year
        };
        let era = y.div_euclid(400);
        let yoe = y.checked_sub(era.checked_mul(400)?)?;
        let mp = if self.month > 2 {
            self.month.checked_sub(3)?
        } else {
            self.month.checked_add(9)?
        };
        let doy = mp
            .checked_mul(153)?
            .checked_add(2)?
            .checked_div(5)?
            .checked_add(self.day)?
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
}

const MONTHS: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];

/// Parses a date in exactly one of the fixed formats. Day and month in the slash and
/// dot formats may be one or two digits; years are always four. The date must exist.
pub(crate) fn parse_date(text: &str, format: DateFormat) -> Result<CivilDate, Invalid> {
    let text = text.trim();
    let (year, month, day) = match format {
        DateFormat::YyyyMmDd => {
            let [y, m, d] = three(text, '-')?;
            (fixed(y, 4)?, fixed(m, 2)?, fixed(d, 2)?)
        }
        DateFormat::MmDdYyyy => {
            let [m, d, y] = three(text, '/')?;
            (fixed(y, 4)?, short(m)?, short(d)?)
        }
        DateFormat::DdMmYyyy => {
            let [d, m, y] = three(text, '/')?;
            (fixed(y, 4)?, short(m)?, short(d)?)
        }
        DateFormat::DdMmYyyyDot => {
            let [d, m, y] = three(text, '.')?;
            (fixed(y, 4)?, short(m)?, short(d)?)
        }
        DateFormat::DMmmYyyy => {
            let [d, m, y] = three(text, ' ')?;
            let lower = m.to_ascii_lowercase();
            let index = MONTHS
                .iter()
                .position(|name| *name == lower)
                .ok_or(Invalid::Date)?;
            let month = i64::try_from(index)
                .map_err(|_| Invalid::Date)?
                .checked_add(1)
                .ok_or(Invalid::Date)?;
            (fixed(y, 4)?, month, short(d)?)
        }
    };
    if !(1..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
    {
        return Err(Invalid::Date);
    }
    Ok(CivilDate { year, month, day })
}

fn three(text: &str, sep: char) -> Result<[&str; 3], Invalid> {
    let mut parts = text.split(sep);
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(a), Some(b), Some(c), None) => Ok([a, b, c]),
        _ => Err(Invalid::Date),
    }
}

/// Exactly `width` ASCII digits.
fn fixed(part: &str, width: usize) -> Result<i64, Invalid> {
    if part.len() != width || !part.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Invalid::Date);
    }
    part.parse().map_err(|_| Invalid::Date)
}

/// One or two ASCII digits.
fn short(part: &str) -> Result<i64, Invalid> {
    if part.is_empty() || part.len() > 2 || !part.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Invalid::Date);
    }
    part.parse().map_err(|_| Invalid::Date)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            let leap =
                year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0);
            if leap { 29 } else { 28 }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use casual_sign_model::CurrencyCode;

    fn num(s: &str) -> Result<String, Invalid> {
        parse_number(s, None).map(|d| d.to_string())
    }

    #[test]
    fn numbers_parse_without_locale() {
        assert_eq!(num("12"), Ok("12".into()));
        assert_eq!(num(" -1,234.50 "), Ok("-1234.50".into()));
        assert_eq!(num("+0.5"), Ok("0.5".into()));
        assert_eq!(num("-0"), Ok("0".into()));
        for bad in [
            "", "-", ".5", "5.", "1,23", "12,3456", "1.2.3", "1e5", "NaN", "nan", "inf",
            "Infinity", "0x10", "1 000", "1_000", "١٢", "１２",
        ] {
            assert_eq!(num(bad), Err(Invalid::Number), "{bad:?}");
        }
    }

    #[test]
    fn huge_numbers_are_refused_not_rounded() {
        assert!(num(&"9".repeat(28)).is_ok());
        assert_eq!(num(&"9".repeat(29)), Err(Invalid::Number));
        assert_eq!(num(&"9".repeat(100_000)), Err(Invalid::Number));
        assert_eq!(num(&format!("0.{}", "1".repeat(40))), Err(Invalid::Number));
    }

    #[test]
    fn number_rules_check_bounds_places_and_currency() {
        let usd = CurrencyCode::new("USD").ok();
        let rule = NumberRule::new(Some(Decimal::ZERO), Some(Decimal::from(1_000)), usd, None).ok();
        let rule = rule.as_ref();
        assert!(parse_number("$12.50", rule).is_ok());
        assert!(parse_number("USD 12.50", rule).is_ok());
        assert!(parse_number("€1,000", rule).is_ok());
        assert_eq!(parse_number("12.505", rule), Err(Invalid::TooManyDecimals));
        assert_eq!(parse_number("-$3", rule), Err(Invalid::BelowMinimum));
        assert_eq!(parse_number("$-3", rule), Err(Invalid::BelowMinimum));
        assert_eq!(parse_number("1,000.01", rule), Err(Invalid::AboveMaximum));
        assert_eq!(parse_number("$$1", rule), Err(Invalid::Number));
        // Without a currency rule a symbol is not a number.
        assert_eq!(parse_number("$1", None), Err(Invalid::Number));
    }

    #[test]
    fn dates_parse_in_each_fixed_format() {
        let day = |s, f| parse_date(s, f).ok().and_then(CivilDate::day_number);
        assert_eq!(day("1970-01-01", DateFormat::YyyyMmDd), Some(0));
        assert_eq!(day("2000-03-01", DateFormat::YyyyMmDd), Some(11_017));
        assert_eq!(day("03/01/2000", DateFormat::MmDdYyyy), Some(11_017));
        assert_eq!(day("3/1/2000", DateFormat::MmDdYyyy), Some(11_017));
        assert_eq!(day("01/03/2000", DateFormat::DdMmYyyy), Some(11_017));
        assert_eq!(day("1.3.2000", DateFormat::DdMmYyyyDot), Some(11_017));
        assert_eq!(day("1 Mar 2000", DateFormat::DMmmYyyy), Some(11_017));
        assert_eq!(day("1 MAR 2000", DateFormat::DMmmYyyy), Some(11_017));
        assert_eq!(day("0001-01-01", DateFormat::YyyyMmDd), Some(-719_162));
        assert_eq!(day("9999-12-31", DateFormat::YyyyMmDd), Some(2_932_896));
    }

    #[test]
    fn impossible_or_misformatted_dates_are_refused() {
        for (s, f) in [
            ("2023-02-29", DateFormat::YyyyMmDd),
            ("1900-02-29", DateFormat::YyyyMmDd),
            ("2000-13-01", DateFormat::YyyyMmDd),
            ("2000-00-10", DateFormat::YyyyMmDd),
            ("0000-01-01", DateFormat::YyyyMmDd),
            ("2000-1-01", DateFormat::YyyyMmDd),
            ("2000/01/01", DateFormat::YyyyMmDd),
            ("31/04/2000", DateFormat::DdMmYyyy),
            ("04/31/2000", DateFormat::MmDdYyyy),
            ("1 Mär 2000", DateFormat::DMmmYyyy),
            ("1  Mar 2000", DateFormat::DMmmYyyy),
            ("1 Mar 20000", DateFormat::DMmmYyyy),
            ("123/1/2000", DateFormat::MmDdYyyy),
            ("", DateFormat::YyyyMmDd),
            ("２０００-01-01", DateFormat::YyyyMmDd),
        ] {
            assert_eq!(parse_date(s, f), Err(Invalid::Date), "{s:?}");
        }
        assert!(parse_date("2000-02-29", DateFormat::YyyyMmDd).is_ok());
    }
}
