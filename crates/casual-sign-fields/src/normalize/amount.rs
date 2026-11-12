//! Monetary amounts: "USD 1,250.00", "$1,250", "1.250,00 €", "1 250,00 EUR",
//! "CHF 1'250.00", "One Thousand Two Hundred Fifty Dollars ($1,250.00)".

use core::fmt;

use casual_sign_model::CurrencyCode;
use rust_decimal::Decimal;

use super::words;

/// An amount of money read from agreement text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Amount {
    value: Decimal,
    currency: Option<CurrencyCode>,
    ambiguous: bool,
}

impl Amount {
    /// The value, with the decimal places as written (`1250.00` stays two places).
    #[must_use]
    pub fn value(&self) -> Decimal {
        self.value
    }

    /// The ISO 4217 currency, when the text names one by code, symbol or word. `$`
    /// alone is read as US dollars, `¥` as yen and `£` as pounds sterling.
    #[must_use]
    pub fn currency(&self) -> Option<CurrencyCode> {
        self.currency
    }

    /// True when one separator followed by exactly three digits could be either a
    /// thousands separator or a decimal point ("1,250", "1.250"). The value follows the
    /// text's style (continental when a decimal-comma currency such as EUR is written
    /// after the number, English otherwise) and a person should confirm it.
    #[must_use]
    pub fn ambiguous(&self) -> bool {
        self.ambiguous
    }
}

impl fmt::Display for Amount {
    /// `1250.00 EUR`, or the value alone when no currency was named.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.currency {
            Some(code) => write!(f, "{} {}", self.value, code.as_str()),
            None => write!(f, "{}", self.value),
        }
    }
}

/// Most significant digits a decimal holds; a longer number is refused, not rounded.
const MAX_DIGITS: usize = 28;

/// ISO 4217 codes recognised before or after a number. A list, not "any three capital
/// letters", so "NET 30" or "ABC 100" is not read as money.
const CODES: [&str; 32] = [
    "AED", "AUD", "BRL", "CAD", "CHF", "CNY", "CZK", "DKK", "EUR", "GBP", "HKD", "HUF", "IDR",
    "ILS", "INR", "JPY", "KRW", "MXN", "MYR", "NOK", "NZD", "PHP", "PLN", "RON", "SAR", "SEK",
    "SGD", "THB", "TRY", "TWD", "USD", "ZAR",
];

/// Currencies whose home locales write a decimal comma.
const DECIMAL_COMMA: [&str; 12] = [
    "BRL", "CZK", "DKK", "EUR", "HUF", "IDR", "NOK", "PLN", "RON", "SEK", "TRY", "ZAR",
];

/// Symbols, longest first so "US$" wins over "$".
const SYMBOLS: [(&str, &str); 8] = [
    ("US$", "USD"),
    ("A$", "AUD"),
    ("C$", "CAD"),
    ("$", "USD"),
    ("€", "EUR"),
    ("£", "GBP"),
    ("¥", "JPY"),
    ("₹", "INR"),
];

/// Currency words, longest first, lower case.
const WORDS: [(&str, &str); 9] = [
    ("united states dollars", "USD"),
    ("u.s. dollars", "USD"),
    ("us dollars", "USD"),
    ("pounds sterling", "GBP"),
    ("dollars", "USD"),
    ("dollar", "USD"),
    ("euros", "EUR"),
    ("euro", "EUR"),
    ("pounds", "GBP"),
];

fn code(text: &str) -> Option<CurrencyCode> {
    CurrencyCode::new(text).ok()
}

/// Reads an amount span. See [`super::normalize_amount`].
pub(super) fn parse(span: &str) -> Option<Amount> {
    let text = span.trim().trim_end_matches([',', ';', ':']).trim_end();
    if let Some(inner) = text.strip_suffix(')') {
        // "Words ($numeral)": both must be present and agree.
        let open = inner.rfind('(')?;
        let outside = inner.get(..open)?.trim();
        let numeral = numeral(inner.get(open.checked_add(1)?..)?)?;
        if outside.is_empty() {
            return None;
        }
        let (value, currency) = in_words(outside, true)?;
        if value != numeral.value {
            return None;
        }
        let currency = match (currency, numeral.currency) {
            (Some(a), Some(b)) if a != b => return None,
            (a, b) => b.or(a),
        };
        return Some(Amount {
            currency,
            ..numeral
        });
    }
    if let Some(found) = numeral(text) {
        return Some(found);
    }
    let (value, currency) = in_words(text, false)?;
    Some(Amount {
        value,
        currency,
        ambiguous: false,
    })
}

/// "USD 1,250.00", "-$3", "1.250,00 €", "1 250,00 EUR", "CHF 1'250.00".
fn numeral(text: &str) -> Option<Amount> {
    let mut rest = text.trim();
    let mut negative = false;
    if let Some(r) = rest.strip_prefix(['-', '−']) {
        (rest, negative) = (r.trim_start(), true);
    }
    let mut currency = None;
    if let Some((symbol, iso)) = SYMBOLS.iter().find(|(s, _)| rest.starts_with(s)) {
        rest = rest.get(symbol.len()..)?.trim_start();
        currency = code(iso);
    } else if let Some(c) = CODES.iter().find(|c| rest.starts_with(*c)) {
        let after = rest.get(c.len()..)?;
        // A code is a word: "USD 5" or "USD5", never the start of "USDA".
        if after.starts_with(|ch: char| ch.is_alphabetic()) {
            return None;
        }
        rest = after.trim_start();
        currency = code(c);
    }
    if !negative
        && currency.is_some()
        && let Some(r) = rest.strip_prefix(['-', '−'])
    {
        (rest, negative) = (r.trim_start(), true);
    }
    let mut suffixed = false;
    if currency.is_none() {
        if let Some((symbol, iso)) = SYMBOLS.iter().find(|(s, _)| rest.ends_with(s)) {
            rest = rest
                .get(..rest.len().checked_sub(symbol.len())?)?
                .trim_end();
            currency = code(iso);
            suffixed = true;
        } else if let Some(c) = CODES.iter().find(|c| rest.ends_with(*c)) {
            let before = rest.get(..rest.len().checked_sub(c.len())?)?;
            if before.ends_with(|ch: char| ch.is_alphabetic()) {
                return None;
            }
            rest = before.trim_end();
            currency = code(c);
            suffixed = true;
        } else {
            let lower = rest.to_lowercase();
            if let Some((word, iso)) = WORDS
                .iter()
                .find(|(w, _)| lower.ends_with(&format!(" {w}")))
            {
                // Lower-casing kept the length for these ASCII words, so the cut is exact.
                let cut = rest.len().checked_sub(word.len())?;
                if lower.len() == rest.len() {
                    rest = rest.get(..cut)?.trim_end();
                    currency = code(iso);
                }
            }
        }
    }
    // The text's style decides a lone separator before three digits: continental when
    // the currency follows the number and is one whose home locales write a decimal
    // comma ("1.250 €", "1.250 EUR"); English otherwise ("1,250 USD", "EUR 1.250").
    let continental = suffixed && currency.is_some_and(|c| DECIMAL_COMMA.contains(&c.as_str()));
    let (magnitude, ambiguous) = body(rest, continental)?;
    let value = if negative && !magnitude.is_zero() {
        Decimal::ZERO.checked_sub(magnitude)?
    } else {
        magnitude
    };
    Some(Amount {
        value,
        currency,
        ambiguous,
    })
}

/// Whether `c` groups thousands: a space, a no-break space, a narrow no-break space or
/// an apostrophe (Swiss). A comma or a full stop may too; see [`body`].
fn is_space_group(c: char) -> bool {
    matches!(c, ' ' | '\u{a0}' | '\u{202f}' | '\'' | '’')
}

/// The number itself, with its separators resolved. `continental` is the hint from the
/// currency (see [`numeral`]) that decides a lone separator followed by exactly three
/// digits ("1.250 €" is 1250; "USD 1.250" is 1.25), marked ambiguous either way.
fn body(text: &str, continental: bool) -> Option<(Decimal, bool)> {
    if !text.starts_with(|c: char| c.is_ascii_digit())
        || !text.ends_with(|c: char| c.is_ascii_digit())
    {
        return None;
    }
    if text
        .chars()
        .any(|c| !(c.is_ascii_digit() || c == '.' || c == ',' || is_space_group(c)))
    {
        return None;
    }
    let dots = text.matches('.').count();
    let commas = text.matches(',').count();
    let spaced: Vec<char> = {
        let mut kinds: Vec<char> = text.chars().filter(|&c| is_space_group(c)).collect();
        kinds.sort_unstable();
        kinds.dedup();
        kinds
    };
    if spaced.len() > 1 {
        return None;
    }
    let space = spaced.first().copied();
    let mut ambiguous = false;
    // (decimal separator, grouping separator)
    let (decimal, group): (Option<char>, Option<char>) = match (dots, commas, space) {
        (0, 0, g) => (None, g),
        (d, c, None) if d > 0 && c > 0 => {
            let last_dot = text.rfind('.')?;
            let last_comma = text.rfind(',')?;
            if last_dot > last_comma {
                (d == 1).then_some(())?;
                (Some('.'), Some(','))
            } else {
                (c == 1).then_some(())?;
                (Some(','), Some('.'))
            }
        }
        (_, _, Some(_)) if dots > 0 && commas > 0 => return None,
        (d, c, g) => {
            let sep = if d > 0 { '.' } else { ',' };
            let n = d.max(c);
            if n > 1 {
                // "1.250.000" or "1,250,000": grouping only, and not alongside spaces.
                if g.is_some() {
                    return None;
                }
                (None, Some(sep))
            } else if g.is_some() {
                // "1 250,00", "1'250.00": the space or apostrophe groups, so this is decimal.
                (Some(sep), g)
            } else {
                let after = text.rsplit(sep).next()?.len();
                if after == 3 {
                    ambiguous = true;
                    let grouping = if continental { sep == '.' } else { sep == ',' };
                    if grouping {
                        (None, Some(sep))
                    } else {
                        (Some(sep), None)
                    }
                } else {
                    (Some(sep), None)
                }
            }
        }
    };
    let (int_part, frac_part) = match decimal {
        Some(sep) => {
            let (i, f) = text.split_once(sep)?;
            (i, Some(f))
        }
        None => (text, None),
    };
    let mut plain = String::with_capacity(MAX_DIGITS.saturating_add(1));
    match group {
        Some(g) if int_part.contains(g) => {
            let mut parts = int_part.split(g);
            let head = parts.next()?;
            if head.is_empty() || head.len() > 3 || !head.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            plain.push_str(head);
            for part in parts {
                if part.len() != 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                plain.push_str(part);
            }
        }
        _ => {
            if !int_part.bytes().all(|b| b.is_ascii_digit()) || int_part.is_empty() {
                return None;
            }
            plain.push_str(int_part);
        }
    }
    let int_len = plain.len();
    if let Some(frac) = frac_part {
        if frac.is_empty() || !frac.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        plain.push('.');
        plain.push_str(frac);
    }
    let digit_count = int_len.saturating_add(frac_part.map_or(0, str::len));
    if digit_count > MAX_DIGITS {
        return None;
    }
    let value = Decimal::from_str_exact(&plain).ok()?;
    Some((value, ambiguous))
}

/// "One Thousand Two Hundred Fifty Dollars", "one thousand dollars and fifty cents",
/// "five hundred and 50/100 dollars". Without `currency_optional` a currency word is
/// required: "thirty" alone is a number, not money.
fn in_words(text: &str, currency_optional: bool) -> Option<(Decimal, Option<CurrencyCode>)> {
    let lower = text.to_lowercase();
    let lower = lower.strip_suffix(" only").unwrap_or(&lower).trim();
    // Split at the currency word, if any.
    let found = WORDS.iter().find_map(|(word, iso)| {
        let at = lower.find(&format!(" {word}"))?;
        let end = at.checked_add(1)?.checked_add(word.len())?;
        // Whole word only.
        if lower.get(end..)?.starts_with(|c: char| c.is_alphanumeric()) {
            return None;
        }
        Some((at, end, *iso))
    });
    let (before, after, currency) = match found {
        Some((at, end, iso)) => (lower.get(..at)?.trim(), lower.get(end..)?.trim(), code(iso)),
        None if currency_optional => (lower, "", None),
        None => return None,
    };
    // Cents: "... and 50/100" before the currency word, or "and fifty cents" after it.
    let (whole_text, cents) = if let Some((head, tail)) = before.rsplit_once(" and ") {
        match tail.strip_suffix("/100") {
            Some(cents) => (head, Some(words::digits(cents, 2)?)),
            None => (before, None),
        }
    } else {
        (before, None)
    };
    let cents = match (cents, after) {
        (c, "") => c,
        (None, tail) => {
            let tail = tail.strip_prefix("and ")?;
            let count = tail
                .strip_suffix(" cents")
                .or_else(|| tail.strip_suffix(" cent"))?;
            Some(words::count(count)?)
        }
        (Some(_), _) => return None,
    };
    let whole = words::cardinal(&words::split_words(whole_text))?;
    let mut value = Decimal::from(whole);
    if let Some(c) = cents {
        if c > 99 {
            return None;
        }
        value = value.checked_add(Decimal::new(i64::try_from(c).ok()?, 2))?;
    }
    Some((value, currency))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separators_resolve_by_position_and_count() {
        let b = |t: &str, c: bool| body(t, c).map(|(v, a)| (v.to_string(), a));
        assert_eq!(b("1,250.00", false), Some(("1250.00".into(), false)));
        assert_eq!(b("1.250,00", false), Some(("1250.00".into(), false)));
        assert_eq!(b("1,250", false), Some(("1250".into(), true)));
        assert_eq!(b("1.250", false), Some(("1.250".into(), true)));
        assert_eq!(b("1.250", true), Some(("1250".into(), true)));
        assert_eq!(b("1,250", true), Some(("1.250".into(), true)));
        assert_eq!(b("1,25", false), Some(("1.25".into(), false)));
        assert_eq!(b("1 250,00", false), Some(("1250.00".into(), false)));
        assert_eq!(b("1'250.00", false), Some(("1250.00".into(), false)));
        assert_eq!(b("1.250.000", false), Some(("1250000".into(), false)));
        for bad in [
            "",
            "1,2,3",
            "1.250.00,0,0",
            "1,250.000.5",
            "12,50,000",
            "1 250'000",
            ".5",
            "5.",
            "1 250.000,5",
            "1e5",
            "1..2",
        ] {
            assert_eq!(body(bad, false), None, "{bad:?}");
        }
        assert!(body(&"9".repeat(28), false).is_some());
        assert_eq!(body(&"9".repeat(29), false), None);
    }
}
