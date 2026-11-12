//! The recognisers. Each runs its patterns over the text, checks each candidate
//! (checksum, format or invalidation rule) and scores it, Presidio's way: a candidate
//! whose check holds scores [`MAX_SCORE`]; one whose check fails is dropped; one with no
//! check keeps its pattern's score, raised by a context word.
//!
//! Patterns are Presidio 2.2.364's (MIT, `LICENSE-PRESIDIO`), rewritten for the
//! `regex` crate, which has no look-around: each look-ahead or look-behind became a
//! check in code on the characters next to the match. ASCII word boundaries are used in
//! the patterns (they keep the regex engine's fast paths on any text) and the Unicode
//! boundary Presidio's `\b` means is then checked in code, so "é4111…" is not a card.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

use regex::Regex;

use crate::checksum;
use crate::context;
use crate::iban;
use crate::phone;
use crate::{Kind, MAX_SCORE, Scan};

macro_rules! patterns {
    ($($name:ident = $pat:expr;)*) => {
        $(static $name: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new($pat).ok());)*
        #[cfg(test)]
        pub(crate) fn all_patterns() -> Vec<(&'static str, bool)> {
            vec![$((stringify!($name), $name.is_some()),)*]
        }
    };
}

patterns! {
    EMAIL = r"(?:[!#$%&'*+\-/=?^_`{|}~\w][!#$%&'*+\-/=?^_`{|}~.\w]*[!#$%&'*+\-/=?^_`{|}~\w]|[!#$%&'*+\-/=?^_`{|}~\w])@\w+(?:-+\w+)*(?:\.\w+(?:-+\w+)*)+";
    IBAN = r"(?-u)[A-Z]{2}[0-9]{2}(?:[ \-]?[A-Z0-9]{4}){2,7}(?:[ \-]?[A-Z0-9]{1,3})?";
    // Presidio's card pattern plus Mastercard's 2-series (2221–2720), which it misses.
    CARD = r"(?-u)\b(?:4[0-9]{3}|5[0-5][0-9]{2}|2[2-7][0-9]{2}|6[0-9]{3}|1[0-9]{3}|3[0-9]{3})[- ]?[0-9]{3,4}[- ]?[0-9]{3,4}[- ]?[0-9]{3,5}\b";
    SSN1 = r"(?-u)\b[0-9]{5}-[0-9]{4}\b";
    SSN2 = r"(?-u)\b[0-9]{3}-[0-9]{6}\b";
    SSN3 = r"(?-u)\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b";
    SSN4 = r"(?-u)\b[0-9]{9}\b";
    SSN5 = r"(?-u)\b[0-9]{3}[- .][0-9]{2}[- .][0-9]{4}\b";
    NINO = r"(?-u)\b[a-ceghj-pr-tw-zA-CEGHJ-PR-TW-Z][a-ceghj-npr-tw-zA-CEGHJ-NPR-TW-Z] ?[0-9]{2} ?[0-9]{2} ?[0-9]{2} ?[a-dA-D]\b";
    PAN_HIGH = r"(?-u)\b[A-Za-z]{3}[AaBbCcFfGgHhJjLlPpTt][A-Za-z][0-9]{4}[A-Za-z]\b";
    PAN_MEDIUM = r"(?-u)\b[A-Za-z]{5}[0-9]{4}[A-Za-z]\b";
    AADHAAR1 = r"(?-u)\b[0-9]{12}\b";
    AADHAAR2 = r"(?-u)\b[0-9]{4}[- :][0-9]{4}[- :][0-9]{4}\b";
    IPV4 = r"(?-u)\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}(?:/(?:[0-2]?[0-9]|3[0-2]))?\b";
    // A candidate only; std's parser decides (Presidio's own pattern lists each form).
    IPV6 = r"(?-u)(?:[0-9A-Fa-f]{0,4}:){2,7}(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9A-Fa-f]{1,4})?(?:%[0-9A-Za-z]+)?(?:/[0-9]{1,3})?";
    PHONE = r"(?-u)\+?\(?[0-9][0-9 ().\-]{4,24}[0-9]";
    DATE_NUM = r"(?-u)\b([0-9]{1,2})([/.\-])([0-9]{1,2})([/.\-])([0-9]{4}|[0-9]{2})\b";
    DATE_YMD = r"(?-u)\b([0-9]{4})([/\-])([0-9]{1,2})([/\-])([0-9]{1,2})\b";
    DATE_D_MON_Y = r"(?i-u)\b([0-9]{1,2})(?:st|nd|rd|th)?[ \-]+(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\.?,?[ \-]+([0-9]{4}|[0-9]{2})\b";
    DATE_MON_D_Y = r"(?i-u)\b(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\.? +([0-9]{1,2})(?:st|nd|rd|th)?,? +([0-9]{4})\b";
}

const EMAIL_CONTEXT: &[&str] = &["email", "e mail"];
const PHONE_CONTEXT: &[&str] = &[
    "phone",
    "number",
    "telephone",
    "cell",
    "cellphone",
    "mobile",
    "call",
    "tel",
    "fax",
];
const IBAN_CONTEXT: &[&str] = &["iban", "bank", "transaction"];
const CARD_CONTEXT: &[&str] = &[
    "credit",
    "card",
    "visa",
    "mastercard",
    "cc",
    "amex",
    "discover",
    "jcb",
    "diners",
    "maestro",
    "instapayment",
];
const SSN_CONTEXT: &[&str] = &["social", "security", "ssn", "ssns", "ssid"];
const NINO_CONTEXT: &[&str] = &["national insurance", "ni number", "nino"];
const PAN_CONTEXT: &[&str] = &["permanent account number", "pan"];
const AADHAAR_CONTEXT: &[&str] = &["aadhaar", "uidai"];
const IP_CONTEXT: &[&str] = &["ip", "ipv4", "ipv6"];
/// Not Presidio's (it has no date-of-birth recogniser): a date is personal data here
/// only when one of these precedes it.
const DOB_CONTEXT: &[&str] = &[
    "birth",
    "born",
    "dob",
    "d o b",
    "birthday",
    "birthdate",
    "birthdays",
];

/// Every recogniser, in a fixed order.
pub(crate) fn run_all(scan: &mut Scan<'_>) {
    email(scan);
    phone(scan);
    iban(scan);
    card(scan);
    ssn(scan);
    nino(scan);
    pan(scan);
    aadhaar(scan);
    ip(scan);
    date_of_birth(scan);
}

/// Matches of `re` in the text, within the kind's candidate budget.
fn each(
    scan: &mut Scan<'_>,
    kind: Kind,
    re: &LazyLock<Option<Regex>>,
    mut f: impl FnMut(&mut Scan<'_>, usize, usize),
) {
    let Some(re) = re.as_ref() else { return };
    let text = scan.text;
    for m in re.find_iter(text) {
        if !scan.take(kind) {
            return;
        }
        f(scan, m.start(), m.end());
    }
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn before(text: &str, at: usize) -> Option<char> {
    text.get(..at).and_then(|s| s.chars().next_back())
}

fn after(text: &str, at: usize) -> Option<char> {
    text.get(at..).and_then(|s| s.chars().next())
}

/// Presidio's `\b…\b` under Unicode rules, for a match whose first and last characters
/// are word characters.
fn word_bounded(text: &str, start: usize, end: usize) -> bool {
    !before(text, start).is_some_and(is_word) && !after(text, end).is_some_and(is_word)
}

/// Whether the match is the tail of a longer grouped number: a space or hyphen before
/// it and a digit before that ("1234 5678 …"), or a chain of four-character groups
/// back to an IBAN's country and check digits ("GB88 CODL 7849 …"). Not Presidio's:
/// without it, the digit groups inside an IBAN whose check fails are read as a card or
/// an Aadhaar number whenever their own check digit happens to hold (one time in ten).
fn continues_group(text: &str, start: usize) -> bool {
    let head = text.get(..start).unwrap_or("").as_bytes();
    let mut end = head.len();
    // At most the 8 groups of the longest IBAN before the match.
    for hop in 0..9 {
        let Some(sep) = end.checked_sub(1) else {
            return false;
        };
        if !matches!(head.get(sep), Some(b' ' | b'-')) {
            return false;
        }
        let from = head
            .get(..sep)
            .unwrap_or(&[])
            .iter()
            .rev()
            .take_while(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
            .count();
        let Some(token) = head.get(sep.saturating_sub(from)..sep) else {
            return false;
        };
        if hop == 0 && token.last().is_some_and(u8::is_ascii_digit) {
            return true;
        }
        if let [a, b, c, d] = token {
            if a.is_ascii_uppercase()
                && b.is_ascii_uppercase()
                && c.is_ascii_digit()
                && d.is_ascii_digit()
            {
                return true;
            }
        } else {
            return false;
        }
        end = sep.saturating_sub(from);
    }
    false
}

/// A pattern score, raised when a context word precedes the match.
fn scored(scan: &Scan<'_>, start: usize, base: u16, words: &[&str]) -> u16 {
    if context::supports(&context::window(scan.text, start), words) {
        context::boosted(base)
    } else {
        base
    }
}

fn digits_of(s: &str) -> Vec<u8> {
    s.bytes().filter(u8::is_ascii_digit).collect()
}

fn email(scan: &mut Scan<'_>) {
    each(scan, Kind::EmailAddress, &EMAIL, |scan, start, end| {
        let Some(found) = scan.text.get(start..end) else {
            return;
        };
        if after(scan.text, end).is_some_and(is_word) || !email_ok(found) {
            return;
        }
        let score = scored(scan, start, MAX_SCORE, EMAIL_CONTEXT);
        scan.push(start, end, Kind::EmailAddress, score);
    });
}

/// Stands in for Presidio's `tldextract` check (a non-empty registrable domain), which
/// needs the Public Suffix List; this one needs no data: an alphabetic or IDNA
/// top-level label of two or more characters, labels of 1 to 63 bytes that neither
/// start nor end with a hyphen, and RFC 5321's length limits.
fn email_ok(address: &str) -> bool {
    let Some((local, domain)) = address.rsplit_once('@') else {
        return false;
    };
    if local.is_empty() || local.len() > 64 || domain.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2
        || labels
            .iter()
            .any(|l| l.is_empty() || l.len() > 63 || l.starts_with('-') || l.ends_with('-'))
    {
        return false;
    }
    let tld = labels.last().copied().unwrap_or("");
    let idna = tld.len() > 4 && tld.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("xn--"));
    idna || (tld.chars().count() >= 2 && tld.chars().all(char::is_alphabetic))
}

fn phone(scan: &mut Scan<'_>) {
    each(scan, Kind::PhoneNumber, &PHONE, |scan, start, end| {
        let text = scan.text;
        // A sign or digit before means the candidate began mid-number; a chain of groups
        // before it means it is the tail of an account number.
        if before(text, start).is_some_and(|c| is_word(c) || c == '+')
            || after(text, end).is_some_and(is_word)
            || continues_group(text, start)
        {
            return;
        }
        let Some(found) = text.get(start..end) else {
            return;
        };
        if phone::valid(found) {
            let score = scored(scan, start, phone::SCORE, PHONE_CONTEXT);
            scan.push(start, end, Kind::PhoneNumber, score);
        }
    });
}

/// Presidio walks its pattern's groups from the longest down; here the country's length
/// decides where the IBAN ends, so "DE89…3000 2 days" ends before " 2".
fn iban(scan: &mut Scan<'_>) {
    each(scan, Kind::Iban, &IBAN, |scan, start, end| {
        let text = scan.text;
        if before(text, start).is_some_and(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
            return;
        }
        let Some(found) = text.get(start..end) else {
            return;
        };
        let Some(want) = found.as_bytes().get(..2).and_then(iban::length) else {
            return;
        };
        let mut compact = Vec::with_capacity(want);
        let mut stop = None;
        for (i, b) in found.bytes().enumerate() {
            if b.is_ascii_alphanumeric() {
                compact.push(b);
                if compact.len() == want {
                    stop = Some(start.saturating_add(i).saturating_add(1));
                    break;
                }
            }
        }
        let Some(stop) = stop else { return };
        if after(text, stop).is_some_and(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
            return;
        }
        if iban::format_ok(&compact) && checksum::iban_mod97(&compact) {
            let score = scored(scan, start, MAX_SCORE, IBAN_CONTEXT);
            scan.push(start, stop, Kind::Iban, score);
        }
    });
}

fn card(scan: &mut Scan<'_>) {
    each(scan, Kind::PaymentCard, &CARD, |scan, start, end| {
        let text = scan.text;
        if !word_bounded(text, start, end) || continues_group(text, start) {
            return;
        }
        // Presidio's `(?!1\d{12}(?!\d))`: thirteen digits starting with 1 are refused.
        let run = text
            .get(start..)
            .unwrap_or("")
            .bytes()
            .take_while(u8::is_ascii_digit)
            .count();
        if run == 13 && text.as_bytes().get(start) == Some(&b'1') {
            return;
        }
        let Some(found) = text.get(start..end) else {
            return;
        };
        if checksum::luhn(&digits_of(found)) {
            let score = scored(scan, start, MAX_SCORE, CARD_CONTEXT);
            scan.push(start, end, Kind::PaymentCard, score);
        }
    });
}

fn ssn(scan: &mut Scan<'_>) {
    for (re, base) in [
        (&SSN1, 50),
        (&SSN2, 50),
        (&SSN3, 50),
        (&SSN4, 50),
        (&SSN5, 500),
    ] {
        each(scan, Kind::UsSsn, re, |scan, start, end| {
            let text = scan.text;
            let Some(found) = text.get(start..end) else {
                return;
            };
            if !word_bounded(text, start, end) || ssn_invalid(found) {
                return;
            }
            let score = scored(scan, start, base, SSN_CONTEXT);
            scan.push(start, end, Kind::UsSsn, score);
        });
    }
}

/// Presidio's `UsSsnRecognizer.invalidate_result`.
fn ssn_invalid(found: &str) -> bool {
    let delimiters = [b'.', b'-', b' ']
        .iter()
        .filter(|d| found.as_bytes().contains(d))
        .count();
    if delimiters > 1 {
        return true;
    }
    let d = digits_of(found);
    if d.len() != 9 || d.iter().all(|c| Some(c) == d.first()) {
        return true;
    }
    d.get(3..5) == Some(b"00".as_slice())
        || d.get(5..) == Some(b"0000".as_slice())
        || matches!(d.get(..3), Some(b"000" | b"666"))
        || matches!(d.as_slice(), b"123456789" | b"987654320" | b"078051120")
}

fn nino(scan: &mut Scan<'_>) {
    each(scan, Kind::UkNino, &NINO, |scan, start, end| {
        let text = scan.text;
        let Some(found) = text.get(start..end) else {
            return;
        };
        let prefix = found.get(..2).unwrap_or("").to_ascii_uppercase();
        if !word_bounded(text, start, end)
            || matches!(
                prefix.as_str(),
                "BG" | "GB" | "NK" | "KN" | "NT" | "TN" | "ZZ"
            )
        {
            return;
        }
        let score = scored(scan, start, 500, NINO_CONTEXT);
        scan.push(start, end, Kind::UkNino, score);
    });
}

/// Presidio's high (0.5) and medium (0.1) patterns. Its low pattern (0.01, any ten
/// characters with a letter and four digits) needs look-ahead and finds mostly noise;
/// it is not ported.
fn pan(scan: &mut Scan<'_>) {
    for (re, base) in [(&PAN_HIGH, 500), (&PAN_MEDIUM, 100)] {
        each(scan, Kind::InPan, re, |scan, start, end| {
            if word_bounded(scan.text, start, end) {
                let score = scored(scan, start, base, PAN_CONTEXT);
                scan.push(start, end, Kind::InPan, score);
            }
        });
    }
}

fn aadhaar(scan: &mut Scan<'_>) {
    for re in [&AADHAAR1, &AADHAAR2] {
        each(scan, Kind::InAadhaar, re, |scan, start, end| {
            let text = scan.text;
            let Some(found) = text.get(start..end) else {
                return;
            };
            if !word_bounded(text, start, end) || continues_group(text, start) {
                return;
            }
            let d = digits_of(found);
            let palindrome = d.iter().eq(d.iter().rev());
            if d.len() == 12
                && d.first().is_some_and(|&c| c >= b'2')
                && !palindrome
                && checksum::verhoeff(&d)
            {
                let score = scored(scan, start, MAX_SCORE, AADHAAR_CONTEXT);
                scan.push(start, end, Kind::InAadhaar, score);
            }
        });
    }
}

fn ip(scan: &mut Scan<'_>) {
    each(scan, Kind::IpAddress, &IPV4, |scan, start, end| {
        let text = scan.text;
        let Some(found) = text.get(start..end) else {
            return;
        };
        let addr = found.split('/').next().unwrap_or("");
        // Presidio's `ipaddress.ip_interface` check: std refuses leading zeros as it does.
        if word_bounded(text, start, end) && addr.parse::<Ipv4Addr>().is_ok() {
            let score = scored(scan, start, 600, IP_CONTEXT);
            scan.push(start, end, Kind::IpAddress, score);
        }
    });
    each(scan, Kind::IpAddress, &IPV6, |scan, start, end| {
        let text = scan.text;
        // Presidio's `(?<![\w:])` before and `(?![\w:]|\.\d)` after.
        if before(text, start).is_some_and(|c| is_word(c) || c == ':')
            || after(text, end).is_some_and(|c| is_word(c) || c == ':')
        {
            return;
        }
        let rest = text.get(end..).unwrap_or("");
        if rest.starts_with('.') && rest.as_bytes().get(1).is_some_and(u8::is_ascii_digit) {
            return;
        }
        let Some(found) = text.get(start..end) else {
            return;
        };
        let (addr, prefix) = match found.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (found, None),
        };
        let addr = addr.split('%').next().unwrap_or("");
        let Ok(parsed) = addr.parse::<Ipv6Addr>() else {
            return;
        };
        if prefix.is_some_and(|p| p.parse::<u8>().map_or(true, |n| n > 128)) {
            return;
        }
        let base = if parsed.is_unspecified() { 100 } else { 600 };
        let score = scored(scan, start, base, IP_CONTEXT);
        scan.push(start, end, Kind::IpAddress, score);
    });
}

fn date_of_birth(scan: &mut Scan<'_>) {
    // Day/month/year or month/day/year with one separator throughout; the '-' form takes
    // a four-digit year only, as Presidio's.
    each(scan, Kind::DateOfBirth, &DATE_NUM, |scan, start, end| {
        let Some(c) = DATE_NUM
            .as_ref()
            .and_then(|re| re.captures(scan.text.get(start..end).unwrap_or("")))
        else {
            return;
        };
        let (a, s1, b, s2, y) = (
            num(c.get(1)),
            c.get(2).map(|m| m.as_str()),
            num(c.get(3)),
            c.get(4).map(|m| m.as_str()),
            c.get(5),
        );
        let year_len = y.map_or(0, |m| m.as_str().len());
        if s1 != s2 || (s1 == Some("-") && year_len != 4) {
            return;
        }
        let y = num(y);
        if calendar(y, b, a, year_len) || calendar(y, a, b, year_len) {
            dob(scan, start, end);
        }
    });
    each(scan, Kind::DateOfBirth, &DATE_YMD, |scan, start, end| {
        let Some(c) = DATE_YMD
            .as_ref()
            .and_then(|re| re.captures(scan.text.get(start..end).unwrap_or("")))
        else {
            return;
        };
        if c.get(2).map(|m| m.as_str()) == c.get(4).map(|m| m.as_str())
            && calendar(num(c.get(1)), num(c.get(3)), num(c.get(5)), 4)
        {
            dob(scan, start, end);
        }
    });
    each(
        scan,
        Kind::DateOfBirth,
        &DATE_D_MON_Y,
        |scan, start, end| {
            let Some(c) = DATE_D_MON_Y
                .as_ref()
                .and_then(|re| re.captures(scan.text.get(start..end).unwrap_or("")))
            else {
                return;
            };
            let year_len = c.get(3).map_or(0, |m| m.as_str().len());
            if calendar(num(c.get(3)), month(c.get(2)), num(c.get(1)), year_len) {
                dob(scan, start, end);
            }
        },
    );
    each(
        scan,
        Kind::DateOfBirth,
        &DATE_MON_D_Y,
        |scan, start, end| {
            let Some(c) = DATE_MON_D_Y
                .as_ref()
                .and_then(|re| re.captures(scan.text.get(start..end).unwrap_or("")))
            else {
                return;
            };
            if calendar(num(c.get(3)), month(c.get(1)), num(c.get(2)), 4) {
                dob(scan, start, end);
            }
        },
    );
}

/// Presidio's date patterns score 0.6; a date of birth needs its context, so it is
/// always boosted.
fn dob(scan: &mut Scan<'_>, start: usize, end: usize) {
    if word_bounded(scan.text, start, end)
        && context::supports(&context::window(scan.text, start), DOB_CONTEXT)
    {
        scan.push(start, end, Kind::DateOfBirth, context::boosted(600));
    }
}

fn num(m: Option<regex::Match<'_>>) -> u32 {
    m.and_then(|m| m.as_str().parse().ok()).unwrap_or(0)
}

fn month(m: Option<regex::Match<'_>>) -> u32 {
    let name = m
        .map(|m| m.as_str().to_ascii_lowercase())
        .unwrap_or_default();
    const NAMES: [&str; 12] = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];
    let head = name.get(..3).unwrap_or("");
    NAMES
        .iter()
        .position(|n| *n == head)
        .map_or(0, |i| u32::try_from(i).unwrap_or(0).saturating_add(1))
}

/// A real calendar day. Two-digit years cannot tell a leap year, so 29 February passes.
fn calendar(year: u32, month: u32, day: u32, year_len: usize) -> bool {
    if year_len == 4 && !(1800..=2199).contains(&year) {
        return false;
    }
    let leap = year_len != 4
        || (year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)));
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pattern_compiles() {
        for (name, ok) in all_patterns() {
            assert!(ok, "{name} does not compile");
        }
    }

    #[test]
    fn email_domain_rules() {
        assert!(email_ok("a@example.com"));
        assert!(email_ok("a@example.xn--p1ai"));
        assert!(email_ok("josé@exemple.fr"));
        assert!(!email_ok("a@example.c"));
        assert!(!email_ok("a@10.0.0.1"));
        assert!(!email_ok("a@-x.com"));
        assert!(!email_ok(&format!("{}@example.com", "a".repeat(65))));
    }

    #[test]
    fn calendar_days() {
        assert!(calendar(2000, 2, 29, 4));
        assert!(!calendar(1900, 2, 29, 4));
        assert!(calendar(0, 2, 29, 2));
        assert!(!calendar(1985, 4, 31, 4));
        assert!(!calendar(1985, 13, 1, 4));
        assert!(!calendar(1700, 1, 1, 4));
    }
}
