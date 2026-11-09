//! One value against one field: kind, options and validation rule.

use std::collections::BTreeMap;

use casual_sign_model::limits::MAX_REGEX_BYTES;
use casual_sign_model::{DateFormat, Field, FieldType, FieldValue, NumberRule, ValidationRule};
use regex::{Regex, RegexBuilder};

use crate::error::{FieldError, Invalid};
use crate::parse::{parse_date, parse_number};

/// Most bytes a sender's pattern may compile to (the `regex` crate's `size_limit`).
/// A decision of `T-1D`: 256 KiB holds any sensible validation pattern and bounds what
/// one hostile pattern can make the server allocate.
pub const REGEX_SIZE_LIMIT: usize = 256 * 1024;
/// Most bytes of lazy DFA cache per pattern (`dfa_size_limit`).
pub const REGEX_DFA_LIMIT: usize = 256 * 1024;
/// Deepest nesting of groups in a pattern (`nest_limit`).
pub const REGEX_NEST_LIMIT: u32 = 32;

/// Compiled patterns, so an envelope with a thousand fields sharing one pattern compiles
/// it once.
#[derive(Debug, Default)]
pub(crate) struct Patterns {
    compiled: BTreeMap<String, Result<Regex, Invalid>>,
}

impl Patterns {
    pub(crate) fn get(&mut self, pattern: &str) -> Result<&Regex, Invalid> {
        self.compiled
            .entry(pattern.to_owned())
            .or_insert_with(|| compile_pattern(pattern))
            .as_ref()
            .map_err(|e| *e)
    }
}

/// Compiles a sender's pattern to match a whole value, within the size limits.
///
/// The pattern is first compiled alone, so one that only parses once wrapped (`a)|(b`)
/// cannot escape the anchors.
fn compile_pattern(pattern: &str) -> Result<Regex, Invalid> {
    if pattern.len() > MAX_REGEX_BYTES {
        return Err(Invalid::PatternTooLong);
    }
    build(pattern)?;
    build(&format!(r"\A(?:{pattern})\z"))
}

fn build(pattern: &str) -> Result<Regex, Invalid> {
    RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_DFA_LIMIT)
        .nest_limit(REGEX_NEST_LIMIT)
        .build()
        .map_err(|e| match e {
            regex::Error::CompiledTooBig(_) => Invalid::PatternTooBig,
            _ => Invalid::PatternSyntax,
        })
}

/// Checks one value against one field: that its kind suits the field's type, that a
/// choice is one of the options, and that it passes the field's validation (or the one
/// its type implies: a `number` field must hold a number).
///
/// An empty value passes; whether one is needed is `required`'s business, checked with
/// visibility in [`evaluate_envelope`](crate::evaluate_envelope). Never panics, whatever
/// the value or the sender's pattern.
pub fn validate(field: &Field, value: &FieldValue) -> Result<(), FieldError> {
    validate_with(field, value, &mut Patterns::default())
}

pub(crate) fn validate_with(
    field: &Field,
    value: &FieldValue,
    patterns: &mut Patterns,
) -> Result<(), FieldError> {
    let ty = field.field_type;
    match (ty, value) {
        (FieldType::Checkbox | FieldType::Approve | FieldType::Decline, FieldValue::Checked(_)) => {
            Ok(())
        }
        (
            FieldType::Signature | FieldType::Initials | FieldType::Stamp | FieldType::Drawing,
            FieldValue::Signature(_),
        ) => Ok(()),
        (FieldType::Attachment, FieldValue::Attachment(_)) => Ok(()),
        (FieldType::RadioGroup | FieldType::Dropdown, FieldValue::Choice(choice)) => {
            if field.options.is_empty() {
                return Err(Invalid::NoOptions.into());
            }
            let custom = ty == FieldType::Dropdown && field.allow_custom;
            if choice.is_empty() || custom || field.options.contains(choice.as_str()) {
                Ok(())
            } else {
                Err(Invalid::NotAnOption.into())
            }
        }
        (
            FieldType::Checkbox
            | FieldType::Approve
            | FieldType::Decline
            | FieldType::Signature
            | FieldType::Initials
            | FieldType::Stamp
            | FieldType::Drawing
            | FieldType::Attachment
            | FieldType::RadioGroup
            | FieldType::Dropdown,
            _,
        )
        | (
            _,
            FieldValue::Checked(_)
            | FieldValue::Choice(_)
            | FieldValue::Signature(_)
            | FieldValue::Attachment(_),
        ) => Err(Invalid::WrongKind.into()),
        (_, FieldValue::Text(text)) if text.is_empty() => Ok(()),
        (_, FieldValue::Text(text)) => match rule_for(field) {
            Some(rule) => check_rule(&rule, text.as_str(), patterns).map_err(FieldError::from),
            None => Ok(()),
        },
        // `FieldValue` is non-exhaustive: a kind added later is refused until handled here.
        _ => Err(Invalid::WrongKind.into()),
    }
}

/// The rule a field's text value is checked against: its own, else the one its type
/// implies.
pub(crate) fn rule_for(field: &Field) -> Option<ValidationRule> {
    if let Some(v) = &field.validation {
        return Some(v.rule.clone());
    }
    Some(match field.field_type {
        FieldType::Number => ValidationRule::Number(NumberRule::default()),
        FieldType::Date => ValidationRule::Date {
            format: date_format(field),
        },
        FieldType::EmailAddress => ValidationRule::Email,
        FieldType::Phone => ValidationRule::Phone,
        FieldType::Ssn => ValidationRule::Ssn,
        FieldType::Zip => ValidationRule::Zip,
        _ => return None,
    })
}

/// The date format a field's value is read in: its date validation's, else its
/// display format's, else ISO.
pub(crate) fn date_format(field: &Field) -> DateFormat {
    if let Some(ValidationRule::Date { format }) = field.validation.as_ref().map(|v| &v.rule) {
        return *format;
    }
    field
        .format
        .as_ref()
        .and_then(|f| f.date_format)
        .unwrap_or_default()
}

fn check_rule(rule: &ValidationRule, text: &str, patterns: &mut Patterns) -> Result<(), Invalid> {
    match rule {
        ValidationRule::Email => is_email(text).then_some(()).ok_or(Invalid::Email),
        ValidationRule::Number(r) => parse_number(text, Some(r)).map(|_| ()),
        ValidationRule::Date { format } => parse_date(text, *format).map(|_| ()),
        ValidationRule::Zip => is_zip(text).then_some(()).ok_or(Invalid::Zip),
        ValidationRule::Ssn => is_ssn(text).then_some(()).ok_or(Invalid::Ssn),
        ValidationRule::Phone => is_phone(text).then_some(()).ok_or(Invalid::Phone),
        ValidationRule::Length(r) => {
            // Counting stops one past the maximum, so a long value costs no more than it.
            let chars = text.chars().count();
            let chars = u32::try_from(chars).unwrap_or(u32::MAX);
            if r.min().is_some_and(|min| chars < min) {
                Err(Invalid::TooShort)
            } else if r.max().is_some_and(|max| chars > max) {
                Err(Invalid::TooLong)
            } else {
                Ok(())
            }
        }
        ValidationRule::Regex { pattern } => {
            let re = patterns.get(pattern.as_str())?;
            re.is_match(text).then_some(()).ok_or(Invalid::Pattern)
        }
        // `ValidationRule` is non-exhaustive: a rule added later is refused until handled here.
        _ => Err(Invalid::WrongKind),
    }
}

/// A pragmatic email check: one `@`; a dot-atom local part of 1 to 64 bytes; a domain of
/// at most 253 bytes, two or more labels of letters, digits and inner hyphens, ending in
/// a letters-only top-level label. International domains must arrive in punycode.
pub(crate) fn is_email(text: &str) -> bool {
    let Some((local, domain)) = text.split_once('@') else {
        return false;
    };
    if local.is_empty() || local.len() > 64 || domain.len() > 253 || domain.contains('@') {
        return false;
    }
    const ATEXT: &[u8] = b"!#$%&'*+-/=?^_`{|}~";
    let local_ok = local.split('.').all(|atom| {
        !atom.is_empty()
            && atom
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || ATEXT.contains(&b))
    });
    let labels: Vec<&str> = domain.split('.').collect();
    let label_ok = |l: &&str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    let tld_ok = labels
        .last()
        .is_some_and(|t| t.len() >= 2 && t.bytes().all(|b| b.is_ascii_alphabetic()));
    local_ok && labels.len() >= 2 && labels.iter().all(label_ok) && tld_ok
}

/// A US ZIP code: `12345`, `12345-6789` or `123456789`.
pub(crate) fn is_zip(text: &str) -> bool {
    let digits = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_digit());
    match text.split_once('-') {
        Some((five, four)) => digits(five, 5) && digits(four, 4),
        None => digits(text, 5) || digits(text, 9),
    }
}

/// A US social security number, `123-45-6789` or nine digits, excluding the numbers
/// the SSA never issues: area 000, 666 or 900–999, group 00, serial 0000.
pub(crate) fn is_ssn(text: &str) -> bool {
    let plain: String = match (text.len(), text.get(3..4), text.get(6..7)) {
        (11, Some("-"), Some("-")) => text.chars().filter(|c| *c != '-').collect(),
        (9, _, _) => text.to_owned(),
        _ => return false,
    };
    if plain.len() != 9 || !plain.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let (Some(area), Some(group), Some(serial)) =
        (plain.get(0..3), plain.get(3..5), plain.get(5..9))
    else {
        return false;
    };
    area != "000" && area != "666" && !area.starts_with('9') && group != "00" && serial != "0000"
}

/// A phone number read leniently in the spirit of E.164: an optional leading `+`, then
/// digits with spaces, hyphens, dots and at most one pair of parentheses; 7 to 15
/// digits; after a `+`, the country code does not start with 0.
pub(crate) fn is_phone(text: &str) -> bool {
    let text = text.trim();
    let (international, rest) = match text.strip_prefix('+') {
        Some(r) => (true, r),
        None => (false, text),
    };
    let mut digits = 0usize;
    let mut first_digit = None;
    let mut opens = 0u8;
    let mut closes = 0u8;
    for c in rest.chars() {
        match c {
            '0'..='9' => {
                first_digit.get_or_insert(c);
                digits = digits.saturating_add(1);
            }
            ' ' | '-' | '.' => {}
            '(' if opens == 0 => opens = 1,
            ')' if opens == 1 && closes == 0 => closes = 1,
            _ => return false,
        }
    }
    opens == closes && (7..=15).contains(&digits) && !(international && first_digit == Some('0'))
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (CLAUDE.md): a failure here is the test failing.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use casual_sign_model::{
        DataLabel, FieldOptions, Id, LengthRule, Placement, Points, Text, Validation,
    };
    use rust_decimal::Decimal;
    use std::time::Instant;

    fn field(ty: FieldType, rule: Option<ValidationRule>) -> Field {
        let p = |n: i64| Points::new(Decimal::from(n)).unwrap();
        let mut f = Field::new(
            Id::new("f").unwrap(),
            Id::new("d").unwrap(),
            ty,
            Placement::new(1, p(0), p(0), p(10), p(10)).unwrap(),
        );
        f.validation = rule.map(|rule| Validation {
            rule,
            message: None,
        });
        f.label = Some(DataLabel::new("x").unwrap());
        f
    }

    fn text(s: &str) -> FieldValue {
        FieldValue::Text(Text::new(s).unwrap())
    }

    fn check(rule: ValidationRule, value: &str) -> Result<(), FieldError> {
        validate(&field(FieldType::Text, Some(rule)), &text(value))
    }

    #[test]
    fn email_validation() {
        for ok in ["a@b.co", "first.last+tag@sub.example.org", "x_y@a-b.io"] {
            assert!(check(ValidationRule::Email, ok).is_ok(), "{ok}");
        }
        for bad in [
            "a",
            "a@b",
            "@b.co",
            "a@.co",
            "a@b..co",
            "a..b@c.co",
            "a@-b.co",
            "a@b.c",
            "a@b.c0",
            "a@@b.co",
            "é@b.co",
            "a b@c.co",
            &format!("{}@b.co", "a".repeat(65)),
        ] {
            assert_eq!(
                check(ValidationRule::Email, bad),
                Err(FieldError::Invalid(Invalid::Email)),
                "{bad}"
            );
        }
    }

    #[test]
    fn email_type_implies_email_validation() {
        let f = field(FieldType::EmailAddress, None);
        assert!(validate(&f, &text("a@b.co")).is_ok());
        assert_eq!(
            validate(&f, &text("nope")).map_err(|e| e.code()),
            Err("CS-FLD-0002")
        );
    }

    #[test]
    fn number_validation_uses_the_rule() {
        let rule = NumberRule::new(
            Some(Decimal::from(-5)),
            Some(Decimal::from(5)),
            None,
            Some(1),
        )
        .unwrap();
        let r = || ValidationRule::Number(rule.clone());
        assert!(check(r(), "-5").is_ok());
        assert!(check(r(), "4.5").is_ok());
        assert_eq!(check(r(), "4.55"), Err(Invalid::TooManyDecimals.into()));
        assert_eq!(check(r(), "5.1"), Err(Invalid::AboveMaximum.into()));
        assert_eq!(check(r(), "-5.1"), Err(Invalid::BelowMinimum.into()));
        assert_eq!(check(r(), "NaN"), Err(Invalid::Number.into()));
        assert!(validate(&field(FieldType::Number, None), &text("1,234,567.891")).is_ok());
    }

    #[test]
    fn date_validation_reads_the_field_format() {
        let r = || ValidationRule::Date {
            format: DateFormat::DdMmYyyyDot,
        };
        assert!(check(r(), "29.02.2024").is_ok());
        assert_eq!(check(r(), "29.02.2023"), Err(Invalid::Date.into()));
        let mut f = field(FieldType::Date, None);
        assert!(validate(&f, &text("2024-02-29")).is_ok());
        f.format = Some(casual_sign_model::Format {
            date_format: Some(DateFormat::MmDdYyyy),
            ..Default::default()
        });
        assert!(validate(&f, &text("02/29/2024")).is_ok());
        assert!(validate(&f, &text("2024-02-29")).is_err());
    }

    #[test]
    fn zip_validation() {
        for ok in ["12345", "12345-6789", "123456789"] {
            assert!(check(ValidationRule::Zip, ok).is_ok());
        }
        for bad in [
            "1234",
            "123456",
            "12345-678",
            "1234a",
            "12345 6789",
            "１２３４５",
        ] {
            assert!(check(ValidationRule::Zip, bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn ssn_validation() {
        for ok in ["123-45-6789", "123456789", "899-01-0001"] {
            assert!(check(ValidationRule::Ssn, ok).is_ok(), "{ok}");
        }
        for bad in [
            "000-12-3456",
            "666-12-3456",
            "900-12-3456",
            "123-00-4567",
            "123-45-0000",
            "123-456-789",
            "12-345-6789",
            "12345678",
            "123 45 6789",
        ] {
            assert!(check(ValidationRule::Ssn, bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn phone_validation() {
        for ok in [
            "+14155552671",
            "+44 20 7946 0958",
            "(415) 555-2671",
            "415.555.2671",
            "5552671",
        ] {
            assert!(check(ValidationRule::Phone, ok).is_ok(), "{ok}");
        }
        for bad in [
            "+0123456789",
            "123456",
            "1234567890123456",
            "+1 (415)) 555",
            "415-555-CALL",
            "++14155552671",
            "(415 555 2671",
        ] {
            assert!(check(ValidationRule::Phone, bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn length_counts_characters_not_bytes() {
        let r = || ValidationRule::Length(LengthRule::new(Some(2), Some(3)).unwrap());
        assert!(check(r(), "€€€").is_ok());
        assert_eq!(check(r(), "€"), Err(Invalid::TooShort.into()));
        assert_eq!(check(r(), "€€€€"), Err(Invalid::TooLong.into()));
    }

    fn regex(p: &str) -> ValidationRule {
        ValidationRule::Regex {
            pattern: Text::new(p).unwrap(),
        }
    }

    #[test]
    fn regex_matches_the_whole_value() {
        assert!(check(regex("[A-Z]{2}[0-9]{4}"), "AB1234").is_ok());
        assert_eq!(
            check(regex("[A-Z]{2}[0-9]{4}"), "xAB1234"),
            Err(Invalid::Pattern.into())
        );
        assert_eq!(check(regex("a|ab"), "ab"), Ok(()));
        // A pattern that only parses once wrapped cannot break out of the anchors.
        assert_eq!(
            check(regex("a)|(b"), "zzzb"),
            Err(Invalid::PatternSyntax.into())
        );
        assert_eq!(check(regex("("), "x"), Err(Invalid::PatternSyntax.into()));
    }

    #[test]
    fn catastrophic_regex_runs_in_linear_time() {
        // `(a+)+$` takes exponential time in a backtracking engine on "aaaa…!".
        let value = format!("{}!", "a".repeat(3_999));
        for pattern in ["(a+)+$", "(a|a)*b", "(a|aa)+$", "(.*a){20}"] {
            let start = Instant::now();
            assert_eq!(
                check(regex(pattern), &value),
                Err(Invalid::Pattern.into()),
                "{pattern}"
            );
            assert!(
                start.elapsed().as_secs() < 2,
                "{pattern} took {:?}",
                start.elapsed()
            );
        }
    }

    #[test]
    fn regex_size_and_length_are_bounded() {
        // Compiles to megabytes; refused by the size limit, not run.
        assert_eq!(
            check(regex(r"\w{1000}"), "x"),
            Err(Invalid::PatternTooBig.into())
        );
        assert_eq!(
            check(
                regex("(((((((((((((((((((((((((((((((((a)))))))))))))))))))))))))))))))))"),
                "a"
            ),
            Err(Invalid::PatternSyntax.into())
        );
        let long = "a".repeat(MAX_REGEX_BYTES + 1);
        assert_eq!(
            check(regex(&long), "a"),
            Err(Invalid::PatternTooLong.into())
        );
        assert!(
            check(
                regex(&"a".repeat(MAX_REGEX_BYTES)),
                &"a".repeat(MAX_REGEX_BYTES)
            )
            .is_ok()
        );
    }

    #[test]
    fn value_kind_must_suit_the_field() {
        assert_eq!(
            validate(&field(FieldType::Text, None), &FieldValue::Checked(true)),
            Err(Invalid::WrongKind.into())
        );
        assert_eq!(
            validate(&field(FieldType::Checkbox, None), &text("yes")),
            Err(Invalid::WrongKind.into())
        );
        assert!(
            validate(
                &field(FieldType::Checkbox, None),
                &FieldValue::Checked(false)
            )
            .is_ok()
        );
        let sig = FieldValue::Signature(Id::new("s1").unwrap());
        assert!(validate(&field(FieldType::Signature, None), &sig).is_ok());
        assert!(validate(&field(FieldType::Text, None), &sig).is_err());
    }

    #[test]
    fn choices_must_be_options_unless_custom_is_allowed() {
        let mut f = field(FieldType::Dropdown, None);
        let choice = |s: &str| FieldValue::Choice(Text::new(s).unwrap());
        assert_eq!(validate(&f, &choice("a")), Err(Invalid::NoOptions.into()));
        f.options =
            FieldOptions::new(vec![Text::new("a").unwrap(), Text::new("b").unwrap()]).unwrap();
        assert!(validate(&f, &choice("a")).is_ok());
        assert_eq!(validate(&f, &choice("c")), Err(Invalid::NotAnOption.into()));
        f.allow_custom = true;
        assert!(validate(&f, &choice("c")).is_ok());
        f.field_type = FieldType::RadioGroup;
        assert_eq!(validate(&f, &choice("c")), Err(Invalid::NotAnOption.into()));
    }
}
