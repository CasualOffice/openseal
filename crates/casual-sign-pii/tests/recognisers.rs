//! Table tests per recogniser: what each finds, with exact offsets, and what each
//! rule rejects. Values are synthetic or published test values (the IBAN registry's
//! examples, card networks' test numbers); none belongs to a person.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use casual_sign_pii::{Kind, MAX_SCORE, Options, Span, detect};

fn spans(text: &str) -> Vec<Span> {
    detect(text, &Options::default()).unwrap().spans
}

/// The spans of `kind` in `text`, as (matched text, score).
fn found(text: &str, kind: Kind) -> Vec<(&str, u16)> {
    spans(text)
        .into_iter()
        .filter(|s| s.kind == kind)
        .map(|s| (&text[s.start..s.end], s.score))
        .collect()
}

fn texts(text: &str, kind: Kind) -> Vec<&str> {
    found(text, kind).into_iter().map(|(t, _)| t).collect()
}

#[test]
fn email_found_with_its_domain_checked() {
    assert_eq!(
        found(
            "Write to j.doe+nda@mail.example.org today.",
            Kind::EmailAddress
        ),
        [("j.doe+nda@mail.example.org", MAX_SCORE)]
    );
    assert_eq!(
        texts("Écrire à josé@exemple.fr.", Kind::EmailAddress),
        ["josé@exemple.fr"]
    );
    // No top-level domain, a numeric one, or a label ending in a hyphen: not an address.
    assert!(
        texts(
            "user@localhost and user@10.0.0.1 and a@b-.com",
            Kind::EmailAddress
        )
        .is_empty()
    );
}

#[test]
fn phone_found_when_valid_for_a_region_and_dates_are_not_phones() {
    assert_eq!(
        texts("Call (202) 555-0123 now", Kind::PhoneNumber),
        ["(202) 555-0123"]
    );
    assert_eq!(
        texts("Tel: +44 20 7946 0958.", Kind::PhoneNumber),
        ["+44 20 7946 0958"]
    );
    assert_eq!(
        texts("mobile +44 161 496 0123", Kind::PhoneNumber),
        ["+44 161 496 0123"]
    );
    // Ofcom's drama mobile range is not allocated, and libphonenumber says so.
    assert!(texts("mobile +44 7700 900123", Kind::PhoneNumber).is_empty());
    // Context lifts the score as Presidio's enhancer does: 0.4 + 0.35.
    assert_eq!(
        found("phone 020 7946 0958", Kind::PhoneNumber),
        [("020 7946 0958", 750)]
    );
    assert_eq!(
        found("see 020 7946 0958", Kind::PhoneNumber),
        [("020 7946 0958", 400)]
    );
    // Too few digits, an invalid number, and date shapes.
    assert!(texts("room 12-34, code 123 4567", Kind::PhoneNumber).is_empty());
    assert!(
        texts(
            "on 12-05-2024 and 2024-05-12 and 12.05.2024",
            Kind::PhoneNumber
        )
        .is_empty()
    );
    // Order numbers written without a trunk 0 are not German, French, Israeli or UK numbers.
    assert!(texts("order 2024-0042 and order 543542055278", Kind::PhoneNumber).is_empty());
    // The digit tail of an IBAN-shaped account number (its check fails) is not a phone.
    assert!(
        texts(
            "Account NL11 JYLI 8753 3411 06 on record.",
            Kind::PhoneNumber
        )
        .is_empty()
    );
}

#[test]
fn iban_needs_mod97_and_the_country_format() {
    assert_eq!(
        found("IBAN DE89 3704 0044 0532 0130 00.", Kind::Iban),
        [("DE89 3704 0044 0532 0130 00", MAX_SCORE)]
    );
    assert_eq!(
        texts("to GB82WEST12345698765432 by Friday", Kind::Iban),
        ["GB82WEST12345698765432"]
    );
    // Presidio's case: a trailing number is not swallowed into the IBAN.
    assert_eq!(
        texts(
            "I want my deposit in DE89370400440532013000 2 days from today.",
            Kind::Iban
        ),
        ["DE89370400440532013000"]
    );
    // Portugal's BBAN is 21 digits; Presidio 2.2.364's table says 17 and misses every PT IBAN.
    assert_eq!(
        texts("PT50 0002 0123 1234 5678 9015 4", Kind::Iban),
        ["PT50 0002 0123 1234 5678 9015 4"]
    );
    // The registry's examples for Mauritius, Qatar and Palestine, whose Presidio
    // 2.2.364 lengths (28, 25, 25) are wrong; compact and grouped.
    for iban in [
        "MU17BOMM0101101030300200000MUR",
        "QA58DOHB00001234567890ABCDEFG",
        "PS92PALS000000000400123456702",
    ] {
        assert_eq!(texts(&format!("IBAN {iban}."), Kind::Iban), [iban]);
        let spaced = common::group4(iban, " ");
        assert_eq!(
            texts(&format!("IBAN {spaced}."), Kind::Iban),
            [spaced.as_str()]
        );
    }
    // Wrong check digits; right checksum but wrong length for the country; run-on text.
    assert!(texts("DE88 3704 0044 0532 0130 00", Kind::Iban).is_empty());
    assert!(texts("DE893704004405320130001", Kind::Iban).is_empty());
    assert!(texts("XDE89370400440532013000", Kind::Iban).is_empty());
}

#[test]
fn card_needs_luhn() {
    assert_eq!(
        found("Visa 4111 1111 1111 1111 exp", Kind::PaymentCard),
        [("4111 1111 1111 1111", MAX_SCORE)]
    );
    assert_eq!(
        texts("amex 3782 822463 10005", Kind::PaymentCard),
        ["3782 822463 10005"]
    );
    assert_eq!(
        texts("mc 5555-5555-5555-4444", Kind::PaymentCard),
        ["5555-5555-5555-4444"]
    );
    // Mastercard's 2-series, which Presidio's pattern does not cover.
    assert_eq!(
        texts("2223003122003222", Kind::PaymentCard),
        ["2223003122003222"]
    );
    assert!(texts("4111 1111 1111 1112", Kind::PaymentCard).is_empty());
    // Presidio's exclusion: thirteen digits starting with 1.
    assert!(texts("1234567890128", Kind::PaymentCard).is_empty());
}

#[test]
fn ssn_patterns_and_presidio_invalidation_rules() {
    assert_eq!(
        found("SSN: 536-22-8726", Kind::UsSsn),
        [("536-22-8726", 850)]
    );
    assert_eq!(
        found("ref 536-22-8726", Kind::UsSsn),
        [("536-22-8726", 500)]
    );
    assert_eq!(found("ref 536228726", Kind::UsSsn), [("536228726", 50)]);
    assert_eq!(found("ssn 536228726", Kind::UsSsn), [("536228726", 400)]);
    for bad in [
        "000-22-8726",
        "666-22-8726",
        "536-00-8726",
        "536-22-0000",
        "536-22.8726",
        "111-11-1111",
        "123-45-6789",
        "078-05-1120",
    ] {
        assert!(
            texts(&format!("SSN {bad}"), Kind::UsSsn).is_empty(),
            "{bad}"
        );
    }
}

#[test]
fn nino_pattern_and_excluded_prefixes() {
    assert_eq!(
        found("NI number AB 12 34 56 C", Kind::UkNino),
        [("AB 12 34 56 C", 850)]
    );
    assert_eq!(texts("ab123456c", Kind::UkNino), ["ab123456c"]);
    for bad in [
        "GB123456A",
        "BG123456A",
        "ZZ123456A",
        "DA123456A",
        "AO123456A",
        "AB123456E",
    ] {
        assert!(texts(bad, Kind::UkNino).is_empty(), "{bad}");
    }
}

#[test]
fn pan_high_and_medium_patterns() {
    assert_eq!(found("PAN ABCPE1234F", Kind::InPan), [("ABCPE1234F", 850)]);
    assert_eq!(found("id ABCPE1234F", Kind::InPan), [("ABCPE1234F", 500)]);
    // Fourth letter not a holder type: the medium pattern only.
    assert_eq!(found("id ABCDE1234F", Kind::InPan), [("ABCDE1234F", 100)]);
    assert!(texts("ABCPE12345", Kind::InPan).is_empty());
}

#[test]
fn aadhaar_needs_verhoeff_a_leading_digit_of_two_or_more_and_no_palindrome() {
    let mut r = common::Rng(7);
    let n = common::aadhaar_compact(&mut r);
    let spaced = common::group4(&n, " ");
    assert_eq!(
        found(&format!("Aadhaar {spaced}"), Kind::InAadhaar),
        [(spaced.as_str(), MAX_SCORE)]
    );
    let last = n.chars().last().unwrap().to_digit(10).unwrap();
    let broken = format!("{}{}", &n[..11], (last + 1) % 10);
    assert!(texts(&broken, Kind::InAadhaar).is_empty());
    // A Verhoeff-valid number starting with 1 is refused.
    let body = "12345678901";
    let one = format!("{body}{}", common::verhoeff_digit(body));
    assert!(texts(&one, Kind::InAadhaar).is_empty());
}

#[test]
fn ip_addresses_validated_by_the_standard_parser() {
    assert_eq!(
        found("from 192.0.2.44 at noon", Kind::IpAddress),
        [("192.0.2.44", 600)]
    );
    assert_eq!(
        found("IP 192.0.2.44", Kind::IpAddress),
        [("192.0.2.44", 950)]
    );
    assert_eq!(
        texts("net 198.51.100.0/24.", Kind::IpAddress),
        ["198.51.100.0/24"]
    );
    assert_eq!(
        texts("host 2001:db8::8a2e:370:7334 up", Kind::IpAddress),
        ["2001:db8::8a2e:370:7334"]
    );
    assert_eq!(
        texts("mapped ::ffff:192.0.2.1 ok", Kind::IpAddress),
        ["::ffff:192.0.2.1"]
    );
    assert!(texts("256.1.1.1 and 10:30:45 and 1.2.3", Kind::IpAddress).is_empty());
}

#[test]
fn a_date_is_a_date_of_birth_only_with_birth_context() {
    assert_eq!(
        found("Date of birth: 14/07/1982", Kind::DateOfBirth),
        [("14/07/1982", 950)]
    );
    assert_eq!(
        texts("born on 3 March 1985 in", Kind::DateOfBirth),
        ["3 March 1985"]
    );
    assert_eq!(
        texts("D.O.B. 1985-03-12", Kind::DateOfBirth),
        ["1985-03-12"]
    );
    assert_eq!(
        texts("birthday: March 3, 1985", Kind::DateOfBirth),
        ["March 3, 1985"]
    );
    assert!(texts("Effective date 14/07/1982", Kind::DateOfBirth).is_empty());
    // Not a calendar date either way round.
    assert!(texts("Date of birth: 31/02/1982", Kind::DateOfBirth).is_empty());
}

#[test]
fn a_span_inside_a_stronger_one_is_dropped() {
    // The card digits inside a valid IBAN are not reported as a card as well.
    let text = "DE89 3704 0044 0532 0130 00";
    let all = spans(text);
    assert_eq!(all.len(), 1, "{all:?}");
    assert_eq!(all[0].kind, Kind::Iban);
}

#[test]
fn spans_are_sorted_and_carry_no_text() {
    let text = "Email x1@example.com, phone (202) 555-0123, IP 192.0.2.1.";
    let s = spans(text);
    assert_eq!(
        s.iter().map(|s| s.kind).collect::<Vec<_>>(),
        [Kind::EmailAddress, Kind::PhoneNumber, Kind::IpAddress]
    );
    assert!(
        s.windows(2)
            .all(|w| (w[0].start, w[0].end) <= (w[1].start, w[1].end))
    );
    let debug = format!("{s:?}");
    assert!(
        !debug.contains("example") && !debug.contains("555"),
        "{debug}"
    );
}

#[test]
fn digit_groups_inside_a_longer_grouped_number_are_not_cards_or_aadhaar() {
    // An IBAN-shaped run whose own check fails, holding a Luhn-valid card and a
    // Verhoeff-valid Aadhaar as inner groups.
    let mut r = common::Rng(11);
    let aadhaar = common::group4(&common::aadhaar_compact(&mut r), " ");
    for text in [
        "DE00 4111 1111 1111 1111 00".to_string(),
        format!("XX00 {aadhaar} 00"),
        format!("GB00 WEST {aadhaar} 12"),
        "GB00 WEST 4111 1111 1111 1111".to_string(),
    ] {
        let all = spans(&text);
        assert!(
            all.iter()
                .all(|s| s.kind != Kind::PaymentCard && s.kind != Kind::InAadhaar),
            "{text}: {all:?}"
        );
    }
    // The same values on their own are found.
    assert_eq!(
        texts("Card 4111 1111 1111 1111", Kind::PaymentCard).len(),
        1
    );
    assert_eq!(texts(&format!("ref {aadhaar}"), Kind::InAadhaar).len(), 1);
}
