//! `ML-08C` (owner instruction 33: validation before models). For each validated
//! identifier: published test values found with their exact offsets, the same values
//! with the check broken not found, and, on a held-out synthetic set generated from its
//! own seed, the detection rate and the false-positive rate on values whose check is
//! broken. Run with `--nocapture` to see the table. Every value is a published
//! specimen or test value, or synthetic (see `common::validated`).

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use casual_sign_pii::{Kind, MAX_SCORE, Options, detect};
use common::Rng;
use common::validated::{self as v, Pair};

/// The spans of `kind` in `text`, as (matched text, score).
fn found(text: &str, kind: Kind) -> Vec<(&str, u16)> {
    detect(text, &Options::default())
        .unwrap()
        .spans
        .into_iter()
        .filter(|s| s.kind == kind)
        .map(|s| (&text[s.start..s.end], s.score))
        .collect()
}

/// `good` is found as `kind`, and `bad` (the same value with its check broken, which
/// must differ from it) is not.
fn holds(kind: Kind, good: &str, bad: &str) {
    assert_ne!(good, bad, "the mutation took no effect");
    let text = format!("Value {good} on file.");
    let hits = found(&text, kind);
    assert!(
        hits.iter().any(|(t, _)| *t == good),
        "{} not found in {text:?}: {hits:?}",
        kind.label()
    );
    let text = format!("Value {bad} on file.");
    let hits = found(&text, kind);
    assert!(
        hits.is_empty(),
        "{} found with its check broken in {text:?}: {hits:?}",
        kind.label()
    );
}

#[test]
fn us_itin_needs_an_irs_middle_group() {
    holds(Kind::UsItin, "912-78-1234", "912-93-1234");
    holds(Kind::UsItin, "912-50-1234", "912-49-1234");
    // An ITIN is not an SSN: area 9XX is never issued as one.
    assert!(found("SSN 912-78-1234", Kind::UsSsn).is_empty());
    assert_eq!(
        found("ITIN 912-78-1234", Kind::UsItin),
        [("912-78-1234", 850)]
    );
    // Mixed separators are not one number.
    assert!(found("912-78 1234", Kind::UsItin).is_empty());
}

#[test]
fn us_ein_needs_an_assigned_prefix() {
    holds(Kind::UsEin, "12-3456789", "07-3456789");
    holds(Kind::UsEin, "98-7654321", "97-7654321");
    assert_eq!(found("EIN 12-3456789", Kind::UsEin), [("12-3456789", 650)]);
}

#[test]
fn aba_routing_needs_the_3_7_1_check_and_a_reserve_prefix() {
    // Federal Reserve Bank routing numbers, published by the Federal Reserve.
    holds(Kind::AbaRouting, "011000015", "011000016");
    holds(Kind::AbaRouting, "021000021", "021000022");
    holds(Kind::AbaRouting, "0110-0001-5", "0110-0001-6");
    // A valid 3-7-1 sum but prefix 13, which the Federal Reserve does not use.
    assert!(found("Value 130000003 on file.", Kind::AbaRouting).is_empty());
    assert_eq!(found("011000015", Kind::AbaRouting), [("011000015", 400)]);
    assert_eq!(
        found("Routing number 011000015", Kind::AbaRouting),
        [("011000015", 750)]
    );
}

#[test]
fn ca_sin_needs_luhn() {
    // The Government of Canada's specimen SIN.
    holds(Kind::CaSin, "046 454 286", "046 454 287");
    holds(Kind::CaSin, "046-454-286", "046-454-287");
    assert_eq!(
        found("Social Insurance Number 046454286", Kind::CaSin),
        [("046454286", 750)]
    );
}

#[test]
fn uk_nhs_needs_mod_11() {
    // NHS Digital's documented example.
    holds(Kind::UkNhs, "943 476 5919", "943 476 5918");
    holds(Kind::UkNhs, "9434765919", "9434765910");
    // A UK phone number after its international prefix is not an NHS number.
    assert!(found("Tel +44 943 476 5919", Kind::UkNhs).is_empty());
}

#[test]
fn au_tfn_needs_its_weighted_check() {
    // The ATO's published example.
    holds(Kind::AuTfn, "123 456 782", "123 456 783");
    // A legacy eight-digit TFN, weights 10, 7, 8, 4, 6, 3, 5, 1.
    holds(Kind::AuTfn, "12345677", "12345678");
}

#[test]
fn au_medicare_needs_its_check_digit() {
    holds(Kind::AuMedicare, "2123 45670 1", "2123 45671 1");
    holds(Kind::AuMedicare, "2123456701", "2123456711");
}

#[test]
fn de_tax_id_needs_the_digit_rule_and_mod_11_10() {
    // The Bundeszentralamt für Steuern's example Steuer-ID.
    holds(Kind::DeTaxId, "86095742719", "86095742718");
    holds(Kind::DeTaxId, "86 095 742 719", "86 095 742 718");
    assert_eq!(
        found("86095742719", Kind::DeTaxId),
        [("86095742719", MAX_SCORE)]
    );
}

#[test]
fn fr_nir_needs_its_mod_97_key() {
    holds(
        Kind::FrNir,
        "2 55 08 14 168 025 38",
        "2 55 08 14 168 025 39",
    );
    holds(Kind::FrNir, "255081416802538", "255081416802539");
    // Corsica: department 2A is read as 19 for the key.
    let p = Pair {
        valid: "1 85 05 2A 004 123 56".into(),
        broken: "1 85 05 2A 004 123 57".into(),
    };
    let n: u64 = "1850519004123".parse().unwrap();
    assert_eq!(97 - n % 97, 56);
    holds(Kind::FrNir, &p.valid, &p.broken);
}

#[test]
fn es_dni_and_nie_need_their_check_letter() {
    holds(Kind::EsNif, "12345678Z", "12345678A");
    holds(Kind::EsNif, "12345678-Z", "12345678-A");
    holds(Kind::EsNie, "X1234567L", "X1234567M");
    holds(Kind::EsNie, "Y-1234567-X", "Y-1234567-Y");
}

#[test]
fn it_fiscal_code_needs_its_check_letter_and_a_real_day() {
    // The textbook example, Mario Rossi.
    holds(Kind::ItFiscalCode, "RSSMRA85T10A562S", "RSSMRA85T10A562T");
    holds(Kind::ItFiscalCode, "rssmra85t10a562s", "rssmra85t10a562t");
    // Omocodia: 0 in the place code replaced by L (and the check letter recomputed).
    let omocode = format!(
        "RSSMRA85T10A5L2{}",
        common::validated::cf_check("RSSMRA85T10A5L2")
    );
    holds(Kind::ItFiscalCode, &omocode, "RSSMRA85T10A5L2A");
    // Mixed case is not a code.
    assert!(found("RSSmra85T10A562S", Kind::ItFiscalCode).is_empty());
}

#[test]
fn nl_bsn_needs_the_11_test() {
    // Test numbers the Dutch government's own test environments use.
    holds(Kind::NlBsn, "111222333", "111222334");
    holds(Kind::NlBsn, "1112.22.333", "1112.22.334");
    assert!(found("000000000", Kind::NlBsn).is_empty());
}

#[test]
fn eu_vat_needs_the_country_check() {
    // Organisations' registration numbers as validators' documentation gives them (no
    // person's), each checked independently against its country's algorithm while this
    // test was written; ES12345678Z is the DNI specimen.
    for (good, bad) in [
        ("ATU13585627", "ATU13585628"),
        ("BE0403170701", "BE0403170702"),
        ("DE136695976", "DE136695977"),
        ("DK13585628", "DK13585629"),
        ("ESA28015865", "ESA28015866"),
        ("ES12345678Z", "ES12345678A"),
        ("FI20774740", "FI20774741"),
        ("FR40303265045", "FR41303265045"),
        ("IT00743110157", "IT00743110158"),
        ("NL004495445B01", "NL004495446B01"),
        ("PL5260001246", "PL5260001247"),
        ("PT501964843", "PT501964844"),
        ("SE556188840401", "SE556188840501"),
    ] {
        holds(Kind::EuVat, good, bad);
    }
    // A covered prefix in front of a word or an IBAN is not a VAT number.
    assert!(found("DEUTSCHLAND and DE89370400440532013000", Kind::EuVat).is_empty());
}

#[test]
fn passport_mrz_needs_every_check_digit() {
    // ICAO Doc 9303's specimen passport line.
    let good = "L898902C36UTO7408122F1204159ZE184226B<<<<<10";
    holds(
        Kind::PassportMrz,
        good,
        "L898902C36UTO7408122F1204159ZE184226B<<<<<11",
    );
    holds(
        Kind::PassportMrz,
        good,
        "L898902C36UTO7408123F1204159ZE184226B<<<<<10",
    );
    holds(
        Kind::PassportMrz,
        good,
        "L898902C36UTO7408122F1204158ZE184226B<<<<<10",
    );
    // Inside a longer run of MRZ characters it is not a line of its own.
    assert!(found(&format!("X{good}"), Kind::PassportMrz).is_empty());
    // A field's own check digit wrong while the composite is recomputed to match: each
    // field check is needed, not only the composite.
    for at in [9, 19, 27, 42] {
        let mut line = good.as_bytes().to_vec();
        line[at] = if line[at] == b'1' { b'2' } else { b'1' };
        let composite: Vec<u8> = [&line[0..10], &line[13..20], &line[21..43]].concat();
        let c = v::mrz_check(std::str::from_utf8(&composite).unwrap());
        line[43] = b'0' + c as u8;
        let bad = String::from_utf8(line).unwrap();
        assert!(
            found(&format!("Value {bad} on file."), Kind::PassportMrz).is_empty(),
            "field check at {at} ignored: {bad}"
        );
    }
}

#[test]
fn swift_bic_needs_a_country_and_scores_by_shape() {
    holds(Kind::SwiftBic, "QABCDEF2", "QABCQQF2");
    holds(Kind::SwiftBic, "QABCGB2LXXX", "QABCGB2LXXY");
    // An all-letter code reads like a word: 0.1, lifted by context.
    assert_eq!(found("QABCDEFF", Kind::SwiftBic), [("QABCDEFF", 100)]);
    assert_eq!(
        found("SWIFT code QABCDEFF", Kind::SwiftBic),
        [("QABCDEFF", 450)]
    );
    // Location starting 0 or 1, or with the letter O second: not a BIC.
    assert!(found("QABCDE0F QABCDEFO", Kind::SwiftBic).is_empty());
}

#[test]
fn imei_needs_luhn() {
    // The example IMEI of 3GPP TS 23.003's Luhn description, as Wikipedia gives it.
    holds(Kind::Imei, "490154203237518", "490154203237519");
    holds(Kind::Imei, "49-015420-323751-8", "49-015420-323751-9");
}

#[test]
fn mac_addresses_need_one_separator_throughout() {
    // RFC 7042's documentation range.
    holds(Kind::MacAddress, "00:00:5E:00:53:01", "00:00:5E:00-53:01");
    holds(Kind::MacAddress, "00-00-5e-00-53-01", "00-00-5e:00-53-01");
    holds(Kind::MacAddress, "0000.5e00.5301", "0000.5e00:5301");
    assert!(found("ff:ff:ff:ff:ff:ff and 00:00:00:00:00:00", Kind::MacAddress).is_empty());
    // An IPv6 address is not a MAC address.
    assert!(found("2001:db8::1:2:3:4", Kind::MacAddress).is_empty());
}

#[test]
fn crypto_needs_its_checksum() {
    // The Bitcoin wiki's example addresses, and BIP 173 and BIP 350 test vectors.
    holds(
        Kind::Crypto,
        "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
        "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3",
    );
    holds(
        Kind::Crypto,
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLz",
    );
    holds(
        Kind::Crypto,
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
    );
    holds(
        Kind::Crypto,
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj2",
    );
}

const HELD_OUT: usize = 300;

/// The kind's context word, for half of the held-out sentences.
fn context(kind: Kind) -> &'static str {
    match kind {
        Kind::UsItin => "ITIN",
        Kind::UsEin => "EIN",
        Kind::AbaRouting => "routing number",
        Kind::CaSin => "SIN",
        Kind::UkNhs => "NHS no.",
        Kind::AuTfn => "tax file number",
        Kind::AuMedicare => "Medicare",
        Kind::NlBsn => "BSN",
        Kind::SwiftBic => "BIC",
        Kind::Imei => "IMEI",
        Kind::MacAddress => "MAC",
        _ => "identifier",
    }
}

fn generate(kind: Kind, r: &mut Rng) -> Pair {
    match kind {
        Kind::UsItin => v::itin(r),
        Kind::UsEin => v::ein(r),
        Kind::AbaRouting => v::aba(r),
        Kind::CaSin => v::ca_sin(r),
        Kind::UkNhs => v::uk_nhs(r),
        Kind::AuTfn => v::au_tfn(r),
        Kind::AuMedicare => v::au_medicare(r),
        Kind::DeTaxId => v::de_tax_id(r),
        Kind::FrNir => v::fr_nir(r),
        Kind::EsNif => v::es_nif(r),
        Kind::EsNie => v::es_nie(r),
        Kind::ItFiscalCode => v::it_fiscal_code(r),
        Kind::NlBsn => v::nl_bsn(r),
        Kind::EuVat => v::eu_vat(r),
        Kind::PassportMrz => v::passport_mrz(r),
        Kind::SwiftBic => v::swift_bic(r),
        Kind::Imei => v::imei(r),
        Kind::MacAddress => v::mac(r),
        Kind::Crypto => v::crypto(r),
        other => panic!("{} is not an ML-08C kind", other.label()),
    }
}

/// The held-out measure: for each `ML-08C` kind, `HELD_OUT` valid values in sentences
/// (half with a context word) and the same values with their check broken. Detection
/// counts a span of the kind at exactly the value; a false positive is a span of the
/// kind on a broken value. Gate: 95% detected and no false positive.
#[test]
fn held_out_detection_and_false_positive_rates() {
    // A different seed from the synthetic set of `tests/synthetic.rs`.
    let mut r = Rng(0x0D0C_2026_1112_08C0);
    let options = Options::default();
    let mut rows = Vec::new();
    let mut notes = Vec::new();
    for kind in Kind::ALL.into_iter().skip(10) {
        let (mut detected, mut false_pos, mut displayed) = (0usize, 0usize, 0usize);
        for i in 0..HELD_OUT {
            let p = generate(kind, &mut r);
            assert_ne!(
                p.valid,
                p.broken,
                "{}: mutation took no effect",
                kind.label()
            );
            let prefix = if i % 2 == 0 {
                format!("The {} is ", context(kind))
            } else {
                "Reference ".to_string()
            };
            let text = format!("{prefix}{} for this agreement.", p.valid);
            let at = prefix.len();
            let hit = detect(&text, &options)
                .unwrap()
                .spans
                .into_iter()
                .find(|s| s.kind == kind && s.start == at && s.end == at + p.valid.len());
            match hit {
                Some(s) => {
                    detected += 1;
                    if s.score >= 500 {
                        displayed += 1;
                    }
                }
                None if notes.len() < 20 => notes.push(format!("missed {}: {text}", kind.label())),
                None => {}
            }
            let text = format!("{prefix}{} for this agreement.", p.broken);
            let bad = detect(&text, &options)
                .unwrap()
                .spans
                .into_iter()
                .filter(|s| s.kind == kind)
                .count();
            if bad > 0 {
                false_pos += 1;
                if notes.len() < 20 {
                    notes.push(format!("false+ {}: {text}", kind.label()));
                }
            }
        }
        rows.push((kind, detected, displayed, false_pos));
    }
    println!(
        "kind                detected/{HELD_OUT}   rate   score>=500   false+ on broken check"
    );
    for (kind, detected, displayed, fp) in &rows {
        println!(
            "{:<19} {:>9}   {:>5.1}%   {:>9}   {:>3} ({:.1}%)",
            kind.label(),
            detected,
            100.0 * *detected as f64 / HELD_OUT as f64,
            displayed,
            fp,
            100.0 * *fp as f64 / HELD_OUT as f64
        );
    }
    for n in &notes {
        println!("{n}");
    }
    for (kind, detected, _, fp) in rows {
        assert!(
            detected * 100 >= HELD_OUT * 95,
            "{} detected {detected}/{HELD_OUT}",
            kind.label()
        );
        assert_eq!(fp, 0, "{} false positives on broken checks", kind.label());
    }
}

/// The cost of a weak check, measured: bare random digit strings of 8 to 16 digits
/// (order and invoice numbers) and random upper-case 8- and 11-letter tokens, none of
/// them personal data. A single check digit passes about one random number in ten, so
/// the weak kinds find some at 0.4; the table shows each kind's rate. Gate: the kinds
/// scored 0.5 or more, other than card and Aadhaar (unchanged by `ML-08C`), together
/// find fewer than 1% of the tokens.
#[test]
fn random_numbers_and_tokens_are_rarely_identifiers() {
    const N: usize = 2_000;
    let mut r = Rng(0x0D0C_2026_1112_08C1);
    let options = Options::default();
    let mut any = std::collections::BTreeMap::<&str, usize>::new();
    let mut shown = std::collections::BTreeMap::<&str, usize>::new();
    for i in 0..N {
        let token = if i % 4 == 3 {
            let len = if r.below(2) == 0 { 8 } else { 11 };
            (0..len).map(|_| r.upper()).collect::<String>()
        } else {
            let len = 8 + r.below(9) as usize;
            format!("{}{}", r.range(1, 9), r.digits(len - 1))
        };
        let text = format!("Order {token} shipped.");
        for s in detect(&text, &options).unwrap().spans {
            *any.entry(s.kind.label()).or_default() += 1;
            if s.score >= 500 {
                *shown.entry(s.kind.label()).or_default() += 1;
            }
        }
    }
    println!("kind                 found in {N} random tokens: any score / score>=500");
    for (label, n) in &any {
        println!(
            "{label:<20} {n:>5} ({:.2}%) / {}",
            100.0 * *n as f64 / N as f64,
            shown.get(label).unwrap_or(&0)
        );
    }
    let strong: usize = shown
        .iter()
        .filter(|(l, _)| !["CREDIT_CARD", "IN_AADHAAR"].contains(l))
        .map(|(_, n)| n)
        .sum();
    assert!(strong * 100 < N, "kinds at 0.5 or more over 1%: {shown:?}");
}
