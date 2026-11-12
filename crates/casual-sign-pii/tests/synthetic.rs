//! ML-08's acceptance measure for the deterministic layer: the detection rate per kind
//! on a synthetic personal-data set, and false positives on synthetic text that holds
//! none. Run with `--nocapture` to see the table. Every value is synthetic (see
//! `common`), generated from a fixed seed, so the set and the rates are reproducible.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use casual_sign_pii::{Kind, Options, detect};
use common::validated::{self as v, Pair};
use common::*;

/// The `ML-08C` generator for `kind`.
pub fn validated_value(kind: Kind, r: &mut Rng) -> Pair {
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
        other => panic!("{} has no ML-08C generator", other.label()),
    }
}

const PER_KIND: usize = 200;

/// The text around a value: half the samples carry the kind's context word, half not.
fn sentence(kind: Kind, value: &str, with_context: bool) -> (String, usize) {
    let prefix = match (kind, with_context) {
        (Kind::EmailAddress, true) => "Signer email: ",
        (Kind::PhoneNumber, true) => "Phone: ",
        (Kind::Iban, true) => "Pay to IBAN ",
        (Kind::PaymentCard, true) => "Card number: ",
        (Kind::UsSsn, true) => "SSN: ",
        (Kind::UkNino, true) => "National Insurance number ",
        (Kind::InPan, true) => "PAN: ",
        (Kind::InAadhaar, true) => "Aadhaar no. ",
        (Kind::IpAddress, true) => "Signed from IP ",
        (Kind::UsItin, true) => "ITIN: ",
        (Kind::UsEin, true) => "Employer Identification Number ",
        (Kind::AbaRouting, true) => "ABA routing number ",
        (Kind::CaSin, true) => "Social Insurance Number ",
        (Kind::UkNhs, true) => "NHS number ",
        (Kind::AuTfn, true) => "TFN ",
        (Kind::AuMedicare, true) => "Medicare card ",
        (Kind::DeTaxId, true) => "Steuer-ID ",
        (Kind::FrNir, true) => "numéro de sécurité sociale ",
        (Kind::EsNif, true) => "DNI ",
        (Kind::EsNie, true) => "NIE ",
        (Kind::ItFiscalCode, true) => "codice fiscale ",
        (Kind::NlBsn, true) => "BSN ",
        (Kind::EuVat, true) => "VAT number ",
        (Kind::PassportMrz, true) => "Passport MRZ:\n",
        (Kind::SwiftBic, true) => "SWIFT code ",
        (Kind::Imei, true) => "Device IMEI ",
        (Kind::MacAddress, true) => "MAC address ",
        (Kind::Crypto, true) => "Bitcoin address ",
        (Kind::DateOfBirth, _) => [
            "Date of birth: ",
            "The tenant was born on ",
            "DOB ",
            "Birthday: ",
        ][value.len() % 4],
        _ => "The reference ",
    };
    let text = format!("{prefix}{value} is recorded in the file.");
    (text, prefix.len())
}

fn value(kind: Kind, r: &mut Rng) -> String {
    match kind {
        Kind::EmailAddress => email(r),
        Kind::PhoneNumber => phone(r),
        Kind::Iban => iban(r),
        Kind::PaymentCard => card(r),
        Kind::UsSsn => ssn(r),
        Kind::UkNino => nino(r),
        Kind::InPan => pan(r),
        Kind::InAadhaar => aadhaar(r),
        Kind::IpAddress => ip(r),
        Kind::DateOfBirth => date(r),
        other => validated_value(other, r).valid,
    }
}

/// Synthetic text that holds no personal data, and the kinds a span in it would be a
/// false positive for (every kind).
fn negatives(r: &mut Rng) -> Vec<String> {
    let mut out: Vec<String> = [
        "This Agreement is made on March 3, 2024 between the Landlord and the Tenant.",
        "The Effective Date is 12/03/2024 and the term is 24 months.",
        "The fee is USD 12,500.00, payable within 30 days of 01.04.2025.",
        "Section 4.2.1 applies; see clause 17(b) and Schedule 3.",
        "The meeting is at 10:30 on 2024-06-01 in room 101.",
        "Version 2.3 of the form, revision 7, page 3 of 12.",
        "Total: 1,234,567 units shipped under order 2024-0042.",
        "Send it by email to the address on file; call us during business hours.",
        "Card holder agreement, terms of the credit facility, section 9.",
        "The national insurance contributions are covered in Part 2.",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for _ in 0..50 {
        // A 16-digit number that fails Luhn.
        let c = card_compact(r);
        let last = c.chars().last().unwrap().to_digit(10).unwrap();
        let bad = format!("{}{}", &c[..c.len() - 1], (last + 1) % 10);
        out.push(format!("Invoice {bad} is due."));
        // An IBAN with wrong check digits.
        let i = iban_compact(r);
        let check: u32 = i[2..4].parse().unwrap();
        let wrong = format!("{}{:02}{}", &i[..2], (check + 1) % 97 + 2, &i[4..]);
        out.push(format!("Account {} on record.", group4(&wrong, " ")));
        // Twelve digits that fail Verhoeff.
        let a = aadhaar_compact(r);
        let d = a.chars().last().unwrap().to_digit(10).unwrap();
        out.push(format!("Order {}{} shipped.", &a[..11], (d + 1) % 10));
        // A date with no birth context.
        out.push(format!("Signed on {}.", date(r)));
        // ML-08C: each validated identifier with its check broken.
        for kind in Kind::ALL.into_iter().skip(10) {
            out.push(format!(
                "Reference {} applies.",
                validated_value(kind, r).broken
            ));
        }
    }
    out.push("THIS AGREEMENT between the LANDLORD and the TENANT covers the PROPERTY.".into());
    out.push("WHEREAS the PURCHASER and the GUARANTOR agree; NOTWITHSTANDING clause 4.".into());
    out
}

#[test]
fn detection_rate_per_kind_on_the_synthetic_set() {
    let mut r = Rng(0x5EA1_2026_1112_0001);
    let options = Options::default();
    let mut rows = Vec::new();
    let mut failed = Vec::new();
    for kind in Kind::ALL {
        let mut found = 0;
        for i in 0..PER_KIND {
            let v = value(kind, &mut r);
            let (text, at) = sentence(kind, &v, i % 2 == 0);
            let spans = detect(&text, &options).unwrap().spans;
            if spans
                .iter()
                .any(|s| s.kind == kind && s.start == at && s.end == at + v.len())
            {
                found += 1;
            } else if failed
                .iter()
                .filter(|f: &&String| f.starts_with(kind.label()))
                .count()
                < 3
            {
                failed.push(format!("{}: {text}", kind.label()));
            }
        }
        rows.push((kind, found));
    }
    let negatives = negatives(&mut r);
    let mut fp_any = std::collections::BTreeMap::new();
    let mut fp_500 = std::collections::BTreeMap::new();
    let mut fp_examples: Vec<String> = Vec::new();
    for text in &negatives {
        for s in detect(text, &options).unwrap().spans {
            *fp_any.entry(s.kind).or_insert(0) += 1;
            if s.score >= 500 {
                *fp_500.entry(s.kind).or_insert(0) += 1;
            }
            if fp_examples
                .iter()
                .filter(|f| f.starts_with(s.kind.label()))
                .count()
                < 3
            {
                fp_examples.push(format!("{} {}: {text}", s.kind.label(), s.score));
            }
        }
    }
    println!(
        "kind             detected/{PER_KIND}  rate    false+ (any / score>=500, {} negative texts)",
        negatives.len()
    );
    for (kind, found) in &rows {
        println!(
            "{:<16} {:>9}      {:>5.1}%  {} / {}",
            kind.label(),
            found,
            100.0 * *found as f64 / PER_KIND as f64,
            fp_any.get(kind).unwrap_or(&0),
            fp_500.get(kind).unwrap_or(&0)
        );
    }
    for f in &failed {
        println!("missed  {f}");
    }
    for f in &fp_examples {
        println!("false+  {f}");
    }
    // The gate: every kind at 95% or better on its synthetic set.
    for (kind, found) in rows {
        assert!(
            found * 100 >= PER_KIND * 95,
            "{} detected {found}/{PER_KIND}",
            kind.label()
        );
    }
    // And no false positive at a score of 0.5 or more on text holding no personal data.
    assert!(
        fp_500.is_empty(),
        "false positives at score >= 500: {fp_500:?}"
    );
}
