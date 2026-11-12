//! Validated identifiers (`ML-08C`, owner instruction 33): national, tax, bank,
//! travel-document, device and crypto-currency identifiers, each found by a pattern
//! and kept only when its check digits or its structural rules hold. Written from each
//! identifier's published specification (named on each function), not ported.
//!
//! Scoring follows one rule. A check that random strings of the same shape pass less
//! than about one time in a hundred (two check digits, a check letter, a check plus a
//! structural rule, a cryptographic checksum, or a country prefix plus a check) gives
//! [`MAX_SCORE`]. A single check digit over a bare string of nine to fifteen digits
//! (one in ten or eleven random numbers passes) gives [`WEAK`], below the 0.5 most
//! callers display, and a context word lifts it to 0.75. A rule with no check digit at
//! all (ITIN, EIN, SWIFT/BIC, MAC) keeps a pattern score, as Presidio's do.

use std::sync::LazyLock;

use regex::Regex;

use crate::checksum::{self, digit};
use crate::coin;
use crate::mrz;
use crate::recognise::{
    after, before, continues_group, digits_of, each, in_mrz, is_word, scored, word_bounded,
};
use crate::vat;
use crate::{Kind, MAX_SCORE, Scan};

/// The score of a single check digit over a bare digit string (see the module docs).
pub(crate) const WEAK: u16 = 400;

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
    ITIN = r"(?-u)\b9[0-9]{2}[- ]?(?:5[0-9]|6[0-5]|7[0-9]|8[0-8]|9[0-2]|9[4-9])[- ]?[0-9]{4}\b";
    EIN = r"(?-u)\b[0-9]{2}-[0-9]{7}\b";
    ABA1 = r"(?-u)\b[0-9]{9}\b";
    ABA2 = r"(?-u)\b[0-9]{4}-[0-9]{4}-[0-9]\b";
    SIN = r"(?-u)\b[0-79][0-9]{2}[- ]?[0-9]{3}[- ]?[0-9]{3}\b";
    NHS = r"(?-u)\b[0-9]{3}[- ]?[0-9]{3}[- ]?[0-9]{4}\b";
    TFN = r"(?-u)\b[0-9]{3} ?[0-9]{3} ?[0-9]{2,3}\b";
    MEDICARE = r"(?-u)\b[2-6][0-9]{3} ?[0-9]{5} ?[0-9]\b";
    DE_TAX = r"(?-u)\b[1-9][0-9] ?[0-9]{3} ?[0-9]{3} ?[0-9]{3}\b";
    NIR = r"(?-u)\b[1-478] ?[0-9]{2} ?(?:0[1-9]|1[0-2]|[2-9][0-9]) ?(?:[0-9]{2}|2[AB]) ?[0-9]{3} ?[0-9]{3} ?[0-9]{2}\b";
    DNI = r"(?-u)\b[0-9]{8}-?[A-Z]\b";
    NIE = r"(?-u)\b[XYZ]-?[0-9]{7}-?[A-Z]\b";
    FISCAL = r"(?i-u)\b[A-Z]{6}[0-9LMNPQRSTUV]{2}[ABCDEHLMPRST][0-9LMNPQRSTUV]{2}[A-Z][0-9LMNPQRSTUV]{3}[A-Z]\b";
    BSN1 = r"(?-u)\b[0-9]{9}\b";
    BSN2 = r"(?-u)\b[0-9]{4}\.[0-9]{2}\.[0-9]{3}\b";
    VAT = r"(?-u)\b(?:AT|BE|DE|DK|ES|FI|FR|IT|NL|PL|PT|SE) ?[0-9A-Z]{8,12}\b";
    MRZ = r"(?-u)[A-Z0-9<]{9}[0-9][A-Z<]{3}[0-9]{7}[MFX<][0-9]{7}[A-Z0-9<]{14}[0-9<][0-9]";
    BIC = r"(?-u)\b[A-Z]{6}[A-Z2-9][A-NP-Z0-9](?:[A-Z0-9]{3})?\b";
    IMEI = r"(?-u)\b[0-9]{2}[- ]?[0-9]{6}[- ]?[0-9]{6}[- ]?[0-9]\b";
    MAC1 = r"(?i-u)\b[0-9a-f]{2}[:-][0-9a-f]{2}(?:[:-][0-9a-f]{2}){4}\b";
    MAC2 = r"(?i-u)\b[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\b";
    BTC58 = r"(?-u)\b[13][1-9A-HJ-NP-Za-km-z]{25,34}\b";
    BECH32 = r"(?i-u)\bbc1[02-9ac-hj-np-z]{11,87}\b";
}

const ITIN_CONTEXT: &[&str] = &[
    "itin",
    "individual taxpayer",
    "taxpayer identification",
    "tin",
];
const EIN_CONTEXT: &[&str] = &["ein", "fein", "employer identification", "tax id", "tin"];
const ABA_CONTEXT: &[&str] = &["aba", "routing", "rtn", "transit"];
const SIN_CONTEXT: &[&str] = &["sin", "social insurance", "nas"];
const NHS_CONTEXT: &[&str] = &["nhs", "health service", "health and care"];
const TFN_CONTEXT: &[&str] = &["tfn", "tax file"];
const MEDICARE_CONTEXT: &[&str] = &["medicare"];
const BSN_CONTEXT: &[&str] = &[
    "bsn",
    "burgerservicenummer",
    "sofinummer",
    "citizen service number",
];
const BIC_CONTEXT: &[&str] = &["swift", "bic", "bank", "bic code", "swift code"];
const IMEI_CONTEXT: &[&str] = &["imei", "device", "handset"];
const MAC_CONTEXT: &[&str] = &["mac", "hardware address", "ethernet", "wifi", "wi fi"];

/// Every validated-identifier recogniser, in a fixed order.
pub(crate) fn run_all(scan: &mut Scan<'_>) {
    itin(scan);
    ein(scan);
    aba(scan);
    ca_sin(scan);
    uk_nhs(scan);
    au_tfn(scan);
    au_medicare(scan);
    de_tax_id(scan);
    fr_nir(scan);
    es_nif_nie(scan);
    it_fiscal_code(scan);
    nl_bsn(scan);
    eu_vat(scan);
    passport_mrz(scan);
    swift_bic(scan);
    imei(scan);
    mac(scan);
    crypto(scan);
}

/// At most one kind of separator in `found`, used everywhere or nowhere: `seps` is the
/// count a fully separated form has ("123-456-789" or "123456789", not "123-456789").
fn uniform(found: &str, seps: usize) -> bool {
    let mut kind = None;
    let mut n = 0usize;
    for b in found.bytes().filter(|b| !b.is_ascii_alphanumeric()) {
        if kind.is_some_and(|k| k != b) {
            return false;
        }
        kind = Some(b);
        n = n.saturating_add(1);
    }
    n == 0 || n == seps
}

/// A digit identifier standing on its own: Unicode word boundaries, not the tail of a
/// grouped number or IBAN (a group of two or more digits and a separator before it),
/// not the head of one (a separator and a digit after it), not a national number after
/// an international prefix ("+1 415 555 0123"), and not a field of an MRZ line.
fn isolated(text: &str, start: usize, end: usize) -> bool {
    if !word_bounded(text, start, end) || continues_group(text, start) || in_mrz(text, start, end) {
        return false;
    }
    let tail = text.get(end..).unwrap_or("").as_bytes();
    if let [b' ' | b'-' | b'.', d, ..] = tail
        && d.is_ascii_digit()
    {
        return false;
    }
    let head = text.get(..start).unwrap_or("").as_bytes();
    if let [before_sep @ .., b' ' | b'-' | b'.'] = head {
        let group = before_sep
            .iter()
            .rev()
            .take_while(|b| b.is_ascii_digit())
            .count();
        let lead = before_sep
            .len()
            .checked_sub(group)
            .and_then(|i| i.checked_sub(1))
            .and_then(|i| before_sep.get(i));
        // After "+44 " it is a national number; after a group of two or more digits it
        // is the tail of a longer number (a lone digit is a row number or a quantity).
        if (group > 0 && lead == Some(&b'+')) || group >= 2 {
            return false;
        }
    }
    true
}

/// Runs `check` on each isolated match of `re` with uniform separators, and pushes a
/// span scored `base` (raised by `context`) when it holds.
fn digits_kind(
    scan: &mut Scan<'_>,
    kind: Kind,
    re: &LazyLock<Option<Regex>>,
    seps: usize,
    base: u16,
    context: &[&str],
    check: impl Fn(&[u8]) -> bool,
) {
    each(scan, kind, re, |scan, start, end| {
        let text = scan.text;
        let Some(found) = text.get(start..end) else {
            return;
        };
        if !isolated(text, start, end) || !uniform(found, seps) {
            return;
        }
        if check(&digits_of(found)) {
            let score = scored(scan, start, base, context);
            scan.push(start, end, kind, score);
        }
    });
}

/// US Individual Taxpayer Identification Number (IRS): 9XX-XX-XXXX with the middle
/// group in 50–65, 70–88, 90–92 or 94–99. No check digit: 0.5 when separated, 0.3
/// when written as nine bare digits.
fn itin(scan: &mut Scan<'_>) {
    each(scan, Kind::UsItin, &ITIN, |scan, start, end| {
        let text = scan.text;
        let Some(found) = text.get(start..end) else {
            return;
        };
        if !isolated(text, start, end) || !uniform(found, 2) {
            return;
        }
        let base = if found.len() == 9 { 300 } else { 500 };
        let score = scored(scan, start, base, ITIN_CONTEXT);
        scan.push(start, end, Kind::UsItin, score);
    });
}

/// US Employer Identification Number (IRS): NN-NNNNNNN with a prefix the IRS assigns
/// (its published campus prefix list). No check digit: 0.3.
fn ein(scan: &mut Scan<'_>) {
    each(scan, Kind::UsEin, &EIN, |scan, start, end| {
        let text = scan.text;
        let Some(found) = text.get(start..end) else {
            return;
        };
        let prefix = found
            .get(..2)
            .and_then(|p| p.parse::<u8>().ok())
            .unwrap_or(0);
        let assigned = matches!(
            prefix,
            1..=6 | 10..=16 | 20..=27 | 30..=48 | 50..=68 | 71..=77 | 80..=88 | 90..=95 | 98 | 99
        );
        if assigned && isolated(text, start, end) {
            let score = scored(scan, start, 300, EIN_CONTEXT);
            scan.push(start, end, Kind::UsEin, score);
        }
    });
}

/// ABA routing number: a Federal Reserve prefix (00–12, 21–32, 61–72, 80) and the
/// 3-7-1 check.
fn aba(scan: &mut Scan<'_>) {
    let check = |d: &[u8]| {
        let prefix = d.get(..2).and_then(checksum::value).unwrap_or(99);
        matches!(prefix, 0..=12 | 21..=32 | 61..=72 | 80) && checksum::aba(d)
    };
    digits_kind(scan, Kind::AbaRouting, &ABA1, 0, WEAK, ABA_CONTEXT, check);
    digits_kind(scan, Kind::AbaRouting, &ABA2, 2, WEAK, ABA_CONTEXT, check);
}

/// Canadian Social Insurance Number (Employment and Social Development Canada): nine
/// digits, first not 8 (business numbers; 0 is unassigned but is the first digit of
/// the government's own specimen, 046 454 286), Luhn.
fn ca_sin(scan: &mut Scan<'_>) {
    digits_kind(scan, Kind::CaSin, &SIN, 2, WEAK, SIN_CONTEXT, |d| {
        d.len() == 9 && checksum::luhn(d)
    });
}

/// UK NHS number: ten digits, mod-11 check.
fn uk_nhs(scan: &mut Scan<'_>) {
    digits_kind(scan, Kind::UkNhs, &NHS, 2, WEAK, NHS_CONTEXT, checksum::nhs);
}

/// Australian Tax File Number (ATO): nine digits with weights 1, 4, 3, 7, 5, 8, 6, 9,
/// 10, or the older eight with 10, 7, 8, 4, 6, 3, 5, 1, summing to a multiple of 11.
fn au_tfn(scan: &mut Scan<'_>) {
    digits_kind(scan, Kind::AuTfn, &TFN, 2, WEAK, TFN_CONTEXT, |d| {
        match d.len() {
            9 => checksum::weighted_zero(d, &[1, 4, 3, 7, 5, 8, 6, 9, 10], 11),
            8 => checksum::weighted_zero(d, &[10, 7, 8, 4, 6, 3, 5, 1], 11),
            _ => false,
        }
    });
}

/// Australian Medicare card number: ten digits starting 2 to 6, check digit ninth.
/// The optional eleventh digit (the person's position on the card) is not matched.
fn au_medicare(scan: &mut Scan<'_>) {
    digits_kind(
        scan,
        Kind::AuMedicare,
        &MEDICARE,
        2,
        WEAK,
        MEDICARE_CONTEXT,
        checksum::medicare,
    );
}

/// German tax identification number (Steuer-ID, BZSt): eleven digits, the first not 0;
/// in the first ten exactly one digit appears twice or three times (never three in a
/// row) and every other at most once; ISO 7064 MOD 11,10 check.
fn de_tax_id(scan: &mut Scan<'_>) {
    digits_kind(scan, Kind::DeTaxId, &DE_TAX, 3, MAX_SCORE, &[], steuer_id);
}

pub(crate) fn steuer_id(d: &[u8]) -> bool {
    let Some(body) = d.get(..10) else {
        return false;
    };
    if d.len() != 11 || d.first() == Some(&b'0') {
        return false;
    }
    let mut counts = [0u8; 10];
    for &b in body {
        let Some(c) = digit(b).and_then(|v| counts.get_mut(v as usize)) else {
            return false;
        };
        *c = c.saturating_add(1);
    }
    let repeated: Vec<u8> = counts.iter().copied().filter(|&c| c > 1).collect();
    if !matches!(repeated.as_slice(), [2] | [3]) {
        return false;
    }
    let triple_run = body
        .windows(3)
        .any(|w| w.first() == w.get(1) && w.get(1) == w.get(2));
    !triple_run && checksum::iso7064_mod11_10(d)
}

/// French social security number (NIR, INSEE): sex, year, month, department (2A and 2B
/// for Corsica, read as 19 and 18), commune and order number, then a two-digit key of
/// 97 minus the thirteen-digit number mod 97.
fn fr_nir(scan: &mut Scan<'_>) {
    each(scan, Kind::FrNir, &NIR, |scan, start, end| {
        let text = scan.text;
        let Some(found) = text.get(start..end) else {
            return;
        };
        if !isolated(text, start, end) {
            return;
        }
        let compact: Vec<u8> = found.bytes().filter(|b| *b != b' ').collect();
        if nir(&compact) {
            scan.push(start, end, Kind::FrNir, MAX_SCORE);
        }
    });
}

pub(crate) fn nir(compact: &[u8]) -> bool {
    if compact.len() != 15 {
        return false;
    }
    let mut number: Vec<u8> = compact.get(..13).unwrap_or(&[]).to_vec();
    match number.get(5..7) {
        Some(b"2A") => number.splice(5..7, *b"19").for_each(drop),
        Some(b"2B") => number.splice(5..7, *b"18").for_each(drop),
        _ => {}
    }
    let (Some(n), Some(key)) = (
        checksum::value(&number),
        compact.get(13..).and_then(checksum::value),
    ) else {
        return false;
    };
    97u64.wrapping_sub(n % 97) == key
}

/// Spanish DNI (eight digits and a check letter) and NIE (X, Y or Z, seven digits and a
/// check letter), Ministerio del Interior's mod-23 letter table.
fn es_nif_nie(scan: &mut Scan<'_>) {
    for (kind, re) in [(Kind::EsNif, &DNI), (Kind::EsNie, &NIE)] {
        each(scan, kind, re, |scan, start, end| {
            let text = scan.text;
            let Some(found) = text.get(start..end) else {
                return;
            };
            if !word_bounded(text, start, end) {
                return;
            }
            let compact: Vec<u8> = found.bytes().filter(|b| *b != b'-').collect();
            let ok = match kind {
                Kind::EsNif => vat::es_nif(&compact),
                _ => vat::es_nie(&compact),
            };
            if ok {
                scan.push(start, end, kind, MAX_SCORE);
            }
        });
    }
}

/// Italian codice fiscale (Agenzia delle Entrate, DM 23/12/1976): six letters of name,
/// year, month letter, day (plus 40 for women), place code and a check letter, with
/// digits replaced by letters (omocodia) where codes collide. One case throughout.
fn it_fiscal_code(scan: &mut Scan<'_>) {
    each(scan, Kind::ItFiscalCode, &FISCAL, |scan, start, end| {
        let text = scan.text;
        let Some(found) = text.get(start..end) else {
            return;
        };
        let upper = found.bytes().all(|b| !b.is_ascii_lowercase());
        let lower = found.bytes().all(|b| !b.is_ascii_uppercase());
        if !word_bounded(text, start, end) || !(upper || lower) {
            return;
        }
        if fiscal_code(&found.to_ascii_uppercase().into_bytes()) {
            scan.push(start, end, Kind::ItFiscalCode, MAX_SCORE);
        }
    });
}

/// A digit, or the omocodia letter standing for it.
fn omocodia(b: u8) -> Option<u32> {
    digit(b).or_else(|| {
        b"LMNPQRSTUV"
            .iter()
            .position(|&l| l == b)
            .and_then(|p| u32::try_from(p).ok())
    })
}

pub(crate) fn fiscal_code(cf: &[u8]) -> bool {
    const ODD: [u32; 26] = [
        1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24,
        23,
    ];
    if cf.len() != 16 {
        return false;
    }
    let day = match (
        cf.get(9).copied().and_then(omocodia),
        cf.get(10).copied().and_then(omocodia),
    ) {
        (Some(t), Some(u)) => t.wrapping_mul(10).wrapping_add(u),
        _ => return false,
    };
    if !matches!(day, 1..=31 | 41..=71) {
        return false;
    }
    let mut sum: u32 = 0;
    for (i, &c) in cf.iter().take(15).enumerate() {
        // Digits count as the letter in the same place: 0 as A, 1 as B and so on.
        let idx = match c {
            b'0'..=b'9' => u32::from(c.wrapping_sub(b'0')),
            b'A'..=b'Z' => u32::from(c.wrapping_sub(b'A')),
            _ => return false,
        };
        let v = if i % 2 == 0 {
            ODD.get(idx as usize).copied().unwrap_or(0)
        } else {
            idx
        };
        sum = sum.wrapping_add(v);
    }
    let want = b'A'.wrapping_add(u8::try_from(sum % 26).unwrap_or(0));
    cf.get(15) == Some(&want)
}

/// Dutch citizen service number (BSN, Rijksoverheid): nine digits passing the 11-test
/// (weights 9 to 2, and -1 for the last), and not all zeros.
fn nl_bsn(scan: &mut Scan<'_>) {
    let check = |d: &[u8]| {
        d.iter().any(|&b| b != b'0')
            && checksum::weighted_zero(d, &[9, 8, 7, 6, 5, 4, 3, 2, 10], 11)
    };
    digits_kind(scan, Kind::NlBsn, &BSN1, 0, WEAK, BSN_CONTEXT, check);
    digits_kind(scan, Kind::NlBsn, &BSN2, 2, WEAK, BSN_CONTEXT, check);
}

/// EU VAT numbers with their country prefix (src/vat.rs).
fn eu_vat(scan: &mut Scan<'_>) {
    each(scan, Kind::EuVat, &VAT, |scan, start, end| {
        let text = scan.text;
        let Some(found) = text.get(start..end) else {
            return;
        };
        if !word_bounded(text, start, end) {
            return;
        }
        let compact: Vec<u8> = found.bytes().filter(|b| *b != b' ').collect();
        if vat::valid(&compact) {
            scan.push(start, end, Kind::EuVat, MAX_SCORE);
        }
    });
}

/// A passport's MRZ second line (src/mrz.rs); the line must stand alone, with no MRZ
/// character either side.
fn passport_mrz(scan: &mut Scan<'_>) {
    let mrz_char = |c: char| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '<';
    each(scan, Kind::PassportMrz, &MRZ, |scan, start, end| {
        let text = scan.text;
        if before(text, start).is_some_and(mrz_char) || after(text, end).is_some_and(mrz_char) {
            return;
        }
        let Some(found) = text.get(start..end) else {
            return;
        };
        if found.len() == mrz::LEN && mrz::td3_line2(found.as_bytes()) {
            scan.push(start, end, Kind::PassportMrz, MAX_SCORE);
        }
    });
}

/// ISO 3166-1 alpha-2 codes in use, and XK (Kosovo), which SWIFT also assigns.
const COUNTRIES: &str = "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS XK YE YT ZA ZM ZW";

/// SWIFT/BIC (ISO 9362): bank code, an ISO 3166 country, a location whose first
/// character is not 0 or 1 and whose second is not the letter O, and an optional branch
/// that starts with X only as XXX. No check digit, and an all-letter code reads like
/// an upper-case word, so all-letter codes score 0.1 and those with a digit 0.3; a
/// context word lifts them.
fn swift_bic(scan: &mut Scan<'_>) {
    each(scan, Kind::SwiftBic, &BIC, |scan, start, end| {
        let text = scan.text;
        let Some(found) = text.get(start..end) else {
            return;
        };
        if !word_bounded(text, start, end) {
            return;
        }
        let bytes = found.as_bytes();
        let country = bytes.get(4..6).and_then(|c| std::str::from_utf8(c).ok());
        let known = country.is_some_and(|c| COUNTRIES.split(' ').any(|k| k == c));
        let branch = bytes.get(8..).unwrap_or(&[]);
        if !known || (branch.first() == Some(&b'X') && branch != b"XXX") {
            return;
        }
        let base = if bytes.iter().any(u8::is_ascii_digit) {
            300
        } else {
            100
        };
        let score = scored(scan, start, base, BIC_CONTEXT);
        scan.push(start, end, Kind::SwiftBic, score);
    });
}

/// IMEI (3GPP TS 23.003): fifteen digits, Luhn.
fn imei(scan: &mut Scan<'_>) {
    digits_kind(scan, Kind::Imei, &IMEI, 3, WEAK, IMEI_CONTEXT, |d| {
        d.len() == 15 && checksum::luhn(d)
    });
}

/// MAC-48 addresses (IEEE 802): six hex pairs with one separator throughout, or
/// Cisco's three dotted groups of four. All-zero and broadcast addresses are not a
/// device's. No check digit: 0.6, as an IP address.
fn mac(scan: &mut Scan<'_>) {
    for (re, seps) in [(&MAC1, 5), (&MAC2, 2)] {
        each(scan, Kind::MacAddress, re, |scan, start, end| {
            let text = scan.text;
            let Some(found) = text.get(start..end) else {
                return;
            };
            if before(text, start).is_some_and(|c| is_word(c) || matches!(c, ':' | '-' | '.'))
                || after(text, end).is_some_and(|c| is_word(c) || matches!(c, ':' | '-'))
                || !uniform(found, seps)
            {
                return;
            }
            let hex: Vec<u8> = found
                .bytes()
                .filter(u8::is_ascii_hexdigit)
                .map(|b| b.to_ascii_lowercase())
                .collect();
            if hex.iter().all(|&b| b == b'0') || hex.iter().all(|&b| b == b'f') {
                return;
            }
            let score = scored(scan, start, 600, MAC_CONTEXT);
            scan.push(start, end, Kind::MacAddress, score);
        });
    }
}

/// Bitcoin addresses (src/coin.rs), Presidio's `CRYPTO` entity.
fn crypto(scan: &mut Scan<'_>) {
    for (re, check) in [
        (&BTC58, coin::base58check as fn(&[u8]) -> bool),
        (&BECH32, coin::segwit),
    ] {
        each(scan, Kind::Crypto, re, |scan, start, end| {
            let text = scan.text;
            let Some(found) = text.get(start..end) else {
                return;
            };
            if word_bounded(text, start, end) && check(found.as_bytes()) {
                scan.push(start, end, Kind::Crypto, MAX_SCORE);
            }
        });
    }
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
    fn separators_uniform() {
        assert!(uniform("123456789", 2));
        assert!(uniform("123-456-789", 2));
        assert!(!uniform("123-456789", 2));
        assert!(!uniform("123-456 789", 2));
    }

    #[test]
    fn steuer_id_rules() {
        assert!(steuer_id(b"86095742719"));
        // Same check rule, but no digit repeated in the first ten.
        assert!(!steuer_id(b"12345678903"));
        assert!(!steuer_id(b"86095742718"));
        assert!(!steuer_id(b"0609574271"));
    }

    #[test]
    fn nir_and_fiscal_code_known_values() {
        assert!(nir(b"255081416802538"));
        assert!(!nir(b"255081416802539"));
        assert!(fiscal_code(b"RSSMRA85T10A562S"));
        assert!(!fiscal_code(b"RSSMRA85T10A562T"));
        // Day 32 is no day, for either sex.
        assert!(!fiscal_code(b"RSSMRA85T32A562S"));
    }

    #[test]
    fn country_list_is_sorted_two_letter_codes() {
        let codes: Vec<&str> = COUNTRIES.split(' ').collect();
        assert!(codes.iter().all(|c| c.len() == 2));
        assert!(codes.windows(2).all(|w| w.first() < w.get(1)));
        assert_eq!(codes.len(), 250);
    }
}
