//! Generators for the validated identifiers of `ML-08C`. Each returns a valid value and
//! the same value with its check broken (a different check digit, letter or checksum
//! character), so a test can show the check is what decides. Check digits are computed
//! here from the published algorithms, written separately from the crate's validators.
//! Every value is synthetic: random digits with a valid check, documentation ranges
//! (RFC 7042 MAC addresses), and invented bank codes.
// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use super::{Rng, luhn_digit};
use sha2::{Digest, Sha256};

/// A valid value and the same value with its check broken.
#[derive(Debug)]
pub struct Pair {
    pub valid: String,
    pub broken: String,
}

fn d(c: u8) -> u32 {
    u32::from(c - b'0')
}

fn other_digit(r: &mut Rng, c: char) -> char {
    loop {
        let x = r.digit();
        if x != c {
            return x;
        }
    }
}

fn other_upper(r: &mut Rng, c: char) -> char {
    loop {
        let x = r.upper();
        if x != c {
            return x;
        }
    }
}

/// Replaces the character at `at` (a byte index of an ASCII string) with `c`.
fn swap(s: &str, at: usize, c: char) -> String {
    let mut b = s.as_bytes().to_vec();
    b[at] = c as u8;
    String::from_utf8(b).unwrap()
}

fn break_last_digit(r: &mut Rng, s: &str) -> String {
    let at = s.rfind(|c: char| c.is_ascii_digit()).unwrap();
    let c = s.as_bytes()[at] as char;
    swap(s, at, other_digit(r, c))
}

/// Groups `s` by the given widths with `sep`.
pub fn grouped(s: &str, widths: &[usize], sep: &str) -> String {
    let mut out = Vec::new();
    let mut at = 0;
    for w in widths {
        out.push(&s[at..at + w]);
        at += w;
    }
    out.join(sep)
}

pub fn itin(r: &mut Rng) -> Pair {
    let groups: Vec<u64> = (50..=65)
        .chain(70..=88)
        .chain(90..=92)
        .chain(94..=99)
        .collect();
    let g = *r.pick(&groups);
    let raw = format!("9{}{g}{}", r.digits(2), r.digits(4));
    let valid = if r.below(2) == 0 {
        grouped(&raw, &[3, 2, 4], "-")
    } else {
        raw.clone()
    };
    // No check digit: broken is a middle group the IRS never issues.
    let bad = *r.pick(&[0u64, 12, 30, 45, 66, 69, 89, 93]);
    let broken = grouped(
        &format!("{}{bad:02}{}", &raw[..3], &raw[5..]),
        &[3, 2, 4],
        "-",
    );
    Pair { valid, broken }
}

pub fn ein(r: &mut Rng) -> Pair {
    let prefixes: Vec<u64> = (1..=6)
        .chain(10..=16)
        .chain(20..=27)
        .chain(30..=48)
        .chain(50..=68)
        .chain(71..=77)
        .chain(80..=88)
        .chain(90..=95)
        .chain([98, 99])
        .collect();
    let body = r.digits(7);
    let p = *r.pick(&prefixes);
    // No check digit: broken is a prefix the IRS never assigns.
    let bad = *r.pick(&[
        0u64, 7, 8, 9, 17, 18, 19, 28, 29, 49, 69, 70, 78, 79, 89, 96, 97,
    ]);
    Pair {
        valid: format!("{p:02}-{body}"),
        broken: format!("{bad:02}-{body}"),
    }
}

fn aba_check(body: &str) -> char {
    let w = [3, 7, 1, 3, 7, 1, 3, 7];
    let s: u32 = body.bytes().zip(w).map(|(b, w)| d(b) * w).sum();
    char::from_digit((10 - s % 10) % 10, 10).unwrap()
}

pub fn aba(r: &mut Rng) -> Pair {
    let prefixes: Vec<u64> = (1..=12).chain(21..=32).chain(61..=72).chain([80]).collect();
    let body = format!("{:02}{}", r.pick(&prefixes), r.digits(6));
    let valid = format!("{body}{}", aba_check(&body));
    let broken = break_last_digit(r, &valid);
    if r.below(3) == 0 {
        return Pair {
            valid: grouped(&valid, &[4, 4, 1], "-"),
            broken: grouped(&broken, &[4, 4, 1], "-"),
        };
    }
    Pair { valid, broken }
}

fn sep_style(r: &mut Rng) -> &'static str {
    r.pick(&["", " ", "-"])
}

pub fn ca_sin(r: &mut Rng) -> Pair {
    let first = *r.pick(&['1', '2', '3', '4', '5', '6', '7', '9']);
    let body = format!("{first}{}", r.digits(7));
    let v = format!("{body}{}", luhn_digit(&body));
    let b = break_last_digit(r, &v);
    let sep = sep_style(r);
    Pair {
        valid: grouped(&v, &[3, 3, 3], sep),
        broken: grouped(&b, &[3, 3, 3], sep),
    }
}

pub fn uk_nhs(r: &mut Rng) -> Pair {
    loop {
        let body = format!("{}{}", r.range(4, 7), r.digits(8));
        let s: u32 = body
            .bytes()
            .enumerate()
            .map(|(i, b)| d(b) * (10 - i as u32))
            .sum();
        let c = match 11 - s % 11 {
            11 => 0,
            10 => continue,
            c => c,
        };
        let v = format!("{body}{c}");
        let b = break_last_digit(r, &v);
        let sep = sep_style(r);
        return Pair {
            valid: grouped(&v, &[3, 3, 4], sep),
            broken: grouped(&b, &[3, 3, 4], sep),
        };
    }
}

pub fn au_tfn(r: &mut Rng) -> Pair {
    loop {
        let body = r.digits(8);
        let w = [1, 4, 3, 7, 5, 8, 6, 9];
        let s: u32 = body.bytes().zip(w).map(|(b, w)| d(b) * w).sum();
        // The last weight is 10, which is -1 mod 11: the check is the sum mod 11.
        let c = s % 11;
        if c == 10 {
            continue;
        }
        let v = format!("{body}{c}");
        let b = break_last_digit(r, &v);
        let sep = *r.pick(&["", " "]);
        return Pair {
            valid: grouped(&v, &[3, 3, 3], sep),
            broken: grouped(&b, &[3, 3, 3], sep),
        };
    }
}

pub fn au_medicare(r: &mut Rng) -> Pair {
    let body = format!("{}{}", r.range(2, 6), r.digits(7));
    let w = [1, 3, 7, 9, 1, 3, 7, 9];
    let s: u32 = body.bytes().zip(w).map(|(b, w)| d(b) * w).sum();
    let issue = r.range(1, 9);
    let v = format!("{body}{}{issue}", s % 10);
    let c = v.as_bytes()[8] as char;
    let b = swap(&v, 8, other_digit(r, c));
    let sep = *r.pick(&["", " "]);
    Pair {
        valid: grouped(&v, &[4, 5, 1], sep),
        broken: grouped(&b, &[4, 5, 1], sep),
    }
}

fn mod11_10_check(body: &str) -> u32 {
    let mut p = 10;
    for b in body.bytes() {
        let mut s = (d(b) + p) % 10;
        if s == 0 {
            s = 10;
        }
        p = s * 2 % 11;
    }
    match 11 - p {
        10 => 0,
        c => c,
    }
}

pub fn de_tax_id(r: &mut Rng) -> Pair {
    let body = loop {
        let body = format!("{}{}", r.range(1, 9), r.digits(9));
        let mut counts = [0; 10];
        for b in body.bytes() {
            counts[d(b) as usize] += 1;
        }
        let rep: Vec<_> = counts.iter().filter(|&&c| c > 1).collect();
        let triple_run = body
            .as_bytes()
            .windows(3)
            .any(|w| w[0] == w[1] && w[1] == w[2]);
        if (rep == [&2] || rep == [&3]) && !triple_run {
            break body;
        }
    };
    let v = format!("{body}{}", mod11_10_check(&body));
    let b = break_last_digit(r, &v);
    let sep = *r.pick(&["", " "]);
    Pair {
        valid: grouped(&v, &[2, 3, 3, 3], sep),
        broken: grouped(&b, &[2, 3, 3, 3], sep),
    }
}

pub fn fr_nir(r: &mut Rng) -> Pair {
    let dept = match r.below(10) {
        0 => "2A".to_string(),
        1 => "2B".to_string(),
        _ => format!("{:02}", r.range(1, 95)),
    };
    let body = format!(
        "{}{:02}{:02}{dept}{:03}{:03}",
        r.range(1, 2),
        r.below(100),
        r.range(1, 12),
        r.range(1, 990),
        r.range(1, 999)
    );
    let n: u64 = body
        .replace("2A", "19")
        .replace("2B", "18")
        .parse()
        .unwrap();
    let key = 97 - n % 97;
    let v = format!("{body}{key:02}");
    let b = break_last_digit(r, &v);
    let sep = *r.pick(&["", " "]);
    let w = [1, 2, 2, 2, 3, 3, 2];
    Pair {
        valid: grouped(&v, &w, sep),
        broken: grouped(&b, &w, sep),
    }
}

const NIF: &[u8] = b"TRWAGMYFPDXBNJZSQVHLCKE";

fn nif_letter(n: u64) -> char {
    NIF[(n % 23) as usize] as char
}

pub fn es_nif(r: &mut Rng) -> Pair {
    let n = r.digits(8);
    let l = nif_letter(n.parse().unwrap());
    let b = other_upper(r, l);
    Pair {
        valid: format!("{n}{l}"),
        broken: format!("{n}{b}"),
    }
}

pub fn es_nie(r: &mut Rng) -> Pair {
    let (p, lead) = *r.pick(&[('X', 0u64), ('Y', 1), ('Z', 2)]);
    let n = r.digits(7);
    let l = nif_letter(lead * 10_000_000 + n.parse::<u64>().unwrap());
    let b = other_upper(r, l);
    Pair {
        valid: format!("{p}{n}{l}"),
        broken: format!("{p}{n}{b}"),
    }
}

pub fn cf_check(s: &str) -> char {
    const ODD: [u32; 26] = [
        1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24,
        23,
    ];
    let mut t = 0;
    for (i, c) in s.bytes().enumerate() {
        let v = if c.is_ascii_digit() {
            u32::from(c - b'0')
        } else {
            u32::from(c - b'A')
        };
        t += if i % 2 == 0 { ODD[v as usize] } else { v };
    }
    char::from(b'A' + (t % 26) as u8)
}

pub fn it_fiscal_code(r: &mut Rng) -> Pair {
    let letters: String = (0..6).map(|_| r.upper()).collect();
    let month = *r.pick(b"ABCDEHLMPRST") as char;
    let day = if r.below(2) == 0 {
        r.range(1, 28)
    } else {
        r.range(41, 68)
    };
    let body = format!(
        "{letters}{}{month}{day:02}{}{}",
        r.digits(2),
        r.upper(),
        r.digits(3)
    );
    let c = cf_check(&body);
    Pair {
        valid: format!("{body}{c}"),
        broken: format!("{body}{}", other_upper(r, c)),
    }
}

pub fn nl_bsn(r: &mut Rng) -> Pair {
    loop {
        let body = format!("{}{}", r.range(1, 9), r.digits(7));
        let w = [9, 8, 7, 6, 5, 4, 3, 2];
        let s: u32 = body.bytes().zip(w).map(|(b, w)| d(b) * w).sum();
        let c = s % 11;
        if c == 10 {
            continue;
        }
        let v = format!("{body}{c}");
        let b = break_last_digit(r, &v);
        if r.below(3) == 0 {
            return Pair {
                valid: grouped(&v, &[4, 2, 3], "."),
                broken: grouped(&b, &[4, 2, 3], "."),
            };
        }
        return Pair {
            valid: v,
            broken: b,
        };
    }
}

fn digitsum2(v: u32) -> u32 {
    let w = v * 2;
    w / 10 + w % 10
}

/// A valid VAT number of one of the twelve covered member states.
pub fn eu_vat(r: &mut Rng) -> Pair {
    let (cc, v): (&str, String) = match r.below(12) {
        0 => {
            let b = r.digits(7);
            let s: u32 = b
                .bytes()
                .enumerate()
                .map(|(i, c)| if i % 2 == 1 { digitsum2(d(c)) } else { d(c) })
                .sum();
            ("AT", format!("U{b}{}", (10 - (s + 4) % 10) % 10))
        }
        1 => {
            let b: u64 = format!("0{}", r.digits(7)).parse().unwrap();
            ("BE", format!("{b:08}{:02}", 97 - b % 97))
        }
        2 => {
            let b = format!("{}{}", r.range(1, 9), r.digits(7));
            ("DE", format!("{b}{}", mod11_10_check(&b)))
        }
        3 => loop {
            // Weights 2,7,6,5,4,3,2 then 1 on the check: the check is -sum mod 11.
            let b = format!("{}{}", r.range(1, 9), r.digits(6));
            let s: u32 = b
                .bytes()
                .zip([2, 7, 6, 5, 4, 3, 2])
                .map(|(c, w)| d(c) * w)
                .sum();
            let c = (11 - s % 11) % 11;
            if c < 10 {
                break ("DK", format!("{b}{c}"));
            }
        },
        4 => {
            let n = r.digits(8);
            ("ES", format!("{n}{}", nif_letter(n.parse().unwrap())))
        }
        5 => loop {
            let b = r.digits(7);
            let s: u32 = b
                .bytes()
                .zip([7, 9, 10, 5, 8, 4, 2])
                .map(|(c, w)| d(c) * w)
                .sum();
            let c = match s % 11 {
                0 => 0,
                1 => continue,
                x => 11 - x,
            };
            break ("FI", format!("{b}{c}"));
        },
        6 => {
            let siren: u64 = format!("{}{}", r.range(1, 9), r.digits(8)).parse().unwrap();
            ("FR", format!("{:02}{siren}", (12 + 3 * (siren % 97)) % 97))
        }
        7 => {
            let b = format!("{}{:03}", r.digits(7), r.range(1, 100));
            ("IT", format!("{b}{}", luhn_digit(&b)))
        }
        8 => loop {
            let b = format!("{}{}", r.range(1, 9), r.digits(7));
            let s: u32 = b
                .bytes()
                .zip([9, 8, 7, 6, 5, 4, 3, 2])
                .map(|(c, w)| d(c) * w)
                .sum();
            let c = s % 11;
            if c < 10 {
                break ("NL", format!("{b}{c}B{:02}", r.range(1, 99)));
            }
        },
        9 => loop {
            let b = format!("{}{}", r.range(1, 9), r.digits(8));
            let s: u32 = b
                .bytes()
                .zip([6, 5, 7, 2, 3, 4, 5, 6, 7])
                .map(|(c, w)| d(c) * w)
                .sum();
            let c = s % 11;
            if c < 10 {
                break ("PL", format!("{b}{c}"));
            }
        },
        10 => {
            let b = format!("{}{}", r.range(1, 9), r.digits(7));
            let s: u32 = b
                .bytes()
                .zip([9, 8, 7, 6, 5, 4, 3, 2])
                .map(|(c, w)| d(c) * w)
                .sum();
            let c = match 11 - s % 11 {
                10 | 11 => 0,
                c => c,
            };
            ("PT", format!("{b}{c}"))
        }
        _ => {
            let b = format!("{}{}", r.range(1, 9), r.digits(8));
            ("SE", format!("{b}{}01", luhn_digit(&b)))
        }
    };
    let valid = format!("{cc}{v}");
    // Break the check character: the last one, or for NL and SE the one before the
    // fixed suffix ("B01", "01").
    let at = match cc {
        "NL" => valid.len() - 4,
        "SE" => valid.len() - 3,
        _ => valid.len() - 1,
    };
    let c = valid.as_bytes()[at] as char;
    let replacement = if c.is_ascii_digit() {
        other_digit(r, c)
    } else {
        other_upper(r, c)
    };
    Pair {
        broken: swap(&valid, at, replacement),
        valid,
    }
}

fn mrz_check(s: &str) -> u32 {
    s.bytes()
        .enumerate()
        .map(|(i, c)| {
            let v = match c {
                b'0'..=b'9' => u32::from(c - b'0'),
                b'A'..=b'Z' => u32::from(c - b'A') + 10,
                _ => 0,
            };
            v * [7, 3, 1][i % 3]
        })
        .sum::<u32>()
        % 10
}

/// A TD3 passport MRZ second line.
pub fn passport_mrz(r: &mut Rng) -> Pair {
    let doc: String = (0..9)
        .map(|i| {
            if i < 2 || r.below(3) == 0 {
                r.upper()
            } else {
                r.digit()
            }
        })
        .collect();
    let nat = *r.pick(&["UTO", "GBR", "FRA", "D<<", "NLD"]);
    let dob = format!(
        "{:02}{:02}{:02}",
        r.below(100),
        r.range(1, 12),
        r.range(1, 28)
    );
    let sex = *r.pick(&["M", "F", "<"]);
    let exp = format!(
        "{:02}{:02}{:02}",
        r.below(100),
        r.range(1, 12),
        r.range(1, 28)
    );
    let personal = if r.below(2) == 0 {
        "<".repeat(14)
    } else {
        format!("{}{}", r.digits(9), "<".repeat(5))
    };
    let pcheck = if personal.starts_with('<') {
        "<".to_string()
    } else {
        mrz_check(&personal).to_string()
    };
    let docf = format!("{doc}{}", mrz_check(&doc));
    let dobf = format!("{dob}{}", mrz_check(&dob));
    let expf = format!("{exp}{}", mrz_check(&exp));
    let composite = format!("{docf}{dobf}{expf}{personal}{pcheck}");
    let valid = format!(
        "{docf}{nat}{dobf}{sex}{expf}{personal}{pcheck}{}",
        mrz_check(&composite)
    );
    assert_eq!(valid.len(), 44);
    // Break the document number's check digit.
    let c = valid.as_bytes()[9] as char;
    let broken = swap(&valid, 9, other_digit(r, c));
    Pair { valid, broken }
}

const BIC_COUNTRIES: &[&str] = &["DE", "FR", "GB", "US", "NL", "IT", "ES", "CH", "JP", "IN"];

/// An invented SWIFT/BIC of the right shape (bank codes start with Q, which no real
/// bank's here does, to keep them plainly synthetic).
pub fn swift_bic(r: &mut Rng) -> Pair {
    let bank = format!("Q{}{}{}", r.upper(), r.upper(), r.upper());
    let cc = *r.pick(BIC_COUNTRIES);
    let loc1 = if r.below(2) == 0 {
        r.upper()
    } else {
        char::from(b'2' + r.below(8) as u8)
    };
    let loc2 = loop {
        let c = if r.below(2) == 0 {
            r.upper()
        } else {
            r.digit()
        };
        if c != 'O' {
            break c;
        }
    };
    let branch = match r.below(3) {
        0 => String::new(),
        1 => "XXX".to_string(),
        _ => format!("{}{}", char::from(b'A' + r.below(23) as u8), r.digits(2)),
    };
    let valid = format!("{bank}{cc}{loc1}{loc2}{branch}");
    // No check digit: broken is the same code with a country that does not exist.
    let broken = format!("{bank}QQ{loc1}{loc2}{branch}");
    Pair { valid, broken }
}

pub fn imei(r: &mut Rng) -> Pair {
    let body = format!("{}{}", *r.pick(&["35", "86", "49", "01"]), r.digits(12));
    let v = format!("{body}{}", luhn_digit(&body));
    let b = break_last_digit(r, &v);
    let sep = *r.pick(&["", "-", " "]);
    Pair {
        valid: grouped(&v, &[2, 6, 6, 1], sep),
        broken: grouped(&b, &[2, 6, 6, 1], sep),
    }
}

/// A MAC address in RFC 7042's documentation range 00-00-5E-00-53-00 to -FF.
pub fn mac(r: &mut Rng) -> Pair {
    let last = r.range(1, 254);
    let hex = format!("00005e0053{last:02x}");
    let hex = if r.below(2) == 0 {
        hex.to_uppercase()
    } else {
        hex
    };
    let pairs: Vec<&str> = (0..6).map(|i| &hex[i * 2..i * 2 + 2]).collect();
    let valid = match r.below(3) {
        0 => pairs.join(":"),
        1 => pairs.join("-"),
        _ => grouped(&hex, &[4, 4, 4], "."),
    };
    // No check digit: broken mixes two separators.
    let broken = format!(
        "{}:{}-{}",
        pairs[..2].join(":"),
        pairs[2..4].join(":"),
        pairs[4..].join("-")
    );
    Pair { valid, broken }
}

const B58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58(bytes: &[u8]) -> String {
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for &b in bytes {
        let mut carry = u32::from(b);
        for x in digits.iter_mut() {
            carry += u32::from(*x) << 8;
            *x = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut s = "1".repeat(zeros);
    s.extend(digits.iter().rev().map(|&x| B58[x as usize] as char));
    s
}

const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn polymod(values: &[u8]) -> u32 {
    let generator = [
        0x3b6a57b2u32,
        0x26508e6d,
        0x1ea119fa,
        0x3d4233dd,
        0x2a1462b3,
    ];
    let mut chk = 1u32;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ u32::from(v);
        for (i, g) in generator.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn segwit_address(version: u8, program: &[u8]) -> String {
    let mut data = vec![version];
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in program {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            data.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        data.push(((acc << (5 - bits)) & 31) as u8);
    }
    let constant = if version == 0 { 1 } else { 0x2bc830a3 };
    let mut values = vec![3u8, 3, 0, 2, 3];
    values.extend_from_slice(&data);
    values.extend_from_slice(&[0; 6]);
    let pm = polymod(&values) ^ constant;
    for i in 0..6 {
        data.push(((pm >> (5 * (5 - i))) & 31) as u8);
    }
    let mut s = "bc1".to_string();
    s.extend(data.iter().map(|&x| CHARSET[x as usize] as char));
    s
}

/// A Bitcoin address from random bytes: no key behind it, so no one's address.
pub fn crypto(r: &mut Rng) -> Pair {
    let valid = match r.below(4) {
        0 | 1 => {
            let mut payload = vec![if r.below(2) == 0 { 0u8 } else { 5 }];
            payload.extend((0..20).map(|_| r.below(256) as u8));
            let check = Sha256::digest(Sha256::digest(&payload));
            payload.extend_from_slice(&check[..4]);
            base58(&payload)
        }
        2 => {
            let program: Vec<u8> = (0..20).map(|_| r.below(256) as u8).collect();
            segwit_address(0, &program)
        }
        _ => {
            let program: Vec<u8> = (0..32).map(|_| r.below(256) as u8).collect();
            segwit_address(1, &program)
        }
    };
    // Break the last checksum character.
    let at = valid.len() - 1;
    let c = valid.as_bytes()[at];
    let alphabet = if valid.starts_with("bc1") {
        CHARSET
    } else {
        B58
    };
    let replacement = loop {
        let x = alphabet[r.below(alphabet.len() as u64) as usize];
        if x != c {
            break x as char;
        }
    };
    Pair {
        broken: swap(&valid, at, replacement),
        valid,
    }
}
