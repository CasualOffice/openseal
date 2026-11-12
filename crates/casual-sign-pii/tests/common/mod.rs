//! Synthetic value generators for the tests. Check digits are computed here, written
//! separately from the crate's validators, so a test does not grade the crate against
//! itself. Every value is synthetic: random digits with a valid check, documentation
//! address ranges, fictional phone ranges and `example.*` domains. No real person's data.
// Test code: a panic is the failure report (CLAUDE.md); each test binary uses a
// different part of this module.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

pub mod validated;

/// splitmix64: deterministic, seedable, no dependency.
#[derive(Debug)]
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    pub fn range(&mut self, lo: u64, hi_inclusive: u64) -> u64 {
        lo + self.below(hi_inclusive - lo + 1)
    }
    pub fn digit(&mut self) -> char {
        char::from(b'0' + self.below(10) as u8)
    }
    pub fn digits(&mut self, n: usize) -> String {
        (0..n).map(|_| self.digit()).collect()
    }
    pub fn upper(&mut self) -> char {
        char::from(b'A' + self.below(26) as u8)
    }
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u64) as usize]
    }
}

/// Luhn check digit for `body` (digits only).
pub fn luhn_digit(body: &str) -> char {
    let mut sum = 0u32;
    // The check digit will sit at the right, so the body's last digit is doubled.
    for (i, c) in body.chars().rev().enumerate() {
        let mut d = c.to_digit(10).unwrap();
        if i % 2 == 0 {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
    }
    char::from_digit((10 - sum % 10) % 10, 10).unwrap()
}

/// ISO 13616 check digits for a country and BBAN.
pub fn iban_check(country: &str, bban: &str) -> String {
    let rearranged = format!("{bban}{country}00");
    let mut rem: u64 = 0;
    for c in rearranged.chars() {
        let v = if c.is_ascii_digit() {
            c as u64 - '0' as u64
        } else {
            c as u64 - 'A' as u64 + 10
        };
        rem = if v >= 10 {
            (rem * 100 + v) % 97
        } else {
            (rem * 10 + v) % 97
        };
    }
    format!("{:02}", 98 - rem)
}

const VD: [[u8; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const VP: [[u8; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];
const VINV: [u8; 10] = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

/// Verhoeff check digit for `body`.
pub fn verhoeff_digit(body: &str) -> char {
    let mut c = 0u8;
    for (i, ch) in body.chars().rev().enumerate() {
        let d = ch.to_digit(10).unwrap() as usize;
        c = VD[c as usize][VP[(i + 1) % 8][d] as usize];
    }
    char::from(b'0' + VINV[c as usize])
}

pub fn verhoeff_ok(number: &str) -> bool {
    let mut c = 0u8;
    for (i, ch) in number.chars().rev().enumerate() {
        let d = ch.to_digit(10).unwrap() as usize;
        c = VD[c as usize][VP[i % 8][d] as usize];
    }
    c == 0
}

pub fn group4(s: &str, sep: &str) -> String {
    s.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(sep)
}

pub fn email(r: &mut Rng) -> String {
    let first = r
        .pick(&["user", "j.doe", "signer", "a_b", "party", "x"])
        .to_string();
    let tag = if r.below(4) == 0 { "+contracts" } else { "" };
    let domain = r.pick(&[
        "example.com",
        "example.org",
        "mail.example.net",
        "example-corp.test",
        "sub.example.co.test",
    ]);
    format!("{first}{}{tag}@{domain}", r.range(1, 9999))
}

pub fn phone(r: &mut Rng) -> String {
    match r.below(6) {
        // US fictional exchange 555-0100..0199.
        0 => format!("(202) 555-01{}", r.digits(2)),
        1 => format!("+1 415 555 01{}", r.digits(2)),
        // Ofcom drama ranges.
        2 => format!("020 7946 0{}", r.digits(3)),
        // (07700 900xxx, Ofcom's drama mobile range, is invalid in libphonenumber.)
        3 => format!("+44 161 496 0{}", r.digits(3)),
        4 => format!("0113 496 0{}", r.digits(3)),
        // ACMA fictional mobile range.
        _ => format!("+61 491 570 1{}", r.digits(2)),
    }
}

/// (country, BBAN spec) for the countries the synthetic set draws from.
const IBAN_COUNTRIES: &[(&str, &str)] = &[
    ("DE", "nnnnnnnnnnnnnnnnnn"),
    ("GB", "aaaannnnnnnnnnnnnn"),
    ("FR", "nnnnnnnnnncccccccccccnn"),
    ("ES", "nnnnnnnnnnnnnnnnnnnn"),
    ("IT", "annnnnnnnnncccccccccccc"),
    ("NL", "aaaannnnnnnnnn"),
    ("BE", "nnnnnnnnnnnn"),
    ("CH", "nnnnncccccccccccc"),
    ("PL", "nnnnnnnnnnnnnnnnnnnnnnnn"),
    ("PT", "nnnnnnnnnnnnnnnnnnnnn"),
    ("SE", "nnnnnnnnnnnnnnnnnnnn"),
    ("AT", "nnnnnnnnnnnnnnnn"),
    ("IE", "aaaannnnnnnnnnnnnn"),
    ("NO", "nnnnnnnnnnn"),
    // The three Presidio 2.2.364 had wrong (review of ML-08).
    ("MU", "aaaannnnnnnnnnnnnnnnnnnaaa"),
    ("QA", "aaaaccccccccccccccccccccc"),
    ("PS", "aaaaccccccccccccccccccccc"),
];

pub fn iban_compact(r: &mut Rng) -> String {
    let (cc, spec) = *r.pick(IBAN_COUNTRIES);
    let bban: String = spec
        .chars()
        .map(|k| match k {
            'n' => r.digit(),
            'a' => r.upper(),
            _ => {
                if r.below(2) == 0 {
                    r.digit()
                } else {
                    r.upper()
                }
            }
        })
        .collect();
    format!("{cc}{}{bban}", iban_check(cc, &bban))
}

pub fn iban(r: &mut Rng) -> String {
    let compact = iban_compact(r);
    if r.below(2) == 0 {
        group4(&compact, " ")
    } else {
        compact
    }
}

pub fn card_compact(r: &mut Rng) -> String {
    let (prefix, len) = *r.pick(&[
        ("4", 16),
        ("51", 16),
        ("55", 16),
        ("2221", 16),
        ("2720", 16),
        ("6011", 16),
        ("34", 15),
        ("37", 15),
    ]);
    let body = format!("{prefix}{}", r.digits(len - prefix.len() - 1));
    format!("{body}{}", luhn_digit(&body))
}

pub fn card(r: &mut Rng) -> String {
    let c = card_compact(r);
    if c.len() == 15 {
        return format!("{} {} {}", &c[..4], &c[4..10], &c[10..]);
    }
    match r.below(3) {
        0 => group4(&c, " "),
        1 => group4(&c, "-"),
        _ => c,
    }
}

pub fn ssn(r: &mut Rng) -> String {
    let area = loop {
        let a = r.range(1, 899);
        if a != 666 {
            break a;
        }
    };
    format!("{area:03}-{:02}-{:04}", r.range(1, 99), r.range(1, 9999))
}

pub fn nino(r: &mut Rng) -> String {
    const FIRST: &[u8] = b"ABCEGHJKLMNOPRSTWXYZ";
    const SECOND: &[u8] = b"ABCEGHJKLMNPRSTWXYZ";
    let prefix = loop {
        let p = format!("{}{}", *r.pick(FIRST) as char, *r.pick(SECOND) as char);
        if !["BG", "GB", "NK", "KN", "NT", "TN", "ZZ"].contains(&p.as_str()) {
            break p;
        }
    };
    let d = r.digits(6);
    let suffix = *r.pick(b"ABCD") as char;
    if r.below(2) == 0 {
        format!("{prefix} {} {} {} {suffix}", &d[..2], &d[2..4], &d[4..])
    } else {
        format!("{prefix}{d}{suffix}")
    }
}

pub fn pan(r: &mut Rng) -> String {
    format!(
        "{}{}{}{}{}{}{}",
        r.upper(),
        r.upper(),
        r.upper(),
        *r.pick(b"ABCFGHLJPT") as char,
        r.upper(),
        r.digits(4),
        r.upper()
    )
}

pub fn aadhaar_compact(r: &mut Rng) -> String {
    loop {
        let body = format!("{}{}", r.range(2, 9), r.digits(10));
        let n = format!("{body}{}", verhoeff_digit(&body));
        let rev: String = n.chars().rev().collect();
        if rev != n {
            assert!(verhoeff_ok(&n));
            return n;
        }
    }
}

pub fn aadhaar(r: &mut Rng) -> String {
    let n = aadhaar_compact(r);
    if r.below(2) == 0 { group4(&n, " ") } else { n }
}

pub fn ip(r: &mut Rng) -> String {
    match r.below(3) {
        0 => format!(
            "{}.{}.{}.{}",
            r.range(1, 254),
            r.below(256),
            r.below(256),
            r.range(1, 254)
        ),
        // Documentation prefix 2001:db8::/32 (RFC 3849).
        1 => format!(
            "2001:db8:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            r.below(65536),
            r.below(65536),
            r.below(65536),
            r.below(65536),
            r.below(65536),
            r.range(1, 65535)
        ),
        _ => format!("2001:db8::{:x}", r.range(1, 65535)),
    }
}

pub const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

pub fn date(r: &mut Rng) -> String {
    let (y, m, d) = (r.range(1940, 2005), r.range(1, 12), r.range(1, 28));
    match r.below(5) {
        0 => format!("{d:02}/{m:02}/{y}"),
        1 => format!("{y}-{m:02}-{d:02}"),
        2 => format!("{d} {} {y}", MONTHS[m as usize - 1]),
        3 => format!("{} {d}, {y}", MONTHS[m as usize - 1]),
        _ => format!("{d:02}.{m:02}.{y}"),
    }
}
