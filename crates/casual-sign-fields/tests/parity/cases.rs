//! A fixed table of field-rule cases whose output must be byte-identical natively and
//! in WebAssembly (ADR-022: the browser and the server agree to the last digit).
//!
//! `run()` returns one line per case. `tests/parity.rs` compares it natively with
//! `expected.txt`; a WASM build of this same file is compared with the same text (see
//! the `T-1D` report for how it was run). Kept free of the test harness, time and I/O so
//! it compiles into a plain `wasm32-unknown-unknown` library.

// Test support (CLAUDE.md: tests may unwrap); the inputs are fixed and known valid.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;
use std::fmt::Write as _;

use casual_sign_fields::{
    Env, ErrorValue, check_client, evaluate_envelope, format_result, parse_formula, validate,
};
use casual_sign_model::{
    Condition, Conditional, CurrencyCode, DataLabel, DateFormat, Field, FieldOptions, FieldType,
    FieldValue, Formula, FormulaText, Group, GroupRule, Id, LengthRule, NumberRule, Placement,
    Points, Text, Validation, ValidationRule,
};
use rust_decimal::Decimal;

struct Vars;

impl Env for Vars {
    fn number(&self, label: &str) -> Result<Decimal, ErrorValue> {
        match label {
            "a" => Ok(Decimal::new(25, 1)),
            "b" => Ok(Decimal::from(-3)),
            "c" => Ok(Decimal::new(1, 28)),
            "big" => Ok(Decimal::MAX),
            "café" => Ok(Decimal::from(7)),
            "bad" => Err(ErrorValue::NotANumber),
            _ => Ok(Decimal::ZERO),
        }
    }
    fn date(&self, label: &str) -> Result<i64, ErrorValue> {
        match label {
            "d1" => Ok(19_782),
            "d2" => Ok(-719_162),
            _ => Err(ErrorValue::NotADate),
        }
    }
}

const FORMULAS: &[&str] = &[
    "1+2*3",
    "(1+2)*3",
    "0.1+0.2",
    "1/3",
    "2/3",
    "1/3*3",
    "10-4-3",
    "100/10/5",
    "-a+-b",
    "--2",
    "a*b",
    "a/b",
    "a-b-c",
    "c*c",
    "big+1",
    "big*2",
    "-big-1",
    "big/c",
    "1/0",
    "a/(b+3)",
    "a<b",
    "a<=2.5",
    "a>b",
    "a>=2.50",
    "a=2.5",
    "a<>b",
    "IF(a>b,1,2)",
    "IF(0,1/0,7)",
    "IF(b,4,5)",
    "SUM(1,2,3)",
    "SUM(a,b,c)",
    "SUM(big,big)",
    "MIN(a,b,0)",
    "MAX(a,b,0)",
    "ROUND(a)",
    "ROUND(b/2)",
    "ROUND(1.005,2)",
    "ROUND(-1.005,2)",
    "ROUND(2/3,15)",
    "ROUND(1,16)",
    "ROUND(1,-1)",
    "ROUND(1,0.5)",
    "ABS(b)",
    "ABS(-0)",
    "DAYS(d1,d2)",
    "DAYS(d2,d1)",
    "DAYS(d1,nothing)",
    "DAYS(1,2)",
    "[café]*2",
    "cafe\u{301}+1",
    "bad+1",
    "unknown*5",
    "1e5",
    "",
    "(",
    "1 2",
    "POW(2,2)",
    "IF(1,2)",
    "1<2<3",
    "[a",
    "79228162514264337593543950336",
    "0.00000000000000000000000000001",
    "SUM(a, b, c, a, b)",
    "MAX(MIN(a,b),ABS(b))",
    "a*a*a*a*a*a*a*a*a*a",
    "1/7",
    "22/7*7",
    "-(1/3)",
    "0-0",
    "-0*1",
];

const PRECISIONS: &[u8] = &[0, 1, 2, 4, 15];

const DECIMALS: &[&str] = &[
    "0",
    "-0.5",
    "0.5",
    "1.5",
    "2.5",
    "-2.5",
    "0.125",
    "1234.5678",
    "-0.0049",
    "79228162514264337593543950335",
    "0.0000000000000000000000000001",
];

fn id(s: &str) -> Id {
    Id::new(s).unwrap()
}

fn text(s: &str) -> FieldValue {
    FieldValue::Text(Text::new(s).unwrap())
}

fn field(name: &str, ty: FieldType) -> Field {
    let p = |n: i64| Points::new(Decimal::from(n)).unwrap();
    let mut f = Field::new(
        id(name),
        id("doc"),
        ty,
        Placement::new(1, p(0), p(0), p(50), p(10)).unwrap(),
    );
    f.recipient_id = Some(id("r1"));
    f
}

fn ruled(rule: ValidationRule) -> Field {
    let mut f = field("v", FieldType::Text);
    f.validation = Some(Validation {
        rule,
        message: None,
    });
    f
}

fn labelled(name: &str, ty: FieldType, label: &str) -> Field {
    let mut f = field(name, ty);
    f.label = Some(DataLabel::new(label).unwrap());
    f
}

fn formula(name: &str, label: &str, expr: &str, precision: u8) -> Field {
    let mut f = labelled(name, FieldType::Formula, label);
    f.formula = Some(Formula::new(FormulaText::new(expr).unwrap(), precision).unwrap());
    f
}

fn validation_cases() -> Vec<(String, Field, Vec<&'static str>)> {
    let usd = CurrencyCode::new("USD").unwrap();
    vec![
        (
            "email".into(),
            ruled(ValidationRule::Email),
            vec![
                "a@b.co",
                "a@b",
                "x.y+z@sub.example.org",
                "a..b@c.co",
                "é@b.co",
            ],
        ),
        (
            "number".into(),
            ruled(ValidationRule::Number(
                NumberRule::new(
                    Some(Decimal::from(-100)),
                    Some(Decimal::from(1_000)),
                    None,
                    Some(2),
                )
                .unwrap(),
            )),
            vec![
                "12", "1,000", "1,000.01", "-100", "-100.5", "0.125", "1e3", "NaN", "Infinity",
                " 7 ", "1,00",
            ],
        ),
        (
            "currency".into(),
            ruled(ValidationRule::Number(
                NumberRule::new(Some(Decimal::ZERO), None, Some(usd), None).unwrap(),
            )),
            vec!["$5", "USD 5.25", "€5", "$-5", "5.255", "$ 5"],
        ),
        (
            "date-iso".into(),
            ruled(ValidationRule::Date {
                format: DateFormat::YyyyMmDd,
            }),
            vec![
                "2024-02-29",
                "2023-02-29",
                "1900-02-29",
                "2000-02-29",
                "9999-12-31",
                "2024-2-01",
            ],
        ),
        (
            "date-us".into(),
            ruled(ValidationRule::Date {
                format: DateFormat::MmDdYyyy,
            }),
            vec!["02/29/2024", "2/9/2024", "13/01/2024", "04/31/2024"],
        ),
        (
            "date-eu".into(),
            ruled(ValidationRule::Date {
                format: DateFormat::DdMmYyyy,
            }),
            vec!["29/02/2024", "31/04/2024", "1/1/0001"],
        ),
        (
            "date-dot".into(),
            ruled(ValidationRule::Date {
                format: DateFormat::DdMmYyyyDot,
            }),
            vec!["29.02.2024", "29.02.2023", "1.1.2000"],
        ),
        (
            "date-mmm".into(),
            ruled(ValidationRule::Date {
                format: DateFormat::DMmmYyyy,
            }),
            vec!["7 Mar 2026", "07 mar 2026", "7 March 2026", "31 Apr 2026"],
        ),
        (
            "zip".into(),
            ruled(ValidationRule::Zip),
            vec!["12345", "12345-6789", "123456789", "1234", "12345-678"],
        ),
        (
            "ssn".into(),
            ruled(ValidationRule::Ssn),
            vec![
                "123-45-6789",
                "000-45-6789",
                "666-45-6789",
                "923-45-6789",
                "123-00-6789",
                "123-45-0000",
                "123456789",
            ],
        ),
        (
            "phone".into(),
            ruled(ValidationRule::Phone),
            vec![
                "+14155552671",
                "(415) 555-2671",
                "+0123456789",
                "12345",
                "415-555-CALL",
            ],
        ),
        (
            "length".into(),
            ruled(ValidationRule::Length(
                LengthRule::new(Some(2), Some(4)).unwrap(),
            )),
            vec!["a", "ab", "€€€€", "abcde"],
        ),
        (
            "regex".into(),
            ruled(ValidationRule::Regex {
                pattern: Text::new("[A-Z]{2}-[0-9]+").unwrap(),
            }),
            vec!["AB-12", "ab-12", "AB-", "xAB-12"],
        ),
        (
            "regex-redos".into(),
            ruled(ValidationRule::Regex {
                pattern: Text::new("(a+)+$").unwrap(),
            }),
            vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!", "aaaa"],
        ),
        (
            "regex-big".into(),
            ruled(ValidationRule::Regex {
                pattern: Text::new(r"\w{100}").unwrap(),
            }),
            vec!["x"],
        ),
    ]
}

/// A named envelope: its fields and the client's values.
type EnvelopeCase = (&'static str, Vec<Field>, Vec<(&'static str, FieldValue)>);

fn envelope_cases() -> Vec<EnvelopeCase> {
    let check = |n: &str, l: &str| labelled(n, FieldType::Checkbox, l);
    let when = |mut f: Field, parent: &str, c: Condition| {
        f.conditional = Some(Conditional {
            parent_label: DataLabel::new(parent).unwrap(),
            when: c,
        });
        f
    };
    let grouped = |n: &str, rule: GroupRule| {
        let mut f = field(n, FieldType::Checkbox);
        f.group = Some(Group { id: id("g"), rule });
        f
    };
    let mut req = field("req", FieldType::Text);
    req.required = true;
    let mut radio = field("radio", FieldType::RadioGroup);
    radio.options =
        FieldOptions::new(vec![Text::new("yes").unwrap(), Text::new("no").unwrap()]).unwrap();
    radio.required = true;
    vec![
        (
            "invoice",
            vec![
                labelled("p", FieldType::Number, "price"),
                labelled("q", FieldType::Number, "qty"),
                check("x", "express"),
                when(
                    labelled("f", FieldType::Number, "fee"),
                    "express",
                    Condition::Checked,
                ),
                formula("t", "total", "price*qty+fee", 2),
                formula("v", "vat", "ROUND(total*0.2,2)", 2),
            ],
            vec![("p", text("19.99")), ("q", text("3")), ("f", text("4.5"))],
        ),
        (
            "invoice-express",
            vec![
                labelled("p", FieldType::Number, "price"),
                labelled("q", FieldType::Number, "qty"),
                check("x", "express"),
                when(
                    labelled("f", FieldType::Number, "fee"),
                    "express",
                    Condition::Checked,
                ),
                formula("t", "total", "price*qty+fee", 2),
            ],
            vec![
                ("p", text("19.99")),
                ("q", text("3")),
                ("x", FieldValue::Checked(true)),
                ("f", text("4.5")),
            ],
        ),
        (
            "cycle",
            vec![
                formula("a", "A", "B+1", 0),
                formula("b", "B", "A+1", 0),
                when(field("c", FieldType::Text), "A", Condition::Any),
            ],
            vec![],
        ),
        (
            "cond-cycle",
            vec![
                when(check("a", "A"), "B", Condition::Checked),
                when(check("b", "B"), "A", Condition::Unchecked),
            ],
            vec![],
        ),
        (
            "group-ok",
            vec![
                grouped("g1", GroupRule::SelectRange { min: 1, max: 2 }),
                grouped("g2", GroupRule::SelectRange { min: 1, max: 2 }),
            ],
            vec![("g1", FieldValue::Checked(true))],
        ),
        (
            "group-bad",
            vec![
                grouped("g1", GroupRule::SelectExactly { count: 2 }),
                grouped("g2", GroupRule::SelectExactly { count: 2 }),
            ],
            vec![("g1", FieldValue::Checked(true))],
        ),
        ("required", vec![req.clone()], vec![]),
        ("required-ok", vec![req], vec![("req", text("x"))]),
        ("radio-none", vec![radio.clone()], vec![]),
        (
            "radio-bad",
            vec![radio],
            vec![("radio", FieldValue::Choice(Text::new("maybe").unwrap()))],
        ),
        (
            "linked",
            vec![
                labelled("a", FieldType::Text, "nm"),
                labelled("b", FieldType::Text, "nm"),
            ],
            vec![("b", text("Ada"))],
        ),
        (
            "linked-lie",
            vec![
                labelled("a", FieldType::Text, "nm"),
                labelled("b", FieldType::Text, "nm"),
            ],
            vec![("a", text("Ada")), ("b", text("Eve"))],
        ),
        (
            "div0",
            vec![
                labelled("a", FieldType::Number, "a"),
                formula("t", "t", "100/a", 2),
            ],
            vec![("a", text("0"))],
        ),
        (
            "dates",
            vec![
                labelled("s", FieldType::Date, "s"),
                labelled("e", FieldType::Date, "e"),
                formula("d", "d", "DAYS(e,s)", 0),
            ],
            vec![("s", text("2024-02-28")), ("e", text("2025-03-01"))],
        ),
        (
            "unknown",
            vec![field("a", FieldType::Text)],
            vec![("zz", text("x"))],
        ),
    ]
}

/// Runs every case and returns one line each.
pub fn run() -> String {
    let mut out = String::new();
    let mut n = 0usize;
    let mut line = |out: &mut String, s: String| {
        n += 1;
        let _ = writeln!(out, "{n:03} {s}");
    };
    for f in FORMULAS {
        let r = parse_formula(f).map(|e| e.evaluate(&Vars).map(|d| d.to_string()));
        line(&mut out, format!("formula {f:?} => {r:?}"));
    }
    for d in DECIMALS {
        let d: Decimal = d.parse().unwrap();
        for p in PRECISIONS {
            line(
                &mut out,
                format!("format {d} @{p} => {}", format_result(d, *p)),
            );
        }
    }
    for (name, f, inputs) in validation_cases() {
        for v in inputs {
            let r = validate(&f, &text(v)).map_err(|e| format!("{} {e:?}", e.code()));
            line(&mut out, format!("validate {name} {v:?} => {r:?}"));
        }
    }
    for (name, fields, vals) in envelope_cases() {
        let values: BTreeMap<Id, FieldValue> = vals.into_iter().map(|(k, v)| (id(k), v)).collect();
        let o = evaluate_envelope(&fields, &values);
        let issues: Vec<String> = o
            .issues
            .iter()
            .map(|i| format!("{}:{}", i.field_id, i.code()))
            .collect();
        line(
            &mut out,
            format!(
                "envelope {name} issues={issues:?} computed={:?} dropped={:?} hidden={:?}",
                o.computed, o.dropped, o.hidden
            ),
        );
        let client: Vec<String> = check_client(&fields, &values)
            .iter()
            .map(|i| format!("{}:{}", i.field_id, i.code()))
            .collect();
        line(&mut out, format!("client {name} => {client:?}"));
    }
    out
}
