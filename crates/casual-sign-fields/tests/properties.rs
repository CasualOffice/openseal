//! Property tests: hostile formulas and values never panic, evaluation is deterministic,
//! and an envelope's outcome does not depend on the order its fields are listed in.

// Tests may unwrap (CLAUDE.md): a failure here is the test failing.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::collections::BTreeMap;

use casual_sign_fields::{
    Env, ErrorValue, check_client, evaluate_envelope, parse_formula, validate,
};
use casual_sign_model::{
    Condition, DateFormat, FieldType, FieldValue, GroupRule, LengthRule, NumberRule, Text,
    Validation, ValidationRule,
};
use common::*;
use proptest::prelude::*;
use rust_decimal::Decimal;

/// Pieces a formula is made of, plus junk, so both valid and broken formulas appear.
const PIECES: &[&str] = &[
    "a",
    "b",
    "c",
    "[a]",
    "[x y]",
    "café",
    "1",
    "0",
    "2.5",
    "79228162514264337593543950335",
    "0.0000000000000000000000000001",
    "+",
    "-",
    "*",
    "/",
    "(",
    ")",
    ",",
    "=",
    "<>",
    "<",
    "<=",
    ">",
    ">=",
    "IF(",
    "SUM(",
    "MIN(",
    "MAX(",
    "ROUND(",
    "ABS(",
    "DAYS(",
    " ",
    "[",
    "]",
    "1e9",
    "NaN",
    "\u{0}",
    "é",
    "\u{301}",
    "😀",
    ".",
    ";",
];

fn formula_text() -> impl Strategy<Value = String> {
    prop::collection::vec(prop::sample::select(PIECES), 0..400).prop_map(|p| p.concat())
}

struct Fixed(BTreeMap<String, Result<Decimal, ErrorValue>>);

impl Env for Fixed {
    fn number(&self, label: &str) -> Result<Decimal, ErrorValue> {
        self.0.get(label).copied().unwrap_or(Ok(Decimal::ZERO))
    }
    fn date(&self, label: &str) -> Result<i64, ErrorValue> {
        match label {
            "a" => Ok(-719_162),
            "b" => Ok(2_932_896),
            _ => Err(ErrorValue::NotADate),
        }
    }
}

fn decimal() -> impl Strategy<Value = Result<Decimal, ErrorValue>> {
    prop_oneof![
        any::<i64>().prop_map(|n| Ok(Decimal::from(n))),
        (any::<i64>(), 0u32..=28).prop_map(|(n, s)| Ok(Decimal::new(n, s))),
        Just(Ok(Decimal::MAX)),
        Just(Ok(Decimal::MIN)),
        Just(Ok(Decimal::ZERO)),
        Just(Err(ErrorValue::NotANumber)),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2_000, ..ProptestConfig::default() })]

    #[test]
    fn formulas_never_panic_and_evaluate_deterministically(
        text in formula_text(),
        a in decimal(), b in decimal(), c in decimal(),
    ) {
        let env = Fixed([("a", a), ("b", b), ("c", c)].into_iter().map(|(k, v)| (k.to_owned(), v)).collect());
        let first = parse_formula(&text);
        prop_assert_eq!(&first, &parse_formula(&text));
        if let Ok(expr) = first {
            prop_assert!(expr.references().len() <= 100);
            prop_assert_eq!(expr.evaluate(&env), expr.evaluate(&env));
        }
    }

    #[test]
    fn arbitrary_unicode_formulas_never_panic(text in any::<String>()) {
        let _ = parse_formula(&text);
    }

    #[test]
    fn values_never_panic_any_rule(value in any::<String>(), digits in prop::collection::vec(prop::sample::select(&['0', '1', '9', '.', ',', '+', '$', ' ', '-', 'e'][..]), 0..40)
        .prop_map(|v| v.into_iter().collect::<String>())) {
        let rules = vec![
            ValidationRule::Email,
            ValidationRule::Number(NumberRule::new(Some(Decimal::from(-10)), Some(Decimal::from(10)), Some(casual_sign_model::CurrencyCode::new("USD").unwrap()), Some(2)).unwrap()),
            ValidationRule::Number(NumberRule::default()),
            ValidationRule::Date { format: DateFormat::YyyyMmDd },
            ValidationRule::Date { format: DateFormat::MmDdYyyy },
            ValidationRule::Date { format: DateFormat::DdMmYyyy },
            ValidationRule::Date { format: DateFormat::DdMmYyyyDot },
            ValidationRule::Date { format: DateFormat::DMmmYyyy },
            ValidationRule::Zip,
            ValidationRule::Ssn,
            ValidationRule::Phone,
            ValidationRule::Length(LengthRule::new(Some(1), Some(5)).unwrap()),
            ValidationRule::Regex { pattern: Text::new("(a+)+$").unwrap() },
        ];
        for v in [&value, &digits] {
            let Ok(t) = Text::new(v.clone()) else { continue };
            for rule in &rules {
                let mut f = field("f", FieldType::Text);
                f.validation = Some(Validation { rule: rule.clone(), message: None });
                let once = validate(&f, &FieldValue::Text(t.clone()));
                prop_assert_eq!(once, validate(&f, &FieldValue::Text(t.clone())));
            }
        }
    }

    #[test]
    fn sender_patterns_never_panic(pattern in any::<String>(), value in any::<String>()) {
        if let (Ok(p), Ok(v)) = (Text::new(pattern), Text::new(value)) {
            let mut f = field("f", FieldType::Text);
            f.validation = Some(Validation { rule: ValidationRule::Regex { pattern: p }, message: None });
            let _ = validate(&f, &FieldValue::Text(v));
        }
    }
}

/// A random small envelope: labels from a small pool so conditions, links, formulas
/// and cycles all happen.
#[derive(Debug, Clone)]
struct Spec {
    ty: u8,
    label: Option<u8>,
    parent: Option<(u8, u8)>,
    formula: String,
    group: Option<u8>,
    required: bool,
    recipient: bool,
}

fn spec() -> impl Strategy<Value = Spec> {
    (
        0u8..6,
        prop::option::of(0u8..6),
        prop::option::of((0u8..6, 0u8..4)),
        prop::collection::vec(
            prop::sample::select(
                &[
                    "L0", "L1", "L2", "L3", "+", "*", "/", "1", "0", "(", ")", "-",
                ][..],
            ),
            0..12,
        ),
        prop::option::of(0u8..2),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(|(ty, label, parent, f, group, required, recipient)| Spec {
            ty,
            label,
            parent,
            formula: f.join(" "),
            group,
            required,
            recipient,
        })
}

fn build(i: usize, s: &Spec) -> casual_sign_model::Field {
    let name = format!("f{i:02}");
    let ty = [
        FieldType::Text,
        FieldType::Number,
        FieldType::Checkbox,
        FieldType::Formula,
        FieldType::Dropdown,
        FieldType::Date,
    ][usize::from(s.ty)];
    let mut f = match (ty, s.label) {
        (FieldType::Formula, l) => {
            let expr = if s.formula.is_empty() {
                "1".to_owned()
            } else {
                s.formula.clone()
            };
            formula(&name, &format!("L{}", l.unwrap_or(9)), &expr, 2)
        }
        (_, Some(l)) => labelled(&name, ty, &format!("L{l}")),
        (_, None) => field(&name, ty),
    };
    if ty == FieldType::Dropdown {
        f = with_options(f, &["x", "y"]);
    }
    if let Some((p, c)) = s.parent {
        let cond = match c {
            0 => Condition::Checked,
            1 => Condition::Unchecked,
            2 => Condition::Any,
            _ => Condition::Value(Text::new("1").unwrap()),
        };
        f = when(f, &format!("L{p}"), cond);
    }
    if let (Some(g), FieldType::Checkbox) = (s.group, ty) {
        f.group = Some(casual_sign_model::Group {
            id: id(&format!("g{g}")),
            rule: GroupRule::SelectRange { min: 1, max: 2 },
        });
    }
    if s.recipient {
        f.recipient_id = Some(id("r2"));
    }
    f.required = s.required;
    f
}

fn value() -> impl Strategy<Value = Option<FieldValue>> {
    prop_oneof![
        Just(None),
        any::<bool>().prop_map(|b| Some(FieldValue::Checked(b))),
        prop::sample::select(
            &[
                "1",
                "2.50",
                "-3",
                "abc",
                "",
                "2024-02-29",
                "x",
                "1e3",
                "99999999999999999999999999999"
            ][..]
        )
        .prop_map(|s| Some(text(s))),
        prop::sample::select(&["x", "y", "z"][..]).prop_map(|s| Some(choice(s))),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1_000, ..ProptestConfig::default() })]

    #[test]
    fn evaluate_envelope_is_order_independent_and_deterministic(
        specs in prop::collection::vec(spec(), 0..14),
        vals in prop::collection::vec(value(), 14),
        seed in any::<u64>(),
    ) {
        let fields: Vec<_> = specs.iter().enumerate().map(|(i, s)| build(i, s)).collect();
        let values: casual_sign_fields::Values = vals
            .iter()
            .enumerate()
            .filter_map(|(i, v)| v.clone().map(|v| (id(&format!("f{i:02}")), v)))
            .collect();
        let base = evaluate_envelope(&fields, &values);
        prop_assert_eq!(&base, &evaluate_envelope(&fields, &values));

        // A deterministic shuffle from the seed (Fisher-Yates over a tiny LCG).
        let mut shuffled = fields.clone();
        let mut state = seed;
        for i in (1..shuffled.len()).rev() {
            state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            let j = (state >> 33) as usize % (i + 1);
            shuffled.swap(i, j);
        }
        prop_assert_eq!(&base, &evaluate_envelope(&shuffled, &values));
        let mut reversed = fields.clone();
        reversed.reverse();
        prop_assert_eq!(&base, &evaluate_envelope(&reversed, &values));
        prop_assert_eq!(check_client(&fields, &values), check_client(&shuffled, &values));

        // Every dropped field is hidden; nothing hidden carries a value out.
        for d in &base.dropped {
            prop_assert!(base.hidden.contains(d));
        }
        for h in &base.hidden {
            prop_assert!(!base.values.contains_key(h));
        }
    }
}
