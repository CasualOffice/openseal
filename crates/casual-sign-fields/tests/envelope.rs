//! Envelope-level rules: visibility, cycles, groups, linking, formulas, client checks.

// Tests may unwrap (CLAUDE.md): a failure here is the test failing.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use casual_sign_fields::{
    ErrorValue, FieldError, FormulaError, check_client, check_for_send, evaluate_envelope,
};
use casual_sign_model::{Condition, FieldType, FieldValue, GroupRule, Text};
use common::*;

fn s(v: &[(&str, &'static str)]) -> Vec<(String, &'static str)> {
    v.iter().map(|(a, b)| ((*a).to_owned(), *b)).collect()
}

#[test]
fn conditional_fields_show_on_checked_and_hide_otherwise() {
    let fields = vec![
        labelled("a", FieldType::Checkbox, "agree"),
        when(
            labelled("b", FieldType::Text, "why"),
            "agree",
            Condition::Checked,
        ),
        when(field("c", FieldType::Text), "agree", Condition::Unchecked),
    ];
    let out = evaluate_envelope(
        &fields,
        &values(&[
            ("a", FieldValue::Checked(true)),
            ("b", text("x")),
            ("c", text("y")),
        ]),
    );
    assert_eq!(out.hidden, vec![id("c")]);
    assert_eq!(out.dropped, vec![id("c")]);
    assert_eq!(out.values.get(&id("b")), Some(&text("x")));
    assert!(!out.values.contains_key(&id("c")));

    let out = evaluate_envelope(
        &fields,
        &values(&[("a", FieldValue::Checked(false)), ("b", text("x"))]),
    );
    assert_eq!(out.hidden, vec![id("b")]);
    assert_eq!(out.dropped, vec![id("b")]);
}

#[test]
fn value_and_any_conditions() {
    let fields = vec![
        with_options(
            labelled("p", FieldType::Dropdown, "plan"),
            &["basic", "pro"],
        ),
        when(
            field("q", FieldType::Text),
            "plan",
            Condition::Value(Text::new("pro").unwrap()),
        ),
        when(field("r", FieldType::Text), "plan", Condition::Any),
    ];
    let out = evaluate_envelope(&fields, &values(&[("p", choice("basic"))]));
    assert_eq!(out.hidden, vec![id("q")]);
    let out = evaluate_envelope(&fields, &values(&[("p", choice("pro"))]));
    assert!(out.hidden.is_empty());
    let out = evaluate_envelope(&fields, &values(&[]));
    assert_eq!(out.hidden, vec![id("q"), id("r")]);
}

#[test]
fn hiding_cascades_to_grandchildren_even_on_unchecked() {
    let fields = vec![
        labelled("a", FieldType::Checkbox, "A"),
        when(
            labelled("b", FieldType::Checkbox, "B"),
            "A",
            Condition::Checked,
        ),
        when(field("c", FieldType::Text), "B", Condition::Unchecked),
    ];
    let out = evaluate_envelope(&fields, &values(&[("c", text("z"))]));
    assert_eq!(out.hidden, vec![id("b"), id("c")]);
    assert_eq!(out.dropped, vec![id("c")]);
}

#[test]
fn hidden_required_fields_are_not_required() {
    let mut b = when(field("b", FieldType::Text), "A", Condition::Checked);
    b.required = true;
    let fields = vec![labelled("a", FieldType::Checkbox, "A"), b];
    assert!(evaluate_envelope(&fields, &values(&[])).is_complete());
    let out = evaluate_envelope(&fields, &values(&[("a", FieldValue::Checked(true))]));
    assert_eq!(codes(&out.issues), s(&[("b", "CS-FLD-0001")]));
}

#[test]
fn condition_cycles_are_found_at_send() {
    let fields = vec![
        when(
            labelled("a", FieldType::Checkbox, "A"),
            "B",
            Condition::Checked,
        ),
        when(
            labelled("b", FieldType::Checkbox, "B"),
            "A",
            Condition::Checked,
        ),
        when(field("c", FieldType::Text), "A", Condition::Any),
        labelled("d", FieldType::Text, "D"),
    ];
    assert_eq!(
        codes(&check_for_send(&fields)),
        s(&[
            ("a", "CS-FLD-0020"),
            ("b", "CS-FLD-0020"),
            ("c", "CS-FLD-0020")
        ])
    );
    let out = evaluate_envelope(&fields, &values(&[("d", text("ok"))]));
    assert_eq!(out.hidden, vec![id("a"), id("b"), id("c")]);
}

#[test]
fn self_condition_and_formula_cycles_are_found() {
    let selfish = vec![when(
        labelled("a", FieldType::Checkbox, "A"),
        "A",
        Condition::Checked,
    )];
    assert_eq!(codes(&check_for_send(&selfish)), s(&[("a", "CS-FLD-0020")]));
    let loop2 = vec![formula("x", "X", "Y + 1", 0), formula("y", "Y", "X + 1", 0)];
    assert_eq!(
        codes(&check_for_send(&loop2)),
        s(&[("x", "CS-FLD-0020"), ("y", "CS-FLD-0020")])
    );
    // A formula and a condition in one cycle: shown when the total is high, and counted in it.
    let mixed = vec![
        formula("t", "total", "line + 1", 0),
        when(
            labelled("l", FieldType::Number, "line"),
            "total",
            Condition::Any,
        ),
    ];
    assert_eq!(
        codes(&check_for_send(&mixed)),
        s(&[("l", "CS-FLD-0020"), ("t", "CS-FLD-0020")])
    );
}

#[test]
fn long_chains_do_not_exhaust_the_stack() {
    // 3,000 fields (the envelope cap), each shown by the one before.
    let mut fields = vec![labelled("f0000", FieldType::Checkbox, "L0")];
    for i in 1..3_000 {
        fields.push(when(
            labelled(&format!("f{i:04}"), FieldType::Checkbox, &format!("L{i}")),
            &format!("L{}", i - 1),
            Condition::Unchecked,
        ));
    }
    let out = evaluate_envelope(&fields, &values(&[]));
    assert!(out.is_complete());
    assert!(out.hidden.is_empty());
    // And a chain of formulas.
    let mut fields = vec![labelled("g0000", FieldType::Number, "N0")];
    for i in 1..3_000 {
        fields.push(formula(
            &format!("g{i:04}"),
            &format!("N{i}"),
            &format!("N{} + 1", i - 1),
            0,
        ));
    }
    let out = evaluate_envelope(&fields, &values(&[("g0000", text("1"))]));
    assert_eq!(out.computed.get(&id("g2999")), Some(&Ok("3000".to_owned())));
}

#[test]
fn group_rules_count_visible_checked_boxes() {
    let rules = [
        (
            GroupRule::SelectAtLeast { min: 2 },
            [false, false, true, true],
        ),
        (
            GroupRule::SelectAtMost { max: 1 },
            [true, true, false, false],
        ),
        (
            GroupRule::SelectExactly { count: 2 },
            [false, false, true, false],
        ),
        (
            GroupRule::SelectRange { min: 1, max: 2 },
            [false, true, true, false],
        ),
    ];
    for (rule, admits) in rules {
        let fields: Vec<_> = ["g1", "g2", "g3"]
            .iter()
            .map(|n| grouped(n, "grp", rule))
            .collect();
        for (checked, expect) in admits.iter().enumerate() {
            let vals: Vec<_> = ["g1", "g2", "g3"]
                .iter()
                .enumerate()
                .map(|(i, n)| (*n, FieldValue::Checked(i < checked)))
                .collect();
            let out = evaluate_envelope(&fields, &values(&vals));
            assert_eq!(
                out.is_complete(),
                *expect,
                "{rule:?} with {checked} checked"
            );
            if !expect {
                assert_eq!(
                    out.issues[0].error,
                    FieldError::GroupRule {
                        group: id("grp"),
                        checked: checked as u32
                    }
                );
                assert_eq!(out.issues[0].code(), "CS-FLD-0003");
            }
        }
    }
}

#[test]
fn hidden_group_members_do_not_count() {
    let rule = GroupRule::SelectExactly { count: 1 };
    let fields = vec![
        labelled("a", FieldType::Checkbox, "A"),
        grouped("g1", "grp", rule),
        when(grouped("g2", "grp", rule), "A", Condition::Checked),
    ];
    let vals = values(&[
        ("g1", FieldValue::Checked(true)),
        ("g2", FieldValue::Checked(true)),
    ]);
    let out = evaluate_envelope(&fields, &vals);
    assert!(out.is_complete(), "{:?}", out.issues);
    assert_eq!(out.dropped, vec![id("g2")]);
}

#[test]
fn group_members_must_agree_and_be_checkboxes() {
    let fields = vec![
        grouped("g1", "grp", GroupRule::SelectAtLeast { min: 1 }),
        grouped("g2", "grp", GroupRule::SelectAtMost { max: 1 }),
    ];
    assert_eq!(codes(&check_for_send(&fields)), s(&[("g1", "CS-FLD-0003")]));
    let mut t = field("t", FieldType::Text);
    t.group = Some(casual_sign_model::Group {
        id: id("g"),
        rule: GroupRule::SelectAtLeast { min: 1 },
    });
    assert_eq!(codes(&check_for_send(&[t])), s(&[("t", "CS-FLD-0003")]));
}

#[test]
fn radio_groups_need_exactly_one_valid_choice() {
    let mut r = with_options(field("r", FieldType::RadioGroup), &["yes", "no"]);
    r.required = true;
    let fields = vec![r];
    assert_eq!(
        codes(&evaluate_envelope(&fields, &values(&[])).issues),
        s(&[("r", "CS-FLD-0003")])
    );
    assert!(evaluate_envelope(&fields, &values(&[("r", choice("no"))])).is_complete());
    assert_eq!(
        codes(&evaluate_envelope(&fields, &values(&[("r", choice("maybe"))])).issues),
        s(&[("r", "CS-FLD-0002")])
    );
    assert_eq!(
        codes(&evaluate_envelope(&fields, &values(&[("r", FieldValue::Checked(true))])).issues),
        s(&[("r", "CS-FLD-0002")])
    );
}

#[test]
fn linked_fields_mirror_one_value_per_recipient() {
    let mut other = labelled("c", FieldType::Text, "name");
    other.recipient_id = Some(id("r2"));
    let fields = vec![
        labelled("a", FieldType::Text, "name"),
        labelled("b", FieldType::Text, "name"),
        other,
    ];
    let out = evaluate_envelope(&fields, &values(&[("b", text("Ada"))]));
    assert!(out.is_complete());
    assert_eq!(out.values.get(&id("a")), Some(&text("Ada")));
    assert_eq!(out.values.get(&id("b")), Some(&text("Ada")));
    assert_eq!(
        out.values.get(&id("c")),
        None,
        "another recipient's field is not linked"
    );
    // A client that sent two different values for one linked label is caught.
    let out = evaluate_envelope(&fields, &values(&[("a", text("Ada")), ("b", text("Eve"))]));
    assert_eq!(codes(&out.issues), s(&[("b", "CS-FLD-0022")]));
}

#[test]
fn unicode_labels_link_after_normalization() {
    let fields = vec![
        labelled("a", FieldType::Number, "caf\u{e9}"),
        formula("t", "t", "[cafe\u{301}] * 2", 0),
    ];
    let out = evaluate_envelope(&fields, &values(&[("a", text("21"))]));
    assert_eq!(out.computed.get(&id("t")), Some(&Ok("42".to_owned())));
}

#[test]
fn formulas_compute_over_visible_values_at_their_precision() {
    let fields = vec![
        labelled("p", FieldType::Number, "price"),
        labelled("q", FieldType::Number, "qty"),
        labelled("x", FieldType::Checkbox, "express"),
        when(
            labelled("f", FieldType::Number, "fee"),
            "express",
            Condition::Checked,
        ),
        formula("t", "total", "price * qty + fee", 2),
        when(
            field("big", FieldType::Text),
            "total",
            Condition::Value(Text::new("100.00").unwrap()),
        ),
    ];
    let out = evaluate_envelope(
        &fields,
        &values(&[("p", text("19.99")), ("q", text("5")), ("f", text("0.05"))]),
    );
    assert_eq!(
        out.computed.get(&id("t")),
        Some(&Ok("99.95".to_owned())),
        "hidden fee counts as 0"
    );
    assert_eq!(out.dropped, vec![id("f")]);
    assert!(out.hidden.contains(&id("big")));
    let out = evaluate_envelope(
        &fields,
        &values(&[
            ("p", text("19.99")),
            ("q", text("5")),
            ("x", FieldValue::Checked(true)),
            ("f", text("0.05")),
        ]),
    );
    assert_eq!(out.computed.get(&id("t")), Some(&Ok("100.00".to_owned())));
    assert_eq!(out.values.get(&id("t")), Some(&text("100.00")));
    assert!(
        !out.hidden.contains(&id("big")),
        "a formula's result drives a condition"
    );
}

#[test]
fn formula_error_values_are_values() {
    let fields = vec![
        labelled("a", FieldType::Number, "a"),
        formula("t", "t", "1 / a", 2),
        formula("u", "u", "t + 1", 2),
    ];
    let out = evaluate_envelope(&fields, &values(&[("a", text("0"))]));
    assert_eq!(
        out.computed.get(&id("t")),
        Some(&Err(ErrorValue::DivisionByZero))
    );
    assert_eq!(
        out.computed.get(&id("u")),
        Some(&Err(ErrorValue::DivisionByZero)),
        "errors propagate"
    );
    assert!(out.is_complete());
    let fields = vec![
        labelled("a", FieldType::Text, "a"),
        formula("t", "t", "a + 1", 0),
    ];
    let out = evaluate_envelope(&fields, &values(&[("a", text("NaN"))]));
    assert_eq!(
        out.computed.get(&id("t")),
        Some(&Err(ErrorValue::NotANumber))
    );
}

#[test]
fn date_difference_reads_each_fields_format() {
    let mut start = labelled("s", FieldType::Date, "start");
    start.format = Some(casual_sign_model::Format {
        date_format: Some(casual_sign_model::DateFormat::DMmmYyyy),
        ..Default::default()
    });
    let fields = vec![
        start,
        labelled("e", FieldType::Date, "end"),
        formula("d", "days", "DAYS(end, start)", 0),
    ];
    let out = evaluate_envelope(
        &fields,
        &values(&[("s", text("28 Feb 2024")), ("e", text("2024-03-01"))]),
    );
    assert_eq!(out.computed.get(&id("d")), Some(&Ok("2".to_owned())));
}

#[test]
fn formulas_are_checked_at_send() {
    let fields = vec![
        formula("a", "A", "B + ", 0),
        formula("b", "B", "nobody + 1", 0),
        formula(
            "c",
            "C",
            &format!("{}1{}", "(".repeat(40), ")".repeat(40)),
            0,
        ),
        labelled("d", FieldType::Formula, "D"),
    ];
    let issues = check_for_send(&fields);
    assert_eq!(
        codes(&issues),
        s(&[
            ("a", "CS-FLD-0021"),
            ("b", "CS-FLD-0021"),
            ("c", "CS-FLD-0021"),
            ("d", "CS-FLD-0021")
        ])
    );
    assert_eq!(
        issues[1].error,
        FieldError::Formula(FormulaError::UnknownLabel { reference: 0 })
    );
    assert_eq!(
        issues[3].error,
        FieldError::Formula(FormulaError::Misplaced)
    );
}

#[test]
fn locked_fields_keep_the_senders_value() {
    let mut f = field("a", FieldType::Text);
    f.locked = true;
    f.value = Some(text("fixed"));
    let fields = vec![f];
    let out = evaluate_envelope(&fields, &values(&[("a", text("changed"))]));
    assert_eq!(codes(&out.issues), s(&[("a", "CS-FLD-0022")]));
    assert_eq!(out.values.get(&id("a")), Some(&text("fixed")));
    assert!(evaluate_envelope(&fields, &values(&[("a", text("fixed"))])).is_complete());
}

#[test]
fn unknown_and_duplicate_ids_are_reported() {
    let fields = vec![
        field("a", FieldType::Text),
        field("a", FieldType::Text),
        field("b", FieldType::Text),
    ];
    let out = evaluate_envelope(&fields, &values(&[("zz", text("x")), ("a", text("y"))]));
    assert_eq!(
        codes(&out.issues),
        s(&[("a", "CS-FLD-0005"), ("zz", "CS-FLD-0005")])
    );
    let cond = vec![when(field("a", FieldType::Text), "missing", Condition::Any)];
    assert_eq!(codes(&check_for_send(&cond)), s(&[("a", "CS-FLD-0005")]));
}

#[test]
fn validation_runs_on_visible_values_with_codes() {
    let mut e = field("e", FieldType::EmailAddress);
    e.required = true;
    let fields = vec![e, field("n", FieldType::Number), field("z", FieldType::Zip)];
    let out = evaluate_envelope(&fields, &values(&[("n", text("1e9")), ("z", text("1234"))]));
    assert_eq!(
        codes(&out.issues),
        s(&[
            ("e", "CS-FLD-0001"),
            ("n", "CS-FLD-0002"),
            ("z", "CS-FLD-0002")
        ])
    );
}

#[test]
fn check_client_flags_formulas_the_client_got_wrong() {
    let fields = vec![
        labelled("a", FieldType::Number, "a"),
        formula("t", "t", "a * 2", 2),
        formula("u", "u", "1 / (a - a)", 2),
    ];
    let good = values(&[("a", text("3")), ("t", text("6.00"))]);
    assert!(check_client(&fields, &good).is_empty());
    let bad = values(&[("a", text("3")), ("t", text("7.00")), ("u", text("0"))]);
    assert_eq!(
        codes(&check_client(&fields, &bad)),
        s(&[("t", "CS-FLD-0022"), ("u", "CS-FLD-0022")])
    );
    let missing = values(&[("a", text("3"))]);
    assert_eq!(
        codes(&check_client(&fields, &missing)),
        s(&[("t", "CS-FLD-0022")])
    );
    // A rounding difference is a difference: the client runs this same code.
    let unrounded = values(&[("a", text("3")), ("t", text("6"))]);
    assert_eq!(
        codes(&check_client(&fields, &unrounded)),
        s(&[("t", "CS-FLD-0022")])
    );
}

#[test]
fn bad_regex_is_refused_at_send() {
    let mut f = field("a", FieldType::Text);
    f.validation = Some(casual_sign_model::Validation {
        rule: casual_sign_model::ValidationRule::Regex {
            pattern: Text::new(r"\w{1000}").unwrap(),
        },
        message: None,
    });
    let issues = check_for_send(&[f]);
    assert_eq!(
        issues[0].error,
        FieldError::Invalid(casual_sign_fields::Invalid::PatternTooBig)
    );
}
