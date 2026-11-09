//! Builders shared by the integration tests.

// Tests may unwrap (CLAUDE.md): a failure here is the test failing.
#![allow(clippy::unwrap_used, dead_code)]

use casual_sign_model::{
    Condition, Conditional, DataLabel, Field, FieldOptions, FieldType, FieldValue, Formula,
    FormulaText, Group, GroupRule, Id, Placement, Points, Text,
};
use rust_decimal::Decimal;

pub fn id(s: &str) -> Id {
    Id::new(s).unwrap()
}

pub fn field(name: &str, ty: FieldType) -> Field {
    let p = |n: i64| Points::new(Decimal::from(n)).unwrap();
    let mut f = Field::new(
        id(name),
        id("doc"),
        ty,
        Placement::new(1, p(10), p(10), p(100), p(20)).unwrap(),
    );
    f.recipient_id = Some(id("r1"));
    f
}

pub fn labelled(name: &str, ty: FieldType, label: &str) -> Field {
    let mut f = field(name, ty);
    f.label = Some(DataLabel::new(label).unwrap());
    f
}

pub fn formula(name: &str, label: &str, expr: &str, precision: u8) -> Field {
    let mut f = labelled(name, FieldType::Formula, label);
    f.formula = Some(Formula::new(FormulaText::new(expr).unwrap(), precision).unwrap());
    f.read_only = true;
    f
}

pub fn when(mut f: Field, parent: &str, cond: Condition) -> Field {
    f.conditional = Some(Conditional {
        parent_label: DataLabel::new(parent).unwrap(),
        when: cond,
    });
    f
}

pub fn grouped(name: &str, group: &str, rule: GroupRule) -> Field {
    let mut f = field(name, FieldType::Checkbox);
    f.group = Some(Group {
        id: id(group),
        rule,
    });
    f
}

pub fn with_options(mut f: Field, options: &[&str]) -> Field {
    f.options =
        FieldOptions::new(options.iter().map(|o| Text::new(*o).unwrap()).collect()).unwrap();
    f
}

pub fn text(s: &str) -> FieldValue {
    FieldValue::Text(Text::new(s).unwrap())
}

pub fn choice(s: &str) -> FieldValue {
    FieldValue::Choice(Text::new(s).unwrap())
}

pub fn values(pairs: &[(&str, FieldValue)]) -> casual_sign_fields::Values {
    pairs.iter().map(|(k, v)| (id(k), v.clone())).collect()
}

pub fn codes(issues: &[casual_sign_fields::Issue]) -> Vec<(String, &'static str)> {
    issues
        .iter()
        .map(|i| (i.field_id.to_string(), i.code()))
        .collect()
}
