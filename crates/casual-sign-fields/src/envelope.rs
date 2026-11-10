//! All of an envelope's fields together: send checks, completion and client checks
//! (docs/24 §5).
//!
//! Fields are first sorted by id, so every result is independent of the order the
//! caller listed them in. Visibility and formulas share one dependency graph, because
//! each can depend on the other (a field shown when a total exceeds a limit; a total
//! that ignores hidden lines). The graph has a node per field and per data label; it is
//! ordered with Kahn's algorithm, smallest node first, without recursion, so 3,000
//! chained fields cost no stack. Whatever the order cannot reach is in or behind a cycle
//! (`CS-FLD-0020`), and is treated as hidden.

use std::collections::{BTreeMap, BTreeSet};

use casual_sign_model::{
    Condition, Field, FieldType, FieldValue, GroupRule, Id, Text, ValidationRule,
};
use rust_decimal::Decimal;

use crate::error::{FieldError, FormulaError, Invalid, Issue};
use crate::formula::{Env, ErrorValue, Expression, format_result, parse_formula, round_result};
use crate::label_key;
use crate::parse::{parse_date, parse_number};
use crate::validate::{Patterns, date_format, validate_with};

/// Values by field id, as a client submits them.
pub type Values = BTreeMap<Id, FieldValue>;

/// A formula field's result: the text the signer sees, or an error value.
pub type Computed = Result<String, ErrorValue>;

/// What completion found (docs/24 §5).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Outcome {
    /// Every problem, sorted by field id then code. Empty means the fields may complete.
    pub issues: Vec<Issue>,
    /// The value of every visible field that has one, after linking, locking and
    /// computing: what is flattened into the document.
    pub values: BTreeMap<Id, FieldValue>,
    /// Each visible formula field's result.
    pub computed: BTreeMap<Id, Computed>,
    /// Hidden fields whose value was dropped, to be recorded as dropped in the audit.
    pub dropped: Vec<Id>,
    /// Every hidden field, whether or not it held a value.
    pub hidden: Vec<Id>,
}

impl Outcome {
    /// Whether the fields may complete: no issue at all.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.issues.is_empty()
    }
}

/// Checks an envelope's fields before sending: ids unique, formulas parse within their
/// bounds and name existing labels, conditions name existing labels, groups agree on
/// their rule, patterns compile, preset values are valid, and no formula or condition
/// cycle (`CS-FLD-0020`).
#[must_use]
pub fn check_for_send(fields: &[Field]) -> Vec<Issue> {
    let mut patterns = Patterns::default();
    let plan = Plan::new(fields, &mut patterns);
    let mut issues = plan.issues.clone();
    for &i in &plan.cyclic {
        push(&mut issues, &plan, i, FieldError::Cycle);
    }
    for (i, field) in plan.fields.iter().enumerate() {
        for preset in [&field.value, &field.default].into_iter().flatten() {
            if field.field_type != FieldType::Formula
                && let Err(e) = validate_with(field, preset, &mut patterns)
            {
                push(&mut issues, &plan, i, e);
            }
        }
    }
    sorted(issues)
}

/// Runs every field rule over an envelope at completion (docs/24 §5): the send checks,
/// linking, locking, visibility (dropping hidden values), formulas, validation,
/// `required`, and group rules.
///
/// A field's value is the client's from `values`, else the field's own `value`, else
/// its `default`; a locked or read-only field keeps the sender's value, and a client
/// that changed it gets `CS-FLD-0022`. Formula fields are always computed here; compare
/// a client's own results with [`check_client`].
///
/// The result does not depend on the order of `fields`.
#[must_use]
pub fn evaluate_envelope(fields: &[Field], values: &Values) -> Outcome {
    let mut patterns = Patterns::default();
    let plan = Plan::new(fields, &mut patterns);
    let mut issues = plan.issues.clone();
    let n = plan.fields.len();

    // Values supplied for fields that are not there.
    for id in values.keys() {
        if plan.fields.binary_search_by(|f| f.id.cmp(id)).is_err()
            && !plan.duplicate_ids.contains(id)
        {
            issues.push(Issue {
                field_id: id.clone(),
                error: FieldError::UnknownField,
            });
        }
    }

    // Effective values: client, else preset; locked and read-only keep the preset.
    let mut eff: Vec<Option<FieldValue>> = Vec::with_capacity(n);
    for (i, field) in plan.fields.iter().enumerate() {
        let preset = field.value.clone().or_else(|| field.default.clone());
        let submitted = values.get(&field.id);
        let value = if field.field_type == FieldType::Formula {
            None
        } else if field.locked || field.read_only {
            if submitted.is_some_and(|s| Some(s) != preset.as_ref()) {
                push(&mut issues, &plan, i, FieldError::ClientMismatch);
            }
            preset
        } else {
            submitted.cloned().or(preset)
        };
        eff.push(value);
    }

    // Linked fields: one recipient, one label, one value (DocuSign's same-label rule).
    let mut links: BTreeMap<(Option<&Id>, &str), Vec<usize>> = BTreeMap::new();
    for (i, field) in plan.fields.iter().enumerate() {
        if let (Some(key), true) = (
            plan.keys.get(i).and_then(Option::as_deref),
            field.field_type != FieldType::Formula,
        ) {
            links
                .entry((field.recipient_id.as_ref(), key))
                .or_default()
                .push(i);
        }
    }
    for members in links.values().filter(|m| m.len() > 1) {
        let canonical = members
            .iter()
            .find_map(|&i| eff.get(i).cloned().flatten().filter(|v| !v.is_empty()));
        let Some(canonical) = canonical else { continue };
        for &i in members {
            if let Some(slot) = eff.get_mut(i) {
                if slot
                    .as_ref()
                    .is_some_and(|v| !v.is_empty() && *v != canonical)
                {
                    push(&mut issues, &plan, i, FieldError::ClientMismatch);
                }
                *slot = Some(canonical.clone());
            }
        }
    }

    // Walk the graph in order.
    let mut state = State {
        plan: &plan,
        visible: vec![false; n],
        finals: vec![None; n],
        numbers: vec![None; n],
        labels: vec![LabelState::default(); plan.label_members.len()],
    };
    let mut computed = BTreeMap::new();
    for node in &plan.order {
        match *node {
            Node::Field(i) => {
                let (Some(field), Some(eff)) = (plan.fields.get(i), eff.get(i)) else {
                    continue;
                };
                let shown = state.condition_holds(i);
                if let Some(v) = state.visible.get_mut(i) {
                    *v = shown;
                }
                if !shown {
                    continue;
                }
                if let Some(Some(expr)) = plan.formulas.get(i) {
                    let precision = field.formula.as_ref().map_or(0, |f| f.precision());
                    let number = expr.evaluate(&state).map(|d| round_result(d, precision));
                    let result = number.map(|d| format_result(d, precision));
                    let shown = result.as_ref().ok().and_then(|t| Text::new(t.clone()).ok());
                    state.set(i, shown.map(FieldValue::Text), Some(number));
                    computed.insert(field.id.clone(), result);
                } else {
                    state.set(i, eff.clone(), None);
                }
            }
            Node::Label(j) => state.settle_label(j),
        }
    }
    for &i in &plan.cyclic {
        push(&mut issues, &plan, i, FieldError::Cycle);
    }

    // Per-field checks on what is visible, and what was dropped.
    let mut outcome = Outcome::default();
    for (i, field) in plan.fields.iter().enumerate() {
        let shown = state.visible.get(i).copied().unwrap_or(false);
        let value = eff.get(i).cloned().flatten();
        if !shown {
            outcome.hidden.push(field.id.clone());
            if value.as_ref().is_some_and(|v| !v.is_empty()) {
                outcome.dropped.push(field.id.clone());
            }
            continue;
        }
        if let Some(v) = &value
            && !v.is_empty()
            && field.field_type != FieldType::Formula
            && let Err(e) = validate_with(field, v, &mut patterns)
        {
            push(&mut issues, &plan, i, e);
        }
        let empty = value.as_ref().is_none_or(FieldValue::is_empty);
        let grouped = field.field_type == FieldType::Checkbox && field.group.is_some();
        if field.required && field.field_type.takes_input() && !grouped && empty {
            let error = if field.field_type == FieldType::RadioGroup {
                FieldError::RadioNotChosen
            } else {
                FieldError::Required
            };
            push(&mut issues, &plan, i, error);
        }
        if let Some(Some(v)) = state.finals.get(i)
            && !v.is_empty()
        {
            outcome.values.insert(field.id.clone(), v.clone());
        }
    }

    // Group rules over the visible members.
    for (group, (rule, members)) in &plan.groups {
        let Some(rule) = rule else { continue };
        let visible: Vec<usize> = members
            .iter()
            .copied()
            .filter(|&i| state.visible.get(i).copied().unwrap_or(false))
            .collect();
        let Some(&first) = visible.first() else {
            continue;
        };
        let checked = visible
            .iter()
            .filter(|&&i| matches!(state.finals.get(i), Some(Some(FieldValue::Checked(true)))))
            .count();
        let checked = u32::try_from(checked).unwrap_or(u32::MAX);
        if !rule.admits(checked) {
            push(
                &mut issues,
                &plan,
                first,
                FieldError::GroupRule {
                    group: group.clone(),
                    checked,
                },
            );
        }
    }

    outcome.issues = sorted(issues);
    outcome.computed = computed;
    outcome
}

/// Recomputes every formula and reports `CS-FLD-0022` for each formula field whose
/// client value differs from the server's: a different number, a value where the
/// server has an error or a hidden field, or no value where the server has one.
#[must_use]
pub fn check_client(fields: &[Field], client_values: &Values) -> Vec<Issue> {
    let outcome = evaluate_envelope(fields, client_values);
    let mut ids: Vec<&Id> = fields
        .iter()
        .filter(|f| f.field_type == FieldType::Formula)
        .map(|f| &f.id)
        .collect();
    ids.sort();
    ids.dedup();
    let mut issues = Vec::new();
    for id in ids {
        let client = client_values.get(id);
        let agrees = match outcome.computed.get(id) {
            Some(Ok(server)) => matches!(client, Some(FieldValue::Text(t)) if t.as_str() == server),
            _ => client.is_none_or(FieldValue::is_empty),
        };
        if !agrees {
            issues.push(Issue {
                field_id: id.clone(),
                error: FieldError::ClientMismatch,
            });
        }
    }
    issues
}

fn push(issues: &mut Vec<Issue>, plan: &Plan<'_>, i: usize, error: FieldError) {
    if let Some(field) = plan.fields.get(i) {
        issues.push(Issue {
            field_id: field.id.clone(),
            error,
        });
    }
}

fn sorted(mut issues: Vec<Issue>) -> Vec<Issue> {
    issues.sort_by(|a, b| {
        a.field_id
            .cmp(&b.field_id)
            .then_with(|| a.code().cmp(b.code()))
    });
    issues
}

/// A graph node: a field, or a data label (all the fields that carry it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Node {
    Field(usize),
    Label(usize),
}

/// The structure of an envelope's fields, independent of values.
struct Plan<'f> {
    /// Fields sorted by id; fields sharing an id are left out.
    fields: Vec<&'f Field>,
    duplicate_ids: BTreeSet<Id>,
    /// Each field's NFC label key.
    keys: Vec<Option<String>>,
    /// Label index of each field's conditional parent, when the label exists.
    parents: Vec<Option<usize>>,
    /// Each formula field's parsed expression, when valid.
    formulas: Vec<Option<Expression>>,
    /// Label key to index.
    label_index: BTreeMap<String, usize>,
    /// Each label's fields, in id order.
    label_members: Vec<Vec<usize>>,
    /// Group id to its agreed rule (`None` when members disagree) and members.
    groups: BTreeMap<Id, (Option<GroupRule>, Vec<usize>)>,
    /// Evaluation order.
    order: Vec<Node>,
    /// Fields the order could not reach: in or behind a cycle.
    cyclic: Vec<usize>,
    issues: Vec<Issue>,
}

impl<'f> Plan<'f> {
    fn new(input: &'f [Field], patterns: &mut Patterns) -> Self {
        let mut all: Vec<&Field> = input.iter().collect();
        all.sort_by(|a, b| a.id.cmp(&b.id));
        let mut duplicate_ids = BTreeSet::new();
        for pair in all.windows(2) {
            if let [a, b] = pair
                && a.id == b.id
            {
                duplicate_ids.insert(a.id.clone());
            }
        }
        let fields: Vec<&Field> = all
            .into_iter()
            .filter(|f| !duplicate_ids.contains(&f.id))
            .collect();
        let mut plan = Plan {
            keys: fields
                .iter()
                .map(|f| f.label.as_ref().map(|l| label_key(l.as_str())))
                .collect(),
            fields,
            issues: duplicate_ids
                .iter()
                .map(|id| Issue {
                    field_id: id.clone(),
                    error: FieldError::DuplicateId,
                })
                .collect(),
            duplicate_ids,
            parents: Vec::new(),
            formulas: Vec::new(),
            label_index: BTreeMap::new(),
            label_members: Vec::new(),
            groups: BTreeMap::new(),
            order: Vec::new(),
            cyclic: Vec::new(),
        };
        plan.index_labels();
        plan.check_fields(patterns);
        plan.order();
        plan
    }

    fn index_labels(&mut self) {
        for (i, key) in self.keys.iter().enumerate() {
            let Some(key) = key else { continue };
            let next = self.label_index.len();
            let j = *self.label_index.entry(key.clone()).or_insert(next);
            if j == self.label_members.len() {
                self.label_members.push(Vec::new());
            }
            if let Some(members) = self.label_members.get_mut(j) {
                members.push(i);
            }
        }
    }

    fn check_fields(&mut self, patterns: &mut Patterns) {
        let mut issues = Vec::new();
        for (i, field) in self.fields.iter().enumerate() {
            let mut say = |error: FieldError| {
                issues.push(Issue {
                    field_id: field.id.clone(),
                    error,
                })
            };

            // Formula: only on formula fields; parses; names existing labels.
            let formula = match (field.field_type == FieldType::Formula, &field.formula) {
                (true, Some(f)) => match parse_formula(f.expression().as_str()) {
                    Ok(expr) => match expr
                        .references()
                        .iter()
                        .position(|r| !self.label_index.contains_key(r))
                    {
                        Some(reference) => {
                            say(FormulaError::UnknownLabel { reference }.into());
                            None
                        }
                        None => Some(expr),
                    },
                    Err(e) => {
                        say(e.into());
                        None
                    }
                },
                (false, None) => None,
                _ => {
                    say(FormulaError::Misplaced.into());
                    None
                }
            };
            self.formulas.push(formula);

            // Condition: names an existing label.
            let parent = field.conditional.as_ref().and_then(|c| {
                let found = self
                    .label_index
                    .get(&label_key(c.parent_label.as_str()))
                    .copied();
                if found.is_none() {
                    say(FieldError::UnknownLabel);
                }
                found
            });
            self.parents.push(parent);

            if matches!(
                field.field_type,
                FieldType::RadioGroup | FieldType::Dropdown | FieldType::MultiSelect
            ) && field.options.is_empty()
            {
                say(Invalid::NoOptions.into());
            }
            if let Some(ValidationRule::Regex { pattern }) =
                field.validation.as_ref().map(|v| &v.rule)
                && let Err(e) = patterns.get(pattern.as_str())
            {
                say(e.into());
            }
            if let Some(group) = &field.group {
                let entry = self
                    .groups
                    .entry(group.id.clone())
                    .or_insert((Some(group.rule), Vec::new()));
                if field.field_type != FieldType::Checkbox
                    || entry.0.is_some_and(|r| r != group.rule)
                {
                    entry.0 = None;
                }
                entry.1.push(i);
            }
        }
        for (group, (rule, members)) in &self.groups {
            if rule.is_none()
                && let Some(field) = members.first().and_then(|&i| self.fields.get(i))
            {
                issues.push(Issue {
                    field_id: field.id.clone(),
                    error: FieldError::GroupMismatch {
                        group: group.clone(),
                    },
                });
            }
        }
        self.issues.extend(issues);
    }

    /// Kahn's algorithm over field and label nodes, smallest ready node first.
    fn order(&mut self) {
        let n = self.fields.len();
        let mut field_deps: Vec<usize> = vec![0; n];
        let mut label_deps: Vec<usize> = self.label_members.iter().map(Vec::len).collect();
        // Who waits on each label (fields) and on each field (its label).
        let mut waiting_on_label: Vec<Vec<usize>> = vec![Vec::new(); self.label_members.len()];
        for i in 0..n {
            let mut deps = BTreeSet::new();
            if let Some(Some(p)) = self.parents.get(i) {
                deps.insert(*p);
            }
            if let Some(Some(expr)) = self.formulas.get(i) {
                deps.extend(
                    expr.references()
                        .iter()
                        .filter_map(|r| self.label_index.get(r).copied()),
                );
            }
            if let Some(count) = field_deps.get_mut(i) {
                *count = deps.len();
            }
            for j in deps {
                if let Some(w) = waiting_on_label.get_mut(j) {
                    w.push(i);
                }
            }
        }
        let mut ready: BTreeSet<Node> = BTreeSet::new();
        ready.extend(
            (0..n)
                .filter(|&i| field_deps.get(i) == Some(&0))
                .map(Node::Field),
        );
        ready.extend(
            (0..label_deps.len())
                .filter(|&j| label_deps.get(j) == Some(&0))
                .map(Node::Label),
        );
        let mut done = vec![false; n];
        while let Some(node) = ready.pop_first() {
            self.order.push(node);
            match node {
                Node::Field(i) => {
                    if let Some(d) = done.get_mut(i) {
                        *d = true;
                    }
                    if let Some(j) = self
                        .keys
                        .get(i)
                        .and_then(Option::as_ref)
                        .and_then(|k| self.label_index.get(k))
                        .copied()
                        && let Some(count) = label_deps.get_mut(j)
                    {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            ready.insert(Node::Label(j));
                        }
                    }
                }
                Node::Label(j) => {
                    for &i in waiting_on_label.get(j).map_or(&[][..], Vec::as_slice) {
                        if let Some(count) = field_deps.get_mut(i) {
                            *count = count.saturating_sub(1);
                            if *count == 0 {
                                ready.insert(Node::Field(i));
                            }
                        }
                    }
                }
            }
        }
        self.cyclic = (0..n).filter(|&i| done.get(i) == Some(&false)).collect();
    }
}

#[derive(Debug, Clone, Default)]
struct LabelState {
    visible: bool,
    /// The first visible member (in id order) with a non-empty value.
    source: Option<usize>,
}

struct State<'p, 'f> {
    plan: &'p Plan<'f>,
    visible: Vec<bool>,
    finals: Vec<Option<FieldValue>>,
    /// A formula field's number, kept exact rather than re-read from its text.
    numbers: Vec<Option<Result<Decimal, ErrorValue>>>,
    labels: Vec<LabelState>,
}

impl State<'_, '_> {
    fn set(
        &mut self,
        i: usize,
        value: Option<FieldValue>,
        number: Option<Result<Decimal, ErrorValue>>,
    ) {
        if let Some(slot) = self.finals.get_mut(i) {
            *slot = value;
        }
        if let Some(slot) = self.numbers.get_mut(i) {
            *slot = number;
        }
    }

    fn settle_label(&mut self, j: usize) {
        let members = self
            .plan
            .label_members
            .get(j)
            .map_or(&[][..], Vec::as_slice);
        let visible = members
            .iter()
            .any(|&i| self.visible.get(i).copied().unwrap_or(false));
        let source = members.iter().copied().find(|&i| {
            self.visible.get(i).copied().unwrap_or(false)
                && (matches!(self.numbers.get(i), Some(Some(_)))
                    || self
                        .finals
                        .get(i)
                        .is_some_and(|v| v.as_ref().is_some_and(|v| !v.is_empty())))
        });
        if let Some(state) = self.labels.get_mut(j) {
            *state = LabelState { visible, source };
        }
    }

    fn condition_holds(&self, i: usize) -> bool {
        let Some(field) = self.plan.fields.get(i) else {
            return false;
        };
        let Some(conditional) = &field.conditional else {
            return true;
        };
        let Some(Some(j)) = self.plan.parents.get(i) else {
            return false;
        };
        let Some(label) = self.labels.get(*j) else {
            return false;
        };
        if !label.visible {
            return false;
        }
        let value = label
            .source
            .and_then(|s| self.finals.get(s))
            .and_then(Option::as_ref);
        match &conditional.when {
            Condition::Checked => matches!(value, Some(FieldValue::Checked(true))),
            Condition::Unchecked => !matches!(value, Some(FieldValue::Checked(true))),
            Condition::Any => value.is_some_and(|v| !v.is_empty()),
            Condition::Value(want) => match value {
                Some(FieldValue::Text(t) | FieldValue::Choice(t)) => t == want,
                // A multi-select shows its dependants while the option is among those
                // chosen (ACRO-02).
                Some(FieldValue::Choices(c)) => c.contains(want.as_str()),
                _ => false,
            },
        }
    }

    fn source(&self, label: &str) -> Option<usize> {
        let j = self.plan.label_index.get(label)?;
        self.labels.get(*j)?.source
    }
}

impl Env for State<'_, '_> {
    fn number(&self, label: &str) -> Result<Decimal, ErrorValue> {
        let Some(i) = self.source(label) else {
            return Ok(Decimal::ZERO);
        };
        if let Some(Some(n)) = self.numbers.get(i) {
            return *n;
        }
        let field = self.plan.fields.get(i).ok_or(ErrorValue::NotANumber)?;
        match self.finals.get(i).and_then(Option::as_ref) {
            None => Ok(Decimal::ZERO),
            Some(FieldValue::Checked(b)) => Ok(if *b { Decimal::ONE } else { Decimal::ZERO }),
            Some(FieldValue::Text(t) | FieldValue::Choice(t)) => {
                let rule = match field.validation.as_ref().map(|v| &v.rule) {
                    Some(ValidationRule::Number(r)) => Some(r),
                    _ => None,
                };
                parse_number(t.as_str(), rule).map_err(|_| ErrorValue::NotANumber)
            }
            Some(_) => Err(ErrorValue::NotANumber),
        }
    }

    fn date(&self, label: &str) -> Result<i64, ErrorValue> {
        let i = self.source(label).ok_or(ErrorValue::NotADate)?;
        let field = self.plan.fields.get(i).ok_or(ErrorValue::NotADate)?;
        match self.finals.get(i).and_then(Option::as_ref) {
            Some(FieldValue::Text(t)) => parse_date(t.as_str(), date_format(field))
                .ok()
                .and_then(crate::parse::CivilDate::day_number)
                .ok_or(ErrorValue::NotADate),
            _ => Err(ErrorValue::NotADate),
        }
    }
}
