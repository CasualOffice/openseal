// The editor's field logic (VS-04C; docs/22 §6): a field's condition, checkbox group and
// formula as the engine's `Field` members take them, from what the sender chose in the
// panel. Pure, for tests. The engine checks them again at send (`check_for_send`:
// labels exist, groups agree, formulas parse, no cycle) and refuses with `CS-FLD-*`.

/// The engine's date formats (casual-sign-model `DateFormat`) with the pattern shown.
export const DATE_FORMATS = Object.freeze([
  ["yyyy_mm_dd", "YYYY-MM-DD"], ["mm_dd_yyyy", "MM/DD/YYYY"], ["dd_mm_yyyy", "DD/MM/YYYY"],
  ["dd_mm_yyyy_dot", "DD.MM.YYYY"], ["d_mmm_yyyy", "D MMM YYYY"],
]);

/// The data labels a field may depend on: every other field's label, once each, sorted.
export function labelsFor(fields, selfKey) {
  const out = new Set();
  for (const f of fields || []) if (f.key !== selfKey && typeof f.label === "string" && f.label.trim()) out.add(f.label.trim());
  return [...out].sort((a, b) => a.localeCompare(b));
}

/// `conditional` `{parent_label, when}`: `when` "checked" | "unchecked" | "any", or
/// "value" with `value` (`{value}`); null for none (no parent, or a value left blank).
export function conditionFrom(parent, when, value = "") {
  const p = String(parent || "").trim();
  if (!p) return null;
  if (when === "value") {
    const v = String(value ?? "");
    return v ? { parent_label: p, when: { value: v } } : null;
  }
  return { parent_label: p, when: ["checked", "unchecked", "any"].includes(when) ? when : "checked" };
}

/// `group` `{id, rule: {rule, min|max|count}}` for a checkbox group, or null for none.
/// `n` is a whole number from 0 (a count the sender typed).
export function groupFrom(id, rule, n) {
  const g = String(id || "").trim();
  if (!g) return null;
  const k = Number.parseInt(String(n), 10);
  const count = Number.isInteger(k) && k >= 0 ? k : 1;
  if (rule === "select_at_most") return { id: g, rule: { rule, max: count } };
  if (rule === "select_exactly") return { id: g, rule: { rule, count } };
  return { id: g, rule: { rule: "select_at_least", min: count } };
}

/// `formula` `{expression, precision}` (precision 0 to 15, default 2), or null when
/// the expression is blank.
export function formulaFrom(expression, precision) {
  const e = String(expression || "").trim();
  if (!e) return null;
  const p = Number.parseInt(String(precision), 10);
  return { expression: e, precision: Number.isInteger(p) && p >= 0 && p <= 15 ? p : 2 };
}
