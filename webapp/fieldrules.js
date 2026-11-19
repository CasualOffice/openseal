// The mock server's stand-in for the engine's field rules (VS-04C): what
// `casual_sign_fields::evaluate_envelope` answers for a signing view's `rules`, for mock
// mode only. The real server runs the engine itself and the signing page never runs
// this: it applies whatever `rules` the server sends. Kept small and close to docs/30 §6
// (conditions, same-recipient linked labels, formulas with + - * / ( ) and comparisons,
// IF, SUM, MIN, MAX, ROUND, ABS; an empty or hidden reference counts as 0; results at
// the formula's precision, half away from zero) and to docs/22 §6 group rules. Numbers
// here are JavaScript numbers, not the engine's decimals: the mock is not evidence.

const key = (label) => String(label || "").normalize("NFC");

/// Whether a value counts as given.
function present(v) {
  if (!v) return false;
  if (typeof v.checked === "boolean") return v.checked;
  if (Array.isArray(v.choices)) return v.choices.length > 0;
  for (const k of ["text", "choice", "signature", "attachment"]) if (typeof v[k] === "string") return v[k] !== "";
  return false;
}

function holds(when, v) {
  if (when === "checked") return v?.checked === true;
  if (when === "unchecked") return v?.checked !== true;
  if (when === "any") return present(v);
  if (when && typeof when === "object" && "value" in when) {
    const want = String(when.value);
    if (Array.isArray(v?.choices)) return v.choices.includes(want);
    return (v?.choice ?? v?.text) === want;
  }
  return false;
}

// ---- Formulas --------------------------------------------------------------------------

function tokens(src) {
  const out = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (/\s/.test(c)) { i++; continue; }
    if (/[0-9.]/.test(c)) { let j = i; while (j < src.length && /[0-9.]/.test(src[j])) j++; out.push({ t: "num", v: Number(src.slice(i, j)) }); i = j; continue; }
    if (c === "[") { const j = src.indexOf("]", i); if (j < 0) throw new Error("syntax"); out.push({ t: "id", v: src.slice(i + 1, j) }); i = j + 1; continue; }
    if (/[\p{L}_]/u.test(c)) { let j = i; while (j < src.length && /[\p{L}\p{N}_]/u.test(src[j])) j++; out.push({ t: "id", v: src.slice(i, j) }); i = j; continue; }
    const two = src.slice(i, i + 2);
    if (["<=", ">=", "<>", "!=", "=="].includes(two)) { out.push({ t: "op", v: two }); i += 2; continue; }
    if ("+-*/(),<>=".includes(c)) { out.push({ t: "op", v: c }); i++; continue; }
    throw new Error("syntax");
  }
  return out;
}

function evaluateFormula(src, lookup) {
  const ts = tokens(String(src || ""));
  let p = 0;
  const peek = () => ts[p];
  const eat = (v) => { if (ts[p]?.v === v) { p++; return true; } return false; };
  const need = (v) => { if (!eat(v)) throw new Error("syntax"); };
  function args() { need("("); const a = [cmp()]; while (eat(",")) a.push(cmp()); need(")"); return a; }
  function atom() {
    const tk = ts[p++];
    if (!tk) throw new Error("syntax");
    if (tk.t === "num") return tk.v;
    if (tk.v === "(") { const v = cmp(); need(")"); return v; }
    if (tk.v === "-") return -atom();
    if (tk.v === "+") return atom();
    if (tk.t === "id") {
      const name = tk.v.toUpperCase();
      if (peek()?.v === "(") {
        const a = args();
        if (name === "IF") return a[0] ? a[1] : a[2];
        if (name === "SUM") return a.reduce((x, y) => x + y, 0);
        if (name === "MIN") return Math.min(...a);
        if (name === "MAX") return Math.max(...a);
        if (name === "ABS") return Math.abs(a[0]);
        if (name === "ROUND") return round(a[0], a[1] ?? 0);
        throw new Error("syntax");
      }
      return lookup(tk.v);
    }
    throw new Error("syntax");
  }
  function mul() { let v = atom(); for (;;) { if (eat("*")) v *= atom(); else if (eat("/")) { const d = atom(); if (d === 0) throw new Error("DivisionByZero"); v /= d; } else return v; } }
  function add() { let v = mul(); for (;;) { if (eat("+")) v += mul(); else if (eat("-")) v -= mul(); else return v; } }
  function cmp() {
    const a = add();
    const op = peek()?.v;
    if (!["<", ">", "<=", ">=", "=", "==", "<>", "!="].includes(op)) return a;
    p++;
    const b = add();
    return ({ "<": a < b, ">": a > b, "<=": a <= b, ">=": a >= b, "=": a === b, "==": a === b, "<>": a !== b, "!=": a !== b })[op] ? 1 : 0;
  }
  const v = cmp();
  if (p !== ts.length) throw new Error("syntax");
  return v;
}

function round(x, places) {
  const f = 10 ** places;
  return (Math.sign(x) * Math.round(Math.abs(x) * f)) / f;
}

/// The view's `rules` for recipient `rid` over every field of the envelope, as the
/// engine answers: `{hidden, computed, values}` (see the top of this file).
export function rulesFor(fields, rid) {
  const list = fields || [];
  // Linked: one recipient, one label, one value (the first given, in id order).
  const linked = new Map();
  for (const f of [...list].sort((a, b) => String(a.id).localeCompare(String(b.id)))) {
    if (!f.label || f.type === "formula" || !present(f.value)) continue;
    const k = `${f.recipient_id}\n${key(f.label)}`;
    if (!linked.has(k)) linked.set(k, f.value);
  }
  const valueOf = (f) => (f.type === "formula" ? null : f.value || linked.get(`${f.recipient_id}\n${key(f.label)}`) || f.default || null);
  const byLabel = new Map();
  for (const f of list) if (f.label) { const k = key(f.label); if (!byLabel.has(k)) byLabel.set(k, []); byLabel.get(k).push(f); }
  // Visibility, to a fixed point (conditions may chain).
  const hidden = new Set();
  for (let pass = 0; pass < 8; pass++) {
    let changed = false;
    for (const f of list) {
      if (!f.conditional) continue;
      const parents = byLabel.get(key(f.conditional.parent_label)) || [];
      const shown = parents.some((q) => !hidden.has(q.id) && holds(f.conditional.when, valueOf(q)));
      if (!shown !== hidden.has(f.id)) { if (shown) hidden.delete(f.id); else hidden.add(f.id); changed = true; }
    }
    if (!changed) break;
  }
  const computed = {};
  const lookup = (label) => {
    const fs = (byLabel.get(key(label)) || []).filter((q) => !hidden.has(q.id));
    let total = 0;
    for (const q of fs) {
      if (q.type === "formula") continue;
      const v = valueOf(q);
      const n = Number(v?.text ?? (v?.checked ? 1 : 0));
      total += Number.isFinite(n) ? n : 0;
    }
    return total;
  };
  for (const f of list) {
    if (f.type !== "formula" || f.recipient_id !== rid || hidden.has(f.id) || !f.formula) continue;
    try {
      computed[f.id] = { ok: round(evaluateFormula(f.formula.expression, lookup), f.formula.precision || 0).toFixed(f.formula.precision || 0) };
    } catch (e) { computed[f.id] = { error: e.message === "DivisionByZero" ? "DivisionByZero" : "NotANumber" }; }
  }
  const values = {};
  for (const f of list) {
    if (f.recipient_id !== rid || f.type === "formula" || hidden.has(f.id)) continue;
    const v = valueOf(f);
    if (v && JSON.stringify(v) !== JSON.stringify(f.value || null)) values[f.id] = v;
  }
  return { hidden: list.filter((f) => f.recipient_id === rid && hidden.has(f.id)).map((f) => f.id), computed, values };
}

/// The problems finishing would meet on recipient `rid`'s fields, as `{pointer, code}`:
/// a required field a condition shows and nobody filled, and a checkbox group whose rule
/// does not hold.
export function finishProblems(fields, rid) {
  const rules = rulesFor(fields, rid);
  const mine = (fields || []).filter((f) => f.recipient_id === rid && !rules.hidden.includes(f.id));
  const out = [];
  for (const f of mine) {
    const v = f.value || rules.values[f.id];
    if (f.required && f.conditional && !present(v)) out.push({ pointer: `/fields/${f.id}`, code: "CS-FLD-0001" });
  }
  const groups = new Map();
  for (const f of mine) if (f.type === "checkbox" && f.group?.id) { if (!groups.has(f.group.id)) groups.set(f.group.id, []); groups.get(f.group.id).push(f); }
  for (const members of groups.values()) {
    const n = members.filter((f) => f.value?.checked === true).length;
    const r = members[0].group.rule || {};
    const ok = r.rule === "select_at_least" ? n >= r.min : r.rule === "select_at_most" ? n <= r.max : r.rule === "select_exactly" ? n === r.count : r.rule === "select_range" ? n >= r.min && n <= r.max : true;
    if (!ok) for (const f of members) out.push({ pointer: `/fields/${f.id}`, code: "CS-FLD-0003" });
  }
  return out;
}
