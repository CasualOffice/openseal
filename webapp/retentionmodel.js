// Retention rules (ASVS-18; docs/40 §3 `/retention`): the pure part of Admin › Retention.
// A rule is a number of whole days, or null for "kept for ever" (the server's default).
// Tested in tests/retention.test.mjs.

/// The data classes, in the order the page and the API list them.
export const CLASSES = Object.freeze(["draft", "ended", "completed", "sessions"]);

/// The days typed in a rule's field: `{ok: true, days}` with `days` null for an empty
/// field, or `{ok: false}` for anything but whole days from 1 to `max`.
export function parseDays(text, max = 36500) {
  const s = String(text ?? "").trim();
  if (!s) return { ok: true, days: null };
  if (!/^[0-9]{1,6}$/.test(s)) return { ok: false };
  const n = Number(s);
  return n >= 1 && n <= max ? { ok: true, days: n } : { ok: false };
}

/// The field text a stored rule shows.
export function daysText(days) {
  return Number.isInteger(days) ? String(days) : "";
}

/// What to send: the classes whose typed value differs from the stored rules, as
/// `{class: days | null}`; `{bad: [class…]}` when any field is not whole days.
export function rulesPatch(stored, typed, max = 36500) {
  const patch = {};
  const bad = [];
  for (const c of CLASSES) {
    const p = parseDays(typed[c], max);
    if (!p.ok) { bad.push(c); continue; }
    if ((stored?.[c] ?? null) !== p.days) patch[c] = p.days;
  }
  return bad.length ? { bad } : { patch };
}

/// The dry run as lines to show: `[{key, n}]` for each envelope class, then sessions and
/// held.
export function previewLines(p) {
  const out = CLASSES.filter((c) => c !== "sessions").map((c) => ({ key: c, n: Number(p?.counts?.[c] ?? 0) }));
  out.push({ key: "sessions", n: Number(p?.sessions ?? 0) });
  out.push({ key: "held", n: Number(p?.held ?? 0) });
  return out;
}
