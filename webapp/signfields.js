// The signer's field kinds (WEB-06; docs/40 "Field types end to end"): which fields the
// recipient fills, what counts as filled, and the inline check of a typed value before
// it goes to the server. The server's engine (casual-sign-fields `validate`) stays the
// authority: it checks every fill and again at finish; this only says the problem early,
// in the same terms. Pure functions, for tests.

/// Types a recipient fills when the sender has not locked them.
export const FILLABLE = new Set(["signature", "initials", "text", "checkbox", "company", "title", "number", "radio_group", "dropdown", "attachment"]);
/// Typed as text: a value `{text}`.
export const TYPED = new Set(["text", "company", "title", "number"]);
/// Chosen from the sender's options: a value `{choice}`.
export const CHOSEN = new Set(["radio_group", "dropdown"]);

/// Read-only or sender-locked: shown with the sender's value, never changed here.
export function isFixed(f) {
  return f?.type === "note" || f?.read_only === true || f?.locked === true;
}

/// Whether the recipient fills field `f`.
export function fills(f) {
  return FILLABLE.has(f?.type) && !isFixed(f);
}

/// Whether value `v` fills field `f` (a required checkbox must be ticked).
export function isFilled(f, v) {
  if (!v) return false;
  if (f.type === "checkbox") return v.checked === true || !f.required;
  if (TYPED.has(f.type)) return typeof v.text === "string" && v.text.trim() !== "";
  if (CHOSEN.has(f.type)) return typeof v.choice === "string" && v.choice !== "";
  if (f.type === "attachment") return typeof v.attachment === "string" && v.attachment !== "";
  return !!v.signature;
}

const EMAIL = /^[^\s@]{1,64}@(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;

/// A phone number: an optional leading +, then digits with spaces, dashes, dots and
/// at most one pair of brackets; 7 to 15 digits.
export function isPhone(text) {
  const s = String(text).trim();
  const rest = s.startsWith("+") ? s.slice(1) : s;
  if (!/^[0-9 ().-]+$/.test(rest)) return false;
  const opens = (rest.match(/\(/g) || []).length;
  const closes = (rest.match(/\)/g) || []).length;
  if (opens !== closes || opens > 1) return false;
  const digits = (rest.match(/[0-9]/g) || []).length;
  return digits >= 7 && digits <= 15;
}

/// A US ZIP code: 5 digits, 9 digits, or 5-4.
export function isZip(text) {
  return /^(?:\d{5}|\d{9}|\d{5}-\d{4})$/.test(String(text));
}

/// The problem with typing `text` into field `f`, as `{key, vars}` for i18n, or null.
/// An empty value passes (whether one is needed is `required`'s business).
export function checkText(f, text) {
  const s = String(text ?? "");
  if (s === "") return null;
  const rule = f.validation || (f.type === "number" ? { kind: "number" } : null);
  if (!rule) return null;
  switch (rule.kind) {
    case "email": return EMAIL.test(s) ? null : { key: "sign.check.email" };
    case "phone": return isPhone(s) ? null : { key: "sign.check.phone" };
    case "zip": return isZip(s) ? null : { key: "sign.check.zip" };
    case "length": {
      const n = [...s].length;
      if (Number.isFinite(Number(rule.max)) && n > Number(rule.max)) return { key: "sign.check.max-length", vars: { n: Number(rule.max) } };
      if (Number.isFinite(Number(rule.min)) && n < Number(rule.min)) return { key: "sign.check.min-length", vars: { n: Number(rule.min) } };
      return null;
    }
    case "number": {
      if (!/^-?\d+(?:\.\d+)?$/.test(s.trim())) return { key: "sign.check.number" };
      const decimals = Number.isInteger(rule.decimals) ? rule.decimals : null;
      const frac = (s.trim().split(".")[1] || "").length;
      if (decimals != null && frac > decimals) return decimals === 0 ? { key: "sign.check.whole" } : { key: "sign.check.decimals", vars: { n: decimals } };
      const x = Number(s);
      const min = rule.min != null && rule.min !== "" ? Number(rule.min) : null;
      const max = rule.max != null && rule.max !== "" ? Number(rule.max) : null;
      if (min != null && max != null && (x < min || x > max)) return { key: "sign.check.between", vars: { min: rule.min, max: rule.max } };
      if (min != null && x < min) return { key: "sign.check.at-least", vars: { min: rule.min } };
      if (max != null && x > max) return { key: "sign.check.at-most", vars: { max: rule.max } };
      return null;
    }
    default: return null;
  }
}

/// The sender's value of a fixed field, as text.
export function fixedText(f) {
  const v = f?.value;
  if (!v) return "";
  if (typeof v.text === "string") return v.text;
  if (typeof v.choice === "string") return v.choice;
  if (typeof v.checked === "boolean") return v.checked ? "✓" : "";
  return "";
}

/// The input mode a phone keyboard should open with for field `f`.
export function inputModeFor(f) {
  const k = f.validation?.kind || (f.type === "number" ? "number" : "");
  if (k === "number") return Number.isInteger(f.validation?.decimals) && f.validation.decimals === 0 ? "numeric" : "decimal";
  if (k === "email") return "email";
  if (k === "phone") return "tel";
  if (k === "zip") return "numeric";
  return "text";
}

// ---- The ceremony's model (WEB-18; docs/47 §As built: signing ceremony) ------------------
// What the guide bar, the page rail, the secure-open loader, the header and the receipt
// show, as pure functions of the ceremony's state; sign.js renders from them. Words are
// returned as `{key, vars}` for i18n, never as text.

/// The words for doing field `f` next, as the guide bar's title. `label`: the field's
/// own label or its kind's name, as the page shows it.
export function nextAction(f, label = "") {
  if (!f) return { key: "sign.guide.all-done" };
  if (f.type === "signature") return { key: "sign.guide.sign" };
  if (f.type === "initials") return { key: "sign.guide.initial", vars: { n: f.p?.page ?? f.page ?? 1 } };
  if (f.type === "checkbox") return { key: "sign.guide.tick", vars: { label } };
  if (f.type === "attachment") return { key: "sign.guide.attach", vars: { label } };
  if (CHOSEN.has(f.type)) return { key: "sign.guide.choose", vars: { label } };
  return { key: "sign.guide.fill", vars: { label } };
}

/// The guide bar's state: `total` required fields, `left` of them still to do, whether
/// the signer has `started` (filled anything), and the `next` field with its `label`.
/// `cta` is "start", "next" or "finish"; `fraction` is the share done (1 with nothing
/// required, so the ring is full and Finish shows).
export function guideState({ total, left, started, next = null, label = "" }) {
  const all = Math.max(0, total | 0);
  const l = Math.min(all, Math.max(0, left | 0));
  const ready = l === 0;
  return {
    done: all - l,
    total: all,
    ready,
    fraction: all ? (all - l) / all : 1,
    cta: ready ? "finish" : started ? "next" : "start",
    title: ready ? { key: all ? "sign.guide.all-done" : "sign.guide.nothing" } : nextAction(next, label),
    sub: ready ? { key: "sign.guide.review" } : { key: l === 1 ? "sign.finish-reason-one" : "sign.finish-reason", vars: { n: l } },
  };
}

/// The progress ring's `stroke-dasharray` for a circle of radius `r` filled to
/// `fraction` (0 to 1).
export function ringDash(fraction, r = 15) {
  const c = 2 * Math.PI * r;
  const f = Math.min(1, Math.max(0, Number(fraction) || 0));
  return `${(c * f).toFixed(1)} ${c.toFixed(1)}`;
}

/// The secure-open loader's steps. `reached`: how many real steps have finished (1 the
/// signing session was opened, 2 the document bytes arrived, 3 the first page was
/// drawn); `pages`: the page count when the view gives it. Each step is `done`,
/// `active` or `todo`. No step claims a check the page does not make.
export function loaderSteps(reached, pages = null) {
  const n = Number.isInteger(pages) && pages > 0 ? pages : null;
  const steps = [
    { key: "sign.loader.link" },
    { key: "sign.loader.document" },
    n ? { key: n === 1 ? "sign.loader.page" : "sign.loader.pages", vars: { n } } : { key: "sign.loader.pages-unknown" },
  ];
  const r = Math.max(0, reached | 0);
  return steps.map((s, i) => ({ ...s, state: i < r ? "done" : i === r ? "active" : "todo" }));
}

/// Required fields still to do on each page: `pages` `[{key, n}]` (a document id and a
/// page number), `left` `[{document_id, p: {page}}]`. Answers a count per page.
export function pageCounts(pages, left) {
  return pages.map((pg) => left.filter((f) => f.document_id === pg.key && (f.p?.page ?? f.page) === pg.n).length);
}

/// The total page count of `documents` when every one says it, else null.
export function pageTotal(documents) {
  const list = documents || [];
  if (!list.length || !list.every((d) => Number.isInteger(d.pages) && d.pages > 0)) return null;
  return list.reduce((a, d) => a + d.pages, 0);
}

/// The kinds of field this signer filled, in the order first met, once each (the
/// receipt's "Fields" line). `filled(f)` says whether `f` was filled.
export function filledKinds(fields, filled) {
  const out = [];
  for (const f of fields) if (filled(f) && !out.includes(f.type)) out.push(f.type);
  return out;
}

/// "Jordan" from "Jordan Rivera"; "" for none.
export function firstName(name) {
  return String(name || "").trim().split(/\s+/)[0] || "";
}

/// The organisation's two-letter mark ("Acme Corporation" → "AC", "Northwind" → "NO").
export function orgMark(org) {
  const clean = (w) => [...w.replace(/[^\p{L}\p{N}]/gu, "")];
  const words = String(org || "").trim().split(/\s+/).map(clean).filter((w) => w.length);
  if (!words.length) return "";
  const letters = words.length > 1 ? [words[0][0], words[1][0]] : words[0].slice(0, 2);
  return letters.join("").toUpperCase();
}

/// Who asked: "<name> at <org> asked you to sign", or without the organisation when it
/// is missing or the same; null when the view names no sender (never a guess).
export function askLine(sender) {
  const who = sender?.name || sender?.email || "";
  if (!who) return null;
  const org = sender?.organisation && sender.organisation !== who ? sender.organisation : "";
  return org ? { key: "sign.ask.org", vars: { name: who, org } } : { key: "sign.ask", vars: { name: who } };
}

/// The date-signed field: the date once a signature or initials field holds a mark,
/// else the words saying it fills itself in.
export function dateField(signedAny, date) {
  return signedAny ? { key: "sign.date.on", vars: { date } } : { key: "sign.date.pending" };
}

/// The phone header's two segments: the fields done, then finished.
export function phoneSegments(ready, finished) {
  return [!!ready || !!finished, !!finished];
}

/// What finishing meant for this recipient type (RTE-02): the receipt never says
/// "signed" to someone who did not sign.
export function actedAs(type) {
  if (type === "approver") return "approved";
  if (type === "viewer") return "viewed";
  if (type === "agent" || type === "intermediary") return "finished";
  return "signed";
}
