// The signer's field kinds (WEB-06; docs/40 "Field types end to end"): which fields the
// recipient fills, what counts as filled, and the inline check of a typed value before
// it goes to the server. The server's engine (casual-sign-fields `validate`) stays the
// authority: it checks every fill and again at finish; this only says the problem early,
// in the same terms. Pure functions, for tests.

/// Types a recipient fills when the sender has not locked them: every engine kind
/// that takes input but payment (slice 13; VS-04A).
export const FILLABLE = new Set(["signature", "initials", "text", "checkbox", "company", "title", "number", "radio_group", "dropdown", "attachment",
  "date", "email_address", "phone", "ssn", "zip", "multi_select", "stamp", "drawing"]);
/// Typed as text: a value `{text}`.
export const TYPED = new Set(["text", "company", "title", "number", "date", "email_address", "phone", "ssn", "zip"]);
/// An image the signer adopts for this kind of field (VS-04A), by how it is made; the
/// server records it under the field's own kind (`mark: stamp | drawing`).
export const IMAGED = Object.freeze({ stamp: "upload", drawing: "draw" });
/// Buttons that act for the signer: approve finishes, decline declines (DocuSign's
/// Approve and Decline tabs; VS-04A).
export const BUTTONS = new Set(["approve", "decline"]);
/// Chosen from the sender's options: a value `{choice}`.
export const CHOSEN = new Set(["radio_group", "dropdown"]);

/// Read-only or sender-locked: shown with the sender's value, never changed here.
export function isFixed(f) {
  return f?.type === "note" || f?.type === "hyperlink" || f?.read_only === true || f?.locked === true;
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
  if (f.type === "multi_select") return Array.isArray(v.choices) && v.choices.length > 0;
  if (f.type === "attachment") return typeof v.attachment === "string" && v.attachment !== "";
  return !!v.signature;
}

// ---- The server's rules on the page (VS-04C) -------------------------------------------
// The signing view carries `rules`, the server's own evaluation of this recipient's
// fields (casual-sign-fields `evaluate_envelope`, as at finish and sealing): `hidden`
// ids, `computed` formula results (`{ok}` or `{error}`), and `values` a field will be
// sealed with where it is not the one stored (a linked field's). The page applies them;
// it never decides them.

/// Whether `rules` hide field `f` (a hidden field is neither shown nor required).
export function isHidden(f, rules) {
  return Array.isArray(rules?.hidden) && rules.hidden.includes(f?.id);
}

/// The value field `f` is sealed with: what this signer gave, else what the rules say
/// it mirrors (a linked field), else null.
export function effectiveValue(f, given, rules) {
  return given || rules?.values?.[f?.id] || null;
}

/// A formula field's result as shown: `{text}`, or `{error}` with the error value's
/// name, or null while the server has none.
export function computedOf(f, rules) {
  const c = rules?.computed?.[f?.id];
  if (!c) return null;
  if (typeof c.ok === "string") return { text: c.ok };
  return { error: String(c.error || "") };
}

/// A hyperlink's address when a page may open it: `http:` or `https:` only, so a
/// `javascript:` or `data:` value is shown as text and never followed.
export function safeHref(text) {
  try {
    const u = new URL(String(text || "").trim());
    return u.protocol === "http:" || u.protocol === "https:" ? u.href : null;
  } catch { return null; }
}

/// The engine's date formats (casual-sign-model `DateFormat`) as the pattern a signer
/// types, for the placeholder and the message.
export const DATE_PATTERNS = Object.freeze({ yyyy_mm_dd: "YYYY-MM-DD", mm_dd_yyyy: "MM/DD/YYYY", dd_mm_yyyy: "DD/MM/YYYY", dd_mm_yyyy_dot: "DD.MM.YYYY", d_mmm_yyyy: "D MMM YYYY" });
const MONTHS = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];

/// The format a date field's value is read in, as the engine's `date_format`: its date
/// rule's, else its display format's, else ISO.
export function dateFormatOf(f) {
  if (f?.validation?.kind === "date" && DATE_PATTERNS[f.validation.format]) return f.validation.format;
  if (DATE_PATTERNS[f?.format?.date_format]) return f.format.date_format;
  return "yyyy_mm_dd";
}

/// Whether `text` is a real calendar date in `format`, as the engine's `parse_date`.
export function isDate(text, format = "yyyy_mm_dd") {
  const s = String(text).trim();
  const fixed = (x, n) => (x.length === n && /^[0-9]+$/.test(x) ? Number(x) : NaN);
  const short = (x) => (/^[0-9]{1,2}$/.test(x) ? Number(x) : NaN);
  const sep = { yyyy_mm_dd: "-", mm_dd_yyyy: "/", dd_mm_yyyy: "/", dd_mm_yyyy_dot: ".", d_mmm_yyyy: " " }[format];
  if (!sep) return false;
  const a = s.split(sep);
  if (a.length !== 3) return false;
  let y; let m; let d;
  if (format === "yyyy_mm_dd") [y, m, d] = [fixed(a[0], 4), fixed(a[1], 2), fixed(a[2], 2)];
  else if (format === "mm_dd_yyyy") [m, d, y] = [short(a[0]), short(a[1]), fixed(a[2], 4)];
  else if (format === "d_mmm_yyyy") [d, m, y] = [short(a[0]), MONTHS.indexOf(a[1].toLowerCase()) + 1 || NaN, fixed(a[2], 4)];
  else [d, m, y] = [short(a[0]), short(a[1]), fixed(a[2], 4)];
  if (![y, m, d].every(Number.isInteger) || y < 1 || m < 1 || m > 12 || d < 1) return false;
  const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
  return d <= [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1];
}

/// A US social security number as the engine's `is_ssn`: nine digits, or 3-2-4 with
/// dashes; the area not 000, 666 or 900 to 999, the group not 00, the serial not 0000.
export function isSsn(text) {
  const s = String(text);
  let plain;
  if (s.length === 11 && s[3] === "-" && s[6] === "-") plain = s.replaceAll("-", "");
  else if (s.length === 9) plain = s;
  else return false;
  if (!/^[0-9]{9}$/.test(plain)) return false;
  const area = Number(plain.slice(0, 3));
  return area !== 0 && area !== 666 && area < 900 && plain.slice(3, 5) !== "00" && plain.slice(5) !== "0000";
}

/// The rule a field's text is checked against, as the engine's `rule_for`: its own,
/// else the one its type implies.
export function ruleFor(f) {
  if (f?.validation) return f.validation;
  switch (f?.type) {
    case "number": return { kind: "number" };
    case "date": return { kind: "date", format: dateFormatOf(f) };
    case "email_address": return { kind: "email" };
    case "phone": return { kind: "phone" };
    case "ssn": return { kind: "ssn" };
    case "zip": return { kind: "zip" };
    default: return null;
  }
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
  const rule = ruleFor(f);
  if (!rule) return null;
  const problem = checkRule(rule, s);
  // The sender's own message replaces the default one (docs/22 §6 `validation.message`).
  if (problem && typeof rule.message === "string" && rule.message) return { key: "sign.check.custom", vars: { message: rule.message } };
  return problem;
}

function checkRule(rule, s) {
  switch (rule.kind) {
    case "ssn": return isSsn(s) ? null : { key: "sign.check.ssn" };
    case "date": {
      const format = DATE_PATTERNS[rule.format] ? rule.format : "yyyy_mm_dd";
      return isDate(s, format) ? null : { key: "sign.check.date", vars: { format: DATE_PATTERNS[format] } };
    }
    case "regex": {
      // The engine matches the whole value with the `regex` crate; a pattern this
      // browser cannot compile is left to the server, never guessed at.
      let re = null;
      try { re = new RegExp(`^(?:${rule.pattern})$`, "u"); } catch { re = null; }
      return !re || re.test(s) ? null : { key: "sign.check.pattern" };
    }
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
  const k = ruleFor(f)?.kind || "";
  if (k === "ssn") return "numeric";
  if (k === "date") return dateFormatOf(f) === "d_mmm_yyyy" ? "text" : "numeric";
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
  if (CHOSEN.has(f.type) || f.type === "multi_select") return { key: "sign.guide.choose", vars: { label } };
  if (f.type === "stamp") return { key: "sign.guide.stamp", vars: { label } };
  if (f.type === "drawing") return { key: "sign.guide.draw", vars: { label } };
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

/// A name as first and last name, as the server's engine fills `first_name` and
/// `last_name` at finish (`FG-055`, docs/24 §5): the first word, and everything after it.
/// "Ludwig van Beethoven" → {first: "Ludwig", last: "van Beethoven"}; one word has no last.
export function nameParts(name) {
  const s = String(name || "").replace(LEAD_WS, "").replace(TRAIL_WS, "");
  const at = s.search(WS);
  return at < 0 ? { first: s, last: "" } : { first: s.slice(0, at), last: s.slice(at).replace(LEAD_WS, "") };
}

// Unicode White_Space, as Rust's `char::is_whitespace` and `str::trim` (the engine's
// `split_name`): JavaScript's `\s` and `trim` also take U+FEFF and leave U+0085.
const WS_CLASS = "[\\t\\n\\v\\f\\r \\u0085\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]";
const WS = new RegExp(WS_CLASS);
const LEAD_WS = new RegExp(`^${WS_CLASS}+`);
const TRAIL_WS = new RegExp(`${WS_CLASS}+$`);

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

/// Where the signing page keeps the link while the signer signs in at an identity
/// provider (`sso`, RAUTH-01): the provider sends the browser back to one fixed address
/// (`/s/oidc`), which cannot carry the link. Only the tab's session storage holds it, and
/// only until the page comes back.
export const SSO_KEY = "openseal.sign.sso";

/// The return from an identity provider: `{token, state, code}` when `loc` is the
/// redirect back (`state`, and `code` or `error`, in the query) and this tab started a
/// sign-in (the link in `storage`); `null` otherwise. Takes the link out of `storage`.
export function ssoReturn(loc, storage) {
  const q = new URLSearchParams(loc.search);
  if (!q.get("state") || !(q.has("code") || q.has("error"))) return null;
  let saved = null;
  try { saved = storage?.getItem(SSO_KEY) || null; storage?.removeItem(SSO_KEY); } catch { saved = null; }
  if (!saved) return null;
  return { token: saved, state: q.get("state"), code: q.get("code") || "" };
}

/// Where the signing page keeps the link while the signer is at their remote signing
/// provider (RSP-01): the provider sends the browser back to `/s/rsp`, which cannot
/// carry the link.
export const RSP_KEY = "openseal.sign.rsp";

/// The return from a remote signing provider: `{token, state, code, error}` when `loc`
/// is `/s/rsp` with `state` in the query and this tab started a session (the link in
/// `storage`); `null` otherwise. Takes the link out of `storage`.
export function rspReturn(loc, storage) {
  if (!/^\/s\/rsp\/?$/.test(loc.pathname)) return null;
  const q = new URLSearchParams(loc.search);
  if (!q.get("state")) return null;
  let saved = null;
  try { saved = storage?.getItem(RSP_KEY) || null; storage?.removeItem(RSP_KEY); } catch { saved = null; }
  if (!saved) return null;
  return { token: saved, state: q.get("state"), code: q.get("code") || null, error: q.get("error") || null };
}
