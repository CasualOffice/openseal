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
