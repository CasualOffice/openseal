// Field geometry for the editor and the signing page (WEB-01).
//
// ADR-019: a field's placement is in the page's *displayed* space — after the page's
// /Rotate — in PDF points, origin top-left, y down. pdf.js's viewport at scale 1 with
// the page's own rotation is exactly that space, so screen ↔ points is one scale
// factor and nothing else. The engine (casual-sign-model `Placement`) refuses page 0,
// a zero width or height, a negative coordinate, and anything past 14 400 points;
// these functions never produce one.
//
// Pure: no DOM, so `tests/geometry.test.mjs` runs it under Node.

/// The engine's largest coordinate (casual-sign-model limits: `MAX_POINTS`).
export const MAX_POINTS = 14400;
/// The smallest field the editor makes, in points, so it stays a usable target.
export const MIN_SIZE = 8;

/// Default size per field type, in points (DocuSign's and SignNow's proportions).
export const DEFAULT_SIZE = {
  signature: { width: 160, height: 44 },
  initials: { width: 64, height: 44 },
  date_signed: { width: 110, height: 22 },
  text: { width: 160, height: 22 },
  checkbox: { width: 16, height: 16 },
  name: { width: 160, height: 22 },
  email: { width: 190, height: 22 },
  company: { width: 160, height: 22 },
  title: { width: 160, height: 22 },
  number: { width: 100, height: 22 },
  radio_group: { width: 120, height: 60 },
  dropdown: { width: 140, height: 22 },
  attachment: { width: 140, height: 30 },
  note: { width: 180, height: 44 },
};

/// The field types the editor places, in palette order (wire names of casual-sign-model
/// `FieldType`): every type the ceremony fills or shows and the flattener draws
/// (api.js `FIELD_TYPES_READY`, UX-05).
export const FIELD_TYPES = ["signature", "initials", "date_signed", "name", "email", "company", "title", "text", "number", "checkbox", "radio_group", "dropdown", "attachment", "note"];

/// The palette's groups (UX-05, as DocuSign's "Standard fields" and SignNow's tool
/// groups): signing, what the recipient's details fill, and what they type or choose.
export const FIELD_GROUPS = [
  ["sign", ["signature", "initials", "date_signed"]],
  ["auto", ["name", "email", "company", "title"]],
  ["input", ["text", "number", "checkbox", "radio_group", "dropdown", "attachment", "note"]],
];

/// Types the recipient fills (signfields.js `FILLABLE`); the others are stamped by the
/// server, filled from the recipient, or (a note) shown as the sender wrote it.
const FILLED = new Set(["signature", "initials", "text", "checkbox", "company", "title", "number", "radio_group", "dropdown", "attachment"]);
export function takesInput(type) {
  return FILLED.has(type);
}

/// Types a new field is required by default (UX-05: DocuSign and SignNow make text and
/// choices required; a checkbox or an attachment is a choice to make optional or not).
const REQUIRED_BY_DEFAULT = new Set(["signature", "initials", "text", "company", "title", "number", "radio_group", "dropdown"]);
export const requiredByDefault = (type) => REQUIRED_BY_DEFAULT.has(type);

/// Types typed as text, which take a sender's value, formatting and validation.
export const TYPED = new Set(["text", "company", "title", "number"]);
/// Types that choose from the sender's options.
export const CHOICE = new Set(["radio_group", "dropdown"]);

/// The engine's `validation` for a preset and its settings (UX-05), or null for none.
/// `kind`: "" | email | phone | zip | ssn | number | length | regex; `opts`:
/// `{min, max, pattern, maxLength, message}` as typed (strings). Numbers stay decimal
/// strings as the engine's `Decimal` takes them; empty settings are left out.
export function validationFrom(kind, opts = {}) {
  if (!kind) return null;
  const msg = String(opts.message || "").trim();
  const out = { kind };
  const dec = (v) => (/^-?\d+(\.\d+)?$/.test(String(v ?? "").trim()) ? String(v).trim() : null);
  const int = (v) => (/^\d+$/.test(String(v ?? "").trim()) ? Number(v) : null);
  if (kind === "number") {
    const min = dec(opts.min);
    const max = dec(opts.max);
    if (min !== null) out.min = min;
    if (max !== null) out.max = max;
  } else if (kind === "length") {
    const max = int(opts.maxLength);
    if (max === null) return null;
    out.max = max;
  } else if (kind === "regex") {
    const p = String(opts.pattern || "");
    if (!p) return null;
    out.pattern = p;
  } else if (!["email", "phone", "zip", "ssn"].includes(kind)) {
    return null;
  }
  if (msg) out.message = msg;
  return out;
}

/// Options from a list typed one per line: trimmed, blanks and repeats dropped (the
/// engine refuses a repeat), at most 500 (its limit).
export function optionsFrom(text) {
  const seen = new Set();
  const out = [];
  for (const line of String(text || "").split(/\r?\n/)) {
    const v = line.trim();
    if (!v || seen.has(v)) continue;
    seen.add(v);
    out.push(v);
    if (out.length === 500) break;
  }
  return out;
}

const round2 = (n) => Math.round(n * 100) / 100;

/// Keep a rectangle on its page: size at least MIN_SIZE and at most the page, then
/// position so it lies wholly inside. `page`: `{width, height}` in points.
export function clampRect(r, page) {
  const width = round2(Math.min(Math.max(r.width, MIN_SIZE), page.width));
  const height = round2(Math.min(Math.max(r.height, MIN_SIZE), page.height));
  const x = round2(Math.min(Math.max(r.x, 0), page.width - width));
  const y = round2(Math.min(Math.max(r.y, 0), page.height - height));
  return { x, y, width, height };
}

/// Move by (dx, dy) points, clamped to the page.
export function nudge(r, dx, dy, page) {
  return clampRect({ ...r, x: r.x + dx, y: r.y + dy }, page);
}

/// Resize by (dw, dh) points from the top-left corner, clamped to the page.
export function resize(r, dw, dh, page) {
  return clampRect({ ...r, width: r.width + dw, height: r.height + dh }, page);
}

/// Screen pixels (relative to the page's top-left on screen) to points, at `scale`
/// screen pixels per point.
export function toPoints(px, py, scale) {
  return { x: px / scale, y: py / scale };
}

/// Points to screen pixels at `scale`.
export function toPixels(r, scale) {
  return { left: r.x * scale, top: r.y * scale, width: r.width * scale, height: r.height * scale };
}

/// A rectangle of the type's default size centred on (cx, cy) points, on the page.
export function placeAt(type, cx, cy, page) {
  const s = DEFAULT_SIZE[type] || DEFAULT_SIZE.text;
  return clampRect({ x: cx - s.width / 2, y: cy - s.height / 2, width: s.width, height: s.height }, page);
}

/// Whether two rectangles overlap, with `gap` points kept clear between them.
export function overlaps(a, b, gap = 4) {
  return a.x < b.x + b.width + gap && b.x < a.x + a.width + gap && a.y < b.y + b.height + gap && b.y < a.y + a.height + gap;
}

/// Where a field of `size` goes without covering `existing` fields on the page: from
/// (cx, cy) as its centre, stepping down 4 points at a time, then across in columns;
/// the starting spot if the page is full.
export function freeSpot(existing, size, page, cx, cy) {
  const start = clampRect({ x: cx - size.width / 2, y: cy - size.height / 2, ...size }, page);
  const columns = [start.x, 36, page.width / 2, page.width - size.width - 36];
  for (const x of columns) {
    for (let y = start.y; y + size.height <= page.height; y += 4) {
      const r = clampRect({ x, y, ...size }, page);
      if (!existing.some((e) => overlaps(r, e))) return r;
    }
  }
  return start;
}

/// Snap a value to a grid of `step` points when within `tolerance` of a line.
export function snap(v, step = 4, tolerance = 1.5) {
  const nearest = Math.round(v / step) * step;
  return Math.abs(nearest - v) <= tolerance ? nearest : v;
}

/// A coordinate as the wire wants it: a decimal string, at most two places, no
/// exponent, no trailing zeros, never negative ("72", "10.5").
export function formatPoints(n) {
  if (!Number.isFinite(n)) throw new RangeError("not a finite number of points");
  const v = Math.max(0, Math.min(MAX_POINTS, round2(n)));
  return v.toFixed(2).replace(/\.?0+$/, "");
}

/// A placement for the API (`page` 1-based; numbers as decimal strings).
export function toWire(page, r) {
  return {
    page,
    x: formatPoints(r.x),
    y: formatPoints(r.y),
    width: formatPoints(r.width),
    height: formatPoints(r.height),
  };
}

/// A placement from the API (strings or numbers) into numbers; null if unreadable.
export function fromWire(p) {
  if (!p) return null;
  const n = (v) => (typeof v === "number" ? v : Number.parseFloat(v));
  const out = { page: Number(p.page), x: n(p.x), y: n(p.y), width: n(p.width), height: n(p.height) };
  if (!Number.isInteger(out.page) || out.page < 1) return null;
  for (const k of ["x", "y", "width", "height"]) if (!Number.isFinite(out[k]) || out[k] < 0) return null;
  if (out.width === 0 || out.height === 0) return null;
  return out;
}
