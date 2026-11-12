// Small DOM helpers (WEB-01). Every string goes in through `textContent` or an
// attribute, never as markup (CLAUDE.md, docs/47 principle 5).
//
// `h` is OpenPresent's `h(tag, cls, text)` from `webapp/ribbon.js` at `e61277d`
// (PROVENANCE.md), widened to take attributes and children.

/// Build an element. `props`: `class`, `text`, `attrs` (object), `on` (event map),
/// `dataset`, `hidden`; any other key is set as a property (`type`, `value`,
/// `checked`, `disabled`…). Children may be nodes, strings (as text) or falsy (skipped).
export function h(tag, props = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false && k !== "checked" && k !== "disabled" && k !== "hidden") continue;
    if (k === "class") e.className = v;
    else if (k === "text") e.textContent = v;
    else if (k === "attrs") for (const [a, av] of Object.entries(v)) { if (av != null && av !== false) e.setAttribute(a, av === true ? "" : String(av)); }
    else if (k === "on") for (const [ev, fn] of Object.entries(v)) e.addEventListener(ev, fn);
    else if (k === "dataset") Object.assign(e.dataset, v);
    else e[k] = v;
  }
  append(e, children);
  return e;
}

/// Append nodes and strings (as text) to `parent`, skipping null, false and undefined.
export function append(parent, children) {
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    parent.appendChild(typeof c === "string" || typeof c === "number" ? document.createTextNode(String(c)) : c);
  }
  return parent;
}

/// Remove every child of `node`.
export function clear(node) {
  node.textContent = "";
  return node;
}

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

/// Point the page's skip link at `href` with `text` ("Skip to document" on the document
/// views, A19).
export function skipTo(href, text) {
  const a = document.querySelector(".os-skip");
  if (!a) return;
  a.setAttribute("href", href);
  if (text) a.textContent = text;
}

/// Whether the user asked the system for less motion.
export function reducedMotion() {
  return typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/// Is this key event typed into an editable control (so single-key shortcuts must not fire)?
export function isTyping(e) {
  const t = e.target;
  if (!t || !t.tagName) return false;
  if (t.isContentEditable) return true;
  if (t.tagName === "TEXTAREA" || t.tagName === "SELECT") return true;
  if (t.tagName === "INPUT") return !["checkbox", "radio", "button", "submit", "reset", "file", "range", "color"].includes(t.type);
  return false;
}

/// Trigger a download of `blob` as `name` (an object URL, revoked after the click).
export function download(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = h("a", { href: url, download: name, hidden: true });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/// A person's initials for an avatar: "Avery Chen" → "AC"; one word → its first letter.
export function initials(name) {
  const parts = String(name || "").trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return "";
  return ((parts[0][0] || "") + (parts.length > 1 ? parts[parts.length - 1][0] : "")).toUpperCase();
}

/// A date for people: "11 Nov 2026, 14:05" in the browser's locale.
export function fmtDate(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleString(undefined, { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

const DAY_MS = 86_400_000;
const dayStart = (ms) => { const d = new Date(ms); d.setHours(0, 0, 0, 0); return d.getTime(); };

/// A short date for lists (UX-07): "Today, 5:28 PM", "Yesterday, 9:02 AM", "Nov 12"
/// this year, "Nov 12, 2025" otherwise, in the browser's locale. `labels` name today
/// and yesterday (from the caller's `t`); `now` in ms. The full timestamp is
/// `fmtDate`'s, for a tooltip.
export function fmtShortDate(iso, { today = "Today", yesterday = "Yesterday" } = {}, now = Date.now()) {
  if (!iso) return "";
  const d = new Date(iso);
  const at = d.getTime();
  if (Number.isNaN(at)) return "";
  const time = () => d.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
  const days = Math.round((dayStart(now) - dayStart(at)) / DAY_MS);
  if (days === 0) return `${today}, ${time()}`;
  if (days === 1) return `${yesterday}, ${time()}`;
  const sameYear = d.getFullYear() === new Date(now).getFullYear();
  return d.toLocaleDateString(undefined, sameYear ? { day: "numeric", month: "short" } : { day: "numeric", month: "short", year: "numeric" });
}
