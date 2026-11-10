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

/// A date for people: "11 Nov 2026, 14:05" in the browser's locale.
export function fmtDate(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleString(undefined, { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
}
