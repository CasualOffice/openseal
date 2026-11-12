// Small DOM helpers of the platform console UI (CON-17). Every string goes in through
// `textContent` or an attribute, never as markup (CLAUDE.md).
//
// `h`, `append`, `clear` and `$` are copied from this repository's `webapp/dom.js`
// (PROVENANCE.md); `svg` and `reducedMotion` are new.

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

const SVG_NS = "http://www.w3.org/2000/svg";

/// Build an SVG element with attributes and children (decorative art; never user text).
export function svg(tag, attrs = {}, ...children) {
  const e = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) if (v != null) e.setAttribute(k, String(v));
  for (const c of children.flat(Infinity)) if (c) e.appendChild(c);
  return e;
}

/// Whether the operator asked the system for less motion.
export function reducedMotion() {
  return typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;
}
