// Icons (WEB-01, WEB-17): Lucide (ISC, vendor/lucide/, PROVENANCE.md), inlined as SVG
// built node by node from `vendor/lucide/nodes.js`, plus a few of OpenSeal's own glyphs
// drawn for the design canvas (`os-*` below: the sidebar's sections, the workspace
// switcher's chevrons, the suggestion sparkle). Strokes are 1.5 by default, the canvas's
// lighter line; sizes are the design tokens: 16 dense, 20 default, 24 toolbars.

import { NODES } from "./vendor/lucide/nodes.js";

const SVG = "http://www.w3.org/2000/svg";

/// Names the app uses for Lucide icons that Lucide calls something else (UX-02): the
/// editor's align commands by the edge they align to, and the older help-circle name.
const ALIAS = {
  "align-start": "align-start-vertical", // left edges
  "align-end": "align-end-vertical", // right edges
  "align-top": "align-start-horizontal",
  "align-bottom": "align-end-horizontal",
  "help-circle": "circle-help",
};

/// OpenSeal's own glyphs, from the design canvas (24 × 24, stroked unless `fill` says so).
const LOCAL = {
  "os-agreements": [["path", { d: "M7 3h7l5 5v13H7z" }], ["path", { d: "M14 3v5h5M10 13h6M10 17h4" }]],
  "os-inbox": [["path", { d: "M4 13h4l1.5 3h5L16 13h4M4 13l2.5-7h11L20 13v5H4z" }]],
  "os-grid": [["rect", { x: "4", y: "4", width: "7", height: "7", rx: "1.5" }], ["rect", { x: "13", y: "4", width: "7", height: "7", rx: "1.5" }], ["rect", { x: "4", y: "13", width: "7", height: "7", rx: "1.5" }], ["rect", { x: "13", y: "13", width: "7", height: "7", rx: "1.5" }]],
  "os-bars": [["path", { d: "M4 20V10M10 20V4M16 20v-7M22 20H2" }]],
  "os-contacts": [["circle", { cx: "9", cy: "9", r: "3.5" }], ["path", { d: "M3 20c.8-3.4 3.2-5 6-5s5.2 1.6 6 5M16 5.5a3.5 3.5 0 0 1 0 7M18 15c1.6.6 2.6 2.2 3 5" }]],
  "os-shield": [["path", { d: "M12 3 4 6v6c0 4.5 3.3 8 8 9 4.7-1 8-4.5 8-9V6z" }]],
  "os-shield-check": [["path", { d: "M12 3 4 6v6c0 4.5 3.3 8 8 9 4.7-1 8-4.5 8-9V6z" }], ["path", { d: "m8.5 12 2.5 2.5 4.5-5" }]],
  "os-updown": [["path", { d: "m8 10 4-4 4 4M8 14l4 4 4-4" }]],
  "os-search": [["circle", { cx: "11", cy: "11", r: "6.5" }], ["path", { d: "m20 20-4-4" }]],
  "os-filter": [["path", { d: "M4 6h16M7 12h10M10 18h4" }]],
  "os-display": [["path", { d: "M4 7h10M18 7h2M4 17h2M10 17h10" }], ["circle", { cx: "16", cy: "7", r: "2" }], ["circle", { cx: "8", cy: "17", r: "2" }]],
  "os-check": [["path", { d: "M5 12.5 10 17 19 7" }]],
  "os-back": [["path", { d: "m15 6-6 6 6 6" }]],
  "os-enter": [["path", { d: "M20 5v7a3 3 0 0 1-3 3H6" }], ["path", { d: "m9 11-4 4 4 4" }]],
  "os-sparkle": [["path", { d: "M12 2l1.8 6.2L20 10l-6.2 1.8L12 18l-1.8-6.2L4 10l6.2-1.8z", fill: "currentColor", stroke: "none" }]],
  // Favourites (UXW-06): a five-point star, outline and filled.
  "os-star": [["path", { d: "M12 3.5l2.6 5.3 5.9.9-4.3 4.1 1 5.8L12 16.9l-5.2 2.7 1-5.8-4.3-4.1 5.9-.9z" }]],
  "os-star-filled": [["path", { d: "M12 3.5l2.6 5.3 5.9.9-4.3 4.1 1 5.8L12 16.9l-5.2 2.7 1-5.8-4.3-4.1 5.9-.9z", fill: "currentColor" }]],
  "os-lock": [["rect", { x: "5", y: "11", width: "14", height: "9", rx: "2" }], ["path", { d: "M8 11V8a4 4 0 0 1 8 0v3" }]],
};

const nodesOf = (name) => LOCAL[name] || NODES[ALIAS[name] || name];

/// An icon. With `label` it is an image with that accessible name; without, it is
/// decorative and hidden from assistive technology (the control around it is named).
/// `stroke` is the line width (default 1.5, the canvas's; 2 for emphasis).
export function icon(name, { size = 20, label = null, className = "", stroke = 1.5 } = {}) {
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", String(size));
  svg.setAttribute("height", String(size));
  // Sized in CSS from a token (WEB-12): `size` is in sixteenths of a rem (16 is 1 rem), so
  // the icon grows with the text when the root size grows; the attributes stay only
  // for a renderer without the stylesheet.
  svg.style.setProperty("--os-icon-size", `${size / 16}rem`);
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", String(stroke));
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("class", `os-icon ${className}`.trim());
  if (label) {
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", label);
  } else {
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("focusable", "false");
  }
  for (const [tag, attrs] of nodesOf(name) || []) {
    const n = document.createElementNS(SVG, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    svg.appendChild(n);
  }
  return svg;
}

/// Whether `name` is vendored or drawn here (for tests and for callers that pick one at
/// run time).
export function hasIcon(name) {
  return Object.prototype.hasOwnProperty.call(LOCAL, name) || Object.prototype.hasOwnProperty.call(NODES, ALIAS[name] || name);
}
