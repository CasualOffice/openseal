// Icons (WEB-01): Lucide (ISC, vendor/lucide/, PROVENANCE.md), inlined as SVG built
// node by node from `vendor/lucide/nodes.js`. Sizes are the design tokens: 16 dense,
// 20 default, 24 toolbars and empty states. Stroke 2, or 1.75 at 24 px and above.

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
const nodesOf = (name) => NODES[ALIAS[name] || name];

/// An icon. With `label` it is an image with that accessible name; without, it is
/// decorative and hidden from assistive technology (the control around it is named).
export function icon(name, { size = 20, label = null, className = "" } = {}) {
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", String(size));
  svg.setAttribute("height", String(size));
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", size >= 24 ? "1.75" : "2");
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

/// Whether `name` is vendored (for tests and for callers that pick one at run time).
export function hasIcon(name) {
  return Object.prototype.hasOwnProperty.call(NODES, ALIAS[name] || name);
}
