// Illustrations of the platform console UI (CON-17): small, decorative SVGs drawn with
// `svg()` (no markup strings), each `aria-hidden`. The all-clear chart is the approved
// canvas's (docs/assets/design-canvas/Console.dc.html); the others follow its style:
// zinc strokes, one accent, a soft band.

import { svg } from "./dom.js";

const STROKE = "#d4d4d8";

function frame(w, h, ...children) {
  return svg("svg", { width: `${w / 16}rem`, height: `${h / 16}rem`, viewBox: `0 0 ${w} ${h}`, fill: "none", "aria-hidden": "true", class: "art" }, ...children);
}

const line = (d, color = STROKE, width = 2.5) => svg("path", { d, stroke: color, "stroke-width": width, "stroke-linecap": "round", "stroke-linejoin": "round" });

/// The seal mark of the sidebar and sign-in card.
export function mark(size = "1.5rem") {
  const s = svg("svg", { width: "0.75rem", height: "0.75rem", viewBox: "0 0 24 24", fill: "none", stroke: "#fff", "stroke-width": "2.4", "aria-hidden": "true" }, svg("path", { d: "M5 12.5 10 17 19 7" }));
  const box = document.createElement("span");
  box.className = "mark";
  box.style.setProperty("--mark", size);
  box.appendChild(s);
  return box;
}

/// Every metric in its range: the canvas's all-clear chart with a check.
export function allClear() {
  return frame(96, 72,
    line("M8 52 26 40l14 8 18-20 14 10 16-14"),
    svg("rect", { x: 4, y: 30, width: 88, height: 22, rx: 3, fill: "#15803d", opacity: ".08" }),
    svg("circle", { cx: 72, cy: 20, r: 12, fill: "#15803d" }),
    line("m66.5 20 4 4 7.5-8", "#fff"));
}

/// No organizations: three stacked buildings, outlined.
export function noOrganizations() {
  return frame(96, 72,
    svg("rect", { x: 14, y: 26, width: 22, height: 36, rx: 3, stroke: STROKE, "stroke-width": 2.5 }),
    svg("rect", { x: 40, y: 12, width: 24, height: 50, rx: 3, stroke: STROKE, "stroke-width": 2.5, fill: "#fff" }),
    svg("rect", { x: 68, y: 32, width: 16, height: 30, rx: 3, stroke: STROKE, "stroke-width": 2.5 }),
    line("M46 22h12M46 30h12M46 38h12", "#c01622", 2),
    line("M6 62h84"));
}

/// No approvals waiting: two shields side by side, one ticked.
export function noApprovals() {
  const shield = (x, tick) => [
    line(`M${x} 14l16 6v14c0 10-7 17-16 21-9-4-16-11-16-21V20z`, tick ? "#15803d" : STROKE),
    tick ? line(`m${x - 6} 34 4.5 4.5 8-9`, "#15803d") : null,
  ];
  return frame(96, 72,
    svg("rect", { x: 6, y: 52, width: 84, height: 10, rx: 3, fill: "#15803d", opacity: ".08" }),
    ...shield(32, false), ...shield(64, true));
}

/// An empty list or log: a page with ruled lines.
export function noEntries() {
  return frame(96, 72,
    svg("rect", { x: 26, y: 8, width: 44, height: 56, rx: 4, stroke: STROKE, "stroke-width": 2.5, fill: "#fff" }),
    line("M34 22h28M34 30h28M34 38h18"),
    svg("circle", { cx: 70, cy: 52, r: 10, fill: "#f4f3f0", stroke: STROKE, "stroke-width": 2.5 }),
    line("m66 52 3 3 5.5-6", "#71717a", 2));
}

/// Something failed: a broken line with a warning dot.
export function failed() {
  return frame(96, 72,
    line("M8 52 26 40l10 6"),
    line("M54 34 58 30l14 10 16-14"),
    svg("circle", { cx: 46, cy: 40, r: 11, fill: "#fef3c7", stroke: "#b45309", "stroke-width": 2 }),
    line("M46 34v7", "#b45309", 2.5),
    svg("circle", { cx: 46, cy: 45.5, r: 1.5, fill: "#b45309" }));
}

/// Sign-in: a key over a lock-plate.
export function signInArt() {
  return frame(96, 72,
    svg("rect", { x: 24, y: 30, width: 48, height: 34, rx: 6, stroke: STROKE, "stroke-width": 2.5, fill: "#fff" }),
    line("M34 30v-8a14 14 0 0 1 28 0v8"),
    svg("circle", { cx: 48, cy: 45, r: 4.5, fill: "#c01622" }),
    line("M48 49v6", "#c01622", 3));
}
