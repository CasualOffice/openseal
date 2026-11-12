// Empty-state and waiting illustrations (WEB-01, redrawn for WEB-17 in the design
// canvas's style): a soft ellipse shadow, white paper with hairline strokes, light text
// bars, one small coloured accent (seal red, green, violet for the model, blue for a
// field) and a few confetti dots. Built from SVG nodes (no markup strings). Colours are
// classes bound to tokens (`.il-*` in app.css), so light and dark follow the theme; the
// empty state makes them float. Always `aria-hidden`: the title and sentence beside
// them carry the meaning.

const SVG = "http://www.w3.org/2000/svg";

function s(tag, attrs, cls) {
  const n = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, String(v));
  if (cls) n.setAttribute("class", cls);
  return n;
}

const shadow = (g, rx = 46) => g.append(s("ellipse", { cx: 80, cy: 110, rx, ry: 5 }, "il-shadow"));
/// A page at (x, y), `w` × `h`, with `lines` text bars.
function page(g, x, y, w = 60, hgt = 78, lines = 4) {
  g.append(s("rect", { x, y, width: w, height: hgt, rx: 5 }, "il-paper"));
  const widths = [0.47, 0.67, 0.57, 0.63, 0.5];
  for (let i = 0; i < lines; i++) g.append(s("path", { d: `M${x + 10} ${y + 14 + i * 8}h${Math.round((w - 20) * widths[i % widths.length] / 0.67)}` }, "il-text"));
}
/// The canvas's confetti: an amber dot, a violet dot and a rose cross.
function confetti(g, [a, b, c] = [[28, 40], [136, 30], [132, 100]]) {
  g.append(s("circle", { cx: a[0], cy: a[1], r: 3 }, "il-amber-dot"));
  g.append(s("circle", { cx: b[0], cy: b[1], r: 2.5 }, "il-violet-dot"));
  g.append(s("path", { d: `M${c[0]} ${c[1]}l3 3m0-3-3 3` }, "il-rose-line"));
}
/// A filled badge with a white check at (cx, cy).
function check(g, cx, cy, r = 14, tone = "il-green") {
  g.append(s("circle", { cx, cy, r }, tone));
  g.append(s("path", { d: `M${cx - r * 0.44} ${cy}l${r * 0.3} ${r * 0.3} ${r * 0.6}-${r * 0.6}` }, "il-on"));
}
/// The suggestion sparkle at (cx, cy) on a soft violet disc.
function sparkle(g, cx, cy) {
  g.append(s("circle", { cx, cy, r: 10 }, "il-violet-soft"));
  g.append(s("path", { d: `M${cx} ${cy - 7}l1.4 4.8 4.6 1.2-4.6 1.4-1.4 4.6-1.4-4.6-4.6-1.4 4.6-1.2z` }, "il-violet"));
}

const DRAW = {
  inbox(g) {
    shadow(g);
    page(g, 50, 14, 60, 70, 4);
    g.append(s("path", { d: "M30 70h28l7 12h30l7-12h28v26a6 6 0 0 1-6 6H36a6 6 0 0 1-6-6z" }, "il-paper"));
    g.append(s("path", { d: "M68 52c3-4 5 1 8-2s4 3 7 0" }, "il-red-line"));
    confetti(g);
  },
  search(g) {
    shadow(g);
    page(g, 34, 14, 60, 80, 5);
    g.append(s("circle", { cx: 100, cy: 64, r: 18 }, "il-paper"));
    g.append(s("path", { d: "M113 77l14 14" }, "il-muted"));
    g.append(s("path", { d: "M94 58l12 12M106 58l-12 12" }, "il-red-line"));
    confetti(g, [[22, 34], [140, 28], [130, 102]]);
  },
  documents(g) {
    shadow(g);
    page(g, 40, 22, 56, 74, 4);
    page(g, 58, 12, 56, 74, 4);
    g.append(s("circle", { cx: 114, cy: 82, r: 14 }, "il-red"));
    g.append(s("path", { d: "M114 75v14M107 82h14" }, "il-on"));
    confetti(g, [[26, 44], [138, 30], [30, 100]]);
  },
  recipients(g) {
    shadow(g);
    g.append(s("circle", { cx: 64, cy: 46, r: 13 }, "il-paper"));
    g.append(s("path", { d: "M40 96c0-15 11-24 24-24s24 9 24 24z" }, "il-paper"));
    g.append(s("circle", { cx: 104, cy: 52, r: 10 }, "il-paper"));
    g.append(s("path", { d: "M88 96c1.5-11 8-18 16-18s14.5 7 16 18" }, "il-paper"));
    g.append(s("circle", { cx: 122, cy: 34, r: 9 }, "il-red"));
    g.append(s("path", { d: "M122 29v10M117 34h10" }, "il-on"));
    confetti(g, [[28, 36], [140, 70], [34, 104]]);
  },
  /// A page with a dashed field being signed (canvas Editor: "No fields yet").
  fields(g) {
    shadow(g, 40);
    page(g, 46, 10, 60, 78, 4);
    g.append(s("rect", { x: 56, y: 58, width: 40, height: 14, rx: 3 }, "il-blue-dash"));
    g.append(s("path", { d: "M62 67c3-2 4-6 6-6s1 4 3 4 3-3 5-3" }, "il-blue-line"));
    g.append(s("path", { d: "M110 52l12 4-5 2-2 5z" }, "il-ink"));
    sparkle(g, 120, 24);
    g.append(s("circle", { cx: 36, cy: 36, r: 2.5 }, "il-rose-dot"));
    g.append(s("circle", { cx: 130, cy: 80, r: 2 }, "il-amber-dot"));
  },
  done(g) {
    shadow(g);
    page(g, 40, 14, 60, 80, 4);
    g.append(s("path", { d: "M52 76c5-7 8 3 13-3s6 5 11 0" }, "il-muted"));
    check(g, 104, 76, 18, "il-red");
    confetti(g);
  },
  error(g) {
    shadow(g);
    page(g, 46, 14, 60, 80, 4);
    g.append(s("path", { d: "M106 56l20 34H86z" }, "il-paper"));
    g.append(s("path", { d: "M106 67v10M106 83v.5" }, "il-danger"));
    confetti(g, [[28, 40], [138, 30], [30, 100]]);
  },
  templates(g) {
    shadow(g);
    g.append(s("rect", { x: 36, y: 24, width: 58, height: 74, rx: 5 }, "il-paper"));
    g.append(s("rect", { x: 46, y: 38, width: 38, height: 10, rx: 2 }, "il-blue-dash"));
    g.append(s("rect", { x: 46, y: 56, width: 38, height: 10, rx: 2 }, "il-blue-dash"));
    g.append(s("rect", { x: 66, y: 12, width: 58, height: 74, rx: 5 }, "il-paper"));
    for (let i = 0; i < 3; i++) g.append(s("path", { d: `M76 ${28 + i * 8}h${i === 2 ? 26 : 38}` }, "il-text"));
    g.append(s("path", { d: "M78 66c3-5 5 1 8-2s4 3 7 0" }, "il-red-line"));
    confetti(g, [[24, 40], [140, 26], [134, 102]]);
  },
  keys(g) {
    shadow(g);
    g.append(s("circle", { cx: 60, cy: 54, r: 20 }, "il-paper"));
    g.append(s("circle", { cx: 60, cy: 54, r: 6 }, "il-red"));
    g.append(s("path", { d: "M74 68l32 32M96 90l8-8M104 98l8-8" }, "il-muted"));
    confetti(g, [[28, 30], [130, 40], [36, 100]]);
  },
  verify(g) {
    shadow(g);
    page(g, 34, 14, 60, 80, 5);
    g.append(s("path", { d: "M108 44l22 8v18c0 15-10 25-22 29-12-4-22-14-22-29V52z" }, "il-paper"));
    g.append(s("path", { d: "M99 70l6 6 12-13" }, "il-red-line"));
    confetti(g, [[24, 40], [140, 28], [134, 106]]);
  },
  offline(g) {
    shadow(g);
    g.append(s("path", { d: "M42 60a54 54 0 0 1 76 0M54 74a36 36 0 0 1 52 0M67 87a17 17 0 0 1 26 0" }, "il-muted"));
    g.append(s("circle", { cx: 80, cy: 98, r: 3 }, "il-ink"));
    g.append(s("path", { d: "M46 40l68 68" }, "il-danger"));
    confetti(g, [[28, 36], [138, 32], [130, 104]]);
  },
  /// A calendar with a green check (canvas Main: "Nothing is about to expire").
  calendar(g) {
    shadow(g);
    g.append(s("rect", { x: 38, y: 18, width: 84, height: 80, rx: 10 }, "il-paper"));
    g.append(s("path", { d: "M38 38h84" }, "il-line"));
    g.append(s("path", { d: "M48 18h64a10 10 0 0 1 10 10v10H38V28a10 10 0 0 1 10-10z" }, "il-red-soft"));
    g.append(s("path", { d: "M58 12v12M102 12v12" }, "il-muted"));
    for (const [x, y] of [[50, 48], [66, 48], [82, 48], [98, 48], [50, 62], [66, 62], [98, 62], [50, 76], [66, 76]]) g.append(s("rect", { x, y, width: 10, height: 8, rx: 2 }, "il-fill"));
    check(g, 112, 84, 17);
    confetti(g);
  },
  /// A rising line inside its usual band with a green check (canvas Console: all clear).
  chart(g) {
    g.append(s("rect", { x: 22, y: 52, width: 116, height: 30, rx: 4 }, "il-green-soft"));
    g.append(s("path", { d: "M28 78 52 62l18 10 24-26 18 13 22-18" }, "il-muted"));
    check(g, 110, 30, 15);
    confetti(g, [[24, 30], [140, 96], [30, 100]]);
  },
  /// A page being read: a violet scan line sweeping it (canvas: "Reading the document").
  scanning(g) {
    shadow(g, 34);
    g.append(s("rect", { x: 56, y: 10, width: 48, height: 64, rx: 4 }, "il-paper"));
    const bars = [[0.6, "il-text"], [1, "il-text"], [0.85, "il-text"], [1, "il-text"], [0.7, "il-violet-text"], [1, "il-text"], [0.5, "il-violet-text"]];
    bars.forEach(([w, cls], i) => g.append(s("path", { d: `M64 ${20 + i * 7}h${Math.round(32 * w)}` }, cls === "il-text" ? "il-text" : "il-text il-violet-bar")));
    const sweep = s("g", {}, "il-sweep");
    sweep.append(s("rect", { x: 56, y: 12, width: 48, height: 12 }, "il-violet-scan"));
    sweep.append(s("path", { d: "M56 24h48" }, "il-scanline"));
    g.append(sweep);
    sparkle(g, 116, 22);
    g.append(s("circle", { cx: 40, cy: 40, r: 2.5 }, "il-amber-dot"));
  },
};

/// Other names screens use for the same drawings.
const ALIAS = { "page-field": "fields", "no-fields": "fields", "calendar-check": "calendar", "chart-check": "chart", "all-clear": "chart", reading: "scanning", "scanning-document": "scanning" };

/// The illustration called `name` (160×120 viewBox), decorative.
export function illustration(name) {
  const svg = s("svg", { viewBox: "0 0 160 120", width: 160, height: 120, "aria-hidden": "true", focusable: "false" }, "os-illus");
  const g = s("g", { fill: "none", "stroke-linecap": "round", "stroke-linejoin": "round" });
  (DRAW[ALIAS[name] || name] || DRAW.inbox)(g);
  svg.append(g);
  return svg;
}

export const ILLUSTRATIONS = Object.keys(DRAW);
