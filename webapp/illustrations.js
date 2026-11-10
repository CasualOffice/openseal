// Empty-state illustrations (WEB-01): original line drawings for OpenSeal, built from
// SVG nodes (no markup strings), in Lucide-weight strokes. Colours are classes bound to
// tokens (`.il-line`, `.il-fill`, `.il-accent`, `.il-paper` in app.css), so light and
// dark follow the theme. Always `aria-hidden`: the title and sentence beside them carry
// the meaning.

const SVG = "http://www.w3.org/2000/svg";

function s(tag, attrs, cls) {
  const n = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, String(v));
  if (cls) n.setAttribute("class", cls);
  return n;
}

/// A document sheet with text lines, at (x, y), 64×80.
function sheet(g, x, y, lines = 4) {
  g.append(s("rect", { x, y, width: 64, height: 80, rx: 6 }, "il-paper il-line"));
  for (let i = 0; i < lines; i++) g.append(s("path", { d: `M${x + 12} ${y + 18 + i * 10}h${i === lines - 1 ? 24 : 40}` }, "il-line il-thin"));
}

/// The seal badge: a scalloped circle with a check, the brand's mark in line form.
function seal(g, cx, cy, r) {
  const pts = [];
  for (let i = 0; i < 24; i++) {
    const a = (i / 24) * Math.PI * 2;
    const rr = i % 2 ? r : r * 0.88;
    pts.push(`${(cx + rr * Math.cos(a)).toFixed(1)},${(cy + rr * Math.sin(a)).toFixed(1)}`);
  }
  g.append(s("polygon", { points: pts.join(" ") }, "il-accent-fill"));
  g.append(s("path", { d: `M${cx - r * 0.35} ${cy}l${r * 0.25} ${r * 0.25}l${r * 0.45} -${r * 0.5}` }, "il-on-accent"));
}

const DRAW = {
  inbox(g) {
    g.append(s("ellipse", { cx: 80, cy: 112, rx: 56, ry: 8 }, "il-fill"));
    sheet(g, 48, 18, 4);
    g.append(s("path", { d: "M28 72h30l8 14h28l8-14h30v30a6 6 0 0 1-6 6H34a6 6 0 0 1-6-6z" }, "il-paper il-line"));
    g.append(s("path", { d: "M70 42h20" }, "il-accent"));
  },
  search(g) {
    g.append(s("ellipse", { cx: 80, cy: 112, rx: 56, ry: 8 }, "il-fill"));
    sheet(g, 36, 16, 5);
    g.append(s("circle", { cx: 98, cy: 66, r: 20 }, "il-paper il-line"));
    g.append(s("path", { d: "M112 80l18 18" }, "il-line il-thick"));
    g.append(s("path", { d: "M91 59l14 14M105 59l-14 14" }, "il-accent"));
  },
  documents(g) {
    g.append(s("ellipse", { cx: 80, cy: 112, rx: 56, ry: 8 }, "il-fill"));
    sheet(g, 40, 22, 4);
    sheet(g, 56, 14, 4);
    g.append(s("circle", { cx: 112, cy: 82, r: 16 }, "il-accent-fill"));
    g.append(s("path", { d: "M112 74v16M104 82h16" }, "il-on-accent"));
  },
  recipients(g) {
    g.append(s("ellipse", { cx: 80, cy: 112, rx: 56, ry: 8 }, "il-fill"));
    g.append(s("circle", { cx: 62, cy: 46, r: 14 }, "il-paper il-line"));
    g.append(s("path", { d: "M36 96c0-16 12-26 26-26s26 10 26 26" }, "il-paper il-line"));
    g.append(s("circle", { cx: 104, cy: 52, r: 11 }, "il-paper il-line"));
    g.append(s("path", { d: "M86 96c2-12 9-19 18-19s17 7 19 19" }, "il-line"));
    g.append(s("circle", { cx: 120, cy: 34, r: 10 }, "il-accent-fill"));
    g.append(s("path", { d: "M120 29v10M115 34h10" }, "il-on-accent"));
  },
  fields(g) {
    g.append(s("ellipse", { cx: 80, cy: 112, rx: 56, ry: 8 }, "il-fill"));
    sheet(g, 46, 14, 3);
    g.append(s("rect", { x: 56, y: 62, width: 44, height: 16, rx: 3 }, "il-accent-dash"));
    g.append(s("path", { d: "M62 73c4-6 6 2 10-3s5 4 9 0" }, "il-accent"));
    g.append(s("path", { d: "M104 86l10 22 3-9 9-3z" }, "il-paper il-line"));
  },
  done(g) {
    g.append(s("ellipse", { cx: 80, cy: 112, rx: 56, ry: 8 }, "il-fill"));
    sheet(g, 40, 16, 4);
    g.append(s("path", { d: "M52 78c5-7 8 3 13-3s6 5 11 0" }, "il-line"));
    seal(g, 104, 76, 24);
  },
  error(g) {
    g.append(s("ellipse", { cx: 80, cy: 112, rx: 56, ry: 8 }, "il-fill"));
    sheet(g, 48, 16, 4);
    g.append(s("path", { d: "M104 58l20 36H84z" }, "il-paper il-accent-line"));
    g.append(s("path", { d: "M104 70v10M104 86v1" }, "il-accent"));
  },
  offline(g) {
    g.append(s("ellipse", { cx: 80, cy: 112, rx: 56, ry: 8 }, "il-fill"));
    g.append(s("path", { d: "M40 60a56 56 0 0 1 80 0M52 74a38 38 0 0 1 56 0M66 88a18 18 0 0 1 28 0" }, "il-line il-thick"));
    g.append(s("circle", { cx: 80, cy: 100, r: 3 }, "il-line-fill"));
    g.append(s("path", { d: "M44 40l72 72" }, "il-accent il-thick"));
  },
};

/// The illustration called `name` (160×128 viewBox), decorative.
export function illustration(name) {
  const svg = s("svg", { viewBox: "0 0 160 128", width: 160, height: 128, "aria-hidden": "true", focusable: "false" }, "os-illus");
  const g = s("g", { fill: "none", "stroke-linecap": "round", "stroke-linejoin": "round" });
  (DRAW[name] || DRAW.inbox)(g);
  svg.append(g);
  return svg;
}

export const ILLUSTRATIONS = Object.keys(DRAW);
