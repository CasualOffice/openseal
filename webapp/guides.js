// Snapping guides for the editor (WEB-09; SignNow's and DocuSign's smart guides): while a
// field moves or resizes, its edges and centre snap to the page's edges and centre and to
// other fields' edges and centres on the same page, and a line shows what it lined up
// with. Holding Alt turns snapping off. The keyboard has the same stops: Alt+Shift+arrow
// jumps to the next one (`nextStop`).
//
// Pure: rectangles in PDF points of the page as displayed (ADR-019, geometry.js), so
// Node tests every rule. Tolerance is in points; the editor passes a screen distance
// divided by the zoom, so snapping feels the same at every zoom.

/// The lines a rectangle offers on an axis: start, centre, end.
const lines = (r, axis) => (axis === "x" ? [r.x, r.x + r.width / 2, r.x + r.width] : [r.y, r.y + r.height / 2, r.y + r.height]);

/// The stops on an axis: the page's edges and centre, and every other field's edges
/// and centre, each `{at, kind, key?}` (`kind`: "page" or "field").
export function stops(others, page, axis) {
  const size = axis === "x" ? page.width : page.height;
  const out = [{ at: 0, kind: "page" }, { at: size / 2, kind: "page" }, { at: size, kind: "page" }];
  for (const o of others) for (const at of lines(o, axis)) out.push({ at, kind: "field", key: o.key });
  return out;
}

/// The smallest shift on `axis` that puts one of `edges` (positions on that axis) on a
/// stop, within `tol`; `{delta, at}` or null.
function nearest(edges, list, tol) {
  let best = null;
  for (const e of edges) {
    for (const s of list) {
      const d = s.at - e;
      if (Math.abs(d) <= tol && (!best || Math.abs(d) < Math.abs(best.delta))) best = { delta: d, at: s.at };
    }
  }
  return best;
}

/// Snap a moving rectangle (`mode` "move") or one being resized from its bottom-right
/// corner (`mode` "resize"): `{rect, guides}`, `guides` being `[{axis, at}]`, the lines to
/// draw (a vertical line at x = `at` for axis "x"). A moved rectangle keeps its size;
/// a resized one keeps its top-left corner.
export function snapRect(r, others, page, tol, mode = "move") {
  const out = { ...r };
  const guides = [];
  for (const axis of ["x", "y"]) {
    const all = lines(r, axis);
    const edges = mode === "move" ? all : [all[2]];
    const hit = nearest(edges, stops(others, page, axis), tol);
    if (!hit) continue;
    if (mode === "move") out[axis] = r[axis] + hit.delta;
    else out[axis === "x" ? "width" : "height"] = r[axis === "x" ? "width" : "height"] + hit.delta;
    guides.push({ axis, at: hit.at });
  }
  // Every stop the result now touches (more than one line can match at once).
  return { rect: out, guides: touching(out, others, page, guides) };
}

/// The guides a rectangle lies on exactly (within 0.01 points): after a keyboard move,
/// to show and announce what it lined up with. `seed` guides are kept.
export function touching(r, others, page, seed = []) {
  const out = [...seed];
  for (const axis of ["x", "y"]) {
    for (const s of stops(others, page, axis)) {
      if (lines(r, axis).some((e) => Math.abs(e - s.at) < 0.01) && !out.some((g) => g.axis === axis && Math.abs(g.at - s.at) < 0.01)) out.push({ axis, at: s.at });
    }
  }
  return out;
}

/// Where Alt+Shift+arrow takes a rectangle: the nearest stop strictly beyond it in the
/// direction `dir` (-1 left or up, +1 right or down) on `axis`, measured from whichever
/// of its edges or centre reaches one first; the new position, or null when none is
/// left (it is at the page edge).
export function nextStop(r, others, page, axis, dir) {
  const size = axis === "x" ? r.width : r.height;
  const limit = axis === "x" ? page.width - r.width : page.height - r.height;
  let best = null;
  const offsets = [0, size / 2, size];
  for (const s of stops(others, page, axis)) {
    for (const off of offsets) {
      const pos = s.at - off;
      if (pos < -0.001 || pos > limit + 0.001) continue;
      const d = (pos - r[axis]) * dir;
      if (d > 0.01 && (best === null || d < best.d)) best = { d, pos };
    }
  }
  return best ? Math.max(0, Math.min(limit, best.pos)) : null;
}

/// The bounding box of rectangles (a group moves as one box).
export function bounds(rs) {
  const x = Math.min(...rs.map((r) => r.x));
  const y = Math.min(...rs.map((r) => r.y));
  return { x, y, width: Math.max(...rs.map((r) => r.x + r.width)) - x, height: Math.max(...rs.map((r) => r.y + r.height)) - y };
}

/// Whether two rectangles intersect (marquee selection takes what it touches).
export function intersects(a, b) {
  return a.x < b.x + b.width && b.x < a.x + a.width && a.y < b.y + b.height && b.y < a.y + a.height;
}

/// A rectangle from two corners, in any order.
export function fromCorners(x1, y1, x2, y2) {
  return { x: Math.min(x1, x2), y: Math.min(y1, y2), width: Math.abs(x2 - x1), height: Math.abs(y2 - y1) };
}
