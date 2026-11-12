// The document view (WEB-06, docs/47 §Layout spec): one scroll container holding the
// pages of one or more PDFs, used by the editor, the signing page and every preview.
//
// - Pages are laid out at a scale (CSS px per PDF point) from a zoom mode: fit width,
//   fit page, or a fixed scale. Placeholders always have their final size, so the
//   scroll height is stable; only pages within a viewport of the visible area are
//   painted, and pages three viewports away give their bitmaps back (A4).
// - A zoom keeps the document point under the pointer (Ctrl+wheel, pinch) or under the
//   centre of the view (buttons, keys) where it was (A3).
// - The current page is the one under the middle of the view; it is reported to the
//   page indicator and the thumbnails, and announced (A5, A20).
// - Field boxes are the caller's: they sit in each page's overlay and are positioned in
//   percentages of the page, which is PDF points × scale without a relayout per zoom.
//
// The PDFs come in as pdfview.js handles; nothing here parses a file.

import { h, clear, reducedMotion } from "./dom.js";
import { t } from "./i18n.js";
import { icon } from "./icons.js";

/// 100 % is the page at its printed size: 96 CSS px per 72 points.
export const ACTUAL = 96 / 72;
export const MIN_SCALE = 0.25 * ACTUAL;
export const MAX_SCALE = 4 * ACTUAL;
/// The zoom presets in the menu, as percentages of the printed size.
export const PRESETS = [50, 75, 100, 125, 150, 200];

/// The scale for `mode` ("fit-width", "fit-page" or a number: CSS px per point) for
/// pages of at most `maxW`×`maxH` points in a view of `w`×`h` CSS px with `pad` px of
/// margin on each side. Pure, for tests.
export function scaleFor(mode, maxW, maxH, w, h, pad = 24) {
  if (typeof mode === "number") return clampScale(mode);
  if (!(maxW > 0) || !(maxH > 0)) return ACTUAL;
  const fitW = Math.max(40, w - 2 * pad) / maxW;
  if (mode === "fit-page") return clampScale(Math.min(fitW, Math.max(40, h - 2 * pad) / maxH));
  return clampScale(fitW);
}

export function clampScale(s) {
  if (!Number.isFinite(s)) return ACTUAL;
  return Math.min(MAX_SCALE, Math.max(MIN_SCALE, s));
}

/// The zoom one preset step from `scale` (dir +1 or −1), as a scale.
export function stepScale(scale, dir) {
  const pct = (scale / ACTUAL) * 100;
  const list = dir > 0 ? PRESETS : [...PRESETS].reverse();
  const next = list.find((p) => (dir > 0 ? p > pct + 0.5 : p < pct - 0.5));
  return clampScale(((next ?? (dir > 0 ? pct * 1.25 : pct / 1.25)) / 100) * ACTUAL);
}

/// Where a scroll position must go so that the point `fy` of the way down page `i`
/// (and `fx` across it) stays at `ay` (and `ax`) px from the view's top-left, given the
/// pages' new tops and sizes. Pure, for tests.
export function anchoredScroll({ top, left, height, width }, fx, fy, ax, ay) {
  return { x: Math.max(0, left + fx * width - ax), y: Math.max(0, top + fy * height - ay) };
}

/// Make a document view. `pages`: `[{key, n, total, name, width, height, pdf}]` (points,
/// pdf: a pdfview.js handle). Callbacks: `onLayout(view)` after a relayout, `onPage(i)`
/// when the current page changes, `onZoom(view)`. `padLeft`: px the fit leaves free on
/// the left beyond the usual margin, or a function answering it at each layout (UX-06:
/// the signer's Start flag room, which a media query sets).
export function docView({ label, pages = [], mode = "fit-width", onLayout = null, onPage = null, onZoom = null, padLeft = 0, testId = "doc-scroller" }) {
  const live = h("div", { class: "os-sr-only", attrs: { "aria-live": "polite", "data-testid": "doc-live" } });
  const inner = h("div", { class: "os-docview__pages" });
  const scroller = h("div", { class: "os-docview", attrs: { role: "region", "aria-label": label, tabindex: "0", "data-testid": testId, id: "document" } }, inner);
  const view = {
    scroller, inner, live, pages: [], els: [], scale: ACTUAL, mode, current: 0,
    setPages, setZoom, zoomBy, step, scrollToPage, scrollToBox, pageAt, relayout, announce, destroy, percent,
  };
  let laidOut = false;
  let tops = [];
  let paintTimer = null;
  let announceTimer = null;
  const painted = new Map(); // page index → scale painted at
  const leftRoom = () => Math.max(0, Number(typeof padLeft === "function" ? padLeft() : padLeft) || 0);

  const near = typeof IntersectionObserver === "function" ? new IntersectionObserver((entries) => {
    for (const e of entries) {
      const i = Number(e.target.dataset.index);
      if (e.isIntersecting) paint(i);
    }
  }, { root: scroller, rootMargin: "100% 0px 100% 0px" }) : null;
  const far = typeof IntersectionObserver === "function" ? new IntersectionObserver((entries) => {
    for (const e of entries) if (!e.isIntersecting) release(Number(e.target.dataset.index));
  }, { root: scroller, rootMargin: "300% 0px 300% 0px" }) : null;

  function setPages(list) {
    near?.disconnect(); far?.disconnect();
    painted.clear();
    clear(inner);
    view.pages = list;
    view.els = list.map((p, i) => {
      const overlay = h("div", { class: "os-page__overlay", attrs: { "data-doc": p.key, "data-page": String(p.n) } });
      const el = h("div", { class: "os-page is-loading", attrs: { role: "group", "aria-label": t("prepare.page-of", { n: p.n, total: p.total, name: p.name }), "data-index": String(i), "data-doc": p.key, "data-page": String(p.n) } }, overlay);
      inner.append(el);
      return { el, overlay, canvas: null };
    });
    view.current = Math.min(view.current, Math.max(0, list.length - 1));
    layout();
    for (const { el } of view.els) { near?.observe(el); far?.observe(el); }
    if (!near) view.els.forEach((_, i) => paint(i));
  }

  function maxSize() {
    let w = 0; let hgt = 0;
    for (const p of view.pages) { w = Math.max(w, p.width); hgt = Math.max(hgt, p.height); }
    return [w, hgt];
  }

  function layout() {
    const [mw, mh] = maxSize();
    const pad = remPx(1.5);
    view.scale = scaleFor(view.mode, mw, mh, scroller.clientWidth - leftRoom(), scroller.clientHeight, pad);
    view.els.forEach(({ el }, i) => {
      const p = view.pages[i];
      el.style.width = `${p.width * view.scale}px`;
      el.style.height = `${p.height * view.scale}px`;
    });
    tops = view.els.map(({ el }) => el.offsetTop);
    laidOut = true;
    onLayout?.(view);
    schedulePaint();
  }

  /// Repaint the painted pages at the new scale once zooming has settled.
  function schedulePaint() {
    clearTimeout(paintTimer);
    paintTimer = setTimeout(() => {
      for (const i of [...painted.keys()]) if (painted.get(i) !== view.scale && isNear(i)) paint(i, true);
    }, 160);
  }
  function isNear(i) {
    const el = view.els[i]?.el;
    if (!el) return false;
    const r = el.getBoundingClientRect();
    const s = scroller.getBoundingClientRect();
    return r.bottom > s.top - s.height && r.top < s.bottom + s.height;
  }

  function paint(i, again = false) {
    const slot = view.els[i];
    const p = view.pages[i];
    if (!slot || !p?.pdf) return;
    if (!again && painted.get(i) === view.scale) return;
    const scale = view.scale;
    painted.set(i, scale);
    // Paint off-screen, then swap: the old bitmap stays (stretched) until the new one is ready.
    const canvas = h("canvas", { class: "os-page__canvas", attrs: { "aria-hidden": "true" } });
    p.pdf.render(p.n, canvas, scale).then(() => {
      if (painted.get(i) !== scale) return;
      if (slot.canvas) slot.canvas.replaceWith(canvas); else slot.el.prepend(canvas);
      slot.canvas = canvas;
      slot.el.classList.remove("is-loading", "is-error");
    }).catch(() => { slot.el.classList.add("is-error"); slot.el.classList.remove("is-loading"); });
  }

  function release(i) {
    const slot = view.els[i];
    if (!slot?.canvas) return;
    slot.canvas.width = 0; slot.canvas.height = 0;
    slot.canvas.remove();
    slot.canvas = null;
    painted.delete(i);
    slot.el.classList.add("is-loading");
  }

  /// The index of the page under the vertical middle of the view.
  function pageAt(y = scroller.scrollTop + scroller.clientHeight / 2) {
    let lo = 0; let hi = tops.length - 1; let ans = 0;
    while (lo <= hi) { const m = (lo + hi) >> 1; if (tops[m] <= y) { ans = m; lo = m + 1; } else hi = m - 1; }
    return ans;
  }

  let scrollRaf = 0;
  scroller.addEventListener("scroll", () => {
    if (scrollRaf) return;
    scrollRaf = requestAnimationFrame(() => {
      scrollRaf = 0;
      if (!laidOut || !view.els.length) return;
      // At the very bottom the last page counts as current even when short.
      const atEnd = scroller.scrollTop + scroller.clientHeight >= scroller.scrollHeight - 2;
      const i = atEnd ? view.els.length - 1 : pageAt();
      if (i !== view.current) {
        view.current = i;
        onPage?.(i);
        const p = view.pages[i];
        clearTimeout(announceTimer);
        announceTimer = setTimeout(() => announce(t("doc.page-now", { n: i + 1, total: view.pages.length, name: p.name })), 600);
      }
    });
  }, { passive: true });

  /// Change the zoom. `anchor`: `{x, y}` in client px to hold still; default the centre.
  function setZoom(mode, anchor = null) {
    if (!view.els.length) { view.mode = mode; return; }
    const s = scroller.getBoundingClientRect();
    const ax = anchor ? anchor.x - s.left : scroller.clientWidth / 2;
    const ay = anchor ? anchor.y - s.top : scroller.clientHeight / 2;
    const cy = scroller.scrollTop + ay;
    const i = pageAt(cy);
    const el = view.els[i].el;
    const fy = (cy - el.offsetTop) / el.offsetHeight;
    const fx = (scroller.scrollLeft + ax - el.offsetLeft) / el.offsetWidth;
    const before = view.scale;
    view.mode = mode;
    layout();
    const pos = anchoredScroll({ top: el.offsetTop, left: el.offsetLeft, height: el.offsetHeight, width: el.offsetWidth }, fx, fy, ax, ay);
    scroller.scrollTop = pos.y;
    scroller.scrollLeft = pos.x;
    if (Math.abs(before - view.scale) > 1e-6) {
      onZoom?.(view);
      clearTimeout(announceTimer);
      announceTimer = setTimeout(() => announce(t("doc.zoom-now", { pct: percent() })), 400);
    }
  }
  function zoomBy(factor, anchor = null) { setZoom(clampScale(view.scale * factor), anchor); }
  function step(dir) { setZoom(stepScale(view.scale, dir)); }
  function percent() { return Math.round((view.scale / ACTUAL) * 100); }

  /// After a resize: refit when the fit's scale changed. Nothing moves otherwise, so a
  /// scroll in progress (a thumbnail's smooth scroll) is never cut short.
  function relayout() {
    if (!view.els.length || typeof view.mode === "number") return;
    const [mw, mh] = maxSize();
    const next = scaleFor(view.mode, mw, mh, scroller.clientWidth - leftRoom(), scroller.clientHeight, remPx(1.5));
    if (Math.abs(next - view.scale) < 1e-4) return;
    setZoom(view.mode);
  }

  function smooth() { return reducedMotion() ? "auto" : "smooth"; }
  function scrollToPage(i) {
    const el = view.els[i]?.el;
    if (!el) return;
    scroller.scrollTo({ top: el.offsetTop - remPx(1), behavior: smooth() });
  }
  /// Bring a box `{x, y, width, height}` (points) on page `i` into the middle of the view.
  function scrollToBox(i, box) {
    const el = view.els[i]?.el;
    if (!el) return;
    const top = el.offsetTop + box.y * view.scale;
    const left = el.offsetLeft + box.x * view.scale;
    const y = top + (box.height * view.scale) / 2 - scroller.clientHeight / 2;
    const x = left + (box.width * view.scale) / 2 - scroller.clientWidth / 2;
    scroller.scrollTo({ top: Math.max(0, y), left: Math.max(0, x), behavior: smooth() });
  }

  function announce(msg) { live.textContent = ""; setTimeout(() => { live.textContent = msg; }, 30); }

  // Ctrl/Cmd + wheel (and a trackpad pinch, which browsers send as Ctrl+wheel): zoom at the pointer.
  scroller.addEventListener("wheel", (e) => {
    if (!(e.ctrlKey || e.metaKey)) return;
    e.preventDefault();
    const d = e.deltaMode === 1 ? e.deltaY * 16 : e.deltaY;
    zoomBy(Math.exp(-d * 0.0025), { x: e.clientX, y: e.clientY });
  }, { passive: false });

  // Two fingers: zoom live at their midpoint; one finger scrolls as usual.
  const touches = new Map();
  let pinch = null;
  scroller.addEventListener("pointerdown", (e) => {
    if (e.pointerType !== "touch") return;
    touches.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (touches.size === 2) {
      const [a, b] = [...touches.values()];
      pinch = { d: Math.hypot(a.x - b.x, a.y - b.y), s: view.scale };
    }
  });
  scroller.addEventListener("pointermove", (e) => {
    if (!touches.has(e.pointerId)) return;
    touches.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (pinch && touches.size === 2) {
      const [a, b] = [...touches.values()];
      const d = Math.hypot(a.x - b.x, a.y - b.y);
      if (pinch.d > 0 && d > 0) setZoom(clampScale(pinch.s * (d / pinch.d)), { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 });
    }
  });
  const lift = (e) => { touches.delete(e.pointerId); if (touches.size < 2) pinch = null; };
  scroller.addEventListener("pointerup", lift);
  scroller.addEventListener("pointercancel", lift);

  // Ctrl/Cmd + = / − / 0 act on the document while this view is mounted.
  const onKey = (e) => {
    if (!(e.ctrlKey || e.metaKey) || e.altKey || !scroller.isConnected) return;
    const k = e.code;
    if (k === "Equal" || k === "NumpadAdd") { e.preventDefault(); step(1); }
    else if (k === "Minus" || k === "NumpadSubtract") { e.preventDefault(); step(-1); }
    else if (k === "Digit0" || k === "Numpad0") { e.preventDefault(); setZoom("fit-width"); }
  };
  window.addEventListener("keydown", onKey, true);

  let resizeTimer = null;
  const ro = typeof ResizeObserver === "function" ? new ResizeObserver(() => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(relayout, 120);
  }) : null;
  ro?.observe(scroller);

  function destroy() {
    near?.disconnect(); far?.disconnect(); ro?.disconnect();
    window.removeEventListener("keydown", onKey, true);
    clearTimeout(paintTimer); clearTimeout(announceTimer); clearTimeout(resizeTimer);
  }

  if (pages.length) queueMicrotask(() => setPages(pages));
  return view;
}

/// `n` rem in CSS px at the current root size.
export function remPx(n) {
  const fs = Number.parseFloat(getComputedStyle(document.documentElement).fontSize) || 16;
  return n * fs;
}

/// The zoom controls for a view: zoom out, a preset menu (fit width, fit page, 50–200 %,
/// and the current custom zoom), zoom in, and "Page n of N". Returns `{el, sync()}`;
/// call `sync()` after the zoom or page changes.
export function zoomControls(view, { size = "sm", testId = "zoom" } = {}) {
  const out = iconBtn("zoom-out", t("doc.zoom-out"), () => view.step(-1), size);
  const inn = iconBtn("zoom-in", t("doc.zoom-in"), () => view.step(1), size);
  const sel = h("select", { class: "os-input os-input--sm os-zoomsel", attrs: { "aria-label": t("doc.zoom"), title: t("doc.zoom"), "data-testid": `${testId}-select` } });
  const custom = h("option", { value: "custom", hidden: true });
  sel.append(
    h("option", { value: "fit-width", text: t("doc.fit-width") }),
    h("option", { value: "fit-page", text: t("doc.fit-page") }),
    ...PRESETS.map((p) => h("option", { value: String(p), text: `${p}%` })),
    custom);
  sel.addEventListener("change", () => {
    const v = sel.value;
    if (v === "fit-width" || v === "fit-page") view.setZoom(v);
    else if (v !== "custom") view.setZoom(clampScale((Number(v) / 100) * ACTUAL));
  });
  const page = h("span", { class: "os-pageind", attrs: { "data-testid": "page-indicator" } });
  const el = h("div", { class: "os-zoomctl", attrs: { role: "group", "aria-label": t("doc.zoom") } }, out, sel, inn, page);
  function sync() {
    const pct = view.percent();
    if (typeof view.mode === "string") {
      sel.value = view.mode;
      custom.hidden = true;
    } else if (PRESETS.includes(pct)) {
      sel.value = String(pct);
    } else {
      custom.textContent = `${pct}%`;
      custom.hidden = false;
      sel.value = "custom";
    }
    // The option's text says what fit means now: "Fit width (142%)".
    sel.options[0].textContent = view.mode === "fit-width" ? `${t("doc.fit-width")} (${pct}%)` : t("doc.fit-width");
    sel.options[1].textContent = view.mode === "fit-page" ? `${t("doc.fit-page")} (${pct}%)` : t("doc.fit-page");
    out.disabled = view.scale <= MIN_SCALE + 1e-6;
    inn.disabled = view.scale >= MAX_SCALE - 1e-6;
    const n = view.pages.length;
    page.textContent = n ? t("doc.page-n", { n: view.current + 1, total: n }) : "";
  }
  return { el, sync, page };
}

function iconBtn(ic, label, onClick, size) {
  const b = h("button", { type: "button", class: `os-btn os-btn--ghost os-btn--${size} os-btn--icon`, attrs: { "aria-label": label, title: label } }, icon(ic, { size: size === "sm" ? 16 : 20 }));
  b.addEventListener("click", onClick);
  return b;
}

/// The page thumbnails for a view in `container` (a list that scrolls on its own): drawn
/// lazily, the current one marked and kept in view, a click jumps to its page.
export function thumbnails(view, container, { width = 96, byDocument = false } = {}) {
  const ol = h("ol", { class: "os-thumbs__list" });
  container.append(ol);
  const btns = [];
  const io = typeof IntersectionObserver === "function" ? new IntersectionObserver((entries) => {
    for (const e of entries) {
      if (!e.isIntersecting) continue;
      const i = Number(e.target.dataset.index);
      const p = view.pages[i];
      const c = e.target.querySelector("canvas");
      if (p?.pdf && c && !c.dataset.done) { c.dataset.done = "1"; p.pdf.render(p.n, c, width / p.width).catch(() => {}); }
      io.unobserve(e.target);
    }
  }, { root: container, rootMargin: "200px" }) : null;
  function build() {
    clear(ol); btns.length = 0;
    view.pages.forEach((p, i) => {
      const c = h("canvas", { attrs: { "aria-hidden": "true" } });
      c.style.aspectRatio = `${p.width} / ${p.height}`;
      const b = h("button", { type: "button", class: "os-thumb", attrs: { "data-index": String(i), "aria-label": t("prepare.page-of", { n: p.n, total: p.total, name: p.name }), title: t("doc.go-page", { n: i + 1 }) } }, c, h("span", { class: "os-thumb__n", text: String(i + 1) }));
      b.addEventListener("click", () => { view.scrollToPage(i); mark(i); });
      // Grouped by document (UX-05, the editor): each document's name heads its pages.
      if (byDocument && p.n === 1) ol.append(h("li", { class: "os-thumbs__doc", attrs: { "data-testid": "thumbs-doc" } }, h("span", { class: "os-trunc", title: p.name, text: p.name })));
      ol.append(h("li", {}, b));
      btns.push(b);
      if (io) io.observe(b); else if (p.pdf) p.pdf.render(p.n, c, width / p.width).catch(() => {});
    });
    mark(view.current);
  }
  function mark(i) {
    btns.forEach((b, j) => { if (j === i) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current"); });
    const b = btns[i];
    if (!b) return;
    const top = b.offsetTop;
    if (top < container.scrollTop || top + b.offsetHeight > container.scrollTop + container.clientHeight) {
      container.scrollTop = Math.max(0, top - container.clientHeight / 3);
    }
  }
  /// A count on each thumbnail (the editor: fields on that page, F-06); 0 shows nothing.
  /// `count(i)` gives the number, `label(n)` its words for assistive technology.
  function badges(count, label) {
    btns.forEach((b, i) => {
      const n = count(i);
      let s = b.querySelector(".os-thumb__count");
      if (!n) { s?.remove(); b.removeAttribute("aria-description"); return; }
      // Drawn from data-count by CSS, so the visible text stays the page number (SC 2.5.3).
      if (!s) { s = h("span", { class: "os-thumb__count", attrs: { "aria-hidden": "true" } }); b.append(s); }
      s.dataset.count = String(n);
      s.title = label(n);
      b.setAttribute("aria-description", label(n));
    });
  }
  return { build, mark, badges, destroy() { io?.disconnect(); } };
}
