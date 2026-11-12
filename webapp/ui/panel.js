// Side panels (WEB-06, docs/47 §Layout spec; owner instruction 22): panels beside the
// document instead of dialogs over it.
//
// - `dockPanel`: a panel docked in a screen's layout (editor palette and properties,
//   signer field list and thumbnails). Resizable from its inner edge by pointer or by
//   arrow keys on the handle (a `separator`, WAI-ARIA window splitter), between a
//   minimum and a maximum; collapsible to an icon rail; width and state remembered per
//   panel. Below 48em it becomes a bottom sheet the screen opens and closes.
// - `openPanel`: a transient side panel with `openDialog`'s contract (title, build,
//   actions; resolves the value given to `close`). Non-modal: the page stays visible
//   and usable; Escape closes it and focus returns where it was. Remembered width; a
//   bottom sheet on phones. True modals remain only for destructive confirmations.

import { h, reducedMotion } from "../dom.js";
import { icon } from "../icons.js";
import { t } from "../i18n.js";
import { button, busy, toastError } from "./core.js";

const KEY = "openseal.panel.";

/// What was remembered for panel `id`: `{w, c}` (width in rem, collapsed), or `{}`.
export function recall(id) {
  try {
    const v = JSON.parse(localStorage.getItem(KEY + id) || "{}");
    return v && typeof v === "object" ? v : {};
  } catch { return {}; }
}
function remember(id, v) {
  try { localStorage.setItem(KEY + id, JSON.stringify(v)); } catch { /* storage blocked: just forget */ }
}

/// A width in rem kept between `min` and `max`, to a tenth of a rem; a non-number is `dflt`.
export function clampWidth(w, min, max, dflt) {
  if (!Number.isFinite(w)) return dflt;
  return Math.round(Math.min(max, Math.max(min, w)) * 10) / 10;
}

const rootPx = () => Number.parseFloat(getComputedStyle(document.documentElement).fontSize) || 16;
const phone = () => typeof matchMedia === "function" && matchMedia("(max-width: 47.999em)").matches;

/// A docked panel. `side`: "left" | "right" (the handle sits on the inner edge).
/// Returns `{el, body, head, collapse(on), isCollapsed(), openSheet(), closeSheet(), sheetOpen()}`.
export function dockPanel({ id, side = "right", title, icon: ic = "layers", width = 15, min = 11, max = 30, collapsed = false, testId = null, onToggle = null }) {
  const saved = recall(id);
  let w = clampWidth(saved.w, min, max, width);
  let c = typeof saved.c === "boolean" ? saved.c : collapsed;
  const headId = `pn-${id}`;
  const bodyId = `pb-${id}`;
  const heading = h("h2", { id: headId, class: "os-dock__title", text: title });
  const toggle = h("button", { type: "button", class: "os-btn os-btn--ghost os-btn--sm os-btn--icon os-dock__toggle", attrs: { "aria-controls": bodyId, "data-testid": `${id}-toggle` } });
  const close = h("button", { type: "button", class: "os-btn os-btn--ghost os-btn--md os-btn--icon os-dock__close", attrs: { "aria-label": t("panel.close", { name: title }), title: t("panel.close", { name: title }) } }, icon("x"));
  const head = h("div", { class: "os-dock__head" }, heading, toggle, close);
  const body = h("div", { class: "os-dock__body", id: bodyId });
  const handle = h("div", { class: "os-dock__handle", attrs: { role: "separator", tabindex: "0", "aria-orientation": "vertical", "aria-controls": bodyId, "aria-label": t("panel.resize", { name: title }), "aria-valuemin": String(min), "aria-valuemax": String(max), title: t("panel.resize-tip") } });
  const el = h("aside", { class: `os-dock os-dock--${side}`, attrs: { "aria-labelledby": headId, "data-testid": testId || `panel-${id}`, "data-panel": id } }, head, body, handle);

  function apply() {
    el.style.setProperty("--os-dock-w", `${w}rem`);
    el.classList.toggle("is-collapsed", c);
    // Collapsed: the body is hidden by `.os-dock.is-collapsed` on desktop only (a phone
    // shows the panel as a sheet), so no `hidden` attribute that a resize would leave stale.
    handle.hidden = c;
    handle.setAttribute("aria-valuenow", String(w));
    handle.setAttribute("aria-valuetext", t("panel.width", { n: w }));
    const label = t(c ? "panel.expand" : "panel.collapse", { name: title });
    toggle.setAttribute("aria-label", label);
    toggle.title = label;
    toggle.setAttribute("aria-expanded", String(!c));
    toggle.replaceChildren(icon(`panel-${side}-${c ? "open" : "close"}`, { size: 16 }));
  }
  function save() { remember(id, { w, c }); }
  function collapse(on) { c = !!on; apply(); save(); onToggle?.(c); }
  toggle.addEventListener("click", () => collapse(!c));
  close.addEventListener("click", () => closeSheet());

  // Resize by pointer: drag the inner edge.
  handle.addEventListener("pointerdown", (e) => {
    if (e.button !== 0) return;
    e.preventDefault();
    handle.setPointerCapture?.(e.pointerId);
    const startX = e.clientX;
    const startW = w;
    const px = rootPx();
    el.classList.add("is-resizing");
    const move = (ev) => {
      const dx = (ev.clientX - startX) / px;
      w = clampWidth(startW + (side === "left" ? dx : -dx), min, max, width);
      apply();
    };
    const up = () => {
      handle.removeEventListener("pointermove", move);
      handle.removeEventListener("pointerup", up);
      handle.removeEventListener("pointercancel", up);
      el.classList.remove("is-resizing");
      save();
      onToggle?.(c);
    };
    handle.addEventListener("pointermove", move);
    handle.addEventListener("pointerup", up);
    handle.addEventListener("pointercancel", up);
  });
  // Resize by keyboard: arrows by 1 rem (Shift ×4), Home and End to the limits, Enter collapses.
  handle.addEventListener("keydown", (e) => {
    const stepRem = e.shiftKey ? 4 : 1;
    const grow = side === "left" ? "ArrowRight" : "ArrowLeft";
    const shrink = side === "left" ? "ArrowLeft" : "ArrowRight";
    let next = null;
    if (e.key === grow) next = w + stepRem;
    else if (e.key === shrink) next = w - stepRem;
    else if (e.key === "Home") next = min;
    else if (e.key === "End") next = max;
    else if (e.key === "Enter") { e.preventDefault(); collapse(true); toggle.focus(); return; }
    if (next == null) return;
    e.preventDefault();
    w = clampWidth(next, min, max, width);
    apply(); save(); onToggle?.(c);
  });

  // Phones: a bottom sheet the screen opens; Escape closes it.
  let returnTo = null;
  function openSheet(focus = true) {
    if (!phone()) { if (c) collapse(false); return; }
    returnTo = document.activeElement;
    el.classList.add("is-sheet-open");
    document.body.classList.add("has-sheet");
    if (focus) (body.querySelector("[autofocus], button, input, select, textarea, a[href]") || close).focus({ preventScroll: true });
  }
  function closeSheet() {
    if (!el.classList.contains("is-sheet-open")) return;
    el.classList.remove("is-sheet-open");
    document.body.classList.remove("has-sheet");
    if (returnTo?.isConnected) returnTo.focus({ preventScroll: true });
    returnTo = null;
  }
  el.addEventListener("keydown", (e) => { if (e.key === "Escape" && el.classList.contains("is-sheet-open")) { e.stopPropagation(); closeSheet(); } });
  apply();
  return { el, body, head, collapse, isCollapsed: () => c, openSheet, closeSheet, sheetOpen: () => el.classList.contains("is-sheet-open"), width: () => w };
}

// ---- Transient side panels ------------------------------------------------------------

let current = null; // the open panel's close function

/// Open a side panel with `openDialog`'s contract. `id` names the remembered width.
/// Resolves with the value given to `close(value)`, or `null` when dismissed.
/// `dismissible: false` (a one-time secret shown once): no close button, Escape and
/// `closePanel()` leave it open, and another panel cannot replace it; only its own
/// actions close it.
export function openPanel({ id = "side", title, description = null, build = null, actions = [], className = "", width = 26, min = 18, max = 48, host = null, dismissible = true }) {
  if (current?.dismissible === false) return Promise.resolve(null);
  current?.(null);
  return new Promise((resolve) => {
    const returnTo = document.activeElement;
    const titleId = `sp-${Math.random().toString(36).slice(2)}`;
    const saved = recall(`sheet.${id}`);
    let w = clampWidth(saved.w, min, max, width);
    const body = h("div", { class: "os-sheet__body" });
    const handle = h("div", { class: "os-dock__handle os-sheet__handle", attrs: { role: "separator", tabindex: "0", "aria-orientation": "vertical", "aria-label": t("panel.resize", { name: title }), "aria-valuemin": String(min), "aria-valuemax": String(max), title: t("panel.resize-tip") } });
    const panel = h("section", { class: `os-sheet ${className}`, attrs: { role: "dialog", "aria-modal": "false", "aria-labelledby": titleId, "data-testid": `sheet-${id}` } });
    let done = false;
    const close = (value = null) => {
      if (done) return;
      done = true;
      if (current === close) current = null;
      document.removeEventListener("keydown", onKey, true);
      panel.classList.add("is-leaving");
      setTimeout(() => {
        panel.remove();
        host?.classList.remove("has-hosted");
        document.body.classList.remove("has-side-sheet");
        if (returnTo?.isConnected) returnTo.focus?.({ preventScroll: true });
        resolve(value);
      }, reducedMotion() ? 0 : 150);
    };
    close.dismissible = dismissible;
    current = close;
    const setW = (v) => {
      w = clampWidth(v, min, max, width);
      panel.style.setProperty("--os-sheet-w", `${w}rem`);
      handle.setAttribute("aria-valuenow", String(w));
      handle.setAttribute("aria-valuetext", t("panel.width", { n: w }));
    };
    setW(w);
    handle.addEventListener("keydown", (e) => {
      const s = e.shiftKey ? 4 : 1;
      let n = null;
      if (e.key === "ArrowLeft") n = w + s;
      else if (e.key === "ArrowRight") n = w - s;
      else if (e.key === "Home") n = min;
      else if (e.key === "End") n = max;
      if (n == null) return;
      e.preventDefault();
      setW(n);
      remember(`sheet.${id}`, { w });
    });
    handle.addEventListener("pointerdown", (e) => {
      if (e.button !== 0) return;
      e.preventDefault();
      handle.setPointerCapture?.(e.pointerId);
      const x0 = e.clientX; const w0 = w; const px = rootPx();
      const move = (ev) => setW(w0 - (ev.clientX - x0) / px);
      const up = () => { handle.removeEventListener("pointermove", move); handle.removeEventListener("pointerup", up); remember(`sheet.${id}`, { w }); };
      handle.addEventListener("pointermove", move);
      handle.addEventListener("pointerup", up);
    });
    const head = h("div", { class: "os-sheet__head" },
      h("h2", { id: titleId, class: "os-dialog__title", text: title }),
      dismissible ? button(t("action.close"), { icon: "x", variant: "ghost", size: "sm", iconOnly: true, onClick: () => close(null) }) : null);
    panel.append(handle, head);
    if (description) body.append(h("p", { class: "os-muted", text: description }));
    if (build) build(body, close);
    panel.append(body);
    if (actions.length) {
      const foot = h("div", { class: "os-sheet__foot" });
      for (const a of actions) {
        const b = button(a.label, { variant: a.variant || "secondary", icon: a.icon, attrs: a.attrs || {} });
        b.addEventListener("click", async () => {
          if (!a.onClick) return close(a.value ?? null);
          try {
            const v = await busy(b, () => a.onClick(close));
            if (v !== undefined) close(v);
          } catch (e) { toastError(e); }
        });
        foot.append(b);
      }
      panel.append(foot);
    }
    const onKey = (e) => {
      if (e.key !== "Escape" || done || !dismissible) return;
      if (!panel.contains(e.target) && document.querySelector("dialog[open]")) return;
      e.preventDefault(); e.stopPropagation();
      close(null);
    };
    document.addEventListener("keydown", onKey, true);
    // In a docked panel's place when one is given and open (the signer's field list):
    // the document stays fully visible. Otherwise over the right edge, below the
    // screen's own bar, so its actions stay visible and reachable.
    const hosted = host && !phone() && host.getClientRects().length && host.getBoundingClientRect().width >= rootPx() * 12;
    if (hosted) {
      panel.classList.add("os-sheet--hosted");
      handle.hidden = true;
      host.classList.add("has-hosted");
      host.append(panel);
    } else {
      const bar = [...document.querySelectorAll(".os-sign__bar, .os-prepare__bar, .os-topbar")].find((b) => b.getClientRects().length);
      if (bar && !phone()) panel.style.setProperty("--os-sheet-top", `${Math.max(0, bar.getBoundingClientRect().bottom)}px`);
      document.body.append(panel);
    }
    document.body.classList.add("has-side-sheet");
    const first = body.querySelector("[autofocus], input:not([type=hidden]), textarea, select") || panel.querySelector(".os-sheet__foot .os-btn--primary") || head.querySelector("button");
    first?.focus({ preventScroll: true });
  });
}

/// Close the open side panel, if any (dismissed: resolves null); not one opened with
/// `dismissible: false`.
export function closePanel() { if (current?.dismissible !== false) current?.(null); }
