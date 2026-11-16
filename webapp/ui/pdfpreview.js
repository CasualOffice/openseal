// A PDF preview for any screen that shows a document (WEB-02 redesign): a toolbar
// (pages, zoom out, zoom in, fit), a strip of page thumbnails, and the pages, drawn by
// the vendored pdf.js in its worker (pdfview.js, ADR-007: no scripts, no forms, no
// links). Used by the envelope detail, Templates and Verify; the editor and the signing
// page draw their own pages because fields sit on them.

import { h, clear, reducedMotion, rem } from "../dom.js";
import { icon } from "../icons.js";
import { t } from "../i18n.js";
import { openPdf, fitScale } from "../pdfview.js";
import { button } from "./core.js";

/// `load()` resolves the PDF's bytes (a Uint8Array) or a Blob. `name` labels the pages.
/// `decorate(pageEl, pageNo, scale)` (UX-08), when given, adds to each drawn page (a
/// template's role outlines), `scale` being CSS pixels per PDF point.
/// `height` is the pages' box in rem (WEB-12; it was px: 640 px is 40 rem).
/// Returns `{el, destroy()}`; the pages paint as soon as the bytes arrive and the
/// preview has a width, and again when that width changes (a wider window, a larger
/// root size, a panel closing).
export function pdfPreview({ load, name = "", height = 40, testId = "pdf-preview", decorate = null }) {
  let pdf = null;
  let zoom = 1;
  const label = h("span", { class: "os-zoom__label", attrs: { "aria-live": "polite" } });
  const count = h("span", { class: "os-muted os-small" });
  const pages = h("div", { class: "os-preview__pages", attrs: { role: "region", "aria-label": t("preview.pages", { name }), tabindex: "0" } });
  const thumbs = h("ol", { class: "os-preview__thumbs", attrs: { "aria-label": t("preview.thumbs") } });
  const zoomBy = (f) => { zoom = Math.max(0.5, Math.min(3, Math.round(zoom * f * 100) / 100)); paint(); };
  const bar = h("div", { class: "os-preview__bar", attrs: { role: "toolbar", "aria-label": t("preview.toolbar") } },
    icon("file-text", { size: 16 }), h("strong", { class: "os-preview__name", text: name }), count, h("span", { class: "os-spacer" }),
    button(t("prepare.zoom-out"), { icon: "zoom-out", size: "sm", variant: "ghost", iconOnly: true, onClick: () => zoomBy(1 / 1.25) }),
    label,
    button(t("prepare.zoom-in"), { icon: "zoom-in", size: "sm", variant: "ghost", iconOnly: true, onClick: () => zoomBy(1.25) }),
    button(t("prepare.zoom-fit"), { size: "sm", variant: "ghost", onClick: () => { zoom = 1; paint(); } }));
  const el = h("div", { class: "os-preview", attrs: { "data-testid": testId, "aria-busy": "true" } }, bar,
    h("div", { class: "os-preview__body" }, h("nav", { class: "os-preview__rail", attrs: { "aria-label": t("preview.thumbs") } }, thumbs), pages));
  el.style.setProperty("--os-preview-h", `${height}rem`);
  pages.append(h("div", { class: "os-page os-skeleton-page", attrs: { "aria-hidden": "true" } }));

  let paintedWidth = 0;
  function paint() {
    if (!pdf) return;
    // Not laid out yet (a screen built before it is shown): the observer below paints
    // once it has a width.
    if (!pages.clientWidth) return;
    paintedWidth = pages.clientWidth;
    clear(pages);
    clear(thumbs);
    label.textContent = `${Math.round(zoom * 100)}%`;
    count.textContent = (pdf.pages.length === 1 ? t("prepare.page-one") : t("prepare.pages-long", { n: pdf.pages.length }));
    const width = Math.max(rem(15), pages.clientWidth - rem(2));
    pdf.pages.forEach((p, i) => {
      const scale = Math.min(fitScale(p.width, width), 1.6) * zoom;
      const canvas = h("canvas", { attrs: { "aria-hidden": "true" } });
      const page = h("div", { class: "os-page is-loading", attrs: { role: "img", "aria-label": t("preview.page", { n: i + 1, total: pdf.pages.length, name }), "data-page": String(i + 1) } }, canvas);
      page.style.width = `${p.width * scale}px`; // px-ok: PDF points × scale
      page.style.height = `${p.height * scale}px`; // px-ok: PDF points × scale
      pages.append(page);
      decorate?.(page, i + 1, scale);
      pdf.render(i + 1, canvas, scale).then(() => page.classList.remove("is-loading")).catch(() => page.classList.add("is-error"));
      const tc = h("canvas", { attrs: { "aria-hidden": "true" } });
      pdf.render(i + 1, tc, rem(4) / p.width).catch(() => {});
      const tb = h("button", { type: "button", class: "os-thumb", attrs: { "aria-label": t("preview.go-page", { n: i + 1 }) } }, tc, h("span", { class: "os-thumb__n", text: String(i + 1) }));
      tb.addEventListener("click", () => page.scrollIntoView({ behavior: reducedMotion() ? "auto" : "smooth", block: "start" }));
      thumbs.append(h("li", {}, tb));
    });
  }

  // Repaint when the pages' width changes by more than a few percent (not on every
  // pixel of a drag), so a page always fits the column it is in.
  const ro = typeof ResizeObserver === "function" ? new ResizeObserver(() => {
    const w = pages.clientWidth;
    if (pdf && w && Math.abs(w - paintedWidth) > Math.max(rem(1), paintedWidth * 0.04)) requestAnimationFrame(paint);
  }) : null;
  ro?.observe(pages);

  (async () => {
    try {
      const got = await load();
      const bytes = got instanceof Uint8Array ? got : new Uint8Array(await got.arrayBuffer());
      pdf = await openPdf(bytes.slice());
      el.removeAttribute("aria-busy");
      requestAnimationFrame(paint);
    } catch {
      el.removeAttribute("aria-busy");
      clear(pages);
      pages.append(h("p", { class: "os-field-error", attrs: { "data-testid": "preview-error" }, text: t("preview.error") }));
    }
  })();
  return { el, destroy() { ro?.disconnect(); pdf?.destroy(); } };
}
