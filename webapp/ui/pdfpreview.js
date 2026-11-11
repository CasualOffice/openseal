// A PDF preview for any screen that shows a document (WEB-02 redesign): a toolbar
// (pages, zoom out, zoom in, fit), a strip of page thumbnails, and the pages, drawn by
// the vendored pdf.js in its worker (pdfview.js, ADR-007: no scripts, no forms, no
// links). Used by the envelope detail, Templates and Verify; the editor and the signing
// page draw their own pages because fields sit on them.

import { h, clear, reducedMotion } from "../dom.js";
import { icon } from "../icons.js";
import { t } from "../i18n.js";
import { openPdf, fitScale } from "../pdfview.js";
import { button } from "./core.js";

/// `load()` resolves the PDF's bytes (a Uint8Array) or a Blob. `name` labels the pages.
/// Returns `{el, destroy()}`; the pages paint as soon as the bytes arrive.
export function pdfPreview({ load, name = "", height = 640, testId = "pdf-preview" }) {
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
  el.style.setProperty("--os-preview-h", `${height}px`);
  pages.append(h("div", { class: "os-page os-skeleton-page", attrs: { "aria-hidden": "true" } }));

  function paint() {
    if (!pdf) return;
    clear(pages);
    clear(thumbs);
    label.textContent = `${Math.round(zoom * 100)}%`;
    count.textContent = (pdf.pages.length === 1 ? t("prepare.page-one") : t("prepare.pages-long", { n: pdf.pages.length }));
    const width = Math.max(240, (pages.clientWidth || 720) - 32);
    pdf.pages.forEach((p, i) => {
      const scale = Math.min(fitScale(p.width, width), 1.6) * zoom;
      const canvas = h("canvas", { attrs: { "aria-hidden": "true" } });
      const page = h("div", { class: "os-page is-loading", attrs: { role: "img", "aria-label": t("preview.page", { n: i + 1, total: pdf.pages.length, name }), "data-page": String(i + 1) } }, canvas);
      page.style.width = `${p.width * scale}px`;
      page.style.height = `${p.height * scale}px`;
      pages.append(page);
      pdf.render(i + 1, canvas, scale).then(() => page.classList.remove("is-loading")).catch(() => page.classList.add("is-error"));
      const tc = h("canvas", { attrs: { "aria-hidden": "true" } });
      pdf.render(i + 1, tc, 64 / p.width).catch(() => {});
      const tb = h("button", { type: "button", class: "os-thumb", attrs: { "aria-label": t("preview.go-page", { n: i + 1 }) } }, tc, h("span", { class: "os-thumb__n", text: String(i + 1) }));
      tb.addEventListener("click", () => page.scrollIntoView({ behavior: reducedMotion() ? "auto" : "smooth", block: "start" }));
      thumbs.append(h("li", {}, tb));
    });
  }

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
  return { el, destroy() { pdf?.destroy(); } };
}
