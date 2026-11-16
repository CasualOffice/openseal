// PDF pages on screen (WEB-01, ADR-007): vendored pdf.js 4.10.38 (Apache-2.0,
// vendor/pdfjs/, PROVENANCE.md), parsing in its worker, painting to canvas only.
//
// Hostile-file posture (docs/07): `isEvalSupported: false` (no `new Function` for
// fonts, so the CSP needs no 'unsafe-eval'); no scripting sandbox is loaded, so a
// document's JavaScript never runs; no annotation or text layer is built, so links,
// launch actions and forms are not live; XFA off; fonts and CMaps come from the
// vendored copies, never the network. The bytes come from our own API.

let lib = null;

async function pdfjs() {
  if (!lib) {
    lib = await import("./vendor/pdfjs/pdf.min.mjs");
    lib.GlobalWorkerOptions.workerSrc = new URL("./vendor/pdfjs/pdf.worker.min.mjs", import.meta.url).href;
  }
  return lib;
}

/// Open a PDF from bytes. Returns `{pages: [{width, height}] in points (displayed
/// space, ADR-019), render(pageNo, canvas, scale), destroy()}`.
export async function openPdf(bytes) {
  const p = await pdfjs();
  const task = p.getDocument({
    data: bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes),
    isEvalSupported: false,
    enableXfa: false,
    disableAutoFetch: true,
    disableStream: true,
    cMapUrl: new URL("./vendor/pdfjs/cmaps/", import.meta.url).href,
    cMapPacked: true,
    standardFontDataUrl: new URL("./vendor/pdfjs/standard_fonts/", import.meta.url).href,
    useSystemFonts: false,
  });
  const doc = await task.promise;
  const pages = [];
  for (let i = 1; i <= doc.numPages; i++) {
    const page = await doc.getPage(i);
    const vp = page.getViewport({ scale: 1 });
    pages.push({ width: vp.width, height: vp.height });
  }
  const tasks = new Map();
  return {
    pages,
    /// Paint page `n` (1-based) into `canvas` at `scale` CSS px per point, sharp on
    /// high-density screens. A repaint of the same canvas cancels the one before.
    async render(n, canvas, scale) {
      const page = await doc.getPage(n);
      const vp = page.getViewport({ scale });
      const dpr = Math.min(globalThis.devicePixelRatio || 1, 3);
      canvas.width = Math.floor(vp.width * dpr);
      canvas.height = Math.floor(vp.height * dpr);
      canvas.style.width = `${vp.width}px`; // px-ok: PDF points × scale
      canvas.style.height = `${vp.height}px`; // px-ok: PDF points × scale
      tasks.get(canvas)?.cancel();
      const task = page.render({
        canvasContext: canvas.getContext("2d"),
        viewport: vp,
        transform: dpr !== 1 ? [dpr, 0, 0, dpr, 0, 0] : undefined,
        annotationMode: p.AnnotationMode.ENABLE,
      });
      tasks.set(canvas, task);
      try { await task.promise; } catch (e) { if (e?.name !== "RenderingCancelledException") throw e; } finally {
        if (tasks.get(canvas) === task) tasks.delete(canvas);
      }
    },
    destroy() { doc.destroy(); },
  };
}

/// The bytes of the file attached to a PDF as `name` (an embedded file, read by pdf.js
/// in its worker), or null when there is none or it is larger than `maxBytes`. Used by
/// the Verify page for `audit-trail.json` (docs/32). Nothing attached is ever opened
/// or run; the bytes go to a bounded JSON reader (trail.js).
export async function readAttachment(bytes, name, maxBytes) {
  const p = await pdfjs();
  // A copy: pdf.js transfers the buffer it is given to its worker.
  const task = p.getDocument({ data: new Uint8Array(bytes).slice(), isEvalSupported: false, enableXfa: false, disableAutoFetch: true, disableStream: true, useSystemFonts: false });
  const doc = await task.promise;
  try {
    const all = (await doc.getAttachments()) || {};
    for (const a of Object.values(all)) {
      if (a?.filename === name && a.content instanceof Uint8Array) return a.content.length <= maxBytes ? a.content : null;
    }
    return null;
  } finally { doc.destroy(); }
}

/// The scale that fits a page `width` points into `available` CSS px, between 0.4 and 2.
export function fitScale(width, available) {
  return Math.max(0.4, Math.min(2, (available - 2) / width));
}
