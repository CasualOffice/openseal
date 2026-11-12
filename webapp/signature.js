// Adopt a signature and initials (WEB-01; UX-06; docs/47 §Signer ceremony): Type (one
// of the bundled OFL script fonts, the accessible default), Draw (pointer and touch,
// with undo and clear), Upload (PNG or JPEG in a drop zone; near-white made transparent
// here, re-checked by the server). Each result is a PNG for `POST /s/{token}/adopt`.
// UX-06, after DocuSign's adopt dialog: the full name and the initials are adopted in
// one step when both are wanted, previewed together in each style; a problem is said
// beside the control (role alert), not in a toast.
// WEB-18 (the approved canvas, Signer.dc.html and SignerPhone.dc.html): a modal dialog
// with the mode as a segmented control, the styles as tiles (the two script faces the
// flattener embeds, so the mark on screen is the face in the PDF), a hinted draw pad,
// the consent line, and Cancel / Adopt and sign; on phones a bottom sheet with a drag
// handle (drag it down to dismiss).

import { h } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { openDialog, button } from "./ui/index.js";

const W = 600;
const H = 200;
const INK = "#0b1f4b";
const FONTS = [
  ["OpenSeal Great Vibes", "Great Vibes"],
  ["OpenSeal Allura", "Allura"],
];
const MAX_UPLOAD = 5 * 1024 * 1024;

/// The initials of a name ("Jordan A. Rivera" → "JAR"), at most three letters.
export function initialsOf(name) {
  return String(name || "").trim().split(/\s+/).filter(Boolean).map((p) => [...p][0].toUpperCase()).slice(0, 3).join("");
}

/// The marks the dialog asks for: `mark` ("signature" or "initials") always, and the
/// other one too when `both`. Pure, for the tests.
export function marksFor(mark, both) {
  const want = mark === "initials" ? "initials" : "signature";
  if (!both) return [want];
  return want === "signature" ? ["signature", "initials"] : ["initials", "signature"];
}

/// Open the adopt panel. Resolves `{marks: {signature?, initials?}}`, each
/// `{method, dataUrl, base64}`, or null when cancelled. `mark` is always in it; with
/// `both`, the other mark too when the signer gave it (typed initials, or drawn ones).
export function adoptDialog({ mark = "signature", name = "", both = false }) {
  const marks = marksFor(mark, both);
  const want = marks[0];
  let mode = "type";
  const typed = { signature: name, initials: initialsOf(name) };
  let font = 0;
  let uploaded = null;
  const pads = {};
  let err = null;
  const say = (key) => { err.textContent = key ? t(key) : ""; };

  let leaveFull = () => {};
  const title = both ? (want === "signature" ? "adopt.title-both" : "adopt.title-both-initials") : want === "initials" ? "adopt.title-initials" : "adopt.title";
  return openDialog({
    title: t(title),
    description: t("adopt.subtitle"),
    className: "os-adopt",
    build(body, close) {
      grabHandle(body, close);
      const tabs = h("div", { class: "os-adopt__modes", attrs: { role: "tablist", "aria-label": t("adopt.how") } });
      const panels = {};
      const tabBtns = {};
      for (const m of ["type", "draw", "upload"]) {
        const b = h("button", { type: "button", class: "os-adopt__mode", id: `adopt-tab-${m}`, attrs: { role: "tab", "aria-controls": `adopt-panel-${m}`, "aria-selected": String(m === mode), tabindex: m === mode ? "0" : "-1" } },
          h("span", { text: t(`adopt.${m}`) }));
        b.addEventListener("click", () => select(m));
        b.addEventListener("keydown", (e) => {
          const order = ["type", "draw", "upload"];
          const i = order.indexOf(m);
          if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
            e.preventDefault();
            const n = order[(i + (e.key === "ArrowRight" ? 1 : 2)) % 3];
            select(n);
            tabBtns[n].focus();
          }
        });
        tabBtns[m] = b;
        tabs.append(b);
        panels[m] = h("div", { class: `os-tabpanel os-adopt__panel os-adopt__panel--${m}`, id: `adopt-panel-${m}`, attrs: { role: "tabpanel", "aria-labelledby": `adopt-tab-${m}` }, hidden: m !== mode });
      }
      function select(m) {
        mode = m;
        say(null);
        for (const k of Object.keys(panels)) {
          panels[k].hidden = k !== m;
          tabBtns[k].setAttribute("aria-selected", String(k === m));
          tabBtns[k].tabIndex = k === m ? 0 : -1;
        }
        if (m === "draw") for (const p of Object.values(pads)) p.redraw();
        if (m === "type") requestAnimationFrame(() => fitSamples(panels.type));
      }

      // Type: the name and the initials, previewed together in each style.
      const inputs = {};
      const inputRow = h("div", { class: "os-adopt__inputs" });
      panels.type.append(inputRow);
      for (const [i, m] of marks.entries()) {
        const id = m === "initials" ? "adopt-initials" : "adopt-name";
        inputs[m] = h("input", { id, class: "os-input", value: typed[m], maxLength: m === "initials" ? 8 : 80, autocomplete: m === "initials" ? "off" : "name", attrs: { ...(i === 0 ? { autofocus: true } : {}), "aria-describedby": "adopt-err" } });
        inputs[m].addEventListener("input", () => { typed[m] = inputs[m].value; say(null); renderPreviews(); });
        inputRow.append(h("div", { class: `os-fieldrow os-adopt__input--${m}` }, h("label", { class: "os-label", attrs: { for: id }, text: t(m === "initials" ? "adopt.your-initials" : "adopt.your-name") }), inputs[m]));
      }
      if (marks.length > 1) panels.type.classList.add("os-adopt__type--both");
      const previews = h("div", { class: "os-adopt__fonts", attrs: { role: "radiogroup", "aria-label": t("adopt.style") } });
      function renderPreviews() {
        previews.replaceChildren(...FONTS.map(([family, label], i) => {
          const id = `adopt-font-${i}`;
          const radio = h("input", { type: "radio", name: "adopt-font", id, checked: i === font, class: "os-sr-only" });
          radio.addEventListener("change", () => { font = i; });
          const samples = marks.map((m) => h("span", { class: `os-adopt__sample os-adopt__sample--${m} os-script-${i + 1}`, text: typed[m] || " " }));
          return h("label", { class: "os-adopt__font", attrs: { for: id } }, radio, ...samples, h("span", { class: "os-sr-only", text: t("adopt.style-n", { name: label }) }));
        }));
        requestAnimationFrame(() => fitSamples(previews));
      }
      renderPreviews();
      panels.type.append(previews);

      // Draw: a pad per mark, 3:1, each with undo and clear and a full-screen mode.
      for (const m of marks) {
        pads[m] = drawPad(m, () => say(null));
        if (marks.length > 1) panels.draw.append(h("p", { class: "os-label", text: t(m === "initials" ? "adopt.your-initials" : "adopt.your-name") }));
        panels.draw.append(pads[m].el);
      }
      leaveFull = () => { for (const p of Object.values(pads)) p.leaveFull(); };

      // Upload: a drop zone for the mark being placed.
      const file = h("input", { id: "adopt-file", type: "file", accept: "image/png,image/jpeg", class: "os-sr-only", attrs: { "aria-describedby": "adopt-drop-help adopt-err" } });
      const preview = h("img", { class: "os-adopt__upload-preview", alt: "", hidden: true });
      const dropTitle = h("span", { class: "os-adopt__drop-title", text: t("adopt.drop") });
      const zone = h("label", { class: "os-adopt__drop", attrs: { for: "adopt-file", "data-testid": "adopt-drop" } },
        icon("upload", { size: 24 }), dropTitle,
        h("span", { id: "adopt-drop-help", class: "os-muted os-small", text: t("adopt.drop-help") }), preview);
      const take = async (f) => {
        say(null);
        if (!f) return;
        if (f.size > MAX_UPLOAD || !/^image\/(png|jpeg)$/.test(f.type)) { say("adopt.bad-image"); file.value = ""; return; }
        try {
          uploaded = await cleanImage(f);
          preview.src = uploaded.toDataURL("image/png");
          preview.hidden = false;
          preview.alt = t("adopt.upload-preview");
          zone.classList.add("has-image");
          dropTitle.textContent = t("adopt.choose-another");
        } catch {
          say("adopt.bad-image");
        }
      };
      file.addEventListener("change", () => take(file.files?.[0]));
      zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("is-dropping"); });
      zone.addEventListener("dragleave", () => zone.classList.remove("is-dropping"));
      zone.addEventListener("drop", (e) => { e.preventDefault(); zone.classList.remove("is-dropping"); take(e.dataTransfer?.files?.[0]); });
      if (marks.length > 1) panels.upload.append(h("p", { class: "os-muted os-small", text: t(want === "initials" ? "adopt.upload-initials-only" : "adopt.upload-signature-only") }));
      panels.upload.append(file, zone);

      err = h("p", { id: "adopt-err", class: "os-field-error", attrs: { role: "alert", "data-testid": "adopt-err" } });
      body.append(tabs, panels.type, panels.draw, panels.upload, err,
        h("p", { class: "os-adopt__legal", text: t("adopt.legal") }));
    },
    actions: [
      { label: t("action.cancel"), value: null, variant: "ghost" },
      {
        label: t("adopt.adopt"),
        variant: "primary",
        attrs: { "data-testid": "adopt-confirm" },
        onClick: async () => {
          const out = {};
          if (mode === "type") {
            if (!typed[want].trim()) { say(want === "initials" ? "adopt.need-initials" : "adopt.need-name"); return undefined; }
            for (const m of marks) if (typed[m].trim()) out[m] = await typedCanvas(typed[m].trim(), FONTS[font][0]);
          } else if (mode === "draw") {
            if (!pads[want].hasInk()) { say(want === "initials" ? "adopt.need-drawing-initials" : "adopt.need-drawing"); return undefined; }
            for (const m of marks) if (pads[m].hasInk()) out[m] = pads[m].toCanvas();
          } else {
            if (!uploaded) { say("adopt.need-image"); return undefined; }
            out[want] = uploaded;
          }
          leaveFull();
          const result = {};
          for (const [m, c] of Object.entries(out)) {
            const dataUrl = c.toDataURL("image/png");
            result[m] = { method: mode, dataUrl, base64: dataUrl.slice(dataUrl.indexOf(",") + 1) };
          }
          return { marks: result };
        },
      },
    ],
  }).finally(() => leaveFull());
}

/// A drawing pad for `mark`: strokes kept in pad units (600 × 200), undo and clear, and
/// full screen on phones (M-03: an upright phone turns the pad a quarter clockwise, so
/// the signature is drawn along the long side; the pointer is mapped back).
function drawPad(mark, onInk) {
  const strokes = [];
  const sig = mark === "signature";
  const canvas = h("canvas", { class: "os-adopt__pad", width: W, height: H, attrs: { "aria-label": t(sig ? "adopt.pad" : "adopt.pad-initials"), role: "img", "data-testid": sig ? "signature-pad" : "initials-pad" } });
  const g = canvas.getContext("2d");
  const paint = (ctx) => {
    ctx.strokeStyle = INK; ctx.lineWidth = 3; ctx.lineCap = "round"; ctx.lineJoin = "round";
    for (const s of strokes) {
      ctx.beginPath();
      s.forEach(([x, y], i) => (i ? ctx.lineTo(x, y) : ctx.moveTo(x, y)));
      if (s.length === 1) ctx.lineTo(s[0][0] + 0.1, s[0][1]);
      ctx.stroke();
    }
  };
  // WEB-18: the pad says how to draw until there is ink, over a dashed baseline.
  const area = h("div", { class: "os-adopt__padarea" },
    h("span", { class: "os-adopt__padhint", attrs: { "aria-hidden": "true" }, text: t("adopt.draw-help") }), canvas);
  const redraw = () => { g.clearRect(0, 0, W, H); paint(g); area.classList.toggle("has-ink", strokes.length > 0); };
  let current = null;
  const wrap = h("div", { class: "os-adopt__padwrap" });
  const turned = () => wrap.classList.contains("is-full") && matchMedia("(orientation: portrait)").matches;
  const pos = (e) => {
    const b = canvas.getBoundingClientRect();
    if (turned()) return [((e.clientY - b.top) / b.height) * W, ((b.right - e.clientX) / b.width) * H];
    return [((e.clientX - b.left) / b.width) * W, ((e.clientY - b.top) / b.height) * H];
  };
  canvas.addEventListener("pointerdown", (e) => { e.preventDefault(); canvas.setPointerCapture(e.pointerId); current = [pos(e)]; strokes.push(current); redraw(); onInk(); });
  canvas.addEventListener("pointermove", (e) => { if (!current) return; current.push(pos(e)); redraw(); });
  const end = () => { current = null; };
  canvas.addEventListener("pointerup", end);
  canvas.addEventListener("pointercancel", end);
  const fullHint = h("p", { class: "os-adopt__fullhint", text: t("adopt.full-hint") });
  const fullBtn = button(t(sig ? "adopt.full" : "adopt.full-initials"), { icon: "maximize", size: "lg", attrs: { "data-testid": sig ? "adopt-full" : "adopt-full-initials" } });
  fullBtn.classList.add("os-adopt__fullbtn");
  const doneBtn = button(t("adopt.full-done"), { icon: "check", variant: "primary", size: "lg", attrs: { "data-testid": sig ? "adopt-full-done" : "adopt-full-done-initials" } });
  doneBtn.classList.add("os-adopt__fulldone");
  const onEsc = (e) => { if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); setFull(false); } };
  function setFull(on) {
    wrap.classList.toggle("is-full", on);
    document.body.classList.toggle("has-fullpad", on);
    for (const [k, v] of Object.entries({ role: "dialog", "aria-modal": "true", "aria-label": t(sig ? "adopt.pad" : "adopt.pad-initials") })) {
      if (on) wrap.setAttribute(k, v); else wrap.removeAttribute(k);
    }
    // Escape leaves full screen only; the panel's own Escape (a document capture
    // listener) must not close the whole panel, so this one listens on window first.
    if (on) window.addEventListener("keydown", onEsc, true); else window.removeEventListener("keydown", onEsc, true);
    (on ? doneBtn : fullBtn).focus({ preventScroll: true });
    redraw();
  }
  fullBtn.addEventListener("click", () => setFull(true));
  doneBtn.addEventListener("click", () => setFull(false));
  wrap.append(fullHint, area,
    h("div", { class: "os-actions os-adopt__padtools" },
      button(t("adopt.undo"), { icon: "undo-2", onClick: () => { strokes.pop(); redraw(); } }),
      button(t("adopt.clear"), { icon: "eraser", onClick: () => { strokes.length = 0; redraw(); } }),
      doneBtn));
  return {
    el: h("div", { class: "os-adopt__padblock" }, fullBtn, wrap),
    redraw,
    hasInk: () => strokes.some((s) => s.length > 1),
    leaveFull: () => { if (wrap.classList.contains("is-full")) setFull(false); },
    toCanvas() {
      const c = document.createElement("canvas");
      c.width = W; c.height = H;
      paint(c.getContext("2d"));
      return c;
    },
  };
}

async function typedCanvas(text, family) {
  try { await document.fonts.load(`64px "${family}"`, text); } catch { /* falls back to cursive */ }
  const c = document.createElement("canvas");
  c.width = W; c.height = H;
  const g = c.getContext("2d");
  let size = 96;
  g.font = `${size}px "${family}", cursive`;
  while (g.measureText(text).width > W - 40 && size > 24) { size -= 4; g.font = `${size}px "${family}", cursive`; }
  g.fillStyle = INK;
  g.textBaseline = "middle";
  g.textAlign = "center";
  g.fillText(text, W / 2, H / 2);
  return c;
}

/// Draw an uploaded image onto a canvas, scaled to fit, with near-white made transparent.
async function cleanImage(file) {
  const bmp = await createImageBitmap(file);
  const s = Math.min(1, W / bmp.width, H / bmp.height);
  const c = document.createElement("canvas");
  c.width = Math.max(1, Math.round(bmp.width * s));
  c.height = Math.max(1, Math.round(bmp.height * s));
  const g = c.getContext("2d");
  g.drawImage(bmp, 0, 0, c.width, c.height);
  const img = g.getImageData(0, 0, c.width, c.height);
  const d = img.data;
  for (let i = 0; i < d.length; i += 4) if (d[i] > 235 && d[i + 1] > 235 && d[i + 2] > 235) d[i + 3] = 0;
  g.putImageData(img, 0, 0);
  return c;
}

/// The bottom sheet's drag handle (phones, the canvas's SignerPhone): put at the top of
/// the dialog `body` will sit in once it is shown; dragging it down by more than a
/// quarter of the sheet dismisses it, as a native sheet does. Decorative for assistive
/// technology, which has the dialog's Close and Cancel.
function grabHandle(body, close) {
  const grab = h("span", { class: "os-adopt__grab", attrs: { "aria-hidden": "true", "data-testid": "adopt-grab" } });
  queueMicrotask(() => body.parentElement?.prepend(grab));
  grab.addEventListener("pointerdown", (e) => {
    const sheet = body.parentElement;
    if (!sheet) return;
    e.preventDefault();
    grab.setPointerCapture?.(e.pointerId);
    const y0 = e.clientY;
    const move = (ev) => sheet.style.setProperty("translate", `0 ${Math.max(0, ev.clientY - y0)}px`);
    const up = (ev) => {
      grab.removeEventListener("pointermove", move);
      grab.removeEventListener("pointerup", up);
      grab.removeEventListener("pointercancel", up);
      const far = ev.type === "pointerup" && ev.clientY - y0 > sheet.offsetHeight / 4;
      sheet.style.removeProperty("translate");
      if (far) close(null);
    };
    grab.addEventListener("pointermove", move);
    grab.addEventListener("pointerup", up);
    grab.addEventListener("pointercancel", up);
  });
}


/// Shrink each style tile's sample until it fits its tile (WEB-18: a signature preview
/// is never cut off). The font size is set through the CSSOM; 12 px is the floor.
function fitSamples(root) {
  for (const el of root.querySelectorAll(".os-adopt__sample")) {
    el.style.removeProperty("font-size");
    const room = el.parentElement?.clientWidth - 24;
    if (!(room > 0)) continue;
    const rem = parseFloat(getComputedStyle(document.documentElement).fontSize) || 16;
    let size = parseFloat(getComputedStyle(el).fontSize);
    while (el.scrollWidth > room && size > 12) {
      size -= 1;
      el.style.setProperty("font-size", `${(size / rem).toFixed(3)}rem`);
    }
  }
}
