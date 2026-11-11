// Adopt a signature or initials (WEB-01; docs/47 §Signer ceremony): Type (one of the
// bundled OFL script fonts, the accessible default), Draw (pointer and touch, with
// undo and clear), Upload (PNG or JPEG; near-white made transparent here, re-checked
// by the server). The result is a PNG for `POST /s/{token}/adopt`.

import { h } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { openPanel, button, toast } from "./ui/index.js";

const W = 600;
const H = 200;
const FONTS = [
  ["OpenSeal Great Vibes", "Great Vibes"],
  ["OpenSeal Allura", "Allura"],
];
const MAX_UPLOAD = 5 * 1024 * 1024;

/// The initials of a name ("Jordan A. Rivera" → "JAR"), at most three letters.
export function initialsOf(name) {
  return String(name || "").trim().split(/\s+/).filter(Boolean).map((p) => [...p][0].toUpperCase()).slice(0, 3).join("");
}

/// Open the adopt dialog. Resolves `{method, png: Uint8Array, dataUrl}` or null.
export function adoptDialog({ mark = "signature", name = "", host = null }) {
  let mode = "type";
  let typed = mark === "initials" ? initialsOf(name) : name;
  let font = 0;
  const strokes = [];
  let uploaded = null;

  let leaveFull = () => {};
  return openPanel({
    id: "adopt",
    host,
    width: 30,
    title: t(mark === "initials" ? "adopt.title-initials" : "adopt.title"),
    className: "os-adopt",
    build(body) {
      const tabs = h("div", { class: "os-tabs", attrs: { role: "tablist", "aria-label": t("adopt.how") } });
      const panels = {};
      const tabBtns = {};
      for (const m of ["type", "draw", "upload"]) {
        const b = h("button", { type: "button", class: "os-tab", id: `adopt-tab-${m}`, attrs: { role: "tab", "aria-controls": `adopt-panel-${m}`, "aria-selected": String(m === mode), tabindex: m === mode ? "0" : "-1" } },
          icon(m === "type" ? "type" : m === "draw" ? "pen-line" : "upload", { size: 16 }), h("span", { text: t(`adopt.${m}`) }));
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
        panels[m] = h("div", { class: "os-tabpanel", id: `adopt-panel-${m}`, attrs: { role: "tabpanel", "aria-labelledby": `adopt-tab-${m}` }, hidden: m !== mode });
      }
      function select(m) {
        mode = m;
        for (const k of Object.keys(panels)) {
          panels[k].hidden = k !== m;
          tabBtns[k].setAttribute("aria-selected", String(k === m));
          tabBtns[k].tabIndex = k === m ? 0 : -1;
        }
        if (m === "draw") redraw();
      }

      // Type
      const nameId = "adopt-name";
      const input = h("input", { id: nameId, class: "os-input", value: typed, maxLength: 80, autocomplete: "name", attrs: { autofocus: true } });
      const previews = h("div", { class: "os-adopt__fonts", attrs: { role: "radiogroup", "aria-label": t("adopt.style") } });
      const renderPreviews = () => {
        previews.replaceChildren(...FONTS.map(([family, label], i) => {
          const id = `adopt-font-${i}`;
          const radio = h("input", { type: "radio", name: "adopt-font", id, checked: i === font, class: "os-sr-only" });
          radio.addEventListener("change", () => { font = i; });
          const sample = h("span", { class: `os-adopt__sample os-script-${i + 1}`, text: typed || " " });
          return h("label", { class: "os-adopt__font", attrs: { for: id } }, radio, sample, h("span", { class: "os-sr-only", text: t("adopt.style-n", { name: label }) }));
        }));
      };
      input.addEventListener("input", () => { typed = input.value; renderPreviews(); });
      renderPreviews();
      panels.type.append(h("label", { class: "os-label", attrs: { for: nameId }, text: t(mark === "initials" ? "adopt.your-initials" : "adopt.your-name") }), input, previews);

      // Draw
      const canvas = h("canvas", { class: "os-adopt__pad", width: W, height: H, attrs: { "aria-label": t("adopt.pad"), role: "img", "data-testid": "signature-pad" } });
      const g = canvas.getContext("2d");
      function redraw() {
        g.clearRect(0, 0, W, H);
        g.strokeStyle = "#0b1f4b";
        g.lineWidth = 3;
        g.lineCap = "round";
        g.lineJoin = "round";
        for (const s of strokes) {
          g.beginPath();
          s.forEach(([x, y], i) => (i ? g.lineTo(x, y) : g.moveTo(x, y)));
          if (s.length === 1) g.lineTo(s[0][0] + 0.1, s[0][1]);
          g.stroke();
        }
      }
      let current = null;
      // Full screen on an upright phone turns the pad a quarter clockwise (app.css), so
      // the signature is drawn along the long side; the pad's x then runs down the screen.
      const turned = () => canvas.parentElement?.classList.contains("is-full") && matchMedia("(orientation: portrait)").matches;
      const pos = (e) => {
        const b = canvas.getBoundingClientRect();
        if (turned()) return [((e.clientY - b.top) / b.height) * W, ((b.right - e.clientX) / b.width) * H];
        return [((e.clientX - b.left) / b.width) * W, ((e.clientY - b.top) / b.height) * H];
      };
      canvas.addEventListener("pointerdown", (e) => { e.preventDefault(); canvas.setPointerCapture(e.pointerId); current = [pos(e)]; strokes.push(current); redraw(); });
      canvas.addEventListener("pointermove", (e) => { if (!current) return; current.push(pos(e)); redraw(); });
      const end = () => { current = null; };
      canvas.addEventListener("pointerup", end);
      canvas.addEventListener("pointercancel", end);
      // M-03: on phones the pad can fill the screen (landscape-friendly); the strokes
      // are kept in pad units, so they survive going in and out of full screen.
      const pad = h("div", { class: "os-adopt__padwrap" });
      const fullHint = h("p", { class: "os-adopt__fullhint", text: t("adopt.full-hint") });
      const fullBtn = button(t("adopt.full"), { icon: "maximize", size: "lg", attrs: { "data-testid": "adopt-full" } });
      fullBtn.classList.add("os-adopt__fullbtn");
      const doneBtn = button(t("adopt.full-done"), { icon: "check", variant: "primary", size: "lg", attrs: { "data-testid": "adopt-full-done" } });
      doneBtn.classList.add("os-adopt__fulldone");
      const setFull = (on) => {
        pad.classList.toggle("is-full", on);
        document.body.classList.toggle("has-fullpad", on);
        for (const [k, v] of Object.entries({ role: "dialog", "aria-modal": "true", "aria-label": t("adopt.pad") })) {
          if (on) pad.setAttribute(k, v); else pad.removeAttribute(k);
        }
        // Escape leaves full screen only; the panel's own Escape (a document capture
        // listener) must not close the whole panel, so this one listens on window first.
        if (on) window.addEventListener("keydown", onEsc, true); else window.removeEventListener("keydown", onEsc, true);
        (on ? doneBtn : fullBtn).focus({ preventScroll: true });
        redraw();
      };
      const onEsc = (e) => { if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); setFull(false); } };
      leaveFull = () => { if (pad.classList.contains("is-full")) setFull(false); };
      fullBtn.addEventListener("click", () => setFull(true));
      doneBtn.addEventListener("click", () => setFull(false));
      pad.append(fullHint, canvas,
        h("div", { class: "os-actions os-adopt__padtools" },
          button(t("adopt.undo"), { icon: "undo-2", size: "lg", onClick: () => { strokes.pop(); redraw(); } }),
          button(t("adopt.clear"), { icon: "eraser", size: "lg", onClick: () => { strokes.length = 0; redraw(); } }),
          doneBtn));
      panels.draw.append(
        h("p", { class: "os-muted os-small", text: t("adopt.draw-help") }),
        fullBtn,
        pad);

      // Upload
      const file = h("input", { id: "adopt-file", type: "file", accept: "image/png,image/jpeg", class: "os-input" });
      const preview = h("img", { class: "os-adopt__upload-preview", alt: "", hidden: true });
      file.addEventListener("change", async () => {
        const f = file.files?.[0];
        if (!f) return;
        if (f.size > MAX_UPLOAD || !/^image\/(png|jpeg)$/.test(f.type)) { toast(t("adopt.bad-image"), "error"); file.value = ""; return; }
        try {
          uploaded = await cleanImage(f);
          preview.src = uploaded.toDataURL("image/png");
          preview.hidden = false;
          preview.alt = t("adopt.upload-preview");
        } catch {
          toast(t("adopt.bad-image"), "error");
        }
      });
      panels.upload.append(h("label", { class: "os-label", attrs: { for: "adopt-file" }, text: t("adopt.upload-label") }), file, preview);

      body.append(tabs, panels.type, panels.draw, panels.upload,
        h("p", { class: "os-muted os-small", text: t("adopt.legal") }));
    },
    actions: [
      { label: t("action.cancel"), value: null },
      {
        label: t("adopt.adopt"),
        variant: "primary",
        attrs: { "data-testid": "adopt-confirm" },
        onClick: async () => {
          let c;
          if (mode === "type") {
            if (!typed.trim()) { toast(t("adopt.need-name"), "error"); return undefined; }
            c = await typedCanvas(typed.trim(), FONTS[font][0]);
          } else if (mode === "draw") {
            if (!strokes.some((s) => s.length > 1)) { toast(t("adopt.need-drawing"), "error"); return undefined; }
            c = document.createElement("canvas");
            c.width = W; c.height = H;
            const g2 = c.getContext("2d");
            g2.strokeStyle = "#0b1f4b"; g2.lineWidth = 3; g2.lineCap = "round"; g2.lineJoin = "round";
            for (const s of strokes) { g2.beginPath(); s.forEach(([x, y], i) => (i ? g2.lineTo(x, y) : g2.moveTo(x, y))); g2.stroke(); }
          } else {
            if (!uploaded) { toast(t("adopt.need-image"), "error"); return undefined; }
            c = uploaded;
          }
          leaveFull();
          const dataUrl = c.toDataURL("image/png");
          return { method: mode, dataUrl, base64: dataUrl.slice(dataUrl.indexOf(",") + 1) };
        },
      },
    ],
  }).finally(() => leaveFull());
}

async function typedCanvas(text, family) {
  try { await document.fonts.load(`64px "${family}"`, text); } catch { /* falls back to cursive */ }
  const c = document.createElement("canvas");
  c.width = W; c.height = H;
  const g = c.getContext("2d");
  let size = 96;
  g.font = `${size}px "${family}", cursive`;
  while (g.measureText(text).width > W - 40 && size > 24) { size -= 4; g.font = `${size}px "${family}", cursive`; }
  g.fillStyle = "#0b1f4b";
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
