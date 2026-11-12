// Verify a signed PDF (WEB-02; docs/47 §Screens "Verify"; docs/32 §4; rebuilt on the
// approved canvas in WEB-18 lane E), at verify.html. Everything runs in this browser:
// the file is never uploaded. The verdict is casual-sign-verify's own, compiled to
// WebAssembly (`crates/casual-sign-wasm`, built into vendor/openseal-wasm/ by
// tools/build-webapp-wasm.sh), the code the server and the CLI run. This page only shows
// its report (verifyreport.js names it, verifyview.js draws it), and the audit trail the
// PDF carries (`audit-trail.json`, read by pdf.js, checked for links by trail.js).
//
// Inputs: the PDF, and optionally trusted certificates (DER or PEM) the person
// supplies; without one, a signature's chain cannot be anchored and the verdict says
// so. The validation time is now, read from the clock here and passed in (the engine
// reads no clock). No account, no server call.
//
// Flow: start (drop zone; the verifier loads behind a skeleton line) → scanning (the
// real stages tick off) → the sealed receipt and the detail cards.

import { h, clear } from "./dom.js";
import { icon } from "./icons.js";
import { t, applyI18n } from "./i18n.js";
import { button, emptyState, toast, pdfPreview } from "./ui/index.js";
import { initTheme, getTheme, toggleTheme } from "./theme.js";
import { summarize, certificatesFrom } from "./verifyreport.js";
import { parseTrail, TRAIL_NAME, MAX_TRAIL_BYTES } from "./trail.js";
import { readAttachment } from "./pdfview.js";
import { createClient, isMockMode } from "./api.js";
import { register } from "./commands.js";
import { dropZone, engineLine, scanning, opening, receipt, detailCard, signatureItem, changesList, trailBody } from "./verifyview.js";

const mock = isMockMode();

const MAX_PDF = 50 * 1024 * 1024; // docs/21: 50 MiB
/// The scanning screen stays at least this long, so a fast check does not flash.
const MIN_SCAN_MS = 600;
const main = document.getElementById("main");
const trust = []; // {name, der: [base64]}
let loading = null;

/// The verifier module, loaded once. Null when it is not installed on this server.
function verifier() {
  loading ||= import("./vendor/openseal-wasm/casual_sign_wasm.js")
    .then(async (mod) => { await mod.default(); return mod; })
    .catch(() => null);
  return loading;
}

const pause = (ms) => new Promise((r) => setTimeout(r, ms));
const reduced = () => typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;

/// One hidden file input, opened by Choose (and by the command).
const fileInput = h("input", { type: "file", accept: "application/pdf,.pdf", class: "os-sr-only", attrs: { "aria-hidden": "true", tabindex: "-1", "data-testid": "verify-input" } });
fileInput.addEventListener("change", () => { const f = fileInput.files[0]; fileInput.value = ""; if (f) check(f); });

// ---- Start: choose a file ------------------------------------------------------------

function start() {
  clear(main);
  const { el: drop, choose } = dropZone(() => fileInput.click());
  wireDrop(drop);
  const engine = engineLine();
  verifier().then((mod) => { if (engine.el.isConnected) engine.set(mod ? "ready" : "missing"); });
  main.append(h("div", { class: "os-vfy os-auth-rise" },
    h("header", { class: "os-vfy__intro" },
      h("h1", { class: "os-vfy__title", text: t("verify.title") }),
      h("p", { class: "os-vfy__lede", text: t("verify.lede") })),
    drop, engine.el, fileInput, trustCard()));
  choose.focus({ preventScroll: true });
}

function wireDrop(drop) {
  for (const ev of ["dragenter", "dragover"]) drop.addEventListener(ev, (e) => { if (e.dataTransfer.types.includes("Files")) { e.preventDefault(); drop.classList.add("is-dropping"); } });
  drop.addEventListener("dragleave", (e) => { if (!drop.contains(e.relatedTarget)) drop.classList.remove("is-dropping"); });
  drop.addEventListener("drop", (e) => {
    e.preventDefault();
    drop.classList.remove("is-dropping");
    const f = e.dataTransfer.files?.[0];
    if (f) check(f);
  });
}

function trustCard() {
  const list = h("ul", { class: "os-vfy__chips", attrs: { "aria-live": "polite" } });
  const input = h("input", { type: "file", accept: ".cer,.crt,.der,.pem,application/x-x509-ca-cert,application/pkix-cert", multiple: true, class: "os-sr-only", attrs: { "aria-hidden": "true", tabindex: "-1", "data-testid": "trust-input" } });
  const render = () => {
    clear(list);
    if (!trust.length) { list.append(h("li", { class: "os-vfy__muted os-vfy__small", text: t("verify.trust-none") })); return; }
    trust.forEach((c, i) => {
      list.append(h("li", { class: "os-vfy__chip" }, icon("shield-check", { size: 12 }), h("span", { class: "os-vfy__ellipsis", text: c.name }),
        button(t("verify.trust-remove", { name: c.name }), { icon: "x", size: "sm", variant: "ghost", iconOnly: true, onClick: () => { trust.splice(i, 1); render(); } })));
    });
  };
  input.addEventListener("change", async () => {
    for (const f of [...input.files]) {
      if (f.size > 1 << 20) { toast(t("verify.trust-bad", { name: f.name }), "error"); continue; }
      const der = certificatesFrom(new Uint8Array(await f.arrayBuffer()));
      if (!der.length) { toast(t("verify.trust-bad", { name: f.name }), "error"); continue; }
      trust.push({ name: f.name.slice(0, 120), der });
    }
    input.value = "";
    render();
  });
  render();
  const add = button(t("verify.trust-add"), { icon: "plus", size: "sm", command: "pdf.trust-add", onClick: () => input.click() });
  return h("section", { class: "os-vfy__trust", attrs: { "aria-labelledby": "trust-h" } },
    h("div", { class: "os-vfy__trust-text" },
      h("h2", { id: "trust-h", class: "os-vfy__trust-title", text: t("verify.trust-title") }),
      h("p", { class: "os-vfy__muted os-vfy__small", text: t("verify.trust-text") }),
      list),
    input, add);
}

// ---- Check -----------------------------------------------------------------------------

/// Read the file, run the verifier, read the trail, then show the receipt. Each stage
/// is one the scanning screen names, and it moves on only when that stage has finished.
async function check(file) {
  clear(main);
  const scan = scanning(file.name);
  main.append(h("h1", { class: "os-sr-only", text: t("verify.title") }), scan.el);
  main.focus({ preventScroll: true });
  const began = Date.now();

  if (file.size > MAX_PDF) return problem(t("verify.too-large"));
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (bytes.length < 5 || String.fromCharCode(...bytes.subarray(0, 5)) !== "%PDF-") return problem(t("verify.not-pdf"));

  scan.step("verify");
  const mod = await verifier();
  if (!mod) {
    clear(main);
    main.append(emptyState({ illus: "error", title: t("verify.missing.title"), text: t("verify.missing.text"), action: button(t("verify.another"), { icon: "file-search", variant: "primary", onClick: start }), testId: "verify-missing" }));
    return;
  }
  // Let the stage paint before the verifier takes the thread.
  await pause(30);
  const checkedAt = Date.now();
  const trustJson = JSON.stringify({ validation_time: Math.floor(checkedAt / 1000), anchors: trust.flatMap((c) => c.der) });
  let report;
  try { report = summarize(mod.verify(bytes, trustJson)); } catch { report = { state: "error", code: "CS-API-0010", signatures: [], changes: [] }; }

  scan.step("trail");
  let trail = null;
  try {
    const raw = await readAttachment(bytes, TRAIL_NAME, MAX_TRAIL_BYTES);
    trail = raw ? parseTrail(raw) : null;
  } catch { trail = null; }
  scan.step("done");
  if (!reduced()) await pause(Math.max(0, MIN_SCAN_MS - (Date.now() - began)));
  show({ file, bytes, report, trail, checkedAt });
}

function problem(text) {
  clear(main);
  main.append(emptyState({ illus: "error", title: t("verify.cannot.title"), text, action: button(t("verify.another"), { icon: "file-search", variant: "primary", onClick: start }), testId: "verify-problem" }));
}

// ---- Result ----------------------------------------------------------------------------

function show({ file, bytes, report: r, trail, checkedAt }) {
  clear(main);
  const details = h("div", { class: "os-vfy__details" });
  if (r.signatures.length) {
    details.append(detailCard("sigs-h", t("verify.signatures", { n: r.signatures.length }), h("ol", { class: "os-vfy__sigs" }, ...r.signatures.map(signatureItem))));
  }
  if (r.changes.length) details.append(detailCard("changes-h", t("verify.changes"), changesList(r.changes)));
  details.append(detailCard("trail-h", t("verify.trail"), ...trailBody(trail)));
  details.append(detailCard("vpreview-h", t("verify.preview"), pdfPreview({ load: async () => bytes, name: file.name, height: 560 }).el));
  main.append(
    h("h1", { class: "os-sr-only", text: t("verify.title") }),
    receipt({ file: file.name, size: bytes.length, report: r, trusted: trust.map((c) => c.name), checkedAt, onAnother: start }),
    details);
  main.querySelector("#verdict-h")?.focus({ preventScroll: true });
}

// ---- Chrome ------------------------------------------------------------------------------

function syncTheme() {
  const b = document.getElementById("theme-btn");
  const dark = getTheme() === "dark" || (getTheme() === "system" && matchMedia("(prefers-color-scheme: dark)").matches);
  b.replaceChildren(icon(dark ? "moon" : "sun"));
  b.setAttribute("aria-label", t(dark ? "theme.to-light" : "theme.to-dark"));
  b.title = b.getAttribute("aria-label");
}

/// Demo mode (UX-04): the banner the app shows, and the bar's links keep `?mock=1`, so
/// going back to the app never lands on a page that calls a server that is not there.
function chrome() {
  if (!mock) return;
  const banner = document.getElementById("mock-banner");
  if (banner) { banner.hidden = false; banner.prepend(icon("info", { size: 16 })); }
  for (const a of document.querySelectorAll("header a[href$='.html']")) a.href = `${a.getAttribute("href")}?mock=1`;
}

/// This page's verbs, so a shortcut or a palette reaches them as it reaches the buttons.
function registerCommands() {
  register("pdf.verify-choose", { label: t("verify.choose"), run: () => fileInput.click() });
  register("pdf.verify-another", { label: t("verify.another"), run: start });
}

// ---- A sealed document handed over by the envelope page (UX-04) -------------------------
//
// `verify.html?envelope={id}&document={id}`: the envelope page's "Verify" opens this page
// with the sealed document named; it is read with the user's session (same origin) and
// checked here as if chosen. Nothing is uploaded; without a session, or for a document
// the user may not read, the server refuses and the page says so and offers the picker.

const ID = /^[A-Za-z0-9._~-]{1,128}$/;

/// The envelope and document named in the address, or null.
export function handoffOf(search) {
  const q = new URLSearchParams(search || "");
  const envelope = q.get("envelope") || "";
  const doc = q.get("document") || "";
  return ID.test(envelope) && ID.test(doc) ? { envelope, document: doc } : null;
}

async function handoff(ref) {
  clear(main);
  main.append(h("h1", { class: "os-sr-only", text: t("verify.title") }), opening(t("verify.handoff")));
  let api;
  if (mock) {
    const { createMockFetch } = await import("./mock.js");
    const store = (() => { try { return globalThis.sessionStorage; } catch { return null; } })();
    api = createClient({ fetch: createMockFetch({ store }), store });
  } else {
    api = createClient({ baseUrl: document.querySelector('meta[name="openseal-api-base"]')?.content || "" });
  }
  try {
    const blob = await api.currentDocument(ref.envelope, ref.document);
    let name = "sealed.pdf";
    try {
      const { envelope } = await api.getEnvelope(ref.envelope);
      const doc = envelope?.documents?.find((d) => d.id === ref.document);
      if (doc?.name) name = /\.pdf$/i.test(doc.name) ? doc.name : `${doc.name}.pdf`;
    } catch { /* the name is only shown */ }
    await check(new File([blob], name.slice(0, 200), { type: "application/pdf" }));
  } catch {
    problem(t("verify.handoff-failed"));
  }
}

initTheme();
applyI18n(document);
chrome();
registerCommands();
document.getElementById("theme-btn").addEventListener("click", () => { toggleTheme(); syncTheme(); });
syncTheme();
const ref = handoffOf(location.search);
if (ref) handoff(ref); else start();
