// The signing ceremony (WEB-01; docs/47 §Signer ceremony; docs/40 §6), at
// `/s/{token}`: identity (access code) → location (only when the envelope asks,
// GEO-01) → consent to electronic records → the documents with this signer's fields
// and a Next-field guide → review → Finish. Decline and Finish later are always
// available. Mobile first: one primary action, a bottom bar, 44 px targets.
//
// The link token is a secret: it is never logged or put in a message; the server
// binds it to this browser with an HttpOnly cookie on `POST /s/{token}/session`.

import { h, clear, reducedMotion, skipTo } from "./dom.js";
import { icon } from "./icons.js";
import { t, applyI18n } from "./i18n.js";
import { createClient, isMockMode, isNoServer, errorMessage, locationFrom, ApiError } from "./api.js";
import { button, busy, emptyState, toast, toastError, reasonDialog, noServerState, dockPanel, closePanel } from "./ui/index.js";
import { openPdf } from "./pdfview.js";
import { fromWire, takesInput } from "./geometry.js";
import { adoptDialog } from "./signature.js";
import { enlargeFor } from "./zoom.js";
import { docView, zoomControls, thumbnails } from "./docview.js";
import { initTheme } from "./theme.js";

const store = (() => { try { return sessionStorage; } catch { return null; } })();
const mock = isMockMode();
let api;
if (mock) {
  const { createMockFetch } = await import("./mock.js");
  api = createClient({ fetch: createMockFetch({ store }), store });
} else {
  api = createClient({ baseUrl: document.querySelector('meta[name="openseal-api-base"]')?.content || "", store });
}

/// The token from `/s/{token}` (or `?t=` when the page is opened as sign.html).
export function tokenFrom(loc) {
  const m = /^\/s\/([^/?#]+)\/?$/.exec(loc.pathname);
  if (m) return decodeURIComponent(m[1]);
  return new URLSearchParams(loc.search).get("t");
}

const token = tokenFrom(location);
const main = document.getElementById("main");
const guide = document.getElementById("guide");
const subjectEl = document.getElementById("subject");
const moreBtn = document.getElementById("more-btn");
const moreMenu = document.getElementById("more-menu");

let view = null;          // the CeremonyView
let location_ = null;     // GEO-01 member, once asked
const adoptions = {};     // mark → {id, dataUrl}
const values = new Map(); // field id → value as sent
let pdfHandles = [];

// ---- Screens ------------------------------------------------------------------------------

function screen(...children) {
  dv?.destroy();
  dv = null;
  closePanel();
  clear(main);
  main.classList.remove("is-frame-host");
  skipTo("#main", t("a11y.skip"));
  const s = h("div", { class: "os-sign__screen" }, ...children);
  main.append(s);
  main.focus({ preventScroll: true });
  return s;
}

function message({ illus, title, text, action = null, testId }) {
  guide.hidden = true;
  moreBtn.hidden = true;
  setTools(false);
  screen(emptyState({ illus, title, text, action, testId }));
}

function fail(err) {
  if (!mock && isNoServer(err)) {
    guide.hidden = true;
    moreBtn.hidden = true;
    return noServerState(screen(), start);
  }
  // The server answers an unknown, expired or revoked link alike (CS-AUTH-0002, so a
  // link cannot be probed); the mock answers CS-API-0002.
  if (err instanceof ApiError && (err.code === "CS-API-0002" || err.code === "CS-AUTH-0002")) {
    return message({ illus: "error", title: t("sign.not-found.title"), text: t("sign.not-found.text"), testId: "sign-not-found" });
  }
  const offline = err?.code === "CS-NET-0001";
  message({ illus: offline ? "offline" : "error", title: offline ? t("empty.offline.title") : t("empty.error.title"), text: errorMessage(err), action: button(t("action.retry"), { icon: "refresh-cw", variant: "primary", size: "lg", onClick: start }), testId: "sign-error" });
}

async function start() {
  if (!token) return message({ illus: "error", title: t("sign.not-found.title"), text: t("sign.no-token"), testId: "sign-not-found" });
  screen(h("div", { class: "os-sign__loading", attrs: { "aria-busy": "true" } }, h("div", { class: "os-page os-skeleton-page" })), h("p", { class: "os-sr-only", attrs: { role: "status" }, text: t("sign.loading") }));
  try {
    view = await api.ceremony.open(token);
  } catch (err) { return fail(err); }
  subjectEl.textContent = view.envelope?.subject || "";
  next();
}

/// Go to whichever step this recipient is at.
function next() {
  const r = view.recipient || {};
  const env = view.envelope || {};
  if (r.status === "completed") return done(everyoneSigned(env.status));
  if (r.status === "declined") return message({ illus: "inbox", title: t("sign.declined.title"), text: t("sign.declined.text"), testId: "sign-declined" });
  if (["voided", "declined", "expired"].includes(env.status)) return message({ illus: "inbox", title: t("sign.closed.title"), text: t(`sign.closed.${env.status}`), testId: "sign-closed" });
  moreBtn.hidden = false;
  if ((view.auth_required || []).includes("access_code")) return accessCode();
  if (env.signing_options?.capture_location && !location_) return askLocation();
  if (view.consent_required && !r.consented) return consent();
  return documents();
}

function accessCode() {
  guide.hidden = true;
  const err = h("p", { id: "code-err", class: "os-field-error", attrs: { role: "alert" } });
  const input = h("input", { id: "access-code", class: "os-input os-input--lg", autocomplete: "one-time-code", inputMode: "text", maxLength: 64, required: true, attrs: { "aria-describedby": "code-err code-help", autofocus: true } });
  const submit = button(t("sign.code.submit"), { variant: "primary", size: "lg", type: "submit" });
  const form = h("form", { class: "os-sign__card", attrs: { novalidate: true } },
    icon("lock", { size: 24 }),
    h("h1", { class: "os-sign__title", text: t("sign.code.title") }),
    h("p", { id: "code-help", class: "os-muted", text: t("sign.code.text") }),
    h("label", { class: "os-label", attrs: { for: "access-code" }, text: t("sign.code.label") }), input, err, submit);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!input.value.trim()) { err.textContent = t("form.required"); input.setAttribute("aria-invalid", "true"); input.focus(); return; }
    try {
      view = await busy(submit, () => api.ceremony.authenticate(token, "access_code", input.value.trim()));
      next();
    } catch (ex) {
      err.textContent = ex.code === "CS-AUTH-0003" ? t("sign.code.wrong") : errorMessage(ex);
      input.value = "";
      input.setAttribute("aria-invalid", "true");
      input.focus();
    }
  });
  screen(form);
  input.focus();
}

function askLocation() {
  guide.hidden = true;
  const share = button(t("sign.location.share"), { icon: "map-pin", variant: "primary", size: "lg" });
  const skip = button(t("sign.location.skip"), { size: "lg" });
  share.addEventListener("click", () => busy(share, async () => {
    location_ = await geolocate();
    locationChip();
    next();
  }));
  skip.addEventListener("click", () => { location_ = { declined: true }; locationChip(); next(); });
  screen(h("div", { class: "os-sign__card" },
    icon("map-pin", { size: 24 }),
    h("h1", { class: "os-sign__title", text: t("sign.location.title") }),
    h("p", { class: "os-muted", text: t("sign.location.text") }),
    h("div", { class: "os-stack" }, share, skip)));
  share.focus();
}

/// A small chip in the bar says whether the location was shared (no toast over the page).
function locationChip() {
  const chip = document.getElementById("loc-chip");
  if (!chip || !location_) return;
  chip.replaceChildren(icon("map-pin", { size: 16 }), h("span", { text: t(location_.declined ? "sign.location.chip-not" : "sign.location.chip-shared") }));
  chip.hidden = false;
}

/// Ask the browser once (GEO-01). A refusal, an error or a timeout is a decline; the
/// server then approximates from the address and records which source it used.
function geolocate() {
  return new Promise((resolve) => {
    if (!navigator.geolocation) return resolve({ declined: true });
    navigator.geolocation.getCurrentPosition(
      (p) => resolve(locationFrom(p)),
      () => resolve({ declined: true }),
      { enableHighAccuracy: false, timeout: 10000, maximumAge: 60000 },
    );
  });
}

function consent() {
  guide.hidden = true;
  const box = h("input", { id: "consent-box", type: "checkbox", attrs: { "aria-describedby": "consent-err" } });
  const err = h("p", { id: "consent-err", class: "os-field-error", attrs: { role: "alert" } });
  const go = button(t("sign.consent.continue"), { variant: "primary", size: "lg", type: "submit" });
  const form = h("form", { class: "os-sign__card", attrs: { novalidate: true } },
    icon("shield-check", { size: 24 }),
    h("h1", { class: "os-sign__title", text: t("sign.consent.title") }),
    h("p", { class: "os-muted", text: t("sign.consent.text") }),
    h("ul", { class: "os-sign__list" },
      h("li", { text: t("sign.consent.point1") }),
      h("li", { text: t("sign.consent.point2") }),
      h("li", { text: t("sign.consent.point3") })),
    h("p", { class: "os-muted os-small", text: t("sign.consent.version", { v: view.consent_required.version }) }),
    h("label", { class: "os-check os-check--lg", attrs: { for: "consent-box" } }, box, h("span", { text: t("sign.consent.agree") })),
    err, go);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!box.checked) { err.textContent = t("sign.consent.need"); box.focus(); return; }
    try {
      view = await busy(go, () => api.ceremony.consent(token, view.consent_required.version, location_));
      next();
    } catch (ex) { toastError(ex); }
  });
  screen(form);
}

// ---- Documents and fields -------------------------------------------------------------------

const AUTO = { date_signed: () => new Date().toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" }), name: () => view.recipient?.name || "", email: () => view.recipient?.email || "" };

// WEB-06 (docs/47 §Layout spec): the pages fill a full-height frame between the page
// thumbnails (left) and the field list (right); one scroll container (docview.js) with
// fit width, fit page, 50–200 %, Ctrl/Cmd +/−/0 and pinch, painted near the view only.
// The PDFs are fetched once and kept.
let dv = null;            // the document view on screen, if any
let zc = null;            // its zoom controls
let loaded = null;        // [{doc, pdf}] once fetched
let listDock = null;      // the field list panel
let listBody = null;
let seenObserver = null;
const seen = new Map();
const phone = () => matchMedia("(max-width: 47.999em)").matches;

async function documents() {
  const fields = myFields();
  for (const f of fields) if (f.value && !values.has(f.id)) values.set(f.id, f.value);
  if (!loaded) {
    screen(h("div", { class: "os-sign__loading", attrs: { "aria-busy": "true" } }, h("div", { class: "os-page os-skeleton-page" })), h("p", { class: "os-sr-only", attrs: { role: "status" }, text: t("sign.loading") }));
    const list = [];
    for (const d of view.envelope?.documents || []) {
      try {
        const blob = await api.ceremony.document(token, d.id);
        list.push({ doc: d, pdf: await openPdf(new Uint8Array(await blob.arrayBuffer())) });
      } catch (err) { return fail(err); }
    }
    loaded = list;
    pdfHandles = list.map((x) => x.pdf);
  }
  if (!seenObserver && typeof IntersectionObserver === "function") {
    seenObserver = new IntersectionObserver((entries) => {
      for (const e of entries) {
        if (!e.isIntersecting) continue;
        const { doc, page } = e.target.dataset;
        const set = seen.get(doc) || new Set();
        if (!set.has(Number(page))) { set.add(Number(page)); seen.set(doc, set); reportViewed(doc, set); }
      }
    }, { threshold: 0.5 });
  }
  const tag = h("button", { type: "button", id: "guide-tag", class: "os-guidetag", attrs: { "data-testid": "guide-tag" } },
    h("span", { class: "os-guidetag__text", text: t("sign.start") }));
  tag.addEventListener("click", goNext);
  const v = docView({
    label: t("sign.documents-title"),
    testId: "signer-doc",
    onLayout: () => { enlarge(); zc?.sync(); requestAnimationFrame(placeTag); },
    onZoom: () => zc?.sync(),
    onPage: (i) => { zc?.sync(); thumbs.mark(i); },
  });
  v.scroller.classList.add("os-sign__pages");
  const thumbsBox = h("nav", { class: "os-thumbs", attrs: { "aria-label": t("prepare.thumbs") } });
  const thumbs = thumbnails(v, thumbsBox, { width: 96 });
  const pagesDock = dockPanel({ id: "sign-pages", side: "left", title: t("prepare.thumbs"), width: 9, min: 7, max: 16, collapsed: matchMedia("(max-width: 79.999em)").matches, testId: "panel-pages" });
  pagesDock.body.append(h("div", { class: "os-panel--thumbs" }, thumbsBox));
  listDock = dockPanel({ id: "sign-fields", side: "right", title: t("sign.fields.title"), width: 18, min: 14, max: 30, testId: "panel-fieldlist" });
  listBody = listDock.body;
  const zoomCtl = zoomControls(v, { size: "sm" });
  const frame = h("div", { class: "os-signframe" },
    pagesDock.el,
    h("div", { class: "os-signframe__centre" }, v.scroller, h("div", { class: "os-docbar", attrs: { role: "toolbar", "aria-label": t("doc.toolbar") } }, zoomCtl.el)),
    listDock.el);
  screen(h("h1", { class: "os-sr-only", text: t("sign.documents-title") }), frame, v.live);
  main.classList.add("is-frame-host");
  dv = v;
  zc = zoomCtl;
  skipTo("#document", t("a11y.skip-doc"));
  guide.hidden = false;
  document.body.classList.add("is-signing");
  setTools(true);
  dv.setPages(loaded.flatMap(({ doc: d, pdf }) => pdf.pages.map((pg, i) => ({ key: d.id, n: i + 1, total: pdf.pages.length, name: d.name, width: pg.width, height: pg.height, pdf }))));
  dv.inner.append(tag);
  dv.els.forEach(({ el, overlay }, i) => {
    const p = dv.pages[i];
    seenObserver?.observe(el);
    const mine = fields.filter((f) => f.document_id === p.key && f.p.page === p.n).sort((a, b) => a.p.y - b.p.y || a.p.x - b.p.x);
    for (const f of mine) overlay.append(fieldNode(f, p));
  });
  thumbs.build();
  enlarge();
  zc.sync();
  updateGuide();
  // Coming back (A36): the guide is at the next required field, not the top of page 1.
  if (values.size && nextField()) setTimeout(() => focusField(nextField().id, false), 50);
}

function myFields() {
  return (view.fields || []).map((f) => ({ ...f, p: fromWire(f.placement) })).filter((f) => f.p);
}

/// Phones: how much each field grows while in use, at the current zoom (zoom.js).
function enlarge() {
  if (!dv) return;
  for (const node of main.querySelectorAll(".os-sfield")) {
    const f = myFields().find((x) => x.id === node.dataset.fieldId);
    const pg = dv.pages.find((p) => p.key === f?.document_id && p.n === f?.p.page);
    if (!f || !pg) continue;
    const s = dv.scale;
    node.style.setProperty("--os-enlarge", String(enlargeFor(f.p.width * s, f.p.height * s, (pg.width - f.p.x) * s - 4)));
  }
}

/// The Start/Next tag in the left margin, beside the next required field.
function placeTag() {
  const tag = document.getElementById("guide-tag");
  if (!tag || !dv) return;
  const next = nextField();
  tag.querySelector(".os-guidetag__text").textContent = values.size ? t("sign.next") : t("sign.start");
  if (!next) { tag.hidden = true; return; }
  tag.hidden = false;
  const el = main.querySelector(`[data-field-id="${CSS.escape(next.id)}"]`);
  const page = el?.closest(".os-page");
  if (!el || !page) return;
  const a = el.getBoundingClientRect();
  const s = dv.inner.getBoundingClientRect();
  tag.style.top = `${a.top - s.top + a.height / 2}px`;
  tag.style.left = `${Math.max(4, page.offsetLeft - tag.offsetWidth - 28)}px`;
}

function nextField() {
  const order = [...main.querySelectorAll(".os-sfield")].map((n) => n.dataset.fieldId);
  return remaining().sort((a, b) => order.indexOf(a.id) - order.indexOf(b.id))[0] || null;
}

/// The field list in the right panel (A7): every field of this signer with its state;
/// choosing one goes there. The sender's message sits above it.
function renderFieldList() {
  if (!listBody || !listBody.isConnected) return;
  const fields = myFields().filter((f) => takesInput(f.type));
  const next = nextField();
  clear(listBody);
  if (view.envelope?.message) {
    listBody.append(h("div", { class: "os-sign__message os-sign__message--panel" },
      h("p", { class: "os-small os-muted", text: t("sign.message") }), h("p", { text: view.envelope.message })));
  }
  listBody.append(h("p", { class: "os-muted os-small", text: t("sign.fields.text") }));
  const ol = h("ol", { class: "os-fieldlist", attrs: { "data-testid": "field-list" } });
  for (const f of fields) {
    const done = isDone(f) && values.has(f.id);
    const state = done ? t("sign.fields.done") : f.required ? t("sign.required") : t("sign.fields.optional");
    const b = h("button", { type: "button", class: `os-fieldlist__item${done ? " is-done" : ""}${next?.id === f.id ? " is-next" : ""}` },
      icon(done ? "circle-check" : f.required ? "circle-alert" : "pen-line", { size: 20 }),
      h("span", { class: "os-fieldlist__main" }, h("strong", { class: "os-trunc", title: f.label || t(`ftype.${f.type}`), text: f.label || t(`ftype.${f.type}`) }), h("span", { class: "os-muted os-small", text: t("sign.fields.page", { n: f.p.page, type: t(`ftype.${f.type}`) }) })),
      h("span", { class: "os-fieldlist__state", text: state }));
    b.addEventListener("click", () => { listDock?.closeSheet(); focusField(f.id); });
    ol.append(h("li", {}, b));
  }
  listBody.append(ol);
}

/// The Fields button: on phones the list is a bottom sheet; on desktop it shows the panel.
function fieldList() {
  if (!listDock) return;
  if (phone()) { listDock.openSheet(); return; }
  if (listDock.isCollapsed()) listDock.collapse(false);
  listBody.querySelector("button")?.focus();
}

/// Bring field `id` into the middle of the view and focus it. On phones a field too
/// small to use is zoomed to a usable size first (P-05, M-01).
function focusField(id, flag = true) {
  const f = myFields().find((x) => x.id === id);
  const el = main.querySelector(`[data-field-id="${CSS.escape(id)}"]`);
  if (!f || !el || !dv) return;
  const i = dv.pages.findIndex((p) => p.key === f.document_id && p.n === f.p.page);
  if (phone() && f.p.height * dv.scale < 32) dv.setZoom(Math.min(32 / f.p.height, dv.scale * 2.5));
  dv.scrollToBox(i, f.p);
  if (flag) {
    el.classList.add("is-flagged");
    setTimeout(() => el.classList.remove("is-flagged"), 1200);
  }
  el.querySelector("button, input")?.focus({ preventScroll: true });
  requestAnimationFrame(placeTag);
}

function setTools(on) {
  document.getElementById("sign-tools").hidden = !on;
  document.getElementById("bar-finish").hidden = !on;
  if (!on) document.body.classList.remove("is-signing");
}

let viewedTimer = null;
const pendingViewed = new Map();
function reportViewed(doc, set) {
  pendingViewed.set(doc, [...set].sort((a, b) => a - b));
  clearTimeout(viewedTimer);
  viewedTimer = setTimeout(async () => {
    const batch = [...pendingViewed];
    pendingViewed.clear();
    for (const [d, pages] of batch) {
      try { await api.ceremony.viewed(token, d, pages, location_); } catch { /* recorded again on the next scroll */ }
    }
  }, 600);
}

function isDone(f) {
  if (!takesInput(f.type)) return true;
  const v = values.get(f.id);
  if (!v) return false;
  if (f.type === "checkbox") return v.checked === true || !f.required;
  if (f.type === "text") return !!v.text;
  return !!v.signature;
}

/// Place a box at `p` (points) on a page of `pg` (points) in percentages: PDF points ×
/// the view's scale at every zoom, without a relayout.
function placeBox(box, p, pg) {
  box.style.left = `${(p.x / pg.width) * 100}%`;
  box.style.top = `${(p.y / pg.height) * 100}%`;
  box.style.width = `${(p.width / pg.width) * 100}%`;
  box.style.height = `${(p.height / pg.height) * 100}%`;
}

/// "Saved" in the bar for a moment after each value reaches the server (A32).
let savedTimer = null;
function savedChip() {
  const chip = document.getElementById("save-chip");
  if (!chip) return;
  chip.textContent = t("sign.saved");
  clearTimeout(savedTimer);
  savedTimer = setTimeout(() => { chip.textContent = ""; }, 2500);
}

function fieldNode(f, pg) {
  const box = h("div", { class: `os-sfield os-sfield--${f.type}${f.required ? " is-required" : ""}`, attrs: { "data-field-id": f.id, "data-field": f.type } });
  placeBox(box, f.p, pg);
  const req = f.required ? `, ${t("sign.required")}` : "";
  const label = f.label || t(`ftype.${f.type}`);
  if (f.type === "signature" || f.type === "initials") {
    const b = h("button", { type: "button", class: "os-sfield__btn" });
    const paint = () => {
      b.replaceChildren();
      const v = values.get(f.id);
      // The accessible name starts with the words shown (SC 2.5.3, label in name).
      const shown = v?.signature ? t("sign.signed") : t(f.type === "signature" ? "sign.sign-here" : "sign.initial-here");
      b.setAttribute("aria-label", `${shown}: ${label}${req}`);
      const a = Object.values(adoptions).find((x) => x.id === v?.signature);
      if (a) b.append(h("img", { src: a.dataUrl, alt: t("sign.signed-alt", { what: label }) }));
      else if (v?.signature) b.append(icon("circle-check", { size: 16 }), h("span", { text: t("sign.signed") }));
      else b.append(icon(f.type === "signature" ? "signature" : "pen-line", { size: 16 }), h("span", { text: t(f.type === "signature" ? "sign.sign-here" : "sign.initial-here") }));
      box.classList.toggle("is-done", isDone(f));
    };
    b.addEventListener("click", () => signField(f, paint));
    box.append(b);
    paint();
  } else if (f.type === "text") {
    const id = `sf-${f.id}`;
    // A rejected value is said beside the field, not only in a toast (A17).
    const err = h("span", { id: `${id}-err`, class: "os-sfield__err", attrs: { role: "alert" } });
    const input = h("input", { id, class: "os-sfield__input", value: values.get(f.id)?.text || "", maxLength: 4000, placeholder: label + (f.required ? " *" : ""), title: label, attrs: { "aria-label": `${label}${req}`, "aria-describedby": `${id}-err`, ...(f.required ? { "aria-required": "true" } : {}) } });
    input.addEventListener("change", async () => {
      const v = { text: input.value };
      try {
        await api.ceremony.fill(token, f.id, v);
        values.set(f.id, v);
        input.removeAttribute("aria-invalid");
        err.textContent = "";
        savedChip();
      } catch (ex) { input.setAttribute("aria-invalid", "true"); err.textContent = errorMessage(ex); }
      box.classList.toggle("is-done", isDone(f));
      updateGuide();
    });
    box.append(input, err);
    box.classList.toggle("is-done", isDone(f));
  } else if (f.type === "checkbox") {
    const input = h("input", { type: "checkbox", class: "os-sfield__check", checked: values.get(f.id)?.checked === true, title: label, attrs: { "aria-label": `${label}${req}` } });
    input.addEventListener("change", async () => {
      const v = { checked: input.checked };
      try { await api.ceremony.fill(token, f.id, v); values.set(f.id, v); savedChip(); } catch (err) { input.checked = !input.checked; toastError(err); }
      box.classList.toggle("is-done", isDone(f));
      updateGuide();
    });
    box.append(input);
    box.classList.toggle("is-done", isDone(f));
  } else {
    box.classList.add("is-auto");
    box.append(h("span", { class: "os-sfield__auto", attrs: { "aria-label": `${label}: ${AUTO[f.type]?.() || ""}` }, text: AUTO[f.type]?.() || label }));
  }
  return box;
}

async function signField(f, paint) {
  const mark = f.type === "initials" ? "initials" : "signature";
  let a = adoptions[mark];
  if (!a) {
    const res = await adoptDialog({ mark, name: view.recipient?.name || "", host: listDock?.isCollapsed() ? null : listDock?.el });
    if (!res) return;
    try {
      const r = await api.ceremony.adopt(token, mark, res.method, res.base64, location_);
      if (!r?.adoption_id) throw new ApiError({ status: 0, code: "CS-API-0010", title: t("sign.no-adoption-id") });
      a = adoptions[mark] = { id: r.adoption_id, dataUrl: res.dataUrl };
    } catch (err) { toastError(err); return; }
  }
  try {
    const v = { signature: a.id };
    await api.ceremony.fill(token, f.id, v);
    values.set(f.id, v);
    paint();
    savedChip();
    const el = main.querySelector(`[data-field-id="${CSS.escape(f.id)}"]`);
    el?.classList.add("is-stamped");
    setTimeout(() => el?.classList.remove("is-stamped"), 300);
  } catch (err) { toastError(err); }
  updateGuide();
}

const myInputs = () => (view.fields || []).filter((f) => takesInput(f.type) && fromWire(f.placement));
function remaining() {
  return myInputs().filter((f) => f.required && !isDone(f));
}

function updateGuide() {
  const req = myInputs().filter((f) => f.required);
  const left = remaining();
  const progress = document.getElementById("guide-progress");
  progress.textContent = req.length ? t("sign.progress", { done: req.length - left.length, total: req.length }) : t("sign.progress-none");
  const barProgress = document.getElementById("bar-progress");
  barProgress.textContent = progress.textContent;
  // Finish says why it cannot finish yet (A18): aria-disabled keeps it focusable and
  // hoverable for its reason; choosing it goes to the next required field.
  const reason = left.length === 1 ? t("sign.finish-reason-one") : t("sign.finish-reason", { n: left.length });
  const reasonEl = document.getElementById("finish-reason");
  if (reasonEl) reasonEl.textContent = left.length ? reason : "";
  for (const b of [document.getElementById("bar-finish"), document.getElementById("guide-finish")]) {
    if (left.length) { b.setAttribute("aria-disabled", "true"); b.title = reason; } else { b.removeAttribute("aria-disabled"); b.removeAttribute("title"); }
    b.setAttribute("aria-describedby", "finish-reason");
    b.classList.toggle("is-ready", left.length === 0);
  }
  requestAnimationFrame(placeTag);
  const nextBtn = document.getElementById("guide-next");
  nextBtn.hidden = left.length === 0;
  nextBtn.querySelector("span").textContent = values.size ? t("sign.next") : t("sign.start");
  renderFieldList();
}

function goNext() {
  const f = nextField();
  if (f) focusField(f.id);
}

async function finish() {
  if (remaining().length) return goNext();
  review();
}

/// The review step (ADR-020, WYSIWYS): the pages as they will be signed, with this
/// signer's values drawn in place and listed beside them, then an explicit Finish.
/// The pages are drawn here from the delivered PDF with the values over them; the
/// engine-flattened preview from the server is row WEB-05 (docs/47 §As built).
function review() {
  guide.hidden = true;
  setTools(false);
  const fields = myFields();
  // The pages in the same document view as signing (fit width, zoom, one scroller).
  const rv = docView({ label: t("sign.review.pages"), testId: "review-doc", onLayout: () => rzc?.sync(), onZoom: () => rzc?.sync(), onPage: () => rzc?.sync() });
  rv.scroller.classList.add("os-review__pages");
  let rzc = null;
  rzc = zoomControls(rv, { size: "sm" });
  closePanel();
  const dl = h("dl", { class: "os-review" });
  for (const f of myInputs()) {
    const v = values.get(f.id);
    const shown = !v ? t(f.type === "checkbox" ? "sign.review.unchecked" : "sign.review.empty") : v.signature ? t("sign.review.adopted") : "checked" in v ? t(v.checked ? "sign.review.checked" : "sign.review.unchecked") : v.text;
    dl.append(h("dt", { text: f.label || t(`ftype.${f.type}`) }), h("dd", { text: shown }));
  }
  const back = button(t("sign.review.back"), { icon: "chevron-left", size: "lg" });
  const go = button(t("sign.finish"), { icon: "check", variant: "primary", size: "lg", attrs: { "data-testid": "review-finish" } });
  back.addEventListener("click", () => documents());
  go.addEventListener("click", async () => {
    try {
      view = await busy(go, () => api.ceremony.finish(token, [], location_));
      done(everyoneSigned(view.envelope?.status), true);
    } catch (err) { toastError(err); }
  });
  // The values panel beside the pages: on desktop a docked panel, on phones above them.
  const side = dockPanel({ id: "sign-review", side: "right", title: t("sign.review.title"), width: 20, min: 16, max: 32, testId: "panel-review" });
  side.el.classList.add("os-dock--static");
  if (side.isCollapsed()) side.collapse(false);
  side.body.append(
    h("h1", { class: "os-sign__title", text: t("sign.review.title") }),
    h("p", { class: "os-muted", text: t("sign.review.text") }),
    h("h2", { id: "rv-values-h", class: "os-card__title", text: t("sign.review.values") }),
    dl,
    h("p", { class: "os-small", text: t("sign.review.legal") }),
    h("div", { class: "os-stack" }, go, back));
  screen(h("div", { class: "os-signframe os-signframe--review" },
    h("div", { class: "os-signframe__centre" }, rv.scroller, h("div", { class: "os-docbar", attrs: { role: "toolbar", "aria-label": t("doc.toolbar") } }, rzc.el)),
    side.el), rv.live);
  main.classList.add("is-frame-host");
  dv = rv;
  rv.setPages((loaded || []).flatMap(({ doc: d, pdf }) => pdf.pages.map((pg, i) => ({ key: d.id, n: i + 1, total: pdf.pages.length, name: d.name, width: pg.width, height: pg.height, pdf }))));
  rv.els.forEach(({ el, overlay }, i) => {
    const p = rv.pages[i];
    el.setAttribute("role", "img");
    el.setAttribute("aria-label", t("sign.review.page", { n: p.n, total: p.total, name: p.name }));
    el.dataset.testid = "review-page";
    el.setAttribute("data-testid", "review-page");
    overlay.setAttribute("aria-hidden", "true");
    for (const f of fields.filter((x) => x.document_id === p.key && x.p.page === p.n)) overlay.append(flat(f, p));
  });
  rzc.sync();
  go.focus({ preventScroll: true });
}

/// A field as it will look on the signed page: the value only, no field chrome. Sized
/// in percentages of the page, the text in container units of the page's height.
function flat(f, pg) {
  const box = h("div", { class: `os-flat os-flat--${f.type}` });
  placeBox(box, f.p, pg);
  box.style.fontSize = `${Math.min(60, (f.p.height / pg.height) * 100 * 0.6).toFixed(3)}cqh`;
  const v = values.get(f.id);
  if (f.type === "signature" || f.type === "initials") {
    const a = Object.values(adoptions).find((x) => x.id === v?.signature);
    if (a) box.append(h("img", { src: a.dataUrl, alt: "" }));
  } else if (f.type === "checkbox") {
    if (v?.checked) box.append(icon("check", { size: 16 }));
  } else if (f.type === "text") {
    box.textContent = v?.text || "";
  } else {
    box.textContent = AUTO[f.type]?.() || "";
  }
  return box;
}

/// Everyone has signed once the envelope is `completing` (the server is sealing it,
/// docs/40 §Statuses on the wire) or `completed`.
function everyoneSigned(status) {
  return status === "completing" || status === "completed";
}

function done(everyone, celebrate = false) {
  guide.hidden = true;
  moreBtn.hidden = true;
  setTools(false);
  const seal = h("img", { class: `os-done__seal${celebrate ? " is-stamping" : ""}`, src: "/assets/mark.svg", alt: "", width: 96, height: 96 });
  screen(h("div", { class: "os-empty os-done", attrs: { "data-testid": "sign-done", role: "status" } },
    seal,
    h("h1", { class: "os-empty__title", text: t("sign.done.title") }),
    h("p", { class: "os-empty__text", text: everyone ? t("sign.done.everyone") : t("sign.done.waiting") })));
}

// ---- Other actions ------------------------------------------------------------------------------

async function decline() {
  closeMore();
  const reason = await reasonDialog(t("sign.decline.title"), t("sign.decline.label"), { confirm: t("sign.decline.confirm"), required: true, maxLength: 2000 });
  if (!reason) return;
  try {
    view = await api.ceremony.decline(token, reason, location_);
    message({ illus: "inbox", title: t("sign.declined.title"), text: t("sign.declined.text"), testId: "sign-declined" });
  } catch (err) { toastError(err); }
}

async function finishLater() {
  closeMore();
  try {
    await api.ceremony.finishLater(token);
    message({ illus: "inbox", title: t("sign.later.title"), text: t("sign.later.text"), testId: "sign-later" });
  } catch (err) { toastError(err); }
}

function closeMore() {
  moreMenu.hidden = true;
  moreBtn.setAttribute("aria-expanded", "false");
}

function buildChrome() {
  applyI18n(document);
  if (mock) {
    const b = document.getElementById("mock-banner");
    b.hidden = false;
    b.prepend(icon("info", { size: 16 }));
  }
  moreBtn.append(icon("ellipsis"), h("span", { text: t("sign.more") }));
  moreBtn.addEventListener("click", () => {
    const open = moreMenu.hidden;
    moreMenu.hidden = !open;
    moreBtn.setAttribute("aria-expanded", String(open));
    if (open) moreMenu.querySelector("button")?.focus();
  });
  const later = h("button", { type: "button", class: "os-menu__item", attrs: { role: "menuitem" } }, icon("clock", { size: 16 }), h("span", { text: t("sign.later") }));
  later.addEventListener("click", finishLater);
  const dec = h("button", { type: "button", class: "os-menu__item os-menu__item--danger", attrs: { role: "menuitem" } }, icon("circle-x", { size: 16 }), h("span", { text: t("sign.decline") }));
  dec.addEventListener("click", decline);
  moreMenu.append(later, dec);
  moreMenu.addEventListener("keydown", (e) => {
    const items = [...moreMenu.querySelectorAll("button")];
    const i = items.indexOf(document.activeElement);
    if (e.key === "ArrowDown") { e.preventDefault(); items[(i + 1) % items.length].focus(); }
    if (e.key === "ArrowUp") { e.preventDefault(); items[(i - 1 + items.length) % items.length].focus(); }
    if (e.key === "Escape") { closeMore(); moreBtn.focus(); }
  });
  document.addEventListener("click", (e) => { if (!e.target.closest?.("#more-menu, #more-btn")) closeMore(); });
  const nextBtn = document.getElementById("guide-next");
  nextBtn.prepend(icon("arrow-right", { size: 20 }));
  nextBtn.addEventListener("click", goNext);
  const fin = document.getElementById("guide-finish");
  fin.prepend(icon("check", { size: 20 }));
  fin.addEventListener("click", finish);
  const barFin = document.getElementById("bar-finish");
  barFin.prepend(icon("check", { size: 20 }));
  barFin.addEventListener("click", finish);
  const fl = document.getElementById("fields-btn");
  fl.prepend(icon("list-checks", { size: 20 }));
  fl.addEventListener("click", fieldList);
  // The document view relays itself out on resize; the tag follows.
  let resizeTimer = null;
  window.addEventListener("resize", () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(placeTag, 250); });
}

initTheme();
buildChrome();
start();
