// The signing ceremony (WEB-01; docs/47 §Signer ceremony; docs/40 §6), at
// `/s/{token}`: identity (access code) → location (only when the envelope asks,
// GEO-01) → consent to electronic records → the documents with this signer's fields
// and a Next-field guide → review → Finish. Decline and Finish later are always
// available. Mobile first: one primary action, a bottom bar, 44 px targets.
//
// The link token is a secret: it is never logged or put in a message; the server
// binds it to this browser with an HttpOnly cookie on `POST /s/{token}/session`.

import { h, clear, skipTo, download, fmtDate } from "./dom.js";
import { icon } from "./icons.js";
import { t, applyI18n } from "./i18n.js";
import { createClient, isMockMode, isNoServer, errorMessage, locationFrom, ApiError } from "./api.js";
import { button, busy, emptyState, toast, toastError, openDialog, noServerState, dockPanel, openPanel, closePanel } from "./ui/index.js";
import { openPdf } from "./pdfview.js";
import { fromWire } from "./geometry.js";
import { fills, isFilled, isFixed, checkText, fixedText, inputModeFor, TYPED, CHOSEN } from "./signfields.js";
import { adoptDialog } from "./signature.js";
import { enlargeFor } from "./zoom.js";
import { docView, zoomControls, thumbnails, clampScale } from "./docview.js";
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
  if (r.status === "reassigned") return message({ illus: "inbox", title: t("sign.reassigned.title"), text: t("sign.reassigned.done"), testId: "sign-reassigned" });
  if (["voided", "declined", "expired"].includes(env.status)) return message({ illus: "inbox", title: t("sign.closed.title"), text: t(`sign.closed.${env.status}`), testId: "sign-closed" });
  const authing = (view.auth_required || []).includes("access_code");
  buildMenu(authing ? "auth" : "open");
  moreBtn.hidden = false;
  if (authing) return accessCode();
  if (env.signing_options?.capture_location && !location_) return askLocation();
  if (view.consent_required && !r.consented) return consent();
  return documents();
}

function accessCode() {
  guide.hidden = true;
  const err = h("p", { id: "code-err", class: "os-field-error", attrs: { role: "alert" } });
  const input = h("input", { id: "access-code", class: "os-input os-input--lg", autocomplete: "one-time-code", inputMode: "text", maxLength: 64, required: true, attrs: { "aria-describedby": "code-err code-help" } });
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
  // The signer's own values so far (a sender's locked value is not theirs: it stays on
  // the field and does not turn Start into Next).
  for (const f of fields) if (fills(f) && f.value && !values.has(f.id)) values.set(f.id, f.value);
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
  // The tag points at the next field; the bar's Start/Next button (G-S1) is the same
  // action for the keyboard and assistive technology, so the tag is a pointer only.
  const tag = h("button", { type: "button", id: "guide-tag", class: "os-guidetag", tabIndex: -1, attrs: { "data-testid": "guide-tag", "aria-hidden": "true" } },
    h("span", { class: "os-guidetag__text", text: t("sign.start") }));
  tag.addEventListener("click", goNext);
  const v = docView({
    label: t("sign.documents-title"),
    testId: "signer-doc",
    onLayout: () => { enlarge(); zc?.sync(); requestAnimationFrame(placeTag); },
    onZoom: () => { enlarge(); zc?.sync(); },
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
  // Arrival (G-S1): the view goes to the first required field, flagged, without taking
  // focus (no keyboard pops up on a phone). Coming back (A36): to the next required
  // field, focused, not the top of page 1.
  const first = nextField();
  if (first) setTimeout(() => (values.size ? focusField(first.id, false) : revealField(first.id)), 50);
}

/// Scroll field `id` into the middle of the view and flag it, leaving focus and zoom.
function revealField(id) {
  const f = myFields().find((x) => x.id === id);
  const el = main.querySelector(`[data-field-id="${CSS.escape(id)}"]`);
  if (!f || !el || !dv) return;
  dv.scrollToBox(dv.pages.findIndex((p) => p.key === f.document_id && p.n === f.p.page), f.p);
  el.classList.add("is-flagged");
  setTimeout(() => el.classList.remove("is-flagged"), 1200);
  requestAnimationFrame(placeTag);
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
    // Room to grow: to the page's right edge, and no further than the screen's right
    // edge with the field centred in view (focusField centres it), so a field zoomed to
    // the width of a phone is not then pushed past the edge of the screen.
    const w = f.p.width * s;
    const room = Math.min((pg.width - f.p.x) * s - 4, (dv.scroller.clientWidth + w) / 2 - 8);
    node.style.setProperty("--os-enlarge", String(enlargeFor(w, f.p.height * s, room)));
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
  const fields = myFields().filter(fills);
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
  zoomToField(f);
  dv.scrollToBox(i, f.p);
  if (flag) {
    el.classList.add("is-flagged");
    setTimeout(() => el.classList.remove("is-flagged"), 1200);
  }
  el.querySelector("button, input")?.focus({ preventScroll: true });
  requestAnimationFrame(placeTag);
}

/// Phones (P-05, M-01; DocuSign's guided zoom): the view zooms until the field is a
/// 44 px target, as far as the field still fits the width, so the words around it are
/// readable too. Never zooms out; pinch still works.
const TOUCH_PX = 44;
function zoomToField(f) {
  if (!phone() || !dv || f.p.height * dv.scale >= TOUCH_PX - 0.5) return;
  const fitsWidth = (dv.scroller.clientWidth - 32) / f.p.width;
  const want = clampScale(Math.min(TOUCH_PX / f.p.height, fitsWidth));
  if (want > dv.scale * 1.02) dv.setZoom(want);
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
  if (!fills(f)) return true;
  return isFilled(f, values.get(f.id));
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
  // Phones: a field too small to use is zoomed to a usable size when it is reached by
  // typing into it or tabbing to it, not only through Next (P-05). A tapped field is
  // left alone: zooming under the finger would swallow the tap; a tap opens the
  // field's own sheet instead (below).
  box.addEventListener("focusin", (e) => {
    if (phone() && dv && f.p.height * dv.scale < TOUCH_PX && e.target.matches?.(":focus-visible")) focusField(f.id, false);
  });
  const req = f.required ? `, ${t("sign.required")}` : "";
  const label = f.label || t(`ftype.${f.type}`);
  // G-S8: every field says what it is on the page: a label tab above it, shown on
  // hover and focus and for the next required field (the names are in the controls'
  // accessible names already, so the tab is hidden from assistive technology).
  const tip = h("span", { class: "os-sfield__tip", attrs: { "aria-hidden": "true" }, text: `${label}${f.required ? " *" : ""}` });
  // P-05: on phones every field has a touch area of at least 44 px, centred on it,
  // under the control so a tap on the control itself still reaches it.
  const hit = h("span", { class: "os-sfield__hit", attrs: { "aria-hidden": "true", "data-testid": "field-hit" } });
  box.append(hit, tip);
  if (isFixed(f)) {
    // A note or a value the sender locked: shown as the sender wrote it, never changed.
    const shown = fixedText(f);
    box.classList.add("is-auto", "is-fixed");
    hit.remove();
    box.append(h("span", { class: "os-sfield__auto", attrs: { role: "note", "aria-label": `${label}: ${shown}` }, title: shown, text: shown || label }));
  } else if (f.type === "signature" || f.type === "initials") {
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
    hit.addEventListener("click", () => b.click());
    box.append(b);
    paint();
  } else if (TYPED.has(f.type)) {
    const id = `sf-${f.id}`;
    // A rejected value is said beside the field, not only in a toast (A17).
    const err = h("span", { id: `${id}-err`, class: "os-sfield__err", attrs: { role: "alert" } });
    const input = h("input", { id, class: "os-sfield__input", value: values.get(f.id)?.text || "", maxLength: 4000, inputMode: inputModeFor(f), placeholder: label + (f.required ? " *" : ""), title: label, attrs: { "aria-label": `${label}${req}`, "aria-describedby": `${id}-err`, ...(f.required ? { "aria-required": "true" } : {}), ...(f.validation?.kind === "email" ? { autocomplete: "email" } : f.validation?.kind === "phone" ? { autocomplete: "tel" } : {}) } });
    // Typing: a problem the field's rule finds is said as soon as the value is left,
    // before the server is asked (it checks again, and at finish).
    const save = async (text) => {
      const v = { text };
      let ok = true;
      const problem = checkText(f, text);
      if (problem) {
        input.setAttribute("aria-invalid", "true");
        err.textContent = t(problem.key, problem.vars || {});
        return err.textContent;
      }
      try {
        await api.ceremony.fill(token, f.id, v);
        values.set(f.id, v);
        input.value = text;
        input.removeAttribute("aria-invalid");
        err.textContent = "";
        savedChip();
      } catch (ex) { ok = false; input.setAttribute("aria-invalid", "true"); err.textContent = errorMessage(ex); }
      box.classList.toggle("is-done", isDone(f));
      updateGuide();
      return ok ? null : err.textContent;
    };
    input.addEventListener("change", () => save(input.value));
    // P-05 (SignNow): on a phone a tap on the small field opens a full-width sheet with
    // a large input; the keyboard path (Tab, Next) types into the field as on desktop.
    let tapped = false;
    input.addEventListener("pointerdown", (e) => { tapped = phone() && e.pointerType !== "mouse"; if (tapped) e.preventDefault(); });
    // On pointerup, not click: WebKit sends no click after a prevented touch pointerdown.
    input.addEventListener("pointerup", () => { if (!tapped) return; tapped = false; textSheet(f, label, input.value, save); });
    input.addEventListener("pointercancel", () => { tapped = false; });
    hit.addEventListener("click", () => (phone() ? textSheet(f, label, input.value, save) : input.focus()));
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
    hit.addEventListener("click", () => input.click());
    box.append(input);
    box.classList.toggle("is-done", isDone(f));
  } else if (f.type === "dropdown" && !f.allow_custom) {
    // A dropdown is the platform's own select: on a phone it opens the system picker.
    const sel = h("select", { class: "os-sfield__select", title: label, attrs: { "aria-label": `${label}${req}`, ...(f.required ? { "aria-required": "true" } : {}) } },
      h("option", { value: "", text: t("sign.choose") }),
      ...(f.options || []).map((o) => h("option", { value: o, text: o })));
    sel.value = values.get(f.id)?.choice || "";
    sel.addEventListener("change", () => saveChoice(f, sel.value, box, () => { sel.value = values.get(f.id)?.choice || ""; }));
    hit.addEventListener("click", () => { sel.focus(); sel.showPicker?.(); });
    box.append(sel);
    box.classList.toggle("is-done", isDone(f));
  } else if (CHOSEN.has(f.type)) {
    // A radio group (or a dropdown that takes a typed value): a button on the page that
    // opens the choices in a panel beside the document (a bottom sheet on phones).
    const b = h("button", { type: "button", class: "os-sfield__btn os-sfield__choice" });
    const paint = () => {
      const c = values.get(f.id)?.choice;
      b.setAttribute("aria-label", `${c ? c : t("sign.choose")}: ${label}${req}`);
      b.replaceChildren(h("span", { class: "os-trunc", text: c || t("sign.choose") }), icon("chevron-down", { size: 16 }));
      box.classList.toggle("is-done", isDone(f));
    };
    b.addEventListener("click", () => choiceSheet(f, label, paint));
    hit.addEventListener("click", () => b.click());
    box.append(b);
    paint();
  } else if (f.type === "attachment") {
    const file = h("input", { type: "file", accept: "application/pdf,image/png,image/jpeg", class: "os-sr-only", tabIndex: -1, attrs: { "aria-hidden": "true" } });
    const b = h("button", { type: "button", class: "os-sfield__btn" });
    const paint = () => {
      const done_ = !!values.get(f.id)?.attachment;
      const name = attachedNames.get(f.id);
      // The accessible name starts with the words shown (SC 2.5.3).
      const shown = done_ ? (name || t("sign.attach.done")) : t("sign.attach");
      b.setAttribute("aria-label", `${shown}: ${label}${done_ && name ? `, ${t("sign.attach.done")}` : ""}${req}`);
      b.replaceChildren(icon(done_ ? "circle-check" : "paperclip", { size: 16 }), h("span", { class: "os-trunc", text: shown }));
      box.classList.toggle("is-done", isDone(f));
    };
    b.addEventListener("click", () => file.click());
    hit.addEventListener("click", () => file.click());
    file.addEventListener("change", () => attachFile(f, file, b, paint));
    box.append(b, file);
    paint();
  } else {
    box.classList.add("is-auto");
    hit.remove();
    box.append(h("span", { class: "os-sfield__auto", attrs: { "aria-label": `${label}: ${AUTO[f.type]?.() || ""}` }, text: AUTO[f.type]?.() || label }));
  }
  return box;
}

/// The phone sheet for a text field (P-05): the field's label, a full-width input at a
/// readable size, Cancel and Save. Enter saves. A rejected value is said in the sheet.
function textSheet(f, label, value, save) {
  let input;
  let err;
  return openPanel({
    id: "field",
    title: label,
    className: "os-fieldsheet",
    build(body, close) {
      const id = "fieldsheet-input";
      input = h("input", { id, class: "os-input os-input--lg", value, maxLength: 4000, autocomplete: "off", inputMode: inputModeFor(f), attrs: { autofocus: true, "aria-describedby": "fieldsheet-err", ...(f.required ? { "aria-required": "true" } : {}) } });
      err = h("p", { id: "fieldsheet-err", class: "os-field-error", attrs: { role: "alert" } });
      input.addEventListener("keydown", (e) => {
        if (e.key !== "Enter") return;
        e.preventDefault();
        input.closest(".os-sheet")?.querySelector(".os-sheet__foot .os-btn--primary")?.click();
      });
      body.append(
        h("label", { class: "os-label", attrs: { for: id }, text: `${label}${f.required ? ` (${t("sign.required")})` : ""}` }),
        input, err);
      void close;
    },
    actions: [
      { label: t("action.cancel"), value: null },
      {
        label: t("sign.field.save"),
        variant: "primary",
        attrs: { "data-testid": "fieldsheet-save" },
        onClick: async () => {
          if (f.required && !input.value.trim()) { err.textContent = t("form.required"); input.setAttribute("aria-invalid", "true"); input.focus(); return undefined; }
          const problem = await save(input.value);
          if (problem) { err.textContent = problem; input.setAttribute("aria-invalid", "true"); input.focus(); return undefined; }
          return true;
        },
      },
    ],
  });
}


/// Save a choice (`{choice}`); on refusal the field goes back and says why.
async function saveChoice(f, choice, box, revert) {
  try {
    await api.ceremony.fill(token, f.id, { choice });
    values.set(f.id, { choice });
    savedChip();
  } catch (err) { revert?.(); toastError(err); }
  box?.classList.toggle("is-done", isDone(f));
  updateGuide();
}

/// A radio group's choices (or a dropdown that also takes a typed value), in a side
/// panel beside the document; a bottom sheet on phones.
function choiceSheet(f, label, paint) {
  const current = values.get(f.id)?.choice || "";
  let custom = null;
  let picked = current;
  return openPanel({
    id: "choice",
    title: label,
    className: "os-choicesheet",
    build(body) {
      const name = `choice-${f.id}`;
      const group = h("div", { class: "os-radios", attrs: { role: "radiogroup", "aria-label": label } });
      for (const [i, o] of (f.options || []).entries()) {
        const id = `${name}-${i}`;
        const r = h("input", { type: "radio", id, name, value: o, checked: o === current });
        r.addEventListener("change", () => { picked = o; if (custom) custom.value = ""; });
        group.append(h("label", { class: "os-radio os-radio--lg", attrs: { for: id } }, r, h("span", { text: o })));
      }
      body.append(group);
      if (f.type === "dropdown" && f.allow_custom) {
        custom = h("input", { id: `${name}-own`, class: "os-input os-input--lg", value: (f.options || []).includes(current) ? "" : current, maxLength: 4000 });
        custom.addEventListener("input", () => { picked = custom.value; for (const r of group.querySelectorAll("input")) r.checked = false; });
        body.append(h("label", { class: "os-label", attrs: { for: custom.id }, text: t("sign.choice.own") }), custom);
      }
    },
    actions: [
      { label: t("action.cancel"), value: null },
      {
        label: t("sign.field.save"),
        variant: "primary",
        attrs: { "data-testid": "choice-save" },
        onClick: async () => {
          if (!picked) return null;
          await saveChoice(f, picked, main.querySelector(`[data-field-id="${CSS.escape(f.id)}"]`));
          paint();
          return true;
        },
      },
    ],
  });
}

/// Attach a file to an attachment field (`PUT /s/{token}/fields/{field}/attachment`):
/// PDF, PNG or JPEG of at most 10 MiB, checked here first and by the server.
const attachedNames = new Map();
const MAX_ATTACH = 10 * 1024 * 1024;
async function attachFile(f, input, btn, paint) {
  const file = input.files?.[0];
  input.value = "";
  if (!file) return;
  if (file.size > MAX_ATTACH || !/^(application\/pdf|image\/png|image\/jpeg)$/.test(file.type)) {
    toast(t("sign.attach.bad"), "error");
    return;
  }
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const r = await busy(btn, () => api.ceremony.attach(token, f.id, bytes));
    const v = (r?.fields || []).find((x) => x.id === f.id)?.value;
    if (!v?.attachment) throw new ApiError({ status: 0, code: "CS-API-0010", title: t("sign.attach.bad") });
    values.set(f.id, v);
    attachedNames.set(f.id, file.name);
    savedChip();
  } catch (err) { toastError(err); }
  paint();
  updateGuide();
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

const myInputs = () => (view.fields || []).filter((f) => fills(f) && fromWire(f.placement));
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
  // Start/Next (G-S1, M-02): in the bar on desktop, in the bottom bar on phones, worded.
  for (const nextBtn of [document.getElementById("guide-next"), document.getElementById("bar-next")]) {
    nextBtn.hidden = left.length === 0;
    nextBtn.querySelector("span").textContent = values.size ? t("sign.next") : t("sign.start");
  }
  const nf = nextField();
  for (const node of main.querySelectorAll(".os-sfield")) node.classList.toggle("is-next", node.dataset.fieldId === nf?.id);
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
  // G-S7: every value this signer's signature carries, in page order, the automatic
  // ones (date signed, name, email) included, as they will be drawn.
  const dl = h("dl", { class: "os-review", attrs: { "data-testid": "review-values" } });
  const order = (a, b) => (loaded || []).findIndex((x) => x.doc.id === a.document_id) - (loaded || []).findIndex((x) => x.doc.id === b.document_id) || a.p.page - b.p.page || a.p.y - b.p.y || a.p.x - b.p.x;
  for (const f of [...fields].sort(order)) {
    const v = values.get(f.id);
    let shown;
    if (isFixed(f)) shown = fixedText(f);
    else if (!fills(f)) shown = AUTO[f.type]?.() || "";
    else if (!v) shown = t(f.type === "checkbox" ? "sign.review.unchecked" : "sign.review.empty");
    else if (v.signature) shown = t("sign.review.adopted");
    else if ("checked" in v) shown = t(v.checked ? "sign.review.checked" : "sign.review.unchecked");
    else if (v.attachment) shown = attachedNames.get(f.id) || t("sign.attach.done");
    else if (typeof v.choice === "string") shown = v.choice;
    else shown = v.text;
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
  const side = dockPanel({ id: "sign-review", side: "right", title: t("sign.review.values"), width: 20, min: 16, max: 32, testId: "panel-review" });
  side.el.classList.add("os-dock--static");
  if (side.isCollapsed()) side.collapse(false);
  side.body.append(
    h("h1", { class: "os-sign__title", text: t("sign.review.title") }),
    h("p", { class: "os-muted", text: t("sign.review.text") }),
    dl,
    h("p", { class: "os-small", text: t("sign.review.legal") }));
  // The one Finish of this step, pinned below the values so it is always in view.
  side.el.append(h("div", { class: "os-review__actions os-stack" }, go, back));
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
    el.setAttribute("data-testid", "review-page");
    overlay.setAttribute("aria-hidden", "true");
    for (const f of fields.filter((x) => x.document_id === p.key && x.p.page === p.n)) overlay.append(flat(f, p));
  });
  rzc.sync();
  // G-S7: the review opens at the top of the first page and of the values.
  const top = () => { rv.scroller.scrollTop = 0; rv.scroller.scrollLeft = 0; side.body.scrollTop = 0; main.scrollTop = 0; };
  top();
  requestAnimationFrame(top);
  go.focus({ preventScroll: true });
}

/// A field as it will look on the signed page: the value only, no field chrome. Sized
/// in percentages of the page, the text in container units of the page's height.
function flat(f, pg) {
  const box = h("div", { class: `os-flat os-flat--${f.type}` });
  placeBox(box, f.p, pg);
  box.style.fontSize = `${Math.min(60, (f.p.height / pg.height) * 100 * 0.6).toFixed(3)}cqh`;
  const v = values.get(f.id);
  if (isFixed(f)) {
    box.textContent = fixedText(f);
  } else if (f.type === "signature" || f.type === "initials") {
    const a = Object.values(adoptions).find((x) => x.id === v?.signature);
    if (a) box.append(h("img", { src: a.dataUrl, alt: "" }));
  } else if (f.type === "checkbox") {
    if (v?.checked) box.append(icon("check", { size: 16 }));
  } else if (TYPED.has(f.type)) {
    box.textContent = v?.text || "";
  } else if (CHOSEN.has(f.type)) {
    box.textContent = v?.choice || "";
  } else if (f.type === "attachment") {
    // Listed in the certificate by hash, not drawn on the page (docs/40, WEB-06).
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
  // Finished: More keeps what still applies (a copy, history, help).
  buildMenu("ended");
  moreBtn.hidden = false;
  document.getElementById("bar-progress").textContent = "";
  setTools(false);
  const seal = h("img", { class: `os-done__seal${celebrate ? " is-stamping" : ""}`, src: "/assets/mark.svg", alt: "", width: 96, height: 96 });
  // G-S3: a copy now, and what happens next.
  const copy = button(t("sign.done.download"), { icon: "download", variant: "primary", size: "lg", attrs: { "data-testid": "done-download" } });
  copy.addEventListener("click", () => busy(copy, () => downloadCopy()));
  const steps = h("ol", { class: "os-done__steps" },
    h("li", { text: everyone ? t("sign.done.next-sealed") : t("sign.done.next-others") }),
    h("li", { text: t("sign.done.next-email") }),
    h("li", { text: t("sign.done.next-verify") }));
  screen(h("div", { class: "os-empty os-done", attrs: { "data-testid": "sign-done" } },
    seal,
    h("h1", { class: "os-empty__title", text: t("sign.done.title") }),
    h("p", { class: "os-empty__text", attrs: { role: "status" }, text: everyone ? t("sign.done.everyone") : t("sign.done.waiting") }),
    h("h2", { class: "os-done__next", text: t("sign.done.next") }),
    steps,
    h("div", { class: "os-done__actions" }, copy)));
}

// ---- Other actions ------------------------------------------------------------------------------

/// The signer's copy (G-S2, G-S3): `GET /s/{token}/document`, one PDF. Until the server
/// answers it, each delivered document is saved as it is. `print`: open it in a new tab,
/// where the browser's PDF viewer prints it.
async function downloadCopy(print = false) {
  closeMore();
  const name = (s) => `${String(s || "document").replace(/\.pdf$/i, "").replace(/[\\/:*?"<>|\u0000-\u001f]+/g, " ").trim().slice(0, 120) || "document"}.pdf`;
  // After finishing, `GET /s/{token}/document?doc=` (the sealed copy once complete,
  // else a preview marked "not signed"); before, the server answers 409 and the copy
  // is the document as delivered, which is what the signer is reading.
  const files = [];
  try {
    for (const d of view.envelope?.documents || []) {
      let blob;
      try { blob = await api.ceremony.download(token, d.id); } catch (err) {
        if (!(err instanceof ApiError) || ![404, 405, 409, 501].includes(err.status)) throw err;
        blob = await api.ceremony.document(token, d.id);
      }
      files.push({ blob, name: name(d.name || view.envelope?.subject) });
    }
  } catch (err) { toastError(err); return; }
  if (print) {
    for (const f of files) {
      const url = URL.createObjectURL(new Blob([f.blob], { type: "application/pdf" }));
      window.open(url, "_blank", "noopener");
      setTimeout(() => URL.revokeObjectURL(url), 60_000);
    }
    return;
  }
  for (const f of files) download(f.blob, f.name);
}

/// Decline (G-S5): a destructive confirmation, so a true modal. It says what declining
/// does before asking why; the confirming button is filled red.
async function decline() {
  closeMore();
  let area;
  let err;
  const reason = await openDialog({
    title: t("sign.decline.title"),
    className: "os-decline",
    build(body) {
      body.append(
        h("div", { class: "os-callout os-callout--danger" }, icon("triangle-alert", { size: 20 }),
          h("div", {}, h("p", { class: "os-callout__title", text: t("sign.decline.consequence") }), h("p", { text: t("sign.decline.consequence-more") }))),
        h("label", { class: "os-label", attrs: { for: "decline-reason" }, text: t("sign.decline.label") }),
        (area = h("textarea", { id: "decline-reason", class: "os-input os-textarea", rows: 4, maxLength: 2000, attrs: { autofocus: true, required: true, "aria-describedby": "decline-err" } })),
        (err = h("p", { id: "decline-err", class: "os-field-error", attrs: { "aria-live": "polite" } })));
    },
    actions: [
      { label: t("action.cancel"), value: null },
      {
        label: t("sign.decline.confirm"),
        variant: "danger-fill",
        attrs: { "data-testid": "decline-confirm" },
        onClick: () => {
          const v = area.value.trim();
          if (!v) { err.textContent = t("form.required"); area.setAttribute("aria-invalid", "true"); area.focus(); return undefined; }
          return v;
        },
      },
    ],
  });
  if (!reason) return;
  try {
    view = await api.ceremony.decline(token, reason, location_);
    message({ illus: "inbox", title: t("sign.declined.title"), text: t("sign.declined.text"), testId: "sign-declined" });
  } catch (ex) { toastError(ex); }
}

async function finishLater() {
  closeMore();
  try {
    await api.ceremony.finishLater(token);
    // G-S4: the way back in is right here, not only in the email.
    const again = button(t("sign.later.continue"), { icon: "arrow-right", variant: "primary", size: "lg", onClick: () => start(), attrs: { "data-testid": "later-continue" } });
    message({ illus: "inbox", title: t("sign.later.title"), text: t("sign.later.text"), action: again, testId: "sign-later" });
  } catch (err) { toastError(err); }
}

/// Assign to someone else (G-S2), only when the envelope allows it: their name and
/// email, and an optional note for the sender. The fields move to them; this link ends.
async function reassign() {
  closeMore();
  let nameIn;
  let emailIn;
  let noteIn;
  let err;
  const res = await openPanel({
    id: "reassign",
    title: t("sign.reassign.title"),
    build(body) {
      body.append(h("p", { class: "os-muted", text: t("sign.reassign.text") }));
      const row = (id, label, el) => h("div", { class: "os-fieldrow" }, h("label", { class: "os-label", attrs: { for: id }, text: label }), el);
      nameIn = h("input", { id: "reassign-name", class: "os-input", autocomplete: "off", maxLength: 200, attrs: { autofocus: true, required: true } });
      emailIn = h("input", { id: "reassign-email", class: "os-input", type: "email", autocomplete: "off", maxLength: 320, attrs: { required: true } });
      noteIn = h("textarea", { id: "reassign-note", class: "os-input os-textarea", rows: 3, maxLength: 2000 });
      err = h("p", { class: "os-field-error", attrs: { role: "alert" } });
      body.append(h("div", { class: "os-stack" }, row("reassign-name", t("sign.reassign.name"), nameIn), row("reassign-email", t("sign.reassign.email"), emailIn), row("reassign-note", t("sign.reassign.note"), noteIn)), err);
    },
    actions: [
      { label: t("action.cancel"), value: null },
      {
        label: t("sign.reassign.confirm"),
        variant: "primary",
        attrs: { "data-testid": "reassign-confirm" },
        onClick: async () => {
          const name = nameIn.value.trim();
          const email = emailIn.value.trim();
          if (!name) { err.textContent = t("form.required"); nameIn.focus(); return undefined; }
          if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) { err.textContent = t("sign.reassign.bad-email"); emailIn.focus(); return undefined; }
          view = await api.ceremony.reassign(token, { name, email, reason: noteIn.value.trim() }, location_);
          return name;
        },
      },
    ],
  });
  if (!res) return;
  message({ illus: "inbox", title: t("sign.reassigned.title"), text: t("sign.reassigned.text", { name: res }), testId: "sign-reassigned" });
}

/// Help (G-S2): how signing works here, and who to ask about the document.
function help() {
  closeMore();
  openPanel({
    id: "help",
    title: t("sign.help.title"),
    build(body) {
      const sec = (title, ...items) => h("section", { class: "os-help-sec" }, h("h3", { class: "os-help-sec__title", text: title }), ...items);
      body.append(
        sec(t("sign.help.how"), h("ol", { class: "os-sign__list" },
          h("li", { text: t("sign.help.step1") }), h("li", { text: t("sign.help.step2") }),
          h("li", { text: t("sign.help.step3") }), h("li", { text: t("sign.help.step4") }))),
        sec(t("sign.help.questions"), h("p", { text: t("sign.help.questions-text") })),
        sec(t("sign.help.trouble"), h("p", { text: t("sign.help.trouble-text") })));
    },
    actions: [{ label: t("action.close"), value: null }],
  });
}

// The server's audit event types (casual-sign-audit, dotted; `GET /s/{token}/history`,
// WEB-07), each as this recipient reads it. `by` says who acted: `you`, `sender`,
// `recipient` (another, never named), `user`, `host` or `system`.
const HISTORY = {
  "envelope.sent": "sign.history.sent",
  "envelope.corrected": "sign.history.corrected",
  "envelope.voided": "sign.history.voided",
  "envelope.declined": "sign.history.envelope-declined",
  "envelope.expired": "sign.history.expired",
  "envelope.completing": "sign.history.completing",
  "envelope.completed": "sign.history.envelope-completed",
  "recipient.delivered": "sign.history.opened",
  "recipient.auth_passed": "sign.history.authenticated",
  "recipient.auth_failed": "sign.history.auth-failed",
  "recipient.consented": "sign.history.consented",
  "recipient.viewed_document": "sign.history.viewed",
  "recipient.signature_adopted": "sign.history.adopted",
  "recipient.field_completed": "sign.history.filled",
  "recipient.finish_later": "sign.history.later",
  "recipient.signed": "sign.history.completed",
  "recipient.approved": "sign.history.approved",
  "recipient.completed": "sign.history.completed",
  "recipient.declined": "sign.history.declined",
  "recipient.reassigned": "sign.history.reassigned",
  "document.sealed": "sign.history.sealed",
};
/// Who acted, for an event someone other than this recipient did.
const BY = { sender: "sign.history.by-sender", recipient: "sign.history.by-recipient", user: "sign.history.by-user", host: "sign.history.by-host" };

/// View history (G-S2): the envelope's events this recipient may see, newest first.
function history() {
  closeMore();
  openPanel({
    id: "history",
    title: t("sign.history.title"),
    build(body) {
      const list = h("ol", { class: "os-history", attrs: { "aria-busy": "true" } });
      body.append(h("p", { class: "os-muted", text: t("sign.history.text") }), list);
      api.ceremony.history(token).then((r) => {
        list.removeAttribute("aria-busy");
        const events = [...(r?.events || [])].reverse();
        if (!events.length) { list.append(h("li", { class: "os-muted", text: t("sign.history.none") })); return; }
        for (const e of events) {
          const key = HISTORY[e.type];
          const by = BY[e.by];
          list.append(h("li", { class: "os-history__item", attrs: { "data-type": String(e.type || "") } },
            h("span", { class: "os-history__what", text: key ? t(key) : String(e.type || "").replace(/[._]/g, " ") }),
            by ? h("span", { class: "os-history__by os-muted os-small", text: t(by) }) : null,
            h("time", { class: "os-history__when os-muted os-small", attrs: { datetime: e.at || "" }, text: fmtDate(e.at) })));
        }
      }).catch((err) => {
        list.removeAttribute("aria-busy");
        list.append(h("li", { class: "os-muted", text: err instanceof ApiError && [404, 405, 501].includes(err.status) ? t("sign.history.unavailable") : errorMessage(err) }));
      });
    },
    actions: [{ label: t("action.close"), value: null }],
  });
}

function closeMore() {
  moreMenu.hidden = true;
  moreBtn.setAttribute("aria-expanded", "false");
}

/// The More menu (G-S2), built for this envelope's options once the view is known.
/// `stage`: "auth" (before the access code: help only, as nothing else is open yet),
/// "open" (signing), "ended" (this recipient finished: copy, history, help).
function buildMenu(stage = "open") {
  const opts = view?.envelope?.signing_options || {};
  const item = (ic, label, onClick, { danger = false, testId = null } = {}) => {
    const b = h("button", { type: "button", class: `os-menu__item${danger ? " os-menu__item--danger" : ""}`, attrs: { role: "menuitem", ...(testId ? { "data-testid": testId } : {}) } }, icon(ic, { size: 16 }), h("span", { text: label }));
    b.addEventListener("click", onClick);
    return b;
  };
  const sep = () => h("div", { class: "os-menu__sep", attrs: { role: "separator" } });
  const help_ = item("circle-help", t("sign.menu.help"), help, { testId: "menu-help" });
  if (stage === "auth") { moreMenu.replaceChildren(help_); return; }
  const items = [
    item("download", t("sign.menu.download"), () => downloadCopy(), { testId: "menu-download" }),
    item("external-link", t("sign.menu.print"), () => downloadCopy(true), { testId: "menu-print" }),
  ];
  if (stage === "open" && opts.allow_reassign === true) items.push(item("user-plus", t("sign.menu.reassign"), reassign, { testId: "menu-reassign" }));
  items.push(item("list-ordered", t("sign.menu.history"), history, { testId: "menu-history" }));
  items.push(help_);
  if (stage === "open") {
    items.push(sep());
    if (opts.allow_finish_later !== false) items.push(item("clock", t("sign.later"), finishLater));
    if (opts.allow_decline !== false) items.push(item("circle-x", t("sign.decline"), decline, { danger: true }));
  }
  moreMenu.replaceChildren(...items);
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
  moreMenu.addEventListener("keydown", (e) => {
    const items = [...moreMenu.querySelectorAll("button")];
    const i = items.indexOf(document.activeElement);
    if (e.key === "ArrowDown") { e.preventDefault(); items[(i + 1) % items.length].focus(); }
    if (e.key === "ArrowUp") { e.preventDefault(); items[(i - 1 + items.length) % items.length].focus(); }
    if (e.key === "Home") { e.preventDefault(); items[0].focus(); }
    if (e.key === "End") { e.preventDefault(); items[items.length - 1].focus(); }
    if (e.key === "Escape") { closeMore(); moreBtn.focus(); }
  });
  document.addEventListener("click", (e) => { if (!e.target.closest?.("#more-menu, #more-btn")) closeMore(); });
  for (const id of ["guide-next", "bar-next"]) {
    const nextBtn = document.getElementById(id);
    nextBtn.prepend(icon("arrow-right", { size: 20 }));
    nextBtn.addEventListener("click", goNext);
  }
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
