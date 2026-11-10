// The signing ceremony (WEB-01; docs/47 §Signer ceremony; docs/40 §6), at
// `/s/{token}`: identity (access code) → location (only when the envelope asks,
// GEO-01) → consent to electronic records → the documents with this signer's fields
// and a Next-field guide → review → Finish. Decline and Finish later are always
// available. Mobile first: one primary action, a bottom bar, 44 px targets.
//
// The link token is a secret: it is never logged or put in a message; the server
// binds it to this browser with an HttpOnly cookie on `POST /s/{token}/session`.

import { h, clear, reducedMotion } from "./dom.js";
import { icon } from "./icons.js";
import { t, applyI18n } from "./i18n.js";
import { createClient, isMockMode, errorMessage, locationFrom, ApiError } from "./api.js";
import { button, busy, emptyState, toast, toastError, openDialog, reasonDialog } from "./ui.js";
import { openPdf, fitScale } from "./pdfview.js";
import { fromWire, takesInput } from "./geometry.js";
import { adoptDialog } from "./signature.js";
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
  clear(main);
  const s = h("div", { class: "os-sign__screen" }, ...children);
  main.append(s);
  main.focus({ preventScroll: true });
  return s;
}

function message({ illus, title, text, action = null, testId }) {
  guide.hidden = true;
  moreBtn.hidden = true;
  screen(emptyState({ illus, title, text, action, testId }));
}

function fail(err) {
  if (err instanceof ApiError && err.code === "CS-API-0002") {
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
  if (r.status === "completed") return done(env.status === "completed");
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
    toast(location_.declined ? t("sign.location.not-shared") : t("sign.location.shared"), "info");
    next();
  }));
  skip.addEventListener("click", () => { location_ = { declined: true }; next(); });
  screen(h("div", { class: "os-sign__card" },
    icon("map-pin", { size: 24 }),
    h("h1", { class: "os-sign__title", text: t("sign.location.title") }),
    h("p", { class: "os-muted", text: t("sign.location.text") }),
    h("div", { class: "os-stack" }, share, skip)));
  share.focus();
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

const AUTO = { date_signed: () => t("sign.auto-date"), name: () => view.recipient?.name || "", email: () => view.recipient?.email || "" };

async function documents() {
  const docs = view.envelope?.documents || [];
  const fields = (view.fields || []).map((f) => ({ ...f, p: fromWire(f.placement) })).filter((f) => f.p);
  for (const f of fields) if (f.value) values.set(f.id, f.value);
  const pagesWrap = h("div", { class: "os-sign__pages" });
  const s = screen(
    view.envelope?.message ? h("p", { class: "os-sign__message", text: view.envelope.message }) : null,
    h("h1", { class: "os-sr-only", text: t("sign.documents-title") }),
    pagesWrap);
  void s;
  guide.hidden = false;
  for (const p of pdfHandles) p.destroy();
  pdfHandles = [];
  const seen = new Map();
  const observer = typeof IntersectionObserver === "function" ? new IntersectionObserver((entries) => {
    for (const e of entries) {
      if (!e.isIntersecting) continue;
      const { doc, page } = e.target.dataset;
      const set = seen.get(doc) || new Set();
      if (!set.has(Number(page))) { set.add(Number(page)); seen.set(doc, set); reportViewed(doc, set); }
    }
  }, { threshold: 0.5 }) : null;

  const width = Math.min(main.clientWidth || 360, 900) - 16;
  const skeleton = h("div", { class: "os-page os-skeleton-page", attrs: { "aria-hidden": "true" } });
  pagesWrap.append(skeleton);
  pagesWrap.setAttribute("aria-busy", "true");
  for (const d of docs) {
    let pdf;
    try {
      const blob = await api.ceremony.document(token, d.id);
      pdf = await openPdf(new Uint8Array(await blob.arrayBuffer()));
    } catch (err) { return fail(err); }
    pdfHandles.push(pdf);
    skeleton.remove();
    pdf.pages.forEach((pg, i) => {
      const scale = fitScale(pg.width, width);
      const canvas = h("canvas", { attrs: { "aria-hidden": "true" } });
      const overlay = h("div", { class: "os-page__overlay" });
      const page = h("div", { class: "os-page is-loading", attrs: { role: "group", "aria-label": t("prepare.page-of", { n: i + 1, total: pdf.pages.length, name: d.name }), "data-doc": d.id, "data-page": String(i + 1) } }, canvas, overlay);
      page.style.width = `${pg.width * scale}px`;
      page.style.height = `${pg.height * scale}px`;
      pagesWrap.append(page);
      pdf.render(i + 1, canvas, scale).then(() => page.classList.remove("is-loading")).catch(() => page.classList.add("is-error"));
      observer?.observe(page);
      const mine = fields.filter((f) => f.document_id === d.id && f.p.page === i + 1).sort((a, b) => a.p.y - b.p.y || a.p.x - b.p.x);
      for (const f of mine) overlay.append(fieldNode(f, scale));
    });
  }
  pagesWrap.removeAttribute("aria-busy");
  updateGuide();
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

function fieldNode(f, scale) {
  const box = h("div", { class: `os-sfield os-sfield--${f.type}${f.required ? " is-required" : ""}`, attrs: { "data-field-id": f.id, "data-field": f.type } });
  box.style.left = `${f.p.x * scale}px`;
  box.style.top = `${f.p.y * scale}px`;
  box.style.width = `${f.p.width * scale}px`;
  box.style.height = `${f.p.height * scale}px`;
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
    const input = h("input", { id, class: "os-sfield__input", value: values.get(f.id)?.text || "", maxLength: 4000, attrs: { "aria-label": `${label}${req}`, ...(f.required ? { "aria-required": "true" } : {}) } });
    input.addEventListener("change", async () => {
      const v = { text: input.value };
      try {
        await api.ceremony.fill(token, f.id, v);
        values.set(f.id, v);
        input.removeAttribute("aria-invalid");
      } catch (err) { input.setAttribute("aria-invalid", "true"); toastError(err); }
      box.classList.toggle("is-done", isDone(f));
      updateGuide();
    });
    box.append(input);
    box.classList.toggle("is-done", isDone(f));
  } else if (f.type === "checkbox") {
    const input = h("input", { type: "checkbox", class: "os-sfield__check", checked: values.get(f.id)?.checked === true, attrs: { "aria-label": `${label}${req}` } });
    input.addEventListener("change", async () => {
      const v = { checked: input.checked };
      try { await api.ceremony.fill(token, f.id, v); values.set(f.id, v); } catch (err) { input.checked = !input.checked; toastError(err); }
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
    const res = await adoptDialog({ mark, name: view.recipient?.name || "" });
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
  const nextBtn = document.getElementById("guide-next");
  const finish = document.getElementById("guide-finish");
  nextBtn.hidden = left.length === 0;
  finish.disabled = left.length > 0;
  finish.classList.toggle("is-ready", left.length === 0);
  nextBtn.querySelector("span").textContent = values.size ? t("sign.next") : t("sign.start");
}

function goNext() {
  const order = [...main.querySelectorAll(".os-sfield")].map((n) => n.dataset.fieldId);
  const left = remaining().sort((a, b) => order.indexOf(a.id) - order.indexOf(b.id));
  const f = left[0];
  if (!f) return;
  const el = main.querySelector(`[data-field-id="${CSS.escape(f.id)}"]`);
  el.scrollIntoView({ behavior: reducedMotion() ? "auto" : "smooth", block: "center" });
  el.classList.add("is-flagged");
  setTimeout(() => el.classList.remove("is-flagged"), 1200);
  el.querySelector("button, input")?.focus({ preventScroll: true });
}

async function finish() {
  if (remaining().length) return goNext();
  const ok = await openDialog({
    title: t("sign.review.title"),
    description: t("sign.review.text"),
    build(body) {
      const dl = h("dl", { class: "os-review" });
      for (const f of myInputs()) {
        const v = values.get(f.id);
        const shown = !v ? t("sign.review.empty") : v.signature ? t("sign.review.adopted") : "checked" in v ? t(v.checked ? "sign.review.checked" : "sign.review.unchecked") : v.text;
        dl.append(h("dt", { text: f.label || t(`ftype.${f.type}`) }), h("dd", { text: shown }));
      }
      body.append(dl, h("p", { class: "os-small", text: t("sign.review.legal") }));
    },
    actions: [
      { label: t("action.back"), value: false },
      { label: t("sign.finish"), variant: "primary", onClick: () => true, attrs: { "data-testid": "review-finish" } },
    ],
  });
  if (!ok) return;
  try {
    view = await busy(document.getElementById("guide-finish"), () => api.ceremony.finish(token, [], location_));
    done(view.envelope?.status === "completed", true);
  } catch (err) { toastError(err); }
}

function done(everyone, celebrate = false) {
  guide.hidden = true;
  moreBtn.hidden = true;
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
}

initTheme();
buildChrome();
start();
