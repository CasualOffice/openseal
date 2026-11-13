// The signing ceremony (WEB-01; docs/47 §Signer ceremony; docs/40 §6), at
// `/s/{token}`: identity (access code) → location (only when the envelope asks,
// GEO-01) → consent to electronic records → the documents with this signer's fields
// and a Next-field guide → review → Finish. Decline and Finish later are always
// available. Mobile first: one primary action, a bottom bar, 44 px targets.
//
// WEB-18 (the approved canvas, docs/assets/design-canvas/Signer.dc.html and
// SignerPhone.dc.html): a secure-open loader that ticks off real steps only, a header
// naming who asked, the pages beside a thumbnail rail, a floating guide bar (progress
// ring, the next action, Start / Next / Finish), the adopt dialog (a bottom sheet on
// phones), a sealed receipt, and full-page states in the same style. What the guide,
// the rail, the loader and the receipt show is computed by the pure model in
// signfields.js; this file renders it. Every verb is a command (commands.js).
//
// The link token is a secret: it is never logged or put in a message; the server
// binds it to this browser with an HttpOnly cookie on `POST /s/{token}/session`.

import { h, clear, skipTo, download, reducedMotion } from "./dom.js";
import { icon } from "./icons.js";
import { t, applyI18n } from "./i18n.js";
import { createClient, isMockMode, isNoServer, errorMessage, locationFrom, ApiError } from "./api.js";
import { button, busy, toast, toastError, openDialog, confirmDialog, noServerState, dockPanel, openPanel, closePanel, placeMenu } from "./ui/index.js";
import { register, run } from "./commands.js";
import { openPdf } from "./pdfview.js";
import { fromWire } from "./geometry.js";
import { fills, isFilled, isFixed, checkText, fixedText, inputModeFor, TYPED, CHOSEN, guideState, ringDash, loaderSteps, pageCounts, pageTotal, filledKinds, firstName, nameParts, orgMark, askLine, dateField, phoneSegments, actedAs, SSO_KEY, ssoReturn } from "./signfields.js";
import { adoptDialog } from "./signature.js";
import { enlargeFor } from "./zoom.js";
import { docView, zoomControls, thumbnails, clampScale, remPx } from "./docview.js";
import { initTheme } from "./theme.js";
import { illustration } from "./illustrations.js";

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

// Back from an identity provider (`sso`, RAUTH-01; signfields.js `ssoReturn`).
let session = null;
try { session = window.sessionStorage; } catch { session = null; }
const ssoBack = ssoReturn(location, session);
const token = ssoBack ? ssoBack.token : tokenFrom(location);
const main = document.getElementById("main");
const guide = document.getElementById("guide");
const subjectEl = document.getElementById("subject");
const moreBtn = document.getElementById("more-btn");
const moreMenu = document.getElementById("more-menu");
const declineBtn = document.getElementById("decline-btn");

let view = null;          // the CeremonyView
let location_ = null;     // GEO-01 member, once asked
const adoptions = {};     // mark → {id, dataUrl}
const values = new Map(); // field id → value as sent
let pdfHandles = [];

// ---- The secure-open loader (WEB-18) ----------------------------------------------------------
// A seal with an orbiting ring over the page while the ceremony opens, with a step list
// that ticks off only what has really happened (signfields.js `loaderSteps`): the
// signing session was opened, the document bytes arrived, the first page was drawn.
// It never claims a check this page does not make.

const loader = (() => {
  let el = null;
  let list = null;
  let sub = null;
  let reached = 0;
  let pages = null;
  function paint() {
    if (!list) return;
    list.replaceChildren(...loaderSteps(reached, pages).map((s) => h("li", { class: `os-loader__step is-${s.state}` },
      h("span", { class: "os-loader__dot", attrs: { "aria-hidden": "true" } }, s.state === "done" ? icon("check", { size: 12 }) : null),
      h("span", { text: t(s.key, s.vars || {}) }),
      s.state === "done" ? h("span", { class: "os-sr-only", text: t("sign.loader.done") }) : null)));
  }
  function subtitle() {
    if (!sub) return;
    const org = view?.sender?.organisation || "";
    const subject = view?.envelope?.subject || "";
    sub.textContent = [org, subject].filter(Boolean).join(" · ");
  }
  return {
    /// Show the loader at step `r` (0 before the session is open).
    show(r = 0) {
      reached = r;
      pages = pageTotal(view?.envelope?.documents);
      if (!el) {
        list = h("ol", { class: "os-loader__steps" });
        sub = h("span", { class: "os-loader__sub" });
        el = h("div", { class: "os-loader", attrs: { "aria-busy": "true", role: "status", "aria-live": "polite", "data-testid": "sign-loader" } },
          h("div", { class: "os-loader__box" },
            h("div", { class: "os-loader__seal", attrs: { "aria-hidden": "true" } },
              orbitRing(),
              h("span", { class: "os-loader__core" }, icon("lock", { size: 24 }))),
            h("div", { class: "os-loader__head" }, h("b", { class: "os-loader__title", text: t("sign.loader.title") }), sub),
            list));
        document.body.append(el);
      }
      subtitle();
      paint();
    },
    /// Tick off up to step `r`.
    reach(r) {
      reached = Math.max(reached, r);
      pages = pageTotal(view?.envelope?.documents);
      subtitle();
      paint();
    },
    /// Fade out and remove.
    hide() {
      const old = el;
      el = null; list = null; sub = null; reached = 0;
      if (!old) return;
      if (reducedMotion()) { old.remove(); return; }
      old.classList.add("is-leaving");
      setTimeout(() => old.remove(), 240);
    },
    get open() { return !!el; },
  };
})();

/// The loader's orbiting ring (the canvas's 88-unit SVG): a faint track and a quarter arc.
function orbitRing() {
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 88 88");
  svg.setAttribute("class", "os-loader__orbit");
  const track = document.createElementNS(NS, "circle");
  for (const [k, v] of Object.entries({ cx: 44, cy: 44, r: 41, fill: "none", "stroke-width": 3, class: "os-loader__track" })) track.setAttribute(k, String(v));
  const arc = document.createElementNS(NS, "path");
  for (const [k, v] of Object.entries({ d: "M44 3a41 41 0 0 1 41 41", fill: "none", "stroke-width": 3, "stroke-linecap": "round", class: "os-loader__arc" })) arc.setAttribute(k, String(v));
  svg.append(track, arc);
  return svg;
}

/// Resolve once the first page of view `v` is drawn (its canvas painted), or after
/// `ms` in any case, so the loader never stays up on a page that fails to draw.
function firstPageDrawn(v, ms = 4000) {
  return new Promise((resolve) => {
    const el = v?.els?.[0]?.el;
    if (!el || !el.classList.contains("is-loading")) return resolve();
    const done = () => { obs.disconnect(); clearTimeout(timer); resolve(); };
    const obs = new MutationObserver(() => { if (!el.classList.contains("is-loading")) done(); });
    obs.observe(el, { attributes: true, attributeFilter: ["class"] });
    const timer = setTimeout(done, ms);
  });
}

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

/// The card every closing screen and the receipt sit in (the canvas's receipt: a
/// tinted frame around a white card), centred on a soft radial wash.
function stateCard({ mark, title, text = null, children = [], actions = [], testId, tone = "neutral" }) {
  return h("div", { class: `os-state os-state--${tone}` },
    h("div", { class: "os-state__frame", attrs: { "data-testid": testId } },
      h("div", { class: "os-state__card" },
        mark,
        h("h1", { class: "os-state__title", text: title }),
        text ? h("p", { class: "os-state__text", attrs: { role: "status" }, text }) : null,
        ...children,
        actions.length ? h("div", { class: "os-state__actions" }, ...actions) : null)));
}

/// A round mark for a state: the seal (red, a tick) or a quieter disc with an icon.
function stateMark(ic, { seal = false, pop = false } = {}) {
  return h("div", { class: `os-state__mark${seal ? " os-state__mark--seal" : ""}${pop ? " is-popping" : ""}`, attrs: { "aria-hidden": "true" } }, icon(ic, { size: 28 }));
}

/// The illustration of each closing state: every closing screen shows an illustration, a
/// title and one sentence, like every empty state in the app (WEB-01, owner 2026-11-11).
const STATE_ILLUS = { declined: "error", reassigned: "recipients", closed: "error", expired: "calendar", later: "documents", "not-found": "search", error: "error", offline: "offline" };

/// The illustrated mark of a closing state (decorative: the title says what happened).
function stateIllus(kind) {
  const art = illustration(STATE_ILLUS[kind] || "inbox");
  art.setAttribute("aria-hidden", "true");
  return h("div", { class: "os-state__illus" }, art);
}

/// End the signing view and show a closing state (declined, closed, error…): no guide,
/// no progress left over (UX-06), More only where it still applies.
function message({ kind = "closed", title, text, action = null, testId }) {
  loader.hide();
  guide.hidden = true;
  moreBtn.hidden = true;
  declineBtn.hidden = true;
  setTools(false);
  // UX-06: no progress from the signing view left over a closing screen.
  document.getElementById("bar-progress").textContent = "";
  screen(stateCard({ mark: stateIllus(kind), title, text, actions: action ? [action] : [], testId, tone: kind === "error" || kind === "offline" ? "warn" : "neutral" }));
}

function fail(err) {
  loader.hide();
  if (!mock && isNoServer(err)) {
    guide.hidden = true;
    moreBtn.hidden = true;
    return noServerState(screen(), start);
  }
  // The server answers an unknown, expired or revoked link alike (CS-AUTH-0002, so a
  // link cannot be probed); the mock answers CS-API-0002.
  if (err instanceof ApiError && (err.code === "CS-API-0002" || err.code === "CS-AUTH-0002")) {
    return message({ kind: "not-found", title: t("sign.not-found.title"), text: t("sign.not-found.text"), testId: "sign-not-found" });
  }
  const offline = err?.code === "CS-NET-0001";
  message({ kind: offline ? "offline" : "error", title: offline ? t("empty.offline.title") : t("empty.error.title"), text: errorMessage(err), action: button(t("action.retry"), { icon: "refresh-cw", variant: "primary", size: "lg", onClick: start }), testId: "sign-error" });
}

async function start() {
  if (!token) return message({ kind: "not-found", title: t("sign.not-found.title"), text: t("sign.no-token"), testId: "sign-not-found" });
  clear(main);
  loader.show(0);
  try {
    view = await api.ceremony.open(token);
  } catch (err) { return fail(err); }
  // Back from the identity provider (RAUTH-01): the address bar shows the link again,
  // then the sign-in is checked; a refusal shows the sign-in step with why.
  let ssoFailed = false;
  if (ssoBack) {
    const back = location.pathname.startsWith("/s/") ? `/s/${encodeURIComponent(token)}` : `?t=${encodeURIComponent(token)}`;
    try { window.history.replaceState(null, "", back); } catch { /* the address bar keeps the return address */ }
    if ((view.auth_required || []).includes("sso")) {
      try {
        view = await api.ceremony.ssoVerify(token, ssoBack.state, ssoBack.code);
      } catch (err) {
        if (err.status !== 403) return fail(err);
        ssoFailed = true;
      }
    }
  }
  loader.reach(1);
  fillHeader();
  if (ssoFailed && (view.auth_required || []).includes("sso")) {
    buildMenu("auth");
    moreBtn.hidden = false;
    declineBtn.hidden = true;
    return asCard(() => ssoSignIn(true));
  }
  next();
}

/// The header from the view: the organisation's mark, the title, and who asked
/// (signfields.js `askLine`; nothing when the view names no sender).
function fillHeader() {
  subjectEl.textContent = view.envelope?.subject || "";
  subjectEl.title = subjectEl.textContent;
  const mark = orgMark(view.sender?.organisation);
  const markEl = document.getElementById("org-mark");
  markEl.textContent = mark;
  markEl.hidden = !mark;
  document.getElementById("brand-mark").hidden = !!mark;
  const ask = askLine(view.sender);
  const askEl = document.getElementById("ask-line");
  askEl.textContent = ask ? t(ask.key, ask.vars) : "";
  askEl.title = askEl.textContent;
}

/// Go to whichever step this recipient is at.
function next() {
  const r = view.recipient || {};
  const env = view.envelope || {};
  if (r.status === "completed") return done(everyoneSigned(env.status));
  if (r.status === "declined") return message({ kind: "declined", title: t("sign.declined.title"), text: t("sign.declined.text"), testId: "sign-declined" });
  if (r.status === "reassigned") return message({ kind: "reassigned", title: t("sign.reassigned.title"), text: t("sign.reassigned.done"), testId: "sign-reassigned" });
  if (["voided", "declined", "expired"].includes(env.status)) return message({ kind: env.status === "expired" ? "expired" : "closed", title: t("sign.closed.title"), text: t(`sign.closed.${env.status}`), testId: "sign-closed" });
  const pending = view.auth_required || [];
  const authing = ["access_code", ...SENT_CODES, "sso"].some((m) => pending.includes(m));
  buildMenu(authing ? "auth" : "open");
  moreBtn.hidden = false;
  declineBtn.hidden = authing || env.signing_options?.allow_decline === false;
  if (pending.includes("access_code")) return asCard(accessCode);
  const sent = SENT_CODES.find((m) => pending.includes(m));
  if (sent) return asCard(() => sentCode(sent));
  if (pending.includes("sso")) return asCard(() => ssoSignIn(false));
  if (env.signing_options?.capture_location && !location_) return asCard(askLocation);
  if (view.consent_required && !r.consented) return asCard(consent);
  return documents();
}

/// A step shown as a card (identity, location, consent): the loader leaves first.
function asCard(show) {
  loader.hide();
  show();
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

/// The one-time codes the server sends, in the order the page asks for them (SEC-A02;
/// SMS and voice since slice 5).
const SENT_CODES = ["email_otp", "sms_otp", "voice_otp"];

/// A sent one-time code (SEC-A02), on the access-code screen's design: ask for a code
/// by `method` (email, text message or phone call), then enter it. A wrong code answers
/// 403 with the view; the server counts it.
function sentCode(method) {
  guide.hidden = true;
  const k = { email_otp: "otp", sms_otp: "sms", voice_otp: "voice" }[method];
  const id = method === "email_otp" ? "email-code" : `${k}-code`;
  const err = h("p", { id: "otp-err", class: "os-field-error", attrs: { role: "alert" } });
  const status = h("p", { id: "otp-status", class: "os-muted", attrs: { role: "status", "aria-live": "polite" } });
  const input = h("input", { id, class: "os-input os-input--lg", autocomplete: "one-time-code", inputMode: "numeric", maxLength: 6, required: true, attrs: { pattern: "[0-9]{6}", "aria-describedby": "otp-err otp-help", "data-testid": id } });
  const send = button(t(`sign.${k}.send`), { size: "lg", type: "button" });
  send.dataset.testid = `${id}-send`;
  const submit = button(t("sign.code.submit"), { variant: "primary", size: "lg", type: "submit" });
  const form = h("form", { class: "os-sign__card", attrs: { novalidate: true } },
    icon("lock", { size: 24 }),
    h("h1", { class: "os-sign__title", text: t(`sign.${k}.title`) }),
    h("p", { id: "otp-help", class: "os-muted", text: t(`sign.${k}.text`) }),
    send, status,
    h("label", { class: "os-label", attrs: { for: id }, text: t("sign.otp.label") }), input, err, submit);
  send.addEventListener("click", async () => {
    err.textContent = "";
    try {
      view = await busy(send, () => api.ceremony.otpSend(token, method));
      status.textContent = t(`sign.${k}.sent`);
      send.textContent = t("sign.otp.resend");
      input.focus();
    } catch (ex) {
      err.textContent = ex.code === "CS-API-0003" ? t("sign.otp.wait") : errorMessage(ex);
    }
  });
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const code = input.value.trim();
    if (!/^[0-9]{6}$/.test(code)) { err.textContent = t("form.required"); input.setAttribute("aria-invalid", "true"); input.focus(); return; }
    try {
      view = await busy(submit, () => api.ceremony.otpVerify(token, code, method));
      next();
    } catch (ex) {
      err.textContent = ex.status === 403 || ex.code === "CS-AUTH-0003" ? t("sign.code.wrong") : errorMessage(ex);
      input.value = "";
      input.setAttribute("aria-invalid", "true");
      input.focus();
    }
  });
  screen(form);
  send.focus();
}

/// Sign in through an identity provider (`sso`, RAUTH-01), on the access-code screen's
/// design: one button per provider the server lists; the browser goes there and comes
/// back to `/s/oidc`. `failed`: the last sign-in did not pass.
function ssoSignIn(failed) {
  guide.hidden = true;
  const providers = Array.isArray(view.sso_providers) ? view.sso_providers : [];
  const err = h("p", { id: "sso-err", class: "os-field-error", attrs: { role: "alert" }, text: failed ? t("sign.sso.failed") : "" });
  const buttons = providers.map((p) => {
    const b = button(t("sign.sso.with", { name: p.name }), { variant: "primary", size: "lg", type: "button" });
    b.dataset.testid = `sso-${p.id}`;
    b.addEventListener("click", async () => {
      err.textContent = "";
      try {
        const v = await busy(b, () => api.ceremony.ssoStart(token, p.id));
        try { session?.setItem(SSO_KEY, token); } catch { /* the return then cannot find the link */ }
        location.assign(v.sso_authorization_url);
      } catch (ex) {
        err.textContent = ex.code === "CS-API-0003" ? t("sign.otp.wait") : errorMessage(ex);
      }
    });
    return b;
  });
  screen(h("div", { class: "os-sign__card", attrs: { "data-testid": "sign-sso" } },
    icon("lock", { size: 24 }),
    h("h1", { class: "os-sign__title", text: t("sign.sso.title") }),
    h("p", { class: "os-muted", text: t(providers.length ? "sign.sso.text" : "sign.sso.none") }),
    h("div", { class: "os-stack" }, ...buttons), err));
  buttons[0]?.focus();
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

/// Who sent this, as the signer can check it (UX-06): "<Name> (<email>) sent you
/// documents to review and sign", and the account on whose behalf when it differs.
/// From the view's `sender` (docs/40 §6; the mock's until `NOT_ON_SERVER.disclosure`
/// lands on the server): nothing is shown without it, never a guess.
function senderLine() {
  const s = view?.sender;
  if (!s?.name && !s?.email) return null;
  const who = s.name && s.email ? t("sign.sender", { name: s.name, email: s.email }) : t("sign.sender-one", { who: s.name || s.email });
  const org = s.organisation && s.organisation !== s.name ? t("sign.sender-org", { org: s.organisation }) : "";
  return h("p", { class: "os-sign__sender", attrs: { "data-testid": "sign-sender" } }, icon("user", { size: 16 }), h("span", { text: org ? `${who} ${org}` : who }));
}

/// "Sign by 15 Nov 2026" when the envelope expires (`envelope.expires_at`).
function signByLine() {
  const d = dateOnly(view?.envelope?.expires_at);
  return d ? h("p", { class: "os-sign__signby", attrs: { "data-testid": "sign-by" } }, icon("clock", { size: 16 }), h("span", { text: t("sign.sign-by", { date: d }) })) : null;
}

/// A date without the time ("15 Nov 2026"), or "" for none.
function dateOnly(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
}

/// A date and time with its zone ("12 Nov 2026, 19:35 CET"): counterparties read it
/// in other zones (UX-06).
function dateTimeZone(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleString(undefined, { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", timeZoneName: "short" });
}

/// The full disclosure the signer consents to (UX-06; `GET /s/{token}/disclosure`,
/// `NOT_ON_SERVER.disclosure`), in a side panel: the account's text as it is, with
/// its version.
function disclosure() {
  openPanel({
    id: "disclosure",
    title: t("sign.consent.disclosure-title"),
    width: 34,
    build(body) {
      const text = h("div", { class: "os-sign__disclosure", attrs: { "aria-busy": "true", "data-testid": "disclosure-text" } });
      body.append(text);
      api.ceremony.disclosure(token).then((r) => {
        text.removeAttribute("aria-busy");
        text.append(h("p", { class: "os-muted os-small", text: t("sign.consent.version", { v: r?.version || view.consent_required?.version || "" }) }),
          h("p", { class: "os-sign__disclosure-text", text: String(r?.text || "") }));
      }).catch((err) => {
        text.removeAttribute("aria-busy");
        text.append(h("p", { class: "os-field-error", attrs: { role: "alert" }, text: errorMessage(err) }));
      });
    },
    actions: [{ label: t("action.close"), value: null }],
  });
}

function consent() {
  guide.hidden = true;
  const box = h("input", { id: "consent-box", type: "checkbox", attrs: { "aria-describedby": "consent-err" } });
  const err = h("p", { id: "consent-err", class: "os-field-error", attrs: { role: "alert" } });
  const go = button(t("sign.consent.continue"), { variant: "primary", size: "lg", type: "submit" });
  // The full text when this server serves it; else the summary and version only.
  const read = api.available("disclosure") ? button(t("sign.consent.read"), { icon: "file-text", variant: "ghost", onClick: disclosure, attrs: { "data-testid": "consent-read" } }) : null;
  read?.classList.add("os-sign__linkbtn");
  // A visible alternative to Continue: the More menu (Decline, Finish later, Help).
  const other = button(t("sign.consent.other"), { variant: "ghost", onClick: (e) => { e.stopPropagation(); moreBtn.click(); }, attrs: { "data-testid": "consent-other" } });
  other.classList.add("os-sign__linkbtn");
  const form = h("form", { class: "os-sign__card", attrs: { novalidate: true } },
    icon("shield-check", { size: 24 }),
    h("h1", { class: "os-sign__title", text: t("sign.consent.title") }),
    senderLine(), signByLine(),
    // WEB-18: the sender's message, here before the documents (the field list that
    // also shows it is opened from More).
    view.envelope?.message ? h("div", { class: "os-sign__message", attrs: { "data-testid": "consent-message" } },
      h("p", { class: "os-small os-muted", text: t("sign.message") }), h("p", { text: view.envelope.message })) : null,
    h("p", { class: "os-muted", text: t("sign.consent.text") }),
    h("ul", { class: "os-sign__list" },
      h("li", { text: t("sign.consent.point1") }),
      h("li", { text: t("sign.consent.point2") }),
      h("li", { text: t("sign.consent.point3") })),
    h("p", { class: "os-muted os-small", text: t("sign.consent.version", { v: view.consent_required.version }) }),
    read,
    h("label", { class: "os-check os-check--lg", attrs: { for: "consent-box" } }, box, h("span", { text: t("sign.consent.agree") })),
    err, go, other);
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

const today = () => new Date().toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
const AUTO = {
  date_signed: () => dateText(),
  name: () => view.recipient?.name || "",
  // FG-055: as the engine cuts the name at finish (docs/24 §5).
  first_name: () => nameParts(view.recipient?.name).first,
  last_name: () => nameParts(view.recipient?.name).last,
  email: () => view.recipient?.email || "",
};

/// The date-signed field's words (WEB-18, the canvas): it fills itself in once this
/// signer has placed a signature or initials.
function dateText() {
  const d = dateField(signedAny(), today());
  return t(d.key, d.vars || {});
}
const signedAny = () => myFields().some((f) => (f.type === "signature" || f.type === "initials") && values.get(f.id)?.signature);

// WEB-06 (docs/47 §Layout spec), as WEB-18 draws it: the pages in one full-height scroll
// container (docview.js: fit width, 50–200 %, Ctrl/Cmd +/−/0 and pinch, painted near the
// view only) between a thumbnail rail (left) and a matching margin (right); the field
// list is a panel opened from More. The PDFs are fetched once and kept.
let dv = null;            // the document view on screen, if any
let zc = null;            // its zoom controls
let thumbs = null;        // its thumbnail rail
let loaded = null;        // [{doc, pdf}] once fetched
let seenObserver = null;
const seen = new Map();
const phone = () => matchMedia("(max-width: 47.999em)").matches;
/// The widest a page is drawn at fit width (the canvas's page: 46 rem plus its shadow).
const PAGE_MAX_REM = 48;

/// Fetch every document of the envelope once (the loader's second step).
async function loadDocuments() {
  const list = [];
  for (const d of view.envelope?.documents || []) {
    const blob = await api.ceremony.document(token, d.id);
    list.push({ doc: d, pdf: await openPdf(new Uint8Array(await blob.arrayBuffer())) });
  }
  return list;
}

/// Record each page this signer has seen (half of it in view), batched.
function watchSeen() {
  if (seenObserver || typeof IntersectionObserver !== "function") return;
  seenObserver = new IntersectionObserver((entries) => {
    for (const e of entries) {
      if (!e.isIntersecting) continue;
      const { doc, page } = e.target.dataset;
      const set = seen.get(doc) || new Set();
      if (!set.has(Number(page))) { set.add(Number(page)); seen.set(doc, set); reportViewed(doc, set); }
    }
  }, { threshold: 0.5 });
}

async function documents() {
  const fields = myFields();
  // The signer's own values so far (a sender's locked value is not theirs: it stays on
  // the field and does not turn Start into Next).
  for (const f of fields) if (fills(f) && f.value && !values.has(f.id)) values.set(f.id, f.value);
  const opening = !loaded;
  if (opening) {
    if (!loader.open) { clear(main); loader.show(1); }
    try { loaded = await loadDocuments(); } catch (err) { return fail(err); }
    pdfHandles = loaded.map((x) => x.pdf);
    loader.reach(2);
  }
  watchSeen();
  const v = docView({
    label: t("sign.documents-title"),
    testId: "signer-doc",
    // WEB-18: fit width, but never wider than the canvas's page, centred.
    padLeft: () => Math.max(0, v.scroller.clientWidth - remPx(3) - remPx(PAGE_MAX_REM)),
    onLayout: () => { enlarge(); zc?.sync(); },
    onZoom: () => { enlarge(); zc?.sync(); },
    onPage: (i) => { zc?.sync(); thumbs?.mark(i); },
  });
  v.scroller.classList.add("os-sign__pages");
  const rail = h("nav", { class: "os-sign__rail", attrs: { "aria-label": t("prepare.thumbs"), "data-testid": "page-rail" } });
  thumbs = thumbnails(v, rail, { width: 52 });
  const zoomCtl = zoomControls(v, { size: "sm" });
  const frame = h("div", { class: "os-signframe" },
    rail,
    h("div", { class: "os-signframe__centre" }, v.scroller, h("div", { class: "os-docbar", attrs: { role: "toolbar", "aria-label": t("doc.toolbar") } }, zoomCtl.el)),
    h("div", { class: "os-signframe__margin", attrs: { "aria-hidden": "true" } }));
  screen(h("h1", { class: "os-sr-only", text: t("sign.documents-title") }), frame, v.live);
  main.classList.add("is-frame-host");
  dv = v;
  zc = zoomCtl;
  skipTo("#document", t("a11y.skip-doc"));
  guide.hidden = false;
  setTools(true);
  buildMenu("open"); // More now offers the field list
  dv.setPages(loaded.flatMap(({ doc: d, pdf }) => pdf.pages.map((pg, i) => ({ key: d.id, n: i + 1, total: pdf.pages.length, name: d.name, width: pg.width, height: pg.height, pdf }))));
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
  // Arrival (UX-06, after DocuSign): the top of page 1, where the document begins, the
  // next field ringed; Start goes there. Coming back (A36): to the next required
  // field, focused, not the top of page 1.
  const first = nextField();
  if (first && values.size) setTimeout(() => focusField(first.id, false), 50);
  if (opening) {
    await firstPageDrawn(v);
    loader.reach(3);
    setTimeout(() => loader.hide(), reducedMotion() ? 0 : 280);
  } else {
    loader.hide(); // back in (Continue signing): the documents were already here
  }
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

function nextField() {
  const order = [...main.querySelectorAll(".os-sfield")].map((n) => n.dataset.fieldId);
  return remaining().sort((a, b) => order.indexOf(a.id) - order.indexOf(b.id))[0] || null;
}

/// The field list (A7), from More or the command palette: every field of this signer
/// with its state; choosing one goes there. Who sent it, their message and the
/// deadline sit above it. A side panel on desktop, a bottom sheet on phones.
function fieldList() {
  closeMore();
  if (!dv) return;
  openPanel({
    id: "fields",
    title: t("sign.fields.title"),
    className: "os-sign__fieldsheet",
    width: 20,
    build(body, close) { renderFieldList(body, close); },
    actions: [],
  });
}

function renderFieldList(body, close) {
  const fields = myFields().filter(fills);
  const next = nextField();
  const s = view.sender;
  const from = s?.name || s?.email ? h("p", { class: "os-small os-sign__from", attrs: { "data-testid": "fieldlist-sender" }, text: s.name && s.email ? t("sign.from", { name: s.name, email: s.email }) : t("sign.from-one", { who: s.name || s.email }) }) : null;
  const by = dateOnly(view.envelope?.expires_at);
  if (view.envelope?.message || from || by) {
    body.append(h("div", { class: "os-sign__message os-sign__message--panel" },
      from,
      view.envelope?.message ? h("p", { class: "os-small os-muted", text: t("sign.message") }) : null,
      view.envelope?.message ? h("p", { text: view.envelope.message }) : null,
      by ? h("p", { class: "os-small os-muted", text: t("sign.sign-by", { date: by }) }) : null));
  }
  body.append(h("p", { class: "os-muted os-small", text: t("sign.fields.text") }));
  const ol = h("ol", { class: "os-fieldlist", attrs: { "data-testid": "field-list" } });
  for (const f of fields) {
    const done_ = isDone(f) && values.has(f.id);
    const state = done_ ? t("sign.fields.done") : f.required ? t("sign.required") : t("sign.fields.optional");
    const name = f.label || t(`ftype.${f.type}`);
    const b = h("button", { type: "button", class: `os-fieldlist__item${done_ ? " is-done" : ""}${next?.id === f.id ? " is-next" : ""}` },
      icon(done_ ? "circle-check" : f.required ? "circle-alert" : "circle-dashed", { size: 20 }),
      h("span", { class: "os-fieldlist__main" }, h("strong", { class: "os-trunc", title: name, text: name }), h("span", { class: "os-muted os-small", text: t("sign.fields.page", { n: f.p.page, type: t(`ftype.${f.type}`) }) })),
      h("span", { class: "os-fieldlist__state", text: state }));
    b.addEventListener("click", () => { close(null); setTimeout(() => focusField(f.id), 0); });
    ol.append(h("li", {}, b));
  }
  body.append(ol);
}

/// Bring field `id` into the middle of the view and focus it. On phones a field too
/// small to use is zoomed to a usable size first (P-05, M-01).
function focusField(id, flag = true) {
  const f = myFields().find((x) => x.id === id);
  const el = main.querySelector(`[data-field-id="${CSS.escape(id)}"]`);
  if (!f || !el || !dv) return;
  const i = dv.pages.findIndex((p) => p.key === f.document_id && p.n === f.p.page);
  zoomToField(f);
  // Centred in the part of the view the guide bar does not cover (WEB-18).
  const cover = coveredBelow();
  dv.scrollToBox(i, { ...f.p, y: f.p.y + cover / 2 / dv.scale });
  if (flag) {
    el.classList.add("is-flagged");
    setTimeout(() => el.classList.remove("is-flagged"), 1200);
  }
  el.querySelector("button, input, select")?.focus({ preventScroll: true });
  setTimeout(() => keepClear(el), reducedMotion() ? 0 : 450);
}

/// What floats over the document view: the guide bar while it floats (desktop) and
/// the zoom pill, as rectangles.
function floaters() {
  const out = [];
  if (!guide.hidden && getComputedStyle(guide).position === "fixed") out.push(guide.getBoundingClientRect());
  const bar = main.querySelector(".os-signframe .os-docbar");
  if (bar && bar.getClientRects().length) out.push(bar.getBoundingClientRect());
  return out;
}

/// Whether a floater (the guide bar, the zoom pill) covers part of `el`.
function underFloater(el) {
  const r = el.getBoundingClientRect();
  return floaters().some((o) => o.left < r.right && o.right > r.left && o.top < r.bottom && o.bottom > r.top);
}

/// Put field `box`'s label tab above it, below it when another field is in the way
/// above, or nowhere when both would cover a field (WEB-18: a tab never covers one).
function placeTip(box) {
  const tip = box.querySelector(".os-sfield__tip");
  if (!tip) return;
  box.classList.remove("tip-below", "tip-none");
  const others = [...box.parentElement.querySelectorAll(".os-sfield")].filter((n) => n !== box).map((n) => n.getBoundingClientRect());
  const hits = () => { const t_ = tip.getBoundingClientRect(); return others.some((o) => o.left < t_.right && o.right > t_.left && o.top < t_.bottom && o.bottom > t_.top); };
  if (!hits()) return;
  box.classList.add("tip-below");
  if (hits()) { box.classList.remove("tip-below"); box.classList.add("tip-none"); }
}

/// How many px at the bottom of the document view the floating guide bar covers.
function coveredBelow() {
  if (!dv) return 0;
  const sc = dv.scroller.getBoundingClientRect();
  return Math.max(0, ...floaters().map((r) => sc.bottom - r.top + 12));
}

/// Scroll the document view so field `el` is not under the guide bar or the zoom pill,
/// nor under the top edge of the view (WEB-18: a field is never covered).
function keepClear(el) {
  if (!dv || !el?.isConnected) return;
  const sc = dv.scroller.getBoundingClientRect();
  const r = el.getBoundingClientRect();
  const GAP = 12;
  let floor = sc.bottom - GAP;
  for (const o of floaters()) if (o.left < r.right && o.right > r.left) floor = Math.min(floor, o.top - GAP);
  let dy = 0;
  if (r.bottom > floor) dy = r.bottom - floor;
  if (r.top - dy < sc.top + GAP) dy = r.top - (sc.top + GAP);
  if (Math.abs(dy) > 0.5) dv.scroller.scrollBy({ top: dy, behavior: "instant" });
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

/// The signing view's chrome on or off: the phone's progress segments and the body
/// class the styles key on.
function setTools(on) {
  document.body.classList.toggle("is-signing", on);
  document.getElementById("phone-progress").hidden = !on;
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
    else requestAnimationFrame(() => keepClear(box));
    placeTip(box);
  });
  box.addEventListener("pointerenter", () => placeTip(box));
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
      if (v?.signature) b.setAttribute("aria-haspopup", "menu"); else b.removeAttribute("aria-haspopup");
      const a = Object.values(adoptions).find((x) => x.id === v?.signature);
      if (a) b.append(h("img", { src: a.dataUrl, alt: t("sign.signed-alt", { what: label }) }));
      else if (v?.signature) b.append(icon("circle-check", { size: 16 }), h("span", { text: t("sign.signed") }));
      else b.append(icon(f.type === "signature" ? "signature" : "pen-line", { size: 16 }), h("span", { text: t(f.type === "signature" ? "sign.sign-here" : "sign.initial-here") }));
      box.classList.toggle("is-done", isDone(f));
    };
    // UX-06: a signed field offers Remove and Change (DocuSign: a placed signature can
    // be cleared or changed); an empty one signs with the adopted mark.
    b.addEventListener("click", () => (values.get(f.id)?.signature ? signedMenu(f, b) : signField(f)));
    hit.addEventListener("click", () => b.click());
    box.append(b);
    paints.set(f.id, paint);
    paint();
  } else if (TYPED.has(f.type)) {
    const id = `sf-${f.id}`;
    // A rejected value is said beside the field, not only in a toast (A17).
    const err = h("span", { id: `${id}-err`, class: "os-sfield__err", attrs: { role: "alert" } });
    // A multi-line text box (FG-057) is a text area: Enter types a line break.
    const input = h(f.format?.multiline ? "textarea" : "input", { id, class: "os-sfield__input", value: values.get(f.id)?.text || "", maxLength: 4000, inputMode: inputModeFor(f), placeholder: label + (f.required ? " *" : ""), title: label, attrs: { "aria-label": `${label}${req}`, "aria-describedby": `${id}-err`, ...(f.required ? { "aria-required": "true" } : {}), ...(f.validation?.kind === "email" ? { autocomplete: "email" } : f.validation?.kind === "phone" ? { autocomplete: "tel" } : {}) } });
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
    // UX-06: a radio group's options in a popover on the field, saved on selection;
    // a dropdown that also takes a typed value keeps its panel (it needs a Save).
    b.addEventListener("click", () => (f.type === "radio_group" ? choicePopover(f, label, b, paint) : choiceSheet(f, label, paint)));
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
    const shown = h("span", { class: "os-sfield__auto" });
    // The date signed fills itself in once a mark is placed (WEB-18); repainted then.
    const paint = () => {
      const text = AUTO[f.type]?.() || label;
      shown.textContent = text;
      shown.title = text;
      shown.setAttribute("aria-label", `${label}: ${AUTO[f.type]?.() || ""}`);
      box.classList.toggle("is-pending", f.type === "date_signed" && !signedAny());
    };
    autoPaints.set(f.id, paint);
    paint();
    box.append(shown);
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
      const multi = !!f.format?.multiline;
      input = h(multi ? "textarea" : "input", { id, class: multi ? "os-input os-textarea" : "os-input os-input--lg", value, maxLength: 4000, autocomplete: "off", inputMode: inputModeFor(f), ...(multi ? { rows: 4 } : {}), attrs: { autofocus: true, "aria-describedby": "fieldsheet-err", ...(f.required ? { "aria-required": "true" } : {}) } });
      err = h("p", { id: "fieldsheet-err", class: "os-field-error", attrs: { role: "alert" } });
      input.addEventListener("keydown", (e) => {
        if (e.key !== "Enter" || multi) return;
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

/// The paint function of each signature or initials field on screen, by field id.
const paints = new Map();
/// The paint function of each automatic field (date signed, name, email), by field id.
const autoPaints = new Map();

/// The mark a field takes: "initials" or "signature".
const markOf = (f) => (f.type === "initials" ? "initials" : "signature");

/// Adopt marks (UX-06: name and initials together, as DocuSign's adopt dialog). `want`:
/// the mark the signer is placing; the other is adopted in the same step when it has
/// not been yet (two `POST /s/{token}/adopt`, each its own audit event). `change`: a
/// new mark for `want` only. Answers the adoption of `want`, or null.
async function adopt(want, { change = false } = {}) {
  const other = want === "signature" ? "initials" : "signature";
  const res = await adoptDialog({ mark: want, name: view.recipient?.name || "", both: !change && !adoptions[other] });
  if (!res) return null;
  try {
    for (const [mark, m] of Object.entries(res.marks)) {
      if (!m) continue;
      const r = await api.ceremony.adopt(token, mark, m.method, m.base64, location_);
      if (!r?.adoption_id) throw new ApiError({ status: 0, code: "CS-API-0010", title: t("sign.no-adoption-id") });
      adoptions[mark] = { id: r.adoption_id, dataUrl: m.dataUrl };
    }
  } catch (err) { toastError(err); return null; }
  buildMenu("open"); // More now offers "Change signature"
  return adoptions[want] || null;
}

/// Put the adopted mark `a` on field `f`.
async function placeMark(f, a) {
  const v = { signature: a.id };
  await api.ceremony.fill(token, f.id, v);
  values.set(f.id, v);
  paints.get(f.id)?.();
  // WEB-18: the mark is inked in from left to right (the canvas's `ink`; none with
  // reduced motion, sign.css).
  main.querySelector(`[data-field-id="${CSS.escape(f.id)}"] img`)?.classList.add("is-inking");
}

async function signField(f) {
  const mark = markOf(f);
  const a = adoptions[mark] || await adopt(mark);
  if (!a) return;
  try {
    await placeMark(f, a);
    savedChip();
  } catch (err) { toastError(err); }
  updateGuide();
}

/// Remove this signer's value from field `f` (`DELETE /s/{token}/fields/{field}`, a new
/// audit event; `NOT_ON_SERVER.clearField`, so offered only where the server has it).
async function clearValue(f) {
  try {
    await api.ceremony.clearField(token, f.id);
    values.delete(f.id);
    paints.get(f.id)?.();
    savedChip();
  } catch (err) { toastError(err); }
  updateGuide();
}

/// Change the adopted signature (or initials): adopt anew, then put the new mark on
/// every field already signed with that mark (DocuSign's behaviour), each fill a new
/// field event in the audit trail.
async function changeMark(mark) {
  const a = await adopt(mark, { change: true });
  if (!a) return;
  try {
    for (const f of myFields().filter((x) => (x.type === "signature" || x.type === "initials") && markOf(x) === mark && values.get(x.id)?.signature)) await placeMark(f, a);
    savedChip();
  } catch (err) { toastError(err); }
  updateGuide();
}

/// The menu on a signed field: Remove (where the server can) and Change.
function signedMenu(f, anchor) {
  const label = f.label || t(`ftype.${f.type}`);
  const mark = markOf(f);
  const items = [];
  if (api.available("clearField")) items.push({ label: t("sign.field.remove"), icon: "eraser", run: () => clearValue(f), testId: "field-remove" });
  items.push({ label: t(mark === "initials" ? "sign.field.change-initials" : "sign.field.change-signature"), icon: "pencil", run: () => changeMark(mark), testId: "field-change" });
  floatingMenu(anchor, label, items);
}

/// A small menu floating beside `anchor`: role menu, arrow keys, Home and End; Escape
/// and Tab close it; placed by the component library's `placeMenu`.
function floatingMenu(anchor, label, items) {
  const list = h("div", { class: "os-menu os-menu--floating os-sign__floating", attrs: { role: "menu", "aria-label": label } });
  let close = null;
  for (const it of items) {
    const b = h("button", { type: "button", class: "os-menu__item", attrs: { role: "menuitem", tabindex: "-1", ...(it.testId ? { "data-testid": it.testId } : {}) } }, icon(it.icon, { size: 16 }), h("span", { text: it.label }));
    b.addEventListener("click", (e) => { e.stopPropagation(); close?.(false); it.run(); });
    list.append(b);
  }
  const entries = [...list.querySelectorAll('[role="menuitem"]')];
  close = floatBeside(anchor, list, {
    onKey(e) {
      const i = entries.indexOf(document.activeElement);
      if (e.key === "ArrowDown") { e.preventDefault(); entries[(i + 1) % entries.length].focus(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); entries[(i - 1 + entries.length) % entries.length].focus(); }
      else if (e.key === "Home") { e.preventDefault(); entries[0].focus(); }
      else if (e.key === "End") { e.preventDefault(); entries[entries.length - 1].focus(); }
    },
  });
  entries[0]?.focus({ preventScroll: true });
}

/// Show `el` floating beside `anchor` until a choice, Escape, Tab, a press elsewhere, or
/// its field scrolling out of view. Answers its close function, `close(focusBack)`.
let floating = null;
function floatBeside(anchor, el, { onKey = null } = {}) {
  floating?.(false);
  document.body.append(el);
  const place = () => {
    const root = document.documentElement;
    const p = placeMenu(anchor.getBoundingClientRect(), { width: el.offsetWidth, height: el.scrollHeight }, { width: root.clientWidth, height: root.clientHeight }, "start");
    el.style.left = `${p.left}px`; // px-ok: measured client rects (placeMenu)
    el.style.top = `${p.top}px`; // px-ok: measured client rects (placeMenu)
    el.style.maxHeight = `${p.maxHeight}px`; // px-ok: measured client rects (placeMenu)
  };
  place();
  anchor.setAttribute("aria-expanded", "true");
  const outside = (e) => { if (!el.contains(e.target) && !anchor.contains(e.target)) close(false); };
  const key = (e) => {
    if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); close(true); return; }
    if (e.key === "Tab") { close(false); return; }
    onKey?.(e);
  };
  // A scroll moves it with its field, and closes it once the field has left the view.
  const scrolled = (e) => {
    if (el.contains(e.target)) return;
    const r = anchor.getBoundingClientRect();
    if (r.bottom < 0 || r.top > innerHeight || !anchor.isConnected) close(false); else place();
  };
  function close(focusBack) {
    if (floating !== close) return;
    floating = null;
    el.remove();
    anchor.removeAttribute("aria-expanded");
    document.removeEventListener("pointerdown", outside, true);
    document.removeEventListener("scroll", scrolled, true);
    window.removeEventListener("resize", place);
    if (focusBack && anchor.isConnected) anchor.focus({ preventScroll: true });
  }
  el.addEventListener("keydown", key);
  document.addEventListener("pointerdown", outside, true);
  document.addEventListener("scroll", scrolled, true);
  window.addEventListener("resize", place);
  floating = close;
  return close;
}

/// A radio group's options in a popover on its field (UX-06): a click, Space or Enter
/// picks and saves; arrow keys move between them; nothing else to confirm.
function choicePopover(f, label, anchor, paint) {
  const current = values.get(f.id)?.choice || "";
  const name = `choice-${f.id}`;
  const group = h("div", { class: "os-radios os-sign__choices", attrs: { role: "radiogroup", "aria-label": label } });
  const pop = h("div", { class: "os-menu os-menu--floating os-sign__floating" }, group);
  let close = null;
  const pick = async (o) => {
    close?.(true);
    await saveChoice(f, o, main.querySelector(`[data-field-id="${CSS.escape(f.id)}"]`));
    paint();
  };
  for (const [i, o] of (f.options || []).entries()) {
    const id = `${name}-${i}`;
    const r = h("input", { type: "radio", id, name, value: o, checked: o === current });
    // A pointer's click (detail > 0) on the option picks it; the click the browser
    // forwards from the label, or makes for an arrow key, does not (detail 0).
    const opt = h("label", { class: "os-radio os-radio--lg", attrs: { for: id } }, r, h("span", { text: o }));
    opt.addEventListener("click", (e) => { if (e.detail > 0) pick(o); });
    r.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(o); } });
    group.append(opt);
  }
  close = floatBeside(anchor, pop);
  (group.querySelector("input:checked") || group.querySelector("input"))?.focus({ preventScroll: true });
}

const myInputs = () => (view.fields || []).filter((f) => fills(f) && fromWire(f.placement));
function remaining() {
  return myInputs().filter((f) => f.required && !isDone(f));
}

/// Bring the guide bar, the rail's counts, the phone's segments, the next-field ring
/// and the automatic fields in line with the values (the model: `guideState`).
function updateGuide() {
  const req = myInputs().filter((f) => f.required);
  const left = remaining();
  const nf = nextField();
  const g = guideState({ total: req.length, left: left.length, started: values.size > 0, next: nf ? { ...nf, p: fromWire(nf.placement) } : null, label: nf ? nf.label || t(`ftype.${nf.type}`) : "" });
  const progress = document.getElementById("guide-progress");
  progress.textContent = req.length ? t("sign.progress", { done: g.done, total: g.total }) : t("sign.progress-none");
  document.getElementById("bar-progress").textContent = progress.textContent;
  // Finish shows once nothing required is left (the canvas); until then the bar says
  // how many are left (A18), and Start / Next goes to the next one.
  document.getElementById("finish-reason").textContent = g.ready ? "" : t(g.sub.key, g.sub.vars);
  paintGuide(g);
  for (const node of main.querySelectorAll(".os-sfield")) node.classList.toggle("is-next", node.dataset.fieldId === nf?.id);
  for (const paint of autoPaints.values()) paint();
  // The next field, when it is in view but under the floating guide bar, comes clear.
  const nextEl = nf && main.querySelector(`[data-field-id="${CSS.escape(nf.id)}"]`);
  if (nextEl && underFloater(nextEl)) requestAnimationFrame(() => keepClear(nextEl));
  const leftPlaced = left.map((f) => ({ ...f, p: fromWire(f.placement) }));
  const counts = dv ? pageCounts(dv.pages, leftPlaced) : [];
  thumbs?.badges((i) => counts[i] || 0, (n) => t(n === 1 ? "sign.rail.left-one" : "sign.rail.left", { n }));
  paintSegments(phoneSegments(g.ready, false));
}

/// The guide bar from its state: the ring, the next action, how many are left, and
/// Start / Next or Finish (red, pulsing, once everything required is done).
function paintGuide(g) {
  const ring = document.getElementById("guide-ring");
  ring.querySelector(".os-guide__arc")?.setAttribute("stroke-dasharray", ringDash(g.fraction));
  const count = ring.querySelector(".os-guide__count");
  if (count) count.textContent = t("sign.guide.count", { done: g.done, total: g.total });
  document.getElementById("guide-title").textContent = t(g.title.key, g.title.vars || {});
  document.getElementById("guide-sub").textContent = t(g.sub.key, g.sub.vars || {});
  const nextBtn = document.getElementById("guide-next");
  const finishBtn = document.getElementById("guide-finish");
  nextBtn.hidden = g.ready;
  nextBtn.querySelector("span").textContent = t(g.cta === "start" ? "sign.start" : "sign.next");
  nextBtn.classList.toggle("is-start", g.cta === "start");
  const wasReady = !finishBtn.hidden;
  finishBtn.hidden = !g.ready;
  finishBtn.classList.toggle("is-ready", g.ready);
  // Focus follows the action that replaced it, so the keyboard is not left on nothing.
  if (g.ready && !wasReady && document.activeElement === nextBtn) finishBtn.focus({ preventScroll: true });
  // Phones: once everything is done, the page is fitted to the width again, so the
  // signer sees it whole before finishing (the guided zoom is for filling in).
  if (g.ready && !wasReady && phone() && dv && dv.mode !== "fit-width") dv.setZoom("fit-width");
}

/// The phone header's two segments (fields done, finished).
function paintSegments([a, b]) {
  const [s1, s2] = document.querySelectorAll("#phone-progress > span");
  s1?.classList.toggle("is-on", a);
  s2?.classList.toggle("is-on", b);
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
  buildMenu("open"); // no field list while reviewing
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
    const mark = v?.signature ? Object.values(adoptions).find((x) => x.id === v.signature) : null;
    if (mark) {
      // The adopted mark itself, as it will be drawn (UX-06), not the word "Signed".
      dl.append(h("dt", { text: f.label || t(`ftype.${f.type}`) }), h("dd", {}, h("img", { class: "os-review__mark", src: mark.dataUrl, alt: t("sign.signed-alt", { what: f.label || t(`ftype.${f.type}`) }) })));
      continue;
    }
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
  // VS-02: an approver approves, a viewer is done once every page was viewed, and an
  // agent or intermediary names the later recipients before finishing.
  const rtype = view.recipient?.type;
  const names = Array.isArray(view.later_recipients) ? laterForm(view.later_recipients) : null;
  const back = button(t("sign.review.back"), { icon: "chevron-left", size: "lg" });
  const goLabel = t(rtype === "approver" ? "sign.approve" : "sign.finish");
  const go = button(goLabel, { icon: "check", variant: "primary", size: "lg", attrs: { "data-testid": "review-finish" } });
  back.addEventListener("click", () => documents());
  go.addEventListener("click", async () => {
    try {
      view = await busy(go, async () => {
        if (rtype === "approver") return api.ceremony.approve(token, location_);
        if (rtype === "viewer") {
          // Viewing to the end completed the viewer already; finishing again is refused.
          const now = await api.ceremony.view(token);
          if (now.recipient?.status === "completed") return now;
        }
        if (names) {
          let list = names.read();
          // On a phone the form is in the values sheet: open it so the message and the
          // focused field can be seen.
          if (!list && onPhone) { side.openSheet(); list = names.read(); }
          if (!list) throw names.invalid;
          if (list.length) await api.ceremony.nameRecipients(token, list, location_);
        }
        return api.ceremony.finish(token, [], location_);
      });
      done(everyoneSigned(view.envelope?.status), true);
    } catch (err) { if (err !== names?.invalid) toastError(err); }
  });
  // The values panel beside the pages on desktop. On phones (UX-06) the document comes
  // first, full height, with a bottom bar: "Review values (n)" opens the values as a
  // sheet, and Finish; there is no screen where Finish comes before the document.
  const onPhone = phone();
  const side = dockPanel({ id: "sign-review", side: "right", title: t("sign.review.values"), width: 20, min: 16, max: 32, testId: "panel-review" });
  if (!onPhone) side.el.classList.add("os-dock--static");
  if (side.isCollapsed()) side.collapse(false);
  const title = h("h1", { class: onPhone ? "os-sr-only" : "os-sign__title", text: t("sign.review.title") });
  if (!onPhone) side.body.append(title);
  side.body.append(
    h("p", { class: "os-muted", text: t("sign.review.text") }),
    ...(names ? [names.el] : []),
    dl,
    h("p", { class: "os-small", text: t(actedAs(rtype) === "signed" ? "sign.review.legal" : `sign.review.legal.${actedAs(rtype)}`) }));
  // The one Finish of this step: pinned below the values on desktop, in the bottom bar
  // on phones, so it is always in view.
  const actions = h("div", { class: "os-review__actions os-stack" }, go, back);
  let phoneBar = null;
  if (onPhone) {
    const n = dl.querySelectorAll("dt").length;
    const valuesBtn = button(t("sign.review.values-button", { n }), { icon: "list-checks", size: "lg", onClick: () => side.openSheet(), attrs: { "data-testid": "review-values-btn" } });
    actions.classList.add("os-review__actions--bar");
    actions.replaceChildren(valuesBtn, go);
    // VS-02: the agent's names are filled in the sheet, which covers the bar, so the
    // sheet has the same Finish below them.
    let inSheet = null;
    if (names) {
      inSheet = button(goLabel, { icon: "check", variant: "primary", size: "lg", attrs: { "data-testid": "review-finish-sheet" } });
      inSheet.addEventListener("click", () => go.click());
    }
    side.body.append(h("div", { class: "os-stack" }, ...(inSheet ? [inSheet] : []), back));
    phoneBar = actions;
  } else {
    side.el.append(actions);
  }
  screen(onPhone ? title : null, h("div", { class: `os-signframe os-signframe--review${onPhone ? " is-phone" : ""}` },
    h("div", { class: "os-signframe__centre" }, rv.scroller, h("div", { class: "os-docbar", attrs: { role: "toolbar", "aria-label": t("doc.toolbar") } }, rzc.el)),
    side.el, phoneBar), rv.live);
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
  if (!onPhone) go.focus({ preventScroll: true });
  // VS-02: an agent's names are asked in the sheet on a phone, so it opens with them.
  else if (names) side.openSheet();
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

/// The receipt (WEB-18, the canvas's sealed card): the seal (popping in when this signer
/// has just finished), "Signed. Thank you, <name>.", what happens next, when they signed
/// and what they filled, the Verify page, and a copy. The document's fingerprint is
/// shown only when the view carries one; today's view does not, so it is not shown.
function done(everyone, celebrate = false) {
  loader.hide();
  guide.hidden = true;
  // Finished: More keeps what still applies (a copy, history, help).
  buildMenu("ended");
  moreBtn.hidden = false;
  declineBtn.hidden = true;
  document.getElementById("bar-progress").textContent = "";
  setTools(false);
  document.getElementById("phone-progress").hidden = false;
  paintSegments(phoneSegments(true, true));
  const copy = button(t("sign.done.download"), { icon: "download", variant: "primary", size: "lg", attrs: { "data-testid": "done-download", "data-os-command": "signer.download" } });
  copy.classList.add("os-state__primary");
  copy.addEventListener("click", () => busy(copy, () => downloadCopy()));
  // UX-06: Print beside the copy, and the Verify page a link, not only a name.
  const print = button(t("sign.done.print"), { icon: "printer", variant: "ghost", size: "lg", attrs: { "data-testid": "done-print" } });
  print.classList.add("os-state__secondary");
  print.addEventListener("click", () => busy(print, () => downloadCopy(true)));
  // VS-01: once the envelope is completed (the completion email's link), the
  // certificate of completion too, so the signer holds what the sender holds.
  const actions = [copy, print];
  if (view?.envelope?.status === "completed") {
    const cert = button(t("sign.done.certificate"), { icon: "file-check", variant: "ghost", size: "lg", attrs: { "data-testid": "done-certificate", "data-os-command": "signer.certificate" } });
    cert.classList.add("os-state__secondary");
    cert.addEventListener("click", () => busy(cert, () => downloadCertificate()));
    actions.push(cert);
  }
  const MARK = "\u0001";
  const [before, after = ""] = t("sign.done.next-verify", { link: MARK }).split(MARK);
  const name = firstName(view?.recipient?.name);
  // RTE-02: an approver approved, a viewer viewed, an agent or intermediary finished;
  // only a signing type is told it signed.
  const act = actedAs(view?.recipient?.type);
  const sfx = act === "signed" ? "" : `.${act}`;
  const title = celebrate || !name ? t(name ? `sign.done.thanks${sfx}` : `sign.done.thanks-anon${sfx}`, { name }) : t(`sign.done.already${sfx}`, { name });
  screen(stateCard({
    mark: stateMark("check", { seal: true, pop: celebrate }),
    title,
    text: everyone ? t("sign.done.everyone") : t("sign.done.waiting"),
    children: [receiptRows(), h("p", { class: "os-state__note" }, before, h("a", { class: "os-sign__inlink", href: location.pathname.startsWith("/s/") ? "/verify.html" : "verify.html", text: t("sign.done.verify-link") }), after)],
    actions,
    testId: "sign-done",
    tone: "seal",
  }));
}

/// The receipt's facts: when this signer signed (with its zone) and the kinds of field
/// they filled. A row is left out when the view does not say it.
function receiptRows() {
  const rows = [];
  const at = dateTimeZone(view?.recipient?.completed_at);
  if (at) rows.push([t(`sign.receipt.${actedAs(view?.recipient?.type)}`), at]);
  const kinds = filledKinds(myFields().filter(fills), (f) => isFilled(f, values.get(f.id) || f.value));
  if (kinds.length) rows.push([t("sign.receipt.fields"), kinds.map((k, i) => (i ? t(`ftype.${k}`).toLowerCase() : t(`ftype.${k}`))).join(", ")]);
  if (!rows.length) return null;
  return h("dl", { class: "os-state__facts", attrs: { "data-testid": "receipt-facts" } }, ...rows.flatMap(([k, v]) => [h("dt", { text: k }), h("dd", { text: v })]));
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

/// The certificate of completion (VS-01): `GET /s/{token}/certificate`, offered once
/// the envelope is completed; the server refuses it before (409), shown as a toast.
async function downloadCertificate() {
  closeMore();
  let blob;
  try { blob = await api.ceremony.certificate(token); } catch (err) { toastError(err); return; }
  const base = String(view?.envelope?.subject || "document").replace(/[\\/:*?"<>|\u0000-\u001f]+/g, " ").trim().slice(0, 100) || "document";
  download(blob, `${base} - certificate.pdf`);
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
    message({ kind: "declined", title: t("sign.declined.title"), text: t("sign.declined.text"), testId: "sign-declined" });
  } catch (ex) { toastError(ex); }
}

/// Withdraw consent to electronic records (`POST /s/{token}/withdraw-consent`): after
/// a confirmation, as declining, since it ends this signer's part in the envelope.
async function withdrawConsent() {
  closeMore();
  const ok = await confirmDialog(t("sign.withdraw.title"), `${t("sign.withdraw.consequence")} ${t("sign.withdraw.consequence-more")}`, { confirm: t("sign.withdraw.confirm"), danger: true, icon: "circle-x" });
  if (!ok) return;
  try {
    view = await api.ceremony.withdrawConsent(token, location_);
    message({ kind: "declined", title: t("sign.withdrawn.title"), text: t("sign.withdrawn.text"), testId: "sign-withdrawn" });
  } catch (ex) { toastError(ex); }
}

async function finishLater() {
  closeMore();
  try {
    await api.ceremony.finishLater(token);
    // G-S4: the way back in is right here, not only in the email.
    const again = button(t("sign.later.continue"), { icon: "arrow-right", variant: "primary", size: "lg", onClick: () => start(), attrs: { "data-testid": "later-continue" } });
    const until = dateOnly(view?.envelope?.expires_at);
    message({ kind: "later", title: t("sign.later.title"), text: until ? `${t("sign.later.text")} ${t("sign.later.expires", { date: until })}` : t("sign.later.text"), action: again, testId: "sign-later" });
  } catch (err) { toastError(err); }
}

/// The agent's form (VS-02): a name and email for each later recipient not yet reached,
/// built from the reassign panel's rows. `read()` answers the changes (only what was
/// edited), or null after showing what is missing.
function laterForm(later) {
  const err = h("p", { class: "os-field-error", attrs: { role: "alert" } });
  const rows = later.map((r, i) => {
    const row = (id, label, el) => h("div", { class: "os-fieldrow" }, h("label", { class: "os-label", attrs: { for: id }, text: label }), el);
    const nameIn = h("input", { id: `later-name-${i}`, class: "os-input", autocomplete: "off", maxLength: 255, value: r.name || "", attrs: { required: true, "data-testid": "later-name" } });
    const emailIn = h("input", { id: `later-email-${i}`, class: "os-input", type: "email", autocomplete: "off", maxLength: 320, value: r.email || "", attrs: { required: true, "data-testid": "later-email" } });
    return { r, nameIn, emailIn, el: h("fieldset", { class: "os-stack" }, h("legend", { class: "os-label", text: t("sign.later-recipients.who", { n: i + 1, type: t(`rtype.${r.type}`) }) }), row(nameIn.id, t("sign.reassign.name"), nameIn), row(emailIn.id, t("sign.reassign.email"), emailIn)) };
  });
  const el = h("section", { class: "os-stack", attrs: { "data-testid": "later-recipients" } },
    h("h2", { class: "os-label", text: t("sign.later-recipients.title") }),
    h("p", { class: "os-muted", text: t("sign.later-recipients.text") }),
    ...rows.map((x) => x.el), err);
  const invalid = new Error("later recipients incomplete");
  const read = () => {
    err.textContent = "";
    const out = [];
    for (const { r, nameIn, emailIn } of rows) {
      const name = nameIn.value.trim();
      const email = emailIn.value.trim();
      if (!name) { err.textContent = t("form.required"); nameIn.focus(); return null; }
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) { err.textContent = t("sign.reassign.bad-email"); emailIn.focus(); return null; }
      if (name !== (r.name || "") || email !== (r.email || "")) out.push({ id: r.id, name, email });
    }
    return out;
  };
  return { el, read, invalid };
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
  message({ kind: "reassigned", title: t("sign.reassigned.title"), text: t("sign.reassigned.text", { name: res }), testId: "sign-reassigned" });
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
        sec(t("sign.help.questions"), h("p", { text: view?.sender?.name && view?.sender?.email ? t("sign.help.questions-sender", { name: view.sender.name, email: view.sender.email }) : t("sign.help.questions-text") })),
        sec(t("sign.help.trouble"), h("p", { text: t("sign.help.trouble-text") })));
    },
    actions: [{ label: t("action.close"), value: null }],
  });
}

// The server's audit event types (casual-sign-audit, dotted; `GET /s/{token}/history`,
// WEB-07), each as this recipient reads it. `by` says who acted: `you`, `sender`,
// `recipient` (another, never named), `user`, `host` or `system`.
const HISTORY = {
  "envelope.created": "sign.history.created",
  "envelope.sent": "sign.history.sent",
  "envelope.corrected": "sign.history.corrected",
  "envelope.voided": "sign.history.voided",
  "envelope.declined": "sign.history.envelope-declined",
  "envelope.expired": "sign.history.expired",
  "envelope.completing": "sign.history.completing",
  "envelope.completed": "sign.history.envelope-completed",
  "recipient.sent": "sign.history.sent-you",
  "recipient.delivered": "sign.history.opened",
  "recipient.auth_challenged": "sign.history.challenged",
  "recipient.consent_withdrawn": "sign.history.consent-withdrawn",
  "recipient.field_cleared": "sign.history.cleared",
  "recipient.in_person_hosted": "sign.history.hosted",
  "recipient.bounced": "sign.history.bounced",
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
  "document.downloaded": "sign.history.downloaded",
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
        // An event type this page has no words for is left out, never printed raw.
        const events = [...(r?.events || [])].filter((e) => HISTORY[e.type]).reverse();
        if (!events.length) { list.append(h("li", { class: "os-muted", text: t("sign.history.none") })); return; }
        for (const e of events) {
          const key = HISTORY[e.type];
          const by = BY[e.by];
          list.append(h("li", { class: "os-history__item", attrs: { "data-type": String(e.type || "") } },
            h("span", { class: "os-history__what", text: t(key) }),
            by ? h("span", { class: "os-history__by os-muted os-small", text: t(by) }) : null,
            h("time", { class: "os-history__when os-muted os-small", attrs: { datetime: e.at || "" }, text: dateTimeZone(e.at) })));
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
/// "open" (signing), "ended" (this recipient finished: copy, history, help). Each item
/// runs its command (commands.js), so the menu, the header and ⌘K do the same thing.
let stage = "auth";
function buildMenu(stage_ = "open") {
  stage = stage_;
  const opts = view?.envelope?.signing_options || {};
  const item = (ic, label, id, { danger = false, testId = null } = {}) => {
    const b = h("button", { type: "button", class: `os-menu__item${danger ? " os-menu__item--danger" : ""}`, attrs: { role: "menuitem", ...(testId ? { "data-testid": testId } : {}) } }, icon(ic, { size: 16 }), h("span", { text: label }));
    b.addEventListener("click", () => { closeMore(); run(id); });
    return b;
  };
  const sep = () => h("div", { class: "os-menu__sep", attrs: { role: "separator" } });
  const help_ = item("circle-help", t("sign.menu.help"), "signer.help", { testId: "menu-help" });
  if (stage === "auth") { moreMenu.replaceChildren(help_); return; }
  const items = [];
  if (stage === "open" && dv && !guide.hidden) items.push(item("list-checks", t("sign.fields.menu"), "signer.fields", { testId: "menu-fields" }));
  items.push(
    item("download", t("sign.menu.download"), "signer.download", { testId: "menu-download" }),
    item("printer", t("sign.menu.print"), "signer.print", { testId: "menu-print" }),
  );
  // UX-06: change the adopted signature from anywhere, once there is one.
  if (stage === "open" && adoptions.signature) items.push(item("pencil", t("sign.field.change-signature"), "signer.change-signature", { testId: "menu-change-signature" }));
  if (stage === "open" && opts.allow_reassign === true) items.push(item("user-plus", t("sign.menu.reassign"), "signer.reassign", { testId: "menu-reassign" }));
  items.push(item("list-ordered", t("sign.menu.history"), "signer.history", { testId: "menu-history" }));
  items.push(help_);
  if (stage === "open") {
    items.push(sep());
    if (opts.allow_finish_later !== false) items.push(item("clock", t("sign.later"), "signer.finish-later"));
    if (opts.allow_decline !== false) items.push(item("circle-x", t("sign.decline"), "signer.decline", { danger: true }));
    // Withdrawing consent to electronic records is a right whatever the envelope allows
    // (ESIGN §7001(c)(1)(B); the engine's `WithdrawConsent`), offered once given.
    if (view?.recipient?.consented) items.push(item("circle-x", t("sign.withdraw"), "signer.withdraw-consent", { danger: true, testId: "menu-withdraw-consent" }));
  }
  moreMenu.replaceChildren(...items);
}

/// Every verb of the signing page, as a command (docs/47 principle 4): the guide bar,
/// the header, the More menu and the command palette all run these.
function registerCommands() {
  const opts = () => view?.envelope?.signing_options || {};
  const signing = () => stage === "open" && !!dv && !guide.hidden;
  register("signer.next", { label: t("sign.next"), run: goNext, enabled: () => signing() && remaining().length > 0 });
  register("signer.finish", { label: t("sign.finish"), run: finish, enabled: signing });
  register("signer.fields", { label: t("sign.fields.menu"), run: fieldList, enabled: signing });
  register("signer.download", { label: t("sign.menu.download"), run: () => downloadCopy(), enabled: () => stage !== "auth" });
  register("signer.certificate", { label: t("sign.done.certificate"), run: () => downloadCertificate(), enabled: () => view?.envelope?.status === "completed" });
  register("signer.print", { label: t("sign.menu.print"), run: () => downloadCopy(true), enabled: () => stage !== "auth" });
  register("signer.change-signature", { label: t("sign.field.change-signature"), run: () => changeMark("signature"), enabled: () => stage === "open" && !!adoptions.signature });
  register("signer.reassign", { label: t("sign.menu.reassign"), run: reassign, enabled: () => stage === "open" && opts().allow_reassign === true });
  register("signer.history", { label: t("sign.menu.history"), run: history, enabled: () => stage !== "auth" });
  register("signer.help", { label: t("sign.menu.help"), run: help });
  register("signer.finish-later", { label: t("sign.later"), run: finishLater, enabled: () => stage === "open" && opts().allow_finish_later !== false });
  register("signer.decline", { label: t("sign.decline"), run: decline, enabled: () => stage === "open" && opts().allow_decline !== false });
  register("signer.withdraw-consent", { label: t("sign.withdraw"), run: withdrawConsent, enabled: () => stage === "open" && !!view?.recipient?.consented });
}

/// The guide bar's progress ring (the canvas's 36-unit SVG): a faint track, the arc
/// done so far, and "n/N" in the middle.
function guideRing() {
  const NS = "http://www.w3.org/2000/svg";
  const el = (tag, a) => { const n = document.createElementNS(NS, tag); for (const [k, v] of Object.entries(a)) n.setAttribute(k, String(v)); return n; };
  const svg = el("svg", { viewBox: "0 0 36 36", class: "os-guide__svg" });
  svg.append(
    el("circle", { cx: 18, cy: 18, r: 15, fill: "none", "stroke-width": 3, class: "os-guide__track" }),
    el("circle", { cx: 18, cy: 18, r: 15, fill: "none", "stroke-width": 3, "stroke-linecap": "round", "stroke-dasharray": ringDash(0), transform: "rotate(-90 18 18)", class: "os-guide__arc" }),
    el("text", { x: 18, y: 22, "text-anchor": "middle", "font-size": 11, "font-weight": 600, class: "os-guide__count" }));
  return svg;
}

function buildChrome() {
  applyI18n(document);
  if (mock) {
    const b = document.getElementById("mock-banner");
    b.hidden = false;
    b.prepend(icon("info", { size: 16 }));
  }
  registerCommands();
  document.getElementById("secured-chip").prepend(icon("lock", { size: 14 }));
  moreBtn.append(icon("ellipsis"));
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
  declineBtn.addEventListener("click", () => run("signer.decline"));
  document.getElementById("guide-ring").append(guideRing());
  const nextBtn = document.getElementById("guide-next");
  nextBtn.append(icon("arrow-right", { size: 16 }));
  nextBtn.addEventListener("click", () => run("signer.next"));
  const fin = document.getElementById("guide-finish");
  fin.append(icon("arrow-right", { size: 16 }));
  fin.addEventListener("click", () => run("signer.finish"));
}

initTheme();
buildChrome();
start();
