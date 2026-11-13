// The OpenSeal platform console UI (CON-17; docs/23 §5, §10). Served only by the
// `casual-sign-console` binary on its private listener; talks to `/console/v1` on the
// same origin. Visual spec: docs/assets/design-canvas/Console.dc.html.
//
// Every verb is a registered command (`command`, `run`); every string reaches the page
// through `textContent` (dom.js `h`). Screens show only what the API returns: no
// invented numbers, no series the API does not keep.

import { h, append, clear, $, svg } from "./dom.js";
import * as api from "./api.js";
import * as M from "./model.js";
import * as art from "./art.js";

const root = $("#root");
const toasts = $("#toasts");

const state = {
  me: null,
  roles: [],
  email: null,
  approvals: [],
  health: null,
  healthAt: 0,
  timers: [],
  view: 0,
  orgNames: new Map(),
};

// Commands -----------------------------------------------------------------------------

const commands = new Map();

/// Register a verb.
function command(name, fn) {
  commands.set(name, fn);
}

/// Run a registered verb.
function run(name, ...args) {
  const fn = commands.get(name);
  if (!fn) throw new Error(`no command ${name}`);
  return fn(...args);
}

// Small pieces -------------------------------------------------------------------------

/// Append children, skipping null and false (the DOM's own `append` would print "null").
const put = (parent, ...kids) => append(parent, kids);

function toast(text, bad = false) {
  const t = h("div", { class: `toast${bad ? " bad" : ""}`, text });
  toasts.appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

function chip(text, tone = "") {
  return h("span", { class: `chip ${tone}`.trim(), text });
}

function statusChip(status) {
  const tone = { active: "ok", suspended: "warn", closed: "bad", archived: "", up: "ok", down: "bad" }[status] ?? "";
  const label = status ? status[0].toUpperCase() + status.slice(1) : "–";
  return chip(label, tone);
}

function regionChips(labels) {
  if (!labels || !labels.length) return h("span", { class: "chip", text: "None" });
  return h("span", { class: "chips" }, labels.map((l) => h("span", { class: "chip region", text: l })));
}

function btn(text, cls, onClick, attrs) {
  return h("button", { type: "button", class: `btn ${cls || ""}`.trim(), text, on: { click: onClick }, attrs });
}

/// A shield icon and "Needs a fresh authenticator code": shown beside every action the
/// server will refuse without a second factor entered within 5 minutes.
function factorNote(text = "Needs a code from your authenticator app") {
  return h("span", { class: "factor" },
    svg("svg", { width: "14", height: "14", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": "2", "aria-hidden": "true" },
      svg("path", { d: "M12 3 5 6v6c0 4.5 3 7.8 7 9 4-1.2 7-4.5 7-9V6z" }),
      svg("path", { d: "m9 12 2 2 4-4" })),
    text);
}

function emptyState(picture, title, text, action) {
  return h("div", { class: "empty rise" }, picture, h("b", { text: title }), text ? h("span", { text }) : null, action || null);
}

function errorState(problem, retry) {
  return emptyState(art.failed(), "This could not be loaded", M.problemMessage(problem), retry ? btn("Try again", "ghost", retry) : null);
}

function skeletonRows(n = 4) {
  return h("div", { attrs: { "aria-busy": "true", "aria-label": "Loading" } },
    Array.from({ length: n }, () => h("div", { class: "row" },
      h("span", { class: "bullet sk" }),
      h("div", { class: "main" }, skel("40%", ".75rem"), skel("70%", ".625rem")))));
}

function skel(width, height) {
  const s = h("span", { class: "sk" });
  s.style.width = width;
  s.style.height = height;
  return s;
}

function heading(title) {
  return h("h1", { text: title, attrs: { tabindex: "-1" } });
}

/// Copy text to the clipboard, saying so.
async function copy(text, what) {
  try {
    await navigator.clipboard.writeText(text);
    toast(`${what} copied`);
  } catch {
    toast("Copy failed: select the text and copy it", true);
  }
}

// Side panel ---------------------------------------------------------------------------

let panelClose = null;

/// Open a side panel (instruction 22: side panels, not dialogs). `build(close)` returns
/// its body. Esc and the scrim close it; focus returns to the opener.
function openPanel(title, build) {
  if (panelClose) panelClose();
  const opener = document.activeElement;
  const scrim = h("div", { class: "scrim" });
  const titleId = `p${Math.random().toString(36).slice(2)}`;
  const body = h("div", { class: "panel-b" });
  const close = () => {
    scrim.remove();
    panel.remove();
    document.removeEventListener("keydown", onKey, true);
    panelClose = null;
    if (opener && opener.isConnected) opener.focus();
  };
  const panel = h("section", { class: "panel", attrs: { role: "dialog", "aria-modal": "true", "aria-labelledby": titleId } },
    h("div", { class: "panel-h" }, h("h2", { id: titleId, text: title }),
      h("button", { type: "button", class: "x", text: "×", attrs: { "aria-label": "Close" }, on: { click: close } })),
    body);
  function onKey(e) {
    if (e.key === "Escape") { e.preventDefault(); close(); return; }
    if (e.key !== "Tab") return;
    const f = [...panel.querySelectorAll("button, a[href], input, select, [tabindex]:not([tabindex='-1'])")].filter((x) => !x.disabled);
    if (!f.length) return;
    const first = f[0];
    const last = f[f.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  }
  scrim.addEventListener("click", close);
  document.addEventListener("keydown", onKey, true);
  body.appendChild(build(close));
  document.body.append(scrim, panel);
  panelClose = close;
  const first = panel.querySelector("input, select, .panel-b button");
  (first || panel.querySelector(".x")).focus();
  return close;
}

/// A form with fields, a submit button and an error line. `submit(form)` throws a
/// `Problem` or a string to show; it returns normally on success.
function form({ fields, submitText, primary = true, danger = false, factor = false, submit, extra }) {
  const err = h("div", { class: "alert-box bad", hidden: true, attrs: { role: "alert" } });
  const go = h("button", { type: "submit", class: `btn big ${danger ? "danger" : primary ? "primary" : ""}`.trim(), text: submitText });
  const f = h("form", { class: "form", attrs: { novalidate: true } },
    fields, extra || null, err,
    h("div", { class: "acts" }, go, factor ? factorNote() : null));
  f.addEventListener("submit", async (e) => {
    e.preventDefault();
    err.hidden = true;
    go.disabled = true;
    try {
      await submit(f);
    } catch (p) {
      err.textContent = typeof p === "string" ? p : M.problemMessage(p);
      err.hidden = false;
    } finally {
      go.disabled = false;
    }
  });
  return f;
}

function field(label, input, hint) {
  const id = input.id || (input.id = `f${Math.random().toString(36).slice(2)}`);
  const hintEl = hint ? h("span", { class: "hint", id: `${id}-h`, text: hint }) : null;
  if (hintEl) input.setAttribute("aria-describedby", hintEl.id);
  return h("div", { class: "field" }, h("label", { attrs: { for: id }, text: label }), input, hintEl);
}

function codeInput() {
  return h("input", { type: "text", class: "code", name: "code", attrs: { inputmode: "numeric", autocomplete: "one-time-code", maxlength: "7", pattern: "[0-9 ]*", required: true } });
}

// Second factor ------------------------------------------------------------------------

/// Run `fn`; when the server answers `CS-CON-0002` (no second factor in the last
/// 5 minutes), ask for a fresh code in a side panel, send it, and run `fn` again.
async function withFactor(fn) {
  try {
    return await fn();
  } catch (p) {
    if (p?.code !== "CS-CON-0002") throw p;
    await new Promise((resolve, reject) => {
      let done = false;
      openPanel("Confirm it's you", (closePanel) => {
        const input = codeInput();
        return h("div", { class: "form" },
          h("p", { class: "d", text: "This action needs a code from your authenticator app entered in the last 5 minutes. Each code works once, so wait for a new one if you just used it." }),
          form({
            fields: field("Authenticator code", input),
            submitText: "Confirm",
            submit: async () => {
              const code = M.cleanCode(input.value);
              if (!code) throw "Enter the 6 digits from your authenticator app.";
              try {
                await api.post("/auth/totp", { code });
              } catch (p) {
                if (p?.code === "CS-CON-0002") throw "That code is not right, or was already used. Wait for the next one.";
                throw p;
              }
              done = true;
              closePanel();
              resolve();
            },
          }));
      });
      // Closing the panel without a code cancels the action.
      const obs = new MutationObserver(() => {
        if (!document.querySelector(".panel")) { obs.disconnect(); if (!done) reject(Object.assign(new api.Problem({ status: 401, code: "CS-CON-0002" }), { cancelled: true })); }
      });
      obs.observe(document.body, { childList: true });
    });
    return fn();
  }
}

// Sign-in, second factor, enrolment ----------------------------------------------------

function authShell(...children) {
  stopTimers();
  clear(root);
  const card = h("main", { class: "auth-card rise", id: "main" },
    h("div", { class: "brand" }, art.mark(), h("span", { class: "txt" }, h("b", { text: "OpenSeal" }), h("span", { class: "sub", text: "Platform console" }))),
    ...children);
  root.appendChild(h("div", { class: "auth" }, card));
  const first = card.querySelector("input");
  if (first) first.focus();
}

function steps(n, of) {
  return h("div", { class: "steps", attrs: { "aria-label": `Step ${n} of ${of}`, role: "img" } },
    Array.from({ length: of }, (_, i) => h("span", { class: i < n ? "on" : "" })));
}

command("signIn", async (email, password) => {
  const r = await api.post("/auth/login", { email, password });
  api.setCsrf(r?.csrf_token);
});

command("submitTotp", async (code) => {
  const r = await api.post("/auth/totp", { code });
  state.me = r.operator;
  state.roles = r.roles || [];
});

command("signOut", async () => {
  try { await api.post("/auth/logout"); } catch { /* the session may already be gone */ }
  api.setCsrf(null);
  state.me = null;
  state.roles = [];
  state.email = null;
  location.hash = "#/health";
  showSignIn();
});

function showSignIn(message) {
  const email = h("input", { type: "email", name: "email", attrs: { autocomplete: "username", required: true, maxlength: "254" } });
  const password = h("input", { type: "password", name: "password", attrs: { autocomplete: "current-password", required: true } });
  authShell(
    steps(1, 2),
    h("h1", { text: "Sign in" }),
    h("p", { text: "Operators only. Your password, then a code from your authenticator app." }),
    message ? h("div", { class: "alert-box warn", text: message, attrs: { role: "status" } }) : null,
    form({
      fields: [field("E-mail", email), field("Password", password)],
      submitText: "Continue",
      submit: async () => {
        if (!email.value.trim() || !password.value) throw "Enter your e-mail and password.";
        try {
          await run("signIn", email.value.trim(), password.value);
        } catch (p) {
          // Wrong password and unknown e-mail answer alike (CS-CON-0001).
          if (p?.code === "CS-CON-0001") throw "That e-mail and password do not match an operator.";
          throw p;
        }
        showTotp();
      },
    }),
    h("div", { class: "auth-foot" }, h("a", { href: "#/enrol", class: "crumb", text: "Have an enrolment link? Set up your account" })));
}

function showTotp() {
  const input = codeInput();
  authShell(
    steps(2, 2),
    h("h1", { text: "Enter your code" }),
    h("p", { text: "Open your authenticator app and enter the 6-digit code for the OpenSeal console." }),
    form({
      fields: field("Authenticator code", input),
      submitText: "Verify",
      submit: async () => {
        const code = M.cleanCode(input.value);
        if (!code) throw "Enter the 6 digits from your authenticator app.";
        try {
          await run("submitTotp", code);
        } catch (p) {
          if (p?.code === "CS-CON-0002") throw "That code is not right, or was already used. Wait for the next one.";
          if (p?.code === "CS-CON-0001" || p?.code === "CS-CON-0013") { showSignIn("Your sign-in has ended. Start again."); return; }
          throw p;
        }
        await enterApp();
      },
    }),
    h("div", { class: "auth-foot" }, h("button", { type: "button", class: "linkbtn", text: "Use a different account", on: { click: () => run("signOut") } })));
}

command("enrolBegin", (token) => api.post("/auth/enrolment/begin", { token }));
command("enrolFinish", (token, password, code) => api.post("/auth/enrolment/finish", { token, password, code }));

function showEnrol(tokenFromLink) {
  const token = h("input", { type: "text", name: "token", value: tokenFromLink || "", attrs: { autocomplete: "off", spellcheck: "false", maxlength: "64", required: true } });
  authShell(
    steps(1, 3),
    h("h1", { text: "Set up your operator account" }),
    h("p", { text: "Use the one-time enrolment token a platform owner gave you. It works once and lasts 24 hours." }),
    form({
      fields: field("Enrolment token", token),
      submitText: "Continue",
      submit: async () => {
        const t = token.value.trim();
        if (!t) throw "Enter your enrolment token.";
        const r = await run("enrolBegin", t);
        showEnrolSecret(t, r.otpauth_uri);
      },
    }),
    h("div", { class: "auth-foot" }, h("a", { href: "#/health", class: "crumb", text: "Back to sign in" })));
}

function showEnrolSecret(token, uri) {
  const secret = M.otpSecret(uri);
  const pw = h("input", { type: "password", name: "password", attrs: { autocomplete: "new-password", minlength: "12", required: true } });
  const again = h("input", { type: "password", name: "again", attrs: { autocomplete: "new-password", required: true } });
  const code = codeInput();
  authShell(
    steps(2, 3),
    h("h1", { text: "Add the console to your authenticator" }),
    h("p", { text: "Open the link on this device, or type the key into your authenticator app. It is shown only now." }),
    h("div", { class: "secret", text: secret, attrs: { "aria-label": "Authenticator key" } }),
    h("div", { class: "acts form" }, h("div", { class: "acts" },
      btn("Copy key", "ghost", () => copy(secret.replace(/ /g, ""), "Key")),
      h("a", { class: "btn ghost", href: uri, text: "Open in authenticator app" }))),
    form({
      fields: [
        field("New password", pw, "At least 12 characters. Nobody else, not even the owner who added you, ever knows it."),
        field("Repeat password", again),
        field("Code from your authenticator app", code),
      ],
      submitText: "Finish setup",
      submit: async () => {
        const bad = M.checkPassword(pw.value, again.value);
        if (bad) throw bad;
        const c = M.cleanCode(code.value);
        if (!c) throw "Enter the 6 digits your authenticator app now shows.";
        await run("enrolFinish", token, pw.value, c);
        history.replaceState(null, "", "#/health");
        authShell(
          steps(3, 3),
          h("h1", { text: "You're set up" }),
          h("p", { text: "Sign in with your e-mail, your new password and a fresh code. Each code works once, so wait for the next one." }),
          btn("Sign in", "primary big wide", () => showSignIn()));
      },
    }));
}

// The signed-in shell -------------------------------------------------------------------

const NAV = [
  ["health", "Health", "health"],
  ["organizations", "Organizations", "organizations"],
  ["approvals", "Approvals", "approvals"],
  ["plans", "Plans", "plans"],
  ["operators", "Operators", "operators"],
  ["log", "Operator log", "log"],
];

function stopTimers() {
  for (const t of state.timers) clearInterval(t);
  state.timers = [];
}

async function enterApp() {
  if (M.access(state.roles).operators && !state.email) {
    try {
      const r = await api.get("/operators");
      state.email = (r.operators || []).find((o) => o.id === state.me)?.email || null;
    } catch { state.email = null; }
  }
  await refreshApprovals();
  route();
}

async function refreshApprovals() {
  if (!M.access(state.roles).approvals) { state.approvals = []; return; }
  try {
    const r = await api.get("/approvals");
    state.approvals = r.approvals || [];
  } catch { /* the badge is a convenience */ }
}

function shell(active) {
  stopTimers();
  const can = M.access(state.roles);
  const grantable = M.grantableCount(state.approvals, state.me);
  const nav = h("nav", { class: "side", attrs: { "aria-label": "Console" } },
    h("div", { class: "brand" }, art.mark(), h("span", { class: "txt" }, h("b", { text: "OpenSeal" }), h("span", { class: "sub", text: "Platform console" }))),
    NAV.filter(([key, , need]) => can[need]).map(([key, label]) => h("a", {
      class: "nav", href: `#/${key}`, attrs: { "aria-current": key === active ? "page" : null },
    }, label, key === "approvals" && grantable ? h("span", { class: "count", text: String(grantable), attrs: { "aria-label": `${grantable} waiting for you` } }) : null)),
    h("div", { class: "who" },
      h("span", { class: "id", text: state.email || `Operator ${M.shortId(state.me)}`, attrs: { title: state.me } }),
      h("span", { class: "roles", text: `${state.roles.map(M.roleLabel).join(", ")} · TOTP verified` }),
      h("button", { type: "button", class: "linkbtn", text: "Sign out", on: { click: () => run("signOut") } })));
  const main = h("main", { class: "content", id: "main" });
  clear(root);
  root.appendChild(h("div", { class: "shell" }, nav, main));
  return main;
}

function page(main, ...children) {
  const p = h("div", { class: "page" }, ...children);
  main.appendChild(p);
  return p;
}

/// Move focus to the new screen's heading, so a screen reader announces the change.
function focusHeading(main) {
  const h1 = main.querySelector("h1");
  if (h1) h1.focus({ preventScroll: true });
}

// Health -------------------------------------------------------------------------------

command("refreshHealth", async () => {
  const [health, alerts, dead] = await Promise.all([
    api.get("/health"),
    api.get("/alerts?limit=20"),
    api.get("/dead-letters?limit=10"),
  ]);
  return { health, alerts: alerts.alerts || [], dead: dead.dead_letters || [] };
});

function tileSkeleton() {
  return h("div", { class: "tiles", attrs: { "aria-busy": "true", "aria-label": "Loading health" } },
    Array.from({ length: 5 }, () => h("div", { class: "tile sk-tile" }, skel("50%", ".625rem"), skel("35%", "1.5rem"), skel("80%", ".625rem"))));
}

function tile(t) {
  const flag = t.state === "warn" ? "Look" : t.state === "bad" ? "Down" : null;
  return h("div", { class: `tile rise ${t.state === "ok" ? "" : t.state}`.trim(), attrs: { role: "group", "aria-label": t.label } },
    h("div", { class: "lbl" }, h("span", { text: t.label }), flag ? h("span", { class: "flag", text: flag }) : null),
    h("div", { class: "val" }, h("b", { text: t.value }), t.unit ? h("span", { text: t.unit }) : null),
    h("span", { class: "note", text: t.note }));
}

function alertsCard(alerts) {
  const open = M.openAlerts(alerts);
  const openIds = new Set(open.map((a) => a.id));
  const closed = alerts.filter((a) => !openIds.has(a.id) && !a.resolves).slice(0, 5);
  const rows = open.map((a) => h("div", { class: "row" },
    h("span", { class: "bullet tone-warn" }),
    h("div", { class: "main" }, h("b", { text: a.code }), h("span", { class: "d", text: `Raised by ${a.source}` }), h("span", { class: "w", text: M.ago(a.at), attrs: { title: M.shortDate(a.at) } }))));
  const done = closed.map((a) => h("div", { class: "row done" },
    h("span", { class: "bullet tone-ok" }),
    h("div", { class: "main" }, h("b", { text: a.code }), h("span", { class: "d", text: `Raised by ${a.source}` }), h("span", { class: "w", text: M.ago(a.at) })),
    h("span", { class: "chip ok", text: "✓ Resolved" })));
  return h("section", { class: "card rise", attrs: { "aria-labelledby": "alerts-h" } },
    h("div", { class: "card-h" }, h("b", { id: "alerts-h", text: "Alerts" }), h("span", { class: "sub", text: "raised by the platform's services; cleared when a later alert resolves them" })),
    open.length ? rows : emptyState(art.allClear(), "No open alerts", "New alerts appear here as services raise them."),
    done);
}

function servicesCard(services) {
  const up = services.filter((s) => s.status === "up").length;
  return h("section", { class: "card rise", attrs: { "aria-labelledby": "svc-h" } },
    h("div", { class: "card-h" }, h("b", { id: "svc-h", text: "Services" }),
      services.length ? h("span", { class: "right" }, h("span", { class: `dot ${up === services.length ? "tone-ok" : "tone-bad"}` }), h("span", { class: "sub", text: `${up} of ${services.length} up` })) : null),
    services.length
      ? services.map((s) => h("div", { class: "row" },
        h("span", { class: `bullet ${s.status === "up" ? "tone-ok" : "tone-bad"}` }),
        h("div", { class: "main" }, h("b", { text: s.name }), h("span", { class: "w", text: `${s.role} · ${s.probe} probe${s.http_status ? ` · HTTP ${s.http_status}` : ""}` })),
        h("span", { class: "w mono", text: `${M.count(s.latency_ms)} ms` }),
        statusChip(s.status)))
      : emptyState(art.noEntries(), "No service targets configured", "They are deployment configuration, set on the host with casual-sign-console set-service-target, never typed here."),
    h("div", { class: "card-f", text: "Shows counts and states only. Document content and per-person data never reach the console." }));
}

function queueCard(jobs) {
  const rows = M.queueByKind(jobs);
  return h("section", { class: "card rise", attrs: { "aria-labelledby": "q-h" } },
    h("div", { class: "card-h" }, h("b", { id: "q-h", text: "Job queue by kind" })),
    rows.length
      ? h("div", { class: "tbl-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, h("th", { text: "Kind" }), h("th", { class: "num", text: "Queued" }), h("th", { class: "num", text: "Running" }), h("th", { class: "num", text: "Dead" }), h("th", { class: "num hide-sm", text: "Oldest queued" }))),
        h("tbody", {}, rows.map((r) => h("tr", {},
          h("td", {}, h("code", { text: r.kind })), h("td", { class: "num", text: M.count(r.queued) }), h("td", { class: "num", text: M.count(r.running) }),
          h("td", { class: "num", text: M.count(r.dead) }), h("td", { class: "num hide-sm", text: r.oldest == null ? "–" : M.duration(r.oldest) }))))))
      : emptyState(art.noEntries(), "The queue is empty", "No job is queued, running or dead."));
}

function deadCard(dead) {
  return h("section", { class: "card rise", attrs: { "aria-labelledby": "d-h" } },
    h("div", { class: "card-h" }, h("b", { id: "d-h", text: "Dead letters" }), h("span", { class: "sub", text: "newest first; never the payload" })),
    dead.length
      ? dead.map((d) => h("div", { class: "row" },
        h("span", { class: "bullet tone-warn" }),
        h("div", { class: "main" }, h("b", {}, h("code", { text: d.kind })),
          h("span", { class: "d", text: `${d.error_code || "No error code"} · ${M.plural(d.attempts, "attempt")}` }),
          h("span", { class: "w mono", text: `job ${M.shortId(d.id)} · workspace ${M.shortId(d.workspace_id)}${d.envelope_id ? ` · envelope ${M.shortId(d.envelope_id)}` : ""}` })),
        h("span", { class: "w", text: d.finished_at ? M.ago(d.finished_at) : "–" })))
      : emptyState(art.allClear(), "No dead letters", "Jobs that run out of attempts appear here."));
}

async function viewHealth(main, view) {
  const pill = h("span", { class: "pill" }, h("span", { class: "dot live tone-ok" }), h("span", { text: "Checking…" }));
  const updated = h("span", { class: "meta", text: "" });
  const body = h("div", { class: "form" }, tileSkeleton(), h("div", { class: "split" }, h("div", { class: "card" }, skeletonRows(2)), h("div", { class: "card" }, skeletonRows(3))));
  page(main, h("div", { class: "head" }, heading("Health"), pill,
    h("span", { class: "right" }, updated, btn("Refresh", "ghost", () => load()))), body);
  focusHeading(main);
  let first = true;
  async function load() {
    try {
      const r = await run("refreshHealth");
      if (view !== state.view) return;
      state.healthAt = Date.now();
      const sum = M.healthSummary(r.health, r.alerts);
      put(clear(pill), h("span", { class: `dot live tone-${sum.tone}` }), h("span", { text: sum.text }));
      put(clear(body), 
        h("div", { class: "tiles" }, M.healthTiles(r.health).map(tile)),
        h("div", { class: "split" }, alertsCard(r.alerts), servicesCard(r.health.services || [])),
        h("div", { class: "split" }, queueCard(r.health.jobs || []), deadCard(r.dead)));
      tick();
    } catch (p) {
      if (view !== state.view) return;
      if (handleAuth(p)) return;
      if (first) put(clear(body), h("div", { class: "card" }, errorState(p, load)));
      else toast(M.problemMessage(p), true);
    } finally { first = false; }
  }
  function tick() {
    if (state.healthAt) updated.textContent = `Live · updated ${M.ago(new Date(state.healthAt).toISOString())}`;
  }
  await load();
  if (view === state.view) state.timers.push(setInterval(load, 15000), setInterval(tick, 1000));
}

// Organizations ------------------------------------------------------------------------

async function viewOrganizations(main, view) {
  const search = h("input", { type: "search", attrs: { "aria-label": "Filter loaded organizations by name or id", placeholder: "Filter by name or id" } });
  const body = h("section", { class: "card" }, skeletonRows(5));
  page(main, h("div", { class: "head" }, heading("Organizations"), h("span", { class: "right searchbar" }, search)), body);
  focusHeading(main);
  const LIMIT = 50;
  let orgs = [];
  let next = null;
  let more = false;
  async function load(after) {
    try {
      const r = await api.get(`/organizations?limit=${LIMIT}${after ? `&after=${after}` : ""}`);
      if (view !== state.view) return;
      const page = r.organizations || [];
      orgs = after ? orgs.concat(page) : page;
      for (const o of page) state.orgNames.set(o.id, o.name);
      next = r.next_after;
      more = page.length === LIMIT && !!next;
      draw();
    } catch (p) {
      if (view !== state.view || handleAuth(p)) return;
      put(clear(body), errorState(p, () => load(after)));
    }
  }
  function draw() {
    const list = M.filterOrgs(orgs, search.value);
    clear(body);
    if (!orgs.length) {
      put(body, emptyState(art.noOrganizations(), "No organizations yet", "Organizations appear here when tenants sign up or are created."));
      return;
    }
    put(body, 
      h("div", { class: "card-h" }, h("b", { text: "All organizations" }), h("span", { class: "sub", text: `${M.count(orgs.length)} loaded` })),
      list.length
        ? h("div", { class: "tbl-wrap" }, h("table", {},
          h("thead", {}, h("tr", {}, h("th", { text: "Name" }), h("th", { text: "Status" }), h("th", { class: "hide-sm", text: "Data regions" }),
            h("th", { class: "num", text: "Workspaces" }), h("th", { class: "num hide-sm", text: "Members" }), h("th", { class: "num hide-sm", text: "Envelopes" }), h("th", { class: "hide-sm", text: "Created" }))),
          h("tbody", {}, list.map((o) => {
            const tr = h("tr", { class: "link" },
              h("td", {}, h("a", { class: "name", href: `#/organizations/${o.id}`, text: o.name })),
              h("td", {}, statusChip(o.status)),
              h("td", { class: "hide-sm" }, regionChips(o.data_regions)),
              h("td", { class: "num", text: M.count(o.counts?.workspaces) }),
              h("td", { class: "num hide-sm", text: M.count(o.counts?.members) }),
              h("td", { class: "num hide-sm", text: M.count(o.counts?.envelopes) }),
              h("td", { class: "hide-sm", text: M.shortDate(o.created_at) }));
            tr.addEventListener("click", (e) => { if (e.target.tagName !== "A") location.hash = `#/organizations/${o.id}`; });
            return tr;
          }))))
        : emptyState(art.noEntries(), "No match among the loaded organizations", more ? "Load more to search further." : "Try another name or id."),
      more ? h("div", { class: "more" }, btn("Load more", "ghost", () => load(next))) : null);
  }
  search.addEventListener("input", draw);
  await load(null);
}

command("renameOrg", (id, name) => api.patch(`/organizations/${id}`, { name }));
command("setRegions", (id, labels) => api.patch(`/organizations/${id}`, { data_regions: labels }));
command("setWorkspace", (id, change) => api.patch(`/workspaces/${id}`, change));
command("requestApproval", (action, organization) => withFactor(() => api.post("/approvals", { action, organization })));
command("grantApproval", (id) => withFactor(() => api.post(`/approvals/${id}/grant`)));
command("applyApproval", (a) => withFactor(() => api.post(`/organizations/${a.organization}/${a.action === "organization.suspend" ? "suspend" : "resume"}`, { approval: a.id })));

async function viewOrganization(main, view, id) {
  const body = h("div", { class: "form" }, h("div", { class: "card" }, skeletonRows(3)));
  const titleSlot = heading("Organization");
  const head = h("div", { class: "head" }, titleSlot);
  page(main, h("a", { class: "crumb", href: "#/organizations", text: "‹ Organizations" }), head, body);
  focusHeading(main);
  const can = M.access(state.roles);
  async function load() {
    try {
      const [o] = await Promise.all([api.get(`/organizations/${id}`), refreshApprovals()]);
      if (view !== state.view) return;
      state.orgNames.set(o.id, o.name);
      draw(o);
    } catch (p) {
      if (view !== state.view || handleAuth(p)) return;
      put(clear(body), h("div", { class: "card" }, errorState(p, load)));
    }
  }
  function draw(o) {
    titleSlot.textContent = o.name;
    put(clear(head), titleSlot, statusChip(o.status),
      can.manage ? h("span", { class: "right" }, btn("Rename", "ghost", () => renamePanel(o))) : null);
    const c = o.counts || {};
    const props = h("section", { class: "card rise", attrs: { "aria-labelledby": "props-h" } },
      h("div", { class: "card-h" }, h("b", { id: "props-h", text: "Properties" })),
      h("div", { class: "card-b" }, h("dl", { class: "kv" },
        h("dt", { text: "Id" }), h("dd", {}, h("code", { text: o.id })),
        h("dt", { text: "Created" }), h("dd", { text: M.shortDate(o.created_at) }),
        h("dt", { text: "Data regions" }), h("dd", {}, h("span", { class: "inline-form" }, regionChips(o.data_regions),
          can.manage ? h("button", { type: "button", class: "linkbtn", text: "Edit labels", on: { click: () => regionsPanel(o) } }) : null)),
        h("dt", { text: "Workspaces" }), h("dd", { text: M.count(c.workspaces) }),
        h("dt", { text: "Members" }), h("dd", { text: M.count(c.members) }),
        h("dt", { text: "Owners" }), h("dd", { text: M.count(c.owners) }),
        h("dt", { text: "Envelopes" }), h("dd", { text: M.count(c.envelopes) }))),
      h("div", { class: "card-f", text: "Region labels are labels only: they do not move or confine data." }));
    const planSlot = h("div", {}, h("section", { class: "card" }, skeletonRows(2)));
    put(clear(body), can.manage ? h("div", { class: "split" }, props, twoPersonCard(o)) : props, planSlot, workspacesCard(o));
    orgPlanCard(planSlot, o, view);
  }
  function renamePanel(o) {
    openPanel("Rename organization", (close) => {
      const name = h("input", { type: "text", value: o.name, attrs: { maxlength: "255", required: true } });
      return form({
        fields: field("Name", name, "1 to 255 characters. Recorded in the operator log by id only."),
        submitText: "Save",
        submit: async () => {
          const r = M.checkName(name.value);
          if (!r.ok) throw r.message;
          await run("renameOrg", o.id, r.value);
          close();
          toast("Organization renamed");
          load();
        },
      });
    });
  }
  function regionsPanel(o) {
    openPanel("Data-region labels", (close) => {
      const input = h("input", { type: "text", value: (o.data_regions || []).join(", "), attrs: { spellcheck: "false" } });
      return form({
        fields: field("Labels", input, "Comma-separated; lower-case letters, digits and hyphens, at most 32 characters each, at most 16. Labels only: no residency is provided."),
        submitText: "Save labels",
        submit: async () => {
          const r = M.parseRegions(input.value);
          if (r.bad.length) throw `Not a label: ${r.bad.join(", ")}`;
          await run("setRegions", o.id, r.labels);
          close();
          toast("Labels saved");
          load();
        },
      });
    });
  }
  function twoPersonCard(o) {
    const action = M.orgAction(o.status);
    const card = h("section", { class: "card rise", attrs: { "aria-labelledby": "tp-h" } },
      h("div", { class: "card-h" }, h("b", { id: "tp-h", text: action === "organization.resume" ? "Resume" : "Suspend" }), h("span", { class: "sub", text: "two-person action" })));
    const b = h("div", { class: "card-b form" });
    put(card, b);
    if (!action) {
      put(b, h("p", { class: "d", text: "A closed organization cannot be suspended or resumed." }));
      return card;
    }
    const verb = action === "organization.suspend" ? "suspension" : "resumption";
    const mine = M.myRequest(state.approvals, o.id, action, state.me);
    put(b, h("p", { class: "d", text: action === "organization.suspend"
      ? "Suspending refuses new work in the organization; envelopes already sent continue. You request it, a second operator approves it, then you apply it."
      : "Resuming lets the organization start new work again. You request it, a second operator approves it, then you apply it." }));
    if (!mine) {
      put(b, h("div", { class: "acts form" }, h("div", { class: "acts" },
        btn(`Request ${verb}`, action === "organization.suspend" ? "danger" : "ghost", async (e) => {
          const t = e.currentTarget;
          t.disabled = true;
          try { await run("requestApproval", action, o.id); toast("Request sent: a second operator must approve it"); load(); }
          catch (p) { if (!p?.cancelled && !handleAuth(p)) toast(M.problemMessage(p), true); }
          finally { t.disabled = false; }
        }), factorNote())));
    } else if (mine.state === "waiting") {
      put(b, h("div", { class: "alert-box warn", attrs: { role: "status" } },
        h("span", { text: `Requested ${M.ago(mine.approval.created_at)}. Waiting for a second operator to approve it in Approvals; the request lapses ${M.until(mine.approval.expires_at)}.` })));
    } else {
      put(b, h("div", { class: "alert-box ok", attrs: { role: "status" } }, h("span", { text: "Approved by a second operator. You can apply it now." })),
        h("div", { class: "acts" },
          btn(`Apply ${verb}`, action === "organization.suspend" ? "danger" : "primary", async (e) => {
            const t = e.currentTarget;
            t.disabled = true;
            try { await run("applyApproval", mine.approval); toast(action === "organization.suspend" ? "Organization suspended" : "Organization resumed"); load(); }
            catch (p) { if (!p?.cancelled && !handleAuth(p)) toast(M.problemMessage(p), true); }
            finally { t.disabled = false; }
          }), factorNote()));
    }
    return card;
  }
  function workspacesCard(o) {
    const ws = o.workspaces || [];
    return h("section", { class: "card rise", attrs: { "aria-labelledby": "ws-h" } },
      h("div", { class: "card-h" }, h("b", { id: "ws-h", text: "Workspaces" }), h("span", { class: "sub", text: M.plural(ws.length, "workspace") })),
      ws.length
        ? h("div", { class: "tbl-wrap" }, h("table", {},
          h("thead", {}, h("tr", {}, h("th", { text: "Name" }), h("th", { text: "Status" }), h("th", { class: "hide-sm", text: "Region" }),
            h("th", { class: "num", text: "Members" }), h("th", { class: "num hide-sm", text: "Templates" }), h("th", { class: "num hide-sm", text: "Drafts" }),
            h("th", { class: "num hide-sm", text: "In progress" }), h("th", { class: "num", text: "Completed" }), can.manage ? h("th", { text: "", attrs: { "aria-label": "Actions" } }) : null)),
          h("tbody", {}, ws.map((w) => h("tr", {},
            h("td", { text: w.name }), h("td", {}, statusChip(w.status)),
            h("td", { class: "hide-sm" }, w.data_region ? h("span", { class: "chip region", text: w.data_region }) : h("span", { class: "w", text: "–" })),
            h("td", { class: "num", text: M.count(w.counts?.members) }), h("td", { class: "num hide-sm", text: M.count(w.counts?.templates) }),
            h("td", { class: "num hide-sm", text: M.count(w.counts?.envelopes_draft) }), h("td", { class: "num hide-sm", text: M.count(w.counts?.envelopes_in_progress) }),
            h("td", { class: "num", text: M.count(w.counts?.envelopes_completed) }),
            can.manage ? h("td", { class: "num" }, btn("Edit", "ghost", () => workspacePanel(o, w), { "aria-label": `Edit workspace ${w.name}` })) : null)))))
        : emptyState(art.noEntries(), "No workspaces", null));
  }
  function workspacePanel(o, w) {
    openPanel(`Workspace: ${w.name}`, (close) => {
      const sel = h("select", {}, h("option", { value: "", text: "No label" }),
        (o.data_regions || []).map((l) => h("option", { value: l, text: l, selected: l === w.data_region })));
      const archived = w.status === "archived";
      return h("div", { class: "form" },
        form({
          fields: field("Data-region label", sel, o.data_regions?.length ? "One of the organization's labels." : "The organization has no labels yet: add them on the organization first."),
          submitText: "Save label",
          primary: false,
          submit: async () => {
            await run("setWorkspace", w.id, { data_region: sel.value || null });
            close(); toast("Workspace label saved"); load();
          },
        }),
        h("div", { class: "alert-box" + (archived ? "" : " warn") },
          h("span", { text: archived ? "Archived: it refuses new envelopes, members and settings. Restoring lets it work again." : "Archiving refuses new envelopes, members and settings; envelopes already sent continue." })),
        h("div", { class: "acts" }, btn(archived ? "Restore workspace" : "Archive workspace", archived ? "ghost" : "danger", async (e) => {
          const t = e.currentTarget;
          t.disabled = true;
          try { await run("setWorkspace", w.id, { status: archived ? "active" : "archived" }); close(); toast(archived ? "Workspace restored" : "Workspace archived"); load(); }
          catch (p) { if (!handleAuth(p)) toast(M.problemMessage(p), true); }
          finally { t.disabled = false; }
        })));
    });
  }
  await load();
}

// Plans (PLAN-02; docs/23 §7.1, §10) --------------------------------------------------

command("createPlan", (body) => api.post("/plans", body));
command("archivePlan", (id) => api.post(`/plans/${id}/archive`));
command("assignPlan", (org, body) => api.post(`/organizations/${org}/plan`, body));
command("setOverride", (org, body) => api.post(`/organizations/${org}/plan-overrides`, body));
command("expireOverride", (id) => api.post(`/plan-overrides/${id}/expire`));

function select(options, value) {
  return h("select", {}, options.map(([v, label]) => h("option", { value: v, text: label, selected: v === value })));
}

function featureChips(entitlements) {
  const on = Object.entries(entitlements || {}).filter(([, v]) => v).map(([f]) => f);
  if (!on.length) return h("span", { class: "w", text: "No features" });
  return h("span", { class: "chips" }, on.map((f) => chip(M.featureLabel(f))));
}

function quotaTable(quotas) {
  if (!quotas?.length) return h("p", { class: "d", text: "No quotas: nothing is limited." });
  return h("div", { class: "tbl-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, h("th", { text: "Meter" }), h("th", { class: "num", text: "Limit" }), h("th", { text: "Period" }),
      h("th", { text: "Enforcement" }), h("th", { text: "Level" }))),
    h("tbody", {}, quotas.map((q) => h("tr", {},
      h("td", { text: M.meterLabel(q.meter) }), h("td", { class: "num", text: M.count(q.limit) }),
      h("td", { text: q.period === "none" ? "–" : q.period }),
      h("td", {}, chip(q.enforcement, q.enforcement === "hard" ? "bad" : q.enforcement === "soft" ? "warn" : "")),
      h("td", { text: q.level }))))));
}

async function viewPlans(main, view) {
  const can = M.access(state.roles);
  const title = heading("Plans");
  const head = h("div", { class: "head" }, title);
  const body = h("div", { class: "form" }, h("section", { class: "card" }, skeletonRows(4)));
  page(main, head, body);
  focusHeading(main);
  let catalogue = null;
  async function load() {
    try {
      const r = await api.get("/plans");
      if (view !== state.view) return;
      catalogue = r.catalogue || {};
      draw(r.plans || []);
    } catch (p) {
      if (view !== state.view || handleAuth(p)) return;
      put(clear(body), h("div", { class: "card" }, errorState(p, load)));
    }
  }
  function draw(plans) {
    put(clear(head), title, can.manage ? h("span", { class: "right" }, btn("New plan", "primary", () => planPanel(null))) : null);
    clear(body);
    const groups = M.planGroups(plans);
    if (!groups.length) {
      put(body, h("section", { class: "card" }, emptyState(art.noEntries(), "No plans yet",
        "A plan sets the features and quotas an organization has. Versions are immutable: changing a plan makes a new version.",
        can.manage ? btn("New plan", "primary", () => planPanel(null)) : null)));
      return;
    }
    for (const g of groups) put(body, planCard(g));
  }
  function planCard(g) {
    const p = g.current || g.latest;
    return h("section", { class: "card rise", attrs: { "aria-label": `Plan ${p.name}` } },
      h("div", { class: "card-h" }, h("b", { text: p.name }), h("span", { class: "sub" }, h("code", { text: g.key }), ` · version ${p.version}`),
        g.current ? null : chip("Archived"),
        can.manage ? h("span", { class: "right" }, btn("New version", "ghost", () => planPanel(p), { "aria-label": `New version of ${p.name}` })) : null),
      h("div", { class: "card-b form" },
        h("dl", { class: "kv" },
          h("dt", { text: "Features" }), h("dd", {}, featureChips(p.entitlements)),
          h("dt", { text: "Seats count" }), h("dd", { text: M.seatRuleLabel(p.seat_rule) })),
        quotaTable(p.quotas)),
      h("div", { class: "tbl-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, h("th", { text: "Version" }), h("th", { class: "num", text: "Organizations" }),
          h("th", { class: "hide-sm", text: "Created" }), h("th", { text: "Status" }), can.manage ? h("th", { text: "", attrs: { "aria-label": "Actions" } }) : null)),
        h("tbody", {}, g.versions.map((v) => h("tr", {},
          h("td", { text: `${v.version}` }), h("td", { class: "num", text: M.count(v.organizations) }),
          h("td", { class: "hide-sm", text: M.shortDate(v.created_at) }),
          h("td", {}, v.archived ? chip("Archived") : chip("Available", "ok")),
          can.manage ? h("td", { class: "num" }, v.archived ? null : btn("Archive", "ghost", (e) => archive(e, v), { "aria-label": `Archive ${v.name} version ${v.version}` })) : null))))),
      h("div", { class: "card-f", text: "Archiving stops new assignments; organizations already on a version keep it." }));
  }
  async function archive(e, v) {
    const t = e.currentTarget;
    t.disabled = true;
    try { await run("archivePlan", v.id); toast(`${v.name} version ${v.version} archived`); load(); }
    catch (p) { if (!handleAuth(p)) toast(M.problemMessage(p), true); }
    finally { t.disabled = false; }
  }
  function planPanel(from) {
    openPanel(from ? `New version of ${from.name}` : "New plan", (close) => {
      const key = h("input", { type: "text", value: from?.key || "", attrs: { maxlength: "64", spellcheck: "false", required: true, readonly: from ? true : null } });
      const name = h("input", { type: "text", value: from?.name || "", attrs: { maxlength: "120", required: true } });
      const seat = select((catalogue.seat_rules || ["can_send", "every_member"]).map((r) => [r, M.seatRuleLabel(r)]), from?.seat_rule || "can_send");
      const boxes = (catalogue.features || []).map((f) => h("input", { type: "checkbox", value: f, checked: !!from?.entitlements?.[f] }));
      const features = h("fieldset", { class: "field checks" }, h("legend", { class: "label", text: "Features" }),
        boxes.map((b) => h("label", {}, b, M.featureLabel(b.value))));
      const rows = h("div", { class: "form" });
      const meters = catalogue.meters || [];
      function quotaRow(q = {}) {
        const meter = select(meters.map((m) => [m.name, M.meterLabel(m.name)]), q.meter || meters[0]?.name);
        const limit = h("input", { type: "text", value: q.limit != null ? String(q.limit) : "", attrs: { inputmode: "numeric", "aria-label": "Limit", placeholder: "Limit" } });
        const period = select((catalogue.periods || []).map((x) => [x, x]), q.period || "month");
        const enforcement = select((catalogue.enforcements || []).map((x) => [x, x]), q.enforcement || "hard");
        const level = select((catalogue.levels || []).map((x) => [x, x]), q.level || "organization");
        for (const [el, label] of [[meter, "Meter"], [period, "Period"], [enforcement, "Enforcement"], [level, "Level"]]) el.setAttribute("aria-label", label);
        const row = h("div", { class: "inline-form quota-row" }, meter, limit, period, enforcement, level);
        row.read = () => ({ meter: meter.value, limit: limit.value, period: period.value, enforcement: enforcement.value, level: level.value });
        put(row, h("button", { type: "button", class: "linkbtn", text: "Remove", on: { click: () => row.remove() } }));
        rows.appendChild(row);
      }
      for (const q of from?.quotas || []) quotaRow(q);
      return form({
        fields: [
          field("Key", key, from ? "A new version keeps the key." : "Lower-case letters, digits, - and _; it names the plan across versions."),
          field("Name", name, "1 to 120 characters, shown to operators."),
          field("Seats count", seat, "Which members of an organization use a seat."),
          features,
          h("div", { class: "field" }, h("span", { class: "label", text: "Quotas" }),
            h("span", { class: "hint", text: "Counts that exist now (seats, storage, workspaces, templates) take period none. API calls are counted approximately and cannot be hard." }),
            rows, h("div", {}, btn("Add quota", "ghost", () => quotaRow()))),
        ],
        submitText: from ? "Create version" : "Create plan",
        submit: async () => {
          const r = M.checkPlan({
            key: key.value, name: name.value, seatRule: seat.value,
            features: boxes.filter((b) => b.checked).map((b) => b.value),
            quotas: [...rows.querySelectorAll(".quota-row")].map((x) => x.read()),
          }, meters);
          if (!r.ok) throw r.message;
          const res = await run("createPlan", r.value);
          close();
          toast(`${r.value.name} version ${res.version} created`);
          load();
        },
      });
    });
  }
  await load();
}

/// The plan card on an organization: effective plan now, assignments, overrides.
async function orgPlanCard(slot, o, view) {
  const can = M.access(state.roles);
  let r;
  let catalogue = null;
  let plans = [];
  try {
    [r] = await Promise.all([
      api.get(`/organizations/${o.id}/plan`),
      can.manage ? api.get("/plans").then((x) => { catalogue = x.catalogue || {}; plans = x.plans || []; }) : null,
    ]);
  } catch (p) {
    if (view !== state.view || handleAuth(p)) return;
    put(clear(slot), h("section", { class: "card" }, errorState(p, () => orgPlanCard(slot, o, view))));
    return;
  }
  if (view !== state.view) return;
  const reload = () => orgPlanCard(slot, o, view);
  const e = r.effective;
  const wsName = (id) => (o.workspaces || []).find((w) => w.id === id)?.name || M.shortId(id);
  const card = h("section", { class: "card rise", attrs: { "aria-labelledby": "plan-h" } },
    h("div", { class: "card-h" }, h("b", { id: "plan-h", text: "Plan" }),
      h("span", { class: "sub", text: e ? `${e.name} · version ${e.version}` : "No plan assigned" }),
      can.manage ? h("span", { class: "right" },
        btn("Assign plan", "ghost", () => assignPanel()),
        e ? btn("Add override", "ghost", () => overridePanel()) : null) : null));
  const b = h("div", { class: "card-b form" });
  put(card, b);
  if (e) {
    put(b, h("dl", { class: "kv" },
      h("dt", { text: "Since" }), h("dd", { text: M.shortDate(e.starts_at) }),
      h("dt", { text: "Until" }), h("dd", { text: e.ends_at ? M.shortDate(e.ends_at) : "Open-ended" }),
      h("dt", { text: "Features" }), h("dd", {}, featureChips(e.entitlements)),
      h("dt", { text: "Seats count" }), h("dd", { text: M.seatRuleLabel(e.seat_rule) })),
    quotaTable(e.quotas),
    e.applied?.length ? h("p", { class: "d", text: `Includes ${M.plural(e.applied.length, "organization override")}. Workspace overrides apply in their workspace only.` }) : null);
  } else {
    put(b, h("p", { class: "d", text: "No plan is current for this organization now." }));
  }
  const assignments = r.assignments || [];
  if (assignments.length) {
    put(b, h("div", { class: "tbl-wrap" }, h("table", { attrs: { "aria-label": "Assignments" } },
      h("thead", {}, h("tr", {}, h("th", { text: "Plan" }), h("th", { text: "From" }), h("th", { text: "Until" }), h("th", { text: "" }))),
      h("tbody", {}, assignments.map((a) => h("tr", {},
        h("td", { text: `${a.plan.name} · v${a.plan.version}` }), h("td", { text: M.shortDate(a.starts_at) }),
        h("td", { text: a.ends_at ? M.shortDate(a.ends_at) : "Open-ended" }),
        h("td", {}, a.current ? chip("Current", "ok") : null)))))));
  }
  const overrides = r.overrides || [];
  if (overrides.length) {
    put(b, h("div", { class: "tbl-wrap" }, h("table", { attrs: { "aria-label": "Overrides" } },
      h("thead", {}, h("tr", {}, h("th", { text: "Override" }), h("th", { text: "Value" }), h("th", { class: "hide-sm", text: "Scope" }),
        h("th", { class: "hide-sm", text: "Reason" }), h("th", { text: "Expires" }), h("th", { text: "" }))),
      h("tbody", {}, overrides.map((v) => h("tr", {},
        h("td", { text: M.overrideKeyLabel(v.key) }), h("td", { text: M.overrideValueLabel(v.key, v.value) }),
        h("td", { class: "hide-sm", text: v.workspace ? `Workspace ${wsName(v.workspace)}` : "Organization" }),
        h("td", { class: "hide-sm", text: v.reason }),
        h("td", { text: !v.live ? "Expired" : v.expires_at ? M.until(v.expires_at) : "Never" }),
        h("td", { class: "num" },
          v.applied ? chip("Applied", "ok") : v.live && v.workspace ? chip("In workspace") : v.live ? chip("Not applied", "warn") : null,
          can.manage && v.live ? btn("Expire", "ghost", (ev) => expire(ev, v), { "aria-label": `Expire override ${M.overrideKeyLabel(v.key)}` }) : null)))))));
  }
  put(clear(slot), card);

  async function expire(ev, v) {
    const t = ev.currentTarget;
    t.disabled = true;
    try { await run("expireOverride", v.id); toast("Override expired"); reload(); }
    catch (p) { if (!handleAuth(p)) toast(M.problemMessage(p), true); }
    finally { t.disabled = false; }
  }
  function assignPanel() {
    openPanel("Assign a plan", (close) => {
      const open = plans.filter((p) => !p.archived).sort((a, b) => a.name.localeCompare(b.name) || b.version - a.version);
      if (!open.length) return h("div", { class: "form" }, h("p", { class: "d", text: "No plan versions are available. Create one under Plans first." }),
        h("a", { class: "btn", href: "#/plans", text: "Go to Plans" }));
      const plan = select(open.map((p) => [p.id, `${p.name} · version ${p.version} (${p.key})`]), e ? open.find((p) => p.key === e.key)?.id : open[0].id);
      const starts = h("input", { type: "datetime-local" });
      const ends = h("input", { type: "datetime-local" });
      return form({
        fields: [
          field("Plan version", plan),
          field("Starts", starts, "Empty for now. The current assignment ends at this instant."),
          field("Ends", ends, "Empty for open-ended."),
        ],
        submitText: "Assign",
        submit: async () => {
          const s = M.localToIso(starts.value);
          const en = M.localToIso(ends.value);
          if (s === undefined || en === undefined) throw "Enter a valid date and time.";
          const body = { plan: plan.value };
          if (s) body.starts_at = s;
          if (en) body.ends_at = en;
          await run("assignPlan", o.id, body);
          close();
          toast("Plan assigned");
          reload();
        },
      });
    });
  }
  function overridePanel() {
    openPanel("Add an override", (close) => {
      const workspaces = (o.workspaces || []).filter((w) => w.status !== "archived");
      const scope = select([["", "Whole organization"], ...workspaces.map((w) => [w.id, `Workspace: ${w.name}`])], "");
      const keySel = h("select", {});
      const valueSlot = h("div", {});
      const reason = h("input", { type: "text", attrs: { maxlength: "200", required: true } });
      const expires = h("input", { type: "datetime-local" });
      let keys = [];
      let valueInput = null;
      function fillKeys() {
        keys = M.overrideKeys(catalogue, e, !!scope.value);
        clear(keySel);
        put(keySel, keys.length ? keys.map((k) => h("option", { value: k.key, text: k.label })) : h("option", { value: "", text: "Nothing a workspace can override" }));
        fillValue();
      }
      function fillValue() {
        const k = keys.find((x) => x.key === keySel.value);
        if (!k) { valueInput = null; clear(valueSlot); return; }
        if (k.kind === "flag") valueInput = select([["true", "On"], ["false", "Off"]], "true");
        else if (k.kind === "enforcement") valueInput = select(["hard", "soft", "notify"].filter((x) => !(x === "hard" && k.approximate)).map((x) => [x, x]), k.approximate ? "soft" : "hard");
        else if (k.kind === "seat_rule") valueInput = select((catalogue.seat_rules || []).map((x) => [x, M.seatRuleLabel(x)]), "can_send");
        else valueInput = h("input", { type: "text", attrs: { inputmode: "numeric" } });
        put(clear(valueSlot), field("Value", valueInput, k.kind === "limit" ? "A whole number." : null));
      }
      scope.addEventListener("change", fillKeys);
      keySel.addEventListener("change", fillValue);
      fillKeys();
      return form({
        fields: [
          field("Scope", scope, "A workspace override may change only a workspace-level quota."),
          field("Override", keySel),
          valueSlot,
          field("Reason", reason, "1 to 200 characters, kept in the console; never in the operator log."),
          field("Expires", expires, "Empty for never. It stops applying at this instant."),
        ],
        submitText: "Add override",
        submit: async () => {
          const k = keys.find((x) => x.key === keySel.value);
          if (!k || !valueInput) throw "Choose what to override.";
          const v = M.checkOverrideValue(k.kind, valueInput.value, k.approximate);
          if (!v.ok) throw v.message;
          const why = reason.value.trim();
          if (!why || [...why].length > 200) throw "Give a reason of 1 to 200 characters.";
          const ex = M.localToIso(expires.value);
          if (ex === undefined) throw "Enter a valid date and time.";
          const body = { key: k.key, value: v.value, reason: why };
          if (scope.value) body.workspace = scope.value;
          if (ex) body.expires_at = ex;
          await run("setOverride", o.id, body);
          close();
          toast("Override added");
          reload();
        },
      });
    });
  }
}

// Approvals ----------------------------------------------------------------------------

async function orgName(id) {
  if (state.orgNames.has(id)) return state.orgNames.get(id);
  try {
    const o = await api.get(`/organizations/${id}`);
    state.orgNames.set(id, o.name);
    return o.name;
  } catch { return null; }
}

const APPROVAL_TEXT = {
  grantable: ["Waiting for your approval", "warn"],
  waiting: ["Waiting for a second operator", ""],
  ready: ["Approved: apply it", "ok"],
  granted: ["Approved, waiting for the requester", ""],
  applied: ["Applied", "ok"],
  expired: ["Expired", ""],
};

async function viewApprovals(main, view) {
  const body = h("section", { class: "card" }, skeletonRows(3));
  page(main, h("div", { class: "head" }, heading("Approvals"), h("span", { class: "right" }, factorNote("Approving needs a code from your authenticator app"))), body);
  focusHeading(main);
  async function load() {
    try {
      const r = await api.get("/approvals");
      state.approvals = r.approvals || [];
      await Promise.all([...new Set(state.approvals.map((a) => a.organization))].map(orgName));
      if (view !== state.view) return;
      draw();
    } catch (p) {
      if (view !== state.view || handleAuth(p)) return;
      put(clear(body), errorState(p, load));
    }
  }
  function draw() {
    put(clear(body), h("div", { class: "card-h" }, h("b", { text: "Two-person requests" }), h("span", { class: "sub", text: "the last 24 hours, newest first" })));
    if (!state.approvals.length) {
      put(body, emptyState(art.noApprovals(), "No requests in the last 24 hours", "Suspending or resuming an organization starts with a request here, which a second operator approves."));
      return;
    }
    for (const a of state.approvals) {
      const st = M.approvalState(a, state.me);
      const [label, tone] = APPROVAL_TEXT[st];
      const name = state.orgNames.get(a.organization);
      const acts = h("div", { class: "acts" });
      if (st === "grantable") {
        put(acts, btn("Approve", "primary", async (e) => {
          const t = e.currentTarget;
          t.disabled = true;
          try { await run("grantApproval", a.id); toast("Approved: the requester can now apply it"); await load(); }
          catch (p) { if (!p?.cancelled && !handleAuth(p)) toast(M.problemMessage(p), true); }
          finally { t.disabled = false; }
        }, { "aria-label": `Approve: ${M.actionLabel(a.action)} ${name || a.organization}` }));
      } else if (st === "ready") {
        put(acts, h("a", { class: "btn", href: `#/organizations/${a.organization}`, text: "Open to apply" }));
      } else put(acts, chip(label, tone));
      put(body, h("div", { class: `row${st === "applied" || st === "expired" ? " done" : ""}` },
        h("span", { class: `bullet tone-${st === "grantable" ? "warn" : st === "ready" || st === "applied" ? "ok" : "ok"}` }),
        h("div", { class: "main" },
          h("b", {}, `${M.actionLabel(a.action)}: `, h("a", { class: "name", href: `#/organizations/${a.organization}`, text: name || M.shortId(a.organization) })),
          h("span", { class: "d", text: `Requested by ${a.requester === state.me ? "you" : `operator ${M.shortId(a.requester)}`} · ${M.plural((a.approvers || []).length, "approval")}` }),
          h("span", { class: "w", text: `${M.ago(a.created_at)} · ${a.used ? "spent" : `lapses ${M.until(a.expires_at)}`}` })),
        acts));
    }
  }
  await load();
}

// Operators ----------------------------------------------------------------------------

command("createOperator", (email, roles) => api.post("/operators", { email, roles }));
command("disableOperator", (id) => api.post(`/operators/${id}/disable`));

async function viewOperators(main, view) {
  const body = h("section", { class: "card" }, skeletonRows(3));
  page(main, h("div", { class: "head" }, heading("Operators"), h("span", { class: "right" }, btn("Add operator", "primary", () => addPanel()))), body);
  focusHeading(main);
  async function load() {
    try {
      const r = await api.get("/operators");
      if (view !== state.view) return;
      draw(r.operators || []);
    } catch (p) {
      if (view !== state.view || handleAuth(p)) return;
      put(clear(body), errorState(p, load));
    }
  }
  function draw(list) {
    put(clear(body), 
      h("div", { class: "card-h" }, h("b", { text: "Operators" }), h("span", { class: "sub", text: "their sign-in e-mail is shown to platform owners only" })),
      h("div", { class: "tbl-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, h("th", { text: "E-mail" }), h("th", { text: "Roles" }), h("th", { class: "hide-sm", text: "Added" }), h("th", { text: "Status" }), h("th", { text: "", attrs: { "aria-label": "Actions" } }))),
        h("tbody", {}, list.map((o) => h("tr", {},
          h("td", {}, h("span", { text: o.email }), o.id === state.me ? h("span", { class: "chip", text: "You" }) : null),
          h("td", {}, h("span", { class: "chips" }, (o.roles || []).map((r) => chip(M.roleLabel(r))))),
          h("td", { class: "hide-sm", text: M.shortDate(o.created_at) }),
          h("td", {}, o.disabled_at ? chip("Disabled", "bad") : chip("Active", "ok")),
          h("td", { class: "num" }, !o.disabled_at && o.id !== state.me ? btn("Disable", "danger", () => disablePanel(o), { "aria-label": `Disable ${o.email}` }) : null)))))));
  }
  function addPanel() {
    openPanel("Add operator", (close) => {
      const email = h("input", { type: "email", attrs: { autocomplete: "off", maxlength: "254", required: true } });
      const boxes = ["operator", "key_custodian", "observer"].map((r) => h("input", { type: "checkbox", value: r, checked: r === "operator" }));
      const roles = h("fieldset", { class: "field checks" }, h("legend", { class: "label", text: "Roles" }),
        boxes.map((b) => h("label", {}, b, M.roleLabel(b.value))),
        h("span", { class: "hint", text: "Adding a platform owner needs a second operator's approval, which the console does not offer yet." }));
      return form({
        fields: [field("E-mail", email, "Their sign-in name. They set their own password and authenticator through a one-time link."), roles],
        submitText: "Create and get enrolment link",
        submit: async () => {
          const chosen = boxes.filter((b) => b.checked).map((b) => b.value);
          if (!email.value.includes("@")) throw "Enter an e-mail address.";
          if (!chosen.length) throw "Choose at least one role.";
          const r = await run("createOperator", email.value.trim(), chosen);
          close();
          tokenPanel(r);
          load();
        },
      });
    });
  }
  function tokenPanel(r) {
    const link = `${location.origin}/#/enrol/${r.enrolment_token}`;
    openPanel("Enrolment link", () => h("div", { class: "form" },
      h("div", { class: "alert-box warn", attrs: { role: "status" } }, h("span", { text: `Shown once. Pass it to the new operator over a channel you trust; it works once and lapses ${M.until(r.enrolment_expires_at)}.` })),
      h("div", { class: "field" }, h("span", { class: "label", text: "Link" }), h("div", { class: "secret", text: link })),
      h("div", { class: "acts" }, btn("Copy link", "primary", () => copy(link, "Link"))),
      h("div", { class: "field" }, h("span", { class: "label", text: "Token only" }), h("div", { class: "secret", text: r.enrolment_token })),
      h("div", { class: "acts" }, btn("Copy token", "ghost", () => copy(r.enrolment_token, "Token")))));
  }
  function disablePanel(o) {
    openPanel("Disable operator", (close) => form({
      fields: h("p", { class: "d", text: `${o.email} will be signed out at once and cannot sign in again. This is recorded in the operator log.` }),
      submitText: "Disable operator",
      danger: true,
      submit: async () => {
        await run("disableOperator", o.id);
        close();
        toast("Operator disabled");
        load();
      },
    }));
  }
  await load();
}

// Operator log -------------------------------------------------------------------------

command("verifyLog", () => api.get("/operator-log/verify"));

async function viewLog(main, view) {
  const result = h("div", { attrs: { "aria-live": "polite" } });
  const verify = btn("Verify chain", "primary", async () => {
    verify.disabled = true;
    clear(result);
    try {
      const r = await run("verifyLog");
      put(result, h("div", { class: "alert-box ok rise" }, h("span", { text: `Verified: ${M.plural(r.events, "event")}, every hash and link recomputed.` }), r.head ? h("code", { text: `head ${r.head.slice(0, 16)}…`, attrs: { title: r.head } }) : null));
    } catch (p) {
      if (handleAuth(p)) return;
      put(result, h("div", { class: "alert-box bad rise", attrs: { role: "alert" } }, h("span", { text: p.code === "CS-CON-0007" ? "The operator log does not verify: an event was changed or removed. Changes are refused until it is repaired." : M.problemMessage(p) })));
    } finally { verify.disabled = false; }
  });
  const body = h("section", { class: "card" }, skeletonRows(5));
  page(main, h("div", { class: "head" }, heading("Operator log"), h("span", { class: "right" }, verify)), result, body);
  focusHeading(main);
  const LIMIT = 100;
  let events = [];
  let more = false;
  let next = null;
  async function load(after) {
    try {
      const r = await api.get(`/operator-log?limit=${LIMIT}${after != null ? `&after=${after}` : ""}`);
      if (view !== state.view) return;
      const page = r.events || [];
      events = after != null ? events.concat(page) : page;
      next = r.next_after;
      more = page.length === LIMIT && next != null;
      draw();
    } catch (p) {
      if (view !== state.view || handleAuth(p)) return;
      put(clear(body), errorState(p, () => load(after)));
    }
  }
  function draw() {
    put(clear(body), h("div", { class: "card-h" }, h("b", { text: "Events" }), h("span", { class: "sub", text: "oldest first; hash-chained, append-only" })));
    if (!events.length) { put(body, emptyState(art.noEntries(), "No events yet", "Every operator action is recorded here.")); return; }
    put(body, h("div", { class: "tbl-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", { class: "num", text: "Seq" }), h("th", { text: "Time" }), h("th", { text: "Action" }), h("th", { class: "hide-sm", text: "Operator" }), h("th", { class: "hide-sm", text: "Details" }), h("th", { class: "hide-sm", text: "Hash" }))),
      h("tbody", {}, events.map((e) => h("tr", {},
        h("td", { class: "num mono", text: String(e.seq) }),
        h("td", { text: M.shortDate(e.at) }),
        h("td", {}, h("span", { text: M.eventLabel(e.action), attrs: { title: e.action } })),
        h("td", { class: "hide-sm" }, e.operator ? h("code", { text: e.operator === state.me ? "you" : M.shortId(e.operator), attrs: { title: e.operator } }) : h("span", { class: "w", text: "host" })),
        h("td", { class: "hide-sm" }, h("span", { class: "chips" }, M.eventDetails(e).map(([k, v]) => h("span", { class: "chip region", text: `${k}: ${/^[0-9a-f-]{36}$/.test(v) ? M.shortId(v) : v}`, attrs: { title: `${k}: ${v}` } })))),
        h("td", { class: "hide-sm" }, h("code", { text: e.hash.slice(0, 10), attrs: { title: e.hash } }))))))),
    more ? h("div", { class: "more" }, btn("Load more", "ghost", () => load(next))) : null);
  }
  await load(null);
}

// Routing ------------------------------------------------------------------------------

/// A session that ended or lost its factor mid-use returns to sign-in; true when handled.
function handleAuth(p) {
  if (p?.code === "CS-CON-0001" || p?.code === "CS-CON-0013") {
    state.me = null;
    api.setCsrf(null);
    showSignIn(M.problemMessage(p));
    return true;
  }
  if (p?.code === "CS-CON-0002" && !p.cancelled) {
    showTotp();
    return true;
  }
  return false;
}

function parseHash() {
  const parts = location.hash.replace(/^#\/?/, "").split("/").filter(Boolean);
  return { name: parts[0] || "health", arg: parts[1] ? decodeURIComponent(parts[1]) : null };
}

function route() {
  if (panelClose) panelClose();
  const { name, arg } = parseHash();
  if (name === "enrol") { showEnrol(arg); return; }
  if (!state.me) { boot(); return; }
  const can = M.access(state.roles);
  const view = ++state.view;
  const screens = {
    health: () => viewHealth(shell("health"), view),
    organizations: () => (arg ? viewOrganization(shell("organizations"), view, arg) : viewOrganizations(shell("organizations"), view)),
    approvals: () => viewApprovals(shell("approvals"), view),
    plans: () => viewPlans(shell("plans"), view),
    operators: () => viewOperators(shell("operators"), view),
    log: () => viewLog(shell("log"), view),
  };
  if (!screens[name] || !can[name === "log" ? "log" : name]) {
    location.hash = "#/health";
    return;
  }
  document.title = `${NAV.find(([k]) => k === name)?.[1] || "Console"} · OpenSeal console`;
  screens[name]();
}

async function boot() {
  const { name, arg } = parseHash();
  if (name === "enrol") { showEnrol(arg); return; }
  try {
    const me = await api.get("/me");
    state.me = me.operator;
    state.roles = me.roles || [];
    if (!api.hasCsrf()) {
      // A session from another tab: this page cannot change anything without its token.
      state.me = null;
      showSignIn("Sign in again in this tab to make changes.");
      return;
    }
    await enterApp();
  } catch (p) {
    if (p?.code === "CS-CON-0002" && api.hasCsrf()) showTotp();
    else if (p?.network) {
      authShell(h("h1", { text: "The console cannot be reached" }), h("p", { text: M.problemMessage(p) }), btn("Try again", "primary big wide", boot));
    } else showSignIn();
  }
}

addEventListener("hashchange", route);
boot();
