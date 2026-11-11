// The sender app's shell (WEB-01): session, top bar, navigation, theme, routing,
// shortcuts. Screens are modules with `mount(container, ctx, params) → cleanup`.
//
// Routes (hash, so a static server needs no rewrites):
//   #/signin  #/home  #/agreements[?status=…]  #/envelopes/{id}  #/prepare  #/prepare/{id}
//   #/templates  #/templates/new  #/templates/{id}  #/admin[?tab=api]   (WEB-02)
// Verify is its own page, verify.html, usable without an account.

import { h, clear, isTyping, initials } from "./dom.js";
import { icon } from "./icons.js";
import { t, applyI18n } from "./i18n.js";
import { createClient, isMockMode, isNoServer, ApiError, errorMessage } from "./api.js";
import { extend } from "./api-extra.js";
import { register, run, command } from "./commands.js";
import { handle, bindings } from "./keys.js";
import { openPanel, toast, errorState, noServerState, menuButton, avatar } from "./ui/index.js";
import { initTheme, setTheme, getTheme, toggleTheme } from "./theme.js";

const mock = isMockMode();
let api;
if (mock) {
  const { createMockFetch } = await import("./mock.js");
  api = createClient({ fetch: createMockFetch({ store: safeSession() }), store: safeSession() });
} else {
  const base = document.querySelector('meta[name="openseal-api-base"]')?.content || "";
  api = createClient({ baseUrl: base, store: safeSession() });
}
extend(api);

function safeSession() {
  try { return globalThis.sessionStorage; } catch { return null; }
}

const ctx = {
  api,
  mock,
  session: null,
  /// Go to a route, keeping `?mock=1` in the page URL (it lives in the search part).
  navigate(hash) { if (location.hash !== hash) location.hash = hash; else route(); },
  contexts: ["global"],
  /// Handle an API error from a screen: a lost session goes to sign-in.
  failed(err) {
    if (err instanceof ApiError && (err.code === "CS-AUTH-0001" || err.code === "CS-AUTH-0002")) {
      ctx.session = null;
      toast(errorMessage(err), "error");
      ctx.navigate("#/signin");
      return true;
    }
    return false;
  },
};

const ROUTES = [
  [/^#\/signin$/, () => import("./signin.js"), { chrome: false }],
  [/^#\/home$/, () => import("./home.js"), { nav: "home" }],
  [/^#\/agreements(?:\?.*)?$/, () => import("./dashboard.js"), { nav: "agreements" }],
  [/^#\/envelopes\/([^/?]+)$/, () => import("./envelope.js"), { nav: "agreements" }],
  // The editor is a full-height frame with its own toolbar (WEB-06): no app bar.
  [/^#\/prepare(?:\/([^/?]+))?$/, () => import("./prepare.js"), { nav: "send", wide: true, chrome: false, frame: true }],
  [/^#\/templates$/, () => import("./templates.js"), { nav: "templates" }],
  [/^#\/templates\/new$/, async () => {
    const prepare = await import("./prepare.js");
    return { mount: (view, c, _m, params) => prepare.mount(view, c, [], params, { template: true }) };
  }, { nav: "templates", wide: true, chrome: false, frame: true }],
  [/^#\/templates\/([^/?]+)$/, async () => ({ mount: (await import("./templates.js")).mountUse }), { nav: "templates" }],
  [/^#\/admin(?:\?.*)?$/, () => import("./admin.js"), { nav: "admin" }],
  [/^#\/reports$/, () => import("./reports.js"), { nav: "reports" }],
];

let cleanup = null;
let routeSeq = 0;

let shownHash = null;

async function route() {
  const seq = ++routeSeq;
  const hash = location.hash || "#/home";
  // A screen with unsaved work may hold the user (A12): put the old address back if so.
  if (ctx.leaveGuard && shownHash && hash !== shownHash) {
    const guard = ctx.leaveGuard;
    const back = shownHash;
    history.replaceState(null, "", `${location.pathname}${location.search}${back}`);
    if (!(await guard())) return;
    if (seq !== routeSeq) return;
    ctx.leaveGuard = null;
    history.replaceState(null, "", `${location.pathname}${location.search}${hash}`);
  }
  shownHash = hash;
  const main = document.getElementById("main");
  if (!ctx.session && hash !== "#/signin") {
    try {
      ctx.session = await api.session();
    } catch (err) {
      ctx.session = null;
      if (!mock && isNoServer(err)) { clear(main); const v = h("div", { class: "os-view" }); main.append(v); noServerState(v, route); return; }
      if (err?.code === "CS-NET-0001" || (err?.status >= 500)) {
        // Not signed out: unreachable. Say so, with a retry, instead of a sign-in form.
        clear(main);
        const view = h("div", { class: "os-view" });
        main.append(view);
        errorState(view, err, route);
        return;
      }
      location.replace(`${location.pathname}${location.search}#/signin`);
      return;
    }
  }
  let match = null;
  let entry = null;
  for (const r of ROUTES) {
    match = hash.match(r[0]);
    if (match) { entry = r; break; }
  }
  // Admin is shown to account admins only; the server enforces it on every call.
  const adminLink = document.getElementById("nav-admin");
  if (adminLink) adminLink.hidden = !ctx.session?.admin;
  if (!entry) { ctx.navigate("#/home"); return; }
  if (hash === "#/signin" && ctx.session) { ctx.navigate("#/home"); return; }
  const mod = await entry[1]();
  if (seq !== routeSeq) return;
  if (cleanup) { try { cleanup(); } catch { /* a screen's own teardown */ } cleanup = null; }
  ctx.contexts = ["global"];
  ctx.onSearch = null;
  if (!whoLoaded && ctx.session) { whoLoaded = true; loadWho(); }
  const opts = entry[2];
  document.body.classList.toggle("is-chromeless", opts.chrome === false);
  document.body.classList.toggle("is-wide", !!opts.wide);
  document.body.classList.toggle("is-frame", !!opts.frame);
  for (const a of document.querySelectorAll(".os-nav__link")) {
    if (a.dataset.nav === opts.nav) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  }
  closeNav();
  clear(main);
  const view = h("div", { class: "os-view" });
  main.append(view);
  const params = new URLSearchParams(hash.split("?")[1] || "");
  cleanup = (await mod.mount(view, ctx, match.slice(1), params)) || null;
  if (document.activeElement === document.body || !document.activeElement) main.focus({ preventScroll: true });
}

// ---- Chrome ------------------------------------------------------------------------

function buildChrome() {
  applyI18n(document);
  if (mock) {
    const banner = document.getElementById("mock-banner");
    banner.hidden = false;
    banner.prepend(icon("info", { size: 16 }));
  }
  const menuBtn = document.getElementById("nav-toggle");
  menuBtn.append(icon("menu"));
  menuBtn.addEventListener("click", () => {
    const open = document.body.classList.toggle("nav-open");
    menuBtn.setAttribute("aria-expanded", String(open));
  });
  for (const a of document.querySelectorAll(".os-nav__link")) {
    a.prepend(icon(a.dataset.icon, { size: 20 }));
    if (mock && !a.getAttribute("href").startsWith("#")) a.href = `${a.getAttribute("href")}?mock=1`;
  }

  // Start: DocuSign's place for beginning anything (component library menu).
  const start = h("button", { type: "button", id: "start-btn", class: "os-btn os-btn--primary os-btn--md" },
    icon("plus", { size: 20 }), h("span", { text: t("start.label") }), icon("chevron-down", { size: 16 }));
  document.getElementById("start-slot").replaceWith(Object.assign(menuButton({
    label: t("start.label"), trigger: start, menuLabel: t("start.menu"), align: "start",
    items: () => [
      { label: t("start.send"), icon: "send", run: () => run("envelope.new") },
      { label: t("start.template"), icon: "layout-template", run: () => ctx.navigate("#/templates") },
      { label: t("start.verify"), icon: "shield-check", run: () => { location.href = mock ? "verify.html?mock=1" : "verify.html"; } },
    ],
  }), { className: "os-menu-wrap os-start" }));

  // Search: on Agreements it filters as you type; elsewhere Enter opens Agreements with it.
  const form = document.getElementById("top-search-form");
  const search = document.getElementById("top-search");
  form.prepend(icon("search", { size: 16 }));
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const q = search.value.trim();
    if (ctx.onSearch) ctx.onSearch(q);
    else ctx.navigate(q ? `#/agreements?q=${encodeURIComponent(q)}` : "#/agreements");
  });
  search.addEventListener("input", () => ctx.onSearch?.(search.value.trim()));

  const themeBtn = document.getElementById("theme-btn");
  themeBtn.append(icon("sun"));
  themeBtn.addEventListener("click", () => run("theme.toggle"));
  syncThemeButton();

  const help = document.getElementById("help-btn");
  help.append(icon("keyboard"));
  help.addEventListener("click", () => run("help.shortcuts"));

  const acct = h("button", { type: "button", id: "account-btn", class: "os-btn os-btn--ghost os-btn--md os-account-btn", attrs: { "aria-label": t("account.menu") } },
    avatar(""), icon("chevron-down", { size: 16 }));
  document.getElementById("account-slot").replaceWith(menuButton({
    label: t("account.menu"), trigger: acct, menuLabel: t("account.menu"),
    items: () => [
      h("div", { class: "os-menu__who" },
        h("strong", { text: who.name || (ctx.mock ? t("mock.user") : t("account.signed-in")) }),
        h("span", { class: "os-muted", text: who.email || ctx.session?.user_id || "" })),
      { label: t("theme.light"), icon: "sun", run: () => run("theme.light") },
      { label: t("theme.dark"), icon: "moon", run: () => run("theme.dark") },
      { label: t("theme.system"), icon: "monitor", run: () => run("theme.system") },
      { label: t("help.shortcuts"), icon: "keyboard", run: () => run("help.shortcuts") },
      { label: t("account.signout"), icon: "log-out", run: () => run("account.signout") },
    ],
  }));
}

/// Who is signed in, for the avatar: an admin can read their own member record; anyone
/// else shows the account's initials.
const who = { name: "", email: "" };
let whoLoaded = false;
async function loadWho() {
  try {
    if (ctx.session?.admin) {
      const me = (await api.users.list()).items?.find((u) => u.id === ctx.session.user_id);
      if (me) { who.name = me.name || ""; who.email = me.email || ""; }
    }
    if (!who.name) who.name = (await api.account())?.name || "";
  } catch { /* the avatar falls back to a person icon */ }
  const av = document.querySelector("#account-btn .os-avatar");
  if (av) {
    av.textContent = initials(who.name) || "";
    // The name starts with what is shown (SC 2.5.3, label in name).
    av.parentElement.setAttribute("aria-label", av.textContent ? `${av.textContent} ${t("account.menu")}` : t("account.menu"));
  }
}

function closeNav() {
  document.body.classList.remove("nav-open");
  document.getElementById("nav-toggle")?.setAttribute("aria-expanded", "false");
}

function syncThemeButton() {
  const b = document.getElementById("theme-btn");
  if (!b) return;
  const dark = getTheme() === "dark" || (getTheme() === "system" && matchMedia("(prefers-color-scheme: dark)").matches);
  b.replaceChildren(icon(dark ? "moon" : "sun"));
  b.setAttribute("aria-label", t(dark ? "theme.to-light" : "theme.to-dark"));
  b.title = b.getAttribute("aria-label");
}

function shortcutsDialog() {
  openPanel({
    title: t("help.shortcuts"),
    build(body) {
      const table = h("table", { class: "os-table os-table--compact" },
        h("thead", {}, h("tr", {}, h("th", { attrs: { scope: "col" }, text: t("help.key") }), h("th", { attrs: { scope: "col" }, text: t("help.action") }))));
      const tb = h("tbody");
      const seen = new Set();
      const mac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent || "");
      // The keys of the screen in use, labelled by the commands they run.
      for (const [k, id] of bindings(ctx.contexts)) {
        const c = command(id);
        if (!c) continue;
        const digit = /^recipient\.select-\d$/.test(id);
        const shown = digit ? "1–9" : k.replace("Ctrl", mac ? "⌘" : "Ctrl");
        const label = c.label || id;
        if (seen.has(`${label}|${shown}`) || (digit && seen.has("digits"))) continue;
        seen.add(`${label}|${shown}`);
        if (digit) seen.add("digits");
        tb.append(h("tr", {}, h("td", {}, h("kbd", { text: shown })), h("td", { text: label })));
      }
      table.append(tb);
      body.append(table);
    },
  });
}

// ---- Commands and keys ---------------------------------------------------------------

function registerCommands() {
  register("help.shortcuts", { label: t("help.shortcuts"), run: shortcutsDialog });
  register("theme.toggle", { label: t("cmd.theme"), run: () => { toggleTheme(); syncThemeButton(); } });
  register("theme.light", { label: t("theme.light"), run: () => { setTheme("light"); syncThemeButton(); } });
  register("theme.dark", { label: t("theme.dark"), run: () => { setTheme("dark"); syncThemeButton(); } });
  register("theme.system", { label: t("theme.system"), run: () => { setTheme("system"); syncThemeButton(); } });
  register("envelope.new", { label: t("nav.new"), run: () => ctx.navigate("#/prepare"), enabled: () => !!ctx.session });
  register("account.signout", {
    label: t("account.signout"),
    run: async () => {
      try { await api.logout(); } catch { /* the session is gone either way */ }
      ctx.session = null;
      toast(t("account.signed-out"), "success");
      ctx.navigate("#/signin");
    },
  });
}

document.addEventListener("keydown", (e) => {
  if (document.querySelector("dialog[open]")) return;
  handle(e, ctx.contexts, isTyping(e));
});

initTheme();
buildChrome();
registerCommands();
window.addEventListener("hashchange", route);
route();
