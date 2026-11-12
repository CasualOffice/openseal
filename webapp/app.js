// The sender app's shell (WEB-01): session, top bar, navigation, theme, routing,
// shortcuts. Screens are modules with `mount(container, ctx, params) → cleanup`.
//
// Routes (hash, so a static server needs no rewrites):
//   #/signin  #/home  #/agreements[?status=…]  #/envelopes/{id}  #/prepare  #/prepare/{id}
//   #/templates  #/templates/new  #/templates/{id}  #/templates/{id}/edit  #/admin[?tab=api|account]
//   #/accept-invite?token=…   (WEB-06; no session needed)
// Any other route shows "This page does not exist" (UX-04). Verify is its own page,
// verify.html, usable without an account.

import { h, clear, isTyping, initials } from "./dom.js";
import { icon } from "./icons.js";
import { t, applyI18n } from "./i18n.js";
import { createClient, isMockMode, isNoServer, ApiError, errorMessage } from "./api.js";
import { register, run, command } from "./commands.js";
import { handle, shortcutGroups } from "./keys.js";
import {
  openPanel, openDialog, closePanel, clearViewToasts, confirmDialog, toast, errorState, noServerState,
  emptyState, button, menuButton, avatar,
} from "./ui/index.js";
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
  // The invitation email's link (WEB-06 AD-01): open without a session.
  [/^#\/accept-invite(?:\?.*)?$/, () => import("./acceptinvite.js"), { chrome: false }],
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
  // WEB-09: a saved template's documents, roles and fields, reopened in the editor.
  [/^#\/templates\/([^/?]+)\/edit$/, async () => {
    const prepare = await import("./prepare.js");
    return { mount: (view, c, m, params) => prepare.mount(view, c, [], params, { template: true, templateId: m[0] }) };
  }, { nav: "templates", wide: true, chrome: false, frame: true }],
  [/^#\/templates\/([^/?]+)$/, async () => ({ mount: (await import("./templates.js")).mountUse }), { nav: "templates" }],
  [/^#\/admin(?:\?.*)?$/, () => import("./admin.js"), { nav: "admin" }],
  [/^#\/reports$/, () => import("./reports.js"), { nav: "reports" }],
];

/// The screen for an address no route matches (UX-04): said, not silently Home.
const NOT_FOUND = [null, async () => ({ mount: mountNotFound }), { nav: null }];

function mountNotFound(view) {
  view.append(
    h("h1", { class: "os-sr-only", text: t("notfound.title") }),
    emptyState({
      illus: "search",
      title: t("notfound.title"),
      text: t("notfound.text"),
      action: button(t("notfound.home"), { icon: "house", variant: "primary", onClick: () => ctx.navigate("#/home") }),
      testId: "empty-not-found",
    }));
}

let cleanup = null;
let routeSeq = 0;

let shownHash = null;

/// Side panels the user has typed into since they opened (UX-04): leaving the screen
/// asks before it throws the input away.
const dirtyPanels = new WeakSet();
for (const ev of ["input", "change"]) {
  document.addEventListener(ev, (e) => {
    const sheet = e.target?.closest?.(".os-sheet");
    if (sheet) dirtyPanels.add(sheet);
  }, true);
}

/// Whether the open side panel may be closed for a navigation: yes when there is none,
/// or nothing was typed into it, or the user agrees to discard it.
async function panelMayClose() {
  const sheet = document.querySelector(".os-sheet:not(.is-leaving)");
  if (!sheet || !dirtyPanels.has(sheet)) return true;
  return confirmDialog(t("shell.panel-leave-title"), t("shell.panel-leave-text"), { confirm: t("shell.panel-leave"), danger: true });
}

/// Put `hash` in the address bar without a new navigation.
const setHash = (hash) => history.replaceState(null, "", `${location.pathname}${location.search}${hash}`);

async function route() {
  const seq = ++routeSeq;
  const hash = location.hash || "#/home";
  // Any navigation closes the drawer and the phone search row first, so a question
  // asked below (unsaved work) is never answered behind them.
  closeNav();
  closeSearch();
  // A screen with unsaved work may hold the user (A12): put the old address back if so.
  if (ctx.leaveGuard && shownHash && hash !== shownHash) {
    const guard = ctx.leaveGuard;
    const back = shownHash;
    setHash(back);
    if (!(await guard())) return;
    if (seq !== routeSeq) return;
    ctx.leaveGuard = null;
    setHash(hash);
  }
  // A side panel with input in it holds the user the same way (UX-04).
  if (shownHash && hash !== shownHash && document.querySelector(".os-sheet:not(.is-leaving)")) {
    const back = shownHash;
    setHash(back);
    if (!(await panelMayClose())) return;
    if (seq !== routeSeq) return;
    setHash(hash);
  }
  // Panels and the toasts about the screen belong to it: a new screen starts clean.
  closePanel();
  clearViewToasts();
  shownHash = hash;
  const main = document.getElementById("main");
  if (!ctx.session && hash !== "#/signin" && !hash.startsWith("#/accept-invite")) {
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
  // No address at all is Home; a mistyped or stale one is said to be missing.
  if (!entry && /^#\/?$/.test(hash)) { ctx.navigate("#/home"); return; }
  if (!entry) { entry = NOT_FOUND; match = [hash]; }
  if (hash === "#/signin" && ctx.session) { ctx.navigate("#/home"); return; }
  const mod = await entry[1]();
  if (seq !== routeSeq) return;
  if (cleanup) { try { cleanup(); } catch { /* a screen's own teardown */ } cleanup = null; }
  ctx.contexts = ["global"];
  ctx.onSearch = null;
  if (!whoLoaded && ctx.session) { whoLoaded = true; loadWho(); }
  if (ctx.session) refreshActivity();
  const opts = entry[2];
  document.body.classList.toggle("is-chromeless", opts.chrome === false);
  document.body.classList.toggle("is-wide", !!opts.wide);
  document.body.classList.toggle("is-frame", !!opts.frame);
  for (const a of document.querySelectorAll(".os-nav__link")) {
    if (opts.nav && a.dataset.nav === opts.nav) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  }
  clear(main);
  const view = h("div", { class: "os-view" });
  main.append(view);
  const params = new URLSearchParams(hash.split("?")[1] || "");
  cleanup = (await mod.mount(view, ctx, match.slice(1), params)) || null;
  if (document.activeElement === document.body || !document.activeElement) main.focus({ preventScroll: true });
}

// ---- Chrome ------------------------------------------------------------------------

/// Below this width the sections are a drawer and search a button (shell.css, 60em).
const narrow = () => matchMedia("(max-width: 60em)").matches;

function buildChrome() {
  applyI18n(document);
  if (mock) {
    const banner = document.getElementById("mock-banner");
    banner.hidden = false;
    banner.prepend(icon("info", { size: 16 }));
  }
  buildDrawer();

  // Start: DocuSign's place for beginning anything (component library menu).
  const start = h("button", { type: "button", id: "start-btn", class: "os-btn os-btn--primary os-btn--md" },
    icon("plus", { size: 20 }), h("span", { text: t("start.label") }), icon("chevron-down", { size: 16 }));
  document.getElementById("start-slot").replaceWith(Object.assign(menuButton({
    label: t("start.label"), trigger: start, menuLabel: t("start.menu"), align: "start",
    items: () => [
      { label: t("start.send"), icon: "send", run: () => run("envelope.new") },
      { label: t("start.template"), icon: "layout-template", run: () => ctx.navigate("#/templates") },
      "separator",
      { label: t("start.verify"), icon: "shield-check", run: () => run("app.verify") },
    ],
  }), { className: "os-menu-wrap os-start" }));

  buildSearch();

  // Help: shortcuts, verify and about (the keyboard and theme buttons it replaces live
  // here and in the account menu).
  const helpBtn = h("button", { type: "button", id: "help-btn", class: "os-btn os-btn--ghost os-btn--md os-btn--icon", attrs: { "aria-label": t("help.menu"), title: t("help.menu") } }, icon("circle-help"));
  document.getElementById("help-slot").replaceWith(menuButton({
    label: t("help.menu"), trigger: helpBtn, menuLabel: t("help.menu"),
    items: helpItems,
  }));

  // Notifications: what happened lately to the envelopes the user can see.
  const bell = h("button", { type: "button", id: "bell-btn", class: "os-btn os-btn--ghost os-btn--md os-btn--icon os-bell", attrs: { "aria-label": t("notify.label"), title: t("notify.label") } },
    icon("bell"), h("span", { class: "os-bell__dot", attrs: { "aria-hidden": "true" }, hidden: true }));
  const bellWrap = menuButton({
    label: t("notify.label"), trigger: bell, menuLabel: t("notify.label"), menuClass: "os-menu--notify",
    items: activityItems,
  });
  bell.addEventListener("click", () => markActivitySeen());
  document.getElementById("bell-slot").replaceWith(bellWrap);

  const acct = h("button", { type: "button", id: "account-btn", class: "os-btn os-btn--ghost os-btn--md os-account-btn", attrs: { "aria-label": t("account.menu") } },
    avatar(""), icon("chevron-down", { size: 16 }));
  document.getElementById("account-slot").replaceWith(menuButton({
    label: t("account.menu"), trigger: acct, menuLabel: t("account.menu"), menuClass: "os-menu--account",
    items: () => {
      const theme = getTheme();
      const mark = (v, ic) => (theme === v ? "check" : ic);
      return [
        h("div", { class: "os-menu__who" },
          h("strong", { text: who.name || (ctx.mock ? t("mock.user") : t("account.signed-in")) }),
          h("span", { class: "os-muted", text: who.email || "" })),
        { label: t("account.profile"), icon: "user", run: () => run("account.profile") },
        { label: t("account.notifications"), icon: "bell", run: () => run("account.notifications") },
        "separator",
        h("div", { class: "os-menu__group", attrs: { "aria-hidden": "true" }, text: t("account.theme") }),
        { label: t("theme.light"), icon: mark("light", "sun"), run: () => run("theme.light") },
        { label: t("theme.dark"), icon: mark("dark", "moon"), run: () => run("theme.dark") },
        { label: t("theme.system"), icon: mark("system", "monitor"), run: () => run("theme.system") },
        "separator",
        { label: t("account.help"), icon: "circle-help", run: () => run("help.shortcuts") },
        { label: t("help.about"), icon: "info", run: () => run("help.about") },
        "separator",
        { label: t("account.signout"), icon: "log-out", run: () => run("account.signout") },
      ];
    },
  }));
}

function helpItems() {
  return [
    { label: t("help.shortcuts"), icon: "keyboard", run: () => run("help.shortcuts") },
    { label: t("start.verify"), icon: "shield-check", run: () => run("app.verify") },
    "separator",
    { label: t("help.about"), icon: "info", run: () => run("help.about") },
  ];
}

// ---- The phone drawer (UX-04) ------------------------------------------------------------
//
// Below 60em the sections are a drawer: a scrim behind it closes it on a tap, Escape
// closes it and returns focus to Menu, it starts under the bar (and the demo banner),
// and while closed it is inert, so its links are not in the tab order. Opening another
// menu closes it.

function buildDrawer() {
  const menuBtn = document.getElementById("nav-toggle");
  const nav = document.getElementById("nav");
  const scrim = document.getElementById("nav-scrim");
  menuBtn.append(icon("menu"));
  menuBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    if (document.body.classList.contains("nav-open")) closeNav(); else openNav();
  });
  scrim.addEventListener("click", () => closeNav(true));
  for (const a of document.querySelectorAll(".os-nav__link")) {
    a.prepend(icon(a.dataset.icon, { size: 20 }));
    if (mock && !a.getAttribute("href").startsWith("#")) a.href = `${a.getAttribute("href")}?mock=1`;
    // A section already shown starts over when chosen again (its search and selection
    // cleared), as DocuSign's do.
    a.addEventListener("click", async (e) => {
      if (a.getAttribute("href") !== location.hash) return;
      e.preventDefault();
      if (await panelMayClose()) route();
    });
  }
  // Another menu opening closes the drawer.
  document.addEventListener("click", (e) => {
    const trigger = e.target?.closest?.('[aria-haspopup="menu"]');
    if (trigger && !nav.contains(trigger)) closeNav();
  }, true);
  const sync = () => {
    const open = document.body.classList.contains("nav-open");
    nav.inert = narrow() && !open;
    if (!narrow() && open) closeNav();
  };
  matchMedia("(max-width: 60em)").addEventListener?.("change", sync);
  sync();
}

function openNav() {
  const nav = document.getElementById("nav");
  const bar = document.querySelector(".os-topbar");
  // Under the bar as it stands now: the demo banner above it scrolls away with the page.
  document.documentElement.style.setProperty("--os-nav-top", `${Math.max(0, bar.getBoundingClientRect().bottom)}px`);
  document.body.classList.add("nav-open");
  document.getElementById("nav-toggle").setAttribute("aria-expanded", "true");
  document.getElementById("nav-scrim").hidden = false;
  nav.inert = false;
  closeSearch();
  nav.querySelector(".os-nav__link:not([hidden])")?.focus({ preventScroll: true });
}

function closeNav(focus = false) {
  const was = document.body.classList.contains("nav-open");
  document.body.classList.remove("nav-open");
  document.getElementById("nav-toggle")?.setAttribute("aria-expanded", "false");
  const scrim = document.getElementById("nav-scrim");
  if (scrim) scrim.hidden = true;
  const nav = document.getElementById("nav");
  if (nav) nav.inert = narrow();
  if (was && focus) document.getElementById("nav-toggle")?.focus({ preventScroll: true });
}

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && document.body.classList.contains("nav-open") && !document.querySelector("dialog[open]")) {
    e.preventDefault();
    e.stopPropagation();
    closeNav(true);
  }
}, true);

// ---- Search (UX-04) ------------------------------------------------------------------------
//
// One input, #top-search (Agreements filters through it). Below 60em a search button
// opens it as a full-width row under the bar; Escape closes the row. "/" focuses it
// from any screen with the bar.

function buildSearch() {
  const form = document.getElementById("top-search-form");
  const search = document.getElementById("top-search");
  form.prepend(icon("search", { size: 16 }));
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const q = search.value.trim();
    if (ctx.onSearch) ctx.onSearch(q);
    else ctx.navigate(q ? `#/agreements?q=${encodeURIComponent(q)}` : "#/agreements");
    if (narrow() && !ctx.onSearch) closeSearch();
  });
  search.addEventListener("input", () => ctx.onSearch?.(search.value.trim()));
  search.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && document.body.classList.contains("search-open")) { e.preventDefault(); e.stopPropagation(); closeSearch(true); }
  });
  const toggle = h("button", {
    type: "button", id: "search-toggle", class: "os-btn os-btn--ghost os-btn--md os-btn--icon os-search-toggle",
    attrs: { "aria-label": t("agreements.search"), title: t("agreements.search"), "aria-controls": "top-search-form", "aria-expanded": "false" },
  }, icon("search"));
  toggle.addEventListener("click", () => { if (document.body.classList.contains("search-open")) closeSearch(true); else openSearch(); });
  form.before(toggle);
}

function openSearch() {
  closeNav();
  document.body.classList.add("search-open");
  document.getElementById("search-toggle")?.setAttribute("aria-expanded", "true");
  document.getElementById("top-search")?.focus();
}

function closeSearch(focus = false) {
  if (!document.body.classList.contains("search-open")) return;
  document.body.classList.remove("search-open");
  const toggle = document.getElementById("search-toggle");
  toggle?.setAttribute("aria-expanded", "false");
  if (focus) toggle?.focus({ preventScroll: true });
}

function focusSearch() {
  if (narrow()) openSearch();
  else document.getElementById("top-search")?.focus();
}

// ---- Notifications (UX-04) ---------------------------------------------------------------
//
// The bell lists the latest changes to envelopes the user can see: completed, declined,
// viewed, voided and expired ones, newest first, read from the envelope list (no
// notification store exists). A dot marks changes since the bell was last opened, a
// per-browser convenience.

const SEEN_KEY = "openseal.activity-seen";
const ACTIVE = ["completed", "declined", "delivered", "voided", "expired"];
let activity = [];
let activityAt = 0;

async function refreshActivity(force = false) {
  if (!force && Date.now() - activityAt < 60_000) return;
  activityAt = Date.now();
  try {
    const page = await api.listEnvelopes({ status: ACTIVE, sort: "updated_at", order: "desc", limit: 8 });
    activity = page?.items || [];
  } catch { activity = []; }
  const seen = (() => { try { return localStorage.getItem(SEEN_KEY) || ""; } catch { return ""; } })();
  const fresh = activity.filter((e) => (e.updated_at || "") > seen).length;
  const bell = document.getElementById("bell-btn");
  if (!bell) return;
  bell.querySelector(".os-bell__dot").hidden = fresh === 0;
  const name = fresh ? t("notify.label-new", { n: fresh }) : t("notify.label");
  bell.setAttribute("aria-label", name);
  bell.title = name;
}

function markActivitySeen() {
  const newest = activity.map((e) => e.updated_at || "").sort().pop();
  try { if (newest) localStorage.setItem(SEEN_KEY, newest); } catch { /* storage off */ }
  const bell = document.getElementById("bell-btn");
  bell.querySelector(".os-bell__dot").hidden = true;
  bell.setAttribute("aria-label", t("notify.label"));
  bell.title = t("notify.label");
}

function activityItems() {
  const head = h("div", { class: "os-menu__group", attrs: { "aria-hidden": "true" }, text: t("notify.recent") });
  if (!activity.length) return [head, h("p", { class: "os-menu__empty os-muted", text: t("notify.none") })];
  return [
    head,
    ...activity.map((e) => ({
      label: t("notify.item", { subject: e.subject || t("notify.untitled"), status: t(`status.${e.status}`) }),
      icon: STATUS_ICON[e.status] || "info",
      run: () => ctx.navigate(`#/envelopes/${encodeURIComponent(e.id)}`),
    })),
    "separator",
    { label: t("notify.all"), icon: "inbox", run: () => ctx.navigate("#/agreements") },
  ];
}

const STATUS_ICON = { completed: "circle-check", declined: "circle-x", delivered: "eye", voided: "ban", expired: "clock" };

// ---- Who is signed in ----------------------------------------------------------------------

/// Who is signed in, for the avatar: an admin can read their own member record; anyone
/// else shows the account's initials.
const who = { name: "", email: "" };
let whoLoaded = false;
async function loadWho() {
  try {
    if (api.available("profile")) {
      const me = await api.me();
      who.name = me?.name || "";
      who.email = me?.email || "";
      ctx.who = who;
    } else if (ctx.session?.admin) {
      const me = (await api.users.list()).items?.find((u) => u.id === ctx.session.user_id);
      if (me) { who.name = me.name || ""; who.email = me.email || ""; }
      ctx.who = who;
    }
    if (!who.name) who.name = (await api.account())?.name || "";
  } catch { /* the avatar falls back to a person icon */ }
  syncAvatar();
}

function syncAvatar() {
  const av = document.querySelector("#account-btn .os-avatar");
  if (av) {
    av.textContent = initials(who.name) || "";
    // The name starts with what is shown (SC 2.5.3, label in name).
    av.parentElement.setAttribute("aria-label", av.textContent ? `${av.textContent} ${t("account.menu")}` : t("account.menu"));
  }
}

// ---- Dialogs ---------------------------------------------------------------------------------

/// The Keyboard shortcuts panel (UX-04): every table, grouped by where it applies, one
/// row per action with its keys (aliases together), and ⌘ ⌥ ⇧ on a Mac.
function shortcutsDialog() {
  const mac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent || "");
  openPanel({
    id: "shortcuts",
    title: t("help.shortcuts"),
    build(body) {
      for (const group of shortcutGroups(ctx.contexts, { mac, label: (id) => command(id)?.label })) {
        const hid = `keys-${group.context}`;
        const table = h("table", { class: "os-table os-table--compact os-keys", attrs: { "aria-labelledby": hid } },
          h("thead", {}, h("tr", {}, h("th", { attrs: { scope: "col" }, text: t("help.action") }), h("th", { attrs: { scope: "col" }, text: t("help.key") }))));
        const tb = h("tbody");
        for (const row of group.rows) {
          const keys = h("td", { class: "os-keys__keys" });
          row.keys.forEach((k, i) => {
            if (i) keys.append(h("span", { class: "os-muted", text: ` ${t("help.or")} ` }));
            k.forEach((part, j) => { if (j) keys.append(document.createTextNode(" ")); keys.append(h("kbd", { text: part })); });
          });
          tb.append(h("tr", {}, h("td", { text: row.label }), keys));
        }
        table.append(tb);
        body.append(h("h3", { id: hid, class: "os-keys__title", text: t(`help.group.${group.context}`) }), table);
      }
    },
  });
}

function aboutDialog() {
  openDialog({
    title: t("help.about"),
    build(body) {
      body.append(
        h("p", { text: t("about.text") }),
        h("p", { class: "os-muted", text: t("about.prerelease") }));
    },
    actions: [{ label: t("action.close"), variant: "primary", value: null }],
  });
}

// ---- Commands and keys ---------------------------------------------------------------

function registerCommands() {
  register("help.shortcuts", { label: t("help.shortcuts"), run: shortcutsDialog });
  register("help.about", { label: t("help.about"), run: aboutDialog });
  register("app.verify", { label: t("start.verify"), run: () => { location.href = mock ? "verify.html?mock=1" : "verify.html"; } });
  register("search.focus", {
    label: t("cmd.search"),
    run: focusSearch,
    enabled: () => !!ctx.session && !document.body.classList.contains("is-chromeless"),
  });
  register("theme.toggle", { label: t("cmd.theme"), run: () => toggleTheme() });
  register("theme.light", { label: t("theme.light"), run: () => setTheme("light") });
  register("theme.dark", { label: t("theme.dark"), run: () => setTheme("dark") });
  register("theme.system", { label: t("theme.system"), run: () => setTheme("system") });
  register("envelope.new", { label: t("nav.new"), run: () => ctx.navigate("#/prepare"), enabled: () => !!ctx.session });
  register("account.profile", {
    label: t("account.profile"),
    run: async () => (await import("./profile.js")).openProfile(ctx, { onSaved: (me) => { who.name = me.name || who.name; syncAvatar(); } }),
    enabled: () => !!ctx.session,
  });
  register("account.notifications", {
    label: t("account.notifications"),
    run: async () => (await import("./profile.js")).openProfile(ctx, { focus: "notifications" }),
    enabled: () => !!ctx.session,
  });
  register("account.signout", {
    label: t("account.signout"),
    run: async () => {
      try { await api.logout(); } catch { /* the session is gone either way */ }
      ctx.session = null;
      whoLoaded = false;
      activityAt = 0;
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
