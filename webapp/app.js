// The sender app's shell (WEB-01, WEB-17): session, sidebar, navigation, ⌘K, theme,
// routing, shortcuts. Screens are modules with `mount(container, ctx, params) → cleanup`.
//
// Routes (hash, so a static server needs no rewrites):
//   #/signin  #/home  #/agreements[?status=…]  #/envelopes/{id}  #/prepare  #/prepare/{id}
//   #/templates  #/templates/new  #/templates/{id}  #/templates/{id}/edit  #/templates/{id}/bulk  #/admin[?tab=api|account]
//   #/org[?section=workspaces|users|admins|audit]   (ORG-06; organization roles only)
//   #/accept-invite?token=…   (WEB-06; no session needed)
// Any other route shows "This page does not exist" (UX-04). Verify is its own page,
// verify.html, usable without an account.
//
// Layout (docs/47 §As built: design foundation): the canvas's quiet sidebar (workspace,
// "Search or jump to… ⌘K", New agreement, sections, saved views, Admin, account) and the
// routed screen in a white content card that scrolls on its own. Below 60em the sidebar
// is a drawer and a top row holds Menu, the logo, search, notifications and the account.

import { h, clear, isTyping, initials } from "./dom.js";
import { icon } from "./icons.js";
import { t, applyI18n } from "./i18n.js";
import { createClient, isMockMode, isNoServer, ApiError, errorMessage } from "./api.js";
import { register, run, command, all as allCommands } from "./commands.js";
import { handle, shortcutGroups } from "./keys.js";
import {
  openPanel, openDialog, closePanel, clearViewToasts, confirmDialog, toast, errorState, noServerState,
  emptyState, button, menuButton, avatar,
} from "./ui/index.js";
import { openPalette, closePalette, paletteOpen, registerPaletteProvider, matches } from "./ui/palette.js";
import { initTheme, setTheme, getTheme, toggleTheme } from "./theme.js";
import { initMl } from "./ml.js";

const mock = isMockMode();
let api;
if (mock) {
  const { createMockFetch } = await import("./mock.js");
  api = createClient({ fetch: createMockFetch({ store: safeSession() }), store: safeSession() });
} else {
  const base = document.querySelector('meta[name="openseal-api-base"]')?.content || "";
  api = createClient({ baseUrl: base, store: safeSession() });
}
initMl(api);

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
  /// Add a section to ⌘K (ui/palette.js); returns the function that removes it.
  registerPaletteProvider,
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
  // UXW-04: bulk send from a template with a CSV list.
  [/^#\/templates\/([^/?]+)\/bulk$/, () => import("./bulk.js"), { nav: "templates" }],
  [/^#\/templates\/([^/?]+)$/, async () => ({ mount: (await import("./templates.js")).mountUse }), { nav: "templates" }],
  [/^#\/admin(?:\?.*)?$/, () => import("./admin.js"), { nav: "admin" }],
  // ORG-06: the organization admin, for a person who holds an organization role.
  [/^#\/org(?:\?.*)?$/, () => import("./org.js"), { nav: "admin" }],
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

/// Drop the screens after `view` once it has something to show: when its first child
/// arrives (a MutationObserver callback, a microtask, so before the next paint), when its
/// mount finishes, or after 400 ms, whichever is first. Until then the empty new view sits
/// above the old, inert one: a route switch never paints an empty card (WEB-17), and the
/// new view is visible from the start, so a screen can focus its first field.
function revealWhenReady(main, view, mounted) {
  let shown = false;
  const show = () => {
    if (shown || !view.isConnected) return;
    shown = true;
    obs?.disconnect();
    clearTimeout(timer);
    for (const old of [...main.children]) if (old !== view) old.remove();
    view.classList.remove("is-entering");
    main.scrollTop = 0;
    if (narrow()) window.scrollTo(0, 0);
  };
  const obs = typeof MutationObserver === "function" ? new MutationObserver(() => { if (view.firstElementChild) show(); }) : null;
  obs?.observe(view, { childList: true });
  if (view.firstElementChild) show();
  const timer = setTimeout(show, 400);
  mounted.then(show, show);
  return show;
}

/// Replace whatever `main` shows with a fresh view at once (error and no-server states).
function freshView(main) {
  clear(main);
  const view = h("div", { class: "os-view" });
  main.append(view);
  main.scrollTop = 0;
  return view;
}

async function route() {
  const seq = ++routeSeq;
  const hash = location.hash || "#/home";
  // Any navigation closes the drawer and the command menu first, so a question asked
  // below (unsaved work) is never answered behind them.
  closeNav();
  closePalette();
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
      if (!mock && isNoServer(err)) { noServerState(freshView(main), route); return; }
      if (err?.code === "CS-NET-0001" || (err?.status >= 500)) {
        // Not signed out: unreachable. Say so, with a retry, instead of a sign-in form.
        errorState(freshView(main), err, route);
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
  if (ctx.session) { refreshActivity(); drawNavViews().catch(() => { /* the views are a shortcut; the screen still works */ }); }
  const opts = entry[2];
  const layoutChanges = document.body.classList.contains("is-chromeless") !== (opts.chrome === false)
    || document.body.classList.contains("is-frame") !== !!opts.frame;
  document.body.classList.toggle("is-chromeless", opts.chrome === false);
  document.body.classList.toggle("is-wide", !!opts.wide);
  document.body.classList.toggle("is-frame", !!opts.frame);
  for (const a of document.querySelectorAll(".os-nav__link")) {
    if (opts.nav && a.dataset.nav === opts.nav) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  }
  // The old screen stays, inert, until the new one has something to show.
  for (const old of main.children) { old.inert = true; old.setAttribute("aria-hidden", "true"); old.classList.add("is-leaving"); }
  if (layoutChanges) clear(main);
  const view = h("div", { class: "os-view is-entering" });
  main.prepend(view);
  const params = new URLSearchParams(hash.split("?")[1] || "");
  const mounted = Promise.resolve().then(() => mod.mount(view, ctx, match.slice(1), params));
  const show = revealWhenReady(main, view, mounted);
  try {
    cleanup = (await mounted) || null;
  } finally {
    show();
  }
  if (seq !== routeSeq) return;
  syncScreenSearch();
  if (document.activeElement === document.body || !document.activeElement) main.focus({ preventScroll: true });
}

// ---- Chrome ------------------------------------------------------------------------

/// Below this width the sidebar is a drawer and the top row shows (shell.css, 60em).
const narrow = () => matchMedia("(max-width: 60em)").matches;
const isMac = () => /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent || "");

let wsName = null; // the workspace name in the switcher row
let spaces = null; // GET /auth/workspaces (ORG-04): the person's workspaces by organization
let orgRole = null; // GET /organizations/me (ORG-06): the person's organization role, or null
let acctWrap = null;
let bellWrap = null;

function buildChrome() {
  applyI18n(document);
  if (mock) {
    const banner = document.getElementById("mock-banner");
    banner.hidden = false;
    banner.title = t("mock.banner");
    banner.prepend(icon("info", { size: 14, stroke: 1.75 }));
  }
  buildDrawer();
  buildWorkspace();

  // Search or jump to… ⌘K (the command menu).
  const jump = h("button", { type: "button", id: "palette-btn", class: "os-jump", attrs: { "aria-haspopup": "dialog", "aria-keyshortcuts": isMac() ? "Meta+K" : "Control+K" } },
    icon("os-search", { size: 14, stroke: 1.6 }), h("span", { text: t("palette.jump") }), h("kbd", { text: isMac() ? "⌘K" : "Ctrl K" }));
  jump.addEventListener("click", () => run("palette.open"));
  document.getElementById("palette-slot").replaceWith(jump);

  // New agreement: DocuSign's Start menu (send, from a template, verify), in the canvas's
  // red with the N shortcut beside it.
  const start = h("button", { type: "button", id: "start-btn", class: "os-btn os-btn--primary os-btn--md", attrs: { "aria-keyshortcuts": "N" } },
    icon("plus", { size: 16, stroke: 2 }), h("span", { text: t("start.label") }), h("kbd", { attrs: { "aria-hidden": "true" }, text: "N" }));
  document.getElementById("start-slot").replaceWith(Object.assign(menuButton({
    label: t("start.label"), trigger: start, menuLabel: t("start.menu"), align: "start",
    items: () => [
      { label: t("start.send"), icon: "send", run: () => run("envelope.new") },
      { label: t("start.template"), icon: "layout-template", run: () => ctx.navigate("#/templates") },
      "separator",
      { label: t("start.verify"), icon: "shield-check", run: () => run("app.verify") },
    ],
  }), { className: "os-menu-wrap os-start" }));

  // Help: shortcuts, verify and about.
  const helpBtn = h("button", { type: "button", id: "help-btn", class: "os-btn os-btn--ghost os-btn--md os-btn--icon", attrs: { "aria-label": t("help.menu"), title: t("help.menu") } }, icon("circle-help", { size: 16 }));
  document.getElementById("help-slot").replaceWith(menuButton({
    label: t("help.menu"), trigger: helpBtn, menuLabel: t("help.menu"),
    items: helpItems,
  }));

  // Notifications: what happened lately to the envelopes the user can see.
  const bell = h("button", { type: "button", id: "bell-btn", class: "os-btn os-btn--ghost os-btn--md os-btn--icon os-bell", attrs: { "aria-label": t("notify.label"), title: t("notify.label") } },
    icon("bell", { size: 16 }), h("span", { class: "os-bell__dot", attrs: { "aria-hidden": "true" }, hidden: true }));
  bellWrap = menuButton({
    label: t("notify.label"), trigger: bell, menuLabel: t("notify.label"), menuClass: "os-menu--notify",
    items: activityItems,
  });
  bell.addEventListener("click", () => markActivitySeen());
  document.getElementById("bell-slot").replaceWith(bellWrap);

  const acct = h("button", { type: "button", id: "account-btn", class: "os-btn os-btn--ghost os-btn--md os-account-btn", attrs: { "aria-label": t("account.menu") } },
    avatar(""), h("span", { class: "os-account__name", text: "" }));
  acctWrap = menuButton({
    label: t("account.menu"), trigger: acct, menuLabel: t("account.menu"), menuClass: "os-menu--account", align: "start",
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
  });
  document.getElementById("account-slot").replaceWith(acctWrap);
  buildScreenSearch();
  placeChrome();
  matchMedia("(max-width: 60em)").addEventListener?.("change", placeChrome);
}

/// Notifications and the account live in the sidebar's foot on a desktop and in the top
/// row on a phone, where the sidebar is a closed drawer: one set of controls, moved.
function placeChrome() {
  const tools = document.getElementById("topbar-tools");
  const me = document.getElementById("side-me");
  if (narrow()) {
    const search = document.getElementById("search-toggle") || makeSearchToggle();
    tools.append(search, bellWrap, acctWrap);
  } else {
    me.prepend(acctWrap);
    me.insertBefore(bellWrap, acctWrap.nextSibling);
  }
}

function makeSearchToggle() {
  const b = h("button", {
    type: "button", id: "search-toggle", class: "os-btn os-btn--ghost os-btn--md os-btn--icon",
    attrs: { "aria-label": t("palette.jump"), title: t("palette.jump"), "aria-haspopup": "dialog" },
  }, icon("os-search", { size: 18, stroke: 1.6 }));
  b.addEventListener("click", () => run("palette.open"));
  return b;
}

/// The workspace switcher row: the seal mark, the account's name and the product.
function buildWorkspace() {
  const btn = h("button", { type: "button", id: "ws-btn", class: "os-ws" },
    h("span", { class: "os-ws__mark", attrs: { "aria-hidden": "true" } }, icon("os-check", { size: 12, stroke: 2.4 })),
    h("span", { class: "os-ws__text" }, (wsName = h("span", { class: "os-ws__name", text: t("ws.default") })), h("span", { class: "os-ws__plan", text: t("ws.plan") })),
    icon("os-updown", { size: 14, stroke: 1.6 }));
  const wrap = menuButton({
    label: t("ws.menu"), trigger: btn, menuLabel: t("ws.menu"), align: "start",
    items: () => [
      h("div", { class: "os-menu__who" }, h("strong", { text: wsName.textContent }), h("span", { class: "os-muted", text: t("ws.plan") })),
      ...switchItems(),
      ctx.session?.admin ? { label: t("ws.settings"), icon: "settings", run: () => ctx.navigate("#/admin?tab=account") } : null,
      orgRole ? { label: t("ws.org"), icon: "layers", run: () => ctx.navigate("#/org") } : null,
      { label: t("start.verify"), icon: "shield-check", run: () => run("app.verify") },
      { label: t("help.about"), icon: "info", run: () => run("help.about") },
    ],
  });
  wrap.classList.add("os-ws-wrap");
  document.getElementById("ws-slot").replaceWith(wrap);
}

/// The other workspaces to switch to (docs/23 §2.3), under the organization's name when
/// the person belongs to more than one organization; nothing with a single workspace.
/// The current one is marked with a check and does nothing.
const spaceCount = () => (spaces?.organizations || []).reduce((n, o) => n + (o.workspaces?.length || 0), 0);
function switchItems() {
  const orgs = spaces?.organizations || [];
  if (spaceCount() < 2) return [];
  const out = [];
  for (const o of orgs) {
    out.push(h("div", { class: "os-menu__group", attrs: { "aria-hidden": "true" }, text: orgs.length > 1 ? o.name : t("ws.switch") }));
    for (const w of o.workspaces || []) {
      out.push({
        label: w.name, icon: w.current ? "check" : "layers",
        run: () => { if (!w.current) run("workspace.switch", w.id); },
      });
    }
  }
  out.push("separator");
  return out;
}

function helpItems() {
  return [
    { label: t("help.shortcuts"), icon: "keyboard", run: () => run("help.shortcuts") },
    { label: t("palette.label"), icon: "search", run: () => run("palette.open") },
    { label: t("start.verify"), icon: "shield-check", run: () => run("app.verify") },
    "separator",
    { label: t("help.about"), icon: "info", run: () => run("help.about") },
  ];
}

// ---- The phone drawer (UX-04) ------------------------------------------------------------
//
// Below 60em the sidebar is a drawer: a scrim behind it closes it on a tap, Escape closes
// it and returns focus to Menu, it starts under the top row, and while closed it is
// inert, so its links are not in the tab order. Opening another menu closes it.

function buildDrawer() {
  const menuBtn = document.getElementById("nav-toggle");
  const nav = document.getElementById("nav");
  const scrim = document.getElementById("nav-scrim");
  menuBtn.append(icon("menu", { size: 20 }));
  menuBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    if (document.body.classList.contains("nav-open")) closeNav(); else openNav();
  });
  scrim.addEventListener("click", () => closeNav(true));
  for (const a of document.querySelectorAll(".os-nav__link")) {
    a.prepend(icon(a.dataset.icon, { size: 16 }));
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
  document.documentElement.style.setProperty("--os-nav-top", `${Math.max(0, bar.getBoundingClientRect().bottom)}px`);
  document.body.classList.add("nav-open");
  document.getElementById("nav-toggle").setAttribute("aria-expanded", "true");
  document.getElementById("nav-scrim").hidden = false;
  nav.inert = false;
  // The drawer is modal: the screen under the scrim leaves the tab order and the
  // accessibility tree until it closes (WEB-17; axe target-size on the covered links).
  const content = document.getElementById("content");
  if (content) content.inert = true;
  nav.querySelector(".os-nav__link:not([hidden])")?.focus({ preventScroll: true });
}

function closeNav(focus = false) {
  const was = document.body.classList.contains("nav-open");
  document.body.classList.remove("nav-open");
  document.getElementById("nav-toggle")?.setAttribute("aria-expanded", "false");
  const scrim = document.getElementById("nav-scrim");
  if (scrim) scrim.hidden = true;
  const content = document.getElementById("content");
  if (content) content.inert = false;
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

// ---- A screen's text filter (Agreements) -----------------------------------------------------
//
// #top-search is shown at the top of the content card while the screen has set
// `ctx.onSearch` (dashboard.js filters through it); everything else searches with ⌘K.

function buildScreenSearch() {
  const form = document.getElementById("top-search-form");
  const search = document.getElementById("top-search");
  const box = h("span", { class: "os-screensearch__box" }, icon("os-search", { size: 16, stroke: 1.6 }));
  search.replaceWith(box);
  box.append(search);
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    ctx.onSearch?.(search.value.trim());
  });
  search.addEventListener("input", () => ctx.onSearch?.(search.value.trim()));
}

function syncScreenSearch() {
  const form = document.getElementById("top-search-form");
  form.hidden = !ctx.onSearch || document.body.classList.contains("is-chromeless");
  if (form.hidden) document.getElementById("top-search").value = "";
}

// ---- ⌘K: the command menu's own sections -----------------------------------------------------

const AGREEMENT_ICON = { draft: "file-pen-line", sent: "send", delivered: "eye", completing: "loader-circle", completed: "circle-check", declined: "circle-x", voided: "ban", expired: "clock" };

/// The command menu's built-in sections: Actions (from the command registry), and
/// Agreements (titles that match, from the envelope list; envelopes waiting for the
/// user's signature first, when the server can say which).
function registerPaletteSections() {
  const actions = (q) => {
    const go = (hash) => () => ctx.navigate(hash);
    const items = [
      { id: "new", label: t("palette.new"), icon: "plus", kbd: "N", run: () => run("envelope.new") },
      { id: "template", label: t("start.template"), icon: "layout-template", run: go("#/templates") },
      { id: "verify", label: t("start.verify"), icon: "shield-check", run: () => run("app.verify") },
      { id: "go-home", label: t("palette.go", { place: t("nav.home-link") }), icon: "house", run: go("#/home") },
      { id: "go-agreements", label: t("palette.go", { place: t("nav.agreements") }), icon: "os-agreements", run: go("#/agreements") },
      { id: "go-templates", label: t("palette.go", { place: t("nav.templates") }), icon: "os-grid", run: go("#/templates") },
      { id: "go-reports", label: t("palette.go", { place: t("nav.reports") }), icon: "os-bars", run: go("#/reports") },
      ctx.session?.admin ? { id: "go-admin", label: t("palette.go", { place: t("nav.admin") }), icon: "os-shield", run: go("#/admin") } : null,
      orgRole ? { id: "go-org", label: t("palette.go", { place: t("ws.org") }), icon: "layers", run: go("#/org") } : null,
      { id: "theme", label: t("cmd.theme"), icon: "moon", kbd: isMac() ? "⌘⇧L" : "Ctrl⇧L", run: () => run("theme.toggle") },
      { id: "keys", label: t("help.shortcuts"), icon: "keyboard", kbd: "?", run: () => run("help.shortcuts") },
    ].filter(Boolean);
    // Commands a screen registered (its own verbs), by their labels.
    const seen = new Set(["envelope.new", "theme.toggle", "help.shortcuts", "palette.open", "search.focus", "app.verify"]);
    for (const c of allCommands()) {
      if (seen.has(c.id) || !c.label || !c.id.includes(".") || /^(theme|account|help|field|edit|recipient)\./.test(c.id)) continue;
      if (c.enabled && !c.enabled()) continue;
      items.push({ id: `cmd:${c.id}`, label: c.label, icon: "arrow-right", run: () => run(c.id) });
    }
    const found = q ? items.filter((it) => matches(it.label, q)) : items.slice(0, 6);
    if (q) found.unshift({ id: "search-all", fallback: true, label: t("palette.search-all", { query: q }), icon: "os-search", run: () => ctx.navigate(`#/agreements?q=${encodeURIComponent(q)}`) });
    return found;
  };
  registerPaletteProvider({ id: "actions", title: t("palette.actions"), order: 10, sync: true, search: (q) => actions(q) });

  registerPaletteProvider({
    id: "agreements", title: t("palette.agreements"), order: 20,
    async search(q, signal) {
      if (!ctx.session) return [];
      const out = [];
      if (api.available("inbox")) {
        try {
          const box = await api.inbox({ limit: 5 });
          for (const e of box?.items || []) {
            if (q && !matches(e.subject, q)) continue;
            out.push({
              id: `sign:${e.id}`, label: t("palette.sign", { subject: e.subject || t("notify.untitled") }), icon: "pen-line",
              hint: t("palette.needs-you"), hintTone: "you",
              run: async () => { try { const r = await api.signLink(e.id); if (r?.url) location.href = r.url; } catch (err) { if (!ctx.failed(err)) toast(errorMessage(err), "error"); } },
            });
          }
        } catch { /* the Inbox is optional here */ }
      }
      if (signal?.aborted) return out;
      const page = await api.listEnvelopes(q ? { q, limit: 6 } : { sort: "updated_at", order: "desc", limit: 5 });
      for (const e of page?.items || []) {
        out.push({
          id: e.id, label: e.subject || t("notify.untitled"), icon: AGREEMENT_ICON[e.status] || "file-text",
          hint: t(`status.${e.status}`),
          run: () => ctx.navigate(e.status === "draft" ? `#/prepare/${encodeURIComponent(e.id)}` : `#/envelopes/${encodeURIComponent(e.id)}`),
        });
      }
      return out;
    },
  });
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

/// The count beside a section (canvas: the red count beside Inbox): a screen that has
/// read how many envelopes wait for this user's signature sets it (`ctx.setNavCount`);
/// the shell does not ask the server for it on every route. 0 removes it.
function setNavCount(nav, n) {
  const link = document.querySelector(`.os-nav__link[data-nav="${nav}"]`);
  if (!link) return;
  link.querySelector(".os-nav__count")?.remove();
  link.removeAttribute("aria-description");
  if (n > 0) {
    link.append(h("span", { class: "os-nav__count", attrs: { "aria-hidden": "true" }, text: String(n) }));
    link.setAttribute("aria-description", t("nav.waiting-you", { n }));
  }
}
ctx.setNavCount = setNavCount;

// ---- Who is signed in ----------------------------------------------------------------------

/// Who is signed in, for the avatar: an admin can read their own member record; anyone
/// else shows the account's initials.
const who = { name: "", email: "" };
let whoLoaded = false;

/// The sidebar's saved Views on any first screen (WEB-17), without counts. Agreements
/// and Home redraw them with live counts; this never overwrites what they drew.
async function drawNavViews() {
  if (document.getElementById("nav-views")?.childElementCount) return;
  const { renderNavViews } = await import("./agreementparts.js");
  if (!document.getElementById("nav-views")?.childElementCount) renderNavViews(ctx);
}
async function loadWho() {
  try {
    const account = await api.account().catch(() => null);
    if (account?.name && wsName) wsName.textContent = account.name;
    spaces = await api.workspaces().catch(() => null);
    orgRole = (await api.org.get().catch(() => null))?.role || null;
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
    if (!who.name) who.name = account?.name || "";
  } catch { /* the avatar falls back to a person icon */ }
  syncAvatar();
}

function syncAvatar() {
  const btn = document.getElementById("account-btn");
  const av = btn?.querySelector(".os-avatar");
  if (av) {
    // Initials drawn by CSS (data-initials), so the button's text is the name alone and its
    // accessible name, "<name>, Account", contains all of it (SC 2.5.3, label in name).
    av.textContent = "";
    if (initials(who.name)) av.dataset.initials = initials(who.name); else delete av.dataset.initials;
    btn.querySelector(".os-account__name").textContent = who.name || t("account.menu");
    btn.setAttribute("aria-label", who.name ? `${who.name}, ${t("account.menu")}` : t("account.menu"));
  }
}

// ---- Dialogs ---------------------------------------------------------------------------------

/// The Keyboard shortcuts panel (UX-04): every table, grouped by where it applies, one
/// row per action with its keys (aliases together), and ⌘ ⌥ ⇧ on a Mac.
function shortcutsDialog() {
  const mac = isMac();
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

const withChrome = () => !!ctx.session && !document.body.classList.contains("is-chromeless");

function registerCommands() {
  register("help.shortcuts", { label: t("help.shortcuts"), run: shortcutsDialog });
  register("help.about", { label: t("help.about"), run: aboutDialog });
  register("app.verify", { label: t("start.verify"), run: () => { location.href = mock ? "verify.html?mock=1" : "verify.html"; } });
  // ⌘K / Ctrl+K, the sidebar's "Search or jump to…" and "/" all open the command menu.
  register("palette.open", { label: t("palette.label"), run: () => { closeNav(); openPalette(); }, enabled: () => !!ctx.session });
  register("search.focus", { label: t("cmd.search"), run: () => run("palette.open"), enabled: withChrome });
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
  // Switch workspace (ORG-04): the server ends this session and starts one in the
  // other workspace; the whole app reloads so no screen keeps the old workspace's data.
  register("workspace.switch", {
    label: t("ws.switch"),
    // Offered only to a person with another workspace; from the command menu (no id)
    // it opens the workspace row's menu to choose one.
    enabled: () => spaceCount() > 1,
    run: async (accountId) => {
      if (!accountId) { document.getElementById("ws-btn")?.click(); return; }
      if (!(await panelMayClose())) return;
      try {
        await api.switchWorkspace(accountId);
      } catch (err) {
        toast(errorMessage(err), "error");
        return;
      }
      location.hash = "#/home";
      location.reload();
    },
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
  // ⌘K / Ctrl+K toggles the command menu from anywhere, even while typing.
  if ((e.metaKey || e.ctrlKey) && !e.altKey && !e.shiftKey && (e.key === "k" || e.key === "K")) {
    if (paletteOpen()) return; // the menu's own handler closes it
    if (document.querySelector("dialog[open]:not(.is-leaving)") || !command("palette.open")?.enabled()) return;
    e.preventDefault();
    run("palette.open");
    return;
  }
  if (document.querySelector("dialog[open]:not(.is-leaving)")) return;
  handle(e, ctx.contexts, isTyping(e));
});

initTheme();
buildChrome();
registerCommands();
registerPaletteSections();
window.addEventListener("hashchange", route);
route();
