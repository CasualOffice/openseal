// The sender app's shell (WEB-01): session, top bar, navigation, theme, routing,
// shortcuts. Screens are modules with `mount(container, ctx, params) → cleanup`.
//
// Routes (hash, so a static server needs no rewrites):
//   #/signin  #/agreements[?status=…]  #/envelopes/{id}  #/prepare  #/prepare/{id}

import { h, clear, isTyping } from "./dom.js";
import { icon } from "./icons.js";
import { t, applyI18n } from "./i18n.js";
import { createClient, isMockMode, ApiError, errorMessage } from "./api.js";
import { register, run, command } from "./commands.js";
import { handle, bindings } from "./keys.js";
import { button, openDialog, toast, errorState } from "./ui.js";
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
  [/^#\/agreements(?:\?.*)?$/, () => import("./dashboard.js"), { nav: "agreements" }],
  [/^#\/envelopes\/([^/?]+)$/, () => import("./envelope.js"), { nav: "agreements" }],
  [/^#\/prepare(?:\/([^/?]+))?$/, () => import("./prepare.js"), { nav: "send", wide: true }],
];

let cleanup = null;
let routeSeq = 0;

async function route() {
  const seq = ++routeSeq;
  const hash = location.hash || "#/agreements";
  const main = document.getElementById("main");
  if (!ctx.session && hash !== "#/signin") {
    try {
      ctx.session = await api.session();
    } catch (err) {
      ctx.session = null;
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
  if (!entry) { ctx.navigate("#/agreements"); return; }
  if (hash === "#/signin" && ctx.session) { ctx.navigate("#/agreements"); return; }
  const mod = await entry[1]();
  if (seq !== routeSeq) return;
  if (cleanup) { try { cleanup(); } catch { /* a screen's own teardown */ } cleanup = null; }
  ctx.contexts = ["global"];
  const opts = entry[2];
  document.body.classList.toggle("is-chromeless", opts.chrome === false);
  document.body.classList.toggle("is-wide", !!opts.wide);
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
    if (mock) a.href = a.getAttribute("href");
  }
  const newBtn = document.getElementById("nav-new");
  newBtn.replaceWith(button(t("nav.new"), { icon: "plus", variant: "primary", command: "envelope.new", onClick: () => ctx.navigate("#/prepare"), attrs: { id: "nav-new" } }));

  const themeBtn = document.getElementById("theme-btn");
  themeBtn.append(icon("sun"));
  themeBtn.addEventListener("click", () => run("theme.toggle"));
  syncThemeButton();

  const help = document.getElementById("help-btn");
  help.append(icon("keyboard"));
  help.addEventListener("click", () => run("help.shortcuts"));

  const acct = document.getElementById("account-btn");
  acct.append(icon("user"), icon("chevron-down", { size: 16 }));
  acct.addEventListener("click", () => toggleAccountMenu());
  document.addEventListener("click", (e) => {
    if (!e.target.closest?.("#account-menu, #account-btn")) closeAccountMenu();
  });
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

function toggleAccountMenu() {
  const menu = document.getElementById("account-menu");
  const btn = document.getElementById("account-btn");
  if (!menu.hidden) return closeAccountMenu();
  clear(menu);
  const item = (label, ic, cmd) => {
    const b = h("button", { type: "button", class: "os-menu__item", attrs: { role: "menuitem", tabindex: "-1" } }, icon(ic, { size: 16 }), h("span", { text: label }));
    b.addEventListener("click", () => { closeAccountMenu(); run(cmd); });
    return b;
  };
  menu.append(
    h("div", { class: "os-menu__who" },
      h("strong", { text: ctx.mock ? t("mock.user") : t("account.signed-in") }),
      h("span", { class: "os-muted", text: ctx.session?.user_id || "" })),
    item(t("theme.light"), "sun", "theme.light"),
    item(t("theme.dark"), "moon", "theme.dark"),
    item(t("theme.system"), "monitor", "theme.system"),
    item(t("help.shortcuts"), "keyboard", "help.shortcuts"),
    item(t("account.signout"), "log-out", "account.signout"),
  );
  menu.hidden = false;
  btn.setAttribute("aria-expanded", "true");
  const items = [...menu.querySelectorAll('[role="menuitem"]')];
  items[0].focus();
  menu.onkeydown = (e) => {
    const i = items.indexOf(document.activeElement);
    if (e.key === "ArrowDown") { e.preventDefault(); items[(i + 1) % items.length].focus(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); items[(i - 1 + items.length) % items.length].focus(); }
    else if (e.key === "Home") { e.preventDefault(); items[0].focus(); }
    else if (e.key === "End") { e.preventDefault(); items[items.length - 1].focus(); }
    else if (e.key === "Escape" || e.key === "Tab") { closeAccountMenu(); if (e.key === "Escape") btn.focus(); }
  };
}

function closeAccountMenu() {
  const menu = document.getElementById("account-menu");
  if (!menu || menu.hidden) return;
  menu.hidden = true;
  document.getElementById("account-btn").setAttribute("aria-expanded", "false");
}

function shortcutsDialog() {
  openDialog({
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
