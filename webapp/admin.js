// Admin (WEB-02; docs/47 §Screens "Admin"): the account's members and its API clients,
// over the endpoints the server has (`/api/v1/users`, `/api/v1/api-clients`). The rest
// of DocuSign's Admin (groups, permission profiles, SSO, brands, retention, webhooks,
// seal and TSA settings) waits for its endpoints and is not drawn (docs/47 principle 4).
//
// Access is the server's: a member without `admin:users` or `admin:account` gets
// CS-AUTH-0006, shown in place. A new API key or OAuth secret is shown once, in a
// dialog with a copy button, and never stored by the page.

import { h, clear } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { button, emptyState, skeletonRows, errorState, openDialog, confirmDialog, toast, toastError } from "./ui.js";

const PROFILES = ["admin", "sender", "viewer"];
const SCOPES = ["envelopes:read", "envelopes:write", "envelopes:send", "templates:read", "templates:write"];
const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

export function mount(view, ctx, _match, params) {
  const tab = params?.get("tab") === "api" ? "api" : "users";
  const tabs = h("div", { class: "os-tabs", attrs: { role: "tablist", "aria-label": t("admin.sections") } });
  const panel = h("div", { class: "os-tabpanel", attrs: { role: "tabpanel", id: "admin-panel", tabindex: "0" } });
  const names = { users: t("admin.users"), api: t("admin.api") };
  const btns = {};
  for (const key of ["users", "api"]) {
    const b = h("button", { type: "button", class: "os-tab", id: `admin-tab-${key}`, attrs: { role: "tab", "aria-selected": String(key === tab), "aria-controls": "admin-panel", tabindex: key === tab ? "0" : "-1" } },
      icon(key === "users" ? "users" : "key-round", { size: 16 }), h("span", { text: names[key] }));
    b.addEventListener("click", () => ctx.navigate(key === "users" ? "#/admin" : "#/admin?tab=api"));
    b.addEventListener("keydown", (e) => {
      if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
        e.preventDefault();
        const other = key === "users" ? "api" : "users";
        btns[other].focus();
        btns[other].click();
      }
    });
    btns[key] = b;
    tabs.append(b);
  }
  panel.setAttribute("aria-labelledby", `admin-tab-${tab}`);
  view.append(h("div", { class: "os-page-head" }, h("h1", { class: "os-page-title", text: t("admin.title") })), tabs, panel);
  if (tab === "users") users(panel, ctx); else clients(panel, ctx);
}

// ---- Members ---------------------------------------------------------------------------

function users(panel, ctx) {
  const list = h("div", { class: "os-list", attrs: { "aria-live": "polite" } });
  panel.append(h("div", { class: "os-panel__head os-panel__head--page" },
    h("h2", { class: "os-card__title", text: t("admin.users") }),
    button(t("admin.add-user"), { icon: "user-plus", variant: "primary", onClick: add })), list);

  async function load() {
    clear(list);
    list.setAttribute("aria-busy", "true");
    list.append(skeletonRows(3));
    try {
      const page = await ctx.api.users.list();
      list.removeAttribute("aria-busy");
      render(page.items || []);
    } catch (err) {
      list.removeAttribute("aria-busy");
      if (ctx.failed(err)) return;
      errorState(list, err, load);
    }
  }

  function render(items) {
    clear(list);
    if (!items.length) {
      list.append(emptyState({ illus: "recipients", title: t("empty.users.title"), text: t("empty.users.text"), action: button(t("admin.add-user"), { icon: "user-plus", variant: "primary", onClick: add }), testId: "empty-users" }));
      return;
    }
    const table = h("table", { class: "os-table os-table--rows" },
      h("caption", { class: "os-sr-only", text: t("admin.users") }),
      h("thead", {}, h("tr", {},
        h("th", { attrs: { scope: "col" }, text: t("prepare.name") }),
        h("th", { attrs: { scope: "col" }, text: t("prepare.email") }),
        h("th", { attrs: { scope: "col" }, class: "os-col-date", text: t("admin.profile") }),
        h("th", { attrs: { scope: "col" }, class: "os-col-actions", text: t("templates.col.actions") }))));
    const tb = h("tbody");
    for (const u of items) {
      const me = u.id === ctx.session?.user_id;
      const profile = String(u.permission_profile_id || "").replace(/^profile-/, "");
      tb.append(h("tr", { attrs: { "data-id": u.id } },
        h("td", {}, h("strong", { text: u.name || "—" }), me ? h("span", { class: "os-muted os-small", text: ` ${t("admin.you")}` }) : null),
        h("td", { class: "os-muted", text: u.email || "" }),
        h("td", { class: "os-col-date", text: PROFILES.includes(profile) ? t(`admin.profile.${profile}`) : profile || "—" }),
        h("td", { class: "os-col-actions" }, h("div", { class: "os-actions os-actions--row" },
          button(t("templates.rename"), { icon: "pencil", size: "sm", attrs: { "aria-label": t("admin.rename-named", { name: u.name }) }, onClick: () => rename(u) }),
          me ? null : button(t("admin.remove"), { icon: "trash-2", size: "sm", variant: "danger", attrs: { "aria-label": t("admin.remove-named", { name: u.name }) }, onClick: () => remove(u) })))));
    }
    table.append(tb);
    list.append(h("div", { class: "os-table-wrap" }, table));
  }

  async function add() {
    const f = {};
    const created = await openDialog({
      title: t("admin.add-user"),
      build(body) {
        f.name = h("input", { id: "u-name", class: "os-input", maxLength: 255, autocomplete: "off", attrs: { autofocus: true } });
        f.email = h("input", { id: "u-email", class: "os-input", type: "email", autocomplete: "off" });
        f.profile = h("select", { id: "u-profile", class: "os-input" }, ...PROFILES.map((p) => h("option", { value: p, text: t(`admin.profile.${p}`), selected: p === "sender" })));
        f.password = h("input", { id: "u-password", class: "os-input", type: "password", autocomplete: "new-password", maxLength: 256, attrs: { "aria-describedby": "u-password-help" } });
        f.err = h("p", { class: "os-field-error", attrs: { role: "alert" } });
        body.append(
          h("label", { class: "os-label", attrs: { for: "u-name" }, text: t("prepare.name") }), f.name,
          h("label", { class: "os-label", attrs: { for: "u-email" }, text: t("prepare.email") }), f.email,
          h("label", { class: "os-label", attrs: { for: "u-profile" }, text: t("admin.profile") }), f.profile,
          h("label", { class: "os-label", attrs: { for: "u-password" }, text: t("admin.password") }), f.password,
          h("p", { id: "u-password-help", class: "os-muted os-small", text: t("admin.password-help") }), f.err);
      },
      actions: [
        { label: t("action.cancel"), value: null },
        {
          label: t("admin.add-user"),
          variant: "primary",
          onClick: async () => {
            const name = f.name.value.trim();
            const email = f.email.value.trim();
            const password = f.password.value;
            const bad = !name ? [f.name, t("form.required")] : !EMAIL.test(email) ? [f.email, t("admin.need-email")] : password && password.length < 12 ? [f.password, t("admin.password-help")] : null;
            if (bad) { f.err.textContent = bad[1]; bad[0].setAttribute("aria-invalid", "true"); bad[0].focus(); return undefined; }
            return ctx.api.users.create({ name, email, profile: f.profile.value, ...(password ? { password } : {}) });
          },
        },
      ],
    });
    if (!created) return;
    toast(t("admin.user-added"), "success");
    load();
  }

  async function rename(u) {
    let input;
    const v = await openDialog({
      title: t("admin.rename-named", { name: u.name }),
      build(body) {
        input = h("input", { id: "u-rename", class: "os-input", value: u.name || "", maxLength: 255, attrs: { autofocus: true } });
        body.append(h("label", { class: "os-label", attrs: { for: "u-rename" }, text: t("prepare.name") }), input);
      },
      actions: [
        { label: t("action.cancel"), value: null },
        { label: t("templates.rename"), variant: "primary", onClick: async () => { const n = input.value.trim(); if (!n) { input.setAttribute("aria-invalid", "true"); input.focus(); return undefined; } await ctx.api.users.patch(u.id, { name: n }); return n; } },
      ],
    });
    if (v) { toast(t("admin.user-renamed"), "success"); load(); }
  }

  async function remove(u) {
    if (!(await confirmDialog(t("admin.remove-title"), t("admin.remove-text", { name: u.name }), { confirm: t("admin.remove"), danger: true }))) return;
    try { await ctx.api.users.remove(u.id); toast(t("admin.user-removed"), "success"); load(); } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }

  load();
}

// ---- API clients -------------------------------------------------------------------------

function clients(panel, ctx) {
  const list = h("div", { class: "os-list", attrs: { "aria-live": "polite" } });
  panel.append(h("div", { class: "os-panel__head os-panel__head--page" },
    h("h2", { class: "os-card__title", text: t("admin.api") }),
    button(t("admin.add-client"), { icon: "plus", variant: "primary", onClick: add })), list);

  async function load() {
    clear(list);
    list.setAttribute("aria-busy", "true");
    list.append(skeletonRows(3));
    try {
      const page = await ctx.api.apiClients.list();
      list.removeAttribute("aria-busy");
      render(page.items || []);
    } catch (err) {
      list.removeAttribute("aria-busy");
      if (ctx.failed(err)) return;
      errorState(list, err, load);
    }
  }

  function render(items) {
    clear(list);
    if (!items.length) {
      list.append(emptyState({ illus: "keys", title: t("empty.clients.title"), text: t("empty.clients.text"), action: button(t("admin.add-client"), { icon: "plus", variant: "primary", onClick: add }), testId: "empty-clients" }));
      return;
    }
    const table = h("table", { class: "os-table os-table--rows" },
      h("caption", { class: "os-sr-only", text: t("admin.api") }),
      h("thead", {}, h("tr", {},
        h("th", { attrs: { scope: "col" }, text: t("prepare.name") }),
        h("th", { attrs: { scope: "col" }, text: t("admin.kind") }),
        h("th", { attrs: { scope: "col" }, class: "os-col-date", text: t("admin.scopes") }),
        h("th", { attrs: { scope: "col" }, class: "os-col-actions", text: t("templates.col.actions") }))));
    const tb = h("tbody");
    for (const c of items) {
      tb.append(h("tr", { attrs: { "data-id": c.id } },
        h("td", {}, h("strong", { text: c.name || "—" }), c.key_prefix ? h("code", { class: "os-muted os-small", text: ` ${c.key_prefix}…` }) : null),
        h("td", {}, c.revoked
          ? h("span", { class: "os-badge os-badge--voided" }, icon("ban", { size: 16 }), h("span", { text: t("admin.revoked") }))
          : h("span", { text: t(c.kind === "api_key" ? "admin.kind.api_key" : "admin.kind.oauth_app") })),
        h("td", { class: "os-col-date os-muted os-small", text: (c.scopes || []).join(", ") }),
        h("td", { class: "os-col-actions" }, c.revoked ? null : button(t("admin.revoke"), { icon: "ban", size: "sm", variant: "danger", attrs: { "aria-label": t("admin.revoke-named", { name: c.name }) }, onClick: () => revoke(c) }))));
    }
    table.append(tb);
    list.append(h("div", { class: "os-table-wrap" }, table));
  }

  async function add() {
    const f = { scopes: [] };
    const created = await openDialog({
      title: t("admin.add-client"),
      build(body) {
        f.name = h("input", { id: "c-name", class: "os-input", maxLength: 255, autocomplete: "off", attrs: { autofocus: true } });
        f.kind = h("select", { id: "c-kind", class: "os-input" },
          h("option", { value: "api_key", text: t("admin.kind.api_key") }),
          h("option", { value: "oauth_app", text: t("admin.kind.oauth_app") }));
        f.days = h("input", { id: "c-days", class: "os-input", type: "number", min: "1", max: "3650", step: "1", value: "365" });
        const scopes = h("fieldset", { class: "os-fieldset" }, h("legend", { class: "os-label", text: t("admin.scopes") }));
        for (const s of SCOPES) {
          const id = `c-scope-${s.replace(":", "-")}`;
          const box = h("input", { id, type: "checkbox", value: s, checked: s.startsWith("envelopes:") });
          f.scopes.push(box);
          scopes.append(h("label", { class: "os-check", attrs: { for: id } }, box, h("code", { text: s })));
        }
        f.err = h("p", { class: "os-field-error", attrs: { role: "alert" } });
        body.append(
          h("label", { class: "os-label", attrs: { for: "c-name" }, text: t("prepare.name") }), f.name,
          h("label", { class: "os-label", attrs: { for: "c-kind" }, text: t("admin.kind") }), f.kind,
          scopes,
          h("label", { class: "os-label", attrs: { for: "c-days" }, text: t("admin.expires-days") }), f.days, f.err);
      },
      actions: [
        { label: t("action.cancel"), value: null },
        {
          label: t("admin.create"),
          variant: "primary",
          onClick: async () => {
            const name = f.name.value.trim();
            const scopes = f.scopes.filter((b) => b.checked).map((b) => b.value);
            const days = Number.parseInt(f.days.value, 10);
            if (!name) { f.err.textContent = t("form.required"); f.name.focus(); return undefined; }
            if (!scopes.length) { f.err.textContent = t("admin.need-scope"); f.scopes[0].focus(); return undefined; }
            if (!(days >= 1 && days <= 3650)) { f.err.textContent = t("admin.need-days"); f.days.focus(); return undefined; }
            return ctx.api.apiClients.create({ name, kind: f.kind.value, scopes, expires_in_days: days });
          },
        },
      ],
    });
    if (!created) return;
    await showSecret(created);
    load();
  }

  async function revoke(c) {
    if (!(await confirmDialog(t("admin.revoke-title"), t("admin.revoke-text", { name: c.name }), { confirm: t("admin.revoke"), danger: true }))) return;
    try { await ctx.api.apiClients.revoke(c.id); toast(t("admin.revoked-done"), "success"); load(); } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }

  load();
}

/// The one time a secret is shown: what to copy, and that it will not be shown again.
function showSecret(c) {
  const rows = c.key ? [[t("admin.key"), c.key]] : [[t("admin.client-id"), c.client_id], [t("admin.client-secret"), c.client_secret]];
  return openDialog({
    title: t("admin.secret-title"),
    description: t("admin.secret-text"),
    build(body) {
      for (const [label, value] of rows) {
        if (!value) continue;
        const id = `secret-${label.replace(/\W+/g, "-").toLowerCase()}`;
        const input = h("input", { id, class: "os-input os-input--mono", value, readOnly: true, attrs: { "data-testid": "secret-value" } });
        const copy = button(t("admin.copy"), { icon: "copy", size: "sm", onClick: async () => {
          try { await navigator.clipboard.writeText(value); toast(t("admin.copied"), "success"); } catch { input.select(); toast(t("admin.copy-manually"), "info"); }
        } });
        body.append(h("label", { class: "os-label", attrs: { for: id }, text: label }), h("div", { class: "os-copyrow" }, input, copy));
      }
    },
    actions: [{ label: t("admin.secret-done"), variant: "primary", value: true }],
  });
}
