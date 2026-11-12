// Admin (WEB-02; docs/47 §Screens "Admin"): the account's members and its API clients,
// over the endpoints the server has (`/api/v1/users`, `/api/v1/api-clients`). The rest
// of DocuSign's Admin (groups, permission profiles, SSO, brands, retention, webhooks,
// seal and TSA settings) waits for its endpoints and is not drawn (docs/47 principle 4).
//
// Access is the server's: a member without `admin:users` or `admin:account` gets
// CS-AUTH-0006, shown in place. A new API key or OAuth secret is shown once, in a
// dialog with a copy button, and never stored by the page.
//
// WEB-06 AD-01: invite a member by email (`POST /users` with `invite: true`), edit one
// (name, permission profile, disabled) in a side panel, and the account's settings and
// branding (`PATCH /accounts/me {settings}`) as cards whose Edit opens a side panel.
// Modals remain only for remove and revoke.
//
// WEB-10, against api/openapi.yaml and the server: a member's `permission_profile_id`
// is an id, named through the account's `settings.builtin_profiles`; the list has no
// invitation state, so it is read per local member (`GET /users/{id}`); the account's
// name is shown, not edited (the API has no rename).

import { h, clear } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { profileName, invitePending } from "./people.js";
import { button, emptyState, skeletonRows, errorState, openPanel, confirmDialog, toast, toastError, selectField, tabs, toggle } from "./ui/index.js";

const PROFILES = ["admin", "sender", "viewer"];
const SCOPES = ["envelopes:read", "envelopes:write", "envelopes:send", "templates:read", "templates:write"];
const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const HEX = /^#[0-9a-fA-F]{6}$/;
const TABS = ["users", "api", "account"];

export function mount(view, ctx, _match, params) {
  const want = params?.get("tab");
  const tab = TABS.includes(want) ? want : "users";
  view.append(h("div", { class: "os-page-head" }, h("h1", { class: "os-page-title", text: t("admin.title") })),
    tabs({
      label: t("admin.sections"),
      tabs: [{ id: "users", label: t("admin.users"), icon: "users" }, { id: "api", label: t("admin.api"), icon: "key-round" }, { id: "account", label: t("admin.account"), icon: "settings" }],
      current: tab,
      render: (id, panel) => { if (id === "users") users(panel, ctx); else if (id === "api") clients(panel, ctx); else account(panel, ctx); },
      onChange: (id) => history.replaceState(null, "", `${location.pathname}${location.search}${id === "users" ? "#/admin" : `#/admin?tab=${id}`}`),
    }));
}

// ---- Account: settings and branding (AD-01) ------------------------------------------

function account(panel, ctx) {
  const box = h("div", { class: "os-admin-cards", attrs: { "aria-busy": "true" } }, skeletonRows(2));
  panel.append(box);
  let acct = null;

  async function load() {
    try {
      acct = await ctx.api.account();
      box.removeAttribute("aria-busy");
      render();
    } catch (err) {
      box.removeAttribute("aria-busy");
      if (ctx.failed(err)) return;
      errorState(box, err, load);
    }
  }
  const s = () => acct?.settings || {};
  const row = (label, value) => [h("dt", { text: label }), h("dd", { text: value === "" || value == null ? t("admin.not-set") : String(value) })];

  function render() {
    clear(box);
    const b = s().branding || {};
    const swatch = HEX.test(b.color || "") ? h("span", { class: "os-swatch", attrs: { "aria-hidden": "true" } }) : null;
    if (swatch) swatch.style.background = b.color;
    box.append(
      card("settings", t("admin.settings"), t("admin.settings-lede"), t("admin.edit-settings"), editSettings,
        h("dl", { class: "os-meta" },
          row(t("admin.account-name"), acct.name),
          row(t("admin.expiry-days"), s().default_expiry_days),
          row(t("admin.reminder-days"), s().first_reminder_days ? s().first_reminder_days : t("admin.reminder-none")))),
      card("branding", t("admin.branding"), t("admin.branding-lede"), t("admin.edit-branding"), editBranding,
        h("dl", { class: "os-meta" },
          row(t("admin.brand-name"), b.name),
          h("dt", { text: t("admin.brand-color") }), h("dd", { class: "os-swatchrow" }, swatch, h("span", { text: b.color || t("admin.not-set") })))));
  }
  function card(id, title, lede, editLabel, onEdit, ...body) {
    return h("section", { class: "os-card", attrs: { "aria-labelledby": `acct-${id}-h`, "data-testid": `account-${id}` } },
      h("div", { class: "os-card__head" },
        h("h2", { id: `acct-${id}-h`, class: "os-card__title", text: title }),
        button(editLabel, { icon: "pencil", size: "sm", onClick: onEdit })),
      h("p", { class: "os-muted os-small", text: lede }), ...body);
  }

  async function editSettings() {
    const f = {};
    const ok = await openPanel({
      id: "account-settings",
      title: t("admin.settings"),
      description: t("admin.settings-lede"),
      build(body) {
        f.expiry = h("input", { id: "a-expiry", class: "os-input", type: "number", min: "1", max: "365", step: "1", value: s().default_expiry_days ?? "", attrs: { autofocus: true } });
        f.remind = h("input", { id: "a-remind", class: "os-input", type: "number", min: "0", max: "60", step: "1", value: s().first_reminder_days ?? "" });
        f.err = h("p", { class: "os-field-error", attrs: { role: "alert" } });
        body.append(
          h("p", { class: "os-label", text: t("admin.account-name") }), h("p", { class: "os-muted", attrs: { "data-testid": "account-name" }, text: acct.name || t("admin.not-set") }),
          h("label", { class: "os-label", attrs: { for: "a-expiry" }, text: t("admin.expiry-days") }), f.expiry,
          h("label", { class: "os-label", attrs: { for: "a-remind" }, text: t("admin.reminder-days") }), f.remind, f.err);
      },
      actions: [
        { label: t("action.cancel"), value: null },
        {
          label: t("templates.save"), variant: "primary",
          onClick: async () => {
            const expiry = f.expiry.value === "" ? null : Number.parseInt(f.expiry.value, 10);
            const remind = f.remind.value === "" ? null : Number.parseInt(f.remind.value, 10);
            if (expiry != null && !(expiry >= 1 && expiry <= 365)) { f.err.textContent = t("admin.need-days"); f.expiry.focus(); return undefined; }
            const out = await ctx.api.patchAccountSettings({ default_expiry_days: expiry, first_reminder_days: remind || null });
            acct = { ...acct, settings: out?.settings || acct.settings };
            return true;
          },
        },
      ],
    });
    if (ok) { toast(t("admin.settings-saved"), "success"); render(); }
  }

  async function editBranding() {
    const f = {};
    const b = s().branding || {};
    const ok = await openPanel({
      id: "account-branding",
      title: t("admin.branding"),
      description: t("admin.branding-lede"),
      build(body) {
        f.name = h("input", { id: "b-name", class: "os-input", value: b.name || "", maxLength: 255, attrs: { autofocus: true } });
        f.color = h("input", { id: "b-color", class: "os-input os-input--mono", value: b.color || "", maxLength: 7, placeholder: "#b3141f", attrs: { "aria-describedby": "b-color-help b-err" } });
        f.err = h("p", { id: "b-err", class: "os-field-error", attrs: { role: "alert" } });
        body.append(
          h("label", { class: "os-label", attrs: { for: "b-name" }, text: t("admin.brand-name") }), f.name,
          h("label", { class: "os-label", attrs: { for: "b-color" }, text: t("admin.brand-color") }), f.color,
          h("p", { id: "b-color-help", class: "os-help", text: t("admin.brand-color-help") }), f.err);
      },
      actions: [
        { label: t("action.cancel"), value: null },
        {
          label: t("templates.save"), variant: "primary",
          onClick: async () => {
            const color = f.color.value.trim();
            if (color && !HEX.test(color)) { f.err.textContent = t("admin.need-color"); f.color.setAttribute("aria-invalid", "true"); f.color.focus(); return undefined; }
            const out = await ctx.api.patchAccountSettings({ branding: { name: f.name.value.trim(), color: color.toLowerCase() } });
            acct = { ...acct, settings: out?.settings || acct.settings };
            return true;
          },
        },
      ],
    });
    if (ok) { toast(t("admin.settings-saved"), "success"); render(); }
  }

  load();
}

// ---- Members ---------------------------------------------------------------------------

function users(panel, ctx) {
  let builtin = {};
  const list = h("div", { class: "os-list os-surface-card", attrs: { "aria-live": "polite" } });
  panel.append(h("div", { class: "os-panel__head os-panel__head--page" },
    h("h2", { class: "os-card__title", text: t("admin.users") }),
    h("div", { class: "os-actions" },
      button(t("admin.add-user"), { icon: "user-plus", onClick: add }),
      button(t("admin.invite"), { icon: "mail", variant: "primary", onClick: invite }))), list);

  async function load() {
    clear(list);
    list.setAttribute("aria-busy", "true");
    list.append(skeletonRows(3));
    try {
      const [page, acct] = await Promise.all([ctx.api.users.list(), ctx.api.account().catch(() => null)]);
      builtin = acct?.settings?.builtin_profiles || {};
      const items = page.items || [];
      // The list carries no invitation state; a single read does. Local members who are
      // not disabled, at most 100, in parallel; one that fails just shows no Resend.
      await Promise.all(items.filter((u) => u.login_kind === "local" && !u.disabled && !("invitation" in u)).slice(0, 100)
        .map(async (u) => { try { u.invitation = (await ctx.api.users.get(u.id))?.invitation ?? null; } catch { u.invitation = null; } }));
      list.removeAttribute("aria-busy");
      render(items);
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
    const table = h("table", { class: "os-table os-table--rows os-table--cards" },
      h("caption", { class: "os-sr-only", text: t("admin.users") }),
      h("thead", {}, h("tr", {},
        h("th", { attrs: { scope: "col" }, text: t("prepare.name") }),
        h("th", { attrs: { scope: "col" }, text: t("prepare.email") }),
        h("th", { attrs: { scope: "col" }, class: "os-col-date", text: t("admin.profile") }),
        h("th", { attrs: { scope: "col" }, class: "os-col-date", text: t("admin.col.status") }),
        h("th", { attrs: { scope: "col" }, class: "os-col-actions", text: t("templates.col.actions") }))));
    const tb = h("tbody");
    for (const u of items) {
      const me = u.id === ctx.session?.user_id;
      const profile = profileName(u, builtin);
      const state = u.disabled ? "disabled" : invitePending(u) ? "pending" : "active";
      tb.append(h("tr", { attrs: { "data-id": u.id } },
        h("td", {}, h("strong", { text: u.name || "—" }), me ? h("span", { class: "os-muted os-small", text: ` ${t("admin.you")}` }) : null),
        h("td", { class: "os-muted os-col-email", text: u.email || "" }),
        h("td", { class: "os-col-date", attrs: { "data-label": t("admin.profile") }, text: PROFILES.includes(profile) ? t(`admin.profile.${profile}`) : profile || "—" }),
        h("td", { class: "os-col-date", attrs: { "data-label": t("admin.col.status") } }, h("span", { class: `os-badge os-badge--user-${state}`, text: t(`admin.${state}`) })),
        h("td", { class: "os-col-actions" }, h("div", { class: "os-actions os-actions--row" },
          button(t("admin.edit"), { icon: "pencil", size: "sm", attrs: { "aria-label": t("admin.edit-named", { name: u.name || u.email }) }, onClick: () => edit(u, me) }),
          invitePending(u) ? button(t("admin.reinvite"), { icon: "mail", size: "sm", attrs: { "aria-label": t("admin.reinvite-named", { email: u.email }) }, onClick: () => reinvite(u) }) : null,
          me ? null : button(t("admin.remove"), { icon: "trash-2", size: "sm", variant: "danger", attrs: { "aria-label": t("admin.remove-named", { name: u.name }) }, onClick: () => remove(u) })))));
    }
    table.append(tb);
    list.append(h("div", { class: "os-table-wrap" }, table));
  }

  async function add() {
    const f = {};
    const created = await openPanel({
      title: t("admin.add-user"),
      build(body) {
        f.name = h("input", { id: "u-name", class: "os-input", maxLength: 255, autocomplete: "off", attrs: { autofocus: true } });
        f.email = h("input", { id: "u-email", class: "os-input", type: "email", autocomplete: "off" });
        const profile = selectField(t("admin.profile"), PROFILES.map((p) => [p, t(`admin.profile.${p}`)]), { id: "u-profile", value: "sender" });
        f.profile = profile.select;
        f.password = h("input", { id: "u-password", class: "os-input", type: "password", autocomplete: "new-password", maxLength: 256, attrs: { "aria-describedby": "u-password-help" } });
        f.err = h("p", { class: "os-field-error", attrs: { role: "alert" } });
        body.append(
          h("label", { class: "os-label", attrs: { for: "u-name" }, text: t("prepare.name") }), f.name,
          h("label", { class: "os-label", attrs: { for: "u-email" }, text: t("prepare.email") }), f.email,
          profile.el,
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

  /// Edit a member in a side panel (AD-01): name, permission profile, disabled. Your
  /// own profile and sign-in are not yours to remove, so those two are fixed for you.
  async function edit(u, me) {
    const f = {};
    const v = await openPanel({
      id: "user-edit",
      title: t("admin.edit-title"),
      description: u.email || null,
      build(body) {
        f.name = h("input", { id: "u-name-e", class: "os-input", value: u.name || "", maxLength: 255, attrs: { autofocus: true, "aria-describedby": "u-err-e" } });
        const profile = selectField(t("admin.profile"), PROFILES.map((p) => [p, t(`admin.profile.${p}`)]), { id: "u-profile-e", value: profileName(u, builtin) || "sender" });
        f.profile = profile.select;
        f.profile.disabled = me;
        const dis = toggle(t("admin.disable"), { id: "u-disabled-e", checked: !!u.disabled });
        f.disabled = dis.input;
        f.disabled.disabled = me;
        f.disabled.setAttribute("aria-describedby", "u-disabled-help");
        f.err = h("p", { id: "u-err-e", class: "os-field-error", attrs: { role: "alert" } });
        body.append(
          h("label", { class: "os-label", attrs: { for: "u-name-e" }, text: t("prepare.name") }), f.name, f.err,
          profile.el,
          h("div", { class: "os-switchrow" }, dis.el, h("p", { id: "u-disabled-help", class: "os-help", text: t("admin.disable-help") })));
      },
      actions: [
        { label: t("action.cancel"), value: null },
        {
          label: t("templates.save"), variant: "primary",
          onClick: async () => {
            const name = f.name.value.trim();
            if (!name) { f.err.textContent = t("form.required"); f.name.setAttribute("aria-invalid", "true"); f.name.focus(); return undefined; }
            // The name only when changed: a member of another account too keeps theirs (SEC-ID-01).
            const named = name !== u.name ? { name } : {};
            await ctx.api.users.patch(u.id, me ? named : { ...named, profile: f.profile.value, disabled: f.disabled.checked });
            return true;
          },
        },
      ],
    });
    if (v) { toast(t("admin.user-saved"), "success"); load(); }
  }

  /// Invite by email (AD-01): the server sends a link to set up their sign-in.
  async function invite() {
    const f = {};
    const done = await openPanel({
      id: "user-invite",
      title: t("admin.invite"),
      description: t("admin.invite-help"),
      build(body) {
        f.email = h("input", { id: "i-email", class: "os-input", type: "email", autocomplete: "off", attrs: { autofocus: true, "aria-describedby": "i-err" } });
        f.name = h("input", { id: "i-name", class: "os-input", maxLength: 255, autocomplete: "off" });
        const profile = selectField(t("admin.profile"), PROFILES.map((p) => [p, t(`admin.profile.${p}`)]), { id: "i-profile", value: "sender" });
        f.profile = profile.select;
        f.err = h("p", { id: "i-err", class: "os-field-error", attrs: { role: "alert" } });
        body.append(
          h("label", { class: "os-label", attrs: { for: "i-email" }, text: t("prepare.email") }), f.email, f.err,
          h("label", { class: "os-label", attrs: { for: "i-name" }, text: t("prepare.name") }), f.name,
          profile.el);
      },
      actions: [
        { label: t("action.cancel"), value: null },
        {
          label: t("admin.invite"), variant: "primary", icon: "mail",
          onClick: async () => {
            const email = f.email.value.trim();
            const name = f.name.value.trim();
            for (const el of [f.email, f.name]) el.removeAttribute("aria-invalid");
            // The server needs both (UserCreate: email, name, profile).
            const bad = !EMAIL.test(email) ? [f.email, t("admin.need-email")] : !name ? [f.name, t("form.required")] : null;
            if (bad) { f.err.textContent = bad[1]; bad[0].setAttribute("aria-invalid", "true"); bad[0].focus(); return undefined; }
            await ctx.api.users.invite({ email, name, profile: f.profile.value });
            return email;
          },
        },
      ],
    });
    if (done) { toast(t("admin.invited", { email: done }), "success"); load(); }
  }

  async function reinvite(u) {
    try { await ctx.api.users.reinvite(u.id); toast(t("admin.reinvited", { email: u.email }), "success"); } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }

  async function remove(u) {
    if (!(await confirmDialog(t("admin.remove-title"), t("admin.remove-text", { name: u.name }), { confirm: t("admin.remove"), danger: true }))) return;
    try { await ctx.api.users.remove(u.id); toast(t("admin.user-removed"), "success"); load(); } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }

  load();
}

// ---- API clients -------------------------------------------------------------------------

function clients(panel, ctx) {
  const list = h("div", { class: "os-list os-surface-card", attrs: { "aria-live": "polite" } });
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
    const table = h("table", { class: "os-table os-table--rows os-table--cards" },
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
        h("td", { class: "os-col-date os-muted os-small", attrs: { "data-label": t("admin.scopes") }, text: (c.scopes || []).join(", ") }),
        h("td", { class: "os-col-actions" }, c.revoked ? null : button(t("admin.revoke"), { icon: "ban", size: "sm", variant: "danger", attrs: { "aria-label": t("admin.revoke-named", { name: c.name }) }, onClick: () => revoke(c) }))));
    }
    table.append(tb);
    list.append(h("div", { class: "os-table-wrap" }, table));
  }

  async function add() {
    const f = { scopes: [] };
    const created = await openPanel({
      title: t("admin.add-client"),
      build(body) {
        f.name = h("input", { id: "c-name", class: "os-input", maxLength: 255, autocomplete: "off", attrs: { autofocus: true } });
        const kind = selectField(t("admin.kind"), [["api_key", t("admin.kind.api_key")], ["oauth_app", t("admin.kind.oauth_app")]], { id: "c-kind" });
        f.kind = kind.select;
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
          kind.el,
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
  return openPanel({
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
