// Admin (WEB-02, UX-08; docs/47 §Screens "Admin"): a section rail after DocuSign
// eSignature Admin (Account, Users and groups, Integrations, Security), a select in its
// place below 37.5em. Sections drawn over the endpoints the server has: the account's
// settings and branding (`/accounts/me`), its members (`/users`), webhooks
// (`/webhooks`, deliveries) and API clients (`/api-clients`). The sections still
// waiting for their endpoints (signing and sending, ERSD, retention, groups,
// permission profiles, SSO, seal and timestamp, the admin audit log) are rows in the
// rail that say so, never hidden (adminmodel.js `SECTIONS`).
//
// Access is the server's: a member without the scope gets CS-AUTH-0006, shown in place.
// A new API key or OAuth secret is shown once, in a panel only "I have copied it"
// closes (no close button, not Escape, not navigating away), and never stored.
// A webhook's signing secret never passes through the API (docs/40 §4): the panel
// names the operator's secrets, so there is nothing to show once.
//
// Calls the server does not serve yet (api.js `NOT_ON_SERVER`: pause and resume a
// webhook, a test event, redelivery) are offered all the same; against a server
// without them they answer CS-NET-0002, "not available on this server yet".
//
// WEB-10, against api/openapi.yaml and the server: a member's `permission_profile_id`
// is an id, named through the account's `settings.builtin_profiles`; the list has no
// invitation state, so it is read per local member (`GET /users/{id}`); the account's
// name is shown, not edited (the API has no rename).

import { h, clear, fmtDate } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { WEBHOOK_EVENT_TYPES } from "./api.js";
import { register, unregisterPrefix } from "./commands.js";
import { profileName } from "./people.js";
import { SECTIONS, GROUPS, sectionFrom, SCOPE_GROUPS, eventGroups, parseSecretRefs, expiryState, userState, filterUsers, contrastRatio } from "./adminmodel.js";
import { button, emptyState, skeletonRows, errorState, openPanel, confirmDialog, toast, toastError, selectField, toggle, menuButton, checkbox } from "./ui/index.js";

const PROFILES = ["admin", "sender", "viewer"];
const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const HEX = /^#[0-9a-fA-F]{6}$/;

/// The section names, written out so the strings check finds every key.
const TITLE = {
  account: () => t("admin.account"), signing: () => t("admin.sec.signing"), ersd: () => t("admin.sec.ersd"), retention: () => t("admin.sec.retention"),
  users: () => t("admin.users"), groups: () => t("admin.sec.groups"), profiles: () => t("admin.sec.profiles"),
  webhooks: () => t("admin.webhooks"), api: () => t("admin.api"),
  sso: () => t("admin.sec.sso"), seal: () => t("admin.sec.seal"), audit: () => t("admin.sec.audit"),
};
const GROUP = { account: () => t("admin.group.account"), people: () => t("admin.group.people"), integrations: () => t("admin.group.integrations"), security: () => t("admin.group.security") };
const WAITS = {
  signing: () => t("admin.wait.signing"), ersd: () => t("admin.wait.ersd"), retention: () => t("admin.wait.retention"),
  groups: () => t("admin.wait.groups"), profiles: () => t("admin.wait.profiles"),
  sso: () => t("admin.wait.sso"), seal: () => t("admin.wait.seal"), audit: () => t("admin.wait.audit"),
};
const href = (id) => (id === "users" ? "#/admin" : `#/admin?section=${id}`);

export function mount(view, ctx, _match, params) {
  const current = sectionFrom(params);
  const sec = SECTIONS.find((s) => s.id === current);

  const rail = h("nav", { class: "os-rail os-admin__rail", attrs: { "aria-label": t("admin.sections"), "data-testid": "admin-rail" } });
  const picker = h("select", { id: "admin-section", class: "os-input os-select" });
  for (const g of GROUPS) {
    rail.append(h("p", { class: "os-rail__group", text: GROUP[g]() }));
    const ul = h("ul", { class: "os-rail__list" });
    const og = h("optgroup", { attrs: { label: GROUP[g]() } });
    for (const s of SECTIONS.filter((x) => x.group === g)) {
      ul.append(h("li", {}, h("a", {
        class: `os-rail__link${s.ready ? "" : " is-waiting"}`, href: href(s.id),
        attrs: { "data-section": s.id, ...(s.id === current ? { "aria-current": "page" } : {}) },
      }, icon(s.icon, { size: 16 }), h("span", { class: "os-rail__label", text: TITLE[s.id]() }),
      s.ready ? null : h("span", { class: "os-rail__soon", text: t("admin.soon") }))));
      og.append(h("option", { value: s.id, selected: s.id === current, text: s.ready ? TITLE[s.id]() : `${TITLE[s.id]()} (${t("admin.soon")})` }));
    }
    rail.append(ul);
    picker.append(og);
  }
  picker.addEventListener("change", () => ctx.navigate(href(picker.value)));
  const pick = h("div", { class: "os-fieldrow os-admin__picker" }, h("label", { class: "os-label", attrs: { for: "admin-section" }, text: t("admin.section") }), picker);

  const content = h("div", { class: "os-manage__content os-admin__content", attrs: { "data-section": current } });
  view.append(h("div", { class: "os-page-head" }, h("h1", { class: "os-page-title", text: t("admin.title") })),
    h("div", { class: "os-manage os-admin" }, rail, h("div", { class: "os-admin__main" }, pick, content)));

  if (!sec.ready) waiting(content, sec);
  else if (current === "users") users(content, ctx);
  else if (current === "api") clients(content, ctx);
  else if (current === "webhooks") webhooks(content, ctx);
  else account(content, ctx);
  return () => { for (const p of ["users.", "webhooks.", "apiclients."]) unregisterPrefix(p); };
}

/// A section's head: its title (h2), a lede, and its actions.
function sectionHead(panel, title, lede, ...actions) {
  panel.append(h("div", { class: "os-panel__head os-panel__head--page" },
    h("h2", { class: "os-card__title", text: title }),
    actions.length ? h("div", { class: "os-actions" }, ...actions) : null));
  if (lede) panel.append(h("p", { class: "os-muted os-admin__lede", text: lede }));
}

/// A section that waits for its server endpoints: what it will hold, and that it is not
/// on this server yet.
function waiting(panel, sec) {
  sectionHead(panel, TITLE[sec.id](), null);
  panel.append(h("section", { class: "os-card os-admin__waiting", attrs: { "data-testid": `waiting-${sec.id}` } },
    h("p", { class: "os-admin__waiting-head" }, icon("hourglass", { size: 20 }), h("strong", { text: t("admin.wait.title") })),
    h("p", { text: WAITS[sec.id]() }),
    h("p", { class: "os-muted os-small", text: t("admin.wait.text") })));
}

/// A text value and its Copy button, for a value people paste elsewhere.
function copyRow(id, label, value) {
  const input = h("input", { id, class: "os-input os-input--mono", value, readOnly: true, attrs: { "data-testid": `${id}-value` } });
  const copy = button(t("admin.copy"), { icon: "copy", size: "sm", attrs: { "aria-label": t("admin.copy-named", { name: label }) }, onClick: async () => {
    try { await navigator.clipboard.writeText(value); toast(t("admin.copied"), "success"); } catch { input.select(); toast(t("admin.copy-manually"), "info"); }
  } });
  return [h("label", { class: "os-label", attrs: { for: id }, text: label }), h("div", { class: "os-copyrow" }, input, copy)];
}

// ---- Account: settings and branding (AD-01) ------------------------------------------

function account(panel, ctx) {
  sectionHead(panel, t("admin.account"), null);
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
        h("h3", { id: `acct-${id}-h`, class: "os-card__title", text: title }),
        button(editLabel, { icon: "pencil", size: "sm", onClick: onEdit })),
      h("p", { class: "os-muted os-small os-card__lede", text: lede }), ...body);
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

  /// Branding (UX-08): the name, a colour picker paired with its hex, a contrast check
  /// of white text on the colour (WCAG 4.5:1), and a live preview of the email header
  /// and the signing page's bar.
  async function editBranding() {
    const f = {};
    const b = s().branding || {};
    const ok = await openPanel({
      id: "account-branding",
      title: t("admin.branding"),
      description: t("admin.branding-lede"),
      build(body) {
        f.name = h("input", { id: "b-name", class: "os-input", value: b.name || "", maxLength: 255, attrs: { autofocus: true } });
        f.color = h("input", { id: "b-color", class: "os-input os-input--mono", value: b.color || "", maxLength: 7, placeholder: "#b3141f", attrs: { "aria-describedby": "b-color-help b-contrast b-err" } });
        f.pick = h("input", { id: "b-pick", type: "color", class: "os-colorpick", value: HEX.test(b.color || "") ? b.color.toLowerCase() : "#b3141f", attrs: { "aria-label": t("admin.brand-pick") } });
        f.err = h("p", { id: "b-err", class: "os-field-error", attrs: { role: "alert" } });
        const contrast = h("p", { id: "b-contrast", class: "os-help", attrs: { "aria-live": "polite", "data-testid": "brand-contrast" } });
        const mail = h("div", { class: "os-brandprev__mail" }, h("span", { class: "os-brandprev__name" }));
        const bar = h("div", { class: "os-brandprev__bar" }, h("span", { class: "os-brandprev__name" }), h("span", { class: "os-brandprev__btn", text: t("admin.brand-preview-btn") }));
        const preview = h("div", { class: "os-brandprev", attrs: { "data-testid": "brand-preview" } },
          h("p", { class: "os-label", text: t("admin.brand-preview") }),
          h("p", { class: "os-muted os-small", text: t("admin.brand-preview-mail") }), mail,
          h("p", { class: "os-muted os-small", text: t("admin.brand-preview-sign") }), bar);
        const sync = () => {
          const hex = f.color.value.trim();
          const ok = HEX.test(hex);
          const colour = ok ? hex.toLowerCase() : "#b3141f";
          preview.style.setProperty("--os-brand", colour);
          for (const n of preview.querySelectorAll(".os-brandprev__name")) n.textContent = f.name.value.trim() || t("admin.brand-preview-default");
          const ratio = ok ? contrastRatio(colour, "#ffffff") : null;
          contrast.classList.toggle("os-help--warn", ratio != null && ratio < 4.5);
          contrast.textContent = ratio == null ? "" : ratio < 4.5 ? t("admin.contrast-low", { n: ratio.toFixed(2) }) : t("admin.contrast-ok", { n: ratio.toFixed(2) });
        };
        f.pick.addEventListener("input", () => { f.color.value = f.pick.value; f.color.removeAttribute("aria-invalid"); f.err.textContent = ""; sync(); });
        f.color.addEventListener("input", () => { if (HEX.test(f.color.value.trim())) f.pick.value = f.color.value.trim().toLowerCase(); sync(); });
        f.name.addEventListener("input", sync);
        body.append(
          h("label", { class: "os-label", attrs: { for: "b-name" }, text: t("admin.brand-name") }), f.name,
          h("label", { class: "os-label", attrs: { for: "b-color" }, text: t("admin.brand-color") }), h("div", { class: "os-copyrow" }, f.pick, f.color),
          h("p", { id: "b-color-help", class: "os-help", text: t("admin.brand-color-help") }), contrast, f.err, preview);
        sync();
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
  let items = [];
  const filter = { q: "", profile: "all", status: "all" };
  sectionHead(panel, t("admin.users"), null,
    button(t("admin.add-user"), { icon: "user-plus", variant: "primary", command: "users.add", onClick: () => add() }));
  const search = h("input", { id: "u-search", type: "search", class: "os-input os-input--sm", autocomplete: "off", placeholder: t("admin.search-users") });
  search.addEventListener("input", () => { filter.q = search.value; render(); });
  const prof = selectField(t("admin.profile"), [["all", t("admin.filter-all")], ...PROFILES.map((p) => [p, t(`admin.profile.${p}`)])], { id: "u-filter-profile", size: "sm", onChange: (v) => { filter.profile = v; render(); } });
  const stat = selectField(t("admin.col.status"), [["all", t("admin.filter-all")], ["active", t("admin.active")], ["pending", t("admin.pending")], ["disabled", t("admin.disabled")]], { id: "u-filter-status", size: "sm", onChange: (v) => { filter.status = v; render(); } });
  const tools = h("div", { class: "os-filters os-admin__tools" },
    h("div", { class: "os-fieldrow os-filters__search" }, h("label", { class: "os-label", attrs: { for: "u-search" }, text: t("admin.search-users") }), search), prof.el, stat.el);
  const count = h("p", { class: "os-muted os-small", attrs: { "aria-live": "polite", "data-testid": "users-count" } });
  const list = h("div", { class: "os-list os-surface-card" });
  panel.append(tools, count, list);
  register("users.add", { label: t("admin.add-user"), run: () => add() });

  async function load() {
    clear(list);
    list.setAttribute("aria-busy", "true");
    list.append(skeletonRows(3));
    try {
      const [page, acct] = await Promise.all([ctx.api.users.list(), ctx.api.account().catch(() => null)]);
      builtin = acct?.settings?.builtin_profiles || {};
      items = page.items || [];
      // The list carries no invitation state; a single read does. Local members who are
      // not disabled, at most 100, in parallel; one that fails just shows no Resend.
      await Promise.all(items.filter((u) => u.login_kind === "local" && !u.disabled && !("invitation" in u)).slice(0, 100)
        .map(async (u) => { try { u.invitation = (await ctx.api.users.get(u.id))?.invitation ?? null; } catch { u.invitation = null; } }));
      list.removeAttribute("aria-busy");
      render();
    } catch (err) {
      list.removeAttribute("aria-busy");
      if (ctx.failed(err)) return;
      errorState(list, err, load);
    }
  }

  function render() {
    clear(list);
    tools.hidden = !items.length;
    if (!items.length) {
      count.textContent = "";
      list.append(emptyState({ illus: "recipients", title: t("empty.users.title"), text: t("empty.users.text"), action: button(t("admin.add-user"), { icon: "user-plus", variant: "primary", onClick: () => add() }), testId: "empty-users" }));
      return;
    }
    const shown = filterUsers(items, filter, (u) => profileName(u, builtin));
    count.textContent = t("admin.users-count", { n: shown.length, total: items.length });
    if (!shown.length) {
      list.append(emptyState({ illus: "search", title: t("admin.no-users-match"), text: "", action: button(t("admin.clear-filters"), { variant: "primary", onClick: clearFilters }), testId: "empty-user-search" }));
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
    for (const u of shown) {
      const me = u.id === ctx.session?.user_id;
      const profile = profileName(u, builtin);
      const state = userState(u);
      const name = u.name || u.email;
      const menu = menuButton({
        label: t("admin.actions-for", { name }),
        buttonOpts: { icon: "ellipsis", variant: "ghost", size: "sm", iconOnly: true },
        items: () => [
          { label: t("admin.edit"), icon: "pencil", run: () => edit(u, me) },
          state === "pending" ? { label: t("admin.reinvite"), icon: "mail", run: () => reinvite(u) } : null,
          me ? null : "separator",
          me ? null : { label: t("admin.remove"), icon: "trash-2", danger: true, run: () => remove(u) },
        ],
      });
      const editBtn = button(t("admin.edit"), { icon: "pencil", size: "sm", attrs: { "aria-label": t("admin.edit-named", { name }) }, onClick: () => edit(u, me) });
      editBtn.classList.add("os-admin__wide-only");
      tb.append(h("tr", { attrs: { "data-id": u.id } },
        h("td", {}, h("strong", { text: u.name || "—" }), me ? h("span", { class: "os-muted os-small", text: ` ${t("admin.you")}` }) : null),
        h("td", { class: "os-muted os-col-email", text: u.email || "" }),
        h("td", { class: "os-col-date", attrs: { "data-label": t("admin.profile") }, text: PROFILES.includes(profile) ? t(`admin.profile.${profile}`) : profile || "—" }),
        h("td", { class: "os-col-date", attrs: { "data-label": t("admin.col.status") } }, h("span", { class: `os-badge os-badge--user-${state}`, text: t(`admin.${state}`) })),
        h("td", { class: "os-col-actions" }, h("div", { class: "os-actions os-actions--row" }, editBtn, menu))));
    }
    table.append(tb);
    list.append(h("div", { class: "os-table-wrap" }, table));
  }
  function clearFilters() {
    Object.assign(filter, { q: "", profile: "all", status: "all" });
    search.value = ""; prof.select.value = "all"; stat.select.value = "all";
    render();
    search.focus();
  }

  /// One Add user panel (UX-08): an invitation email by default (the server sends a link
  /// to set up their sign-in); switched off, a password is set here instead.
  async function add() {
    const f = {};
    const created = await openPanel({
      id: "user-add",
      title: t("admin.add-user"),
      build(body) {
        f.name = h("input", { id: "u-name", class: "os-input", maxLength: 255, autocomplete: "off", attrs: { autofocus: true, "aria-describedby": "u-err" } });
        f.email = h("input", { id: "u-email", class: "os-input", type: "email", autocomplete: "off", attrs: { "aria-describedby": "u-err" } });
        const profile = selectField(t("admin.profile"), PROFILES.map((p) => [p, t(`admin.profile.${p}`)]), { id: "u-profile", value: "sender" });
        f.profile = profile.select;
        const inv = toggle(t("admin.send-invite"), { id: "u-invite", checked: true });
        f.invite = inv.input;
        f.invite.setAttribute("aria-describedby", "u-invite-help");
        f.password = h("input", { id: "u-password", class: "os-input", type: "password", autocomplete: "new-password", maxLength: 256, attrs: { "aria-describedby": "u-password-help" } });
        const pw = h("div", { class: "os-fieldrow", hidden: true },
          h("label", { class: "os-label", attrs: { for: "u-password" }, text: t("admin.password") }), f.password,
          h("p", { id: "u-password-help", class: "os-help", text: t("admin.password-help") }));
        const help = h("p", { id: "u-invite-help", class: "os-help", text: t("admin.invite-help") });
        f.invite.addEventListener("change", () => { pw.hidden = f.invite.checked; help.textContent = t(f.invite.checked ? "admin.invite-help" : "admin.no-invite-help"); });
        f.err = h("p", { id: "u-err", class: "os-field-error", attrs: { role: "alert" } });
        body.append(
          h("label", { class: "os-label", attrs: { for: "u-name" }, text: t("prepare.name") }), f.name,
          h("label", { class: "os-label", attrs: { for: "u-email" }, text: t("prepare.email") }), f.email,
          profile.el,
          h("div", { class: "os-switchrow" }, inv.el, help), pw, f.err);
      },
      actions: [
        { label: t("action.cancel"), value: null },
        {
          label: t("admin.add-user"),
          variant: "primary",
          onClick: async () => {
            const name = f.name.value.trim();
            const email = f.email.value.trim();
            const invite = f.invite.checked;
            const password = f.password.value;
            for (const el of [f.name, f.email, f.password]) el.removeAttribute("aria-invalid");
            // The server needs a name, an email and a profile (UserCreate).
            const bad = !name ? [f.name, t("form.required")] : !EMAIL.test(email) ? [f.email, t("admin.need-email")] : !invite && password.length < 12 ? [f.password, t("admin.need-password")] : null;
            if (bad) { f.err.textContent = bad[1]; bad[0].setAttribute("aria-invalid", "true"); bad[0].focus(); return undefined; }
            if (invite) { await ctx.api.users.invite({ email, name, profile: f.profile.value }); return { invited: email }; }
            await ctx.api.users.create({ name, email, profile: f.profile.value, password });
            return { added: true };
          },
        },
      ],
    });
    if (!created) return;
    toast(created.invited ? t("admin.invited", { email: created.invited }) : t("admin.user-added"), "success");
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

  async function reinvite(u) {
    try { await ctx.api.users.reinvite(u.id); toast(t("admin.reinvited", { email: u.email }), "success"); } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }

  async function remove(u) {
    if (!(await confirmDialog(t("admin.remove-title"), t("admin.remove-text", { name: u.name }), { confirm: t("admin.remove"), danger: true }))) return;
    try { await ctx.api.users.remove(u.id); toast(t("admin.user-removed"), "success"); load(); } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }

  load();
}

// ---- Webhooks (UX-08; docs/40 §4) ------------------------------------------------------

function webhooks(panel, ctx) {
  let items = [];
  let selected = null;
  sectionHead(panel, t("admin.webhooks"), t("admin.wh.lede"),
    button(t("admin.wh.new"), { icon: "plus", variant: "primary", command: "webhooks.new", onClick: () => add() }));
  const list = h("div", { class: "os-list os-surface-card", attrs: { "data-testid": "webhooks" } });
  const deliveries = h("section", { class: "os-card os-card--flush os-admin__deliveries", attrs: { "aria-labelledby": "wh-del-h", "data-testid": "deliveries" }, hidden: true });
  panel.append(list, deliveries);
  register("webhooks.new", { label: t("admin.wh.new"), run: () => add() });

  async function load(keep = selected) {
    clear(list);
    list.setAttribute("aria-busy", "true");
    list.append(skeletonRows(2));
    try {
      items = (await ctx.api.listWebhooks()).items || [];
      list.removeAttribute("aria-busy");
      selected = items.find((w) => w.id === keep)?.id || items[0]?.id || null;
      render();
      showDeliveries();
    } catch (err) {
      list.removeAttribute("aria-busy");
      if (ctx.failed(err)) return;
      errorState(list, err, () => load());
    }
  }

  function render() {
    clear(list);
    if (!items.length) {
      list.append(emptyState({ illus: "inbox", title: t("admin.wh.empty-title"), text: t("admin.wh.empty-text"), action: button(t("admin.wh.new"), { icon: "plus", variant: "primary", onClick: () => add() }), testId: "empty-webhooks" }));
      return;
    }
    const table = h("table", { class: "os-table os-table--rows os-table--cards" },
      h("caption", { class: "os-sr-only", text: t("admin.webhooks") }),
      h("thead", {}, h("tr", {},
        h("th", { attrs: { scope: "col" }, text: t("admin.wh.url") }),
        h("th", { attrs: { scope: "col" }, class: "os-col-date", text: t("admin.wh.events") }),
        h("th", { attrs: { scope: "col" }, class: "os-col-date", text: t("admin.col.status") }),
        h("th", { attrs: { scope: "col" }, class: "os-col-actions", text: t("templates.col.actions") }))));
    const tb = h("tbody");
    for (const w of items) {
      const types = w.event_types || [];
      const shownTypes = types.slice(0, 2).join(", ") + (types.length > 2 ? ` ${t("admin.wh.more", { n: types.length - 2 })}` : "");
      const menu = menuButton({
        label: t("admin.actions-for", { name: w.url }),
        buttonOpts: { icon: "ellipsis", variant: "ghost", size: "sm", iconOnly: true },
        items: () => [
          { label: t("admin.wh.test"), icon: "send", run: () => test(w) },
          w.active ? { label: t("admin.wh.pause"), icon: "clock", run: () => setActive(w, false) } : { label: t("admin.wh.resume"), icon: "refresh-cw", run: () => setActive(w, true) },
          w.active ? "separator" : null,
          w.active ? { label: t("admin.wh.disable"), icon: "ban", danger: true, run: () => disable(w) } : null,
        ],
      });
      const view = button(t("admin.wh.deliveries"), { icon: "list", size: "sm", attrs: { "aria-label": t("admin.wh.deliveries-for", { url: w.url }), "aria-pressed": String(w.id === selected) }, onClick: () => { selected = w.id; render(); showDeliveries(true); } });
      view.classList.add("os-btn--keep-label");
      tb.append(h("tr", { class: w.id === selected ? "is-selected" : null, attrs: { "data-id": w.id } },
        h("td", { class: "os-col-email" }, h("code", { class: "os-admin__url", text: w.url }),
          w.envelope_id ? h("span", { class: "os-row__sub os-muted os-small", text: t("admin.wh.one-envelope") }) : null),
        h("td", { class: "os-col-date os-small", attrs: { "data-label": t("admin.wh.events"), title: types.join(", ") } }, h("span", { text: shownTypes })),
        h("td", { class: "os-col-date", attrs: { "data-label": t("admin.col.status") } }, h("span", { class: `os-badge os-badge--user-${w.active ? "active" : "disabled"}`, text: t(w.active ? "admin.wh.active" : "admin.wh.inactive") })),
        h("td", { class: "os-col-actions" }, h("div", { class: "os-actions os-actions--row" }, view, menu))));
    }
    table.append(tb);
    list.append(h("div", { class: "os-table-wrap" }, table));
  }

  /// The selected subscription's latest deliveries (the server keeps the last 100).
  async function showDeliveries(focus = false) {
    clear(deliveries);
    const w = items.find((x) => x.id === selected);
    deliveries.hidden = !w;
    if (!w) return;
    const body = h("div", { attrs: { "aria-busy": "true", "aria-live": "polite" } }, skeletonRows(2));
    const heading = h("h3", { id: "wh-del-h", class: "os-card__title", attrs: { tabindex: "-1" }, text: t("admin.wh.deliveries-title") });
    deliveries.append(h("div", { class: "os-card__head" },
      h("div", {}, heading, h("p", { class: "os-muted os-small os-admin__url", text: w.url })),
      h("div", { class: "os-actions" },
        button(t("admin.wh.refresh"), { icon: "refresh-cw", size: "sm", onClick: () => showDeliveries() }),
        button(t("admin.wh.test"), { icon: "send", size: "sm", attrs: { "data-testid": "webhook-test" }, onClick: () => test(w) }))), body);
    if (focus) heading.focus({ preventScroll: false });
    try {
      const rows = (await ctx.api.listDeliveries(w.id)).items || [];
      body.removeAttribute("aria-busy");
      clear(body);
      if (!rows.length) { body.append(h("p", { class: "os-muted os-admin__none", attrs: { "data-testid": "no-deliveries" }, text: t("admin.wh.no-deliveries") })); return; }
      const table = h("table", { class: "os-table os-table--rows os-table--cards" },
        h("caption", { class: "os-sr-only", text: t("admin.wh.deliveries-title") }),
        h("thead", {}, h("tr", {},
          h("th", { attrs: { scope: "col" }, text: t("admin.wh.event") }),
          h("th", { attrs: { scope: "col" }, class: "os-col-date", text: t("admin.wh.result") }),
          h("th", { attrs: { scope: "col" }, class: "os-col-date", text: t("admin.wh.attempts") }),
          h("th", { attrs: { scope: "col" }, class: "os-col-date", text: t("admin.wh.http") }),
          h("th", { attrs: { scope: "col" }, class: "os-col-actions", text: t("templates.col.actions") }))));
      const tb = h("tbody");
      for (const d of rows) {
        const state = ["delivered", "failed", "pending"].includes(d.status) ? d.status : "pending";
        const tone = state === "delivered" ? "completed" : state === "failed" ? "declined" : "sent";
        tb.append(h("tr", { attrs: { "data-testid": "delivery-row", "data-id": d.id } },
          h("td", {}, h("code", { text: d.event_type || "" })),
          h("td", { class: "os-col-date", attrs: { "data-label": t("admin.wh.result") } },
            h("span", { class: `os-badge os-badge--${tone}` }, icon(state === "delivered" ? "circle-check" : state === "failed" ? "circle-x" : "hourglass", { size: 16 }), h("span", { text: t(`admin.wh.${state}`) }))),
          h("td", { class: "os-col-date", attrs: { "data-label": t("admin.wh.attempts") }, text: String(d.attempts ?? 0) }),
          h("td", { class: "os-col-date", attrs: { "data-label": t("admin.wh.http") }, text: d.last_status_code == null ? "—" : String(d.last_status_code) }),
          h("td", { class: "os-col-actions" }, state === "failed"
            ? button(t("admin.wh.redeliver"), { icon: "refresh-cw", size: "sm", attrs: { "aria-label": t("admin.wh.redeliver-named", { event: d.event_type || "" }) }, onClick: () => redeliver(w, d) })
            : null)));
      }
      table.append(tb);
      body.append(h("div", { class: "os-table-wrap" }, table));
    } catch (err) {
      body.removeAttribute("aria-busy");
      if (ctx.failed(err)) return;
      errorState(body, err, () => showDeliveries());
    }
  }

  async function test(w) {
    try { await ctx.api.testWebhook(w.id); toast(t("admin.wh.tested"), "success"); selected = w.id; render(); showDeliveries(); } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }
  async function redeliver(w, d) {
    try { await ctx.api.redeliver(w.id, d.id); toast(t("admin.wh.redelivered"), "success"); showDeliveries(); } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }
  async function setActive(w, active) {
    try { await ctx.api.updateWebhook(w.id, { active }); toast(t(active ? "admin.wh.resumed" : "admin.wh.paused"), "success"); load(w.id); } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }
  async function disable(w) {
    if (!(await confirmDialog(t("admin.wh.disable-title"), t("admin.wh.disable-text", { url: w.url }), { confirm: t("admin.wh.disable"), danger: true, icon: "ban" }))) return;
    try { await ctx.api.deleteWebhook(w.id); toast(t("admin.wh.disabled"), "success"); load(w.id); } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }

  /// New webhook (UX-08): the https:// address, the events, and the names of the
  /// operator's signing secrets (the secret itself never passes through the API).
  async function add() {
    const f = { events: [] };
    const made = await openPanel({
      id: "webhook-new",
      title: t("admin.wh.new"),
      width: 30,
      build(body) {
        f.url = h("input", { id: "wh-url", class: "os-input os-input--mono", type: "url", inputMode: "url", autocomplete: "off", maxLength: 2048, placeholder: "https://", attrs: { autofocus: true, "aria-describedby": "wh-url-help wh-err" } });
        f.refs = h("input", { id: "wh-refs", class: "os-input os-input--mono", autocomplete: "off", maxLength: 300, attrs: { "aria-describedby": "wh-refs-help wh-err" } });
        const events = h("div", { class: "os-admin__events" });
        for (const [group, types] of eventGroups(WEBHOOK_EVENT_TYPES)) {
          const fs = h("fieldset", { class: "os-fieldset" }, h("legend", { class: "os-label", text: t(`admin.wh.group.${group}`) }));
          for (const e of types) {
            const box = checkbox(e, { id: `wh-ev-${e.replace(/\W/g, "-")}`, checked: /^envelope\.(completed|declined|voided)$/.test(e), attrs: { value: e } });
            f.events.push(box.input);
            fs.append(box.el);
          }
          events.append(fs);
        }
        f.err = h("p", { id: "wh-err", class: "os-field-error", attrs: { role: "alert" } });
        body.append(
          h("label", { class: "os-label", attrs: { for: "wh-url" }, text: t("admin.wh.url") }), f.url,
          h("p", { id: "wh-url-help", class: "os-help", text: t("admin.wh.url-help") }),
          h("label", { class: "os-label", attrs: { for: "wh-refs" }, text: t("admin.wh.secrets") }), f.refs,
          h("p", { id: "wh-refs-help", class: "os-help", text: t("admin.wh.secrets-help") }),
          events, f.err);
      },
      actions: [
        { label: t("action.cancel"), value: null },
        {
          label: t("admin.create"), variant: "primary",
          onClick: async () => {
            for (const el of [f.url, f.refs]) el.removeAttribute("aria-invalid");
            f.err.textContent = "";
            const url = f.url.value.trim();
            const event_types = f.events.filter((b) => b.checked).map((b) => b.value);
            const refs = parseSecretRefs(f.refs.value);
            const bad = !/^https:\/\/\S+$/i.test(url) ? [f.url, t("admin.wh.need-url")]
              : refs.error ? [f.refs, t(refs.error === "none" ? "admin.wh.need-secret" : refs.error === "many" ? "admin.wh.many-secrets" : "admin.wh.bad-secret")]
                : !event_types.length ? [f.events[0], t("admin.wh.need-event")] : null;
            if (bad) { f.err.textContent = bad[1]; if (bad[0] !== f.events[0]) bad[0].setAttribute("aria-invalid", "true"); bad[0].focus(); return undefined; }
            try {
              return await ctx.api.createWebhook({ url, event_types, secret_refs: refs.refs });
            } catch (err) {
              if (err?.code !== "CS-API-0013") throw err;
              f.err.textContent = t("admin.wh.url-refused");
              f.url.setAttribute("aria-invalid", "true");
              f.url.focus();
              return undefined;
            }
          },
        },
      ],
    });
    if (!made) return;
    toast(t("admin.wh.added"), "success");
    load(made.id);
  }

  load();
}

// ---- API clients -------------------------------------------------------------------------

function clients(panel, ctx) {
  let items = [];
  let showRevoked = false;
  const revokedToggle = toggle(t("admin.show-revoked"), { id: "c-show-revoked", onChange: (on) => { showRevoked = on; render(); } });
  sectionHead(panel, t("admin.api"), null,
    button(t("admin.add-client"), { icon: "plus", variant: "primary", command: "apiclients.new", onClick: () => add() }));
  const dev = h("section", { class: "os-card os-admin__dev", attrs: { "aria-labelledby": "dev-h", "data-testid": "api-details" } },
    h("h3", { id: "dev-h", class: "os-card__title", text: t("admin.dev-title") }),
    h("p", { class: "os-muted os-small os-card__lede", text: t("admin.dev-lede") }));
  const devBody = h("div", { class: "os-admin__devgrid" });
  dev.append(devBody);
  const tools = h("div", { class: "os-admin__tools os-admin__tools--end" }, revokedToggle.el);
  const list = h("div", { class: "os-list os-surface-card", attrs: { "aria-live": "polite" } });
  panel.append(dev, tools, list);
  register("apiclients.new", { label: t("admin.add-client"), run: () => add() });

  (async () => {
    let id = "";
    try { id = (await ctx.api.account())?.id || ""; } catch { /* the base URL still helps */ }
    devBody.append(
      h("div", {}, ...copyRow("dev-account", t("admin.account-id"), id || t("admin.not-set"))),
      h("div", {}, ...copyRow("dev-base", t("admin.base-url"), `${location.origin}/api/v1`)));
  })();

  async function load() {
    clear(list);
    list.setAttribute("aria-busy", "true");
    list.append(skeletonRows(3));
    try {
      items = (await ctx.api.apiClients.list()).items || [];
      list.removeAttribute("aria-busy");
      render();
    } catch (err) {
      list.removeAttribute("aria-busy");
      if (ctx.failed(err)) return;
      errorState(list, err, load);
    }
  }

  function render() {
    clear(list);
    const revoked = items.filter((c) => c.revoked).length;
    revokedToggle.el.querySelector("span:last-child").textContent = t("admin.show-revoked-n", { n: revoked });
    tools.hidden = !revoked;
    if (!items.length) {
      list.append(emptyState({ illus: "keys", title: t("empty.clients.title"), text: t("empty.clients.text"), action: button(t("admin.add-client"), { icon: "plus", variant: "primary", onClick: () => add() }), testId: "empty-clients" }));
      return;
    }
    const shown = showRevoked ? items : items.filter((c) => !c.revoked);
    if (!shown.length) {
      list.append(h("p", { class: "os-muted os-admin__none", text: t("admin.only-revoked", { n: revoked }) }));
      return;
    }
    // Created and Last used appear once the server reports them (row in docs/14).
    const created = shown.some((c) => c.created_at);
    const used = shown.some((c) => "last_used_at" in c);
    const table = h("table", { class: "os-table os-table--rows os-table--cards" },
      h("caption", { class: "os-sr-only", text: t("admin.api") }),
      h("thead", {}, h("tr", {},
        h("th", { attrs: { scope: "col" }, text: t("prepare.name") }),
        h("th", { attrs: { scope: "col" }, text: t("admin.kind") }),
        h("th", { attrs: { scope: "col" }, class: "os-col-date", text: t("admin.scopes") }),
        created ? h("th", { attrs: { scope: "col" }, class: "os-col-date", text: t("admin.col.created") }) : null,
        h("th", { attrs: { scope: "col" }, class: "os-col-date", text: t("admin.col.expires") }),
        used ? h("th", { attrs: { scope: "col" }, class: "os-col-date", text: t("admin.col.used") }) : null,
        h("th", { attrs: { scope: "col" }, class: "os-col-actions", text: t("templates.col.actions") }))));
    const tb = h("tbody");
    const when = (iso) => (iso ? h("time", { attrs: { datetime: iso }, text: fmtDate(iso) }) : null);
    for (const c of shown) {
      const ex = expiryState(c.expires_at);
      const expires = c.revoked ? h("span", { class: "os-muted", text: "—" })
        : ex.state === "none" ? h("span", { class: "os-muted", text: t("admin.never-expires") })
          : h("span", { class: "os-admin__expiry" }, when(c.expires_at),
            ex.state === "expired" ? h("span", { class: "os-badge os-badge--declined", attrs: { "data-testid": "expiry-badge" }, text: t("admin.expired") })
              : ex.state === "soon" ? h("span", { class: "os-badge os-badge--expired", attrs: { "data-testid": "expiry-badge" }, text: t("admin.expires-in", { n: ex.days }) }) : null);
      tb.append(h("tr", { attrs: { "data-id": c.id } },
        h("td", {}, h("strong", { text: c.name || "—" }), c.key_prefix ? h("code", { class: "os-muted os-small", text: ` ${c.key_prefix}…` }) : null),
        h("td", {}, c.revoked
          ? h("span", { class: "os-badge os-badge--voided" }, icon("ban", { size: 16 }), h("span", { text: t("admin.revoked") }))
          : h("span", { text: t(c.kind === "api_key" ? "admin.kind.api_key" : "admin.kind.oauth_app") })),
        h("td", { class: "os-col-date os-muted os-small", attrs: { "data-label": t("admin.scopes") }, text: (c.scopes || []).join(", ") }),
        created ? h("td", { class: "os-col-date", attrs: { "data-label": t("admin.col.created") } }, when(c.created_at) || "—") : null,
        h("td", { class: "os-col-date", attrs: { "data-label": t("admin.col.expires") } }, expires),
        used ? h("td", { class: "os-col-date", attrs: { "data-label": t("admin.col.used") } }, when(c.last_used_at) || t("admin.never-used")) : null,
        h("td", { class: "os-col-actions" }, c.revoked ? null : menuButton({
          label: t("admin.actions-for", { name: c.name }),
          buttonOpts: { icon: "ellipsis", variant: "ghost", size: "sm", iconOnly: true },
          items: () => [{ label: t("admin.revoke"), icon: "ban", danger: true, run: () => revoke(c) }],
        }))));
    }
    table.append(tb);
    list.append(h("div", { class: "os-table-wrap" }, table));
  }

  async function add() {
    const f = { scopes: [] };
    const created = await openPanel({
      id: "client-new",
      title: t("admin.add-client"),
      width: 30,
      build(body) {
        f.name = h("input", { id: "c-name", class: "os-input", maxLength: 255, autocomplete: "off", attrs: { autofocus: true } });
        const kind = selectField(t("admin.kind"), [["api_key", t("admin.kind.api_key")], ["oauth_app", t("admin.kind.oauth_app")]], { id: "c-kind" });
        f.kind = kind.select;
        f.days = h("input", { id: "c-days", class: "os-input", type: "number", min: "1", max: "3650", step: "1", value: "365" });
        const scopes = h("div", { class: "os-admin__scopes" });
        for (const [group, list] of SCOPE_GROUPS) {
          const fs = h("fieldset", { class: "os-fieldset" }, h("legend", { class: "os-label", text: t(`admin.scope-group.${group}`) }));
          for (const s of list) {
            const id = `c-scope-${s.replace(":", "-")}`;
            const box = h("input", { id, type: "checkbox", value: s, checked: s.startsWith("envelopes:"), attrs: { "aria-describedby": `${id}-d` } });
            f.scopes.push(box);
            fs.append(h("label", { class: "os-check os-check--desc", attrs: { for: id } }, box,
              h("span", {}, h("code", { text: s }), h("span", { id: `${id}-d`, class: "os-muted os-small os-block", text: t(`admin.scope.${s}`) }))));
          }
          scopes.append(fs);
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
    if (!(await confirmDialog(t("admin.revoke-title"), t("admin.revoke-text", { name: c.name }), { confirm: t("admin.revoke"), danger: true, icon: "ban" }))) return;
    try { await ctx.api.apiClients.revoke(c.id); toast(t("admin.revoked-done"), "success"); load(); } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }

  load();
}

/// The one time a secret is shown: what to copy, and that it will not be shown again.
/// Not dismissible (UX-08): no close button, Escape and navigating away leave it open;
/// only "I have copied it" closes it.
function showSecret(c) {
  const rows = c.key ? [[t("admin.key"), c.key]] : [[t("admin.client-id"), c.client_id], [t("admin.client-secret"), c.client_secret]];
  return openPanel({
    id: "secret",
    title: t("admin.secret-title"),
    dismissible: false,
    build(body) {
      body.append(h("div", { class: "os-callout os-callout--warning", attrs: { "data-testid": "secret-warning" } }, icon("triangle-alert", { size: 20 }), h("p", { text: t("admin.secret-text") })));
      for (const [label, value] of rows) {
        if (!value) continue;
        const id = `secret-${label.replace(/\W+/g, "-").toLowerCase()}`;
        const input = h("input", { id, class: "os-input os-input--mono", value, readOnly: true, attrs: { "data-testid": "secret-value" } });
        const copy = button(t("admin.copy"), { icon: "copy", size: "sm", attrs: { "aria-label": t("admin.copy-named", { name: label }) }, onClick: async () => {
          try { await navigator.clipboard.writeText(value); toast(t("admin.copied"), "success"); } catch { input.select(); toast(t("admin.copy-manually"), "info"); }
        } });
        body.append(h("label", { class: "os-label", attrs: { for: id }, text: label }), h("div", { class: "os-copyrow" }, input, copy));
      }
    },
    actions: [{ label: t("admin.secret-done"), variant: "primary", value: true }],
  });
}
