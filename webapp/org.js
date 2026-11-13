// Organization admin, first cut (ORG-06; docs/23 §10, docs/47 §As built: organization
// admin). `#/org`, for a person who holds an organization role: Overview, Workspaces,
// Users, Administrators and Audit log, drawn with the Admin screen's own parts (the
// secondary nav inside the content card, a "Section" select on phones, the page head
// with its title, lede and actions, cards, row tables, side panels and the danger
// confirmation) over the server's `/organizations/me` routes (ORG-03, ORG-05).
//
// The server decides every action on every request (`SEC-O06`): the role read here only
// decides which buttons to draw (orgmodel.js `orgCan`), and a refusal is shown in place.
// The routes answer user ids, not names: a name is shown when the person is a member of
// the workspace this session is in (`GET /users`), else a short id (ORG-34).

import { h, clear, fmtDate } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { register, unregisterPrefix } from "./commands.js";
import { ORG_NAV, orgRouteFrom, orgHref, orgCan, workspaceCounts, adminCounts, auditAll, changeText, filterAudit, shortId } from "./orgmodel.js";
import { button, emptyState, skeletonRows, skeletonBlock, errorState, openPanel, confirmDialog, toast, toastError, selectField, menuButton } from "./ui/index.js";

const TITLE = {
  overview: () => t("admin.org.nav.overview"), workspaces: () => t("admin.org.nav.workspaces"), users: () => t("admin.org.nav.users"),
  admins: () => t("admin.org.nav.admins"), audit: () => t("admin.org.nav.audit"),
};
const LEDE = {
  overview: () => t("admin.org.lede.overview"), workspaces: () => t("admin.org.lede.workspaces"), users: () => t("admin.org.lede.users"),
  admins: () => t("admin.org.lede.admins"), audit: () => t("admin.org.lede.audit"),
};
const ROLE = { owner: () => t("admin.org.role.owner"), admin: () => t("admin.org.role.admin"), delegated: () => t("admin.org.role.delegated") };
const roleName = (r) => ROLE[r]?.() || r || "—";
const PROFILES = ["admin", "sender", "viewer"];

export function mount(view, ctx, _match, params) {
  const current = orgRouteFrom(params);
  const orgLabel = h("span", { class: "os-adm__org", text: t("admin.org.title") });
  const nav = h("nav", { class: "os-adm__nav", attrs: { "aria-label": t("admin.org.sections"), "data-testid": "org-rail" } },
    h("a", { class: "os-adm__link os-adm__back", href: "#/agreements" }, icon("os-back", { size: 16, stroke: 1.6 }), h("span", { text: t("admin.back") })),
    orgLabel,
    ...ORG_NAV.map((id) => h("a", {
      class: "os-adm__link", href: orgHref(id),
      attrs: { "data-section": id, ...(id === current ? { "aria-current": "page" } : {}) },
    }, h("span", { class: "os-adm__label", text: TITLE[id]() }))));
  const picker = h("select", { id: "org-section", class: "os-input os-select" },
    ...ORG_NAV.map((id) => h("option", { value: id, selected: id === current, text: TITLE[id]() })));
  picker.addEventListener("change", () => ctx.navigate(orgHref(picker.value)));
  const actions = h("div", { class: "os-adm__actions" });
  const lede = h("p", { class: "os-adm__lede", text: LEDE[current]() });
  const head = h("div", { class: "os-adm__head os-rise" },
    h("div", { class: "os-adm__titles" }, h("h1", { class: "os-adm__title", text: TITLE[current]() }), lede), h("span", { class: "os-adm__chip-slot" }), actions);
  const body = h("div", { class: "os-adm__body", attrs: { "data-section": current, "aria-busy": "true" } }, skeletonBlock({ height: 9 }));
  view.append(h("div", { class: "os-adm", attrs: { "data-page": `org-${current}` } }, nav,
    h("div", { class: "os-adm__main" },
      h("div", { class: "os-fieldrow os-adm__picker" }, h("label", { class: "os-label", attrs: { for: "org-section" }, text: t("admin.section") }), picker),
      h("div", { class: "os-adm__page" }, head, body))));
  for (const id of ORG_NAV) register(`org.go.${id}`, { label: t("palette.go", { place: TITLE[id]() }), run: () => ctx.navigate(orgHref(id)) });

  const page = { ctx, body, actions, lede, org: null, names: new Map(), emails: new Map(), members: [] };
  start();
  return () => unregisterPrefix("org.");

  async function start() {
    try {
      page.org = await ctx.api.org.get();
    } catch (err) {
      body.removeAttribute("aria-busy");
      if (ctx.failed(err)) return;
      clear(body);
      if (err?.code === "CS-AUTH-0006") {
        body.append(emptyState({ illus: "keys", title: t("admin.org.no-role.title"), text: t("admin.org.no-role.text"), testId: "org-no-role" }));
      } else errorState(body, err, () => { clear(body); start(); });
      return;
    }
    orgLabel.textContent = t("admin.org.of", { name: page.org.name });
    // Names for user ids: this workspace's members, when this person may list them.
    try {
      page.members = (await ctx.api.users.list())?.items || [];
      for (const u of page.members) { page.names.set(u.id, u.name || u.email || ""); page.emails.set(u.id, u.email || ""); }
    } catch { page.members = []; }
    body.removeAttribute("aria-busy");
    clear(body);
    ({ overview, workspaces, users, admins, audit })[current](page);
  }
}

const can = (page, action) => orgCan(page.org?.role, action);
const who = (page, id) => page.names.get(id) || shortId(id);

/// A row table in the Admin screen's style (`os-table--cards`: one card per row on phones).
function table(caption, cols, testId) {
  const tb = h("tbody");
  const el = h("div", { class: "os-list os-surface-card", attrs: { "data-testid": testId } },
    h("div", { class: "os-table-wrap" }, h("table", { class: "os-table os-table--rows os-table--cards" },
      h("caption", { class: "os-sr-only", text: caption }),
      h("thead", {}, h("tr", {}, ...cols.map(([label, cls]) => h("th", { attrs: { scope: "col" }, class: cls || "", text: label })))),
      tb)));
  return { el, tb };
}
const cell = (label, child, cls = "") => h("td", { class: cls, attrs: { "data-label": label } }, child);
const loadingList = (box) => { clear(box); box.setAttribute("aria-busy", "true"); box.append(skeletonRows(3)); };

// ---- Overview ------------------------------------------------------------------------------

async function overview(page) {
  const { ctx, body } = page;
  const render = (spaces, admins) => {
    clear(body);
    const w = workspaceCounts(spaces);
    const a = adminCounts(admins);
    if (can(page, "settings")) page.actions.replaceChildren(button(t("admin.org.rename"), { icon: "pencil", onClick: () => rename() }));
    const tile = (id, ic, label, value, sample) => h("li", {}, h("div", { class: "os-counter os-counter--static", attrs: { "data-testid": `org-tile-${id}` } },
      h("span", { class: "os-counter__icon" }, icon(ic, { size: 24 })),
      h("span", { class: "os-counter__n", text: String(value) }),
      h("span", { class: "os-counter__label", text: label }),
      h("span", { class: "os-counter__sample", text: sample })));
    const row = (label, value, testId) => [h("dt", { text: label }), h("dd", { text: value, attrs: testId ? { "data-testid": testId } : {} })];
    body.append(
      h("ul", { class: "os-counters" },
        tile("workspaces", "layers", t("admin.org.tile.workspaces"), w.active, t("admin.org.tile.archived", { n: w.archived })),
        tile("admins", "os-shield", t("admin.org.tile.admins"), a.owner + a.admin + a.delegated, t("admin.org.tile.owners", { n: a.owner }))),
      h("section", { class: "os-card os-adm__card", attrs: { "aria-labelledby": "org-about-h", "data-testid": "org-about" } },
        h("h2", { id: "org-about-h", class: "os-card__title", text: t("admin.org.about") }),
        h("dl", { class: "os-meta os-adm__meta" },
          row(t("admin.org.name"), page.org.name, "org-name"),
          row(t("admin.org.your-role"), roleName(page.org.role), "org-role"),
          row(t("admin.org.created"), page.org.created_at ? fmtDate(page.org.created_at) : "—"))),
      h("p", { class: "os-adm__later", attrs: { "data-testid": "org-later" }, text: t("admin.org.later") }));
  };
  try {
    const [spaces, admins] = await Promise.all([ctx.api.org.workspaces(), ctx.api.org.admins()]);
    render(spaces?.items || [], admins?.items || []);
  } catch (err) {
    if (ctx.failed(err)) return;
    errorState(body, err, () => overview(page));
  }

  async function rename() {
    const f = {};
    const out = await openPanel({
      id: "org-rename",
      title: t("admin.org.rename"),
      build(b) {
        f.name = h("input", { id: "org-name-i", class: "os-input", value: page.org.name || "", maxLength: 255, attrs: { autofocus: true, "aria-describedby": "org-name-err" } });
        f.err = h("p", { id: "org-name-err", class: "os-field-error", attrs: { role: "alert" } });
        b.append(h("label", { class: "os-label", attrs: { for: "org-name-i" }, text: t("admin.org.name") }), f.name, f.err);
      },
      actions: [
        { label: t("action.cancel"), value: null },
        {
          label: t("templates.save"), variant: "primary",
          onClick: async () => {
            const name = f.name.value.trim();
            if (!name) { f.err.textContent = t("form.required"); f.name.setAttribute("aria-invalid", "true"); f.name.focus(); return undefined; }
            return ctx.api.org.rename(name);
          },
        },
      ],
    });
    if (!out) return;
    page.org = { ...page.org, name: out.name };
    toast(t("admin.org.renamed"), "success");
    overview(page);
  }
}

// ---- Workspaces -------------------------------------------------------------------------

async function workspaces(page) {
  const { ctx, body } = page;
  if (can(page, "workspaces")) {
    page.actions.replaceChildren(button(t("admin.org.ws.new"), { icon: "plus", variant: "primary", command: "org.ws.new", onClick: () => create() }));
    register("org.ws.new", { label: t("admin.org.ws.new"), run: () => create() });
  }
  const box = h("div");
  body.append(box);
  let items = [];
  let mine = new Map();

  async function load() {
    loadingList(box);
    try {
      const [spaces, member] = await Promise.all([ctx.api.org.workspaces(), ctx.api.workspaces().catch(() => null)]);
      items = spaces?.items || [];
      mine = new Map((member?.organizations || []).flatMap((o) => o.workspaces || []).map((w) => [w.id, w]));
      box.removeAttribute("aria-busy");
      render();
    } catch (err) {
      box.removeAttribute("aria-busy");
      if (ctx.failed(err)) return;
      errorState(box, err, load);
    }
  }

  function render() {
    clear(box);
    const { el, tb } = table(t("admin.org.nav.workspaces"), [[t("prepare.name")], [t("admin.col.status"), "os-col-date"], [t("admin.org.col.you"), "os-col-date"], [t("templates.col.actions"), "os-col-actions"]], "org-workspaces");
    for (const w of items) {
      const archived = w.status === "archived";
      const m = mine.get(w.id);
      const joinable = !archived && !m && (page.org.role === "owner" || page.org.role === "admin");
      const menu = !archived && can(page, "workspaces") ? menuButton({
        label: t("admin.actions-for", { name: w.name }),
        buttonOpts: { icon: "ellipsis", variant: "ghost", size: "sm", iconOnly: true },
        items: () => [{ label: t("admin.org.ws.archive"), icon: "ban", danger: true, run: () => archive(w) }],
      }) : null;
      const join = joinable ? button(t("admin.org.ws.join"), { icon: "arrow-right", size: "sm", attrs: { "aria-label": t("admin.org.ws.join-named", { name: w.name }) }, onClick: () => joinWs(w) }) : null;
      tb.append(h("tr", { attrs: { "data-id": w.id } },
        h("td", {}, h("strong", { text: w.name })),
        cell(t("admin.col.status"), h("span", { class: `os-badge os-badge--user-${archived ? "disabled" : "active"}`, text: archived ? t("admin.org.ws.archived") : t("admin.active") }), "os-col-date"),
        cell(t("admin.org.col.you"), h("span", { class: "os-muted os-small", text: m ? (m.current ? t("admin.org.ws.current") : t("admin.org.ws.member")) : "—" }), "os-col-date"),
        h("td", { class: "os-col-actions" }, h("div", { class: "os-actions os-actions--row" }, join, menu))));
    }
    box.append(el);
  }

  async function create() {
    const f = {};
    const out = await openPanel({
      id: "org-ws-new",
      title: t("admin.org.ws.new"),
      description: t("admin.org.ws.new-lede"),
      build(b) {
        f.name = h("input", { id: "org-ws-name", class: "os-input", maxLength: 255, autocomplete: "off", attrs: { autofocus: true, "aria-describedby": "org-ws-err" } });
        f.err = h("p", { id: "org-ws-err", class: "os-field-error", attrs: { role: "alert" } });
        b.append(h("label", { class: "os-label", attrs: { for: "org-ws-name" }, text: t("prepare.name") }), f.name, f.err);
      },
      actions: [
        { label: t("action.cancel"), value: null },
        {
          label: t("admin.org.ws.create"), variant: "primary",
          onClick: async () => {
            const name = f.name.value.trim();
            if (!name) { f.err.textContent = t("form.required"); f.name.setAttribute("aria-invalid", "true"); f.name.focus(); return undefined; }
            return ctx.api.org.createWorkspace(name);
          },
        },
      ],
    });
    if (!out) return;
    toast(t("admin.org.ws.created", { name: out.name }), "success");
    load();
  }

  async function archive(w) {
    if (!(await confirmDialog(t("admin.org.ws.archive-title", { name: w.name }), t("admin.org.ws.archive-text"), { confirm: t("admin.org.ws.archive"), danger: true }))) return;
    try { await ctx.api.org.archiveWorkspace(w.id); toast(t("admin.org.ws.archived-done", { name: w.name }), "success"); load(); } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }

  async function joinWs(w) {
    const f = {};
    const out = await openPanel({
      id: "org-ws-join",
      title: t("admin.org.ws.join-title", { name: w.name }),
      description: t("admin.org.ws.join-lede"),
      build(b) {
        const p = selectField(t("admin.profile"), PROFILES.map((x) => [x, t(`admin.profile.${x}`)]), { id: "org-join-profile", value: "admin" });
        f.profile = p.select;
        b.append(p.el);
      },
      actions: [
        { label: t("action.cancel"), value: null },
        { label: t("admin.org.ws.join"), variant: "primary", onClick: () => ctx.api.org.joinWorkspace(w.id, f.profile.value) },
      ],
    });
    if (!out) return;
    toast(t("admin.org.ws.joined", { name: w.name }), "success");
    load();
  }

  load();
}

// ---- Users --------------------------------------------------------------------------------

/// First cut: the members of the workspace this session is in, with their organization
/// role. A directory across every workspace needs a server route (ORG-33).
async function users(page) {
  const { ctx, body } = page;
  const box = h("div");
  body.append(box, h("p", { class: "os-adm__later", attrs: { "data-testid": "org-users-later" }, text: t("admin.org.users-later") }));
  loadingList(box);
  try {
    const admins = new Map(((await ctx.api.org.admins())?.items || []).map((a) => [a.user_id, a.role]));
    box.removeAttribute("aria-busy");
    clear(box);
    if (!page.members.length) {
      box.append(emptyState({ illus: "recipients", title: t("empty.users.title"), text: t("admin.org.users-none"), testId: "org-users-empty" }));
      return;
    }
    const { el, tb } = table(t("admin.org.nav.users"), [[t("prepare.name")], [t("prepare.email")], [t("admin.col.status"), "os-col-date"], [t("admin.org.col.role"), "os-col-date"]], "org-users");
    for (const u of page.members) {
      const role = admins.get(u.id);
      tb.append(h("tr", { attrs: { "data-id": u.id } },
        h("td", {}, h("strong", { text: u.name || "—" }), u.id === ctx.session?.user_id ? h("span", { class: "os-muted os-small", text: ` ${t("admin.you")}` }) : null),
        h("td", { class: "os-muted os-col-email", text: u.email || "" }),
        cell(t("admin.col.status"), h("span", { class: `os-badge os-badge--user-${u.disabled ? "disabled" : "active"}`, text: u.disabled ? t("admin.disabled") : t("admin.active") }), "os-col-date"),
        cell(t("admin.org.col.role"), h("span", { text: role ? roleName(role) : "—" }), "os-col-date")));
    }
    box.append(el);
  } catch (err) {
    box.removeAttribute("aria-busy");
    if (ctx.failed(err)) return;
    errorState(box, err, () => { clear(body); users(page); });
  }
}

// ---- Administrators ---------------------------------------------------------------------

async function admins(page) {
  const { ctx, body } = page;
  const owner = can(page, "admins");
  if (owner) {
    page.actions.replaceChildren(button(t("admin.org.adm.add"), { icon: "user-plus", variant: "primary", command: "org.admins.add", onClick: () => add() }));
    register("org.admins.add", { label: t("admin.org.adm.add"), run: () => add() });
  }
  const box = h("div");
  body.append(box);
  let items = [];

  async function load() {
    loadingList(box);
    try {
      items = (await ctx.api.org.admins())?.items || [];
      box.removeAttribute("aria-busy");
      render();
    } catch (err) {
      box.removeAttribute("aria-busy");
      if (ctx.failed(err)) return;
      errorState(box, err, load);
    }
  }

  function render() {
    clear(box);
    const { el, tb } = table(t("admin.org.nav.admins"), [[t("prepare.name")], [t("prepare.email")], [t("admin.org.col.role"), "os-col-date"], [t("admin.org.col.since"), "os-col-date"], [t("templates.col.actions"), "os-col-actions"]], "org-admins");
    for (const a of items) {
      const me = a.user_id === ctx.session?.user_id;
      const name = who(page, a.user_id);
      const menu = owner ? menuButton({
        label: t("admin.actions-for", { name }),
        buttonOpts: { icon: "ellipsis", variant: "ghost", size: "sm", iconOnly: true },
        items: () => [
          me || a.role === "delegated" ? null : { label: t("admin.org.adm.change"), icon: "pencil", run: () => change(a, name) },
          { label: me ? t("admin.org.adm.resign") : t("admin.org.adm.remove"), icon: "trash-2", danger: true, run: () => remove(a, name, me) },
        ],
      }) : null;
      tb.append(h("tr", { attrs: { "data-id": a.user_id } },
        h("td", {}, h("strong", { text: name }), me ? h("span", { class: "os-muted os-small", text: ` ${t("admin.you")}` }) : null),
        h("td", { class: "os-muted os-col-email", text: page.emails.get(a.user_id) || "" }),
        cell(t("admin.org.col.role"), h("span", { text: roleName(a.role) }), "os-col-date"),
        cell(t("admin.org.col.since"), h("span", { text: a.created_at ? fmtDate(a.created_at) : "—" }), "os-col-date"),
        h("td", { class: "os-col-actions" }, h("div", { class: "os-actions os-actions--row" }, menu))));
    }
    box.append(el);
  }

  async function add() {
    const f = {};
    const held = new Set(items.map((a) => a.user_id));
    const choices = page.members.filter((u) => !u.disabled && !held.has(u.id) && u.id !== ctx.session?.user_id);
    const out = await openPanel({
      id: "org-admin-add",
      title: t("admin.org.adm.add"),
      description: t("admin.org.adm.add-lede"),
      build(b) {
        if (!choices.length) { b.append(h("p", { class: "os-muted", attrs: { "data-testid": "org-admin-none" }, text: t("admin.org.adm.none") })); return; }
        const person = selectField(t("admin.org.adm.person"), choices.map((u) => [u.id, u.email ? `${u.name || u.email} (${u.email})` : u.name]), { id: "org-admin-user" });
        const role = selectField(t("admin.org.col.role"), [["admin", roleName("admin")], ["owner", roleName("owner")]], { id: "org-admin-role", value: "admin", help: t("admin.org.adm.role-help") });
        f.user = person.select; f.role = role.select;
        b.append(person.el, role.el);
      },
      actions: [
        { label: t("action.cancel"), value: null },
        ...(choices.length ? [{ label: t("admin.org.adm.add"), variant: "primary", onClick: () => ctx.api.org.addAdmin(f.user.value, f.role.value) }] : []),
      ],
    });
    if (!out) return;
    toast(t("admin.org.adm.added", { name: who(page, out.user_id) }), "success");
    load();
  }

  async function change(a, name) {
    const f = {};
    const out = await openPanel({
      id: "org-admin-role",
      title: t("admin.org.adm.change"),
      description: name,
      build(b) {
        const role = selectField(t("admin.org.col.role"), [["admin", roleName("admin")], ["owner", roleName("owner")]], { id: "org-admin-role-e", value: a.role, help: t("admin.org.adm.role-help") });
        f.role = role.select;
        b.append(role.el);
      },
      actions: [
        { label: t("action.cancel"), value: null },
        { label: t("templates.save"), variant: "primary", onClick: () => ctx.api.org.setAdminRole(a.user_id, f.role.value) },
      ],
    });
    if (!out) return;
    toast(t("admin.org.adm.changed", { name }), "success");
    load();
  }

  async function remove(a, name, me) {
    if (!(await confirmDialog(t("admin.org.adm.remove-title", { name }), t(me ? "admin.org.adm.resign-text" : "admin.org.adm.remove-text"), { confirm: me ? t("admin.org.adm.resign") : t("admin.org.adm.remove"), danger: true }))) return;
    try {
      await ctx.api.org.removeAdmin(a.user_id);
      toast(t("admin.org.adm.removed", { name }), "success");
      if (me) { ctx.navigate("#/home"); return; }
      load();
    } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }

  load();
}

// ---- Audit log ----------------------------------------------------------------------------

async function audit(page) {
  const { ctx, body } = page;
  page.actions.replaceChildren(button(t("admin.org.audit.verify"), { icon: "shield-check", attrs: { "data-testid": "org-audit-verify" }, onClick: () => verify() }));
  const search = h("input", { id: "org-audit-q", type: "search", class: "os-input os-input--sm", autocomplete: "off", placeholder: t("admin.org.audit.filter") });
  const tools = h("div", { class: "os-filters os-admin__tools" },
    h("div", { class: "os-fieldrow os-filters__search" }, h("label", { class: "os-label", attrs: { for: "org-audit-q" }, text: t("admin.org.audit.filter") }), search));
  const count = h("p", { class: "os-muted os-small", attrs: { "aria-live": "polite", "data-testid": "org-audit-count" } });
  const box = h("div");
  const capped = h("p", { class: "os-adm__later", attrs: { "data-testid": "org-audit-capped" }, text: t("admin.org.audit.capped") });
  capped.hidden = true;
  body.append(tools, count, box, capped);
  let rows = [];
  search.addEventListener("input", () => render());

  // The server pages oldest first with a forward cursor, so newest first means reading
  // to the last page (orgmodel.js `auditAll`); each page is verified as it is read.
  async function load() {
    rows = [];
    loadingList(box);
    try {
      rows = await auditAll((q) => ctx.api.org.audit(q));
      capped.hidden = !rows.truncated;
      box.removeAttribute("aria-busy");
      render();
    } catch (err) {
      box.removeAttribute("aria-busy");
      if (ctx.failed(err)) return;
      errorState(box, err, () => load());
    }
  }

  function render() {
    clear(box);
    const shown = filterAudit(rows, search.value, (id) => page.names.get(id) || "").slice().reverse();
    count.textContent = t("admin.org.audit.count", { n: shown.length, total: rows.length });
    if (!shown.length) {
      box.append(emptyState({ illus: "search", title: t("admin.org.audit.none"), text: "", testId: "org-audit-empty" }));
      return;
    }
    const { el, tb } = table(t("admin.org.nav.audit"), [[t("admin.org.audit.when"), "os-col-date"], [t("admin.org.audit.what")], [t("admin.org.audit.by")], [t("admin.org.audit.about")]], "org-audit");
    for (const r of shown) {
      const by = r.actor.kind === "system" ? t("admin.org.audit.system") : r.actor.id ? who(page, r.actor.id) : r.actor.kind || "—";
      const about = r.targets.map(([k, id]) => `${k}: ${k === "user" ? who(page, id) : shortId(id)}`).join(", ");
      const change = r.changes.map(changeText).join("; ");
      tb.append(h("tr", { attrs: { "data-seq": String(r.seq), "data-action": r.action } },
        cell(t("admin.org.audit.when"), h("span", { text: r.at ? fmtDate(r.at) : "—" }), "os-col-date"),
        h("td", {}, h("strong", { text: r.known ? t(`admin.org.act.${r.action}`) : r.action }), change ? h("div", { class: "os-muted os-small", text: change }) : null),
        cell(t("admin.org.audit.by"), h("span", { text: by })),
        cell(t("admin.org.audit.about"), h("span", { class: "os-muted os-small", text: about || "—" }))));
    }
    box.append(el);
  }

  async function verify() {
    try {
      await ctx.api.org.audit({ verify: "full", limit: 1 });
      toast(t("admin.org.audit.verified"), "success");
    } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }

  load();
}
