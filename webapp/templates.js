// Templates (WEB-02, WEB-06, WEB-09; docs/47 §Screens "Templates", after DocuSign's):
// the list with search, owner and last use; a new template in the editor
// (`#/templates/new`, prepare.js in template mode); Edit reopens its documents, roles
// and fields in the same editor (`#/templates/{id}/edit`); edit details (name, email
// subject and message) in a side panel; duplicate; delete (a destructive
// confirmation); and "Use" (`#/templates/{id}`): the document on the left, the roles
// and Send in a sticky side panel on the right (T-03).
//
// Sharing (UXW-06; after DocuSign's Templates): pill tabs All, Mine, Shared with me and
// Favourites (`GET /templates?view=`); a star on each row; Share (the owner's) in a side
// panel: members by email, groups, or everyone in the workspace, each "can edit" or
// not. The row menu offers what the caller's `access` allows; the server decides.
//
// Folders (TSH-03): each member's own template folders; a folder filter beside the
// search, New folder, and Move to folder in each row's menu.
//
// Using a template, or several together (composite templates, slice 3), is one
// `POST /api/v1/envelopes/from-templates`: the server makes the envelope from the
// templates' stored documents, their roles filled with people (matched by name across
// templates) and their fields bound to them. A template without documents becomes a
// draft with its recipients, opened in the editor to add the PDF and fields. Every call
// is api.js's (WEB-10).

import { h, clear, fmtDate } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { register, unregisterPrefix } from "./commands.js";
import { button, busy, emptyState, skeletonRows, errorState, openPanel, confirmDialog, toast, toastError, pdfPreview, menuButton, selectField, tabs, iconButton, checkbox, field, pill } from "./ui/index.js";
import { peopleProblems, extraProblems, canDo, shareItems, hasShare, isEmail, mergeTemplates, fromTemplatesBody } from "./templatemodel.js";

/// The list's views (UXW-06): `id` is the `view` the server takes.
const VIEWS = ["all", "owned", "shared", "favourites"];

/// Templates whose name or email subject contains `q` (any case).
export function matchTemplates(items, q) {
  const s = (q || "").trim().toLowerCase();
  if (!s) return items;
  return items.filter((tp) => [tp.name, tp.email_subject].some((v) => (v || "").toLowerCase().includes(s)));
}

/// The canvas's document thumbnail for a list row (WEB-17): a small page with lines.
/// Decorative; the row's link names the template.
function docThumb() {
  return h("span", { class: "os-docthumb", attrs: { "aria-hidden": "true" } },
    h("span", { class: "os-docthumb__line" }), h("span", { class: "os-docthumb__line" }), h("span", { class: "os-docthumb__line os-docthumb__line--short" }));
}

/// `#/templates`: the list.
export function mount(view, ctx) {
  let items = [];
  const people = new Map();
  const head = h("div", { class: "os-page-head" },
    h("h1", { class: "os-page-title", text: t("templates.title") }),
    button(t("templates.new"), { icon: "plus", variant: "primary", command: "template.new", onClick: () => ctx.navigate("#/templates/new") }));
  const search = h("input", { id: "tpl-search", type: "search", class: "os-input os-input--sm", autocomplete: "off", placeholder: t("templates.search") });
  search.addEventListener("input", () => render());
  // Template folders (TSH-03, after DocuSign's): each member's own; a folder filter
  // beside the search, New folder, and Move to folder in each row's menu.
  let folders = [];
  let folder = "";
  const folderPick = h("select", { id: "tpl-folder", class: "os-input os-input--sm", attrs: { "data-testid": "tpl-folder" } });
  folderPick.addEventListener("change", () => { folder = folderPick.value; load(); });
  const drawFolders = () => {
    clear(folderPick);
    folderPick.append(h("option", { value: "", text: t("templates.folder.all") }), h("option", { value: "none", text: t("templates.folder.none") }),
      ...folders.map((f) => h("option", { value: f.id, text: t("templates.folder.option", { name: f.name, n: f.count }) })));
    folderPick.value = folders.some((f) => f.id === folder) || folder === "none" ? folder : "";
  };
  drawFolders();
  const newFolder = button(t("templates.folder.new"), { icon: "plus", size: "sm", command: "templatefolder.new", attrs: { "data-testid": "tpl-new-folder" }, onClick: () => makeFolder() });
  const tools = h("div", { class: "os-filters" }, h("div", { class: "os-fieldrow os-filters__search" },
    h("label", { class: "os-sr-only", attrs: { for: "tpl-search" }, text: t("templates.search") }), search),
  h("div", { class: "os-fieldrow" }, h("label", { class: "os-sr-only", attrs: { for: "tpl-folder" }, text: t("templates.folder.label") }), folderPick), newFolder);
  const list = h("div", { class: "os-list os-surface-card", attrs: { "aria-live": "polite" } });
  let shown = "all";
  let quiet = true; // the tabs' first render is not a choice
  const tabset = tabs({
    label: t("templates.views"),
    variant: "pill",
    tabs: VIEWS.map((id) => ({ id, label: t(`templates.view.${id}`) })),
    current: "all",
    render: (id, panel) => { panel.append(tools, list); if (!quiet) { shown = id; load(); } },
  });
  quiet = false;
  view.append(head, h("p", { class: "os-muted os-lede", text: t("templates.lede") }), tabset);

  async function load() {
    clear(list);
    list.setAttribute("aria-busy", "true");
    list.append(skeletonRows(3));
    try {
      const page = await ctx.api.templates.list(shown, folder || undefined);
      items = page.items || [];
      list.removeAttribute("aria-busy");
      render();
    } catch (err) {
      list.removeAttribute("aria-busy");
      if (ctx.failed(err)) return;
      errorState(list, err, load);
    }
  }
  async function loadPeople() {
    try {
      for (const u of (await ctx.api.users.list()).items || []) people.set(u.id, u.name || u.email || "");
      render();
    } catch { /* not an admin: owners read You or — */ }
  }
  const owner = (tp) => (tp.owner_user_id && tp.owner_user_id === ctx.session?.user_id ? t("agreements.you") : people.get(tp.owner_user_id) || "—");
  /// The row's one main action keeps its word on phones (UX-08): a bare paper plane read as Send.
  const useButton = (name, href) => {
    const b = button(t("templates.use"), { icon: "layout-template", size: "sm", variant: "primary", attrs: { "aria-label": t("templates.use-named", { name }) }, onClick: () => ctx.navigate(href) });
    b.classList.add("os-btn--keep-label");
    return b;
  };

  async function loadFolders() {
    try { folders = (await ctx.api.listFolders("templates")).items || []; } catch { folders = []; }
    drawFolders();
  }
  const folderName = (id) => folders.find((f) => f.id === id)?.name;

  function render() {
    clear(list);
    tools.hidden = !items.length && !folder;
    if (!items.length && folder) {
      list.append(emptyState({ illus: "templates", title: t("templates.folder.empty"), text: "", testId: "empty-template-folder" }));
      return;
    }
    if (!items.length && shown !== "all") {
      list.append(emptyState({ illus: "templates", title: t(`templates.empty-view.${shown}`), text: "", testId: `empty-templates-${shown}` }));
      return;
    }
    if (!items.length) {
      list.append(emptyState({ illus: "templates", title: t("empty.templates.title"), text: t("empty.templates.text"), action: button(t("templates.new"), { icon: "plus", variant: "primary", onClick: () => ctx.navigate("#/templates/new") }), testId: "empty-templates" }));
      return;
    }
    const matches = matchTemplates(items, search.value);
    if (!matches.length) {
      list.append(emptyState({ illus: "search", title: t("templates.no-match", { query: search.value.trim() }), text: "", action: button(t("action.clear-search"), { variant: "primary", onClick: () => { search.value = ""; search.focus(); render(); } }), testId: "empty-template-search" }));
      return;
    }
    const table = h("table", { class: "os-table os-table--rows os-table--cards" },
      h("caption", { class: "os-sr-only", text: t("templates.caption") }),
      h("thead", {}, h("tr", {},
        h("th", { attrs: { scope: "col" }, text: t("templates.col.name") }),
        h("th", { attrs: { scope: "col" }, class: "os-col-date", text: t("templates.col.owner") }),
        h("th", { attrs: { scope: "col" }, class: "os-col-date", text: t("templates.col.used") }),
        h("th", { attrs: { scope: "col" }, class: "os-col-actions", text: t("templates.col.actions") }))));
    const tb = h("tbody");
    for (const tp of matches) {
      const href = `#/templates/${encodeURIComponent(tp.id)}`;
      const name = tp.name || t("templates.untitled");
      tb.append(h("tr", { class: "os-row", attrs: { "data-id": tp.id } },
        h("td", {}, h("div", { class: "os-col-subject os-tplrow" }, docThumb(),
          h("span", { class: "os-tplrow__text" },
            h("a", { href, class: "os-row-link os-tplrow__name", text: name }),
            h("span", { class: "os-row__sub os-muted os-tplrow__sub", text: tp.email_subject || t("home.template-no-subject") }),
            folderName(tp.folder_id) ? h("span", { attrs: { "data-testid": "tpl-in-folder" } }, pill(folderName(tp.folder_id), { ic: "inbox" })) : null))),
        h("td", { class: "os-col-date", attrs: { "data-label": t("templates.col.owner") } }, owner(tp), tp.shared && canDo(tp, "owner") ? pill(t("templates.shared"), { ic: "users" }) : null),
        h("td", { class: "os-col-date os-muted", attrs: { "data-label": t("templates.col.used") } }, tp.last_used_at ? h("time", { attrs: { datetime: tp.last_used_at }, text: fmtDate(tp.last_used_at) }) : t("templates.never-used")),
        h("td", { class: "os-col-actions" },
          h("div", { class: "os-actions os-actions--row" },
            starButton(tp, name),
            useButton(name, href),
            menuButton({
              label: t("templates.actions-for", { name }),
              buttonOpts: { icon: "ellipsis", variant: "ghost", size: "sm", iconOnly: true },
              // What the caller's access allows (UXW-06); the server decides every call.
              items: () => [
                canDo(tp, "edit") ? { label: t("templates.edit-fields"), icon: "file-pen-line", run: () => ctx.navigate(`#/templates/${encodeURIComponent(tp.id)}/edit`) } : null,
                { label: t("templates.bulk.menu"), icon: "send", run: () => ctx.navigate(`#/templates/${encodeURIComponent(tp.id)}/bulk`) },
                canDo(tp, "edit") ? { label: t("templates.edit"), icon: "pencil", run: () => edit(tp) } : null,
                canDo(tp, "owner") ? { label: t("templates.share"), icon: "users", run: () => share(tp) } : null,
                { label: t("templates.folder.move"), icon: "move", run: () => move(tp) },
                { label: t("templates.duplicate"), icon: "copy", run: () => duplicate(tp) },
                canDo(tp, "owner") ? { label: t("templates.delete"), icon: "trash-2", danger: true, run: () => remove(tp) } : null,
              ].filter(Boolean),
            })))));
    }
    table.append(tb);
    list.append(h("div", { class: "os-table-wrap" }, table));
  }

  /// The row's star (UXW-06): adds the template to the member's Favourites or takes it
  /// out; a toggle button (`aria-pressed`).
  function starButton(tp, name) {
    const on = !!tp.favourite;
    return iconButton(t(on ? "templates.unfavourite" : "templates.favourite", { name }), on ? "os-star-filled" : "os-star", {
      size: "sm",
      attrs: { "aria-pressed": String(on), "data-testid": "tpl-star" },
      onClick: async () => {
        try {
          await ctx.api.templates.favourite(tp.id, !on);
          tp.favourite = !on;
          toast(t(on ? "templates.unfavourited" : "templates.favourited"), "success");
          if (shown === "favourites") load(); else render();
        } catch (err) { if (!ctx.failed(err)) toastError(err); }
      },
    });
  }

  /// Share in a side panel (UXW-06): whom it is shared with, each "can edit" or not;
  /// add a member by email, a group, or everyone in the workspace; Save replaces the
  /// shares. The owner's (or an administrator's).
  async function share(tp) {
    let entries;
    let groups = [];
    try {
      entries = ((await ctx.api.templates.shares(tp.id)).items || []).map((x) => ({ ...x }));
      try { groups = (await ctx.api.groups.list()).items || []; } catch { /* no groups to offer */ }
    } catch (err) { if (!ctx.failed(err)) toastError(err); return; }
    const name = tp.name || t("templates.untitled");
    const done = await openPanel({
      id: "template-share",
      title: t("templates.share-title", { name }),
      description: t("templates.share-lede"),
      build(body) {
        const who = (e) => (e.account ? t("templates.share-everyone")
          : e.group ? t("templates.share-group", { name: e.group.name || "—" })
            : e.user?.name ? `${e.user.name} <${e.user.email || ""}>` : (e.user?.email || e.email || ""));
        const listEl = h("ul", { class: "os-use__roles", attrs: { "aria-label": t("templates.share-list"), "data-testid": "share-list" } });
        const draw = () => {
          clear(listEl);
          if (!entries.length) listEl.append(h("li", { class: "os-muted os-small", attrs: { "data-testid": "share-none" }, text: t("templates.share-none") }));
          entries.forEach((e, i) => {
            const label = who(e);
            const edit = checkbox(t("templates.share-can-edit"), { checked: !!e.can_edit, onChange: (v) => { e.can_edit = v; }, attrs: { "data-testid": "share-can-edit", "aria-describedby": `share-who-${i}` } });
            // The Use panel's person row (os-use__role), reused.
            listEl.append(h("li", { class: "os-use__role", attrs: { "data-testid": "share-entry" } },
              h("div", { class: "os-use__role-head" },
                h("strong", { id: `share-who-${i}`, text: label }),
                h("span", { class: "os-spacer" }),
                iconButton(t("templates.share-remove", { who: label }), "x", { size: "sm", onClick: () => { entries.splice(i, 1); draw(); } })),
              edit.el));
          });
        };
        draw();
        const email = field(t("templates.share-email"), { id: "share-email", type: "email", maxLength: 320, attrs: { "data-testid": "share-email" } });
        const add = () => {
          const v = email.input.value.trim();
          if (!isEmail(v)) { email.setError(t("templates.share-bad-email")); email.input.focus(); return; }
          email.setError("");
          if (!hasShare(entries, { email: v })) entries.push({ email: v, can_edit: false });
          email.input.value = "";
          draw();
        };
        email.input.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); add(); } });
        const addBtn = button(t("templates.share-add"), { icon: "user-plus", size: "sm", attrs: { "data-testid": "share-add" }, onClick: add });
        const parts = [h("h3", { class: "os-card__title", text: t("templates.share-list") }), listEl, email.el, h("div", { class: "os-actions" }, addBtn)];
        if (groups.length) {
          const pick = selectField(t("templates.share-group-pick"), [["", t("templates.share-group-none")], ...groups.map((g) => [g.id, g.name])], {
            id: "share-group",
            attrs: { "data-testid": "share-group" },
            onChange: (id) => {
              const g = groups.find((x) => x.id === id);
              if (g && !hasShare(entries, { group: g })) entries.push({ group: { id: g.id, name: g.name }, can_edit: false });
              pick.select.value = "";
              draw();
            },
          });
          parts.push(pick.el);
        }
        parts.push(h("div", { class: "os-actions" }, button(t("templates.share-everyone-add"), { icon: "users", size: "sm", attrs: { "data-testid": "share-everyone" }, onClick: () => {
          if (!hasShare(entries, { account: true })) entries.push({ account: true, can_edit: false });
          draw();
        } })));
        body.append(...parts);
      },
      actions: [
        { label: t("action.cancel"), value: null },
        { label: t("templates.save"), variant: "primary", attrs: { "data-testid": "share-save" }, onClick: async () => { await ctx.api.templates.setShares(tp.id, shareItems(entries)); return true; } },
      ],
    });
    if (!done) return;
    toast(t("templates.share-saved"), "success");
    load();
  }

  /// Edit details in a side panel (T-01): name, email subject, message.
  async function edit(tp) {
    let f = {};
    const done = await openPanel({
      id: "template-edit",
      title: t("templates.edit-title"),
      build(body) {
        f.name = h("input", { id: "tpl-name", class: "os-input", value: tp.name || "", maxLength: 255, attrs: { autofocus: true, "aria-describedby": "tpl-name-err" } });
        f.subject = h("input", { id: "tpl-subject", class: "os-input", value: tp.email_subject || "", maxLength: 255 });
        f.message = h("textarea", { id: "tpl-message", class: "os-input os-textarea", rows: 5, maxLength: 10000, value: tp.email_message || "" });
        f.err = h("p", { id: "tpl-name-err", class: "os-field-error", attrs: { "aria-live": "polite" } });
        body.append(
          h("label", { class: "os-label", attrs: { for: "tpl-name" }, text: t("template.name") }), f.name, f.err,
          h("label", { class: "os-label", attrs: { for: "tpl-subject" }, text: t("template.email-subject") }), f.subject,
          h("label", { class: "os-label", attrs: { for: "tpl-message" }, text: t("prepare.message") }), f.message);
      },
      actions: [
        { label: t("action.cancel"), value: null },
        {
          label: t("templates.save"), variant: "primary",
          onClick: async () => {
            const name = f.name.value.trim();
            if (!name) { f.err.textContent = t("form.required"); f.name.setAttribute("aria-invalid", "true"); f.name.focus(); return undefined; }
            const { etag } = await ctx.api.templates.get(tp.id);
            await ctx.api.templates.patch(tp.id, etag, { name, email_subject: f.subject.value, email_message: f.message.value });
            return true;
          },
        },
      ],
    });
    if (!done) return;
    toast(t("templates.saved-details"), "success");
    load();
  }
  /// New folder (TSH-03): a name in a side panel; `exists` from the server is shown.
  async function makeFolder() {
    let f;
    const done = await openPanel({
      id: "template-folder-new",
      title: t("templates.folder.new-title"),
      build(body) {
        f = field(t("templates.folder.name"), { id: "tpl-folder-name", maxLength: 100, attrs: { "data-testid": "tpl-folder-name", autofocus: true } });
        body.append(f.el);
      },
      actions: [
        { label: t("action.cancel"), value: null },
        {
          label: t("templates.folder.create"), variant: "primary", attrs: { "data-testid": "tpl-folder-create" },
          onClick: async () => {
            const name = f.input.value.trim();
            if (!name) { f.setError(t("form.required")); f.input.focus(); return undefined; }
            try {
              return await ctx.api.createFolder(name, "templates");
            } catch (err) {
              if (err?.errors?.some((x) => x.code === "exists")) { f.setError(t("templates.folder.exists")); f.input.focus(); return undefined; }
              throw err;
            }
          },
        },
      ],
    });
    if (!done) return;
    toast(t("templates.folder.created", { name: done.name }), "success");
    await loadFolders();
  }

  /// Move to folder (TSH-03): the member's template folders, or none.
  async function move(tp) {
    if (!folders.length) await loadFolders();
    const name = tp.name || t("templates.untitled");
    let pick;
    const done = await openPanel({
      id: "template-move",
      title: t("templates.folder.move-title", { name }),
      build(body) {
        pick = selectField(t("templates.folder.label"), [["", t("templates.folder.no-folder")], ...folders.map((f) => [f.id, f.name])], { id: "tpl-move-to", value: tp.folder_id || "", attrs: { "data-testid": "tpl-move-to" } });
        body.append(pick.el);
        if (!folders.length) body.append(h("p", { class: "os-muted os-small", text: t("templates.folder.none-yet") }));
      },
      actions: [
        { label: t("action.cancel"), value: null },
        { label: t("templates.folder.move-do"), variant: "primary", attrs: { "data-testid": "tpl-move-save" }, onClick: async () => { await ctx.api.moveTemplates(pick.select.value || null, [tp.id]); return pick.select.value || "none"; } },
      ],
    });
    if (!done) return;
    toast(done === "none" ? t("templates.folder.moved-out") : t("templates.folder.moved", { name: folderName(done) || "" }), "success");
    await loadFolders();
    load();
  }

  async function duplicate(tp) {
    try { await ctx.api.templates.duplicate(tp.id); toast(t("templates.duplicated"), "success"); load(); } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }
  async function remove(tp) {
    const name = tp.name || t("templates.untitled");
    if (!(await confirmDialog(t("templates.delete-title"), t("templates.delete-text", { name }), { confirm: t("templates.delete"), danger: true }))) return;
    try {
      const { etag } = await ctx.api.templates.get(tp.id);
      await ctx.api.templates.remove(tp.id, etag);
      toast(t("templates.deleted"), "success");
      load();
    } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }

  register("template.new", { label: t("templates.new"), run: () => ctx.navigate("#/templates/new") });
  register("templatefolder.new", { label: t("templates.folder.new"), run: () => makeFolder() });
  load();
  loadPeople();
  loadFolders();
  return () => { unregisterPrefix("template."); unregisterPrefix("templatefolder."); };
}

/// `#/templates/{id}`: use a template, or several together (composite templates, slice
/// 3, after DocuSign's). The documents on the left; the templates, the people, the email
/// and Send in a sticky panel on the right (T-03); stacked on phones, the form first.
/// "Add a template" puts another template's documents and roles in the same envelope: a
/// role named in two templates (any case) is one person, the server's rule
/// (templatemodel.js `mergeTemplates`). Send, and Edit before sending, are one
/// `POST /envelopes/from-templates`: the server makes the envelope from the templates'
/// stored documents.
export function mountUse(view, ctx, [rawId]) {
  const id = decodeURIComponent(rawId);
  const body = h("div", { class: "os-detail", attrs: { "aria-busy": "true" } }, skeletonRows(4));
  view.append(body);
  /// The whole templates, in the envelope's order; the first is the one opened.
  const chosen = [];
  /// The templates the caller may use, offered by Add a template.
  let usable = [];
  /// What was typed, kept when a template is added or removed: people by role key,
  /// people beyond the roles, the subject and message once edited.
  const people = {};
  const extra = [];
  let typed = { subject: null, message: null };
  let focusAfter = "#use-name-0";

  async function load() {
    try {
      const [{ template }, list] = await Promise.all([ctx.api.templates.get(id), ctx.api.templates.list().catch(() => ({ items: [] }))]);
      chosen.push(template);
      usable = list.items || [];
      render();
    } catch (err) {
      if (ctx.failed(err)) return;
      errorState(body, err, load);
    } finally {
      body.removeAttribute("aria-busy");
    }
  }

  async function addTemplate(tid) {
    try {
      const { template } = await ctx.api.templates.get(tid);
      if (mergeTemplates([...chosen, template]).conflict >= 0) {
        toast(t("use.role-conflict", { name: template.name || t("templates.untitled") }), "error");
        return;
      }
      chosen.push(template);
      focusAfter = "[data-testid=use-add-template]";
      render();
      toast(t("use.template-added", { name: template.name || t("templates.untitled") }), "success");
    } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }

  function render() {
    clear(body);
    const lead = chosen[0];
    const { roles, roleOf } = mergeTemplates(chosen);
    const items = chosen.flatMap((tp) => (Array.isArray(tp.documents) ? tp.documents : []).map((d) => ({ tp, d })));
    const fields = chosen.flatMap((tp) => (Array.isArray(tp.fields) ? tp.fields : []).map((f) => ({ tp, f })));
    for (const r of roles) people[r.key] ||= { name: "", email: "" };
    const back = h("a", { href: "#/templates", class: "os-back" }, icon("chevron-left", { size: 16 }), h("span", { text: t("templates.title") }));
    const title = h("h1", { class: "os-page-title", text: t("use.title", { name: lead.name || t("templates.untitled") }) });

    const form = h("form", { class: "os-use os-usepanel", attrs: { novalidate: true, "aria-labelledby": "use-h" } });
    const subject = h("input", { id: "use-subject", class: "os-input", maxLength: 255, value: typed.subject ?? (lead.email_subject || lead.name || "") });
    const message = h("textarea", { id: "use-message", class: "os-input os-textarea", rows: 3, maxLength: 10000, value: typed.message ?? (lead.email_message || ""), placeholder: t("prepare.message-placeholder") });
    subject.addEventListener("input", () => { typed.subject = subject.value; });
    message.addEventListener("input", () => { typed.message = message.value; });

    // The templates in this envelope (composite templates): the first is the one opened;
    // the others can be taken out again.
    const tplList = h("ol", { class: "os-use__roles", attrs: { "aria-label": t("use.templates"), "data-testid": "use-templates" } });
    chosen.forEach((tp, i) => {
      const name = tp.name || t("templates.untitled");
      const n = Array.isArray(tp.documents) ? tp.documents.length : 0;
      tplList.append(h("li", { class: "os-use__role", attrs: { "data-testid": "use-template" } },
        h("div", { class: "os-use__role-head" },
          h("span", { class: "os-order", text: String(i + 1) }),
          h("strong", { text: name }),
          h("span", { class: "os-muted os-small", text: t("use.template-docs", { n }) }),
          h("span", { class: "os-spacer" }),
          i > 0 ? button(t("use.remove-template", { name }), { icon: "x", size: "sm", variant: "ghost", iconOnly: true, attrs: { "data-testid": "use-remove-template" }, onClick: () => { chosen.splice(i, 1); focusAfter = "[data-testid=use-add-template]"; render(); } }) : null)));
    });
    const others = usable.filter((x) => !chosen.some((c) => c.id === x.id));
    const tplCard = h("section", { class: "os-usepanel__sec", attrs: { "aria-labelledby": "use-tpls-h" } },
      h("h3", { id: "use-tpls-h", class: "os-card__title", text: t("use.templates") }),
      h("p", { class: "os-muted os-small", text: t("use.templates-help") }), tplList);
    if (others.length) {
      const pick = selectField(t("use.add-template"), [["", t("use.add-template-choose")], ...others.map((x) => [x.id, x.name || t("templates.untitled")])], {
        id: "use-add-template",
        attrs: { "data-testid": "use-add-template" },
        onChange: (v) => { if (v) addTemplate(v); },
      });
      tplCard.append(pick.el);
    }

    const rolesCard = h("section", { class: "os-usepanel__sec", attrs: { "aria-labelledby": "use-roles-h" } },
      h("h3", { id: "use-roles-h", class: "os-card__title", text: t("use.people") }),
      h("p", { class: "os-muted os-small", text: t(chosen.length > 1 ? "use.people-help-n" : "use.people-help") }));
    if (!roles.length) {
      rolesCard.append(emptyState({ illus: "recipients", title: t("empty.use-roles.title"), text: t("empty.use-roles.text"), testId: "empty-use-roles" }));
    }
    const errors = new Map();
    const list = h("ol", { class: "os-use__roles" });
    // Contacts (UX-08): the people this account has sent to, suggested as you type a
    // name or an email; choosing one fills the other.
    const byEmail = new Map();
    const byName = new Map();
    const emailList = h("datalist", { id: "use-contacts-email" });
    const nameList = h("datalist", { id: "use-contacts-name" });
    let lookup = 0;
    const suggest = (q) => {
      clearTimeout(lookup);
      if (!q.trim()) return;
      lookup = setTimeout(async () => {
        let found = [];
        try { found = (await ctx.api.contacts(q.trim(), 8))?.items || []; } catch { return; }
        clear(emailList); clear(nameList);
        for (const c of found) {
          if (!c?.email) continue;
          byEmail.set(c.email.toLowerCase(), c.name || "");
          if (c.name) byName.set(c.name.toLowerCase(), c.email);
          emailList.append(h("option", { value: c.email, attrs: { label: c.name || c.email } }));
          if (c.name) nameList.append(h("option", { value: c.name, attrs: { label: c.email } }));
        }
      }, 200);
    };
    /// A name and an email input pair that suggest contacts and complete each other.
    const personInputs = (nid, eid, describe, p, testIds = ["use-name", "use-email"]) => {
      const name = h("input", { id: nid, class: "os-input", autocomplete: "off", maxLength: 255, value: p.name || "", attrs: { list: "use-contacts-name", "aria-describedby": describe, "data-testid": testIds[0] } });
      const email = h("input", { id: eid, class: "os-input", type: "email", autocomplete: "off", value: p.email || "", attrs: { list: "use-contacts-email", "aria-describedby": describe, "data-testid": testIds[1] } });
      name.addEventListener("input", () => {
        suggest(name.value);
        const e = byName.get(name.value.trim().toLowerCase());
        if (e && !email.value) email.value = e;
        p.name = name.value; p.email = email.value;
      });
      email.addEventListener("input", () => {
        suggest(email.value);
        const n = byEmail.get(email.value.trim().toLowerCase());
        if (n && !name.value) name.value = n;
        p.name = name.value; p.email = email.value;
      });
      return [name, email];
    };
    roles.forEach((r, i) => {
      const nid = `use-name-${i}`;
      const eid = `use-email-${i}`;
      const hid = `use-role-${i}-h`;
      const err = h("p", { id: `use-err-${i}`, class: "os-field-error", attrs: { "aria-live": "polite" } });
      errors.set(r.key, err);
      const [name, email] = personInputs(nid, eid, `${hid} use-err-${i}`, people[r.key]);
      list.append(h("li", { class: `os-use__role os-r${(i % 6) + 1}` },
        h("div", { class: "os-use__role-head" },
          h("span", { class: "os-rcpt__dot", attrs: { "aria-hidden": "true" } }),
          h("span", { class: "os-order", attrs: { title: t("prepare.routing-order") }, text: String(r.routing_order) }),
          h("strong", { id: hid, text: r.name }),
          h("span", { class: "os-muted os-small", text: t(`rtype.${r.type}`) })),
        h("div", { class: "os-use__inputs" },
          h("div", {}, h("label", { class: "os-label", attrs: { for: nid }, text: t("prepare.name") }), name),
          h("div", {}, h("label", { class: "os-label", attrs: { for: eid }, text: t("prepare.email") }), email)),
        err));
    });
    rolesCard.append(list, emailList, nameList);

    // People beyond the roles (UX-08): a copy, or another signer whose fields are placed
    // in the editor.
    const extraList = h("ol", { class: "os-use__roles os-use__extra", attrs: { "aria-label": t("use.extra") } });
    const addExtra = button(t("use.add-recipient"), { icon: "user-plus", size: "sm", command: "usetemplate.add-recipient", onClick: () => addPerson() });
    rolesCard.append(extraList, h("div", { class: "os-use__add" }, addExtra));
    let extraSeq = 0;
    function drawPerson(p, focus) {
      const k = extraSeq++;
      const hid = `use-x-${k}-h`;
      const err = h("p", { id: `use-x-err-${k}`, class: "os-field-error", attrs: { "aria-live": "polite" } });
      const [name, email] = personInputs(`use-x-name-${k}`, `use-x-email-${k}`, `${hid} use-x-err-${k}`, p, ["extra-name", "extra-email"]);
      const type = selectField(t("use.recipient-type"), [["cc", t("rtype.cc")], ["signer", t("rtype.signer")]], { id: `use-x-type-${k}`, value: p.type, attrs: { "data-testid": "extra-type", "aria-describedby": hid }, onChange: (v) => { p.type = v; } });
      const item = h("li", { class: "os-use__role os-use__role--extra", attrs: { "data-extra": String(k) } },
        h("div", { class: "os-use__role-head" },
          h("strong", { id: hid, text: t("use.extra-n", { n: extra.indexOf(p) + 1 }) }),
          h("span", { class: "os-spacer" }),
          button(t("use.remove-extra", { n: extra.indexOf(p) + 1 }), { icon: "x", size: "sm", variant: "ghost", iconOnly: true, onClick: () => {
            extra.splice(extra.indexOf(p), 1);
            item.remove();
            addExtra.focus();
          } })),
        type.el,
        h("div", { class: "os-use__inputs" },
          h("div", {}, h("label", { class: "os-label", attrs: { for: `use-x-name-${k}` }, text: t("prepare.name") }), name),
          h("div", {}, h("label", { class: "os-label", attrs: { for: `use-x-email-${k}` }, text: t("prepare.email") }), email)),
        err);
      p.item = item;
      extraList.append(item);
      if (focus) name.focus();
    }
    function addPerson() {
      const p = { name: "", email: "", type: "cc" };
      extra.push(p);
      drawPerson(p, true);
    }
    for (const p of extra) drawPerson(p, false);
    register("usetemplate.add-recipient", { label: t("use.add-recipient"), run: () => addPerson() });

    const messageCard = h("section", { class: "os-usepanel__sec", attrs: { "aria-labelledby": "use-msg-h" } },
      h("h3", { id: "use-msg-h", class: "os-card__title", text: t("use.email") }),
      h("label", { class: "os-label", attrs: { for: "use-subject" }, text: t("prepare.subject") }), subject,
      h("label", { class: "os-label", attrs: { for: "use-message" }, text: t("prepare.message") }), message);

    const send = button(t("prepare.send"), { icon: "send", variant: "primary", type: "submit", attrs: { "data-testid": "use-send" } });
    const edit = button(t(items.length ? "use.edit-first" : "use.continue"), { icon: "file-pen-line", variant: items.length ? "secondary" : "primary", attrs: { "data-testid": "use-edit" } });
    const actions = h("div", { class: "os-actions os-usepanel__foot" }, items.length ? send : null, edit);

    form.append(h("h2", { id: "use-h", class: "os-usepanel__title", text: t("use.panel") }),
      h("div", { class: "os-usepanel__body" }, tplCard, rolesCard, messageCard), actions);

    const docsCard = h("section", { class: "os-usedoc", attrs: { "aria-labelledby": "use-docs-h" } },
      h("h2", { id: "use-docs-h", class: "os-sr-only", text: t("use.document") }));
    if (items.length) {
      // The field count and a key to the role colours above the pages (UX-08), and each
      // role's fields outlined on them in its colour.
      const colourOf = new Map(roles.map((r, i) => [r.key, (i % 6) + 1]));
      const nameOf = new Map(roles.map((r) => [r.key, r.name]));
      const keyOf = (f) => roleOf.get(f.role_id);
      docsCard.append(h("div", { class: "os-usedoc__bar" },
        h("p", { class: "os-muted os-small", attrs: { "data-testid": "use-fields-n" }, text: t("use.fields-n", { n: fields.length }) }),
        h("ul", { class: "os-usedoc__key", attrs: { "aria-label": t("use.key") } },
          ...roles.filter((r) => fields.some(({ f }) => keyOf(f) === r.key)).map((r) => h("li", { class: `os-r${colourOf.get(r.key)}` },
            h("span", { class: "os-rcpt__dot", attrs: { "aria-hidden": "true" } }), h("span", { text: r.name }))))));
      for (const { tp, d } of items) {
        const decorate = (page, n, scale) => {
          for (const { tp: ft, f } of fields) {
            const p = f.placement;
            const key = keyOf(f);
            if (ft !== tp || f.document_id !== d.id || !p || p.page !== n || !colourOf.has(key)) continue;
            const box = h("span", { class: `os-use__field os-r${colourOf.get(key)}`, attrs: { "aria-hidden": "true", title: nameOf.get(key) } });
            Object.assign(box.style, { left: `${p.x * scale}px`, top: `${p.y * scale}px`, width: `${p.width * scale}px`, height: `${p.height * scale}px` }); // px-ok: PDF points × scale
            page.append(box);
          }
        };
        docsCard.append(pdfPreview({ load: () => ctx.api.templates.documentContent(tp.id, d.id), name: d.name, height: 32.5, decorate }).el);
      }
    } else {
      docsCard.append(h("div", { class: "os-card" }, h("p", { class: "os-muted", attrs: { "data-testid": "use-no-docs" }, text: t("use.no-docs") })));
    }

    body.append(back, h("div", { class: "os-page-head" }, h("div", { class: "os-page-head__main" }, title)),
      h("div", { class: "os-usegrid" }, docsCard, form));

    function check() {
      for (const e of errors.values()) e.textContent = "";
      for (const inp of form.querySelectorAll("[aria-invalid]")) inp.removeAttribute("aria-invalid");
      const probs = peopleProblems(roles.map((r) => ({ name: r.key })), people);
      for (const p of probs) {
        const i = roles.findIndex((r) => r.key === p.role);
        const err = errors.get(p.role);
        err.textContent = [err.textContent, t(p.problem === "name" ? "use.need-name" : "use.need-email")].filter(Boolean).join(" ");
        form.querySelector(`#use-${p.problem}-${i}`)?.setAttribute("aria-invalid", "true");
      }
      for (const p of extra) p.item.lastChild.textContent = "";
      const xprobs = extraProblems(extra);
      for (const x of xprobs) {
        const p = extra[x.index];
        const err = p.item.lastChild;
        err.textContent = [err.textContent, t(x.problem === "name" ? "use.need-name" : "use.need-email")].filter(Boolean).join(" ");
        p.item.querySelector(`[data-testid="extra-${x.problem}"]`)?.setAttribute("aria-invalid", "true");
      }
      if (!probs.length && xprobs.length) {
        extra[xprobs[0].index].item.querySelector(`[data-testid="extra-${xprobs[0].problem}"]`)?.focus();
        return false;
      }
      if (probs.length) {
        const first = probs[0];
        form.querySelector(`#use-${first.problem}-${roles.findIndex((r) => r.key === first.role)}`)?.focus();
        return false;
      }
      return true;
    }

    const create = (status) => ctx.api.templates.use(fromTemplatesBody(chosen.map((c) => c.id), roles, people, { extra, subject: subject.value, message: message.value, status }));

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (!items.length || !check()) return;
      // An added signer has no fields yet: they are placed in the editor first.
      if (extra.some((p) => p.type === "signer")) { toast(t("use.extra-signer"), "info"); edit.focus(); return; }
      const signers = roles.filter((r) => r.type === "signer").length;
      if (!(await confirmDialog(t("send.confirm-title"), t("send.confirm-text", { n: signers, subject: subject.value.trim() || lead.name }), { confirm: t("prepare.send") }))) return;
      await busy(send, async () => {
        try {
          const env = await create("sent");
          toast(t("send.sent"), "success");
          ctx.navigate(`#/envelopes/${encodeURIComponent(env.id)}`);
        } catch (err) { if (!ctx.failed(err)) toastError(err); }
      });
    });
    edit.addEventListener("click", async () => {
      if (!check()) return;
      await busy(edit, async () => {
        try {
          const env = await create("draft");
          ctx.navigate(`#/prepare/${encodeURIComponent(env.id)}`);
        } catch (err) { if (!ctx.failed(err)) toastError(err); }
      });
    });
    form.querySelector(focusAfter)?.focus();
  }

  load();
  return () => unregisterPrefix("usetemplate.");
}
