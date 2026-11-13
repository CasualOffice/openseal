// Templates (WEB-02, WEB-06, WEB-09; docs/47 §Screens "Templates", after DocuSign's):
// the list with search, owner and last use; a new template in the editor
// (`#/templates/new`, prepare.js in template mode); Edit reopens its documents, roles
// and fields in the same editor (`#/templates/{id}/edit`); edit details (name, email
// subject and message) in a side panel; duplicate; delete (a destructive
// confirmation); and "Use" (`#/templates/{id}`): the document on the left, the roles
// and Send in a sticky side panel on the right (T-03).
//
// Using a template is one `POST /api/v1/envelopes` (templatemodel.js): the template's
// documents, its roles filled with people, and its fields bound to the roles' ids. A
// template without documents becomes a draft with its recipients, opened in the editor
// to add the PDF and fields. Every call is api.js's (WEB-10).

import { h, clear, fmtDate } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { toBase64 } from "./api.js";
import { register, unregisterPrefix } from "./commands.js";
import { button, busy, emptyState, skeletonRows, errorState, openPanel, confirmDialog, toast, toastError, pdfPreview, menuButton, selectField } from "./ui/index.js";
import { rolesOf, peopleProblems, extraProblems, envelopeFromTemplate } from "./templatemodel.js";

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
  const tools = h("div", { class: "os-filters" }, h("div", { class: "os-fieldrow os-filters__search" },
    h("label", { class: "os-sr-only", attrs: { for: "tpl-search" }, text: t("templates.search") }), search));
  const list = h("div", { class: "os-list os-surface-card", attrs: { "aria-live": "polite" } });
  view.append(head, h("p", { class: "os-muted os-lede", text: t("templates.lede") }), tools, list);

  async function load() {
    clear(list);
    list.setAttribute("aria-busy", "true");
    list.append(skeletonRows(3));
    try {
      const page = await ctx.api.templates.list();
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

  function render() {
    clear(list);
    tools.hidden = !items.length;
    if (!items.length) {
      list.append(emptyState({ illus: "templates", title: t("empty.templates.title"), text: t("empty.templates.text"), action: button(t("templates.new"), { icon: "plus", variant: "primary", onClick: () => ctx.navigate("#/templates/new") }), testId: "empty-templates" }));
      return;
    }
    const shown = matchTemplates(items, search.value);
    if (!shown.length) {
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
    for (const tp of shown) {
      const href = `#/templates/${encodeURIComponent(tp.id)}`;
      const name = tp.name || t("templates.untitled");
      tb.append(h("tr", { class: "os-row", attrs: { "data-id": tp.id } },
        h("td", {}, h("div", { class: "os-col-subject os-tplrow" }, docThumb(),
          h("span", { class: "os-tplrow__text" },
            h("a", { href, class: "os-row-link os-tplrow__name", text: name }),
            h("span", { class: "os-row__sub os-muted os-tplrow__sub", text: tp.email_subject || t("home.template-no-subject") })))),
        h("td", { class: "os-col-date", attrs: { "data-label": t("templates.col.owner") }, text: owner(tp) }),
        h("td", { class: "os-col-date os-muted", attrs: { "data-label": t("templates.col.used") } }, tp.last_used_at ? h("time", { attrs: { datetime: tp.last_used_at }, text: fmtDate(tp.last_used_at) }) : t("templates.never-used")),
        h("td", { class: "os-col-actions" },
          h("div", { class: "os-actions os-actions--row" },
            useButton(name, href),
            menuButton({
              label: t("templates.actions-for", { name }),
              buttonOpts: { icon: "ellipsis", variant: "ghost", size: "sm", iconOnly: true },
              items: () => [
                { label: t("templates.edit-fields"), icon: "file-pen-line", run: () => ctx.navigate(`#/templates/${encodeURIComponent(tp.id)}/edit`) },
                { label: t("templates.edit"), icon: "pencil", run: () => edit(tp) },
                { label: t("templates.duplicate"), icon: "copy", run: () => duplicate(tp) },
                { label: t("templates.delete"), icon: "trash-2", danger: true, run: () => remove(tp) },
              ],
            })))));
    }
    table.append(tb);
    list.append(h("div", { class: "os-table-wrap" }, table));
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
  load();
  loadPeople();
  return () => unregisterPrefix("template.");
}

/// `#/templates/{id}`: use a template. The document on the left, the people, the email
/// and Send in a sticky panel on the right (T-03); stacked on phones, the form first.
export function mountUse(view, ctx, [rawId]) {
  const id = decodeURIComponent(rawId);
  const body = h("div", { class: "os-detail", attrs: { "aria-busy": "true" } }, skeletonRows(4));
  view.append(body);

  async function load() {
    try {
      const { template } = await ctx.api.templates.get(id);
      render(template);
    } catch (err) {
      if (ctx.failed(err)) return;
      errorState(body, err, load);
    } finally {
      body.removeAttribute("aria-busy");
    }
  }

  function render(tp) {
    clear(body);
    const roles = rolesOf(tp);
    const docs = Array.isArray(tp.documents) ? tp.documents : [];
    const fields = Array.isArray(tp.fields) ? tp.fields : [];
    const people = {};
    const back = h("a", { href: "#/templates", class: "os-back" }, icon("chevron-left", { size: 16 }), h("span", { text: t("templates.title") }));
    const title = h("h1", { class: "os-page-title", text: t("use.title", { name: tp.name || t("templates.untitled") }) });

    const form = h("form", { class: "os-use os-usepanel", attrs: { novalidate: true, "aria-labelledby": "use-h" } });
    const subject = h("input", { id: "use-subject", class: "os-input", maxLength: 255, value: tp.email_subject || tp.name || "" });
    const message = h("textarea", { id: "use-message", class: "os-input os-textarea", rows: 3, maxLength: 10000, value: tp.email_message || "", placeholder: t("prepare.message-placeholder") });

    const rolesCard = h("section", { class: "os-usepanel__sec", attrs: { "aria-labelledby": "use-roles-h" } },
      h("h3", { id: "use-roles-h", class: "os-card__title", text: t("use.people") }),
      h("p", { class: "os-muted os-small", text: t("use.people-help") }));
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
        let items = [];
        try { items = (await ctx.api.contacts(q.trim(), 8))?.items || []; } catch { return; }
        clear(emailList); clear(nameList);
        for (const c of items) {
          if (!c?.email) continue;
          byEmail.set(c.email.toLowerCase(), c.name || "");
          if (c.name) byName.set(c.name.toLowerCase(), c.email);
          emailList.append(h("option", { value: c.email, attrs: { label: c.name || c.email } }));
          if (c.name) nameList.append(h("option", { value: c.name, attrs: { label: c.email } }));
        }
      }, 200);
    };
    /// A name and an email input pair that suggest contacts and complete each other.
    const personInputs = (nid, eid, describe, onChange, testIds = ["use-name", "use-email"]) => {
      const name = h("input", { id: nid, class: "os-input", autocomplete: "off", maxLength: 255, attrs: { list: "use-contacts-name", "aria-describedby": describe, "data-testid": testIds[0] } });
      const email = h("input", { id: eid, class: "os-input", type: "email", autocomplete: "off", attrs: { list: "use-contacts-email", "aria-describedby": describe, "data-testid": testIds[1] } });
      name.addEventListener("input", () => {
        suggest(name.value);
        const e = byName.get(name.value.trim().toLowerCase());
        if (e && !email.value) email.value = e;
        onChange(name.value, email.value);
      });
      email.addEventListener("input", () => {
        suggest(email.value);
        const n = byEmail.get(email.value.trim().toLowerCase());
        if (n && !name.value) name.value = n;
        onChange(name.value, email.value);
      });
      return [name, email];
    };
    roles.forEach((r, i) => {
      people[r.name] = { name: "", email: "" };
      const nid = `use-name-${i}`;
      const eid = `use-email-${i}`;
      const hid = `use-role-${i}-h`;
      const err = h("p", { id: `use-err-${i}`, class: "os-field-error", attrs: { "aria-live": "polite" } });
      errors.set(r.name, err);
      const [name, email] = personInputs(nid, eid, `${hid} use-err-${i}`, (n, e) => { people[r.name] = { name: n, email: e }; });
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
    const extra = [];
    const extraList = h("ol", { class: "os-use__roles os-use__extra", attrs: { "aria-label": t("use.extra") } });
    const addExtra = button(t("use.add-recipient"), { icon: "user-plus", size: "sm", command: "usetemplate.add-recipient", onClick: () => addPerson() });
    rolesCard.append(extraList, h("div", { class: "os-use__add" }, addExtra));
    let extraSeq = 0;
    function addPerson() {
      const k = extraSeq++;
      const p = { name: "", email: "", type: "cc" };
      extra.push(p);
      const hid = `use-x-${k}-h`;
      const err = h("p", { id: `use-x-err-${k}`, class: "os-field-error", attrs: { "aria-live": "polite" } });
      const [name, email] = personInputs(`use-x-name-${k}`, `use-x-email-${k}`, `${hid} use-x-err-${k}`, (n, e) => { p.name = n; p.email = e; }, ["extra-name", "extra-email"]);
      const type = selectField(t("use.recipient-type"), [["cc", t("rtype.cc")], ["signer", t("rtype.signer")]], { id: `use-x-type-${k}`, value: "cc", attrs: { "data-testid": "extra-type", "aria-describedby": hid }, onChange: (v) => { p.type = v; } });
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
      item.err = err;
      p.item = item;
      extraList.append(item);
      name.focus();
    }
    register("usetemplate.add-recipient", { label: t("use.add-recipient"), run: () => addPerson() });

    const messageCard = h("section", { class: "os-usepanel__sec", attrs: { "aria-labelledby": "use-msg-h" } },
      h("h3", { id: "use-msg-h", class: "os-card__title", text: t("use.email") }),
      h("label", { class: "os-label", attrs: { for: "use-subject" }, text: t("prepare.subject") }), subject,
      h("label", { class: "os-label", attrs: { for: "use-message" }, text: t("prepare.message") }), message);

    const send = button(t("prepare.send"), { icon: "send", variant: "primary", type: "submit", attrs: { "data-testid": "use-send" } });
    const edit = button(t(docs.length ? "use.edit-first" : "use.continue"), { icon: "file-pen-line", variant: docs.length ? "secondary" : "primary", attrs: { "data-testid": "use-edit" } });
    const actions = h("div", { class: "os-actions os-usepanel__foot" }, docs.length ? send : null, edit);

    form.append(h("h2", { id: "use-h", class: "os-usepanel__title", text: t("use.panel") }),
      h("div", { class: "os-usepanel__body" }, rolesCard, messageCard), actions);

    const docsCard = h("section", { class: "os-usedoc", attrs: { "aria-labelledby": "use-docs-h" } },
      h("h2", { id: "use-docs-h", class: "os-sr-only", text: t("use.document") }));
    if (docs.length) {
      // The field count and a key to the role colours above the pages (UX-08), and each
      // role's fields outlined on them in its colour.
      const colourOf = new Map(roles.map((r, i) => [r.id, (i % 6) + 1]));
      const nameOf = new Map(roles.map((r) => [r.id, r.name]));
      docsCard.append(h("div", { class: "os-usedoc__bar" },
        h("p", { class: "os-muted os-small", attrs: { "data-testid": "use-fields-n" }, text: t("use.fields-n", { n: fields.length }) }),
        h("ul", { class: "os-usedoc__key", attrs: { "aria-label": t("use.key") } },
          ...roles.filter((r) => fields.some((f) => f.role_id === r.id)).map((r) => h("li", { class: `os-r${colourOf.get(r.id)}` },
            h("span", { class: "os-rcpt__dot", attrs: { "aria-hidden": "true" } }), h("span", { text: r.name }))))));
      for (const d of docs) {
        const decorate = (page, n, scale) => {
          for (const f of fields) {
            const p = f.placement;
            if (f.document_id !== d.id || !p || p.page !== n || !colourOf.has(f.role_id)) continue;
            const box = h("span", { class: `os-use__field os-r${colourOf.get(f.role_id)}`, attrs: { "aria-hidden": "true", title: nameOf.get(f.role_id) } });
            Object.assign(box.style, { left: `${p.x * scale}px`, top: `${p.y * scale}px`, width: `${p.width * scale}px`, height: `${p.height * scale}px` });
            page.append(box);
          }
        };
        docsCard.append(pdfPreview({ load: () => ctx.api.templates.documentContent(tp.id, d.id), name: d.name, height: 520, decorate }).el);
      }
    } else {
      docsCard.append(h("div", { class: "os-card" }, h("p", { class: "os-muted", attrs: { "data-testid": "use-no-docs" }, text: t("use.no-docs") })));
    }

    body.append(back, h("div", { class: "os-page-head" }, h("div", { class: "os-page-head__main" }, title)),
      h("div", { class: "os-usegrid" }, docsCard, form));

    function check() {
      for (const e of errors.values()) e.textContent = "";
      for (const inp of form.querySelectorAll("[aria-invalid]")) inp.removeAttribute("aria-invalid");
      const probs = peopleProblems(roles, people);
      for (const p of probs) {
        const i = roles.findIndex((r) => r.name === p.role);
        const err = errors.get(p.role);
        err.textContent = [err.textContent, t(p.problem === "name" ? "use.need-name" : "use.need-email")].filter(Boolean).join(" ");
        form.querySelector(`#use-${p.problem}-${i}`)?.setAttribute("aria-invalid", "true");
      }
      for (const p of extra) p.item.err.textContent = "";
      const xprobs = extraProblems(extra);
      for (const x of xprobs) {
        const p = extra[x.index];
        p.item.err.textContent = [p.item.err.textContent, t(x.problem === "name" ? "use.need-name" : "use.need-email")].filter(Boolean).join(" ");
        p.item.querySelector(`[data-testid="extra-${x.problem}"]`)?.setAttribute("aria-invalid", "true");
      }
      if (!probs.length && xprobs.length) {
        extra[xprobs[0].index].item.querySelector(`[data-testid="extra-${xprobs[0].problem}"]`)?.focus();
        return false;
      }
      if (probs.length) {
        const first = probs[0];
        form.querySelector(`#use-${first.problem}-${roles.findIndex((r) => r.name === first.role)}`)?.focus();
        return false;
      }
      return true;
    }

    async function create(status) {
      const withDocs = [];
      for (const d of docs) {
        const blob = await ctx.api.templates.documentContent(tp.id, d.id);
        withDocs.push({ id: d.id, name: d.name, base64: toBase64(new Uint8Array(await blob.arrayBuffer())) });
      }
      const { body: req, dropped } = envelopeFromTemplate(tp, people, { docs: withDocs, fields, subject: subject.value, message: message.value, status, extra });
      if (dropped) toast(t("use.dropped", { n: dropped }), "info");
      return ctx.api.createEnvelope(req);
    }

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (!docs.length || !check()) return;
      // An added signer has no fields yet: they are placed in the editor first.
      if (extra.some((p) => p.type === "signer")) { toast(t("use.extra-signer"), "info"); edit.focus(); return; }
      const signers = roles.filter((r) => r.type === "signer").length;
      if (!(await confirmDialog(t("send.confirm-title"), t("send.confirm-text", { n: signers, subject: subject.value.trim() || tp.name }), { confirm: t("prepare.send") }))) return;
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
    form.querySelector("#use-name-0")?.focus();
  }

  load();
  return () => unregisterPrefix("usetemplate.");
}
