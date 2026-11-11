// Templates (WEB-02; docs/47 §Screens "Templates", after DocuSign's): the list, a new
// template in the editor (`#/templates/new`, prepare.js in template mode), rename, and
// "Use" (`#/templates/{id}`): fill each role with a person, then send, or open the
// envelope in the editor first.
//
// Using a template is one `POST /api/v1/envelopes` (templatemodel.js), so it works on
// today's API. A template the server keeps without documents (no slice-3 template
// documents yet) becomes a draft with its recipients, opened in the editor to add the
// PDF and fields. Delete is not drawn: the API has no `DELETE /templates/{id}` yet
// (docs/47 principle 4; row in the WEB-02 report).

import { h, clear } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { toBase64 } from "./api.js";
import { register, unregisterPrefix } from "./commands.js";
import { button, busy, emptyState, skeletonRows, errorState, openDialog, confirmDialog, toast, toastError, pdfPreview } from "./ui/index.js";
import { rolesOf, peopleProblems, envelopeFromTemplate } from "./templatemodel.js";

/// `#/templates`: the list.
export function mount(view, ctx) {
  const head = h("div", { class: "os-page-head" },
    h("h1", { class: "os-page-title", text: t("templates.title") }),
    button(t("templates.new"), { icon: "plus", variant: "primary", command: "template.new", onClick: () => ctx.navigate("#/templates/new") }));
  const list = h("div", { class: "os-list", attrs: { "aria-live": "polite" } });
  view.append(head, h("p", { class: "os-muted os-lede", text: t("templates.lede") }), list);

  async function load() {
    clear(list);
    list.setAttribute("aria-busy", "true");
    list.append(skeletonRows(3));
    try {
      const page = await ctx.api.templates.list();
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
      list.append(emptyState({ illus: "templates", title: t("empty.templates.title"), text: t("empty.templates.text"), action: button(t("templates.new"), { icon: "plus", variant: "primary", onClick: () => ctx.navigate("#/templates/new") }), testId: "empty-templates" }));
      return;
    }
    const table = h("table", { class: "os-table os-table--rows" },
      h("caption", { class: "os-sr-only", text: t("templates.caption") }),
      h("thead", {}, h("tr", {},
        h("th", { attrs: { scope: "col" }, text: t("templates.col.name") }),
        h("th", { attrs: { scope: "col" }, class: "os-col-date", text: t("templates.col.subject") }),
        h("th", { attrs: { scope: "col" }, class: "os-col-actions", text: t("templates.col.actions") }))));
    const tb = h("tbody");
    for (const tp of items) {
      const href = `#/templates/${encodeURIComponent(tp.id)}`;
      tb.append(h("tr", { class: "os-row", attrs: { "data-id": tp.id } },
        h("td", {}, h("span", { class: "os-row-title" }, icon("layout-template", { size: 16 }), h("a", { href, class: "os-row-link", text: tp.name || t("templates.untitled") }))),
        h("td", { class: "os-col-date os-muted", text: tp.email_subject || "—" }),
        h("td", { class: "os-col-actions" },
          h("div", { class: "os-actions os-actions--row" },
            button(t("templates.use"), { icon: "send", size: "sm", variant: "primary", attrs: { "aria-label": t("templates.use-named", { name: tp.name }) }, onClick: () => ctx.navigate(href) }),
            button(t("templates.rename"), { icon: "pencil", size: "sm", attrs: { "aria-label": t("templates.rename-named", { name: tp.name }) }, onClick: () => rename(tp) })))));
    }
    table.append(tb);
    list.append(h("div", { class: "os-table-wrap" }, table));
  }

  async function rename(tp) {
    let input;
    let err;
    const name = await openDialog({
      title: t("templates.rename-title"),
      build(body) {
        body.append(
          h("label", { class: "os-label", attrs: { for: "tpl-rename" }, text: t("template.name") }),
          (input = h("input", { id: "tpl-rename", class: "os-input", value: tp.name || "", maxLength: 255, attrs: { autofocus: true, "aria-describedby": "tpl-rename-err" } })),
          (err = h("p", { id: "tpl-rename-err", class: "os-field-error", attrs: { "aria-live": "polite" } })));
        input.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); body.closest("dialog")?.querySelector(".os-dialog__foot .os-btn--primary")?.click(); } });
      },
      actions: [
        { label: t("action.cancel"), value: null },
        {
          label: t("templates.rename"),
          variant: "primary",
          onClick: async () => {
            const v = input.value.trim();
            if (!v) { err.textContent = t("form.required"); input.setAttribute("aria-invalid", "true"); input.focus(); return undefined; }
            const { etag } = await ctx.api.templates.get(tp.id);
            await ctx.api.templates.rename(tp.id, etag, v);
            return v;
          },
        },
      ],
    });
    if (!name) return;
    toast(t("templates.renamed"), "success");
    load();
  }

  register("template.new", { label: t("templates.new"), run: () => ctx.navigate("#/templates/new") });
  load();
  return () => unregisterPrefix("template.");
}

/// `#/templates/{id}`: use a template.
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

    const form = h("form", { class: "os-use", attrs: { novalidate: true, "aria-labelledby": "use-h" } });
    const subject = h("input", { id: "use-subject", class: "os-input", maxLength: 255, value: tp.email_subject || tp.name || "" });
    const message = h("textarea", { id: "use-message", class: "os-input os-textarea", rows: 3, maxLength: 10000, value: tp.email_message || "", placeholder: t("prepare.message-placeholder") });

    const rolesCard = h("section", { class: "os-card", attrs: { "aria-labelledby": "use-roles-h" } },
      h("h2", { id: "use-roles-h", class: "os-card__title", text: t("use.people") }),
      h("p", { class: "os-muted os-small", text: t("use.people-help") }));
    if (!roles.length) {
      rolesCard.append(emptyState({ illus: "recipients", title: t("empty.use-roles.title"), text: t("empty.use-roles.text"), testId: "empty-use-roles" }));
    }
    const errors = new Map();
    const list = h("ol", { class: "os-use__roles" });
    roles.forEach((r, i) => {
      people[r.name] = { name: "", email: "" };
      const nid = `use-name-${i}`;
      const eid = `use-email-${i}`;
      const err = h("p", { id: `use-err-${i}`, class: "os-field-error", attrs: { "aria-live": "polite" } });
      errors.set(r.name, err);
      const name = h("input", { id: nid, class: "os-input", autocomplete: "off", maxLength: 255, attrs: { "aria-describedby": `use-err-${i}`, "data-testid": "use-name" } });
      const email = h("input", { id: eid, class: "os-input", type: "email", autocomplete: "off", attrs: { "aria-describedby": `use-err-${i}`, "data-testid": "use-email" } });
      name.addEventListener("input", () => { people[r.name].name = name.value; });
      email.addEventListener("input", () => { people[r.name].email = email.value; });
      list.append(h("li", { class: `os-use__role os-r${(i % 6) + 1}` },
        h("div", { class: "os-use__role-head" },
          h("span", { class: "os-rcpt__dot", attrs: { "aria-hidden": "true" } }),
          h("span", { class: "os-order", attrs: { title: t("prepare.routing-order") }, text: String(r.routing_order) }),
          h("strong", { text: r.name }),
          h("span", { class: "os-muted os-small", text: t(`rtype.${r.type}`) })),
        h("div", { class: "os-use__inputs" },
          h("div", {}, h("label", { class: "os-label", attrs: { for: nid }, text: t("use.name-for", { role: r.name }) }), name),
          h("div", {}, h("label", { class: "os-label", attrs: { for: eid }, text: t("use.email-for", { role: r.name }) }), email)),
        err));
    });
    rolesCard.append(list);

    const docsCard = h("section", { class: "os-card", attrs: { "aria-labelledby": "use-docs-h" } },
      h("h2", { id: "use-docs-h", class: "os-card__title", text: t("prepare.documents") }));
    if (docs.length) {
      for (const d of docs) docsCard.append(pdfPreview({ load: () => ctx.api.templates.documentContent(tp.id, d.id), name: d.name, height: 520 }).el);
      docsCard.append(
        h("p", { class: "os-muted os-small", text: t("use.fields-n", { n: fields.length }) }));
    } else {
      docsCard.append(h("p", { class: "os-muted", attrs: { "data-testid": "use-no-docs" }, text: t("use.no-docs") }));
    }

    const messageCard = h("section", { class: "os-card", attrs: { "aria-labelledby": "use-msg-h" } },
      h("h2", { id: "use-msg-h", class: "os-card__title", text: t("use.email") }),
      h("label", { class: "os-label", attrs: { for: "use-subject" }, text: t("prepare.subject") }), subject,
      h("label", { class: "os-label", attrs: { for: "use-message" }, text: t("prepare.message") }), message);

    const send = button(t("prepare.send"), { icon: "send", variant: "primary", type: "submit", attrs: { "data-testid": "use-send" } });
    const edit = button(t(docs.length ? "use.edit-first" : "use.continue"), { icon: "file-pen-line", variant: docs.length ? "secondary" : "primary", attrs: { "data-testid": "use-edit" } });
    const actions = h("div", { class: "os-actions" }, docs.length ? send : null, edit);

    form.append(h("h2", { id: "use-h", class: "os-sr-only", text: t("use.form") }), rolesCard, docsCard, messageCard, actions);
    body.append(back, h("div", { class: "os-page-head" }, h("div", { class: "os-page-head__main" }, title)), form);

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
      const { body: req, dropped } = envelopeFromTemplate(tp, people, { docs: withDocs, fields, subject: subject.value, message: message.value, status });
      if (dropped) toast(t("use.dropped", { n: dropped }), "info");
      return ctx.api.createEnvelope(req);
    }

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (!docs.length || !check()) return;
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
}
