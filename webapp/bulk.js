// Bulk send from a template (UXW-04; docs/47 §Screens "Templates", after DocuSign's Bulk
// Send and SignNow's bulk invite): `#/templates/{id}/bulk`. The list is a CSV file (or
// pasted text) with two columns per role, `<role>::name` and `<role>::email`; a sample
// to fill in is offered. "Check the list" asks the server (`validate_only`) and shows
// every row with its problems; "Send" makes the batch and sends it ten rows at a time,
// showing the progress, and ends with the result list: each row's envelope or why it
// was not sent. Earlier batches of this template are listed and can be continued.
// Built only from the component library (docs/47): cards, tables, status pills, the
// progress ring, buttons, dialogs and toasts. Every user value is text (`textContent`).

import { h, clear, fmtDate, download } from "./dom.js";
import { icon } from "./icons.js";
import { t, has } from "./i18n.js";
import { register, unregisterPrefix } from "./commands.js";
import { button, busy, card, table, statusPill, progressRing, emptyState, skeletonRows, errorState, confirmDialog, toast, toastError } from "./ui/index.js";
import { rolesOf } from "./templatemodel.js";
import { columnsOf, sampleCsv, progressOf, sending } from "./bulkmodel.js";

const TONE = { pending: "wait", sent: "done", failed: "danger", cancelled: "draft", queued: "wait", sending: "wait", completed: "done" };

/// A code as people read it, or the code itself when it has no message.
const said = (code) => (has(`error.${code}`) ? t(`error.${code}`) : code);

/// A row's problems as people read them: "Tenant::email: not an email address".
export function problemText(problems) {
  return (problems || []).map((p) => (p.column ? `${p.column}: ${said(p.code)}` : said(p.code))).join("; ");
}

/// `#/templates/{id}/bulk`.
export function mount(view, ctx, [rawId]) {
  const id = decodeURIComponent(rawId);
  let alive = true;
  let stop = false;
  const body = h("div", { class: "os-bulk", attrs: { "aria-busy": "true" } }, skeletonRows(4));
  view.append(body);

  async function load() {
    try {
      const { template } = await ctx.api.templates.get(id);
      let earlier = [];
      try { earlier = ((await ctx.api.bulk.list())?.items || []).filter((b) => b.template_id === template.id); } catch { earlier = []; }
      if (alive) render(template, earlier);
    } catch (err) {
      if (ctx.failed(err)) return;
      errorState(body, err, load);
    } finally {
      body.removeAttribute("aria-busy");
    }
  }

  function render(tp, earlier) {
    clear(body);
    const roles = rolesOf(tp);
    const docs = Array.isArray(tp.documents) ? tp.documents : [];
    const name = tp.name || t("templates.untitled");
    const back = h("a", { href: "#/templates", class: "os-back" }, icon("chevron-left", { size: 16 }), h("span", { text: t("templates.title") }));
    body.append(back,
      h("div", { class: "os-page-head" }, h("h1", { class: "os-page-title", text: t("templates.bulk.title", { name }) })),
      h("p", { class: "os-muted os-lede", text: t("templates.bulk.lede") }));
    if (!docs.length || !roles.length) {
      body.append(emptyState({ illus: "templates", title: t("templates.bulk.not-ready"), text: t("templates.bulk.not-ready-text"), action: button(t("templates.edit-fields"), { icon: "file-pen-line", variant: "primary", onClick: () => ctx.navigate(`#/templates/${encodeURIComponent(tp.id)}/edit`) }), testId: "bulk-not-ready" }));
      return;
    }

    // 1. The list.
    const cols = columnsOf(roles);
    const file = h("input", { id: "bulk-file", type: "file", class: "os-input", attrs: { accept: ".csv,text/csv", "data-testid": "bulk-file" } });
    const text = h("textarea", { id: "bulk-csv", class: "os-input os-textarea", rows: 6, spellcheck: false, attrs: { "aria-describedby": "bulk-cols", "data-testid": "bulk-csv" } });
    file.addEventListener("change", async () => {
      const f = file.files?.[0];
      if (!f) return;
      text.value = await f.text();
    });
    const sample = button(t("templates.bulk.sample"), { icon: "download", size: "sm", command: "bulk.sample", onClick: () => downloadSample() });
    const downloadSample = () => download(new Blob([sampleCsv(roles)], { type: "text/csv" }), `${name.replace(/[^\w.-]+/g, "_").slice(0, 60) || "template"}-bulk.csv`);
    const check = button(t("templates.bulk.check"), { icon: "list-checks", variant: "primary", command: "bulk.check", attrs: { "data-testid": "bulk-check" }, onClick: () => runCheck() });
    const listCard = card({ title: t("templates.bulk.list"), actions: sample, testId: "bulk-list" },
      h("p", { id: "bulk-cols", class: "os-muted os-small", text: t("templates.bulk.columns", { columns: cols.join(", ") }) }),
      h("label", { class: "os-label", attrs: { for: "bulk-file" }, text: t("templates.bulk.file") }), file,
      h("label", { class: "os-label", attrs: { for: "bulk-csv" }, text: t("templates.bulk.paste") }), text,
      h("div", { class: "os-actions" }, check));

    // 2. The check, then 3. sending and the result.
    const checkOut = h("div", { attrs: { "aria-live": "polite", "data-testid": "bulk-checked" } });
    const runOut = h("div", { attrs: { "aria-live": "polite", "data-testid": "bulk-run" } });
    const earlierOut = h("div");
    body.append(listCard, checkOut, runOut, earlierOut);

    const rowsTable = (rows, caption, { withEnvelope = false } = {}) => table({
      caption,
      className: "os-table--rows",
      columns: [{ label: t("templates.bulk.col.row") }, { label: t("templates.bulk.col.people") }, { label: t("templates.bulk.col.status") }, { label: withEnvelope ? t("templates.bulk.col.result") : t("templates.bulk.col.problem") }],
      rows: rows.map((r) => ({
        attrs: { "data-row": String(r.row), "data-status": r.status },
        cells: [
          String(r.row + 1),
          h("span", {}, ...(r.recipients || []).flatMap((p, i) => [i ? h("br") : null, h("span", { text: `${p.role}: ${p.name || "—"} <${p.email || "—"}>` })])),
          statusPill(t(`templates.bulk.status.${r.status}`), { tone: TONE[r.status] || "draft" }),
          r.envelope_id
            ? h("a", { href: `#/envelopes/${encodeURIComponent(r.envelope_id)}`, text: t("templates.bulk.open-envelope") })
            : h("span", { class: r.status === "failed" ? "os-field-error" : "os-muted", text: r.problems?.length ? problemText(r.problems) : r.error_code ? said(r.error_code) : "" }),
        ],
      })),
    });

    let checked = null;
    async function runCheck() {
      const csv = text.value;
      clear(checkOut);
      clear(runOut);
      checked = null;
      if (!csv.trim()) { checkOut.append(h("p", { class: "os-field-error", text: t("templates.bulk.empty") })); text.focus(); return; }
      await busy(check, async () => {
        try {
          checked = await ctx.api.bulk.check(tp.id, { csv });
        } catch (err) {
          if (ctx.failed(err)) return;
          const codes = (err.errors || []).map((e) => said(e.code));
          checkOut.append(h("p", { class: "os-field-error", attrs: { role: "alert" }, text: codes.length ? [...new Set(codes)].join(" ") : said(err.code) }));
          return;
        }
        showChecked();
      });
    }

    function showChecked() {
      clear(checkOut);
      const bad = checked.rows.filter((r) => r.status === "failed");
      const batchName = h("input", { id: "bulk-name", class: "os-input", maxLength: 255, value: name, attrs: { "data-testid": "bulk-name" } });
      const send = button(t("templates.bulk.send", { n: checked.valid }), { icon: "send", variant: "primary", command: "bulk.send", attrs: { "data-testid": "bulk-send", disabled: checked.valid ? null : true }, onClick: () => startSend(batchName.value.trim()) });
      checkOut.append(card({ title: t("templates.bulk.checked"), testId: "bulk-check-card" },
        h("p", { "data-testid": "bulk-summary", text: t("templates.bulk.summary", { n: checked.row_count, ok: checked.valid, bad: bad.length }) }),
        bad.length ? h("p", { class: "os-muted os-small", text: t("templates.bulk.bad-help") }) : null,
        rowsTable(checked.rows, t("templates.bulk.checked")),
        h("label", { class: "os-label", attrs: { for: "bulk-name" }, text: t("templates.bulk.name") }), batchName,
        h("div", { class: "os-actions" }, send)));
      register("bulk.send", { label: t("templates.bulk.send", { n: checked.valid }), run: () => startSend(batchName.value.trim()) });
    }

    async function startSend(batchName) {
      if (!checked?.valid) return;
      if (!(await confirmDialog(t("templates.bulk.confirm-title"), t("templates.bulk.confirm-text", { n: checked.valid, name }), { confirm: t("templates.bulk.send", { n: checked.valid }) }))) return;
      let b;
      try {
        b = await ctx.api.bulk.create(tp.id, { csv: text.value }, batchName);
      } catch (err) { if (!ctx.failed(err)) toastError(err); return; }
      clear(checkOut);
      await run(b);
    }

    /// Show a batch, and send its pending rows ten at a time until none is left.
    async function run(b) {
      clear(runOut);
      stop = false;
      const ring = progressRing({ size: 44, label: t("templates.bulk.progress-label") });
      const line = h("p", { attrs: { "data-testid": "bulk-progress" } });
      const cancel = button(t("templates.bulk.cancel"), { icon: "ban", variant: "secondary", command: "bulk.cancel", attrs: { "data-testid": "bulk-cancel" }, onClick: async () => {
        stop = true;
        try { b = await ctx.api.bulk.cancel(b.id); show(); } catch (err) { if (!ctx.failed(err)) toastError(err); }
      } });
      register("bulk.cancel", { label: t("templates.bulk.cancel"), run: () => cancel.click() });
      const results = h("div");
      runOut.append(card({ title: b.name || name, actions: cancel, testId: "bulk-run-card" },
        h("div", { class: "os-actions" }, ring.el, line), results));
      function show() {
        const p = progressOf(b);
        ring.set(p.done, p.total || 1);
        line.textContent = t(`templates.bulk.state.${b.status}`, { sent: b.counts?.sent || 0, failed: b.counts?.failed || 0, done: p.done, total: p.total });
        cancel.hidden = !sending(b);
        clear(results);
        if (b.rows) results.append(rowsTable(b.rows, t("templates.bulk.results"), { withEnvelope: true }));
      }
      show();
      while (alive && !stop && sending(b)) {
        try {
          b = await ctx.api.bulk.send(b.id);
        } catch (err) {
          if (!ctx.failed(err)) toastError(err);
          break;
        }
        if (alive) show();
      }
      if (alive && b.status === "completed") toast(t("templates.bulk.done", { sent: b.counts?.sent || 0, failed: b.counts?.failed || 0 }), (b.counts?.failed || 0) ? "info" : "success");
    }

    // Earlier batches of this template.
    if (earlier.length) {
      earlierOut.append(card({ title: t("templates.bulk.earlier"), testId: "bulk-earlier" }, table({
        caption: t("templates.bulk.earlier"),
        className: "os-table--rows",
        columns: [{ label: t("templates.bulk.col.name") }, { label: t("templates.bulk.col.status") }, { label: t("templates.bulk.col.created") }, { label: t("templates.bulk.col.open"), hidden: true }],
        rows: earlier.map((b) => [
          b.name || name,
          statusPill(t(`templates.bulk.status.${b.status}`), { tone: TONE[b.status] || "draft" }),
          b.created_at ? h("time", { attrs: { datetime: b.created_at }, text: fmtDate(b.created_at) }) : "",
          button(t(sending(b) ? "templates.bulk.continue" : "templates.bulk.open"), { size: "sm", onClick: async () => {
            try { await run(await ctx.api.bulk.get(b.id)); runOut.scrollIntoView?.({ block: "start" }); } catch (err) { if (!ctx.failed(err)) toastError(err); }
          } }),
        ]),
      })));
    }

    register("bulk.sample", { label: t("templates.bulk.sample"), run: () => downloadSample() });
    register("bulk.check", { label: t("templates.bulk.check"), run: () => runCheck() });
  }

  load();
  return () => { alive = false; stop = true; unregisterPrefix("bulk."); };
}
