// Agreements (WEB-01, redesigned in WEB-02; docs/47 §Screens "Agreements", after
// DocuSign's Manage page): a folder rail with quick views and counts, a dense table
// (select, subject with its recipients, status, last change, row actions), a bulk
// action bar, and the top bar's search filtering what is loaded.
//
// Folders are status filters on `GET /api/v1/envelopes?status=`; a view over two
// statuses (Waiting for others = sent + delivered) pages each and merges them, newest
// first. Recipients and the last change come from each row's `GET …/{id}`, fetched
// after the list paints. Search matches subject, recipient names and emails among
// the loaded rows (the API has no text query yet, row WEB-04).

import { h, clear, fmtDate, download } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { register, unregisterPrefix } from "./commands.js";
import { button, busy, emptyState, skeletonRows, statusBadge, errorState, toast, toastError, reasonDialog, confirmDialog, menuButton } from "./ui/index.js";
import { countLabel } from "./templatemodel.js";

/// The rail: id, statuses (none = every status), icon, group.
export const FOLDERS = [
  { id: "all", statuses: [], icon: "inbox", group: "folders" },
  { id: "drafts", statuses: ["draft"], icon: "file-pen-line", group: "folders" },
  { id: "action", statuses: ["declined", "expired"], icon: "circle-alert", group: "views" },
  { id: "waiting", statuses: ["sent", "delivered"], icon: "hourglass", group: "views" },
  { id: "completed", statuses: ["completed"], icon: "circle-check", group: "views" },
  { id: "declined", statuses: ["declined"], icon: "circle-x", group: "ended" },
  { id: "voided", statuses: ["voided"], icon: "ban", group: "ended" },
  { id: "expired", statuses: ["expired"], icon: "clock", group: "ended" },
];
const LEGACY = { draft: "drafts", sent: "waiting", delivered: "waiting", completed: "completed", declined: "declined", voided: "voided", expired: "expired" };
const ACTIVE = new Set(["sent", "delivered"]);

/// The folder a route's parameters name: `?folder=`, or the older `?status=`.
export function folderFrom(params) {
  const f = params?.get("folder");
  if (FOLDERS.some((x) => x.id === f)) return f;
  return LEGACY[params?.get("status")] || "all";
}

export function mount(view, ctx, _match, params) {
  const folder = FOLDERS.find((f) => f.id === folderFrom(params));
  let rows = [];
  let cursors = new Map(); // status|"" → next cursor
  let query = (params.get("q") || "").trim().toLowerCase();
  const details = new Map(); // id → envelope
  const selected = new Set();

  const topSearch = document.getElementById("top-search");
  if (topSearch) topSearch.value = params.get("q") || "";
  ctx.onSearch = (q) => { query = q.toLowerCase(); renderRows(); };

  // ---- Rail -------------------------------------------------------------------------
  const rail = h("nav", { class: "os-rail", attrs: { "aria-label": t("agreements.folders") } });
  const counts = new Map();
  for (const group of ["folders", "views", "ended"]) {
    rail.append(h("p", { class: "os-rail__group", text: t(`agreements.group.${group}`) }));
    const ul = h("ul", { class: "os-rail__list" });
    for (const f of FOLDERS.filter((x) => x.group === group)) {
      const n = h("span", { class: "os-rail__count" });
      counts.set(f.id, n);
      ul.append(h("li", {}, h("a", {
        class: "os-rail__link", href: f.id === "all" ? "#/agreements" : `#/agreements?folder=${f.id}`,
        attrs: { "aria-current": f.id === folder.id ? "page" : null, "data-folder": f.id },
      }, icon(f.icon, { size: 16 }), h("span", { class: "os-rail__label", text: t(`agreements.folder.${f.id}`) }), n)));
    }
    rail.append(ul);
  }

  // ---- Content -------------------------------------------------------------------------
  const title = h("h1", { class: "os-page-title", text: t("agreements.title") });
  const sub = h("p", { class: "os-muted", text: t(`agreements.folder.${folder.id}`) });
  const head = h("div", { class: "os-page-head" }, h("div", { class: "os-page-head__main os-page-head__stack" }, title, sub),
    button(t("nav.new"), { icon: "plus", variant: "primary", onClick: () => ctx.navigate("#/prepare") }));
  const bulk = h("div", { class: "os-bulk", attrs: { role: "region", "aria-label": t("agreements.bulk"), hidden: true } });
  const list = h("div", { class: "os-list os-surface-card", attrs: { "aria-live": "polite" } });
  const more = h("div", { class: "os-list__more" });
  const content = h("div", { class: "os-manage__content" }, head, bulk, list, more);
  view.append(h("div", { class: "os-manage" }, rail, content));

  register("list.search", { label: t("cmd.search"), run: () => topSearch?.focus() });

  // ---- Loading ---------------------------------------------------------------------------
  const keys = () => (folder.statuses.length ? folder.statuses : [""]);
  async function load(append = false) {
    if (!append) {
      clear(list);
      list.setAttribute("aria-busy", "true");
      list.append(skeletonRows(8));
      cursors = new Map(keys().map((k) => [k, undefined]));
    }
    try {
      const want = keys().filter((k) => !append || cursors.get(k));
      const pages = await Promise.all(want.map((k) => ctx.api.listEnvelopes({ status: k || undefined, cursor: append ? cursors.get(k) : undefined, limit: 25 })));
      const got = pages.flatMap((p) => p.items || []);
      want.forEach((k, i) => cursors.set(k, pages[i].next_cursor || null));
      rows = (append ? rows.concat(got) : got).sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
      list.removeAttribute("aria-busy");
      renderRows();
      fillDetails(got);
    } catch (err) {
      list.removeAttribute("aria-busy");
      if (ctx.failed(err)) return;
      if (append) toastError(err);
      else errorState(list, err, () => load());
    }
  }

  async function loadCounts() {
    await Promise.all(FOLDERS.map(async (f) => {
      try {
        const parts = await Promise.all((f.statuses.length ? f.statuses : [undefined]).map((s) => ctx.api.countEnvelopes(s)));
        const label = countLabel({ n: parts.reduce((s, p) => s + p.n, 0), more: parts.some((p) => p.more) });
        counts.get(f.id).textContent = label;
      } catch { /* counts are a convenience */ }
    }));
  }

  /// Recipients and last change for each row, a few at a time, without blocking the list.
  async function fillDetails(items) {
    const queue = items.filter((r) => !details.has(r.id));
    const worker = async () => {
      while (queue.length) {
        const r = queue.shift();
        try {
          const { envelope } = await ctx.api.getEnvelope(r.id);
          details.set(r.id, envelope);
          paintDetail(r.id);
        } catch { /* the row keeps its summary */ }
      }
    };
    await Promise.all([worker(), worker(), worker(), worker()]);
  }

  function lastChange(r) {
    const e = details.get(r.id);
    return [e?.ended_at, e?.sent_at, r.created_at].filter(Boolean).sort().pop();
  }
  function recipientsLine(e) {
    const recs = [...(e?.recipients || [])].sort((a, b) => a.routing_order - b.routing_order);
    if (!recs.length) return t("agreements.no-recipients");
    return t("agreements.to", { names: recs.map((r) => r.name || r.email).join(", ") });
  }
  function paintDetail(id) {
    const tr = list.querySelector(`tr[data-id="${CSS.escape(id)}"]`);
    if (!tr) return;
    const e = details.get(id);
    tr.querySelector(".os-row__sub").textContent = recipientsLine(e);
    const when = lastChange({ id, created_at: e.created_at });
    const time = tr.querySelector(".os-col-date time");
    time.dateTime = when;
    time.textContent = fmtDate(when);
  }

  // ---- Rendering --------------------------------------------------------------------------
  function matches(r) {
    if (!query) return true;
    const e = details.get(r.id);
    const hay = [r.subject, ...(e?.recipients || []).flatMap((x) => [x.name, x.email])].join(" ").toLowerCase();
    return hay.includes(query);
  }

  function renderRows() {
    clear(list);
    clear(more);
    const shown = rows.filter(matches);
    for (const id of [...selected]) if (!rows.some((r) => r.id === id)) selected.delete(id);
    renderBulk();
    if (!rows.length) {
      list.append(folder.id === "all"
        ? emptyState({ illus: "documents", title: t("empty.envelopes.title"), text: t("empty.envelopes.text"), action: button(t("nav.new"), { icon: "plus", variant: "primary", onClick: () => ctx.navigate("#/prepare") }), testId: "empty-envelopes" })
        : emptyState({ illus: "inbox", title: t("empty.folder.title", { folder: t(`agreements.folder.${folder.id}`) }), text: t("empty.filter.text"), action: button(t("agreements.folder.all"), { variant: "primary", onClick: () => ctx.navigate("#/agreements") }), testId: "empty-filter" }));
      return;
    }
    if (!shown.length) {
      const q = document.getElementById("top-search")?.value.trim() || query;
      list.append(emptyState({ illus: "search", title: t("empty.search.title"), text: t("empty.search.text", { query: q }), action: button(t("action.clear-search"), { variant: "primary", onClick: () => { const s = document.getElementById("top-search"); if (s) { s.value = ""; s.focus(); } query = ""; renderRows(); } }), testId: "empty-search" }));
      return;
    }
    const all = h("input", { type: "checkbox", class: "os-checkbox", attrs: { "aria-label": t("agreements.select-all") } });
    all.checked = shown.every((r) => selected.has(r.id));
    all.indeterminate = !all.checked && shown.some((r) => selected.has(r.id));
    all.addEventListener("change", () => { for (const r of shown) { if (all.checked) selected.add(r.id); else selected.delete(r.id); } renderRows(); });
    const table = h("table", { class: "os-table os-table--rows os-table--manage" },
      h("caption", { class: "os-sr-only", text: t("agreements.caption") }),
      h("thead", {}, h("tr", {},
        h("th", { class: "os-col-check", attrs: { scope: "col" } }, all),
        h("th", { attrs: { scope: "col" }, text: t("agreements.col.subject") }),
        h("th", { attrs: { scope: "col" }, text: t("agreements.col.status") }),
        h("th", { attrs: { scope: "col" }, class: "os-col-date", text: t("agreements.col.changed") }),
        h("th", { attrs: { scope: "col" }, class: "os-col-actions" }, h("span", { class: "os-sr-only", text: t("templates.col.actions") })))));
    const tb = h("tbody");
    for (const r of shown) {
      const href = `#/envelopes/${encodeURIComponent(r.id)}`;
      const subject = r.subject || t("envelope.untitled");
      const box = h("input", { type: "checkbox", class: "os-checkbox", checked: selected.has(r.id), attrs: { "aria-label": t("agreements.select", { subject }) } });
      box.addEventListener("change", () => { if (box.checked) selected.add(r.id); else selected.delete(r.id); tr.classList.toggle("is-selected", box.checked); renderBulk(); syncAll(); });
      const e = details.get(r.id);
      const when = lastChange(r);
      const tr = h("tr", { class: `os-row${selected.has(r.id) ? " is-selected" : ""}`, attrs: { "data-id": r.id } },
        h("td", { class: "os-col-check" }, box),
        h("td", {}, h("div", { class: "os-col-subject" },
          h("a", { href, class: "os-row-link", text: subject }),
          h("span", { class: "os-row__sub os-muted", text: e ? recipientsLine(e) : "" }))),
        h("td", {}, statusBadge(r.status)),
        h("td", { class: "os-col-date os-muted" }, h("time", { attrs: { datetime: when }, text: fmtDate(when) })),
        h("td", { class: "os-col-actions" }, rowMenu(r, subject)));
      tr.addEventListener("click", (ev) => { if (ev.target.closest("a, button, input, .os-menu")) return; ctx.navigate(href); });
      tb.append(tr);
    }
    table.append(tb);
    list.append(h("div", { class: "os-table-wrap" }, table));
    function syncAll() {
      all.checked = shown.every((r) => selected.has(r.id));
      all.indeterminate = !all.checked && shown.some((r) => selected.has(r.id));
    }
    if ([...cursors.values()].some(Boolean)) {
      const b = button(t("agreements.more"), { icon: "chevron-down", onClick: async () => { b.disabled = true; await load(true); } });
      more.append(b);
    }
  }

  /// The row's actions, as DocuSign's per-row menu: what the envelope's state allows.
  function rowMenu(r, subject) {
    const acts = [[t("agreements.open"), "eye", () => ctx.navigate(`#/envelopes/${encodeURIComponent(r.id)}`)]];
    if (r.status === "draft") acts.push([t("envelope.edit"), "file-pen-line", () => ctx.navigate(`#/prepare/${encodeURIComponent(r.id)}`)]);
    if (ACTIVE.has(r.status)) {
      acts.push([t("envelope.resend"), "rotate-cw", () => resend([r.id])]);
      acts.push([t("envelope.void"), "ban", () => voidMany([r.id]), true]);
    }
    if (r.status === "completed") {
      acts.push([t("envelope.download"), "download", () => downloadMany([r.id])]);
      acts.push([t("envelope.certificate"), "file-check", () => certificate(r.id)]);
    }
    return menuButton({
      label: t("agreements.actions-for", { subject }),
      buttonOpts: { icon: "ellipsis", variant: "ghost", size: "sm", iconOnly: true },
      items: () => acts.map(([label, ic, run, danger]) => ({ label, icon: ic, run, danger })),
    });
  }

  // ---- Bulk actions --------------------------------------------------------------------------
  function renderBulk() {
    clear(bulk);
    bulk.hidden = selected.size === 0;
    if (!selected.size) return;
    const chosen = rows.filter((r) => selected.has(r.id));
    const active = chosen.filter((r) => ACTIVE.has(r.status)).map((r) => r.id);
    const done = chosen.filter((r) => r.status === "completed").map((r) => r.id);
    bulk.append(...[
      h("strong", { attrs: { "aria-live": "polite" }, text: t("agreements.selected", { n: selected.size }) }),
      active.length ? button(t("agreements.bulk-resend", { n: active.length }), { icon: "rotate-cw", size: "sm", onClick: (e) => busy(e.currentTarget, () => resend(active)) }) : null,
      done.length ? button(t("agreements.bulk-download", { n: done.length }), { icon: "download", size: "sm", onClick: (e) => busy(e.currentTarget, () => downloadMany(done)) }) : null,
      active.length ? button(t("agreements.bulk-void", { n: active.length }), { icon: "ban", size: "sm", variant: "danger", onClick: () => voidMany(active) }) : null,
      h("span", { class: "os-spacer" }),
      button(t("agreements.clear-selection"), { icon: "x", size: "sm", variant: "ghost", onClick: () => { selected.clear(); renderRows(); } })].filter(Boolean));
  }

  async function resend(ids) {
    try {
      for (const id of ids) await ctx.api.resend(id);
      toast(t(ids.length > 1 ? "agreements.resent-n" : "envelope.resent", { n: ids.length }), "success");
    } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }
  async function voidMany(ids) {
    if (ids.length > 1 && !(await confirmDialog(t("agreements.void-many-title", { n: ids.length }), t("agreements.void-many-text"), { confirm: t("envelope.void"), danger: true }))) return;
    const reason = await reasonDialog(t("envelope.void-title"), t("envelope.void-label"), { confirm: t("envelope.void") });
    if (!reason) return;
    try {
      for (const id of ids) await ctx.api.voidEnvelope(id, reason);
      toast(t("envelope.voided"), "success");
      selected.clear();
      details.clear();
      load();
      loadCounts();
    } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }
  async function downloadMany(ids) {
    try {
      for (const id of ids) {
        const e = details.get(id) || (await ctx.api.getEnvelope(id)).envelope;
        for (const d of e.documents || []) download(await ctx.api.documentContent(id, d.id, "sealed"), `${(d.name || "document.pdf").replace(/\.pdf$/i, "")}-sealed.pdf`);
      }
    } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }
  async function certificate(id) {
    try { download(await ctx.api.certificate(id), `certificate-${id}.pdf`); } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }

  load();
  loadCounts();
  return () => { unregisterPrefix("list."); ctx.onSearch = null; };
}
