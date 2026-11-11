// Agreements (WEB-01, redesigned in WEB-02 and WEB-06; docs/47 §Screens "Agreements",
// after DocuSign's Manage page): a folder rail with quick views and counts, filters
// (sender, last change), a dense table (select, subject with its recipients, status
// with a line in words, sender, last change, expiry, row actions) with sortable
// columns, a bulk action bar, and the top bar's search.
//
// Folders are status filters on `GET /api/v1/envelopes?status=`; a view over two
// statuses (Waiting for others = sent + delivered) pages each and merges them, newest
// first. Recipients, dates and the status line come from each row's `GET …/{id}`,
// fetched after the list paints. Search is the server's (`q`, WEB-04). Sorting and the
// sender and date filters apply to the envelopes loaded (the API has neither yet; the
// page says so when more could be loaded — docs/47 finding A-01).
//
// A draft opens in the editor (A-02). Each row's menu (A-03) offers what its state
// allows: edit or delete a draft; correct, resend, download as it stands or void one
// in progress; download, certificate; copy, save as template and history for any
// sent one; delete one that ended without completing.

import { h, clear, fmtDate, download } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { register, unregisterPrefix } from "./commands.js";
import { button, busy, emptyState, skeletonRows, statusBadge, errorState, toast, toastError, reasonDialog, confirmDialog, menuButton, selectField } from "./ui/index.js";
import { countLabel } from "./templatemodel.js";
import { statusLine, copyEnvelope, saveAsTemplate, deleteEnvelope, downloadCurrent, downloadSealed, historyPanel, correctPanel, DELETABLE, ACTIVE } from "./envactions.js";

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
const DAY = 86_400_000;

/// The folder a route's parameters name: `?folder=`, or the older `?status=`.
export function folderFrom(params) {
  const f = params?.get("folder");
  if (FOLDERS.some((x) => x.id === f)) return f;
  return LEGACY[params?.get("status")] || "all";
}

/// Where a row goes: a draft to the editor (A-02), anything sent to its details.
export function rowHref(r) {
  return r.status === "draft" ? `#/prepare/${encodeURIComponent(r.id)}` : `#/envelopes/${encodeURIComponent(r.id)}`;
}

/// Whether `when` (ISO) falls in the filter's range. `range`: "any" | "7" | "30" | "90"
/// | "custom" with `from`/`to` as yyyy-mm-dd (inclusive, local days). `now` in ms.
export function inRange(when, { range = "any", from = "", to = "" } = {}, now = Date.now()) {
  if (range === "any") return true;
  const at = Date.parse(when);
  if (!Number.isFinite(at)) return false;
  if (range === "custom") {
    if (from && at < new Date(`${from}T00:00:00`).getTime()) return false;
    if (to && at >= new Date(`${to}T00:00:00`).getTime() + DAY) return false;
    return true;
  }
  const days = Number(range);
  return Number.isFinite(days) ? at >= now - days * DAY : true;
}

/// Compare two rows for a sort key; empty values sort last either way.
export function compareBy(key, dir, get) {
  return (a, b) => {
    const x = get(a, key);
    const y = get(b, key);
    if (x === y) return 0;
    if (x == null || x === "") return 1;
    if (y == null || y === "") return -1;
    return (x < y ? -1 : 1) * (dir === "asc" ? 1 : -1);
  };
}

const SORTS = [["subject", "agreements.col.subject"], ["status", "agreements.col.status"], ["changed", "dates.changed"], ["expires", "agreements.col.expires"]];

export function mount(view, ctx, _match, params) {
  const folder = FOLDERS.find((f) => f.id === folderFrom(params));
  let rows = [];
  // Whether `rows` holds a loaded list. Until then the list shows the skeleton or the
  // error state, and late helpers (sender names, details) must not draw over it.
  let ready = false;
  let cursors = new Map(); // status|"" → next cursor
  let query = (params.get("q") || "").trim().toLowerCase();
  const details = new Map(); // id → envelope
  const selected = new Set();
  const filter = { sender: "", range: "any", from: "", to: "" };
  let sort = { key: null, dir: "desc" };
  const people = new Map(); // user id → name

  const topSearch = document.getElementById("top-search");
  if (topSearch) topSearch.value = params.get("q") || "";
  // The server searches subject, names and emails (`q`, WEB-04); typing waits 250 ms.
  let searchTimer = null;
  ctx.onSearch = (q) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { if (q.toLowerCase() !== query) { query = q.toLowerCase(); load(); } }, 250);
  };

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

  // ---- Filters (A-01) ------------------------------------------------------------------
  const senderSel = selectField(t("agreements.filter.sender"), [["", t("agreements.filter.anyone")], ["me", t("agreements.filter.me")]], { id: "flt-sender", size: "sm", onChange: (v) => { filter.sender = v; renderRows(); } });
  const rangeSel = selectField(t("agreements.filter.when"), ["any", "7", "30", "90", "custom"].map((k) => [k, t(`agreements.filter.${k}`)]), { id: "flt-range", size: "sm", onChange: (v) => { filter.range = v; custom.hidden = v !== "custom"; renderRows(); } });
  const fromIn = h("input", { id: "flt-from", type: "date", class: "os-input os-input--sm" });
  const toIn = h("input", { id: "flt-to", type: "date", class: "os-input os-input--sm" });
  fromIn.addEventListener("change", () => { filter.from = fromIn.value; renderRows(); });
  toIn.addEventListener("change", () => { filter.to = toIn.value; renderRows(); });
  const custom = h("div", { class: "os-filters__custom", hidden: true },
    h("div", { class: "os-fieldrow" }, h("label", { class: "os-label", attrs: { for: "flt-from" }, text: t("agreements.filter.from") }), fromIn),
    h("div", { class: "os-fieldrow" }, h("label", { class: "os-label", attrs: { for: "flt-to" }, text: t("agreements.filter.to") }), toIn));
  const clearBtn = button(t("agreements.filter.clear"), { icon: "x", size: "sm", variant: "ghost", onClick: () => {
    Object.assign(filter, { sender: "", range: "any", from: "", to: "" });
    senderSel.select.value = ""; rangeSel.select.value = "any"; fromIn.value = ""; toIn.value = ""; custom.hidden = true;
    renderRows();
  } });
  const filters = h("div", { class: "os-filters", attrs: { role: "group", "aria-label": t("agreements.filters") } }, senderSel.el, rangeSel.el, custom, clearBtn);
  const filtering = () => !!filter.sender || filter.range !== "any";

  // ---- Content -------------------------------------------------------------------------
  const title = h("h1", { class: "os-page-title", text: t("agreements.title") });
  const sub = h("p", { class: "os-muted", text: t(`agreements.folder.${folder.id}`) });
  const head = h("div", { class: "os-page-head" }, h("div", { class: "os-page-head__main os-page-head__stack" }, title, sub),
    button(t("nav.new"), { icon: "plus", variant: "primary", onClick: () => ctx.navigate("#/prepare") }));
  const bulk = h("div", { class: "os-bulk", attrs: { role: "region", "aria-label": t("agreements.bulk"), hidden: true } });
  const list = h("div", { class: "os-list os-surface-card", attrs: { "aria-live": "polite" } });
  const note = h("p", { class: "os-muted os-small os-filters__note", hidden: true });
  const more = h("div", { class: "os-list__more" });
  const content = h("div", { class: "os-manage__content" }, head, filters, bulk, list, note, more);
  view.append(h("div", { class: "os-manage" }, rail, content));

  register("list.search", { label: t("cmd.search"), run: () => topSearch?.focus() });

  // ---- Loading ---------------------------------------------------------------------------
  const keys = () => (folder.statuses.length ? folder.statuses : [""]);
  async function load(append = false) {
    if (!append) {
      clear(list);
      list.setAttribute("aria-busy", "true");
      list.append(skeletonRows(8));
      ready = false;
      cursors = new Map(keys().map((k) => [k, undefined]));
    }
    try {
      const want = keys().filter((k) => !append || cursors.get(k));
      const pages = await Promise.all(want.map((k) => ctx.api.listEnvelopes({ status: k || undefined, cursor: append ? cursors.get(k) : undefined, limit: 25, q: query || undefined })));
      const got = pages.flatMap((p) => p.items || []);
      want.forEach((k, i) => cursors.set(k, pages[i].next_cursor || null));
      rows = (append ? rows.concat(got) : got).sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
      list.removeAttribute("aria-busy");
      ready = true;
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

  /// Names of the account's members for the Sender column and filter; a member who may
  /// not list users sees "You" and the others as "—".
  async function loadPeople() {
    try {
      for (const u of (await ctx.api.users.list()).items || []) people.set(u.id, u.name || u.email || "");
      const others = [...people].filter(([id]) => id !== ctx.session?.user_id).sort((a, b) => a[1].localeCompare(b[1]));
      for (const [id, name] of others) senderSel.select.append(h("option", { value: id, text: name }));
      renderRows();
    } catch { /* not an admin: the column says You or — */ }
  }

  /// Recipients and dates for each row, a few at a time, without blocking the list; the
  /// rows are drawn again once all are in when a sort or filter depends on them.
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
    if (sort.key || filter.range !== "any") renderRows();
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
  const senderName = (r) => (r.sender_user_id && r.sender_user_id === ctx.session?.user_id ? t("agreements.you") : people.get(r.sender_user_id) || "—");
  function paintDetail(id) {
    const tr = list.querySelector(`tr[data-id="${CSS.escape(id)}"]`);
    if (!tr) return;
    const e = details.get(id);
    tr.querySelector(".os-row__sub").textContent = recipientsLine(e);
    tr.querySelector(".os-row__line").textContent = statusLine(e);
    const when = lastChange({ id, created_at: e.created_at });
    const time = tr.querySelector(".os-col-changed time");
    time.dateTime = when;
    time.textContent = fmtDate(when);
    const exp = tr.querySelector(".os-col-expires");
    exp.replaceChildren(expiresCell(e));
  }
  function expiresCell(e) {
    if (!e) return "";
    if (!e.expires_at) return h("span", { class: "os-muted", text: ACTIVE.has(e.status) || e.status === "draft" ? t("agreements.never") : "—" });
    return h("time", { attrs: { datetime: e.expires_at }, text: fmtDate(e.expires_at) });
  }

  // ---- Rendering --------------------------------------------------------------------------
  const sortValue = (r, key) => {
    const e = details.get(r.id);
    if (key === "subject") return (r.subject || "").toLowerCase();
    if (key === "status") return r.status;
    if (key === "changed") return lastChange(r);
    if (key === "expires") return e?.expires_at || "";
    return r.created_at;
  };
  const visible = () => {
    const me = ctx.session?.user_id;
    let out = rows.filter((r) => {
      if (filter.sender === "me" && r.sender_user_id !== me) return false;
      if (filter.sender && filter.sender !== "me" && r.sender_user_id !== filter.sender) return false;
      return inRange(lastChange(r), filter);
    });
    if (sort.key) out = [...out].sort(compareBy(sort.key, sort.dir, sortValue));
    return out;
  };

  function sortHeader(key, labelKey, cls = "") {
    const label = t(labelKey);
    const on = sort.key === key;
    const b = h("button", { type: "button", class: "os-sort", attrs: { "data-sort": key, title: t("agreements.sort-by", { column: label }) } },
      h("span", { text: label }), icon("chevron-down", { size: 16, className: `os-sort__icon${on ? ` is-${sort.dir}` : ""}` }));
    b.addEventListener("click", () => {
      sort = on ? { key, dir: sort.dir === "asc" ? "desc" : "asc" } : { key, dir: key === "subject" || key === "status" ? "asc" : "desc" };
      renderRows();
      list.querySelector(`.os-sort[data-sort="${key}"]`)?.focus();
    });
    return h("th", { class: cls, attrs: { scope: "col", "aria-sort": on ? (sort.dir === "asc" ? "ascending" : "descending") : null } }, b);
  }

  function clearSearch() {
    const s = document.getElementById("top-search");
    if (s) { s.value = ""; s.focus(); }
    query = "";
    load();
  }

  function renderRows() {
    if (!ready) return; // the skeleton or the error state stays (a late name or filter must not hide it)
    clear(list);
    clear(more);
    const shown = visible();
    for (const id of [...selected]) if (!rows.some((r) => r.id === id)) selected.delete(id);
    renderBulk();
    const canMore = [...cursors.values()].some(Boolean);
    note.hidden = !(canMore && (filtering() || sort.key));
    note.textContent = t("agreements.filter.loaded", { n: rows.length });
    clearBtn.hidden = !filtering();
    if (!rows.length && query) {
      const q = document.getElementById("top-search")?.value.trim() || query;
      list.append(emptyState({ illus: "search", title: t("empty.search.title"), text: t("empty.search.text", { query: q }), action: button(t("action.clear-search"), { variant: "primary", onClick: clearSearch }), testId: "empty-search" }));
      return;
    }
    if (!rows.length) {
      list.append(folder.id === "all"
        ? emptyState({ illus: "documents", title: t("empty.envelopes.title"), text: t("empty.envelopes.text"), action: button(t("nav.new"), { icon: "plus", variant: "primary", onClick: () => ctx.navigate("#/prepare") }), testId: "empty-envelopes" })
        : emptyState({ illus: "inbox", title: t("empty.folder.title", { folder: t(`agreements.folder.${folder.id}`) }), text: t("empty.filter.text"), action: button(t("agreements.folder.all"), { variant: "primary", onClick: () => ctx.navigate("#/agreements") }), testId: "empty-filter" }));
      return;
    }
    if (!shown.length) {
      list.append(emptyState({ illus: "search", title: t("agreements.filter.none"), text: t("agreements.filter.none-text"), action: button(t("agreements.filter.clear"), { variant: "primary", onClick: () => clearBtn.click() }), testId: "empty-filters" }));
      if (canMore) more.append(moreButton());
      return;
    }
    const all = h("input", { type: "checkbox", class: "os-checkbox", attrs: { "aria-label": t("agreements.select-all") } });
    all.checked = shown.every((r) => selected.has(r.id));
    all.indeterminate = !all.checked && shown.some((r) => selected.has(r.id));
    all.addEventListener("change", () => { for (const r of shown) { if (all.checked) selected.add(r.id); else selected.delete(r.id); } renderRows(); });
    const table = h("table", { class: "os-table os-table--rows os-table--manage os-table--cards has-check" },
      h("caption", { class: "os-sr-only", text: t("agreements.caption") }),
      h("thead", {}, h("tr", {},
        h("th", { class: "os-col-check", attrs: { scope: "col" } }, all),
        sortHeader("subject", "agreements.col.subject"),
        sortHeader("status", "agreements.col.status"),
        h("th", { class: "os-col-opt", attrs: { scope: "col" }, text: t("agreements.col.sender") }),
        sortHeader("changed", "dates.changed", "os-col-date"),
        sortHeader("expires", "agreements.col.expires", "os-col-opt"),
        h("th", { attrs: { scope: "col" }, class: "os-col-actions" }, h("span", { class: "os-sr-only", text: t("templates.col.actions") })))));
    const tb = h("tbody");
    for (const r of shown) {
      const href = rowHref(r);
      const subject = r.subject || t("envelope.untitled");
      const box = h("input", { type: "checkbox", class: "os-checkbox", checked: selected.has(r.id), attrs: { "aria-label": t("agreements.select", { subject }) } });
      box.addEventListener("change", () => { if (box.checked) selected.add(r.id); else selected.delete(r.id); tr.classList.toggle("is-selected", box.checked); renderBulk(); syncAll(); });
      const e = details.get(r.id);
      const when = lastChange(r);
      const tr = h("tr", { class: `os-row${selected.has(r.id) ? " is-selected" : ""}`, attrs: { "data-id": r.id, "data-status": r.status } },
        h("td", { class: "os-col-check" }, box),
        h("td", {}, h("div", { class: "os-col-subject" },
          h("a", { href, class: "os-row-link", text: subject }),
          h("span", { class: "os-row__sub os-muted", text: e ? recipientsLine(e) : "" }))),
        h("td", { class: "os-col-status" }, statusBadge(r.status), h("span", { class: "os-row__line os-small", text: e ? statusLine(e) : "" })),
        h("td", { class: "os-col-opt os-col-sender", attrs: { "data-label": t("agreements.col.sender") }, text: senderName(r) }),
        h("td", { class: "os-col-date os-col-changed", attrs: { "data-label": t("dates.changed") } },
          h("time", { attrs: { datetime: when }, text: fmtDate(when) }),
          h("span", { class: "os-muted os-small os-block", text: t("agreements.created-on", { date: fmtDate(r.created_at) }) })),
        h("td", { class: "os-col-opt os-col-expires", attrs: { "data-label": t("agreements.col.expires") } }, expiresCell(e)),
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
    if (canMore) more.append(moreButton());
  }
  function moreButton() {
    const b = button(t("agreements.more"), { icon: "chevron-down", onClick: async () => { b.disabled = true; await load(true); } });
    return b;
  }

  /// The row's actions, as DocuSign's per-row menu: what the envelope's state allows.
  function rowMenu(r, subject) {
    const id = r.id;
    const acts = [];
    const refresh = () => { details.delete(id); load(); loadCounts(); };
    const guard = (fn) => async () => { try { await fn(); } catch (err) { if (!ctx.failed(err)) toastError(err); } };
    if (r.status === "draft") {
      acts.push([t("envelope.edit"), "file-pen-line", () => ctx.navigate(rowHref(r))]);
    } else {
      acts.push([t("agreements.open"), "eye", () => ctx.navigate(rowHref(r))]);
    }
    if (ACTIVE.has(r.status)) {
      acts.push([t("agreements.correct"), "pencil", guard(async () => { if (await correctPanel(ctx, id)) refresh(); })]);
      acts.push([t("envelope.resend"), "rotate-cw", () => resend([id])]);
      acts.push([t("agreements.download-current"), "download", guard(() => downloadCurrent(ctx, id, details.get(id)))]);
    }
    if (r.status === "completed") {
      acts.push([t("envelope.download"), "download", () => downloadMany([id])]);
      acts.push([t("envelope.certificate"), "file-check", () => certificate(id)]);
    }
    acts.push([t("agreements.copy"), "copy", guard(async () => { const c = await copyEnvelope(ctx, id); ctx.navigate(`#/prepare/${encodeURIComponent(c.id)}`); })]);
    acts.push([t("agreements.save-template"), "layout-template", guard(() => saveAsTemplate(ctx, id))]);
    if (r.status !== "draft") acts.push([t("agreements.history"), "list-ordered", guard(() => historyPanel(ctx, id, subject))]);
    if (ACTIVE.has(r.status)) acts.push([t("envelope.void"), "ban", () => voidMany([id]), true]);
    if (DELETABLE.has(r.status)) acts.push([t(r.status === "draft" ? "agreements.delete-draft" : "agreements.delete"), "trash-2", guard(async () => { if (await deleteEnvelope(ctx, id, subject, r.status)) { selected.delete(id); refresh(); } }), true]);
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
      for (const id of ids) await downloadSealed(ctx, id, details.get(id));
    } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }
  async function certificate(id) {
    try {

      download(await ctx.api.certificate(id), `certificate-${id}.pdf`);
    } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }

  load();
  loadCounts();
  loadPeople();
  return () => { unregisterPrefix("list."); ctx.onSearch = null; };
}
