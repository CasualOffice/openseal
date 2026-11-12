// Agreements (WEB-17, WEB-18; canvas Main.dc.html; docs/47 §As built: Agreements): the
// list grouped by where each agreement stands, with sticky group headers, beside a
// docked inspector for the selected one.
//
// Header: pill tabs (All, Needs me, Waiting, Completed, Drafts, Expiring), Search,
// Filter (sender, last change), Display (sort, select for bulk, export CSV) and New
// agreement. The sidebar's Views (#nav-views) show the same views with live counts and
// switch in place. Older addresses (`?status=`, `?folder=declined|voided|expired|action`)
// still open their filter, named above the list.
//
// Data: every agreement up to 1000, newest change first (`GET /envelopes`, the server's
// search `q`), and the Inbox for "Needs me" where the server has one
// (`NOT_ON_SERVER.inbox`; hidden otherwise). Views, groups and counts are the pure rules
// of managemodel.js over those rows. Recipients, progress and page counts come from each
// row's `GET …/{id}`, a few at a time after the list paints; suggestion counts from
// ml.js only when document intelligence is available.
//
// The list is a WAI-ARIA grid: rows are focusable (roving tabindex), ↑/↓/Home/End move
// the selection, Enter opens, Space ticks a row while selecting. Clicking a row selects
// it; on narrower screens it opens the inspector as a slide-over (a full page on phones),
// which Escape closes, returning focus to the row.

import { h, clear, download, reducedMotion } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { register, unregisterPrefix } from "./commands.js";
import { button, busy, emptyState, errorState, toast, toastError, confirmDialog, menuButton, selectField, tabs, iconButton } from "./ui/index.js";
import {
  copyEnvelope, saveAsTemplate, deleteEnvelope, downloadCurrent, downloadSealed, downloadCertificate, hasCertificate,
  historyPanel, correctPanel, voidEnvelopes, waitingFor, DELETABLE, ACTIVE,
} from "./envactions.js";
import {
  agreementsHash, rowActions, toCsv, VIEWS, toneOf, viewFrom, groupRows, flatIds, moveSelection, viewCounts, signingProgress, primaryVerb, inView,
} from "./managemodel.js";
import {
  docThumb, progressSegments, whenEl, statusPillFor, subText, recipientAvatars, openDetails, insightsAvailable, renderNavViews,
  fetchAgreements, fetchInbox,
} from "./agreementparts.js";
import { registerMeaningSearch } from "./meaning.js";
import { loadSuggestions, onSuggestions } from "./ml.js";
import { createInspector } from "./inspector.js";

const DAY = 86_400_000;

/// Where a row opens: a draft in the editor (A-02), anything sent on its own page.
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

/// Within-group orders for Display → Sort; empty values last.
const ORDERS = {
  changed: (a, b) => String(b.updated_at || b.created_at || "").localeCompare(String(a.updated_at || a.created_at || "")),
  created: (a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")),
  subject: (a, b) => (a.subject || "").localeCompare(b.subject || "", undefined, { sensitivity: "base" }),
  expires: (a, b) => (a.expires_at ? (b.expires_at ? a.expires_at.localeCompare(b.expires_at) : -1) : b.expires_at ? 1 : 0),
};

const narrow = () => matchMedia("(max-width: 74.999em)").matches;

export function mount(view, ctx, _match, params) {
  const s = {
    view: viewFrom(params),
    q: (params.get("q") || "").trim(),
    rows: [],
    mine: new Set(),
    inbox: new Map(), // id → Inbox item (my_recipient_id)
    ready: false,
    capped: false,
    order: "changed",
    filter: { sender: "", range: "any", from: "", to: "" },
    selected: null,
    selecting: false,
    picked: new Set(),
    open: false, // the inspector, when it floats
  };
  const details = new Map(); // id → envelope
  const audits = new Map(); // id → audit
  const people = new Map(); // user id → name
  let mlOn = false;
  let gone = false;

  // ---- Header ------------------------------------------------------------------------
  const inboxOn = ctx.api.available ? ctx.api.available("inbox") : true;
  const tabViews = VIEWS.filter((v) => v.tab && (!v.inbox || inboxOn));
  const listHost = h("div", { class: "os-agr__scroll" });
  let quiet = true; // the tabs' first render is not a choice
  const tabset = tabs({
    label: t("agreements.views"),
    variant: "pill",
    tabs: tabViews.map((v) => ({ id: v.id, label: t(`agreements.view.${v.id}`) })),
    current: tabViews.some((v) => v.id === s.view) ? s.view : "all",
    render: (id, panel) => { panel.append(listHost); if (!quiet) setView(id); },
  });
  quiet = false;
  const tablist = tabset.querySelector('[role="tablist"]');
  const tabpanel = tabset.querySelector('[role="tabpanel"]');
  tabpanel.classList.add("os-agr__panel");
  tabpanel.removeAttribute("tabindex");

  const searchInput = h("input", { id: "agr-search", type: "search", class: "os-agr__searchinput", autocomplete: "off", value: s.q, attrs: { "aria-label": t("agreements.search"), placeholder: t("agreements.search") } });
  const searchRow = h("form", { class: "os-agr__searchrow", attrs: { role: "search" }, hidden: !s.q },
    icon("os-search", { size: 16 }), searchInput,
    iconButton(t("agreements.search-clear"), "x", { size: "sm", onClick: () => clearSearch() }));
  searchRow.addEventListener("submit", (e) => e.preventDefault());
  const searchBtn = iconButton(t("agreements.search"), "os-search", { size: "sm", onClick: () => toggleSearch(true) });
  searchBtn.setAttribute("aria-controls", "agr-search");
  const filterBtn = button(t("agreements.filter-btn"), { icon: "os-filter", variant: "ghost", size: "sm", attrs: { "aria-expanded": "false", "aria-controls": "agr-filters", "data-testid": "filters-toggle" }, onClick: () => toggleFilters() });
  filterBtn.classList.add("os-agr__hbtn");
  const filterCount = h("span", { class: "os-count-badge", hidden: true });
  filterBtn.append(filterCount);
  const displayMenu = menuButton({
    label: t("agreements.display-btn"),
    buttonOpts: { icon: "os-display", variant: "ghost", size: "sm", attrs: { "data-testid": "display-toggle" } },
    items: () => [
      h("p", { class: "os-menu__head", text: t("agreements.sort-label") }),
      ...Object.keys(ORDERS).map((k) => ({ label: t(`agreements.sort.${k}`), icon: s.order === k ? "os-check" : "os-blank", run: () => { s.order = k; renderList(); } })),
      "separator",
      { label: s.selecting ? t("agreements.select-off") : t("agreements.select-on"), icon: "square-check", run: () => toggleSelect() },
      { label: t("agreements.export-csv"), icon: "file-text", run: () => exportCsv(visibleRows()) },
    ],
  });
  displayMenu.querySelector("button").classList.add("os-agr__hbtn");
  const newBtn = h("a", { class: "os-btn os-btn--primary os-btn--sm os-agr__new", href: "#/prepare", attrs: { "data-testid": "agreements-new" } },
    icon("plus", { size: 16 }), h("span", { class: "os-agr__btnlabel", text: t("agreements.new") }), h("kbd", { class: "os-kbd os-kbd--on-accent", attrs: { "aria-hidden": "true" }, text: "N" }));
  const head = h("header", { class: "os-agr__head" },
    h("h1", { class: "os-agr__title", text: t("agreements.title") }), tablist,
    h("div", { class: "os-agr__tools" }, searchBtn, filterBtn, displayMenu, newBtn));

  // Filter popover (A-01): sender and last change, applied to the loaded rows.
  const f = s.filter;
  const senderSel = selectField(t("agreements.filter.sender"), [["", t("agreements.filter.anyone")], ["me", t("agreements.filter.me")]], { id: "flt-sender", size: "sm", onChange: (v) => { f.sender = v; renderList(); } });
  const rangeSel = selectField(t("agreements.filter.when"), ["any", "7", "30", "90", "custom"].map((k) => [k, t(`agreements.filter.${k}`)]), { id: "flt-range", size: "sm", onChange: (v) => { f.range = v; custom.hidden = v !== "custom"; renderList(); } });
  const fromIn = h("input", { id: "flt-from", type: "date", class: "os-input os-input--sm" });
  const toIn = h("input", { id: "flt-to", type: "date", class: "os-input os-input--sm" });
  fromIn.addEventListener("change", () => { f.from = fromIn.value; renderList(); });
  toIn.addEventListener("change", () => { f.to = toIn.value; renderList(); });
  const custom = h("div", { class: "os-filters__custom", hidden: true },
    h("div", { class: "os-fieldrow" }, h("label", { class: "os-label", attrs: { for: "flt-from" }, text: t("agreements.filter.from") }), fromIn),
    h("div", { class: "os-fieldrow" }, h("label", { class: "os-label", attrs: { for: "flt-to" }, text: t("agreements.filter.to") }), toIn));
  const clearBtn = button(t("agreements.filter.clear"), { icon: "x", size: "sm", variant: "ghost", onClick: () => clearFilters() });
  const filters = h("div", { id: "agr-filters", class: "os-agr__filters", attrs: { role: "group", "aria-label": t("agreements.filter.title") }, hidden: true },
    senderSel.el, rangeSel.el, custom, clearBtn, button(t("agreements.filter.apply"), { size: "sm", variant: "subtle", onClick: () => toggleFilters(false) }));
  filters.addEventListener("keydown", (e) => { if (e.key === "Escape") { e.stopPropagation(); toggleFilters(false); filterBtn.focus(); } });
  const filtering = () => !!f.sender || f.range !== "any";

  const note = h("p", { class: "os-agr__note", attrs: { "data-testid": "agreements-sub", "aria-live": "polite" }, hidden: true });
  const bulk = h("div", { class: "os-bulk os-agr__bulk", attrs: { role: "region", "aria-label": t("agreements.bulk"), "data-testid": "bulk-bar" }, hidden: true });
  const main = h("section", { class: "os-agr__main", attrs: { "aria-labelledby": "agr-h" } }, head, searchRow, filters, note, bulk, tabpanel);
  head.querySelector("h1").id = "agr-h";

  // ---- Inspector -------------------------------------------------------------------
  const inspector = createInspector(ctx, { load: loadDetail, actionsFor, onClose: () => setOpen(false) });
  const scrim = h("div", { class: "os-agr__scrim", hidden: true });
  scrim.addEventListener("click", () => setOpen(false));
  inspector.el.addEventListener("keydown", (e) => { if (e.key === "Escape" && s.open && !e.defaultPrevented) { e.preventDefault(); setOpen(false); } });
  const root = h("div", { class: "os-agr" }, main, scrim, inspector.el);
  view.append(root);

  // ---- Commands (⌘K and shortcuts reach every verb) ---------------------------------
  register("list.search", { label: t("cmd.search"), run: () => toggleSearch(true) });
  register("list.filters", { label: t("agreements.filters"), run: () => toggleFilters(true) });
  register("list.select", { label: t("agreements.select-on"), run: () => toggleSelect() });
  register("list.export", { label: t("agreements.export-csv"), run: () => exportCsv(visibleRows()) });
  register("list.open", { label: t("inspector.open"), run: () => { const r = selectedRow(); if (r) ctx.navigate(rowHref(r)); }, enabled: () => !!selectedRow() });
  register("list.primary", { label: t("inspector.sign"), run: () => { const r = selectedRow(); const a = r && actionsFor(r, details.get(r.id)).primary; if (a) a.run(); }, enabled: () => !!selectedRow() });
  for (const v of tabViews) register(`list.view.${v.id}`, { label: t("agreements.legacy-view", { view: t(`agreements.view.${v.id}`) }), run: () => setView(v.id) });
  const offMeaning = registerMeaningSearch(ctx);

  // ---- State changes ---------------------------------------------------------------
  function syncHash() {
    const want = agreementsHash(s.view, s.q);
    if (location.hash !== want) history.replaceState(history.state, "", `${location.pathname}${location.search}${want}`);
  }
  function setView(id) {
    if (!VIEWS.some((v) => v.id === id)) return;
    s.view = id;
    syncHash();
    for (const b of tablist.querySelectorAll('[role="tab"]')) {
      const on = b.dataset.tab === id;
      b.setAttribute("aria-selected", String(on));
      b.tabIndex = on ? 0 : -1;
    }
    if (!tabViews.some((v) => v.id === id)) tablist.querySelector('[role="tab"]').tabIndex = 0;
    renderList();
    renderNav();
  }
  function toggleSearch(on) {
    searchRow.hidden = !on && !s.q;
    if (on) searchInput.focus();
  }
  let searchTimer = null;
  searchInput.addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      const q = searchInput.value.trim();
      if (q === s.q) return;
      s.q = q;
      syncHash();
      load();
    }, 250);
  });
  searchInput.addEventListener("keydown", (e) => { if (e.key === "Escape" && !searchInput.value) { e.stopPropagation(); searchRow.hidden = true; searchBtn.focus(); } });
  function clearSearch() {
    searchInput.value = "";
    if (s.q) { s.q = ""; syncHash(); load(); }
    searchInput.focus();
  }
  function toggleFilters(open = filters.hidden) {
    filters.hidden = !open;
    filterBtn.setAttribute("aria-expanded", String(open));
    if (open) senderSel.select.focus();
  }
  function clearFilters() {
    Object.assign(f, { sender: "", range: "any", from: "", to: "" });
    senderSel.select.value = ""; rangeSel.select.value = "any"; fromIn.value = ""; toIn.value = ""; custom.hidden = true;
    renderList();
  }
  function toggleSelect(on = !s.selecting) {
    s.selecting = on;
    if (!on) s.picked.clear();
    renderList();
  }
  function setOpen(open, { focus = true } = {}) {
    const floating = narrow();
    s.open = open && floating;
    root.classList.toggle("is-inspecting", s.open);
    scrim.hidden = !s.open;
    main.inert = s.open;
    if (s.open) {
      inspector.el.setAttribute("role", "dialog");
      inspector.el.setAttribute("aria-modal", "true");
      inspector.el.setAttribute("aria-labelledby", "insp-title");
      inspector.el.removeAttribute("aria-label");
      if (focus) requestAnimationFrame(() => inspector.el.querySelector(".os-insp__close")?.focus());
    } else {
      inspector.el.removeAttribute("role");
      inspector.el.removeAttribute("aria-modal");
      inspector.el.removeAttribute("aria-labelledby");
      inspector.el.setAttribute("aria-label", t("inspector.label"));
      if (focus && floating) rowEl(s.selected)?.focus();
    }
  }
  const mq = matchMedia("(max-width: 74.999em)");
  const onMq = () => { if (!mq.matches && s.open) setOpen(false, { focus: false }); };
  mq.addEventListener("change", onMq);

  // ---- Loading ---------------------------------------------------------------------
  let loadSeq = 0;
  async function load() {
    const my = ++loadSeq;
    s.ready = false;
    clear(listHost);
    listHost.setAttribute("aria-busy", "true");
    listHost.append(skeletonGrid());
    try {
      const [list, inbox] = await Promise.all([fetchAgreements(ctx, { q: s.q }), fetchInbox(ctx)]);
      if (my !== loadSeq || gone) return;
      s.rows = list.items;
      s.capped = list.capped;
      s.inbox = new Map(inbox.items.map((x) => [x.id, x]));
      s.mine = inbox.ids;
      // An Inbox item another member sent may not be in the account's list under a search.
      for (const it of inbox.items) if (!s.rows.some((r) => r.id === it.id) && (!s.q || (it.subject || "").toLowerCase().includes(s.q.toLowerCase()))) s.rows.push(it);
      s.ready = true;
      listHost.removeAttribute("aria-busy");
      renderList();
      renderNav();
      fillDetails();
    } catch (err) {
      if (my !== loadSeq || gone) return;
      listHost.removeAttribute("aria-busy");
      if (ctx.failed(err)) return;
      errorState(listHost, err, () => load());
      inspector.showNone();
    }
  }

  async function loadDetail(id) {
    const [env, audit] = await Promise.all([
      details.has(id) ? details.get(id) : ctx.api.getEnvelope(id).then((x) => { details.set(id, x.envelope); return x.envelope; }),
      audits.has(id) ? audits.get(id) : ctx.api.audit(id).then((a) => { audits.set(id, a); return a; }, () => ({ items: [], chain_head: null })),
    ]);
    return { env, audit };
  }

  /// Recipients, progress and pages for the rows in view, four at a time.
  async function fillDetails() {
    const queue = visibleRows().map((r) => r.id).filter((id) => !details.has(id)).slice(0, 150);
    const worker = async () => {
      while (queue.length && !gone) {
        const id = queue.shift();
        try {
          const { envelope } = await ctx.api.getEnvelope(id);
          details.set(id, envelope);
          paintRow(id);
        } catch { /* the row keeps its summary */ }
      }
    };
    await Promise.all([worker(), worker(), worker(), worker()]);
    if (mlOn) fillSuggestions();
  }
  async function fillSuggestions() {
    const queue = visibleRows().map((r) => r.id).slice(0, 150);
    const worker = async () => { while (queue.length && !gone) { const id = queue.shift(); try { await loadSuggestions(id); } catch { /* no chip */ } } };
    await Promise.all([worker(), worker(), worker()]);
  }
  const offSugg = onSuggestions(({ envId }) => paintRow(envId));

  async function loadPeople() {
    try {
      for (const u of (await ctx.api.users.list()).items || []) people.set(u.id, u.name || u.email || "");
      const others = [...people].filter(([id]) => id !== ctx.session?.user_id).sort((a, b) => a[1].localeCompare(b[1]));
      for (const [id, name] of others) senderSel.select.append(h("option", { value: id, text: name }));
    } catch { /* not an admin: Anyone and Me only */ }
  }

  // ---- Rendering -------------------------------------------------------------------
  const selectedRow = () => s.rows.find((r) => r.id === s.selected) || null;
  const lastChange = (r) => r.updated_at || r.created_at;
  function passesFilter(r) {
    const me = ctx.session?.user_id;
    if (f.sender === "me" && r.sender_user_id !== me) return false;
    if (f.sender && f.sender !== "me" && r.sender_user_id !== f.sender) return false;
    return inRange(lastChange(r), f);
  }
  const groups = () => groupRows(s.rows.filter(passesFilter), s.view, s.mine, { order: ORDERS[s.order] });
  function visibleRows() { return groups().flatMap((g) => g.items); }
  const fromName = (r) => people.get(r.sender_user_id) || null;
  const rowEl = (id) => (id ? listHost.querySelector(`[role="row"][data-id="${CSS.escape(id)}"]`) : null);

  function renderNav() {
    renderNavViews(ctx, { current: s.view, counts: s.ready ? viewCounts(s.rows, s.mine) : null, onPick: (id) => { setView(id); syncTabFocus(); } });
  }
  function syncTabFocus() { tablist.querySelector('[aria-selected="true"]')?.scrollIntoView?.({ block: "nearest", inline: "nearest" }); }

  function renderNote() {
    const legacy = !tabViews.some((v) => v.id === s.view);
    const parts = [];
    if (legacy) parts.push(t("agreements.legacy-view", { view: t(`agreements.view.${s.view}`) }));
    if (s.q) parts.push(t("agreements.searching", { folder: t(`agreements.view.${s.view}`), query: s.q }));
    if (s.capped) parts.push(t("agreements.capped", { n: s.rows.length }));
    note.hidden = !parts.length;
    note.textContent = parts.join(" · ");
    const n = (f.sender ? 1 : 0) + (f.range !== "any" ? 1 : 0);
    filterCount.hidden = !n;
    filterCount.textContent = n ? String(n) : "";
    clearBtn.hidden = !filtering();
  }

  function renderList() {
    renderNote();
    renderBulk();
    if (!s.ready) return;
    const gs = groups();
    const ids = flatIds(gs);
    clear(listHost);
    if (!gs.length) {
      listHost.append(emptyFor());
      s.selected = null;
      inspector.showNone();
      root.classList.add("is-empty");
      return;
    }
    root.classList.remove("is-empty");
    if (!ids.includes(s.selected)) s.selected = ids[0];
    const grid = h("div", { class: `os-agr-grid${s.selecting ? " is-selecting" : ""}`, attrs: { role: "grid", "aria-labelledby": "agr-h", "aria-multiselectable": s.selecting ? "true" : null, "data-testid": "agreements-grid" } });
    grid.append(h("div", { class: "os-sr-only", attrs: { role: "row" } },
      ...(s.selecting ? [""] : []).map(() => h("span", { attrs: { role: "columnheader" }, text: t("agreements.select-all") })),
      ...["agreement", "recipients", "progress", "status", "when"].map((c) => h("span", { attrs: { role: "columnheader" }, text: t(`agreements.col.${c}`) }))));
    for (const g of gs) {
      const label = t(`agreements.grp.${g.group}`);
      grid.append(h("div", { class: "os-agr-group", attrs: { role: "row" } },
        h("span", { class: "os-agr-group__cell", attrs: { role: "gridcell", "aria-colspan": s.selecting ? "6" : "5" } },
          h("span", { class: `os-dot os-dot--${g.tone}`, attrs: { "aria-hidden": "true" } }),
          h("span", { text: label }), h("span", { class: "os-agr-group__n", text: String(g.items.length) }))));
      for (const r of g.items) grid.append(rowNode(r));
    }
    grid.addEventListener("keydown", onGridKey);
    listHost.append(grid);
    showSelected();
  }

  function rowNode(r) {
    const env = details.get(r.id);
    const on = r.id === s.selected;
    const subject = r.subject || t("envelope.untitled");
    const n = mlOn ? openDetails(r.id) : 0;
    const cells = [];
    if (s.selecting) {
      const box = h("input", { type: "checkbox", class: "os-checkbox", checked: s.picked.has(r.id), attrs: { "aria-label": t("agreements.select", { subject }), tabindex: "-1" } });
      box.addEventListener("click", (e) => e.stopPropagation());
      box.addEventListener("change", () => pick(r.id, box.checked));
      cells.push(h("span", { class: "os-agr-cell os-agr-cell--check", attrs: { role: "gridcell" } }, box));
    }
    cells.push(
      h("span", { class: "os-agr-cell os-agr-cell--main", attrs: { role: "gridcell" } },
        docThumb(toneOf(r, s.mine)),
        h("span", { class: "os-agr-cell__text" },
          h("span", { class: "os-agr-name", text: subject }),
          h("span", { class: "os-agr-sub", text: subText(r, env, s.mine, { from: fromName(r) }) }))),
      h("span", { class: "os-agr-cell os-agr-cell--people", attrs: { role: "gridcell" } }, env ? recipientAvatars(env) : null),
      h("span", { class: "os-agr-cell os-agr-cell--progress", attrs: { role: "gridcell" } }, env ? progressSegments(signingProgress(env), r.status) : null),
      h("span", { class: "os-agr-cell os-agr-cell--status", attrs: { role: "gridcell" } }, statusPillFor(r, env, s.mine),
        n ? h("span", { class: "os-sugg-chip", attrs: { title: t("agreements.sugg-chip", { n }), "data-testid": "sugg-chip" } }, icon("os-sparkle", { size: 12 }), h("span", { attrs: { "aria-hidden": "true" }, text: String(n) }), h("span", { class: "os-sr-only", text: t("agreements.sugg-chip", { n }) })) : null),
      h("span", { class: "os-agr-cell os-agr-cell--when", attrs: { role: "gridcell" } }, whenEl(lastChange(r))));
    const row = h("div", {
      class: `os-agr-row${on ? " is-selected" : ""}${s.picked.has(r.id) ? " is-picked" : ""}`,
      attrs: { role: "row", tabindex: on ? "0" : "-1", "aria-selected": String(s.selecting ? s.picked.has(r.id) : on), "data-id": r.id, "data-status": r.status, "aria-current": on && s.selecting ? "true" : null },
    }, ...cells);
    row.addEventListener("click", () => activate(r.id, { fromPointer: true }));
    row.addEventListener("dblclick", () => ctx.navigate(rowHref(r)));
    return row;
  }

  function paintRow(id) {
    const old = rowEl(id);
    const r = s.rows.find((x) => x.id === id);
    if (!old || !r) return;
    const had = document.activeElement === old;
    const fresh = rowNode(r);
    old.replaceWith(fresh);
    if (had) fresh.focus({ preventScroll: true });
  }

  function select(id, { focus = false } = {}) {
    if (!id) return;
    const prev = s.selected;
    s.selected = id;
    if (prev && prev !== id) paintRow(prev);
    paintRow(id);
    const el = rowEl(id);
    if (focus) { el?.focus({ preventScroll: true }); el?.scrollIntoView({ block: "nearest", behavior: reducedMotion() ? "auto" : "smooth" }); }
    showSelected();
  }
  function showSelected() {
    const r = selectedRow();
    if (!r) { inspector.showNone(); return; }
    if (inspector.current()?.id === r.id) return;
    const item = s.inbox.get(r.id);
    inspector.show(r, { mine: s.mine, mineId: item?.my_recipient_id || null, from: fromName(r) });
  }
  function activate(id, { fromPointer = false } = {}) {
    if (s.selecting && fromPointer) { pick(id, !s.picked.has(id)); return; }
    select(id, { focus: !fromPointer });
    if (narrow()) setOpen(true);
  }
  function pick(id, on) {
    if (on) s.picked.add(id); else s.picked.delete(id);
    paintRow(id);
    renderBulk();
  }

  function onGridKey(e) {
    const row = e.target.closest?.('[role="row"][data-id]');
    if (!row || e.target.matches("input")) return;
    const ids = flatIds(groups());
    if (["ArrowDown", "ArrowUp", "Home", "End"].includes(e.key)) {
      e.preventDefault();
      select(moveSelection(ids, row.dataset.id, e.key), { focus: true });
    } else if (e.key === "Enter") {
      e.preventDefault();
      const r = s.rows.find((x) => x.id === row.dataset.id);
      if (r) ctx.navigate(rowHref(r));
    } else if (e.key === " ") {
      e.preventDefault();
      if (s.selecting) pick(row.dataset.id, !s.picked.has(row.dataset.id));
      else activate(row.dataset.id);
    }
  }

  function emptyFor() {
    if (s.q) {
      return emptyState({ illus: "search", title: t("empty.search.title"), text: t("empty.search.text", { query: s.q }), action: button(t("action.clear-search"), { variant: "primary", onClick: clearSearch }), testId: "empty-search" });
    }
    if (!s.rows.length) {
      return emptyState({
        illus: "documents", title: t("agreements.empty.first.title"), text: t("agreements.empty.first.text"), testId: "empty-envelopes",
        action: h("div", { class: "os-actions" },
          button(t("agreements.new"), { icon: "plus", variant: "primary", onClick: () => ctx.navigate("#/prepare") }),
          button(t("agreements.empty.use-template"), { icon: "layout-template", variant: "subtle", onClick: () => ctx.navigate("#/templates") })),
      });
    }
    if (filtering() && s.rows.some((r) => inView(r, s.view, s.mine))) {
      return emptyState({ illus: "search", title: t("agreements.filter.none"), text: t("agreements.filter.none-text"), action: button(t("agreements.filter.clear"), { variant: "primary", onClick: clearFilters }), testId: "empty-filters" });
    }
    const known = ["me", "waiting", "completed", "drafts", "expiring"].includes(s.view) ? s.view : "other";
    const illus = { me: "inbox", waiting: "recipients", completed: "done", drafts: "documents", expiring: "calendar-check", other: "inbox" }[known];
    return emptyState({
      illus, title: t(`agreements.empty.${known}.title`), text: t(`agreements.empty.${known}.text`), testId: "empty-filter",
      action: button(t("agreements.empty.see-all"), { variant: "subtle", onClick: () => setView("all") }),
    });
  }

  function skeletonGrid() {
    const wrap = h("div", { class: "os-agr-skel", attrs: { "aria-label": t("agreements.loading"), role: "status" } },
      h("div", { class: "os-agr-group os-agr-group--skel", attrs: { "aria-hidden": "true" } }, h("span", { class: "os-skel os-agr-skel__head" })));
    [62, 48, 70, 55, 66, 44, 58].forEach((w) => {
      const a = h("span", { class: "os-skel" });
      const b = h("span", { class: "os-skel os-skel--sub" });
      a.style.width = `${w}%`;
      b.style.width = `${Math.round(w * 0.6)}%`;
      wrap.append(h("div", { class: "os-agr-row os-agr-row--skel", attrs: { "aria-hidden": "true" } },
        h("span", { class: "os-agr-cell os-agr-cell--main" }, h("span", { class: "os-skel os-skel--doc" }), h("span", { class: "os-skel-lines" }, a, b)),
        h("span", { class: "os-agr-cell os-agr-cell--people" }, h("span", { class: "os-skel os-skel--circle" }), h("span", { class: "os-skel os-skel--circle os-skel--overlap" })),
        h("span", { class: "os-agr-cell os-agr-cell--progress" }, h("span", { class: "os-skel os-agr-skel__prog" })),
        h("span", { class: "os-agr-cell os-agr-cell--status" }, h("span", { class: "os-skel os-skel--pill" })),
        h("span", { class: "os-agr-cell os-agr-cell--when" }, h("span", { class: "os-skel os-agr-skel__when" }))));
    });
    return wrap;
  }

  // ---- Actions -----------------------------------------------------------------------
  const guard = (fn) => async () => { try { await fn(); } catch (err) { if (!ctx.failed(err)) toastError(err); } };
  function refreshAfter(id) {
    details.delete(id);
    audits.delete(id);
    load();
  }
  /// What the inspector offers for `r` (see inspector.js).
  function actionsFor(r, env) {
    const id = r.id;
    const subject = r.subject || t("envelope.untitled");
    const copyThen = guard(async () => { const c = await copyEnvelope(ctx, id); ctx.navigate(`#/prepare/${encodeURIComponent(c.id)}`); });
    const verb = primaryVerb(r.status, s.mine.has(id));
    let primary = null;
    if (verb === "sign") primary = { label: t("inspector.sign"), run: guard(async () => { const x = await ctx.api.signLink(id); if (x?.url) location.href = x.url; }) };
    else if (verb === "remind") {
      const waiting = env ? waitingFor(env) : [];
      const first = waiting.length === 1 ? (waiting[0].name || waiting[0].email || "").split(/\s+/)[0] : "";
      primary = { label: first ? t("inspector.remind", { name: first }) : t("inspector.remind-all"), run: guard(async () => {
        await ctx.api.resend(id, waiting.length ? waiting.map((x) => x.id) : undefined);
        toast(t("inspector.reminded", { name: waiting.map((x) => x.name || x.email).join(", ") || subject }), "success");
        audits.delete(id);
        inspector.refresh();
      }) };
    } else if (verb === "download") primary = { label: t("inspector.download"), run: guard(() => downloadSealed(ctx, id, env)) };
    else if (verb === "edit") primary = { label: t("inspector.edit"), run: async () => ctx.navigate(rowHref(r)) };
    else if (verb === "copy-resend") primary = { label: t("envelope.copy-resend"), run: copyThen };
    const verbs = {
      edit: [t("envelope.edit"), "file-pen-line", () => ctx.navigate(rowHref(r))],
      open: [t("agreements.open"), "eye", () => ctx.navigate(rowHref(r))],
      correct: [t("agreements.correct"), "pencil", guard(async () => { if (await correctPanel(ctx, id)) refreshAfter(id); })],
      resend: [t("envelope.resend"), "rotate-cw", () => resend([id])],
      "download-current": [t("agreements.download-current"), "download", guard(() => downloadCurrent(ctx, id, details.get(id)))],
      "download-ended": [t("envelope.download-ended"), "download", guard(() => downloadCurrent(ctx, id, details.get(id) || r))],
      download: [t("envelope.download"), "download", guard(() => downloadSealed(ctx, id, details.get(id)))],
      certificate: [t("envelope.certificate"), "file-check", guard(() => downloadCertificate(ctx, id))],
      "copy-resend": [t("envelope.copy-resend"), "copy", copyThen],
      copy: [t("agreements.copy"), "copy", copyThen],
      template: [t("agreements.save-template"), "layout-template", guard(() => saveAsTemplate(ctx, id))],
      history: [t("agreements.history"), "list-ordered", guard(() => historyPanel(ctx, id, subject))],
      void: [t("envelope.void"), "ban", guard(async () => { if (await voidEnvelopes(ctx, [id])) refreshAfter(id); }), true],
      delete: [t(r.status === "draft" ? "agreements.delete-draft" : "agreements.delete"), "trash-2", guard(async () => { if (await deleteEnvelope(ctx, id, subject, r.status)) { s.picked.delete(id); refreshAfter(id); } }), true],
    };
    const more = rowActions(r.status, { cert: hasCertificate(ctx, r.status) }).map((g) => g.map((a) => {
      const [label, ic, run, danger] = verbs[a];
      return { label, icon: ic, run, danger };
    }));
    return { primary, open: () => ctx.navigate(rowHref(r)), more };
  }

  // ---- Bulk (Display → Select agreements) ---------------------------------------------
  function renderBulk() {
    clear(bulk);
    for (const id of [...s.picked]) if (!s.rows.some((r) => r.id === id)) s.picked.delete(id);
    bulk.hidden = !s.selecting;
    if (!s.selecting) return;
    const chosen = s.rows.filter((r) => s.picked.has(r.id));
    const active = chosen.filter((r) => ACTIVE.has(r.status)).map((r) => r.id);
    const sentOnes = chosen.filter((r) => r.status !== "draft").map((r) => r.id);
    const deletable = chosen.filter((r) => DELETABLE.has(r.status));
    bulk.append(...[
      h("strong", { attrs: { "aria-live": "polite" }, text: t("agreements.selected", { n: chosen.length }) }),
      active.length ? button(t("agreements.bulk-resend", { n: active.length }), { icon: "rotate-cw", size: "sm", onClick: (e) => busy(e.currentTarget, () => resend(active)) }) : null,
      sentOnes.length ? button(t("agreements.bulk-download", { n: sentOnes.length }), { icon: "download", size: "sm", onClick: (e) => busy(e.currentTarget, () => downloadMany(sentOnes)) }) : null,
      chosen.length ? button(t("agreements.export-csv"), { icon: "file-text", size: "sm", attrs: { "data-testid": "bulk-export" }, onClick: () => exportCsv(chosen) }) : null,
      active.length ? button(t("agreements.bulk-void", { n: active.length }), { icon: "ban", size: "sm", variant: "danger", attrs: { "data-testid": "bulk-void" }, onClick: () => voidMany(active) }) : null,
      deletable.length ? button(t("agreements.bulk-delete", { n: deletable.length }), { icon: "trash-2", size: "sm", variant: "danger", attrs: { "data-testid": "bulk-delete" }, onClick: () => deleteMany(deletable) }) : null,
      h("span", { class: "os-spacer" }),
      chosen.length ? button(t("agreements.clear-selection"), { icon: "x", size: "sm", variant: "ghost", onClick: () => { s.picked.clear(); renderList(); } }) : null,
      button(t("agreements.select-off"), { size: "sm", variant: "ghost", attrs: { "data-testid": "select-off" }, onClick: () => toggleSelect(false) })].filter(Boolean));
  }
  async function resend(ids) {
    try {
      for (const id of ids) await ctx.api.resend(id);
      toast(t(ids.length > 1 ? "agreements.resent-n" : "envelope.resent", { n: ids.length }), "success");
    } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }
  async function voidMany(ids) {
    try {
      if (!(await voidEnvelopes(ctx, ids))) return;
      s.picked.clear();
      details.clear();
      audits.clear();
      load();
    } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }
  async function deleteMany(chosen) {
    const ok = await confirmDialog(t("agreements.delete-many-title", { n: chosen.length }), t("agreements.delete-many-text", { n: chosen.length }), { confirm: t("agreements.bulk-delete", { n: chosen.length }), danger: true, icon: "trash-2" });
    if (!ok) return;
    try {
      for (const r of chosen) {
        const { etag } = await ctx.api.getEnvelope(r.id);
        await ctx.api.deleteEnvelope(r.id, etag);
        s.picked.delete(r.id);
      }
      toast(t("agreements.deleted-n", { n: chosen.length }), "success");
    } catch (err) { if (!ctx.failed(err)) toastError(err); }
    details.clear();
    load();
  }
  async function downloadMany(ids) {
    try {
      for (const id of ids) {
        const r = s.rows.find((x) => x.id === id);
        if (r?.status === "completed") await downloadSealed(ctx, id, details.get(id));
        else await downloadCurrent(ctx, id, details.get(id));
      }
    } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }
  /// The chosen rows as CSV (UX-07): what the list shows, one agreement a line.
  function exportCsv(chosen) {
    const head = [t("agreements.col.subject"), t("agreements.col.status"), t("agreements.csv.recipients"), t("agreements.col.sender"), t("agreements.col.created"), t("dates.changed"), t("agreements.col.expires"), t("envelope.id")];
    const lines = chosen.map((r) => {
      const e = details.get(r.id);
      const recs = [...(e?.recipients || [])].sort((a, b) => a.routing_order - b.routing_order).map((x) => (x.email ? `${x.name} <${x.email}>` : x.name)).join("; ");
      const sender = r.sender_user_id === ctx.session?.user_id ? t("agreements.you") : people.get(r.sender_user_id) || "";
      return [r.subject || "", t(`status.${r.status}`), recs, sender, r.created_at || "", lastChange(r) || "", r.expires_at || e?.expires_at || "", r.id];
    });
    download(new Blob(["﻿", toCsv([head, ...lines])], { type: "text/csv;charset=utf-8" }), `agreements-${new Date().toISOString().slice(0, 10)}.csv`);
    toast(t("agreements.exported", { n: chosen.length }), "success");
  }

  // ---- Start ------------------------------------------------------------------------
  if (!tabViews.some((v) => v.id === s.view)) setView(s.view);
  renderNav();
  insightsAvailable().then((v) => { mlOn = v; if (v && s.ready) fillSuggestions(); }, () => { mlOn = false; });
  load();
  loadPeople();
  return () => {
    gone = true;
    clearTimeout(searchTimer);
    offSugg();
    offMeaning();
    inspector.destroy();
    mq.removeEventListener("change", onMq);
    unregisterPrefix("list.");
    renderNavViews(ctx, { current: null, counts: s.ready ? viewCounts(s.rows, s.mine) : null });
  };
}
