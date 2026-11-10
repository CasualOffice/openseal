// Agreements (WEB-01; docs/47 §Screens): the sender's envelopes, newest first, with
// status filters (`GET /api/v1/envelopes?status=`), cursor paging and search.
//
// Search filters the loaded rows by subject in the browser: the API has no text query
// yet (proposed row in the WEB-01 report). "Load more" fetches the next page.

import { h, clear, fmtDate } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { register, unregisterPrefix } from "./commands.js";
import { button, emptyState, skeletonRows, statusBadge, errorState, toastError } from "./ui.js";

const FILTERS = ["", "draft", "sent", "delivered", "completed", "declined", "voided"];

export function mount(view, ctx, _match, params) {
  let status = FILTERS.includes(params.get("status") || "") ? params.get("status") || "" : "";
  let rows = [];
  let cursor = null;
  let query = "";

  const title = h("h1", { class: "os-page-title", text: t("agreements.title") });
  const head = h("div", { class: "os-page-head" }, title,
    button(t("nav.new"), { icon: "plus", variant: "primary", onClick: () => ctx.navigate("#/prepare") }));

  const tabs = h("div", { class: "os-filters", attrs: { role: "group", "aria-label": t("agreements.filter") } });
  for (const f of FILTERS) {
    const b = h("button", { type: "button", class: "os-chip", attrs: { "aria-pressed": String(f === status), "data-status": f || "all" } },
      h("span", { text: f ? t(`status.${f}`) : t("agreements.all") }));
    b.addEventListener("click", () => {
      ctx.navigate(f ? `#/agreements?status=${f}` : "#/agreements");
    });
    tabs.append(b);
  }

  const search = h("input", { id: "agreements-search", class: "os-input os-search__input", type: "search", placeholder: t("agreements.search"), attrs: { "aria-label": t("agreements.search") } });
  search.addEventListener("input", () => { query = search.value.trim().toLowerCase(); renderRows(); });
  const searchBox = h("div", { class: "os-search" }, icon("search", { size: 16 }), search);

  const list = h("div", { class: "os-list", attrs: { "aria-live": "polite" } });
  const more = h("div", { class: "os-list__more" });
  view.append(head, h("div", { class: "os-toolbar" }, tabs, searchBox), list, more);

  register("list.search", { label: t("cmd.search"), run: () => search.focus() });

  async function load(append = false) {
    if (!append) {
      clear(list);
      list.setAttribute("aria-busy", "true");
      list.append(skeletonRows(6));
    }
    try {
      const page = await ctx.api.listEnvelopes({ status: status || undefined, cursor: append ? cursor : undefined, limit: 25 });
      rows = append ? rows.concat(page.items || []) : page.items || [];
      cursor = page.next_cursor || null;
      list.removeAttribute("aria-busy");
      renderRows();
    } catch (err) {
      list.removeAttribute("aria-busy");
      if (ctx.failed(err)) return;
      if (append) toastError(err);
      else errorState(list, err, () => load());
    }
  }

  function renderRows() {
    clear(list);
    clear(more);
    const shown = query ? rows.filter((r) => (r.subject || "").toLowerCase().includes(query)) : rows;
    if (!rows.length) {
      list.append(status
        ? emptyState({ illus: "inbox", title: t("empty.filter.title", { status: t(`status.${status}`) }), text: t("empty.filter.text"), action: button(t("agreements.all"), { variant: "primary", onClick: () => ctx.navigate("#/agreements") }), testId: "empty-filter" })
        : emptyState({ illus: "documents", title: t("empty.envelopes.title"), text: t("empty.envelopes.text"), action: button(t("nav.new"), { icon: "plus", variant: "primary", onClick: () => ctx.navigate("#/prepare") }), testId: "empty-envelopes" }));
      return;
    }
    if (!shown.length) {
      list.append(emptyState({ illus: "search", title: t("empty.search.title"), text: t("empty.search.text", { query: search.value.trim() }), action: button(t("action.clear-search"), { variant: "primary", onClick: () => { search.value = ""; query = ""; renderRows(); search.focus(); } }), testId: "empty-search" }));
      return;
    }
    const table = h("table", { class: "os-table os-table--rows" },
      h("caption", { class: "os-sr-only", text: t("agreements.caption") }),
      h("thead", {}, h("tr", {},
        h("th", { attrs: { scope: "col" }, text: t("agreements.col.subject") }),
        h("th", { attrs: { scope: "col" }, text: t("agreements.col.status") }),
        h("th", { attrs: { scope: "col" }, class: "os-col-date", text: t("agreements.col.created") }))));
    const tb = h("tbody");
    for (const r of shown) {
      const href = `#/envelopes/${encodeURIComponent(r.id)}`;
      const link = h("a", { href, class: "os-row-link", text: r.subject || t("envelope.untitled") });
      const tr = h("tr", { class: "os-row", attrs: { "data-id": r.id } },
        h("td", {}, link),
        h("td", {}, statusBadge(r.status)),
        h("td", { class: "os-col-date os-muted", text: fmtDate(r.created_at) }));
      tr.addEventListener("click", (e) => { if (e.target.closest("a")) return; ctx.navigate(href); });
      tb.append(tr);
    }
    table.append(tb);
    list.append(table);
    if (cursor) {
      const b = button(t("agreements.more"), { icon: "chevron-down", onClick: async () => { b.disabled = true; await load(true); } });
      more.append(b);
    }
  }

  load();
  return () => unregisterPrefix("list.");
}
