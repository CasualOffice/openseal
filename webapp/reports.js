// Reports (WEB-02; docs/47 §Screens "Reports", after DocuSign's envelope report): what
// the account has sent, by status, how long completion takes, and a CSV of the
// envelopes. Computed in the page from `GET /api/v1/envelopes` (up to 1,000 envelopes,
// newest first) and each completed envelope's `sent_at` and `ended_at`; a server-side
// report endpoint with date ranges and recipient reports is row REP-01 territory and
// not drawn until it exists.

import { h, clear, download } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { button, emptyState, skeletonRows, errorState } from "./ui/index.js";
import { statusCounts, medianHours, toCsv } from "./reportmodel.js";

const STATUSES = ["draft", "sent", "delivered", "completed", "declined", "voided", "expired"];
const MAX = 1000;

export function mount(view, ctx) {
  const exportBtn = button(t("reports.export"), { icon: "download", onClick: () => exportCsv() });
  exportBtn.disabled = true;
  view.append(h("div", { class: "os-page-head" }, h("h1", { class: "os-page-title", text: t("reports.title") }), exportBtn),
    h("p", { class: "os-muted os-lede", text: t("reports.lede") }));
  const body = h("div", { attrs: { "aria-busy": "true" } }, skeletonRows(5));
  view.append(body);
  let rows = [];

  async function load() {
    try {
      rows = [];
      let cursor;
      do {
        const page = await ctx.api.listEnvelopes({ cursor, limit: 200 });
        rows.push(...(page.items || []));
        cursor = page.next_cursor;
      } while (cursor && rows.length < MAX);
      const done = rows.filter((r) => r.status === "completed").slice(0, 50);
      const details = (await Promise.all(done.map((r) => ctx.api.getEnvelope(r.id).then((x) => x.envelope).catch(() => null)))).filter(Boolean);
      render(details, !!cursor);
    } catch (err) {
      if (ctx.failed(err)) return;
      errorState(body, err, load);
    } finally {
      body.removeAttribute("aria-busy");
    }
  }

  function render(completed, truncated) {
    clear(body);
    if (!rows.length) {
      body.append(emptyState({ illus: "documents", title: t("empty.reports.title"), text: t("empty.reports.text"), action: button(t("nav.new"), { icon: "plus", variant: "primary", onClick: () => ctx.navigate("#/prepare") }), testId: "empty-reports" }));
      return;
    }
    exportBtn.disabled = false;
    const counts = statusCounts(rows);
    const sent = rows.length - (counts.draft || 0);
    const rate = sent ? Math.round(((counts.completed || 0) / sent) * 100) : 0;
    const median = medianHours(completed);
    const tiles = h("ul", { class: "os-counters" },
      tile("send", t("reports.sent"), String(sent)),
      tile("circle-check", t("reports.completion"), `${rate}%`),
      tile("clock", t("reports.median"), median == null ? "—" : t("reports.hours", { n: median })),
      tile("file-pen-line", t("reports.drafts"), String(counts.draft || 0)));
    const max = Math.max(1, ...STATUSES.map((s) => counts[s] || 0));
    const bars = h("table", { class: "os-table os-bars" },
      h("caption", { class: "os-sr-only", text: t("reports.by-status") }),
      h("thead", {}, h("tr", {}, h("th", { attrs: { scope: "col" }, text: t("agreements.col.status") }), h("th", { attrs: { scope: "col" }, text: t("reports.count") }))),
      h("tbody", {}, ...STATUSES.map((s) => {
        const n = counts[s] || 0;
        const bar = h("span", { class: `os-bar os-bar--${s}`, attrs: { "aria-hidden": "true" } });
        bar.style.setProperty("--os-bar", `${Math.round((n / max) * 100)}%`);
        return h("tr", {}, h("th", { attrs: { scope: "row" }, text: t(`status.${s}`) }), h("td", {}, h("span", { class: "os-bar__row" }, bar, h("span", { class: "os-bar__n", text: String(n) }))));
      })));
    body.append(tiles,
      h("section", { class: "os-card", attrs: { "aria-labelledby": "rep-status-h" } }, h("h2", { id: "rep-status-h", class: "os-card__title", text: t("reports.by-status") }), bars),
      truncated ? h("p", { class: "os-muted os-small", text: t("reports.truncated", { n: rows.length }) }) : "");
  }

  function tile(ic, label, value) {
    return h("li", {}, h("div", { class: "os-counter os-counter--static" },
      h("span", { class: "os-counter__icon" }, icon(ic, { size: 24 })),
      h("span", { class: "os-counter__n", text: value }),
      h("span", { class: "os-counter__label", text: label })));
  }

  function exportCsv() {
    const csv = toCsv(rows.map((r) => ({ id: r.id, subject: r.subject || "", status: r.status, created_at: r.created_at })));
    download(new Blob([csv], { type: "text/csv" }), "envelopes.csv");
  }

  load();
}
