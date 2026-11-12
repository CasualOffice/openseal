// Reports (WEB-02, WEB-06, UX-08; docs/47 §Screens "Reports", after DocuSign's envelope
// report): what the account has sent in a period, by status, how long completion takes,
// and a CSV of the envelopes. Computed in the page from `GET /api/v1/envelopes` (the
// newest 1,000 envelopes at most), whose summaries carry `sent_at` and `completed_at`;
// every figure says how many envelopes it rests on, so a cap is never silent. The
// period is by creation date: a preset or a custom range; a sender filter; each status
// row opens the matching Agreements view. A server-side report endpoint with recipient
// and usage reports is row REP-01 and not drawn until it exists.

import { h, clear, download } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { button, emptyState, skeletonRows, errorState, selectField } from "./ui/index.js";
import { statusCounts, medianHours, toCsv, hasTimes, inWindow, csvRows } from "./reportmodel.js";

const STATUSES = ["draft", "sent", "delivered", "completed", "declined", "voided", "expired"];
const MAX = 1000;
const OLD_SAMPLE = 50; // completed envelopes read one by one when the list has no times
const RANGES = ["all", "7", "30", "90", "365", "custom"];

/// The rows created within the last `range` days (`"all"`: every row). `now` in ms.
export function inPeriod(rows, range, now = Date.now()) {
  return inWindow(rows, { range }, now);
}

export function mount(view, ctx) {
  const exportBtn = button(t("reports.export"), { icon: "download", onClick: () => exportCsv() });
  exportBtn.disabled = true;
  const win = { range: "all", from: "", to: "" };
  let sender = "all";
  const names = new Map();
  const period = selectField(t("reports.range"), RANGES.map((r) => [r, r === "all" ? t("reports.range-all") : r === "custom" ? t("reports.range-custom") : t("reports.range-days", { n: r })]),
    { id: "rep-range", size: "sm", value: win.range, onChange: (v) => { win.range = v; dates.hidden = v !== "custom"; render(); } });
  const date = (id, label, key) => {
    const input = h("input", { id, type: "date", class: "os-input os-input--sm" });
    input.addEventListener("change", () => { win[key] = input.value; render(); });
    return h("div", { class: "os-fieldrow" }, h("label", { class: "os-label", attrs: { for: id }, text: label }), input);
  };
  const dates = h("div", { class: "os-reports__dates", hidden: true }, date("rep-from", t("reports.from"), "from"), date("rep-to", t("reports.to"), "to"));
  const who = selectField(t("reports.sender"), [["all", t("reports.sender-all")], ["me", t("reports.sender-me")]], { id: "rep-sender", size: "sm", value: sender, onChange: (v) => { sender = v; render(); } });
  const note = h("p", { class: "os-muted os-small os-reports__note", attrs: { "data-testid": "report-note", "aria-live": "polite" } });
  const tools = h("div", { class: "os-reports__tools" }, period.el, dates, who.el, note);
  view.append(h("div", { class: "os-page-head" }, h("h1", { class: "os-page-title", text: t("reports.title") }), exportBtn),
    h("p", { class: "os-muted os-lede", text: t("reports.lede") }), tools);
  const body = h("div", { attrs: { "aria-busy": "true", "aria-live": "polite" } }, skeletonRows(5));
  view.append(body);
  let rows = [];
  let completed = [];
  let truncated = false;
  let sampled = false; // the median rests on the first OLD_SAMPLE completed (a list without times)

  async function load() {
    try {
      rows = [];
      let cursor;
      do {
        const page = await ctx.api.listEnvelopes({ cursor, limit: 200 });
        rows.push(...(page.items || []));
        cursor = page.next_cursor;
      } while (cursor && rows.length < MAX);
      truncated = !!cursor;
      const done = rows.filter((r) => r.status === "completed");
      if (done.every(hasTimes)) {
        completed = done;
      } else {
        // An older server's summary has no times: read the newest completed ones.
        sampled = done.length > OLD_SAMPLE;
        completed = (await Promise.all(done.slice(0, OLD_SAMPLE).map((r) => ctx.api.getEnvelope(r.id).then((x) => x.envelope).catch(() => null)))).filter(Boolean);
      }
      await senders();
      render();
    } catch (err) {
      if (ctx.failed(err)) return;
      errorState(body, err, load);
    } finally {
      body.removeAttribute("aria-busy");
    }
  }
  /// The sender filter's names: the account's members when this user may list them,
  /// else "Me" and the ids seen.
  async function senders() {
    try { for (const u of (await ctx.api.users.list()).items || []) names.set(u.id, u.name || u.email || ""); } catch { /* not an admin */ }
    const me = ctx.session?.user_id;
    const ids = [...new Set(rows.map((r) => r.sender_user_id).filter((x) => x && x !== me))];
    for (const id of ids) who.select.append(h("option", { value: id, text: names.get(id) || t("reports.sender-other") }));
  }

  const shown = () => inWindow(rows, win).filter((r) => sender === "all" || r.sender_user_id === (sender === "me" ? ctx.session?.user_id : sender));

  function render() {
    clear(body);
    if (!rows.length) {
      tools.hidden = true;
      body.append(emptyState({ illus: "documents", title: t("empty.reports.title"), text: t("empty.reports.text"), action: button(t("nav.new"), { icon: "plus", variant: "primary", onClick: () => ctx.navigate("#/prepare") }), testId: "empty-reports" }));
      return;
    }
    exportBtn.disabled = false;
    const list = shown();
    const ids = new Set(list.map((r) => r.id));
    const counts = statusCounts(list);
    const sent = list.length - (counts.draft || 0);
    const rate = sent ? Math.round(((counts.completed || 0) / sent) * 100) : 0;
    const done = completed.filter((e) => ids.has(e.id));
    const median = medianHours(done);
    const doneIn = counts.completed || 0;
    note.textContent = t(truncated ? "reports.range-note-capped" : "reports.range-note", { n: list.length, max: rows.length.toLocaleString() });
    const loaded = truncated ? t("reports.of-newest", { n: rows.length.toLocaleString() }) : t("reports.of-loaded", { n: list.length });
    const tiles = h("ul", { class: "os-counters" },
      tile("sent", "send", t("reports.sent"), String(sent), loaded),
      tile("completion", "circle-check", t("reports.completion"), `${rate}%`, t("reports.of-sent", { n: sent })),
      tile("median", "clock", t("reports.median"), median == null ? "—" : t("reports.hours", { n: median }),
        sampled && done.length < doneIn ? t("reports.median-sample", { n: done.length, total: doneIn }) : t("reports.median-from", { n: done.length })),
      tile("drafts", "file-pen-line", t("reports.drafts"), String(counts.draft || 0), loaded));
    const max = Math.max(1, ...STATUSES.map((s) => counts[s] || 0));
    const bars = h("table", { class: "os-table os-bars", attrs: { "data-testid": "report-bars" } },
      h("caption", { class: "os-sr-only", text: t("reports.by-status") }),
      h("thead", {}, h("tr", {}, h("th", { attrs: { scope: "col" }, text: t("agreements.col.status") }), h("th", { attrs: { scope: "col" }, text: t("reports.count") }))),
      h("tbody", {}, ...STATUSES.map((s) => {
        const n = counts[s] || 0;
        const bar = h("span", { class: `os-bar os-bar--${s}`, attrs: { "aria-hidden": "true" } });
        bar.style.setProperty("--os-bar", `${Math.round((n / max) * 100)}%`);
        return h("tr", { attrs: { "data-status": s } },
          h("th", { attrs: { scope: "row" } }, h("a", { class: "os-bars__link", href: `#/agreements?status=${s}`, attrs: { title: t("reports.open-list") } },
            h("span", { class: `os-bar__key os-bar--${s}`, attrs: { "aria-hidden": "true" } }), h("span", { text: t(`status.${s}`) }))),
          h("td", {}, h("span", { class: "os-bar__row" }, bar, h("span", { class: "os-bar__n", text: String(n) }))));
      })));
    body.append(tiles,
      h("section", { class: "os-card", attrs: { "aria-labelledby": "rep-status-h" } },
        h("h2", { id: "rep-status-h", class: "os-card__title", text: t("reports.by-status") }),
        h("p", { class: "os-muted os-small", text: t("reports.by-status-help") }), bars),
      truncated ? h("p", { class: "os-muted os-small", attrs: { "data-testid": "report-capped" }, text: t("reports.truncated", { n: rows.length.toLocaleString() }) }) : "");
  }

  function tile(id, ic, label, value, sample) {
    return h("li", {}, h("div", { class: "os-counter os-counter--static", attrs: { "data-testid": `tile-${id}` } },
      h("span", { class: "os-counter__icon" }, icon(ic, { size: 24 })),
      h("span", { class: "os-counter__n", text: value }),
      h("span", { class: "os-counter__label", text: label }),
      h("span", { class: "os-counter__sample", text: sample })));
  }

  function exportCsv() {
    const csv = toCsv(csvRows(shown(), (id) => names.get(id) || ""));
    download(new Blob([csv], { type: "text/csv" }), "envelopes.csv");
  }

  load();
}
