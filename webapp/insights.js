// Insights (FG-141, after DocuSign's Insights dashboard), `#/insights`, reached from
// Reports: how sending is going over a period. Figures come from the server's
// `GET /insights`, computed over every envelope of the period (not a page of the list):
// envelopes sent and completed, the completion rate, the median and 90th-percentile time
// to complete, declined and voided; sent and completed over time; the outcomes; the top
// senders. An administrator (`reports.read`) sees the workspace and may choose a
// sender; anyone else sees their own envelopes, and the page says so.
//
// Accessible charts: each chart is an SVG with a role of img and a summary label, and
// its data as a table below it, opened by "Show as a table" (a native disclosure). The
// outcomes and the top senders are tables with an inline bar, which serve as both.

import { h, clear, download } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { register, unregisterPrefix } from "./commands.js";
import { button, skeletonBlock, errorState, selectField, toastError } from "./ui/index.js";
import { windowBounds, toCsv } from "./reportmodel.js";
import { completionRate, duration, series, windowDays, niceMax, utcOffsetMinutes, seriesCsvRows } from "./insightsmodel.js";

const RANGES = ["30", "7", "90", "365", "all", "custom"];
const SVG = "http://www.w3.org/2000/svg";
const OUTCOMES = ["completed", "in_progress", "declined", "voided", "expired"];

function svg(tag, attrs = {}) {
  const el = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
  return el;
}

/// While the figures load: the tiles and the chart, shaped like the page.
function skeleton() {
  return h("div", { class: "os-repskel", attrs: { "aria-hidden": "true" } },
    h("div", { class: "os-repskel__tiles" }, ...[0, 1, 2, 3].map(() => skeletonBlock({ height: 8.25 }))),
    skeletonBlock({ height: 18 }));
}

const fmtDuration = (seconds) => {
  const d = duration(seconds);
  return d ? t(`insights.${d.unit}`, { n: d.n.toLocaleString() }) : "—";
};

export function mount(view, ctx) {
  const win = { range: "30", from: "", to: "" };
  let sender = "all";
  let data = null;
  let current = null; // the series drawn
  const names = new Map();
  const admin = !!ctx.session?.admin;

  const refreshBtn = button(t("insights.refresh"), { icon: "refresh-cw", variant: "secondary", attrs: { "data-os-command": "insights.refresh" }, onClick: () => load() });
  const exportBtn = button(t("insights.export"), { icon: "download", attrs: { "data-os-command": "insights.export" }, onClick: () => exportCsv() });
  exportBtn.disabled = true;
  const period = selectField(t("reports.range"), RANGES.map((r) => [r, r === "all" ? t("reports.range-all") : r === "custom" ? t("reports.range-custom") : t("reports.range-days", { n: r })]),
    { id: "ins-range", size: "sm", value: win.range, onChange: (v) => { win.range = v; dates.hidden = v !== "custom"; if (v !== "custom") load(); } });
  const date = (id, label, key) => {
    const input = h("input", { id, type: "date", class: "os-input os-input--sm" });
    input.addEventListener("change", () => { win[key] = input.value; load(); });
    return h("div", { class: "os-fieldrow" }, h("label", { class: "os-label", attrs: { for: id }, text: label }), input);
  };
  const dates = h("div", { class: "os-reports__dates", hidden: true }, date("ins-from", t("reports.from"), "from"), date("ins-to", t("reports.to"), "to"));
  const who = selectField(t("reports.sender"), admin ? [["all", t("reports.sender-all")], ["me", t("reports.sender-me")]] : [["me", t("reports.sender-me")]],
    { id: "ins-sender", size: "sm", value: admin ? sender : "me", onChange: (v) => { sender = v; load(); } });
  if (!admin) sender = "me";
  const note = h("p", { class: "os-muted os-small os-reports__note", attrs: { "data-testid": "insights-note", "aria-live": "polite" } });
  const tools = h("div", { class: "os-reports__tools" }, period.el, dates, who.el, note);
  view.append(
    h("div", { class: "os-page-head" },
      h("h1", { class: "os-page-title", text: t("insights.title") }),
      h("div", { class: "os-actions" }, h("a", { class: "os-btn os-btn--ghost", href: "#/reports", text: t("insights.to-reports") }), refreshBtn, exportBtn)),
    h("p", { class: "os-muted os-lede", text: t("insights.lede") }), tools);
  const body = h("div", { class: "os-insights", attrs: { "aria-busy": "true", "aria-live": "polite", "data-testid": "insights" } }, skeleton());
  view.append(body);

  register("insights.refresh", { label: t("insights.refresh"), run: () => load() });
  register("insights.export", { label: t("insights.export"), run: () => exportCsv(), enabled: () => !!current?.points.length });

  let seq = 0;
  async function load() {
    const mine = ++seq;
    body.setAttribute("aria-busy", "true");
    try {
      const bounds = windowBounds(win);
      const offset = utcOffsetMinutes();
      const q = { ...bounds, utc_offset_minutes: offset, ...(sender === "all" ? {} : { sender }) };
      const got = await ctx.api.insights(q);
      if (mine !== seq) return;
      data = got;
      if (admin && !names.size) await senders();
      current = series(data.days, windowDays(bounds, offset));
      render();
    } catch (err) {
      if (mine !== seq || ctx.failed(err)) return;
      errorState(body, err, load);
    } finally {
      if (mine === seq) body.removeAttribute("aria-busy");
    }
  }

  /// Members' names for the sender filter and the top senders (administrators).
  async function senders() {
    try {
      for (const u of (await ctx.api.users.list()).items || []) names.set(u.id, u.name || u.email || "");
    } catch { /* not allowed to list members: ids stay unnamed */ }
    const me = ctx.session?.user_id;
    for (const [id, name] of names) if (id !== me) who.select.append(h("option", { value: id, text: name || t("reports.sender-other") }));
  }

  function render() {
    clear(body);
    const tot = data.totals || {};
    const ttc = data.time_to_complete || {};
    const rate = completionRate(tot);
    exportBtn.disabled = !current.points.length;
    note.textContent = t(data.scope === "own" ? "insights.scope-own" : "insights.scope-workspace", { n: (tot.created || 0).toLocaleString() });
    body.append(
      h("ul", { class: "os-counters os-insights__tiles" },
        tile("sent", "send", t("insights.sent"), (tot.sent || 0).toLocaleString(), t("insights.created", { n: (tot.created || 0).toLocaleString() })),
        tile("completed", "circle-check", t("insights.completed"), (tot.completed || 0).toLocaleString(), t("reports.of-sent", { n: (tot.sent || 0).toLocaleString() })),
        tile("rate", "chart-column", t("reports.completion"), rate == null ? "—" : `${rate}%`, t("reports.of-sent", { n: (tot.sent || 0).toLocaleString() })),
        tile("median", "clock", t("reports.median"), fmtDuration(ttc.median_seconds), t("reports.median-from", { n: (ttc.completed || 0).toLocaleString() })),
        tile("p90", "hourglass", t("insights.p90"), fmtDuration(ttc.p90_seconds), t("insights.p90-help")),
        tile("declined", "circle-x", t("insights.declined-voided"), `${(tot.declined || 0).toLocaleString()} / ${(tot.voided || 0).toLocaleString()}`, t("insights.declined-voided-help"))),
      overTime(),
      h("div", { class: "os-insights__grid" }, outcomes(tot), topSenders()));
  }

  function tile(id, ic, label, value, sample) {
    return h("li", {}, h("div", { class: "os-counter os-counter--static", attrs: { "data-testid": `insight-${id}` } },
      h("span", { class: "os-counter__icon" }, icon(ic, { size: 24 })),
      h("span", { class: "os-counter__n", text: value }),
      h("span", { class: "os-counter__label", text: label }),
      h("span", { class: "os-counter__sample", text: sample })));
  }

  /// Sent and completed per day (or week): paired bars, a legend, the summary as the
  /// image's name, and the same numbers as a table under a disclosure.
  function overTime() {
    const pts = current.points;
    const weekly = current.unit === "week";
    const sumSent = pts.reduce((a, p) => a + p.sent, 0);
    const sumDone = pts.reduce((a, p) => a + p.completed, 0);
    const card = h("section", { class: "os-card", attrs: { "aria-labelledby": "ins-time-h", "data-testid": "insights-over-time" } },
      h("h2", { id: "ins-time-h", class: "os-card__title", text: t(weekly ? "insights.over-time-week" : "insights.over-time-day") }));
    if (!pts.length || !(sumSent + sumDone)) {
      card.append(h("p", { class: "os-muted", attrs: { "data-testid": "insights-none" }, text: t("insights.none") }));
      return card;
    }
    const W = 640;
    const H = 200;
    const pad = { l: 32, r: 8, t: 8, b: 24 };
    const max = niceMax(Math.max(...pts.map((p) => Math.max(p.sent, p.completed))));
    const slot = (W - pad.l - pad.r) / pts.length;
    const bw = Math.max(1, Math.min(14, slot / 2 - 1));
    const y = (v) => pad.t + (H - pad.t - pad.b) * (1 - v / max);
    const label = t("insights.over-time-summary", { sent: sumSent.toLocaleString(), completed: sumDone.toLocaleString(), first: pts[0].day, last: pts[pts.length - 1].day });
    const chart = svg("svg", { viewBox: `0 0 ${W} ${H}`, class: "os-chart", role: "img", "aria-label": label, preserveAspectRatio: "none", "data-testid": "insights-chart" });
    for (const v of [0, max / 2, max]) {
      chart.append(svg("line", { x1: pad.l, x2: W - pad.r, y1: y(v), y2: y(v), class: "os-chart__grid" }));
      const tx = svg("text", { x: pad.l - 4, y: y(v) + 4, "text-anchor": "end", class: "os-chart__tick" });
      tx.textContent = Number.isInteger(v) ? String(v) : v.toFixed(1);
      chart.append(tx);
    }
    pts.forEach((p, i) => {
      const x0 = pad.l + i * slot + slot / 2 - bw;
      chart.append(svg("rect", { x: x0, y: y(p.sent), width: bw, height: Math.max(0, y(0) - y(p.sent)), class: "os-chart__bar os-chart__bar--sent" }));
      chart.append(svg("rect", { x: x0 + bw + 1, y: y(p.completed), width: bw, height: Math.max(0, y(0) - y(p.completed)), class: "os-chart__bar os-chart__bar--completed" }));
    });
    for (const [i, p] of [[0, pts[0]], [pts.length - 1, pts[pts.length - 1]]]) {
      const tx = svg("text", { x: pad.l + i * slot + slot / 2, y: H - 6, "text-anchor": i ? "end" : "start", class: "os-chart__tick" });
      tx.textContent = p.day;
      chart.append(tx);
    }
    const legend = h("ul", { class: "os-chart__legend" },
      h("li", {}, h("span", { class: "os-chart__key os-chart__key--sent", attrs: { "aria-hidden": "true" } }), h("span", { text: t("insights.sent") })),
      h("li", {}, h("span", { class: "os-chart__key os-chart__key--completed", attrs: { "aria-hidden": "true" } }), h("span", { text: t("insights.completed") })));
    const table = h("table", { class: "os-table os-insights__table", attrs: { "data-testid": "insights-over-time-table" } },
      h("caption", { class: "os-sr-only", text: t(weekly ? "insights.over-time-week" : "insights.over-time-day") }),
      h("thead", {}, h("tr", {},
        h("th", { attrs: { scope: "col" }, text: t(weekly ? "insights.week-of" : "insights.day") }),
        h("th", { attrs: { scope: "col" }, text: t("insights.sent") }),
        h("th", { attrs: { scope: "col" }, text: t("insights.completed") }))),
      h("tbody", {}, ...pts.filter((p) => p.sent || p.completed).map((p) => h("tr", {},
        h("th", { attrs: { scope: "row" }, text: p.day }), h("td", { text: p.sent.toLocaleString() }), h("td", { text: p.completed.toLocaleString() })))));
    card.append(h("div", { class: "os-chart__wrap" }, chart), legend,
      h("details", { class: "os-insights__data" }, h("summary", { attrs: { "data-testid": "insights-show-table" }, text: t("insights.show-table") }), table));
    return card;
  }

  /// How the period's envelopes stand: a table whose rows carry a bar.
  function outcomes(tot) {
    const max = Math.max(1, ...OUTCOMES.map((k) => tot[k] || 0));
    const rows = OUTCOMES.map((k) => {
      const n = tot[k] || 0;
      const bar = h("span", { class: `os-bar os-bar--${k === "in_progress" ? "sent" : k}`, attrs: { "aria-hidden": "true" } });
      bar.style.setProperty("--os-bar", `${Math.round((n / max) * 100)}%`);
      return h("tr", { attrs: { "data-outcome": k } }, h("th", { attrs: { scope: "row" }, text: t(`insights.outcome.${k}`) }),
        h("td", {}, h("span", { class: "os-bar__row" }, bar, h("span", { class: "os-bar__n", text: n.toLocaleString() }))));
    });
    return h("section", { class: "os-card", attrs: { "aria-labelledby": "ins-out-h", "data-testid": "insights-outcomes" } },
      h("h2", { id: "ins-out-h", class: "os-card__title", text: t("insights.outcomes") }),
      h("table", { class: "os-table os-bars" },
        h("caption", { class: "os-sr-only", text: t("insights.outcomes") }),
        h("thead", {}, h("tr", {}, h("th", { attrs: { scope: "col" }, text: t("agreements.col.status") }), h("th", { attrs: { scope: "col" }, text: t("reports.count") }))),
        h("tbody", {}, ...rows)));
  }

  /// The senders who sent most (the workspace's view only).
  function topSenders() {
    const top = data.top_senders || [];
    const card = h("section", { class: "os-card", attrs: { "aria-labelledby": "ins-top-h", "data-testid": "insights-top-senders" } },
      h("h2", { id: "ins-top-h", class: "os-card__title", text: t("insights.top-senders") }));
    if (data.scope === "own") { card.append(h("p", { class: "os-muted os-small", text: t("insights.top-own") })); return card; }
    if (!top.length) { card.append(h("p", { class: "os-muted", text: t("insights.none") })); return card; }
    const max = Math.max(1, ...top.map((s) => s.sent));
    const me = ctx.session?.user_id;
    card.append(h("table", { class: "os-table os-bars" },
      h("caption", { class: "os-sr-only", text: t("insights.top-senders") }),
      h("thead", {}, h("tr", {},
        h("th", { attrs: { scope: "col" }, text: t("reports.sender") }),
        h("th", { attrs: { scope: "col" }, text: t("insights.sent") }),
        h("th", { attrs: { scope: "col" }, text: t("insights.completed") }))),
      h("tbody", {}, ...top.map((s) => {
        const bar = h("span", { class: "os-bar os-bar--sent", attrs: { "aria-hidden": "true" } });
        bar.style.setProperty("--os-bar", `${Math.round((s.sent / max) * 100)}%`);
        const name = s.sender_user_id === me ? t("reports.sender-me") : names.get(s.sender_user_id) || t("reports.sender-other");
        return h("tr", {}, h("th", { attrs: { scope: "row" }, text: name }),
          h("td", {}, h("span", { class: "os-bar__row" }, bar, h("span", { class: "os-bar__n", text: s.sent.toLocaleString() }))),
          h("td", { text: s.completed.toLocaleString() }));
      }))));
    return card;
  }

  function exportCsv() {
    if (!current?.points.length) return;
    download(new Blob([toCsv(seriesCsvRows(current))], { type: "text/csv" }), "insights.csv");
  }

  load().catch((err) => { if (!ctx.failed(err)) toastError(err); });
  return () => unregisterPrefix("insights.");
}
