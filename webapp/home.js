// Home (WEB-02; docs/47 §Screens "Home", after DocuSign's): start something (send,
// use a template, verify a PDF), four counters, and the most recent envelopes.
//
// Counters come from `GET /api/v1/envelopes?status=` (the API has no count): each is
// one page of up to 200, shown as "200+" past that. "Action required" is the sender's
// own to-do: envelopes that ended without completing and need correcting, resending
// or voiding (declined, expired). Envelopes waiting for *this user's* signature need
// a recipient filter the API lacks (row in the WEB-02 report).

import { h, clear, fmtDate } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { button, emptyState, skeletonRows, statusBadge, errorState } from "./ui.js";
import { countLabel } from "./templatemodel.js";

const COUNTERS = [
  { key: "action", statuses: ["declined", "expired"], icon: "circle-alert", href: "#/agreements?status=declined" },
  { key: "waiting", statuses: ["sent", "delivered"], icon: "hourglass", href: "#/agreements?status=sent" },
  { key: "completed", statuses: ["completed"], icon: "circle-check", href: "#/agreements?status=completed" },
  { key: "drafts", statuses: ["draft"], icon: "file-pen-line", href: "#/agreements?status=draft" },
];

export function mount(view, ctx) {
  const head = h("div", { class: "os-page-head" },
    h("h1", { class: "os-page-title", text: t("home.title") }),
    h("div", { class: "os-actions" },
      button(t("home.use-template"), { icon: "layout-template", onClick: () => ctx.navigate("#/templates") }),
      button(t("nav.new"), { icon: "plus", variant: "primary", onClick: () => ctx.navigate("#/prepare") })));

  const counters = h("ul", { class: "os-counters", attrs: { "aria-label": t("home.overview"), "aria-busy": "true" } });
  const cells = new Map();
  for (const c of COUNTERS) {
    const n = h("span", { class: "os-counter__n" }, h("span", { class: "os-skel os-skel--short", attrs: { "aria-hidden": "true" } }));
    const a = h("a", { class: `os-counter os-counter--${c.key}`, href: c.href, attrs: { "data-testid": `counter-${c.key}` } },
      h("span", { class: "os-counter__icon" }, icon(c.icon, { size: 24 })),
      n,
      h("span", { class: "os-counter__label", text: t(`home.counter.${c.key}`) }));
    cells.set(c.key, { a, n });
    counters.append(h("li", {}, a));
  }

  const recentTitle = h("h2", { id: "recent-h", class: "os-card__title", text: t("home.recent") });
  const recent = h("div", { class: "os-list", attrs: { "aria-busy": "true" } }, skeletonRows(4));
  const recentCard = h("section", { class: "os-card", attrs: { "aria-labelledby": "recent-h" } },
    h("div", { class: "os-card__head" }, recentTitle, h("a", { class: "os-link", href: "#/agreements", text: t("home.all-agreements") })),
    recent);

  const start = h("section", { class: "os-card os-start", attrs: { "aria-labelledby": "start-h" } },
    h("h2", { id: "start-h", class: "os-card__title", text: t("home.start") }),
    h("ul", { class: "os-start__list" },
      startItem("send", "#/prepare", t("home.start.send"), t("home.start.send-text")),
      startItem("layout-template", "#/templates", t("home.start.template"), t("home.start.template-text")),
      startItem("shield-check", "verify.html", t("home.start.verify"), t("home.start.verify-text"))));

  view.append(head, counters, h("div", { class: "os-home__grid" }, recentCard, start));

  function startItem(ic, href, title, text) {
    const link = h("a", { class: "os-start__item", href: href === "verify.html" && ctx.mock ? "verify.html?mock=1" : href },
      h("span", { class: "os-start__icon" }, icon(ic, { size: 24 })),
      h("span", { class: "os-start__text" }, h("strong", { text: title }), h("span", { class: "os-muted", text })));
    return h("li", {}, link);
  }

  async function load() {
    const totals = COUNTERS.map(async (c) => {
      const parts = await Promise.all(c.statuses.map((s) => ctx.api.countEnvelopes(s)));
      return { n: parts.reduce((s, p) => s + p.n, 0), more: parts.some((p) => p.more) };
    });
    const recentP = ctx.api.listEnvelopes({ limit: 5 });
    try {
      const [values, page] = await Promise.all([Promise.all(totals), recentP]);
      COUNTERS.forEach((c, i) => {
        const { n } = cells.get(c.key);
        const label = countLabel(values[i]);
        n.replaceChildren(label);
      });
      counters.removeAttribute("aria-busy");
      renderRecent(page.items || []);
    } catch (err) {
      counters.removeAttribute("aria-busy");
      recent.removeAttribute("aria-busy");
      if (ctx.failed(err)) return;
      for (const { n } of cells.values()) n.replaceChildren("—");
      errorState(recent, err, () => { recent.setAttribute("aria-busy", "true"); recent.replaceChildren(skeletonRows(4)); load(); });
    }
  }

  function renderRecent(items) {
    clear(recent);
    recent.removeAttribute("aria-busy");
    if (!items.length) {
      recent.append(emptyState({ illus: "documents", title: t("empty.home.title"), text: t("empty.home.text"), action: button(t("nav.new"), { icon: "plus", variant: "primary", onClick: () => ctx.navigate("#/prepare") }), testId: "empty-home" }));
      return;
    }
    const ul = h("ul", { class: "os-recent" });
    for (const r of items) {
      ul.append(h("li", { class: "os-recent__item" },
        h("a", { class: "os-row-link", href: `#/envelopes/${encodeURIComponent(r.id)}`, text: r.subject || t("envelope.untitled") }),
        statusBadge(r.status),
        h("time", { class: "os-muted os-small", attrs: { datetime: r.created_at }, text: fmtDate(r.created_at) })));
    }
    recent.append(ul);
  }

  load();
}
