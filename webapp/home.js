// Home (WEB-02; docs/47 §Screens "Home", after DocuSign's): a greeting, four stat
// cards, a drop zone that starts an envelope with the dropped PDFs, recent activity and
// recent templates. One way in to a new envelope (WEB-06 G-03): the top bar's Start;
// the drop zone is the same action for files already in hand, so its button is quiet.
//
// Counts come from `GET /api/v1/envelopes?status=` (the API has no count): one page of
// up to 200 per status, shown as "200+" past that. "Declined or expired" (WEB-06 A-04;
// it was "Action required", which DocuSign uses for "waiting for you") is the sender's
// own to-do: envelopes that ended without completing and need a new copy or a word with
// the recipient. "Expiring soon" reads each waiting list item's `expires_at` and counts
// those ending within 7 days; its card opens the matching quick view (UX-07). Envelopes
// waiting for *this user's* signature need the Inbox (UXW-01, NOT_ON_SERVER.inbox).
//
// UX-07: each recent envelope says who it went to ("To: …"), where it stands (the
// status line) and when it last changed, and the whole row opens it; the drop zone is
// one slim line, so the list starts above the fold; a Drafts counter.

import { h, clear, fmtDate } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { button, emptyState, skeletonRows, statusBadge, errorState, toast } from "./ui/index.js";
import { countLabel } from "./templatemodel.js";
import { handFiles } from "./handoff.js";
import { statusLine, shortDate } from "./envactions.js";
import { rowHref } from "./dashboard.js";
import { expiringSoon } from "./managemodel.js";

export const CARDS = [
  { key: "action", icon: "circle-alert", href: "#/agreements?folder=action" },
  { key: "waiting", icon: "hourglass", href: "#/agreements?folder=waiting" },
  { key: "expiring", icon: "clock", href: "#/agreements?folder=expiring" },
  { key: "drafts", icon: "file-pen-line", href: "#/agreements?folder=drafts" },
  { key: "completed", icon: "circle-check", href: "#/agreements?folder=completed" },
];

/// The greeting for the hour: morning before 12, afternoon before 18, else evening.
export function greetingKey(hour) {
  return hour < 12 ? "home.greeting.morning" : hour < 18 ? "home.greeting.afternoon" : "home.greeting.evening";
}

export function mount(view, ctx) {
  const head = h("div", { class: "os-page-head os-home__head" },
    h("div", { class: "os-page-head__main os-page-head__stack" },
      h("h1", { class: "os-page-title", text: t("home.title") }),
      h("p", { class: "os-muted", text: t(greetingKey(new Date().getHours())) })));

  const counters = h("ul", { class: "os-counters os-counters--home", attrs: { "aria-label": t("home.overview"), "aria-busy": "true" } });
  const cells = new Map();
  for (const c of CARDS) {
    const n = h("span", { class: "os-counter__n" }, h("span", { class: "os-skel os-skel--short", attrs: { "aria-hidden": "true" } }));
    const a = h("a", { class: `os-counter os-counter--${c.key}`, href: c.href, attrs: { "data-testid": `counter-${c.key}` } },
      h("span", { class: "os-counter__icon" }, icon(c.icon, { size: 20 })),
      h("span", { class: "os-counter__label", text: t(`home.counter.${c.key}`) }),
      n);
    cells.set(c.key, n);
    counters.append(h("li", {}, a));
  }

  // Drop zone: SignNow's speed, the editor opens on the files.
  const input = h("input", { type: "file", accept: "application/pdf,.pdf", multiple: true, class: "os-sr-only", attrs: { "aria-hidden": "true", tabindex: "-1", "data-testid": "home-input" } });
  const start = (files) => {
    const pdfs = [...files].filter((f) => f.type === "application/pdf" || /\.pdf$/i.test(f.name));
    if (!pdfs.length) { toast(t("home.drop-not-pdf"), "error"); return; }
    handFiles(pdfs);
    ctx.navigate("#/prepare");
  };
  input.addEventListener("change", () => { if (input.files.length) start(input.files); input.value = ""; });
  const drop = h("section", { class: "os-dropzone", attrs: { "aria-labelledby": "drop-h", "data-testid": "home-drop" } },
    h("span", { class: "os-dropzone__icon" }, icon("file-up", { size: 24 })),
    h("div", { class: "os-dropzone__text" },
      h("h2", { id: "drop-h", class: "os-dropzone__title", text: t("home.drop") }),
      h("p", { class: "os-muted", text: t("home.drop-text") })),
    button(t("home.choose-files"), { icon: "upload", onClick: () => input.click() }),
    input);
  for (const ev of ["dragenter", "dragover"]) drop.addEventListener(ev, (e) => { if (e.dataTransfer.types.includes("Files")) { e.preventDefault(); drop.classList.add("is-dropping"); } });
  drop.addEventListener("dragleave", (e) => { if (!drop.contains(e.relatedTarget)) drop.classList.remove("is-dropping"); });
  drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("is-dropping"); if (e.dataTransfer.files?.length) start(e.dataTransfer.files); });

  const recent = h("div", { class: "os-list", attrs: { "aria-busy": "true" } }, skeletonRows(4));
  const recentCard = h("section", { class: "os-card os-card--flush", attrs: { "aria-labelledby": "recent-h" } },
    h("div", { class: "os-card__head" },
      h("h2", { id: "recent-h", class: "os-card__title", text: t("home.recent") }),
      h("a", { class: "os-link", href: "#/agreements" }, h("span", { text: t("home.all-agreements") }), icon("arrow-right", { size: 16 }))),
    recent);

  // Recent templates (G-03): the old Start card repeated the top bar's Start menu.
  const tplList = h("div", { class: "os-list", attrs: { "aria-busy": "true" } }, skeletonRows(3));
  const tplCard = h("section", { class: "os-card os-card--flush", attrs: { "aria-labelledby": "tpl-h", "data-testid": "home-templates" } },
    h("div", { class: "os-card__head" },
      h("h2", { id: "tpl-h", class: "os-card__title", text: t("home.templates") }),
      h("a", { class: "os-link", href: "#/templates" }, h("span", { text: t("home.all-templates") }), icon("arrow-right", { size: 16 }))),
    tplList);

  view.append(head, counters, drop, h("div", { class: "os-home__grid" }, recentCard, tplCard));

  async function count(statuses) {
    const parts = await Promise.all(statuses.map((s) => ctx.api.countEnvelopes(s)));
    return { n: parts.reduce((s, p) => s + p.n, 0), more: parts.some((p) => p.more) };
  }
  /// Waiting envelopes expiring within 7 days, from each list item's `expires_at`.
  async function expiring() {
    const pages = await Promise.all(["sent", "delivered"].map((s) => ctx.api.listEnvelopes({ status: s, limit: 200 })));
    return { n: pages.flatMap((p) => p.items || []).filter((r) => expiringSoon(r.expires_at)).length, more: pages.some((p) => p.next_cursor) };
  }

  async function load() {
    try {
      const [action, waiting, soon, drafts, completed, page] = await Promise.all([
        count(["declined", "expired"]), count(["sent", "delivered"]), expiring(), count(["draft"]), count(["completed"]), ctx.api.listEnvelopes({ limit: 6, sort: "updated_at" }),
      ]);
      for (const [k, v] of [["action", action], ["waiting", waiting], ["expiring", soon], ["drafts", drafts], ["completed", completed]]) cells.get(k).replaceChildren(countLabel(v));
      counters.removeAttribute("aria-busy");
      const items = page.items || [];
      const envs = await Promise.all(items.map((r) => ctx.api.getEnvelope(r.id).then((x) => x.envelope).catch(() => null)));
      renderRecent(items, envs);
    } catch (err) {
      counters.removeAttribute("aria-busy");
      recent.removeAttribute("aria-busy");
      if (ctx.failed(err)) return;
      for (const n of cells.values()) n.replaceChildren("—");
      errorState(recent, err, () => { recent.setAttribute("aria-busy", "true"); recent.replaceChildren(skeletonRows(4)); load(); });
    }
  }

  async function loadTemplates() {
    try {
      const items = ((await ctx.api.templates.list()).items || []).slice(0, 5);
      tplList.removeAttribute("aria-busy");
      if (!items.length) {
        tplList.replaceChildren(h("div", { class: "os-home__none" },
          h("p", { class: "os-muted", text: t("home.no-templates") }),
          h("a", { class: "os-link", href: "#/templates/new" }, icon("plus", { size: 16 }), h("span", { text: t("templates.new") }))));
        return;
      }
      tplList.replaceChildren(h("ul", { class: "os-recent" }, items.map((tp) => {
        const name = tp.name || t("templates.untitled");
        return h("li", { class: "os-recent__item" },
          h("span", { class: "os-recent__icon os-recent__icon--tpl" }, icon("layout-template", { size: 20 })),
          h("span", { class: "os-recent__main" },
            h("a", { class: "os-row-link", href: `#/templates/${encodeURIComponent(tp.id)}`, text: name }),
            h("span", { class: "os-muted os-small", text: tp.email_subject || t("home.template-no-subject") })),
          h("a", { class: "os-btn os-btn--secondary os-btn--sm", href: `#/templates/${encodeURIComponent(tp.id)}`, attrs: { "aria-label": t("templates.use-named", { name }) } }, h("span", { text: t("templates.use") })));
      })));
    } catch (err) {
      tplList.removeAttribute("aria-busy");
      if (ctx.failed(err)) return;
      errorState(tplList, err, loadTemplates);
    }
  }

  /// The recent envelopes (UX-07): subject, who it went to, where it stands and when it
  /// last changed; the whole row opens it (a draft in the editor, A-02).
  function renderRecent(items, envs = []) {
    clear(recent);
    recent.removeAttribute("aria-busy");
    if (!items.length) {
      recent.append(emptyState({ illus: "documents", title: t("empty.home.title"), text: t("empty.home.text"), action: button(t("nav.new"), { icon: "plus", variant: "primary", onClick: () => ctx.navigate("#/prepare") }), testId: "empty-home" }));
      return;
    }
    const ul = h("ul", { class: "os-recent" });
    items.forEach((r, i) => {
      const e = envs[i];
      const href = rowHref(r);
      const recs = [...(e?.recipients || [])].sort((a, b) => a.routing_order - b.routing_order).map((x) => x.name || x.email);
      const when = r.updated_at || e?.ended_at || e?.sent_at || r.created_at;
      const line = e ? statusLine(e) : "";
      const li = h("li", { class: "os-recent__item os-recent__item--env", attrs: { "data-testid": "recent-row" } },
        h("span", { class: "os-recent__icon" }, icon("file-text", { size: 20 })),
        h("span", { class: "os-recent__main" },
          h("a", { class: "os-row-link", href, text: r.subject || t("envelope.untitled") }),
          h("span", { class: "os-muted os-small os-recent__to", text: recs.length ? t("agreements.to", { names: recs.join(", ") }) : t("agreements.no-recipients") })),
        h("span", { class: "os-recent__state" },
          statusBadge(r.status),
          line ? h("span", { class: "os-muted os-small os-recent__line", text: line }) : null),
        h("time", { class: "os-muted os-small os-recent__when", attrs: { datetime: when, title: fmtDate(when) }, text: shortDate(when) }));
      li.addEventListener("click", (ev) => { if (ev.target.closest("a, button")) return; ctx.navigate(href); });
      ul.append(li);
    });
    recent.append(ul);
  }

  load();
  loadTemplates();
}
