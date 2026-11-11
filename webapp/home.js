// Home (WEB-02; docs/47 §Screens "Home", after DocuSign's): a greeting, four stat
// cards, a drop zone that starts an envelope with the dropped PDFs, recent activity and
// recent templates. One way in to a new envelope (WEB-06 G-03): the top bar's Start;
// the drop zone is the same action for files already in hand, so its button is quiet.
//
// Counts come from `GET /api/v1/envelopes?status=` (the API has no count): one page of
// up to 200 per status, shown as "200+" past that. "Declined or expired" (WEB-06 A-04;
// it was "Action required", which DocuSign uses for "waiting for you") is the sender's
// own to-do: envelopes that ended without completing and need a new copy or a word with
// the recipient. "Expiring soon" reads `expires_at` from the waiting envelopes (at most
// 50) and counts those ending within 7 days. Envelopes waiting for *this user's*
// signature need a recipient filter the API lacks (row in the WEB-02 report).

import { h, clear, fmtDate } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { button, emptyState, skeletonRows, statusBadge, errorState, toast } from "./ui/index.js";
import { countLabel } from "./templatemodel.js";
import { handFiles } from "./handoff.js";

const SOON_DAYS = 7;
const CARDS = [
  { key: "action", icon: "circle-alert", href: "#/agreements?folder=action" },
  { key: "waiting", icon: "hourglass", href: "#/agreements?folder=waiting" },
  { key: "expiring", icon: "clock", href: "#/agreements?folder=waiting" },
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
  async function expiring() {
    const pages = await Promise.all(["sent", "delivered"].map((s) => ctx.api.listEnvelopes({ status: s, limit: 25 })));
    const ids = pages.flatMap((p) => p.items || []).map((r) => r.id);
    const soon = Date.now() + SOON_DAYS * 86_400_000;
    const envs = await Promise.all(ids.map((id) => ctx.api.getEnvelope(id).then((x) => x.envelope).catch(() => null)));
    return { n: envs.filter((e) => e?.expires_at && Date.parse(e.expires_at) <= soon).length, more: false };
  }

  async function load() {
    try {
      const [action, waiting, soon, completed, page] = await Promise.all([
        count(["declined", "expired"]), count(["sent", "delivered"]), expiring(), count(["completed"]), ctx.api.listEnvelopes({ limit: 6 }),
      ]);
      for (const [k, v] of [["action", action], ["waiting", waiting], ["expiring", soon], ["completed", completed]]) cells.get(k).replaceChildren(countLabel(v));
      counters.removeAttribute("aria-busy");
      renderRecent(page.items || []);
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

  function renderRecent(items) {
    clear(recent);
    recent.removeAttribute("aria-busy");
    if (!items.length) {
      recent.append(emptyState({ illus: "documents", title: t("empty.home.title"), text: t("empty.home.text"), action: button(t("nav.new"), { icon: "plus", variant: "primary", onClick: () => ctx.navigate("#/prepare") }), testId: "empty-home" }));
      return;
    }
    const ul = h("ul", { class: "os-recent" });
    for (const r of items) {
      // A draft opens in the editor (A-02); anything sent opens its details.
      const href = r.status === "draft" ? `#/prepare/${encodeURIComponent(r.id)}` : `#/envelopes/${encodeURIComponent(r.id)}`;
      ul.append(h("li", { class: "os-recent__item" },
        h("span", { class: "os-recent__icon" }, icon("file-text", { size: 20 })),
        h("span", { class: "os-recent__main" },
          h("a", { class: "os-row-link", href, text: r.subject || t("envelope.untitled") }),
          h("span", { class: "os-muted os-small" }, h("span", { text: `${t("dates.created")} ` }), h("time", { attrs: { datetime: r.created_at }, text: fmtDate(r.created_at) }))),
        statusBadge(r.status)));
    }
    recent.append(ul);
  }

  load();
  loadTemplates();
}
