// Home (WEB-02, UX-07; restyled in WEB-17 on the approved canvas, Main.dc.html): a
// greeting, the overview counts (each opens its view), "Needs your attention" (waiting
// for this user's signature, expiring within 7 days, ended without everyone signing),
// quick actions (upload PDFs to send, start from a template, verify a sealed PDF), recent
// activity and recent templates. Skeletons while loading; illustrated empty states.
//
// Data: every agreement (agreementparts.fetchAgreements) and the Inbox where the server
// has one; counts are managemodel.viewCounts over them, the same numbers the sidebar's
// Views and the Agreements tabs show. Recipients for the recent rows come from each
// one's `GET …/{id}`.

import { h, clear } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { button, emptyState, errorState, toast, skeletonLines } from "./ui/index.js";
import { illustration } from "./illustrations.js";
import { handFiles } from "./handoff.js";
import { shortDate } from "./envactions.js";
import { rowHref } from "./dashboard.js";
import { viewCounts, groupRows, toneOf } from "./managemodel.js";
import { docThumb, statusPillFor, subText, whenEl, renderNavViews, fetchAgreements, fetchInbox } from "./agreementparts.js";
import { registerMeaningSearch } from "./meaning.js";

export const CARDS = [
  { key: "action", view: "action" },
  { key: "waiting", view: "waiting" },
  { key: "expiring", view: "expiring" },
  { key: "drafts", view: "drafts" },
  { key: "completed", view: "completed" },
];

/// The greeting for the hour: morning before 12, afternoon before 18, else evening.
export function greetingKey(hour) {
  return hour < 12 ? "home.greeting.morning" : hour < 18 ? "home.greeting.afternoon" : "home.greeting.evening";
}

/// What needs this user's attention, at most `max`, most pressing first: waiting for
/// their signature, then expiring within 7 days, then ended without everyone signing
/// (declined or expired). Each item is `{row, why}`. Pure.
export function attentionItems(rows, mine, { now = Date.now(), max = 5 } = {}) {
  const out = [];
  const seen = new Set();
  const add = (why, list) => { for (const r of list) if (!seen.has(r.id)) { seen.add(r.id); out.push({ row: r, why }); } };
  const pick = (view) => groupRows(rows, view, mine, { now }).flatMap((g) => g.items);
  add("you", pick("me"));
  add("expiring", pick("expiring").sort((a, b) => String(a.expires_at).localeCompare(String(b.expires_at))));
  add("ended", pick("action"));
  return out.slice(0, max);
}

export function mount(view, ctx) {
  const hour = new Date().getHours();
  const hello = hour < 12 ? "home.hello.morning" : hour < 18 ? "home.hello.afternoon" : "home.hello.evening";
  const head = h("div", { class: "os-home2__head" },
    h("h1", { class: "os-home2__title", text: t("home.title") }),
    h("p", { class: "os-home2__hello" }, h("span", { class: "os-home2__greet", text: t(hello) }), h("span", { class: "os-muted", text: t("home.lede") })));

  // Overview: one count per view, each a link to it.
  const counters = h("ul", { class: "os-home2__stats", attrs: { "aria-label": t("home.overview"), "aria-busy": "true" } });
  const cells = new Map();
  for (const c of CARDS) {
    const n = h("span", { class: "os-counter__n" }, h("span", { class: "os-skel os-skel--short", attrs: { "aria-hidden": "true" } }));
    counters.append(h("li", {}, h("a", { class: `os-stat os-stat--${c.key}`, href: `#/agreements?folder=${c.view}`, attrs: { "data-testid": `counter-${c.key}` } },
      h("span", { class: `os-dot os-dot--${{ action: "danger", waiting: "wait", expiring: "draft", drafts: "draft", completed: "done" }[c.key]}`, attrs: { "aria-hidden": "true" } }),
      h("span", { class: "os-counter__label", text: t(`home.counter.${c.key}`) }), n)));
    cells.set(c.key, n);
  }

  // Needs your attention.
  const attention = h("div", { class: "os-home2__list", attrs: { "aria-busy": "true" } }, skeletonList(3));
  const attentionCard = card("attn-h", t("home.attention"), attention, h("a", { class: "os-link", href: "#/agreements" }, h("span", { text: t("home.all-agreements") }), icon("arrow-right", { size: 16 })), "home-attention");

  // Quick actions: upload (also a drop target), a template, Verify.
  const input = h("input", { type: "file", accept: "application/pdf,.pdf", multiple: true, class: "os-sr-only", attrs: { "aria-hidden": "true", tabindex: "-1", "data-testid": "home-input" } });
  const start = (files) => {
    const pdfs = [...files].filter((f) => f.type === "application/pdf" || /\.pdf$/i.test(f.name));
    if (!pdfs.length) { toast(t("home.drop-not-pdf"), "error"); return; }
    handFiles(pdfs);
    ctx.navigate("#/prepare");
  };
  input.addEventListener("change", () => { if (input.files.length) start(input.files); input.value = ""; });
  const quick = h("ul", { class: "os-quick" },
    quickItem("file-up", t("home.quick.upload"), t("home.quick.upload-text"), { onClick: () => input.click(), testId: "home-drop" }),
    quickItem("layout-template", t("home.quick.template"), t("home.quick.template-text"), { href: "#/templates" }),
    quickItem("shield-check", t("home.quick.verify"), t("home.quick.verify-text"), { href: "verify.html" }));
  const quickCard = card("quick-h", t("home.quick"), h("div", {}, quick, input), null, "home-quick");
  for (const ev of ["dragenter", "dragover"]) quickCard.addEventListener(ev, (e) => { if (e.dataTransfer.types.includes("Files")) { e.preventDefault(); quickCard.classList.add("is-dropping"); } });
  quickCard.addEventListener("dragleave", (e) => { if (!quickCard.contains(e.relatedTarget)) quickCard.classList.remove("is-dropping"); });
  quickCard.addEventListener("drop", (e) => { e.preventDefault(); quickCard.classList.remove("is-dropping"); if (e.dataTransfer.files?.length) start(e.dataTransfer.files); });

  // Recent activity: the agreements that changed last.
  const recent = h("div", { class: "os-home2__list", attrs: { "aria-busy": "true" } }, skeletonList(4));
  const recentCard = card("recent-h", t("home.recent-activity"), recent, h("a", { class: "os-link", href: "#/agreements" }, h("span", { text: t("home.all-agreements") }), icon("arrow-right", { size: 16 })));

  // Recent templates (G-03).
  const tplList = h("div", { class: "os-home2__list", attrs: { "aria-busy": "true" } }, skeletonList(3));
  const tplCard = card("tpl-h", t("home.templates"), tplList, h("a", { class: "os-link", href: "#/templates" }, h("span", { text: t("home.all-templates") }), icon("arrow-right", { size: 16 })), "home-templates");

  view.append(h("div", { class: "os-home2" }, head, counters,
    h("div", { class: "os-home2__grid" }, h("div", { class: "os-home2__col" }, attentionCard, recentCard), h("div", { class: "os-home2__col" }, quickCard, tplCard))));
  const offMeaning = registerMeaningSearch(ctx);

  async function load() {
    try {
      const [list, inbox] = await Promise.all([fetchAgreements(ctx), fetchInbox(ctx)]);
      const rows = list.items.concat(inbox.items.filter((x) => !list.items.some((r) => r.id === x.id)));
      const counts = viewCounts(rows, inbox.ids);
      for (const c of CARDS) cells.get(c.key).replaceChildren(String(counts[c.view]) + (list.capped && c.key !== "expiring" ? "+" : ""));
      counters.removeAttribute("aria-busy");
      renderNavViews(ctx, { counts });
      renderAttention(rows, inbox.ids);
      const latest = [...list.items].sort((a, b) => String(b.updated_at || b.created_at).localeCompare(String(a.updated_at || a.created_at))).slice(0, 6);
      const envs = await Promise.all(latest.map((r) => ctx.api.getEnvelope(r.id).then((x) => x.envelope).catch(() => null)));
      renderRecent(latest, envs, inbox.ids);
    } catch (err) {
      counters.removeAttribute("aria-busy");
      for (const el of [attention, recent]) el.removeAttribute("aria-busy");
      if (ctx.failed(err)) return;
      for (const n of cells.values()) n.replaceChildren("—");
      clear(attention);
      errorState(recent, err, () => { recent.setAttribute("aria-busy", "true"); recent.replaceChildren(skeletonList(4)); load(); });
    }
  }

  function renderAttention(rows, mine) {
    attention.removeAttribute("aria-busy");
    const items = attentionItems(rows, mine);
    if (!items.length) {
      attention.replaceChildren(h("div", { class: "os-home2__none", attrs: { "data-testid": "home-attention-none" } },
        illustration("done"), h("div", {}, h("p", { class: "os-home2__none-title", text: t("home.attention-none.title") }), h("p", { class: "os-muted", text: t("home.attention-none.text") }))));
      return;
    }
    attention.replaceChildren(h("ul", { class: "os-hrows" }, items.map(({ row, why }) => {
      const line = why === "you" ? t("home.why.you") : why === "expiring" ? t("home.why.expiring", { date: shortDate(row.expires_at) }) : t("home.why.ended");
      return hrow(row, null, mine, line, { testId: "attention-row" });
    })));
  }

  /// The recent agreements: subject, who it went to, where it stands and when it last
  /// changed; the whole row opens it (a draft in the editor, A-02).
  function renderRecent(items, envs, mine) {
    clear(recent);
    recent.removeAttribute("aria-busy");
    if (!items.length) {
      recent.append(emptyState({ illus: "documents", title: t("empty.home.title"), text: t("empty.home.text"), action: button(t("agreements.new"), { icon: "plus", variant: "primary", onClick: () => ctx.navigate("#/prepare") }), testId: "empty-home" }));
      return;
    }
    recent.append(h("ul", { class: "os-hrows" }, items.map((r, i) => {
      const e = envs[i];
      const recs = [...(e?.recipients || [])].sort((a, b) => a.routing_order - b.routing_order).map((x) => x.name || x.email);
      const to = recs.length ? t("agreements.to", { names: recs.join(", ") }) : t("agreements.no-recipients");
      return hrow(r, e, mine, to, { testId: "recent-row", recent: true });
    })));
  }

  /// One agreement as a row: thumbnail, name and a line, status pill, time. The name is
  /// the link; the whole row is clickable too.
  function hrow(r, e, mine, line, { testId, recent: isRecent = false }) {
    const href = rowHref(r);
    const li = h("li", { class: `os-hrow${isRecent ? " os-recent__item" : ""}`, attrs: { "data-testid": testId } },
      docThumb(toneOf(r, mine)),
      h("span", { class: "os-hrow__main" },
        h("a", { class: "os-hrow__name", href, text: r.subject || t("envelope.untitled") }),
        h("span", { class: "os-hrow__line", text: line || subText(r, e, mine) })),
      statusPillFor(r, e, mine),
      whenEl(r.updated_at || r.created_at));
    li.addEventListener("click", (ev) => { if (ev.target.closest("a, button")) return; ctx.navigate(href); });
    return li;
  }

  async function loadTemplates() {
    try {
      const items = ((await ctx.api.templates.list()).items || []).slice(0, 4);
      tplList.removeAttribute("aria-busy");
      if (!items.length) {
        tplList.replaceChildren(h("div", { class: "os-home__none" },
          h("p", { class: "os-muted", text: t("home.no-templates") }),
          h("a", { class: "os-link", href: "#/templates/new" }, icon("plus", { size: 16 }), h("span", { text: t("templates.new") }))));
        return;
      }
      tplList.replaceChildren(h("ul", { class: "os-hrows" }, items.map((tp) => {
        const name = tp.name || t("templates.untitled");
        return h("li", { class: "os-hrow os-hrow--tpl" },
          h("span", { class: "os-hrow__icon", attrs: { "aria-hidden": "true" } }, icon("layout-template", { size: 16 })),
          h("span", { class: "os-hrow__main" },
            h("span", { class: "os-hrow__name", text: name }),
            h("span", { class: "os-hrow__line", text: tp.email_subject || t("home.template-no-subject") })),
          h("a", { class: "os-btn os-btn--subtle os-btn--sm", href: `#/templates/${encodeURIComponent(tp.id)}`, attrs: { "aria-label": t("templates.use-named", { name }) } }, h("span", { text: t("templates.use") })));
      })));
    } catch (err) {
      tplList.removeAttribute("aria-busy");
      if (ctx.failed(err)) return;
      errorState(tplList, err, loadTemplates);
    }
  }

  load();
  loadTemplates();
  return () => offMeaning();
}

/// A card with a heading, an optional link on the right, and a body.
function card(hid, title, body, link = null, testId = null) {
  return h("section", { class: "os-card os-card--flush os-home2__card", attrs: { "aria-labelledby": hid, "data-testid": testId } },
    h("div", { class: "os-card__head" }, h("h2", { id: hid, class: "os-card__title", text: title }), link), body);
}

/// A quick action: an icon, a title and a line; a link, or a button for `onClick`.
function quickItem(ic, title, text, { href = null, onClick = null, testId = null }) {
  const inner = [h("span", { class: "os-quick__icon", attrs: { "aria-hidden": "true" } }, icon(ic, { size: 16 })),
    h("span", { class: "os-quick__text" }, h("span", { class: "os-quick__title", text: title }), h("span", { class: "os-quick__line", text }))];
  const el = href
    ? h("a", { class: "os-quick__item", href, attrs: { "data-testid": testId } }, ...inner)
    : h("button", { type: "button", class: "os-quick__item", attrs: { "data-testid": testId }, on: { click: onClick } }, ...inner);
  return h("li", {}, el);
}

/// Skeleton rows shaped like the home rows: thumbnail, two lines, a pill.
function skeletonList(n) {
  const ul = h("div", { class: "os-hrows os-hrows--skel", attrs: { "aria-hidden": "true" } });
  for (let i = 0; i < n; i++) ul.append(h("div", { class: "os-hrow" }, h("span", { class: "os-skel os-skel--doc" }), skeletonLines(2), h("span", { class: "os-skel os-skel--pill" })));
  return ul;
}

