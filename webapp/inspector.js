// The Agreements inspector (WEB-17, WEB-18; canvas Main.dc.html, the docked panel):
// the selected agreement's status, name and sub line, its primary action with Open and
// More, and underline tabs — Recipients, Activity, Insights (only when ml.js says
// document intelligence is available) and Evidence. Docked beside the list from 75rem;
// a slide-over below that and a full page on phones (dashboard.js opens and closes it).
//
// It renders from what the screen hands it (`load(id)` → `{env, audit}`, cached there)
// and from ml.js's suggestion store; it owns no list state.

import { h, clear } from "./dom.js";
import { t } from "./i18n.js";
import { button, busy, tabs, menuButton, iconButton, skeletonLines } from "./ui/index.js";
import { onSuggestions } from "./ml.js";
import {
  statusPillFor, subText, recipientsSection, activitySection, insightsSection, evidenceSection, insightsAvailable, openDetails,
} from "./agreementparts.js";

const TABS = ["people", "activity", "insights", "evidence"];

/// Make the inspector. `load(id)` resolves `{env, audit}`; `actionsFor(row, env)` gives
/// `{primary: {label, run, testId}|null, open(), more: [[{label, icon, run, danger}]]}`;
/// `onClose()` is the close button (shown only when it floats). Returns
/// `{el, show(row, info), refresh(), destroy()}`.
export function createInspector(ctx, { load, actionsFor, onClose }) {
  const pill = h("div", { class: "os-insp__pill" });
  const title = h("h2", { id: "insp-title", class: "os-insp__title" });
  const sub = h("p", { class: "os-insp__sub" });
  const actions = h("div", { class: "os-insp__actions" });
  const close = iconButton(t("inspector.close"), "x", { size: "sm", onClick: () => onClose?.() });
  close.classList.add("os-insp__close");
  const head = h("div", { class: "os-insp__head" }, close, pill, title, sub, actions);
  const body = h("div", { class: "os-insp__body" });
  const el = h("aside", { class: "os-insp os-slide", attrs: { "aria-label": t("inspector.label"), "data-testid": "inspector" } }, head, body);
  let tab = "people";
  let row = null;
  let info = {};
  let seq = 0;
  let mlOn = false;
  let sections = []; // destroy() of the live sections
  let badge = null;

  insightsAvailable().then((v) => { mlOn = v; if (row) renderBody(); }, () => { mlOn = false; });
  const offSugg = onSuggestions(({ envId }) => { if (row && envId === row.id) syncBadge(); });

  function syncBadge() {
    if (!badge) return;
    const n = row ? openDetails(row.id) : 0;
    badge.hidden = !n;
    badge.textContent = n ? String(n) : "";
  }

  function renderHead() {
    const env = info.env;
    pill.replaceChildren(statusPillFor(row, env, info.mine));
    title.textContent = row.subject || t("envelope.untitled");
    sub.textContent = subText(row, env, info.mine, { from: info.from });
    clear(actions);
    const a = actionsFor(row, env);
    if (a.primary) {
      actions.append(button(a.primary.label, { variant: "strong", size: "sm", attrs: { "data-testid": "inspector-primary" }, onClick: (ev) => busy(ev.currentTarget, a.primary.run) }));
    }
    actions.append(button(t("inspector.open"), { variant: "subtle", size: "sm", attrs: { "data-testid": "inspector-open" }, onClick: a.open }));
    if (a.more.length) {
      actions.append(menuButton({
        label: t("agreements.actions-for", { subject: row.subject || t("envelope.untitled") }),
        buttonOpts: { icon: "ellipsis", variant: "subtle", size: "sm", iconOnly: true, attrs: { "data-testid": "inspector-more" } },
        items: () => a.more.flatMap((g, i) => [i ? "separator" : null, ...g]).filter(Boolean),
      }));
    }
  }

  function renderBody() {
    for (const s of sections) s();
    sections = [];
    clear(body);
    const list = TABS.filter((id) => id !== "insights" || mlOn);
    if (!list.includes(tab)) tab = "people";
    const set = tabs({
      label: t("inspector.tabs"),
      tabs: list.map((id) => ({ id, label: t(`inspector.tab.${id}`) })),
      current: tab,
      onChange: (id) => { tab = id; },
      render: (id, panel) => fill(id, panel),
    });
    set.classList.add("os-insp__tabset");
    const insightsTab = set.querySelector('[data-tab="insights"]');
    badge = null;
    if (insightsTab) {
      badge = h("span", { class: "os-tab__badge", attrs: { "aria-hidden": "true" }, hidden: true });
      insightsTab.append(badge);
      syncBadge();
    }
    body.append(set);
  }

  function fill(id, panel) {
    for (const s of sections) s();
    sections = [];
    const { env, audit } = info;
    if (!env) { panel.append(h("div", { class: "os-insp__loading", attrs: { "aria-busy": "true", "aria-label": t("inspector.loading") } }, skeletonLines(4))); return; }
    if (id === "people") panel.append(recipientsSection(env, audit, { mineId: info.mineId }));
    else if (id === "activity") panel.append(audit ? activitySection(ctx, env, audit) : skeletonLines(3));
    else if (id === "insights") { const s = insightsSection(ctx, env); sections.push(s.destroy); panel.append(s.el); }
    else panel.append(audit ? evidenceSection(ctx, env, audit) : skeletonLines(3));
  }

  /// Show `r` (a list row). `extra`: `{mine, mineId, from}`. Loads its details and audit.
  async function show(r, extra = {}) {
    const same = row?.id === r.id;
    row = r;
    const mySeq = ++seq;
    info = { ...extra, env: same ? info.env : null, audit: same ? info.audit : null };
    el.dataset.id = r.id;
    renderHead();
    renderBody();
    try {
      const got = await load(r.id);
      if (mySeq !== seq) return;
      info = { ...info, ...got };
      renderHead();
      renderBody();
    } catch (err) {
      if (mySeq === seq) ctx.failed(err);
    }
  }

  function showNone() {
    row = null;
    seq++;
    pill.replaceChildren();
    title.textContent = "";
    sub.textContent = "";
    clear(actions);
    clear(body);
    body.append(h("p", { class: "os-muted os-insp__none", text: t("inspector.none") }));
  }

  return {
    el,
    title,
    show,
    showNone,
    /// Draw again from fresh data for the shown row (after an action).
    refresh: () => (row ? show(row, info) : null),
    current: () => row,
    destroy() { offSugg(); for (const s of sections) s(); sections = []; },
  };
}
