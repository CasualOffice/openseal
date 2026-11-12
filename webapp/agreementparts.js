// The parts of an agreement that the Agreements inspector, the envelope page and Home
// share (WEB-17, WEB-18; canvas Main.dc.html): the status pill and the lines under a
// title, the page thumbnail, signing progress, the relative time, and the inspector's
// sections — Recipients (the signing order), Activity (from the audit trail), Insights
// (model suggestions, only where ml.js says they are available) and Evidence (what the
// API really returns: the audit trail's links and head, a document fingerprint when the
// server recorded one). Also the sidebar's Views and the list loader. Each part renders
// from data it is given; the screens own loading and state.

import { h, fmtDate, initials } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { button, busy, statusPill, avatarStack, mlHeading, suggestion, toast, toastError } from "./ui/index.js";
import { mlStatus, loadSuggestions, suggestions as storedSuggestions, acceptSuggestion, dismissSuggestion, onSuggestions, openOf, featureOn } from "./ml.js";
import {
  VIEWS, toneOf, groupOf, signingProgress, relativeWhen, recipientBadge, piiSummary, auditLinks, documentFingerprint, groupHex, agreementsHash,
} from "./managemodel.js";
import { statusLine, historyVerb, actorOf, copyText, shortDate, downloadCertificate, hasCertificate, historyPanel, ACTIVE } from "./envactions.js";

const SIGNING = new Set(["signer", "in_person_signer", "approver"]);
/// Events a recipient makes on opening: the first of them is when they opened it.
/// (Audit event types are data, not message keys: built from their suffixes.)
const rev = (x) => `recipient.${x}`;
const OPENING = ["delivered", "auth_passed", "consented", "viewed_document"].map(rev);

// ---- Small parts ----------------------------------------------------------------------

/// A page thumbnail with a signature line in the status tone (canvas row).
export function docThumb(tone) {
  return h("span", { class: `os-thumb os-thumb--${tone}`, attrs: { "aria-hidden": "true" } },
    h("span", { class: "os-thumb__l1" }), h("span", { class: "os-thumb__l2" }), h("span", { class: "os-thumb__l3" }), h("span", { class: "os-thumb__sig" }));
}

/// Signing progress as segments and "n/m" (a draft shows "—"). Named for screen readers.
export function progressSegments(progress, status) {
  const wrap = h("span", { class: "os-prog" });
  if (!progress || status === "draft" || !progress.total) {
    wrap.append(h("span", { class: "os-prog__n", text: "—" }));
    return wrap;
  }
  const segs = h("span", { class: "os-prog__segs", attrs: { "aria-hidden": "true" } });
  for (let i = 0; i < progress.total; i++) segs.append(h("span", { class: `os-prog__seg${i < progress.signed ? " is-done" : ""}` }));
  wrap.append(segs, h("span", { class: "os-prog__n", attrs: { "aria-hidden": "true" }, text: `${progress.signed}/${progress.total}` }),
    h("span", { class: "os-sr-only", text: t("agreements.progress", progress) }));
  return wrap;
}

const timeOf = (d) => d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
const dayOf = (d, year = false) => d.toLocaleDateString(undefined, year ? { day: "numeric", month: "short", year: "numeric" } : { day: "numeric", month: "short" });

/// The list's relative time ("2h ago", "09:41", "Yesterday", "Nov 10").
export function whenText(iso, now = Date.now()) {
  const w = relativeWhen(iso, now);
  const d = new Date(iso);
  switch (w.kind) {
    case "now": return t("agreements.when.now");
    case "min": return t("agreements.when.min", { n: Math.max(1, w.n) });
    case "hours": return t("agreements.when.hours", { n: w.n });
    case "time": return timeOf(d);
    case "yesterday": return t("agreements.when.yesterday");
    case "date": return dayOf(d);
    case "year": return dayOf(d, true);
    default: return "";
  }
}

/// A `<time>` with the relative text and the full date as its tooltip.
export function whenEl(iso, cls = "os-when") {
  if (!iso) return h("span", { class: cls, text: "—" });
  return h("time", { class: cls, attrs: { datetime: iso, title: fmtDate(iso) }, text: whenText(iso) });
}

/// The status as words for a pill: "Needs your signature", "Waiting for Sam Patel",
/// "Declined by Morgan Diaz", else the status's name.
export function statusText(row, env, mine) {
  if (mine?.has(row.id)) return t("agreements.status.you");
  const line = env ? statusLine(env) : "";
  if (line && (row.status === "sent" || row.status === "delivered" || row.status === "declined")) return line;
  return t(`status.${row.status}`);
}

/// A status pill in its group's tone (class `os-row__status`, for tests and styles).
export function statusPillFor(row, env, mine) {
  const p = statusPill(statusText(row, env, mine), { tone: toneOf(row, mine) });
  p.classList.add("os-row__status");
  p.dataset.status = row.status;
  return p;
}

/// The line under a title: who sent it or when, and how many pages.
export function subText(row, env, mine, { from = null } = {}) {
  const parts = [];
  const date = (iso) => shortDate(iso);
  if (mine?.has(row.id) && from) parts.push(t("agreements.sub.from", { name: from }));
  else if (row.status === "draft") parts.push(t("agreements.sub.draft", { date: date(row.updated_at || row.created_at) }));
  else if (row.status === "completed") parts.push(t("agreements.sub.completed", { date: date(row.completed_at || env?.ended_at || row.updated_at) }));
  else if (ACTIVE.has(row.status)) parts.push(t("agreements.sub.sent", { date: date(row.sent_at || env?.sent_at || row.created_at) }));
  else if (env) parts.push(statusLine(env));
  else parts.push(t(`status.${row.status}`));
  const pages = (env?.documents || []).reduce((n, d) => n + (Number.isInteger(d.pages) ? d.pages : 0), 0);
  if (pages) parts.push(pages === 1 ? t("agreements.sub.page") : t("agreements.sub.pages", { n: pages }));
  return parts.filter(Boolean).join(" · ");
}

/// The avatars of an envelope's recipients, in signing order.
export function recipientAvatars(env) {
  const names = [...(env?.recipients || [])].sort((a, b) => a.routing_order - b.routing_order).map((r) => r.name || r.email);
  return avatarStack(names, { max: 3 });
}

// ---- Recipients ------------------------------------------------------------------------

const byOrder = (e) => [...(e?.recipients || [])].sort((a, b) => a.routing_order - b.routing_order);

/// The events of the audit trail that recipient `r` made or that name them.
function eventsOf(audit, r) {
  return (audit?.items || []).filter((a) => (a.event?.data?.recipient_id || (a.event?.actor?.kind === "recipient" ? a.event.actor.id : null)) === r.id);
}

/// One line on where a recipient stands, for the signing order (canvas Recipients).
function recipientDetail(r, env, audit, prev, mineId) {
  const at = (type) => eventsOf(audit, r).find((x) => x.type === type)?.at;
  const opened = OPENING.map(at).filter(Boolean).sort()[0] || null;
  const cc = !SIGNING.has(r.type) && r.type !== "viewer";
  if (cc) return r.status === "completed" ? t("recipient.cc-done") : t("recipient.cc-later");
  if (r.status === "completed") return t("recipient.signed-at", { date: shortDate(r.completed_at || at(rev("completed"))) });
  if (r.status === "declined") return t("recipient.declined-at", { date: shortDate(r.completed_at || at(rev("declined")) || env.ended_at) });
  if (r.id === mineId) return t("recipient.turn-you");
  if (r.status === "delivered" || opened) return t("recipient.opened-at", { date: shortDate(opened || env.sent_at) });
  if (r.status === "sent") return t("recipient.sent-at", { date: shortDate(at("invitation.sent") || env.sent_at) });
  if (env.status === "draft") return t("recipient.not-sent");
  return prev ? t("recipient.after", { name: prev.name || prev.email }) : t("recipient.not-sent");
}

/// The signing order (canvas inspector Recipients): a numbered or ✓ badge, the name and
/// one line on where they stand. `detailed` (the envelope page) adds the email, the role,
/// the Sent / Opened / Signed steps with times, Resend for someone still to act, and the
/// demo signing link. Each row is `data-testid="recipient-row"`.
export function recipientsSection(env, audit, { mineId = null, detailed = false, onResend = null, mock = false } = {}) {
  const recs = byOrder(env);
  const list = h("ol", { class: `os-ordl${detailed ? " is-detailed" : ""}`, attrs: { "aria-label": t("envelope.recipients") } });
  if (!recs.length) return h("p", { class: "os-muted os-insp__none", text: t("inspector.no-recipients") });
  let prev = null;
  for (const r of recs) {
    const b = recipientBadge(r, { mineId });
    const name = r.id === mineId ? t("recipient.you") : r.name || r.email;
    const main = h("span", { class: "os-ord__main" },
      h("span", { class: "os-ord__name" }, h("strong", { text: name }),
        detailed ? h("span", { class: "os-muted", text: ` · ${r.email} · ${t(`rtype.${r.type}`)}` }) : null),
      h("span", { class: "os-ord__detail", text: recipientDetail(r, env, audit, prev, mineId) }));
    const li = h("li", { class: `os-ord is-${b.kind}`, attrs: { "data-testid": "recipient-row", "data-status": r.status } },
      h("span", { class: `os-ord__badge is-${b.kind}`, attrs: { "aria-hidden": "true" }, text: b.mark }),
      h("span", { class: "os-sr-only", text: t("recipient.order-n", { n: r.routing_order }) }), main);
    if (detailed) {
      main.append(stepsOf(r, env, audit));
      if (r.declined_reason) main.append(h("p", { class: "os-muted os-small", text: t("envelope.declined-reason", { reason: r.declined_reason }) }));
      const canResend = onResend && ACTIVE.has(env.status) && SIGNING.has(r.type) && (r.status === "sent" || r.status === "delivered");
      if (canResend) li.append(button(t("envelope.resend"), { icon: "rotate-cw", size: "sm", variant: "subtle", attrs: { "aria-label": t("envelope.resend-to", { name: r.name || r.email }) }, onClick: (ev) => busy(ev.currentTarget, () => onResend(r)) }));
      if (mock && r.mock_token && ACTIVE.has(env.status) && ["sent", "delivered"].includes(r.status)) {
        main.append(h("a", { class: "os-link os-small", href: `/s/${encodeURIComponent(r.mock_token)}?mock=1`, attrs: { "data-testid": "signing-link" } }, icon("external-link", { size: 14 }), h("span", { text: t("mock.signing-link") })));
      }
    }
    list.append(li);
    prev = r;
  }
  return list;
}

/// Sent, opened and signed with their times; a copy says when it goes (E-04).
function stepsOf(r, env, audit) {
  const events = eventsOf(audit, r);
  const at = (type) => events.find((x) => x.type === type)?.at;
  const opened = OPENING.map(at).filter(Boolean).sort()[0] || null;
  const sent = env.sent_at && r.status !== "created" ? (at("invitation.sent") || env.sent_at) : null;
  const steps = r.type === "cc"
    ? [[r.status === "completed" ? t("timeline.delivered") : t("timeline.cc-waiting"), r.status === "completed" ? (r.completed_at || env.ended_at) : null]]
    : [[t("timeline.sent"), sent], [t("timeline.opened"), opened],
      [r.status === "declined" ? t("timeline.declined") : t("timeline.completed"), r.completed_at || at(rev("completed")) || at(rev("declined"))]];
  return h("ul", { class: "os-steps" }, steps.map(([label, when]) =>
    h("li", { class: when ? "is-done" : "" }, icon(when ? "circle-check" : "clock", { size: 14 }), h("span", { text: label }),
      when ? h("time", { class: "os-muted", attrs: { datetime: when, title: fmtDate(when) }, text: shortDate(when) }) : null)));
}

// ---- Activity --------------------------------------------------------------------------

/// The time column of an activity line: the hour today, else the day.
function clock(iso, now = Date.now()) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return new Date(now).toDateString() === d.toDateString() ? timeOf(d) : dayOf(d);
}

/// Activity (canvas inspector): the latest audit events, newest first, as "time · what,
/// by whom"; Full history opens the History panel.
export function activitySection(ctx, env, audit, { senderName = "", limit = 8 } = {}) {
  const items = [...(audit?.items || [])].reverse();
  if (!items.length) return h("p", { class: "os-muted os-insp__none", text: t("inspector.no-activity") });
  const ol = h("ol", { class: "os-activity", attrs: { "data-testid": "activity-list" } });
  for (const a of items.slice(0, limit)) {
    ol.append(h("li", { class: "os-activity__item" },
      h("time", { class: "os-activity__t", attrs: { datetime: a.at, title: fmtDate(a.at) }, text: clock(a.at) }),
      h("span", { class: "os-activity__text" }, h("span", { text: historyVerb(a.type) }), h("span", { class: "os-muted", text: ` · ${actorOf(a, env, senderName)}` }))));
  }
  const wrap = h("div", { class: "os-activity-wrap" }, ol);
  if (items.length > limit || env.status !== "draft") {
    wrap.append(button(t("inspector.full-history"), { icon: "list-ordered", size: "sm", variant: "subtle", onClick: async () => {
      try { await historyPanel(ctx, env.id, env.subject || t("envelope.untitled")); } catch (err) { if (!ctx.failed(err)) toastError(err); }
    } }));
  }
  return wrap;
}

// ---- Insights (WEB-18) -----------------------------------------------------------------

/// Whether the Insights tab exists for this session: ML available with extraction or
/// personal-data detection on. When ML is unavailable nothing ML is shown at all.
export async function insightsAvailable() {
  const st = await mlStatus();
  return featureOn(st, "extraction") || featureOn(st, "personal_data");
}

/// How many details are suggested and still open for an envelope (the row chip and the
/// tab badge): open `entity` suggestions, as the canvas counts them.
export function openDetails(envId) {
  return openOf(storedSuggestions(envId)).filter((s) => s.kind === "entity").length;
}

/// The "Reading the document" state (canvas): a page with a scanning band and an
/// indeterminate bar. Its motion stops under reduced motion (app.css).
function readingCard() {
  return h("div", { class: "os-reading os-rise", attrs: { role: "status", "data-testid": "insights-reading" } },
    h("div", { class: "os-reading__page", attrs: { "aria-hidden": "true" } },
      ...["w60", "", "w85", "", "w70 is-hit", "", "w50 is-hit"].map((c) => h("span", { class: `os-reading__line ${c}`.trim() })),
      h("span", { class: "os-reading__band os-scan" })),
    h("div", { class: "os-reading__text" }, h("b", { text: t("ml.reading") }), h("span", { class: "os-muted", text: t("insights.reading-text") })),
    h("span", { class: "os-indet", attrs: { "aria-hidden": "true" } }));
}

/// Whether a draft's documents are still being read (analysis queued or running).
async function analysing(ctx, env) {
  if (env.status !== "draft" || !ctx.api.getAnalysis) return false;
  const runs = await Promise.all((env.documents || []).map((d) => ctx.api.getAnalysis(env.id, d.id).catch(() => null)));
  return runs.some((r) => r && (r.status === "queued" || r.status === "running"));
}

/// Insights (canvas): the heading with where it ran, the reading state while analysis
/// runs, a card per suggested detail (Save to details / Dismiss), and the personal data
/// found, in an amber card whose "Review for redaction" lists each item to add to the
/// redaction proposal or dismiss (docs/33 §6: accepting a personal_data suggestion adds
/// it to that proposal). Suggestions are only ever applied by a person's click. Returns
/// `{el, destroy}`.
export function insightsSection(ctx, env) {
  const el = h("div", { class: "os-insights", attrs: { "data-testid": "insights" } }, mlHeading());
  const body = h("div", { class: "os-insights__body", attrs: { "aria-live": "polite" } });
  el.append(body);
  let reviewing = false;
  let timer = null;
  let gone = false;
  const decide = (fn) => async (s) => {
    try { await fn(env.id, s.id); } catch (err) { if (!ctx.failed(err)) toast(t("insights.failed"), "error"); }
  };
  function render() {
    const all = storedSuggestions(env.id);
    const details = all.filter((s) => s.kind === "entity");
    const pii = piiSummary(all);
    const nodes = details.map((s) => suggestion(s, { onAccept: decide(acceptSuggestion), onDismiss: decide(dismissSuggestion) }).el);
    if (pii.total) nodes.push(piiCard(all, pii));
    if (!nodes.length) nodes.push(h("p", { class: "os-muted os-insp__none", text: t("insights.empty") }));
    body.querySelectorAll(":scope > :not(.os-reading)").forEach((n) => n.remove());
    body.append(...nodes);
  }
  function piiCard(all, pii) {
    const pages = pii.pages.length === 1 ? t("insights.pii-pages-one", { list: pii.pages[0] }) : t("insights.pii-pages", { list: pii.pages.join(", ") });
    const items = pii.items.map((x) => (x.n > 1 ? `${x.label} ×${x.n}` : x.label)).join(", ");
    const card = h("div", { class: "os-pii", attrs: { "data-testid": "insights-pii" } },
      h("b", { class: "os-pii__title", text: t("ml.pii") }),
      h("span", { class: "os-pii__text", text: pii.pages.length ? t("insights.pii-text", { items, pages }) : items }));
    const toggle = h("button", { type: "button", class: "os-pii__btn", attrs: { "aria-expanded": String(reviewing) }, text: reviewing ? t("insights.pii-hide") : t("insights.pii-review") });
    toggle.addEventListener("click", () => { reviewing = !reviewing; render(); el.querySelector(".os-pii__btn")?.focus(); });
    card.append(toggle);
    if (reviewing) {
      const list = h("div", { class: "os-pii__list" });
      for (const s of all.filter((x) => x.kind === "personal_data")) {
        list.append(suggestion(s, { onAccept: decide(acceptSuggestion), onDismiss: decide(dismissSuggestion), acceptLabel: t("insights.pii-accept"), acceptedText: t("insights.pii-accepted"), testId: "pii-item" }).el);
      }
      card.append(list);
    }
    return card;
  }
  async function poll() {
    if (gone) return;
    let running = false;
    try { running = await analysing(ctx, env); } catch { running = false; }
    if (gone) return;
    const card = body.querySelector(".os-reading");
    if (running && !card) body.prepend(readingCard());
    if (!running && card) card.remove();
    if (running) timer = setTimeout(async () => { await poll(); if (!gone && !body.querySelector(".os-reading")) { await loadSuggestions(env.id, { refresh: true }).catch(() => []); render(); } }, 1500);
  }
  const off = onSuggestions(({ envId }) => { if (envId === env.id && !gone) render(); });
  loadSuggestions(env.id).then(render, (err) => { if (!ctx.failed(err)) render(); });
  poll();
  return { el, destroy() { gone = true; clearTimeout(timer); off(); } };
}

// ---- Evidence ------------------------------------------------------------------------

/// Evidence (canvas inspector): the audit trail's links as checked here (never "verified"
/// or "unchanged": no hash is recomputed in the page), the chain head, the document
/// fingerprint when the server recorded one, and the certificate and Verify for a
/// completed agreement.
export function evidenceSection(ctx, env, audit) {
  const wrap = h("div", { class: "os-evid", attrs: { "data-testid": "evidence" } });
  const links = auditLinks(audit);
  if (!links.n) wrap.append(h("p", { class: "os-muted os-insp__none", text: t("evidence.none") }));
  else {
    wrap.append(h("div", { class: `os-evid__card${links.ok ? "" : " is-broken"}`, attrs: { "data-testid": "evidence-links" } },
      h("span", { class: "os-evid__title" }, icon(links.ok ? "shield-check" : "triangle-alert", { size: 16 }), h("span", { text: t(links.ok ? "evidence.linked" : "evidence.broken") })),
      h("span", { class: "os-evid__text", text: t(links.ok ? "evidence.linked-text" : "evidence.broken-text", { n: links.n }) })));
  }
  if (audit?.chain_head) {
    wrap.append(h("div", { class: "os-evid__field" },
      h("span", { class: "os-evid__label", text: t("evidence.head") }),
      h("span", { class: "os-evid__hashrow" },
        h("code", { class: "os-evid__hash", attrs: { "data-testid": "chain-head" }, text: groupHex(audit.chain_head) }),
        button(t("envelope.copy-chain"), { icon: "copy", size: "sm", variant: "ghost", iconOnly: true, onClick: () => copyText(audit.chain_head, t("envelope.chain-copied")) }))));
  }
  for (const d of env.documents || []) {
    const fp = documentFingerprint(d);
    if (!fp) continue;
    wrap.append(h("div", { class: "os-evid__field" },
      h("span", { class: "os-evid__label", text: t("evidence.fingerprint") }),
      h("code", { class: "os-evid__hash", attrs: { "data-testid": "evidence-fingerprint" }, text: groupHex(fp) })));
  }
  const acts = h("div", { class: "os-evid__actions" });
  if (hasCertificate(ctx, env.status)) acts.append(button(t("evidence.certificate"), { icon: "file-check", size: "sm", variant: "subtle", onClick: (ev) => busy(ev.currentTarget, async () => { try { await downloadCertificate(ctx, env.id); } catch (err) { if (!ctx.failed(err)) toastError(err); } }) }));
  if (env.status === "completed") {
    acts.append(h("a", { class: "os-btn os-btn--subtle os-btn--sm", href: "verify.html", target: "_blank", rel: "noopener", attrs: { "data-testid": "evidence-verify" } },
      icon("shield-check", { size: 16 }), h("span", { text: t("envelope.verify") }), h("span", { class: "os-sr-only", text: t("action.new-tab") })));
  }
  if (acts.childElementCount) wrap.append(acts);
  return wrap;
}

// ---- Views in the sidebar -------------------------------------------------------------

/// Fill the shell's `#nav-views` (canvas sidebar Views): a dot, the name and a live
/// count per view. `current` is marked; `onPick(id)` switches in place on Agreements,
/// else the links navigate. Views that need the Inbox are left out where the server has
/// none.
export function renderNavViews(ctx, { current = null, counts = null, onPick = null } = {}) {
  const host = document.getElementById("nav-views");
  if (!host) return;
  const inbox = ctx.api.available ? ctx.api.available("inbox") : true;
  const views = VIEWS.filter((v) => v.nav && (!v.inbox || inbox));
  host.replaceChildren(h("p", { class: "os-side__views-title", attrs: { "aria-hidden": "true" }, text: t("agreements.views") }));
  for (const v of views) {
    const n = counts ? counts[v.id] : null;
    const a = h("a", {
      class: "os-nav__link os-navview", href: agreementsHash(v.id),
      attrs: { "data-view": v.id, "aria-current": current === v.id ? "page" : null, "aria-label": n == null ? null : t("agreements.nav.count", { view: t(`agreements.nav.${v.id}`), n }) },
    }, h("span", { class: `os-dot os-dot--${v.dot}`, attrs: { "aria-hidden": "true" } }), h("span", { text: t(`agreements.nav.${v.id}`) }),
      n == null ? null : h("span", { class: "os-navview__n", attrs: { "aria-hidden": "true" }, text: String(n) }));
    if (onPick) a.addEventListener("click", (e) => { if (e.metaKey || e.ctrlKey || e.shiftKey) return; e.preventDefault(); onPick(v.id); });
    host.append(a);
  }
}

// ---- Loading -------------------------------------------------------------------------

/// Every agreement (newest change first), up to `cap`, with the server's search `q`:
/// `{items, capped}`.
export async function fetchAgreements(ctx, { q = "", cap = 1000 } = {}) {
  const items = [];
  let cursor;
  do {
    const page = await ctx.api.listEnvelopes({ limit: 200, cursor, q: q || undefined, sort: "updated_at", order: "desc" });
    items.push(...(page?.items || []));
    cursor = page?.next_cursor || null;
  } while (cursor && items.length < cap);
  return { items, capped: !!cursor };
}

/// The envelopes waiting for this user's signature (the Inbox), `{ids, items}`; empty
/// where the server has no Inbox yet (`NOT_ON_SERVER.inbox`).
export async function fetchInbox(ctx) {
  if (ctx.api.available && !ctx.api.available("inbox")) return { ids: new Set(), items: [] };
  try {
    const page = await ctx.api.inbox({ limit: 200 });
    const items = page?.items || [];
    return { ids: new Set(items.map((x) => x.id)), items };
  } catch {
    return { ids: new Set(), items: [] };
  }
}

/// A person's initials (re-exported for the screens that draw an avatar themselves).
export { initials, groupOf };
