// Envelope detail (WEB-01, WEB-06, UX-07; restyled in WEB-17 on the approved canvas,
// Main.dc.html): the header in the inspector's language (status pill, where it stands,
// the name and its sub line, the actions), the documents, the summary and the audit
// trail, and beside them the inspector's own sections as components (agreementparts.js):
// Recipients in signing order (with each one's Sent / Opened / Signed steps and Resend
// here), Insights where ml.js says document intelligence is available, and Evidence.
//
// UX-07 (after DocuSign's envelope page): one primary and one secondary action for each
// state, everything else in a grouped More menu with destructive items last —
//   draft:     Edit draft            | —            | More: copy, save as template · delete
//   sent:      Correct               | Resend       | More: download current, copy, save as template, history · void
//   completed: Download signed PDF   | Certificate  | More: copy, save as template, history
//   declined, voided, expired: Copy and resend | Download (as it ended) | More: certificate (UXW-30), save as template, history · delete
// A callout under the title says why an envelope ended. The summary is two columns:
// the envelope ID (with Copy), dates and sender beside the message and the settings
// (reminders, expiry, signing order, authentication). The Evidence card says what the
// API's audit trail shows (its links checked here, its head) and, once completed, how
// to verify the sealed PDF.

import { h, clear, fmtDate } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { register, unregisterPrefix } from "./commands.js";
import { button, busy, statusPill, errorState, skeletonLines, skeletonBlock, toast, toastError, emptyState, pdfPreview, menuButton } from "./ui/index.js";
import {
  statusLine, auditTable, copyEnvelope, saveAsTemplate, deleteEnvelope, downloadCurrent, downloadSealed, downloadCertificate, hasCertificate,
  correctPanel, historyPanel, voidEnvelopes, copyText, shortDate, DELETABLE, ENDED,
} from "./envactions.js";
import { envelopeActions, pillOf } from "./managemodel.js";
import { recipientsSection, evidenceSection, insightsSection, insightsAvailable } from "./agreementparts.js";
import { registerMeaningSearch } from "./meaning.js";

const SIGNING = new Set(["signer", "in_person_signer", "approver"]);

export function mount(view, ctx, [rawId]) {
  const id = decodeURIComponent(rawId);
  // Loading: the page's own shape (header, then the two columns) in skeleton.
  const body = h("div", { class: "os-detail os-env", attrs: { "aria-busy": "true", "aria-label": t("inspector.loading") } },
    h("div", { class: "os-env__skelhead" }, skeletonLines(2)),
    h("div", { class: "os-env__grid" }, h("div", { class: "os-env__main" }, skeletonBlock({ height: 9 }), skeletonBlock({ height: 18 })), h("div", { class: "os-env__side" }, skeletonBlock({ height: 14 }))));
  view.append(body);
  let env = null;
  let previews = [];
  let senderName = "";
  let mlOn = false;
  let live = []; // destroy() of live sections (Insights)
  const offMeaning = registerMeaningSearch(ctx);

  async function load() {
    try {
      const [{ envelope }, audit] = await Promise.all([ctx.api.getEnvelope(id), ctx.api.audit(id).catch(() => ({ items: [], chain_head: null }))]);
      env = envelope;
      senderName = envelope.sender_user_id && envelope.sender_user_id === ctx.session?.user_id ? t("agreements.you") : "";
      if (!senderName && ctx.session?.admin) {
        try { senderName = ((await ctx.api.users.list()).items || []).find((u) => u.id === envelope.sender_user_id)?.name || ""; } catch { /* the line says "sender" */ }
      }
      mlOn = await insightsAvailable().catch(() => false);
      render(envelope, audit);
    } catch (err) {
      if (ctx.failed(err)) return;
      errorState(body, err, load);
    } finally {
      body.removeAttribute("aria-busy");
    }
  }

  const guard = (fn) => async () => { try { await fn(); } catch (err) { if (!ctx.failed(err)) toastError(err); } };

  /// Every verb on this page, by action id: its label, icon, command id and what it does.
  function verbs(e) {
    const subject = e.subject || t("envelope.untitled");
    const copyThen = guard(async () => { const c = await copyEnvelope(ctx, id); ctx.navigate(`#/prepare/${encodeURIComponent(c.id)}`); });
    return {
      edit: { label: t("envelope.edit"), icon: "file-pen-line", panel: true, run: () => ctx.navigate(`#/prepare/${encodeURIComponent(e.id)}`) },
      correct: { label: t("envelope.correct"), icon: "pencil", testId: "envelope-correct", panel: true, run: guard(async () => { if (await correctPanel(ctx, id)) load(); }) },
      resend: { label: t("envelope.resend"), icon: "rotate-cw", run: () => resend() },
      "download-current": { label: t("envelope.download-current"), icon: "download", title: t("envelope.download-current-help"), run: guard(() => downloadCurrent(ctx, id, env)) },
      "download-ended": { label: t("envelope.download-ended"), icon: "download", title: t("envelope.download-ended-help"), run: guard(() => downloadCurrent(ctx, id, env)) },
      download: { label: t("envelope.download"), icon: "download", run: guard(() => downloadSealed(ctx, id, env)) },
      certificate: { label: t("envelope.certificate"), icon: "file-check", run: guard(() => downloadCertificate(ctx, id)) },
      "copy-resend": { label: t("envelope.copy-resend"), icon: "copy", title: t("envelope.copy-resend-help"), run: copyThen },
      copy: { label: t("agreements.copy"), icon: "copy", run: copyThen },
      template: { label: t("agreements.save-template"), icon: "layout-template", run: guard(() => saveAsTemplate(ctx, id)) },
      history: { label: t("agreements.history"), icon: "list-ordered", panel: true, run: guard(() => historyPanel(ctx, id, subject)) },
      void: { label: t("envelope.void"), icon: "ban", danger: true, panel: true, run: guard(async () => { if (await voidEnvelopes(ctx, [id])) load(); }) },
      delete: { label: t(e.status === "draft" ? "agreements.delete-draft" : "agreements.delete"), icon: "trash-2", danger: true, panel: true, run: guard(async () => { if (await deleteEnvelope(ctx, id, subject, e.status)) ctx.navigate("#/agreements"); }) },
    };
  }

  function render(e, audit) {
    clear(body);
    for (const s of live) s();
    live = [];
    unregisterPrefix("envelope.act.");
    const subject = e.subject || t("envelope.untitled");
    const back = h("a", { href: "#/agreements", class: "os-back" }, icon("chevron-left", { size: 16 }), h("span", { text: t("agreements.title") }));
    const v = verbs(e);
    const plan = envelopeActions(e.status, { cert: hasCertificate(ctx, e.status) });
    // Every verb is a command (docs/47 principle 4): the buttons own theirs, the More
    // menu's are registered.
    for (const ids of plan.more) for (const a of ids) if (v[a]) register(`envelope.act.${a}`, { label: v[a].label, run: v[a].run });
    const btn = (a, variant) => {
      const x = v[a];
      // Work that ends on its own (a download, a resend, a copy) shows the button busy;
      // one that opens a panel or a dialog does not (the panel is the feedback).
      return button(x.label, { icon: x.icon, variant, command: `envelope.act.${a}`, attrs: { title: x.title || null, "data-testid": x.testId || `envelope-${a}` }, onClick: (ev) => (x.panel ? x.run() : busy(ev.currentTarget, x.run)) });
    };
    const actions = h("div", { class: "os-actions os-detail__actions" });
    if (plan.primary) actions.append(btn(plan.primary, "primary"));
    if (plan.secondary) actions.append(btn(plan.secondary, "secondary"));
    const groups = plan.more.map((ids) => ids.filter((a) => v[a] && (a !== "delete" || DELETABLE.has(e.status)))).filter((g) => g.length);
    if (groups.length) {
      actions.append(menuButton({
        label: t("envelope.more-actions"),
        menuLabel: t("agreements.actions-for", { subject }),
        buttonOpts: { icon: "ellipsis", variant: "secondary", attrs: { "data-testid": "envelope-more" } },
        items: () => groups.flatMap((g, i) => [i ? "separator" : null, ...g.map((a) => ({ label: v[a].label, icon: v[a].icon, danger: v[a].danger, run: v[a].run }))]).filter(Boolean),
      }));
    }

    // The header in the inspector's language (canvas Main): status pill and where it
    // stands, the name, the sub line; the actions on the right.
    const line = statusLine(e);
    // The sub line says when it went out and how long it is (the status line says where it stands).
    const pages = (e.documents || []).reduce((n, d) => n + (Number.isInteger(d.pages) ? d.pages : 0), 0);
    const sub = [e.sent_at ? t("agreements.sub.sent", { date: shortDate(e.sent_at) }) : t("agreements.sub.draft", { date: shortDate(e.updated_at || e.created_at) }), pages ? (pages === 1 ? t("agreements.sub.page") : t("agreements.sub.pages", { n: pages })) : null].filter(Boolean).join(" · ");
    const head = h("div", { class: "os-page-head os-detail__head os-env__head" },
      h("div", { class: "os-page-head__main os-env__title" },
        h("div", { class: "os-env__pillrow" }, statusPill(t(`status.${e.status}`), pillOf(e)),
          line ? h("p", { class: "os-env__line os-detail__line", attrs: { "data-testid": "status-line" }, text: line }) : null),
        h("h1", { class: "os-page-title", text: subject }),
        h("p", { class: "os-env__sub", text: sub })),
      actions);

    // The documents, then the summary and the audit trail; beside them the inspector's
    // sections (Recipients, Insights, Evidence) as the list's inspector draws them.
    for (const p of previews) p.destroy();
    previews = [];
    const docs = e.documents || [];
    const docCard = h("section", { class: "os-card os-env__docs", attrs: { "aria-labelledby": "docs-h", "data-testid": "envelope-documents" } },
      h("h2", { id: "docs-h", class: "os-card__title", text: t("envelope.documents") }));
    if (!docs.length) docCard.append(emptyState({ illus: "documents", title: t("empty.documents.title"), text: t("envelope.no-docs"), testId: "empty-envelope-docs" }));
    for (const d of docs) {
      const p = pdfPreview({ load: () => ctx.api.documentContent(id, d.id, e.status === "completed" ? "sealed" : "normalized"), name: d.name });
      p.el.dataset.doc = d.id;
      previews.push(p);
      docCard.append(p.el);
    }
    const sideCard = (title, hid, node, testId = null) => h("section", { class: "os-card os-env__card", attrs: { "aria-labelledby": hid, "data-testid": testId } },
      h("h2", { id: hid, class: "os-card__title", text: title }), node);
    const people = sideCard(t("envelope.recipients"), "rcpt-h",
      (e.recipients || []).length
        ? recipientsSection(e, audit, { detailed: true, onResend: (r) => resend(r), onHost: (r) => host(r), mock: ctx.mock })
        : emptyState({ illus: "recipients", title: t("empty.recipients.title"), text: t("empty.recipients.text"), action: e.status === "draft" ? button(t("envelope.edit"), { variant: "primary", onClick: () => ctx.navigate(`#/prepare/${encodeURIComponent(e.id)}`) }) : null, testId: "empty-recipients" }));
    const side = h("div", { class: "os-env__side" }, people);
    if (mlOn) {
      const s = insightsSection(ctx, e);
      live.push(s.destroy);
      side.append(h("section", { class: "os-card os-env__card", attrs: { "aria-label": t("inspector.tab.insights") } }, s.el));
    }
    if (e.status !== "draft") side.append(sideCard(t("envelope.evidence"), "evidence-h", evidenceSection(ctx, e, audit, { certificate: false }), "evidence-card"));
    const mainCol = h("div", { class: "os-env__main" }, summaryCard(e), docCard, auditSection(e, audit));
    body.append(...[back, head, endedCallout(e), h("div", { class: "os-env__grid" }, mainCol, side)].filter(Boolean));
  }

  /// Why an envelope ended, under its title (UX-07): who declined and their reason, the
  /// void reason, or when it expired.
  function endedCallout(e) {
    if (!ENDED.has(e.status)) return null;
    let title;
    let text = "";
    if (e.status === "declined") {
      const r = (e.recipients || []).find((x) => x.status === "declined");
      title = t("envelope.callout.declined", { name: r?.name || r?.email || t("actor.unknown") });
      text = r?.declined_reason ? t("envelope.callout.reason", { reason: r.declined_reason }) : t("envelope.callout.no-reason");
    } else if (e.status === "voided") {
      title = t("envelope.callout.voided", { date: fmtDate(e.ended_at) });
      text = e.void_reason ? t("envelope.callout.reason", { reason: e.void_reason }) : "";
    } else {
      title = t("envelope.callout.expired", { date: fmtDate(e.ended_at || e.expires_at) });
    }
    return h("div", { class: `os-callout os-callout--ended is-${e.status}`, attrs: { role: "note", "data-testid": "decline-callout" } },
      icon(e.status === "expired" ? "clock" : e.status === "voided" ? "ban" : "circle-x", { size: 20 }),
      h("div", {}, h("p", { class: "os-callout__title", text: title }), text ? h("p", { text }) : null,
        h("p", { class: "os-muted os-small", text: t("envelope.callout.next") })));
  }

  /// The two-column summary (UX-07): identity and dates; message and settings.
  function summaryCard(e) {
    const recs = [...(e.recipients || [])].sort((a, b) => a.routing_order - b.routing_order);
    const idRow = h("dd", { class: "os-envid" },
      h("code", { attrs: { "data-testid": "envelope-id" }, text: e.id }),
      button(t("envelope.copy-id"), { icon: "copy", size: "sm", variant: "ghost", iconOnly: true, onClick: () => copyText(e.id, t("envelope.id-copied")) }));
    const docs = e.documents || [];
    const facts = h("dl", { class: "os-meta os-envsum__facts" },
      h("dt", { text: t("envelope.id") }), idRow,
      h("dt", { text: t("envelope.created") }), h("dd", { text: fmtDate(e.created_at) }),
      e.sent_at ? [h("dt", { text: t("envelope.sent") }), h("dd", { text: fmtDate(e.sent_at) })] : null,
      e.ended_at ? [h("dt", { text: t("envelope.ended") }), h("dd", { text: fmtDate(e.ended_at) })] : null,
      senderName ? [h("dt", { text: t("envelope.sender") }), h("dd", { text: senderName })] : null,
      h("dt", { text: t("envelope.documents") }),
      h("dd", { class: "os-envsum__docs" }, docs.length
        ? docs.map((d) => h("button", { type: "button", class: "os-linkbtn", text: d.name || t("envelope.untitled-doc"), on: { click: () => body.querySelector(`[data-doc="${CSS.escape(d.id)}"]`)?.scrollIntoView({ block: "start" }) } }))
        : "—"));
    const rem = e.reminders || {};
    const reminders = rem.first_after_days || rem.then_every_days
      ? [rem.first_after_days ? t("envelope.reminders-first", { n: rem.first_after_days }) : null, rem.then_every_days ? t("envelope.reminders-every", { n: rem.then_every_days }) : null].filter(Boolean).join(", ")
      : t("envelope.reminders-off");
    const signers = recs.filter((r) => SIGNING.has(r.type));
    const order = new Set(signers.map((r) => r.routing_order)).size > 1 ? t("envelope.order-on") : t("envelope.order-off");
    const coded = recs.filter((r) => (r.auth || []).includes("access_code")).map((r) => r.name || r.email);
    const auth = coded.length ? t("envelope.auth-code", { names: coded.join(", ") }) : t("envelope.auth-email");
    const settings = h("dl", { class: "os-meta os-envsum__settings" },
      h("dt", { text: t("envelope.subject") }), h("dd", { text: e.subject || "—" }),
      h("dt", { text: t("envelope.message") }), h("dd", { class: "os-envsum__message", text: e.message || t("envelope.no-message") }),
      h("dt", { text: t("envelope.expires") }), h("dd", { text: e.expires_at ? fmtDate(e.expires_at) : t("agreements.never") }),
      h("dt", { text: t("envelope.reminders") }), h("dd", { text: reminders }),
      h("dt", { text: t("envelope.signing-order") }), h("dd", { text: order }),
      h("dt", { text: t("envelope.authentication") }), h("dd", { text: auth }),
      e.void_reason ? [h("dt", { text: t("envelope.void-reason") }), h("dd", { text: e.void_reason })] : null);
    return h("section", { class: "os-card os-envsum", attrs: { "aria-label": t("envelope.summary") } },
      h("div", { class: "os-envsum__col" }, h("h2", { class: "os-envsum__title", text: t("envelope.details") }), facts),
      h("div", { class: "os-envsum__col" }, h("h2", { class: "os-envsum__title", text: t("envelope.message-settings") }), settings));
  }

  function auditSection(e, audit) {
    const sec = h("section", { class: "os-card", attrs: { "aria-labelledby": "audit-h" } }, h("h2", { id: "audit-h", class: "os-card__title", text: t("envelope.audit") }));
    if (!(audit.items || []).length) { sec.append(h("p", { class: "os-muted", text: t("envelope.audit-empty") })); return sec; }
    sec.append(auditTable(audit, e, senderName));
    return sec;
  }

  /// Resend to everyone still to act, or to one recipient (E-03).
  /// UXW-18: host an in-person signer here: the server's one-time link acts as this
  /// member hosting them, so the signing page opens in this tab, on its own path.
  async function host(r) {
    try {
      const v = await ctx.api.hostInPerson(id, r.id);
      const u = new URL(v.url, location.href);
      location.assign(`${u.pathname}${u.search}${ctx.mock ? `${u.search ? "&" : "?"}mock=1` : ""}`);
    } catch (err) { toastError(err); }
  }

  async function resend(r = null) {
    try {
      await ctx.api.resend(id, r ? [r.id] : undefined);
      toast(r ? t("envelope.resent-to", { name: r.name || r.email }) : t("envelope.resent"), "success");
      load();
    } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }
  register("envelope.refresh", { label: t("action.refresh"), run: load });
  load();
  return () => { unregisterPrefix("envelope.refresh"); unregisterPrefix("envelope.act."); for (const p of previews) p.destroy(); for (const s of live) s(); offMeaning(); };
}
