// Envelope detail (WEB-01, WEB-06, UX-07): status, the recipients' timeline in routing
// order, the audit events with who did each (docs/32), and the sender's actions.
//
// UX-07 (after DocuSign's envelope page): one primary and one secondary action for each
// state, everything else in a grouped More menu with destructive items last —
//   draft:     Edit draft            | —            | More: copy, save as template · delete
//   sent:      Correct               | Resend       | More: download current, copy, save as template, history · void
//   completed: Download signed PDF   | Certificate  | More: copy, save as template, history
//   declined, voided, expired: Copy and resend | Download (as it ended) | More: certificate (UXW-30), save as template, history · delete
// A callout under the title says why an envelope ended. The summary is two columns:
// the envelope ID (with Copy), dates and sender beside the message and the settings
// (reminders, expiry, signing order, authentication). An Evidence card gives the chain
// head with Copy, what it means, and for a completed envelope the way to verify it.

import { h, clear, fmtDate } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { register, unregisterPrefix } from "./commands.js";
import { button, busy, statusBadge, errorState, skeletonRows, toast, toastError, emptyState, tabs, pdfPreview, menuButton } from "./ui/index.js";
import {
  statusLine, auditTable, copyEnvelope, saveAsTemplate, deleteEnvelope, downloadCurrent, downloadSealed, downloadCertificate, hasCertificate,
  correctPanel, historyPanel, voidEnvelopes, copyText, DELETABLE, ACTIVE, ENDED,
} from "./envactions.js";
import { envelopeActions } from "./managemodel.js";

const SIGNING = new Set(["signer", "in_person_signer", "approver"]);
/// Events a recipient makes on opening: the first of them is when they opened it.
const OPENING = ["recipient.delivered", "recipient.auth_passed", "recipient.consented", "recipient.viewed_document"];

export function mount(view, ctx, [rawId]) {
  const id = decodeURIComponent(rawId);
  const body = h("div", { class: "os-detail", attrs: { "aria-busy": "true" } }, skeletonRows(4));
  view.append(body);
  let env = null;
  let previews = [];
  let tab = "summary";
  let senderName = "";
  let showTab = null;

  async function load() {
    try {
      const [{ envelope }, audit] = await Promise.all([ctx.api.getEnvelope(id), ctx.api.audit(id).catch(() => ({ items: [], chain_head: null }))]);
      env = envelope;
      senderName = envelope.sender_user_id && envelope.sender_user_id === ctx.session?.user_id ? t("agreements.you") : "";
      if (!senderName && ctx.session?.admin) {
        try { senderName = ((await ctx.api.users.list()).items || []).find((u) => u.id === envelope.sender_user_id)?.name || ""; } catch { /* the line says "sender" */ }
      }
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

    const line = statusLine(e);
    const head = h("div", { class: "os-page-head os-detail__head" },
      h("div", { class: "os-page-head__main" }, h("h1", { class: "os-page-title", text: subject }), statusBadge(e.status),
        line ? h("p", { class: "os-muted os-detail__line", attrs: { "data-testid": "status-line" }, text: line }) : null),
      actions);

    // Summary (routing and history) and Documents (a preview of each, sealed once
    // completed), as DocuSign's envelope page.
    for (const p of previews) p.destroy();
    previews = [];
    const docTab = (panel, focus = null) => {
      const docs = e.documents || [];
      if (!docs.length) { panel.append(emptyState({ illus: "documents", title: t("empty.documents.title"), text: t("envelope.no-docs"), testId: "empty-envelope-docs" })); return; }
      for (const d of docs) {
        const variant = e.status === "completed" ? "sealed" : "normalized";
        const p = pdfPreview({ load: () => ctx.api.documentContent(id, d.id, variant), name: d.name });
        p.el.dataset.doc = d.id;
        previews.push(p);
        panel.append(p.el);
      }
      if (focus) requestAnimationFrame(() => panel.querySelector(`[data-doc="${CSS.escape(focus)}"]`)?.scrollIntoView({ block: "start" }));
    };
    let focusDoc = null;
    const tabset = tabs({
      label: t("envelope.sections"),
      tabs: [{ id: "summary", label: t("envelope.tab.summary"), icon: "list-checks" }, { id: "documents", label: t("envelope.tab.documents"), icon: "file-text" }],
      current: tab,
      onChange: (which) => { tab = which; },
      render: (which, panel) => {
        if (which === "documents") { docTab(panel, focusDoc); focusDoc = null; } else panel.append(...[recipientsSection(e, audit), evidenceSection(e, audit), auditSection(e, audit)].filter(Boolean));
      },
    });
    showTab = (which, doc = null) => { focusDoc = doc; tabset.querySelector(`[data-tab="${which}"]`)?.click(); };
    body.append(...[back, head, endedCallout(e), summaryCard(e), tabset].filter(Boolean));
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
        ? docs.map((d) => h("button", { type: "button", class: "os-linkbtn", text: d.name || t("envelope.untitled-doc"), on: { click: () => showTab?.("documents", d.id) } }))
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

  /// Evidence (UX-07): the chain head with Copy and what it is; for a completed envelope
  /// Verify (verify.html checks the sealed PDF and its embedded trail in the browser,
  /// offline). None for a draft.
  function evidenceSection(e, audit) {
    if (e.status === "draft") return null;
    const sec = h("section", { class: "os-card os-evidence", attrs: { "aria-labelledby": "evidence-h", "data-testid": "evidence-card" } },
      h("div", { class: "os-evidence__head" }, h("span", { class: "os-evidence__icon" }, icon("shield-check", { size: 20 })),
        h("h2", { id: "evidence-h", class: "os-card__title", text: t("envelope.evidence") })));
    const done = e.status === "completed";
    sec.append(h("p", { class: "os-muted", text: t(done ? "envelope.evidence-sealed" : ENDED.has(e.status) ? "envelope.evidence-ended" : "envelope.evidence-open") }));
    if (audit.chain_head) {
      sec.append(h("div", { class: "os-evidence__chain" },
        h("span", { class: "os-label", text: t("audit.head") }),
        h("code", { class: "os-chainhead", attrs: { "data-testid": "chain-head" }, text: audit.chain_head }),
        button(t("envelope.copy-chain"), { icon: "copy", size: "sm", variant: "ghost", iconOnly: true, onClick: () => copyText(audit.chain_head, t("envelope.chain-copied")) })),
      h("p", { class: "os-help", text: t("envelope.chain-help") }));
    }
    // Verify; the signed PDF and the certificate are the header's own buttons, not repeated.
    if (done) {
      sec.append(h("div", { class: "os-actions os-evidence__actions" },
        h("a", { class: "os-btn os-btn--secondary os-btn--sm", href: "verify.html", target: "_blank", rel: "noopener", attrs: { "data-testid": "evidence-verify" } },
          icon("shield-check", { size: 16 }), h("span", { text: t("envelope.verify") }), h("span", { class: "os-sr-only", text: t("action.new-tab") }))));
    }
    if (done) sec.append(h("p", { class: "os-help", text: t("envelope.verify-help") }));
    return sec;
  }

  function recipientsSection(e, audit) {
    const sec = h("section", { class: "os-card", attrs: { "aria-labelledby": "rcpt-h" } }, h("h2", { id: "rcpt-h", class: "os-card__title", text: t("envelope.recipients") }));
    const recs = [...(e.recipients || [])].sort((a, b) => a.routing_order - b.routing_order);
    if (!recs.length) {
      sec.append(emptyState({ illus: "recipients", title: t("empty.recipients.title"), text: t("empty.recipients.text"), action: e.status === "draft" ? button(t("envelope.edit"), { variant: "primary", onClick: () => ctx.navigate(`#/prepare/${encodeURIComponent(e.id)}`) }) : null, testId: "empty-recipients" }));
      return sec;
    }
    const ol = h("ol", { class: "os-timeline" });
    for (const r of recs) {
      // The server's events name their recipient in `data.recipient_id` (WEB-12).
      const events = (audit.items || []).filter((a) => (a.event?.data?.recipient_id || (a.event?.actor?.kind === "recipient" ? a.event.actor.id : null)) === r.id);
      const at = (type) => events.find((x) => x.type === type)?.at;
      const opened = OPENING.map(at).filter(Boolean).sort()[0] || null;
      const sent = e.sent_at && r.status !== "created" ? (events.find((x) => x.type === "invitation.sent")?.at || e.sent_at) : null;
      // A copy (CC) is sent once everyone has signed: it has no opened or signed step (E-04).
      const steps = r.type === "cc"
        ? [[r.status === "completed" ? t("timeline.delivered") : t("timeline.cc-waiting"), r.status === "completed" ? (r.completed_at || e.ended_at) : null]]
        : [
          [t("timeline.sent"), sent],
          [t("timeline.opened"), opened],
          [r.status === "declined" ? t("timeline.declined") : t("timeline.completed"), r.completed_at || at("recipient.completed") || at("recipient.declined")],
        ];
      const canResend = ACTIVE.has(e.status) && SIGNING.has(r.type) && (r.status === "sent" || r.status === "delivered");
      const li = h("li", { class: `os-timeline__item is-${r.status}`, attrs: { "data-testid": "recipient-row" } },
        h("div", { class: "os-timeline__who" },
          h("span", { class: "os-order", attrs: { "aria-label": t("recipient.order-n", { n: r.routing_order }) }, text: String(r.routing_order) }),
          h("div", {},
            h("strong", { text: r.name }),
            h("span", { class: "os-muted", text: ` · ${r.email} · ${t(`rtype.${r.type}`)}` })),
          statusBadge(r.status),
          canResend ? button(t("envelope.resend"), { icon: "rotate-cw", size: "sm", attrs: { "aria-label": t("envelope.resend-to", { name: r.name || r.email }) }, onClick: (ev) => busy(ev.currentTarget, () => resend(r)) }) : null),
        h("ul", { class: "os-steps" }, steps.map(([label, when]) =>
          h("li", { class: when ? "is-done" : "" }, icon(when ? "circle-check" : "clock", { size: 16 }), h("span", { text: label }), when ? h("time", { class: "os-muted", attrs: { datetime: when }, text: fmtDate(when) }) : null))),
        r.declined_reason ? h("p", { class: "os-muted", text: t("envelope.declined-reason", { reason: r.declined_reason }) }) : null,
      );
      if (ctx.mock && r.mock_token && ACTIVE.has(e.status) && ["sent", "delivered"].includes(r.status)) {
        li.append(h("a", { class: "os-link", href: `/s/${encodeURIComponent(r.mock_token)}?mock=1`, attrs: { "data-testid": "signing-link" } }, icon("external-link", { size: 16 }), h("span", { text: t("mock.signing-link") })));
      }
      ol.append(li);
    }
    sec.append(ol);
    return sec;
  }

  function auditSection(e, audit) {
    const sec = h("section", { class: "os-card", attrs: { "aria-labelledby": "audit-h" } }, h("h2", { id: "audit-h", class: "os-card__title", text: t("envelope.audit") }));
    if (!(audit.items || []).length) { sec.append(h("p", { class: "os-muted", text: t("envelope.audit-empty") })); return sec; }
    sec.append(auditTable(audit, e, senderName));
    return sec;
  }

  /// Resend to everyone still to act, or to one recipient (E-03).
  async function resend(r = null) {
    try {
      await ctx.api.resend(id, r ? [r.id] : undefined);
      toast(r ? t("envelope.resent-to", { name: r.name || r.email }) : t("envelope.resent"), "success");
      load();
    } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }
  register("envelope.refresh", { label: t("action.refresh"), run: load });
  load();
  return () => { unregisterPrefix("envelope.refresh"); unregisterPrefix("envelope.act."); for (const p of previews) p.destroy(); };
}
