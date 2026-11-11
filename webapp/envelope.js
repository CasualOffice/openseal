// Envelope detail (WEB-01, WEB-06): status, the recipients' timeline in routing order,
// the audit events with who did each (docs/32), and the sender's actions: edit or delete
// a draft; correct (a side panel), resend to everyone or to one recipient, download the
// PDF as it stands, or void one in progress; download the sealed PDF and the
// certificate of a completed one; copy or save as template any of them; delete one that
// ended without completing. docs/47 §UX audit E-01 to E-05.

import { h, clear, fmtDate, download } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { register, unregisterPrefix } from "./commands.js";
import { button, busy, statusBadge, errorState, skeletonRows, toast, toastError, reasonDialog, emptyState, tabs, pdfPreview, menuButton } from "./ui/index.js";
import { statusLine, auditTable, copyEnvelope, saveAsTemplate, deleteEnvelope, downloadCurrent, downloadSealed, correctPanel, DELETABLE, ACTIVE } from "./envactions.js";

const SIGNING = new Set(["signer", "in_person_signer", "approver"]);
/// Events a recipient makes on opening: the first of them is when they opened it.
const OPENING = ["recipient_opened", "recipient_authenticated", "recipient_consented", "document_viewed"];

export function mount(view, ctx, [rawId]) {
  const id = decodeURIComponent(rawId);
  const body = h("div", { class: "os-detail", attrs: { "aria-busy": "true" } }, skeletonRows(4));
  view.append(body);
  let env = null;
  let previews = [];
  let tab = "summary";
  let senderName = "";

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

  function render(e, audit) {
    clear(body);
    const subject = e.subject || t("envelope.untitled");
    const back = h("a", { href: "#/agreements", class: "os-back" }, icon("chevron-left", { size: 16 }), h("span", { text: t("agreements.title") }));
    const actions = h("div", { class: "os-actions" });
    const more = [];
    if (e.status === "draft") actions.append(button(t("envelope.edit"), { icon: "file-pen-line", variant: "primary", command: "envelope.edit", onClick: () => ctx.navigate(`#/prepare/${encodeURIComponent(e.id)}`) }));
    if (ACTIVE.has(e.status)) {
      actions.append(button(t("envelope.correct"), { icon: "pencil", variant: "primary", command: "envelope.correct", attrs: { "data-testid": "envelope-correct" }, onClick: guard(async () => { if (await correctPanel(ctx, id)) load(); }) }));
      actions.append(button(t("envelope.resend"), { icon: "rotate-cw", command: "envelope.resend", onClick: (ev) => busy(ev.currentTarget, () => resend()) }));
      actions.append(button(t("envelope.download-current"), { icon: "download", command: "envelope.download-current", attrs: { title: t("envelope.download-current-help") }, onClick: (ev) => busy(ev.currentTarget, guard(() => downloadCurrent(ctx, id, env))) }));
      actions.append(button(t("envelope.void"), { icon: "ban", variant: "danger", command: "envelope.void", onClick: voidIt }));
    }
    if (e.status === "completed") {
      actions.append(button(t("envelope.download"), { icon: "download", variant: "primary", command: "envelope.download", onClick: (ev) => busy(ev.currentTarget, guard(() => downloadSealed(ctx, id, env))) }));
      actions.append(button(t("envelope.certificate"), { icon: "file-check", command: "envelope.certificate", onClick: (ev) => busy(ev.currentTarget, downloadCertificate) }));
    }
    more.push({ label: t("agreements.copy"), icon: "copy", run: guard(async () => { const c = await copyEnvelope(ctx, id); ctx.navigate(`#/prepare/${encodeURIComponent(c.id)}`); }) });
    more.push({ label: t("agreements.save-template"), icon: "layout-template", run: guard(() => saveAsTemplate(ctx, id)) });
    if (DELETABLE.has(e.status)) {
      more.push({ label: t(e.status === "draft" ? "agreements.delete-draft" : "agreements.delete"), icon: "trash-2", danger: true, run: guard(async () => { if (await deleteEnvelope(ctx, id, subject, e.status)) ctx.navigate("#/agreements"); }) });
    }
    actions.append(menuButton({ label: t("agreements.actions-for", { subject }), buttonOpts: { icon: "ellipsis", variant: "secondary", iconOnly: true }, items: () => more }));

    const line = statusLine(e);
    const head = h("div", { class: "os-page-head" },
      h("div", { class: "os-page-head__main" }, h("h1", { class: "os-page-title", text: subject }), statusBadge(e.status),
        line ? h("p", { class: "os-muted os-detail__line", attrs: { "data-testid": "status-line" }, text: line }) : null),
      actions);
    const meta = h("dl", { class: "os-meta" },
      h("dt", { text: t("envelope.created") }), h("dd", { text: fmtDate(e.created_at) }),
      e.sent_at ? [h("dt", { text: t("envelope.sent") }), h("dd", { text: fmtDate(e.sent_at) })] : null,
      e.expires_at ? [h("dt", { text: t("envelope.expires") }), h("dd", { text: fmtDate(e.expires_at) })] : null,
      e.ended_at ? [h("dt", { text: t("envelope.ended") }), h("dd", { text: fmtDate(e.ended_at) })] : null,
      senderName ? [h("dt", { text: t("envelope.sender") }), h("dd", { text: senderName })] : null,
      e.void_reason ? [h("dt", { text: t("envelope.void-reason") }), h("dd", { text: e.void_reason })] : null,
      h("dt", { text: t("envelope.documents") }), h("dd", { text: (e.documents || []).map((d) => d.name).join(", ") || "—" }));

    // Summary (routing and history) and Documents (a preview of each, sealed once
    // completed), as DocuSign's envelope page.
    for (const p of previews) p.destroy();
    previews = [];
    const docTab = (panel) => {
      const docs = e.documents || [];
      if (!docs.length) { panel.append(emptyState({ illus: "documents", title: t("empty.documents.title"), text: t("envelope.no-docs"), testId: "empty-envelope-docs" })); return; }
      for (const d of docs) {
        const v = e.status === "completed" ? "sealed" : "normalized";
        const p = pdfPreview({ load: () => ctx.api.documentContent(id, d.id, v), name: d.name });
        previews.push(p);
        panel.append(p.el);
      }
    };
    body.append(back, head, meta, tabs({
      label: t("envelope.sections"),
      tabs: [{ id: "summary", label: t("envelope.tab.summary"), icon: "list-checks" }, { id: "documents", label: t("envelope.tab.documents"), icon: "file-text" }],
      current: tab,
      onChange: (v) => { tab = v; },
      render: (which, panel) => { if (which === "documents") docTab(panel); else panel.append(recipientsSection(e, audit), auditSection(e, audit)); },
    }));
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
      const events = (audit.items || []).filter((a) => (a.event?.recipient_id || a.event?.actor?.id) === r.id);
      const at = (type) => events.find((x) => x.type === type)?.at;
      const opened = OPENING.map(at).filter(Boolean).sort()[0] || null;
      const sent = e.sent_at && r.status !== "created" ? (events.find((x) => x.type === "recipient_sent")?.at || e.sent_at) : null;
      // A copy (CC) is sent once everyone has signed: it has no opened or signed step (E-04).
      const steps = r.type === "cc"
        ? [[r.status === "completed" ? t("timeline.delivered") : t("timeline.cc-waiting"), r.status === "completed" ? (r.completed_at || e.ended_at) : null]]
        : [
          [t("timeline.sent"), sent],
          [t("timeline.opened"), opened],
          [r.status === "declined" ? t("timeline.declined") : t("timeline.completed"), r.completed_at || at("recipient_completed") || at("recipient_declined")],
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
    if (audit.chain_head) sec.append(h("p", { class: "os-muted os-small os-chainhead" }, h("span", { text: `${t("audit.head")} ` }), h("code", { text: audit.chain_head })));
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
  async function voidIt() {
    const reason = await reasonDialog(t("envelope.void-title"), t("envelope.void-label"), { confirm: t("envelope.void") });
    if (!reason) return;
    try { await ctx.api.voidEnvelope(id, reason); toast(t("envelope.voided"), "success"); load(); } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }
  async function downloadCertificate() {
    try { download(await ctx.api.certificate(id), `certificate-${id}.pdf`); } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }

  register("envelope.refresh", { label: t("action.refresh"), run: load });
  load();
  return () => { unregisterPrefix("envelope.refresh"); for (const p of previews) p.destroy(); };
}
