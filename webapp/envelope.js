// Envelope detail (WEB-01): status, the recipients' timeline in routing order, the
// audit events (docs/32), and the sender's actions: resend, void, edit a draft,
// download the sealed PDF and the certificate of completion.

import { h, clear, fmtDate, download } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { register, unregisterPrefix } from "./commands.js";
import { button, busy, statusBadge, errorState, skeletonRows, toast, toastError, reasonDialog, emptyState, tabs, pdfPreview } from "./ui/index.js";

const ACTIVE = new Set(["sent", "delivered"]);

export function mount(view, ctx, [rawId]) {
  const id = decodeURIComponent(rawId);
  const body = h("div", { class: "os-detail", attrs: { "aria-busy": "true" } }, skeletonRows(4));
  view.append(body);
  let env = null;
  let previews = [];
  let tab = "summary";

  async function load() {
    try {
      const [{ envelope }, audit] = await Promise.all([ctx.api.getEnvelope(id), ctx.api.audit(id).catch(() => ({ items: [], chain_head: null }))]);
      env = envelope;
      render(envelope, audit);
    } catch (err) {
      if (ctx.failed(err)) return;
      errorState(body, err, load);
    } finally {
      body.removeAttribute("aria-busy");
    }
  }

  function render(e, audit) {
    clear(body);
    const back = h("a", { href: "#/agreements", class: "os-back" }, icon("chevron-left", { size: 16 }), h("span", { text: t("agreements.title") }));
    const actions = h("div", { class: "os-actions" });
    if (e.status === "draft") actions.append(button(t("envelope.edit"), { icon: "file-pen-line", variant: "primary", command: "envelope.edit", onClick: () => ctx.navigate(`#/prepare/${encodeURIComponent(e.id)}`) }));
    if (ACTIVE.has(e.status)) {
      actions.append(button(t("envelope.resend"), { icon: "rotate-cw", command: "envelope.resend", onClick: (ev) => busy(ev.currentTarget, resend) }));
      actions.append(button(t("envelope.void"), { icon: "ban", variant: "danger", command: "envelope.void", onClick: voidIt }));
    }
    if (e.status === "completed") {
      actions.append(button(t("envelope.download"), { icon: "download", variant: "primary", command: "envelope.download", onClick: (ev) => busy(ev.currentTarget, downloadSealed) }));
      actions.append(button(t("envelope.certificate"), { icon: "file-check", command: "envelope.certificate", onClick: (ev) => busy(ev.currentTarget, downloadCertificate) }));
    }
    const head = h("div", { class: "os-page-head" },
      h("div", { class: "os-page-head__main" }, h("h1", { class: "os-page-title", text: e.subject || t("envelope.untitled") }), statusBadge(e.status)),
      actions);
    const meta = h("dl", { class: "os-meta" },
      h("dt", { text: t("envelope.created") }), h("dd", { text: fmtDate(e.created_at) }),
      e.sent_at ? [h("dt", { text: t("envelope.sent") }), h("dd", { text: fmtDate(e.sent_at) })] : null,
      e.ended_at ? [h("dt", { text: t("envelope.ended") }), h("dd", { text: fmtDate(e.ended_at) })] : null,
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
      render: (which, panel) => { if (which === "documents") docTab(panel); else panel.append(recipientsSection(e, audit), auditSection(audit)); },
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
      const events = (audit.items || []).filter((a) => a.event?.recipient_id === r.id);
      const at = (type) => events.find((x) => x.type === type)?.at;
      const steps = [
        [t("timeline.sent"), e.sent_at && r.status !== "created" ? e.sent_at : null],
        [t("timeline.opened"), at("recipient_opened")],
        [r.status === "declined" ? t("timeline.declined") : t("timeline.completed"), r.completed_at || at("recipient_completed") || at("recipient_declined")],
      ];
      const li = h("li", { class: `os-timeline__item is-${r.status}` },
        h("div", { class: "os-timeline__who" },
          h("span", { class: "os-order", attrs: { "aria-label": t("recipient.order-n", { n: r.routing_order }) }, text: String(r.routing_order) }),
          h("div", {},
            h("strong", { text: r.name }),
            h("span", { class: "os-muted", text: ` · ${r.email} · ${t(`rtype.${r.type}`)}` })),
          statusBadge(r.status)),
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

  function auditSection(audit) {
    const sec = h("section", { class: "os-card", attrs: { "aria-labelledby": "audit-h" } }, h("h2", { id: "audit-h", class: "os-card__title", text: t("envelope.audit") }));
    const items = audit.items || [];
    if (!items.length) { sec.append(h("p", { class: "os-muted", text: t("envelope.audit-empty") })); return sec; }
    const table = h("table", { class: "os-table os-table--compact" },
      h("thead", {}, h("tr", {},
        h("th", { attrs: { scope: "col" }, text: "#" }),
        h("th", { attrs: { scope: "col" }, text: t("audit.event") }),
        h("th", { attrs: { scope: "col" }, text: t("audit.when") }),
        h("th", { attrs: { scope: "col" }, class: "os-col-hash", text: t("audit.hash") }))));
    const tb = h("tbody");
    for (const a of items) {
      tb.append(h("tr", {},
        h("td", { text: String(a.seq) }),
        h("td", { text: t(`event.${a.type}`) === `event.${a.type}` ? a.type : t(`event.${a.type}`) }),
        h("td", {}, h("time", { attrs: { datetime: a.at }, text: fmtDate(a.at) })),
        h("td", { class: "os-col-hash" }, h("code", { attrs: { title: a.hash }, text: `${(a.hash || "").slice(0, 12)}…` }))));
    }
    table.append(tb);
    sec.append(h("div", { class: "os-table-wrap" }, table));
    if (audit.chain_head) sec.append(h("p", { class: "os-muted os-small" }, h("span", { text: `${t("audit.head")} ` }), h("code", { text: audit.chain_head })));
    return sec;
  }

  async function resend() {
    try { await ctx.api.resend(id); toast(t("envelope.resent"), "success"); load(); } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }
  async function voidIt() {
    const reason = await reasonDialog(t("envelope.void-title"), t("envelope.void-label"), { confirm: t("envelope.void") });
    if (!reason) return;
    try { await ctx.api.voidEnvelope(id, reason); toast(t("envelope.voided"), "success"); load(); } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }
  async function downloadSealed() {
    try {
      for (const d of env.documents || []) {
        const blob = await ctx.api.documentContent(id, d.id, "sealed");
        download(blob, (d.name || "document.pdf").replace(/\.pdf$/i, "") + "-sealed.pdf");
      }
    } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }
  async function downloadCertificate() {
    try { download(await ctx.api.certificate(id), `certificate-${id}.pdf`); } catch (err) { if (!ctx.failed(err)) toastError(err); }
  }

  register("envelope.refresh", { label: t("action.refresh"), run: load });
  load();
  return () => { unregisterPrefix("envelope.refresh"); for (const p of previews) p.destroy(); };
}
