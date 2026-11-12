// What Agreements and the envelope page share (WEB-06; docs/47 §UX audit A-01, A-03,
// E-01, E-02, E-05): a one-line status ("Waiting for Taylor Kim"), who did each audit
// event, the history panel, and the actions on one envelope — copy, save as template,
// delete, download the PDF as it stands, correct. Each screen calls these and refreshes
// itself; nothing here keeps state.

import { h, fmtDate, download } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { toBase64 } from "./api.js";
import { added } from "./templatesync.js";
import { recipientCorrection } from "./people.js";
import { openPanel, toast, confirmDialog, emptyState } from "./ui/index.js";

const SIGNING = new Set(["signer", "in_person_signer", "approver"]);
const ACTED = new Set(["completed", "declined"]);
/// Statuses a sender may delete (A-03): a draft, or an envelope that ended without
/// completing. A completed agreement is evidence and stays (retention decides, docs/32).
export const DELETABLE = new Set(["draft", "voided", "declined", "expired"]);
export const ACTIVE = new Set(["sent", "delivered"]);

const byOrder = (e) => [...(e?.recipients || [])].sort((a, b) => a.routing_order - b.routing_order);
const who = (r) => r?.name || r?.email || t("actor.unknown");

/// The recipients the envelope is waiting for: signing recipients who have been sent
/// it and not acted, at the lowest routing order still open.
export function waitingFor(e) {
  const open = byOrder(e).filter((r) => SIGNING.has(r.type) && !ACTED.has(r.status));
  if (!open.length) return [];
  const sent = open.filter((r) => r.status === "sent" || r.status === "delivered");
  if (sent.length) return sent;
  const first = Math.min(...open.map((r) => r.routing_order));
  return open.filter((r) => r.routing_order === first);
}

/// One line saying where an envelope stands, in words (A-01): "Waiting for Taylor Kim".
export function statusLine(e) {
  if (!e) return "";
  switch (e.status) {
    case "draft": return "";
    case "sent":
    case "delivered": {
      const names = waitingFor(e).map(who);
      return names.length ? t("agreements.line.waiting", { names: names.join(", ") }) : "";
    }
    case "completed": return t("agreements.line.completed", { date: fmtDate(e.ended_at) });
    case "declined": return t("agreements.line.declined", { name: who(byOrder(e).find((r) => r.status === "declined")) });
    case "voided": return t("agreements.line.voided", { date: fmtDate(e.ended_at) });
    case "expired": return t("agreements.line.expired", { date: fmtDate(e.ended_at || e.expires_at) });
    default: return "";
  }
}

/// Who did an audit event (E-05): the event's `actor` (docs/32 §2: `{kind, id, name}`;
/// the mock writes `"sender"`, `"recipient"` or `"system"`), else its recipient, else
/// the system. `senderName` names the sending user.
export function actorOf(item, env, senderName = "") {
  const ev = item?.event || {};
  const a = ev.actor;
  const kind = a && typeof a === "object" ? a.kind : a;
  // Only an event a recipient made is theirs; the system's invitation to them is not.
  const rid = kind === "recipient" ? (a.id || ev.data?.recipient_id) : null;
  const sender = () => t("actor.sender", { name: (a && typeof a === "object" && a.name) || senderName || t("agreements.you") });
  if (kind === "sender" || kind === "user" || kind === "api_client") return sender();
  if (kind === "recipient") {
    const r = (env?.recipients || []).find((x) => x.id === rid);
    return t("actor.recipient", { name: (a && typeof a === "object" && a.name) || who(r) });
  }
  return t("actor.system");
}

/// The label of an audit event type, or the type itself when there is none.
export function eventLabel(type) {
  const label = t(`event.${type}`);
  return label === `event.${type}` ? type : label;
}

/// The audit events as a table: number, event, by whom, when, hash.
export function auditTable(audit, env, senderName) {
  const table = h("table", { class: "os-table os-table--compact os-table--cards os-audit" },
    h("caption", { class: "os-sr-only", text: t("envelope.audit") }),
    h("thead", {}, h("tr", {},
      h("th", { class: "os-col-num", attrs: { scope: "col" }, text: "#" }),
      h("th", { attrs: { scope: "col" }, text: t("audit.event") }),
      h("th", { attrs: { scope: "col" }, text: t("envelope.by") }),
      h("th", { attrs: { scope: "col" }, text: t("audit.when") }),
      h("th", { attrs: { scope: "col" }, class: "os-col-hash", text: t("audit.hash") }))));
  const tb = h("tbody");
  for (const a of audit.items || []) {
    tb.append(h("tr", {},
      h("td", { class: "os-col-num", text: String(a.seq) }),
      h("td", { class: "os-audit__event", text: eventLabel(a.type) }),
      h("td", { attrs: { "data-label": t("envelope.by") }, text: actorOf(a, env, senderName) }),
      h("td", { attrs: { "data-label": t("audit.when") } }, h("time", { attrs: { datetime: a.at }, text: fmtDate(a.at) })),
      h("td", { class: "os-col-hash" }, h("code", { attrs: { title: a.hash }, text: `${(a.hash || "").slice(0, 12)}…` }))));
  }
  table.append(tb);
  return h("div", { class: "os-table-wrap" }, table);
}

/// The history of one envelope in a side panel (A-03 "History").
export async function historyPanel(ctx, id, subject) {
  const [{ envelope }, audit] = await Promise.all([ctx.api.getEnvelope(id), ctx.api.audit(id)]);
  await openPanel({
    id: "history",
    title: t("agreements.history-title", { subject }),
    width: 34,
    build(body) {
      if (!(audit.items || []).length) { body.append(emptyState({ illus: "documents", title: t("envelope.audit-empty"), text: "" })); return; }
      body.append(auditTable(audit, envelope, ""));
    },
    actions: [{ label: t("action.close"), value: null }],
  });
}

/// Fetch every document of an envelope as `{name, content_base64}`.
async function docsOf(ctx, e, variant = "normalized") {
  const out = [];
  for (const d of e.documents || []) {
    const blob = await ctx.api.documentContent(e.id, d.id, variant);
    out.push({ id: d.id, name: d.name, content_base64: toBase64(new Uint8Array(await blob.arrayBuffer())) });
  }
  return out;
}
const num = (v) => Number.parseFloat(v);

/// Copy (A-03): a new draft with the same documents, recipients, fields, message and
/// options. Access codes are secrets and are not copied; the copy asks for them again.
export async function copyEnvelope(ctx, id) {
  const { envelope: e } = await ctx.api.getEnvelope(id);
  const docs = await docsOf(ctx, e);
  const docIndex = new Map(docs.map((d, i) => [d.id, i]));
  const recs = byOrder(e);
  const body = {
    subject: e.subject ? `${e.subject} (copy)`.slice(0, 255) : "",
    message: e.message || "",
    signing_options: e.signing_options || {},
    documents: docs.map(({ name, content_base64 }) => ({ name, content_base64 })),
    recipients: recs.map((r, i) => ({ ref: `r${i}`, type: r.type, name: r.name, email: r.email || undefined, routing_order: r.routing_order, auth: (r.auth || []).filter((m) => m !== "access_code") })),
    fields: (e.fields || []).filter((f) => docIndex.has(f.document_id) && recs.some((r) => r.id === f.recipient_id)).map((f) => ({
      recipient: `r${recs.findIndex((r) => r.id === f.recipient_id)}`,
      document: docIndex.get(f.document_id),
      type: f.type,
      page: f.placement.page, x: num(f.placement.x), y: num(f.placement.y), width: num(f.placement.width), height: num(f.placement.height),
      ...(f.required ? { required: true } : {}),
      ...(f.label ? { label: f.label } : {}),
    })),
  };
  const created = await ctx.api.createEnvelope(body);
  toast(t("agreements.copied"), "success");
  return created;
}

/// Save as template (A-03): roles "Role 1…n" in routing order, then the documents and
/// the fields bound to the roles' ids (the server answers the template with ids; adding
/// a document answers the whole template, so the new document is the one not there).
export async function saveAsTemplate(ctx, id) {
  const { envelope: e } = await ctx.api.getEnvelope(id);
  const recs = byOrder(e);
  const roleOf = new Map(recs.map((r, i) => [r.id, t("template.role-n", { n: i + 1 })]));
  const name = (e.subject || t("envelope.untitled")).slice(0, 255);
  const tpl = await ctx.api.templates.create({
    name, ...(e.subject ? { email_subject: e.subject } : {}), ...(e.message ? { email_message: e.message } : {}),
    roles: recs.map((r) => ({ name: roleOf.get(r.id), type: r.type, routing_order: r.routing_order })),
  });
  const roleId = new Map(recs.map((r) => [r.id, (tpl.roles || []).find((x) => x.name === roleOf.get(r.id))?.id]));
  const docs = await docsOf(ctx, e);
  const ids = new Map();
  let known = tpl.documents || [];
  for (const d of docs) {
    const bytes = Uint8Array.from(atob(d.content_base64), (c) => c.charCodeAt(0));
    const next = await ctx.api.templates.addDocument(tpl.id, d.name, bytes);
    ids.set(d.id, added(known, next?.documents)[0]?.id);
    known = next?.documents || known;
  }
  const fields = (e.fields || []).filter((f) => ids.get(f.document_id) && roleId.get(f.recipient_id));
  if (fields.length) {
    await ctx.api.templates.addFields(tpl.id, fields.map((f) => ({
      role_id: roleId.get(f.recipient_id), document_id: ids.get(f.document_id), type: f.type, placement: f.placement,
      ...(f.required ? { required: true } : {}), ...(f.label ? { label: f.label } : {}),
    })));
  }
  toast(t("agreements.template-saved", { name }), "success");
  return tpl;
}

/// Delete (A-03; a destructive confirmation, so a modal). Resolves true when deleted.
export async function deleteEnvelope(ctx, id, subject, status) {
  const draft = status === "draft";
  const ok = await confirmDialog(t(draft ? "agreements.delete-draft-title" : "agreements.delete-title"), t("agreements.delete-text", { subject }), { confirm: t(draft ? "agreements.delete-draft" : "agreements.delete"), danger: true });
  if (!ok) return false;
  const { etag } = await ctx.api.getEnvelope(id);
  await ctx.api.deleteEnvelope(id, etag);
  toast(t("agreements.deleted"), "success");
  return true;
}

/// Download each document as it stands while the envelope is in progress (E-02).
export async function downloadCurrent(ctx, id, env = null) {
  const e = env || (await ctx.api.getEnvelope(id)).envelope;
  for (const d of e.documents || []) {
    download(await ctx.api.documentContent(id, d.id, "current"), `${(d.name || "document.pdf").replace(/\.pdf$/i, "")}-current.pdf`);
  }
}

/// Download the sealed documents of a completed envelope.
export async function downloadSealed(ctx, id, env = null) {
  const e = env || (await ctx.api.getEnvelope(id)).envelope;
  for (const d of e.documents || []) {
    download(await ctx.api.documentContent(id, d.id, "sealed"), `${(d.name || "document.pdf").replace(/\.pdf$/i, "")}-sealed.pdf`);
  }
}

const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

/// Correct a sent envelope (E-01, DocuSign's Correct) in a side panel: name, email and
/// access code of each recipient who has not acted, then a new invitation to those
/// changed who were already sent it. Resolves true when corrected.
///
/// WEB-10: each changed recipient is one `PATCH …/recipients/{r}` (If-Match), which the
/// server applies as a correction of a sent envelope. `POST …/correct`'s
/// `update_recipient` replaces the whole engine `RecipientSpec`, refuses an
/// `access_code` member, and needs members the API does not show (`date_format`), so
/// it would drop settings or fail; the PATCH keeps the rest and stores the code.
export async function correctPanel(ctx, id) {
  const { envelope: e, etag } = await ctx.api.getEnvelope(id);
  const recs = byOrder(e);
  const rows = [];
  const result = await openPanel({
    id: "correct",
    title: t("envelope.correct-title"),
    width: 30,
    build(body) {
      body.append(h("p", { class: "os-muted", text: t("envelope.correct-lede") }));
      const list = h("ol", { class: "os-correct" });
      recs.forEach((r, i) => {
        const acted = ACTED.has(r.status);
        const head = h("div", { class: "os-correct__head" },
          h("span", { class: "os-order", text: String(r.routing_order) }),
          h("strong", { text: who(r) }),
          h("span", { class: "os-muted os-small", text: t(`rtype.${r.type}`) }));
        const li = h("li", { class: `os-correct__item os-r${(i % 6) + 1}${acted ? " is-acted" : ""}` }, head);
        if (acted) {
          li.append(h("p", { class: "os-muted os-small", text: t("envelope.correct-acted", { name: who(r) }) }));
          list.append(li);
          return;
        }
        const p = `cr-${i}`;
        const name = h("input", { id: `${p}-name`, class: "os-input", value: r.name || "", maxLength: 255, autocomplete: "off", attrs: { "aria-describedby": `${p}-err` } });
        const email = h("input", { id: `${p}-email`, class: "os-input", type: "email", value: r.email || "", autocomplete: "off", attrs: { "aria-describedby": `${p}-err` } });
        const had = (r.auth || []).includes("access_code");
        const req = h("input", { id: `${p}-req`, type: "checkbox", class: "os-checkbox", checked: had });
        const code = h("input", { id: `${p}-code`, class: "os-input", type: "text", autocomplete: "off", maxLength: 255, attrs: { "aria-describedby": `${p}-code-help ${p}-err` } });
        const codeRow = h("div", { class: "os-correct__code" },
          h("label", { class: "os-label", attrs: { for: `${p}-code` }, text: t("envelope.correct-code") }), code,
          h("p", { id: `${p}-code-help`, class: "os-help", text: t("envelope.correct-code-help") }));
        codeRow.hidden = !had;
        req.addEventListener("change", () => { codeRow.hidden = !req.checked; });
        const err = h("p", { id: `${p}-err`, class: "os-field-error", attrs: { "aria-live": "polite" } });
        li.append(
          h("label", { class: "os-label", attrs: { for: `${p}-name` }, text: t("prepare.name") }), name,
          h("label", { class: "os-label", attrs: { for: `${p}-email` }, text: t("prepare.email") }), email,
          h("label", { class: "os-check", attrs: { for: `${p}-req` } }, req, h("span", { text: t("envelope.require-code") })),
          codeRow, err);
        rows.push({ r, name, email, req, code, err, had });
        list.append(li);
      });
      body.append(list);
      if (!rows.length) body.append(h("p", { class: "os-muted", attrs: { "data-testid": "correct-none" }, text: t("envelope.correct-none") }));
    },
    actions: [
      { label: t("action.cancel"), value: null },
      {
        label: t("envelope.correct-save"), variant: "primary", icon: "send", attrs: { "data-testid": "correct-save" },
        onClick: async () => {
          if (!rows.length) return null;
          let bad = null;
          for (const x of rows) {
            x.err.textContent = "";
            for (const el of [x.name, x.email, x.code]) el.removeAttribute("aria-invalid");
            const problem = !x.name.value.trim() ? [x.name, t("use.need-name")]
              : !EMAIL.test(x.email.value.trim()) ? [x.email, t("use.need-email")]
                : x.req.checked && !x.had && !x.code.value ? [x.code, t("envelope.correct-need-code")] : null;
            if (problem) { x.err.textContent = problem[1]; problem[0].setAttribute("aria-invalid", "true"); bad ||= problem[0]; }
          }
          if (bad) { bad.focus(); return undefined; }
          const changed = rows.filter((x) => x.name.value.trim() !== (x.r.name || "") || x.email.value.trim() !== (x.r.email || "") || x.req.checked !== x.had || (x.req.checked && x.code.value));
          if (!changed.length) return "same";
          let tag = etag;
          for (const x of changed) {
            const body = recipientCorrection(x.r, { name: x.name.value.trim(), email: x.email.value.trim(), requireCode: x.req.checked, code: x.code.value });
            if (!body) continue;
            await ctx.api.patchRecipient(id, x.r.id, tag, body);
            tag = (await ctx.api.getEnvelope(id)).etag;
          }
          const notify = changed.filter((x) => x.r.status === "sent" || x.r.status === "delivered").map((x) => x.r.id);
          if (notify.length) await ctx.api.resend(id, notify);
          return "corrected";
        },
      },
    ],
  });
  if (result === "same") toast(t("envelope.corrected-nochange"), "info");
  if (result === "corrected") toast(t("envelope.corrected"), "success");
  return result === "corrected";
}

/// The icon for a status line, for lists.
export function lineIcon(status) {
  return icon({ draft: "file-pen-line", sent: "hourglass", delivered: "hourglass", completed: "circle-check", declined: "circle-x", voided: "ban", expired: "clock" }[status] || "file-text", { size: 16 });
}
